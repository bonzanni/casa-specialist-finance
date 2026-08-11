# plugins/bank-feed/server/tools_auth.py
"""Authorization and renewal MCP tools, and the plumbing collection shares.

THE DESTRUCTIVE GATE IS CASA'S, NOT OURS. The protected tools are declared in
`casa.protectedTools`; casa's fail-closed PreToolUse hook demands an operator
grant BOUND TO THE EXACT ARGUMENTS before the call reaches this process. No tool
takes a `confirm` argument: a model-supplied boolean IS inference alone and
would satisfy itself, which is why no such argument exists. The check in
`_require_declared` is DEFENCE IN DEPTH, not the boundary.

`collect_authorization` is NEVER protected — casa's nudge turns have no
operator sender and the call would be denied outright, stranding every
authorization.

`setup_bank_feed` is ARGUMENT-FREE, and that is casa's contract rather than this
module's taste (issue #7). `plugin_setup_episodes._instruction`
dispatches it unprompted after the trigger consent settles and tells the running
agent to "Call it with no arguments" — there is no caller to supply arguments and
no approval round in which to choose them, so a schema that ADVERTISED parameters
would only invite an agent to invent values for them on the one path where none
can be meaningful. The operator's half of the credential dance therefore lives in
its own ordinary tool, `bank_feed_signin`, which takes the email / pasted link /
resend arguments and then runs the very same ladder (`_reconcile`). The setup tool
does not merely ignore arguments it happens to receive — it never forwards them.

Neither of the two is protected, and that is deliberate rather than an omission.
The ladder's writes are broad: it forges a signing key inside 1Password when one
is absent, writes the durable refresh token to the vault, REGISTERS the Enable
Banking application when none exists yet, and PATCHes casa's callback redirect
URI onto it. Casa's setup episode runs the ladder BEFORE any operator grant
could exist, so a grant bound to exact arguments is not expressible for any of
these writes — and `bank_feed_signin` reaches the same rungs, so protecting it
alone would buy nothing while adding a confirmation round to the one step the
operator is already, visibly, driving by hand.

Every write is additive-only and idempotent — nothing here ever deletes
anything, an existing application is adopted rather than duplicated, and a
second run with nothing left to do changes nothing observable. `POST
/api/applications` (registration) IS in `eb_admin.ALLOW`, narrowly, for exactly
this; `DELETE` is not in `ALLOW` at all and stays that way — deleting an
application orphans every bank session riding it, and no reconcile rung is
allowed to hold that power. The real risk was never the writes but the
ARGUMENT: a caller-supplied redirect URI would register an attacker-controlled
redirect and harvest authorization codes. No tool here accepts one — the single
source is `callbacks.discover()`, which cross-checks casa's routed callback name
before it will hand the URI over, and that same string is threaded into
`mint()`, into `start_auth()` and into `add_redirect_url()`. Registering
one string while minting another would make the provider reject every
authorization, and the two would differ only in ways nobody reads closely.

The plugin never waits and never schedules: `link_bank` returns a URL and the
turn ends. It cannot see or set reminders either, so it records its OWN half of
the renewal exchange — the date it asked for — and reports that, rather than
printing a warning it can never clear.

The control-panel credential is `CASA_BANKFEED_EB_CP_TOKEN`, which is what
`.mcp.json` passes into this process. Reading any other name means production
can never whitelist a bank.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import os
import platform
import time
from pathlib import Path

import apply
import callbacks
import eb_admin
import eb_ais
import ebmode
import fbauth
import flows
import jwtsign
import opvault
import provenance
import store
import tools_read
from tools_read import register

# Declared in `.claude-plugin/plugin.json::casa.protectedTools`.
# `label_account` is here because included=false removes an account from every
# balance and total: not destructive, but an inference-only path from
# attacker-controlled text to a money-relevant answer.
# `accept_app_reregistration` is the ONLY key to the vanished-app gate: no
# model-suppliable argument may authorize a registration that orphans every
# bank session, so casa's operator-confirmation hook is what gates it.
PROTECTED = frozenset({"unlink_bank", "purge", "forget_local_account",
                       "delete_all_data", "label_account",
                       "accept_app_reregistration"})

def _app_name() -> str:
    """The ONE application this plugin owns — in the mode's world.

    A function, not a constant, so no
    comparison site can pair the name with a stale mode: every site that
    matches an application record checks `(_app_name(), ebmode.mode())`
    together, which is what keeps a SANDBOX app named 'casa-finance' out
    of production and a PRODUCTION app named 'casa-finance-sandbox' out
    of the sandbox world."""
    return ("casa-finance-sandbox" if ebmode.is_sandbox()
            else "casa-finance")

#: The ONE name deployment supplies, and it is an ALIAS of `eb_admin`'s — the
#: same rule this module applies to `apply`'s revocation statuses. `eb_admin`
#: owns the control-panel credential and already asserts its own constant
#: against `.mcp.json`; re-typing the literal here is how a second spelling
#: gets introduced, and that defect has happened here — the manifest
#: declared one name, this module read a DIFFERENT, undeclared one, `_admin()`
#: raised on every production call, and `link_bank` silently took its
#: "whitelist unknown" branch, so production could never whitelist a bank. The
#: undeclared name is deliberately not written anywhere in this file: a test
#: greps the source for it.
ADMIN_TOKEN_VAR = eb_admin.ENV_TOKEN_VAR

# --------------------------------------------------------------------------
# THE TWO SETUP-PROVISIONED CREDENTIALS ARE WIRED UNDER DIFFERENT NAMES THAN
# THE SERVER READS (issue #4, casa v0.155.0). Every other constant here, and
# every `os.environ` read in this file, names a PROCESS KEY — the `.mcp.json`
# env dict's KEY, fixed at spawn. The two names below are the OTHER side of
# that dict for the key and the app id: the REFERENCES casa resolves out of
# `plugin-env.conf`, and therefore the only names a "have the configurator
# wire X" sentence in this module may ever contain.
#
# They differ from the process keys for one reason: `plugin.json` declares
# them in `casa.setupProvides` (so casa loads the plugin without them instead
# of deadlocking setup against its own output, and reports them
# `unprovisioned` until they land), and a DECLARED name must carry casa's
# reserved `CASA_PLUGIN_` prefix — declaring binds the name session-wide, so
# that namespace is fenced (`plugin_store._DECLARABLE_ENV_NAME_RE`). Nothing
# else in the env block renames: the CP token and the mode variable are
# referenced as `${VAR:-}` instead, which needs no declaration and no prefix.
#
# Naming them here, once, is the whole point: the readiness gate reports the
# DECLARED name unprovisioned, while a setup run that printed the process key
# would send the configurator to write a line nothing resolves. The two would
# agree in every test that spells them itself and disagree only on the live
# install. `test_component` pins each against `.mcp.json` and against the
# manifest declaration, and greps this file so no wiring sentence can name a
# process key again.
# --------------------------------------------------------------------------
WIRE_KEY_VAR = "CASA_PLUGIN_BANKFEED_EB_PRIVATE_KEY"
WIRE_APP_ID_VAR = "CASA_PLUGIN_BANKFEED_EB_APP_ID"

PENDING_TTL_S = 1800          # 30 minutes from mint
RENEWAL_LEAD_DAYS = 21        # the single reminder, once per consent
CONSENT_DAYS = 179            # the provider's ceiling, strict

# Rate control: our own limits, not the provider's quota.
MIN_REFRESH_INTERVAL_S = 900   # our own per-account cooldown on AUTOMATIC reads
RATE_LIMIT_BACKOFF_S = 900     # used when a 429 carries no Retry-After
INFLIGHT_TTL_S = 300           # a single-flight claim older than this is stale

#: The two states of a consent that is STILL LIVE AT THE BANK because a
#: revocation did not complete. Both are ALIASES of `apply`'s constants, never
#: re-declared literals: `apply.record_revocation` is the only writer of
#: `closed_at`, so it is also the authority on what it writes instead. Two
#: modules spelling "REVOKE_FAILED" independently is the drift this aliasing
#: exists to prevent.
#:
#: * `REVOKE_PENDING` — `apply.switch_bindings` has retired the old session
#:   locally and deliberately stopped short of `closed_at`, because at that
#:   commit the grant still exists at the bank. A lost lease or a killed
#:   process between the switch and the DELETE leaves the row here.
#: * `REVOKE_FAILED` — the provider was asked and refused, rate-limited, or
#:   could not be reached.
#:
#: Both keep `closed_at` NULL, which is what keeps them listed by
#: `consent_status` and reachable by `unlink_bank` under the same
#: `consent_ref`. Neither is `AUTHORIZED`, so `_renewable_session` excludes them
#: from renewal.
REVOKE_FAILED_STATUS = apply.REVOKE_FAILED_STATUS
REVOKE_PENDING_STATUS = apply.RETIRED_STATUS
REVOCATION_INCOMPLETE_STATUSES = frozenset({REVOKE_FAILED_STATUS,
                                            REVOKE_PENDING_STATUS})

#: Every session status that means "the operator has something to do about
#: this consent". Read by `consent_status`'s per-session branches AND by its
#: handoff-caveat guard, so a further stopped state cannot be added to one and
#: forgotten in the others. None of them carry renewal wording: a consent that
#: is quarantined, or that is being revoked, is not one to be reminded to
#: extend — and a consent that was renewed AWAY must never be offered for
#: renewal again.
NEEDS_ATTENTION_STATUSES = (frozenset({callbacks.REVIEW_REQUIRED_STATUS})
                            | REVOCATION_INCOMPLETE_STATUSES)

HANDOFF_CAVEAT = (
    "A renewal handoff records that this plugin asked for a reminder on that "
    "date. It is not confirmation that a reminder exists: specialists cannot "
    "see or set reminders, so this is the strongest honest claim "
    "available.")

# Seams, so the whole surface is testable without a provider or a spool.
CB = callbacks
AIS_FACTORY = None
ADMIN_FACTORY = None
OPVAULT = opvault     # test seam: setup's vault access goes through this name
FB = fbauth           # test seam: setup's Firebase access goes through this name

#: App ids this process has proven to live in THIS mode's world. A plain set:
#: within one process the mode is a constant (ebmode's memo), so the id alone
#: keys it exactly. Tests reset it like eb_admin's _MINTER.
_WORLD_OK: set = set()


class WorldMismatch(RuntimeError):
    """This mode was asked to operate on an application that is not its
    own. Raised BEFORE the operation — nothing was sent."""


class WorldUnverified(RuntimeError):
    """The world check itself could not run (a transient provider
    failure on the verification GET) — NOT a mismatch and NOT a failure
    of any account-data endpoint, which were never tried. Distinct from
    WorldMismatch and from eb_ais.ApiError so that sync's per-resource
    "FAILED (<type>)" line and the dispatcher's error rendering name the
    check, not the bank: a 503 on GET /application must not read as two dead
    account endpoints."""


def _assert_world(app_id, record=None, admin=None) -> None:
    """The world guard: no operation that addresses an app id — admin or AIS,
    read-modify-write or data pull — before the world that id lives in is
    verified, once per process per id. A guard on the AIS client alone fires
    too late, after setup's PATCH and link_bank's whitelist writes, which is
    why this is a helper every resolution site calls rather than a property of
    one client factory.

    Active in BOTH modes: a production process wired with sandbox values must
    refuse exactly as the mirror image does.

    Evidence rules: the record must claim the mode's
    environment AND the mode's application name AND describe the id being
    trusted. `record` given: a listing entry or verification read already
    in hand — its own `app_id`/`kid` claim must equal `app_id` (a record
    with no id claim fails; it is evidence about nothing in particular).
    `admin` given: fetched via GET /api/application/{app_id}, which is
    path-bound — the provider answers for that id or 404s — so a body
    with no id echo still binds. The AIS-view case (GET /application,
    whose JWT is signed with kid=app_id and whose live response carries
    `kid` — read on record, this file's setup docstring) is served at
    the `_ais()` call site, which passes that response as `record`;
    this helper itself demands evidence and never constructs a client
    to go find some.
    """
    app_id = str(app_id or "")
    if app_id in _WORLD_OK:
        return
    path_bound = False
    if record is None:
        if admin is None:
            raise ValueError("_assert_world needs record= or admin= — "
                             "evidence, never a guess")
        record = admin.application(app_id)
        path_bound = True
    record = record or {}
    claimed = str(record.get("app_id") or record.get("kid") or "")
    ok = (str(record.get("environment") or "").upper() == ebmode.mode()
          and record.get("name") == _app_name()
          and (claimed == app_id or (path_bound and not claimed)))
    if not ok:
        raise WorldMismatch(
            "refusing to touch application %s: %s mode requires the "
            "application named '%s' in the %s environment, but the "
            "provider describes name %s, environment %s, id %s. This "
            "wiring points at another world's application (a "
            "plugin-env.conf copied from the other world's install does "
            "exactly this) — fix %s / %s and re-run. Nothing was sent "
            "to it."
            % (_safe(app_id), ebmode.mode(), _app_name(), ebmode.mode(),
               _safe(record.get("name") or "unset"),
               _safe(record.get("environment") or "unset"),
               _safe(claimed or "unset"), WIRE_APP_ID_VAR, WIRE_KEY_VAR))
    _WORLD_OK.add(app_id)

_PROTECTED_CACHE = None

# Renewal handoffs the exchange QUEUED for the current collect_authorization
# call. They are not durable records yet: `collect_authorization` writes each
# one only as it emits the corresponding instruction. A queued handoff
# that never reaches the operator therefore leaves no record, and
# `consent_status` goes on asking — which is the safe direction.
_HANDOFFS: list = []

# Accounts whose authorization-time backfill did NOT complete. The ledger
# is safe, but the fresh-SCA window has been spent without the deep history it
# existed for, so the initiating call must say so instead of reporting a link.
_INCOMPLETE: list = []

# Renewals refused this turn because the returned account set was not the bound
# set. Refusing is right and stays; what this carries is the half that
# was missing — WHICH accounts differed, so the turn the operator is reading can
# say it. The durable copy lives in `meta` and is what `consent_status` and the
# next `link_bank` read; this list only tells `collect_authorization` which of
# its own outcomes to describe.
_MISMATCHES: list = []


class RateControlDeferred(Exception):
    """A refresh was deliberately NOT performed, to protect the rate budget.

    Distinct from a failure: nothing broke and nothing was called. The class
    name is what reaches the operator through `tools_read`'s freshness note, so
    it is named for the reason rather than for the mechanism.
    """


def _safe(text) -> str:
    """Render a name we did not write ourselves.

    Every value that reaches a formatted line goes through the neutralising
    path, because this
    output is LINE-ORIENTED and an embedded newline forges a whole line the
    operator reads as ours. A bank name is the obvious carrier — `list_banks`
    prints the provider's catalogue verbatim, and `consent_status` prints the
    `aspsp_name` a session was recorded under into four different instructions
    — but the argument applies equally to a `valid_until` the provider chose
    and to a `psu_type` the model supplied. `_neutralized` rather than
    `_untrusted`: these are short, structured values printed inside sentences,
    and the visible fence would clutter output that is normally clean without
    closing anything `_neutralize` does not already close.
    """
    return tools_read._neutralized(text)


def _safe_url(url) -> str:
    """A provider- or casa-written URL, neutralised but NEVER clipped.

    `_safe` is right for a name, a status or a date; it is wrong for a URL,
    and the difference is not stylistic. `tools_read._clip` truncates at 256
    characters and appends a marker — but an Enable Banking authorization URL
    is a ONE-TIME CREDENTIAL the operator has to tap, and its query string
    routinely runs past that. A clipped one is a dead link whose only remedy
    is another full authorization with another set of SCA taps, which is the
    exact cost this module spends the rest of its output trying to avoid.

    So only the half that matters here is applied: neither untrusted-fence
    delimiter and no newline survives, which is what stops a URL from forging
    a line in this line-oriented output. No legitimate URL contains either —
    a newline is not a valid URL character at all — so nothing real is
    altered, and unlike the clip this cannot damage a working link.
    """
    return tools_read._neutralize(str(url or ""))


# --------------------------------------------------------------------------
# gate: defence in depth only
# --------------------------------------------------------------------------

def protected_tools() -> set:
    """Read `casa.protectedTools` from the SHIPPED manifest.

    Resolved relative to this file, never from an environment variable: the
    manifest travels with the code, and an env-derived path would be one more
    thing an attacker could point elsewhere.
    """
    global _PROTECTED_CACHE
    if _PROTECTED_CACHE is None:
        path = Path(__file__).resolve().parent.parent / ".claude-plugin/plugin.json"
        try:
            data = json.loads(path.read_text("utf-8"))
        except Exception:                        # noqa: BLE001
            data = {}
        entries = (data.get("casa") or {}).get("protectedTools") or []
        # casa's `manifest_protected_tools` accepts BOTH the bare-string form
        # and the {"name", "summary"} object form. This manifest ships the
        # object form deliberately: casa interpolates `summary` with the call's
        # canonical arguments (authz_grants._interpolate_summary) into the
        # operator's approval challenge, so they see a specific sentence naming
        # what is about to happen instead of a generic "approve this tool
        # call?". Normalise to names here — a bare set() over dicts is a
        # TypeError.
        _PROTECTED_CACHE = {e["name"] if isinstance(e, dict) else e
                            for e in entries}
    return _PROTECTED_CACHE


def _require_declared(name: str):
    """Defence in depth. Casa's hook is the boundary; this is a tripwire."""
    if name not in protected_tools():
        return ("Refusing: %s changes or destroys data and is NOT declared in "
                "casa.protectedTools, so casa's authorization hook is not "
                "gating it and no operator grant was demanded. Nothing has been "
                "changed. Fix the plugin manifest." % name)
    return None


GATE_NOTE = ("This ran because casa's authorization hook granted an operator "
             "confirmation bound to these exact arguments; the plugin does not "
             "and cannot gate it itself.")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def _conn():
    # The capability seed lives in `store.open_db`, not here: seeding from a
    # tool module covers every ingest path but not a purely read-only turn,
    # and two call sites are two places to forget.
    return tools_read.conn()


def _now_s() -> float:
    """The ONE clock seam, so deadline and cooldown arithmetic is assertable
    exactly. Without it a test can only assert a range, and then it passes or
    fails depending on how fast the machine is."""
    return time.time()


def _utcnow_iso() -> str:
    """Derived from `_now_s`, deliberately.

    Timestamps written into `sync_state` are compared against `_now_s()` by
    the cooldown, so a second clock here would make the comparison meaningless
    the moment a test froze one of them.
    """
    return _dt.datetime.fromtimestamp(
        _now_s(), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_id() -> str:
    return os.environ.get("CASA_HOST_ID") or platform.node() or "unknown-host"


def _consent_ref(session_id: str) -> str:
    """A local, non-reversible alias for a session.

    Session identifiers are bearer-equivalent and never appear in tool output,
    but the operator still needs a handle to name one consent.
    """
    digest = hashlib.sha256(("consent-ref|" + str(session_id)).encode("utf-8"))
    return "c" + digest.hexdigest()[:8]


def _resolve_consent_ref(c, ref):
    if not ref:
        return None
    for row in c.execute("SELECT session_id FROM sessions"):
        if _consent_ref(row[0]) == str(ref):
            return row[0]
    return None


#: Does a failed `delete_session` still prove the consent is gone?
#:
#: Exactly one failure does: a 404. The provider is stating authoritatively
#: that the session it was asked to delete does not exist, which is the state a
#: successful DELETE produces — refusing to close on it would leave a row that
#: can never be cleared, asking for ever for a retry that will 404 again.
#:
#: Nothing else qualifies, and the distinction is the whole finding. A 429, a
#: timeout, a dropped socket, a 5xx: the consent is very probably STILL LIVE at
#: the bank, and treating "we could not tell" as "it is revoked" is what closed
#: the local row and erased the operator's only retry handle. A 401 or a 403
#: does not qualify either — those say our credential is wrong, not that the
#: consent is gone.
#:
#: **It is an ALIAS, and the definition is `eb_ais`'s.** There are
#: two paths that end a consent at the bank — `unlink_bank` here and
#: `flows._revoke` on the renewal path — and they were deciding this
#: differently: `unlink_bank` called this predicate, `flows._revoke` treated
#: every exception including a 404 as a failure, so a renewal against a consent
#: the bank had already dropped left the row `REVOKE_FAILED` for ever. One
#: decision needs one implementation, and it cannot live in this module:
#: `tools_auth` imports `flows`, so `flows` importing `tools_auth` would be a
#: cycle. `eb_ais` owns `ApiError` and `error_kind` — which is what the decision
#: is actually about — and both modules already depend on it. Aliasing rather
#: than re-implementing is the same rule this file already applies to
#: `REVOKE_FAILED_STATUS`: two modules spelling one decision independently is
#: the drift aliasing exists to prevent.
revocation_is_final = eb_ais.revocation_is_final


def _days_until(iso_date):
    if not iso_date:
        return None
    try:
        target = _dt.date.fromisoformat(str(iso_date)[:10])
    except ValueError:
        return None
    return (target - _dt.date.today()).days


#: The three states a consent's validity can be in, and the reason there are
#: three (issue #6). Two is the shape that keeps failing: every branch written
#: `expired or not` swept "we have no usable date" into the liveness leg, so a
#: NULL or malformed `valid_until` printed "you already have a live consent",
#: "stays bound and live", "the bank still serves this account" — the strongest
#: claims in the plugin, resting on nothing. `unknown` is a state the provider
#: really produces: `callbacks` records a session whose existence we witnessed
#: and whose term we were never told.
EXPIRED, LIVE, UNKNOWN = "expired", "live", "unknown"


def _expiry_instant(iso_date):
    """The moment this validity ends, as an aware UTC datetime, or None.

    TIMESTAMPS, NOT DATES. `_days_until` truncates to `[:10]`, and a
    shared truncation does not make the branches agree — it makes all of them
    wrong together for the rest of expiry day: a consent that lapsed at 09:00
    was still "live, with 0 days left on it" at 21:00, beside a line saying it
    was no longer refreshing. `eb_ais.start_auth` sends an exact instant and
    the provider echoes one back, so the exact instant is what we have.

    A DATE-ONLY value expires at the END of its day, not at midnight. That is
    the cautious direction for the one claim that cannot be taken back: every
    expired branch tells the operator the bank most likely holds nothing, and
    it must not start saying so a day early because a provider sent `2026-11-10`
    instead of a timestamp.
    """
    text = str(iso_date or "").strip()
    if not text:
        return None
    try:
        if len(text) <= 10:
            day = _dt.date.fromisoformat(text)
            # End of that day in the HOST's zone, which is the same frame
            # `_expiry_state` counts in and `_minus_days` writes the reminder
            # date in. Anchoring a bare date to UTC instead put the instant in
            # one frame and the day count in another, and the two disagreed for
            # the hours between them.
            return _dt.datetime.combine(day, _dt.time.max).astimezone()
        moment = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    # A provider that omits the offset is describing UTC; assuming so is what
    # keeps this comparable, and the alternative — treating it as unknown —
    # would silence the expiry warning on the shape most likely to carry it.
    return (moment if moment.tzinfo is not None
            else moment.replace(tzinfo=_dt.timezone.utc))


def _expiry_state(iso_date):
    """`(EXPIRED, days_ago)`, `(LIVE, days_left)` or `(UNKNOWN, None)`.

    ONE dispatch, three states, every caller — because every defect of this
    shape was a caller that had only two. `days_ago` is 0
    for a consent that lapsed earlier today, which is why callers must never
    branch on truthiness of the number (see `_ago`).

    **The STATE comes from the instant; both COUNTS are calendar differences —
    and all three are derived from that ONE instant, in ONE timezone.** The
    questions differ: "has it lapsed?" is a moment (the whole finding), while
    "how many days" is what the operator plans around, what `RENEWAL_LEAD_DAYS`
    measures, and what `_minus_days` builds the reminder date from.

    The timezone is the HOST's local one, because that is the frame the
    operator's "today" is in and the frame `_minus_days` already writes the
    reminder date in; a count in one frame beside a date in another is a
    disagreement waiting on the hours between them. Two concrete forms of it:

    * elapsed 24-hour flooring made `(now - end).days == 0` for a consent that
      lapsed at 22:24 *yesterday*, so `_ago` called it "earlier today";
    * `_days_until` compares the WRITTEN date against the local date and
      reconciles no offset, so `2026-08-06T10:22:45-12:00` — an hour in the
      future — printed "live, with -1 days left on it" once the local date had
      rolled over. A negative remainder on a live consent is the shape issue #6
      started from.

    `astimezone()` with no argument converts to the host's zone, so the
    provider's offset is reconciled rather than ignored.
    """
    end = _expiry_instant(iso_date)
    if end is None:
        return UNKNOWN, None
    days = (end.astimezone().date() - _dt.date.today()).days
    if _dt.datetime.now(_dt.timezone.utc) > end:
        # `max` because the last hours of expiry day floor to 0, and "expired 0
        # days ago" is `_ago`'s "earlier today" — never a negative lapse.
        return EXPIRED, max(0, -days)
    return LIVE, max(0, days)


def _ago(days: int) -> str:
    """"earlier today" / "yesterday" / "N days ago" — the lapse, in words.

    `days == 0` is a real and common answer once expiry is an instant rather
    than a date, and "0 days ago" is not something to print at an operator.
    `days == 1` is "yesterday" for the same reason: the count is a CALENDAR
    difference, so a consent that lapsed at 23:50 reads as yesterday an hour
    later, which is what it was. Spelling both once also removes the
    `"" if n == 1 else "s"` each of these branches would otherwise carry.

    **`None` is accepted, and that is a fail-safe, not sloppiness.** Every
    caller picks its sentence from a `{LIVE: …, EXPIRED: …, UNKNOWN: …}` table,
    and a dict literal BUILDS EVERY ARM before one is chosen — so the EXPIRED
    arm is formatted with `value=None` on exactly the rows the UNKNOWN arm
    exists for. That raised `TypeError` out of `consent_status` and
    `unlink_bank` for a whole class of real rows (a quarantine recorded with no
    term), turning a wording bug into a dead tool. Sites still hoist the lapse
    out of the table where they can; this is the backstop for the ones that do
    not, and it says something TRUE if it is ever printed rather than a
    duration nobody measured.
    """
    if days is None:
        return "at a time not recorded here"
    return ("earlier today" if days == 0
            else "yesterday" if days == 1 else "%d days ago" % days)


def _minus_days(iso_date, days):
    """The date `days` before this validity ends, in the HOST's calendar.

    The last frame mismatch of issue #6. An earlier version truncated the
    provider's string to `[:10]` and did date arithmetic on whatever was
    written, while `_expiry_state` converts the instant to the host's zone —
    two frames, one row, and they disagree by a day whenever the offset crosses
    local midnight. With the host in America/Los_Angeles and
    `valid_until=2026-08-10T00:30:00+14:00` (which is 9 August, 03:30 local),
    `consent_status` printed "3 days remaining" beside a reminder date computed
    from 10 August. The operator is asked to set a durable reminder on that
    date; a day of drift in it is the difference between a renewal prompt
    arriving inside the window and outside it.

    `_expiry_instant` is therefore the single parse — which also means this
    accepts every shape it does, instead of only those whose first ten
    characters happen to be a date.
    """
    end = _expiry_instant(iso_date)
    if end is None:
        return None
    return (end.astimezone().date() - _dt.timedelta(days=days)).isoformat()


def _resolve_key():
    """Rung 2's ladder: env → vault → forge. Returns (source, key, pem)
    or, on any stop condition, the finished report line for rung 2.

    Present-but-unparseable NEVER falls through to the next rung: a
    configured key that no longer loads is drift in the op:// wiring, and
    silently substituting a fresh key would strand the application on key
    material nothing can read (guards branch on the truth — the parse —
    not on the presence proxy)."""
    pem = os.environ.get("CASA_BANKFEED_EB_PRIVATE_KEY")
    if pem:
        try:
            return "env", jwtsign.load_pkcs8(pem), pem
        except Exception as exc:                     # noqa: BLE001
            return ("2. Key: present but UNREADABLE (%s). Fix the %s "
                    "op:// wiring — refusing to forge a replacement while "
                    "one is configured. Stopping."
                    % (_safe(str(exc)), WIRE_KEY_VAR))
    reason = OPVAULT.status()
    if reason is not None:
        return ("2. Key: %s did not resolve to a usable value (it may be "
                "unwired, or its op:// reference may have failed to resolve) "
                "and 1Password is unreachable (%s). Stopping."
                % (WIRE_KEY_VAR, _safe(reason)))
    try:
        pem = OPVAULT.read(OPVAULT.REF_PRIVATE_KEY)
    except OPVAULT.OpError as exc:
        if not exc.not_found:
            # A timeout or auth failure is NOT absence. Forging here would
            # create a second, identically-named key item over the real
            # one and make every later key selection ambiguous. Absence must
            # be op's explicit answer, never an inference from a failure.
            return ("2. Key: %s did not resolve to a usable value and the "
                    "1Password read FAILED (%s) — this is a fault, not an "
                    "absent key, so nothing was forged. Retry when the vault "
                    "answers. Stopping." % (WIRE_KEY_VAR, _safe(str(exc))))
        pem = None
    if pem is not None:
        try:
            return "vault", jwtsign.load_pkcs8(pem), pem
        except Exception as exc:                     # noqa: BLE001
            return ("2. Key: the vault item '%s' is present but UNREADABLE "
                    "(%s) — refusing to forge a replacement over it. "
                    "Stopping." % (OPVAULT.KEY_ITEM, _safe(str(exc))))
    # The second, independent negative before the one create this rung can
    # perform: read() said not_found; item_exists must agree. A transient
    # failure inside item_exists RAISES and is reported — never treated as
    # absence.
    try:
        if OPVAULT.item_exists(OPVAULT.KEY_ITEM, OPVAULT.VAULT):
            return ("2. Key: the vault item '%s' EXISTS but its private-key "
                    "field could not be read — refusing to forge a sibling "
                    "item. Inspect it in 1Password. Stopping."
                    % OPVAULT.KEY_ITEM)
    except OPVAULT.OpError as exc:
        return ("2. Key: could not confirm the key item's absence (%s) — "
                "nothing was forged. Retry when the vault answers. "
                "Stopping." % _safe(str(exc)))
    # Confirmed absent twice → forge, then verify the READ-BACK, not the
    # create.
    try:
        OPVAULT.create_ssh_key(OPVAULT.KEY_ITEM, OPVAULT.VAULT)
        pem = OPVAULT.read(OPVAULT.REF_PRIVATE_KEY)
        key = jwtsign.load_pkcs8(pem)
        jwtsign.sign(b"setup-probe", key)            # it SIGNS, not just parses
    except Exception as exc:                         # noqa: BLE001
        return ("2. Key: forging in 1Password FAILED (%s: %s). If the item "
                "was created, the NEXT run will find and use it — nothing "
                "is forged twice. Stopping."
                % (type(exc).__name__, _safe(str(exc))))
    return "forged", key, pem


def _resolved_app_id(c):
    """Env first (the declared steady state), then the id setup itself
    discovered or created (meta)."""
    return (os.environ.get("CASA_BANKFEED_EB_APP_ID")
            or _meta_get(c, "setup.app_id"))


def _bare_ais():
    if AIS_FACTORY is not None:
        return AIS_FACTORY()
    # `_resolved_app_id` already states this exact env->meta contract;
    # inlining it here separately is a drift risk, not a stylistic choice.
    app_id = _resolved_app_id(_conn())
    pem = os.environ.get("CASA_BANKFEED_EB_PRIVATE_KEY")
    if not pem and OPVAULT.status() is None:
        try:
            pem = OPVAULT.read(OPVAULT.REF_PRIVATE_KEY)
        except OPVAULT.OpError:
            pem = None
    if not app_id or not pem:
        raise RuntimeError("at least one of %s / %s did not resolve to a "
                           "usable value, and no substitute was available to "
                           "this attempt (the vault read may also have "
                           "failed)" % (WIRE_APP_ID_VAR, WIRE_KEY_VAR))
    return eb_ais.AIS(app_id, jwtsign.load_pkcs8(pem))


def _ais():
    """The world-guarded AIS client: the first client this
    process hands out proves the application it would pull data from IS
    this mode's own — one GET /application, whose response is
    self-describing for the JWT's kid — so a mis-wired install refuses
    instead of syncing another world's money into this mode's ledger.
    Both modes: one extra AIS GET per
    process is the whole production cost, on the app's own JWT — the
    steady-state path still never holds the admin credential."""
    client = _bare_ais()
    app_id = str(getattr(client, "app_id", "")
                 or _resolved_app_id(_conn()) or "")
    if app_id not in _WORLD_OK:
        try:
            record = client.application()
        except Exception as exc:                 # noqa: BLE001
            raise WorldUnverified(
                "the application world check could not run (%s) — the "
                "account data endpoints were NOT tried and cached data "
                "is unchanged. This is a transient verification "
                "failure, not a bank failure: retry when "
                "GET /application answers." % type(exc).__name__
            ) from None
        _assert_world(app_id, record=record)
    return client


def _admin():
    """The control-panel client. ONE name, and it is the declared one.

    Delegated to `eb_admin.from_env()` rather than reading the variable here:
    that function documents itself as "the one place production constructs an
    Admin client", and a second reader in this module is exactly how the two
    names drifted apart the first time. It raises `AdminTokenMissing` (a
    `RuntimeError`) naming the declared variable.
    """
    if ADMIN_FACTORY is not None:
        return ADMIN_FACTORY()
    return eb_admin.from_env()


def _entry():
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if not root:
        return None
    try:
        return CB.discover(root)
    except Exception:                            # noqa: BLE001
        return None


def _vacuum(c) -> None:
    """Real deletes plus VACUUM, not tombstones."""
    c.execute("VACUUM")


# --------------------------------------------------------------------------
# meta: small durable records that have no table of their own
# --------------------------------------------------------------------------

def _meta_get(c, key):
    row = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def _meta_set(c, key: str, value: str) -> None:
    c.execute("INSERT INTO meta(key, value) VALUES (?,?)"
              " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
              (key, value))


def _meta_del(c, key: str) -> None:
    c.execute("DELETE FROM meta WHERE key=?", (key,))


def _handoff_key(session_id: str) -> str:
    return "renewal_handoff|" + str(session_id)


#: The ONLY handoff state that silences `consent_status`. The previous design
#: wrote the record inside `_exchange`, before `collect_authorization` had
#: emitted anything, so a crash between the two left "handoff made" recorded
#: for a request nobody ever received — and the warning was then suppressed for
#: ever. Suppression is now keyed on this value, so any other state, and any
#: record from an older build that carries none, reads as "not made" and keeps
#: asking.
HANDOFF_EMITTED = "emitted"


def record_renewal_handoff(c, session_id: str, valid_until,
                           state: str = HANDOFF_EMITTED):
    """Record that we asked for a renewal reminder, and for which date.

    Call this at the point the instruction is ACTUALLY EMITTED, never before.

    Returns the date asked for, or None when the consent has no usable expiry
    (in which case no handoff is recorded — reporting one we could not actually
    make would be the same dishonesty the permanent warning was).
    """
    asked_for = _minus_days(valid_until, RENEWAL_LEAD_DAYS)
    if not asked_for:
        return None
    _meta_set(c, _handoff_key(session_id),
              json.dumps({"asked_for": asked_for,
                          "recorded_at": _utcnow_iso(),
                          "state": str(state)}))
    return asked_for


def handoff_emitted(record) -> bool:
    """True only for a handoff whose instruction really went out."""
    return bool(record) and record.get("state") == HANDOFF_EMITTED


def backfill_complete(c, account_id: str, result, *, session_id: str) -> bool:
    """Did the authorization-time backfill actually finish?

    Two independent signals, because one of them can be forgotten and the
    consequence of a false "yes" is a silently lost deep-history window:

    * the value `flows.backfill` returned — `capped`/`completeness`;
    * the durable `sync_state` row a capped or failed run is obliged to write,
      which is the claim every read tool already labels answers from.

    BOTH MUST BE AFFIRMATIVE. This function's previous version said exactly
    that and then did the opposite: an absent `completeness` defaulted to
    "complete" and a missing row returned True, so a producer that reported
    nothing at all — which `flows.backfill`'s own success path did, until this
    round — was read as a finished deep fetch. Nothing may be assumed here.
    Absence of a claim is not a claim.

    `session_id` is KEYWORD-ONLY WITH NO DEFAULT for the same reason
    `flows.verify_accounts`'s bank is: the durable evidence belongs to a
    specific session, and a renewal whose new fetch never ran leaves the OLD
    session's `complete` row sitting on the account. A caller that has not been
    updated must raise, not quietly credit that row to the new consent.

    The durable half is `apply.deep_fetch_complete` rather than a query of our
    own — the same predicate `apply.switch_bindings` refuses on and
    `flows.complete_renewal` reports `retired: False` from. One predicate,
    three uses, so they cannot drift apart.
    """
    if not isinstance(result, dict):
        return False
    if result.get("capped"):
        return False
    if result.get("completeness") != "complete":
        return False
    return bool(apply.deep_fetch_complete(c, account_id, session_id))


def renewal_handoff(c, session_id: str):
    raw = _meta_get(c, _handoff_key(session_id))
    if not raw:
        return None
    try:
        record = json.loads(raw)
    except ValueError:
        return None
    return record if isinstance(record, dict) else None


# --------------------------------------------------------------------------
# the refused renewal — what differed, and the call that unblocks it
# --------------------------------------------------------------------------

def _mismatch_key(session_id: str) -> str:
    return "renewal_mismatch|" + str(session_id)


def renewal_mismatch(c, session_id: str):
    """What a refused renewal found, or None. Durable, so the answer survives
    the turn that produced it — the operator normally asks afterwards."""
    raw = _meta_get(c, _mismatch_key(session_id))
    if not raw:
        return None
    try:
        record = json.loads(raw)
    except ValueError:
        return None
    return record if isinstance(record, dict) else None


def _account_labels(c, account_ids, offered: dict) -> str:
    """Name accounts an operator can recognise, from whichever side has them.

    A bound account has a row, so it is named the way `list_accounts` names it
    — label or name, plus the masked IBAN — and the two outputs agree. An
    account the bank returned that is NOT bound here has no row at all, so the
    only name available is the provider's own, which is why `_exchange` hands
    it down. An `account_id` is an HMAC; printing one at an operator is not
    naming anything, so it is the last resort rather than the first.
    """
    named = []
    for account_id in account_ids:
        row = c.execute(
            "SELECT label, name, iban_masked FROM accounts WHERE account_id=?",
            (account_id,)).fetchone()
        if row is not None:
            label = _safe(row["label"] or row["name"]) or account_id[:8]
            masked = _safe(row["iban_masked"])
            named.append("%s (%s)" % (label, masked) if masked else label)
            continue
        named.append(_safe(offered.get(account_id)) or account_id[:8])
    return ", ".join(named) or "none"


def record_renewal_mismatch(c, session_id: str, *, prior, attempt, bound,
                            returned, offered: dict) -> dict:
    """Durably record WHICH accounts differed, at the moment of the refusal.

    Written from inside the exchange, while the canonical ledger is still shut.
    That is allowed and is the point: `meta` is not one of
    `callbacks._GUARDED_TABLES`, so the diagnostic survives even though — and
    precisely because — nothing was bound. The connection is in autocommit, so
    it is durable the instant it is written; a later raise cannot take it back.

    The refusal itself is unchanged. This is only the answer to "what
    differed?", which `link_bank`'s own renewal message promises the operator
    will be able to get and which nothing previously recorded.
    """
    record = {
        "old_consent_ref": _consent_ref(prior["session_id"]),
        # Issue #6. The DATE is recorded, never the verdict: this record is
        # written once at the refusal and read in every later turn, so a
        # consent that was live when it was written can be lapsed when it is
        # printed. `_mismatch_lines` asks `_expiry_state` at print time. A
        # record written before this key existed reads as None — unknown, not
        # expired — which is the wording those records already carried.
        "old_valid_until": prior.get("valid_until"),
        "aspsp": attempt.get("aspsp_name") or "",
        "country": attempt.get("country") or "",
        "psu_type": attempt.get("psu_type") or "",
        # Named, not counted: "1 account differed" is not something an operator
        # can act on, and these are the two halves of the difference.
        "unlinked": _account_labels(c, sorted(returned - bound), offered),
        "absent": _account_labels(c, sorted(bound - returned), offered),
        "n_unlinked": len(returned - bound),
        "n_absent": len(bound - returned),
        "recorded_at": _utcnow_iso(),
    }
    _meta_set(c, _mismatch_key(session_id), json.dumps(record))
    return record


def _mismatch_lines(record: dict, quarantined_ref: str) -> list:
    """The one place this is worded, read by all three call sites.

    Refusing a renewal whose account set changed is correct. What is easy to
    get wrong is everything said afterwards: the generic quarantine line makes
    three claims and all three fail this operator.

    * it never said WHAT differed, though `link_bank`'s renewal message
      promises "consent_status tells you what differed";
    * it said "fix the whitelist", which is actively misleading —
      `verify_accounts` PASSED, so the whitelist is the one thing that is not
      broken;
    * it said "link again", which is a closed loop: the old consent is still
      live, so `renewal_target` finds it, `link_bank` mints another
      `purpose=renew`, the bank returns the same set, and it quarantines again
      — one more live consent at the bank per attempt, which is the exact
      accumulation `outstanding_consents` exists to stop. The consent then
      expires and the bank stops refreshing altogether.

    This is not an exotic shape: a joint savings account, a business
    sub-account, or a bank moving a product to a new IBAN all produce it.

    The working sequence is revoke-then-link, and it is spelled out because it
    is not guessable: the OLD consent has to go first, since while it is live
    every `link_bank` is a renewal of it and repeats the refusal. Once it is
    gone the next `link_bank` is a FIRST link, which binds every account the
    bank now returns and reopens the deep-history window.

    The history sentence is not reassurance padding. An operator who believes
    `unlink_bank` erases their transactions will not run it, and this whole
    message is worthless if its one instruction is the one they are afraid of.
    """
    state, value = _expiry_state(record.get("old_valid_until"))
    return [
        "  WHAT DIFFERED: the bank returned %d account(s) that are not linked "
        "here (%s), and %d account(s) linked here did not come back (%s). "
        "Nothing was switched, and that is deliberate: remapping a "
        "changed set would silently reattribute history to the wrong account."
        % (record.get("n_unlinked", 0), record.get("unlinked") or "none",
           record.get("n_absent", 0), record.get("absent") or "none"),
        "  THE WHITELIST IS NOT THE PROBLEM — every account the bank returned "
        "was approved, which is how the authorization got this far. Do not "
        "change it.",
        # Issue #6. The reassurance half is a claim about the OLD consent, and
        # for a lapsed one it is false in both clauses — it is not serving
        # answers and refreshing has already stopped. The BLOCKED half is
        # unchanged and is why the sequence below still reads the same: an
        # expired consent is renewable (`_renewable_session`), so `link_bank`
        # is still a renewal and still repeats this refusal.
        # The BLOCKED half is the same in all three states, and that is why the
        # sequence below never changes: an expired consent is still renewable
        # (`_renewable_session`), so link_bank is still a renewal and still
        # repeats this refusal. Only the reassurance moves.
        {LIVE: "  Your OLD consent is still live and still serving every "
               "answer, so nothing has stopped working.",
         EXPIRED: "  Your OLD consent's validity passed %s, so it cannot be "
                  "relied on to keep serving answers — the stored history "
                  "stays queryable either way." % _ago(value),
         UNKNOWN: "  How long your OLD consent is valid for was not recorded, "
                  "so whether it is still serving answers cannot be said from "
                  "here — the stored history stays queryable either way.",
         }[state] + (
            " It cannot be RENEWED past this, though: while that consent is the "
            "one recorded here, link_bank renews it, the bank returns the same "
            "set, and each attempt leaves one more consent at the bank. Do this "
            "instead:"),
        "    1. unlink_bank consent_ref=%s — withdraw the half-finished "
        "candidate this attempt left at the bank." % quarantined_ref,
        "    2. unlink_bank consent_ref=%s — withdraw the OLD consent. This is "
        "the step that unblocks you. Refreshing stops until step 3, and your "
        "labels, categories, include flags, coverage and every stored "
        "transaction are UNTOUCHED: unlink_bank withdraws the bank's "
        "permission, it does not erase local history."
        % (record.get("old_consent_ref") or "the old consent"),
        "    3. link_bank aspsp=%s, country=%s, psu_type=%s — now a FIRST "
        "link, not a renewal, so it binds every account the bank currently "
        "returns (the new one included) and reopens the deep-history window."
        % (_safe(record.get("aspsp")) or "that bank",
           _safe(record.get("country")), _safe(record.get("psu_type"))),
    ]


# --------------------------------------------------------------------------
# rate control — the primitives; the collection tools enforce them
# --------------------------------------------------------------------------

def _parse_ts(text):
    return tools_read._parse_ts(text)


def _inflight_key(account_id: str) -> str:
    return "refresh_inflight|" + str(account_id)


def admit_refresh(c, account_id: str, resource: str, *, automatic: bool):
    """None when the refresh may proceed, else the reason it may not.

    Two rules, and they are not the same rule:

    * A provider `Retry-After` binds EVERYTHING except an authorization-time
      backfill. Hammering after a 429 is what earns a longer one.
    * Our own minimum interval binds only AUTOMATIC (read-triggered) refreshes.
      An operator who ran `sync` asked for it. The case this exists for is a
      refresh that keeps failing: `last_success_at` stays old, so every
      subsequent read retries it, and three banks fanned out on every question
      is exactly the traffic that gets an application throttled.

    Both are read across the WHOLE ACCOUNT, not one resource: a 429 is aimed at
    the application, and answering it by asking for the other resource instead
    is the abuse the header exists to stop.

    **BOTH RULES FAIL CLOSED, and one of them used to fail open.** The cooldown
    was `if 0 <= since < MIN_REFRESH_INTERVAL_S`, so a `last_attempt_at` in the
    FUTURE — negative `since` — was admitted, while the `Retry-After` check ten
    lines up (`if wait > 0`) refused. Two guards in one function with opposite
    failure directions, and the one that failed open is the one this docstring
    calls the rule that matters most in practice.
    It is not theoretical here: a Home Assistant host with no RTC boots with a
    wrong clock and corrects by NTP minutes later, so every timestamp written
    before the correction is then in the future — and for the length of the skew
    EVERY automatic refresh for EVERY account was admitted, three banks fanned
    out on every read, which is the exact traffic the cooldown exists to stop.
    A timestamp we cannot make sense of is a reason to wait, not a licence.
    """
    now = _now_s()
    rows = [dict(r) for r in c.execute(
        "SELECT resource, last_attempt_at, next_retry_after FROM sync_state"
        " WHERE account_id=?", (account_id,))]

    for row in rows:
        until = _parse_ts(row.get("next_retry_after"))
        if until is None:
            continue
        wait = until.timestamp() - now
        if wait > 0:
            return ("the provider asked us to wait: Retry-After is still %d s "
                    "away (recorded against %s on this account)"
                    % (int(wait), row.get("resource")))
    if not automatic:
        return None
    for row in rows:
        stamp = _parse_ts(row.get("last_attempt_at"))
        if stamp is None:
            continue
        since = now - stamp.timestamp()
        if since < MIN_REFRESH_INTERVAL_S:
            if since < 0:
                return ("the last refresh attempt for this account is stamped "
                        "%d s in the FUTURE, so the cooldown cannot be "
                        "evaluated; waiting rather than assuming (a host whose "
                        "clock was corrected by NTP leaves exactly this)"
                        % int(-since))
            return ("an automatic refresh for this account was attempted %d s "
                    "ago; the minimum interval is %d s"
                    % (int(since), MIN_REFRESH_INTERVAL_S))
    return None


def claim_refresh(c, account_id: str, *, priority: bool = False) -> bool:
    """Single-flight. Durable in `meta`, because our processes are ephemeral.

    A priority claim (an authorization-time backfill) always wins: the
    deep-history window is minutes wide and no later slice can reopen it.
    """
    key = _inflight_key(account_id)
    raw = _meta_get(c, key)
    if raw and not priority:
        try:
            held = json.loads(raw)
        except ValueError:
            held = {}
        started = float(held.get("started_at") or 0)
        if _now_s() - started < INFLIGHT_TTL_S:
            return False
    _meta_set(c, key, json.dumps({"started_at": _now_s(),
                                  "priority": bool(priority)}))
    return True


def release_refresh(c, account_id: str) -> None:
    _meta_del(c, _inflight_key(account_id))


@contextlib.contextmanager
def authorization_priority(c, account_id: str):
    """Backfill inside the fresh-SCA window. Preempts, and defers to nothing."""
    claim_refresh(c, account_id, priority=True)
    try:
        yield
    finally:
        release_refresh(c, account_id)


# --------------------------------------------------------------------------
# setup and discovery
# --------------------------------------------------------------------------

_ONE_BANK_AT_A_TIME = (
    "8. Linking: ONE BANK AT A TIME — each bank costs two operator "
    "approvals and its own SCA taps, and interleaving banks is how a tap "
    "lands on the wrong one. The admin credential renews itself from the "
    "stored refresh token; only if this run fell back to a pasted "
    "control-panel token, expect to re-paste it between banks — it lasts "
    "about an hour, and a token that expires mid-setup simply stops the "
    "next link; nothing is corrupted.")


_OOB_RESEND_S = 900          # one email per 15 min unless resend=true


def _cred_store(field: str, value: str, concealed: bool = True) -> None:
    """The credential rung's ONE vault-write seam.

    `upsert_field` in BOTH modes: a missing credential item is created on first
    store — `op item edit` cannot create one, and without the upsert an
    empty-vault dance never goes durable and every run needs a fresh sign-in
    email. The sandbox item exists in no vault yet by construction; a FRESH
    production vault (a reinstall, a new 1Password account) has the same gap.
    The create keeps the module's two-negative evidence rule, so a transient
    fault still cannot forge a sibling over a live item."""
    OPVAULT.upsert_field(OPVAULT.CRED_ITEM, OPVAULT.VAULT, field, value,
                         concealed=concealed)


def _credential_rung(c, lines, args):
    """Rung 3. Returns True when a durable (or pasted) credential is
    proven and the ladder may continue; False after writing the stop
    lines. The flow:

        stored refresh token mints        -> durable, done
        INVALID_REFRESH_TOKEN / missing   -> the email-link dance
        any OTHER mint failure            -> stop; the token is probably
                                             fine and a new dance would
                                             burn a single-use code on an
                                             outage (branch on the truth)

    The dance is resumable across calls: sendOobCode now, then the
    operator runs bank_feed_signin with signin_link=<pasted URL> — the
    argument-carrying sibling of the argument-free setup tool (issue #7);
    both reach this rung through `_reconcile`. State (email, send time)
    lives in the meta table, not memory."""
    fault = OPVAULT.status()
    refresh = None
    if fault is None:
        try:
            refresh = OPVAULT.read(OPVAULT.REF_REFRESH_TOKEN)
        except OPVAULT.OpError as exc:
            # not_found alone means "no stored token" (the dance path).
            # Any OTHER failure is a FAULT: the durable token may exist
            # and be valid, and a sign-in started now would burn a
            # single-use code AND be unstorable — the credential twin of
            # the forge rung's transient-vs-absent rule. An unusable op is
            # the same fault, not a missing token.
            if not exc.not_found:
                fault = str(exc)
    if fault is not None:
        lines.append(
            "3. Credential: 1Password could not be consulted (%s). The "
            "durable refresh token may well exist and be valid, so NO "
            "new sign-in was started — its code is single-use, and a "
            "credential acquired now could not be stored anyway. Retry "
            "when the vault answers. Stopping." % _safe(fault))
        return False
    if refresh:
        try:
            FB.mint_id_token(refresh)
            # A finished flow leaves no dance state behind: a lingering
            # send-timestamp would suppress the NEXT genuinely-needed
            # email as "already sent".
            _meta_del(c, "setup.oob_sent_at")
            lines.append(
                "3. Credential: durable — the stored refresh token mints a "
                "fresh control-panel token on demand. Nothing to do.")
            return True
        except FB.AuthError as exc:
            if exc.code != "INVALID_REFRESH_TOKEN":
                lines.append(
                    "3. Credential: the stored refresh token could not be "
                    "proven (%s). This does NOT look like a revoked token, "
                    "so no new sign-in was started — retry later, and if "
                    "it persists check the Enable Banking control panel. "
                    "Stopping." % _safe(exc.code))
                return False
            # Drop any cached minter NOW: it holds the token just proven
            # dead, and from_env returns the cached minter before every
            # other rung — without this, a CP-token continuation would
            # ride the corpse into a 401 loop.
            eb_admin.drop_minter()
            lines.append(
                "3. Credential: the stored refresh token was REVOKED or "
                "has gone stale (INVALID_REFRESH_TOKEN) — a fresh sign-in "
                "is needed.")
        except Exception as exc:                     # noqa: BLE001
            # A transport failure (URLError, a socket timeout,
            # httpx.RateLimited, httpx.TooLarge, ...) is not AuthError
            # and is not proof the token is bad — the same "branch on the
            # truth" rule as a non-INVALID_REFRESH_TOKEN AuthError code:
            # retry later, no new sign-in was started on what is probably
            # just an outage.
            lines.append(
                "3. Credential: the stored refresh token could not be "
                "proven (%s). This does NOT look like a revoked token, "
                "so no new sign-in was started — retry later, and if "
                "it persists check the Enable Banking control panel. "
                "Stopping." % _safe(type(exc).__name__))
            return False
    # --- the dance -------------------------------------------------------
    email = args.get("email") or ""
    email_fault = ""
    if email:
        try:
            _cred_store("username", email, concealed=False)
        except OPVAULT.OpError:
            pass                                  # meta still remembers it
        _meta_set(c, "setup.oob_email", email)
    else:
        # The fault is CARRIED rather than folded into "" (issue #5, item
        # 1): a read that RAISED never observed the field, so the stop
        # below must not describe it as empty — that sends the operator to
        # re-supply an address 1Password may already hold. `not_found` is
        # the one OpError that IS an observation (op said the item or field
        # does not exist), so it keeps the absent-or-empty wording, the
        # same not_found-vs-any-other-OpError split the forge rung makes.
        email = ""
        unusable = OPVAULT.status()
        if unusable is None:
            try:
                email = OPVAULT.read(OPVAULT.REF_EMAIL)
            except OPVAULT.OpError as exc:
                if not exc.not_found:
                    email_fault = type(exc).__name__
        else:
            email_fault = unusable
        email = email or _meta_get(c, "setup.oob_email") or ""
    if not email:
        if email_fault:
            lines.append(
                "3. Credential: no durable credential, and the account email "
                "could not be read from 1Password (%s) — nothing observed the "
                "username field, so this is NOT evidence that it is empty. "
                "Retry once 1Password answers, or run bank_feed_signin with "
                "email=<the Enable Banking account email> to supply it "
                "directly. Stopping." % _safe(email_fault))
            return False
        lines.append(
            "3. Credential: no durable credential, and the account email "
            "is unknown (the vault's username field is absent or empty). Run "
            "bank_feed_signin with email=<the Enable Banking account email> "
            "— it is stored and never asked again. Stopping.")
        return False

    link = args.get("signin_link") or ""
    if link:
        try:
            code = FB.parse_signin_link(link)
        except FB.DefangedLink as exc:
            lines.append("3. Credential: %s. Stopping." % _safe(str(exc)))
            return False
        # The exchange and the PROOF get SEPARATE handlers (issue #5). In
        # one `try`, a transport failure is reported identically whether or
        # not the redemption had been observed — and the honest sentence for
        # one is a false one for the other. The split is what makes each
        # branch able to say only what it watched:
        #
        #   * exchange_link raised  -> the request may never have reached
        #     the provider, so the code may still be live. Re-paste first.
        #   * exchange_link RETURNED and the proof failed -> the code IS
        #     spent, whatever happened next. Only a resend recovers.
        #
        # Nothing is primed or stored on either: without these handlers the
        # fresh token a failure could carry would be discarded uncaught,
        # and the outer generic error renderer would surface the raw
        # exception text instead of this module's own report.
        try:
            fresh = FB.exchange_link(email, code)
        except FB.AuthError as exc:
            lines.append(
                "3. Credential: the sign-in link did not redeem (%s). The "
                "code is single-use and lives ~1 hour — run "
                "bank_feed_signin with resend=true for a fresh email, then "
                "paste the new link. Stopping." % _safe(exc.code))
            return False
        except Exception as exc:                     # noqa: BLE001
            lines.append(
                "3. Credential: the sign-in link could not be redeemed (%s). "
                "The provider did not REJECT it — that arrives as an "
                "AuthError and is reported differently — so this is some "
                "other failure. The code may "
                "already have been consumed, or the request may never have "
                "reached the provider; this run cannot tell which. Paste the "
                "SAME link again first — if it was consumed the provider says "
                "so, and only then run bank_feed_signin with resend=true for "
                "a fresh sign-in email. Stopping."
                % _safe(type(exc).__name__))
            return False
        try:
            FB.mint_id_token(fresh)               # PROVE before storing
        except FB.AuthError as exc:
            lines.append(
                "3. Credential: the sign-in link redeemed, but the credential "
                "it returned could not be proven to mint (%s). The code is "
                "spent — run bank_feed_signin with resend=true for a fresh "
                "email, then paste the new link. Stopping." % _safe(exc.code))
            return False
        except Exception as exc:                     # noqa: BLE001
            lines.append(
                "3. Credential: the sign-in link redeemed, but the fresh "
                "credential could not be proven (%s). The provider did not "
                "reject the credential — that arrives as an AuthError and is "
                "reported differently — so this is some other failure. The "
                "code was consumed by the redemption "
                "this run watched succeed, so the same link cannot be pasted "
                "again: run bank_feed_signin with resend=true for a fresh "
                "sign-in email. Stopping." % _safe(type(exc).__name__))
            return False
        # The proven token becomes THIS PROCESS's admin credential right
        # now, storable or not — this is the mechanism behind every
        # "continue" claim below: without it, a failed store leaves later
        # rungs credential-less while the report says the run continues.
        eb_admin.prime_minter(fresh)
        stored = False
        try:
            _cred_store("refresh token", fresh)
            stored = OPVAULT.read(OPVAULT.REF_REFRESH_TOKEN) == fresh
        except OPVAULT.OpError:
            stored = False
        _meta_del(c, "setup.oob_sent_at")
        if stored:
            lines.append(
                "3. Credential: acquired and stored — the refresh token "
                "was proven to mint, written to 1Password ('%s' → refresh "
                "token), and read back identical. The hourly token paste "
                "is retired." % OPVAULT.CRED_ITEM)
        else:
            lines.append(
                "3. Credential: acquired and proven, but it was NOT stored "
                "in 1Password (the vault write failed or did not read "
                "back). This run continues on the in-memory credential; "
                "durability is NOT achieved — fix vault access, then run "
                "bank_feed_signin with resend=true: the next attempt needs "
                "a fresh sign-in email.")
        return True

    sent_at = _meta_get(c, "setup.oob_sent_at")
    try:
        # Clamped on BOTH sides: a future timestamp (clock rollback, bad
        # meta) must read as "not recent", not suppress resends until
        # wall time catches up.
        recently = (sent_at is not None
                    and 0 <= _now_s() - float(sent_at) < _OOB_RESEND_S)
    except ValueError:
        recently = False
    if recently and not args.get("resend"):
        lines.append(
            "3. Credential: a sign-in email was already sent to %s in the "
            "last 15 minutes. Find 'Sign in to Enable Banking' in that "
            "mailbox, COPY the full link from your own mail client "
            "(do not click it, and do not relay it through a connector — "
            "both destroy the single-use code), and run bank_feed_signin "
            "with signin_link=<the copied URL>. Use resend=true for a "
            "fresh email. Stopping." % _safe(email))
        return False
    try:
        FB.send_signin_email(email)
    except FB.AuthError as exc:
        lines.append("3. Credential: the sign-in email could not be sent "
                     "(%s). Stopping." % _safe(exc.code))
        return False
    except Exception as exc:                     # noqa: BLE001
        # A transport failure — same stop line, naming the exception
        # TYPE only.
        lines.append("3. Credential: the sign-in email could not be sent "
                     "(%s). Stopping." % _safe(type(exc).__name__))
        return False
    _meta_set(c, "setup.oob_sent_at", str(_now_s()))
    lines.append(
        "3. Credential: a 'Sign in to Enable Banking' email was just sent "
        "to %s. This is the one human step software must not do: open "
        "that email IN YOUR OWN MAIL CLIENT, COPY the full sign-in URL "
        "(do not click it — a browser visit consumes the single-use "
        "code), and run bank_feed_signin with signin_link=<the copied "
        "URL> within the hour. Everything after that paste is "
        "automatic. Stopping until then." % _safe(email))
    return False


def _reconcile(args: dict) -> str:
    """The reconcile ladder — the plugin's setup-time writes: key forge,
    vault store, application registration, redirect PATCH.

    The shared body of the two tools below. `setup_bank_feed` calls it with
    NO arguments (casa's setup-tool contract, issue #7); `bank_feed_signin`
    calls it with the operator's credential-dance arguments. `args` reaches
    rung 3 and nowhere else — no rung here has ever accepted a redirect URI
    or an application id from a caller, and none may start.

    **It is no longer diagnostic-only**: the plugin drives its own
    application registration, including adding
    `<PUBLIC_URL>/callback/plg-bank-feed--authorize` to the app;
    `eb_admin.Admin.add_redirect_url` exists for exactly this. Printing a
    browser instruction instead would leave the plugin unable to complete its
    own
    setup, and casa matches the redirect URI byte-for-byte, so a URI the
    operator retyped is a URI that silently rejects every authorization.

    **The redirect question is asked and answered through the CONTROL PANEL,
    not through the AIS view — because the answer has to be WRITABLE, not
    because the AIS view lacks the field.** Correcting the record: an earlier
    version of this comment said the app-JWT `GET /application` does not carry
    `redirect_urls`. IT DOES: the response carries `active`, `countries`,
    `description`, `environment`, `kid`, `name`, `redirect_urls` and
    `services`.
    That earlier claim was inferred from one incomplete read on record and it
    was wrong about the provider; a later slice reading it would have avoided
    the AIS view for a reason that does not exist.

    The DECISION is unchanged and correct on its own terms. `add_redirect_url`
    does not merely CHECK the redirect, it REGISTERS it, and writes exist only
    on the control panel (`PATCH /api/applications`; the AIS view is read-only
    to us). So the check has to happen where the write happens: one
    read-modify-write, against one view, in one place. Reading the AIS view
    and writing the control panel would put the question and the answer on two
    different reads and add a second place for them to disagree — for no gain,
    since the control-panel read is one `add_redirect_url` must perform
    anyway. `_ais()` is kept for what it is separately authoritative about:
    `environment` and `active`.

    It is called UNCONDITIONALLY, because it is idempotent in the strong
    sense: when the URI is already registered it issues no HTTP request at all
    and returns `changed: False`. Branching on a read we would have to perform
    anyway would only add a second place for the two answers to disagree.
    `changed` is reported truthfully — a setup tool that claims a repair every
    time teaches the operator that its output means nothing.
    """
    lines = ["bank-feed setup — reconcile ladder. It repairs "
             "what is absent — the signing key (forged inside 1Password), "
             "the durable credential, the application ('%s', registered "
             "when none exists — never a second one), and casa's callback "
             "redirect URI — and it NEVER deletes an application or "
             "re-registers over an existing one (DELETE on "
             "/api/applications is not in eb_admin.ALLOW at all)."
             % _app_name()]
    entry = _entry()
    if not entry:
        lines.append(
            "1. Discovery: not_configured — no callback .index entry. The "
            "callback is not routed. Likely gates: the plugin's callback "
            "consent was never granted, the plugin is not assigned to a role, "
            "or casa's public_url is invalid. Stopping: linking a bank cannot "
            "work until this is fixed, and there is no redirect URI to "
            "register until casa publishes one.")
        return "\n".join(lines)
    lines.append("1. Discovery: OK — callback routed.")
    # The redirect URI comes from `callbacks.discover()` and from nowhere
    # else. It is never reconstructed from PUBLIC_URL and never accepted as
    # an argument: casa matches it byte-for-byte, and a caller-supplied value
    # would register an attacker-controlled redirect on our own application.
    # Resolved here, ahead of every other rung, because rung 4 needs it too
    # (the certificate registration carries it as the initial redirect_urls
    # entry).
    redirect_uri = entry["redirect_uri"]
    resolved = _resolve_key()
    if isinstance(resolved, str):
        lines.append(resolved)
        return "\n".join(lines)
    key_source, key, key_pem = resolved
    if key_source == "env":
        lines.append("2. Key: present.")
    elif key_source == "vault":
        lines.append(
            "2. Key: read from 1Password (%s) — it did not reach this "
            "process as a usable value: the plugin-env.conf line may never "
            "have been written, may be present but empty, or may hold an "
            "op:// reference that failed to resolve. Steady state should not shell out per read: have the "
            "configurator wire the op:// reference '%s' as %s, and if it is "
            "already there, check that it resolves."
            % (OPVAULT.KEY_ITEM, OPVAULT.REF_PRIVATE_KEY, WIRE_KEY_VAR))
    else:
        lines.append(
            "2. Key: FORGED — 1Password generated a fresh RSA-4096 keypair "
            "inside the vault ('%s'), and the private key was read back into "
            "this process and proven to sign. It was never written to disk "
            "by this plugin, and it was never generated outside the vault. "
            "Have the configurator wire '%s' into plugin-env.conf as %s."
            % (OPVAULT.KEY_ITEM, OPVAULT.REF_PRIVATE_KEY, WIRE_KEY_VAR))

    c = _conn()
    proceed = _credential_rung(c, lines, args)
    if not proceed and eb_admin._MINTER is not None:
        # A same-process re-run after an acquired-but-not-stored call
        # primes eb_admin's in-process minter — _admin() rides it fine, but
        # a continuation check that looks only for the pasted CP token
        # stops dead at rung 3 with a working credential sitting
        # right there.
        lines.append("   …continuing this run on the primed in-process "
                     "credential from an earlier acquired-but-not-stored "
                     "call; durability still needs a successful vault "
                     "write.")
        proceed = True
    elif not proceed and os.environ.get(ADMIN_TOKEN_VAR):
        # The dance stopped (instructions above stay in the report), but
        # the operator pasted an hourly CP token — this run's remaining
        # rungs ride it rather than stranding a working credential.
        lines.append("   …continuing this run on the pasted 1-hour token "
                     "from %s; durability still needs the sign-in step "
                     "above." % ADMIN_TOKEN_VAR)
        proceed = True
    if not proceed:
        return "\n".join(lines)

    app_id = os.environ.get("CASA_BANKFEED_EB_APP_ID")
    if app_id:
        # The world guard runs FIRST: a wired id is verified against the
        # path-bound admin view BEFORE it is recorded and BEFORE the redirect
        # rung can PATCH it — a plugin-env.conf copied from the other world's
        # install is exactly the input this refuses. Both modes: the env id is
        # still the deployment contract, but the contract now includes being
        # THIS world's application — one path-bound GET per process, against
        # the same credential rung 5's PATCH needs anyway.
        try:
            _assert_world(app_id, admin=_admin())
        except WorldMismatch as exc:
            lines.append("4. Application: %s Stopping." % exc)
            return "\n".join(lines)
        except Exception as exc:                 # noqa: BLE001
            # Same remedy family as rung 5's failure text: when this run rides
            # a pasted 1-hour token, expiry is the USUAL cause of a failure
            # here, and "retry" alone misdiagnoses it as provider availability.
            lines.append(
                "4. Application: the application world check could not "
                "run (%s) — refusing to touch the configured "
                "application unverified. Remedy: if this run fell back "
                "to a pasted control-panel token, re-check %s — it "
                "expires after about an hour, so re-pasting a fresh one "
                "is the usual fix; otherwise the stored credential "
                "renews itself, so simply retry. Stopping."
                % (type(exc).__name__, ADMIN_TOKEN_VAR))
            return "\n".join(lines)
        # RECORD the binding even on the trusted-env path: a wired install that
        # never wrote meta would have no recorded binding, so a later
        # vanish-plus-unwire would walk the guardless first-install create. The
        # env branch makes NO liveness determination, so it must not touch the
        # acceptance marker either way — THE MARKER'S LIFECYCLE RULE: it
        # survives exactly as long as the vanish it authorized persists, and
        # only branches that PROVE the app alive void it.
        _meta_set(c, "setup.app_id", app_id)
        # Named by its plugin-env.conf REFERENCE, not by the process key
        # the branch above read: after issue #4 those differ, and the
        # reference is the only one of the two an operator can find in a
        # file or hand to set_plugin_env_reference.
        lines.append("4. Application: %s resolved — using the configured "
                     "application id." % WIRE_APP_ID_VAR)
    else:
        recorded = _meta_get(c, "setup.app_id")
        try:
            apps = _admin().applications()
        except Exception as exc:                 # noqa: BLE001
            lines.append(
                "4. Application: GET /api/applications failed (%s) — "
                "cannot tell whether '%s' exists, and creating blind is "
                "how duplicates accumulate. Nothing was changed. "
                "Stopping." % (type(exc).__name__, _app_name()))
            return "\n".join(lines)
        by_id = {str(a.get("app_id") or a.get("kid") or ""): a for a in apps}
        # The RECORDED binding outranks the name search: once this setup has
        # bound an app (created or adopted), that id is the truth, and its
        # disappearance from the list is RE-registration territory — never
        # walked silently: without this, an unwired env plus a vanished app
        # reaches the create path as if this were a first install. Trust
        # asymmetry, on purpose: the ENV id is the deployment contract and is
        # trusted without a list call — long-standing behavior, and the
        # no-list-call property is pinned by test. The RECORDED id is
        # self-made, so before it is touched it must still LOOK like ours in
        # the list we already fetched: presence alone would adopt-and-PATCH an
        # app that was renamed or moved to SANDBOX since we bound it.
        if recorded and recorded in by_id:
            candidate = by_id[recorded]
            if (candidate.get("name") == _app_name()
                    and str(candidate.get("environment") or "").upper()
                    == ebmode.mode()):
                app_id = recorded
                # The candidate record just matched the mode pair — it IS
                # the world evidence for this id: an adopted branch
                # re-uses evidence in hand, with no extra call.
                _assert_world(app_id, record=candidate)
                # The app is ALIVE: any outstanding acceptance was for a
                # vanish that resolved itself, and letting it linger
                # would silently authorize a FUTURE vanish — the marker
                # survives only while the vanish it authorized persists.
                _meta_del(c, "setup.rereg_accepted")
                lines.append(
                    "4. Application: adopted the previously bound app (%s) "
                    "— still present. Have the configurator wire "
                    "%s=%s into plugin-env.conf."
                    % (_safe(recorded), WIRE_APP_ID_VAR, _safe(recorded)))
            else:
                # A drifted reappearance also un-persists the vanish: the
                # id exists again, just wrong. Whatever happens next is a
                # NEW situation the operator must look at — an old grant
                # must not ride through it (same lifecycle rule).
                _meta_del(c, "setup.rereg_accepted")
                lines.append(
                    "4. Application: the previously bound app (%s) is "
                    "still listed but no longer looks like ours (name %s, "
                    "environment %s) — refusing to touch or replace it. "
                    "Resolve in the control panel. Stopping."
                    % (_safe(recorded),
                       _safe(candidate.get("name") or "unset"),
                       _safe(candidate.get("environment") or "unset")))
                return "\n".join(lines)
        elif recorded and _meta_get(c, "setup.rereg_accepted") != recorded:
            # No argument can open this gate: setup_bank_feed is unprotected,
            # and a model-supplied argument IS inference alone. The only key is
            # the marker the PROTECTED accept_app_reregistration tool writes
            # after casa's operator-confirmation hook fires.
            lines.append(
                "4. Application: the application this setup previously "
                "bound (%s) is NO LONGER in the control-panel list. "
                "Registering a replacement would orphan every bank "
                "session that rode it, so nothing was created — "
                "re-registration is an informed operator action. If "
                "the app is truly gone and you accept "
                "re-linking every bank, run the PROTECTED tool "
                "accept_app_reregistration (casa will ask the operator "
                "to confirm), then re-run setup_bank_feed. Stopping."
                % _safe(recorded))
            return "\n".join(lines)
        elif recorded:
            # Operator-authorized via the protected tool. Neither record is
            # deleted here: the binding is the guard and the create below can
            # fail ambiguously. On success the create path overwrites the
            # binding and consumes the acceptance marker; on failure both
            # stand.
            lines.append(
                "4. Application: re-registration ACCEPTED (operator-"
                "confirmed) for the vanished app %s — every bank must be "
                "re-linked after this." % _safe(recorded))
        if app_id:
            matches = []                       # adopted above; skip search
        else:
            matches = [a for a in apps
                       if a.get("name") == _app_name()
                       and str(a.get("environment") or "").upper()
                       == ebmode.mode()]
        if len(matches) > 1:
            lines.append(
                "4. Application: %d %s applications named '%s' "
                "exist — duplicates a repair must not add to and cannot "
                "choose between. Resolve in the control panel (the one "
                "whose kid matches the configured key stays). Stopping."
                % (len(matches), ebmode.mode(), _app_name()))
            return "\n".join(lines)
        if app_id:
            pass                    # adopted the recorded binding above
        elif matches:
            found = str(matches[0].get("app_id")
                        or matches[0].get("kid") or "")
            if not found:
                # A malformed list record must stop the rung: "adopting"
                # an empty id poisons the meta record and every later
                # rung, and creating instead would duplicate a live app.
                lines.append(
                    "4. Application: a %s app named '%s' exists "
                    "but its list record carries no usable id — cannot "
                    "adopt it, and registering another would duplicate a "
                    "live application. Report this record shape. "
                    "Stopping." % (ebmode.mode(), _app_name()))
                return "\n".join(lines)
            app_id = found
            # The matched listing entry is the world evidence.
            _assert_world(app_id, record=matches[0])
            _meta_set(c, "setup.app_id", app_id)
            _meta_del(c, "setup.rereg_accepted")   # alive → marker void
            lines.append(
                "4. Application: '%s' already exists (%s) — adopted, not "
                "re-registered. Have the configurator wire it into "
                "plugin-env.conf as %s=%s."
                % (_app_name(), _safe(app_id), WIRE_APP_ID_VAR,
                   _safe(app_id)))
        else:
            # The cross-phase invariant, ENFORCED at the one site it protects:
            # an application may only be registered against key material PROVEN
            # re-readable from the vault. "vault" and "forged" sources carry
            # that proof by construction; "env" is a deployment CONVENTION —
            # the variable is normally the resolved op:// reference, but
            # nothing stops it carrying a literal whose only copy dies with
            # this process, and an app registered against that can never be
            # authenticated again after a restart.
            if key_source == "env":
                try:
                    vault_key = jwtsign.load_pkcs8(
                        OPVAULT.read(OPVAULT.REF_PRIVATE_KEY))
                except Exception:                # noqa: BLE001
                    vault_key = None
                if (vault_key is None
                        or (vault_key.n, vault_key.e) != (key.n, key.e)):
                    lines.append(
                        "4. Application: registration requires the signing "
                        "key to be RE-READABLE from 1Password, and the key "
                        "wired as %s does not match the vault's '%s' (or the "
                        "vault could not answer). Registering against key "
                        "material that exists only in this process would "
                        "create an application nothing can authenticate to "
                        "after a restart. Fix the op:// wiring, then re-run. "
                        "Stopping." % (WIRE_KEY_VAR, OPVAULT.KEY_ITEM))
                    return "\n".join(lines)
            certificate = jwtsign.public_spki_pem(key)
            try:
                # The environment is passed EXPLICITLY: the eb_admin default
                # stays PRODUCTION for any other caller, and this one call site
                # is where the mode's world is chosen.
                app_id = _admin().create_application(
                    _app_name(), certificate, [redirect_uri],
                    environment=ebmode.mode())
            except Exception as exc:             # noqa: BLE001
                lines.append(
                    "4. Application: registration FAILED (%s). Check "
                    "GET /api/applications before retrying — do not "
                    "assume it does not exist. Stopping."
                    % type(exc).__name__)
                return "\n".join(lines)
            # Verify the CLAIM before anything rides it — the create twin of
            # the probe's cleanup rule: the response is provider-controlled,
            # and recording or PATCHing an id it merely NAMED would aim a live
            # write at an app this run never made. The returned id must appear
            # in a fresh listing as OUR app.
            try:
                fresh = [a for a in _admin().applications()
                         if str(a.get("app_id") or a.get("kid") or "")
                         == app_id]
            except Exception:                    # noqa: BLE001
                fresh = None
            record = fresh[0] if fresh else None
            if (record is None
                    or record.get("name") != _app_name()
                    or str(record.get("environment") or "").upper()
                    != ebmode.mode()):
                lines.append(
                    "4. Application: registration returned id %s, but a "
                    "fresh listing does not show that id as '%s' in "
                    "%s%s. NOT recording it and NOT touching it — "
                    "inspect the control panel before re-running. "
                    "Stopping."
                    % (_safe(app_id), _app_name(), ebmode.mode(),
                       "" if fresh is not None
                       else " (the verification listing itself failed)"))
                return "\n".join(lines)
            _meta_set(c, "setup.app_id", app_id)
            # Consume the operator's acceptance ONLY now that the
            # replacement exists AND verified — one grant, one
            # registration. A no-op on a first install.
            _meta_del(c, "setup.rereg_accepted")
            # The fresh listing above IS the world evidence for this id:
            # cache it so the redirect rung's assert needs no extra
            # call: an adopted or created branch re-uses evidence already
            # in hand.
            _assert_world(app_id, record=record)
            # Activation wording differs by world and both sentences are
            # live-verified: production apps start Inactive and the first
            # completed link activates them; sandbox apps are activated
            # automatically at registration (vendor docs).
            if ebmode.is_sandbox():
                activation = ("It is activated automatically in the "
                              "SANDBOX environment — no bank link or "
                              "control-panel visit needed for that.")
            else:
                activation = ("It starts Inactive; completing the first "
                              "bank link activates it — no control-panel "
                              "visit needed.")
            lines.append(
                "4. Application: REGISTERED '%s' (%s) with the resolved "
                "key's public half (SPKI) and casa's callback redirect. "
                "%s Have the configurator wire "
                "%s=%s into plugin-env.conf."
                % (_app_name(), _safe(app_id), activation, WIRE_APP_ID_VAR,
                   _safe(app_id)))

    # Belt over the branches above: every path to this PATCH has already
    # verified-and-cached the id, so this is a free assert — and if a future
    # branch forgets, it fetches path-bound evidence rather than PATCHing
    # unverified. Its own handler, so a mismatch is not misreported as a
    # redirect failure. Both modes.
    try:
        _assert_world(app_id, admin=_admin())
    except WorldMismatch as exc:
        lines.append("5. Callback redirect: %s Stopping." % exc)
        return "\n".join(lines)
    except Exception as exc:                     # noqa: BLE001
        lines.append(
            "5. Callback redirect: the application world check could not "
            "run (%s) — refusing to touch the application unverified. "
            "Stopping." % type(exc).__name__)
        return "\n".join(lines)
    try:
        registration = _admin().add_redirect_url(app_id, redirect_uri)
    except Exception as exc:                     # noqa: BLE001
        lines.append(
            "5. Callback redirect: could not be checked or registered (%s). "
            "Stopping: casa's redirect URI is matched byte-for-byte by the "
            "provider, so until it is on the application every authorization "
            "is rejected and running link_bank would spend SCA taps for "
            "nothing. This run cannot tell whether the application was "
            "changed: a PATCH that failed in transit may have been applied "
            "with only the response lost (issue #5, item 3). Remedy: if this "
            "run fell back to a pasted control-panel token, re-check %s — it "
            "expires after about an hour, so re-pasting a fresh one is the "
            "usual fix; otherwise the stored credential renews itself, so "
            "simply retry. Then run setup_bank_feed again — it re-reads the "
            "redirect list before touching it, so a write that did land is "
            "reported as already registered and nothing is duplicated."
            % (type(exc).__name__, ADMIN_TOKEN_VAR))
        return "\n".join(lines)
    if registration.get("changed"):
        lines.append(
            "5. Callback redirect: REGISTERED %s on the application. Existing "
            "redirect URLs were preserved — a PATCH replaces the list "
            "wholesale, so the complete desired set is always sent."
            % _safe_url(redirect_uri))
    else:
        lines.append(
            "5. Callback redirect: already registered (%s) — nothing to do, "
            "and no request was made." % _safe_url(redirect_uri))

    try:
        app = _ais().application()
    except (WorldMismatch, WorldUnverified) as exc:
        # The guarded _ais() itself refused — each carries its own remedy
        # sentence, and folding either into the generic GET-failed wording
        # below would bury it under 404-recovery advice it must never receive.
        lines.append("6. Application: %s Stopping." % exc)
        return "\n".join(lines)
    except Exception as exc:                     # noqa: BLE001
        status = getattr(exc, "status", None)
        lines.append(
            "6. Application: GET /application failed (%s%s). Reported, never "
            "auto-repaired: re-registering very likely orphans every existing "
            "bank session. If this is a genuine 404, the recovery is: run "
            "accept_app_reregistration (casa will ask the operator to "
            "confirm), have the configurator CLEAR %s "
            "from plugin-env.conf (setup re-records the binding itself), "
            "then re-run setup_bank_feed — every bank must be re-linked "
            "afterwards."
            % (type(exc).__name__,
               "" if status is None else " status %s" % status,
               WIRE_APP_ID_VAR))
        return "\n".join(lines)
    # The app answered under its OWN key — the strongest liveness proof
    # there is, and the only one the env-wired path ever produces. Void
    # any outstanding acceptance regardless of the health verdict below: a
    # reachable-but-inactive app is still an EXISTING app, so the vanish
    # it authorized has un-persisted.
    _meta_del(c, "setup.rereg_accepted")
    if str(app.get("environment") or "").upper() != ebmode.mode():
        # A hard stop in BOTH modes, symmetrically: an install whose
        # app answers as another world's must not proceed to "run
        # list_banks, then link_bank" — that next step would spend taps
        # against the wrong world. After the guarded _ais() above this
        # is between-GET drift, vanishingly rare, and rare is not a
        # reason to fail open.
        lines.append(
            "6. Application: reachable, but its environment is %s, "
            "not %s — this wiring points at another world's "
            "application. Refusing to continue; fix the "
            "plugin-env.conf wiring and re-run. Stopping."
            % (_safe(app.get("environment") or "unset"), ebmode.mode()))
        return "\n".join(lines)
    active = app.get("active")
    if active is None:
        # `app.get("active", True)` asserted health from silence (issue #5,
        # item 4) — and health is the rung that sends the operator off to
        # run link_bank. The one live GET /application read on record
        # returned `active` among its keys (see this rung's docstring), so
        # an absent key is an unrecognised response shape, not a statement
        # about activation. The ladder still CONTINUES: an unknown
        # activation is not a reason to refuse, only a reason not to
        # promise.
        lines.append(
            "6. Application: reachable in %s, but the response carried no "
            "usable `active` value — the key was absent or null — so this "
            "run cannot tell whether the application is activated, and does "
            "not assume it is. If link_bank is rejected, check the "
            "application's activation in the Enable Banking control panel."
            % ebmode.mode())
    elif not active:
        lines.append(
            "6. Application: reachable, but the application is inactive "
            "(pending activation?). Reported; not repairable from here — it "
            "is control-panel state the operator owns.")
    else:
        lines.append("6. Application: healthy — %s, active. Nothing "
                     "to do." % ebmode.mode())
    lines.append(
        "7. Next: run list_banks, then link_bank — one bank at a time. "
        "What stays human, by design: two approvals per bank (whitelist "
        "tap, then the bank's own SCA), labelling each discovered account "
        "once, and a bank re-approval every 179 days. Note that HA "
        "backups contain this plugin's transaction history.")
    lines.append(_ONE_BANK_AT_A_TIME)
    return "\n".join(lines)


@register("setup_bank_feed",
          "Run the setup reconcile ladder: callback routing, signing key "
          "(forged in 1Password when absent), the durable control-panel "
          "credential, the application (registered when absent), and casa's "
          "callback redirect URI. Argument-free and idempotent; re-run any "
          "time. When it needs the one human step — a copy/pasted email "
          "sign-in link — it says so and names bank_feed_signin.",
          {"type": "object", "properties": {}})
def setup_bank_feed(args: dict) -> str:
    """casa's setup tool, and therefore ARGUMENT-FREE (issue #7, module
    docstring). `plugin_setup_episodes` dispatches it with no arguments
    after the trigger consent settles, so `args` is DISCARDED rather than
    forwarded: an argument that arrives here arrived by invention, and
    honouring it would let a model choose an email address or replay a
    sign-in link on the one path where no operator is in the loop. The
    operator's own credential step is `bank_feed_signin`."""
    return _reconcile({})


@register("bank_feed_signin",
          "The one human step of setup: supply the Enable Banking account "
          "email, paste the COPIED sign-in URL from that email, or ask for "
          "a fresh one. Then it runs the same reconcile ladder as "
          "setup_bank_feed, so a successful paste finishes setup in one "
          "call. Use it only when setup_bank_feed asks for one of these.",
          {"type": "object", "properties": {
              "email": {"type": "string", "description":
                        "The Enable Banking account email. Needed once; "
                        "stored in the vault's username field thereafter."},
              "signin_link": {"type": "string", "description":
                              "The full 'Sign in to Enable Banking' URL, "
                              "COPIED (not clicked) from the operator's own "
                              "mail client. Single-use, expires in ~1 h."},
              "resend": {"type": "boolean", "description":
                         "Send a fresh sign-in email even if one was sent "
                         "in the last 15 minutes."}}})
def bank_feed_signin(args: dict) -> str:
    """The argument-carrying half of setup, split out so casa's setup tool
    can keep the argument-free contract its automatic dispatch assumes
    (issue #7). Every argument here is the OPERATOR's own text, relayed:
    the account email, the sign-in URL they copied out of their mailbox,
    and a resend flag. It runs the whole ladder because the paste is a
    resume point, not a step — 'everything after that paste is automatic'
    is only true if the same call continues.

    Unprotected for the same reason `setup_bank_feed` is (module docstring):
    it reaches exactly the same rungs, all additive and idempotent, and the
    one argument that would be dangerous — a redirect URI — is not on offer
    here or anywhere else in this module."""
    return _reconcile(args)


@register("accept_app_reregistration",
          "Accept re-registering the Enable Banking application after "
          "setup_bank_feed reports the previously bound one VANISHED from "
          "the control panel. Protected: casa demands an operator "
          "confirmation. Every bank must be re-linked afterwards.",
          {"type": "object", "properties": {}})
def accept_app_reregistration(args: dict) -> str:
    """Argument-free on purpose: the acceptance binds to the RECORDED
    vanished binding, read here — nothing model-suppliable selects what
    is being authorized. The marker is consumed by the successful
    registration that replaces the binding, never before — the marker
    guards until success."""
    refusal = _require_declared("accept_app_reregistration")
    if refusal:
        return refusal
    c = _conn()
    recorded = _meta_get(c, "setup.app_id")
    if not recorded:
        return ("Nothing to accept: no application binding is recorded, "
                "so the next setup_bank_feed run is an ordinary first "
                "install and needs no authorization.")
    try:
        apps = _admin().applications()
    except Exception as exc:                     # noqa: BLE001
        return ("Could not verify the application's absence (%s) — "
                "refusing to record an acceptance for a state that may "
                "not exist. Nothing was changed." % type(exc).__name__)
    ids = {str(a.get("app_id") or a.get("kid") or "") for a in apps}
    if recorded in ids:
        return ("The bound application (%s) is still registered — "
                "nothing has vanished, so there is nothing to accept and "
                "no authorization was recorded. (A pre-recorded "
                "acceptance would silently authorize a FUTURE vanish.)"
                % _safe(recorded))
    _meta_set(c, "setup.rereg_accepted", recorded)
    return (("Re-registration is now authorized for the vanished "
             "application %s — bound to exactly that binding, consumed "
             "by the registration that replaces it. Run setup_bank_feed "
             "to proceed; every bank must be re-linked afterwards. %s")
            % (_safe(recorded), GATE_NOTE))


@register("list_banks",
          "List the banks (ASPSPs) available in a country, with their PSU types "
          "and consent ceiling.",
          {"type": "object",
           "properties": {"country": {"type": "string", "default": "NL"}}})
def list_banks(args: dict) -> str:
    country = str(args.get("country") or "NL").upper()
    banks = _ais().aspsps(country)
    lines = ["Banks available in %s (%d)." % (_safe(country), len(banks))]
    for bank in banks:
        ceiling = bank.get("maximum_consent_validity")
        ceiling_days = int(ceiling) // 86400 if ceiling else None
        # Every field here is the PROVIDER's catalogue text, so every field is
        # neutralised: the row format is line-oriented and a name carrying a
        # newline would forge a bank that does not exist.
        lines.append("  %s — psu_types: %s; consent ceiling %s" % (
            _safe(bank.get("name")),
            ", ".join(_safe(p) for p in (bank.get("psu_types") or []))
            or "unknown",
            ("%d days" % ceiling_days) if ceiling_days else "unknown"))
    lines.append("This plugin always requests %d days of validity — the ceiling "
                 "check is strict, so exactly 180 days is rejected."
                 % CONSENT_DAYS)
    return "\n".join(lines)


# --------------------------------------------------------------------------
# linking
# --------------------------------------------------------------------------

def _bank_key(record) -> tuple:
    """The comparable identity of a BANK: `(aspsp, country)`, normalised.

    Used to compare two records that both claim to name one bank — an attempt
    row, a session row, or the ASPSP block of a provider payload — all of which
    carry `aspsp_name` / `country` once shaped that way.

    Normalisation is not cosmetic. `link_bank` upper-cases the country and the
    provider echoes back whatever it likes; a provider name arrives with
    different case and internal spacing from the catalogue than from the
    session payload. Comparing raw strings would report drift that is not
    drift — and the obvious "fix" for that false alarm is to trust the returned
    value, which is the exact substitution this repair removes.
    """
    return (" ".join(str(record.get("aspsp_name") or "").split()).casefold(),
            str(record.get("country") or "").strip().upper())


def _consent_key(record) -> tuple:
    """The comparable identity of a CONSENT: `(aspsp, country, psu_type)`.

    The bank key plus the third dimension. `psu_type` is ours — it is minted
    into the attempt and stored on the session, and no provider payload carries
    it — so it is compared exactly rather than normalised.
    """
    return _bank_key(record) + (str(record.get("psu_type") or ""),)


def _renewable_session(c, aspsp: str, country: str, psu_type: str):
    """The consent a second `link_bank` would RENEW, or None.

    **It was `_renewable_session`, and the name was the bug's hiding place (issue
    #6).** Nothing flips `sessions.status` away from `AUTHORIZED` when a consent
    expires — expiry happens at the bank, on a clock, with no local event — so
    an expired row satisfies every clause below and is returned by this
    function. That is CORRECT and deliberate (see the next paragraph); what was
    wrong is that a function called "the live session" was believed by every
    caller, and three separate messages went on to say "live", in the present
    tense, about a consent whose validity was behind us. The row is *renewable*.
    Only `valid_until` says whether it is live, `_expiry_state` is the one
    predicate that reads it, and callers that make a claim about the bank must
    ask it rather than infer liveness from arriving here.

    **An expired consent is renewed, not re-linked from scratch, and the
    alternative was tried on paper and rejected.** Excluding expired rows here
    would make the re-link a first link, and `apply.upsert_account`'s rebinding
    backstop then refuses every account already bound to the old session — so
    the new consent is quarantined, and an expired bank can never be re-linked
    at all. That is the exact remedy `consent_status` now hands the operator for
    an expired consent (issue #5, item 6), and it would fail in place. Renewal
    also keeps what that message promises: labels, categories, include flags,
    coverage and history key on `account_id`, and `flows.complete_renewal` is
    the only thing that carries them across a consent boundary.

    The consequence — a `delete_session` owed to a consent the provider may have
    already dropped — is left in place on purpose. Skipping it on the strength
    of a local date is the one failure this codebase treats as unrecoverable: if
    `valid_until` is stale, absent or misparsed, we would close the row while
    the grant is still live at the bank, with no handle left to withdraw it. A
    wasted DELETE costs one call; the messages either side of it now tell the
    truth about an expired consent, which is what the false narrative actually
    needed.

    ALL THREE DIMENSIONS, and none of them optional. A consent
    is identified by `(aspsp, country, psu_type)`: `_start_auth` mints all
    three and every attempt row carries them. Matching on the provider NAME
    alone made Rabobank BE look like a renewal of Rabobank NL. The exact
    account-set comparison then fails safe and switches nothing — but the
    consequence is that the second consent can never be linked at all, and
    every attempt leaves one more quarantined consent live at the bank.

    Country is compared case-insensitively because `link_bank` upper-cases it
    while the provider echoes back whatever it likes; the two must not disagree
    about whether a consent already exists.

    Quarantined sessions — and consents whose revocation failed — are excluded
    by the status filter: neither is something to renew.

    The live status is `callbacks.LIVE_SESSION_STATUS`, bound as a parameter and
    never spelled as a SQL literal. It was `status='AUTHORIZED'` — the only
    hardcoded copy of that constant in this file, in a module whose own comments
    forbid exactly this twice. It is not cosmetic: `outstanding_consents` reads
    the constant, so a rename upstream would have made this function stop
    finding the live consent (no renewal) WHILE the sibling stopped listing it
    as outstanding (no warning), and `link_bank` would have minted a second live
    consent at the bank in silence — consent accumulation, arrived at through
    a one-word divergence.
    """
    row = c.execute(
        "SELECT session_id, generation, valid_until FROM sessions"
        " WHERE aspsp_name=? AND UPPER(COALESCE(country,''))=UPPER(?)"
        " AND COALESCE(psu_type,'')=? AND closed_at IS NULL"
        " AND COALESCE(status,'')=?"
        " ORDER BY generation DESC, authorized_at DESC LIMIT 1",
        (aspsp, str(country or ""), str(psu_type or ""),
         callbacks.LIVE_SESSION_STATUS)).fetchone()
    return None if row is None else dict(row)


def outstanding_consents(c, aspsp: str, country: str, psu_type: str) -> list:
    """Every consent for this exact bank the BANK still holds and we do not use.

    This warning has twice been found unable to see the case it most needed
    to. Named `unrevoked_sessions`, it enumerated the two
    `REVOCATION_INCOMPLETE_STATUSES`, so a **quarantined** consent was
    invisible to it — and quarantine is the commonest way one is left
    behind. A failed verification and a capped renewal each leave a real
    provider consent with nothing bound to it; `link_bank` then went on minting
    a second one beside it in silence, which is precisely the accumulation this
    warning exists to stop.

    So the rule is now the INVERSE of a list, not a longer list: a row that is
    still open (`closed_at IS NULL`) and is not `AUTHORIZED` is a permission the
    bank holds and we are not using. Any further stopped state added later is
    covered by construction, instead of having to be remembered in a second
    place — which is exactly how `REVIEW_REQUIRED` came to be missing.

    `AUTHORIZED` is the one exclusion, and it is not an omission: such a row is
    either the consent this call is about to renew (named as a renewal, not as
    debris) or a live consent for another PSU type this call does not touch.

    The `status` comes back with each row because the caller has to say what
    actually happened. A quarantined consent was never the subject of a failed
    revocation, and telling the operator that a revocation failed when none was
    attempted is the kind of wrong detail that teaches people to stop reading
    warnings.

    `valid_until` comes back for the same reason (issue #6). The note this feeds
    tells the operator the bank STILL HOLDS a permission, and that sentence is
    the one thing here that expiry falsifies: a lapsed consent is not a standing
    grant, and sending someone to a bank consent screen to withdraw it is a
    wasted errand. The date is on the row; not selecting it was what left the
    caller nothing to branch on.

    It does not BLOCK: the operator may well want the new link anyway, and a
    tool that refuses to work until an unrelated cleanup succeeds is how people
    learn to route around it.
    """
    return [dict(r) for r in c.execute(
        "SELECT session_id, status, valid_until FROM sessions"
        " WHERE aspsp_name=? AND UPPER(COALESCE(country,''))=UPPER(?)"
        " AND COALESCE(psu_type,'')=? AND closed_at IS NULL"
        " AND COALESCE(status,'') <> ? ORDER BY authorized_at",
        (aspsp, str(country or ""), str(psu_type or ""),
         callbacks.LIVE_SESSION_STATUS))]


def _outstanding_note(status: str, aspsp: str, ref: str, mismatch=None,
                      valid_until=None) -> str:
    """What to tell the operator about ONE outstanding consent.

    Status-appropriate wording, because the states got there by different
    routes and only one of them involved a revocation at all. Both notes carry
    the same two facts — the bank still holds a permission, and linking now
    adds a second one beside it — and the same `consent_ref`, so the remedy is
    the identical call either way.

    A third shape needs its own note, and it is the one where saying the wrong
    thing costs the most. When the quarantined consent came from a renewal the bank's
    account set had moved under, the operator is ABOUT TO REPEAT IT — this note
    is printed immediately before the URL of another `purpose=renew` attempt
    that will refuse identically and leave one more consent at the bank. So it
    says so here, before the URL, rather than leaving the operator to discover
    it from `consent_status` after the third attempt.
    """
    # Issue #6. Read once, before the three branches, because all three make a
    # claim about what the BANK holds and all three can be handed a row whose
    # validity has passed — a quarantine sits until someone acts on it, and a
    # renewal is how an expired consent reaches a failed revocation.
    state, value = _expiry_state(valid_until)
    if mismatch is not None:
        # "While your old consent is live": the clause is a liveness
        # claim, and the thing it is actually establishing is that link_bank
        # will be a RENEWAL — which is true of an expired consent too, since
        # `_renewable_session` deliberately still finds one. So the neutral
        # phrasing is the accurate one in every state, and it costs the live
        # case nothing.
        return "\n".join([
            "WARNING — LINKING %s AGAIN WILL STOP THE SAME WAY IT DID LAST "
            "TIME. The previous attempt was a renewal, and it was refused "
            "because the bank's account set is no longer the one you linked; "
            "the consent it created was left at the bank. While that consent is "
            "the one recorded here this call is another RENEWAL, so it will be "
            "refused again and leave another consent behind."
            % _safe(aspsp)] + _mismatch_lines(mismatch, ref) + [
            "  Nothing below is blocked on that — the URL is still minted if "
            "you want it — but it is very unlikely to be what you want."])
    if status == callbacks.REVIEW_REQUIRED_STATUS:
        if state == EXPIRED:
            return ("WARNING — AN EARLIER AUTHORIZATION FOR %s LEFT A CONSENT "
                    "BEHIND, AND ITS VALIDITY HAS SINCE PASSED (%s). It was "
                    "quarantined rather than linked, so nothing here is bound "
                    "to it, and no revocation was ever attempted on it — so "
                    "the bank very likely holds nothing now, and what is left "
                    "is the record here. Run unlink_bank consent_ref=%s to "
                    "clear it; consent_status describes it. Nothing below is "
                    "blocked on that." % (_safe(aspsp), _ago(value), ref))
        if state == UNKNOWN:
            # No date, so no claim about the term — but a quarantined consent
            # was really created at the bank and no revocation was attempted on
            # it, and THAT is observed. It is the half worth saying.
            return ("WARNING — AN EARLIER AUTHORIZATION FOR %s LEFT A CONSENT "
                    "AT THE BANK. It was quarantined rather than linked, so "
                    "nothing here is bound to it and no revocation has been "
                    "attempted on it; how long it is valid for is not recorded "
                    "here, so whether the bank still holds it cannot be said "
                    "from here. Run unlink_bank consent_ref=%s to withdraw it; "
                    "consent_status describes it. Nothing below is blocked on "
                    "that." % (_safe(aspsp), ref))
        return ("WARNING — AN EARLIER AUTHORIZATION FOR %s LEFT A CONSENT THE "
                "BANK STILL HOLDS. It was quarantined rather than linked "
                "(either the accounts it returned were not the ones approved, "
                "or its history fetch did not finish), so nothing here is bound "
                "to it — but it is a real permission at the bank, no revocation "
                "has been attempted on it, and linking now adds a second one "
                "beside it. Run unlink_bank consent_ref=%s to withdraw it; "
                "consent_status describes it. Nothing below is blocked on that."
                % (_safe(aspsp), ref))
    # Everything this last note says follows from the failed revocation EXCEPT
    # the standing grant, which follows from the consent's validity — and a
    # renewal is exactly how an already-expired consent reaches REVOKE_FAILED,
    # so this is not a hypothetical row. The remedy is unchanged (the ref still
    # reaches it, and clearing the local row is still worth doing); what changes
    # is that the operator is not sent to a bank consent screen to withdraw a
    # permission that lapsed on its own.
    if state == EXPIRED:
        # "and this is a local record rather than a standing grant" was the
        # overclaim: a past date plus an UNCONFIRMED withdrawal is two
        # pieces of weak evidence, not a proof. Both are stated, neither is
        # promoted to a conclusion.
        return ("WARNING — AN EARLIER CONSENT FOR %s WAS NOT WITHDRAWN, AND ITS "
                "RECORDED VALIDITY HAD ALREADY PASSED (%s). This plugin tried "
                "to revoke it and could not (status %s), so the withdrawal was "
                "never confirmed — but its validity is behind us, so the bank "
                "most likely no longer holds it. Retry unlink_bank "
                "consent_ref=%s to settle it. Nothing below is blocked on that."
                % (_safe(aspsp), _ago(value), _safe(status), ref))
    if state == UNKNOWN:
        # A three-state predicate whose callers still branch two ways is the
        # original defect wearing a new shape: this row is `REVOKE_FAILED` with
        # no readable `valid_until` — production- reachable, since a quarantine
        # is recorded with NULL and a failed unlink turns it into this status —
        # and it printed "IS STILL LIVE AT THE BANK" while `link_bank`'s own
        # renewal line, two states richer, said the term was not recorded. Same
        # row, same turn, opposite claims.
        return ("WARNING — AN EARLIER CONSENT FOR %s WAS NOT WITHDRAWN. This "
                "plugin tried to revoke it and could not (status %s), and how "
                "long it is valid for is not recorded here — so whether the "
                "bank still holds it cannot be said from here, and if it does, "
                "linking now adds a second one beside it. Retry unlink_bank "
                "consent_ref=%s first if you meant to clear it. Nothing below "
                "is blocked on that." % (_safe(aspsp), _safe(status), ref))
    return ("WARNING — AN EARLIER CONSENT FOR %s IS STILL LIVE AT THE BANK. "
            "This plugin tried to revoke it and could not (status %s), so the "
            "bank still holds that permission and linking now adds a second one "
            "beside it. Retry unlink_bank consent_ref=%s first if you meant to "
            "clear it. Nothing below is blocked on that."
            % (_safe(aspsp), _safe(status), ref))


def _bound_accounts(c, session_id: str) -> dict:
    """`{account_id: incarnation}` for every account bound to a session.

    ONE statement, deliberately: `_renewal_precondition` validates the
    renewal's exact account set against the keys and captures the issue-#8
    life tokens from the values — the same read for both, so there is no
    window in which the set was validated against one life and the tokens
    read from another.
    """
    return {r[0]: r[1] for r in c.execute(
        "SELECT account_id, incarnation FROM accounts WHERE session_id=?",
        (session_id,))}


def _bound_account_ids(c, session_id: str) -> set:
    return set(_bound_accounts(c, session_id))


def renewal_target(c, aspsp: str, country: str, psu_type: str):
    """`(account_id, session)` to fence a renewal against, or `(None, None)`.

    Takes the same three dimensions as `_renewable_session` for the same
    reason: the question "is this a renewal?" is asked about a consent, and a
    consent is `(aspsp, country, psu_type)`.

    The fence names ONE account, and every account on a session shares that
    session's generation, so any bound account is an equally good witness —
    `min` only makes the choice deterministic. A live session with nothing
    bound to it is not renewable: there is no generation to be stale against,
    and `_start_auth` would rightly refuse to mint an unfenced attempt.
    """
    prior = _renewable_session(c, aspsp, country, psu_type)
    if not prior:
        return None, None
    bound = _bound_account_ids(c, prior["session_id"])
    return (min(bound) if bound else None), prior


def current_generation(c, account_id: str):
    """The generation of the session an account is bound to RIGHT NOW.

    None when the account is unknown or unbound — a first link has nothing to
    be stale against. `callbacks.fence_verdict` does NOT treat a missing value
    as unfenced for a `renew` or `repair` attempt — it refuses it outright as
    `unfenced_repair` — which is why `_start_auth` raises rather than minting
    one, and why this returning None for a targeted account is a bug, not a
    soft pass.
    """
    row = c.execute(
        "SELECT s.generation AS generation FROM accounts a"
        " JOIN sessions s ON s.session_id = a.session_id"
        " WHERE a.account_id = ?", (account_id,)).fetchone()
    if row is None or row["generation"] is None:
        return None
    return int(row["generation"])


def _fenced_prior(c, attempt: dict):
    """The consent a RENEWAL is renewing, resolved from the FENCE.

    Not from the returned session — that is the whole point. `_exchange` used
    to ask `_renewable_session` for a live consent under the ASPSP and country
    the provider had just echoed back, so a drifted, malformed or mis-fixtured
    value made the lookup miss, `prior` became None, and a `purpose="renew"`
    attempt walked into the first-link branch with the exact-set comparison
    skipped. The generation fence did not catch it: it verifies the target
    account's generation, not the returned bank identity.

    The attempt is the authority. `_start_auth` minted `account_id` and
    `expected_generation` at the moment `link_bank` decided this was a renewal,
    `callbacks.mint` persisted them, and `callbacks.fence_verdict` has already
    refused the attempt outright if either is absent or the account has since
    been bound by a higher generation. So the old session is exactly "the
    session that account is bound to, at the generation this attempt was minted
    against" — a question the provider cannot answer wrongly because it is
    never asked.

    Returns None — never a guess — when the fence is absent, the account is
    unbound, the generation has moved, or the session is no longer live. Every
    one of those means "this is not the renewal that was authorized", and the
    caller's only correct response is to refuse and leave the consent
    quarantined.
    """
    account_id = attempt.get("account_id")
    expected = attempt.get("expected_generation")
    if not account_id or expected is None:
        return None
    row = c.execute(
        "SELECT s.session_id AS session_id, s.aspsp_name AS aspsp_name,"
        " s.country AS country, s.psu_type AS psu_type, s.status AS status,"
        " s.generation AS generation, s.valid_until AS valid_until"
        " FROM accounts a JOIN sessions s ON s.session_id = a.session_id"
        " WHERE a.account_id = ?", (account_id,)).fetchone()
    if row is None:
        return None
    prior = dict(row)
    if prior["generation"] is None or int(prior["generation"]) != int(expected):
        return None
    if str(prior["status"] or "") != callbacks.LIVE_SESSION_STATUS:
        return None
    return prior


def _start_auth(c, aspsp: str, country: str, psu_type: str, purpose: str, *,
                account_id: str | None = None) -> str:
    """Mint an authorization, WITH the generation fence when it has a target.

    A defect shape this module has met more than once: `attempts` carries
    `account_id` and `expected_generation`, `callbacks.mint` writes them from
    `meta`, and `callbacks.fence_verdict` reads them — but if this function,
    the only production producer, mints neither, every production attempt is
    unfenced and only the tests' hand-written attempt rows carry the columns.

    The fence therefore lives HERE, in the producer, and is minted through
    `callbacks.META_COLUMNS`'s own key names. `generation` is read at mint
    time: it is the binding this callback expects to find when it comes back,
    and a newer one means a renewal has overtaken it.

    An `account_id` naming an account we cannot resolve a generation for is a
    programming error, not a fence to skip: a renewal that silently minted an
    unfenced attempt is precisely what this repair removes. It raises.

    The redirect URI is `entry["redirect_uri"]` — casa's own, discovered — for
    BOTH the mint and the provider call, and it is the same string
    `setup_bank_feed` registers on the application. Three consumers, one
    source, byte for byte.
    """
    entry = _entry()
    if not entry:
        raise RuntimeError("callback is not routed; run setup_bank_feed")
    generation = None
    if account_id:
        generation = current_generation(c, account_id)
        if generation is None:
            raise RuntimeError(
                "refusing to mint an unfenced %s attempt for %s: the account "
                "has no bound session generation to fence against"
                % (purpose, account_id))
    sp = CB.spool()
    # Every key `callbacks.META_COLUMNS` maps to an attempt column, minted
    # explicitly — including the two that are None for a first link, so a
    # missing key can never be mistaken for a deliberate absence.
    meta = {"aspsp": aspsp, "country": country, "psu_type": psu_type,
            "purpose": purpose, "account_id": account_id or None,
            "generation": generation}
    state = CB.mint(c, sp, entry["plugin_dir"], meta, entry["redirect_uri"])
    result = _ais().start_auth(aspsp, country, psu_type, state,
                               entry["redirect_uri"], valid_days=CONSENT_DAYS)
    return result.get("url") or ""


# Stated BEFORE the operator taps anything. After the window closes the
# only remedy is another full authorization, so this has to be a choice they
# made rather than a surprise they were handed.
_SHALLOW_WARNING = (
    "Before you tap: approving reopens this bank's deep-history window for "
    "only a few minutes. casa redelivers the result on its own durable "
    "schedule, and if that delivery is delayed past the window, the first sync "
    "may reach only a recent slice of the history instead of all of it — "
    "recovering the rest would then need another link and another set of "
    "taps. That risk is "
    "not ours to remove (casa#399 tracks a delivery guarantee); it is stated "
    "here so approving now is an informed choice.")


@register("link_bank",
          "Start a bank authorization: returns the URL to tap. Returns "
          "immediately; casa redelivers the result, this plugin never polls.",
          {"type": "object",
           "properties": {"aspsp": {"type": "string"},
                          "country": {"type": "string", "default": "NL"},
                          "psu_type": {"type": "string",
                                       "enum": ["personal", "business"]}},
           "required": ["aspsp", "psu_type"]})
def link_bank(args: dict) -> str:
    c = _conn()
    aspsp = str(args.get("aspsp") or "")
    country = str(args.get("country") or "NL").upper()
    psu_type = str(args.get("psu_type") or "personal")
    app_id = os.environ.get("CASA_BANKFEED_EB_APP_ID") or ""

    # The world guard, BEFORE tap 1 can whitelist or link against the
    # id: a mis-wired install must refuse here, not after the admin path
    # has already written to another world's application. Both modes; the
    # admin client it verifies with is the one tap 1 needs anyway.
    try:
        _assert_world(app_id, admin=_admin())
    except WorldMismatch as exc:
        return ("Linking has NOT been started: %s" % exc)
    except Exception as exc:                     # noqa: BLE001
        # Same remedy wording as the whitelist stop below: this check rides
        # the same credential, so the same fix (usually a fresh pasted
        # token) clears both.
        return ("Cannot verify which world the configured application "
                "lives in (%s), so linking has NOT been started — "
                "nothing touches an unverified application. Remedy: "
                "check %s — it expires after about an hour, and "
                "re-pasting a fresh one is the usual fix. Then run "
                "link_bank again." % (type(exc).__name__, ADMIN_TOKEN_VAR))

    # Tap 1 of 2 — the whitelist, if this bank is not on it yet. PRODUCTION
    # ONLY (issue #10): account whitelisting is the provider's activation
    # mechanism for production applications, and `link_accounts` is a
    # Control-Panel operation whose authentication session is initiated by
    # the Control Panel's OWN application — the `appId` in the form only
    # names which app's whitelist gains the account, it does not govern
    # which world the session routes to, and the session was measured
    # landing on the real bank's live login. Sandbox applications activate
    # automatically, so in sandbox the gate is doubly wrong: it routes to
    # the real world, for a step the sandbox world does not require. The
    # gate therefore does not exist in sandbox at all — no whitelist read,
    # no CP session, straight to the app-JWT authorization below, whose
    # identity carries the SANDBOX environment.
    if not ebmode.is_sandbox():
        try:
            missing = flows.needs_whitelist(_admin(), app_id, aspsp, country)
        except Exception as exc:                     # noqa: BLE001
            # STOP. Carrying on would mint a consent, which spends a real bank
            # approval — SCA taps and a minutes-wide deep-history window — on a
            # session that will very likely return zero accounts because the
            # ASPSP was never whitelisted. Paying the cost and not gaining the
            # information is the worst available outcome.
            return "\n".join([
                "Cannot check the whitelist for %s (%s), so linking has NOT "
                "been started. Nothing has been started, nothing was minted, "
                "and no bank approval was spent."
                % (_safe(aspsp), type(exc).__name__),
                "Why this stops rather than continuing: whitelisting is what "
                "makes the bank return accounts at all. Authorizing without "
                "it costs you the SCA taps and the few-minutes-wide "
                "deep-history window, and very likely returns nothing.",
                "Remedy: check %s — it is the Enable Banking control-panel "
                "token, it expires after about an hour, and re-pasting a "
                "fresh one is the usual fix. Then run link_bank again."
                % ADMIN_TOKEN_VAR,
            ])
        if missing:
            url = (_admin().link_accounts(app_id, aspsp, country, psu_type)
                   or {}).get("url") or ""
            return ("Linking %s takes two taps. This is tap 1 of 2 — the "
                    "account whitelist.\n%s\n"
                    "That link ends on an Enable Banking page: nothing comes "
                    "back to our callback, so completion is confirmed by "
                    "re-reading the whitelist, never assumed. When you have "
                    "finished it, call link_bank again for tap 2 (the bank's "
                    "own approval).\n"
                    "The turn ends here — nothing is waiting on you."
                    % (_safe(aspsp), _safe_url(url)))

    # A bank that already holds a live consent is being RENEWED,
    # not linked for the first time. The distinction is not cosmetic — it
    # selects `purpose="renew"`, which is what makes the generation fence
    # mandatory on both sides, and it is what the operator is actually doing.
    target, prior = renewal_target(c, aspsp, country, psu_type)
    if prior is not None and target is None:
        # A live session with nothing bound to it. Renewing it would mint an
        # unfenced attempt, and there is nothing to carry forward anyway.
        return ("%s has a consent recorded with no accounts bound to it, so "
                "there is nothing to renew and a fresh link would collide with "
                "it. Run consent_status, revoke it with unlink_bank, then run "
                "link_bank again." % _safe(aspsp))

    # The consent-accumulation case. A consent that is open but not
    # `AUTHORIZED` — quarantined, or one whose revocation did not complete — is
    # NOT something the code above can renew, so this is correctly a first
    # link; but the bank still holds that permission, and minting a second one
    # beside it silently is how they pile up. Named, with the ref that clears
    # it, and then we proceed: the operator may want this link regardless, and
    # blocking on an unrelated cleanup is how a tool gets routed around.
    preface = [
        _outstanding_note(str(row.get("status") or ""), aspsp,
                          _consent_ref(row["session_id"]),
                          renewal_mismatch(c, row["session_id"]),
                          row.get("valid_until"))
        for row in outstanding_consents(c, aspsp, country, psu_type)]

    url = _start_auth(c, aspsp, country, psu_type,
                      "renew" if prior else "link", account_id=target)
    if prior:
        # Issue #6. `_renewable_session` returns an expired consent — correctly,
        # since renewal is the path that carries everything forward — so THIS
        # sentence is where an expired row used to be announced as "a live
        # consent … with -3 days left on it": a liveness claim and a negative
        # duration, about a consent that lapsed at the bank days ago. The branch
        # is right; only the tense was wrong.
        #
        # Three states, and this is the line where the missing third one printed
        # the strongest unearned claim: an AUTHORIZED row with no
        # usable `valid_until` is a consent we watched being authorized and were
        # never told the term of, so "you already have a live consent" rested on
        # nothing. The date is what we have; when we do not have it, say that.
        state, value = _expiry_state(prior.get("valid_until"))
        if state == EXPIRED:
            standing = ("Your consent for this bank EXPIRED %s"
                        % _ago(value).upper())
        elif state == UNKNOWN:
            standing = ("You already have a consent for this bank, and how long "
                        "it is valid for is not recorded here")
        else:
            standing = ("You already have a live consent for this bank, with "
                        "%d days left on it" % value)
        return "\n".join(preface + [
            "Renewing %s (%s, %s). %s, and this replaces it — it is the same "
            "%s as the original link." % (
                _safe(aspsp), _safe(country), _safe(psu_type), standing,
                "single-tap approval" if ebmode.is_sandbox()
                else "two-tap approval"),
            "Your labels, categories, include flags, coverage and full "
            "transaction history all carry forward untouched: they key on an "
            "account id derived from the IBAN and currency, which does not "
            "change when the consent does. Nothing is re-imported or "
            "renumbered.",
            _SHALLOW_WARNING,
            _safe_url(url),
            "Tap it within 30 minutes — the pending authorization expires "
            "1800 s after it was minted.",
            # The refusal branch's own consequence, and the second place the
            # expired case had to be told apart (issue #6): the old consent
            # stays BOUND either way — that is what makes the ledger keep
            # answering — but "stays live" is a claim about the bank, and for a
            # lapsed consent it is false. Nothing about the refusal changes.
            "On collection: the new consent's accounts must match the ones you "
            "have exactly. They will, unless the bank has added or removed an "
            "account since you linked it — in which case nothing is switched, "
            "your OLD consent stays bound%s, and consent_status tells you what "
            "differed. The old consent is only retired once the new one's "
            "history fetch is durably complete."
            % {EXPIRED: " (its recorded validity has passed, so it cannot be "
                        "relied on to keep serving answers)",
               UNKNOWN: " (how long it is valid for is not recorded here, so "
                        "whether it keeps serving answers is not something "
                        "this turn can tell you)",
               LIVE: " and live"}[state],
            "The turn ends here. This plugin never polls or waits: when the "
            "redirect lands, casa dispatches a fresh turn on its own durable "
            "schedule, and that turn should call collect_authorization.",
        ])
    if ebmode.is_sandbox():
        opening = (
            "Linking %s (%s, %s) takes one tap in sandbox mode: there is no "
            "whitelist step here — sandbox applications activate "
            "automatically — so this is the bank approval itself, against "
            "the provider's sandbox with its published test credentials."
            % (_safe(aspsp), _safe(country), _safe(psu_type)))
    else:
        opening = (
            "Linking %s (%s, %s) takes two taps. Tap 1 — the account "
            "whitelist, which ends on an Enable Banking page with nothing "
            "coming back to our callback — is already satisfied. This is "
            "tap 2 of 2, the bank's own approval."
            % (_safe(aspsp), _safe(country), _safe(psu_type)))
    return "\n".join(preface + [
        opening,
        _SHALLOW_WARNING,
        _safe_url(url),
        "Tap it within 30 minutes — the pending authorization expires 1800 s "
        "after it was minted, and a fresh link must then be created.",
        "The URL is a one-time credential; it is not logged or repeated.",
        "The turn ends here. This plugin never polls or waits: when the "
        "redirect lands, casa dispatches a fresh turn on its own durable "
        "schedule, and that turn should call collect_authorization.",
    ])


class _FencedAIS:
    """The AIS client, with a lease heartbeat on every transactions page.

    The lease contract requires the injected exchange to heartbeat between
    transaction pages, but `flows.backfill` owns the pagination loop and takes
    no hook. Wrapping the one call it makes per page puts the beat exactly where
    the contract asks for it, without flows growing a parameter for our benefit.

    A known residual: a single slow page can still outlast the lease between
    two beats. Closing it needs a protocol split, not a wrapper.
    """

    def __init__(self, inner, conn, state_hash, fence):
        self._inner = inner
        self._conn = conn
        self._state_hash = state_hash
        self._fence = fence

    def beat(self) -> None:
        """Prove we still hold the lease. `Indeterminate` MUST propagate:
        stopping mid-way with the fence lost is correct, continuing is the
        corruption."""
        CB.heartbeat(self._conn, self._state_hash, self._fence)

    def transactions(self, uid, date_from, continuation_key=None):
        self.beat()
        return self._inner.transactions(uid, date_from, continuation_key)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _renewal_precondition(c, attempt: dict, returned_ids: set, *,
                          session_id: str, offered: dict):
    """The old consent this renewal switches away from, or None to REFUSE.

    Everything a renewal must be true about, in the one place, and it runs
    while the ledger is still shut — before `declare_verified` — so a refusal
    is atomic: nothing has been written and nothing can be.

    Three questions, and a None from any of them is the same answer:

    1. **Which consent is being renewed?** `_fenced_prior` resolves it from the
       attempt's own fence, never from the returned session.
    2. **Is it the bank this attempt was minted for?** The fence names an
       account, not a bank, so a target whose session somehow names a different
       consent is a refusal rather than an assumption. Belt and braces over (1),
       and cheap.
    3. **Is the account set exactly the one already bound?** An exact
       `account_id` match carries labels and history forward; anything else
       stops for operator review. `apply.upsert_account` would refuse each
       account anyway, but it fires per account — the first would already be
       bound before the second refused. Asking about the whole set here is what
       makes the refusal atomic and lands it in `review_required` rather than
       `indeterminate`.

    `session_id` and `offered` exist only for question 3's REPORT: a refusal
    here is a routine, recoverable event (the bank added an account) and the
    operator has to be told which accounts differed and which call unblocks
    them. `offered` maps the returned `account_id`s to the provider's own names,
    because an account that is not bound has no row to read a name from.
    """
    prior = _fenced_prior(c, attempt)
    if prior is None:
        return None
    if _consent_key(prior) != _consent_key(attempt):
        return None
    bound_map = _bound_accounts(c, prior["session_id"])
    bound = set(bound_map)
    if bound != returned_ids:
        record = record_renewal_mismatch(
            c, session_id, prior=prior, attempt=attempt, bound=bound,
            returned=returned_ids, offered=offered)
        _MISMATCHES.append({"state_hash": attempt.get("state_hash"),
                            "session_id": session_id, "record": record})
        return None
    # The issue-#8 life tokens ride WITH the validation that captured them:
    # the renewal's every later write (each backfill, and the switch) is
    # conditioned on these exact values, so an account forgotten — or
    # forgotten and re-linked — after this read can only make those writes
    # refuse, never land the old life's pages under a new one.
    prior = dict(prior)
    prior["incarnations"] = bound_map
    return prior


def _bind_renewal(c, fenced, attempt, *, records, session_id, secret, prior):
    """Switch an existing binding onto the new consent. Returns
    `(complete, renewal_result)`.

    `flows.complete_renewal` is THE renewal entry point — never
    `apply.switch_bindings` directly. The split makes the required ordering
    visible: the deep fetch on the NEW session must be durably committed
    *before* the switch begins, and a single call that both fetched and
    switched could not express that to us. It runs the backfill to exhaustion
    and only then the one switch transaction.

    The priority claim is held across the WHOLE call, not per backfill: the
    fetch and the switch are one authorization-time operation and an ordinary
    read refresh must not interleave with it.
    """
    with contextlib.ExitStack() as stack:
        for record in records:
            stack.enter_context(authorization_priority(c, record["account_id"]))
        fenced.beat()
        result = flows.complete_renewal(
            c, fenced, old_session_id=prior["session_id"],
            new_session_id=session_id, accounts=records, secret=secret,
            incarnations=prior.get("incarnations") or {})
    # `retired` is False when the fetch fell short, because the switch never
    # began — so the old consent is still live and still bound. The per-account
    # `sync_state` check is belt-and-braces on top: anything this cannot
    # positively read as complete is incomplete. The completeness question is
    # asked about the NEW session — that is the one `complete_renewal` fetched
    # for, and the one whose evidence the switch stands on. The old session's
    # `complete` row is still on every account and is exactly what a
    # session-blind check would credit.
    complete = bool(result.get("retired")) and all(
        backfill_complete(c, r["account_id"], result, session_id=session_id)
        for r in records)
    if not complete:
        _INCOMPLETE.append({"state_hash": attempt.get("state_hash"),
                            "bank": attempt.get("aspsp_name") or "that bank",
                            "account_id": records[0]["account_id"],
                            "session_id": session_id, "renewing": True,
                            "erased": bool(result.get("erased_accounts"))})
    return complete, result


def _bind_first_link(c, fenced, attempt, *, records, session_id, secret, prior):
    """Bind accounts to a brand-new consent. Returns `(complete, None)`.

    `prior` is always None here and is accepted only so the two binders share
    one signature — the dispatch below is what guarantees it, and a first link
    that had a prior consent to reason about would not be a first link.
    """
    complete = True
    for record in records:
        fenced.beat()
        account_id = record["account_id"]
        # A first link binds immediately. `apply.RebindRefused` is NOT caught:
        # an exchange that translated apply's exception into a verdict of its
        # own would be reporting on itself again, which is what this protocol
        # removed. On a first link it fires only if the account changed
        # identity UNDER the link (erased, or erased and re-linked, between
        # the upsert's read and its fenced write) — and then failing the
        # exchange is the honest outcome.
        #
        # The returned incarnation is the issue-#8 life token, established by
        # the upsert's own read/write — never re-read afterwards, because a
        # later SELECT can adopt a relinked life's token for pages this link
        # is about to fetch under its own uid, and every guard downstream
        # would then pass.
        _aid, incarnation = apply.upsert_account(c, record, session_id, secret)
        # Deep backfill NOW: the window closes within minutes.
        # It preempts any in-flight read refresh and consults no cooldown — an
        # ordinary question must never starve this.
        with authorization_priority(c, account_id):
            # observe=True: the first-link backfill is one of the two
            # labelled deep-observation runs reference trust can be earned
            # from (the renewal fetch is the other).
            result = flows.backfill(
                fenced, c, dict(record, account_id=account_id), session_id,
                observe=True, incarnation=incarnation)
        # The RESULT is read now rather than discarded. A capped run
        # leaves the ledger safe but loses the deep history the fresh-SCA
        # window was for, and that window does not reopen — so it must not be
        # reported as a completed link.
        if not backfill_complete(c, account_id, result, session_id=session_id):
            complete = False
            _INCOMPLETE.append({"state_hash": attempt.get("state_hash"),
                                "bank": attempt.get("aspsp_name") or "that bank",
                                "account_id": account_id,
                                "session_id": session_id, "renewing": False,
                                "erased": bool(result.get("erased"))})
    return complete, None


#: WHICH of the two an exchange performs is a LOOKUP on the attempt's own
#: minted `purpose`, and on nothing else. That is the structural half of the
#: repair. The old shape decided it with `renewing = bool(prior) and purpose ==
#: "renew"`, where `prior` came from a query keyed on values the PROVIDER had
#: just returned — so a drifted ASPSP or country turned a fenced renewal into a
#: first link, silently, with the exact-set comparison skipped and the old
#: binding overwritten. A boolean that any of three inputs can flip is not a
#: branch anyone can reason about.
#:
#: The purpose is minted by `_start_auth`, persisted by `callbacks.mint` and
#: already fenced by `callbacks.fence_verdict` before the provider is contacted;
#: the returned session is none of those things. So it decides, alone, and
#: `_bind_first_link` is simply not reachable from `purpose="renew"` — there is
#: no fallback edge to fall down.
#:
#: A purpose that is in neither key — `"repair"`, or anything a later slice
#: adds — binds NOTHING and quarantines the consent. Falling through to the
#: first-link binder is how `"repair"` would have silently created a second
#: consent for an already-linked bank, which is this same defect wearing a
#: different purpose.
_BINDERS = {"link": _bind_first_link, "renew": _bind_renewal}


def _exchange(code: str, attempt: dict) -> None:
    """Injected into casa's collection loop: code -> provider session.

    **THIS FUNCTION'S RETURN VALUE IS IGNORED.** Returning `verified: True`
    for the loop to read back cannot work: a value read *after* the call cannot
    prove the verification happened *before* the writes. `collect_one` shuts
    every canonical table with TEMP `BEFORE`
    triggers that `RAISE(ABORT, …)` and reads back only the fenced markers left
    in `attempts.outcome`. The obligations are therefore performed, in this
    order, and nothing here reports on itself:

    1. `note_session` the instant the provider returns a session id, before
       anything else. That is what makes a stranded consent recoverable,
       and `declare_verified` refuses without it.
    2. `declare_verified` once `flows.verify_accounts` has passed on the
       COMPLETE returned set — and not before, because it is the only thing
       that reopens the ledger. Until then every canonical write fails in
       SQLite, so an exchange that forgets to verify cannot bind anything.
       It reopens the ledger **staged**, not free: see 3.
    3. Insert every new session STAGED — `REVIEW_REQUIRED_STATUS` at
       `REVIEW_REQUIRED_GENERATION` — on a first link exactly as on a renewal
       alike. This function may bind accounts to that staged session;
       it may NOT make it live, and `_stage_ledger`'s trigger aborts the write
       if it tries. `collect_one` promotes a first link after this returns;
       `apply.switch_bindings` promotes a renewal inside its own transaction.
       So every path out of here — a raise, a missing verdict, a killed
       process — leaves a consent no read tool counts as a link.
    4. `heartbeat` before each ledger write and between transaction pages,
       with the token `collect_one` put in `attempt["lease_fence"]`.
    5. `declare_partial` when `flows.backfill` reports the page cap, so
       the attempt settles `partial` and never `succeeded`.

    Returning early without declaring is how this reports a refusal: no
    verdict means `review_required`, with the noted consent quarantined.

    **THE ATTEMPT NAMES THE BANK; THE RETURNED SESSION ONLY CONFIRMS IT**
    — never the other way round. Overwriting the attempt's bank and country
    with whatever the provider echoes back, verifying the whitelist against
    *those*, and then deciding whether this is still a renewal by querying for a
    live consent under them has three consequences, all from one substitution: a
    drifted ASPSP makes the lookup miss, so a fenced
    `purpose="renew"` attempt entered the first-link branch with the exact-set
    comparison skipped; the whitelist was narrowed to a bank nobody had
    approved; and the session row was written under a spelling the next
    `link_bank` would not find. The attempt's values are minted by
    `_start_auth`, persisted by `callbacks.mint` and fenced by
    `callbacks.fence_verdict`; the returned session's are none of those. So the
    attempt is used throughout, the returned pair is compared against it once —
    normalised, before verification — and a mismatch refuses.
    """
    c = _conn()
    fenced = _FencedAIS(_ais(), c, attempt.get("state_hash"),
                        attempt.get("lease_fence"))
    session = fenced.create_session(code)
    sid = session.get("session_id") or ""
    returned = session.get("aspsp") or {}
    # The bank THIS authorization was minted for. Not the returned session's.
    bank = attempt.get("aspsp_name")
    country = attempt.get("country")
    accounts = session.get("accounts") or []
    valid_until = ((session.get("access") or {}).get("valid_until")
                   or session.get("valid_until"))

    # STEP 1, before anything else. A consent now EXISTS at the bank; recording
    # which one is what lets the collector quarantine it if the rest of this
    # function fails, verifies nothing, or is killed. Recording it only in
    # a return value — or not at all — is what made a stranded consent
    # invisible to consent_status and unreachable by unlink_bank.
    CB.note_session(c, attempt, sid)

    # ---- the returned session must be the bank we asked for (R4) ----------
    # Before verification, because everything downstream is about one bank and
    # this is the question "which bank?". A mismatch is not reconciled and not
    # trusted: the consent is left quarantined, revocable by its consent_ref,
    # and nothing is bound. An ABSENT ASPSP block fails this too — silence is
    # not agreement, and a session payload that does not say which bank it is
    # for is exactly the malformed case this guard exists for.
    confirmed = {"aspsp_name": returned.get("name"),
                 "country": returned.get("country")}
    if not bank or _bank_key(confirmed) != _bank_key(attempt):
        return

    # ---- renewal or first link is decided by the ATTEMPT -----------------
    # A lookup, not a boolean, and keyed on the fenced purpose alone. See
    # `_BINDERS`: there is no edge from `purpose="renew"` to the first-link
    # binder, so the returned session can no longer degrade one into the other.
    bind = _BINDERS.get(str(attempt.get("purpose") or ""))
    if bind is None:
        return
    renewing = bind is _bind_renewal

    # ---- verify BEFORE anything is bound ---------------------------------
    app_id = os.environ.get("CASA_BANKFEED_EB_APP_ID") or ""
    try:
        admin = _admin()
        # This is link_bank's OTHER app-id resolution site — the exchange
        # re-reads the env id — so it asserts too. Cached after the link_bank
        # chokepoint, so no extra call in the normal flow; a WorldMismatch
        # lands in the same unable-to-verify-is-not-verified return below,
        # leaving the consent quarantined rather than bound.
        _assert_world(app_id, admin=admin)
        # SANDBOX has no whitelist gate (issue #10): link_bank never runs
        # tap 1 there, so there are no entries to read and nothing for the
        # verification below to compare against. The read is skipped rather
        # than tolerated-empty, so the mode carries through this call site
        # the same way it carries through link_bank's.
        listed = [] if ebmode.is_sandbox() else admin.whitelisted(app_id)
    except Exception:                            # noqa: BLE001
        # Unable to verify is NOT verified: return without declaring, and the
        # noted consent is quarantined for the operator to see and revoke.
        return
    # `aspsp` and `country` name the bank THIS authorization was for — the
    # ATTEMPT's values, checked against the returned session above — and
    # `verify_accounts` narrows the application-wide whitelist to them. Passing
    # the returned session's instead would verify a consent against a bank the
    # operator never approved. Without them the intended set defaulted to every
    # entry, so once bank A was linked bank B's session reported all of bank
    # A's IBANs as missing and bank B could never link — "one bank at a time"
    # does not help, because bank A's entry never goes away. They are
    # keyword-only with no defaults so a caller that forgets them fails loudly
    # instead of silently verifying against everything; do not pass empty
    # values to satisfy the signature. `intended` is empty: link_bank names a
    # bank, not a list of IBANs, so the whitelist entries for that bank ARE the
    # intent.
    verdict = flows.verify_accounts(accounts, listed, [], aspsp=bank,
                                    country=country,
                                    whitelist_gated=not ebmode.is_sandbox())
    if not verdict.ok:
        return

    secret = store.local_secret(c)
    records = []
    for acct in accounts:
        # The provider NESTS the IBAN: account_id.iban, never a flat `iban`.
        iban = (acct.get("account_id") or {}).get("iban")
        records.append({"uid": acct.get("uid"), "iban": iban,
                        "currency": acct.get("currency"),
                        "name": acct.get("name") or acct.get("product"),
                        # Without this the account row has no ASPSP, so
                        # provenance.capability() is asked about "" for ever
                        # after and every ingest degrades to heuristic matching.
                        "aspsp": bank,
                        "account_id": store.account_id(
                            str(iban or ""), str(acct.get("currency") or ""),
                            secret)})

    # ---- renewal COMPLETES when the set matches exactly -------------------
    # Refusing every rebinding would mean a renewal stops for review every time
    # and therefore never finishes, killing the requirement it was meant to
    # protect. The rule instead: an exact `account_id` match carries labels and
    # history forward; anything else stops for operator review. `account_id` is
    # an HMAC over IBAN + currency and is stable across sessions BY
    # CONSTRUCTION, so the happy path is exactly detectable rather than
    # guessed at.
    #
    # `_renewal_precondition` owns all of it now, and it resolves the old
    # consent from the FENCE rather than from a live-session lookup keyed on
    # returned values. It runs while the ledger is still shut,
    # so a refusal is atomic and lands in `review_required` rather than
    # `indeterminate`. A first link has no precondition and no `prior`.
    prior = None
    if renewing:
        # Fenced like every other write this function makes: the refusal
        # path records what differed, and a record written under a lease we no
        # longer hold is a record about somebody else's collection.
        fenced.beat()
        prior = _renewal_precondition(
            c, attempt, {r["account_id"] for r in records}, session_id=sid,
            offered={r["account_id"]: r.get("name") for r in records})
        if prior is None:
            return

    # Everything past here is a first link or an exact-match renewal, and both
    # are allowed to write. `declare_verified` is what makes that true: it is
    # the ONLY thing that reopens the ledger, and until it runs every canonical
    # write raises inside SQLite. Nothing above this line has written anything.
    CB.declare_verified(c, attempt)

    fenced.beat()
    # EVERY new session is inserted STAGED — a first link exactly like a
    # renewal. This function cannot make a consent live, and does not branch
    # on `renewing` to decide.
    #
    # Inserting a first link as AUTHORIZED at generation 1 instead, and
    # then bound accounts and paged a backfill in autocommit. Anything that
    # raised in there left a LIVE consent with a partial binding, and
    # `_quarantine`'s `INSERT OR IGNORE` could not undo it — the TEMP triggers
    # had closed the hole before `declare_verified` and it simply moved to just
    # after. Staging is the prevention half: `_stage_ledger` holds a trigger
    # for the rest of this call that ABORTS a `sessions` INSERT of any other
    # status, so this is enforced rather than requested.
    #
    # Promotion belongs to whoever can prove the link is finished, and there
    # are exactly two: `apply.switch_bindings` for a renewal, inside the one
    # transaction that also moves the bindings and sets `generation = old + 1`;
    # and `collect_one._promote` for a first link, in one fenced statement
    # inside the settle transaction, after this function has returned. Neither
    # is reachable from here, which is the point. An UPSERT that names its
    # columns, never `INSERT OR REPLACE`. REPLACE deletes the conflicting row
    # and inserts a fresh one, so every column this statement does not list is
    # reset — including `closed_at`, which `apply.record_revocation` is
    # documented across three files as the ONLY writer of. A REPLACE onto an id
    # whose consent the provider had already confirmed gone would resurrect it
    # as an open consent, and `consent_status` lists exactly `closed_at IS
    # NULL`. The `WHERE` makes that structural rather than incidental: a
    # session the provider confirmed closed is not written at all.
    c.execute("INSERT INTO sessions(session_id, aspsp_name, country,"
              " psu_type, status, authorized_at, valid_until, generation)"
              " VALUES (?,?,?,?,?,?,?,?)"
              " ON CONFLICT(session_id) DO UPDATE SET"
              " aspsp_name=excluded.aspsp_name, country=excluded.country,"
              " psu_type=excluded.psu_type, status=excluded.status,"
              " authorized_at=excluded.authorized_at,"
              " valid_until=excluded.valid_until,"
              " generation=excluded.generation"
              " WHERE sessions.closed_at IS NULL",
              (sid, bank, country, attempt.get("psu_type"),
               callbacks.REVIEW_REQUIRED_STATUS, _utcnow_iso(), valid_until,
               callbacks.REVIEW_REQUIRED_GENERATION))

    # The binder chosen above, and there is no third path out of the dispatch.
    complete, renewal = bind(c, fenced, attempt, records=records,
                             session_id=sid, secret=secret, prior=prior)

    fenced.beat()
    if not complete:
        # On a renewal this is also the safety rule: the switch does NOT
        # happen, so the OLD session stays live and stays bound and the ledger
        # is never half-moved. The new consent is left in review, visible and
        # revocable, and the operator is told to retry the renewal.
        CB.declare_partial(c, attempt)
        return

    # QUEUED, not recorded. The durable handoff record is written by
    # `collect_authorization` at the moment it actually emits the instruction —
    # writing it here would record "handoff made" for a turn that might never
    # be delivered, and `consent_status` would then go silent about a reminder
    # nobody had been asked for. The consumer half. `complete_renewal`
    # withdraws the OLD grant at the bank and reports whether the provider
    # confirmed it; a failure is durable (`REVOKE_FAILED`, still listed by
    # consent_status) but it must also be SAID, in the turn the operator is
    # actually reading. A renewal that succeeded and left a live permission
    # behind is not the same event as a renewal that finished cleanly, and only
    # the queue can carry the difference to the message. `old_consent_ref` is
    # the alias, never the id.
    _HANDOFFS.append({"state_hash": attempt.get("state_hash"),
                      "bank": bank or "that bank", "session_id": sid,
                      "valid_until": valid_until, "renewing": renewing,
                      "revoked": bool((renewal or {}).get("revoked")),
                      "revoke_error": (renewal or {}).get("revoke_error"),
                      "old_consent_ref": (
                          _consent_ref(prior["session_id"]) if renewing
                          else None),
                      # Issue #6. The message this feeds says what is LEFT at
                      # the bank when the withdrawal did not confirm, and that
                      # claim is false for a consent that had already lapsed —
                      # which is a state `link_bank` deliberately renews. The
                      # date travels with the handoff because the queue is the
                      # only thing that can carry the old consent to the
                      # message; the verdict is taken at print time, from
                      # `_expiry_state`, like every other branch.
                      "old_valid_until": (
                          prior.get("valid_until") if renewing else None)})


@register("collect_authorization",
          "Collect and exchange any authorization result casa has published. "
          "Idempotent and safe when nothing is pending. NEVER protected.",
          {"type": "object", "properties": {}})
def collect_authorization(args: dict) -> str:
    c = _conn()
    entry = _entry()
    if not entry:
        return ("not_configured: no callback .index entry, so there is nothing "
                "to collect. Run setup_bank_feed.")
    del _HANDOFFS[:]
    del _INCOMPLETE[:]
    del _MISMATCHES[:]
    outcomes = CB.run_collection(c, CB.spool(), entry["plugin_dir"], _exchange)
    if not outcomes:
        return ("Nothing to collect — no authorization result is waiting. This "
                "tool is idempotent and safe to call at any time; casa's nudge "
                "is at-least-once.")
    lines = ["Collected %d authorization result(s)." % len(outcomes)]
    for outcome in outcomes:
        lines.append("  %s: %s" % (outcome.status, _safe(outcome.detail)))

    # `Outcome.status` is the authority, not "run_collection returned without
    # raising": conflating the two is exactly how a capped link reports as a
    # completed one. Only membership of SUCCESS_STATUSES may be reported as a
    # completed link or carry the renewal handoff; `partial` and
    # `review_required` mean the operator has something to do NOW.
    succeeded = {o.state_hash for o in outcomes
                 if o.status in callbacks.SUCCESS_STATUSES}
    incomplete = {e["state_hash"]: e for e in _INCOMPLETE}
    mismatched = {e["state_hash"]: e for e in _MISMATCHES}

    for outcome in outcomes:
        if outcome.status in callbacks.SUCCESS_STATUSES:
            continue
        # A renewal refused because the bank's account set changed is a
        # routine, recoverable event, and the collector's own `Outcome`
        # detail ("the accounts returned were not the ones approved") is
        # indistinguishable from a failed whitelist check. Say what actually
        # differed and name the call that unblocks it, in the turn the operator
        # is reading — the same rule an unwithdrawn old consent gets.
        mismatch = mismatched.get(outcome.state_hash)
        if mismatch is not None:
            lines.append(
                "RENEWAL STOPPED for %s: the bank's account set is no longer "
                "the one you linked, so nothing was switched and your existing "
                "consent is untouched."
                % (_safe(mismatch["record"].get("aspsp")) or "that bank"))
            lines.extend(_mismatch_lines(
                mismatch["record"], _consent_ref(mismatch["session_id"])))
        detail = incomplete.get(outcome.state_hash) or {}
        if outcome.status != "partial":
            continue
        bank_name = _safe(detail.get("bank") or "that bank")
        if detail.get("erased"):
            # The issue-#8 fence fired inside the authorization-time
            # backfill: the account was erased locally while the fetch was
            # in flight, so nothing landed — and the "marked partial /
            # resume it" wording below would be false on both counts: there
            # is no sync_state row left to be marked, and nothing to resume.
            # A renewal that hit the fence switched nothing, so the old
            # consent (if any) is still the live one.
            lines.append(
                "NOTHING STORED for %s: an account was erased locally while "
                "this authorization's history fetch was in flight, so "
                "nothing the fetch returned was kept%s. The consent at the "
                "bank is untouched; if the erasure was yours, run link_bank "
                "again if you want the account back, or unlink_bank to "
                "withdraw the consent."
                % (bank_name,
                   " and nothing was switched — the existing consent is "
                   "still the live one" if detail.get("renewing") else ""))
            continue
        # A capped backfill spent the fresh-SCA window without getting the
        # history it was for, and the window does not reopen — so the
        # instruction arrives in the same breath as the collection rather than
        # being inferred later from a freshness label.
        lines.append(
            "INCOMPLETE HISTORY for %s: the consent is good but the "
            "transaction backfill did not finish, so the deep-history window "
            "this authorization opened has been spent without the history it "
            "existed for. Nothing was corrupted — the ledger is marked partial "
            "and nothing was tombstoned — but this is NOT a completed link."
            % bank_name)
        if detail.get("renewing"):
            # `sync` refreshes accounts that are BOUND, and a capped renewal
            # binds nothing: the new consent is quarantined and the uids it
            # returned are not durable anywhere, so sync would refresh the OLD
            # session and report success while the renewal stayed unfinished.
            # Telling the operator to run it would be an instruction that
            # cannot work. Durable staged continuation — a quarantined session
            # whose candidate uids survive the turn, so a later sync can finish
            # it — is deliberately not built; the honest remedy is to clear the
            # candidate and authorize again, and saying so is better than
            # offering a remedy that silently does nothing. Issue #6's
            # sentence, third instance, and the one that reads most like
            # reassurance. Nothing was switched, so the account named in the
            # detail is still bound to the OLD session — which is where its
            # validity is read from, rather than assumed from the fact that the
            # renewal reached this branch. A renewal of an ALREADY EXPIRED
            # consent lands here (`_renewable_session` hands `link_bank` one on
            # purpose), and telling that operator their accounts keep working
            # from the old consent is the opposite of what happens: it is
            # bound, it will not be fetching. The remedy below is unchanged
            # either way.
            old = c.execute(
                "SELECT s.valid_until AS valid_until FROM accounts a"
                " JOIN sessions s ON s.session_id = a.session_id"
                " WHERE a.account_id = ?",
                (detail.get("account_id") or "",)).fetchone()
            # `old` is None only if the account went unbound or vanished
            # between the exchange and this line — corruption, or a concurrent
            # mutation. That is not evidence of liveness, and defaulting to the
            # reassuring branch would state the one thing we just failed to
            # read. Say nothing about the old consent instead.
            state, value = _expiry_state(old["valid_until"] if old else None)
            # The expired wording says what the DATE says and stops there. It
            # does NOT say refreshing has stopped: `tools_refresh` binds to the
            # session and never reads `valid_until`, so whether the bank still
            # answers is the bank's to decide — and the same local date that is
            # not proof enough to skip a withdrawal is not proof enough to
            # promise a refusal. Both fail-safe directions point the same way:
            # never claim the bank dropped a grant, never promise fresh data.
            still = {
                LIVE: "your old consent is still live and still bound, and your "
                      "accounts keep working from it",
                EXPIRED: "your old consent is still bound, but its validity "
                         "passed %s — so your accounts stay queryable from the "
                         "data already here, and that consent cannot be relied "
                         "on to fetch anything new" % _ago(value),
                UNKNOWN: "your old consent is still bound, and this call could "
                         "not read how long it is valid for — so whether it "
                         "keeps serving answers is not something this turn can "
                         "tell you",
            }[state]
            lines.append(
                "  Because that was a RENEWAL, nothing was switched: %s "
                "(the old session is not retired until the new one's fetch "
                "is durably complete). sync "
                "CANNOT resume this: the new consent is quarantined with "
                "nothing bound to it, so sync would only refresh the old one. "
                "Run unlink_bank consent_ref=%s to withdraw the half-finished "
                "new consent at the bank, then link_bank against %s again to "
                "retry the renewal from the start."
                % (still, _consent_ref(detail.get("session_id") or ""),
                   bank_name))
        else:
            lines.append(
                "  Run sync now to resume the remaining pages while the session "
                "is still valid: this account IS bound to the new consent, so "
                "an ordinary refresh continues where the backfill stopped.")

    # The durable record is written HERE, as the instruction is emitted, and
    # only for an outcome the collector itself called a success. Recording it
    # inside the exchange means a crash between the two leaves `consent_status`
    # silent about a reminder nobody had been asked for.
    for handoff in _HANDOFFS:
        if handoff["state_hash"] not in succeeded:
            continue
        if handoff.get("renewing"):
            bank_name = _safe(handoff["bank"])
            if handoff.get("revoked"):
                lines.append(
                    "Renewed %s. The new consent is live, the old one has been "
                    "withdrawn at the bank, and every label, category, include "
                    "flag and transaction carried forward — nothing was "
                    "re-imported." % bank_name)
            else:
                # The renewal SUCCEEDED — accounts are bound to a live,
                # fully fetched consent — and the old grant is a separate
                # cleanup obligation that did not complete. Saying only
                # "renewed" would leave a live bank permission unmentioned in
                # the one turn the operator reads; saying "failed" would invite
                # them to run a completed renewal again. Both facts, in order.
                lines.append(
                    "Renewed %s. The new consent is live and every label, "
                    "category, include flag and transaction carried forward — "
                    "nothing was re-imported." % bank_name)
                # Issue #6, and the FIRST-HAND telling of it: this is the turn
                # the renewal completed in, printed before anyone runs
                # consent_status. The withdrawal was owed and was attempted —
                # a local date is never grounds to skip it — but "what is left
                # is a permission the bank still holds" is a claim about the
                # bank, and a consent that had already lapsed does not leave
                # one. Same predicate, same boundary, as every other branch.
                old_state, old_value = _expiry_state(
                    handoff.get("old_valid_until"))
                left = {
                    LIVE: "what is left is a permission the bank still holds.",
                    EXPIRED: "the old consent's validity had already passed (%s)"
                             ", so the withdrawal was never confirmed but the "
                             "bank most likely holds nothing."
                             % _ago(old_value),
                    UNKNOWN: "how long that consent was valid for is not "
                             "recorded here, so whether the bank still holds it "
                             "cannot be said from here.",
                }[old_state]
                lines.append(
                    "  BUT THE OLD CONSENT WAS NOT WITHDRAWN AT THE BANK (%s). "
                    "The renewal itself is complete and your accounts are "
                    "served by the new consent; %s Run unlink_bank "
                    "consent_ref=%s to settle it — consent_status lists it "
                    "until you do."
                    % (_safe(handoff.get("revoke_error")
                             or "no reason reported"),
                       left, handoff.get("old_consent_ref")))
        asked_for = record_renewal_handoff(c, handoff["session_id"],
                                           handoff["valid_until"])
        if not asked_for:
            continue
        lines.append("Renewal handoff for %s: ask the resident to call "
                     "set_reminder for %s, %d days before this consent expires. "
                     "That request is recorded here, so consent_status will "
                     "stop asking." % (_safe(handoff["bank"]),
                                       asked_for, RENEWAL_LEAD_DAYS))
    lines.append("Session identifiers and authorization codes are never "
                 "reported. Run consent_status for expiry dates and "
                 "list_accounts for what came back.")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# consent
# --------------------------------------------------------------------------

@register("consent_status",
          "Per-bank consent status: expiry, days remaining, in-flight "
          "authorizations, renewal-handoff state, and restore detection.",
          {"type": "object", "properties": {}})
def consent_status(args: dict) -> str:
    c = _conn()
    lines = []

    # Configuration FIRST. `provenance.fingerprint` rightly refuses to
    # fingerprint nothing, so calling it with an empty key raises — and an
    # unset key is precisely the "not configured yet" state this tool has to
    # name gracefully. A brand-new install asking "what is my consent status?"
    # must get an answer, not a traceback.
    app_id = os.environ.get("CASA_BANKFEED_EB_APP_ID")
    key_pem = os.environ.get("CASA_BANKFEED_EB_PRIVATE_KEY")
    if not app_id or not key_pem:
        # Named by their plugin-env.conf REFERENCES, not by the process keys
        # read just above (issue #4): those two differ now, and only the
        # reference is a name the operator can wire or look up.
        missing = [n for n, v in ((WIRE_APP_ID_VAR, app_id),
                                  (WIRE_KEY_VAR, key_pem))
                   if not v]
        # It does NOT say "nothing is wrong, this is a fresh install". An empty
        # value is the SAME observation for a fresh install, a wiring that was
        # deleted, and a live install whose op:// reference stopped resolving —
        # casa empties a declared var in that last case on purpose. This rung
        # cannot tell those apart, so it reports what it saw and sends the
        # operator to the one thing that can: guards branch on the truth, and
        # so does the prose about them. And it says consent status CANNOT BE
        # REPORTED, not that there are no consents — a distinction that bites
        # with an open session already in the ledger. The fingerprint this rung
        # needs is unavailable, so consent state is UNKNOWN from here — a live
        # install whose wiring broke still has its consents, and telling the
        # operator there are none is a false claim about the one thing they
        # asked.
        return ("not_configured: %s did not resolve to a usable value, so "
                "consent status cannot be reported. That is the expected "
                "state of an install whose setup has not run yet — but it is "
                "also "
                "what a wiring that has BROKEN looks like from here, and "
                "this tool cannot tell the two apart. Run setup_bank_feed: "
                "it walks the reconcile ladder and names exactly what is "
                "missing." % ", ".join(missing))

    # A restored backup must never answer as if nothing happened.
    try:
        fingerprint = provenance.fingerprint(app_id, key_pem, _host_id())
    except ValueError:
        # SET BUT UNUSABLE is its own state, and it is reachable in production:
        # a truncated PEM, armor lines with no body, or an op:// reference that
        # resolved to something degenerate. It is neither a crash nor
        # "you never set this up" — the remedy differs, so the wording does too.
        return ("key_unreadable: the key wired as %s carries "
                "no usable key material — most likely a truncated PEM, armor "
                "lines with no body, or an op:// reference that resolved to "
                "something degenerate. A key value REACHED this process and "
                "is unusable, which is a different problem from no value at "
                "all — though it does not by itself prove setup ever ran. "
                "Consent status cannot be reported until the key is "
                "fixed: re-check the 1Password item, then run setup_bank_feed. No "
                "provider call was attempted and nothing has been changed."
                % WIRE_KEY_VAR)
    state = provenance.check(c, fingerprint)
    if state.get("state") == "mismatch":
        lines.append(
            "RESTORE MISMATCH: this database was created under a "
            "different application id, signing key, or host — almost certainly "
            "restored from a Home Assistant backup. Until a post-restore "
            "reconciliation runs, every session status below is UNVERIFIED, any "
            "pending authorization here can no longer complete, and cached data "
            "must be treated as stale. If history is missing, the remedy is a "
            "re-link.")
    elif state.get("state") == "fresh":
        provenance.record(c, fingerprint)
        lines.append("Provenance: first run in this environment — fingerprint "
                     "recorded.")

    sessions = [dict(r) for r in c.execute(
        "SELECT * FROM sessions WHERE closed_at IS NULL ORDER BY aspsp_name")]
    if not sessions:
        lines.append("No active bank consents. Run link_bank to connect one.")
    for s in sessions:
        bank = _safe(s.get("aspsp_name"))
        ref = _consent_ref(s["session_id"])
        # Issue #6: `"%d days remaining" % days` had no lower bound either, so
        # a lapsed consent's header read "-3 days remaining" — a remaining
        # duration that is negative, one line above a branch that says it has
        # expired. `state` is computed ONCE per row here and every branch below
        # reads it, so no two lines about one consent can disagree about
        # whether it has lapsed. That was the whole cost of the old shape:
        # `days < 0` in one place, `status` in another, nothing in a third.
        state, value = _expiry_state(s.get("valid_until"))
        # The three-way tables below are dict literals, so every arm is built
        # whether or not it is chosen: the lapse is rendered ONCE, here, where
        # `value` is known to be a number, rather than inside an arm that a
        # `None` would reach on its way to being discarded.
        lapse = _ago(value) if state == EXPIRED else ""
        lines.append(
            "%s (%s, psu_type=%s) — status %s, valid_until %s, %s. "
            "consent_ref %s" % (
                bank, _safe(s.get("country")), _safe(s.get("psu_type")),
                _safe(s.get("status")),
                _safe(s.get("valid_until")) or "unknown",
                "expired %s" % _ago(value) if state == EXPIRED else
                "%d days remaining" % value if state == LIVE else
                "days remaining unknown",
                ref))

        # A consent whose account set did not verify — or which a refused
        # rebinding left behind — still EXISTS at the bank. Leaving only
        # `attempts.session_id` behind would make it invisible to this tool and
        # unrevocable by `unlink_bank`, with each retry creating another one.
        # It is quarantined instead, as a session row with no account binding;
        # here it is reported as needing action, with the ref that revokes it.
        # No renewal wording: there is nothing to renew, and asking for a
        # reminder about a consent the operator is being told to revoke would
        # be noise.
        status = str(s.get("status") or "")
        if status == callbacks.REVIEW_REQUIRED_STATUS:
            # A quarantine has two quite different causes and they had
            # one message. If we recorded WHY — the bank's account set changed —
            # then say that and give the sequence that recovers; the generic
            # text's "fix the whitelist, then link again" is wrong in both
            # halves for this cause and walks the operator into a loop.
            mismatch = renewal_mismatch(c, s["session_id"])
            if mismatch is not None:
                lines.append(
                    "  NEEDS ATTENTION: this consent exists at %s and nothing "
                    "is bound to it, because the RENEWAL it came from was "
                    "stopped: the bank's account set is no longer the one you "
                    "linked." % bank)
                lines.extend(_mismatch_lines(mismatch, ref))
                continue
            # Issue #6 reaches a QUARANTINE too, and this is the branch where it
            # is least obvious: the row carries the `valid_until` the exchange
            # wrote, a quarantine sits until the operator acts on it, and after
            # 179 days of sitting "it stays a live consent at the bank" is
            # false. The accumulation half stays true regardless — each retry
            # really does mint another consent — so only the standing-grant
            # clause and the reason to revoke move.
            lines.append(
                "  NEEDS ATTENTION: this consent exists at %s but nothing was "
                "linked from it — the accounts it returned were not the ones "
                "approved, or linking them would have re-bound an account that "
                "is already linked. It is quarantined: no account is bound to "
                "it and it is never refreshed. %s, then fix the whitelist and "
                "link again. Leaving it costs you nothing locally, but %s."
                % (bank,
                   {EXPIRED: "Its recorded validity passed %s, so there is very "
                             "likely nothing left to withdraw — run unlink_bank "
                             "consent_ref=%s to clear the record"
                             % (lapse, ref),
                    LIVE: "Revoke it with unlink_bank consent_ref=%s" % ref,
                    # `callbacks` records a quarantine with `valid_until` NULL
                    # when the provider never told us the term, so this is the
                    # COMMON quarantine, not an exotic one — and it printed "it
                    # stays a live consent at the bank" two lines under a
                    # header saying the term was unknown.
                    UNKNOWN: "How long it is valid for is not recorded here, so "
                             "whether the bank still holds it cannot be said "
                             "from here — run unlink_bank consent_ref=%s to "
                             "withdraw it either way" % ref}[state],
                   {EXPIRED: "every retry leaves another consent at the bank, "
                             "and another record to clear once each one lapses",
                    LIVE: "it stays a live consent at the bank and every retry "
                          "adds another one",
                    UNKNOWN: "every retry leaves another consent at the bank, "
                             "however many of them the bank still holds"}[state]))
            continue

        # A revocation was owed on this consent and did not complete, so the
        # bank very likely still holds the permission. The row is deliberately
        # still OPEN: this tool lists only open sessions, so closing it would
        # hide a consent that is still live — the same stranding quarantine
        # exists to undo, arrived at from the other direction. The
        # `consent_ref` is unchanged, so the retry is the identical call.
        #
        # The two states differ in HOW the operator got here, and the remedy is
        # the same, so the reason is one clause rather than two branches.
        #
        # The test is the INVERSE OF A LIST, exactly as `outstanding_consents`
        # is, and for the same reason its docstring gives. This branch used to
        # enumerate the two revocation statuses and let everything else fall
        # through to the renewal wording — so a status this plugin does not know
        # about would be told to "RENEW IT NOW", while `_renewable_session`'s
        # status filter refuses to renew it, and following the instruction
        # mints a SECOND consent. Anything not live is something the operator
        # has to deal with; only the reason is looked up, never the question.
        if status in REVOCATION_INCOMPLETE_STATUSES:
            how = ("this plugin asked the bank to revoke it and the bank did "
                   "not confirm"
                   if status == REVOKE_FAILED_STATUS else
                   "it was replaced by a renewal and the withdrawal never "
                   "ran, most likely an interrupted turn")
            # Issue #6, and the sentence the issue is named for. "The bank very
            # likely still holds the permission" is true of a failed revocation
            # and false of an expired consent, and the renewal path reaches
            # both: `_renewable_session` hands `link_bank` an expired consent
            # (correctly — it is what carries the ledger forward), so
            # `complete_renewal` owes it a `delete_session`, and any answer
            # other than success or a 404 lands the row here. The revocation
            # was still owed and still attempted — a local date is not proof
            # the bank dropped it — but what we tell the operator about the
            # bank must come from the validity, not from the failure.
            if state == EXPIRED:
                # Two weak facts, both stated, neither promoted. The
                # first wording here said "(LOCAL ONLY)" and "a stale local
                # marker rather than a live grant" — conclusions drawn from a
                # local date, in the same change that refuses to skip the
                # withdrawal on the strength of one. The bank consent screen
                # stays named for exactly that reason.
                lines.append(
                    "  NEEDS ATTENTION: this consent at %s was not withdrawn — "
                    "%s — and its recorded validity HAD ALREADY PASSED (%s). So "
                    "the withdrawal was never confirmed, but its validity is "
                    "behind us and the bank most likely no longer holds the "
                    "permission. Nothing local was lost, and this consent no "
                    "longer serves any account. Run unlink_bank consent_ref=%s "
                    "to settle it — the handle has not changed. If that keeps "
                    "failing and you want certainty, %s's own consent screen is "
                    "the one place that can give it."
                    % (bank, how, _ago(value), ref, bank))
                continue
            if state == UNKNOWN:
                # The pairing is what makes this necessary: the header one line
                # above already says "days remaining unknown", and this said
                # "the bank very likely still holds the permission" underneath
                # it. The remedy is identical in all three states — it is only
                # the claim about the bank that has to be earned.
                lines.append(
                    "  NEEDS ATTENTION: this consent at %s was not withdrawn — "
                    "%s — and how long it was valid for is not recorded here, "
                    "so whether the bank still holds the permission cannot be "
                    "said from here. Nothing local was lost, and this consent "
                    "no longer serves any account. Run unlink_bank "
                    "consent_ref=%s — the handle has not changed, so it reaches "
                    "the same consent. If it keeps failing, %s's own consent "
                    "screen is the one place that can settle it."
                    % (bank, how, ref, bank))
                continue
            lines.append(
                "  NEEDS ATTENTION: this consent at %s was not withdrawn — %s. "
                "The bank very likely still holds the permission. Nothing "
                "local was lost, and this consent no longer serves any "
                "account. Run unlink_bank consent_ref=%s — the handle has not "
                "changed, so it reaches the same consent. If it keeps failing, "
                "withdraw it from %s's own consent screen."
                % (bank, how, ref, bank))
            continue

        if status != callbacks.LIVE_SESSION_STATUS:
            # The inversion above still holds — anything not live is the
            # operator's to deal with and is never offered for renewal — but an
            # unmapped status has no known history and no known local
            # consequence (issue #5, item 5). The old wording borrowed BOTH
            # from the revocation branch: a renewal that replaced it, and an
            # account binding it no longer serves.
            lines.append(
                "  NEEDS ATTENTION: this consent at %s carries status %s, "
                "which this version does not recognise — how it reached this "
                "state is not known here, and it is not offered for renewal. "
                "It may still be live at the bank, and anything shown as "
                "bound to it above may still be bound. Run unlink_bank "
                "consent_ref=%s to withdraw it — the handle reaches the same "
                "consent — or withdraw it from %s's own consent screen."
                % (bank, _safe(status), ref, bank))
            continue

        # Three honest states, and silence is the default once a handoff is
        # recorded. A warning printed for every consent forever is one
        # operators normalise, and the one consent that genuinely has no
        # reminder then looks exactly like the others.
        record = renewal_handoff(c, s["session_id"])
        remind_on = _minus_days(s.get("valid_until"), RENEWAL_LEAD_DAYS)
        # Only a handoff whose instruction was actually emitted silences
        # this. An intended one does not.
        if handoff_emitted(record):
            lines.append("  Renewal: handoff made on %s for %s."
                         % (_safe(str(record.get("recorded_at"))[:10]),
                            _safe(record.get("asked_for"))))
        elif state == EXPIRED:
            # Issue #5, item 6. `days <= RENEWAL_LEAD_DAYS` had no lower
            # bound, so an ALREADY EXPIRED consent took the renewal-window
            # path and printed "EXPIRES IN -2 DAYS" beside "this consent
            # stays live" — a future tense and a liveness claim for a
            # consent whose validity is behind us. The window is an
            # interval, so the guard is one.
            #
            # Issue #6 moves the guard from `days < 0` — a DATE difference — to
            # the shared instant. It was the same interval read two ways: a
            # consent that lapsed at 09:00 had `days == 0`, so it printed
            # "EXPIRES IN 0 DAYS … RENEW IT NOW" for the rest of the day, while
            # the header above it now said it had expired.
            lines.append(
                "  Renewal: THIS CONSENT HAS EXPIRED (%s) AND THE RENEWAL "
                "HANDOFF WAS NEVER MADE. Link %s again to get a fresh "
                "consent, and ask the resident to call set_reminder for the "
                "next one." % (_ago(value), bank))
        elif state == LIVE and value <= RENEWAL_LEAD_DAYS:
            lines.append(
                "  Renewal: THIS CONSENT EXPIRES IN %d DAYS AND THE RENEWAL "
                "HANDOFF WAS NEVER MADE. Renew it now with link_bank against "
                "%s, and ask the resident to call set_reminder for the next "
                "one." % (value, bank))
        else:
            lines.append(
                "  Renewal: handoff not yet made. Ask the resident to call "
                "set_reminder for %s (%d days before expiry) to renew %s; "
                "collect_authorization records the handoff automatically when "
                "a link completes."
                % (remind_on or "the date 21 days before expiry",
                   RENEWAL_LEAD_DAYS, bank))

        if state == EXPIRED:
            # The action half of item 6, guarded by the same interval. What
            # this branch KNOWS is a date difference — it has not asked the
            # bank, read coverage, or watched a refresh. Replacing the
            # window branch's false liveness claim with equally unfounded
            # ones about what stopped when and what the next fetch will
            # recover would be no better, so it drops the renewal branch's
            # liveness promise and promises nothing in its place.
            lines.append(
                "  EXPIRED — RE-LINK IT: run link_bank with aspsp=%s, "
                "country=%s, psu_type=%s. Your labels, categories, include "
                "flags, proven coverage and every transaction carry forward "
                "untouched, exactly as in a renewal. What differs from a "
                "renewal inside the window: this consent's validity has "
                "already passed, so unlike one still inside it, this one "
                "cannot be relied on to keep serving answers in the meantime. "
                "Check the ledger's coverage once the new link's fetch "
                "finishes rather than assuming it filled everything."
                % (bank, _safe(s.get("country")), _safe(s.get("psu_type"))))
            lines.append("  Expiry is not an error state: the data already "
                         "here stays queryable, clearly marked as no longer "
                         "refreshing.")
        elif state == LIVE and value <= RENEWAL_LEAD_DAYS:
            # The operator-facing half of renewal, and the point
            # of the whole feature. A consent inside the renewal window is not
            # a warning to absorb; it is one action to take, and the reason
            # people hesitate over it ("will I lose my history?") is answered
            # here rather than left to be discovered.
            lines.append(
                "  RENEW IT NOW: run link_bank with aspsp=%s, country=%s, "
                "psu_type=%s. That is the renewal — same two taps as the "
                "original link. Your labels, categories, include flags, proven "
                "coverage and every transaction carry forward untouched, and "
                "this consent stays live and serving answers until the new "
                "one's history fetch is durably complete."
                % (bank, _safe(s.get("country")), _safe(s.get("psu_type"))))
            lines.append("  Expiry is not an error state: data stays queryable, "
                         "clearly marked as no longer refreshing.")
    # Only when a renewal is actually in question: a list containing nothing
    # but stopped consents — quarantined, or one whose revocation failed — has
    # no handoff to caveat. Inverted with the branches above so the
    # guard and the branch cannot disagree about an unmapped status: a handoff
    # line is printed for a LIVE consent and for nothing else, so the caveat is
    # printed when there is a live consent and for nothing else.
    if any(str(s.get("status") or "") == callbacks.LIVE_SESSION_STATUS
           for s in sessions):
        lines.append(HANDOFF_CAVEAT)

    now = _now_s()
    pending = [dict(r) for r in c.execute(
        "SELECT aspsp_name, country, psu_type, created_at, phase FROM attempts"
        " WHERE phase IN ('minted','held') ORDER BY created_at")]
    for p in pending:
        left = PENDING_TTL_S - (now - float(p.get("created_at") or 0))
        lines.append(
            "In flight: %s (%s, %s) — %s. Tap the link you were given, then "
            "call collect_authorization." % (
                _safe(p.get("aspsp_name")), _safe(p.get("country")),
                _safe(p.get("psu_type")),
                ("about %d min left of the 30-minute window" % int(left // 60))
                if left > 0 else "the 30-minute window has passed; mint a fresh "
                                 "link, never replay the old one"))

    # The durable half. `apply.upsert_account` records a refused rebinding in
    # `sync_state` under `resource='account_binding'` rather than a table of
    # its own — which only helps if something reads it. A refused rebinding is
    # precisely the kind of thing an operator has to be TOLD, so it is reported
    # here, beside the quarantined consents, and the two "we stopped and need
    # you" states arrive in one place. The note never carries a session id.
    for row in c.execute(
            "SELECT s.account_id AS account_id, s.last_error AS last_error,"
            " a.name AS name FROM sync_state s"
            " LEFT JOIN accounts a ON a.account_id = s.account_id"
            " WHERE s.resource='account_binding'"
            " AND s.completeness='review_required'"
            " ORDER BY s.account_id"):
        lines.append(
            "BINDING NEEDS REVIEW for %s: %s"
            % (_safe(row["name"]) or row["account_id"][:10],
               _safe(row["last_error"])
               or "a new authorization would have re-bound this account and "
                  "was refused"))
        lines.append(
            "  A renewal carries everything forward when the accounts match "
            "exactly; this one did not match, and remapping a changed set "
            "would silently reattribute history to the wrong account. "
            "Nothing was switched. Revoke the consent you do not want "
            "with unlink_bank, or unlink this bank and link it again.")

    # The range is the account's OWN PROVEN SPAN, never 1970.
    #
    # This asked `apply.holes(c, account_id, "1970-01-01", today)`. The deepest
    # history any authorization can reach is `flows.BACKFILL_FLOOR_DAYS` (2900
    # days; beyond eight years is rejected outright), and `record_coverage`
    # records only what was actually proven — so `1970-01-01 → oldest proven
    # row` was a gap on EVERY account, FOR EVER, and no action in this system
    # could close it. An account with the full eight-year window proven still
    # reported a gap and was told to spend another set of SCA taps.
    #
    # That is the always-on-warning anti-pattern all over again: a warning
    # that is always on is normalised within a week, and the one
    # account that genuinely lost history to a capped fetch then looks exactly
    # like the other two. It also turned a truthful "we do not know" into a
    # standing instruction to spend taps that provably cannot help — the
    # "remedy that silently does nothing" this module rejects elsewhere.
    #
    # Asking inside `[earliest proven, latest proven)` reports exactly the
    # actionable thing: a hole BETWEEN intervals we did prove, which is a
    # stretch we once had a claim around and do not have. A contiguous account
    # is silent, which is the correct answer for it.
    #
    # An account with NO coverage at all is silent too, and that is `flows`'
    # own reasoning rather than an omission: an account that returned no rows
    # records no coverage, because "the account is dormant" and "the bank
    # silently truncated to nothing" are indistinguishable, and claiming a
    # proven-empty interval on the weakest evidence we ever have is the
    # confident lie this system exists to avoid. Nothing proven is not a gap.
    for row in c.execute("SELECT account_id, name FROM accounts WHERE included=1"):
        proven = apply.merged_coverage(c, row[0])
        if len(proven) < 2:
            continue                     # nothing proven, or one solid span
        gaps = apply.holes(c, row[0], proven[0][0], proven[-1][1])
        if gaps:
            lines.append(
                "Account %s has %d coverage gap(s) inside the range it has "
                "proven (%s to %s); the earliest is %s to %s. Only a fresh SCA "
                "reopens the deep-history window, so this is closed at the next "
                "renewal — run link_bank against that bank when you are ready. "
                "It is REPORTED rather than silently filled: a gap is 'we do "
                "not know', never 'nothing happened'. Targeted gap filling is "
                "follow-up work."
                % (_safe(row[1]) or row[0], len(gaps), _safe(proven[0][0]),
                   _safe(proven[-1][1]), _safe(gaps[0][0]), _safe(gaps[0][1])))
    return "\n".join(lines)
