# plugins/bank-feed/server/tools_refresh.py
"""Refresh, labelling and export — and the enforcement of rate control.

Every provider call that is NOT part of an authorization goes through
`_refresh_resource`, so there is exactly one place where quota can be burned
by ordinary reads. A fresh-SCA window exhausted by routine questions cannot be
reopened by anything, which is why the control set lives here at all.

**The primitives are `tools_auth`'s and are imported, never re-spelled.**
`MIN_REFRESH_INTERVAL_S`, `RATE_LIMIT_BACKOFF_S` and `INFLIGHT_TTL_S` live
there beside `admit_refresh`/`claim_refresh`/`release_refresh`. Two modules
spelling one constant independently is a recurring drift — the admin-token
variable, the revocation statuses, `LIVE_SESSION_STATUS` — and a
cooldown constant that drifts fails silently — the guard simply stops
engaging. A test greps this file for a second declaration.

**Provider text is neutralised at BOTH ends.** This module's output is
line-oriented, so a value carrying a newline forges a whole line the operator
reads as ours. It is also the module that WRITES `balances.reference_date` and
`balances.balance_type`, so it holds the writer half of a rule whose read half
lives in `tools_read` — that column had a reader before it had a writer. And it
writes `accounts.label`,
the one provider-adjacent column `tools_read` renders UNFENCED on the stated
grounds that it is the operator's own text: that stays true only if this
writer keeps it true, so a label is neutralised on the way in.

`label_account` is a PROTECTED tool. It is not destructive, but included=false
removes an account from every balance and every total, and the only thing that
would make the model call it is text it read.
"""
from __future__ import annotations

import csv
import datetime as _dt
import json
import os
from pathlib import Path

import flows
import httpx
import money
import rules
import tools_auth
import tools_read
from tools_auth import GATE_NOTE, RateControlDeferred, _conn, _require_declared
from tools_read import register

#: The resources this module knows how to fetch, and the ONE place that set is
#: written down: the `sync` schema's enum is built from it and `_do_refresh`
#: refuses anything else. The tool schema is advertised to the model, not
#: enforced by anything in this process, so an unvalidated `resource` used to
#: fall into `_do_refresh`'s transactions branch as its `else` — a deep
#: transaction fetch under a resource name no read tool will ever consult.
RESOURCES = ("balances", "transactions")

#: Categories `label_account` accepts, matching its schema enum and the values
#: `tools_read._included_accounts` filters `scope` on. Validated rather than
#: fenced, the same choice `tools_read._safe_currency` makes: a value that
#: passes is one of two known words and can carry nothing.
CATEGORIES = ("personal", "company")

#: Routine refreshes work inside the 90-day window. Used when the
#: ledger holds no usable newest booked date to count back from.
DEFAULT_WINDOW_DAYS = 90

#: "routine refreshes use last booked date − 7 days".
REFRESH_MARGIN_DAYS = 7

#: The clamp on a provider `Retry-After`. The header is a protocol instruction
#: from a party we do not trust to be sane, and an absurd figure must not
#: disable refreshing for a week — at which point it is not a cooldown, it is
#: an outage the operator cannot explain.
MAX_RETRY_AFTER_S = 24 * 3600


# --------------------------------------------------------------------------
# rate control: recording what the provider told us
# --------------------------------------------------------------------------

def _iso_at(epoch: float) -> str:
    """The instant `epoch` in the exact form `tools_auth._utcnow_iso` writes.

    It has to be the same form: `admit_refresh` parses `next_retry_after` back
    with `tools_read._parse_ts` and compares it against `tools_auth._now_s()`,
    so a second spelling here would surface as a cooldown that never engages.
    A test pins the two against each other rather than trusting this comment.
    """
    return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _retry_after_s(exc) -> float:
    """How long to wait after a 429, in seconds. Never None, never zero.

    `httpx` does the parsing — both legal forms (RFC 9110 delta-seconds and
    HTTP-date) become `RateLimited.retry_after_s`. What is left here is the
    reading of it, and both ends matter:

    * **No usable instruction means OUR conservative default.** An absent
      header, an unparseable one and a literal `Retry-After: 0` are the same
      case. `0` is legal delta-seconds and the parser reports it faithfully,
      but honouring it means answering a 429 with an immediate retry, which is
      exactly what earns a longer one. The parser's own contract is that a
      caller treats None as "no information, never retry immediately"; a zero
      carries no more information than an absent header does.
    * **An absurd figure is clamped**, see `MAX_RETRY_AFTER_S`.
    """
    raw = getattr(exc, "retry_after_s", None)
    try:
        seconds = float(raw)
    except (TypeError, ValueError):
        return float(tools_auth.RATE_LIMIT_BACKOFF_S)
    if not seconds > 0:                  # False for 0, negatives and NaN
        return float(tools_auth.RATE_LIMIT_BACKOFF_S)
    return min(seconds, float(MAX_RETRY_AFTER_S))


def _honoured(exc) -> bool:
    """Did the provider supply a delay we could actually use?

    Only for the wording. The wait itself comes from `_retry_after_s`, so the
    two cannot disagree about whether the header was usable.
    """
    raw = getattr(exc, "retry_after_s", None)
    try:
        return float(raw) > 0
    except (TypeError, ValueError):
        return False


def _is_rate_limited(exc) -> bool:
    return (isinstance(exc, httpx.RateLimited)
            or getattr(exc, "kind", "") == "rate_limited")


def _ensure_sync_row(c, account_id: str, resource: str) -> None:
    c.execute("INSERT OR IGNORE INTO sync_state(account_id, resource)"
              " VALUES (?,?)", (account_id, resource))


def _note_failure(c, account_id: str, resource: str, exc) -> None:
    """Record the failure per resource, and the provider's own backoff.

    The class name only — never the message, which can carry a provider
    body.
    """
    _ensure_sync_row(c, account_id, resource)
    label = type(exc).__name__
    if _is_rate_limited(exc):
        wait = _retry_after_s(exc)
        label += (" (Retry-After honoured)" if _honoured(exc)
                  else " (no usable Retry-After; conservative default)")
        c.execute("UPDATE sync_state SET last_error=?, next_retry_after=?"
                  " WHERE account_id=? AND resource=?",
                  (label, _iso_at(tools_auth._now_s() + wait), account_id,
                   resource))
    else:
        c.execute("UPDATE sync_state SET last_error=? WHERE account_id=? AND"
                  " resource=?", (label, account_id, resource))


class NotLinked(RuntimeError):
    """This account is not bound to a consent, so there is nobody to ask.

    Named for what the operator has to do about it, because the class name is
    all that reaches them (`tools_read._freshness` prints the class, never the
    message). Refusing here is not tidiness: `flows.backfill` would stamp its
    durable completeness row with an EMPTY session id, and
    `apply.deep_fetch_complete` then matches that against the next caller's
    empty string and reports a deep fetch that never ran.
    """


#: The way OUT of the state `NoBalancesReturned` creates, in the operator's
#: own vocabulary. The refusal is deliberately permanent — nothing deletes the
#: cached rows, so an account whose bank has genuinely stopped offering
#: balances re-raises on every read for as long as it stays linked — and a
#: fail-closed refusal with no stated exit is a wedged account, not a
#: safeguard. `_reclaim`'s failure branch and `forget_local_account`'s
#: provider-residue paragraph both name their remedy; this is the same rule.
#:
#: ONE string, used by the raise and by `sync`'s failure line, so the exit the
#: operator is told about cannot drift from the exit the class documents. It is
#: appended ONLY to this failure: a remedy printed beside every failed fetch is
#: an always-on warning, and within a week the case that matters reads like the
#: others.
#:
#: NO PARENTHESES, and that is load-bearing rather than a style choice.
#: `tools_read._freshness_note` prints this text inside a parenthesised clause
#: of its own, so `tools_read._clause_safe` substitutes `(`/`)` out of any exit
#: hint to stop a future exit built from a provider body forging a freshness
#: clause. Written with em-dashes instead, that substitution changes nothing
#: here — so what `get_balances` shows stays byte-identical to what `sync`
#: prints, which `assertIs` on the object cannot check. Pinned by
#: `test_the_only_shipped_exit_carries_no_clause_delimiter`.
NO_BALANCES_EXIT = (
    ". If this bank has genuinely stopped offering balances for this account "
    "— a closed account, a permissions change — this refusal will repeat on "
    "every read until the cached rows are gone: run forget_local_account for "
    "that account to clear them. Bank access is not touched by that — it "
    "erases this plugin's local copy of the account, and a later link_bank "
    "brings the account back")


class NoBalancesReturned(RuntimeError):
    """The bank returned no balances at all while the ledger holds some.

    Named for what it is, because the class name is most of what reaches the
    operator through `tools_read._freshness`. It is deliberately NOT treated as
    "the account has no balances": see `_reconcile_balance_types`.

    `operator_exit` is the one thing this class asks a caller to print BESIDE
    the class name. `tools_read._freshness` reads
    it with `getattr`, so the read tools show the exit without importing this
    module and without matching on a class name that a rename would silently
    break — and an exception that declares no exit gets none, which is what
    keeps the remedy attached to the one state it leaves rather than to every
    failed fetch. It is the SAME constant `sync`'s failure line appends, so
    the exit an operator is told about cannot differ between the tool that
    fetched and the tool that read.
    """

    operator_exit = NO_BALANCES_EXIT


def _reconcile_balance_types(c, account_id: str, returned: list) -> None:
    """Drop this account's balance types the bank has stopped returning.

    **Why a delete is needed at all.** The write path was upsert-only, so a
    `balance_type` the bank stopped sending stayed in the ledger for ever, and
    `tools_read._select_balance` kept choosing it off the `BALANCE_PREFERENCE`
    ladder — a three-month-old `CLBD 5000.00` reported as the account's current
    balance while the bank's actual figure was `ITAV 12.00`, summed into
    `balance_total`, and labelled "fresh, cache age 0m" because
    `_freshness_note` reads the age of the SYNC, not of the row it printed.
    The guard branched on a derivative that drifts in exactly the failure mode
    it exists for. With this reconciliation every surviving row was written by
    the latest successful fetch, so that label is true by construction rather
    than by luck.

    **A NON-EMPTY response is authoritative for the SET.** Unlike a transaction
    list, `GET /balances` is a single unpaginated answer to "what are this
    account's balances" — there is no continuation key and no page cap, so a
    type absent from an answer that carried other types is genuinely no longer
    offered. Scoped to this account, by construction: `returned` is built from
    the rows just written for `account_id` and the delete carries the same
    account.

    **AN EMPTY RESPONSE PROVES NOTHING, and must never wipe the account.** That
    is the tombstone rule applied here (`flows.backfill`: "a response proves
    what it CONTAINS, not what it omits"), and the shapes are genuinely
    indistinguishable from in here — a closed account, a bank degrading to an
    empty body, a permissions change. So nothing is deleted. But the previous
    rows must then stop being vouched for, and returning quietly would do
    exactly that: `_do_refresh` would stamp `last_success_at` and the freshness
    note would relabel a months-old figure "fresh". Raising instead leaves the
    stamp untouched, so the age on display stays the real one and the read
    tools add "(inline refresh FAILED: NoBalancesReturned)" beside it. Neither
    the stale row nor the "fresh" label is left standing.

    An empty response with nothing stored is not that case: there is no claim
    to withdraw and no row to mislabel, so it is an ordinary success and
    `_balance_usable` reports the gap ("a gap, not zero") as it always has.
    """
    if returned:
        c.execute(
            "DELETE FROM balances WHERE account_id=? AND balance_type NOT IN (%s)"
            % ",".join("?" * len(returned)), [account_id] + list(returned))
        return
    held = c.execute("SELECT COUNT(*) FROM balances WHERE account_id=?",
                     (account_id,)).fetchone()[0]
    if held:
        raise NoBalancesReturned(
            "the bank returned no balances while this account still has some "
            "cached; they are kept and stay labelled with their own age"
            + NO_BALANCES_EXIT)


def _refresh_window_days(c, account_id: str) -> int:
    """How far back a routine transactions refresh asks.

    `last booked date − 7 days`, expressed as the `floor_days` `flows.backfill`
    counts back from today — or the 90-day default when the ledger holds no
    date we can make sense of.

    **The stored date is provider text with no format validation on any
    path**, and `MAX()` over a TEXT column hands whatever is there straight
    back. Two failures follow if it is trusted: `date.fromisoformat` RAISES
    inside the refresh, so one malformed row makes every later transactions
    refresh for that account fail for ever; and a date in the FUTURE makes the
    subtraction small or negative,
    so `max(days, 7)` silently narrowed the fetch to a week — a provider string
    choosing how little history we ask for. Both fall back to the default,
    which asks for MORE history: the safe direction, since a wider request can
    only prove more.
    """
    newest = c.execute(
        "SELECT MAX(booking_date) FROM transactions WHERE account_id=?"
        " AND state='active'", (account_id,)).fetchone()[0]
    if not newest:
        return DEFAULT_WINDOW_DAYS
    try:
        last = _dt.date.fromisoformat(str(newest)[:10])
    except ValueError:
        return DEFAULT_WINDOW_DAYS
    days = (_dt.date.today() - last).days
    if days < 0:                                  # stamped in the future
        return DEFAULT_WINDOW_DAYS
    # No `max(..., REFRESH_MARGIN_DAYS)` floor: the guard above already
    # returned for every negative `days`, so the floor could never bind. It was
    # dead code that read as a live safeguard.
    return days + REFRESH_MARGIN_DAYS


# --------------------------------------------------------------------------
# the refresher the read tools call for the inline refresh
# --------------------------------------------------------------------------

def _claim(c, account_id: str):
    """Take the single-flight claim, returning the exact record we took.

    That record is the evidence `_release_own` needs. `claim_refresh` answers
    only yes/no, and yes/no is not enough to release safely — see below.
    """
    if not tools_auth.claim_refresh(c, account_id):
        return None
    return tools_auth._meta_get(c, tools_auth._inflight_key(account_id))


def _release_own(c, account_id: str, held) -> None:
    """Release the claim ONLY while it is still the one we took.

    `tools_auth.release_refresh` is deliberately unfenced: it deletes whatever
    claim is there. That is right for the preemptor — an authorization-time
    backfill must win, because the fresh-SCA window is minutes wide and no
    later slice can reopen it — but it was wrong for the party that LOST.
    `claim_refresh(priority=True)` overwrites a live read-refresh claim, and
    the read refresh's own `finally` then deleted the WINNER's claim, so the
    very next read could fan out alongside the backfill it had just been made
    to yield to. Deliberate preemption and an unrelated process clearing
    somebody's lock were indistinguishable at the point of release; comparing
    what is there against what we took tells them apart.

    A mismatch is left ALONE rather than corrected: whoever holds it now owns
    releasing it, and this module has no standing to judge their claim.
    """
    if held is None:
        return
    current = tools_auth._meta_get(c, tools_auth._inflight_key(account_id))
    if current == held:
        tools_auth.release_refresh(c, account_id)


def _refresh_resource(c, account_id: str, resource: str, *,
                      automatic: bool = True, out=None) -> bool:
    """Refresh one resource of one account, subject to rate control.

    `automatic` is True for the inline refresh a read triggers and False for an
    explicit `sync`. It changes exactly one thing: our own minimum interval is
    skipped when an operator asked. A provider `Retry-After` binds both.

    Raises `RateControlDeferred` rather than returning quietly, because
    `tools_read._freshness` treats a clean return as "refreshed inline just
    now" — printing that next to an eight-hour-old figure would be a lie.

    **A deferral writes nothing.** It is not a failure — that is the whole
    reason it is a distinct class — so it does not touch `last_error`, which
    answers "what went wrong" and would otherwise lose the real cause rate
    control needs recorded; and it does not touch `last_attempt_at`, or a
    stream of reads
    would extend its own cooldown for ever. The durable state a deferral is
    computed FROM (`next_retry_after`, `last_attempt_at`) is already there, so
    a copy of the conclusion beside it could only drift from it.

    **Returns whether the refresh actually COMPLETED**. A capped
    pagination returns normally and leaves the ledger safe, so a caller
    that only checked for an exception reported "refreshed" over a run that
    fetched part of the history and stopped. `sync` reads this return value.
    """
    if resource not in RESOURCES:
        # Never interpolated into the message: an unknown resource is a string
        # this process did not choose, and this output is line-oriented.
        raise ValueError("unknown resource; this plugin fetches %s"
                         % " and ".join(RESOURCES))
    reason = tools_auth.admit_refresh(c, account_id, resource,
                                      automatic=automatic)
    if reason:
        raise RateControlDeferred(reason)
    held = _claim(c, account_id)
    if held is None:
        raise RateControlDeferred(
            "another refresh for this account is already in flight; only one "
            "runs at a time")
    try:
        return _do_refresh(c, account_id, resource, out=out)
    except Exception as exc:                     # noqa: BLE001 — recorded, re-raised
        _note_failure(c, account_id, resource, exc)
        raise
    finally:
        _release_own(c, account_id, held)


def _do_refresh(c, account_id: str, resource: str, out=None) -> bool:
    row = c.execute("SELECT * FROM accounts WHERE account_id=?",
                    (account_id,)).fetchone()
    if row is None:
        raise RuntimeError("unknown account")
    account = dict(row)
    session_id = account.get("session_id")
    if not session_id or not account.get("uid"):
        raise NotLinked("this account is not bound to a live consent")
    # BEFORE the attempt stamp below, which CREATES the row when there is none
    # — reading it afterwards found this call's own empty row every time and
    # "restored" its NULLs over whatever the fetch went on to write. The record
    # this protects is the one that existed before this refresh ran.
    standing = c.execute(
        "SELECT completeness, last_success_session, last_error FROM sync_state"
        " WHERE account_id=? AND resource='transactions'",
        (account_id,)).fetchone()
    now = tools_auth._utcnow_iso()
    c.execute("INSERT INTO sync_state(account_id, resource, last_attempt_at)"
              " VALUES (?,?,?) ON CONFLICT(account_id, resource) DO UPDATE SET"
              " last_attempt_at=excluded.last_attempt_at",
              (account_id, resource, now))
    ais = tools_auth._ais()
    if resource == "balances":
        returned = []
        for entry in ais.balances(account.get("uid")):
            amount = entry.get("balance_amount") or {}
            currency = amount.get("currency") or account.get("currency") or "EUR"
            # `balance_type` and `reference_date` are provider text and this is
            # their writer. The read side is already fenced/neutralised;
            # neutralising here as well means the ledger itself never holds a
            # value that could forge a line, so a future reader that forgets is
            # not the only thing standing between a bank payload and the
            # operator. `_neutralized` also clips, and a balance type longer
            # than that is not a balance type.
            balance_type = (tools_read._neutralized(entry.get("balance_type"))
                            or "UNKNOWN")
            c.execute(
                "INSERT INTO balances(account_id, balance_type, amount_minor,"
                " currency, reference_date, fetched_at) VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(account_id, balance_type) DO UPDATE SET"
                " amount_minor=excluded.amount_minor,"
                " currency=excluded.currency,"
                " reference_date=excluded.reference_date,"
                " fetched_at=excluded.fetched_at",
                (account_id, balance_type,
                 money.to_minor(str(amount.get("amount")), currency), currency,
                 tools_read._neutralized(entry.get("reference_date")) or None,
                 now))
            returned.append(balance_type)
        _reconcile_balance_types(c, account_id, returned)
        # LAST, and that ordering is the safety property: every intermediate
        # state is honest. A crash after the upserts but before the delete
        # leaves an extra row AND no success stamp, so the freshness note goes
        # on showing the previous sync's age rather than vouching for a set
        # this run never finished reconciling.
        c.execute("UPDATE sync_state SET last_success_at=?,"
                  " completeness='complete', last_error=NULL,"
                  " next_retry_after=NULL WHERE account_id=? AND resource=?",
                  (now, account_id, resource))
        return True

    # `flows.backfill` writes the transactions row of sync_state itself —
    # completeness, the shallow warning, and the ASPSP-drift note from
    # provenance.capability_warning. Stamping success over it here would erase
    # exactly the disclosures those fields exist to carry.
    #
    # AND SO WOULD LETTING A NARROW RUN'S OWN STAMP STAND. `flows.backfill`
    # is documented as the exhaustive deep backfill inside the fresh-SCA window,
    # and its success path writes `completeness='complete'` plus
    # `last_success_session` unconditionally. This module is the first caller to
    # invoke it with a NARROW window (`last booked date - 7 days`), so a
    # nine-day run that completes writes the same claim a nine-YEAR run
    # writes — over a row durably marked `partial`. One routine refresh,
    # and: the operator-visible "(completeness=partial — this range is
    # incomplete)" disclosure disappeared from all three read tools; the cause
    # was overwritten with SHALLOW_NOTE, which a narrow window makes true on
    # every refresh that returns rows; and `apply.deep_fetch_complete` — the
    # predicate three call sites stand on — flipped False to True on the
    # strength of nine days.
    #
    # The discipline, applied here and one layer down: a later routine pass
    # must not overwrite a standing finding with an assessment that was
    # never about that finding. So a narrow run puts back exactly what it found.
    # It still contributes everything it genuinely established — the rows, the
    # coverage, `last_attempt_at`, `last_success_at`, `oldest_fetched` — and the
    # standing deep-history record travels intact WITH ITS CAUSE, because a
    # finding whose reason has been overwritten is an orphaned cause.
    #
    # AND ONLY WHERE THIS RUN HAS NOTHING BETTER TO SAY. A condition that asks
    # whether the run was NARROW and whether a standing record EXISTED — and
    # never what the run itself just discovered — lets a narrow run that hit
    # the page cap write its own `partial` + CAPPED_NOTE and have them put
    # straight back to the pre-run `complete`: the cause NULLed,
    # `deep_fetch_complete` flipped to True, and the incompleteness disclosure
    # gone from the read tools, on the strength of a run that fetched NOTHING.
    # That is this branch's own defect turned on a FRESHER victim — and worse
    # than the one it exists for, because nothing re-creates the erased
    # finding: the next narrow run that completes writes `complete`
    # legitimately, so one capped run loses it for good.
    #
    # The restore is therefore scoped, in the WHERE clause, to a row this run
    # left `complete`. That is the record itself rather than a proxy for it:
    # `result["capped"]` names ONE cause of an incomplete run, and any branch
    # of `flows.backfill` that records `partial` for another reason would slip
    # past a guard that reads it. The rule the ledger owns — a narrow pass may
    # restore a STRONGER standing claim, never over a WEAKER current one — is
    # here as a predicate on the exact bytes about to be overwritten, so there
    # is no window in which the two can disagree. An unrecognised value fails
    # closed: the run keeps its own finding.
    floor_days = _refresh_window_days(c, account_id)
    result = flows.backfill(ais, c, account, session_id, floor_days=floor_days)
    if out is not None:
        # Classifier trailer facts: server-generated ids and the FINAL-state
        # auto-tagged count, straight from apply_plan.
        out["new_row_ids"] = list(result.get("new_row_ids") or [])
        out["auto_tagged"] = int(result.get("auto_tagged") or 0)
        out["needs_classification"] = int(
            result.get("needs_classification") or 0)
    if floor_days < flows.BACKFILL_FLOOR_DAYS and standing is not None:
        c.execute(
            "UPDATE sync_state SET completeness=?, last_success_session=?,"
            " last_error=? WHERE account_id=? AND resource='transactions'"
            " AND completeness='complete'",
            (standing["completeness"], standing["last_success_session"],
             standing["last_error"], account_id))
    # The result is READ, not discarded. A capped run returns normally, so
    # "no exception" was never the same thing as "the history is here".
    # The session is named explicitly — `flows.backfill` stamps
    # `last_success_session` with this exact value, and `backfill_complete`
    # requires that stamp rather than accepting any row it happens to find.
    return tools_auth.backfill_complete(c, account_id, result,
                                        session_id=session_id)


# --------------------------------------------------------------------------
# tools
# --------------------------------------------------------------------------

@register("label_account",
          "Set an account's friendly name, personal/company category, and "
          "whether it is included in answers. Protected: casa demands an "
          "operator grant.",
          {"type": "object",
           "properties": {"account_id": {"type": "string"},
                          "label": {"type": "string"},
                          "category": {"type": "string",
                                       "enum": list(CATEGORIES)},
                          "included": {"type": "boolean"}},
           "required": ["account_id"]})
def label_account(args: dict) -> str:
    refusal = _require_declared("label_account")
    if refusal:
        return refusal
    c = _conn()
    account_id = str(args.get("account_id") or "")
    sets, params, changed = [], [], []
    if args.get("label") is not None:
        # NEUTRALISED, not merely clipped. `tools_read._label` renders this
        # column UNFENCED, on the stated grounds that it is the operator's own
        # text — and its sweep SKIP set records that as the reason it is not
        # swept. The operator does approve this exact argument through casa's
        # grant, but they approve a STRING; they are not granting a licence to
        # forge the `Coverage:` line the reader acts on, and the model that
        # composed the argument has been reading bank text all turn. Closing it
        # at the writer is what keeps the read side's exemption honest.
        sets.append("label=?")
        params.append(tools_read._neutralized(args["label"]))
        changed.append("label")
    if args.get("category") is not None:
        category = str(args["category"])
        if category not in CATEGORIES:
            # The offered value is deliberately not echoed. An unknown category
            # also removes the account from every scope-filtered answer
            # silently, which is why this refuses rather than storing it.
            return ("category must be one of: %s. Nothing has been changed."
                    % ", ".join(CATEGORIES))
        sets.append("category=?")
        params.append(category)
        changed.append("category")
    if args.get("included") is not None:
        sets.append("included=?")
        params.append(1 if args["included"] else 0)
        changed.append("included")
    if not sets:
        return "Nothing to change: pass at least one of label, category, included."
    cur = c.execute("UPDATE accounts SET " + ", ".join(sets) +
                    " WHERE account_id=?", params + [account_id])
    if not cur.rowcount:
        return "No account with that account_id. Run list_accounts."
    lines = ["Updated %s: %s." % (tools_read._neutralized(account_id),
                                  ", ".join(changed))]
    # Reported from the STORED row, not from the argument: what the operator
    # needs to know is what the ledger now holds.
    included = c.execute("SELECT included FROM accounts WHERE account_id=?",
                         (account_id,)).fetchone()[0]
    if args.get("included") is not None and not included:
        lines.append("This account is now EXCLUDED: it is dropped from every "
                     "balance and every total until it is included again, and "
                     "the totals will say one account is missing rather than "
                     "counting it as zero.")
    elif args.get("included") is not None:
        lines.append("This account is now included in every balance and every "
                     "total.")
    lines.append(GATE_NOTE)
    return "\n".join(lines)


def _account_line(name: str, resource: str, tail: str) -> str:
    return "  %s / %s: %s" % (name, resource, tail)


@register("sync",
          "Force a refresh now, regardless of cache age. Still honours a "
          "provider Retry-After.",
          {"type": "object",
           "properties": {"account": {"type": "string"},
                          "resource": {"type": "string",
                                       "enum": list(RESOURCES)}}})
def sync(args: dict) -> str:
    c = _conn()
    requested = str(args.get("resource") or "")
    if requested and requested not in RESOURCES:
        # Never echoed back: the schema's enum is advertised to the model, not
        # enforced here, so this argument is an arbitrary string and this
        # output is line-oriented.
        return ("resource must be one of: %s, or omitted to sync both. "
                "Nothing has been fetched." % ", ".join(RESOURCES))
    sql = "SELECT * FROM accounts WHERE included=1"
    params: list = []
    if args.get("account"):
        sql += " AND account_id=?"
        params.append(str(args["account"]))
    accounts = [dict(r) for r in c.execute(sql + " ORDER BY account_id", params)]
    # The same count `tools_read` discloses behind every total, computed by the
    # same function so the two can never disagree about who was left out.
    excluded = tools_read._excluded_count(c, args)
    if not accounts:
        msg = "No included accounts to sync."
        if excluded:
            msg += (" %d account(s) matched but are EXCLUDED by their include "
                    "flag; label_account can include one again." % excluded)
        return msg
    resources = [requested] if requested else list(RESOURCES)
    lines = []
    batch_new = batch_tagged = batch_needs = 0
    for account in accounts:
        # The same handle the read tools print, through the same fence:
        # `accounts.name` is written verbatim from the bank's own payload.
        name = tools_read._label(account)
        account_id = account["account_id"]
        for resource in resources:
            try:
                res_out = {}
                if _refresh_resource(c, account_id, resource,
                                     automatic=False, out=res_out):
                    lines.append(_account_line(name, resource, "refreshed"))
                else:
                    # A capped pagination returns normally, so "refreshed" was
                    # printed over a run that fetched part of the history and
                    # stopped. The ledger is marked partial and nothing was
                    # tombstoned, but the operator has to be told here — this
                    # is where they are looking. This line now has TWO causes
                    # and must be true of both — the run that just hit the page
                    # cap, and the account whose history was already marked
                    # partial and which a narrow refresh cannot repair. The old
                    # wording asserted the first ("the fetch stopped before the
                    # history was exhausted", "is NOT a refresh"), which is
                    # false of the second: that run completed and its rows were
                    # stored.
                    lines.append(_account_line(
                        name, resource,
                        "INCOMPLETE — whatever this run fetched has been "
                        "stored, but this account's history is still marked "
                        "partial, so answers about it cover an incomplete "
                        "range. If the last run stopped at the page cap, "
                        "running sync again resumes the remaining pages; a "
                        "routine refresh cannot close a deep-history gap, "
                        "because only a fresh SCA reopens that window — run "
                        "link_bank against that bank to renew the consent."))
            except RateControlDeferred as exc:
                lines.append(_account_line(
                    name, resource,
                    "DEFERRED — %s. Nothing was called and the previous cached "
                    "answer is unchanged." % tools_read._neutralized(exc)))
            except Exception as exc:             # noqa: BLE001
                # The class name only — a provider body must never reach this
                # line. `NO_BALANCES_EXIT` is not a message: it is OUR literal,
                # appended for the one failure that is permanent until the
                # operator acts, and for no other. See the constant for why it
                # is not printed beside every failure.
                lines.append(_account_line(
                    name, resource,
                    "FAILED (%s) — the previous cached answer is unchanged and "
                    "still labelled with its own age%s%s"
                    % (type(exc).__name__,
                       _recorded_wait(c, account_id, resource),
                       NO_BALANCES_EXIT
                       if isinstance(exc, NoBalancesReturned) else "")))
            else:
                batch_new += len(res_out.get("new_row_ids") or [])
                batch_tagged += res_out.get("auto_tagged") or 0
                batch_needs += res_out.get("needs_classification") or 0
    if batch_new:
        # needs is the propagated FINAL-STATE workable count, never
        # new-minus-tagged: a parked/terminal insert is neither bucket, so
        # this line and the Queue line agree.
        lines.append("Classification: %d new transaction(s); %d "
                     "auto-tagged by rules; %d need classification."
                     % (batch_new, batch_tagged, batch_needs))
    workable, parked = rules.queue_totals(c)
    lines.append("Queue: %d workable transaction(s), %d awaiting the "
                 "operator (all accounts, included or not)."
                 % (workable, parked))
    if workable + parked:
        lines.append("Unclassified rows await the classifier.")
    return ("Forced refresh (our own cache-age cooldown ignored; a provider "
            "Retry-After is still honoured).\n" + "\n".join(lines))


def _recorded_wait(c, account_id: str, resource: str) -> str:
    """The provider backoff this failure just recorded, or ''.

    Read back from the durable row rather than passed down from the handler,
    because the row is what `admit_refresh` will actually consult next time —
    naming anything else would be describing a different number from the one
    that binds.

    It fires only when there IS a backoff. A caveat that appears on every line
    is normalised within a week, and then the one failure that genuinely
    stopped refreshing looks exactly like the others.
    """
    row = c.execute("SELECT next_retry_after FROM sync_state WHERE"
                    " account_id=? AND resource=?",
                    (account_id, resource)).fetchone()
    until = tools_read._parse_ts(row[0]) if row else None
    if until is None or until.timestamp() <= tools_auth._now_s():
        return ""
    # `next_retry_after` is written by `_iso_at` in this module and by nothing
    # else (`flows` only ever NULLs it), so it is ours to print.
    return (". The provider asked us to wait: nothing will be fetched for this "
            "account until %s, and the next sync will say DEFERRED rather than "
            "ask again" % row[0])


#: Transactions columns deliberately kept OUT of an export, each with the
#: reason it is not simply an omission. Everything else is derived from `PRAGMA
#: table_info` and exported BY DEFAULT — the same fail-closed inversion as the
#: unfenced-field sweep, and for the same reason: a hand-written list held 14
#: of the table's 24 columns and silently dropped `review_reason` and
#: `state_reason`, the two columns that answer "why does this row need review?"
#: — from a file its own output called "the full local ledger".
EXPORT_EXCLUDE = {
    "raw_json": "the verbatim provider payload, unbounded and already held in "
                "the ledger; an export is the operator's copy of the LEDGER, "
                "not a wire log",
}


def _export_columns(c) -> list:
    columns = [row[1] for row in c.execute("PRAGMA table_info(transactions)")]
    stale = [name for name in EXPORT_EXCLUDE if name not in columns]
    if stale:
        # A renamed or dropped column would leave an exclusion that reads as
        # "considered and rejected" while excluding nothing.
        raise RuntimeError("export exclusion names no such column: %s"
                           % ", ".join(sorted(stale)))
    return [name for name in columns if name not in EXPORT_EXCLUDE]


@register("export_history",
          "Write the full local ledger to a file under the plugin's data "
          "directory, as CSV or JSONL, and return the path.",
          {"type": "object",
           "properties": {"format": {"type": "string",
                                     "enum": ["csv", "jsonl"]}}})
def export_history(args: dict) -> str:
    c = _conn()
    fmt = str(args.get("format") or "csv").lower()
    if fmt not in ("csv", "jsonl"):
        return "format must be csv or jsonl."
    data_dir = os.environ.get("CLAUDE_PLUGIN_DATA")
    if not data_dir:
        raise RuntimeError("CLAUDE_PLUGIN_DATA is not set")
    columns = _export_columns(c)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = Path(data_dir) / ("export-%s.%s" % (stamp, fmt))
    rows = [dict(r) for r in c.execute(
        "SELECT %s FROM transactions ORDER BY account_id, booking_date, row_id"
        % ", ".join(columns))]
    with open(path, "w", encoding="utf-8", newline="") as handle:
        if fmt == "csv":
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        else:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    os.chmod(path, 0o600)
    return "\n".join([
        "Exported %d transaction(s) as %s, every column of the ledger except "
        "%s. The file is yours to keep and is written in full — it is a file "
        "for you, not model context, so nothing is clipped or delimited, and "
        "it therefore contains bank-supplied text exactly as the bank sent it."
        % (len(rows), fmt, ", ".join(sorted(EXPORT_EXCLUDE))),
        "Path: %s" % path,
    ])


# The read tools perform the inline refresh through this seam. Assigned at
# import, so importing tools_refresh is what wires refreshing on.
tools_read.REFRESHER = _refresh_resource
