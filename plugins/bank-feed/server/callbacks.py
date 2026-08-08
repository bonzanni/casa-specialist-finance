# plugins/bank-feed/server/callbacks.py
"""Consumer half of casa's authorization-callback contract, from casa v0.147.

casa owns mint/collect/ack, the spool grammars, the TTLs and redelivery. We own
the durable attempt row, the lease, validation before exchange, and the outcome.
See docs/reference/casa-compatibility.md for the division of labour in full.

Nothing in this module waits, polls or schedules: casa's nudge ladder — publish
+0 s, +60 s, +3 min, +8 min, then +30 min and +2 h, six accepted dispatches,
resuming across restarts — is the continuation mechanism, and `run_collection`
is simply what a nudged turn calls.
"""
from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

#: The callback protocol this consumer implements: casa's v2 mint envelope with
#: the v1 attempt and result records.
PROTOCOL_VERSION = 2

#: Half one of the compatibility gate: casa's own IN-BAND schema constant, in
#: the very module whose records we parse. `(module, constant, expected)`.
#: Half two is `_verify_surface`, and `check_supported` runs BOTH.
#:
#: Deliberately NOT `CASA_VERSION`. That variable is exported into casa's s6
#: service environment and reaches a plugin's stdio server by process
#: inheritance alone; nothing guarantees it arrives, and the global constraints
#: forbid declaring it in `.mcp.json::env`. A guard keyed on it would fail
#: closed on the WRONG signal and brick bank linking on a healthy deployment.
#:
#: Deliberately NOT `callback_spool.REMOVAL_SCHEMA_VERSION` either. That
#: constant versions casa's PLUGIN-REMOVAL records — a store this consumer
#: never opens. Cross-checking it read like a second opinion and was in fact a
#: reading of an unrelated file: it can move when nothing we use moved, and sit
#: at 1 while everything we use changes.
#:
#: WHAT THIS GATE DOES NOT COVER, stated plainly because it is load-bearing:
#: the three halves together cover the attempt-record schema, the consumer API
#: surface, and the TTL constants we copy. They do NOT cover the hold semantics
#: of a `.collect-*` inode, or how `publish_result` constructs a result record.
#: Both can change while all three halves keep passing. This is a
#: BEST-AVAILABLE check, NOT a protocol version; the real fix is a dedicated
#: callback-consumer protocol constant in casa, which casa#401 asks for.
EXPECTED_SCHEMAS = (
    ("callback_attempts", "SCHEMA_VERSION", 1),      # the attempt record
)

#: Half three: casa constants we DUPLICATE, checked against the module we
#: copied them from. A copied value is the one thing that drifts in total
#: silence — casa lengthens or shortens `RESULT_TTL_S`, our copy does not move,
#: and a flow expires while we still believe we have time to exchange (or we
#: refuse a flow that had minutes left). This module's `RESULT_TTL_S` is DERIVED
#: from this tuple rather than written out again, so there is exactly one copy
#: and it is the one under the gate. `RESULT_TTL_S` is the only casa constant
#: we duplicate: `MIN_REMAINING_S` and `MINT_TS_TOLERANCE_S` are our own
#: policy, and `PENDING_TTL_S` we never copy.
EXPECTED_SPOOL_TTLS = (
    ("RESULT_TTL_S", 900),
)

#: Our one declared callback (`casa.callbacks: [{"name": "authorize"}]`).
#: casa routes it as `plg-<registry name>--authorize`.
CALLBACK_NAME = "authorize"

#: The published RESULT record's version — 1, and deliberately NOT the protocol
#: number above. casa's `publish_result` augments a `{"v": 1, ...}` record with
#: `meta` and `minted_ts`; `{"v": 2, "meta": ...}` is the separate MINT
#: ENVELOPE, which casa reads and never republishes.
RESULT_RECORD_V = 1

DEFAULT_SPOOL_ROOT = "/data/callbacks"
DEFAULT_CASA_ROOT = "/opt/casa"

#: A live collector re-stamps its lease this often; three missed re-stamps mean
#: it is dead. Both constants are load-bearing — the TTL is derived from the
#: heartbeat, and `begin_exchange` is the re-stamp point (the plugin has no
#: background thread to heartbeat from, and may not grow one).
LEASE_HEARTBEAT_S = 30
LEASE_TTL_S = 3 * LEASE_HEARTBEAT_S

#: How far the record's echoed `minted_ts` may sit from our recorded mint clock.
#: Normally ZERO: `mint()` re-stamps `created_at` from the minted artifact's
#: mtime, and casa preserves that inode's mtime through the claim before
#: echoing it back as `minted_ts`. The window only covers the degraded path
#: where the artifact could not be stat'd and the pre-mint wall clock stands in.
MINT_TS_TOLERANCE_S = 5.0

#: The `meta` keys casa echoes back, paired with the attempt column each is stored
#: in. `mint` writes through this map and `_meta_of` reads back through it, so
#: the echoed meta is comparable EXACTLY without a second copy on disk.
#:
#: `account_id` and `generation` together are the GENERATION FENCE: a renewal
#: or repair names the account it is for and the session generation it expected
#: to find there. A callback that arrives after a newer session has already
#: rebound that account is stale, and it is stopped before the exchange rather
#: than allowed to overwrite the newer binding.
META_COLUMNS = (("purpose", "purpose"), ("aspsp", "aspsp_name"),
                ("country", "country"), ("psu_type", "psu_type"),
                ("account_id", "account_id"),
                ("generation", "expected_generation"))

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

#: The minimum surface a supported `callback_spool` must expose, with the
#: number of parameters each entry point takes. Checked in addition to the
#: version table, never instead of it.
_REQUIRED_ARITY = {"mint": 3, "collect": 2, "ack": 2, "state_hash": 1}

_NO_ROUTE = (
    "This plugin has no callback route: it is unconsented, unassigned, or the "
    "casa public URL is invalid. Ask the operator to check the callback "
    "consent; bank linking cannot start until the route is live.")


class Unsupported(RuntimeError):
    """casa's callback protocol is absent, unreadable or outside the tested
    range. Always carries an operator-facing sentence."""


class Invalid(ValueError):
    """The published record is malformed or does not belong to this attempt."""


class Indeterminate(RuntimeError):
    """An exchange may already have happened; never retry the code."""


def _import_casa(name: str):
    """Import one casa runtime module from `$CASA_ROOT` (default `/opt/casa`),
    converting an absent module into the operator-facing refusal.

    APPENDED to `sys.path`, never inserted at the front: `/opt/casa` ships 119
    top-level modules, and this plugin's own server directory ships `store`,
    `money`, `ingest` and `provenance` — ordinary-enough names to collide.
    Exactly ONE of the four collides today, checked against the CASA_ROOT
    checkout rather than assumed: casa ships `provenance.py` (exposing
    `Provenance` / `turn_provenance` / `sanitize_external_context`, nothing
    like ours) and ships no `store.py`, `money.py` or `ingest.py` — its
    nearest names are `plugin_store.py` and `explanation_store.py`, which do
    not collide. One live collision is all the ordering argument needs; the
    other three names are listed because they are the kind of single word a
    later casa release could claim, not because they clash now. An
    insert-at-0 would let casa's module win an `import provenance` issued by
    our own `store.py`, and the failure would surface nowhere near here: the
    import would succeed silently, and `store.open_db()`'s seeding call would
    fail later with an `AttributeError` on a module that never even looked
    like a refusal. Appending is safe rather than merely convenient: the
    transitive closure of casa-internal imports reachable from
    `callback_spool` / `callback_attempts` is exactly those two modules
    (`callback_spool` imports stdlib plus `callback_attempts`;
    `callback_attempts` imports only `json`, `math`, `re`), and we ship
    neither of those two names — so nothing on an earlier `sys.path` entry can
    ever satisfy either import instead of casa's real one.
    """
    root = os.environ.get("CASA_ROOT") or DEFAULT_CASA_ROOT
    if root not in sys.path:
        sys.path.append(root)
    try:
        return importlib.import_module(name)
    except ImportError:
        raise Unsupported(
            f"casa's {name} is not importable from {root}; bank linking is "
            "unavailable. This plugin only runs inside casa.") from None


def _casa_version() -> str:
    """DIAGNOSTICS ONLY — never a compatibility decision (see
    :data:`EXPECTED_SCHEMAS`). Present it so an operator reading a refusal can
    still see which casa they are on; its absence disables nothing."""
    return os.environ.get("CASA_VERSION") or "unknown"


def check_supported() -> int:
    """Prove casa's callback contract is the one we were tested against.

    THREE halves run here, and all three fail closed:

    1. the in-band attempt-record schema (`EXPECTED_SCHEMAS`),
    2. the consumer API surface we actually call (`_verify_surface`), and
    3. the casa constants we DUPLICATE (`EXPECTED_SPOOL_TTLS`).

    Any one alone is weak — a matching constant next to a renamed `collect` is
    not compatibility, a present `collect` next to a changed record shape is not
    either, and both together still let a copied TTL drift in silence.
    Together they are the strongest signal casa exports today, and they are
    still NOT a protocol version: see `EXPECTED_SCHEMAS` for exactly what stays
    uncovered. A consumer that guesses at a changed protocol is worse than one
    that stops. Returns the protocol version on success.
    """
    for module_name, constant, expected in EXPECTED_SCHEMAS:
        module = _import_casa(module_name)
        found = getattr(module, constant, None)
        if isinstance(found, bool) or found != expected:
            raise Unsupported(
                f"casa's {module_name}.{constant} is {found!r}, not "
                f"{expected!r}: the callback schema this plugin was tested "
                f"against has changed (casa release: {_casa_version()}). "
                "Bank linking is unavailable until this plugin is updated.")
    spool_module = _import_casa("callback_spool")
    _verify_surface(spool_module)
    for constant, ours in EXPECTED_SPOOL_TTLS:
        found = getattr(spool_module, constant, None)
        if isinstance(found, bool) or not isinstance(found, (int, float)) \
                or found != ours:
            raise Unsupported(
                f"casa's callback_spool.{constant} is {found!r}, but this "
                f"plugin copies it as {ours!r}. A duplicated timeout that "
                "drifts is invisible at runtime — a flow would expire while we "
                "still believed we had time to exchange, or be refused with "
                f"minutes left (casa release: {_casa_version()}). Bank linking "
                "is unavailable until this plugin is updated.")
    return PROTOCOL_VERSION


def _verify_surface(mod) -> None:
    """Half two of the gate: the consumer entry points exist, are callable,
    and expose AT LEAST as many parameters as the arity we call them with.

    That is a bare parameter COUNT, not a proof of the arity we call them
    with: a `mint` whose `meta` moved keyword-only, or that grew a fourth
    REQUIRED parameter, still has "at least 3" parameters and passes this
    gate, then raises a raw `TypeError` at the call site instead of the
    operator-facing `Unsupported` this function exists to produce. Left as
    a known, latent gap (not fixed here) — every casa signature checked
    against today is plain positional-or-keyword, so it is fail-closed
    either way in practice, just not for the reason this docstring used to
    claim. Shape alone is never sufficient, which is why this runs
    *alongside* the schema constant, never instead."""
    for name, arity in sorted(_REQUIRED_ARITY.items()):
        fn = getattr(mod, name, None)
        if not callable(fn):
            raise Unsupported(
                f"casa's callback_spool exposes no {name}(); the callback "
                "protocol has changed. Bank linking is unavailable.")
        try:
            params = inspect.signature(fn).parameters
        except (TypeError, ValueError):       # pragma: no cover - builtins
            raise Unsupported(
                f"casa's callback_spool.{name}() has no inspectable "
                "signature; refusing to guess at the protocol.") from None
        if len(params) < arity:
            raise Unsupported(
                f"casa's callback_spool.{name}() takes {len(params)} "
                f"arguments, not {arity} — the callback protocol has changed. "
                "Bank linking is unavailable.")
    for const in ("COLLECT_PREFIX", "ACK_PREFIX"):
        if not isinstance(getattr(mod, const, None), str):
            raise Unsupported(
                f"casa's callback_spool has no {const}; the callback protocol "
                "has changed. Bank linking is unavailable.")


def spool():
    """Import casa's `callback_spool` and prove it is a protocol we have
    tested against. Importing is what "writing a consumer" means here — this
    is a bundled specialist shipped with casa, not a standalone plugin, and a
    second byte-exact implementation of the protocol is worse than an
    error."""
    check_supported()          # schema constant AND consumer surface, both
    return _import_casa("callback_spool")


def _effective(plugin: str) -> str:
    """casa's routed callback name: `plg-<plugin>--<declared>`
    (`plugin_callbacks.effective_name`)."""
    return f"plg-{plugin}--{CALLBACK_NAME}"


def discover(plugin_root: str) -> dict:
    """Read the `.index` entry casa publishes for this artifact.

    Called on EVERY entry, never cached: a plugin upgrade changes
    the artifact path and therefore the index key, so a cached answer would
    point at a directory nobody reads.

    casa's payload is `dict(ready_payload, plugin_dir=<registry name>)`, so its
    `plugin_dir` is a NAME, not a path. We return both: `plugin` (the name,
    which the result record's `plugin` field must equal) and `plugin_dir` (the
    resolved `<spool_root>/<name>` directory that casa's mint/collect/ack take).
    """
    root = Path(os.environ.get("CASA_CALLBACK_SPOOL_ROOT") or DEFAULT_SPOOL_ROOT)
    key = hashlib.sha256(
        os.path.realpath(plugin_root).encode("utf-8")).hexdigest()
    try:
        payload = json.loads(
            (root / ".index" / f"{key}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Unsupported(_NO_ROUTE) from None
    if not isinstance(payload, dict):
        raise Unsupported(_NO_ROUTE)
    name = payload.get("plugin_dir")
    routed = payload.get("callbacks")
    if not isinstance(name, str) or not name or not isinstance(routed, dict):
        raise Unsupported(_NO_ROUTE)
    entry = routed.get(CALLBACK_NAME)
    if not isinstance(entry, dict):
        raise Unsupported(
            f"casa is not routing this plugin's {CALLBACK_NAME!r} callback. "
            "Ask the operator to re-run the callback consent.")
    effective = entry.get("effective")
    redirect_uri = entry.get("redirect_uri")
    if not isinstance(redirect_uri, str) or not redirect_uri:
        raise Unsupported(_NO_ROUTE)
    # Cross-check the routed name against the name we bind results against.
    # Failing here is far better than failing at every validation later.
    if effective != _effective(name):
        raise Unsupported(
            "casa's routed callback name is not the one this plugin binds "
            "against; refusing to start an authorization it could not verify.")
    return {"plugin": name, "plugin_dir": str(root / name),
            "effective": effective, "redirect_uri": redirect_uri,
            "spool_root": str(root)}


def _normalised_meta(meta: dict) -> dict:
    """Exactly the `META_COLUMNS` keys — no more, no less.
    Minting a normalised dict is what makes the echoed copy comparable, and it
    is why a caller that forgets `generation` gets an explicit NULL rather than
    an absent key that would compare unequal forever."""
    src = meta or {}
    return {key: src.get(key) for key, _column in META_COLUMNS}


def _meta_of(attempt: dict) -> dict:
    """Rebuild the minted `meta` from the attempt row's own columns."""
    return {key: attempt.get(column) for key, column in META_COLUMNS}


def mint(conn, sp, plugin_dir: str, meta: dict, redirect_uri: str) -> str:
    """Write our durable row BEFORE minting, then mint the v2 envelope.

    The six meta columns are DERIVED from `META_COLUMNS`, both the column
    list and the value tuple — never typed out by hand. `_meta_of` already
    reads back through that same map; a hand-typed INSERT here would only
    have to drop, rename or misalign one column for the echoed `meta` to stop
    matching the minted one for ever, silently failing the equality every real
    callback is checked against in `validate_record`. The SYMPTOM differs by
    cause and only one of the three is a `None`: a DROPPED or RENAMED column
    leaves `_meta_of` reading a column `mint` never wrote, so that key echoes
    back `None`; a MISALIGNED pair (two columns swapped) echoes the OTHER
    key's real value, which is not `None` and can even look plausible. Both
    fail the equality permanently and silently, which is the property that
    matters here (a fake that built its INSERT from a fixed list, rather than
    from `META_COLUMNS`, is exactly the defect shape the generation fence
    was written to prevent — relocating that same shape into production here
    would be worse, not better, for having a passing test suite on top of
    it).

    `created_at` is re-stamped from the minted artifact afterwards: casa's
    `publish_result` echoes `minted_ts = claim.mtime`, and `rename(2)`/`link(2)`
    preserve an inode's mtime, so the pending file's mtime IS the value we will
    later be asked to match.
    """
    normalised = _normalised_meta(meta)
    state = secrets.token_urlsafe(32)     # 43 chars of the legal state charset
    state_hash = sp.state_hash(state)
    meta_columns = [column for _key, column in META_COLUMNS]
    meta_values = [normalised[key] for key, _column in META_COLUMNS]
    columns = ["state_hash", "state_secret", *meta_columns,
               "plugin_dir", "redirect_uri", "created_at", "phase"]
    placeholders = ",".join("?" * (len(columns) - 1))   # 'phase' is literal
    conn.execute(
        f"INSERT INTO attempts({','.join(columns)})"
        f" VALUES ({placeholders},'minted')",
        (state_hash, state, *meta_values, str(plugin_dir), redirect_uri,
         time.time()))
    try:
        path = sp.mint(plugin_dir, state, normalised)
    except Exception:
        # Retire the row we just wrote rather than leave a `minted` pending
        # nothing will ever collect: whatever failed, THIS attempt has no
        # envelope of its own to be answered.
        #
        # "No envelope exists" is true of every mint failure but one, and the
        # exception is worth naming because it is the opposite: casa raises
        # `FileExistsError` ("state already minted") precisely BECAUSE an
        # envelope for this state hash already exists — `mint` publishes by
        # `link(2)` and treats the final name existing as a hard error, never
        # an overwrite. That is reachable only when casa's spool holds an
        # envelope our own `attempts` table does not, since `state_hash` is
        # that table's PRIMARY KEY and a repeat would have failed the INSERT
        # above. Retiring is still right there: the pre-existing envelope was
        # minted against a different row's secret and meta, so this row could
        # never be the one to answer it.
        conn.execute(
            "UPDATE attempts SET phase='abandoned', outcome='mint_failed'"
            " WHERE state_hash=?", (state_hash,))
        raise
    try:
        stamped = os.stat(os.fspath(path)).st_mtime
    except (OSError, TypeError, ValueError):
        stamped = None                    # degraded: the wall clock stands in
    if stamped is not None:
        conn.execute("UPDATE attempts SET created_at=? WHERE state_hash=?",
                     (stamped, state_hash))
    return state


def take_lease(conn, state_hash: str, owner: str, ttl_s: int = LEASE_TTL_S):
    """Take the per-state collection lease; returns the fencing token or None.

    Expiry alone is NEVER permission to retry an exchange — that is
    `begin_exchange`'s job. This only decides who may look.
    """
    now = time.time()
    row = conn.execute(
        "SELECT lease_token, lease_expiry FROM attempts WHERE state_hash=?",
        (state_hash,)).fetchone()
    if row is None:
        return None
    if row["lease_token"] and (row["lease_expiry"] or 0.0) > now:
        return None
    token = secrets.token_hex(8)
    # Compare-and-set on the token we just read. SQLite's `IS` is `=` with
    # NULL-equals-NULL semantics, so the never-leased case needs no second
    # statement, and a concurrent taker between the SELECT and here loses.
    cur = conn.execute(
        "UPDATE attempts SET lease_owner=?, lease_token=?, lease_expiry=?"
        " WHERE state_hash=? AND lease_token IS ?"
        " AND COALESCE(lease_expiry, 0.0) <= ?",
        (owner, token, now + ttl_s, state_hash, row["lease_token"], now))
    return token if cur.rowcount == 1 else None


def begin_exchange(conn, state_hash: str, fence: str) -> None:
    """Commit `exchange_started` BEFORE the provider call, under the fence.

    Two refusals, both `Indeterminate`, both meaning "do not post this code":
    a phase that shows an exchange already began (the provider has no
    idempotency key, so a second POST could burn a code the first spent), and
    a fencing token that no longer matches (another collector owns this flow
    and may be inside the provider call right now).

    The successful path also re-stamps the lease — this is the heartbeat point
    (`LEASE_HEARTBEAT_S`), and it exists here because the provider call is the
    one long operation in the loop and the plugin has no thread to beat from.
    """
    row = conn.execute("SELECT phase FROM attempts WHERE state_hash=?",
                       (state_hash,)).fetchone()
    if row is not None and row["phase"] in ("exchange_started", "exchanged",
                                            "indeterminate"):
        raise Indeterminate(
            "an exchange for this authorization was already started; probing "
            "rather than re-posting the code")
    cur = conn.execute(
        "UPDATE attempts SET phase='exchange_started', lease_expiry=?"
        " WHERE state_hash=? AND lease_token=?",
        (time.time() + LEASE_TTL_S, state_hash, fence))
    if cur.rowcount != 1:
        raise Indeterminate(
            "the collection lease moved to another collector before the "
            "exchange; not re-posting the code")


def _pairs(record: dict) -> list:
    query = record.get("query")
    if not isinstance(query, list):
        raise Invalid("record has no decoded query pair list")
    pairs = []
    for item in query:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise Invalid("record's query list is malformed")
        pairs.append((str(item[0]), str(item[1])))
    return pairs


def validate_record(record: dict, attempt: dict) -> dict:
    """Every check casa's callback contract requires before a code is
    exchanged.

    No message below interpolates a state, a code or a provider payload — the
    class of failure is the whole story.
    """
    if not isinstance(record, dict):
        raise Invalid("result record is not an object")
    if record.get("v") != RESULT_RECORD_V:
        # v2 is the MINT ENVELOPE's version; casa's published result record
        # stays v1 (callback_http builds it, publish_result augments it).
        raise Invalid(f"unexpected result record version {record.get('v')!r}")

    plugin_dir = attempt.get("plugin_dir")
    if not plugin_dir:
        raise Invalid("this attempt records no spool dir; cannot bind a result")
    plugin = os.path.basename(str(plugin_dir).rstrip("/"))
    if record.get("plugin") != plugin:
        raise Invalid("result record belongs to another plugin")
    if record.get("effective") != _effective(plugin):
        raise Invalid("result record carries another callback's routed name")

    # The binding: casa echoes back the meta we minted and the mint
    # clock of the pending inode. Without both, two concurrent flows can adopt
    # each other's results and misbind accounts.
    if record.get("meta") != _meta_of(attempt):
        raise Invalid("result record echoes another flow's meta")
    minted_ts = record.get("minted_ts")
    if isinstance(minted_ts, bool) or not isinstance(minted_ts, (int, float)):
        raise Invalid("result record carries no usable mint clock")
    created_at = attempt.get("created_at")
    if created_at is None or abs(
            float(minted_ts) - float(created_at)) > MINT_TS_TOLERANCE_S:
        raise Invalid("result record echoes another flow's mint clock")

    pairs = _pairs(record)
    states = [value for key, value in pairs if key == "state"]
    if len(states) != 1:
        raise Invalid(f"expected exactly one state, got {len(states)}")
    # `compare_digest` only accepts ASCII str; a minted state always is, and a
    # record carrying anything else is refused before the comparison.
    if not states[0].isascii() or not secrets.compare_digest(
            states[0], str(attempt["state_secret"])):
        raise Invalid("state does not match this attempt")
    if hashlib.sha256(states[0].encode("utf-8")).hexdigest() != \
            attempt.get("state_hash"):
        raise Invalid("state does not hash to this attempt's spool name")

    codes = [value for key, value in pairs if key == "code"]
    errors = [value for key, value in pairs if key == "error"]
    if codes and errors:
        raise Invalid("record carries both a code and an error")
    if len(codes) > 1:
        raise Invalid("record carries a duplicate code parameter")
    if errors:
        return {"code": None, "error": errors[0]}
    if not codes:
        raise Invalid("record carries neither a code nor an error")
    return {"code": codes[0], "error": None}


# ---------------------------------------------------------------------------
# Collection: turning an approval into a session.
#
# This is what a NUDGED TURN calls. It never waits for a redirect,
# never schedules anything, is idempotent because the nudge is at-least-once,
# and returns [] when there is nothing to collect.
# ---------------------------------------------------------------------------

import datetime                                       # noqa: E402
import glob                                           # noqa: E402
from typing import NamedTuple                         # noqa: E402

#: casa's result TTL — the artifact clock. The rename that creates
#: the hold preserves the mtime, so a `.collect-*` file ages from PUBLISH, not
#: from pickup.
#:
#: DERIVED from `EXPECTED_SPOOL_TTLS`, not written out a second time: this is a
#: value we copy from casa, and `check_supported` refuses to run when our copy
#: and `callback_spool.RESULT_TTL_S` disagree. Writing `900` again here would
#: create a second copy that the gate does not cover, which is the exact drift
#: the gate exists to catch.
RESULT_TTL_S = dict(EXPECTED_SPOOL_TTLS)["RESULT_TTL_S"]

#: The floor: below this much remaining artifact lifetime we do
#: not start an exchange at all — we record, ack, and offer a fresh link. The
#: authorization CODE dies at the provider (~10 min, RFC 6749) independently of
#: the artifact, and `minted_ts` is only a LOWER bound on its age, so there is
#: one rule here and not two.
MIN_REMAINING_S = 60

#: Phases OUR store considers finished. casa's ledger is derived from the live
#: artifacts and re-derived every pass, so a `done` record may legitimately
#: reopen — our own store is the durable truth.
#:
#: `review_required` is settled DELIBERATELY: the code has been spent, the
#: provider consent exists, and no amount of re-nudging turns an unverified
#: account set into a verified one. It needs an operator, not a retry.
SETTLED_PHASES = frozenset({"exchanged", "declined", "closed", "abandoned",
                            "review_required"})

#: The ONLY `Outcome.status` a caller may report to the operator as a completed
#: link, and the only one that may trigger the renewal handoff. It is a set of
#: one on purpose: a capped backfill's outcome is `partial`, and a caller
#: that branches on "did run_collection return without raising" rather than on
#: this set will report a capped backfill as a success.
SUCCESS_STATUSES = frozenset({"succeeded"})

#: Purposes whose attempt MUST carry the generation fence. A first link has
#: nothing to be stale against; a repair or a renewal always does, so an
#: attempt of those purposes carrying no `account_id` or no
#: `expected_generation` is REFUSED rather than waved through. See
#: `fence_verdict` for what that costs.
FENCED_PURPOSES = frozenset({"repair", "renew"})

#: The `sessions.status` of a QUARANTINED consent: one that exists at the bank
#: but was never bound to anything here. It is a real `sessions` row precisely
#: because `consent_status` and `consent_ref` resolution read `sessions` and
#: nothing else — an unverified consent recorded only in `attempts.session_id`
#: is a live AIS consent the plugin can neither show nor revoke, and every
#: retry creates another one.
REVIEW_REQUIRED_STATUS = "REVIEW_REQUIRED"

#: A quarantined row's generation sits BELOW every real session's default of 1,
#: so it can never win a `fence_verdict` comparison and can never be mistaken
#: for the current binding of an account.
REVIEW_REQUIRED_GENERATION = 0

#: The `sessions.status` of a LIVE consent — the only status a read tool may
#: count as a link, and the status `_promote` moves a staged session to.
#:
#: It is the same word `apply.RENEWAL_SESSION_STATUS` promotes a renewed session
#: to. The duplication exists only because this module is built before
#: `apply`, and it is load-bearing: if the two ever disagree, a renewed consent
#: and a first-linked one are live under different names and half the read tools
#: go blind. Neither copy may change alone.
LIVE_SESSION_STATUS = "AUTHORIZED"

#: The generation a session gets when its bank has NO PRIOR session at all —
#: `sessions.generation`'s own DEFAULT. A renewal's generation is `old + 1`
#: and `apply.switch_bindings` sets it inside the switch transaction; a first
#: link promoted over a bank that already has a session instead takes
#: `MAX(generation) + 1` over that bank's OTHER sessions (`_promote`), so this
#: is only the floor for a bank with no prior session to be above.
FIRST_GENERATION = 1

#: Canonical tables an `exchange` may not write until it has declared a
#: verified account set. `attempts` is deliberately absent: `heartbeat`,
#: `note_session` and `declare_verified` are how an exchange talks to the
#: collector, and banning those would ban the protocol itself.
_GUARDED_TABLES = ("sessions", "accounts", "balances", "transactions",
                   "transaction_refs", "coverage")

#: Raised by the SQLite triggers above. It must contain no apostrophe: it is
#: interpolated into a `RAISE(ABORT, '...')` literal.
_LEDGER_CLOSED = ("bank-feed: this authorization has not declared a verified "
                  "account set, so the ledger is closed to it")

#: Raised by the STAGING triggers. Same apostrophe rule.
_NOT_STAGED = ("bank-feed: an authorization may not create a live consent - a new "
               "session is staged REVIEW_REQUIRED and the collector promotes it "
               "once the exchange has returned")
_NOT_PROMOTABLE = ("bank-feed: an authorization may not promote its own session - "
                   "only a renewal switch, which replaces a live consent for the "
                   "same bank, may make a session live inside an exchange")

_ATTEMPT_NAME_RE = re.compile(r"^[0-9a-f]{64}\.json$")


class Outcome(NamedTuple):
    state_hash: str
    status: str
    #: Operator-facing, and NEVER a session id, code, state or provider body.
    detail: str


def _utc_iso() -> str:
    return datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def heartbeat(conn, state_hash: str, fence: str) -> None:
    """Re-stamp the lease and prove we still hold it, or raise `Indeterminate`.

    EVERY state transition and ledger write in a collection passes a fence
    check, not just the final attempt update: ours go through
    `_settle`/`begin_exchange`, and the injected `exchange` callable goes
    through here.

    **Contract for `exchange`.** `collect_one` puts the
    fencing token in `attempt["lease_fence"]`. `exchange` MUST call
    `callbacks.heartbeat(conn, attempt["state_hash"], attempt["lease_fence"])`
    immediately before each of its own ledger writes — the session insert, each
    account upsert, the binding switch — and once between transaction pages
    during backfill. It must let the `Indeterminate` propagate: stopping mid-way
    with the fence lost is correct, and continuing is the corruption.

    **Residual, and it is NOT closed.** This re-stamps only where it is called
    from, and the plugin has no background thread to beat from — a specialist
    may not have one. A single provider call — one slow transaction page,
    or a stalled socket inside the 20 s client timeout plus retries — can still
    outlast `LEASE_TTL_S` between two heartbeats. A successor then steals the
    lease, classifies the exchange `indeterminate`, and the original collector
    finds it cannot settle or ack. That window is narrower than it was, but it
    is real. Closing it needs a protocol split: commit the provider session id
    immediately under the fence, ack the callback, and drive the backfill from a
    separately durable, resumable state machine that owns no callback lease at
    all.
    """
    cur = conn.execute(
        "UPDATE attempts SET lease_expiry=?"
        " WHERE state_hash=? AND lease_token=?",
        (time.time() + LEASE_TTL_S, state_hash, fence))
    if cur.rowcount != 1:
        raise Indeterminate(
            "the collection lease moved to another collector; stopping before "
            "this write rather than racing it")


def _close_ledger(conn) -> None:
    """Shut the canonical tables to this connection until a verdict is declared.

    **This is why the account-set check is not a post-return boolean.** A
    value read AFTER `exchange` returns cannot enforce that verification
    happened BEFORE the writes: an injected exchange could insert a session,
    upsert accounts and then return `verified: False`, and `collect_one` would
    only observe the flag afterwards. So the loop observes nothing. It
    closes the ledger with `BEFORE INSERT/UPDATE/DELETE` triggers that
    `RAISE(ABORT, ...)`, and the only thing that reopens it is
    `declare_verified`, which is fenced and durable. A write attempted before
    the declaration is not detected afterwards — it fails, in SQLite, with
    nothing written.

    The triggers are TEMP, so they exist only on this connection and only for
    the duration of one `exchange` call: a concurrent collector in another
    process is unaffected, no lock is held across the provider call, and a crash
    leaves nothing behind (temp objects die with the connection).

    **The one thing this does not cover, stated plainly:** an `exchange` that
    opens its OWN connection to the same database bypasses these triggers,
    because temp triggers are per-connection. Nothing in this plugin does that —
    `store.open_db` is called once per turn, and `heartbeat`/`note_session` are
    only meaningful on the collector's connection — but it is a discipline, not
    a wall, and it is the residual an implementer must not quietly break.
    """
    for table in _GUARDED_TABLES:
        for verb, event in (("ins", "INSERT"), ("upd", "UPDATE"),
                            ("del", "DELETE")):
            conn.execute(
                f"CREATE TEMP TRIGGER IF NOT EXISTS _fin_ban_{verb}_{table}"
                f" BEFORE {event} ON {table}"
                f" BEGIN SELECT RAISE(ABORT, '{_LEDGER_CLOSED}'); END")


def _open_ledger(conn) -> None:
    """Drop the write ban. Idempotent, and safe when it was never set —
    `collect_one` runs it from a `finally`, because the collector's own
    quarantine write is one of the writes the ban blocks."""
    for table in _GUARDED_TABLES:
        for verb in ("ins", "upd", "del"):
            conn.execute(f"DROP TRIGGER IF EXISTS temp._fin_ban_{verb}_{table}")


def _stage_ledger(conn) -> None:
    """The SECOND gate: an exchange may write, but it may not make a consent
    LIVE.

    Shutting the ledger until `declare_verified` and then opening it completely
    only moves the hole: production declares, inserts an `AUTHORIZED` session,
    binds an account and then runs a paginated backfill in autocommit, so
    anything that raises in there leaves a live consent with a partial binding
    and no quarantine.

    Two TEMP triggers hold for the rest of the call, and they are what makes a
    first link and a renewal the same shape:

    * a `sessions` row may only be INSERTed **staged** — `REVIEW_REQUIRED`. A
      renewal already did that; a first link now does it too.
    * a session may only be UPDATEd into `LIVE_SESSION_STATUS` when ANOTHER
      live session **for the same bank** already exists — the write aborts
      precisely when the bank has none.

      **This is a narrowing, not an absolute guarantee.** A `BEFORE
      UPDATE` trigger sees only the PRE-state of the write it is deciding on,
      so it has no way to express "this specific write is the one replacing a
      live consent" — it can only ask "does a live consent for this bank
      exist at all, right now". Those coincide for `apply.switch_bindings`
      (the renewal switch, which promotes while the OLD consent it replaces
      is still live) precisely because the switch is the ONLY thing that
      needs a live consent to exist in order to do its job.

      When the bank has NO live consent — the ordinary first-link case — the
      guard is airtight: there is nothing for the trigger to find, so the
      write aborts and a first link cannot promote itself in any order it
      chooses; the promotion is `collect_one`'s (`_promote`), in one fenced
      statement after the exchange has returned.

      When the bank ALREADY holds a live consent — a re-link, not a renewal —
      the trigger cannot tell an exchange's own self-promotion apart from
      `switch_bindings`' legitimate replacement, and the same UPDATE is
      allowed through. That residual is real; it is contained in production
      only because `apply.switch_bindings` is the sole writer that promotes
      during an exchange and its own precondition is durable deep-fetch
      evidence — the trigger is not what stops an untrusted exchange in that
      case. It is named and pinned, not silently reconciled, by
      `test_a_staged_session_can_self_promote_when_the_bank_is_already_live`.

    `IS`/`IS NOT` rather than `=`/`<>` throughout: a NULL status or a NULL
    `aspsp_name` must compare, not evaporate into NULL and let the write pass.
    """
    conn.execute(
        "CREATE TEMP TRIGGER IF NOT EXISTS _fin_stage_ins_sessions"
        " BEFORE INSERT ON sessions"
        f" WHEN NEW.status IS NOT '{REVIEW_REQUIRED_STATUS}'"
        f" BEGIN SELECT RAISE(ABORT, '{_NOT_STAGED}'); END")
    conn.execute(
        "CREATE TEMP TRIGGER IF NOT EXISTS _fin_stage_upd_sessions"
        " BEFORE UPDATE ON sessions"
        f" WHEN NEW.status IS '{LIVE_SESSION_STATUS}'"
        f" AND OLD.status IS NOT '{LIVE_SESSION_STATUS}'"
        " AND NOT EXISTS (SELECT 1 FROM sessions o"
        "                 WHERE o.session_id <> NEW.session_id"
        "                   AND o.aspsp_name IS NEW.aspsp_name"
        f"                   AND o.status IS '{LIVE_SESSION_STATUS}'"
        "                   AND o.closed_at IS NULL)"
        f" BEGIN SELECT RAISE(ABORT, '{_NOT_PROMOTABLE}'); END")


def _unstage_ledger(conn) -> None:
    """Drop the staging gate. Idempotent, and run from the same `finally` as
    `_open_ledger` — the collector's own promotion is one of the writes it
    blocks, and so is `_contain`'s demotion."""
    for name in ("_fin_stage_ins_sessions", "_fin_stage_upd_sessions"):
        conn.execute(f"DROP TRIGGER IF EXISTS temp.{name}")


def _session_status(conn, session_id):
    """The recorded status of a session row, or None when there is no row."""
    if not session_id:
        return None
    row = conn.execute("SELECT status FROM sessions WHERE session_id=?",
                       (str(session_id),)).fetchone()
    return None if row is None else row["status"]


def _live_link(conn, session_id) -> bool:
    """Is this consent LIVE — authorized, open, and owning at least one account?

    Both halves are the point. A consent nothing is bound to is not a link, and
    reporting one as a completed link is how a renewal that never switched, or
    an exchange that bound nothing, would be acked as a success.
    """
    if not session_id:
        return False
    return conn.execute(
        "SELECT 1 FROM sessions s WHERE s.session_id=? AND s.status IS ?"
        " AND s.closed_at IS NULL"
        " AND EXISTS (SELECT 1 FROM accounts a WHERE a.session_id=s.session_id)",
        (str(session_id), LIVE_SESSION_STATUS)).fetchone() is not None


def _promote(conn, session_id) -> bool:
    """Make the staged consent live. ONE statement, at the collector's fenced
    commit point, inside the settle transaction.

    It promotes only a session that is still `REVIEW_REQUIRED` at the quarantine
    generation AND already owns an account — so a renewal, whose session
    `apply.switch_bindings` promoted inside the exchange, is untouched, and a
    renewal that never switched (its accounts are still on the OLD consent) is
    NOT promoted into a second live consent for one bank.

    The generation is `MAX(generation) + 1` over
    every OTHER session recorded for the same bank (`aspsp_name`), never the
    literal `FIRST_GENERATION`. A first link promoted while the bank already
    holds a live (or merely older) session must land ABOVE it: the generation
    fence (`fence_verdict`) is what stops a stale repair or renewal from
    rebinding an account a newer session already owns, and a hardcoded `1`
    silently inverted that fence — a repair minted against a bank's
    generation-4 consent read as current again the moment a same-bank first
    link was promoted at generation 1, because `1 > 4` is false. `COALESCE`
    only falls back to `FIRST_GENERATION` when NO other session for the bank
    exists at all, which is the genuinely-first-link case that constant is for.
    The subquery is correlated against the row being updated (`sessions` on
    the left of `IS`, not a parameter), so it reads the bank of the SPECIFIC
    row this statement is about to promote, and everything else about the
    statement — the fenced `WHERE`, the staged-status and generation-0
    preconditions, and running inside the collector's own settle transaction —
    is unchanged. Pinned by
    `test_a_promotion_over_an_existing_live_session_lands_above_it`.

    Promotion is a property, not a repair: it happens after the exchange has
    returned, or it does not happen — for a bank whose staging trigger held,
    which is exactly the case where the bank has NO OTHER live consent (see
    `_stage_ledger`). In that case every earlier exit — a raise, an undeclared
    verdict, a killed collector — leaves a session that no read tool counts as
    a link. **That does not extend to a re-link**, stated plainly rather than
    quietly reconciled: a `BEFORE UPDATE` trigger sees only the pre-state of a
    write, so `_stage_ledger`'s promotion guard can ask only "does a live
    consent for this bank exist right now", never "is THIS write the one
    replacing it" — and when the bank already has a live consent, an exchange
    that self-promotes its own staged session mid-call is not stopped by that
    trigger at all, `_promote` here never runs (the session is no longer
    `REVIEW_REQUIRED` by the time this executes), and `_contain` will not
    demote it back on a later raise because `_contain` never demotes an
    `AUTHORIZED` row on purpose. That residual is real and is pinned, not
    hidden, by
    `test_a_staged_session_can_self_promote_when_the_bank_is_already_live`.
    """
    if not session_id:
        return False
    cur = conn.execute(
        "UPDATE sessions SET status=?,"
        " generation=COALESCE((SELECT MAX(o.generation) + 1 FROM sessions o"
        "                      WHERE o.aspsp_name IS sessions.aspsp_name"
        "                        AND o.session_id <> sessions.session_id), ?)"
        " WHERE session_id=? AND status IS ? AND generation IS ?"
        " AND EXISTS (SELECT 1 FROM accounts a WHERE a.session_id=?)",
        (LIVE_SESSION_STATUS, FIRST_GENERATION, str(session_id),
         REVIEW_REQUIRED_STATUS, REVIEW_REQUIRED_GENERATION, str(session_id)))
    return cur.rowcount == 1


def _contain(conn, attempt: dict, session_id) -> bool:
    """Leave nothing half-linked: quarantine the consent and release what it
    bound. Three single statements, always inside the caller's transaction.

    Called on EVERY non-live exit — the exchange raised, it declared no verdict,
    it declared one and bound nothing, or a previous collector was killed and a
    later nudge finds `exchange_started`. It is the containment half of R3; the
    prevention half is `_stage_ledger`, and the prevention is what makes this
    small enough to be atomic.

    * `_quarantine` first, because the consent may exist at the bank without any
      session row here at all (the exchange died before it wrote one).
    * then force the row to `REVIEW_REQUIRED` at the quarantine generation, so a
      session left in some other non-live state is still exactly the row
      `consent_status` and `unlink_bank` know how to handle.
    * then release every account bound to it — `session_id` AND `uid` back to
      NULL. Both: `apply.upsert_account`'s rebinding backstop compares the
      offered uid and session against the recorded ones, so a row left carrying
      a dead uid would make the operator's retry fail as an unexplained
      rebinding rather than link cleanly.

    **A live link is never demoted.** A renewal that completed its switch and
    then lost the connection is a FINISHED renewal — its old consent is already
    retired — and "cleaning it up" would break a working link. That is the one
    thing a cleanup path must not do, and it is why this asks the ledger first.
    """
    if not session_id:
        return False
    if _session_status(conn, session_id) == LIVE_SESSION_STATUS:
        return False
    _quarantine(conn, attempt, session_id)
    conn.execute(
        "UPDATE sessions SET status=?, generation=? WHERE session_id=?"
        " AND status IS NOT ? AND closed_at IS NULL",
        (REVIEW_REQUIRED_STATUS, REVIEW_REQUIRED_GENERATION, str(session_id),
         LIVE_SESSION_STATUS))
    conn.execute("UPDATE accounts SET session_id=NULL, uid=NULL"
                 " WHERE session_id=?", (str(session_id),))
    return True


def note_session(conn, attempt: dict, session_id: str) -> None:
    """Record the provider session id the INSTANT the provider returns it.

    **Contract for `exchange`: call this first, before anything else.** It is
    what makes a stranded consent recoverable. If the exchange then fails
    verification, raises, or is killed, the collector still knows which consent
    exists at the bank and can quarantine it (`_quarantine`). Without it, a
    consent that was created and then abandoned is invisible to
    `consent_status` and unreachable by `unlink_bank`.

    Writing `attempts.session_id` is NOT banned by `_close_ledger`: it binds
    nothing and grants nothing. It is fenced like every other write.
    """
    if not session_id:
        raise Invalid("an exchange may not note an empty session id")
    cur = conn.execute(
        "UPDATE attempts SET session_id=?, lease_expiry=?"
        " WHERE state_hash=? AND lease_token=?",
        (str(session_id), time.time() + LEASE_TTL_S,
         attempt["state_hash"], attempt["lease_fence"]))
    if cur.rowcount != 1:
        raise Indeterminate(
            "the collection lease moved to another collector; not recording "
            "this consent under a fence we no longer hold")


def declare_verified(conn, attempt: dict) -> None:
    """Reopen the ledger — the exchange's single, ordered, durable promise.

    **Contract for `exchange`.** Call this once `flows.verify_accounts` has
    passed on the COMPLETE returned account set against the whitelist and the
    operator's intent, and BEFORE upserting an account, switching a binding or
    fetching a transaction. Until it is called every canonical write raises
    (`_close_ledger`), so an exchange that forgets to verify cannot bind
    anything: it is not trusted to report, it is prevented from acting.

    The declaration is recorded in `attempts.outcome` under the fence, so it is
    durable, ordered and impossible to back-date. `collect_one` reads THAT and
    never the exchange's return value, which it ignores entirely.

    **What it reopens the ledger INTO matters.** Not to a free
    hand: `_stage_ledger` immediately narrows it, so for the rest of the call the
    exchange may write but may not make a consent live. Its new session goes in
    `REVIEW_REQUIRED` at generation 0 — a first link exactly like a renewal — and
    `collect_one` promotes it in one fenced statement after the exchange returns.
    """
    row = conn.execute("SELECT session_id FROM attempts WHERE state_hash=?",
                       (attempt["state_hash"],)).fetchone()
    if row is None or not row["session_id"]:
        raise Invalid(
            "an account set cannot be verified before its session is noted; "
            "call note_session() first")
    cur = conn.execute(
        "UPDATE attempts SET outcome='verified', lease_expiry=?"
        " WHERE state_hash=? AND lease_token=? AND phase='exchange_started'",
        (time.time() + LEASE_TTL_S, attempt["state_hash"],
         attempt["lease_fence"]))
    if cur.rowcount != 1:
        raise Indeterminate(
            "the collection lease moved to another collector; refusing to "
            "reopen the ledger for a flow we no longer own")
    _open_ledger(conn)
    _stage_ledger(conn)


def declare_partial(conn, attempt: dict) -> None:
    """Downgrade a declared verdict: the consent is good, the history is not.

    Without this, a capped backfill returns a perfectly ordinary result, so
    authorization records a successful collection and the fresh-SCA loss is
    silent at the initiating call.
    `exchange` MUST call this when `flows.backfill` reports the page cap — or
    any other reason the proved range fell short of what was asked for. The
    attempt then settles as `partial`, never `succeeded`, and `Outcome.status`
    carries that out to the caller in a form it cannot mistake for success:
    `SUCCESS_STATUSES` is the set to branch on.

    Callable only after `declare_verified`: an unverified set is already going
    to `review_required`, where partiality is not the story.
    """
    cur = conn.execute(
        "UPDATE attempts SET outcome='verified_partial', lease_expiry=?"
        " WHERE state_hash=? AND lease_token=? AND outcome IN"
        " ('verified','verified_partial')",
        (time.time() + LEASE_TTL_S, attempt["state_hash"],
         attempt["lease_fence"]))
    if cur.rowcount != 1:
        raise Indeterminate(
            "no verified declaration under this fence to downgrade; the "
            "collection lease has moved, or the set was never verified")


def _quarantine(conn, attempt: dict, session_id: str) -> None:
    """Materialise a stranded consent as a visible, revocable session row.

    A failed path that writes only `attempts.session_id` is invisible, because
    `consent_status` and `consent_ref` resolution read `sessions` and nothing
    else. A transient whitelist or admin mismatch would then leave a REAL AIS
    consent at the bank that the plugin could neither display nor revoke, with
    each retry creating another one — while the collector's own text told the
    operator to run `consent_status`, which could not see it.

    The row is deliberately DEGENERATE:

    * `status = 'REVIEW_REQUIRED'`, never `AUTHORIZED`. It is not usable, and no
      read tool may count it as a live link.
    * **no account is bound to it.** Quarantine means visible and revocable, not
      usable; the account set is exactly what could not be verified.
    * `generation = 0`, below every real session's default of 1, so it can never
      win a `fence_verdict` comparison.
    * `valid_until` NULL — we know the consent exists, not how long it lives.
      `authorized_at` is OUR observation time, not the provider's; nothing here
      invents a provider fact we were never told.

    Its `consent_ref` needs no column: it is `sha256("consent-ref|" + id)[:8]`,
    derived wherever it is printed. `INSERT OR IGNORE` makes a re-nudge
    harmless, while a genuine retry — one that creates a SECOND consent at the
    bank — gets its own row. That is the point: each stranded consent is
    separately visible and separately revocable.

    The other half lives in the tools: `consent_status` shows it as needing
    attention, and protected `unlink_bank` revokes it by `consent_ref`.
    """
    conn.execute(
        "INSERT OR IGNORE INTO sessions(session_id, aspsp_name, country,"
        " psu_type, status, authorized_at, valid_until, closed_at, generation)"
        " VALUES (?,?,?,?,?,?,NULL,NULL,?)",
        (str(session_id), attempt.get("aspsp_name"), attempt.get("country"),
         attempt.get("psu_type"), REVIEW_REQUIRED_STATUS, _utc_iso(),
         REVIEW_REQUIRED_GENERATION))


def _finish_exchange(conn, attempt: dict, session_id, marker):
    """Promote the staged consent or contain it, and say how the attempt
    settles. Returns `(live, phase, outcome)`.

    This is the whole of the collector's tail, in one place on purpose. It
    runs INSIDE the caller's transaction: `collect_one` pairs it
    with the fenced `_settle`, so the promotion, the containment and the attempt
    row commit together or not at all.

    * `verified` + a live consent  -> `exchanged` / `collected`.
    * `verified_partial`           -> `exchanged` / `collected_partial`, live or
      not: a capped FIRST link is live and short of history, and a renewal that
      could not switch is not live at all — in both cases `partial` is the
      honest word, and the new consent of the second is quarantined here.
    * `verified` + nothing bound   -> `review_required` / `unbound_link`. A
      consent nothing is bound to is not a link and is not reported as one.

    **Any collection harness must call this**, exactly as it already calls
    `_close_ledger`/`_open_ledger`: a fake that stops at the marker leaves the
    tools a ledger production never produces — a consent still staged, which
    then reads as "no live session for this bank" and turns the next renewal
    into a first link. That defect shape recurs, so the end state has one
    implementation and everything calls it.
    """
    partial = marker == "verified_partial"
    _promote(conn, session_id)
    live = _live_link(conn, session_id)
    if not live:
        _contain(conn, attempt, session_id)
    phase = "exchanged" if (live or partial) else "review_required"
    outcome = ("collected_partial" if partial
               else "collected" if live else "unbound_link")
    return live, phase, outcome


def _release(conn, state_hash: str, fence: str) -> None:
    """Drop the lease under the fence, so the next nudged turn is not locked
    out for the rest of the TTL. Only ever called on a non-committing exit."""
    conn.execute(
        "UPDATE attempts SET lease_owner=NULL, lease_token=NULL,"
        " lease_expiry=NULL WHERE state_hash=? AND lease_token=?",
        (state_hash, fence))


def _settle(conn, state_hash: str, fence: str, *, phase: str,
            outcome=None, session_id=None) -> bool:
    """The one commit point, fenced. Returns False when the fencing token no
    longer matches — a stale owner must not commit, and the caller
    must then NOT ack, NOT quarantine and NOT report."""
    cur = conn.execute(
        "UPDATE attempts SET phase=?, outcome=?,"
        " session_id=COALESCE(?, session_id), lease_owner=NULL,"
        " lease_token=NULL, lease_expiry=NULL"
        " WHERE state_hash=? AND lease_token=?",
        (phase, outcome, session_id, state_hash, fence))
    return cur.rowcount == 1


def fence_verdict(conn, attempt: dict):
    """The generation fence.

    **Public on purpose.** A caller reasons about this verdict before it mints —
    telling the operator that a repair cannot be fenced beats minting one the
    collector will refuse — so it is part of this module's surface and must not
    hide behind an underscore. (`_close_ledger`/`_open_ledger` stay private:
    those are a test-harness dependency, not something production reasons
    about.)

    Returns an outcome string when this callback must not proceed, else None.

    * `'unfenced_repair'` — the purpose is in `FENCED_PURPOSES` but the attempt
      carries no `account_id`, no `expected_generation`, or names an account
      whose current generation cannot be resolved. **This is a HARD REFUSAL, not
      a soft pass**: a repair or renewal that cannot prove it is still
      current is precisely the callback that must not be applied. What it costs,
      said plainly — a repair minted by an older build, before `_start_auth`
      minted the fence, can no longer be collected after an upgrade; and an
      account removed by `forget_local_account` while its repair was in flight
      makes that repair uncollectable. Each costs one fresh authorization. The
      alternative costs a silent rebind onto a stale consent.
    * `'stale_generation'` — the account has since been bound by a session of a
      HIGHER generation, so this callback would roll it back.

    A `link` fences nothing and is not required to: a first link has no prior
    binding to be stale against, which is why the refusal keys on PURPOSE and
    not on the mere presence of the columns.
    """
    account_id = attempt.get("account_id")
    expected = attempt.get("expected_generation")
    fenced = (attempt.get("purpose") or "") in FENCED_PURPOSES
    if not account_id or expected is None:
        return "unfenced_repair" if fenced else None
    row = conn.execute(
        "SELECT s.generation AS generation FROM accounts a"
        " JOIN sessions s ON s.session_id = a.session_id"
        " WHERE a.account_id = ?", (account_id,)).fetchone()
    if row is None or row["generation"] is None:
        return "unfenced_repair" if fenced else None
    current = int(row["generation"])
    return "stale_generation" if current > int(expected) else None


def _existing_hold(sp, plugin_dir: str, state_hash: str):
    """A previous life may have renamed the result and died; the payload then
    lives ONLY in the hold, and `results/<h>.json` never reappears — retrying
    it forever would be a silent credential loss."""
    pattern = os.path.join(str(plugin_dir), "results",
                           f"{sp.COLLECT_PREFIX}{state_hash}-*")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle), path
        except (OSError, ValueError):
            continue
    return None, None


def _remaining_budget(held) -> float | None:
    """Seconds of the result artifact's TTL still to run, or None when the
    hold cannot be stat'd. UNKNOWN is not "expired": a provider rejecting a
    stale code is an ordinary outcome, while refusing a live flow on a stat
    failure would throw away a good authorization."""
    try:
        return RESULT_TTL_S - (time.time() - os.stat(os.fspath(held)).st_mtime)
    except (OSError, TypeError, ValueError):
        return None


def pending_attempts(conn, sp, plugin_dir: str) -> list[dict]:
    """casa's `attempts/` ledger for this plugin, restricted to flows we minted.

    Only `<64hex>.json` is read: `.ack-*` receipts and any other residue are
    skipped, and an unparseable attempt file means *no information*, never an
    outcome. A hash with no row in our own store is left alone
    rather than acked — acking a flow we cannot recognise would silently hide
    a restored-from-backup mismatch, and casa's own expiry plus its single
    operator note is the right escalation for it.
    """
    directory = os.path.join(str(plugin_dir), "attempts")
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []                          # no spool dir yet: nothing to do
    out = []
    for name in names:
        if name.startswith(sp.ACK_PREFIX) or not _ATTEMPT_NAME_RE.match(name):
            continue
        try:
            with open(os.path.join(directory, name), "r",
                      encoding="utf-8") as handle:
                record = json.load(handle)
        except (OSError, ValueError):
            continue
        if not isinstance(record, dict):
            continue
        state_hash = record.get("state_hash")
        if not isinstance(state_hash, str) or not _HASH_RE.match(state_hash):
            continue
        if state_hash != name[:-len(".json")]:
            continue
        known = conn.execute(
            "SELECT 1 FROM attempts WHERE state_hash=?",
            (state_hash,)).fetchone()
        if known is None:
            continue
        out.append(record)
    return out


def _run_exchange(conn, attempt: dict, exchange, code: str):
    """Call the injected exchange with the ledger closed, then read back the
    DURABLE verdict it left behind. Returns `(marker, session_id, failed)`.

    `marker` is `attempts.outcome` as the exchange left it — `'verified'`,
    `'verified_partial'`, or anything else (including None), which means no
    verdict was declared. The exchange's RETURN VALUE is never consulted, and
    that is the point: there is no boolean here that could be read at the
    wrong time.
    """
    _close_ledger(conn)
    failed = False
    try:
        exchange(code, attempt)
    except Exception:                  # noqa: BLE001 - the class, not the text
        failed = True
    finally:
        # An exchange that died INSIDE its own transaction — `apply.apply_plan`
        # and `apply.switch_bindings` both take one — would otherwise leave it
        # open, and the collector's `BEGIN IMMEDIATE` would raise on top of the
        # failure it was recording. Rolling back here discards exactly the work
        # that was never committed, which is the work that must not survive.
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        # BOTH gates come down here: the collector's own promotion, quarantine
        # and demotion are writes that `_close_ledger` and `_stage_ledger` block.
        _open_ledger(conn)
        _unstage_ledger(conn)
    row = conn.execute(
        "SELECT outcome, session_id FROM attempts WHERE state_hash=?",
        (attempt["state_hash"],)).fetchone()
    marker = row["outcome"] if row is not None else None
    session_id = row["session_id"] if row is not None else None
    return marker, session_id, failed


def collect_one(conn, sp, plugin_dir: str, record: dict, fence: str,
                exchange) -> Outcome:
    """Collect → exchange → COMMIT → ack, in exactly that order.

    `record` is casa's attempt record; `fence` is the token `take_lease`
    returned. An `awaiting_redirect` record is reported as `waiting` here:
    deciding whether it has been ABANDONED needs the freshly discovered
    context, which `run_collection` owns.

    Two gates sit around the injected `exchange`, and NEITHER is a value read
    back out of it:

    * BEFORE it, the generation fence — a callback that would rebind an account
      a newer session already owns, or a repair that cannot prove it is current
      at all, never reaches the provider.
    * AROUND it, `_close_ledger` — every canonical table is shut to this
      connection until `declare_verified` reopens it. An exchange that skips
      verification is not caught afterwards; its writes fail at the database.
      The verdict it leaves in `attempts.outcome` is fenced and durable, and it
      is the only thing read back.

    Three settled shapes come out of a completed exchange: `verified` →
    `succeeded`; `verified_partial` → **`partial`** (a capped backfill is
    never reported as success); no verdict → **`review_required`**, with the
    consent quarantined so it can be seen and revoked.
    """
    state_hash = record.get("state_hash")
    if not isinstance(state_hash, str) or not _HASH_RE.match(state_hash):
        return Outcome("", "skipped", "unparseable attempt record")
    row = conn.execute("SELECT * FROM attempts WHERE state_hash=?",
                       (state_hash,)).fetchone()
    if row is None:
        return Outcome(state_hash, "skipped",
                       "this authorization is not one of ours")
    attempt = dict(row)
    #: The fencing token travels WITH the attempt so the injected `exchange`
    #: can fence its own ledger writes through `heartbeat`.
    attempt["lease_fence"] = fence
    status = record.get("status")

    if attempt["phase"] in SETTLED_PHASES:
        # Our store already decided. Ack again — it is idempotent, and an
        # unacked flow nudges to the six-dispatch budget. Drop the
        # lease first: holding it for the rest of the TTL over a decision
        # already made just delays the next nudged turn.
        _release(conn, state_hash, fence)
        sp.ack(plugin_dir, state_hash)
        return Outcome(state_hash, "skipped",
                       "already settled here; acknowledged again")

    if status == "done":
        outcome = record.get("outcome")
        if not _settle(conn, state_hash, fence, phase="closed",
                       outcome=outcome if isinstance(outcome, str) else None):
            return Outcome(state_hash, "skipped",
                           "the collection lease moved; not acknowledging")
        sp.ack(plugin_dir, state_hash)
        return Outcome(state_hash, "terminal",
                       f"casa ended this authorization: "
                       f"{outcome if isinstance(outcome, str) else 'ended'}")

    if status == "awaiting_redirect":
        _release(conn, state_hash, fence)
        return Outcome(state_hash, "waiting",
                       "the bank has not sent the operator back yet")

    if status != "result_ready":
        _release(conn, state_hash, fence)
        return Outcome(state_hash, "skipped",
                       "attempt status is not one this version understands")

    payload, held = _existing_hold(sp, plugin_dir, state_hash)
    if payload is None:
        try:
            payload, held = sp.collect(plugin_dir, state_hash)
        except FileNotFoundError:
            # casa writes the attempt just before the result link lands, so a
            # brief window exists where the record leads the payload. RETRY —
            # never ack, which would discard a live authorization.
            _release(conn, state_hash, fence)
            return Outcome(state_hash, "retry",
                           "the authorization result has not landed yet")
        except ValueError:
            if not _settle(conn, state_hash, fence, phase="closed",
                           outcome="invalid"):
                return Outcome(state_hash, "skipped",
                               "the collection lease moved; not acknowledging")
            sp.ack(plugin_dir, state_hash)
            return Outcome(state_hash, "invalid",
                           "the published result was unreadable")

    remaining = _remaining_budget(held)
    if remaining is not None and remaining < MIN_REMAINING_S:
        if not _settle(conn, state_hash, fence, phase="closed",
                       outcome="expired_budget"):
            return Outcome(state_hash, "skipped",
                           "the collection lease moved; not acknowledging")
        sp.ack(plugin_dir, state_hash)
        return Outcome(state_hash, "expired",
                       "too little of this authorization's life remained to "
                       "finish safely; ask the operator for a fresh link")

    try:
        parsed = validate_record(payload, attempt)
    except Invalid as exc:
        if not _settle(conn, state_hash, fence, phase="closed",
                       outcome="invalid"):
            return Outcome(state_hash, "skipped",
                           "the collection lease moved; not acknowledging")
        sp.ack(plugin_dir, state_hash)
        return Outcome(state_hash, "invalid", str(exc))

    if parsed["error"]:
        # A refusal still collects, records and acks: leaving it unacked would
        # nudge until expiry over a decision already made.
        if not _settle(conn, state_hash, fence, phase="declined",
                       outcome=parsed["error"]):
            return Outcome(state_hash, "skipped",
                           "the collection lease moved; not acknowledging")
        sp.ack(plugin_dir, state_hash)
        return Outcome(state_hash, "declined",
                       f"the bank refused the consent: {parsed['error']}")

    # The generation fence, BEFORE the provider call. A stale or unfenced
    # repair must not spend its code either: exchanging would create a live
    # consent nobody asked for and then discard it.
    verdict = fence_verdict(conn, attempt)
    if verdict is not None:
        if not _settle(conn, state_hash, fence, phase="closed",
                       outcome=verdict):
            return Outcome(state_hash, "skipped",
                           "the collection lease moved; not acknowledging")
        sp.ack(plugin_dir, state_hash)
        if verdict == "stale_generation":
            return Outcome(state_hash, "stale",
                           "this authorization was started for an older "
                           "consent than the one this account now holds; it "
                           "was discarded and no binding changed")
        return Outcome(state_hash, "stale",
                       "this repair was started without the account and "
                       "consent generation it exists to protect, so there is "
                       "no way to prove it is still current; it was discarded "
                       "and no binding changed. Start the repair again")

    try:
        begin_exchange(conn, state_hash, fence)   # durable BEFORE the call
    except Indeterminate as exc:
        # A previous collector committed `exchange_started` and never came back
        # — it was killed, or it lost its lease mid-exchange. Nothing runs in a
        # killed process, so this later turn is where its half-done work gets
        # contained: the consent it noted is quarantined and every account
        # it bound is released. `heartbeat` proves the fence first, and the
        # whole thing is one transaction, so a stale owner changes nothing.
        conn.execute("BEGIN IMMEDIATE")
        try:
            heartbeat(conn, state_hash, fence)
            contained = _contain(conn, attempt, attempt.get("session_id"))
        except Indeterminate:
            conn.execute("ROLLBACK")
            return Outcome(state_hash, "skipped",
                           "the collection lease moved; nothing was changed")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
        if contained:
            return Outcome(
                state_hash, "indeterminate",
                str(exc) + ". Nothing is linked to the consent that exchange "
                "created: it is quarantined and every account it had bound has "
                "been released. Run consent_status to see it, and unlink_bank "
                "to revoke it")
        return Outcome(state_hash, "indeterminate", str(exc))

    marker, session_id, failed = _run_exchange(conn, attempt, exchange,
                                               parsed["code"])

    if failed:
        # `exchange_started` is already committed, so the code is never
        # re-posted. The message names no provider text. The write
        # is fenced like every other one, and a lost fence means a successor
        # owns this flow's outcome — we record nothing and ack nothing.
        #
        # The failure may have landed AFTER the verdict, with a
        # session row and one or more bindings already written. `_contain` is
        # what makes that state harmless, and it shares this transaction with
        # the settle so there is no half-contained ledger to find.
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "UPDATE attempts SET phase='indeterminate',"
                " outcome='indeterminate'"
                " WHERE state_hash=? AND lease_token=?", (state_hash, fence))
            if cur.rowcount != 1:
                conn.execute("ROLLBACK")
                return Outcome(state_hash, "skipped",
                               "the collection lease moved before the failure "
                               "could be recorded; not acknowledging")
            # The exchange got far enough to note a consent, so one
            # EXISTS at the bank whatever else went wrong: quarantine it, or it
            # is invisible to consent_status and unreachable by unlink_bank —
            # and release whatever it had already bound, so no account is left
            # naming a consent that is not live.
            _contain(conn, attempt, session_id)
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
        return Outcome(state_hash, "indeterminate",
                       "the exchange did not complete; the code is spent and "
                       "will not be retried. Nothing was linked: any consent "
                       "the bank did create is quarantined and listed by "
                       "consent_status for review")

    if marker not in ("verified", "verified_partial"):
        # The account set was never declared verified against the
        # whitelist AND the operator's intent, so nothing could be bound off
        # the back of it — the ledger was closed for the whole call. This is
        # DURABLE, not a retry: the code is spent and the consent exists at the
        # provider, so the operator has to be able to SEE it.
        conn.execute("BEGIN IMMEDIATE")
        try:
            if not _settle(conn, state_hash, fence, phase="review_required",
                           outcome="unverified_accounts"):
                conn.execute("ROLLBACK")
                return Outcome(state_hash, "skipped",
                               "the collection lease moved; not acknowledging")
            _contain(conn, attempt, session_id)
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
        sp.ack(plugin_dir, state_hash)
        return Outcome(state_hash, "review_required",
                       "the bank authorized a consent but the accounts it "
                       "returned were not the ones approved; nothing was "
                       "linked and nothing was fetched. The consent itself is "
                       "recorded and awaiting review — run consent_status to "
                       "see it, and unlink_bank to revoke it")

    # COMMIT to our own store first: acking first and then crashing loses the
    # payload for good. The fence is re-checked HERE, at the commit point.
    #
    # This is ALSO where the consent becomes live, and it is the
    # only place that can be. `_promote` and `_settle` share one transaction, so
    # the ledger never holds a live consent for an authorization it has not
    # settled, and a lost fence rolls the promotion back with everything else.
    # `_promote` is a no-op for a renewal (already promoted by the switch) and
    # for a renewal that never switched (its accounts are still on the old
    # consent), which is why one statement serves both paths.
    partial = marker == "verified_partial"
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Promote, or contain — either a renewal that could not switch, whose
        # consent stays quarantined while the OLD one stays live and bound, or a
        # verdict that bound nothing at all. Neither is a link, so neither is
        # left looking like one.
        live, phase, outcome = _finish_exchange(conn, attempt, session_id,
                                                marker)
        if not _settle(conn, state_hash, fence, phase=phase, outcome=outcome):
            conn.execute("ROLLBACK")
            return Outcome(state_hash, "skipped",
                           "the collection lease moved before the commit; not "
                           "acknowledging")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    sp.ack(plugin_dir, state_hash)     # never unlink the hold — casa owns it
    if not live and not partial:
        # A declared exchange that ended with nothing bound to its consent. It
        # is settled and acked — the code is spent — but it is NOT a link, and
        # SUCCESS_STATUSES is what a caller branches on.
        return Outcome(state_hash, "review_required",
                       "the bank authorized a consent but nothing was left "
                       "linked to it, so it was not made live. The consent is "
                       "recorded and awaiting review — run consent_status to "
                       "see it, and unlink_bank to revoke it")
    if partial:
        # NOT a success, and worded so it cannot be read as one: no "linked",
        # no "refreshed", no renewal handoff. The consent is real, the history
        # behind it is short, and the operator has a live window in which to
        # fix that.
        return Outcome(state_hash, "partial",
                       "the bank consent was accepted but this account's "
                       "history is INCOMPLETE: the provider stopped paging "
                       "before the requested range was fetched. Run sync now, "
                       "while the consent is still fresh, or ask the operator "
                       "for a fresh authorization if it has lapsed")
    return Outcome(state_hash, "succeeded",
                   "the bank consent was accepted and recorded")


def _context(plugin_root: str | None = None):
    """Re-read the `.index` entry — every time, never cached.

    Returns None when discovery fails. UNKNOWN is deliberately not "changed":
    a transiently missing entry (casa mid-reconcile) must not abandon live
    authorizations, exactly as casa's own passes never treat an unreadable
    probe as grounds for a destructive path.
    """
    root = plugin_root or os.environ.get("CLAUDE_PLUGIN_ROOT")
    if not root:
        return None
    try:
        return discover(root)
    except Unsupported:
        return None


def _context_changed(row, current) -> bool:
    """True when this pending was minted under a different callback route.
    A recorded value we do not have is unknowable, never changed."""
    if current is None:
        return False
    for column, key in (("plugin_dir", "plugin_dir"),
                        ("redirect_uri", "redirect_uri")):
        recorded = row[column]
        if recorded and str(recorded) != str(current[key]):
            return True
    return False


def run_collection(conn, sp, plugin_dir: str, exchange) -> list:
    """One collection pass — what a nudged turn runs.

    Idempotent and safe with nothing to collect: the nudge is at-least-once,
    and a turn that finds an empty ledger returns an empty list rather than
    doing anything.

    **The caller may not treat "returned without raising" as success.** Branch
    on `Outcome.status` against `SUCCESS_STATUSES`: `partial` and
    `review_required` are both ordinary, non-raising returns that mean the
    operator has something to do right now.
    """
    current = _context()
    owner = f"bank-feed-{os.getpid()}"
    outcomes = []
    for record in pending_attempts(conn, sp, plugin_dir):
        state_hash = record["state_hash"]
        row = conn.execute(
            "SELECT plugin_dir, redirect_uri FROM attempts WHERE state_hash=?",
            (state_hash,)).fetchone()
        fence = take_lease(conn, state_hash, owner)
        if fence is None:
            outcomes.append(Outcome(
                state_hash, "skipped",
                "another collector holds this authorization"))
            continue
        if record.get("status") == "awaiting_redirect" and \
                _context_changed(row, current):
            # An in-flight authorization whose route has changed can never
            # complete. Acking an `awaiting_redirect` record is the abort verb
            # and it kills the pending cleanly.
            if _settle(conn, state_hash, fence, phase="abandoned",
                       outcome="abandoned"):
                sp.ack(plugin_dir, state_hash)
                outcomes.append(Outcome(
                    state_hash, "abandoned",
                    "this authorization was started under a different callback "
                    "route and can no longer complete; start a fresh link"))
            else:
                outcomes.append(Outcome(
                    state_hash, "skipped",
                    "the collection lease moved; not acknowledging"))
            continue
        outcomes.append(
            collect_one(conn, sp, plugin_dir, record, fence, exchange))
    return outcomes
