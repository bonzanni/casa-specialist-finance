# plugins/bank-feed/server/flows.py
"""Setup and linking orchestration.

Per bank there are TWO approvals. The whitelist step runs on the admin
credential and ends on Enable Banking's own page — its redirect is fixed and
cannot be pointed at us, verified through every available lever — so nothing
comes back and completion is confirmed by re-reading `whitelisted_accounts`,
never assumed. Then the API authorization, which does come back to casa's
callback.

Between the two, this module WAITS FOR NOTHING — a specialist cannot: an
`await_whitelist` that sleeps in three-second steps for ten minutes has no turn
to sleep in. The continuation is the operator returning and
calling `link_bank` again, which re-reads `whitelisted_accounts` and goes
straight to tap 2 when the entry has appeared.

Then, immediately: BACKFILL. History is deep only inside the fresh-SCA window,
and that window closes within minutes: the SAME session, asked again half an
hour later, can return a fraction of the history it returned the first time,
with no error and no cap to distinguish the two answers. So the backfill runs
first, synchronously, before
mapping review or any other interactive step; it pages to exhaustion; it
stages every page and commits them in one transaction; and it records the
interval it actually PROVED. "Paged to exhaustion" proves that a response set
was consumed — it does not prove that eight years of history is in the ledger.
And when pagination does NOT complete, nothing canonical is touched at all: a
partial page set is not evidence that anything vanished.

This module never waits on a redirect and never schedules anything: casa's
nudge ladder is the continuation and the resident owns reminders.
"""
from __future__ import annotations

import datetime as dt
import re
from typing import NamedTuple

import apply
import eb_ais                    # for revocation_is_final; see _revoke
import ingest
import provenance
import store

BACKFILL_FLOOR_DAYS = 2900      # ~7.94 y; beyond 8 years is rejected outright
MAX_PAGES = 60
SHALLOW_SPAN_DAYS = 180

#: ASPSPs for which a CLEAN, uncapped `transactions` response has been MEASURED
#: to prove the completeness of the interval it covers, not merely the
#: existence of the rows it happened to return. A response never licenses a
#: tombstone interval by itself: a clean paginated response proves the
#: existence of POINTS, never the completeness of an INTERVAL, and computing
#: the licence from the very response under reconciliation is a structural
#: error whichever interval it derives — `(requested_from, end)` and
#: `(proved_from, proved_to)` are both derivations of it. The premise is
#: falsified by the provider's own behaviour: one session can return deep
#: history and then, asked again on that same session after the SCA window
#: closes, return only the most recent months -- both responses clean,
#: `key=None`, no cap, no exception. A requested interval is therefore never
#: evidence of a proved one.
#:
#: Empty means DENY for every ASPSP: `backfill` never passes `ingest.reconcile`
#: anything but the degenerate no-licence interval below, regardless of what
#: was fetched. This is deliberately NOT a column on `aspsp_capability` — there
#: is nothing MEASURED yet to record, and a schema bump for a column nothing
#: can ever set buys nothing. When a re-list-completeness measurement exists,
#: it gets a home in the durable capability table and an ASPSP is added here to
#: reflect it; until then this frozenset stays empty and this comment is the
#: record of why.
TOMBSTONE_LICENSED_ASPSPS: frozenset = frozenset()

#: What the caller must tell the operator when a renewal did NOT complete —
#: there is no durable staged continuation: the renewed session stays
#: quarantined and its candidate `uid`s live only in the dict the caller passed
#: in, for the length of this call. `sync` therefore cannot pick the attempt up
#: — it can only refresh the still-bound OLD session, so telling the operator
#: to run it reports progress that is not happening. The only honest remedy in
#: the honest remedy is to revoke the quarantined candidate (`unlink_bank`, by the
#: `consent_ref` `consent_status` prints for it) and authorize again. Durable
#: staged continuation is follow-up work; when it lands this constant becomes
#: the resumption instruction and the operator wording follows it instead of
#: being rewritten.
REAUTHORIZE_REMEDY = "reauthorize"

SHALLOW_NOTE = ("deep-history window missed: fewer than 180 days proved. "
                "Re-link this bank to reopen the window; until then the read "
                "tools report the gap")
CAPPED_NOTE = ("pagination cap reached: no interval proved for this run, and "
               "nothing in the ledger was changed. Re-run the backfill inside "
               "the authorization window")

#: The two reference-trust transitions, disclosed on the sync_state note line
#: beside SHALLOW_NOTE and the drift warning. One constant each, so the tool
#: output and the durable row cannot drift apart.
TRUST_GRANTED_NOTE = (
    "reference identity earned: a completed deep run observed enough stable "
    "entry references on this account, so future runs may key on the "
    "provider's reference (still corroborated, never blind)")
TRUST_DEMOTED_NOTE = (
    "reference trust withdrawn: reference reuse was measured on this "
    "account. Rows already matched by reference keep their recorded match "
    "method; future runs fall back to heuristic date matching")
FAILED_NOTE = ("the bank stopped answering partway through pagination: no "
               "interval proved for this run, and nothing in the ledger was "
               "changed. Re-run the backfill inside the authorization window")

# Anchor on country code + check digits, with a LEADING \b. Matches ONLY a
# contiguous run with no embedded whitespace: the [A-Z0-9] character class
# cannot cross a space, so it can never reach into a preceding or following
# token regardless of that token's shape or length -- a real word boundary
# always stops it, on both ends. A bare [A-Z]{2}[0-9A-Z]+ would match the
# literal word "IBAN" in a title like "IBAN NL67REVO…"; the digit
# requirement right after the two letters is what excludes it (its 3rd/4th
# characters are letters, not digits), independent of the boundary.
#
# ONE pattern, matching the tight uppercase form. A second pattern tolerant of
# internal spacing -- to support a conventionally-grouped or lowercase title
# ("IBAN NL00 REVO 0000 0000 01") -- was tried and removed: this provider does
# not emit that shape (see `tests/fixtures/whitelisted_accounts.json`), and
# tolerating internal spacing is what lets a following or preceding token be
# mistaken for more of the code. Every defect the tolerant pattern produced --
# absorbing a neighbouring token, truncating the code, depending on the IBAN
# body's length for alignment -- came from exactly that tolerance.
#
# This is a MEASURED limitation, not a guess: a lowercase or
# conventionally-spaced title will not parse and the link will be refused.
# If the provider ever starts emitting one, `tests/test_flows.py`'s tests
# against this pattern (driven off `whitelisted_accounts.json`) are exactly
# the corpus that would need a new entry to notice.
_IBAN_RE = re.compile(r"\b([A-Z]{2}[0-9]{2}[A-Z0-9]{6,30})\b")


class Verdict(NamedTuple):
    ok: bool
    message: str


def _today() -> dt.date:
    """Clock seam, so backfill's proved interval is assertable exactly."""
    return dt.date.today()


def _for_bank(entries, aspsp: str, country: str) -> list:
    """The whitelist entries belonging to ONE bank in ONE country.

    `whitelisted()` answers for the whole APPLICATION, so after bank A is
    linked its IBANs are in every later answer. Verification that compares a
    bank B consent against that full list reports every one of bank A's IBANs
    as missing, and the second bank can never link. Linking one bank
    at a time does not help — old entries persist.
    """
    return [w for w in entries
            if (w.get("aspsp") or {}).get("name") == aspsp
            and (w.get("aspsp") or {}).get("country") == country]


def _entries(admin, app_id, aspsp, country):
    return _for_bank(admin.whitelisted(app_id), aspsp, country)


def needs_whitelist(admin, app_id: str, aspsp: str, country: str) -> bool:
    return not _entries(admin, app_id, aspsp, country)


def _iban_of(entry: dict) -> str:
    """IBAN out of a whitelist entry's human title -- EXTRACT, then
    CANONICALISE, never the other way round.

    Extraction runs `_IBAN_RE` against the RAW title, uppercased first. That
    ordering matters even with a single pattern: uppercasing the WHOLE title
    before searching is what lets a lowercase title still match; searching
    (rather than requiring the match to start at position 0) is what lets
    "IBAN " precede the code without being part of it.

    The shape this provider emits is `"IBAN <tight-iban>"` -- uppercase, with
    no internal spaces (see `tests/fixtures/whitelisted_accounts.json`) -- so
    this is also the canonicalisation step, not merely the extraction one: `_IBAN_RE`'s
    character class cannot cross a space, so a successful match is already
    an alnum-only, upper-case run with nothing left to strip. The session
    side, `_account_iban`, normalises its own field the same way
    (`.strip().upper()`) for the same reason -- the provider does not space
    that field internally either -- so both sides land in the same
    vocabulary because both inputs are, in fact, tight. `_iban_of`'s output
    is compared directly against `_account_iban`'s in `verify_accounts` and
    never reaches `store.account_id` at all.

    A conventionally-spaced or lowercase title does not match this pattern,
    and never occurs against the real data, so an unparsed title here is a
    signal that the
    provider's title format has changed, worth investigating on its own
    rather than worked around with more pattern tolerance.
    """
    match = _IBAN_RE.search((entry.get("title") or "").upper())
    return match.group(1) if match else ""


def _account_iban(account: dict) -> str:
    """IBAN out of a provider session account.

    The provider NESTS it: account["account_id"]["iban"], confirmed by the
    recorded session fixture. A flat "iban" key is the
    LEDGER's shape, and our own `account_id` is a string HMAC — reading
    reading account["iban"] here finds nothing, which turns every successful
    link into a reported zero-accounts failure.
    """
    ident = account.get("account_id")
    if isinstance(ident, dict):
        return (ident.get("iban") or "").strip().upper()
    return ""


def _account_currency(account: dict) -> str:
    return (account.get("currency") or "").strip().upper()


def verify_accounts(session_accounts: list, whitelisted: list,
                    intended: list, *, aspsp: str, country: str) -> Verdict:
    """Compare what came back against the whitelist AND the operator's intent.

    `aspsp` and `country` name the bank THIS authorization was for, and they
    are required. `whitelisted` is the whole application's list, so
    once bank A is linked its IBANs appear in every later answer; comparing a
    bank B consent against all of them reported bank A's IBANs as missing and
    made the second bank unlinkable. They are keyword-only and have no
    defaults so that a caller which has not been updated fails loudly here
    rather than silently verifying against everything.

    **This is a precondition, not a report**. Nothing may be
    upserted, bound or backfilled until this returns `ok`; the collection loop
    enforces that by refusing to record a success without the verdict, so
    an exchange that forgets to ask lands in `review_required` rather than
    quietly recording an authorized session with no history.

    Three failures, not one. "Non-zero" does not establish success — per-account
    filtering can return one account and silently drop another. Zero does not
    uniquely prove a whitelist gap — a wrong PSU type or a closed account look
    identical from here. And MORE than was approved is a failure too: binding it
    would ingest an account the operator never agreed to expose. So the verdict
    reports the specific difference and the evidence, never a guessed cause.

    **A fourth shape of "more than approved" needs its own check.**
    `want`/`listed` name IBANs — the whitelist carries no currency,
    and neither does `intended` — but the LEDGER's identity is the PAIR:
    `store.account_id` hashes `(iban, currency)`. A consent that returns the
    SAME whitelisted IBAN under more than one currency (a multi-currency
    sub-account does exactly this) creates a SECOND ledger account
    nothing approved, and a plain IBAN-set comparison cannot see it — both
    pairs collapse onto the one IBAN already sitting in `want`. Detected here
    directly, against the pair, rather than trusted to the IBAN-only sets.
    """
    got = {i for i in (_account_iban(a) for a in session_accounts) if i}
    listed = {i for i in (_iban_of(w) for w in _for_bank(whitelisted, aspsp,
                                                        country)) if i}
    want = {i.strip().upper() for i in intended if i} or listed
    missing = sorted(want - got)
    unexpected = sorted(got - want)

    by_iban: dict = {}
    for a in session_accounts:
        iban = _account_iban(a)
        if iban:
            by_iban.setdefault(iban, set()).add(_account_currency(a))
    extra_currency = sorted(
        f"{iban}/{currency or '?'}"
        for iban, currencies in by_iban.items() if len(currencies) > 1
        for currency in sorted(currencies))

    if not got:
        return Verdict(False,
            "The bank authorized the consent but returned no usable accounts. "
            "The usual cause is that the account is not on the application's "
            "whitelist, but a wrong PSU type (personal vs business) or a "
            "closed account look identical from here. The whitelist currently "
            f"holds: {sorted(listed) or 'nothing'}. Next step: run the link "
            "step for this account, then authorize again.")
    if missing or unexpected or extra_currency:
        parts = []
        if missing:
            parts.append(
                f"missing {missing} — each account needs its own whitelist "
                "entry, so link the missing ones and authorize again")
        if unexpected:
            parts.append(
                f"unexpected {unexpected} — the bank returned an account that "
                "was neither approved nor whitelisted, so nothing here has "
                "been linked; check which accounts the consent covers before "
                "authorizing again")
        if extra_currency:
            parts.append(
                f"unexpected currency variants {extra_currency} — the same "
                "IBAN was returned under more than one currency, and the "
                "ledger keys each currency as a SEPARATE account, so only "
                "one of them was ever approved; nothing here has been "
                "linked, check which currency the consent covers before "
                "authorizing again")
        return Verdict(False,
            f"Linked nothing. The bank returned {sorted(got)} but "
            f"{sorted(want)} was expected: " + "; ".join(parts) + ".")
    return Verdict(True, f"Linked {sorted(got)}.")


def complete_renewal(conn, ais, *, old_session_id: str, new_session_id: str,
                     accounts: list, secret: bytes, incarnations: dict) -> dict:
    """THE renewal entry point. Deep fetch first, then the one switch.

    `incarnations` is `{account_id: incarnation}` captured by the SAME read
    that validated the exact bound set — the issue-#8 fence's token, one per
    account. Every write each backfill makes, and the switch itself, is
    conditioned on the account still living that life. An account erased (or
    erased and re-linked) mid-renewal joins `erased_accounts` in the return —
    present on EVERY path, like `remedy` — nothing is switched, nothing is
    retired, and the old consent stays the live one: the safe direction when
    the operator erased an account out from under their own renewal.

    A renewal must not close the old session until the new session's deep
    fetch is durably complete. So, strictly:

    1. backfill the **new** session to exhaustion, inside the fresh-SCA window,
       while every account is still bound to the **old** one — `backfill` takes
       the uid from the caller's dict, not from the account row, which is
       exactly what lets the old consent stay live and serving while the new
       one is being paged;
    2. only once every account's fetch is durably committed,
       `apply.switch_bindings` promotes the new session, moves every binding,
       bumps the generation and retires the old one, in one transaction.

    3. and then, outside that transaction, **revoke the old consent at the
       bank** — `ais.delete_session(old_session_id)` — because closing the old
       session means a `DELETE /sessions/{id}`, not a local flag. Without this
       step a successful renewal leaves the old AIS grant
       live for the remainder of its 179 days while the ledger stops showing
       it: three banks renewed yearly accumulate live grants the operator can
       neither see nor revoke.

    A run that fell short — a pagination cap, or a bank that proved nothing —
    returns `retired: False` having switched nothing, so the OLD consent is
    still live and still bound and the renewed one is still quarantined,
    visible and revocable. A hard failure mid-pagination propagates from
    `backfill` for the same reason it always did: the caller must not read a
    silent zero as an empty account.

    **A short run also returns `remedy`, and it is NOT `sync`.** A capped
    renewal is not resumable here, because the candidate session stays
    quarantined and its `uid`s are never written down. `sync` can only refresh
    the still-bound OLD session, so pointing the operator at it reports
    progress on the wrong consent. `remedy` therefore carries
    `REAUTHORIZE_REMEDY`, and the caller's wording must be the honest one:
    revoke the quarantined candidate and authorize again. It is present and
    `None` on the completing path too, because a key that only appears on
    failure is a key callers forget to read.

    **A failed revocation does not undo the renewal, and is never recorded as
    a success.** The new consent is live, mapped and correct; the old
    grant is a separate cleanup obligation, so a 429 on the `DELETE` must not
    throw a completed renewal away. It is reported instead: `revoked: False`
    plus the provider's own failure text, and `apply.record_revocation` leaves
    the old row visible (`closed_at` NULL) under `REVOKE_FAILED_STATUS` so
    `consent_status` still lists it and `unlink_bank` can still revoke it by
    the same `consent_ref`. Hiding a consent we did not actually revoke is the
    the stranding a quarantine exists to undo — putting it back on the success
    path would be no better than leaving it on the failure path.

    The caller has already checked that the returned `account_id` set is
    exactly the bound set; this owns the ordering, not the mapping.

    The split between this and `apply.switch_bindings` is not taste. One call
    that both fetched and switched would either hide a multi-minute paginated
    fetch inside something named like a database operation, or switch too
    early — and the ordering is the entire safety property.
    """
    bindings, results = [], {}
    for account in accounts or ():
        account_id = account.get("account_id")
        if not account_id:
            account_id = store.account_id(str(account.get("iban") or ""),
                                          str(account.get("currency") or ""),
                                          secret)
        bindings.append((account_id, account.get("uid")))

    inserted, shallow, short, erased = 0, False, [], []
    for account_id, uid in bindings:
        # observe=True: a renewal's fetch is one of the two labelled
        # deep-observation runs reference trust can be earned from.
        out = backfill(ais, conn, {"account_id": account_id, "uid": uid},
                       new_session_id, observe=True,
                       incarnation=incarnations.get(account_id))
        inserted += out.get("inserted") or 0
        shallow = shallow or bool(out.get("shallow"))
        if out.get("erased"):
            erased.append(account_id)
        if not apply.deep_fetch_complete(conn, account_id, new_session_id):
            # The same predicate switch_bindings refuses on, asked here so the
            # caller gets `retired: False` — a durable "come back and finish
            # this" — rather than an exception. One predicate, two uses, so the
            # two can never drift apart. Note it asks whether the FETCH
            # completed, not whether rows came back: a dormant account renews.
            # An erased account always lands here too — its stamp was fenced.
            short.append(account_id)
    if short:
        # Nothing is switched, nothing is retired and nothing is revoked — the
        # old consent is still the live one. Reported rather than raised: the
        # caller turns this into `declare_partial`, which is a durable "come
        # back and finish this", not a lost exchange.
        #
        # `remedy` is the honest half of that durable note. The candidate
        # session is quarantined and its `uid`s were never persisted, so `sync`
        # CANNOT continue this attempt — it would refresh the old bound session
        # and report progress on the wrong consent. The caller must say: revoke
        # the quarantined candidate and authorize again.
        # `capped` stays True only when a NON-erased account fell short: it
        # is the "re-run may help" signal, and an erased account has nothing
        # to re-run against — labelling it capped sent the operator back to
        # finish a fetch for an account that no longer exists.
        return {"accounts": 0, "generation": None, "retired": False,
                "inserted": inserted, "shallow": True, "incomplete": short,
                "capped": bool(set(short) - set(erased)),
                "completeness": "aborted" if set(short) <= set(erased)
                else "partial",
                "erased_accounts": erased,
                "revoked": False, "revoke_error": None,
                "remedy": REAUTHORIZE_REMEDY}

    try:
        switched = apply.switch_bindings(conn, bindings, new_session_id,
                                         old_session_id,
                                         incarnations=incarnations)
    except apply.AccountErased as exc:
        # Erased AFTER every fetch completed and BEFORE the switch took its
        # lock. Same honest outcome as an erasure mid-fetch: nothing
        # switched, nothing retired, old consent still the live one — and
        # the report says which account ended it, not a generic failure.
        return {"accounts": 0, "generation": None, "retired": False,
                "inserted": inserted, "shallow": shallow,
                "incomplete": [exc.account_id] if exc.account_id else [],
                "capped": False, "completeness": "aborted",
                "erased_accounts": [exc.account_id] if exc.account_id else [],
                "revoked": False, "revoke_error": None,
                "remedy": REAUTHORIZE_REMEDY}
    revoked, revoke_error = _revoke(conn, ais, old_session_id)
    # `capped`/`completeness` too, so the caller's two-signal completeness
    # check reads this exactly as it reads a plain backfill result. `remedy` is
    # present on BOTH paths and None here — and `erased_accounts` on all
    # three: a key that appears only on failure is a key callers forget to
    # read.
    return dict(switched, inserted=inserted, shallow=shallow, incomplete=[],
                capped=False, completeness="complete", erased_accounts=[],
                revoked=revoked, revoke_error=revoke_error, remedy=None)


def _revoke(conn, ais, old_session_id: str):
    """Close the old consent AT THE BANK, and record what actually happened.

    Only after the new session is authorized and mapped is the old session
    closed, with a `DELETE /sessions/{id}`. `switch_bindings` performs
    the local half and deliberately stops short of `closed_at`, because at that
    commit the grant still exists at the bank. This is the other half, and it
    runs OUTSIDE the switch transaction: an HTTP call inside it could fail
    after the bindings moved and leave the ledger and the bank disagreeing,
    and the switch is the part that has to be atomic.

    The failure is caught, never propagated. The renewal has already succeeded
    — accounts are bound to a live, fully fetched consent — and raising here
    would report a completed renewal as a failure and invite the operator to
    run it again. What must not happen is the opposite error: recording a
    revocation the provider never confirmed. So the outcome is written through
    `apply.record_revocation`, which sets `closed_at` only on a confirmed
    revocation and otherwise leaves the row visible under
    `REVOKE_FAILED_STATUS`, carrying its `consent_ref`, for `unlink_bank` to
    retry.

    **A 404 is a success, and the rule that says so is shared.**
    `eb_ais.revocation_is_final` is the ONE predicate; `unlink_bank` calls the
    same one. The provider answering "that session does not exist" is the
    provider describing the state a successful DELETE produces, so recording it
    as a failure would pin the row in `REVOKE_FAILED` for ever — visible,
    nagging, and unresolvable, because every retry can only 404 again. The
    predicate lives in `eb_ais` precisely so both callers share it: in
    `tools_auth` it would sit ABOVE this module, which cannot import it.
    Nothing else qualifies: a 429, a timeout, a 5xx, a 401 and a 403 all leave
    the grant very probably live at the bank.

    Only `Exception` is caught, so a genuine `BaseException` — a
    KeyboardInterrupt, a SystemExit — propagates untouched and the row keeps
    the `RETIRED_STATUS` (`REVOKE_PENDING`) that `switch_bindings` just left
    it in: visible, revocable, and truthful about what we do not know.

    `callbacks.Indeterminate` is NOT in that group, despite being exactly the
    shape this reasoning is about. It subclasses `RuntimeError`, so the
    `except Exception` below WOULD catch it and file a lease loss as a
    provider refusal (`REVOKE_FAILED`, `revoke_error="Indeterminate"`).
    Nothing inside the `try` can raise it today — the only call is
    `ais.delete_session`, whose failures are `ApiError` and transport errors —
    so this is a bound on the argument, not a live path. Anything added inside
    the `try` that CAN raise `Indeterminate` must re-raise it explicitly;
    catching by base class will not do it for us.
    """
    try:
        ais.delete_session(old_session_id)
    except Exception as exc:                     # provider said no, or nothing
        final = eb_ais.revocation_is_final(exc)
        apply.record_revocation(conn, old_session_id, revoked=final)
        # The class name, not str(exc): a provider body may echo identifiers,
        # nothing a tool can print may carry one.
        return (True, None) if final else (False, type(exc).__name__)
    apply.record_revocation(conn, old_session_id, revoked=True)
    return True, None


def _aspsp_of(conn, account: dict) -> str:
    """The bank name to look reference behaviour up under, read from the
    ACCOUNT ROW.

    `accounts.aspsp` is written at upsert time from the session's ASPSP name.
    Nothing supplied it before this repair, so `provenance.capability()` was
    always asked about `""`, always answered `DEFAULT_CAPABILITY`, and every
    ingest silently fell back to heuristic matching — including for accounts
    whose capability this installation had recorded. The caller's dict is only
    a fallback for an account not yet persisted.
    """
    row = conn.execute("SELECT aspsp FROM accounts WHERE account_id=?",
                       (account["account_id"],)).fetchone()
    stored = (row["aspsp"] if row is not None else "") or ""
    return (stored or account.get("aspsp") or "").strip()


def _incomplete(conn, account_id: str, note: str, incarnation) -> bool:
    """Persist that an attempt happened and proved nothing. Returns whether
    the row landed.

    A capped or failed run may keep staging and checkpoint state, but it must
    neither update nor tombstone a canonical row and must record NO coverage.
    `last_success_at` and `oldest_fetched` are carried over from the previous
    row rather than cleared — an earlier complete sync really did happen, and
    erasing it would turn one bad page into an apparent total loss — while
    `completeness` goes to 'partial' so every read tool labels its answers as
    covering an incomplete range.

    Guarded on the run's captured `incarnation` like every other late write:
    a capped or failed run whose account was erased underneath it must not
    recreate `sync_state` for the erased account — issue #8's fence covers
    the failure paths too, because a resurrection through the error path is
    still a resurrection. False means the guard refused; the caller converts
    that into its erased report (the failed path still re-raises regardless).
    """
    now = dt.datetime.now().isoformat()
    prior = conn.execute(
        "SELECT last_success_at, oldest_fetched, last_success_session"
        " FROM sync_state WHERE account_id=? AND resource='transactions'",
        (account_id,)).fetchone()
    cur = conn.execute(
        "INSERT OR REPLACE INTO sync_state(account_id, resource,"
        " last_attempt_at, last_success_at, completeness, last_error,"
        " next_retry_after, oldest_fetched, last_success_session)"
        " SELECT ?,'transactions',?,?,'partial',?,NULL,?,?"
        " WHERE EXISTS (SELECT 1 FROM accounts WHERE account_id=?"
        " AND incarnation=?)",
        (account_id, now, prior["last_success_at"] if prior else None, note,
         prior["oldest_fetched"] if prior else None,
         prior["last_success_session"] if prior else None,
         account_id, incarnation))
    return bool(cur.rowcount)


def _proven_lower_bound(fetched: list, requested_from: str) -> str | None:
    """The oldest date THIS response proves history EXISTS down to.

    For COVERAGE only -- never a tombstone licence, see
    `TOMBSTONE_LICENSED_ASPSPS`.

    `None` when `fetched` is empty: there is no earliest returned row, so
    there is nothing to claim exists -- an empty response proves nothing,
    never an empty account.

    Otherwise, the oldest `booking_date` actually returned, floored at
    `requested_from` only defensively -- the provider should never return a
    row older than what we asked for, but if it somehow did, that is MORE
    proof of existence, not less, so it is never used to WIDEN the bound past
    what the response itself contains. This says NOTHING about whether any
    row between that date and `requested_from` is absent -- proving a row
    exists is not proving every OTHER row in an interval doesn't.
    """
    dates = [r["booking_date"] for r in fetched if r.get("booking_date")]
    return max(requested_from, min(dates)) if dates else None


def backfill(ais, conn, account: dict, session_id: str,
             floor_days: int = BACKFILL_FLOOR_DAYS,
             observe: bool = False, *, incarnation) -> dict:
    """Exhaustive deep backfill, INSIDE the fresh-SCA window.

    `account` is the ledger-side dict {"account_id", "uid"}; the ASPSP is read
    from the account row (`_aspsp_of`).

    `observe=True` is the DEEP-OBSERVATION LABEL (issue #1): exactly the two
    fresh-SCA call sites pass it — the first-link backfill and the renewal
    backfill — and it is what licenses writing a `kind='deep'` evidence row,
    the only kind that can GRANT reference trust. A narrow routine refresh
    must never carry it: measuring a nine-day window and letting any
    "insufficient sample" reading near the grant path is how legitimately
    earned trust gets revoked by a thin sample. The guard below refuses the
    mislabel outright rather than quietly not-observing, because a caller
    that believes it scheduled a deep observation and didn't is a programmer
    error worth hearing about. Reuse EVENTS are different: every completed
    run measures, and a measured sighting demotes whatever the window size —
    sample size bounds what silence proves, never what a sighting proves.

    Returns {"inserted", "proved_from", "proved_to", "shallow", "pages",
    "capped", "completeness", "erased"} — **the completeness signals and
    `erased` on EVERY return path**, the capped one included. `erased: True`
    is the issue-#8 fence firing: the account was erased (or erased and
    re-linked) while this run held its pages, every write refused, and
    nothing durable exists for this run — `completeness` is then 'aborted',
    which no consumer may read as complete. The consumer reads a missing
    `completeness` as complete, so a branch that omits it is a branch that
    reports an unfinished fetch as a finished one; the durable
    `sync_state.completeness` written alongside carries the identical fact, and
    the two are set from the same variable so they cannot drift.

    `shallow` is True when under 180 days was proved: the window was missed
    and the caller MUST surface that as a named gap with the remedy — re-link
    the bank — never as a quiet success. It is also written to
    sync_state.last_error so the gap is durable, not merely returned. Filling
    the gap in place is follow-up work; the read tools already name holes, and
    the next renewal's deep fetch is the ordinary way one closes.

    **A CLEAN, empty response is not a shallow window.**
    An account that returned nothing has not missed a window — there is no
    window to miss, and it is indistinguishable here from a bank that
    silently truncated an active account to zero — so `shallow` is
    only ever True on a NONZERO but short proven span, and the durable
    re-link note is only ever written then. Re-linking a genuinely dormant
    account reproduces the same nothing, and nothing would ever clear a note
    that stayed there durably — the pinned-forever shape
    `eb_ais.revocation_is_final` exists to prevent on the revocation path.

    **Pagination completes before anything canonical is touched**. The old
    order — reconcile, apply, *then* check `capped` — tombstoned every stored
    row that merely happened to live on an unconsumed page, because
    reconciliation marks any unmatched stored row inside the requested interval
    as `vanished`. Calling the sync partial afterwards does not bring the row
    back. So a capped or failed run returns here having changed nothing:
    no updates, no tombstones, no coverage, no success stamp.

    **A response never licenses a tombstone interval by itself.** `capped` and
    the mid-pagination exception are proxies for "the fetch was complete" — but
    even a fetch that is neither capped nor failed only proves the EXISTENCE of
    the rows it returned, never the COMPLETENESS of the interval it covered.
    Two derivations were tried and both destroy real history. Licensing
    `reconcile`'s rule 3 with `(requested_from, end)` tombstones everything a
    truncated-but-clean response simply did not repeat. Licensing it with
    `(proved_from, proved_to)` — the span the RESPONSE itself proved — destroys
    rows whenever that truncated response happens to carry one old, unrelated
    row (an account-opening entry, a backdated correction): the licence widens
    straight back out to that row's date, and everything between it and the
    genuinely-missing rows is tombstoned on no better evidence. Both make the
    identical structural error: computing the licence FROM the very response
    under reconciliation. See `TOMBSTONE_LICENSED_ASPSPS` above — no ASPSP has the
    capability that would justify a licence, so `reconcile` gets the same
    explicit, degenerate no-licence interval on every path, and rule 3 can
    never fire. `_proven_lower_bound` below is kept for `proved_from`/
    `proved_to`/coverage — what this response proves about history that
    EXISTS — which is a different question from what it proves is ABSENT.
    """
    if observe and floor_days != BACKFILL_FLOOR_DAYS:
        raise ValueError(
            "observe=True is the deep-observation label and only the deep "
            "window may carry it; a narrow run must not write the evidence "
            "that grants reference trust")
    today = _today()
    requested_from = (today - dt.timedelta(days=floor_days)).isoformat()
    end = (today + dt.timedelta(days=1)).isoformat()
    aid = account["account_id"]

    # `incarnation` is the CALLER's capture, made atomically with the binding
    # read this run fetches under, and required — issue #8. This function
    # used to read the token here, at entry, and that read races the caller's
    # own earlier account read: a forget-and-relink between the two hands
    # this run the NEW life's token for pages it is about to fetch under the
    # OLD life's uid/session, and every guard below then passes. Every write
    # this run makes — plan rows, evidence, coverage, sync_state, on the
    # failure paths too — is conditioned on this token still being the live
    # one, inside the same transaction as the write. A None (the account row
    # was already gone at capture) matches no row: fail-closed.

    def _erased(pages: int) -> dict:
        """The report of a run fenced off because its account was erased.

        Neither a failure nor a success: `completeness` is 'aborted' (never
        'complete', so no consumer can credit it), nothing durable was
        written, and `erased` says WHY nothing landed. `forget_local_account`
        already told the operator what was erased; this run's job is only to
        not contradict it.
        """
        return {"inserted": 0, "proved_from": None, "proved_to": None,
                "shallow": False, "pages": pages,
                "capped": False, "completeness": "aborted", "erased": True,
                "new_row_ids": [], "auto_tagged": 0,
                "needs_classification": 0}

    # ---- stage every page; NOTHING destructive runs until this finishes ----
    staged, key, pages, capped = [], None, 0, False
    try:
        while True:
            rows, key = ais.transactions(account["uid"], requested_from, key)
            staged.extend(rows)
            pages += 1
            if not key:
                break
            if pages >= MAX_PAGES:
                capped = True
                break
    except Exception:
        # A 429 or a dropped socket mid-pagination is exactly the incomplete
        # fetch above: record the attempt, prove nothing, and re-raise so the
        # caller cannot mistake a silent zero for an empty account. The
        # attempt note is fenced like every other write — an erased account
        # records nothing — but the exception re-raises REGARDLESS: what the
        # provider did and what the operator did are two different facts,
        # and the caller still has to hear the first one.
        _incomplete(conn, aid, FAILED_NOTE, incarnation)
        raise

    if capped:
        if not _incomplete(conn, aid, CAPPED_NOTE, incarnation):
            # The cap happened, but the account was erased underneath the
            # run — and "erased" is the finding that decides what the
            # operator may rely on: a capped report would send them back to
            # re-run a backfill for an account that no longer exists.
            return _erased(pages)
        # `capped` and `completeness` on THIS path too. The contract says
        # every return carries both and that a missing signal means incomplete,
        # but the consumer defaults an absent `completeness` to "complete" — so
        # the one branch that omitted them was the one where omitting them
        # reads as success. The durable sync_state row above happens to mask it
        # today; that is exactly the producer-to-consumer loss this round is
        # about, and a signal that only survives by accident is not a signal.
        return {"inserted": 0, "proved_from": None, "proved_to": None,
                "shallow": True, "pages": pages,
                "capped": True, "completeness": "partial", "erased": False,
                "new_row_ids": [], "auto_tagged": 0,
                "needs_classification": 0}

    fetched = [ingest.normalise(r, aid) for r in staged]
    # Every state, not just 'active': occurrence is allocated above every value
    # ever issued INCLUDING tombstoned rows, and hiding them here
    # reissues a tuple the UNIQUE index still owns.
    stored = [dict(r) for r in conn.execute(
        "SELECT * FROM transactions WHERE account_id=? AND booking_date >= ?"
        " AND booking_date < ?", (aid, requested_from, end))]
    aspsp = _aspsp_of(conn, account)
    # MEASURE BEFORE RECONCILE. The run that carries the counter-evidence
    # must not itself rewrite history under the premise it just refuted: a
    # page set showing reference reuse reconciles UNTRUSTED, whatever the
    # ledger's standing evidence says, and the sighting is filed durably
    # inside the same transaction that applies this run's plan (below).
    metrics = provenance.measure_references(fetched)
    ledger_capability = provenance.capability(conn, aspsp, aid)
    trusted_before = ingest.ref_trusted(ledger_capability)
    capability = (dict(provenance.DEFAULT_CAPABILITY)
                  if metrics["reused_refs"] else ledger_capability)
    built_trusted = ingest.ref_trusted(capability)
    # Reported, never silently downgraded: a name that resolves to no
    # evidence is far more often a spelling drift than a bank that reuses
    # references, and the two are indistinguishable from in here. The
    # downgrade itself is correct and stays — an unmeasured account is
    # untrusted.
    drift = provenance.capability_warning(conn, aspsp, aid)
    # The DURABLE occurrence high-water for every cluster this pass can touch.
    # `stored` above is only the rows inside the requested interval, and a
    # routine refresh narrows that to about a week — so without this a monthly
    # standing order re-allocates occurrence 0 over a row that is simply out of
    # view, and apply_plan dies on UNIQUE (account_id, identity_key,
    # occurrence).
    idents = {ingest.identity_key(f) for f in fetched}
    idents.update(s["identity_key"] for s in stored if s.get("identity_key"))
    allocated = apply.occurrence_allocations(conn, aid, idents)

    # ---- what did THIS response prove EXISTS? (coverage, not tombstoning) --
    # Kept for `proved_from`/`proved_to`/coverage only: a response proves the
    # EXISTENCE of the rows it returned regardless of whether it proves the
    # COMPLETENESS of any interval, and coverage's job is to record the
    # former ("history down to this date is in the ledger"), never the
    # latter. `proved_to` stays the REQUESTED `end`: `eb_ais.AIS.transactions`
    # takes a `date_from` but no `date_to`, so every call implicitly asks
    # "from date_from through now", and a clean completion is the provider
    # affirming it answered that open-ended question — a fact about what
    # EXISTS up to today, which is all coverage ever claims.
    proved_from = _proven_lower_bound(fetched, requested_from)
    proved_to = None if proved_from is None else end

    # A response never licenses a tombstone interval BY ITSELF, and the licence
    # is withheld UNCONDITIONALLY. `TOMBSTONE_LICENSED_ASPSPS` above records
    # that no ASPSP has the measured capability which would justify one — but
    # it is deliberately NOT consulted here. A branch reading `(proved_from,
    # proved_to)` for an ASPSP that happened to be in that set would be the
    # invalid derivation kept alive on nothing but a name check, reactivatable
    # by a one-line edit and no design work. What is wrong is the DERIVATION,
    # not merely the evidence for it, so there is no formula here to
    # reactivate. rule 3 gets the same explicit, degenerate no-licence interval
    # unconditionally, on every path: `(end, end)` empties rule 3's inner range
    # at EVERY window size. inner_start = end + match_window_days is never less
    # than inner_end = end - match_window_days — strictly greater for any
    # positive window, and EQUAL at match_window_days = 0, where the strict `<`
    # in `inner_start <= booking_date < inner_end` empties the range anyway —
    # so that test can never hold and rule 3 can never fire. Whoever eventually
    # wires up a re-list-completeness measurement must derive a licence FROM
    # that measurement, here, from scratch — not flip this back on.
    reconcile_interval = (end, end)

    plan = ingest.reconcile(stored, fetched, reconcile_interval, capability,
                            allocated=allocated)

    def _evidence_and_revalidate(c):
        """Inside apply_plan's BEGIN IMMEDIATE, before any plan row lands.

        Order is load-bearing: (0) THE FENCE — is the account still living
        the life this run captured? Asked here, under the write lock that
        holds through COMMIT, because this is the one place the answer
        cannot change between the asking and the writing.
        `forget_local_account`'s own BEGIN IMMEDIATE orders entirely before
        or entirely after this transaction, so a run whose account was
        erased (or erased and re-linked — same deterministic id, new token)
        raises `apply.AccountErased`, the whole plan rolls back, and the
        pages this run holds in memory land nowhere. Then (1) file THIS
        run's evidence, so no state exists in which the run's rows are
        committed and its demotion is not; (2) re-derive trust under the
        write lock; (3) hand back a heuristic replan when a plan built under
        trust arrives at a ledger that has since demoted — a concurrent deep
        run can file a reuse event between this run's derivation above and
        this lock. Grants never replan: a plan built untrusted is always
        licensed.
        """
        live = c.execute("SELECT 1 FROM accounts WHERE account_id=?"
                         " AND incarnation=?", (aid, incarnation)).fetchone()
        if live is None:
            raise apply.AccountErased(
                "account %s was erased while this run was fetching; nothing "
                "from the fetch may land" % aid, aid)
        if observe:
            # The labelled deep run files its observation whatever it saw --
            # a zero-row dormant account included: "measured, and nothing"
            # is a different fact from "never measured".
            provenance.record_observation(
                c, account_id=aid, incarnation=incarnation, aspsp=aspsp,
                session_id=session_id, kind="deep", window_days=floor_days,
                metrics=metrics)
        elif metrics["reused_refs"]:
            # A narrow run that measured reuse files the sighting. On an
            # observe run the deep row above already carries reused_refs>0,
            # so a second row would say nothing new.
            provenance.record_observation(
                c, account_id=aid, incarnation=incarnation, aspsp=aspsp,
                session_id=session_id, kind="reuse_event", source="measure",
                window_days=floor_days, metrics=metrics)
        if built_trusted:
            current = provenance.capability(c, aspsp, aid)
            if not ingest.ref_trusted(current):
                return ingest.reconcile(stored, fetched, reconcile_interval,
                                        current, allocated=allocated)
        return None

    try:
        stats = apply.apply_plan(conn, aid, plan,  # one transaction, or raises
                                 pre_apply=_evidence_and_revalidate)
    except apply.AccountErased:
        # ONLY the fence's own signal is converted; every other exception —
        # provider, plan, database — keeps its meaning and propagates. The
        # rollback already unwound rows, evidence and allocations together.
        return _erased(pages)

    span = 0 if proved_from is None else (dt.date.fromisoformat(proved_to)
                                          - dt.date.fromisoformat(proved_from)).days
    # "Under 180 days" and "nothing at all" are DIFFERENT findings and must not
    # share one signal. An account that proved nothing has not missed a window
    # -- there is no window to miss -- and treating it as shallow durably tells
    # the operator to re-link a bank that has nothing to re-link: doing that to
    # a genuinely dormant account reproduces the same nothing, and nothing
    # would ever clear the note again. Only a NONZERO but short proven span is
    # "shallow".
    shallow = proved_from is not None and span < SHALLOW_SPAN_DAYS

    if proved_from is not None:
        # AFTER the rows are durably committed: coverage attests to the ledger,
        # never to what an HTTP call returned.
        #
        # Coverage stays the interval we PROVED — bounded by the oldest row the
        # bank actually returned, never by the floor we requested. An account
        # that returns NOTHING therefore records no coverage, and that is
        # deliberate: "the account is dormant" and "the bank silently truncated
        # to nothing" are indistinguishable from here -- the same session can
        # return deep history once and a narrow window later, both clean -- and
        # claiming a proven-empty multi-year interval on the weakest evidence
        # we ever have is exactly the confident lie this design refuses.
        # `last_success_session` below carries the narrower, answerable fact —
        # the retrieval completed — which is what a renewal actually needs.
        #
        # False from the guard means the account was erased between
        # apply_plan's commit and this separate transaction: the rows this
        # run committed are already gone (forget deleted them), so coverage
        # attesting to them would be the confident lie, and the honest
        # report for the WHOLE run is "erased" — the end state holds nothing.
        if not apply.record_coverage(conn, aid, proved_from, proved_to,
                                     session_id, incarnation=incarnation):
            return _erased(pages)

    now = dt.datetime.now().isoformat()
    # A trust transition is DISCLOSED, not silent, beside the shallow and
    # drift notes the operator already reads. Compared ledger-to-ledger --
    # the derivation before this run against the derivation after it -- so
    # the note names what actually changed durably, not what this run
    # intended. Committed rows are deliberately untouched by a demotion:
    # their match_method is a true statement about how they were matched at
    # the time, under a grant the evidence record still explains.
    trusted_after = ingest.ref_trusted(provenance.capability(conn, aspsp, aid))
    trust_note = None
    if trusted_before and not trusted_after:
        trust_note = TRUST_DEMOTED_NOTE
    elif not trusted_before and trusted_after:
        trust_note = TRUST_GRANTED_NOTE
    notes = [n for n in (SHALLOW_NOTE if shallow else None, drift,
                         trust_note) if n]
    # `last_success_session` is the durable fact a renewal switch stands on:
    # THIS session ran the fetch to exhaustion for this account.
    # It is written here, after apply_plan committed, and only on a run that
    # completed — which is why apply.switch_bindings can check it instead of
    # trusting that its caller backfilled first. Unlike coverage it does not
    # depend on rows coming back, so a dormant account renews normally.
    cur = conn.execute(
        "INSERT OR REPLACE INTO sync_state(account_id, resource,"
        " last_attempt_at, last_success_at, completeness, last_error,"
        " next_retry_after, oldest_fetched, last_success_session)"
        " SELECT ?,'transactions',?,?,?,?,NULL,?,?"
        " WHERE EXISTS (SELECT 1 FROM accounts WHERE account_id=?"
        " AND incarnation=?)",
        (aid, now, now, "complete", "; ".join(notes) or None, proved_from,
         session_id, aid, incarnation))
    if not cur.rowcount:
        # Erased between the previous write and this one; same reasoning as
        # the coverage guard above — the end state holds nothing, say so.
        return _erased(pages)
    # The returned pair and the durable row are written from the same fact, in
    # the same place, so a caller reading either learns the same thing.
    return {"inserted": stats["inserted"], "proved_from": proved_from,
            "proved_to": proved_to, "shallow": shallow, "pages": pages,
            "capped": False, "completeness": "complete", "erased": False,
            "new_row_ids": stats["inserted_row_ids"],
            "auto_tagged": stats["auto_tagged"],
            "needs_classification": stats["needs_classification"]}
