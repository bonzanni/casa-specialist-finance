# plugins/bank-feed/server/apply.py
"""Persist an ingest.Plan, and maintain proven coverage intervals.

Three rules govern this module:
  * a plan lands whole or not at all — a half-applied page set would leave
    `coverage` attesting to rows that are not in the ledger;
  * inserts run FIRST, because a supersede points a stored pending row at a
    booked row this same plan is inserting and only the database knows that
    row's id;
  * coverage intervals are merged ON WRITE, so the table is a set of disjoint
    proven intervals rather than an append log that only looks right when read
    through the right function.

The four Plan fields are all `list[dict]`. Nothing here accepts a bare row id:
that would absorb a contract violation instead of failing on it.

**HONEST COUNTS.** `apply_plan`'s returned `stats` describe
WRITES, not the Plan's length. `plan.updates`/`tombstones`/`flags` each name a
`row_id` the caller read as `stored` at some earlier point; a row deleted
underneath the plan between that read and this call (`purge_before`,
`forget_local_account`) makes that entry's `UPDATE` affect zero rows.
`update`, `supersede`, `tombstone` and `flag` writes therefore only count
(and, for `update`, only raise the durable `occurrence_alloc` mark and record
a reference) when `cur.rowcount` says the row was actually there —
`switch_bindings` already held every per-account write to this standard
(`cur.rowcount != 1`), and the plan-application loop does too. A
zero-rowcount entry counts as nothing and the plan otherwise proceeds: a
plan racing a legitimate deletion is recoverable, and `flows.backfill` losing
an entire interval's coverage because one row vanished underneath it would be
worse than the entry being silently skipped. This is deliberately NOT a raise.

**EVERY WRITE IS SCOPED TO THE ACCOUNT THIS PLAN IS FOR.** `row_id` is a global
primary key across every account's transactions, so an
`update`/`supersede`/`tombstone`/`flag` `UPDATE` keyed on it ALONE lets a plan
applied under account A — by a stale caller, or two callers racing on the same
row_id space — name an account B row_id and silently rewrite B's ledger while
reporting it as A's write. Each of those four statements therefore also requires
`account_id=?`, exactly as every INSERT does, and a row_id belonging to a
different account affects zero rows: the SAME honest, non-raising no-op path,
because "doesn't exist" and "exists but isn't yours" are indistinguishable from
here and do not need to be told apart.
"""
from __future__ import annotations

import datetime as _dt
import secrets

import rules
import store


def _now() -> str:
    return _dt.datetime.now().isoformat()


class AccountErased(Exception):
    """A write was refused because the account's life ended under the run.

    Raised only inside a write transaction, when the incarnation a run
    captured at its start is no longer the account's live one — the account
    was erased (`forget_local_account`), or erased and re-linked, while the
    run held its fetched pages in memory. The raiser's transaction rolls
    back whole, so nothing the run staged lands.

    This is NEITHER a failure of the run NOR a defect: the honest outcome is
    a run that reports it stopped because the account was erased underneath
    it. `flows.backfill` converts it into that report; `flows.complete_renewal`
    converts it into a renewal that switched nothing and says why.

    Carries the account it refused for; it NEVER carries a session id.
    """

    def __init__(self, message: str, account_id: str = ""):
        super().__init__(message)
        self.account_id = account_id


class RebindRefused(Exception):
    """A binding would have moved without exact-match evidence: an exact
    `account_id` match carries labels and history forward, and anything else
    stops for operator review. Fuzzy remapping is not built; stopping is safe,
    guessing is not."

    Raised on two paths. `flows.complete_renewal` raises it when the renewed
    consent's account set is not exactly the bound set — the case the operator
    filed as follow-up. `upsert_account` raises it as the BACKSTOP, for any
    caller that tries to move a bound account without going through the
    renewal sequence at all.

    Carries the account it refused for; it NEVER carries a session id.
    """

    def __init__(self, message: str, account_id: str = ""):
        super().__init__(message)
        self.account_id = account_id


def record_binding_review(conn, account_id: str, note: str,
                          incarnation) -> None:
    """Record, durably, that this account's binding needs a human decision.

    `sync_state` rather than a table of its own: it is already keyed
    (account_id, resource), `completeness` already says how far a resource's
    state can be trusted, and the tools that report per-resource state read
    every resource rather than only 'transactions' — so a review lands
    somewhere an operator already looks instead of in a table nothing queries.
    The note names the account and the bank and never a session id.

    `incarnation` is required and the write is conditioned on it, the same
    guard every other late write carries: this upsert used to be
    unconditional, which made the REFUSAL paths that call it into
    resurrection paths of their own — a rebind refused because the account
    was erased (or erased and re-linked) underneath its flow would have
    recorded the OLD attempt's review row under the account's NEW life, or
    recreated `sync_state` for an account `forget_local_account` had just
    reported gone. When the token no longer matches, the refusal itself
    still happens — it simply leaves no durable note, because there is no
    account of this life to leave it about.
    """
    conn.execute(
        "INSERT INTO sync_state(account_id, resource, last_attempt_at,"
        " completeness, last_error)"
        " SELECT ?,'account_binding',?,'review_required',?"
        " WHERE EXISTS (SELECT 1 FROM accounts WHERE account_id=?"
        " AND incarnation=?)"
        " ON CONFLICT(account_id, resource) DO UPDATE SET"
        " last_attempt_at=excluded.last_attempt_at,"
        " completeness='review_required', last_error=excluded.last_error",
        (account_id, _now(), note, account_id, incarnation))


def _row_id(entry) -> int:
    """Every Plan entry is a dict; `ingest` emits nothing else. A bare id is a
    contract violation and fails here rather than being silently absorbed."""
    if not isinstance(entry, dict):
        raise TypeError("Plan entries must be dicts carrying row_id, got "
                        f"{type(entry).__name__}")
    return int(entry["row_id"])


def upsert_account(conn, account: dict, session_id: str, secret: bytes):
    """Durable account_id from IBAN + currency; `uid` is only the current
    session's handle, so a renewal updates the row instead of forking a new
    account.

    Returns `(account_id, incarnation)` — the id AND the life token this
    upsert's own read or write established: the token it minted on the
    INSERT path, or the one read by the SAME initial SELECT that decides the
    rebind refusal on the UPDATE path, with the UPDATE itself conditioned on
    that token still being live. The pair is what a caller must fetch under.
    Capturing the token with a LATER read instead is the defect this return
    exists to prevent: a forget-and-relink between this call and that read
    would hand the caller the NEW life's token for pages it is about to
    fetch under the binding this call established for the OLD one, and
    every downstream incarnation guard would then pass.

    `account` is {"uid", "iban", "currency", "name", "aspsp"}. The IBAN comes
    from the provider payload's NESTED account_id.iban — the caller unwraps it.
    An empty IBAN is refused: deriving a key over "|EUR" would silently merge
    every account in the ledger into one.

    `aspsp` is what scopes the account's reference evidence in production.
    Without it flows.backfill has no name to pass to
    provenance.capability(), every lookup returns DEFAULT_CAPABILITY, and every
    production ingest falls back to heuristic windowed matching. An OMITTED
    aspsp on a later upsert keeps the recorded one: a renewal payload that
    happens not to carry the bank name must not disable reference identity for
    an account that already had it.

    `uid` DOES NOT get that treatment, and the asymmetry is worth stating
    because it is easy to read the COALESCE list below as covering everything.
    `name`, `product`, `currency`, `usage` and `aspsp` are COALESCEd —
    omitting them keeps the recorded value. `uid` and `session_id` are written
    unconditionally, so a payload that omits `uid` BLANKS the column. That is
    consistent with what `uid` is (the current session's handle, not durable
    account metadata) but it has a consequence on the rebinding backstop
    below: `moves_uid` requires the STORED `uid` to be truthy, so once it has
    been blanked the uid half of that check cannot fire on the next call, and
    only the session half is still guarding. Brief-literal and recorded as a
    known bound, not a repair this function makes.
    """
    iban = (account.get("iban") or "").strip()
    if not iban:
        raise ValueError(
            "upsert_account needs an IBAN; the provider nests it at "
            "account['account_id']['iban'] and the caller must unwrap it")
    # `.strip()` above removes only LEADING and TRAILING whitespace, so an IBAN
    # carrying whitespace or a control character INSIDE it survives into two
    # places at once: `store.account_id` keys the whole ledger on it, and
    # `iban_masked` below keeps the raw bytes whenever the value is short
    # enough to be stored unmasked.
    #
    # THE GUARD UPSTREAM BRANCHES ON A DERIVATIVE, which is why this one is
    # here rather than trusted to it: `flows._account_iban` normalises with
    # `.strip().upper()` before comparing against the whitelist, so the value
    # this function is handed is not the value the whitelist check approved.
    # Today that difference happens to be case only, because a whitelist entry
    # is whitespace-free by construction and an equality against it cannot pass
    # for a whitespace-bearing session IBAN — but that is a property of a
    # comparison two modules away, not of this function's own input, and it is
    # exactly the shape of reasoning this codebase has had to retract five
    # times. Refusing outright is cheap, is the fail-closed direction, and
    # rejects nothing a real provider emits.
    #
    # The value is never interpolated into the message.
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7f for ch in iban):
        raise ValueError(
            "upsert_account refuses an IBAN carrying whitespace or a control "
            "character: the ledger would be keyed on one form while the "
            "whitelist check approved another, and the masked copy stored on "
            "the account row would carry the raw provider bytes")
    aid = store.account_id(iban, account.get("currency") or "", secret)
    now = _now()
    masked = f"{iban[:4]}…{iban[-4:]}" if len(iban) > 8 else iban
    exists = conn.execute("SELECT uid, session_id, incarnation FROM accounts"
                          " WHERE account_id=?", (aid,)).fetchone()
    aspsp = (account.get("aspsp") or "").strip() or None   # None => keep/default
    if exists:
        # Refuse a rebinding that did not come through the renewal sequence.
        #
        # This is the BACKSTOP, not the renewal mechanism. A real renewal is
        # `flows.complete_renewal`: it proves the returned account set is
        # EXACTLY the bound set, backfills the new session to exhaustion, and
        # only then calls `switch_bindings`, which moves every account and
        # retires the old session in ONE transaction. Per-account
        # rebinding here could not honour either half of that -- it runs
        # before the deep fetch and it is one account at a time -- so the
        # renewal path deliberately does not come through this function at all,
        # and anything that does is rebinding without the evidence.
        #
        # Overwriting `uid`/`session_id` in place is what let a slow or
        # out-of-order callback move a live account onto a session nobody had
        # reviewed, with the old consent still open and no generation bump to
        # notice it. An account that carries no binding yet is not a
        # rebinding, and re-applying the SAME uid and session is idempotent.
        offered_uid = (account.get("uid") or "").strip()
        moves_uid = bool(offered_uid and exists["uid"]
                         and offered_uid != exists["uid"])
        moves_session = bool(session_id and exists["session_id"]
                             and session_id != exists["session_id"])
        if moves_uid or moves_session:
            what = " and ".join(
                [w for w, hit in (("the provider account handle", moves_uid),
                                  ("the consent it is bound to", moves_session))
                 if hit])
            note = (
                "REVIEW REQUIRED: something tried to move account %s onto %s "
                "without completing the renewal sequence. A renewal proves "
                "the bank returned exactly the accounts already linked, then "
                "backfills, then switches every binding at once. Nothing was "
                "changed. Re-run the authorization, or unlink this bank and "
                "link it again." % (aid, what))
            record_binding_review(conn, aid, note, exists["incarnation"])
            raise RebindRefused(note, aid)
        cur = conn.execute(
            "UPDATE accounts SET uid=?, session_id=?, last_seen=?,"
            " name=COALESCE(?, name), product=COALESCE(?, product),"
            " currency=COALESCE(?, currency), usage=COALESCE(?, usage),"
            " aspsp=COALESCE(?, aspsp)"
            # Conditioned on the life the SELECT above read, not on bare
            # existence: `account_id` is a deterministic HMAC, so a
            # forget-and-relink between that SELECT and this autocommit
            # UPDATE puts a NEW life under the same id — and an unconditioned
            # UPDATE would stamp the OLD flow's uid/session onto it. The
            # history fences downstream would still refuse every write made
            # under the stale token; this clause is what stops the new life
            # from durably carrying the old binding itself.
            " WHERE account_id=? AND incarnation=?",
            (account.get("uid"), session_id, now, account.get("name"),
             account.get("product"), account.get("currency"),
             account.get("usage"), aspsp, aid, exists["incarnation"]))
        if cur.rowcount != 1:
            # No durable note: the zero-row cause IS that this life is gone,
            # so `record_binding_review`'s own guard could never land one —
            # and writing it unguarded is the resurrection this fence exists
            # to prevent. The refusal alone is the honest outcome.
            raise RebindRefused(
                "the account changed identity while this link was binding "
                "it — it was erased, or erased and re-linked, underneath "
                "this authorization. Nothing was changed. Re-run the "
                "authorization if the account is still linked.", aid)
        return aid, exists["incarnation"]
    # `incarnation` is minted HERE, once per creation, because the
    # account_id above is a deterministic HMAC of IBAN+currency: erase
    # this account and link the same IBAN again and the id comes back
    # IDENTICAL. The random token is what tells the two lives apart --
    # provenance.record_observation refuses to file reference evidence
    # under an incarnation other than the one the measuring run captured
    # at its start, so a backfill paused across a forget-and-relink cannot
    # attach its stale measurements to the account's new life. A concurrent
    # relink between the SELECT above and this INSERT collides on the
    # primary key and raises — fail-closed, reported by the exchange as its
    # own failure rather than absorbed.
    incarnation = secrets.token_hex(8)
    conn.execute(
        "INSERT INTO accounts(account_id, uid, session_id, iban_masked,"
        " name, product, currency, usage, aspsp, incarnation, included,"
        " first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)",
        (aid, account.get("uid"), session_id, masked, account.get("name"),
         account.get("product"), account.get("currency"),
         account.get("usage"), aspsp or "", incarnation, now, now))
    return aid, incarnation


_ALLOC_CHUNK = 400          # well under SQLite's default parameter limit


def occurrence_allocations(conn, account_id: str, identity_keys) -> dict:
    """The DURABLE high-water occurrence per identity cluster.

    Returns {identity_key: next free occurrence} for the keys asked about.
    `ingest.reconcile` takes it as `allocated`, and without it rule 4 —
    "occurrence is never reused" — only holds within a single pass: a routine
    refresh loads roughly the last seven days, so a monthly standing order's
    earlier occurrences are not in `stored` and occurrence 0 is handed out a
    second time, colliding with UNIQUE (account_id, identity_key, occurrence).

    TWO sources, and both are load-bearing:

    * `occurrence_alloc`, written by `apply_plan` in the same transaction as
      the rows themselves. It is the ONLY record of a slot a re-keyed row
      VACATED — after a re-key no transactions row carries the old tuple, so a
      floor taken from the surviving rows would hand that slot straight back.
    * `MAX(occurrence) + 1` over the rows that are actually there, which is a
      floor the table can never sit below. A ledger repaired by hand, or one
      whose allocation row was somehow lost, still allocates safely.
    """
    keys = sorted({k for k in identity_keys if k})
    out: dict = {}
    for i in range(0, len(keys), _ALLOC_CHUNK):
        chunk = keys[i:i + _ALLOC_CHUNK]
        marks = ",".join("?" * len(chunk))
        for sql in (
            "SELECT identity_key, next_occurrence FROM occurrence_alloc"
            " WHERE account_id=? AND identity_key IN (%s)" % marks,
            "SELECT identity_key, MAX(occurrence) + 1 FROM transactions"
            " WHERE account_id=? AND identity_key IN (%s)"
            " GROUP BY identity_key" % marks,
        ):
            for key, nxt in conn.execute(sql, (account_id,) + tuple(chunk)):
                if nxt is not None and int(nxt) > out.get(key, 0):
                    out[key] = int(nxt)
    return out


def _raise_allocations(conn, account_id: str, high: dict, now: str) -> None:
    """Push the high-water marks this plan issued, monotonically.

    MAX() on conflict, so the mark only ever rises — a later pass that saw
    fewer rows can never lower it and free a tuple for reuse. Runs inside
    apply_plan's transaction, so allocation and rows commit together.
    """
    for ident, nxt in sorted(high.items()):
        conn.execute(
            "INSERT INTO occurrence_alloc(account_id, identity_key,"
            " next_occurrence, updated_at) VALUES (?,?,?,?)"
            " ON CONFLICT(account_id, identity_key) DO UPDATE SET"
            " next_occurrence=MAX(next_occurrence, excluded.next_occurrence),"
            " updated_at=excluded.updated_at",
            (account_id, ident, int(nxt), now))


RENEWAL_SESSION_STATUS = "AUTHORIZED"
#: The old consent the moment the switch commits: no longer the live session,
#: not yet known to be gone at the bank. `closed_at` stays NULL, so
#: `consent_status` still lists it and `unlink_bank` can still revoke it.
RETIRED_STATUS = "REVOKE_PENDING"
#: The provider refused, rate limited, or could not be reached. Same
#: visibility, and it says WHY the row is still there.
REVOKE_FAILED_STATUS = "REVOKE_FAILED"


def record_revocation(conn, session_id: str, *, revoked: bool) -> None:
    """Record what the PROVIDER said about the old consent.

    The only thing that ever sets `closed_at` on a renewed-away session, and it
    sets it only on `revoked=True`. `closed_at` is what hides a session from
    `consent_status` (`WHERE closed_at IS NULL`) and it is the operator's whole
    view of which consents exist, so writing it for a consent we did not
    actually revoke would leave a live AIS grant at the bank that nothing in
    this plugin can show or revoke for the remainder of its 179 days — a
    stranded consent, arrived at through the success path.

    `revoked=False` is therefore not a no-op and not a log line: it leaves the
    row visible and revocable and changes its status to `REVOKE_FAILED_STATUS`
    so the operator is told the difference between "retired" and "we could not
    reach the bank". A later protected `unlink_bank` resolves the same
    `consent_ref` and retries.

    Idempotent, and it never reopens a session someone else already closed.
    """
    if not session_id:
        return
    if revoked:
        conn.execute(
            "UPDATE sessions SET status='CLOSED', closed_at=?"
            " WHERE session_id=? AND closed_at IS NULL", (_now(), session_id))
    else:
        conn.execute(
            "UPDATE sessions SET status=? WHERE session_id=?"
            " AND closed_at IS NULL", (REVOKE_FAILED_STATUS, session_id))


def deep_fetch_complete(conn, account_id: str, session_id: str) -> bool:
    """Did THIS session run a transactions fetch to exhaustion for this account?

    The precondition on a renewal switch — a renewal must not close the old
    session until the new session's deep fetch is durably complete — asked as a
    question about the ledger rather than trusted from
    the caller's call order. `flows.backfill` writes both columns after
    `apply_plan` committed; a capped or failed run writes `partial` and carries
    the PREVIOUS session's stamp over, so it can never answer True.

    Deliberately not a coverage lookup. Coverage records the interval we
    PROVED, and for an account that returned no rows there is none — the bank
    may have been truncating rather than telling us the account is empty, and
    we cannot tell those apart. This asks the narrower question we can actually
    answer: did the retrieval complete? A dormant account answers True and
    renews normally; an interval we never really saw is still never claimed as
    proven.
    """
    row = conn.execute(
        "SELECT completeness, last_success_session FROM sync_state"
        " WHERE account_id=? AND resource='transactions'",
        (account_id,)).fetchone()
    return bool(row) and row["completeness"] == "complete" \
        and row["last_success_session"] == session_id


def switch_bindings(conn, bindings, new_session_id: str,
                    old_session_id: str, *, incarnations) -> dict:
    """Promote, switch, bump, retire — ONE transaction, and it runs LAST.

    `incarnations` is `{account_id: incarnation}`, captured by the SAME read
    that validated the renewal's exact account set, and re-checked here
    INSIDE the transaction before anything is written. The per-account
    UPDATE below was already fail-closed against an account erased or
    re-linked after the last backfill — its `(account_id, old_session_id)`
    key hits zero rows and the whole switch rolls back — but it failed as a
    generic ValueError, which the caller could only report as a broken
    renewal. The revalidation turns that into `AccountErased`, which
    `flows.complete_renewal` converts into the honest outcome: nothing
    switched, nothing retired, and the report names the erasure.

    `flows.complete_renewal` owns the ordering and calls this as its final
    step; nothing else calls it. It does four things and only together:

    1. **promote** the new session from `REVIEW_REQUIRED` to `AUTHORIZED`;
    2. move every account's `uid`/`session_id` onto it;
    3. set the new session's `generation` to the old one's plus one;
    4. retire the old session locally and VISIBLY: `RETIRED_STATUS`, with
       `closed_at` left NULL until the provider confirms the revocation.

    The renewed session is inserted QUARANTINED when the callback lands and is
    promoted here, not before. An interrupted renewal therefore defaults to
    "needs your attention" and stays visible and revocable, instead of leaving
    two `AUTHORIZED` consents for one bank with nothing to say which is live.
    Because the promotion shares this transaction with the switch, there is no
    window in which the ledger disagrees with itself about which is current.

    `bindings` is `[(account_id, uid)]`, already checked by the caller to be
    exactly the set bound to `old_session_id`: an exact `account_id` match
    carries labels and history forward, and anything else stops for operator
    review.

    **The deep-fetch precondition is enforced here, on evidence.** A renewal
    must not close the old session until the new session's deep fetch is
    durably complete, and `deep_fetch_complete` asks the ledger whether THIS
    session ran a fetch to exhaustion for each account, which `flows.backfill`
    stamps only after `apply_plan` committed and a capped or failed run never
    stamps. Checking the ledger rather than trusting the caller to have run the
    steps in order is the difference between an invariant and a comment — and
    "the mechanism exists, the caller does not use it" is the defect class this
    design has produced three times.

    A half-switched ledger is never reachable: the per-account update is
    re-checked against `old_session_id` inside the transaction, so a read
    overtaken between check and write fails the whole thing.

    Labels, `included`, categories, coverage and transactions are untouched and
    cannot be — they key on `account_id`, which does not move. That is the
    whole reason the exact-match test is the right test.

    The old session is retired LOCALLY, and deliberately NOT hidden: no HTTP
    call may run inside this transaction — it could fail after the switch and
    leave the ledger and the bank disagreeing — so at COMMIT the old consent is
    still live at the bank. `closed_at` is what removes a session from
    `consent_status`, so setting it here would hide a live AIS grant, and a
    crash before the provider call would hide it for the rest of its 179 days.
    Instead the row goes to `RETIRED_STATUS`: not `AUTHORIZED`, so
    `_renewable_session` can never pick it; `closed_at` NULL, so it is still
    listed and still revocable by its `consent_ref`. `flows.complete_renewal` calls
    `ais.delete_session` next and reports the answer to `record_revocation`,
    the only thing that closes a renewed-away session.
    """
    pairs = [(str(a), b) for a, b in bindings]
    if not pairs:
        raise ValueError("a renewal that binds nothing is not a renewal")
    if not new_session_id or new_session_id == old_session_id:
        raise ValueError("a renewal switches onto a DIFFERENT session")
    # Erasure is asked about FIRST, because the unfetched check below reads
    # sync_state — which `forget_local_account` deletes — so an account
    # erased after its fetch completed would otherwise surface as a generic
    # "has not completed a history fetch" refusal and a review note about an
    # account that no longer exists. This read is best-effort (no lock yet);
    # the re-check inside the transaction below is the authoritative one.
    for account_id, _uid in pairs:
        if conn.execute("SELECT 1 FROM accounts WHERE account_id=?"
                        " AND incarnation=?",
                        (account_id,
                         incarnations.get(account_id))).fetchone() is None:
            raise AccountErased(
                "account %s was erased (or erased and re-linked) after the "
                "renewal's fetch completed; nothing was switched and the "
                "existing consent is still the live one" % account_id,
                account_id)
    unfetched = sorted(a for a, _ in pairs
                       if not deep_fetch_complete(conn, a, new_session_id))
    if unfetched:
        note = ("REVIEW REQUIRED: the renewed consent has not completed a "
                "history fetch for %d of the %d account(s) it would take over, "
                "so nothing was switched and the existing consent is still the "
                "live one. A renewal must not retire the old consent until the "
                "new one's deep fetch is complete. Run the authorization "
                "again." % (len(unfetched), len(pairs)))
        for account_id in unfetched:
            record_binding_review(conn, account_id, note,
                                  incarnations.get(account_id))
        raise RebindRefused(note, unfetched[0])

    now = _now()
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Under the write lock, before anything is written: is every account
        # still living the life the renewal validated? The per-account UPDATE
        # below already fails closed on a moved binding, but "erased under
        # the renewal" deserves its own name — the caller converts it into a
        # report, not a crash.
        for account_id, _uid in pairs:
            live = conn.execute(
                "SELECT 1 FROM accounts WHERE account_id=? AND incarnation=?",
                (account_id, incarnations.get(account_id))).fetchone()
            if live is None:
                raise AccountErased(
                    "account %s was erased (or erased and re-linked) after "
                    "the renewal's fetch completed; nothing was switched and "
                    "the existing consent is still the live one" % account_id,
                    account_id)
        if conn.execute("SELECT 1 FROM sessions WHERE session_id=?",
                        (new_session_id,)).fetchone() is None:
            raise ValueError("the renewed session has no row yet; record it "
                             "before switching any binding onto it")
        old = conn.execute("SELECT generation FROM sessions WHERE session_id=?",
                           (old_session_id,)).fetchone()
        generation = int((old["generation"] if old else 0) or 0) + 1
        conn.execute("UPDATE sessions SET status=?, generation=?"
                     " WHERE session_id=?",
                     (RENEWAL_SESSION_STATUS, generation, new_session_id))
        for account_id, uid in pairs:
            cur = conn.execute(
                "UPDATE accounts SET uid=?, session_id=?, last_seen=?"
                " WHERE account_id=? AND session_id=?",
                (uid, new_session_id, now, account_id, old_session_id))
            if cur.rowcount != 1:
                raise ValueError(
                    "account %s is not bound to the session being renewed; "
                    "nothing was switched" % account_id)
        conn.execute("UPDATE sessions SET status=?"
                     " WHERE session_id=? AND closed_at IS NULL",
                     (RETIRED_STATUS, old_session_id))
        # A completed renewal answers any binding review this bank was carrying;
        # leaving it behind reports a resolved problem for ever, which teaches
        # the operator to ignore the report.
        marks = ",".join("?" * len(pairs))
        conn.execute(
            "DELETE FROM sync_state WHERE resource='account_binding'"
            " AND account_id IN (%s)" % marks, tuple(a for a, _ in pairs))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return {"accounts": len(pairs), "generation": generation, "retired": True}


def _remember_ref(conn, row_id: int, rec: dict, now: str) -> None:
    """Identifiers are APPENDED, never overwritten.

    `Plan` has exactly four fields and cannot carry reference history, so this
    is apply's job. A reference already recorded for this row is touched
    (last_seen) rather than duplicated; a reference that CHANGED lands as an
    additional row, so the transaction keeps its current reference on
    `transactions.provider_ref` and its whole history in `transaction_refs`.
    """
    if not rec.get("provider_ref"):
        return
    conn.execute(
        "INSERT OR IGNORE INTO transaction_refs(row_id, provider_ref,"
        " provider_ref_kind, first_seen, last_seen) VALUES (?,?,?,?,?)",
        (row_id, rec["provider_ref"], rec.get("provider_ref_kind"), now, now))
    conn.execute("UPDATE transaction_refs SET last_seen=? WHERE row_id=?"
                 " AND provider_ref=?", (now, row_id, rec["provider_ref"]))


def apply_plan(conn, account_id: str, plan, pre_apply=None) -> dict:
    """One transaction: either the whole plan lands or none of it does.

    Inserts run first and their `local_id -> row_id` map is what a supersede
    resolves through — a pending row is superseded by a booked row that this
    same plan is inserting, and only the database knows its id.

    `pre_apply`, when given, is called with the connection immediately after
    `BEGIN IMMEDIATE` — inside the transaction, before any plan row is
    written — and may return a REPLACEMENT plan (or None to keep this one).
    It exists for exactly one caller: `flows.backfill` files the run's
    reference-trust evidence there and revalidates the trust the plan was
    built under, now that the write lock is held. A plan is built OUTSIDE any
    transaction, so a concurrent run can demote an account's reference trust
    between the build and this apply; the hook re-derives under the lock and
    hands back a heuristically-matched replan when the premise no longer
    holds — `ingest.reconcile` is pure, so replanning here is a function
    call, not I/O. An exception from the hook rolls the whole transaction
    back, evidence included, exactly like a failure in the plan itself.
    """
    now = _now()
    stats = {"inserted": 0, "updated": 0, "superseded": 0,
             "tombstoned": 0, "flagged": 0,
             "inserted_row_ids": [], "auto_tagged": 0,
             "needs_classification": 0, "rules": {},
             "rule_skipped_overcap": 0}
    local_ids = {}
    high: dict = {}          # identity_key -> next free occurrence, this plan

    def issued(identity_key, occurrence):
        """Every occurrence this plan hands out raises the durable mark."""
        if identity_key is None or occurrence is None:
            return
        nxt = int(occurrence) + 1
        if nxt > high.get(identity_key, 0):
            high[identity_key] = nxt

    conn.execute("BEGIN IMMEDIATE")
    try:
        if pre_apply is not None:
            replacement = pre_apply(conn)
            if replacement is not None:
                plan = replacement
        for rec in plan.inserts:
            cur = conn.execute(
                "INSERT INTO transactions(account_id, provider_ref,"
                " provider_ref_kind, match_method, match_confidence,"
                # `ingest` emits `reason` on inserts[] too, not only on
                # flags[]/tombstones[]. Dropping it here would leave a
                # needs_review=1 row with no stated cause, which is exactly
                # what review_reason exists to prevent: a reader that says "N
                # rows need review" has to be able to say why.
                " needs_review, review_reason, identity_key, occurrence,"
                " booking_date,"
                " value_date, amount_minor, currency, direction, status,"
                " counterparty, remittance, raw_json, first_seen, last_seen,"
                " state) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (account_id, rec.get("provider_ref"), rec.get("provider_ref_kind"),
                 rec.get("match_method"), rec.get("match_confidence"),
                 1 if rec.get("needs_review") else 0, rec.get("reason"),
                 rec["identity_key"],
                 rec["occurrence"], rec.get("booking_date"), rec.get("value_date"),
                 rec["amount_minor"], rec["currency"], rec["direction"],
                 rec.get("status"), rec.get("counterparty"),
                 rec.get("remittance"), rec.get("raw_json"), now, now,
                 rec.get("state") or "active"))
            if rec.get("local_id") is not None:
                local_ids[rec["local_id"]] = cur.lastrowid
            stats["inserted_row_ids"].append(cur.lastrowid)
            _remember_ref(conn, cur.lastrowid, rec, now)
            issued(rec["identity_key"], rec["occurrence"])
            stats["inserted"] += 1

        for rec in plan.updates:
            row_id = _row_id(rec)
            op = rec.get("op")
            if op == "supersede":
                local = rec.get("superseded_by_local")
                if local not in local_ids:
                    # Internally inconsistent plan. Writing state='superseded'
                    # with a dangling pointer would lose the row from every
                    # active view while naming nothing as its replacement.
                    raise ValueError(
                        f"supersede of row {row_id} points at {local!r}, which "
                        "this plan does not insert — the plan is inconsistent")
                cur = conn.execute(
                    # `needs_review` is MONOTONIC here for the same reason it
                    # is on the op="update" statement below: a pending
                    # row superseded by its booked twin used to come back
                    # needs_review=0 with its `review_reason` still set --
                    # internally inconsistent, and invisible, because every
                    # reader counts needs_review=1.
                    "UPDATE transactions SET state=?, state_reason=?,"
                    " superseded_by=?, match_method=?, match_confidence=?,"
                    " needs_review=MAX(needs_review, ?), last_seen=? WHERE row_id=?"
                    # Scoped to the account this plan is FOR. row_id alone
                    # is a global primary key, so a plan applied under one
                    # account naming another account's row_id -- a stale
                    # caller, or two callers racing on the same row_id space
                    # -- would otherwise silently rewrite a different
                    # account's ledger.
                    " AND account_id=?",
                    (rec.get("state") or "superseded", rec.get("reason"),
                     local_ids[local], rec.get("match_method"),
                     rec.get("match_confidence"),
                     1 if rec.get("needs_review") else 0, now, row_id,
                     account_id))
                # The count attests to a WRITE, not to a plan entry. A row_id that no longer exists (deleted by
                # purge_before or forget_local_account between the caller
                # loading `stored` and this plan landing) affects zero rows;
                # counting it anyway would tell flows.backfill a supersession
                # happened when nothing did. Silently skipping is the chosen
                # reading -- see the module docstring's "honest counts" note
                # -- not a raise, because a plan racing a legitimate deletion is
                # recoverable and losing a whole backfill over one vanished row
                # would not be. A row_id belonging to a DIFFERENT account
                # affects zero rows for the same reason -- the AND
                # account_id=? above -- and is counted, or rather not counted,
                # identically: the two cases are indistinguishable from here
                # and do not need to be told apart.
                if cur.rowcount:
                    # Annotations follow the replacement. Plain UPDATE, no
                    # collision handling: the new row was inserted by THIS
                    # uncommitted transaction, so no other writer can have
                    # annotated it yet. Gated on rowcount because a skipped
                    # supersede (row already deleted, or another account's
                    # row_id) superseded nothing — moving annotations for it
                    # would attach them to an unrelated fresh insert. OR IGNORE
                    # + sweep, NOT a plain UPDATE: reconciliation is one-to-one
                    # today, but apply_plan structurally accepts a FAN-IN plan
                    # — two supersedes naming the same replacement — and when
                    # the two source rows share a tag a plain UPDATE raises
                    # UNIQUE(row_id, tag) and rolls back the whole plan. The
                    # "fresh destination" assumption holds against OTHER
                    # writers (the row is uncommitted); it does not hold
                    # against annotations THIS transaction already migrated
                    # there. Notes have no unique constraint, so the plain
                    # UPDATE stands.
                    conn.execute(
                        "UPDATE OR IGNORE transaction_tags SET row_id=?"
                        " WHERE row_id=?", (local_ids[local], row_id))
                    conn.execute(
                        "DELETE FROM transaction_tags WHERE row_id=?",
                        (row_id,))
                    conn.execute(
                        "UPDATE transaction_notes SET row_id=? WHERE row_id=?",
                        (local_ids[local], row_id))
                    stats["superseded"] += 1
                continue
            if op != "update":
                raise ValueError("update entries must carry op='update' or "
                                 f"op='supersede', got {op!r}")
            # The identity invariant: identity_key and occurrence are written
            # HERE, in the same statement as the content they hash -- together
            # or not at all. Omitting them (the previous round) left rows whose
            # stored identity disagreed with their own content, so a later
            # reference-less fetch found no cluster, inserted a duplicate and
            # tombstoned the original. A collision on UNIQUE (account_id,
            # identity_key, occurrence) raises here and rolls the whole plan
            # back; there is deliberately no retry that picks a different
            # occurrence, because reconcile already allocated above the new
            # cluster's maximum and a collision means the plan was built
            # against stale rows.
            if not rec.get("identity_key") or rec.get("occurrence") is None:
                raise ValueError(
                    f"update of row {row_id} carries no identity_key/occurrence; "
                    "reconcile must supply both so identity and content stay "
                    "consistent")
            cur = conn.execute(
                "UPDATE transactions SET identity_key=?, occurrence=?,"
                " booking_date=?, value_date=?,"
                # identity_key hashes `currency` and `direction` too
                # (ingest.identity_key), but a fixed "mutable fields" list --
                # the exact shape of ingest._MUTABLE -- omits both. Writing
                # identity_key/occurrence without also writing these two would
                # store a row whose stated identity does not hash its own
                # stored content the moment either one changes (a DBIT->CRDT
                # flip or a currency correction, both of which ingest.py's
                # _money_change exists to detect and flag).
                #
                # The SET list below is a hand-written literal SQL column list
                # -- it is NOT derived from the record at runtime. What makes
                # it correct is that it is every field ingest.identity_key
                # hashes EXCEPT account_id, which is deliberately excluded (an
                # op="update" record carries account_id from the FETCHED row
                # via dict(f, ...), not the stored row being updated, so
                # writing it would silently re-home the transaction) and is
                # provably invariant here regardless -- ingest.normalise stamps
                # every row's account_id from the caller's own parameter and
                # reconcile never mixes accounts within one Plan -- so there is
                # no seventh hashed field left dangling.
                " amount_minor=?, currency=?, direction=?, status=?,"
                " counterparty=?, remittance=?,"
                " provider_ref=?, provider_ref_kind=?, match_method=?,"
                # needs_review is MONOTONIC and its cause is STICKY,
                # and this is a fix, not a stylistic choice. `needs_review=?`
                # wrote THIS pass's assessment over the stored one, so an
                # ordinary refresh in which the bank merely corrected a
                # remittance string silently un-flagged a row an earlier pass
                # had flagged for provider_ref_reuse -- `Disclosure: 1 flagged
                # for review` became `none flagged for review` with nothing
                # reviewed. Every field in ingest._MUTABLE does it
                # (status PDNG->BOOK, counterparty, remittance, booking_date,
                # value_date, amount_minor, provider_ref), and a routine
                # refresh asks for `last booked date - 7 days`, which is
                # precisely the window banks amend.
                #
                # The contract was already written down -- ingest.Plan's
                # docstring says "needs_review = needs_review OR 1, never an
                # assignment" -- but that argues it WITHIN ONE PLAN, and the
                # property that matters is the flag surviving ACROSS PASSES.
                # Resting the guarantee on the order records appear in one plan
                # is a guard on a derivative rather than on the value: what the
                # ledger already says about this row.
                #
                # COALESCE, not a plain write, because preserving the flag
                # alone would leave a row flagged with NO stated cause the
                # moment a later clean pass carried `reason=None` -- which is
                # exactly what the comment on the insert statement above says
                # `review_reason` exists to prevent. A newer pass that HAS a
                # cause still overwrites: the newest finding is the one worth
                # naming.
                #
                # NOTHING MAY CLEAR needs_review, verified by grep over the
                # tree: these two statements are the only writers of a non-1
                # value, and the manifest declares no tool that could mark a
                # row reviewed. A feature that adds one MUST clear the column
                # with its own explicit statement -- it cannot rely
                # on an ingest update doing it, and it should not make these
                # two assignments again to get it.
                " match_confidence=?, needs_review=MAX(needs_review, ?),"
                " review_reason=COALESCE(?, review_reason),"
                # The SAME gap as inserts -- ingest also emits `reason`
                # on op="update" records and it was going straight to the
                # floor.
                " raw_json=?, last_seen=?"
                # Scoped to the account this plan is FOR, same reasoning as
                # the supersede statement above.
                " WHERE row_id=? AND account_id=?",
                (rec["identity_key"], int(rec["occurrence"]),
                 rec.get("booking_date"), rec.get("value_date"),
                 rec["amount_minor"], rec["currency"], rec["direction"],
                 rec.get("status"), rec.get("counterparty"),
                 rec.get("remittance"), rec.get("provider_ref"),
                 rec.get("provider_ref_kind"), rec.get("match_method"),
                 rec.get("match_confidence"),
                 1 if rec.get("needs_review") else 0, rec.get("reason"),
                 rec.get("raw_json"), now,
                 row_id, account_id))
            # As with supersede above, a row_id this plan was built against but
            # that no longer exists affects zero rows. Recording a reference,
            # raising the durable occurrence_alloc high-water, and counting
            # "updated" all describe a WRITE that took the identity/occurrence
            # this update would have issued -- none of that happened, so none
            # of it is recorded. Silent skip, not a raise: see the module
            # docstring's "honest counts" note.
            if cur.rowcount:
                _remember_ref(conn, row_id, rec, now)
                # A re-key ARRIVES in a new cluster and DEPARTS an old one.
                # Only the arrival needs recording here: the departed
                # cluster's mark was raised when the row was first allocated
                # there and never falls, so the vacated tuple stays spent for
                # good.
                issued(rec["identity_key"], rec["occurrence"])
                stats["updated"] += 1

        for entry in plan.tombstones:
            # Why a row is gone is part of the record: a tombstone with no
            # stated cause is indistinguishable from one we can no longer
            # explain.
            cur = conn.execute(
                "UPDATE transactions SET state=?, state_reason=?,"
                # Scoped to this plan's account, same reasoning as the
                # update/supersede statements above.
                " last_seen=? WHERE row_id=? AND account_id=?",
                (entry.get("state") or "vanished", entry.get("reason"),
                 now, _row_id(entry), account_id))
            # A tombstone for a row that is no longer there marks nothing
            # gone, and neither does one naming another account's row_id;
            # count only what was actually written.
            if cur.rowcount:
                stats["tombstoned"] += 1

        for entry in plan.flags:
            # needs_review and its reason, and nothing else — not even
            # last_seen. A flag is a disclosure ABOUT a row, not a change to
            # it. review_reason is separate from state_reason so that a row
            # which is flagged and later vanishes keeps both causes.
            #
            # Flags are ADDITIVE and must never clear needs_review, so a row
            # that carries both an op="update" with needs_review=False and a
            # flags entry in the SAME plan ends up needs_review=1 regardless of
            # which order ingest listed them in.
            #
            # CORRECTED: this comment used to justify that guarantee
            # with "flags is the LAST thing applied in this loop, after
            # updates". That was an argument about ORDERING WITHIN ONE PLAN,
            # and it was the whole defence -- so it said nothing at all about
            # the case that actually occurs in production, an update in a
            # LATER plan overwriting a flag an earlier one set. It did not,
            # and a routine refresh silently un-flagged rows on every pass.
            # The guarantee now rests on the two statements above being
            # MONOTONIC in this column rather than on the order this loop
            # happens to run in; the ordering is no longer load-bearing.
            # The claim here is deliberately the narrow true one.
            #
            # Pinned by, in tests/test_apply.py:
            #   TestReviewReasonAndIdentityIntegrity
            #     .test_a_flag_in_the_same_plan_survives_an_update_that_clears_review
            #   TestReviewFlagsSurviveLaterPasses (the cross-pass case)
            cur = conn.execute(
                "UPDATE transactions SET needs_review=1,"
                # Scoped to this plan's account, same reasoning as the other
                # three statements above.
                " review_reason=? WHERE row_id=? AND account_id=?",
                (entry.get("reason"), _row_id(entry), account_id))
            # A flag against a row that is gone flags nothing, and neither
            # does one naming another account's row_id; count only what was
            # actually written.
            if cur.rowcount:
                stats["flagged"] += 1

        # Deterministic rule pass over exactly this plan's inserts, inside the
        # same transaction: every ingest entry point applies rules atomically
        # with the rows themselves; a crash cannot produce
        # committed-but-unruled rows. After the updates loop, so
        # supersede-migrated tags are visible to the 32-cap union; auto_tagged
        # is FINAL tag state, not rules-changed-this- call — a booked insert
        # that inherited migrated tags counts.
        rule_out = rules.apply_to_rows(conn, stats["inserted_row_ids"], now)
        stats["rules"] = rule_out["per_rule"]
        stats["rule_skipped_overcap"] = len(rule_out["skipped_overcap"])
        for rid in stats["inserted_row_ids"]:
            tags = [t[0] for t in conn.execute(
                "SELECT tag FROM transaction_tags WHERE row_id=?", (rid,))]
            # auto_tagged means ≥1 non-workflow tag — NOT classification_state,
            # whose precedence lets a migrated awaiting-operator marker hide a
            # content tag. needs_classification is the final-state workable
            # count, NOT new-minus-tagged: a parked/terminal insert is neither
            # bucket, so the sync trailer can never contradict the queue line.
            if any(t not in rules.WORKFLOW_TAGS for t in tags):
                stats["auto_tagged"] += 1
            if rules.classification_state(tags) == "workable":
                stats["needs_classification"] += 1

        # In the SAME transaction as the rows: an allocation that commits
        # separately can be lost by a rollback and reissued, which is the
        # collision this table exists to prevent.
        _raise_allocations(conn, account_id, high, now)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return stats


def record_coverage(conn, account_id: str, start: str, end: str,
                    session_id: str, *, incarnation) -> bool:
    """Record a PROVEN interval, merged on write. Returns whether it did.

    Only ever called after apply_plan committed: coverage attests to what is
    durably in the ledger, never to what an HTTP call returned. Every stored
    interval that overlaps or abuts the new one is absorbed, so the table
    stays a disjoint set and a direct reader sees merged intervals too. The
    surviving row carries the newest session_id — the session that just
    proved the widened interval.

    `incarnation` is required: this runs in its OWN transaction, after
    apply_plan's committed, so `forget_local_account` can land between the
    two — and coverage written then would attest to rows the erasure just
    deleted, for an account that may already be living a new life under the
    same deterministic id. The token is re-checked under this transaction's
    write lock; a mismatch writes nothing and returns False, which the
    caller must convert into its erased report rather than a success.
    """
    if not (start < end):
        raise ValueError(f"empty coverage interval [{start}, {end})")
    conn.execute("BEGIN IMMEDIATE")
    try:
        live = conn.execute("SELECT 1 FROM accounts WHERE account_id=?"
                            " AND incarnation=?",
                            (account_id, incarnation)).fetchone()
        if live is None:
            conn.execute("ROLLBACK")
            return False
        touching = [(r["interval_start"], r["interval_end"]) for r in conn.execute(
            "SELECT interval_start, interval_end FROM coverage"
            " WHERE account_id=? AND complete=1 AND interval_start <= ?"
            " AND interval_end >= ?", (account_id, end, start))]
        lo, hi = start, end
        for c_start, c_end in touching:
            lo, hi = min(lo, c_start), max(hi, c_end)
            conn.execute("DELETE FROM coverage WHERE account_id=?"
                         " AND interval_start=? AND interval_end=?",
                         (account_id, c_start, c_end))
        conn.execute(
            "INSERT OR REPLACE INTO coverage(account_id, interval_start,"
            " interval_end, fetched_at, session_id, complete)"
            " VALUES (?,?,?,?,?,1)", (account_id, lo, hi, _now(), session_id))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return True


def merged_coverage(conn, account_id: str) -> list:
    """Read the proven intervals. They are already disjoint and ordered —
    record_coverage merged them on the way in."""
    return [(r["interval_start"], r["interval_end"]) for r in conn.execute(
        "SELECT interval_start, interval_end FROM coverage WHERE account_id=?"
        " AND complete=1 ORDER BY interval_start, interval_end", (account_id,))]


def holes(conn, account_id: str, start: str, end: str) -> list:
    """Gaps between proven intervals inside [start, end). What every tool must
    disclose alongside an answer whose range touches one."""
    gaps, cursor = [], start
    for c_start, c_end in merged_coverage(conn, account_id):
        if c_end <= cursor or c_start >= end:
            continue
        if c_start > cursor:
            gaps.append((cursor, min(c_start, end)))
        cursor = max(cursor, c_end)
        if cursor >= end:
            break
    if cursor < end:
        gaps.append((cursor, end))
    return gaps


def purge_before(conn, cutoff: str, account_id=None) -> dict:
    """Erase everything before `cutoff` AND make coverage tell the truth.

    The `purge` tool is the caller; the operation lives here because it
    touches the same three tables apply_plan and record_coverage own.

    The defect this exists to prevent: deleting transactions before a cutoff
    while leaving a [2020-01-01, 2026-01-01) coverage interval intact makes
    every later tool report 2020-2024 as PROVEN -- the strongest claim this
    system makes -- for rows the operator deliberately erased. Coverage that
    outlives its rows is worse than no coverage: it is a confident lie, and
    the gap disclosure has no way to notice.

    So: rows go, their reference history goes with them, intervals wholly
    before the cutoff are dropped, and intervals that SPAN it are trimmed to
    start at it. One transaction, so there is no window in which coverage and
    rows disagree.

    `account_id=None` means every account. Returns counts.
    """
    if not cutoff:
        raise ValueError("purge_before needs a cutoff date")
    scope = () if account_id is None else (account_id,)
    where = "" if account_id is None else " AND account_id=?"
    stats = {"transactions": 0, "refs": 0,
             "coverage_dropped": 0, "coverage_trimmed": 0}
    conn.execute("BEGIN IMMEDIATE")
    try:
        doomed = [r[0] for r in conn.execute(
            "SELECT row_id FROM transactions WHERE booking_date < ?" + where,
            (cutoff,) + scope)]
        for row_id in doomed:
            cur = conn.execute(
                "DELETE FROM transaction_refs WHERE row_id=?", (row_id,))
            stats["refs"] += cur.rowcount if cur.rowcount > 0 else 0
        if doomed:
            marks = ",".join("?" * len(doomed))
            # Annotations die with their rows, same as refs: a tag left
            # behind would corrupt every list_tags count from then on, and
            # an orphaned note is erased history the operator asked purged.
            conn.execute("DELETE FROM transaction_tags WHERE row_id IN (%s)"
                         % marks, doomed)
            conn.execute("DELETE FROM transaction_notes WHERE row_id IN (%s)"
                         % marks, doomed)
            conn.execute(
                "DELETE FROM transactions WHERE row_id IN (%s)" % marks, doomed)
            stats["transactions"] = len(doomed)

        # Coverage is rewritten wholesale rather than UPDATEd in place.
        # Trimming changes interval_start, which is part of coverage's primary
        # key; record_coverage merges on write, so today no two rows can end up
        # trimmed onto the same start and an in-place UPDATE would in fact be
        # safe. Rewriting the surviving set costs nothing, does not depend on
        # that invariant continuing to hold, and cannot half-apply.
        # Trimming preserves disjointness, so no re-merge is needed.
        rows = [tuple(r) for r in conn.execute(
            "SELECT account_id, interval_start, interval_end, fetched_at,"
            " session_id, complete FROM coverage WHERE 1=1" + where, scope)]
        keep = []
        for acc, c_start, c_end, fetched_at, session_id, complete in rows:
            if c_end <= cutoff:
                stats["coverage_dropped"] += 1          # nothing left to attest
                continue
            if c_start < cutoff:
                c_start = cutoff                        # trim the spanning part
                stats["coverage_trimmed"] += 1
            keep.append((acc, c_start, c_end, fetched_at, session_id, complete))
        if rows:
            conn.execute("DELETE FROM coverage WHERE 1=1" + where, scope)
            conn.executemany(
                "INSERT INTO coverage(account_id, interval_start, interval_end,"
                " fetched_at, session_id, complete) VALUES (?,?,?,?,?,?)", keep)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return stats
