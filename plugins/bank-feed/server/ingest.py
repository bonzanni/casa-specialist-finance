# plugins/bank-feed/server/ingest.py
"""Transaction identity and reconciliation. Pure: no I/O.

The rules, in order:
  0. account_id is the durable key (assigned by the caller). Enable Banking's
     `uid` is a session-scoped handle and is NEVER a durable key: a renewal
     mints new uids for the same real accounts.
  1. provider reference IS identity where present — corroborated, never blind,
     and only for an ASPSP *observed* to supply stable references, within the
     scope in which they were observed unique. `capability` carries that
     observation; "global is never assumed", so an unobserved ASPSP falls
     straight through to rule 2.
  2. reference-less rows use windowed nearest-date matching, not multisets.
  3. deficits tombstone only well inside a proven interval.
  4. occurrence is monotonic per (account_id, identity_key) and never reused —
     allocated above every occurrence ever issued INCLUDING tombstoned rows
     and INCLUDING occurrences no longer visible in this pass, which is why
     `reconcile` takes the durable `allocated` high-water map.
  5. matching is deterministic and every heuristic decision is recorded.

Plan shape (consumed by `apply.apply_plan`):
  inserts    [dict]  new rows; each carries `local_id`, `identity_key`,
                     `occurrence`, `match_method`, `match_confidence`,
                     `needs_review`, `reason` (None unless needs_review).
                     No `row_id` — the database assigns it.
  updates    [dict]  changes to stored rows, discriminated by `op`:
                       op="update"    -> write the carried fields onto row_id,
                                         INCLUDING `identity_key` and
                                         `occurrence`, which move together or
                                         not at all (see emit_match)
                       op="supersede" -> set state='superseded' on row_id and
                                         point superseded_by at the row inserted
                                         for `superseded_by_local`
                     both carry `needs_review` and `reason` (None unless
                     needs_review). apply MUST insert first, remember
                     local_id -> row_id, then resolve `superseded_by_local`.
  tombstones [dict]  {"row_id", "state": "vanished", "reason"}
  flags      [dict]  {"row_id", "reason"} — flag needs_review, change nothing else

FLAGS ARE ADDITIVE AND NEVER CLEAR `needs_review`. This is a CONTRACT, not an
implementation detail apply may reorder around. One `row_id`
can legitimately receive BOTH an `op="update"` carrying `needs_review=False,
reason=None` and a `flags` entry carrying a reason, in the same Plan: the
update is what rule 2 decided about that row's content, the flag is what rule 1
observed about its reference, and the two are independent findings. `apply` MUST
therefore treat `flags` as a set-only operation — `needs_review = needs_review
OR 1`, never an assignment — so the outcome does not depend on whether `flags`
happen to be applied before or after `updates`. Writing `needs_review=0` from an
update over a flag from the same Plan silently discards a review the module
asked for. Pinning insert-before-supersede alone is not enough: it leaves the
guarantee resting on whatever order apply happens to choose.

Reason vocabulary this module emits -- every path that sets needs_review=1
carries one of these, so apply can persist it into review_reason/state_reason
and the read tools can report the breakdown by name:
  provider_ref_reuse        -- a fetched row claimed a trusted reference that
                               did not corroborate; carried on the flag
                               against the stored row AND on whatever this
                               module's Plan record the claiming fetched row
                               eventually lands in (an insert, or a later
                               content-based match).
  reference_shared_in_fetch -- two or more DISTINCT fetched contents shared
                               one trusted reference and BOTH corroborated the
                               same stored row; one was kept deterministically
                               (never silently picked) and flagged.
  unresolved_cluster        -- a stored row inside an oversized cluster that
                               MAX_EXACT_CLUSTER's greedy fallback could not
                               carry.
  windowed_ambiguous        -- an update or insert produced by that same
                               greedy fallback rather than exact matching.
  absent_from_a_proven_interval -- rule 3's tombstone reason.
  amount_changed            -- a reference match rewrote `amount_minor` with
                               `currency` and `direction` unchanged. In practice
                               this is the corroborated arm (conf 0.7, the
                               counterparty arm), because the conf-1.0 arm fires
                               only when the magnitude already matches: the only
                               evidence the two rows are one transaction is then
                               a counterparty name plus <= 3 days, and a money
                               field moved on it.
  content_present_elsewhere -- "the matcher did something else with content
                               identical to this row". TWO producers, and a
                               reader must label both from this one reason --
                               they are told apart by WHERE the reason arrives:
                                 (a) rule 1 re-keyed a stored row while that
                                     row's EXACT content was sitting in the same
                                     fetch (the pairing stands -- see the reason
                                     ladder in rule 1 -- but the rewrite is not
                                     silent). Arrives as the `reason` on an
                                     op="update" record.
                                 (b) rule 3 SPARED a row from a tombstone
                                     because its exact content was in the fetch.
                                     The ledger may then hold TWO rows with the
                                     same content. Arrives as a `flags` entry
                                     and nothing else.
                               In (b) there need not be any insert: the twin can
                               equally have been consumed as an update to a
                               DIFFERENT stored row, in which case the two
                               same-content rows are both stored rows. (Two
                               stored rows with identical content two days apart
                               and one fetched row between them produce exactly
                               that: no insert, one windowed update, and this
                               flag on the row that lost.) The split
                               between the two producers is a property of the
                               data, not of the code -- a corpus can be almost
                               entirely one or almost entirely the other -- so
                               do not size either from a sample.
  direction_or_currency_changed -- a reference match rewrote `direction` or
                               `currency`: the magnitude matched, so
                               corroboration scored it 1.0, but a DBIT->CRDT
                               flip is a double-magnitude swing in every total
                               and a currency change makes the stored integer
                               mean a different unit. Ranked ABOVE
                               amount_changed: rarer, more alarming, and must
                               not be hidden inside the common bucket.

CAVEAT FOR ANY BREAKDOWN BY REASON. The money check sits THIRD in rule 1's
reason ladder, so a money-bearing rewrite that is also ambiguous, or that
re-keys a row whose own content is present, is disclosed under the earlier
reason's name -- reference_shared_in_fetch or content_present_elsewhere. Nothing
is silent: `needs_review` is True on every one of them. But a count of
`direction_or_currency_changed` (or of `amount_changed`) is therefore a LOWER
BOUND on money-bearing rewrites, not a total, and the ladder order is deliberate
and settled. The boundary is crisp -- for a sign-flipped row sharing the
reference, the reason is content_present_elsewhere while the stored row's own
twin sits within AMOUNT_ONLY_MATCH_WINDOW_DAYS of THAT STORED ROW's booking date
(which is what `_content_present` measures) and direction_or_currency_changed
once the twin is further away than that. Anything wanting a true total must test
the money fields on the record rather than read the label.
"""
from __future__ import annotations
import datetime as _dt
import hashlib
import itertools
import json
import money
import re
import unicodedata
from typing import NamedTuple

MATCH_WINDOW_DAYS = 7
# Inside MATCH_WINDOW_DAYS, a reference match corroborates -- on EITHER arm --
# only within this narrower bound. Beyond it, but still inside
# MATCH_WINDOW_DAYS, a WEEKLY (or faster) standing order would otherwise look
# exactly like a corrected date and erase the earlier occurrence:
# MATCH_WINDOW_DAYS (7) coincides with that recurrence period, so date
# proximity alone cannot tell a correction from a recurrence the way it can for
# a monthly one. The name names the amount arm because that is where the bound
# started; it governs both, and one constant is better here than two that can
# drift apart.
AMOUNT_ONLY_MATCH_WINDOW_DAYS = 3
MAX_EXACT_CLUSTER = 8      # above this, fall back and flag rather than hang
_WS = re.compile(r"\s+")

_PENDING = {"PDNG", "PNDG", "PENDING", "HOLD"}
_BOOKED = {"BOOK", "BOOKED"}


class Plan(NamedTuple):
    inserts: list      # rows to insert (carry local_id, occurrence, match_method)
    updates: list      # changes to stored rows (carry row_id and op)
    tombstones: list   # rows to mark 'vanished'
    flags: list        # rows to flag needs_review without other change


_ABSENT = "\x00ABSENT"


def _canon(value) -> str:
    """Absent is distinguished from empty; text is NFC + whitespace-collapsed."""
    if value is None:
        return _ABSENT
    text = unicodedata.normalize("NFC", str(value)).strip().lower()
    return _WS.sub(" ", text)


def _present(canon: str) -> bool:
    """True when a canonicalised value actually says something.

    Absent and empty are both SILENCE, and silence corroborates nothing.
    `_canon` maps them to two different strings, so plain equality would make
    two absent counterparties compare equal and count as agreement -- which
    lets a reused reference with a changed amount and no counterparty on either
    row go on rewriting history in place.
    """
    return bool(canon) and canon != _ABSENT


def identity_key(row: dict) -> str:
    """Date-free content hash. Dates and status are ATTRIBUTES, not identity."""
    material = json.dumps([
        _canon(row.get("account_id")), int(row["amount_minor"]),
        _canon(row.get("currency")), _canon(row.get("direction")),
        _canon(row.get("counterparty")), _canon(row.get("remittance")),
    ], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def normalise(raw: dict, account_id: str) -> dict:
    """Provider payload -> canonical row. Amounts become integer minor units;
    magnitudes stay non-negative with direction carried separately, and a
    payload that contradicts itself is rejected rather than normalised."""
    amt = raw.get("transaction_amount") or {}
    currency = amt.get("currency")
    minor = money.to_minor(str(amt.get("amount")), currency)
    direction = raw.get("credit_debit_indicator")
    if direction not in ("CRDT", "DBIT"):
        raise ValueError("unknown credit_debit_indicator %r" % (direction,))
    if minor < 0:
        raise ValueError("provider sent a negative magnitude; direction is authoritative")
    # Magnitudes are stored NON-NEGATIVE with direction carried separately.
    # Aggregation applies the sign (SUM(CASE WHEN direction='DBIT' THEN
    # -amount_minor ELSE amount_minor END)).
    party = raw.get("creditor") if direction == "DBIT" else raw.get("debtor")
    counterparty = (party or {}).get("name") if isinstance(party, dict) else None
    if not isinstance(counterparty, str):
        # A non-string scalar here is malformed provider data. SQLite TEXT
        # affinity would store 123 as '123' and erase the evidence, so the type
        # check must happen HERE or nowhere: a numeric name then EQUALS a rule
        # anchor '123'). None, not str(): absent is the fail-closed reading of
        # a value we cannot vouch for.
        counterparty = None
    remittance = raw.get("remittance_information")
    if isinstance(remittance, list):
        remittance = " ".join(str(x) for x in remittance) if remittance else None
    if not isinstance(remittance, str):
        remittance = None                      # same contract as counterparty
    ref = raw.get("entry_reference") or raw.get("transaction_id")
    row = {
        "account_id": account_id,
        "booking_date": raw.get("booking_date") or raw.get("value_date"),
        "value_date": raw.get("value_date"),
        "amount_minor": minor,
        "currency": currency,
        "direction": direction,
        "status": raw.get("status"),
        "counterparty": counterparty,
        "remittance": remittance,
        "provider_ref": ref,
        "provider_ref_kind": ("entry_reference" if raw.get("entry_reference")
                              else ("transaction_id" if raw.get("transaction_id") else None)),
        "raw_json": json.dumps(raw, separators=(",", ":"), sort_keys=True),
    }
    if not row["booking_date"]:
        raise ValueError("transaction has neither booking_date nor value_date")
    return row


def _date(value: str) -> _dt.date:
    return _dt.date.fromisoformat(value)


def _days(a: str, b: str) -> int:
    return abs((_date(a) - _date(b)).days)


def _status(row: dict) -> str:
    return str(row.get("status") or "").strip().upper()


def _is_pending(row: dict) -> bool:
    return _status(row) in _PENDING


def _is_booked(row: dict) -> bool:
    return _status(row) in _BOOKED


def _status_rank(row: dict) -> int:
    """Ordering for "which restatement of one transaction do we keep": BOOKED
    first, an unrecognised status next, PENDING last. A booked row is the
    provider's settled account of the
    transaction, so a pending restatement of the same row never outranks it --
    and it must not win merely by appearing earlier in the page.
    """
    if _is_booked(row):
        return 0
    return 2 if _is_pending(row) else 1


def ref_trusted(capability: dict) -> bool:
    """Rule 1's gate. A reference keys `(account_id, provider_ref)` only for ASPSPs
    observed to supply stable references, "and only within the scope in which
    the reference was observed unique, recorded per ASPSP (per-account is
    assumed; global is never assumed)".

    reconcile sees one account's rows, so `account` is the only scope it can
    honour; `unknown` means the scope was never established and the reference
    must not be keyed on. An absent capability row reads as
    provenance.DEFAULT_CAPABILITY, which lands here as False.
    """
    if not capability:
        return False
    return bool(capability.get("ref_stable")) and capability.get("ref_scope") == "account"


def _corroborate(stored: dict, fetched: dict, window: int):
    """Rule 1: a reference match is corroborated BEFORE it is trusted.

    The rule, stated as an invariant:

        A reference match is corroborated only when the two rows' booking
        dates agree within the match window AND at least one of
        (amount unchanged, counterparty unchanged) also holds.

    Both halves are load-bearing, and the date half is the one that keeps
    getting dropped:

    * **An unchanged amount alone is never corroboration.** A monthly standing
      order has an identical amount, counterparty AND remittance every single
      month. Treating "same amount" as proof means an incremental fetch that
      contains only February updates January IN PLACE, silently rewriting its
      date and erasing the month — precisely the history rewriting this rule
      exists to prevent. Same reasoning kills "counterparty alone".
    * **The date is what separates a correction from a recurrence.** A genuine
      correction moves a booking date by days; a recurrence sits ~30 days away.
      Two rows sharing a reference a month apart are a REUSED reference, not
      one transaction whose date moved. Outside the window we insert and flag
      both rows — the safe direction, because inserting a duplicate is
      recoverable and overwriting valid financial history is not.
    * Inside the window, agreement on either the amount or the counterparty is
      enough, which is what lets a reference carry a genuine amount correction
      (the case a date-free content hash cannot follow at all).
    * **An ABSENT counterparty agrees with nothing**. `_canon`
      distinguishes absent from empty, so two rows that both omit the
      counterparty would compare equal and corroborate — and a reused
      reference with a changed amount and no counterparty anywhere would then
      rewrite history in place, which is the direction this rule exists to
      close. The arm requires a non-empty normalised counterparty on BOTH rows.
    * **Corroboration itself -- either arm -- only reaches within
      AMOUNT_ONLY_MATCH_WINDOW_DAYS.** MATCH_WINDOW_DAYS (7) coincides with a
      WEEKLY standing order's own recurrence period, so "near" alone does not
      separate a correction from a recurrence the way it does for a monthly
      one. Narrowing the amount arm alone leaves the realistic shape open: a
      weekly standing order whose counterparty is ALSO unchanged (identical
      content, only the date differs) corroborates via the counterparty arm at
      the full 7-day window. Corroboration exists
      to confirm "this is the same transaction, the bank moved its booking
      date" -- a genuine correction moves a date by days, a recurrence sits a
      week or more away -- so the drift bound belongs on the corroboration
      decision as a whole, not on one arm of it. Both arms now share this one
      constant; a genuine 1-2 day correction still corroborates via either
      arm, and a 7-day-apart pair -- same amount, same counterparty, or
      both -- falls through to provider_ref_reuse instead.

    Returns (trusted, match_method, confidence).
    """
    same_amount = int(stored["amount_minor"]) == int(fetched["amount_minor"])
    # The counterparty arm needs a REAL name on BOTH rows. Two absent
    # counterparties are not an agreement about anything, and treating them
    # as one reopens the in-place rewrite this rule closes.
    stored_cp = _canon(stored.get("counterparty"))
    same_cp = (_present(stored_cp)
               and stored_cp == _canon(fetched.get("counterparty")))
    days = _days(stored["booking_date"], fetched["booking_date"])
    near = days <= window
    if not near:
        return False, "inserted", 0.0          # a recurrence, not a correction
    if days > AMOUNT_ONLY_MATCH_WINDOW_DAYS:
        # Too far apart to be a mere correction, on EITHER arm -- a
        # week or more is a recurrence, not a date the bank moved.
        return False, "inserted", 0.0
    if same_amount:
        return True, "reference", 1.0
    if same_cp:
        return True, "reference_corroborated", 0.7
    return False, "inserted", 0.0


_MUTABLE = ("booking_date", "value_date", "amount_minor", "status",
            "counterparty", "remittance", "provider_ref")


def _money_change(stored_row: dict, candidate: dict):
    """Which MONEY-BEARING field a match rewrites, as a review reason, or None.

    The precise claim, because a looser version of this sentence is wrong:
    `_corroborate` compares `amount_minor`, `counterparty` and both booking
    dates -- but the arm that returns confidence **1.0** keys on `amount_minor`
    ALONE (`if same_amount: return True, "reference", 1.0`), and `identity_key`
    hashes `currency` and `direction` too. So a row whose SIGN changed
    corroborates at confidence 1.0 -- the magnitude matched, and nothing on
    that arm looks further -- and would be re-keyed in place with no disclosure
    at all:

        stored DBIT 1000 EUR -> fetched CRDT 1000 EUR
            a EUR 10 debit becomes a EUR 10 credit: a EUR 20 swing in every
            total, at conf 1.0, needs_review=False, reason=None
        stored DBIT 1000 EUR -> fetched DBIT 1000 USD
            the integer means a different unit; same silence

    `_MUTABLE` covers neither field either, so such a write reaches the row
    only via `rekeyed` -- which is exactly why it would leave no trace
    anywhere. "The conf=1.0 arm keeps the amount by construction, so money is
    intact there" is true of `amount_minor` alone and false of the money.

    Direction/currency outrank an amount change deliberately: a sign flip or a
    unit change is rarer and more alarming than a value correction, so it must
    not be hidden inside the common bucket when a reader reports the
    breakdown.

    Comparison goes through `_canon`, the same normalisation `identity_key`
    uses, so a row that merely restates "EUR" as "eur" neither re-keys nor
    flags -- the flag can only fire where the identity genuinely moved.

    NOT covered, deliberately: of the six fields `identity_key` hashes,
    `_corroborate` checks `amount_minor` and `counterparty` and this function
    checks `amount_minor`, `currency` and `direction`, which leaves `remittance`
    and `account_id` checked by neither. `remittance` is not money-bearing, so a
    re-key that moves only it (or only `counterparty`) stays unflagged: that
    is a relabelling, not a money change. `account_id` is not expected to move
    within one call, because `reconcile` sees a single account by contract --
    though nothing here enforces that.
    """
    if (_canon(stored_row.get("direction")) != _canon(candidate.get("direction"))
            or _canon(stored_row.get("currency"))
            != _canon(candidate.get("currency"))):
        return "direction_or_currency_changed"
    if int(stored_row["amount_minor"]) != int(candidate["amount_minor"]):
        return "amount_changed"
    return None


def _changed(stored_row: dict, candidate: dict) -> bool:
    """True when a match actually differs. Re-fetching an unchanged interval must
    be a genuine no-op, not a stream of identical rewrites."""
    return any(stored_row.get(k) != candidate.get(k) for k in _MUTABLE)


def _next_occurrence(stored: list, identity: str, allocated=None) -> int:
    """Monotonic per identity, allocated above every occurrence ever issued —
    including tombstoned rows, so a resurrection cannot collide with the
    UNIQUE (account_id, identity_key, occurrence) constraint (rule 4).

    `allocated` is the DURABLE high-water map the caller loaded from the ledger
    ({identity_key: next free occurrence}), and it is what makes rule 4 hold
    across passes rather than only within one. `stored` is whatever
    rows the caller happened to fetch, and a routine refresh fetches roughly
    the last seven days — so a monthly standing order's earlier occurrences are
    simply not in it, and this function on its own would hand out occurrence 0
    again. The durable map is also the only thing that remembers a slot a
    re-keyed row VACATED: no surviving row carries that tuple any more.

    The in-memory maximum still counts, because the current pass allocates
    several occurrences before any of them is written.

    NOTE the loop. `dict.get(key, default)` evaluates its default EAGERLY, so
    `s.get("identity_key", identity_key(s))` hashes every row whether or not the
    key is missing — and rows that legitimately carry only their key (a
    tombstone read back from the ledger, the shadow rows this module appends
    after each insert) have no `amount_minor` to hash. identity_key(s) is
    therefore computed lazily, only when the key is genuinely absent.
    """
    floor = int((allocated or {}).get(identity) or 0)
    for s in stored:
        key = s.get("identity_key")
        if key is None:
            key = identity_key(s)
        if key == identity:
            floor = max(floor, int(s.get("occurrence") or 0) + 1)
    return floor


def _best_matching(fetched_items, stored_items, window, blocked=frozenset()):
    """Maximum-cardinality matching, then minimum total distance.

    Returns (pairs, exact) where pairs is [(fetched_index, stored_row, days)].

    `exact` is False when the cluster exceeded MAX_EXACT_CLUSTER and a
    deterministic greedy fallback ran instead — the caller then flags every row
    involved, because rule 5 forbids an unresolved cluster passing silently. We
    degrade and disclose; we never hang.

    Greedy shortest-edge is NOT correct in the exact regime: a zero-distance
    edge can consume the only stored row another fetched row could reach,
    leaving it unmatched — which produces a spurious insert AND a spurious
    tombstone for one real transaction. Verified failing case: stored at day 10
    and day 3, fetched at day 10 and day 16, window 7 — greedy matches 1 pair,
    optimal matches 2.

    `blocked` is a set of (fetched_index, stored row_id) pairs that are not
    edges of this graph at all, because rule 1 already examined that exact
    pairing and rejected it. It is deliberately per-PAIR: withholding the
    stored row itself would also block every OTHER fetched row from matching
    it, which is how a genuine continuation arriving under a different
    reference becomes a silent, permanent duplicate. Removing
    edges rather than vertices also keeps the maximum-cardinality property
    meaningful -- every other fetched row in the cluster can still reach the
    row. BOTH regimes honour it: the exact search and the greedy fallback, or
    the guarantee would silently evaporate for clusters above the cap.
    """
    fs = list(fetched_items)                      # [(fi, row), ...]
    ss = list(stored_items)                       # [row, ...]
    if not fs or not ss:
        return [], True
    if len(fs) > MAX_EXACT_CLUSTER or len(ss) > MAX_EXACT_CLUSTER:
        out, used = [], set()
        for fi, f in sorted(fs, key=lambda t: (t[1]["booking_date"], t[0])):
            best = None
            for sr in sorted(ss, key=lambda r: (r["booking_date"], r["row_id"])):
                if sr["row_id"] in used or (fi, sr["row_id"]) in blocked:
                    continue
                d = _days(f["booking_date"], sr["booking_date"])
                if d <= window and (best is None or d < best[1]):
                    best = (sr, d)
            if best:
                out.append((fi, best[0], best[1]))
                used.add(best[0]["row_id"])
        return out, False

    best = None
    for k in range(min(len(fs), len(ss)), 0, -1):
        for fsub in itertools.combinations(range(len(fs)), k):
            for ssub in itertools.permutations(range(len(ss)), k):
                total, ok = 0, True
                for fi_idx, si_idx in zip(fsub, ssub):
                    d = _days(fs[fi_idx][1]["booking_date"], ss[si_idx]["booking_date"])
                    if d > window or (fs[fi_idx][0], ss[si_idx]["row_id"]) in blocked:
                        ok = False
                        break
                    total += d
                if not ok:
                    continue
                # deterministic tie-break: total distance, then dates, then row ids
                key = (total,
                       tuple(fs[i][1]["booking_date"] for i in fsub),
                       tuple(ss[i]["booking_date"] for i in ssub),
                       tuple(ss[i]["row_id"] for i in ssub))
                if best is None or key < best[0]:
                    best = (key, [(fs[fi][0], ss[si],
                                   _days(fs[fi][1]["booking_date"],
                                         ss[si]["booking_date"]))
                                  for fi, si in zip(fsub, ssub)])
        if best is not None:
            return best[1], True
    return [], True


def reconcile(stored: list, fetched: list, interval: tuple, capability: dict,
              match_window_days: int = MATCH_WINDOW_DAYS,
              allocated: dict | None = None) -> Plan:
    """`stored` must contain rows in EVERY state — passing only state='active'
    rows lets a tombstoned occurrence be reissued (rule 4).

    `allocated` is `apply.occurrence_allocations(conn, account_id, keys)`: the
    DURABLE high-water occurrence per identity cluster. Omitting it is safe
    only when `stored` is the account's complete history; every production
    caller loads it, because a routine refresh loads roughly the last seven
    days and rule 4 is a statement about every occurrence EVER issued, not
    about the ones this pass happened to see.
    """
    start, end = interval
    inserts, updates, tombstones, flags = [], [], [], []
    stored = [dict(s) for s in stored]
    for s in stored:
        if not s.get("identity_key"):      # lazy, for the reason in _next_occurrence
            s["identity_key"] = identity_key(s)
        if s.get("occurrence") is None:
            s["occurrence"] = 0
        if not s.get("state"):
            s["state"] = "active"
    live = [s for s in stored if s["state"] == "active"]
    matched_rows, matched_fetched, unresolved = set(), set(), set()

    # Every fetched row indexed by content, so any stored row can ask
    # "is my own content sitting in this page?".
    _fetched_by_ident = {}
    for _f in fetched:
        _fetched_by_ident.setdefault(identity_key(_f), []).append(_f)

    def _content_present(s) -> bool:
        """True when this stored row's EXACT content -- all six hashed fields --
        sits in the fetch within AMOUNT_ONLY_MATCH_WINDOW_DAYS of its booking
        date -- the same bound corroboration uses, deliberately not a new one.

        A row whose own content is in the page is not ABSENT, whatever else the
        page contains -- that, and only that, is what this predicate licenses.
        It does NOT establish that the row is correctly paired: the rule-3 use
        site below concedes that sparing the row can leave the ledger holding
        this row AND an insert of the same content, which is why that site
        discloses rather than staying silent. Two places act on the predicate:
        rule 3 refuses to tombstone such a row, and rule 1 refuses to re-key one
        SILENTLY.
        """
        for f in _fetched_by_ident.get(s["identity_key"], ()):
            if _days(s["booking_date"],
                     f["booking_date"]) <= AMOUNT_ONLY_MATCH_WINDOW_DAYS:
                return True
        return False
    # Stored row_ids whose reference was claimed by a fetched row that failed
    # corroboration (ref_reused), and the fetched indices that failed that
    # attempt (ref_reuse_fi). Tracked SEPARATELY from
    # matched_rows/matched_fetched: the fetched row is still eligible for an
    # ordinary content-based match in rule 2 if its real continuation is
    # elsewhere in this fetch (never force-inserted here), and the stored row
    # is exempt from the rule-3 tombstone pass below WITHOUT being parked as
    # "matched" -- a row we flagged as reused was never proven absent. Wherever
    # a fetched index in ref_reuse_fi eventually lands (an insert, or a
    # windowed match), needs_review is forced True with reason
    # "provider_ref_reuse", since it claimed a reference under false pretences.
    # The (fetched_index, stored_row_id) pairs that actually went through
    # _corroborate under rule 1 and were REJECTED. Rule 2 must not rediscover
    # one of those pairings by content+date alone -- but it is only ever
    # allowed to block THAT pairing, never the stored row wholesale (see the
    # comment at rule 2's clustering loop).
    failed_pairs = set()
    ref_reused, ref_reuse_fi = set(), set()

    def emit_insert(f, method, confidence, needs_review, reason=None):
        ident = identity_key(f)
        rec = dict(f)
        rec.pop("row_id", None)            # the database assigns it
        rec.update(identity_key=ident,
                   occurrence=_next_occurrence(stored, ident, allocated),
                   match_method=method, match_confidence=confidence,
                   needs_review=bool(needs_review), reason=reason, state="active",
                   local_id="ins:%d" % len(inserts))
        inserts.append(rec)
        stored.append(dict(rec))   # a COMPLETE shadow row: the next allocation
        return rec                 # sees this occurrence and allocates above it

    def emit_match(s, f, method, confidence, needs_review, reason=None):
        """A corroborated or windowed match. pending -> booked is a SUPERSESSION,
        not an in-place update: the booked row is inserted and the
        pending row is pointed at it, so the transition stays in the record and
        `state='superseded'` / `superseded_by` are live schema.

        THE IDENTITY INVARIANT. A row's stored `identity_key` always equals
        the hash of its own current content. A corroborated reference match may
        change hashed content — an amount correction is the ordinary case — and
        when it does the row is RE-KEYED, which means `identity_key` and
        `occurrence` move together, in the same update, or not at all. The
        previous round emitted the new key and never reallocated the occurrence
        (and apply never wrote either), so the row's stored identity disagreed
        with its own content and a later reference-less fetch could insert a
        duplicate and tombstone the original.

        The new occurrence is allocated above every occurrence ever issued in
        the NEW cluster (rule 4), and the row's OLD (identity_key, occurrence)
        pair is left in `stored` as a ghost so nothing in this same pass can
        take the slot it vacated. apply writes both columns in one statement and
        the UNIQUE (account_id, identity_key, occurrence) constraint turns any
        collision into a raise, never a silent reuse.
        """
        if _is_pending(s) and _is_booked(f):
            # THE REPLACEMENT INHERITS A FINDING ALREADY STANDING
            # AGAINST THE ROW IT REPLACES, unless this pass has one of its own.
            #
            # A supersession is the only match that moves the money onto a
            # DIFFERENT row. Every other match rewrites the stored row in
            # place, so a standing `needs_review` stays attached to the money
            # it is about; here the flagged row goes `state='superseded'` and a
            # brand-new active row takes its place. `list_transactions` filters
            # `state='active'`, so the finding left the operator's view
            # entirely: a pending row flagged provider_ref_reuse booked on the
            # next pass and the ledger reported "none flagged for review" over
            # money it had itself marked as possibly duplicated or
            # misattributed. Reproduced end to end through `sync`.
            #
            # INHERITED, NOT RE-DERIVED, and that is forced rather than
            # preferred: the evidence for the original finding was a
            # non-corroborating claimant of the same reference in an EARLIER
            # fetch, which need not appear in this one at all. `reconcile` sees
            # only the rows it was handed, so it cannot rediscover the finding
            # and a "re-derive" rule would silently drop every finding whose
            # evidence has aged out of the window. The stored row's own
            # `needs_review` is the durable record of it.
            #
            # THIS PASS'S FINDING WINS when it has one — the newest, most
            # specific cause is the one worth naming, exactly as
            # `apply`'s COALESCE(?, review_reason) decides the same question
            # one layer down.
            #
            # BOUNDED AT ONE HOP, so nothing accumulates: this branch requires
            # `_is_pending(s)`, and the row it inserts carries the FETCHED
            # row's status, which `_is_booked` just asserted. A booked row can
            # never be the pending side of a later supersession, so an
            # inherited flag cannot be handed down a chain. Pinned by
            # test_an_inherited_flag_does_not_chain_through_later_passes.
            if not needs_review and s.get("needs_review"):
                # A reason of None is carried as None rather than invented:
                # tools_read._reason_label renders that as "no reason
                # recorded", which is the honest rendering of a flag whose
                # cause was already missing.
                needs_review, reason = True, s.get("review_reason")
            rec = emit_insert(f, method, confidence, needs_review, reason)
            updates.append({"op": "supersede", "row_id": s["row_id"],
                            "state": "superseded",
                            "superseded_by_local": rec["local_id"],
                            "match_method": method,
                            "match_confidence": confidence,
                            "needs_review": bool(needs_review),
                            "reason": reason})
            return
        new_ident = identity_key(f)
        rekeyed = new_ident != s["identity_key"]
        occurrence = s["occurrence"]
        if rekeyed:
            occurrence = _next_occurrence(stored, new_ident, allocated)
            # Record the ARRIVAL in the new cluster so the next allocation there
            # sits above it. `s` itself stays in `stored` untouched, which is
            # what leaves the ghost behind in the old cluster — mutating s would
            # free the vacated occurrence for reissue and break rule 4.
            stored.append({"identity_key": new_ident, "occurrence": occurrence,
                           "row_id": s["row_id"], "state": "active"})
        upd = dict(f, op="update", row_id=s["row_id"], identity_key=new_ident,
                   occurrence=occurrence, match_method=method,
                   match_confidence=confidence, needs_review=bool(needs_review),
                   reason=reason, state="active")
        # unchanged rows produce no write; a re-key is always a change, even if
        # every field _MUTABLE watches happened to compare equal
        if _changed(s, upd) or rekeyed or needs_review:
            updates.append(upd)

    # ---- rule 1: reference identity, corroborated, PER-ASPSP ---------------
    # ref_stable means unique WITHIN THE RECORDED SCOPE, and this whole block
    # is built around that consequence: every fetched row sharing one trusted
    # reference is resolved as a GROUP, deterministically, rather than
    # one-fetched-row-at-a-time in provider page order — which would make the
    # outcome depend on that order, and let a failing candidate be popped and
    # lost for the fetched row that would actually have corroborated it).
    if ref_trusted(capability):
        by_ref_stored = {}
        for s in live:
            if s.get("provider_ref"):
                by_ref_stored.setdefault(s["provider_ref"], []).append(s)
        by_ref_fetched = {}
        for fi, f in enumerate(fetched):
            ref = f.get("provider_ref")
            if ref:
                by_ref_fetched.setdefault(ref, []).append((fi, f))

        for ref in sorted(by_ref_fetched):
            group = sorted(by_ref_fetched[ref], key=lambda t: t[0])
            # collapse fetched rows in this group that are restatements of ONE
            # transaction: same date-free content hash AND booking dates close
            # enough that one row is the other with its date moved. N identical
            # copies of one page are one transaction, never N -- even when no
            # stored row carries this ref at all (two identical copies of a
            # brand-new transaction must not both survive to the final insert
            # pass and double-count the money).
            #
            # THE DATE BOUND IS LOAD-BEARING. Collapsing on identity_key alone,
            # which is deliberately date-free AND status-free, merges not only
            # restatements but any two fetched rows with matching content under
            # a reused reference -- including CONSECUTIVE OCCURRENCES OF A
            # STANDING ORDER. Three monthly rents sharing one reused reference
            # would collapse to one insert: two months of money gone, with no
            # insert, no flag, no needs_review and nothing for the review
            # breakdown to surface -- i.e. trusting the reference was strictly
            # WORSE than ignoring it, the one thing this block must never be.
            #
            # The premise was wrong, not the mechanism. `ref_stable` /
            # `ref_scope="account"` records that references were observed
            # UNIQUE; it is not evidence that a provider never reuses one --
            # this module's entire provider_ref_reuse apparatus exists because
            # trusted providers demonstrably do, across recurrences. So "never
            # insert twice" means never twice for one TRANSACTION, and only
            # date proximity can establish that two same-content rows are one.
            # The bound is AMOUNT_ONLY_MATCH_WINDOW_DAYS, the same constant
            # that bounds corroboration in _corroborate for exactly the same
            # reason (a correction moves a date by days; a recurrence sits a
            # week or more away). A genuinely duplicated page has IDENTICAL
            # dates, so drift 0 still collapses and the standing-order case stays
            # closed.
            #
            # Bands are anchored on the earliest date in date order, so every
            # band spans at most the bound (single-linkage chaining would let
            # rows an arbitrary distance apart collapse transitively) and the
            # partition depends only on the dates, never on provider row order.
            by_ident = {}
            for fi, f in group:
                by_ident.setdefault(identity_key(f), []).append((fi, f))
            reps = []
            for ident in sorted(by_ident):
                items = sorted(by_ident[ident],
                               key=lambda t: (t[1]["booking_date"], t[0]))
                bands = []
                for fi, f in items:
                    if bands and _days(bands[-1][0][1]["booking_date"],
                                       f["booking_date"]) <= AMOUNT_ONLY_MATCH_WINDOW_DAYS:
                        bands[-1].append((fi, f))
                    else:
                        bands.append([(fi, f)])
                for band in bands:
                    # Within a band, prefer a BOOKED restatement over a pending
                    # one instead of taking whichever the page listed first
                    # -- taking items[0] persists the PDNG row and drops the
                    # BOOK row whenever a page lists pending first. Keeping
                    # the booked row is also what makes the pending->booked
                    # transition reach emit_match's supersession branch, so a
                    # stored pending row is pointed at the booked row that
                    # replaced it rather than silently overwritten.
                    # booked first, then the earliest booking date, and only
                    # then the fetch index.
                    #
                    # WHAT THIS DOES AND DOES NOT GUARANTEE. It is NOT that
                    # the fetch index "never decides anything two rows could
                    # disagree about" -- that is false, and the kind of
                    # overclaim that turns into a defect. The key ranks by
                    # _status_rank, which BUCKETS statuses rather than comparing
                    # them -- BOOK and BOOKED share rank 0, PDNG/PNDG/PENDING/
                    # HOLD share rank 2, and every unrecognised status shares
                    # rank 1 -- and identity_key covers neither `status` nor
                    # `value_date`. So when two rows in one band tie on rank AND
                    # on booking_date, the fetch index really does decide, and
                    # the survivor's persisted status SPELLING (BOOK vs BOOKED,
                    # PDNG vs HOLD, one unrecognised status vs another) and its
                    # `value_date` can flip with provider row order. All four
                    # cases are demonstrable.
                    #
                    # What IS guaranteed: every field identity_key covers
                    # (account, amount, currency, direction, counterparty,
                    # remittance) is identical across a band by construction,
                    # and booking_date is settled by the date key -- so no money
                    # field, no counterparty and no booking date can flip. The
                    # residue is a status spelling within one rank and a
                    # value_date, neither of which any rule in this module reads
                    # as anything but its rank. Keying this on the fetch index
                    # ALONE makes which restatement survives -- dates, status
                    # rank and all -- depend on page order.
                    keep = min(band, key=lambda t: (_status_rank(t[1]),
                                                    t[1]["booking_date"], t[0]))
                    reps.append(keep)
                    for dup_fi, _dup in band:
                        if dup_fi != keep[0]:
                            matched_fetched.add(dup_fi)   # a restatement of the
                                                          # kept row: no separate
                                                          # Plan record

            cands = list(by_ref_stored.get(ref, []))
            if not cands:
                continue    # no stored anchor for this ref; every rep here
                            # falls through untouched to rule 2

            cands_sorted = sorted(cands, key=lambda r: r["row_id"])

            def _rep_order(rf):
                return (identity_key(rf[1]), rf[1]["booking_date"], rf[0])

            # CONTENT IDENTITY OUTRANKS INCIDENTAL CORROBORATION, across
            # candidates and not merely within one.
            #
            # Preferring a content twin per candidate is not enough while the
            # assignment stays greedy in row_id order: a candidate can still
            # take the rep a later candidate needed. Two stored rows under one
            # reference, the first with no twin in the page and the second with
            # one: the first goes first, sees a single corroborating rep -- the
            # SECOND row's twin -- and takes it on the 0.7 counterparty arm.
            # Both rows are then re-keyed, unflagged: the second row's amount
            # overwritten while its exact content sat in the same page, and the
            # first row's content destroyed outright with no tombstone, no
            # supersession and no flag. Swapping only the two row_ids produced
            # the correct plan instead, so two ledgers differing by real money
            # were decided by row_id alone -- and the adverse order is what
            # natural evolution produces (page 1 inserts them in that order).
            #
            # So twins are RESERVED for their own rows first, across every
            # candidate, before any candidate is allowed to claim a rep it
            # merely corroborates. Greed was the mechanism; precedence is the
            # defect.
            #
            # WHAT IS AND IS NOT PRESERVED. It is NOT that "record order,
            # local_ids and occurrence allocation are untouched" -- that is
            # false, because reserving a twin can route a pairing through the
            # same overclaiming shape that argued the wholesale block into the
            # module). The candidate LOOP ORDER is untouched -- emission still
            # happens below in row_id order. Nothing else is guaranteed:
            # changing which rep a candidate gets can flip `emit_match` into its
            # supersession branch, which INSERTS, and an insert consumes a
            # local_id and allocates an occurrence. Measured against the parent
            # over 6000 fixtures: insert count differs on 8 fixtures, supersede
            # count on 7, (identity_key, occurrence) allocation on 22 and the
            # local_id list on 8. Those behaviour differences are intended,
            # and are covered by this module's tests.
            claimed = set()
            reserved = {}
            for s in cands_sorted:
                twins = [rf for rf in reps
                         if rf[0] not in claimed
                         and identity_key(rf[1]) == s["identity_key"]
                         and _corroborate(s, rf[1], match_window_days)[0]]
                if twins:
                    twins.sort(key=_rep_order)
                    reserved[s["row_id"]] = twins[0][0]
                    claimed.add(twins[0][0])

            for s in cands_sorted:
                mine = reserved.get(s["row_id"])
                # `mine` is this row's reserved twin; everything else must still
                # be unclaimed to be a candidate pairing.
                corroborating = [rf for rf in reps
                                 if (rf[0] == mine or rf[0] not in claimed)
                                 and _corroborate(s, rf[1], match_window_days)[0]]
                if corroborating:
                    # Order-independent AND, when more than one distinct
                    # fetched content corroborates the SAME stored row under
                    # one "unique" reference, this is genuine disagreement --
                    # keep one, deterministically, and flag it rather than
                    # silently picking, under the reason
                    # "reference_shared_in_fetch".
                    #
                    # The date joins the tie-break key. Once the
                    # collapse is date-bound, two reps under one reference CAN
                    # share an identity_key (same content, different bands), and
                    # both can corroborate one stored row from opposite sides of
                    # it -- at which point fetch index alone would have decided
                    # it, reintroducing provider row order as an input.
                    #
                    # PREFER THE CONTENT-IDENTICAL REP. Ranking
                    # the corroborating reps by content hash and date alone is
                    # arbitrary with respect to the one signal that settles the
                    # question: whether a rep IS this stored row's content. Two
                    # fetched rows a few days apart under one reference each
                    # corroborate the OTHER's stored row via the amount arm
                    # (a recurrence has the same amount every time), so rule 1
                    # would CROSS-PAIR them -- and because a cross-pair can land
                    # a pending stored row against a booked fetched row, it hit
                    # emit_match's supersession branch and INSERTED. Re-fetching
                    # an unchanged interval then never reached a fixed point:
                    # one extra physical row and one extra occurrence per pass,
                    # for ever, with the active row count pinned (which is what
                    # made a short-horizon check read as converged) and 199 of
                    # 200 passes emitting an `op="update"` that rewrote amount,
                    # date, status AND identity_key carrying needs_review=False.
                    #
                    # When two fetched rows genuinely share a trusted reference,
                    # the pairing that keeps content is the correct reading: the
                    # alternative is unbounded churn on a recurring input, and
                    # the loser is not discarded -- it stays unclaimed, lands in
                    # ref_reuse_fi and becomes a DISCLOSED insert. Content
                    # identity is only ever a preference INSIDE the corroborating
                    # set: when no rep carries this row's content (the ordinary
                    # amount correction a reference exists to carry) the
                    # fallback order stands.
                    #
                    # This selection is unchanged, and it does not need
                    # to change -- pass A's whole job is to keep a twin
                    # AVAILABLE to its own row by withholding it from everybody
                    # else, after which this preference picks it. `_rep_order` is
                    # the same order pass A reserved with, so when a reservation
                    # exists it is exactly pool[0].
                    same_content = [rf for rf in corroborating
                                    if identity_key(rf[1]) == s["identity_key"]]
                    pool = same_content or corroborating
                    pool.sort(key=_rep_order)
                    rep_fi, rep_f = pool[0]
                    ok, method, conf = _corroborate(s, rep_f, match_window_days)
                    # Exactly one rep carrying this row's own content is not a
                    # disagreement about which row is current -- the reference
                    # and the content agree, and the other corroborations were
                    # incidental (an unchanged amount corroborates every
                    # occurrence of a recurrence). Genuine ambiguity is: no rep
                    # matches the content and more than one corroborates, or
                    # SEVERAL reps carry it (same content in two date bands,
                    # corroborating this row from opposite sides) -- both still
                    # pick deterministically and still disclose.
                    ambiguous = len(corroborating) > 1 and len(same_content) != 1
                    # THE REASON LADDER for a reference match. Every arm below
                    # exists because the alternative was a silent rewrite.
                    #
                    # 1. Genuine ambiguity about WHICH fetched row this is.
                    # 2. A re-key while this row's own content sits in the
                    #    page. Reserving twins fixes candidate-order greed
                    #    WITHIN one reference, but a twin carrying a DIFFERENT
                    #    reference, or none, is not among this group's reps at
                    #    all, so rule 1 can still re-key such a row. Making
                    #    content win outright would give rule 2 precedence over
                    #    a trusted reference generally, and
                    #    test_the_vacated_occurrence_is_not_reissued_in_the_same_pass
                    #    requires the opposite: that a reference-less twin
                    #    becomes a NEW row. So the pairing stands and the
                    #    rewrite is DISCLOSED instead.
                    # 3. A MONEY-BEARING field moved.
                    #    `reference_corroborated` (conf 0.7) always means
                    #    `amount_minor` differs, on evidence that is one
                    #    counterparty name plus <= 3 days -- rule 2's greedy
                    #    fallback discloses at 0.5 and reference_shared_in_fetch
                    #    at 1.0, so needs_review=False here would be internally
                    #    inconsistent. But conf 1.0 is NOT safe either: the arm
                    #    returning 1.0 keys on `amount_minor` alone, while
                    #    `identity_key` also hashes `currency` and `direction`,
                    #    so a DBIT->CRDT flip or EUR->USD change corroborates
                    #    at 1.0 and would be re-keyed in silence. See
                    #    _money_change -- "the conf=1.0 arm keeps the amount by
                    #    construction, so money is intact there" is true of
                    #    `amount_minor` alone and false of the money.
                    #
                    # Deliberately NOT flagged: a conf-1.0 re-key that moves
                    # only `counterparty` or `remittance` with amount, currency
                    # and direction all intact. That is a relabelling, not a
                    # money change, and flagging the whole arm would be noise.
                    rekeys = identity_key(rep_f) != s["identity_key"]
                    if ambiguous:
                        reason = "reference_shared_in_fetch"
                    elif rekeys and _content_present(s):
                        reason = "content_present_elsewhere"
                    else:
                        reason = _money_change(s, rep_f)
                    emit_match(s, rep_f, method, conf, reason is not None, reason)
                    claimed.add(rep_fi)
                    matched_rows.add(s["row_id"])
                    matched_fetched.add(rep_fi)
                else:
                    # provider reference REUSE -- never update in place:
                    # overwriting would silently destroy valid history. The
                    # fetched row that claimed this reference is left
                    # UNTOUCHED here (never force-inserted) so it can find its
                    # own match in rule 2 if its real continuation is
                    # elsewhere in this fetch; ref_reuse_fi (populated below,
                    # once every candidate has had a turn) ensures it still
                    # carries needs_review + a reason wherever it lands.
                    flags.append({"row_id": s["row_id"], "reason": "provider_ref_reuse"})
                    ref_reused.add(s["row_id"])
                    # Record exactly WHICH pairings were examined and rejected.
                    # Every rep still unclaimed at this point was tried against
                    # `s` by the comprehension above and failed, so those pairs
                    # -- and only those -- are the ones rule 2 must not
                    # rediscover.
                    for rf in reps:
                        if rf[0] not in claimed:
                            failed_pairs.add((rf[0], s["row_id"]))
            # anything still unclaimed once every candidate under this ref has
            # had a turn genuinely failed to corroborate any of them
            for rf in reps:
                if rf[0] not in claimed:
                    ref_reuse_fi.add(rf[0])

    # ---- rule 2 + 5: windowed, deterministic, matched as a batch -----------
    # KNOWN LIMITATION, documented rather than fixed. Unlike rule 1's
    # _corroborate, this pass has no analogous drift bound: it clusters by
    # identity_key (full content) and pairs within match_window_days on date
    # proximity alone. That IS the design -- it is what makes a genuine
    # reference-less date correction work, and the confidence curve below
    # (dividing by match_window_days + 1) depends on it. But it means a
    # content-identical recurrence at or inside the match window -- a WEEKLY
    # (or faster) standing order with no reference at all, or one whose
    # reference-corroboration attempt failed and fell through here with its
    # content otherwise unchanged -- can be absorbed as a date correction if
    # its earlier occurrence is simply MISSING from `fetched`. The safeguard
    # against that is the caller's fetch-completeness guarantee (a proven
    # interval must actually contain every row inside it, not an interval
    # truncated mid-pagination), not this function -- that guarantee lives in
    # the fetch/pagination layer, which re-raises on an incomplete page rather
    # than handing reconcile a partial interval.
    clusters = {}
    for fi, f in enumerate(fetched):
        if fi in matched_fetched:
            continue
        clusters.setdefault(identity_key(f), {"f": [], "s": []})["f"].append((fi, f))
    for s in live:
        # A stored row whose reference was reused stays in this pool. What is
        # withheld from it is only the SPECIFIC pairings rule 1 examined and
        # rejected (`failed_pairs`, passed to _best_matching below), because
        # letting rule 2 re-pair those by content+date alone would silently
        # rediscover the exact match _corroborate correctly refused -- a weekly
        # standing order whose reference is reused has content identical to the
        # stored occurrence, and rule 2 has no drift bound of its own.
        #
        # PER-PAIR, NEVER WHOLESALE. Withholding the stored row entirely
        # would be justified by "that pairing already went through
        # _corroborate under rule 1 and was rejected", and that premise is
        # false: rule 1 only ever corroborated fetched rows carrying THAT
        # reference. A fetched row with a different reference, or none at all,
        # was never examined against this stored row -- so whenever any fetched
        # row squats a stored row's trusted reference and fails to corroborate
        # it (the ordinary provider_ref_reuse case this module is built around)
        # while that stored row's genuine continuation arrives in the same fetch
        # under a different reference, the continuation would be blocked from
        # matching and inserted as a duplicate carrying needs_review=False,
        # reason=None, confidence 1.0 -- invisible to the review breakdown. And
        # it never converged: on the next pass the squatter's inserted row
        # carries the reference too, so the stored row was re-flagged, stayed
        # excluded here and stayed exempt from rule 3, for ever.
        if s["row_id"] in matched_rows:
            continue
        c = clusters.get(s["identity_key"])
        if c is not None:
            c["s"].append(s)

    for ident in sorted(clusters):
        c = clusters[ident]
        pairs, exact = _best_matching(c["f"], c["s"], match_window_days,
                                      failed_pairs)
        if not exact:
            unresolved.add(ident)
        for fi, s_row, d in pairs:
            conf = round(1.0 - d / (match_window_days + 1), 3)
            if not exact:
                conf = min(conf, 0.5)
            # A fetched row that already claimed (and lost) a trusted
            # reference elsewhere in this fetch keeps needs_review + its
            # reason even when it goes on to find a genuine content match here.
            if fi in ref_reuse_fi:
                needs_review, reason = True, "provider_ref_reuse"
            elif not exact:
                needs_review, reason = True, "windowed_ambiguous"
            else:
                needs_review, reason = False, None
            emit_match(s_row, dict(fetched[fi]), "windowed", conf, needs_review, reason)
            matched_rows.add(s_row["row_id"])
            matched_fetched.add(fi)
        if not exact:
            carried = {u["row_id"] for u in updates}
            # A row already flagged (provider_ref_reuse) is not flagged a
            # second time. Now that ref-reused rows cluster here rather than
            # being excluded wholesale, an oversized cluster could emit a
            # duplicate `flags` entry for the same row_id. apply would just set
            # needs_review=1 twice, but the read tools count the breakdown BY
            # reason, and one row must not appear in two buckets.
            flagged = {f["row_id"] for f in flags}
            for s_row in c["s"]:
                if s_row["row_id"] not in carried and s_row["row_id"] not in flagged:
                    flags.append({"row_id": s_row["row_id"],
                                  "reason": "unresolved_cluster"})

    # ---- inserts: everything still unmatched ------------------------------
    for fi, f in enumerate(fetched):
        if fi in matched_fetched:
            continue
        ident = identity_key(f)
        if fi in ref_reuse_fi:
            needs_review, reason = True, "provider_ref_reuse"
        elif ident in unresolved:
            needs_review, reason = True, "windowed_ambiguous"
        else:
            needs_review, reason = False, None
        emit_insert(f, "inserted", 1.0, needs_review, reason)

    # ---- rule 3: tombstone only well inside the proven interval -----------
    inner_start = (_date(start) + _dt.timedelta(days=match_window_days)).isoformat()
    inner_end = (_date(end) - _dt.timedelta(days=match_window_days)).isoformat()
    for s in live:
        # an unresolved cluster retains all its rows (rule 5) — never tombstone
        # on the strength of a matching pass we could not complete exactly.
        # A row whose reference was reused by something that failed to
        # corroborate it (ref_reused) was never PROVEN absent either -- it is
        # exempt here WITHOUT being parked in matched_rows (see the comment at
        # the top of reconcile).
        if (s["row_id"] in matched_rows or s["identity_key"] in unresolved
                or s["row_id"] in ref_reused):
            continue
        # NEVER tombstone a row whose own content is in the page. This
        # is not a heuristic -- rule 3's whole claim is "proven absent from a
        # proven interval", and a row whose six hashed fields sit in the fetch
        # within the drift bound is not absent by any reading. It could reach
        # here without being matched: rule 1 may have let another candidate
        # claim its twin, or the twin may have paired with a different stored
        # row in rule 2. Declaring it vanished while it is literally in the page
        # is the most destructive thing this module can do, and it did it with
        # zero disclosure. Retaining an extra active row is the safe direction
        # the module takes everywhere else.
        if _content_present(s):
            # ... but not silently. Reaching here means the matcher did
            # something ELSE with content identical to this row -- rule 1 may
            # have claimed this row's twin for a different stored row, or rule 2
            # may have paired the twin with one -- so the ledger may now hold
            # TWO rows with the same content. There need not be any insert
            # involved: when the twin was consumed as an UPDATE to another stored
            # row, both same-content rows are stored rows (two stored rows two
            # days apart with one fetched row between them do exactly that -- no
            # insert, one windowed update, and this flag on the row that lost).
            # Either way it is a double count, and it is the right trade (a
            # recoverable duplicate over destroyed history, the direction this
            # module takes everywhere) only if somebody is told.
            # Measured: without this flag the change converts one silent
            # deletion of a present row into one UNDISCLOSED duplicate.
            flags.append({"row_id": s["row_id"],
                          "reason": "content_present_elsewhere"})
            continue
        if inner_start <= s["booking_date"] < inner_end:
            tombstones.append({"row_id": s["row_id"], "state": "vanished",
                               "reason": "absent_from_a_proven_interval"})
    return Plan(inserts=inserts, updates=updates, tombstones=tombstones, flags=flags)
