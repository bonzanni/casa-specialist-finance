# plugins/bank-feed/server/provenance.py
"""Restore provenance and earned per-account reference trust.

Both live in the store's own tables: the fingerprint in `meta`, the reference
evidence in `ref_observations`. Neither ever holds key material.

What is built is the restore *check* and its report. Re-validating
key<->application identity, re-checking session status against the provider and
marking cached data stale are NOT: a mismatch is reported, and the remedy is the
operator's.

TRUST IS EARNED, PER ACCOUNT, FROM THIS INSTALLATION'S OWN EVIDENCE (issue #1).
The evidence table is append-only: `measure_references` reduces one completed
run's fetched rows to aggregate metrics, `record_observation` files them, and
`capability` derives the verdict AT READ TIME from the metrics and the current
constants — there is no cached capability row to drift, and no verdict column
whose thresholds could go stale. A trust claim an operator cannot trace to an
observation row does not exist here: the old `set_capability` writer is gone
with the model that needed it.
"""
from __future__ import annotations

import hashlib
import time

import ingest

#: An account nobody has measured is untrusted: `ref_stable` False means the
#: provider's own reference is not used as identity and matching falls back
#: to the windowed heuristic. Trust is a per-installation property -- whether
#: THIS account's provider supplies references that are present and unique --
#: so there is no defensible global default and none is shipped. It is earned
#: from local observation: `capability()` below derives it from the
#: `ref_observations` evidence this installation recorded about its own
#: accounts, and from nothing else.
DEFAULT_CAPABILITY = {"ref_stable": False, "ref_scope": "unknown", "observed_n": 0}

#: A QUALIFYING deep observation needs this many distinct referenced
#: TRANSACTIONS (restatement bands, not raw rows -- 50 copies of one row are
#: one transaction) with zero measured reuse. Rationale (rule of three): zero
#: collisions among 100 transactions bounds the per-transaction reuse rate
#: below ~3% at 95% confidence. Not a tuning knob: a bank that cannot show
#: this in its own deep window keeps heuristic matching, which works and is
#: disclosed.
MIN_QUALIFYING_REF_TRANSACTIONS = 100

#: ... and the referenced transactions must span this many days. The
#: empirically observed reuse shape is RECURRENCE reuse -- a standing order
#: carrying one reference across occurrences -- and 180 days contains >= 6
#: occurrences of any monthly pattern and >= 26 of any weekly one, so if the
#: bank reuses references across recurrences the sample CONTAINS the
#: collision. The span floor is what gives "zero reuse observed" its meaning.
#: Numerically equal to flows.SHALLOW_SPAN_DAYS by coincidence of purpose, not
#: by reference: that constant says when a deep fetch is too shallow to be
#: worth calling deep, this one says when a silence is too short to mean
#: anything. They may legitimately diverge.
MIN_QUALIFYING_SPAN_DAYS = 180

#: The two evidence kinds. Only a 'deep' row -- written by a labelled,
#: completed deep-observation run -- can GRANT. A 'reuse_event' -- written by
#: any completed run whose measurement showed reuse -- can only demote.
#: Sample size bounds what silence proves, never what a sighting proves.
OBSERVATION_KINDS = ("deep", "reuse_event")

_SCOPES = ("account", "unknown")
_FP_KEY = "provenance_fp"
_FP_AT_KEY = "provenance_recorded_at"


def _key_fingerprint(key_pem: str) -> str:
    """Digest the PEM body, never the key.

    The armor lines and all whitespace are stripped first, so a re-wrapped or
    CRLF-converted copy of the same key is not mistaken for a rotation. The
    body itself is never stored, logged, or returned.
    """
    body = "".join(ln.strip() for ln in (key_pem or "").splitlines()
                   if ln.strip() and not ln.strip().startswith("-----"))
    if not body:
        raise ValueError("no key material to fingerprint")
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def fingerprint(app_id: str, key_pem: str, host_id: str) -> str:
    """Fingerprint the environment the ledger belongs to.

    A restored Home Assistant backup can carry a stale app id, sit on a
    different host, or pair with a rotated 1Password key; any of the three
    changes this value.
    """
    parts = ("fpv1", (app_id or "").strip(), _key_fingerprint(key_pem),
             (host_id or "").strip())
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def record(conn, fp: str) -> None:
    if not fp or len(fp) != 64:
        raise ValueError("a provenance fingerprint is a 64-character digest")
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                 (_FP_KEY, fp))
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                 (_FP_AT_KEY, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))


def check(conn, fp: str) -> dict:
    """Compare the live environment against what this ledger last recorded.

    `fresh` means nothing has been recorded yet — a first run, not a fault.
    `mismatch` means report it to the operator; it does not itself decide what
    to do about it.
    """
    row = conn.execute("SELECT value FROM meta WHERE key=?", (_FP_KEY,)).fetchone()
    if row is None:
        return {"state": "fresh", "recorded": None}
    recorded = str(row[0])
    return {"state": "match" if recorded == fp else "mismatch",
            "recorded": recorded}


def _norm(aspsp: str) -> str:
    return " ".join((aspsp or "").split()).upper()


def measure_references(fetched) -> dict:
    """Reduce one completed run's fetched rows to reference-behaviour metrics.

    Pure, like ingest. `fetched` is the run's NORMALISED rows
    (`ingest.normalise` output); nothing stored participates, so the
    measurement describes exactly what the provider said in this one run.

    The unit is the TRANSACTION, not the row. Rows sharing a `provider_ref`
    are grouped by `identity_key` and then banded by booking date with
    ingest's own restatement bound (`AMOUNT_ONLY_MATCH_WINDOW_DAYS`, anchored
    on the earliest date, exactly as rule 1 collapses restatements) -- N
    identical copies of one page are one transaction. Counting raw rows
    instead let 50 restatements of each of two transactions read as a 100-row
    sample; the whole threshold would then measure the provider's appetite
    for restating, not the stability of its references.

    * `ref_transactions` counts distinct `(provider_ref, identity_key, band)`
      groups whose rows carry `provider_ref_kind == "entry_reference"` -- the
      `transaction_id` fallback never counts toward the QUALIFYING sample,
      because what is being earned is entry_reference trust and a bank
      supplying only the fallback has shown nothing about it.
    * `reused_refs` counts `provider_ref` values (ANY kind) carried by more
      than one such group: restatements are one transaction; a standing order
      sharing one reference across occurrences is reuse -- the precise shape
      rule 1's collapse comments name as the catastrophic one.
    * `span_days` is measured over the BAND-ANCHOR dates of the
      entry-reference transactions, so the same restatement inflation cannot
      stretch it.
    """
    by_ref: dict = {}
    for f in fetched:
        if f.get("provider_ref"):
            by_ref.setdefault(f["provider_ref"], []).append(f)
    reused = 0
    anchors = []
    for ref in by_ref:
        groups = 0
        by_ident: dict = {}
        for f in by_ref[ref]:
            by_ident.setdefault(ingest.identity_key(f), []).append(f)
        for ident in by_ident:
            items = sorted(by_ident[ident], key=lambda r: r["booking_date"])
            bands: list = []
            for f in items:
                if bands and ingest._days(
                        bands[-1][0]["booking_date"],
                        f["booking_date"]) <= ingest.AMOUNT_ONLY_MATCH_WINDOW_DAYS:
                    bands[-1].append(f)
                else:
                    bands.append([f])
            groups += len(bands)
            for band in bands:
                if any(b.get("provider_ref_kind") == "entry_reference"
                       for b in band):
                    anchors.append(band[0]["booking_date"])
        if groups > 1:
            reused += 1
    span = ingest._days(min(anchors), max(anchors)) if len(anchors) >= 2 else 0
    return {"rows_total": len(fetched), "ref_transactions": len(anchors),
            "distinct_refs": len(by_ref), "reused_refs": reused,
            "span_days": span}


def record_observation(conn, *, account_id: str, incarnation, aspsp: str,
                       session_id, kind: str, window_days: int, metrics: dict,
                       source: str = "") -> bool:
    """File one evidence row. Append-only; returns whether a row was written.

    Runs inside the CALLER's transaction (flows opens it around the plan
    application) and never opens one of its own: an evidence row must commit
    atomically with the rows of the run that measured it, or a run that
    demotes exists briefly with its rows committed and its demotion not --
    which is exactly the window a concurrent trusted plan revalidates in.

    THE GUARD IS THE ACCOUNT'S INCARNATION, NOT ITS EXISTENCE. `account_id`
    is a deterministic HMAC of IBAN+currency (`store.account_id`), so
    forget-then-relink recreates the SAME id -- a bare existence check would
    let a run paused across the erasure attach its stale evidence to the new
    incarnation. The single INSERT...SELECT is atomic under SQLite's write
    lock: either the incarnation the run captured at its start is still the
    live one and the row lands, or nothing is written and the caller's run
    simply leaves no evidence -- the fail-closed direction, since absent
    evidence never grants.
    """
    if kind not in OBSERVATION_KINDS:
        raise ValueError("kind must be one of %r" % (list(OBSERVATION_KINDS),))
    if not account_id:
        raise ValueError("an observation needs the account it measured")
    fields = ("rows_total", "ref_transactions", "distinct_refs",
              "reused_refs", "span_days")
    values = []
    for name in fields:
        n = int(metrics[name])
        if n < 0:
            raise ValueError("%s cannot be negative" % name)
        values.append(n)
    cur = conn.execute(
        "INSERT INTO ref_observations(account_id, aspsp, session_id, kind,"
        " source, observed_at, window_days, rows_total, ref_transactions,"
        " distinct_refs, reused_refs, span_days)"
        " SELECT ?,?,?,?,?,?,?,?,?,?,?,?"
        " WHERE EXISTS (SELECT 1 FROM accounts WHERE account_id=?"
        " AND incarnation=?)",
        (account_id, _norm(aspsp), session_id, kind, source or "",
         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         int(window_days), *values, account_id, incarnation))
    return bool(cur.rowcount)


def capability(conn, aspsp: str, account_id: str) -> dict:
    """What this installation's own evidence says about ONE account's
    references -- derived at read time, never cached.

    The verdict comes from the metrics and the current constants, so the
    stored record never carries a conclusion that outlives the reasoning:

    * any evidence row with measured reuse makes the account UNSTABLE --
      untrusted, whatever else was observed, in whatever order. A sighting is
      positive evidence at any sample size.
    * absent that, one QUALIFYING deep observation grants: `kind='deep'`,
      zero reuse, and the sample floors above.
    * everything else is insufficient and changes nothing in either
      direction, which is what keeps a nine-day run or a thin re-link from
      revoking trust a bank legitimately earned.

    Only evidence recorded under the account's CURRENT normalised ASPSP name
    counts; `capability_warning` reports the drift when that excludes
    everything.

    An unmeasured account reads as DEFAULT_CAPABILITY -- untrusted -- and the
    caller learns *why* from capability_warning(), not from an extra key here.
    The three keys ARE the contract, so the shape does not grow: ingest
    reads this dict BY KEY, never as a whole. `ingest.ref_trusted` tests
    `ref_stable` and `ref_scope == "account"` directly and nothing in ingest
    compares the returned dict against DEFAULT_CAPABILITY -- that constant is
    the value returned HERE for an unmeasured account, not a sentinel the
    caller matches on -- so a fourth key added here would be read by nothing.
    """
    rows = conn.execute(
        "SELECT kind, ref_transactions, reused_refs, span_days"
        " FROM ref_observations WHERE account_id=? AND aspsp=?",
        (account_id, _norm(aspsp))).fetchall()
    best = 0
    for row in rows:
        if int(row[2]) > 0:                      # reused_refs: unstable
            return dict(DEFAULT_CAPABILITY)
        if (str(row[0]) == "deep"
                and int(row[1]) >= MIN_QUALIFYING_REF_TRANSACTIONS
                and int(row[3]) >= MIN_QUALIFYING_SPAN_DAYS):
            best = max(best, int(row[1]))
    if not best:
        return dict(DEFAULT_CAPABILITY)          # a copy; the default is shared
    return {"ref_stable": True, "ref_scope": "account", "observed_n": best}


def capability_warning(conn, aspsp: str, account_id: str):
    """None when this account's evidence resolves; a reportable sentence
    when it does not.

    An unresolved lookup must be REPORTED, not silently downgraded.
    The downgrade itself is correct and stays -- an unmeasured account is
    untrusted -- but from the inside a spelling drift (the account row now
    carries "ABN-AMRO" while the evidence was recorded under "ABN AMRO", or
    an empty string because nothing recorded the name) is indistinguishable
    from an account that was never measured, and the two are not the same
    event. One is the design working as intended; the other is a silent,
    permanent loss of reference identity for an account we actually measured.

    Measured-and-insufficient and measured-and-unstable return None here:
    those are the design working, and the sync-note lines flows writes when
    trust changes are what carry the events.

    Callers surface this string to the operator. They must NOT use it to widen
    trust: the answer to a drift is to fix the name, never to trust the
    reference anyway.
    """
    key = _norm(aspsp)
    if not key:
        return ("No ASPSP name is recorded for this account, so provider "
                "references cannot be trusted and every row falls back to "
                "heuristic date matching. Re-link the bank so the "
                "account records which institution it belongs to.")
    recorded = [str(r[0]) for r in conn.execute(
        "SELECT DISTINCT aspsp FROM ref_observations WHERE account_id=?"
        " ORDER BY aspsp", (account_id,))]
    if not recorded:
        return ("%r has never been measured on this account, so its provider "
                "references are not trusted and every row falls back to "
                "heuristic date matching. A deep observation runs "
                "automatically the next time this bank is linked or renewed."
                % (aspsp,))
    if key in recorded:
        return None
    return ("%r has reference evidence recorded under a different bank name "
            "(%s), so its provider references are not trusted and every row "
            "falls back to heuristic date matching. That is a naming drift "
            "to fix -- not a new bank." % (aspsp, ", ".join(recorded)))
