# plugins/bank-feed/server/provenance.py
"""Restore provenance and per-ASPSP reference capability.

Both live in the store's own tables: the fingerprint in `meta`, the capability
rows in `aspsp_capability`. Neither ever holds key material.

What is built is the restore *check* and its report. Re-validating
key<->application identity, re-checking session status against the provider and
marking cached data stale are NOT: a mismatch is reported, and the remedy is the
operator's.
"""
from __future__ import annotations

import hashlib
import time

#: An ASPSP nobody has measured is untrusted: `ref_stable` False means the
#: provider's own reference is not used as identity and matching falls back
#: to the windowed heuristic. Trust is a per-installation property -- whether
#: THIS account's provider supplies references that are present and unique --
#: so there is no defensible global default and none is shipped. Earning it
#: from local observation is issue #1.
DEFAULT_CAPABILITY = {"ref_stable": False, "ref_scope": "unknown", "observed_n": 0}

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


def capability(conn, aspsp: str) -> dict:
    """What this installation has recorded about an ASPSP's references.

    An unrecorded name reads as DEFAULT_CAPABILITY -- untrusted -- and the
    caller learns *why* from capability_warning(), not from an extra key here.
    The three keys ARE the contract, so the shape does not grow: ingest
    reads this dict BY KEY, never as a whole. `ingest.ref_trusted` tests
    `ref_stable` and `ref_scope == "account"` directly and nothing in ingest
    compares the returned dict against DEFAULT_CAPABILITY -- that constant is
    the value returned HERE for an unrecorded name, not a sentinel the caller
    matches on -- so a fourth key added here would be read by nothing.
    """
    row = conn.execute(
        "SELECT ref_stable, ref_scope, observed_n FROM aspsp_capability"
        " WHERE aspsp=?", (_norm(aspsp),)).fetchone()
    if row is None:
        return dict(DEFAULT_CAPABILITY)          # a copy; the default is shared
    return {"ref_stable": bool(row[0]), "ref_scope": str(row[1]),
            "observed_n": int(row[2])}


def set_capability(conn, aspsp: str, *, ref_stable: bool, ref_scope: str,
                   observed_n: int, provenance: str = "") -> None:
    """Record what was observed about an ASPSP, and where the claim came from.

    `provenance` is mandatory whenever `ref_stable` is True. A trust claim with
    no stated origin cannot be audited later, and cannot be retired when the
    bank's behaviour changes -- which is the whole reason this lives in the
    database as an observation rather than in the code as a constant.
    """
    key = _norm(aspsp)
    if not key:
        raise ValueError("aspsp must be a non-empty name")
    if ref_scope not in _SCOPES:
        raise ValueError("ref_scope must be one of %r, got %r"
                         % (list(_SCOPES), ref_scope))
    if ref_stable and ref_scope == "unknown":
        raise ValueError(
            "a reference cannot be trusted without the scope in which it was "
            "observed unique; per-account is assumed, global is never "
            "assumed")
    origin = (provenance or "").strip()
    if ref_stable and not origin:
        raise ValueError(
            "ref_stable=True needs a provenance saying what was observed and "
            "when; an unattributable trust claim cannot be audited or retired")
    n = int(observed_n)
    if n < 0:
        raise ValueError("observed_n cannot be negative")
    conn.execute(
        "INSERT OR REPLACE INTO aspsp_capability"
        "(aspsp, ref_stable, ref_scope, observed_n, provenance, updated_at)"
        " VALUES (?,?,?,?,?,?)",
        (key, 1 if ref_stable else 0, ref_scope, n, origin,
         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))


def capability_warning(conn, aspsp: str):
    """None when the name resolves; a reportable sentence when it does not.

    An unresolved ASPSP name must be REPORTED, not silently downgraded.
    The downgrade itself is correct and stays -- an unobserved ASPSP is
    untrusted -- but from the inside a spelling drift ("ABN-AMRO",
    "Revolut Business", or an empty string because nothing recorded the name)
    is indistinguishable from a genuinely new bank, and the two are not the
    same event. One is the design working as intended; the other is a silent,
    permanent loss of reference identity for a bank we actually measured.

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
    if conn.execute("SELECT 1 FROM aspsp_capability WHERE aspsp=?",
                    (key,)).fetchone():
        return None
    known = [r[0] for r in conn.execute(
        "SELECT aspsp FROM aspsp_capability ORDER BY aspsp")]
    return ("%r has no capability row, so its provider references are not "
            "trusted and every row falls back to heuristic date matching. "
            "Recorded ASPSPs: %s. If this bank was measured under "
            "a different spelling, that is a naming drift to fix -- not a new "
            "bank." % (aspsp, ", ".join(known) if known else "none"))
