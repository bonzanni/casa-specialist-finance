#!/usr/bin/env python3
"""End-to-end rehearsal against the SANDBOX Enable Banking application.

SANDBOX ONLY — see tests/e2e/README.md. A production application holds live
consents against real accounts and must never be touched by this script. The
guard below reads the application's `environment` back from the live provider
(not a name anyone typed) and refuses to continue unless it reads "SANDBOX".

Not a unit test: it needs a live credential and one human tap (approving the
authorization and handing back the callback URL). Proves the wiring the unit
suite cannot, and asserts the idempotence property the whole ingest design
rests on.

TWO PHASES, which is the one deviation from the plan's script. The plan
called `input()` between minting the authorization and exchanging the code.
That assumes a terminal; here the human tap happens out of band, so the run
is split and the CSRF `state` is persisted between the halves:

    rehearsal.py start
    rehearsal.py finish '<the callback URL you were redirected to>'

`state` is written to CASA_E2E_STATE_FILE (default: alongside this file's
run directory) and compared on `finish` exactly as the single-process
version compared it in memory — the check is not weakened by the split, only
moved. Session identifiers are bearer-equivalent and are never
printed, here or anywhere else in the plugin.
"""
import json
import os
import pathlib
import secrets
import sys
import tempfile
from urllib.parse import parse_qs, urlparse

SERVER = pathlib.Path(__file__).resolve().parents[2] / "plugins/bank-feed/server"
sys.path.insert(0, str(SERVER))
import apply, eb_ais, flows, jwtsign, store  # noqa: E402

REDIRECT = os.environ.get("CASA_E2E_REDIRECT", "https://localhost/callback")
#: Which sandbox bank to link. `Mock ASPSP` returns `account_id = {}` — no
#: IBAN at all — and the ledger keys every account on HMAC(IBAN, currency),
#: so the mock cannot be linked at all. Pick a bank that exists in both the
#: sandbox and production, so the rehearsal exercises a real bank's payload
#: shape rather than a placeholder's.
ASPSP = os.environ.get("CASA_E2E_ASPSP", "Rabobank")
STATE_FILE = pathlib.Path(
    os.environ.get("CASA_E2E_STATE_FILE",
                   tempfile.gettempdir() + "/casa-e2e-state.json"))
DB_FILE = pathlib.Path(
    os.environ.get("CASA_E2E_DB", tempfile.gettempdir() + "/casa-e2e.sqlite"))


def _client():
    """Build the AIS client and REFUSE anything that is not the sandbox.

    The environment is read back from the live provider rather than trusted
    from a name someone exported, because the whole point of the guard is to
    survive a mistyped or stale APP_ID.
    """
    app_id = os.environ["CASA_BANKFEED_EB_APP_ID"]
    key = jwtsign.load_pkcs8(os.environ["CASA_BANKFEED_EB_PRIVATE_KEY"])
    ais = eb_ais.AIS(app_id, key)
    app = ais.application()
    if app.get("environment") != "SANDBOX":
        sys.exit(
            f"refusing to run against environment {app.get('environment')!r} — "
            "this script is SANDBOX ONLY. A production application holds live "
            "consents against real accounts and must never be touched by this "
            "script. Export the SANDBOX application's CASA_BANKFEED_EB_APP_ID "
            "and try again.")
    print(f"application {app['name']} ({app['environment']}) "
          f"active={app['active']}")
    return ais


def start():
    ais = _client()
    names = {(a["name"], a["country"]) for a in ais.aspsps("NL")}
    assert (ASPSP, "NL") in names, f"{ASPSP} missing from the sandbox"
    print(f"{len(names)} NL ASPSPs; linking {ASPSP!r}")

    state = secrets.token_urlsafe(32)
    auth = ais.start_auth(ASPSP, "NL", "personal", state, REDIRECT)
    STATE_FILE.write_text(json.dumps({"state": state}))
    STATE_FILE.chmod(0o600)
    print(f"\nOpen and approve (personal PSU):\n  {auth['url']}\n")
    print("then re-run:  rehearsal.py finish '<callback URL>'")


def finish(callback: str):
    ais = _client()
    state = json.loads(STATE_FILE.read_text())["state"]
    q = {k: v[0] for k, v in parse_qs(urlparse(callback).query).items()}
    assert q.get("state") == state, "state mismatch — refusing to exchange"

    session = ais.create_session(q["code"])
    # Persist the handle BEFORE anything can throw. A crash between here and
    # the revoke at the end leaves a live grant at the bank with no way to
    # withdraw it — the exact harm `delete_all_data` was rewritten to avoid,
    # and this script reproduced it on its first run. The file is 0600 and
    # local; the identifier is still never printed.
    STATE_FILE.write_text(json.dumps({"state": state,
                                      "session_id": session["session_id"]}))
    STATE_FILE.chmod(0o600)

    try:
        _ingest(ais, session)
    finally:
        # Revoke whatever happened. An exception between the exchange and the
        # revoke strands a grant at the bank — and `GET /sessions` is 405, so
        # there is no way to enumerate and clean up afterwards. The local
        # record is the ONLY handle, which is the
        # premise the whole revocation design rests on, confirmed live.
        ais.delete_session(session["session_id"])
        STATE_FILE.unlink(missing_ok=True)
        print("sandbox session revoked")


def _ingest(ais, session):
    accounts = session["accounts"]
    print(f"session established with {len(accounts)} account(s)")
    assert accounts, ("AUTHORIZED with zero accounts — the account is not "
                      "whitelisted")
    for i, a in enumerate(accounts):
        ident = a.get("account_id") or {}
        print(f"  account[{i}] top-level={sorted(a.keys())}")
        print(f"  account[{i}] identifiers={ident} "
              f"currency={a.get('currency')} usage={a.get('usage')}")
        print(f"  account[{i}] all_account_ids={a.get('all_account_ids')}")

    if DB_FILE.exists():
        DB_FILE.unlink()
    conn = store.open_db(DB_FILE)
    secret = store.local_secret(conn)
    acct = accounts[0]
    account_id, incarnation = apply.upsert_account(
        conn,
        {"uid": acct["uid"], "iban": (acct.get("account_id") or {}).get("iban"),
         "currency": acct.get("currency"), "name": acct.get("name"),
         "aspsp": ASPSP},
        session["session_id"], secret)

    def _tombstones() -> int:
        return conn.execute(
            "SELECT COUNT(*) FROM transactions WHERE account_id=? "
            "AND state='vanished'", (account_id,)).fetchone()[0]

    led = {"uid": acct["uid"], "account_id": account_id}
    first = flows.backfill(ais, conn, led, session["session_id"],
                           incarnation=incarnation)
    print(f"first ingest : inserted={first['inserted']} "
          f"proved={first['proved_from']}..{first['proved_to']} "
          f"shallow={first['shallow']} pages={first['pages']} "
          f"capped={first['capped']} completeness={first['completeness']}")
    if first["shallow"]:
        print("WARNING: shallow backfill — the deep-history window closed "
              "before the full span was proved")

    before = _tombstones()
    second = flows.backfill(ais, conn, led, session["session_id"],
                            incarnation=incarnation)
    after = _tombstones()
    print(f"re-ingest    : inserted={second['inserted']}")
    assert second["inserted"] == 0 and after == before, (
        "RE-INGEST WAS NOT IDEMPOTENT — this is the property the design "
        "rests on")
    print("re-ingest: 0 inserts, 0 tombstones — idempotent")
    print("coverage:", apply.merged_coverage(conn, account_id))

    # `_reconcile_balance_types` DELETES balance types absent from a response,
    # which is safe only if one response is the whole answer. True of
    # `eb_ais.AIS.balances` in this tree (no continuation key, no page cap),
    # and this is where that is observed against the live provider.
    raw = ais.balances(acct["uid"])
    print("L2 balances  : top-level keys =", sorted(raw.keys())
          if isinstance(raw, dict) else type(raw).__name__)
    print("L2 balances  : types =",
          [b.get("balance_type") for b in (raw.get("balances") or [])]
          if isinstance(raw, dict) else "n/a")

    print("ingest checks complete")


def revoke():
    """Withdraw a session left live by a crashed `finish`.

    Recovery only. `finish` revokes its own session on the happy path; this
    exists because a mid-run exception otherwise strands a grant at the bank
    with no handle to reach it by.
    """
    saved = json.loads(STATE_FILE.read_text())
    sid = saved.get("session_id")
    if not sid:
        sys.exit("no session_id recorded — nothing to revoke")
    _client().delete_session(sid)
    STATE_FILE.unlink(missing_ok=True)
    print("stranded sandbox session revoked")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "start":
        start()
    elif len(sys.argv) >= 3 and sys.argv[1] == "finish":
        finish(sys.argv[2])
    elif len(sys.argv) >= 2 and sys.argv[1] == "revoke":
        revoke()
    else:
        sys.exit("usage: rehearsal.py start | finish '<url>' | revoke")
