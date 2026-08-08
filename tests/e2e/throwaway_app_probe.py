# tests/e2e/throwaway_app_probe.py
"""LIVE probe: create_application against a THROWAWAY, then delete it.

Run manually, on purpose, with real credentials:

    RUN_EB_LIVE=1 python3 tests/e2e/throwaway_app_probe.py

with a 1Password service-account token already loaded into the environment.

Never touches a production application. Deletion uses a LOCAL client defined here —
DELETE is deliberately absent from eb_admin.ALLOW and stays that way; a
probe cleaning up its own throwaway is the one legitimate use and it does
not get to ride the production module to do it.
"""
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]
                       / "plugins/bank-feed/server"))

import eb_admin    # noqa: E402
import httpx       # noqa: E402
import jwtsign     # noqa: E402
import opvault     # noqa: E402

if os.environ.get("RUN_EB_LIVE") != "1":
    raise SystemExit("refusing: set RUN_EB_LIVE=1 to run this live probe")

NAME = "casa-finance-probe-%d" % int(time.time())

# The SANDBOX key's public half backs the throwaway — the same public key may
# back multiple applications, and the production key stays out of probe
# traffic. The vault comes from BANKFEED_OP_VAULT like every other reference; a
# hardcoded name would make this recipe runnable only for whoever wrote it.
key = jwtsign.load_pkcs8(opvault.read(
    "op://%s/EnableBanking Key Sandbox/private key" % opvault.VAULT))
spki = jwtsign.public_spki_pem(key)

admin = eb_admin.from_env()
before = {str(a.get("app_id") or a.get("kid")): a.get("name")
          for a in admin.applications()}
assert not any(n == NAME for n in before.values())

app_id = None
try:
    app_id = admin.create_application(NAME, spki,
                                      ["https://example.invalid/probe"],
                                      environment="SANDBOX")
    print("created:", app_id)
    after = {str(a.get("app_id") or a.get("kid")): a.get("name")
             for a in admin.applications()}
    assert after.get(app_id) == NAME, (app_id, after)
    print("listed: OK (name matches)")
finally:
    # Cleanup targets come ONLY from a fresh listing filtered by the unique
    # timestamped NAME — never from the create response. An anomalous response
    # could name an EXISTING application, including the real casa-finance, and
    # deleting the returned id would kill it; and a LOST response does not mean
    # no app was created. A throwaway left on the real account is residue this
    # probe must not leak; an id the response merely CLAIMED is not this
    # probe's to delete.
    try:
        doomed = [str(a.get("app_id") or a.get("kid"))
                  for a in admin.applications() if a.get("name") == NAME]
    except Exception:
        # The cleanup listing itself failed after a create may have happened:
        # leave the operator an actionable instruction naming the exact
        # throwaway, then let the failure surface.
        print("CLEANUP LISTING FAILED — check the control panel NOW for "
              "any application named %r and delete it by hand" % NAME)
        raise
    # Local DELETE client — see module docstring.
    deleter = httpx.Client(eb_admin.CP_HOST,
                           {("DELETE", r"^/api/applications$")})
    for aid in doomed:
        status, _ = deleter.request(
            "DELETE", "/api/applications",
            headers={"Authorization": "Bearer " + admin._bearer()},
            json_body={"appId": aid})
        print("delete", aid, "status:", status)
        assert status < 400, ("DELETE failed — remove %r (%s) in the "
                              "control panel by hand NOW" % (NAME, aid))

final = {a.get("name") for a in admin.applications()}
assert NAME not in final
print("probe complete: create -> list -> delete")
