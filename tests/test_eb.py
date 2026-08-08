# tests/test_eb.py
import datetime as dt
import json
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"))
import eb_ais            # noqa: E402
import eb_admin         # noqa: E402
import fbauth           # noqa: E402
import httpx            # noqa: E402

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
FROZEN = dt.datetime(2026, 8, 3, 12, 0, 0, tzinfo=dt.timezone.utc)


def fixture(name):
    return (FIX / name).read_bytes()


class StubClient:
    """Records calls and replays fixtures — but runs the REAL allowlist first,
    so a test can never exercise a path production would refuse."""

    def __init__(self, real, responses):
        self.real, self.responses, self.calls = real, responses, []

    def request(self, method, path, **kw):
        self.real._check(method, path)
        self.calls.append((method, path, kw))
        return self.responses.pop(0)


class TestAIS(unittest.TestCase):
    def setUp(self):
        self._real_now = eb_ais._now
        eb_ais._now = lambda: FROZEN

    def tearDown(self):
        eb_ais._now = self._real_now

    def _ais(self, responses):
        ais = eb_ais.AIS(app_id="app-1", key=None)
        ais.client = StubClient(ais.client, responses)
        ais._token = lambda: "fake.jwt.token"
        return ais

    def test_start_auth_requests_exactly_179_days(self):
        ais = self._ais([(200, b'{"url":"https://x/","authorization_id":"a"}')])
        ais.start_auth("Revolut", "NL", "business", "state123", "https://x/cb")
        _, _, kw = ais.client.calls[0]
        valid_until = kw["json_body"]["access"]["valid_until"]
        self.assertEqual(valid_until, "2027-01-29T12:00:00+00:00")
        self.assertEqual(
            (dt.datetime.fromisoformat(valid_until) - FROZEN).total_seconds(),
            179 * 86400)

    def test_exactly_180_days_is_refused_before_the_call_is_made(self):
        # The ceiling is 15 552 000 s == 180 days and the provider's check is
        # STRICT, so 180 is over it.
        self.assertEqual(eb_ais.CONSENT_CEILING_S, 180 * 86400)
        self.assertLess(eb_ais.CONSENT_DAYS * 86400, eb_ais.CONSENT_CEILING_S)
        ais = self._ais([])
        with self.assertRaises(ValueError):
            ais.start_auth("Revolut", "NL", "business", "s", "https://x/cb",
                           valid_days=180)
        self.assertEqual(ais.client.calls, [])

    def test_transactions_returns_one_page_and_its_continuation_key(self):
        ais = self._ais([(200, fixture("transactions_page1.json"))])
        rows, key = ais.transactions("uid-1", "2018-08-25")
        self.assertEqual(len(rows), 3)
        self.assertEqual(key, "page-2-of-2")
        self.assertIsNone(rows[1].get("entry_reference"))

    def test_continuation_key_is_sent_on_the_next_page(self):
        page2 = json.dumps({"transactions": []}).encode()
        ais = self._ais([(200, page2)])
        rows, key = ais.transactions("uid-1", "2018-08-25", "page-2-of-2")
        self.assertEqual((rows, key), ([], None))
        path = ais.client.calls[0][1]
        self.assertIn("date_from=2018-08-25", path)
        self.assertIn("continuation_key=page-2-of-2", path)

    def test_session_accounts_nest_the_iban_under_account_id(self):
        """The recorded shape. Reading a flat account["iban"] finds nothing —
        that is a production false negative."""
        ais = self._ais([(200, fixture("session_revolut.json"))])
        session = ais.get_session("11111111-2222-4333-8444-555555555555")
        account = session["accounts"][0]
        self.assertEqual(account["account_id"]["iban"], "NL00REVO0000000001")
        self.assertNotIn("iban", account)

    def test_aspsps_are_unwrapped_from_the_recorded_shape(self):
        ais = self._ais([(200, fixture("aspsps_nl.json"))])
        banks = ais.aspsps("NL")
        self.assertEqual([b["name"] for b in banks],
                         ["Revolut", "ABN AMRO", "Rabobank"])
        self.assertEqual({b["maximum_consent_validity"] for b in banks},
                         {eb_ais.CONSENT_CEILING_S})

    def test_payments_are_not_reachable(self):
        ais = eb_ais.AIS(app_id="app-1", key=None)
        with self.assertRaises(httpx.NotAllowed):
            ais.client.request("POST", "/payments", json_body={})

    def test_a_non_idempotent_post_is_never_retried(self):
        """POST /sessions burns a one-shot code; a retry destroys the flow."""
        ais = self._ais([(500, b'{"message":"boom"}'),
                         (200, b'{"session_id":"s"}')])
        with self.assertRaises(eb_ais.ApiError):
            ais.create_session("code-1")
        self.assertEqual(len(ais.client.calls), 1)

    def test_error_carries_a_status_and_a_class_never_a_body_or_an_id(self):
        ais = self._ais([(403, b'{"message":"PROVIDER-PAYLOAD-MUST-NOT-LEAK"}')])
        with self.assertRaises(eb_ais.ApiError) as ctx:
            ais.get_session("session-id-must-not-leak")
        text = str(ctx.exception)
        self.assertNotIn("PROVIDER-PAYLOAD-MUST-NOT-LEAK", text)
        self.assertNotIn("session-id-must-not-leak", text)
        self.assertFalse(hasattr(ctx.exception, "body"))
        self.assertEqual((ctx.exception.status, ctx.exception.kind),
                         (403, "forbidden"))

    def test_allow_set_is_pinned(self):
        """A literal comparison to a frozen expected set, so any edit to a
        pattern -- widen, narrow, add, remove -- fails here on the spot
        rather than surviving until someone runs a manual pass. The
        pinned-refusal tests above only probe specific calls; this probes
        the whole allowlist at once."""
        self.assertEqual(eb_ais.ALLOW, {
            ("GET", r"^/application$"),
            ("GET", r"^/aspsps$"),
            ("POST", r"^/auth$"),
            ("POST", r"^/sessions$"),
            ("GET", r"^/sessions/[A-Za-z0-9-]+$"),
            ("DELETE", r"^/sessions/[A-Za-z0-9-]+$"),
            ("GET", r"^/accounts/[A-Za-z0-9-]+/balances$"),
            ("GET", r"^/accounts/[A-Za-z0-9-]+/transactions$"),
        })

    def test_a_query_string_in_a_trailing_identifier_is_refused(self):
        """`httpx.Client._check` strips a path at its FIRST `?` before
        matching, so `sid="abc?x=1"` would otherwise truncate the checked
        path to the allowlisted `/sessions/abc`, turning `?x=1` into an
        unchecked query string. Validating the identifier before
        interpolation closes this without touching the allowlist or
        httpx.py itself."""
        ais = self._ais([])
        with self.assertRaises(ValueError):
            ais.get_session("abc?x=1")
        self.assertEqual(ais.client.calls, [])


class TestRevocationIsFinal(unittest.TestCase):
    """The finality rule, tested where it is DEFINED so both callers inherit
    one answer.

    The rule used to live in `tools_auth`, above `flows` in the import graph,
    so the renewal path could not reach it and answered differently. These
    tests are the shared contract `flows._revoke` and
    `tools_destructive.unlink_bank` both stand on.
    """

    def _api(self, status):
        return eb_ais.ApiError(status, "delete_session")

    def test_only_a_404_proves_the_consent_is_gone(self):
        exc = self._api(404)
        self.assertEqual(exc.kind, "not_found")
        self.assertTrue(eb_ais.revocation_is_final(exc))

    def test_nothing_that_merely_failed_counts_as_revoked(self):
        """A 429, a 5xx, a 401 and a 403 all leave the grant very probably LIVE
        at the bank. Treating "we could not tell" as "it is gone" closes the
        local row and takes the operator's only retry handle with it."""
        for status in (401, 403, 429, 500, 502, 400, 409, 422):
            with self.subTest(status=status):
                self.assertFalse(eb_ais.revocation_is_final(self._api(status)))

    def test_a_transport_failure_is_not_an_api_error_at_all(self):
        """A dropped socket or a read timeout never reaches `ApiError`, so the
        predicate must reject it on the isinstance rather than on the kind."""
        self.assertFalse(eb_ais.revocation_is_final(OSError("connection reset")))
        self.assertFalse(eb_ais.revocation_is_final(TimeoutError("slow")))


class TestAdmin(unittest.TestCase):
    def _admin(self, responses):
        admin = eb_admin.Admin(token="t")
        admin.client = StubClient(admin.client, responses)
        return admin

    def test_link_accounts_uses_form_encoding_and_the_fixed_redirect(self):
        admin = self._admin([(200, b'{"url":"https://tilisy/","authorization_id":"a"}')])
        admin.link_accounts("app-1", "ABN AMRO", "NL", "personal")
        method, path, kw = admin.client.calls[0]
        self.assertEqual((method, path), ("POST", "/api/link_accounts"))
        self.assertIsNone(kw.get("json_body"))
        self.assertEqual(kw["form_body"]["redirectUrl"],
                         "https://enablebanking.com/api/auth_redirect")
        self.assertEqual(kw["form_body"]["psuType"], "personal")
        self.assertEqual(kw["form_body"]["appId"], "app-1")

    def test_whitelisted_reads_the_admin_only_field(self):
        record = {"app_id": "app-1", "active": True,
                  "whitelisted_accounts": [
                      {"aspsp": {"name": "Revolut", "country": "NL"},
                       "title": "IBAN NL00REVO0000000001",
                       "identification_hash": "H1"}]}
        admin = self._admin([(200, json.dumps(record).encode())])
        entries = admin.whitelisted("app-1")
        self.assertEqual(admin.client.calls[0][1], "/api/application/app-1")
        self.assertEqual([e["identification_hash"] for e in entries], ["H1"])
        # It is exposed ONLY on the admin API — the app-key GET /application
        # does not carry it, so AIS must not offer this at all.
        self.assertFalse(hasattr(eb_ais.AIS, "whitelisted"))

    def test_add_redirect_url_is_a_noop_when_already_registered(self):
        """Idempotent: the URI is already present, so change nothing and
        make no write request."""
        record = {"app_id": "app-1", "name": "casa-finance",
                  "redirect_urls": ["https://existing/one",
                                    "https://public.example/callback/plg-bank-feed--authorize"],
                  "whitelisted_accounts": [{"identification_hash": "H1"}]}
        admin = self._admin([(200, json.dumps(record).encode())])
        result = admin.add_redirect_url(
            "app-1", "https://public.example/callback/plg-bank-feed--authorize")
        self.assertEqual(result, {
            "changed": False,
            "redirect_urls": record["redirect_urls"]})
        # Exactly the one GET used to check -- no PATCH, no second call.
        self.assertEqual(len(admin.client.calls), 1)
        self.assertEqual(admin.client.calls[0][:2], ("GET", "/api/application/app-1"))

    def test_add_redirect_url_writes_the_complete_object_when_absent(self):
        record = {"app_id": "app-1", "name": "casa-finance",
                  "redirect_urls": ["https://existing/one"],
                  "active": True,
                  "whitelisted_accounts": [{"identification_hash": "H1"}]}
        admin = self._admin([
            (200, json.dumps(record).encode()),
            (200, b'{"status":"OK","isApplicationUpdated":true}')])
        result = admin.add_redirect_url(
            "app-1", "https://public.example/callback/plg-bank-feed--authorize")
        self.assertEqual(result, {
            "changed": True,
            "redirect_urls": ["https://existing/one",
                              "https://public.example/callback/plg-bank-feed--authorize"]})
        self.assertEqual(len(admin.client.calls), 2)
        method, path, kw = admin.client.calls[1]
        self.assertEqual((method, path), ("PATCH", "/api/applications"))
        body = kw["json_body"]
        # appId in the BODY, not the path; never the pre-existing app_id key.
        self.assertEqual(body["appId"], "app-1")
        self.assertNotIn("app_id", body)
        # Existing entries preserved, ours appended -- the COMPLETE desired set.
        self.assertEqual(body["redirect_urls"], [
            "https://existing/one",
            "https://public.example/callback/plg-bank-feed--authorize"])
        # whitelisted_accounts is read-only; must never be echoed back.
        self.assertNotIn("whitelisted_accounts", body)
        # Every other field round-trips unchanged.
        self.assertEqual(body["name"], "casa-finance")
        self.assertIs(body["active"], True)

    def test_add_redirect_url_round_trips_the_production_fields(self):
        """A production PATCH that omits description/gdpr_email/privacy_url/
        terms_url fails with "Description must be set". All
        four must be echoed back untouched, not hand-picked."""
        record = {"app_id": "app-2", "name": "casa-finance",
                  "redirect_urls": [],
                  "description": "Personal finance aggregation",
                  "gdpr_email": "privacy@example.com",
                  "privacy_url": "https://example.com/privacy",
                  "terms_url": "https://example.com/terms",
                  "whitelisted_accounts": []}
        admin = self._admin([
            (200, json.dumps(record).encode()),
            (200, b'{"status":"OK","isApplicationUpdated":true}')])
        admin.add_redirect_url("app-2", "https://public.example/callback/plg-bank-feed--authorize")
        body = admin.client.calls[1][2]["json_body"]
        self.assertEqual(body["description"], "Personal finance aggregation")
        self.assertEqual(body["gdpr_email"], "privacy@example.com")
        self.assertEqual(body["privacy_url"], "https://example.com/privacy")
        self.assertEqual(body["terms_url"], "https://example.com/terms")

    def test_add_redirect_url_error_carries_no_provider_body_or_credential(self):
        record = {"app_id": "app-1", "name": "casa-finance", "redirect_urls": []}
        admin = self._admin([
            (200, json.dumps(record).encode()),
            (500, b'{"message":"CP-PAYLOAD-MUST-NOT-LEAK","token":"tok-must-not-leak"}')])
        with self.assertRaises(eb_admin.AdminError) as ctx:
            admin.add_redirect_url("app-1", "https://public.example/callback/plg-bank-feed--authorize")
        text = str(ctx.exception)
        self.assertNotIn("CP-PAYLOAD-MUST-NOT-LEAK", text)
        self.assertNotIn("tok-must-not-leak", text)
        self.assertFalse(hasattr(ctx.exception, "body"))
        self.assertFalse(hasattr(ctx.exception, "token"))
        self.assertEqual((ctx.exception.status, ctx.exception.kind), (500, "provider_error"))

    def test_create_application_posts_the_verified_shape(self):
        admin = self._admin([(200, b'{"app_id": "app-new"}')])
        app_id = admin.create_application(
            "casa-finance", "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n",
            ["https://casa.example/callback/plg-bank-feed--authorize"])
        self.assertEqual(app_id, "app-new")
        method, path, kw = admin.client.calls[0]
        self.assertEqual((method, path), ("POST", "/api/applications"))
        self.assertEqual(kw["json_body"], {
            "certificate": "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n",
            "environment": "PRODUCTION",
            "name": "casa-finance",
            "redirect_urls": ["https://casa.example/callback/plg-bank-feed--authorize"],
        })

    def test_create_application_refuses_a_response_without_an_app_id(self):
        # A 200 with no app_id would let setup "succeed" and store nothing;
        # the invariant (key -> app -> STORED id) dies right there.
        admin = self._admin([(200, b'{"status": "OK"}')])
        with self.assertRaises(RuntimeError):
            admin.create_application("casa-finance", "PEM", ["https://x/cb"])

    def test_delete_remains_impossible(self):
        # POST is open, narrowly. DELETE stays out of ALLOW — an
        # application delete orphans every session riding it, and no
        # reconcile rung is allowed to hold that power.
        admin = self._admin([])
        with self.assertRaises(httpx.NotAllowed):
            admin.client.request("DELETE", "/api/applications",
                                 headers={}, json_body={"appId": "x"})

    def test_delete_is_still_impossible_and_post_is_only_the_collection(self):
        """POST /api/applications is open narrowly, for registration.
        DELETE stays out permanently -- an application delete
        orphans every session riding it, and no reconcile rung is allowed
        to hold that power."""
        admin = eb_admin.Admin(token="t")
        self.assertIn(("POST", r"^/api/applications$"), eb_admin.ALLOW)
        with self.assertRaises(httpx.NotAllowed):
            admin.client.request("DELETE", "/api/applications", json_body={})
        self.assertFalse(any(method == "DELETE" for method, _pattern in eb_admin.ALLOW))
        post_patterns = {pattern for method, pattern in eb_admin.ALLOW if method == "POST"}
        self.assertEqual(post_patterns, {
            r"^/api/applications$",
            r"^/api/link_accounts$",
            r"^/api/unlink_accounts$",
        })

    def test_no_call_can_mutate_a_single_application(self):
        """The plural /api/applications probe above never exercises the
        singular /api/application/{id} pattern -- PATCH there replaces
        redirect_urls wholesale and DELETE deregisters the application, so
        both are probed directly against the endpoint they would actually
        hit."""
        admin = eb_admin.Admin(token="t")
        for method in ("PATCH", "DELETE"):
            with self.assertRaises(httpx.NotAllowed):
                admin.client.request(method, "/api/application/app-1", json_body={})

    def test_allow_set_is_pinned(self):
        """Same rationale as eb_ais's pinned-set test: a literal comparison
        that fails the instant a pattern drifts, since with no integration
        integration test, this suite is the entire regression guard."""
        self.assertEqual(eb_admin.ALLOW, {
            ("GET", r"^/api/applications$"),
            ("GET", r"^/api/application/[A-Za-z0-9-]+$"),
            ("PATCH", r"^/api/applications$"),
            ("POST", r"^/api/applications$"),
            ("POST", r"^/api/link_accounts$"),
            ("POST", r"^/api/unlink_accounts$"),
        })

    def test_admin_cannot_reach_the_ais_host(self):
        admin = eb_admin.Admin(token="t")
        with self.assertRaises(httpx.NotAllowed):
            admin.client.request("GET", "/application")

    def test_admin_error_carries_a_status_and_a_class_never_a_body(self):
        admin = self._admin([(401, b'{"message":"CP-PAYLOAD-MUST-NOT-LEAK"}')])
        with self.assertRaises(eb_admin.AdminError) as ctx:
            admin.application("app-1")
        self.assertNotIn("CP-PAYLOAD-MUST-NOT-LEAK", str(ctx.exception))
        self.assertFalse(hasattr(ctx.exception, "body"))
        self.assertEqual((ctx.exception.status, ctx.exception.kind),
                         (401, "unauthorized"))


class TestAdminFromEnv(unittest.TestCase):
    """Production must construct its one Admin client from the SAME env var
    name the manifest declares. An admin client that reads an undeclared name
    (`CASA_BANKFEED_EB_ADMIN_TOKEN`) while the manifest declares
    `CASA_BANKFEED_EB_CP_TOKEN` means production can never
    populate the token the code actually read, so tap 1 (whitelisting) could
    never start. These tests set ONLY the declared name; setting the old
    undeclared one here would silently reproduce the exact defect that hid
    behind a green suite last time."""

    def setUp(self):
        self._had = os.environ.pop("CASA_BANKFEED_EB_CP_TOKEN", None)
        self.addCleanup(setattr, eb_admin, "opvault", eb_admin.opvault)
        eb_admin.opvault = FakeVaultModule(reason="op not installed")
        self.addCleanup(setattr, eb_admin, "_MINTER", None)

    def tearDown(self):
        if self._had is not None:
            os.environ["CASA_BANKFEED_EB_CP_TOKEN"] = self._had
        else:
            os.environ.pop("CASA_BANKFEED_EB_CP_TOKEN", None)

    def test_from_env_reads_the_declared_token_name(self):
        os.environ["CASA_BANKFEED_EB_CP_TOKEN"] = "cp-token-value"
        admin = eb_admin.from_env()
        self.assertEqual(admin.token, "cp-token-value")

    def test_from_env_refuses_loudly_when_unset(self):
        with self.assertRaises(eb_admin.AdminTokenMissing):
            eb_admin.from_env()

    def test_the_env_var_eb_admin_reads_is_the_one_the_manifest_declares(self):
        """The authoritative check: read `.mcp.json` directly rather than
        hard-coding the name a second time, so a future rename on either
        side is CAUGHT here instead of silently drifting apart again -- this
        is precisely the check whose absence let the two names diverge."""
        mcp_json = json.loads((pathlib.Path(__file__).resolve().parents[1] /
                               "plugins/bank-feed/.mcp.json").read_text())
        declared_env_vars = set(mcp_json["mcpServers"]["bank-feed"]["env"])
        self.assertIn(eb_admin.ENV_TOKEN_VAR, declared_env_vars)
        self.assertEqual(eb_admin.ENV_TOKEN_VAR, "CASA_BANKFEED_EB_CP_TOKEN")


class FakeMinter:
    def __init__(self, tokens=("id-1", "id-2")):
        self.tokens = list(tokens)
        self.invalidated = 0
        self.served = 0

    def token(self):
        self.served += 1
        return self.tokens[0]

    def invalidate(self):
        self.invalidated += 1
        self.tokens.pop(0)


class TestAdminMinterBearer(unittest.TestCase):
    def _admin(self, minter, responses):
        admin = eb_admin.Admin(minter=minter)
        admin.client = StubClient(admin.client, list(responses))
        return admin

    def test_exactly_one_of_token_or_minter(self):
        with self.assertRaises(ValueError):
            eb_admin.Admin()
        with self.assertRaises(ValueError):
            eb_admin.Admin(token="t", minter=FakeMinter())

    def test_the_bearer_is_the_minters_token(self):
        minter = FakeMinter()
        admin = self._admin(minter, [(200, b'{"applications": []}')])
        admin.applications()
        _, _, kw = admin.client.calls[0]
        self.assertEqual(kw["headers"]["Authorization"], "Bearer id-1")

    def test_a_401_is_re_minted_exactly_once_and_succeeds(self):
        # The cached ID token can expire between the cache check and the
        # provider's clock; a 401 on a Bearer means the request was
        # REJECTED before acting, so one re-send is safe even for the
        # non-idempotent POSTs.
        minter = FakeMinter()
        admin = self._admin(minter, [(401, b"{}"),
                                     (200, b'{"applications": []}')])
        admin.applications()
        self.assertEqual(minter.invalidated, 1)
        self.assertEqual(len(admin.client.calls), 2)
        _, _, kw = admin.client.calls[1]
        self.assertEqual(kw["headers"]["Authorization"], "Bearer id-2")

    def test_a_second_401_raises_and_does_not_loop(self):
        minter = FakeMinter(tokens=("id-1", "id-2", "id-3"))
        admin = self._admin(minter, [(401, b"{}"), (401, b"{}")])
        with self.assertRaises(eb_admin.AdminError) as ctx:
            admin.applications()
        self.assertEqual(ctx.exception.status, 401)
        self.assertEqual(len(admin.client.calls), 2)

    def test_a_pasted_token_401_is_never_retried(self):
        admin = eb_admin.Admin(token="cp-token")
        admin.client = StubClient(admin.client, [(401, b"{}")])
        with self.assertRaises(eb_admin.AdminError):
            admin.applications()
        self.assertEqual(len(admin.client.calls), 1)


class TestMalformedIdTokenNeverReachesTheBearerHeader(unittest.TestCase):
    """The malformed-token boundary Admin+StubClient CAN reach.

    The real leak path is `urllib.request.Request`'s header validation
    inside `http.client.HTTPConnection.putheader`, which only runs AFTER
    `connect()` succeeds -- there is no seam to drive that with a stub, and
    exercising it for real would require a live socket. What IS testable
    end to end without a network is the guarantee that actually prevents
    the leak: `eb_admin.Admin`, wired to a REAL `fbauth.Minter` (not a
    fake), never even gets a bearer string to put in a header when the
    provider's id_token is malformed -- `Minter.token()` raises before
    `Admin._bearer()` returns, so the StubClient standing in for the CP
    host records zero calls."""

    def test_a_hostile_id_token_raises_before_any_bearer_header_is_built(self):
        hostile = "aaa.bbb.SECRET\nX-Leak: yes"

        class TokenStub:
            def __init__(self, real, responses):
                self.real, self.responses, self.calls = real, list(responses), []

            def request(self, method, path, **kw):
                self.real._check(method, path)
                self.calls.append((method, path, kw))
                return self.responses.pop(0)

        stub = TokenStub(
            httpx.Client(fbauth.TOKEN_HOST, fbauth.TOKEN_ALLOW),
            [(200, json.dumps({"id_token": hostile,
                               "expires_in": "3600"}).encode())])
        real_token_client = fbauth._token_client
        fbauth._token_client = lambda: stub
        self.addCleanup(setattr, fbauth, "_token_client", real_token_client)

        minter = fbauth.Minter(lambda: "rt-1")
        admin = eb_admin.Admin(minter=minter)
        admin.client = StubClient(admin.client, [])   # would IndexError if ever called
        with self.assertRaises(fbauth.AuthError) as ctx:
            admin.applications()
        self.assertEqual(ctx.exception.code, "MALFORMED_ID_TOKEN_IN_RESPONSE")
        self.assertNotIn("SECRET", str(ctx.exception))
        self.assertEqual(admin.client.calls, [])       # no header was ever built


class FakeVaultModule:
    """opvault as eb_admin consumes it — status/read/REF only."""

    REF_REFRESH_TOKEN = "op://ExampleVault/EnableBanking/refresh token"
    OpError = eb_admin.opvault.OpError

    def __init__(self, refresh=None, reason=None):
        self._refresh, self._reason = refresh, reason
        self.reads = 0

    def status(self):
        return self._reason

    def read(self, ref):
        assert ref == self.REF_REFRESH_TOKEN
        self.reads += 1
        if self._refresh is None:
            raise self.OpError('"refresh token" isn\'t a field')
        return self._refresh


class FakeFbModule:
    """fbauth as from_env consumes it: the Minter class and AuthError.
    `mint_ok` decides whether a constructed Minter's token() succeeds —
    False models a stored-but-REVOKED refresh token."""

    class AuthError(RuntimeError):
        def __init__(self, code):
            self.code = code
            super().__init__(code)

    def __init__(self, mint_ok=True):
        self.mint_ok = mint_ok
        self.built = []
        outer = self

        class _Minter:
            def __init__(self, read_refresh):
                outer.built.append(self)
                self._read = read_refresh

            def token(self):
                if not outer.mint_ok:
                    raise outer.AuthError("INVALID_REFRESH_TOKEN")
                return "id-minted"

            def invalidate(self):
                pass

        self.Minter = _Minter


class TestFromEnvLadder(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(),
                                 os.environ.update(self._env)))
        os.environ.pop(eb_admin.ENV_TOKEN_VAR, None)
        self.addCleanup(setattr, eb_admin, "opvault", eb_admin.opvault)
        self.addCleanup(setattr, eb_admin, "fbauth", eb_admin.fbauth)
        self.addCleanup(setattr, eb_admin, "_MINTER", None)
        eb_admin._MINTER = None
        eb_admin.fbauth = FakeFbModule()

    def test_rung_2_a_stored_MINTING_token_wins_even_over_the_env_token(self):
        # The ladder is ordered durable-first. The pasted token goes stale
        # within the hour; preferring it would silently reintroduce an
        # hourly-paste dependency.
        os.environ[eb_admin.ENV_TOKEN_VAR] = "cp-token"
        eb_admin.opvault = FakeVaultModule(refresh="rt-1")
        admin = eb_admin.from_env()
        self.assertIsNone(admin.token)
        self.assertIsNotNone(admin.minter)

    def test_a_stored_but_REVOKED_token_falls_through_to_the_env_token(self):
        # Adoption requires PROOF, not presence: a revoked stored token must
        # not shadow a working pasted token. The failed candidate must not be
        # retained as the singleton either.
        os.environ[eb_admin.ENV_TOKEN_VAR] = "cp-token"
        eb_admin.opvault = FakeVaultModule(refresh="rt-revoked")
        eb_admin.fbauth = FakeFbModule(mint_ok=False)
        admin = eb_admin.from_env()
        self.assertEqual(admin.token, "cp-token")
        self.assertIsNone(eb_admin._MINTER)

    def test_no_stored_refresh_falls_back_to_the_declared_env_token(self):
        os.environ[eb_admin.ENV_TOKEN_VAR] = "cp-token"
        eb_admin.opvault = FakeVaultModule(refresh=None)
        admin = eb_admin.from_env()
        self.assertEqual(admin.token, "cp-token")

    def test_op_unusable_falls_back_to_the_declared_env_token(self):
        os.environ[eb_admin.ENV_TOKEN_VAR] = "cp-token"
        eb_admin.opvault = FakeVaultModule(reason="op not installed")
        admin = eb_admin.from_env()
        self.assertEqual(admin.token, "cp-token")

    def test_nothing_at_all_names_both_remedies(self):
        eb_admin.opvault = FakeVaultModule(refresh=None)
        with self.assertRaises(eb_admin.AdminTokenMissing) as ctx:
            eb_admin.from_env()
        text = str(ctx.exception)
        self.assertIn("setup_bank_feed", text)
        self.assertIn(eb_admin.ENV_TOKEN_VAR, text)

    def test_the_adopted_minter_is_a_process_singleton(self):
        # A fresh Minter per Admin would re-mint every tool call and
        # discard the ~55-minute cache.
        eb_admin.opvault = FakeVaultModule(refresh="rt-1")
        a = eb_admin.from_env()
        b = eb_admin.from_env()
        self.assertIs(a.minter, b.minter)
        self.assertEqual(len(eb_admin.fbauth.built), 1)

    def test_a_primed_minter_wins_and_skips_the_vault_probe(self):
        # prime_minter is the mechanism behind setup's "continue on the
        # in-memory credential" — the primed token was ALREADY proven by
        # setup, so no vault read and no re-proof happen here.
        vault = FakeVaultModule(refresh="rt-on-disk")
        eb_admin.opvault = vault
        eb_admin.prime_minter("rt-in-memory")
        admin = eb_admin.from_env()
        self.assertIsNotNone(admin.minter)
        self.assertEqual(vault.reads, 0)

    def test_a_dead_cached_minter_is_evicted_and_a_working_vault_token_adopted(self):
        # from_env returned Admin(minter=_MINTER) on mere EXISTENCE of the
        # cache. If the cached minter's refresh token was revoked (e.g. the
        # vault token rotated after adoption), every later from_env kept
        # returning the corpse -- a working rotated vault token was never
        # reached. Proving the cache (a cache-aware .token() call, free while
        # fresh) before trusting it is the fix.
        class DeadMinter:
            def token(self):
                raise eb_admin.fbauth.AuthError("INVALID_REFRESH_TOKEN")
        eb_admin._MINTER = DeadMinter()
        eb_admin.opvault = FakeVaultModule(refresh="rt-fresh")
        admin = eb_admin.from_env()
        self.assertIsNotNone(admin.minter)
        self.assertIsNone(admin.token)
        self.assertEqual(len(eb_admin.fbauth.built), 1)   # the fresh candidate

    def test_a_dead_cached_minter_falls_through_to_the_cp_token(self):
        # Same eviction, but the vault has nothing usable either -- the
        # ladder must still reach rung 3, not get stuck on the corpse.
        class DeadMinter:
            def token(self):
                raise eb_admin.fbauth.AuthError("INVALID_REFRESH_TOKEN")
        eb_admin._MINTER = DeadMinter()
        os.environ[eb_admin.ENV_TOKEN_VAR] = "cp-token"
        eb_admin.opvault = FakeVaultModule(refresh=None)
        admin = eb_admin.from_env()
        self.assertEqual(admin.token, "cp-token")
        self.assertIsNone(eb_admin._MINTER)

    def test_drop_minter_lets_a_revoked_process_fall_back(self):
        # setup drops the cached minter the moment it proves revocation -- the
        # next construction re-proves the vault token, fails, and lands on the
        # pasted token — instead of returning the cached corpse and 401-looping
        # on it forever.
        os.environ[eb_admin.ENV_TOKEN_VAR] = "cp-token"
        eb_admin.opvault = FakeVaultModule(refresh="rt-1")
        a = eb_admin.from_env()                    # adopts (mints OK)
        self.assertIsNotNone(a.minter)
        eb_admin.fbauth.mint_ok = False            # revoked upstream
        eb_admin.drop_minter()
        b = eb_admin.from_env()
        self.assertEqual(b.token, "cp-token")


if __name__ == "__main__":
    unittest.main()
