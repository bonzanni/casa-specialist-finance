# tests/test_sandbox_mode.py
"""SANDBOX mode (sandbox-mode design, 2026-08-06): the world guard, the
mode-derived setup ladder, the credential-writer routing, and the
dispatcher banner/refusals.

Everything here runs with BANKFEED_EB_ENVIRONMENT=SANDBOX set per-case via
`SandboxBase.sandbox()` — the rest of the suite runs mode-unset and IS the
byte-identical detector for production. Dispatcher cases go through
`bank_feed_server.handle`, never the tool functions directly, because the
checks under test live at dispatch.
"""
import json
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import bank_feed_server  # noqa: E402
import ebmode  # noqa: E402
import store  # noqa: E402
import tools_auth  # noqa: E402

from _toolbase import (Base, FakeAIS, FakeAdmin, TEST_KEY_PEM,  # noqa: E402
                       call)

SANDBOX_APP = {"app_id": "app-1", "name": "casa-finance-sandbox",
               "environment": "SANDBOX", "active": True,
               "services": ["AIS"]}


class SandboxBase(Base):
    def sandbox(self):
        self.addCleanup(os.environ.pop, ebmode.ENV_MODE_VAR, None)
        self.addCleanup(ebmode._reset)
        os.environ[ebmode.ENV_MODE_VAR] = "SANDBOX"
        ebmode._reset()

    def sandbox_world(self):
        """The correctly wired sandbox install: provider answers describe
        the mode's own application, both views."""
        self.sandbox()
        self.admin.apps = [dict(SANDBOX_APP)]
        self.ais.app = dict(SANDBOX_APP)


class TestSetupLadder(SandboxBase):
    def test_registers_with_sandbox_environment_and_the_sandbox_name(self):
        self.sandbox_world()
        os.environ.pop("CASA_BANKFEED_EB_APP_ID", None)
        self.admin.apps = []                     # fresh account view
        out = call("setup_bank_feed")
        self.assertEqual(len(self.admin.create_calls), 1)
        name, _cert, _urls, environment = self.admin.create_calls[0]
        self.assertEqual(name, "casa-finance-sandbox")
        self.assertEqual(environment, "SANDBOX")
        self.assertIn("REGISTERED 'casa-finance-sandbox'", out)
        # Sandbox apps activate automatically: the production-only "starts
        # Inactive" sentence must not appear.
        self.assertIn("activated automatically", out)
        self.assertNotIn("starts Inactive", out)

    def test_a_production_app_with_the_sandbox_name_is_not_adopted(self):
        # The name-and-environment double match, mirror image of the
        # sandbox-not-adopted-in-production case.
        self.sandbox_world()
        os.environ.pop("CASA_BANKFEED_EB_APP_ID", None)
        self.admin.apps = [{"app_id": "app-x", "name": "casa-finance-sandbox",
                            "environment": "PRODUCTION"}]
        call("setup_bank_feed")
        self.assertEqual(len(self.admin.create_calls), 1)
        self.assertNotIn("app-x",
                         [c[0] for c in self.admin.redirect_calls])

    def test_a_sandbox_casa_finance_is_not_adopted_either(self):
        self.sandbox_world()
        os.environ.pop("CASA_BANKFEED_EB_APP_ID", None)
        self.admin.apps = [{"app_id": "app-y", "name": "casa-finance",
                            "environment": "SANDBOX"}]
        call("setup_bank_feed")
        self.assertEqual(len(self.admin.create_calls), 1)

    def test_env_wired_production_app_is_refused_before_meta_and_patch(self):
        # The guard fires BEFORE _meta_set and before the redirect rung can
        # PATCH — a copied production plugin-env.conf is exactly this input.
        # FakeAdmin's default apps list IS the production record.
        self.sandbox()
        out = call("setup_bank_feed")
        self.assertIn("refusing to touch application", out)
        self.assertIn("Stopping", out)
        self.assertEqual(self.admin.redirect_calls, [])
        self.assertEqual(self.admin.create_calls, [])
        self.assertIsNone(tools_auth._meta_get(self.raw, "setup.app_id"))

    def test_env_wired_sandbox_app_verifies_and_completes(self):
        self.sandbox_world()
        out = call("setup_bank_feed")
        self.assertIn("4. Application: %s resolved" % tools_auth.WIRE_APP_ID_VAR,
                      out)
        self.assertIn("healthy — SANDBOX, active", out)
        # Verified once, against the path-bound admin view.
        self.assertEqual(self.admin.application_calls, ["app-1"])

    def test_health_rung_mismatch_is_a_hard_stop_in_sandbox(self):
        # Rung 6 fails CLOSED in the new mode: the wired app verified as
        # sandbox at rung 4, but the AIS view answers as another world —
        # nothing may tell the operator to run link_bank.
        self.sandbox_world()
        self.ais.app = {"app_id": "app-1", "name": "casa-finance-sandbox",
                        "environment": "PRODUCTION", "active": True}
        out = call("setup_bank_feed")
        self.assertIn("not SANDBOX", out)
        self.assertIn("Stopping", out)
        self.assertNotIn("run list_banks", out)


class TestCredentialWriterRouting(SandboxBase):
    def _to_the_dance(self):
        # No stored refresh token and no stored email: the dance's first
        # rung, where the email argument is stored via the mode's writer.
        del self.vault.values[self.vault.REF_REFRESH_TOKEN]
        del self.vault.values[self.vault.REF_EMAIL]
        os.environ.pop(tools_auth.ADMIN_TOKEN_VAR, None)

    def test_sandbox_routes_the_email_store_through_upsert(self):
        self.sandbox_world()
        self._to_the_dance()
        call("bank_feed_signin", email="op@example.com")
        self.assertEqual([c[2] for c in self.vault.upsert_calls],
                         ["username"])
        self.assertEqual(self.vault.set_calls, [])

    def test_production_routes_through_upsert_too(self):
        # The fresh-production-vault durability gap closes the same way:
        # set_field is not a credential-rung writer in either mode.
        self._to_the_dance()
        call("bank_feed_signin", email="op@example.com")
        self.assertEqual([c[2] for c in self.vault.upsert_calls],
                         ["username"])
        self.assertEqual(self.vault.set_calls, [])


class TestWorldGuardAIS(SandboxBase):
    def test_ais_refuses_a_production_answer(self):
        # FakeAIS's default record IS the production application.
        self.sandbox()
        with self.assertRaises(tools_auth.WorldMismatch):
            tools_auth._ais()

    def test_ais_refuses_a_wrong_id_even_in_the_right_world(self):
        # Evidence must describe the id being trusted. A right-name
        # right-environment answer about ANOTHER id is a copied
        # casa-sandbox-test-shaped mis-wire, not a pass.
        self.sandbox()
        self.ais.app = {"app_id": "app-other",
                        "name": "casa-finance-sandbox",
                        "environment": "SANDBOX"}
        with self.assertRaises(tools_auth.WorldMismatch):
            tools_auth._ais()

    def test_ais_refuses_right_environment_wrong_name(self):
        # Environment alone would wave casa-sandbox-test through.
        self.sandbox()
        self.ais.app = {"app_id": "app-1", "name": "casa-sandbox-test",
                        "environment": "SANDBOX"}
        with self.assertRaises(tools_auth.WorldMismatch):
            tools_auth._ais()

    def test_ais_verifies_once_per_process(self):
        self.sandbox_world()
        tools_auth._ais()
        tools_auth._ais()
        self.assertEqual(self.ais.app_calls, 1)

    def test_production_ais_verifies_once_too(self):
        # The guard is symmetric. One GET per process, on the app's own JWT.
        tools_auth._ais()
        tools_auth._ais()
        self.assertEqual(self.ais.app_calls, 1)

    def test_a_transient_check_failure_is_named_as_the_check_not_the_bank(self):
        # A 503 on the verification GET must not read as dead account endpoints
        # — WorldUnverified is its own type, its message says the data
        # endpoints were never tried, and cached data is unchanged.
        import eb_ais
        self.ais.raise_on_application = eb_ais.ApiError(503, "application")
        with self.assertRaises(tools_auth.WorldUnverified) as ctx:
            tools_auth._ais()
        self.assertIn("NOT tried", str(ctx.exception))
        self.assertIn("retry", str(ctx.exception))
        # Both modes: same behaviour under sandbox.
        self.sandbox()
        with self.assertRaises(tools_auth.WorldUnverified):
            tools_auth._ais()

    def test_a_transient_check_failure_does_not_poison_the_cache(self):
        # The next call retries the verification instead of riding a
        # verdict that was never reached.
        import eb_ais
        self.ais.raise_on_application = eb_ais.ApiError(503, "application")
        with self.assertRaises(tools_auth.WorldUnverified):
            tools_auth._ais()
        self.ais.raise_on_application = None
        tools_auth._ais()                        # now verifies and passes
        self.assertEqual(self.ais.app_calls, 2)

    def test_production_ais_refuses_a_sandbox_answer(self):
        # The mirror image of the mis-wired sandbox install: production
        # wired with sandbox values must never sync fake rows into the
        # real ledger.
        self.ais.app = dict(SANDBOX_APP)
        with self.assertRaises(tools_auth.WorldMismatch):
            tools_auth._ais()

    def test_evidence_with_no_id_claim_fails_unless_path_bound(self):
        # A record that names the right world but claims no id is evidence
        # about nothing in particular.
        self.sandbox()
        with self.assertRaises(tools_auth.WorldMismatch):
            tools_auth._assert_world(
                "app-1", record={"name": "casa-finance-sandbox",
                                 "environment": "SANDBOX"})

    def test_adoption_re_uses_listing_evidence_with_zero_extra_fetches(self):
        # Adopted branches pass the record already in hand — the path-bound
        # admin GET count stays at zero for the whole run, redirect belt
        # included.
        self.sandbox_world()
        os.environ.pop("CASA_BANKFEED_EB_APP_ID", None)
        out = call("setup_bank_feed")
        self.assertIn("adopted", out)
        self.assertEqual(self.admin.application_calls, [])


class TestWorldGuardLinkBank(SandboxBase):
    def test_link_bank_refuses_before_any_whitelist_operation(self):
        # Tap 1 writes were reachable before the AIS-only guard. The
        # whitelist/link logs are the proof: a guard moved AFTER whitelisted()
        # would still refuse but would leave a read in the log.
        self.sandbox()
        out = call("link_bank", aspsp="Rabobank", psu_type="personal")
        self.assertIn("Linking has NOT been started", out)
        self.assertIn("refusing to touch application", out)
        self.assertEqual(self.admin.application_calls, ["app-1"])
        self.assertEqual(self.admin.whitelisted_calls, [])
        self.assertEqual(self.admin.link_calls, [])

    def test_link_bank_proceeds_in_the_right_world(self):
        self.sandbox_world()
        out = call("link_bank", aspsp="Rabobank", psu_type="personal")
        self.assertNotIn("Linking has NOT been started", out)

    def test_sandbox_link_bank_never_runs_the_whitelist_tap(self):
        # Issue #10, the boundary itself: in sandbox the whitelist gate does
        # not exist. Even for a bank with NO whitelist entry — the input that
        # sent production down tap 1 — there is no whitelist read and no
        # Control-Panel link_accounts session (the CP-initiated session was
        # measured routing to the real bank's LIVE login); the one URL
        # returned is the app-JWT authorization, whose identity carries the
        # SANDBOX environment.
        self.sandbox_world()
        self.admin._whitelisted = False
        out = call("link_bank", aspsp="Rabobank", psu_type="personal")
        self.assertEqual(self.admin.whitelisted_calls, [])
        self.assertEqual(self.admin.link_calls, [])
        self.assertEqual(len(self.ais.auths), 1)
        self.assertIn("one tap", out)
        self.assertNotIn("tap 1", out)
        self.assertNotIn("enablebanking.com/whitelist", out)

    def test_production_link_bank_still_runs_the_whitelist_tap(self):
        # The mirror pin: outside sandbox, an unwhitelisted bank still gets
        # tap 1 — the CP link_accounts URL — and no authorization is minted.
        self.admin._whitelisted = False
        out = call("link_bank", aspsp="Rabobank", psu_type="personal")
        self.assertEqual(self.admin.whitelisted_calls, ["app-1"])
        self.assertEqual(self.admin.link_calls,
                         [("app-1", "Rabobank", "NL", "personal")])
        self.assertEqual(self.ais.auths, [])
        self.assertIn("tap 1 of 2", out)

    def test_production_link_bank_verifies_and_proceeds(self):
        # Production verifies too — FakeAdmin's default record IS production's
        # own app, so the guard passes and tap 1 proceeds.
        out = call("link_bank", aspsp="Rabobank", psu_type="personal")
        self.assertEqual(self.admin.application_calls, ["app-1"])
        self.assertNotIn("Linking has NOT been started", out)

    def test_production_link_bank_refuses_a_sandbox_wired_app(self):
        self.admin.apps = [dict(SANDBOX_APP)]
        out = call("link_bank", aspsp="Rabobank", psu_type="personal")
        self.assertIn("Linking has NOT been started", out)
        self.assertEqual(self.admin.whitelisted_calls, [])
        self.assertEqual(self.admin.link_calls, [])


class TestProductionSetupGuard(SandboxBase):
    def test_env_wired_sandbox_app_is_refused_before_meta_and_patch(self):
        # Production mirror of the sandbox refusal.
        self.admin.apps = [dict(SANDBOX_APP)]
        out = call("setup_bank_feed")
        self.assertIn("refusing to touch application", out)
        self.assertEqual(self.admin.redirect_calls, [])
        self.assertIsNone(tools_auth._meta_get(self.raw, "setup.app_id"))

    def test_health_rung_drift_is_a_hard_stop_in_production_too(self):
        # Between-GET drift: rung 4 verified via the admin view, but the
        # AIS view answers as the other world. Rare is not a reason to
        # fail open.
        self.ais.app = {"app_id": "app-1", "name": "casa-finance",
                        "environment": "SANDBOX", "active": True}
        # rung 4's guard passes via the admin view; the _ais() guard
        # would ALSO catch this, so the drift must slip past it to reach
        # rung 6's own comparison: pre-seed the world cache the way an
        # earlier same-process verification would have.
        tools_auth._WORLD_OK.add("app-1")
        out = call("setup_bank_feed")
        self.assertIn("not PRODUCTION", out)
        self.assertIn("Stopping", out)
        self.assertNotIn("run list_banks", out)


class TestWorldGuardExchange(SandboxBase):
    def test_the_exchange_verifies_before_reading_the_whitelist(self):
        # The exchange's own resolution sites: its guarded _ais() refuses
        # before any session exchange, and the WorldMismatch leaves the harness
        # as a raise — production's callbacks._run_exchange catches every
        # exchange exception (callbacks.py:1259-1260) and quarantines, so
        # "raised before anything bound" IS the production-safe shape. Nothing
        # is bound, and the whitelist is never read.
        self.sandbox()
        with self.assertRaises(tools_auth.WorldMismatch):
            self.collect()
        self.assertEqual(self.admin.whitelisted_calls, [])
        self.assertEqual(self.raw.execute(
            "SELECT count(*) FROM accounts").fetchone()[0], 0)

    def test_the_exchange_proceeds_in_the_right_world(self):
        # Issue #10: sandbox has no whitelist gate, so the exchange neither
        # reads the whitelist nor compares against it — an EMPTY whitelist
        # (the sandbox steady state, since tap 1 never runs there) must not
        # refuse the link. The world guard still ran — via the AIS view at
        # _ais(), whose verdict the exchange's own _assert_world re-uses.
        self.sandbox_world()
        self.admin._whitelisted = False
        out = self.collect()
        self.assertEqual(self.admin.whitelisted_calls, [])
        self.assertEqual(self.ais.app_calls, 1)
        self.assertIn("account", out)
        self.assertEqual(self.raw.execute(
            "SELECT count(*) FROM accounts").fetchone()[0], 1)

    def test_production_exchange_still_reads_and_enforces_the_whitelist(self):
        # The mirror pin: outside sandbox the whitelist comparison is
        # unchanged — an empty whitelist refuses, nothing is bound, and the
        # noted consent is quarantined for review.
        self.admin._whitelisted = False
        self.collect()
        self.assertEqual(self.admin.whitelisted_calls, ["app-1"])
        self.assertEqual(self.raw.execute(
            "SELECT count(*) FROM accounts").fetchone()[0], 0)


class TestDispatcher(SandboxBase):
    """Through handle() only. A stub tool keeps these cases
    about the dispatcher, not about any real tool's world."""

    def register_stub(self, fn=None):
        bank_feed_server.TOOLS["__stub__"] = {
            "description": "stub", "schema": {"type": "object"},
            "fn": fn or (lambda args: "stub-ok")}
        self.addCleanup(bank_feed_server.TOOLS.pop, "__stub__", None)

    def dispatch(self, name="__stub__"):
        resp = bank_feed_server.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": name, "arguments": {}}})
        return resp["result"]["content"][0]["text"]

    def test_sandbox_success_carries_the_banner(self):
        self.sandbox()
        self.register_stub()
        text = self.dispatch()
        self.assertTrue(text.startswith(bank_feed_server.SANDBOX_BANNER),
                        text)
        self.assertTrue(text.endswith("stub-ok"))

    def test_sandbox_error_responses_carry_the_banner_too(self):
        # The rendered exception is what a wrapper inside register() could
        # never see.
        self.sandbox()
        self.register_stub(fn=lambda args: (_ for _ in ()).throw(
            RuntimeError("boom")))
        text = self.dispatch()
        self.assertTrue(text.startswith(bank_feed_server.SANDBOX_BANNER))
        self.assertIn("error: RuntimeError: boom", text)

    def test_production_bytes_carry_no_banner_on_success_or_error(self):
        self.register_stub()
        self.assertEqual(self.dispatch(), "stub-ok")
        self.register_stub(fn=lambda args: (_ for _ in ()).throw(
            RuntimeError("boom")))
        self.assertEqual(self.dispatch(), "error: RuntimeError: boom")

    def test_an_invalid_mode_refuses_every_tool_unbannered(self):
        ran = []
        self.register_stub(fn=lambda args: ran.append(1) or "ran")
        os.environ[ebmode.ENV_MODE_VAR] = "garbage"
        self.addCleanup(os.environ.pop, ebmode.ENV_MODE_VAR, None)
        ebmode._reset()
        self.addCleanup(ebmode._reset)
        # Step order: the marker must never be consulted under an unparseable
        # mode — check_mode_marker would call ebmode.mode() and turn the
        # uniform refusal into a traceback-shaped one.
        consulted = []
        self.addCleanup(setattr, store, "check_mode_marker",
                        store.check_mode_marker)
        store.check_mode_marker = lambda data: consulted.append(data)
        text = self.dispatch()
        self.assertIn(ebmode.ENV_MODE_VAR, text)
        self.assertNotIn("garbage", text)         # never echoed
        self.assertNotIn("[SANDBOX]", text)        # no truthful banner
        self.assertEqual(ran, [])                  # body never entered
        self.assertEqual(consulted, [])            # marker never consulted

    def test_a_mode_flip_refuses_at_dispatch_before_the_tool_body(self):
        # The marker refusal must fire before setup_bank_feed could touch vault
        # state — here, before any body.
        (self.root / "eb-environment").write_text("PRODUCTION\n")
        self.sandbox()
        ran = []
        self.register_stub(fn=lambda args: ran.append(1) or "ran")
        text = self.dispatch()
        self.assertIn("does not migrate", text)
        self.assertTrue(text.startswith(bank_feed_server.SANDBOX_BANNER))
        self.assertEqual(ran, [])

    def test_unknown_tool_error_is_unchanged_in_both_modes(self):
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "__nope__", "arguments": {}}}
        prod = bank_feed_server.handle(req)
        self.sandbox()
        sand = bank_feed_server.handle(req)
        self.assertEqual(prod, sand)
        self.assertIn("error", prod)


class TestConfigThreading(unittest.TestCase):
    def _env(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        mcp = json.loads(
            (root / "plugins/bank-feed/.mcp.json").read_text("utf-8"))
        return mcp["mcpServers"]["bank-feed"]["env"]

    def test_mcp_json_declares_the_mode_variable(self):
        # Without the env-block entry the server process never sees the
        # variable at all — the undeclared-name shape. The KEY is the
        # process name `ebmode` reads; the reference on the VALUE side keeps
        # the same spelling (issue #4: only the two setup-provisioned
        # credentials are renamed, because only a DECLARED name must carry
        # casa's reserved prefix).
        self.assertIn(ebmode.ENV_MODE_VAR, self._env())
        self.assertEqual(self._env()[ebmode.ENV_MODE_VAR],
                         "${%s:-}" % ebmode.ENV_MODE_VAR)

    def test_the_mode_reference_carries_an_empty_default_so_it_cannot_withhold(self):
        # Issue #4, and NOT cosmetic: `mode()` treats unset/empty as
        # PRODUCTION, and this page's own operator contract is that a
        # production install leaves the variable UNSET. Under casa's
        # env-readiness gate a BARE unresolved reference WITHHOLDS the plugin
        # — so a bare `${BANKFEED_EB_ENVIRONMENT}` would deadlock every
        # production install exactly as the setup credentials did, for a
        # variable whose absence is the documented normal case. The `:-`
        # default is what makes it invisible to that gate.
        #
        # EMPTY, never `sandbox`: a non-empty default would silently put a
        # production install in the sandbox world.
        self.assertTrue(self._env()[ebmode.ENV_MODE_VAR].endswith(":-}"))
        self.assertEqual(ebmode.mode(), ebmode.PRODUCTION)   # what "" means
        root = pathlib.Path(__file__).resolve().parents[1]
        manifest = json.loads(
            (root / "plugins/bank-feed/.claude-plugin/plugin.json")
            .read_text("utf-8"))
        self.assertNotIn(ebmode.ENV_MODE_VAR, manifest["casa"]["setupProvides"])


class TestLedgerIsolation(SandboxBase):
    def test_the_sandbox_ledger_is_its_own_file(self):
        self.sandbox()
        self.assertEqual(store.db_filename(), "bank_feed.sandbox.sqlite")

    def test_conn_composes_the_modes_path_and_commits_the_marker(self):
        # The filename has one spelling (store's) and the marker
        # commits at conn(), after a successful open.
        import tools_read
        self.sandbox()
        tools_read.CONN = None
        try:
            c = tools_read.conn()
            c.close()
        finally:
            tools_read.CONN = None
        self.assertTrue((self.root / "bank_feed.sandbox.sqlite").exists())
        self.assertEqual(
            (self.root / "eb-environment").read_text().strip(), "SANDBOX")

    def test_a_failed_open_commits_no_marker(self):
        # The commit rule, the failure half: DB first, marker second — an open
        # that raises must pin nothing.
        import tools_read
        self.sandbox()
        tools_read.CONN = None
        self.addCleanup(setattr, tools_read, "CONN", None)
        self.addCleanup(setattr, store, "open_db", store.open_db)
        def refuse(path=None):
            raise store.StoreError("integrity check failed: simulated")
        store.open_db = refuse
        with self.assertRaises(store.StoreError):
            tools_read.conn()
        self.assertFalse((self.root / "eb-environment").exists())

    def test_a_commit_failure_closes_the_connection_conn_just_opened(self):
        # Fail closed: a ledger left open in an unclaimed directory is
        # exactly the state the commit rule exists to prevent — and CONN
        # must stay unset so a retry re-runs the whole protocol.
        import sqlite3
        import tools_read
        self.sandbox()
        tools_read.CONN = None
        self.addCleanup(setattr, tools_read, "CONN", None)
        self.addCleanup(setattr, store, "commit_mode_marker",
                        store.commit_mode_marker)
        opened = []
        real_open = store.open_db
        self.addCleanup(setattr, store, "open_db", real_open)
        def recording_open(path=None):
            c = real_open(path)
            opened.append(c)
            return c
        store.open_db = recording_open
        def refuse(data):
            raise store.StoreError("cannot record the install marker")
        store.commit_mode_marker = refuse
        with self.assertRaises(store.StoreError):
            tools_read.conn()
        self.assertIsNone(tools_read.CONN)
        self.assertEqual(len(opened), 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            opened[0].execute("SELECT 1")       # closed = unusable


if __name__ == "__main__":
    unittest.main()
