"""Setup meets an application its signing key cannot authenticate to (issue
#80). After `delete_all_data` erased the key, the application survives in the
control panel; a reinstall forges a new key, and until this fix step 4 adopted
the old application by name and step 6 then failed with a 401 whose only
advice was for a 404. Step 4 now proves the key before it records a binding,
and both steps name the mismatch and the recoveries that exist."""
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import eb_ais  # noqa: E402
import jwtsign  # noqa: E402
import tools_auth  # noqa: E402
from _toolbase import TEST_KEY_PEM, Base, call  # noqa: E402

TEST_KEY = jwtsign.load_pkcs8(TEST_KEY_PEM)


def refused(status):
    return eb_ais.ApiError(status, "application")


class TestStepFourProvesTheKeyBeforeAdopting(Base):
    def setUp(self):
        super().setUp()
        os.environ.pop("CASA_BANKFEED_EB_APP_ID", None)     # the name path

    def meta(self, key):
        return tools_auth._meta_get(self.raw, key)

    def test_the_resolved_key_is_what_the_probe_signs_with(self):
        out = call("setup_bank_feed")
        self.assertIn("adopted, not re-registered", out)
        self.assertEqual(self.keyed_calls,
                         [("app-1", (TEST_KEY.n, TEST_KEY.e))])
        self.assertEqual(self.meta("setup.app_id"), "app-1")

    def test_a_refused_key_adopts_nothing_and_creates_nothing(self):
        for status in (401, 403):
            with self.subTest(status=status):
                self.keyed_error = refused(status)
                out = call("setup_bank_feed")
                self.assertIn("4. Application: the signing key this process "
                              "received as %s cannot authenticate to "
                              "application app-1 (HTTP %d)"
                              % (tools_auth.WIRE_KEY_VAR, status), out)
                self.assertIn("It was not adopted and no application was "
                              "created.", out)
                self.assertIsNone(self.meta("setup.app_id"))
                self.assertEqual(self.admin.create_calls, [])
                self.assertEqual(self.admin.redirect_calls, [])
                self.assertNotIn("5. Callback redirect", out)
                self.assertNotIn("genuine 404", out)

    def test_the_recoveries_are_named_and_deletion_is_not_the_default(self):
        self.keyed_error = refused(401)
        out = call("setup_bank_feed")
        self.assertIn("Recently Deleted", out)
        self.assertIn("exactly one item carries that title", out)
        self.assertIn("it is your decision whether that application can go",
                      out)
        self.assertIn("re-run setup_bank_feed and it registers a new one", out)
        # The name path records nothing, so nothing needs accepting.
        self.assertNotIn("accept_app_reregistration (casa", out)

    def test_an_env_key_names_the_restart_and_a_vault_key_does_not(self):
        self.keyed_error = refused(401)
        out = call("setup_bank_feed")
        self.assertIn("make %s resolve to the restored key and restart the "
                      "plugin" % tools_auth.WIRE_KEY_VAR, out)
        os.environ.pop("CASA_BANKFEED_EB_PRIVATE_KEY")      # key from vault
        out = call("setup_bank_feed")
        self.assertIn("the signing key in 1Password ('EnableBanking Key') "
                      "cannot authenticate", out)
        self.assertNotIn("restart the plugin", out)

    def test_a_freshly_forged_key_is_probed_too(self):
        # The run that forges is the one a key_source guard would skip.
        os.environ.pop("CASA_BANKFEED_EB_PRIVATE_KEY")
        del self.vault.values[self.vault.REF_PRIVATE_KEY]
        self.keyed_error = refused(401)
        out = call("setup_bank_feed")
        self.assertIn("2. Key: FORGED", out)
        self.assertEqual(len(self.vault.created), 1)
        self.assertEqual(len(self.keyed_calls), 1)
        self.assertIn("4. Application: the signing key in 1Password "
                      "('EnableBanking Key') cannot authenticate", out)
        self.assertIsNone(self.meta("setup.app_id"))
        self.assertEqual(self.admin.create_calls, [])
        self.assertEqual(self.admin.redirect_calls, [])

    def test_a_probe_that_cannot_run_adopts_nothing(self):
        for exc in (refused(503), refused(404), RuntimeError("timed out")):
            with self.subTest(exc=exc):
                self.keyed_error = exc
                out = call("setup_bank_feed")
                self.assertIn("whether the signing key can authenticate to it "
                              "could not be checked", out)
                self.assertIsNone(self.meta("setup.app_id"))
                self.assertEqual(self.admin.create_calls, [])
                self.assertNotIn("cannot authenticate to application", out)

    def test_removing_the_application_then_re_running_registers_a_new_one(self):
        # Recovery (2), walked: nothing was recorded, so no acceptance is
        # needed once the operator removed the application.
        self.keyed_error = refused(401)
        call("setup_bank_feed")
        self.admin.apps = []
        out = call("setup_bank_feed")
        self.assertEqual(len(self.admin.create_calls), 1)
        self.assertIn("REGISTERED", out)

    def test_a_recorded_binding_is_not_re_probed_at_step_four(self):
        # The recorded and env paths are proven by step 6's own call.
        call("setup_bank_feed")
        self.keyed_calls.clear()
        call("setup_bank_feed")
        self.assertEqual(self.keyed_calls, [])


class TestStepSixNamesAKeyMismatch(Base):
    def test_a_refused_key_on_an_env_wired_app(self):
        for status in (401, 403):
            with self.subTest(status=status):
                self.ais.raise_on_application = refused(status)
                out = call("setup_bank_feed")
                self.assertIn("6. Application: the signing key this process "
                              "received as %s cannot authenticate to "
                              "application app-1 (HTTP %d)"
                              % (tools_auth.WIRE_KEY_VAR, status), out)
                self.assertIn("No application was created.", out)
                self.assertNotIn("not adopted", out)
                self.assertIn("run accept_app_reregistration (casa will ask "
                              "the operator to confirm), have the configurator "
                              "CLEAR %s from plugin-env.conf and restart the "
                              "plugin, then re-run setup_bank_feed"
                              % tools_auth.WIRE_APP_ID_VAR, out)
                self.assertNotIn("genuine 404", out)

    def test_a_refused_key_on_a_recorded_binding_needs_no_env_clearing(self):
        os.environ.pop("CASA_BANKFEED_EB_APP_ID")
        call("setup_bank_feed")                     # records app-1 by name
        self.ais.raise_on_application = refused(401)
        out = call("setup_bank_feed")
        self.assertIn("6. Application: the signing key", out)
        self.assertIn("run accept_app_reregistration (casa will ask the "
                      "operator to confirm), then re-run setup_bank_feed", out)
        self.assertNotIn("CLEAR", out)

    def test_a_404_keeps_its_own_advice(self):
        self.ais.raise_on_application = refused(404)
        out = call("setup_bank_feed")
        self.assertIn("If this is a genuine 404", out)
        self.assertNotIn("cannot authenticate", out)

    def test_a_refusal_wrapped_by_the_world_check_is_still_a_mismatch(self):
        # A process that had not yet checked the id gets the 401 wrapped in
        # WorldUnverified, whose own text says "transient, retry".
        def unverified():
            raise tools_auth.WorldUnverified("the check could not run",
                                             status=401)
        self.addCleanup(setattr, tools_auth, "_ais", tools_auth._ais)
        tools_auth._ais = unverified
        out = call("setup_bank_feed")
        self.assertIn("6. Application: the signing key", out)
        self.assertNotIn("the check could not run", out)

    def test_a_transient_world_check_keeps_its_own_text(self):
        def unverified():
            raise tools_auth.WorldUnverified("the check could not run",
                                             status=503)
        self.addCleanup(setattr, tools_auth, "_ais", tools_auth._ais)
        tools_auth._ais = unverified
        out = call("setup_bank_feed")
        self.assertIn("6. Application: the check could not run Stopping.", out)


class TestTheWorldCheckCarriesTheStatus(Base):
    def test_the_status_of_a_refused_check(self):
        self.ais.raise_on_application = refused(401)
        with self.assertRaises(tools_auth.WorldUnverified) as caught:
            tools_auth._ais()
        self.assertEqual(caught.exception.status, 401)

    def test_no_status_from_a_failure_that_has_none(self):
        self.ais.raise_on_application = OSError("reset")
        with self.assertRaises(tools_auth.WorldUnverified) as caught:
            tools_auth._ais()
        self.assertIsNone(caught.exception.status)


if __name__ == "__main__":
    unittest.main()
