# tests/test_provenance.py
"""Restore fingerprint and per-ASPSP reference capability."""
import hashlib
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
import provenance  # noqa: E402
import store  # noqa: E402

# Synthetic, sanitised fixture: provenance never parses a key, it
# only fingerprints the armored body, so this need not be a real RSA key.
PEM_A = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAtWXyH0LmR4mE5xQe\n"
    "c1nBQm0RHRZq7bK9y2FQ1pXnA0Vr8dJ7T5sYbN2wQ3fKlOZi9uHhVxG8mCpDtEaS\n"
    "wIDAQABAkAn3Qz0lYqTn6bJ8kM2rVdG5xWc7aBfLhP9uEoNsRtYvCiKmZ0DqXlWb\n"
    "-----END PRIVATE KEY-----\n"
)
BODY_A = "".join(ln for ln in PEM_A.splitlines() if not ln.startswith("-----"))
# same key, re-wrapped at a different width with CRLF endings
PEM_A_REWRAPPED = (
    "-----BEGIN PRIVATE KEY-----\r\n"
    + "\r\n".join(BODY_A[i:i + 32] for i in range(0, len(BODY_A), 32))
    + "\r\n-----END PRIVATE KEY-----\r\n\r\n"
)
# a rotated 1Password key: different material, same armor
PEM_ROTATED = PEM_A.replace("tWXyH0LmR4mE5xQe", "QQQQQQQQQQQQQQQQ")


class TestFingerprint(unittest.TestCase):
    def test_fingerprint_is_a_composite_hex_digest(self):
        fp = provenance.fingerprint("app-1", PEM_A, "host-1")
        self.assertEqual(len(fp), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in fp))
        # composite over three inputs, not just the key
        self.assertNotEqual(fp, hashlib.sha256(BODY_A.encode()).hexdigest())
        self.assertNotEqual(fp, hashlib.sha256(PEM_A.encode()).hexdigest())

    def test_fingerprint_ignores_pem_wrapping_and_line_endings(self):
        self.assertEqual(provenance.fingerprint("app-1", PEM_A, "host-1"),
                         provenance.fingerprint("app-1", PEM_A_REWRAPPED, "host-1"))

    def test_a_rotated_key_changes_the_fingerprint(self):
        self.assertNotEqual(provenance.fingerprint("app-1", PEM_A, "host-1"),
                            provenance.fingerprint("app-1", PEM_ROTATED, "host-1"))

    def test_app_id_and_host_id_each_change_the_fingerprint(self):
        base = provenance.fingerprint("app-1", PEM_A, "host-1")
        self.assertNotEqual(base, provenance.fingerprint("app-2", PEM_A, "host-1"))
        self.assertNotEqual(base, provenance.fingerprint("app-1", PEM_A, "host-2"))

    def test_empty_key_material_is_rejected(self):
        with self.assertRaises(ValueError):
            provenance.fingerprint("app-1", "", "host-1")
        with self.assertRaises(ValueError):
            provenance.fingerprint(
                "app-1", "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
                "host-1")


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.conn = store.open_db(pathlib.Path(self.dir.name) / "bank_feed.sqlite")

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    def meta_values(self):
        return [r[0] for r in self.conn.execute("SELECT value FROM meta")]


class TestRestoreCheck(Base):
    def test_check_is_fresh_before_anything_is_recorded(self):
        fp = provenance.fingerprint("app-1", PEM_A, "host-1")
        self.assertEqual(provenance.check(self.conn, fp),
                         {"state": "fresh", "recorded": None})

    def test_check_matches_what_was_recorded(self):
        fp = provenance.fingerprint("app-1", PEM_A, "host-1")
        provenance.record(self.conn, fp)
        self.assertEqual(provenance.check(self.conn, fp),
                         {"state": "match", "recorded": fp})

    def test_a_rotated_key_reads_as_mismatch(self):
        # A restored database paired with a rotated 1Password key. It is
        # REPORTED; no reconciliation ladder runs.
        old = provenance.fingerprint("app-1", PEM_A, "host-1")
        provenance.record(self.conn, old)
        new = provenance.fingerprint("app-1", PEM_ROTATED, "host-1")
        out = provenance.check(self.conn, new)
        self.assertEqual(out["state"], "mismatch")
        self.assertEqual(out["recorded"], old)

    def test_record_is_idempotent_and_keeps_one_row(self):
        first = provenance.fingerprint("app-1", PEM_A, "host-1")
        second = provenance.fingerprint("app-2", PEM_A, "host-1")
        provenance.record(self.conn, first)
        provenance.record(self.conn, first)
        provenance.record(self.conn, second)
        n = self.conn.execute(
            "SELECT count(*) FROM meta WHERE key='provenance_fp'").fetchone()[0]
        self.assertEqual(n, 1)
        self.assertEqual(provenance.check(self.conn, second)["state"], "match")

    def test_no_meta_row_ever_contains_key_material(self):
        provenance.record(self.conn, provenance.fingerprint("app-1", PEM_A, "h"))
        for value in self.meta_values():
            self.assertNotIn("PRIVATE KEY", value)
            self.assertNotIn(BODY_A[:24], value)
            self.assertNotIn(BODY_A, value)


class TestCapability(Base):
    def test_default_capability_is_untrusted(self):
        self.assertEqual(provenance.DEFAULT_CAPABILITY,
                         {"ref_stable": False, "ref_scope": "unknown",
                          "observed_n": 0})

    def test_an_unrecorded_aspsp_reads_as_untrusted(self):
        # "global is never assumed" — no row means no trust.
        self.assertEqual(provenance.capability(self.conn, "Bunq"),
                         provenance.DEFAULT_CAPABILITY)

    def test_capability_returns_a_copy_of_the_default(self):
        got = provenance.capability(self.conn, "Bunq")
        got["ref_stable"] = True
        self.assertFalse(provenance.DEFAULT_CAPABILITY["ref_stable"])
        self.assertFalse(provenance.capability(self.conn, "Bunq")["ref_stable"])

    def test_an_observation_round_trips(self):
        # The figures here are the test's own: capability is written by local
        # observation, so there is no shipped set of values to pin.
        provenance.set_capability(self.conn, "Revolut", ref_stable=True,
                                  ref_scope="account", observed_n=100,
                                  provenance="observed locally, 100/100")
        provenance.set_capability(self.conn, "ABN AMRO", ref_stable=True,
                                  ref_scope="account", observed_n=900,
                                  provenance="observed locally, 900/1000")
        self.assertEqual(provenance.capability(self.conn, "Revolut"),
                         {"ref_stable": True, "ref_scope": "account",
                          "observed_n": 100})
        self.assertEqual(provenance.capability(self.conn, "ABN AMRO"),
                         {"ref_stable": True, "ref_scope": "account",
                          "observed_n": 900})

    def test_recording_one_aspsp_does_not_change_another(self):
        provenance.set_capability(self.conn, "Revolut", ref_stable=True,
                                  ref_scope="account", observed_n=100,
                                  provenance="observed locally, 100/100")
        self.assertEqual(provenance.capability(self.conn, "ABN AMRO"),
                         provenance.DEFAULT_CAPABILITY)

    def test_set_capability_overwrites_in_place(self):
        provenance.set_capability(self.conn, "Rabobank", ref_stable=False,
                                  ref_scope="unknown", observed_n=10)
        provenance.set_capability(self.conn, "Rabobank", ref_stable=True,
                                  ref_scope="account", observed_n=200,
                                  provenance="observed locally, 200/200")
        n = self.conn.execute(
            "SELECT count(*) FROM aspsp_capability").fetchone()[0]
        self.assertEqual(n, 1)
        self.assertEqual(provenance.capability(self.conn, "Rabobank"),
                         {"ref_stable": True, "ref_scope": "account",
                          "observed_n": 200})

    def test_lookup_is_case_and_whitespace_insensitive(self):
        provenance.set_capability(self.conn, "ABN AMRO", ref_stable=True,
                                  ref_scope="account", observed_n=900,
                                  provenance="observed locally, 900/1000")
        for spelling in ("abn amro", "  ABN   AMRO ", "Abn Amro"):
            self.assertTrue(
                provenance.capability(self.conn, spelling)["ref_stable"], spelling)

    def test_an_unknown_ref_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            provenance.set_capability(self.conn, "Revolut", ref_stable=True,
                                      ref_scope="global", observed_n=100,
                                      provenance="observed locally, 100/100")

    def test_a_stable_reference_with_unknown_scope_is_rejected(self):
        # Trusting a reference whose uniqueness scope was never established is
        # the global assumption that is never made.
        with self.assertRaises(ValueError):
            provenance.set_capability(self.conn, "Revolut", ref_stable=True,
                                      ref_scope="unknown", observed_n=100,
                                      provenance="observed locally, 100/100")

    def test_a_negative_observation_count_is_rejected(self):
        with self.assertRaises(ValueError):
            provenance.set_capability(self.conn, "Revolut", ref_stable=True,
                                      ref_scope="account", observed_n=-1,
                                      provenance="observed locally, 100/100")

    def test_a_trust_claim_without_a_provenance_is_rejected(self):
        # A claim with no stated origin cannot be audited later, and cannot be
        # retired when the bank's behaviour changes.
        with self.assertRaises(ValueError):
            provenance.set_capability(self.conn, "Revolut", ref_stable=True,
                                      ref_scope="account", observed_n=100)
        with self.assertRaises(ValueError):
            provenance.set_capability(self.conn, "Revolut", ref_stable=True,
                                      ref_scope="account", observed_n=100,
                                      provenance="   ")
        # an UNTRUSTED row needs no provenance: it claims nothing
        provenance.set_capability(self.conn, "Revolut", ref_stable=False,
                                  ref_scope="unknown", observed_n=3)
        self.assertFalse(provenance.capability(self.conn, "Revolut")["ref_stable"])


class NothingIsTrustedUntilObserved(Base):
    """A fresh install trusts no provider reference.

    Capability is a per-installation property: whether THIS account's
    provider supplies references that are present and unique. Shipping a
    default derived from any other installation asserts something about a
    stranger's bank that nobody measured there.

    Until the observation mechanism lands (issue #7) the honest default is
    untrusted, and matching falls back to the windowed heuristic.
    """

    def test_a_fresh_database_trusts_no_aspsp(self):
        for name in ("Revolut", "Rabobank", "ABN AMRO", "Bunq", "anything"):
            self.assertEqual(provenance.capability(self.conn, name),
                             provenance.DEFAULT_CAPABILITY, name)

    def test_a_fresh_database_has_an_empty_capability_table(self):
        # Not just "reads as untrusted": nothing is WRITTEN either, so an
        # operator inspecting the table sees no claim they did not make.
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM aspsp_capability").fetchone()[0], 0)

    def test_the_seed_is_gone(self):
        self.assertFalse(hasattr(provenance, "seed_measured_capabilities"))
        self.assertFalse(hasattr(provenance, "MEASURED_CAPABILITIES"))

    def test_set_capability_still_works_for_a_local_observation(self):
        # The writer stays: issue #7 needs it, and an operator or a later
        # slice can still record what this installation observed.
        provenance.set_capability(self.conn, "Revolut", ref_stable=True,
                                  ref_scope="account", observed_n=120,
                                  provenance="observed locally 2026-01-01")
        got = provenance.capability(self.conn, "Revolut")
        self.assertTrue(got["ref_stable"])
        self.assertEqual(got["observed_n"], 120)


class TestUnresolvedAspsp(Base):
    """A name that does not resolve is REPORTED, not silently downgraded.

    Nothing is recorded until this installation observes it, so each test
    here writes whatever rows it needs -- the connection arrives empty.
    """

    def _observe(self, name):
        provenance.set_capability(self.conn, name, ref_stable=True,
                                  ref_scope="account", observed_n=100,
                                  provenance="observed locally")

    def test_a_resolved_name_produces_no_warning(self):
        self._observe("Revolut")
        self._observe("ABN AMRO")
        for spelling in ("Revolut", "revolut", "  ABN   AMRO "):
            self.assertIsNone(provenance.capability_warning(self.conn, spelling),
                              spelling)

    def test_a_spelling_drift_is_reported_with_the_names_we_do_know(self):
        """'ABN-AMRO' is untrusted for the same reason a genuinely new bank is,
        but it is not the same event: it is a permanent, silent loss of
        reference identity for a bank this installation did observe."""
        self._observe("ABN AMRO")
        warning = provenance.capability_warning(self.conn, "ABN-AMRO")
        self.assertIsNotNone(warning)
        self.assertIn("ABN-AMRO", warning)
        self.assertIn("ABN AMRO", warning)          # what we do have recorded
        self.assertIn("drift", warning.lower())
        # reporting must not widen trust
        self.assertEqual(provenance.capability(self.conn, "ABN-AMRO"),
                         provenance.DEFAULT_CAPABILITY)

    def test_an_account_with_no_recorded_aspsp_is_reported(self):
        """flows.backfill passes account['aspsp'] or ''. An empty name is the
        worst shape of this: silent, total fallback for every row."""
        warning = provenance.capability_warning(self.conn, "")
        self.assertIsNotNone(warning)
        self.assertIn("No ASPSP name", warning)

    def test_a_genuinely_new_bank_is_reported_too(self):
        self.assertIsNotNone(provenance.capability_warning(self.conn, "Bunq"))

    def test_an_installation_that_has_observed_nothing_still_reports(self):
        """The empty table is the shipped state, so the warning must read
        correctly with no recorded names at all -- not crash or claim one."""
        warning = provenance.capability_warning(self.conn, "Revolut")
        self.assertIsNotNone(warning)
        self.assertIn("none", warning)


if __name__ == "__main__":
    unittest.main()
