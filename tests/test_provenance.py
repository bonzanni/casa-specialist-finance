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


def norm_row(date, ref, kind="entry_reference", amount=1234,
             counterparty="Voorbeeld Supermarkt", remittance="boodschappen",
             direction="DBIT", currency="EUR"):
    """A row shaped like ingest.normalise output — the input measure takes."""
    return {"account_id": "acc1", "booking_date": date, "value_date": date,
            "amount_minor": amount, "currency": currency,
            "direction": direction, "status": "BOOK",
            "counterparty": counterparty, "remittance": remittance,
            "provider_ref": ref, "provider_ref_kind": kind if ref else None}


class EvidenceBase(Base):
    """Shared fixtures for the earned-trust half of this module."""

    def account(self, account_id="acc1", aspsp="Revolut", incarnation="inc-1"):
        self.conn.execute(
            "INSERT INTO accounts(account_id, aspsp, incarnation)"
            " VALUES (?,?,?)", (account_id, aspsp, incarnation))

    def metrics(self, **kw):
        m = {"rows_total": 200, "ref_transactions": 150, "distinct_refs": 150,
             "reused_refs": 0, "span_days": 400}
        m.update(kw)
        return m

    def observe(self, account_id="acc1", aspsp="Revolut", kind="deep",
                incarnation="inc-1", **kw):
        return provenance.record_observation(
            self.conn, account_id=account_id, incarnation=incarnation,
            aspsp=aspsp, session_id="s1", kind=kind, window_days=2900,
            metrics=self.metrics(**kw))


class TestMeasureReferences(unittest.TestCase):
    """The pure reduction: transactions, not rows; reuse, not restatement."""

    def test_zero_rows_measure_as_zeros(self):
        self.assertEqual(provenance.measure_references([]),
                         {"rows_total": 0, "ref_transactions": 0,
                          "distinct_refs": 0, "reused_refs": 0,
                          "span_days": 0})

    def test_restatements_of_one_row_are_one_transaction_not_reuse(self):
        # Two identical copies on one page, and a third whose date drifted a
        # day: one band, one transaction, nothing reused.
        rows = [norm_row("2026-01-10", "R1"), norm_row("2026-01-10", "R1"),
                norm_row("2026-01-11", "R1")]
        got = provenance.measure_references(rows)
        self.assertEqual(got["ref_transactions"], 1)
        self.assertEqual(got["reused_refs"], 0)

    def test_a_recurrence_sharing_one_reference_is_reuse(self):
        # Same content, same reference, a month apart: the standing-order
        # shape rule 1's collapse comments name as the catastrophic one.
        rows = [norm_row("2026-01-10", "R1"), norm_row("2026-02-10", "R1")]
        got = provenance.measure_references(rows)
        self.assertEqual(got["reused_refs"], 1)
        self.assertEqual(got["ref_transactions"], 2)

    def test_distinct_contents_sharing_one_reference_are_reuse(self):
        rows = [norm_row("2026-01-10", "R1"),
                norm_row("2026-01-10", "R1", amount=9999)]
        self.assertEqual(provenance.measure_references(rows)["reused_refs"], 1)

    def test_restatement_inflation_cannot_reach_the_sample_floor(self):
        # 50 copies each of two transactions 200 days apart: raw rows would
        # read 100, the transaction count must read 2 -- or the threshold
        # measures the provider's appetite for restating, not its references.
        rows = ([norm_row("2026-01-10", "R1")] * 50
                + [norm_row("2026-07-29", "R2", amount=5678)] * 50)
        got = provenance.measure_references(rows)
        self.assertEqual(got["rows_total"], 100)
        self.assertEqual(got["ref_transactions"], 2)
        self.assertEqual(got["reused_refs"], 0)
        self.assertEqual(got["span_days"], 200)

    def test_transaction_id_fallback_never_counts_toward_the_sample(self):
        # ... but its reuse still counts: what is gated is ALL ref keying.
        rows = [norm_row("2026-01-10", "T1", kind="transaction_id"),
                norm_row("2026-02-10", "T1", kind="transaction_id")]
        got = provenance.measure_references(rows)
        self.assertEqual(got["ref_transactions"], 0)
        self.assertEqual(got["reused_refs"], 1)

    def test_referenceless_rows_count_only_toward_rows_total(self):
        rows = [norm_row("2026-01-10", None), norm_row("2026-02-10", "R1")]
        got = provenance.measure_references(rows)
        self.assertEqual(got["rows_total"], 2)
        self.assertEqual(got["distinct_refs"], 1)
        self.assertEqual(got["ref_transactions"], 1)

    def test_span_is_measured_over_band_anchors(self):
        rows = [norm_row("2026-01-10", "R1"),
                norm_row("2026-01-11", "R1"),          # restatement drift
                norm_row("2026-06-10", "R2", amount=5678)]
        # anchor of R1's band is the EARLIEST date, so the drifted copy
        # cannot stretch the span.
        self.assertEqual(provenance.measure_references(rows)["span_days"], 151)


class TestRecordObservation(EvidenceBase):
    def test_writes_under_the_captured_incarnation(self):
        self.account()
        self.assertTrue(self.observe())
        row = self.conn.execute("SELECT account_id, aspsp, kind, source,"
                                " ref_transactions FROM ref_observations"
                                ).fetchone()
        self.assertEqual((row[0], row[1], row[2], row[3], row[4]),
                         ("acc1", "REVOLUT", "deep", "", 150))

    def test_refuses_when_the_account_is_gone(self):
        # forget_local_account committed while the run was paging: the
        # evidence must not outlive the account it describes.
        self.assertFalse(self.observe())
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM ref_observations").fetchone()[0], 0)

    def test_refuses_a_stale_incarnation_after_forget_and_relink(self):
        # THE ABA CASE: account_id is a deterministic HMAC
        # of IBAN+currency, so forget + re-link recreates the SAME id. Bare
        # existence would admit the stale run's evidence; the incarnation
        # token refuses it.
        self.account(incarnation="inc-2")               # the account's new life
        self.assertFalse(self.observe(incarnation="inc-1"))
        self.assertTrue(self.observe(incarnation="inc-2"))

    def test_an_unknown_kind_is_rejected(self):
        self.account()
        with self.assertRaises(ValueError):
            self.observe(kind="seeded")

    def test_a_negative_metric_is_rejected(self):
        self.account()
        with self.assertRaises(ValueError):
            self.observe(reused_refs=-1)


class TestCapabilityDerivation(EvidenceBase):
    """Trust derives at read time from the evidence, and from nothing else."""

    def test_default_capability_is_untrusted(self):
        self.assertEqual(provenance.DEFAULT_CAPABILITY,
                         {"ref_stable": False, "ref_scope": "unknown",
                          "observed_n": 0})

    def test_a_fresh_install_trusts_nothing(self):
        for name in ("Revolut", "Rabobank", "ABN AMRO", "Bunq", "anything"):
            self.assertEqual(provenance.capability(self.conn, name, "acc1"),
                             provenance.DEFAULT_CAPABILITY, name)

    def test_a_fresh_database_holds_no_evidence(self):
        # Not just "reads as untrusted": nothing is WRITTEN either, so an
        # operator inspecting the table sees no claim they did not make.
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM ref_observations").fetchone()[0], 0)
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM aspsp_capability").fetchone()[0], 0)

    def test_the_seed_and_the_manual_writer_are_gone(self):
        self.assertFalse(hasattr(provenance, "seed_measured_capabilities"))
        self.assertFalse(hasattr(provenance, "MEASURED_CAPABILITIES"))
        # A hand-asserted trust claim is exactly the unattributable row the
        # seeder was; the only writer left is the observation recorder.
        self.assertFalse(hasattr(provenance, "set_capability"))

    def test_capability_returns_a_copy_of_the_default(self):
        got = provenance.capability(self.conn, "Bunq", "acc1")
        got["ref_stable"] = True
        self.assertFalse(provenance.DEFAULT_CAPABILITY["ref_stable"])
        self.assertFalse(
            provenance.capability(self.conn, "Bunq", "acc1")["ref_stable"])

    def test_a_qualifying_deep_observation_grants(self):
        self.account()
        self.observe()
        self.assertEqual(provenance.capability(self.conn, "Revolut", "acc1"),
                         {"ref_stable": True, "ref_scope": "account",
                          "observed_n": 150})

    def test_lookup_normalises_case_and_whitespace(self):
        self.account()
        self.observe()
        for spelling in ("revolut", "  REVOLUT ", "Revolut"):
            self.assertTrue(provenance.capability(
                self.conn, spelling, "acc1")["ref_stable"], spelling)

    def test_below_the_sample_floor_does_not_grant(self):
        self.account()
        self.observe(ref_transactions=
                     provenance.MIN_QUALIFYING_REF_TRANSACTIONS - 1)
        self.assertFalse(provenance.capability(
            self.conn, "Revolut", "acc1")["ref_stable"])

    def test_below_the_span_floor_does_not_grant(self):
        self.account()
        self.observe(span_days=provenance.MIN_QUALIFYING_SPAN_DAYS - 1)
        self.assertFalse(provenance.capability(
            self.conn, "Revolut", "acc1")["ref_stable"])

    def test_a_reuse_event_never_grants_whatever_its_numbers(self):
        self.account()
        self.observe(kind="reuse_event")
        self.assertFalse(provenance.capability(
            self.conn, "Revolut", "acc1")["ref_stable"])

    def test_one_measured_reuse_revokes_in_either_order(self):
        self.account()
        self.observe()                                   # qualifying grant
        self.observe(kind="reuse_event", reused_refs=1, ref_transactions=2)
        self.assertFalse(provenance.capability(
            self.conn, "Revolut", "acc1")["ref_stable"])
        # and the reverse order: the sighting poisons a LATER grant too
        self.account(account_id="acc2", incarnation="inc-9")
        self.observe(account_id="acc2", incarnation="inc-9",
                     kind="reuse_event", reused_refs=1, ref_transactions=2)
        self.observe(account_id="acc2", incarnation="inc-9")
        self.assertFalse(provenance.capability(
            self.conn, "Revolut", "acc2")["ref_stable"])

    def test_a_later_insufficient_sample_does_not_revoke(self):
        # The issue's named failure: a nine-day-shaped observation over a
        # qualifying one must not overwrite trust the bank earned. Evidence
        # is append-only; silence at a small sample size proves nothing.
        self.account()
        self.observe()
        self.observe(ref_transactions=3, span_days=9, rows_total=4)
        got = provenance.capability(self.conn, "Revolut", "acc1")
        self.assertTrue(got["ref_stable"])
        self.assertEqual(got["observed_n"], 150)

    def test_trust_is_per_account_the_clean_sibling_keeps_it(self):
        # One clean account and one dirty account at the same bank: the case
        # that decides the scope of the model. The dirty sibling's reuse
        # must not cost the clean one its earned identity, and the clean
        # one's grant must not launder the dirty one.
        self.account(account_id="clean", incarnation="i-c")
        self.account(account_id="dirty", incarnation="i-d")
        self.observe(account_id="clean", incarnation="i-c")
        self.observe(account_id="dirty", incarnation="i-d",
                     kind="reuse_event", reused_refs=1, ref_transactions=2)
        self.assertTrue(provenance.capability(
            self.conn, "Revolut", "clean")["ref_stable"])
        self.assertFalse(provenance.capability(
            self.conn, "Revolut", "dirty")["ref_stable"])

    def test_evidence_under_another_name_does_not_count(self):
        self.account()
        self.observe()
        self.assertEqual(provenance.capability(self.conn, "Bunq", "acc1"),
                         provenance.DEFAULT_CAPABILITY)


class TestCapabilityWarning(EvidenceBase):
    """An unresolved lookup is REPORTED, not silently downgraded."""

    def test_a_measured_account_produces_no_warning(self):
        self.account()
        self.observe()
        for spelling in ("Revolut", "revolut", "  REVOLUT "):
            self.assertIsNone(provenance.capability_warning(
                self.conn, spelling, "acc1"), spelling)

    def test_a_spelling_drift_is_reported_with_the_recorded_name(self):
        """'ABN-AMRO' is untrusted for the same reason a never-measured
        account is, but it is not the same event: it is a permanent, silent
        loss of reference identity for an account this installation DID
        measure."""
        self.account(aspsp="ABN AMRO")
        self.observe(aspsp="ABN AMRO")
        warning = provenance.capability_warning(self.conn, "ABN-AMRO", "acc1")
        self.assertIsNotNone(warning)
        self.assertIn("ABN-AMRO", warning)
        self.assertIn("ABN AMRO", warning)          # what we do have recorded
        self.assertIn("drift", warning.lower())
        # reporting must not widen trust
        self.assertEqual(provenance.capability(self.conn, "ABN-AMRO", "acc1"),
                         provenance.DEFAULT_CAPABILITY)

    def test_an_account_with_no_recorded_aspsp_is_reported(self):
        """flows.backfill passes the account row's aspsp or ''. An empty name
        is the worst shape of this: silent, total fallback for every row."""
        warning = provenance.capability_warning(self.conn, "", "acc1")
        self.assertIsNotNone(warning)
        self.assertIn("No ASPSP name", warning)

    def test_a_never_measured_account_is_reported(self):
        warning = provenance.capability_warning(self.conn, "Bunq", "acc1")
        self.assertIsNotNone(warning)
        self.assertIn("never been measured", warning)

    def test_measured_but_insufficient_is_not_a_warning(self):
        # The design working as intended: the sync-note lines carry trust
        # transitions; the warning exists for lookups that RESOLVE to nothing.
        self.account()
        self.observe(ref_transactions=3, span_days=9)
        self.assertIsNone(
            provenance.capability_warning(self.conn, "Revolut", "acc1"))

    def test_measured_and_unstable_is_not_a_warning_either(self):
        self.account()
        self.observe(kind="reuse_event", reused_refs=1, ref_transactions=2)
        self.assertIsNone(
            provenance.capability_warning(self.conn, "Revolut", "acc1"))


if __name__ == "__main__":
    unittest.main()
