# tests/test_apply.py
import hashlib
import json
import pathlib
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"))
import apply            # noqa: E402
import callbacks        # noqa: E402
import ingest           # noqa: E402
import rules            # noqa: E402
import store            # noqa: E402

IV = ("2026-01-01", "2026-04-01")
IBAN = "NL00ABNA0000000002"
# provenance.capability() results, inlined so this test does not depend on the
# provenance module's own fixtures.
CAP_UNKNOWN = {"ref_stable": False, "ref_scope": "unknown", "observed_n": 0}
CAP_STABLE = {"ref_stable": True, "ref_scope": "account", "observed_n": 200}


def row(date, amount=1000, ref=None, counterparty="Voorbeeld Supermarkt",
        status="BOOK"):
    """A normalised row, as ingest.normalise would produce it — no row_id and
    no local_id: reconcile adds those."""
    return {"account_id": "acc1", "booking_date": date, "value_date": date,
            "amount_minor": amount, "currency": "EUR", "direction": "DBIT",
            "counterparty": counterparty, "remittance": "boodschappen",
            "provider_ref": ref,
            "provider_ref_kind": "entry_reference" if ref else None,
            "status": status, "raw_json": "{}"}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.open_db(pathlib.Path(self.tmp.name) / "f.sqlite")

    def tearDown(self):
        self.tmp.cleanup()

    def _all(self):
        """EVERY state. reconcile needs tombstoned rows to allocate occurrence
        above every value ever issued."""
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM transactions ORDER BY row_id")]

    def _active(self):
        return [r for r in self._all() if r["state"] == "active"]


class TestApply(Base):
    def test_inserts_then_re_ingest_is_idempotent(self):
        fetched = [row("2026-02-05"), row("2026-03-05")]
        plan = ingest.reconcile([], fetched, IV, CAP_UNKNOWN)
        apply.apply_plan(self.conn, "acc1", plan)
        self.assertEqual(len(self._active()), 2)
        plan2 = ingest.reconcile(self._all(), fetched, IV, CAP_UNKNOWN)
        stats = apply.apply_plan(self.conn, "acc1", plan2)
        self.assertEqual((stats["inserted"], stats["tombstoned"]), (0, 0))
        self.assertEqual(len(self._active()), 2)          # no duplicates, ever

    def test_tombstone_marks_state_and_never_deletes(self):
        plan = ingest.reconcile([], [row("2026-02-05")], IV, CAP_UNKNOWN)
        apply.apply_plan(self.conn, "acc1", plan)
        plan2 = ingest.reconcile(self._all(), [], IV, CAP_UNKNOWN)
        apply.apply_plan(self.conn, "acc1", plan2)
        self.assertEqual(self._active(), [])
        self.assertEqual(len(self._all()), 1)             # tombstoned, not deleted
        self.assertEqual(self._all()[0]["state"], "vanished")

    def test_reference_history_is_appended_not_overwritten(self):
        """Plan carries no ref history — appending is apply's job."""
        plan = ingest.reconcile([], [row("2026-02-05", ref="R1")], IV, CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan)
        plan2 = ingest.reconcile(self._all(), [row("2026-02-05", ref="R2")],
                                 IV, CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan2)
        refs = {r[0] for r in self.conn.execute(
            "SELECT provider_ref FROM transaction_refs")}
        self.assertEqual(refs, {"R1", "R2"})              # both preserved
        self.assertEqual(len(self._all()), 1)
        # the row keeps its CURRENT reference; the table keeps the history
        self.assertEqual(self._all()[0]["provider_ref"], "R2")

    def test_flags_are_persisted(self):
        plan = ingest.reconcile([], [row("2026-02-05")], IV, CAP_UNKNOWN)
        apply.apply_plan(self.conn, "acc1", plan)
        rid = self._all()[0]["row_id"]
        self.assertEqual(self._all()[0]["needs_review"], 0)
        stats = apply.apply_plan(self.conn, "acc1", ingest.Plan(
            inserts=[], updates=[], tombstones=[],
            flags=[{"row_id": rid, "reason": "provider_ref_reuse"}]))
        self.assertEqual(stats["flagged"], 1)
        self.assertEqual(self._all()[0]["needs_review"], 1)
        self.assertEqual(self._all()[0]["review_reason"], "provider_ref_reuse")

    def test_a_flag_changes_nothing_but_needs_review_and_its_reason(self):
        plan = ingest.reconcile([], [row("2026-02-05", ref="R1")], IV, CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan)
        before = self._all()[0]
        apply.apply_plan(self.conn, "acc1", ingest.Plan(
            inserts=[], updates=[], tombstones=[],
            flags=[{"row_id": before["row_id"], "reason": "provider_ref_reuse"}]))
        after = self._all()[0]
        self.assertEqual((before["needs_review"], after["needs_review"]), (0, 1))
        self.assertEqual((before["review_reason"], after["review_reason"]),
                         (None, "provider_ref_reuse"))
        untouched = {"needs_review", "review_reason"}
        self.assertEqual({k: v for k, v in after.items() if k not in untouched},
                         {k: v for k, v in before.items() if k not in untouched})

    def test_a_tombstone_records_why_the_row_vanished(self):
        plan = ingest.reconcile([], [row("2026-02-05")], IV, CAP_UNKNOWN)
        apply.apply_plan(self.conn, "acc1", plan)
        plan2 = ingest.reconcile(self._all(), [], IV, CAP_UNKNOWN)
        self.assertEqual([t["reason"] for t in plan2.tombstones],
                         ["absent_from_a_proven_interval"])
        apply.apply_plan(self.conn, "acc1", plan2)
        gone = self._all()[0]
        self.assertEqual((gone["state"], gone["state_reason"]),
                         ("vanished", "absent_from_a_proven_interval"))
        # a row can be flagged AND later vanish: the two causes are separate
        # columns precisely so the second cannot overwrite the first
        self.assertIsNone(gone["review_reason"])

    def test_re_ingest_does_not_churn_the_reason_columns(self):
        fetched = [row("2026-02-05"), row("2026-03-05")]
        apply.apply_plan(self.conn, "acc1",
                         ingest.reconcile([], fetched, IV, CAP_UNKNOWN))
        rid = self._all()[0]["row_id"]
        apply.apply_plan(self.conn, "acc1", ingest.Plan(
            inserts=[], updates=[], tombstones=[],
            flags=[{"row_id": rid, "reason": "unresolved_cluster"}]))
        before = self._all()
        stats = apply.apply_plan(
            self.conn, "acc1", ingest.reconcile(before, fetched, IV, CAP_UNKNOWN))
        self.assertEqual((stats["inserted"], stats["tombstoned"], stats["flagged"]),
                         (0, 0, 0))
        after = self._all()
        self.assertEqual([(r["needs_review"], r["review_reason"], r["state"],
                           r["state_reason"]) for r in after],
                         [(r["needs_review"], r["review_reason"], r["state"],
                           r["state_reason"]) for r in before])

    def test_a_failing_row_rolls_back_the_whole_plan(self):
        """backfill commits an interval atomically; a half-applied page set
        would make coverage attest to rows that are not there."""
        good = dict(row("2026-02-05"), identity_key="K", occurrence=0)
        clash = dict(row("2026-03-05"), identity_key="K", occurrence=0)
        with self.assertRaises(sqlite3.IntegrityError):
            apply.apply_plan(self.conn, "acc1",
                             ingest.Plan([good, clash], [], [], []))
        self.assertEqual(self._all(), [])


class TestIdentityStaysConsistent(Base):
    """A row's stored identity_key always equals the hash of its own
    current content, so a corroborated correction rewrites identity_key and
    occurrence together — in one statement — or not at all."""

    def test_a_correction_rewrites_identity_and_occurrence_together(self):
        """The previous round wrote NEITHER, leaving the row carrying a key
        that no longer hashed its own content. A later reference-less fetch of
        the same transaction then found no cluster to match, inserted a
        duplicate and tombstoned the original."""
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-02-05", amount=1000, ref="R1")], IV, CAP_STABLE))
        first = self._all()[0]
        corrected = row("2026-02-06", amount=1200, ref="R1")
        plan = ingest.reconcile(self._all(), [corrected], IV, CAP_STABLE)
        self.assertEqual([u["op"] for u in plan.updates], ["update"])
        apply.apply_plan(self.conn, "acc1", plan)
        after = self._all()
        self.assertEqual(len(after), 1)                    # no duplicate
        self.assertEqual(after[0]["row_id"], first["row_id"])   # lineage kept
        self.assertEqual(after[0]["amount_minor"], 1200)
        # the stored key now hashes the row's OWN content, which is the invariant
        self.assertEqual(after[0]["identity_key"],
                         ingest.identity_key(dict(after[0])))
        self.assertNotEqual(after[0]["identity_key"], first["identity_key"])

    def test_a_re_ingest_after_a_correction_finds_the_row_instead_of_forking_it(self):
        """The consequence: with identity left stale, this second
        pass — reference-less, so it can only match on the content hash —
        inserts a duplicate and tombstones the original."""
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-02-05", amount=1000, ref="R1")], IV, CAP_STABLE))
        corrected = row("2026-02-06", amount=1200, ref="R1")
        apply.apply_plan(self.conn, "acc1",
                         ingest.reconcile(self._all(), [corrected], IV, CAP_STABLE))
        plain = dict(corrected, provider_ref=None, provider_ref_kind=None)
        stats = apply.apply_plan(
            self.conn, "acc1",
            ingest.reconcile(self._all(), [plain], IV, CAP_UNKNOWN))
        self.assertEqual((stats["inserted"], stats["tombstoned"]), (0, 0))
        self.assertEqual(len(self._all()), 1)

    def test_the_reallocated_occurrence_clears_a_tombstone_in_the_new_cluster(self):
        """The new occurrence is allocated above every occurrence ever issued
        in the NEW cluster, tombstones included — otherwise this update dies on
        UNIQUE (account_id, identity_key, occurrence)."""
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-02-05", amount=1000, ref="R1"),
                 row("2026-02-20", amount=1200)], IV, CAP_STABLE))
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            self._all(), [row("2026-02-05", amount=1000, ref="R1")],
            IV, CAP_STABLE))
        gone = [r for r in self._all() if r["state"] == "vanished"]
        self.assertEqual(len(gone), 1)                  # the 1200 row is a tombstone
        stats = apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            self._all(), [row("2026-02-06", amount=1200, ref="R1")],
            IV, CAP_STABLE))
        self.assertEqual(stats["updated"], 1)
        moved = [r for r in self._all() if r["row_id"] != gone[0]["row_id"]][0]
        self.assertEqual(moved["identity_key"], gone[0]["identity_key"])
        self.assertGreater(moved["occurrence"], gone[0]["occurrence"])

    def test_a_colliding_reallocation_raises_and_rolls_back(self):
        """No 'find a free slot and retry': reconcile allocates above the new
        cluster's maximum, so a collision means the plan was built against
        stale rows and quietly repairing it would hide the real fault."""
        apply.apply_plan(self.conn, "acc1", ingest.Plan(
            inserts=[dict(row("2026-02-05"), identity_key="K1", occurrence=0,
                          match_method="inserted", match_confidence=1.0,
                          needs_review=False, state="active", local_id="ins:0"),
                     dict(row("2026-03-05"), identity_key="K2", occurrence=0,
                          match_method="inserted", match_confidence=1.0,
                          needs_review=False, state="active", local_id="ins:1")],
            updates=[], tombstones=[], flags=[]))
        rid = self._all()[0]["row_id"]
        collide = dict(row("2026-02-05"), op="update", row_id=rid,
                       identity_key="K2", occurrence=0)
        with self.assertRaises(sqlite3.IntegrityError):
            apply.apply_plan(self.conn, "acc1",
                             ingest.Plan([], [collide], [], []))
        self.assertEqual([r["identity_key"] for r in self._all()], ["K1", "K2"])

    def test_an_update_that_carries_no_identity_is_refused(self):
        """An update missing these columns is how the invariant was lost last
        round. It must fail loudly rather than write a partial identity."""
        apply.apply_plan(self.conn, "acc1",
                         ingest.reconcile([], [row("2026-02-05")], IV, CAP_UNKNOWN))
        rid = self._all()[0]["row_id"]
        naked = dict(row("2026-02-07"), op="update", row_id=rid)
        with self.assertRaises(ValueError):
            apply.apply_plan(self.conn, "acc1", ingest.Plan([], [naked], [], []))
        self.assertEqual(self._all()[0]["booking_date"], "2026-02-05")


class TestSupersede(Base):
    def test_a_pending_row_is_superseded_by_the_booked_row(self):
        """pending -> booked is a SUPERSESSION, not an in-place update: the
        transition stays in the record and `superseded_by` points at the row
        that replaced it. Only the database knows that row_id, so
        apply must insert first and resolve `superseded_by_local` after."""
        plan = ingest.reconcile([], [row("2026-02-05", ref="R1", status="PDNG")],
                                IV, CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan)
        first = self._all()[0]["row_id"]
        plan2 = ingest.reconcile(self._all(),
                                 [row("2026-02-06", ref="R1", status="BOOK")],
                                 IV, CAP_STABLE)
        self.assertEqual([u["op"] for u in plan2.updates], ["supersede"])
        stats = apply.apply_plan(self.conn, "acc1", plan2)
        self.assertEqual((stats["inserted"], stats["superseded"]), (1, 1))
        rows = {r["row_id"]: r for r in self._all()}
        self.assertEqual(len(rows), 2)
        booked = next(r for r in rows.values() if r["row_id"] != first)
        self.assertEqual(rows[first]["state"], "superseded")
        self.assertEqual(rows[first]["superseded_by"], booked["row_id"])
        self.assertEqual((booked["state"], booked["status"]), ("active", "BOOK"))

    def test_an_unresolvable_supersede_is_a_hard_error(self):
        plan = ingest.reconcile([], [row("2026-02-05")], IV, CAP_UNKNOWN)
        apply.apply_plan(self.conn, "acc1", plan)
        rid = self._all()[0]["row_id"]
        inconsistent = ingest.Plan(
            inserts=[],
            updates=[{"op": "supersede", "row_id": rid, "state": "superseded",
                      "superseded_by_local": "ins:0", "match_method": "windowed",
                      "match_confidence": 0.9, "needs_review": False}],
            tombstones=[], flags=[])
        with self.assertRaises(ValueError):
            apply.apply_plan(self.conn, "acc1", inconsistent)
        self.assertEqual(self._all()[0]["state"], "active")     # rolled back
        self.assertIsNone(self._all()[0]["superseded_by"])


class TestCoverage(Base):
    def _rows(self):
        return self.conn.execute(
            "SELECT COUNT(*) FROM coverage WHERE account_id='acc1'").fetchone()[0]

    def test_overlapping_intervals_are_merged_on_write(self):
        apply.record_coverage(self.conn, "acc1", "2026-01-01", "2026-03-01", "s1")
        apply.record_coverage(self.conn, "acc1", "2026-02-01", "2026-04-01", "s2")
        self.assertEqual(apply.merged_coverage(self.conn, "acc1"),
                         [("2026-01-01", "2026-04-01")])
        self.assertEqual(self._rows(), 1)      # merged ON WRITE, not on read

    def test_adjacent_intervals_are_merged_on_write(self):
        apply.record_coverage(self.conn, "acc1", "2026-01-01", "2026-02-01", "s1")
        apply.record_coverage(self.conn, "acc1", "2026-02-01", "2026-03-01", "s1")
        self.assertEqual(apply.merged_coverage(self.conn, "acc1"),
                         [("2026-01-01", "2026-03-01")])
        self.assertEqual(self._rows(), 1)

    def test_disjoint_intervals_are_not_merged(self):
        apply.record_coverage(self.conn, "acc1", "2026-01-01", "2026-02-01", "s1")
        apply.record_coverage(self.conn, "acc1", "2026-03-01", "2026-04-01", "s1")
        self.assertEqual(apply.merged_coverage(self.conn, "acc1"),
                         [("2026-01-01", "2026-02-01"),
                          ("2026-03-01", "2026-04-01")])
        self.assertEqual(self._rows(), 2)

    def test_a_gap_is_reported_as_a_hole(self):
        apply.record_coverage(self.conn, "acc1", "2026-01-01", "2026-02-01", "s1")
        apply.record_coverage(self.conn, "acc1", "2026-03-01", "2026-04-01", "s1")
        self.assertEqual(apply.holes(self.conn, "acc1", "2026-01-01", "2026-04-01"),
                         [("2026-02-01", "2026-03-01")])

    def test_a_range_outside_all_coverage_is_entirely_a_hole(self):
        apply.record_coverage(self.conn, "acc1", "2026-01-01", "2026-02-01", "s1")
        self.assertEqual(apply.holes(self.conn, "acc1", "2026-05-01", "2026-06-01"),
                         [("2026-05-01", "2026-06-01")])


class TestPurgeTrimsCoverage(Base):
    """Coverage that outlives the rows it attests to is worse than no
    coverage: it reports deliberately erased history as PROVEN, and the gap
    disclosure has no way to notice."""

    def test_a_spanning_interval_is_trimmed_to_start_at_the_cutoff(self):
        """The exact case. A [2020, 2026) interval survived a
        purge-before-2024 completely unchanged, so 2020–2024 went on being
        reported as proven after the operator erased it."""
        apply.record_coverage(self.conn, "acc1", "2020-01-01", "2026-01-01", "s1")
        stats = apply.purge_before(self.conn, "2024-01-01")
        self.assertEqual(apply.merged_coverage(self.conn, "acc1"),
                         [("2024-01-01", "2026-01-01")])
        self.assertEqual(stats["coverage_trimmed"], 1)
        self.assertEqual(
            apply.holes(self.conn, "acc1", "2020-01-01", "2026-01-01"),
            [("2020-01-01", "2024-01-01")])      # the erased span reads as a hole

    def test_an_interval_wholly_before_the_cutoff_is_dropped(self):
        apply.record_coverage(self.conn, "acc1", "2020-01-01", "2021-01-01", "s1")
        apply.record_coverage(self.conn, "acc1", "2025-01-01", "2026-01-01", "s2")
        stats = apply.purge_before(self.conn, "2024-01-01")
        self.assertEqual(apply.merged_coverage(self.conn, "acc1"),
                         [("2025-01-01", "2026-01-01")])
        self.assertEqual((stats["coverage_dropped"], stats["coverage_trimmed"]),
                         (1, 0))

    def test_an_interval_at_or_after_the_cutoff_is_untouched(self):
        apply.record_coverage(self.conn, "acc1", "2024-01-01", "2026-01-01", "s1")
        stats = apply.purge_before(self.conn, "2024-01-01")
        self.assertEqual(apply.merged_coverage(self.conn, "acc1"),
                         [("2024-01-01", "2026-01-01")])
        self.assertEqual((stats["coverage_dropped"], stats["coverage_trimmed"]),
                         (0, 0))

    def test_transactions_and_their_reference_history_go_together(self):
        """The reference history of a deleted transaction is the same
        disclosure the transaction was; leaving it behind erases nothing."""
        wide = ("2023-01-01", "2026-01-01")
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2023-06-01", ref="OLD"), row("2025-06-01", ref="NEW")],
            wide, CAP_STABLE))
        stats = apply.purge_before(self.conn, "2024-01-01")
        self.assertEqual(stats["transactions"], 1)
        self.assertEqual([r["booking_date"] for r in self._all()], ["2025-06-01"])
        self.assertEqual({r[0] for r in self.conn.execute(
            "SELECT provider_ref FROM transaction_refs")}, {"NEW"})

    def test_a_purge_scoped_to_one_account_leaves_the_others_alone(self):
        apply.record_coverage(self.conn, "acc1", "2020-01-01", "2026-01-01", "s1")
        apply.record_coverage(self.conn, "acc2", "2020-01-01", "2026-01-01", "s1")
        apply.purge_before(self.conn, "2024-01-01", account_id="acc1")
        self.assertEqual(apply.merged_coverage(self.conn, "acc1"),
                         [("2024-01-01", "2026-01-01")])
        self.assertEqual(apply.merged_coverage(self.conn, "acc2"),
                         [("2020-01-01", "2026-01-01")])

    def test_every_account_is_trimmed_when_no_account_is_named(self):
        """The tool purges the whole ledger, and the operator has three banks.
        A spanning interval left behind on the second account is the same lie
        as one left behind on the first."""
        for acc in ("acc1", "acc2", "acc3"):
            apply.record_coverage(self.conn, acc, "2020-01-01", "2026-01-01", "s1")
        stats = apply.purge_before(self.conn, "2024-01-01")
        self.assertEqual(stats["coverage_trimmed"], 3)
        for acc in ("acc1", "acc2", "acc3"):
            self.assertEqual(apply.merged_coverage(self.conn, acc),
                             [("2024-01-01", "2026-01-01")], acc)

    def test_a_purge_that_erases_nothing_still_leaves_coverage_disjoint(self):
        """record_coverage merges on write, and trimming must preserve that:
        the surviving set stays a disjoint, ordered set of proven intervals."""
        apply.record_coverage(self.conn, "acc1", "2020-01-01", "2022-01-01", "s1")
        apply.record_coverage(self.conn, "acc1", "2023-01-01", "2026-01-01", "s2")
        apply.purge_before(self.conn, "2019-01-01")
        self.assertEqual(apply.merged_coverage(self.conn, "acc1"),
                         [("2020-01-01", "2022-01-01"),
                          ("2023-01-01", "2026-01-01")])


class TestAccountUpsert(Base):
    def test_the_same_account_keeps_its_id_across_sessions(self):
        """Rule 0 still holds: the durable key is derived from IBAN and
        currency, so a later session resolves to the SAME account rather than
        forking a second one. What is refused is rewriting that account's
        binding without review — not the identity, which never moves."""
        secret = store.local_secret(self.conn)
        a1 = apply.upsert_account(self.conn, {"uid": "u1", "iban": IBAN,
                                              "currency": "EUR",
                                              "name": "N. Voorbeeld"}, "s1", secret)
        with self.assertRaises(apply.RebindRefused) as cm:
            apply.upsert_account(self.conn, {"uid": "u2-NEW", "iban": IBAN,
                                             "currency": "EUR",
                                             "name": "N. Voorbeeld"}, "s2", secret)
        self.assertEqual(cm.exception.account_id, a1)   # one account, not two
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM accounts").fetchone()[0], 1)

    def test_re_applying_the_same_binding_is_idempotent(self):
        """A repeated collection of the same authorization is not a rebinding
        and must not refuse: the handle and the consent are the ones already
        recorded, so labels and everything else simply stay put."""
        secret = store.local_secret(self.conn)
        aid = apply.upsert_account(self.conn, {"uid": "u1", "iban": IBAN,
                                               "currency": "EUR"}, "s1", secret)
        self.conn.execute("UPDATE accounts SET label='huishouden',"
                          " category='personal' WHERE account_id=?", (aid,))
        again = apply.upsert_account(self.conn, {"uid": "u1", "iban": IBAN,
                                                 "currency": "EUR",
                                                 "name": "N. Voorbeeld"},
                                     "s1", secret)
        got = self.conn.execute("SELECT label, category, uid, session_id, name"
                                " FROM accounts WHERE account_id=?",
                                (aid,)).fetchone()
        self.assertEqual(again, aid)
        self.assertEqual((got["label"], got["category"], got["uid"],
                          got["session_id"], got["name"]),
                         ("huishouden", "personal", "u1", "s1", "N. Voorbeeld"))

    def test_the_caller_unwraps_the_nested_provider_iban(self):
        secret = store.local_secret(self.conn)
        provider = {"uid": "u1", "account_id": {"iban": IBAN},
                    "currency": "EUR", "name": "N. Voorbeeld"}
        aid = apply.upsert_account(self.conn, {
            "uid": provider["uid"],
            "iban": (provider.get("account_id") or {}).get("iban"),
            "currency": provider["currency"], "name": provider["name"]},
            "s1", secret)
        self.assertEqual(aid, store.account_id(IBAN, "EUR", secret))
        # Handing the RAW provider payload straight in used to produce
        # HMAC("|EUR") for every account. It must fail loudly instead.
        with self.assertRaises(ValueError):
            apply.upsert_account(self.conn, provider, "s1", secret)

    def test_the_aspsp_is_persisted_so_capability_lookup_can_work(self):
        """Without this column flows.backfill has no name to pass to
        provenance.capability(), so every ingest silently falls back to
        heuristic matching even for the rows the provider identifies
        exactly."""
        secret = store.local_secret(self.conn)
        aid = apply.upsert_account(self.conn, {"uid": "u1", "iban": IBAN,
                                               "currency": "EUR",
                                               "aspsp": "ABN AMRO"}, "s1", secret)
        self.assertEqual(self.conn.execute(
            "SELECT aspsp FROM accounts WHERE account_id=?",
            (aid,)).fetchone()[0], "ABN AMRO")

    def test_an_omitted_aspsp_does_not_erase_the_recorded_one(self):
        """A renewal payload that happens not to carry the bank name must not
        disable reference identity for an account that already had it."""
        secret = store.local_secret(self.conn)
        aid = apply.upsert_account(self.conn, {"uid": "u1", "iban": IBAN,
                                               "currency": "EUR",
                                               "aspsp": "Rabobank"}, "s1", secret)
        apply.upsert_account(self.conn, {"uid": "u1", "iban": IBAN,
                                         "currency": "EUR"}, "s1", secret)
        self.assertEqual(self.conn.execute(
            "SELECT aspsp FROM accounts WHERE account_id=?",
            (aid,)).fetchone()[0], "Rabobank")

    def test_an_iban_carrying_whitespace_is_refused_not_masked(self):
        """The WRITER's half of a defect whose reader half is fencing.

        `.strip()` removes leading and trailing whitespace only, so an IBAN
        with whitespace INSIDE it reaches two places at once: `store.account_id`
        keys the ledger on it, and `iban_masked` stores the raw provider bytes
        whenever the value was short enough to be kept unmasked. The read side
        now neutralises what it renders; this refuses to store it in the first
        place.

        Both shapes are covered on purpose. The long one proves the mask is not
        the only exposure — the ACCOUNT KEY is derived from the same string —
        and the short one is the branch that stores the value verbatim, where a
        newline would forge a line of output before any renderer saw it.
        """
        secret = store.local_secret(self.conn)
        for bad in ("NL00ABNA\n0000000002",     # long: keys the ledger
                    "NL00\tAB",                 # short: stored verbatim
                    "NL00ABNA\x000000002"):     # a control char, not whitespace
            with self.assertRaises(ValueError):
                apply.upsert_account(self.conn, {"uid": "u1", "iban": bad,
                                                 "currency": "EUR"},
                                     "s1", secret)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], 0)
        # And the message never echoes the value back.
        with self.assertRaises(ValueError) as caught:
            apply.upsert_account(self.conn,
                                 {"uid": "u1", "iban": "NL00ABNA\n0000000002",
                                  "currency": "EUR"}, "s1", secret)
        self.assertNotIn("0000000002", str(caught.exception))
        # Surrounding whitespace is still stripped, not refused: that is the
        # ordinary shape of a provider payload and it normalises unambiguously.
        aid = apply.upsert_account(self.conn, {"uid": "u1", "iban": " %s\n" % IBAN,
                                               "currency": "EUR"}, "s1", secret)
        self.assertEqual(aid, store.account_id(IBAN, "EUR", secret))

    def test_an_account_with_no_aspsp_reads_as_the_empty_string(self):
        """Not NULL: an unrecorded ASPSP must resolve through
        provenance.capability("") to DEFAULT_CAPABILITY — untrusted — which is
        the correct fail-closed direction."""
        secret = store.local_secret(self.conn)
        aid = apply.upsert_account(self.conn, {"uid": "u1", "iban": IBAN,
                                               "currency": "EUR"}, "s1", secret)
        self.assertEqual(self.conn.execute(
            "SELECT aspsp FROM accounts WHERE account_id=?",
            (aid,)).fetchone()[0], "")


class TestUnreviewedRebindingIsRefused(Base):
    """The BACKSTOP, not the renewal mechanism. A real renewal goes through
    `flows.complete_renewal` -> `apply.switch_bindings`, which proves the
    account set is exactly the bound one, backfills first, and then moves every
    binding in one transaction. `upsert_account` is one account at a
    time and runs before any fetch, so it can honour neither half — anything
    that rebinds through it is rebinding without the evidence, which is how a
    slow or out-of-order callback moved an account onto a session nobody had
    reviewed, with the old consent still open."""

    def bind(self, uid, session_id):
        return apply.upsert_account(
            self.conn, {"uid": uid, "iban": IBAN, "currency": "EUR",
                        "aspsp": "Rabobank"}, session_id,
            store.local_secret(self.conn))

    def account(self):
        return self.conn.execute("SELECT * FROM accounts").fetchone()

    def test_a_new_session_for_a_bound_account_is_refused_and_changes_nothing(self):
        aid = self.bind("u1", "s1")
        before = dict(self.account())
        with self.assertRaises(apply.RebindRefused) as cm:
            self.bind("u2", "s2")   # not the renewal path: no evidence, no move
        self.assertEqual(cm.exception.account_id, aid)
        self.assertEqual(dict(self.account()), before)   # uid and session intact

    def test_the_refusal_is_recorded_durably_and_names_no_session(self):
        """`review_required` has to outlive the call: the consent now exists at
        the bank and the operator must be able to find out why nothing was
        bound. The record names the account and never a session id."""
        aid = self.bind("u1", "s1")
        with self.assertRaises(apply.RebindRefused) as cm:
            self.bind("u1", "s2-fresh")
        row = self.conn.execute(
            "SELECT completeness, last_error FROM sync_state WHERE"
            " account_id=? AND resource='account_binding'", (aid,)).fetchone()
        self.assertEqual(row["completeness"], "review_required")
        self.assertIn("REVIEW REQUIRED", row["last_error"])
        self.assertNotIn("s1", row["last_error"])
        self.assertNotIn("s2-fresh", row["last_error"])
        self.assertNotIn("s2-fresh", str(cm.exception))

    def test_an_account_that_holds_no_binding_yet_is_not_a_rebinding(self):
        """A row created by an earlier partial run, or by a repair, carries no
        uid or session. Binding it for the first time is the ordinary path and
        must not be refused."""
        secret = store.local_secret(self.conn)
        aid = store.account_id(IBAN, "EUR", secret)
        self.conn.execute("INSERT INTO accounts(account_id) VALUES (?)", (aid,))
        again = apply.upsert_account(
            self.conn, {"uid": "u1", "iban": IBAN, "currency": "EUR"},
            "s1", secret)
        got = self.conn.execute("SELECT uid, session_id FROM accounts"
                                " WHERE account_id=?", (aid,)).fetchone()
        self.assertEqual(again, aid)
        self.assertEqual((got["uid"], got["session_id"]), ("u1", "s1"))

    def test_a_new_uid_on_the_SAME_session_is_also_refused(self):
        """Every OTHER test in this class changes the
        session, or changes both -- none offers a new `uid` alone. The
        backstop's whole job is to catch a moved BINDING, and the `uid` half
        (`apply.py`'s `moves_uid` check) is exactly as load-bearing as the
        `session_id` half: a provider account handle can be swapped out from
        under a session that never itself moved, and that is still a
        rebinding no renewal sequence reviewed."""
        aid = self.bind("u1", "s1")
        before = dict(self.account())
        with self.assertRaises(apply.RebindRefused) as cm:
            apply.upsert_account(
                self.conn, {"uid": "u1-NEW", "iban": IBAN, "currency": "EUR",
                            "aspsp": "Rabobank"}, "s1",
                store.local_secret(self.conn))
        self.assertEqual(cm.exception.account_id, aid)
        self.assertEqual(dict(self.account()), before)   # uid unchanged
        row = self.conn.execute(
            "SELECT completeness FROM sync_state WHERE"
            " account_id=? AND resource='account_binding'", (aid,)).fetchone()
        self.assertEqual(row["completeness"], "review_required")


class TestDurableOccurrenceAllocation(Base):
    """Rule 4 says an occurrence is never reused. `reconcile` can
    only see the rows a pass loaded, so the ledger has to remember the rest."""

    def _alloc(self, ident):
        row = self.conn.execute(
            "SELECT next_occurrence FROM occurrence_alloc WHERE account_id='acc1'"
            " AND identity_key=?", (ident,)).fetchone()
        return None if row is None else row["next_occurrence"]

    def test_applying_a_plan_raises_the_high_water_and_never_lowers_it(self):
        ident = ingest.identity_key(row("2026-02-05"))
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-02-05"), row("2026-02-05")], IV, CAP_UNKNOWN))
        self.assertEqual(self._alloc(ident), 2)
        # a later pass that can see only ONE of the two rows must not be able
        # to walk the mark back and free occurrence 1 for reuse
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            self._all()[:1], [row("2026-02-05")], IV, CAP_UNKNOWN,
            allocated=apply.occurrence_allocations(self.conn, "acc1", [ident])))
        self.assertEqual(self._alloc(ident), 2)

    def test_the_allocation_floors_on_rows_no_allocation_row_covers(self):
        """A ledger written before this table existed, or repaired by hand,
        still allocates safely: MAX(occurrence)+1 over the surviving rows is a
        floor the table can never sit below."""
        ident = ingest.identity_key(row("2026-02-05"))
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-02-05"), row("2026-02-05")], IV, CAP_UNKNOWN))
        self.conn.execute("DELETE FROM occurrence_alloc")
        self.assertEqual(
            apply.occurrence_allocations(self.conn, "acc1", [ident]), {ident: 2})

    def test_a_rolled_back_plan_leaves_no_allocation_behind(self):
        """Allocation and rows commit together. A mark raised by a plan that
        never landed would push real occurrences up for no reason; a mark
        LOST by a rollback that did land is the collision this table exists to
        prevent."""
        good = dict(row("2026-02-05"), identity_key="K", occurrence=0)
        clash = dict(row("2026-03-05"), identity_key="K", occurrence=0)
        with self.assertRaises(sqlite3.IntegrityError):
            apply.apply_plan(self.conn, "acc1",
                             ingest.Plan([good, clash], [], [], []))
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM occurrence_alloc").fetchone()[0], 0)

    def test_a_rekeyed_rows_vacated_slot_is_never_reissued_through_the_reader(self):
        """`occurrence_allocations`' own docstring calls
        `occurrence_alloc` "the ONLY record of a slot a re-keyed row VACATED"
        -- true, and until this test nothing exercised it end to end. Every
        existing test in this class reads the table directly
        (`self._alloc`); this one asks through `occurrence_allocations`, the
        actual function `ingest.reconcile`'s callers use, and feeds the
        result to a REAL later pass to prove the vacated slot is not handed
        back out."""
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-02-05", amount=1000, ref="R1")], IV, CAP_STABLE))
        original = self._all()[0]
        old_ident = original["identity_key"]
        corrected = row("2026-02-06", amount=1200, ref="R1")
        plan = ingest.reconcile(self._all(), [corrected], IV, CAP_STABLE)
        self.assertEqual([u["op"] for u in plan.updates], ["update"])
        apply.apply_plan(self.conn, "acc1", plan)
        after = self._all()[0]
        new_ident = after["identity_key"]
        self.assertNotEqual(old_ident, new_ident)          # genuinely re-keyed
        # zero surviving rows carry old_ident -- a row-derived floor sees
        # nothing at all for it
        self.assertEqual([r for r in self._all() if r["identity_key"] == old_ident], [])
        alloc = apply.occurrence_allocations(self.conn, "acc1", [old_ident])
        self.assertEqual(alloc, {old_ident: 1})     # remembered anyway
        # and the point of remembering it: a LATER pass, with no visibility
        # into the row that used to occupy old_ident (this simulates a
        # narrow refresh window that never loaded it), must not reissue
        # occurrence 0 when the ORIGINAL content resurfaces.
        resurfaced = row("2026-02-05", amount=1000, ref="R9")
        self.assertEqual(ingest.identity_key(resurfaced), old_ident)
        plan2 = ingest.reconcile([], [resurfaced], IV, CAP_UNKNOWN,
                                 allocated=alloc)
        self.assertEqual(plan2.inserts[0]["identity_key"], old_ident)
        self.assertGreater(plan2.inserts[0]["occurrence"], 0)   # NOT reissued


class TestSwitchBindings(Base):
    """The renewal HAPPY PATH. What makes it safe is not refusing it — that
    never completes and strands the operator — but the order and the atomicity:
    deep fetch first, then promote/switch/bump/retire together.
    `flows.complete_renewal` owns the order; this owns the act."""

    OTHER = "NL00RABO0000000003"

    def setUp(self):
        super().setUp()
        self.secret = store.local_secret(self.conn)
        self.aid = store.account_id(IBAN, "EUR", self.secret)
        self.other = store.account_id(self.OTHER, "EUR", self.secret)
        self.conn.execute(
            "INSERT INTO sessions(session_id, aspsp_name, status, generation)"
            " VALUES ('s-old','Rabobank','AUTHORIZED',4)")
        # the callback inserts the renewed session QUARANTINED; only the switch
        # promotes it, so an interrupted renewal defaults to "needs your
        # attention" instead of a second consent claiming to be live
        self.conn.execute(
            "INSERT INTO sessions(session_id, aspsp_name, status, generation)"
            " VALUES ('s-new','Rabobank','REVIEW_REQUIRED',0)")
        for aid in (self.aid, self.other):
            self.conn.execute(
                "INSERT INTO accounts(account_id, uid, session_id, aspsp,"
                " label, included) VALUES (?,?, 's-old', 'Rabobank', ?, ?)",
                (aid, "old-" + aid[:4], "huishouden", 0))

    def bindings(self):
        return [(self.aid, "new-1"), (self.other, "new-2")]

    def fetched(self, *account_ids, session_id="s-new", completeness="complete"):
        """The stamp flows.backfill leaves once apply_plan has committed.

        Deliberately writes no transactions: what a renewal needs to know is
        that the fetch RAN TO EXHAUSTION under the new consent, not that rows
        came back. A dormant account must renew like any other.
        """
        for account_id in (account_ids or (self.aid, self.other)):
            self.conn.execute(
                "INSERT OR REPLACE INTO sync_state(account_id, resource,"
                " last_attempt_at, last_success_at, completeness,"
                " last_success_session) VALUES (?,'transactions',?,?,?,?)",
                (account_id, "2026-08-03", "2026-08-03", completeness,
                 session_id))

    def accounts(self):
        return {r["account_id"]: dict(r) for r in self.conn.execute(
            "SELECT * FROM accounts")}

    def session(self, sid):
        return dict(self.conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (sid,)).fetchone())

    def test_it_promotes_switches_bumps_and_retires_together(self):
        self.fetched()
        out = apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        self.assertEqual((out["accounts"], out["generation"], out["retired"]),
                         (2, 5, True))
        rows = self.accounts()
        self.assertEqual({r["session_id"] for r in rows.values()}, {"s-new"})
        self.assertEqual(rows[self.aid]["uid"], "new-1")
        new = self.session("s-new")
        self.assertEqual((new["status"], new["generation"]), ("AUTHORIZED", 5))
        old = self.session("s-old")
        # Retired, and NOT hidden: at COMMIT the consent still exists at the
        # bank. `closed_at` is what removes a session from consent_status, so
        # it stays NULL until the provider confirms the revocation.
        self.assertEqual(old["status"], apply.RETIRED_STATUS)
        self.assertIsNone(old["closed_at"])

    def test_the_real_staging_trigger_permits_the_switchs_promote_then_retire_order(self):
        """`callbacks._stage_ledger` installs a TEMP
        trigger that aborts any UPDATE promoting a session to AUTHORIZED
        unless ANOTHER session for the same bank is ALREADY AUTHORIZED with
        closed_at NULL at that instant -- and `switch_bindings` is the sole
        production writer that residual is contained by (callbacks.py's own
        docstring names it). No test in this file installs that real trigger
        and drives a real switch through it, so nothing here actually
        exercises the interaction between this module and the gate that
        contains its residual: promote the new session while the old one it
        replaces is STILL AUTHORIZED, or the trigger fires and the whole
        renewal aborts."""
        self.fetched()
        callbacks._stage_ledger(self.conn)
        out = apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        self.assertEqual((out["accounts"], out["generation"], out["retired"]),
                         (2, 5, True))
        new = self.session("s-new")
        self.assertEqual((new["status"], new["generation"]), ("AUTHORIZED", 5))
        old = self.session("s-old")
        self.assertEqual(old["status"], apply.RETIRED_STATUS)
        self.assertIsNone(old["closed_at"])

    def test_the_retired_session_is_neither_live_nor_hidden(self):
        """The two queries that decide what an operator sees, run verbatim.

        `tools_auth._renewable_session` picks the current consent with
        `status='AUTHORIZED' AND closed_at IS NULL`; `consent_status` lists
        `closed_at IS NULL`. The old row must fail the first and pass the
        second, or the switch either forks the live consent or hides a grant
        that is still live at the bank."""
        self.fetched()
        apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        live = [r["session_id"] for r in self.conn.execute(
            "SELECT session_id FROM sessions WHERE aspsp_name='Rabobank'"
            " AND closed_at IS NULL AND status='AUTHORIZED'")]
        self.assertEqual(live, ["s-new"])
        listed = {r["session_id"] for r in self.conn.execute(
            "SELECT session_id FROM sessions WHERE closed_at IS NULL")}
        self.assertEqual(listed, {"s-new", "s-old"})

    def test_only_a_confirmed_revocation_closes_the_old_session(self):
        """The ledger half. `record_revocation` is the only thing that sets
        `closed_at` on a renewed-away session, and only the provider's
        confirmation gets it."""
        self.fetched()
        apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        apply.record_revocation(self.conn, "s-old", revoked=True)
        old = self.session("s-old")
        self.assertEqual(old["status"], "CLOSED")
        self.assertIsNotNone(old["closed_at"])
        self.assertEqual([r["session_id"] for r in self.conn.execute(
            "SELECT session_id FROM sessions WHERE closed_at IS NULL")],
            ["s-new"])

    def test_a_failed_revocation_stays_visible_and_revocable(self):
        """The consent is still live at the bank, so it must still be in front
        of the operator, still carry its `consent_ref`, and still be something
        `unlink_bank` can retry against. Hiding a consent we did not revoke is
        the stranding a quarantine exists to undo."""
        self.fetched()
        apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        apply.record_revocation(self.conn, "s-old", revoked=False)
        old = self.session("s-old")
        self.assertEqual(old["status"], apply.REVOKE_FAILED_STATUS)
        self.assertIsNone(old["closed_at"])
        # the lookup consent_status and unlink_bank actually perform
        refs = {hashlib.sha256(("consent-ref|" + r["session_id"]).encode()
                               ).hexdigest()[:8]: r["session_id"]
                for r in self.conn.execute(
                    "SELECT session_id FROM sessions WHERE closed_at IS NULL")}
        self.assertEqual(
            refs.get(hashlib.sha256(b"consent-ref|s-old").hexdigest()[:8]),
            "s-old")
        # and the retry closes it, which a hidden row could never reach
        apply.record_revocation(self.conn, "s-old", revoked=True)
        self.assertIsNotNone(self.session("s-old")["closed_at"])

    def test_labels_and_exclusions_survive_the_renewal_untouched(self):
        """They key on account_id, which does not move. A renewal that silently
        re-included an account the operator had excluded would change every
        balance and total in the system."""
        self.fetched()
        apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        for row in self.accounts().values():
            self.assertEqual((row["label"], row["included"]),
                             ("huishouden", 0))

    def test_a_renewal_whose_deep_fetch_did_not_complete_is_refused(self):
        """A renewal must not close the old session until the new session's
        deep fetch is durably complete. The evidence is the NEW
        session's completion stamp, which a capped or failed backfill never
        writes — so the invariant is checked against the ledger rather than
        assumed from call order."""
        self.fetched(self.aid)                     # only one of the two fetched
        with self.assertRaises(apply.RebindRefused) as cm:
            apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        self.assertIn("has not completed a history fetch", str(cm.exception))
        self.assertEqual({r["session_id"] for r in self.accounts().values()},
                         {"s-old"})
        self.assertEqual(self.session("s-new")["status"], "REVIEW_REQUIRED")
        self.assertIsNone(self.session("s-old")["closed_at"])

    def test_a_fetch_completed_by_the_OLD_session_is_not_evidence(self):
        """The account was fetched — by the consent being replaced. That says
        nothing about whether the NEW consent can read it."""
        self.fetched(session_id="s-old")
        with self.assertRaises(apply.RebindRefused):
            apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        self.assertEqual({r["session_id"] for r in self.accounts().values()},
                         {"s-old"})

    def test_an_account_not_bound_to_the_renewed_session_switches_nothing(self):
        """The per-account update is re-checked against the old session id, so
        a set that was right when it was read and wrong by the time it is
        written fails the whole thing rather than half of it."""
        self.fetched()
        self.conn.execute("UPDATE accounts SET session_id='s-elsewhere'"
                          " WHERE account_id=?", (self.other,))
        with self.assertRaises(ValueError):
            apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        self.assertEqual(self.accounts()[self.aid]["session_id"], "s-old")
        self.assertEqual(self.session("s-new")["status"], "REVIEW_REQUIRED")

    def test_a_switch_that_fails_partway_moves_nothing_at_all(self):
        """One transaction. Half an operator's accounts on the renewed session
        and half on one about to be retired is the forbidden state, and
        retrying does not repair it — so the failure is injected between the
        two account updates, which is exactly where a non-transactional
        implementation leaves that state."""
        self.fetched()

        class FailOnSecondAccount:
            """Passes everything through until the Nth matching statement."""

            def __init__(self, conn, needle, after):
                self.conn, self.needle, self.left = conn, needle, after

            def execute(self, sql, params=()):
                if self.needle in sql:
                    if self.left <= 0:
                        raise sqlite3.OperationalError("disk I/O error")
                    self.left -= 1
                return self.conn.execute(sql, params)

        broken = FailOnSecondAccount(self.conn, "UPDATE accounts SET uid=", 1)
        with self.assertRaises(sqlite3.OperationalError):
            apply.switch_bindings(broken, self.bindings(), "s-new", "s-old")
        rows = self.accounts()
        self.assertEqual({r["session_id"] for r in rows.values()}, {"s-old"})
        self.assertEqual(rows[self.aid]["uid"], "old-" + self.aid[:4])
        new = self.session("s-new")
        self.assertEqual((new["status"], new["generation"]),
                         ("REVIEW_REQUIRED", 0))
        self.assertIsNone(self.session("s-old")["closed_at"])

    def test_a_dormant_account_renews_like_any_other(self):
        """The point of stamping the FETCH rather than the coverage. An account
        that returned no rows proves no interval — "dormant" and "the bank
        truncated to nothing" are indistinguishable, so coverage must not claim
        one — but its retrieval still completed, and refusing to renew it would
        strand the operator on a consent about to expire."""
        self.fetched()
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM coverage").fetchone()[0], 0)
        out = apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        self.assertTrue(out["retired"])
        self.assertEqual({r["session_id"] for r in self.accounts().values()},
                         {"s-new"})

    def test_a_partial_fetch_is_not_a_completed_one(self):
        """A capped run stamps `partial` and carries the PREVIOUS session's id
        over, so it can never answer the precondition."""
        self.fetched(completeness="partial")
        with self.assertRaises(apply.RebindRefused):
            apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        self.assertEqual({r["session_id"] for r in self.accounts().values()},
                         {"s-old"})

    def test_a_completed_renewal_clears_the_binding_review_it_answers(self):
        """A resolved problem that keeps being reported teaches the operator to
        ignore the report."""
        self.fetched()
        apply.record_binding_review(self.conn, self.aid, "REVIEW REQUIRED: x")
        apply.switch_bindings(self.conn, self.bindings(), "s-new", "s-old")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM sync_state WHERE resource='account_binding'"
        ).fetchone()[0], 0)


class TestHonestCounts(Base):
    """`apply_plan`'s counts describe what was actually
    WRITTEN, not the length of the Plan it was handed -- reachable whenever a
    row_id the caller read into `stored` is deleted (purge_before,
    forget_local_account) before this Plan lands, and load-bearing because
    flows.backfill is about to record coverage on the strength of these
    counts."""

    def test_a_ghost_tombstone_and_flag_count_nothing(self):
        """A row_id that does not exist anywhere. Both statements affect zero
        rows; the pre-fix code counted them as one tombstone and one flag
        regardless, and the ledger held zero transactions the whole time."""
        ghost_tombstone = {"row_id": 999999, "state": "vanished", "reason": "x"}
        ghost_flag = {"row_id": 999999, "reason": "y"}
        stats = apply.apply_plan(self.conn, "acc1", ingest.Plan(
            [], [], [ghost_tombstone], [ghost_flag]))
        self.assertEqual((stats["tombstoned"], stats["flagged"]), (0, 0))
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM transactions").fetchone()[0], 0)

    def test_a_ghost_update_does_not_raise_the_durable_mark(self):
        """A ghost op="update" for a cluster with no rows must not raise the
        DURABLE occurrence_alloc mark from absent to present -- that mark
        means "this occurrence was issued", and none was."""
        ghost_update = {"op": "update", "row_id": 999999, "identity_key": "GHOST",
                        "occurrence": 5, "amount_minor": 100, "currency": "EUR",
                        "direction": "DBIT"}
        stats = apply.apply_plan(self.conn, "acc1",
                                 ingest.Plan([], [ghost_update], [], []))
        self.assertEqual(stats["updated"], 0)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM occurrence_alloc WHERE identity_key='GHOST'"
        ).fetchone()[0], 0)

    def test_a_ghost_supersede_counts_nothing(self):
        """The same discipline applies to supersede: a row_id vanished
        underneath the plan supersedes nothing, and an insert alongside it
        still lands and is still counted -- the ghost entry is skipped, not
        the whole plan."""
        ghost = {"op": "supersede", "row_id": 999999,
                 "superseded_by_local": "ins:0", "state": "superseded",
                 "match_method": "windowed", "match_confidence": 0.9,
                 "needs_review": False}
        plan = ingest.Plan(
            inserts=[dict(row("2026-02-05"), identity_key="K1", occurrence=0,
                          match_method="inserted", match_confidence=1.0,
                          needs_review=False, state="active", local_id="ins:0")],
            updates=[ghost], tombstones=[], flags=[])
        stats = apply.apply_plan(self.conn, "acc1", plan)
        self.assertEqual((stats["inserted"], stats["superseded"]), (1, 0))

    def test_a_real_row_alongside_a_ghost_is_still_counted(self):
        """The honest-count fix skips the GHOST entry, not the whole plan: a
        genuine flag in the same Plan as a ghost tombstone still lands and is
        still counted."""
        apply.apply_plan(self.conn, "acc1",
                         ingest.reconcile([], [row("2026-02-05")], IV, CAP_UNKNOWN))
        rid = self._all()[0]["row_id"]
        stats = apply.apply_plan(self.conn, "acc1", ingest.Plan(
            inserts=[], updates=[], tombstones=[],
            flags=[{"row_id": rid, "reason": "unresolved_cluster"},
                  {"row_id": 999999, "reason": "unresolved_cluster"}]))
        self.assertEqual(stats["flagged"], 1)
        self.assertEqual(self._all()[0]["needs_review"], 1)

    def test_a_plan_applied_under_one_account_cannot_touch_another_accounts_row(self):
        """row_id is a GLOBAL primary key, so a plan applied under account A
        that names account B's row_id -- a stale caller, or two callers racing
        on the same row_id space -- would silently rewrite B's ledger while
        reporting the write as A's. Unscoped, update, tombstone and flag all
        key on row_id alone; this reproduces the cross-account write against
        all three in one plan and asserts B's row is untouched in EVERY column
        and the counts are honestly zero, through the same rowcount==0 no-op."""
        apply.apply_plan(self.conn, "A",
                         ingest.reconcile([], [row("2026-02-05")], IV, CAP_UNKNOWN))
        apply.apply_plan(self.conn, "B",
                         ingest.reconcile([], [row("2026-03-05")], IV, CAP_UNKNOWN))
        b_before = next(r for r in self._all() if r["account_id"] == "B")
        b_row_id = b_before["row_id"]

        hostile_update = dict(row("2026-03-06", amount=9999), op="update",
                              row_id=b_row_id, identity_key="HOSTILE",
                              occurrence=0, needs_review=True,
                              reason="hostile")
        hostile_tombstone = {"row_id": b_row_id, "state": "vanished",
                             "reason": "hostile"}
        hostile_flag = {"row_id": b_row_id, "reason": "hostile"}
        stats = apply.apply_plan(self.conn, "A", ingest.Plan(
            inserts=[], updates=[hostile_update], tombstones=[hostile_tombstone],
            flags=[hostile_flag]))

        self.assertEqual((stats["updated"], stats["tombstoned"], stats["flagged"]),
                         (0, 0, 0))
        b_after = next(r for r in self._all() if r["row_id"] == b_row_id)
        self.assertEqual(b_after, b_before)     # every column, untouched
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM occurrence_alloc WHERE identity_key='HOSTILE'"
        ).fetchone()[0], 0)          # the ghost update raised no durable mark

    def test_a_plan_applied_under_one_account_cannot_supersede_anothers_row(self):
        """The fourth statement: supersede. A's plan still inserts its own
        booked row -- only the cross-account supersede of B's row is refused,
        the same "skip the ghost entry, not the whole plan" composition round
        1 established."""
        apply.apply_plan(self.conn, "A", ingest.reconcile(
            [], [row("2026-02-05", status="PDNG")], IV, CAP_UNKNOWN))
        apply.apply_plan(self.conn, "B",
                         ingest.reconcile([], [row("2026-03-05")], IV, CAP_UNKNOWN))
        b_before = next(r for r in self._all() if r["account_id"] == "B")

        plan = ingest.Plan(
            inserts=[dict(row("2026-02-06"), identity_key="K-NEW", occurrence=0,
                          match_method="inserted", match_confidence=1.0,
                          needs_review=False, state="active", local_id="ins:0")],
            updates=[{"op": "supersede", "row_id": b_before["row_id"],
                     "state": "superseded", "superseded_by_local": "ins:0",
                     "match_method": "windowed", "match_confidence": 0.9,
                     "needs_review": False, "reason": None}],
            tombstones=[], flags=[])
        stats = apply.apply_plan(self.conn, "A", plan)
        self.assertEqual((stats["inserted"], stats["superseded"]), (1, 0))
        b_after = next(r for r in self._all() if r["row_id"] == b_before["row_id"])
        self.assertEqual(b_after, b_before)     # B's row untouched: still active


class TestReviewReasonAndIdentityIntegrity(Base):
    """Two independent guarantees about what an `apply_plan` write leaves behind.

    **A review flag and its cause travel together, WITHIN one plan**: an
    insert's reason reaches `review_reason`, an update's reason reaches it, and
    an update does not clear a flag set in the same plan.

    **A row's identity keeps hashing its own content**: a re-key that moves
    `direction` or `currency` writes those columns too, so `identity_key` never
    describes content the row no longer holds.

    They live together because both are properties of one statement's column
    list, and a mutation of that list breaks one or the other.

    The cross-pass half — a flag and its cause surviving a LATER plan — is
    `TestReviewFlagsSurviveLaterPasses` below, and it is deliberately separate:
    every property here can hold while that one fails, because a single plan
    carrying both records cannot express the failure at all."""

    def test_an_insert_reason_is_persisted_to_review_reason(self):
        """ingest.emit_insert carries `reason` (None unless
        needs_review) on every inserts[] record; dropping it here is exactly
        the gap that leaves a reader unable to say WHY a row needs review.

        A reference reused 45 days later (beyond the match window) fails
        corroboration: the stored row is flagged provider_ref_reuse AND the
        fetched row lands as an INSERT carrying the same reason, because it
        claimed a trusted reference under false pretences."""
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-01-01", ref="R1")], IV, CAP_STABLE))
        plan2 = ingest.reconcile(self._all(), [row("2026-02-15", ref="R1")],
                                 IV, CAP_STABLE)
        self.assertTrue(plan2.inserts and plan2.inserts[0]["needs_review"],
                        "fixture must exercise a needs_review insert or this "
                        "test proves nothing")
        self.assertEqual(plan2.inserts[0]["reason"], "provider_ref_reuse")
        apply.apply_plan(self.conn, "acc1", plan2)
        inserted = next(r for r in self._all() if r["booking_date"] == "2026-02-15")
        self.assertEqual(inserted["needs_review"], 1)
        self.assertEqual(inserted["review_reason"], "provider_ref_reuse")

    def test_an_update_reason_is_persisted_to_review_reason(self):
        """The other half: op="update" records also carry `reason`
        (ingest.emit_match). A direction/currency flip is corroborated at
        confidence 1.0 and re-keyed silently unless the reason it carries
        (direction_or_currency_changed) reaches review_reason."""
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-02-05", ref="R1")], IV, CAP_STABLE))
        flipped = dict(row("2026-02-06", ref="R1"), direction="CRDT")
        plan = ingest.reconcile(self._all(), [flipped], IV, CAP_STABLE)
        self.assertEqual([u["op"] for u in plan.updates], ["update"])
        self.assertEqual(plan.updates[0]["reason"],
                         "direction_or_currency_changed")
        apply.apply_plan(self.conn, "acc1", plan)
        after = self._all()[0]
        self.assertTrue(after["needs_review"])
        self.assertEqual(after["review_reason"], "direction_or_currency_changed")

    def test_a_rekey_that_flips_direction_keeps_identity_matching_content(self):
        """identity_key hashes `currency` and `direction`
        (ingest.identity_key); a re-key that writes the new identity_key
        without also writing the new direction/currency columns would leave
        the row's OWN content hash disagreeing with its own stored row -- the
        same identity-drift defect, just for the two fields a fixed 'mutable
        columns' list omits."""
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-02-05", ref="R1")], IV, CAP_STABLE))
        flipped = dict(row("2026-02-06", ref="R1"), direction="CRDT")
        plan = ingest.reconcile(self._all(), [flipped], IV, CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan)
        after = self._all()[0]
        self.assertEqual(after["direction"], "CRDT")
        self.assertEqual(after["identity_key"], ingest.identity_key(dict(after)))

    def test_a_flag_in_the_same_plan_survives_an_update_that_clears_review(self):
        """Asserted directly rather than only via ordering. One row_id
        carries BOTH an op="update" with needs_review=False and a flags entry
        with a reason, in the SAME Plan -- exactly the scenario ingest.Plan's
        docstring names. Applying the update must not undo the flag."""
        apply.apply_plan(self.conn, "acc1",
                         ingest.reconcile([], [row("2026-02-05")], IV, CAP_UNKNOWN))
        rid = self._all()[0]["row_id"]
        clean_update = dict(row("2026-02-05", counterparty="Bijgewerkt"),
                            op="update", row_id=rid,
                            identity_key=ingest.identity_key(
                                dict(row("2026-02-05", counterparty="Bijgewerkt"))),
                            occurrence=0, needs_review=False)
        plan = ingest.Plan(
            inserts=[], updates=[clean_update], tombstones=[],
            flags=[{"row_id": rid, "reason": "content_present_elsewhere"}])
        apply.apply_plan(self.conn, "acc1", plan)
        after = self._all()[0]
        self.assertEqual(after["needs_review"], 1)
        self.assertEqual(after["review_reason"], "content_present_elsewhere")
        self.assertEqual(after["counterparty"], "Bijgewerkt")   # the update DID land


class TestReviewFlagsSurviveLaterPasses(Base):
    """The cross-pass half of the same guarantee, which nothing held.

    `ingest.Plan`'s docstring already says "needs_review = needs_review OR 1,
    never an assignment", and apply's own comment argues flags cannot be
    cleared because they are applied last -- but BOTH arguments are about ONE
    PLAN,
    and the case that occurs in production is an update in a LATER plan
    overwriting a flag an earlier one set. Every test that existed used a
    single plan carrying both records, which is precisely why this survived:
    the fixture could not express the failure.

    Reproduced through the shipped `sync` tool before it was fixed: the bank
    corrected one remittance string, and a row flagged provider_ref_reuse came
    back needs_review=0 / review_reason=NULL, turning `list_transactions`'
    "1 flagged for review (1 provider reference reuse)" into "none flagged for
    review" with nothing reviewed. Reachable on every routine refresh -- one
    asks for `last booked date - 7 days`, exactly the window in which banks
    amend remittance text and flip PDNG to BOOK, and EVERY field in
    ingest._MUTABLE triggers it.
    """

    def _flagged_row(self, reason="provider_ref_reuse"):
        """Pass 1: a row in the ledger, flagged through the real producer path
        (a `flags` entry), not by a hand-written UPDATE."""
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-02-05", ref="R1")], IV, CAP_STABLE))
        rid = self._all()[0]["row_id"]
        apply.apply_plan(self.conn, "acc1", ingest.Plan(
            inserts=[], updates=[], tombstones=[],
            flags=[{"row_id": rid, "reason": reason}]))
        self.assertEqual(self._all()[0]["needs_review"], 1)
        return rid

    def _clean_later_pass(self, **overrides):
        """Pass 2, a SEPARATE apply_plan call: the bank amends one mutable
        field and nothing about this pass is remarkable. Asserts the plan
        really carries needs_review=False and reason=None first -- a fixture
        that quietly produced a flagged update would prove nothing."""
        amended = dict(row("2026-02-05", ref="R1"),
                       remittance="boodschappen (gecorrigeerd)", **overrides)
        plan = ingest.reconcile(self._all(), [amended], IV, CAP_STABLE)
        self.assertEqual([u["op"] for u in plan.updates], ["update"],
                         "fixture must produce a plain update or this test "
                         "proves nothing")
        self.assertFalse(plan.updates[0]["needs_review"])
        self.assertIsNone(plan.updates[0].get("reason"))
        apply.apply_plan(self.conn, "acc1", plan)
        return self._all()[0]

    def test_a_later_clean_pass_does_not_un_flag_a_row(self):
        self._flagged_row()
        self.assertEqual(self._clean_later_pass()["needs_review"], 1)

    def test_a_later_clean_pass_does_not_erase_the_stated_cause(self):
        # The other half. Preserving the flag alone would leave a row flagged
        # with NO stated cause -- which is what the insert statement's own
        # comment says review_reason exists to prevent, and what the
        # disclosure line has to be able to answer.
        self._flagged_row()
        self.assertEqual(self._clean_later_pass()["review_reason"],
                         "provider_ref_reuse")

    def test_the_amendment_itself_still_lands(self):
        # Monotonic in ONE column, not frozen. A fix that stopped the update
        # from applying would be a worse defect than the one it closed.
        self._flagged_row()
        self.assertEqual(self._clean_later_pass()["remittance"],
                         "boodschappen (gecorrigeerd)")

    def test_a_newer_cause_replaces_the_older_one(self):
        # Sticky is not the same as immutable: a pass that HAS a finding must
        # name it, or COALESCE would pin the first cause a row ever received
        # and hide every later, more alarming one. A direction flip is
        # corroborated at confidence 1.0 and re-keyed, carrying
        # direction_or_currency_changed.
        self._flagged_row(reason="windowed_ambiguous")
        flipped = dict(row("2026-02-06", ref="R1"), direction="CRDT")
        plan = ingest.reconcile(self._all(), [flipped], IV, CAP_STABLE)
        self.assertEqual(plan.updates[0]["reason"],
                         "direction_or_currency_changed")
        apply.apply_plan(self.conn, "acc1", plan)
        after = self._all()[0]
        self.assertEqual(after["needs_review"], 1)
        self.assertEqual(after["review_reason"], "direction_or_currency_changed")

    def test_a_supersede_does_not_un_flag_the_row_it_replaces(self):
        # The COMPOSITE behaviour through the real producer: reconcile plus
        # apply, end to end.
        #
        # This is NOT the kill for the supersede statement's `MAX(needs_review,
        # ?)`: `ingest.emit_match` sets needs_review=True on the supersede
        # record whenever the stored row is flagged, so the third parameter is
        # already 1 by the time apply sees it and `MAX` is never load-bearing
        # on THIS path. What this test pins is that the two layers compose
        # correctly. The apply-layer guarantee itself is pinned by the test
        # below, which hands apply a plan that really does try to clear the
        # flag.
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-02-05", ref="R1", status="PDNG")], IV, CAP_STABLE))
        rid = self._all()[0]["row_id"]
        apply.apply_plan(self.conn, "acc1", ingest.Plan(
            inserts=[], updates=[], tombstones=[],
            flags=[{"row_id": rid, "reason": "provider_ref_reuse"}]))
        plan = ingest.reconcile(
            self._all(), [row("2026-02-05", ref="R1", status="BOOK")],
            IV, CAP_STABLE)
        self.assertIn("supersede", [u.get("op") for u in plan.updates],
                      "fixture must produce a supersede or this test proves "
                      "nothing")
        apply.apply_plan(self.conn, "acc1", plan)
        superseded = next(r for r in self._all() if r["row_id"] == rid)
        self.assertEqual(superseded["state"], "superseded")
        self.assertEqual(superseded["needs_review"], 1)
        self.assertEqual(superseded["review_reason"], "provider_ref_reuse")

    def test_a_supersede_RECORD_that_clears_review_cannot_un_flag_the_row(self):
        """The apply-layer guarantee, executed rather than grepped for.

        Without this, the only executable defence of the supersede statement's
        `MAX(needs_review, ?)` is
        `test_nothing_in_this_slice_can_clear_the_flag`'s grep for the literal
        `needs_review=?` — which a reformat (`needs_review = ?`, a named
        parameter, a split string literal) walks straight past. A guarantee
        held by a grep is weaker than the report claimed.

        `apply` must not depend on its producer being careful: its contract is
        per-record, and `ingest` is not the only thing that can hand it a Plan.
        So the plan here is built by hand and its supersede record carries
        `needs_review=False, reason=None` over a row already flagged —
        precisely the record `ingest` used to emit and a future producer could
        emit again.
        """
        apply.apply_plan(self.conn, "acc1", ingest.reconcile(
            [], [row("2026-02-05", ref="R1", status="PDNG")], IV, CAP_STABLE))
        rid = self._all()[0]["row_id"]
        apply.apply_plan(self.conn, "acc1", ingest.Plan(
            inserts=[], updates=[], tombstones=[],
            flags=[{"row_id": rid, "reason": "provider_ref_reuse"}]))

        booked = row("2026-02-07", ref="R1", status="BOOK")
        replacement = dict(booked, identity_key=ingest.identity_key(booked),
                           occurrence=1, match_method="reference",
                           match_confidence=1.0, needs_review=False,
                           reason=None, state="active", local_id="ins:0")
        plan = ingest.Plan(
            inserts=[replacement],
            updates=[{"op": "supersede", "row_id": rid, "state": "superseded",
                      "superseded_by_local": "ins:0",
                      "match_method": "reference", "match_confidence": 1.0,
                      "needs_review": False, "reason": None}],
            tombstones=[], flags=[])
        self.assertFalse(plan.updates[0]["needs_review"],
                         "the plan must really try to clear the flag or this "
                         "test proves nothing")
        apply.apply_plan(self.conn, "acc1", plan)

        superseded = next(r for r in self._all() if r["row_id"] == rid)
        self.assertEqual(superseded["state"], "superseded")
        self.assertEqual(superseded["needs_review"], 1)
        self.assertEqual(superseded["review_reason"], "provider_ref_reuse")

    def test_nothing_in_this_slice_can_clear_the_flag(self):
        """The constraint written down rather than discovered later.

        These two statements were the ONLY writers of a non-1 `needs_review`
        in the tree, and the manifest declares no tool that could mark a row
        reviewed -- so making them monotonic costs nothing. A feature that
        adds a "mark reviewed" path MUST clear the column with its
        own explicit statement; it cannot rely on an ingest update doing it,
        and this test is what will tell it so.
        """
        # Comment lines are stripped: the comments beside those statements
        # QUOTE the old assignment to explain what was wrong with it, and a
        # grep that cannot tell prose from code would forbid saying so.
        source = "\n".join(
            line for line in
            pathlib.Path(apply.__file__).read_text("utf-8").splitlines()
            if not line.lstrip().startswith("#"))
        self.assertNotIn("needs_review=?", source,
                         "a plain assignment to needs_review is what let a "
                         "routine refresh un-flag a row; use "
                         "MAX(needs_review, ?) or clear it deliberately")
        manifest = json.loads(
            (pathlib.Path(apply.__file__).resolve().parents[1] /
             ".claude-plugin/plugin.json").read_text("utf-8"))
        tools = {t.rsplit("__", 1)[-1]
                 for t in manifest["casa"]["provides_tools"]}
        self.assertEqual(
            tools & {"mark_reviewed", "review_transaction", "clear_review"},
            set(), "a review-clearing tool now exists: it needs its own "
                   "explicit UPDATE, and this test needs updating with it")


class TestAnnotationSurvival(Base):
    """Annotations are anchored to row_id; the ONE event that changes which
    row is live is supersession, so apply_plan must re-point them there —
    and ONLY when the supersede actually landed (the UPDATE deliberately
    skips rows a concurrent purge/forget already deleted)."""

    def _annotate(self, row_id):
        self.conn.execute(
            "INSERT INTO transaction_tags(row_id, tag, added_at)"
            " VALUES (?, 'groceries', '2026-08-05T00:00:00')", (row_id,))
        self.conn.execute(
            "INSERT INTO transaction_notes(row_id, author, note, created_at)"
            " VALUES (?, 'user', 'invoice missing', '2026-08-05T00:00:00')",
            (row_id,))

    def _superseding_plan(self):
        plan = ingest.reconcile([], [row("2026-02-05", ref="R1", status="PDNG")],
                                IV, CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan)
        old = self._all()[0]["row_id"]
        plan2 = ingest.reconcile(self._all(),
                                 [row("2026-02-06", ref="R1", status="BOOK")],
                                 IV, CAP_STABLE)
        self.assertEqual([u["op"] for u in plan2.updates], ["supersede"])
        return old, plan2

    def test_supersede_moves_annotations_to_replacement(self):
        old, plan2 = self._superseding_plan()
        self._annotate(old)
        apply.apply_plan(self.conn, "acc1", plan2)
        new = self.conn.execute(
            "SELECT superseded_by FROM transactions WHERE row_id=?",
            (old,)).fetchone()[0]
        self.assertIsNotNone(new)
        self.assertEqual(
            [r[0] for r in self.conn.execute(
                "SELECT row_id FROM transaction_tags WHERE tag='groceries'")],
            [new])
        self.assertEqual(
            [r[0] for r in self.conn.execute(
                "SELECT row_id FROM transaction_notes")],
            [new])

    def _fts_in_sync(self):
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM notes_fts"
                              ).fetchone()[0],
            self.conn.execute("SELECT COUNT(*) FROM transaction_notes"
                              ).fetchone()[0])
        # FTS5's own integrity check raises on a desynced index.
        self.conn.execute("INSERT INTO notes_fts(notes_fts)"
                          " VALUES('integrity-check')")

    def test_supersede_migration_keeps_note_searchable_under_new_row(self):
        # The migration UPDATEs transaction_notes.row_id only — a column the
        # FTS index does not carry. The note must stay searchable and resolve
        # to the NEW row.
        old, plan2 = self._superseding_plan()
        self.conn.execute(
            "INSERT INTO transaction_notes(row_id, author, note,"
            " created_at) VALUES (?, 'user', 'migratemarker abc',"
            " '2026-08-05T00:00:00')", (old,))
        apply.apply_plan(self.conn, "acc1", plan2)
        new = self.conn.execute(
            "SELECT superseded_by FROM transactions WHERE row_id=?",
            (old,)).fetchone()[0]
        hits = self.conn.execute(
            "SELECT n.row_id FROM transaction_notes n WHERE n.note_id IN"
            " (SELECT rowid FROM notes_fts WHERE notes_fts MATCH"
            " 'migratemarker')").fetchall()
        self.assertEqual([r[0] for r in hits], [new])
        self._fts_in_sync()

    def test_skipped_supersede_moves_nothing(self):
        """A supersede whose UPDATE affects zero rows (the row was deleted
        between plan build and apply — the intentional silent-skip path)
        superseded nothing, so moving annotations for it would annotate an
        unrelated fresh insert."""
        old, plan2 = self._superseding_plan()
        self._annotate(old)
        self.conn.execute("DELETE FROM transactions WHERE row_id=?", (old,))
        stats = apply.apply_plan(self.conn, "acc1", plan2)
        self.assertEqual(stats["superseded"], 0)          # precondition: skipped
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM transaction_tags WHERE row_id=?",
            (old,)).fetchone()[0], 1)                     # stranded, NOT moved
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM transaction_notes WHERE row_id=?",
            (old,)).fetchone()[0], 1)

    def test_tombstone_and_rekey_leave_annotations_in_place(self):
        plan = ingest.reconcile([], [row("2026-02-05", ref="R1")],
                                IV, CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan)
        rid = self._all()[0]["row_id"]
        self._annotate(rid)
        # a later fetch of the same interval without the row tombstones it
        plan2 = ingest.reconcile(self._all(), [], IV, CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan2)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM transaction_tags WHERE row_id=?",
            (rid,)).fetchone()[0], 1)


class TestFanInSupersede(Base):
    def test_two_sources_sharing_a_tag_migrate_without_rollback(self):
        """apply_plan structurally accepts a FAN-IN plan (two supersedes
        naming the same replacement). reconciliation is one-to-one today,
        but when the sources share a tag a plain migration UPDATE would
        raise UNIQUE(row_id, tag) and roll back the WHOLE plan — one
        annotation collision destroying an entire backfill's writes."""
        plan = ingest.reconcile(
            [], [row("2026-02-05", ref="R1", status="PDNG"),
                 row("2026-02-06", ref="R2", status="PDNG")],
            IV, CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan)
        old_a, old_b = [r["row_id"] for r in self._all()]
        for rid in (old_a, old_b):
            self.conn.execute(
                "INSERT INTO transaction_tags(row_id, tag, added_at)"
                " VALUES (?, 'shared', '2026-08-05T00:00:00')", (rid,))
        booked = dict(row("2026-02-07", ref="R3", status="BOOK"),
                      local_id="ins:0", identity_key="ik-new", occurrence=0,
                      match_method="reference", needs_review=False)
        fan_in = ingest.Plan(
            inserts=[booked],
            updates=[{"op": "supersede", "row_id": old_a,
                      "state": "superseded", "superseded_by_local": "ins:0",
                      "match_method": "reference", "match_confidence": 1.0,
                      "needs_review": False},
                     {"op": "supersede", "row_id": old_b,
                      "state": "superseded", "superseded_by_local": "ins:0",
                      "match_method": "reference", "match_confidence": 1.0,
                      "needs_review": False}],
            tombstones=[], flags=[])
        stats = apply.apply_plan(self.conn, "acc1", fan_in)   # must not raise
        self.assertEqual(stats["superseded"], 2)
        new_id = self.conn.execute(
            "SELECT superseded_by FROM transactions WHERE row_id=?",
            (old_a,)).fetchone()[0]
        self.assertEqual([tuple(r) for r in self.conn.execute(
            "SELECT row_id, tag FROM transaction_tags")], [(new_id, "shared")])


class TestPurgeDeletesAnnotations(Base):
    def test_purged_rows_lose_annotations_kept_rows_keep_them(self):
        plan = ingest.reconcile(
            [], [row("2020-02-05"), row("2026-03-05")],
            ("2020-01-01", "2026-04-01"), CAP_UNKNOWN)
        apply.apply_plan(self.conn, "acc1", plan)
        by_date = {r["booking_date"]: r["row_id"] for r in self._all()}
        for rid in by_date.values():
            self.conn.execute(
                "INSERT INTO transaction_tags(row_id, tag, added_at)"
                " VALUES (?, 'old', '2026-08-05T00:00:00')", (rid,))
            self.conn.execute(
                "INSERT INTO transaction_notes(row_id, author, note,"
                " created_at) VALUES (?, 'agent', 'n', '2026-08-05T00:00:00')",
                (rid,))
        apply.purge_before(self.conn, "2025-01-01")
        doomed, kept = by_date["2020-02-05"], by_date["2026-03-05"]
        for table in ("transaction_tags", "transaction_notes"):
            self.assertEqual(self.conn.execute(
                "SELECT COUNT(*) FROM %s WHERE row_id=?" % table,
                (doomed,)).fetchone()[0], 0, table)
            self.assertEqual(self.conn.execute(
                "SELECT COUNT(*) FROM %s WHERE row_id=?" % table,
                (kept,)).fetchone()[0], 1, table)

    def test_purge_leaves_fts_in_sync_and_unmatchable(self):
        # The AFTER DELETE trigger must fire inside purge_before's own
        # deletes — a purged note that still MATCHed would resurrect
        # deleted history through the search surface.
        plan = ingest.reconcile(
            [], [row("2020-02-05"), row("2026-03-05")],
            ("2020-01-01", "2026-04-01"), CAP_UNKNOWN)
        apply.apply_plan(self.conn, "acc1", plan)
        by_date = {r["booking_date"]: r["row_id"] for r in self._all()}
        self.conn.execute(
            "INSERT INTO transaction_notes(row_id, author, note,"
            " created_at) VALUES (?, 'agent', 'purgemarker xyz', 't')",
            (by_date["2020-02-05"],))
        self.conn.execute(
            "INSERT INTO transaction_notes(row_id, author, note,"
            " created_at) VALUES (?, 'agent', 'keepmarker xyz', 't')",
            (by_date["2026-03-05"],))
        apply.purge_before(self.conn, "2025-01-01")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM notes_fts WHERE notes_fts MATCH"
            " 'purgemarker'").fetchone()[0], 0)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM notes_fts WHERE notes_fts MATCH"
            " 'keepmarker'").fetchone()[0], 1)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM notes_fts"
                              ).fetchone()[0],
            self.conn.execute("SELECT COUNT(*) FROM transaction_notes"
                              ).fetchone()[0])
        self.conn.execute("INSERT INTO notes_fts(notes_fts)"
                          " VALUES('integrity-check')")


if __name__ == "__main__":
    unittest.main()


class TestRuleApplicationInApplyPlan(Base):
    def _mint_rule(self, counterparty="Voorbeeld Supermarkt",
                   tags=("food", "groceries")):
        fields, refusal = rules.validate_rule(
            {"counterparty": counterparty, "tags": list(tags)})
        assert refusal is None, refusal
        self.conn.execute(
            "INSERT INTO tag_rules(signature, counterparty_canon, tags,"
            " created_at) VALUES (?,?,?,'t')",
            (rules.signature(fields), fields["counterparty_canon"],
             fields["tags"]))

    def test_inserted_rows_are_rule_tagged_atomically(self):
        self._mint_rule()
        plan = ingest.reconcile([], [row("2026-02-05")], IV, CAP_UNKNOWN)
        stats = apply.apply_plan(self.conn, "acc1", plan)
        self.assertEqual(len(stats["inserted_row_ids"]), 1)
        rid = stats["inserted_row_ids"][0]
        self.assertEqual(stats["auto_tagged"], 1)
        self.assertTrue(stats["rules"])          # per-rule report present
        tags = sorted(r[0] for r in self.conn.execute(
            "SELECT tag FROM transaction_tags WHERE row_id=?", (rid,)))
        self.assertEqual(tags, ["food", "groceries"])

    def test_no_rules_means_zero_tagged_and_ids_still_returned(self):
        plan = ingest.reconcile([], [row("2026-02-05")], IV, CAP_UNKNOWN)
        stats = apply.apply_plan(self.conn, "acc1", plan)
        self.assertEqual(stats["auto_tagged"], 0)
        self.assertEqual(len(stats["inserted_row_ids"]), 1)

    def test_rule_failure_rolls_back_whole_plan(self):
        self._mint_rule()
        plan = ingest.reconcile([], [row("2026-02-05")], IV, CAP_UNKNOWN)
        orig = rules.apply_to_rows
        rules.apply_to_rows = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("boom"))
        try:
            with self.assertRaises(RuntimeError):
                apply.apply_plan(self.conn, "acc1", plan)
        finally:
            rules.apply_to_rows = orig
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM transactions").fetchone()[0], 0)
        # The occurrence high-water mark rolled back too.
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM occurrence_alloc").fetchone()[0], 0)

    def test_supersede_migration_lands_before_rules_run(self):
        # A PENDING row with a stable reference, hand-tagged.
        plan = ingest.reconcile(
            [], [row("2026-02-05", ref="R1", status="PDNG")], IV,
            CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan)
        old_id = self._all()[0]["row_id"]
        self.conn.execute(
            "INSERT INTO transaction_tags(row_id, tag, added_at)"
            " VALUES (?,'handmade','t')", (old_id,))
        # The booked twin arrives (same ref) — reconcile emits a
        # supersede pointing at a row THIS plan inserts. With a rule
        # minted, the replacement must end up carrying BOTH the migrated
        # hand tag and the rule tags: rules ran after the updates loop,
        # inside the same transaction.
        self._mint_rule()
        plan2 = ingest.reconcile(
            self._all(), [row("2026-02-05", ref="R1", status="BOOK")],
            IV, CAP_STABLE)
        stats = apply.apply_plan(self.conn, "acc1", plan2)
        self.assertEqual(stats["superseded"], 1)
        new_id = stats["inserted_row_ids"][0]
        tags = sorted(r[0] for r in self.conn.execute(
            "SELECT tag FROM transaction_tags WHERE row_id=?",
            (new_id,)))
        self.assertEqual(tags, ["food", "groceries", "handmade"])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM transaction_tags WHERE row_id=?",
            (old_id,)).fetchone()[0], 0)

    def test_parked_insert_is_neither_auto_tagged_nor_needing(self):
        # A replacement row inheriting awaiting-operator via supersede
        # migration is parked — not "needs classification". One inheriting a
        # content tag counts as auto-tagged even when the marker rides along.
        plan = ingest.reconcile(
            [], [row("2026-02-05", ref="R1", status="PDNG")], IV,
            CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan)
        old_id = self._all()[0]["row_id"]
        self.conn.execute(
            "INSERT INTO transaction_tags(row_id, tag, added_at)"
            " VALUES (?,'awaiting-operator','t')", (old_id,))
        plan2 = ingest.reconcile(
            self._all(), [row("2026-02-05", ref="R1", status="BOOK")],
            IV, CAP_STABLE)
        stats = apply.apply_plan(self.conn, "acc1", plan2)
        self.assertEqual(stats["superseded"], 1)
        self.assertEqual(stats["auto_tagged"], 0)
        self.assertEqual(stats["needs_classification"], 0)  # parked
        # Now the same shape with a content tag beside the marker.
        self.conn.execute("DELETE FROM transactions")
        self.conn.execute("DELETE FROM transaction_tags")
        plan3 = ingest.reconcile(
            [], [row("2026-03-05", ref="R2", status="PDNG")], IV,
            CAP_STABLE)
        apply.apply_plan(self.conn, "acc1", plan3)
        old_id = self._all()[0]["row_id"]
        for tag in ("awaiting-operator", "food"):
            self.conn.execute(
                "INSERT INTO transaction_tags(row_id, tag, added_at)"
                " VALUES (?,?,'t')", (old_id, tag))
        plan4 = ingest.reconcile(
            self._all(), [row("2026-03-05", ref="R2", status="BOOK")],
            IV, CAP_STABLE)
        stats = apply.apply_plan(self.conn, "acc1", plan4)
        self.assertEqual(stats["auto_tagged"], 1)     # ≥1 non-workflow tag
        self.assertEqual(stats["needs_classification"], 0)
