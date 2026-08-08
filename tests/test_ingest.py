# tests/test_ingest.py
"""Ingestion: identity, matching, coverage."""
import pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"))
import ingest

IV = ("2026-01-01", "2026-05-01")            # half-open [start, end)

# provenance.capability() results. A reference is used as identity only for an
# ASPSP this installation has OBSERVED to supply stable ones, and only within
# the scope in which the reference was observed unique. Per-account is the most
# any observation establishes; global is never assumed.
STABLE = {"ref_stable": True, "ref_scope": "account", "observed_n": 500}
UNSTABLE = {"ref_stable": False, "ref_scope": "unknown", "observed_n": 0}
STABLE_BUT_UNSCOPED = {"ref_stable": True, "ref_scope": "unknown", "observed_n": 40}


def row(date, amount=1000, cp="Albert Heijn", rem="groceries", ref=None, rid=None,
        status="BOOK"):
    # Rule 0: the durable key is account_id. The session-scoped `uid` never
    # appears here, because it is never a durable key.
    return {"row_id": rid, "account_id": "acc1", "booking_date": date,
            "value_date": date, "amount_minor": amount, "currency": "EUR",
            "direction": "DBIT", "counterparty": cp,
            "remittance": rem, "provider_ref": ref, "status": status}


def touched(plan):
    return ([u["row_id"] for u in plan.updates]
            + [t["row_id"] for t in plan.tombstones]
            + [f["row_id"] for f in plan.flags])


class TestIdentity(unittest.TestCase):
    def test_identity_excludes_dates_and_status(self):
        a = ingest.identity_key(row("2026-02-01"))
        b = ingest.identity_key(row("2026-03-15", status="PDNG"))
        self.assertEqual(a, b)

    def test_identity_separates_amount_and_counterparty(self):
        base = ingest.identity_key(row("2026-02-01"))
        self.assertNotEqual(base, ingest.identity_key(row("2026-02-01", amount=1001)))
        self.assertNotEqual(base, ingest.identity_key(row("2026-02-01", cp="Jumbo")))

    def test_identity_canonicalises_text(self):
        self.assertEqual(ingest.identity_key(row("2026-02-01", cp="Albert  Heijn")),
                         ingest.identity_key(row("2026-02-01", cp=" albert heijn ")))

    def test_absent_is_not_empty(self):
        self.assertNotEqual(ingest.identity_key(row("2026-02-01", rem=None)),
                            ingest.identity_key(row("2026-02-01", rem="")))


class TestNormalise(unittest.TestCase):
    RAW = {"entry_reference": "R1", "booking_date": "2026-02-01",
           "value_date": "2026-01-31", "status": "BOOK",
           "transaction_amount": {"currency": "EUR", "amount": "12.34"},
           "credit_debit_indicator": "DBIT",
           "creditor": {"name": "Albert Heijn"},
           "remittance_information": ["BEA, Betaalpas", "AH 1234"]}

    def test_magnitude_is_stored_unsigned_with_direction_separate(self):
        out = ingest.normalise(self.RAW, "acc1")
        self.assertEqual(out["amount_minor"], 1234)      # unsigned
        self.assertEqual(out["direction"], "DBIT")

    def test_credit_uses_the_same_magnitude(self):
        raw = dict(self.RAW, credit_debit_indicator="CRDT", creditor=None,
                   debtor={"name": "Employer"})
        self.assertEqual(ingest.normalise(raw, "acc1")["amount_minor"], 1234)

    def test_remittance_list_is_flattened(self):
        self.assertIn("Betaalpas", ingest.normalise(self.RAW, "acc1")["remittance"])

    def test_reference_kind_is_recorded(self):
        self.assertEqual(ingest.normalise(self.RAW, "acc1")["provider_ref_kind"],
                         "entry_reference")

    def test_missing_reference_is_allowed(self):
        raw = dict(self.RAW); raw.pop("entry_reference")
        self.assertIsNone(ingest.normalise(raw, "acc1")["provider_ref"])

    def test_rejects_unknown_direction(self):
        with self.assertRaises(ValueError):
            ingest.normalise(dict(self.RAW, credit_debit_indicator="XXXX"), "acc1")

    def test_rejects_a_row_with_no_usable_date(self):
        raw = dict(self.RAW); raw.pop("booking_date"); raw.pop("value_date")
        with self.assertRaises(ValueError):
            ingest.normalise(raw, "acc1")


class TestReferenceIdentity(unittest.TestCase):
    """Rule 1, with an ASPSP observed to supply stable references."""

    def test_reference_match_updates_in_place(self):
        stored = [row("2026-02-01", ref="R1", rid=7)]
        fetched = [row("2026-02-02", ref="R1")]        # date corrected
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.inserts, [])
        self.assertEqual(len(plan.updates), 1)
        self.assertEqual(plan.updates[0]["op"], "update")
        self.assertEqual(plan.updates[0]["row_id"], 7)
        self.assertEqual(plan.updates[0]["booking_date"], "2026-02-02")
        self.assertEqual(plan.updates[0]["match_method"], "reference")

    def test_amount_correction_is_corroborated_and_keeps_lineage(self):
        """Amount changed, counterparty and date agree -> corroborated, not reuse."""
        stored = [row("2026-02-01", amount=1000, ref="R1", rid=7)]
        fetched = [row("2026-02-01", amount=1200, ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual([u["row_id"] for u in plan.updates], [7])
        self.assertEqual(plan.updates[0]["amount_minor"], 1200)
        self.assertEqual(plan.updates[0]["match_method"], "reference_corroborated")
        self.assertEqual(plan.tombstones, [])
        self.assertEqual(plan.inserts, [])

    def test_reference_reuse_is_not_trusted(self):
        """Same ref, different amount AND counterparty => reuse, not the same row.
        Updating in place would silently overwrite valid financial history."""
        stored = [row("2026-02-01", amount=1000, cp="Albert Heijn", ref="R1", rid=7)]
        fetched = [row("2026-02-01", amount=9999, cp="Shell", ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(len(plan.inserts), 1)
        self.assertTrue(plan.inserts[0]["needs_review"])          # the new row
        self.assertEqual([(f["row_id"], f["reason"]) for f in plan.flags],
                         [(7, "provider_ref_reuse")])             # and the old one
        self.assertEqual(plan.updates, [])
        self.assertEqual(plan.tombstones, [])   # the stored row keeps its history

    def test_uncorroborated_reference_far_outside_the_window_is_reuse(self):
        """Amount differs; the counterparty agrees but nothing else does — the
        requires the row to 'otherwise agree WITHIN the match window'."""
        stored = [row("2026-02-01", amount=1000, ref="R1", rid=7)]
        fetched = [row("2026-04-15", amount=1200, ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(len(plan.inserts), 1)
        self.assertTrue(plan.inserts[0]["needs_review"])
        self.assertEqual([f["row_id"] for f in plan.flags], [7])
        self.assertEqual(plan.updates, [])

    def test_a_reused_reference_across_monthly_occurrences_inserts_and_flags(self):
        """The named case, and the THIRD appearance of this defect class.

        A monthly standing order has an identical amount, counterparty AND
        remittance every month, so amount-agreement and counterparty-agreement
        are both worthless as corroboration here — only the date separates the
        two occurrences, and 31 days apart is a recurrence, not a correction.
        An incremental fetch carrying only February must never update January
        in place: that silently rewrites January's date and erases the month,
        which is exactly the history rewriting corroboration prevents.

        If this fails, do NOT relax it. An empty `updates` list is the point.
        """
        stored = [row("2026-01-05", amount=100000, cp="Verhuurder B.V.",
                      rem="huur januari", ref="R1", rid=7)]
        fetched = [row("2026-02-05", amount=100000, cp="Verhuurder B.V.",
                       rem="huur januari", ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.updates, [])            # January is never rewritten
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual(plan.inserts[0]["booking_date"], "2026-02-05")
        self.assertTrue(plan.inserts[0]["needs_review"])
        self.assertEqual([(f["row_id"], f["reason"]) for f in plan.flags],
                         [(7, "provider_ref_reuse")])
        self.assertEqual(plan.tombstones, [])         # January keeps its history
        # and the new row takes a fresh occurrence in the same identity cluster
        self.assertEqual(plan.inserts[0]["occurrence"], 1)

    def test_an_unchanged_amount_alone_is_never_corroboration(self):
        """The rule stated directly. Treating "same amount" as perfect
        proof and returned before the date was even consulted."""
        stored = [row("2026-02-01", amount=1000, cp="Albert Heijn", ref="R1",
                      rid=7)]
        fetched = [row("2026-03-20", amount=1000, cp="Shell", ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.updates, [])
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual([f["reason"] for f in plan.flags], ["provider_ref_reuse"])

    def test_an_unchanged_counterparty_alone_is_never_corroboration(self):
        """The mirror case. Both signals are constant across a recurrence, so
        neither can substitute for date agreement."""
        stored = [row("2026-02-01", amount=1000, cp="Albert Heijn", ref="R1",
                      rid=7)]
        fetched = [row("2026-03-20", amount=4200, cp="Albert Heijn", ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.updates, [])
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual([f["reason"] for f in plan.flags], ["provider_ref_reuse"])


    def test_two_absent_counterparties_are_not_corroboration(self):
        """`_canon` distinguishes absent from empty, so plain
        equality made two ABSENT counterparties compare equal and count as
        AGREEMENT — and a reused reference, dated inside the window, with a
        changed amount and no counterparty on either row, therefore went on
        rewriting history in place. That is the exact direction closed for
        populated fields, reopened for the (very common) rows a bank sends
        with no counterparty at all. Silence corroborates nothing.

        Both rows must be inserted-and-flagged, not merged. If this fails, do
        NOT relax it.
        """
        for absent in (None, "", "   "):
            stored = [row("2026-02-01", amount=1000, cp=absent, ref="R1", rid=7)]
            fetched = [row("2026-02-03", amount=9999, cp=absent, ref="R1")]
            plan = ingest.reconcile(stored, fetched, IV, STABLE)
            self.assertEqual(plan.updates, [], repr(absent))
            self.assertEqual(len(plan.inserts), 1, repr(absent))
            self.assertTrue(plan.inserts[0]["needs_review"], repr(absent))
            self.assertEqual([(f["row_id"], f["reason"]) for f in plan.flags],
                             [(7, "provider_ref_reuse")], repr(absent))
            self.assertEqual(plan.tombstones, [], repr(absent))


class TestIdentityAfterCorrection(unittest.TestCase):
    """A row's identity_key always equals the hash of its own current
    content, so a corroborated correction RE-KEYS it — and identity_key and
    occurrence then move together or not at all."""

    def test_a_corrected_amount_rekeys_the_row_and_carries_an_occurrence(self):
        stored = [row("2026-02-01", amount=1000, ref="R1", rid=7)]
        fetched = [row("2026-02-01", amount=1200, ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        upd = plan.updates[0]
        self.assertEqual(upd["op"], "update")
        self.assertEqual(upd["identity_key"], ingest.identity_key(fetched[0]))
        self.assertNotEqual(upd["identity_key"],
                            ingest.identity_key(stored[0]))
        self.assertEqual(upd["occurrence"], 0)    # first row in the new cluster

    def test_the_new_occurrence_sits_above_the_new_clusters_maximum(self):
        """Rule 4 applies to the cluster the row is moving INTO, including any
        tombstone that already owns a slot there — otherwise apply dies on
        UNIQUE (account_id, identity_key, occurrence)."""
        neighbour = row("2026-02-02", amount=1200)
        stored = [row("2026-02-01", amount=1000, ref="R1", rid=7),
                  dict(neighbour, row_id=8,
                       identity_key=ingest.identity_key(neighbour),
                       occurrence=0, state="vanished")]
        fetched = [row("2026-02-01", amount=1200, ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        upd = next(u for u in plan.updates if u["row_id"] == 7)
        self.assertEqual(upd["identity_key"], ingest.identity_key(fetched[0]))
        self.assertEqual(upd["occurrence"], 1)    # above the tombstone at 0

    def test_the_vacated_occurrence_is_not_reissued_in_the_same_pass(self):
        """The re-keyed row leaves its old (identity_key, occurrence) behind. A
        reference-less row arriving with the OLD identity in the same pass must
        allocate above it, not step into the slot that was just vacated."""
        stored = [row("2026-02-01", amount=1000, ref="R1", rid=7)]
        fetched = [row("2026-02-01", amount=1200, ref="R1"),
                   row("2026-02-01", amount=1000)]      # old identity, no ref
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual(plan.inserts[0]["identity_key"],
                         ingest.identity_key(stored[0]))
        self.assertEqual(plan.inserts[0]["occurrence"], 1)

    def test_a_correction_that_does_not_change_hashed_content_keeps_its_key(self):
        """A date-only correction touches nothing the hash covers, so the row
        keeps both its identity_key and its occurrence."""
        stored = [dict(row("2026-02-01", ref="R1", rid=7), occurrence=3)]
        fetched = [row("2026-02-03", ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        upd = plan.updates[0]
        self.assertEqual(upd["identity_key"], ingest.identity_key(stored[0]))
        self.assertEqual(upd["occurrence"], 3)


class TestReferenceCapability(unittest.TestCase):
    """References are keyed on only for ASPSPs OBSERVED to supply stable
    ones, in the scope observed unique. 'Global is never assumed.'"""

    def test_unstable_aspsp_ignores_the_reference_and_uses_the_window(self):
        stored = [row("2026-02-01", ref="R1", rid=1)]
        fetched = [row("2026-02-03", ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, UNSTABLE)
        self.assertEqual([u["row_id"] for u in plan.updates], [1])
        self.assertEqual(plan.updates[0]["match_method"], "windowed")   # not "reference"

    def test_unstable_aspsp_cannot_follow_a_change_the_reference_carries(self):
        """What keying on a reference actually buys, expressed as the contrast.

        The amount is corrected inside the match window. With a STABLE
        reference that is a corroborated in-place update. Without one, the
        amount is part of the date-free content hash, so the corrected row has
        a DIFFERENT identity_key, lands in no cluster with the stored row, and
        can only be an insert plus a tombstone.

        (This deliberately uses a same-window correction rather than the old
        fixture's 15-day gap: two rows sharing a reference a fortnight apart are
        a reused reference under corroboration, so such a fixture distinguishes
        nothing — it asserts the very behaviour the rule removes.)
        """
        stored = [row("2026-02-05", amount=1000, ref="R1", rid=1)]
        fetched = [row("2026-02-08", amount=1200, ref="R1")]
        stable = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual([u["row_id"] for u in stable.updates], [1])   # ref carries it
        self.assertEqual(stable.updates[0]["match_method"],
                         "reference_corroborated")
        self.assertEqual(stable.tombstones, [])
        plan = ingest.reconcile(stored, fetched, IV, UNSTABLE)
        self.assertEqual(plan.updates, [])                             # it must not
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual([t["row_id"] for t in plan.tombstones], [1])

    def test_unstable_aspsp_beyond_the_window_never_keys_on_the_reference(self):
        """UNSTABLE plus a gap wider than the window: the reference is not
        consulted at all, so this is an insert and a tombstone. Under STABLE the
        same pair is provider reference reuse — never an in-place update."""
        stored = [row("2026-02-05", ref="R1", rid=1)]
        fetched = [row("2026-02-20", ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, UNSTABLE)
        self.assertEqual(plan.updates, [])
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual([t["row_id"] for t in plan.tombstones], [1])
        self.assertEqual(plan.flags, [])              # nothing to say about a ref
        stable = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(stable.updates, [])
        self.assertEqual([f["reason"] for f in stable.flags],
                         ["provider_ref_reuse"])

    def test_unscoped_capability_is_not_trusted_even_when_ref_stable(self):
        """reconcile sees one account's rows, so `account` is the only scope it can
        honour; `unknown` means the scope was never established. Same fixture as
        the corroborated-correction case above, so the ONLY difference is the
        scope — with it the reference carries the correction, without it the
        content hash cannot follow and the row is replaced."""
        stored = [row("2026-02-05", amount=1000, ref="R1", rid=1)]
        fetched = [row("2026-02-08", amount=1200, ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE_BUT_UNSCOPED)
        self.assertEqual(plan.updates, [])
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual([t["row_id"] for t in plan.tombstones], [1])


class TestWindowedMatching(unittest.TestCase):
    def test_standing_order_does_not_erase_the_earlier_month(self):
        """The case that breaks a multiset design, carried by two
        spec revisions. A monthly standing order — identical amount, counterparty
        and remittance — held as Jan/Feb/Mar and re-fetched as Feb/Mar/Apr gives
        multisets of equal size: no surplus, no deficit. A naive matcher pairs
        them off in order, rewrites all three dates and erases January."""
        stored = [row("2026-01-05", rid=1), row("2026-02-05", rid=2),
                  row("2026-03-05", rid=3)]
        fetched = [row("2026-02-05"), row("2026-03-05"), row("2026-04-05")]
        plan = ingest.reconcile(stored, fetched, ("2026-02-01", "2026-05-01"), STABLE)
        self.assertEqual(len(plan.inserts), 1)                   # April only
        self.assertEqual(plan.inserts[0]["booking_date"], "2026-04-05")
        self.assertEqual(plan.tombstones, [])                    # January untouched
        self.assertEqual(plan.updates, [])   # Feb->Feb, Mar->Mar: matched, no rewrite
        self.assertNotIn(1, touched(plan))   # January is out of the fetched interval

    def test_two_identical_same_day_payments_are_both_kept(self):
        fetched = [row("2026-02-05"), row("2026-02-05")]
        plan = ingest.reconcile([], fetched, IV, STABLE)
        self.assertEqual(len(plan.inserts), 2)
        self.assertEqual(sorted(i["occurrence"] for i in plan.inserts), [0, 1])

    def test_re_fetching_an_unchanged_interval_is_a_no_op(self):
        stored = [row("2026-02-05", rid=1), row("2026-03-05", rid=2)]
        fetched = [row("2026-02-05"), row("2026-03-05")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.inserts, [])
        self.assertEqual(plan.tombstones, [])
        self.assertEqual(plan.updates, [])          # genuinely a no-op
        self.assertEqual(plan.flags, [])

    def test_deficit_well_inside_the_interval_is_tombstoned(self):
        stored = [row("2026-03-01", rid=5)]
        plan = ingest.reconcile(stored, [], IV, STABLE)
        self.assertEqual([t["row_id"] for t in plan.tombstones], [5])
        self.assertEqual(plan.tombstones[0]["state"], "vanished")

    def test_deficit_near_the_edge_is_left_alone(self):
        """A corrected date may have moved it across the boundary."""
        stored = [row("2026-01-03", rid=5)]           # 2 days inside a 7-day window
        plan = ingest.reconcile(stored, [], IV, STABLE)
        self.assertEqual(plan.tombstones, [])

    def test_a_short_edge_must_not_block_a_second_pairing(self):
        """Greedy shortest-edge fails here: it matches 1 pair and manufactures a
        spurious insert + tombstone. Maximum-cardinality matching matches 2."""
        stored = [row("2026-02-10", rid=1), row("2026-02-03", rid=2)]
        fetched = [row("2026-02-10"), row("2026-02-16")]
        plan = ingest.reconcile(stored, fetched, ("2026-01-01", "2026-04-01"), STABLE)
        self.assertEqual(plan.inserts, [])
        self.assertEqual(plan.tombstones, [])
        self.assertEqual(sorted(u["row_id"] for u in plan.updates), [1, 2])

    def test_matching_is_order_independent(self):
        stored = [row("2026-02-05", rid=1), row("2026-02-09", rid=2)]
        fetched = [row("2026-02-06"), row("2026-02-10")]
        a = ingest.reconcile(stored, fetched, IV, STABLE)
        b = ingest.reconcile(list(reversed(stored)), list(reversed(fetched)), IV, STABLE)
        self.assertEqual(sorted(u["row_id"] for u in a.updates),
                         sorted(u["row_id"] for u in b.updates))
        self.assertEqual([u["booking_date"] for u in sorted(a.updates,
                          key=lambda u: u["row_id"])],
                         [u["booking_date"] for u in sorted(b.updates,
                          key=lambda u: u["row_id"])])

    def test_windowed_matches_are_disclosed(self):
        """'Every reference-less match is disclosed, not merely the ambiguous
        ones'."""
        stored = [row("2026-02-05", rid=1)]
        fetched = [row("2026-02-06")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.updates[0]["match_method"], "windowed")
        self.assertLess(plan.updates[0]["match_confidence"], 1.0)

    def test_beyond_the_window_is_an_insert_not_a_match(self):
        stored = [row("2026-02-05", rid=1)]
        fetched = [row("2026-02-20")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual([t["row_id"] for t in plan.tombstones], [1])

    def test_occurrence_never_reuses_a_tombstoned_slot(self):
        """Only works because the caller passes rows in EVERY state — see the
        interface note. A caller filtering on state='active' reissues occurrence
        0, which the tombstone still owns, and apply_plan dies on
        UNIQUE (account_id, identity_key, occurrence)."""
        stored = [dict(row("2026-02-05", rid=1), occurrence=0, state="vanished")]
        fetched = [row("2026-02-20")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.inserts[0]["occurrence"], 1)
        self.assertEqual(plan.tombstones, [])      # a tombstone is not re-tombstoned


class TestOccurrenceAllocation(unittest.TestCase):
    def test_allocation_does_not_rehash_rows_that_declare_their_identity(self):
        """Regression. `s.get("identity_key", identity_key(s))` evaluates its
        default EAGERLY, so it hashes every row whether or not the key is
        missing — and a row that carries only its key (a tombstone read back from
        the ledger, or the shadow row reconcile appends after each insert) has no
        `amount_minor` to hash. That raised KeyError on the SECOND insert of any
        pass, killing this module's own test, apply's idempotence test and the
        end-to-end re-ingest assertion."""
        ident = ingest.identity_key(row("2026-02-05"))
        stored = [{"row_id": 1, "identity_key": ident, "occurrence": 3,
                   "state": "vanished", "booking_date": "2026-02-05"}]
        plan = ingest.reconcile(stored, [row("2026-02-05")], IV, STABLE)
        self.assertEqual(plan.inserts[0]["occurrence"], 4)

    def test_three_identical_rows_get_three_distinct_occurrences(self):
        fetched = [row("2026-02-05"), row("2026-02-05"), row("2026-02-05")]
        plan = ingest.reconcile([], fetched, IV, STABLE)
        self.assertEqual(sorted(i["occurrence"] for i in plan.inserts), [0, 1, 2])

    def test_the_durable_high_water_is_honoured_when_stored_cannot_show_it(self):
        """`stored` is only the rows the caller loaded, and a routine
        refresh loads roughly the last booked date minus seven days — so a
        monthly standing order's earlier occurrences are simply not there.
        Allocating from `stored` alone reissues occurrence 0 and apply_plan
        dies on UNIQUE (account_id, identity_key, occurrence). The durable
        map is what carries rule 4 across passes."""
        ident = ingest.identity_key(row("2026-02-05"))
        plan = ingest.reconcile([], [row("2026-02-05")], IV, STABLE,
                                allocated={ident: 2})
        self.assertEqual(plan.inserts[0]["occurrence"], 2)

    def test_the_durable_high_water_never_lowers_this_passs_allocation(self):
        """It is a floor, not an override. A stale or partial map — one written
        before a row this pass can see — must never hand back a tuple the
        ledger still owns."""
        stored = [dict(row("2026-02-05", rid=1), occurrence=4, state="vanished")]
        ident = ingest.identity_key(row("2026-02-05"))
        plan = ingest.reconcile(stored, [row("2026-02-05")], IV, STABLE,
                                allocated={ident: 2})
        self.assertEqual(plan.inserts[0]["occurrence"], 5)


class TestOversizedCluster(unittest.TestCase):
    def test_cluster_above_the_cap_falls_back_and_flags_rather_than_hanging(self):
        """Exact matching is exponential; above MAX_EXACT_CLUSTER we take a
        deterministic greedy pass and flag everything it touched, because
        rule 5 forbids an unresolved cluster passing silently."""
        n = ingest.MAX_EXACT_CLUSTER + 1
        stored = [row("2026-02-%02d" % (1 + 2 * i), rid=i + 1) for i in range(n)]
        fetched = [row("2026-02-%02d" % (2 + 2 * i)) for i in range(n)]
        plan = ingest.reconcile(stored, fetched, ("2026-01-01", "2026-04-01"), STABLE)
        self.assertEqual(len(plan.updates), n)      # all paired by the fallback
        self.assertTrue(all(u["needs_review"] for u in plan.updates))
        self.assertTrue(all(u["match_confidence"] <= 0.5 for u in plan.updates))
        self.assertEqual(plan.inserts, [])
        self.assertEqual(plan.tombstones, [])


class TestPendingToBooked(unittest.TestCase):
    def test_pending_becoming_booked_supersedes_rather_than_updating_in_place(self):
        """State is active|superseded|vanished and superseded_by points a
        pending row at the booked row that replaced it. An in-place update makes
        both columns dead schema and loses the transition."""
        pend = row("2026-02-05", rid=9, status="PDNG")
        booked = row("2026-02-07", status="BOOK")
        plan = ingest.reconcile([pend], [booked], IV, UNSTABLE)
        self.assertEqual([u for u in plan.updates if u["op"] == "update"], [])
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual(plan.inserts[0]["status"], "BOOK")
        self.assertEqual(plan.inserts[0]["occurrence"], 1)   # above the pending row
        self.assertEqual(plan.tombstones, [])

    def test_supersession_points_the_pending_row_at_the_booked_row(self):
        pend = row("2026-02-05", rid=9, status="PDNG")
        booked = row("2026-02-07", status="BOOK")
        plan = ingest.reconcile([pend], [booked], IV, UNSTABLE)
        sup = [u for u in plan.updates if u["op"] == "supersede"]
        self.assertEqual(len(sup), 1)
        self.assertEqual(sup[0]["row_id"], 9)
        self.assertEqual(sup[0]["state"], "superseded")
        self.assertEqual(sup[0]["superseded_by_local"], plan.inserts[0]["local_id"])

    def test_a_reference_matched_pending_also_supersedes(self):
        pend = row("2026-02-05", rid=9, ref="R1", status="PDNG")
        booked = row("2026-02-07", ref="R1", status="BOOK")
        plan = ingest.reconcile([pend], [booked], IV, STABLE)
        sup = [u for u in plan.updates if u["op"] == "supersede"]
        self.assertEqual([s["row_id"] for s in sup], [9])
        self.assertEqual(sup[0]["match_method"], "reference")
        self.assertEqual(len(plan.inserts), 1)

    def test_booked_to_booked_still_updates_in_place(self):
        """Supersession is the pending->booked transition ONLY; an ordinary
        correction stays an in-place update and keeps its first_seen."""
        stored = [row("2026-02-05", rid=1)]
        fetched = [row("2026-02-07")]
        plan = ingest.reconcile(stored, fetched, IV, UNSTABLE)
        self.assertEqual(plan.inserts, [])
        self.assertEqual([u["op"] for u in plan.updates], ["update"])
        self.assertEqual(plan.updates[0]["row_id"], 1)


class TestReferenceCollisionWithinOneFetch(unittest.TestCase):
    """ref_stable means unique within the recorded
    scope, so two fetched rows sharing one trusted reference are AT MOST one
    transaction restated -- never two. Failing to collapse them
    double-counts money in every aggregate, and marks the phantom row
    needs_review=False so the review breakdown cannot even surface it."""

    def test_a_duplicated_page_produces_one_row_not_two(self):
        """The exact reproduction: the SAME fetched row appears twice under
        one trusted reference (a provider re-sending one page twice). This
        must settle on the single stored row, never insert a phantom
        duplicate."""
        stored = [row("2026-02-01", ref="R1", rid=7)]
        fetched = [row("2026-02-01", ref="R1"), row("2026-02-01", ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.inserts, [])
        self.assertEqual(plan.updates, [])        # unchanged content: a no-op match
        self.assertEqual(plan.tombstones, [])
        self.assertEqual(plan.flags, [])

    def test_matching_is_independent_of_fetch_order_even_with_a_shared_reference(self):
        """An unmodified refetch of the original, alongside a genuinely NEW
        transaction that happens to reuse R1, must resolve the SAME way
        regardless of which one the provider's page lists first. Provider
        row order is not ours to control."""
        stored = [row("2026-02-01", amount=1000, cp="Albert Heijn", ref="R1", rid=7)]
        orig = row("2026-02-01", amount=1000, cp="Albert Heijn", ref="R1")
        new = row("2026-02-01", amount=4200, cp="Shell", ref="R1")

        def summary(plan):
            return (len(plan.inserts), len(plan.updates), len(plan.tombstones),
                    sorted(f["reason"] for f in plan.flags))

        forward = ingest.reconcile(stored, [orig, new], IV, STABLE)
        backward = ingest.reconcile(stored, [new, orig], IV, STABLE)
        self.assertEqual(summary(forward), summary(backward))
        self.assertEqual(summary(forward), (1, 0, 0, []))
        self.assertEqual(forward.inserts[0]["amount_minor"], 4200)

    def test_a_trusted_reference_reused_by_an_unrelated_row_never_tombstones_the_original(self):
        """A stored row's reference is reused by a fetched row that actually
        belongs, by CONTENT, to a DIFFERENT stored row. Trusting the
        reference must never make the outcome worse than ignoring it: the
        unrelated stored row is proven present (by content, in the windowed
        pass) and must not be tombstoned, and nothing may be inserted twice."""
        a = row("2026-02-01", amount=1000, cp="Albert Heijn", ref="R1", rid=7)
        b = row("2026-02-05", amount=9999, cp="Shell", ref="R2", rid=8)
        b_restated = row("2026-02-06", amount=9999, cp="Shell", ref="R1")
        plan = ingest.reconcile([a, b], [b_restated], IV, STABLE)
        self.assertEqual(plan.inserts, [])
        self.assertEqual(plan.tombstones, [])
        self.assertEqual([u["row_id"] for u in plan.updates], [8])
        self.assertEqual([(f["row_id"], f["reason"]) for f in plan.flags],
                         [(7, "provider_ref_reuse")])


class TestWeeklyStandingOrderWindow(unittest.TestCase):
    """Amount agreement alone corroborates a
    reference match only within AMOUNT_ONLY_MATCH_WINDOW_DAYS (3), a
    narrower bound than match_window_days (7) -- otherwise a WEEKLY standing
    order (7 days apart, same amount every week) looks exactly like a
    corrected date and erases the earlier week. The counterparty arm is
    untouched by this fix and still spans the full match_window_days."""

    def test_a_weekly_recurrence_with_no_stable_counterparty_is_not_erased(self):
        """Isolates the amount-only mechanism: the counterparty differs (a
        merchant name drifting slightly between statements is common), so
        neither the untouched counterparty arm nor rule 2's identity-based
        windowed matching can rescue this pair -- only the amount-only bound
        is exercised. A fixture with the SAME counterparty on both sides is
        NOT closed by this bound -- see the module's KNOWN LIMITATION note on
        rule 2, which has no drift bound of its own."""
        stored = [row("2026-02-05", amount=2500, cp="FitClub", rem="membership",
                      ref="R1", rid=9)]
        fetched = [row("2026-02-12", amount=2500, cp="Fitness Club Ltd",
                       rem="membership", ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.updates, [])          # week 5 is never rewritten
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual(plan.inserts[0]["booking_date"], "2026-02-12")
        self.assertEqual([f["reason"] for f in plan.flags], ["provider_ref_reuse"])

    def test_a_one_day_correction_still_updates_in_place(self):
        """Regression guard: the narrower amount-only bound must not break the
        ordinary same-day/next-day correction case."""
        stored = [row("2026-02-05", amount=2500, ref="R1", rid=9)]
        fetched = [row("2026-02-06", amount=2500, ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual([u["row_id"] for u in plan.updates], [9])
        self.assertEqual(plan.updates[0]["match_method"], "reference")
        self.assertEqual(plan.inserts, [])

    def test_an_identical_content_weekly_recurrence_is_not_erased(self):
        """Bounding the amount-only
        arm; the counterparty arm, left at the full 7-day window, still
        rescued a weekly standing order whose counterparty happens to be
        unchanged -- the realistic shape, and the one a narrower test
        (drifted counterparty) missed. Both arms now share
        AMOUNT_ONLY_MATCH_WINDOW_DAYS."""
        stored = [row("2026-02-05", amount=2500, cp="Gym", rem="membership",
                      ref="R1", rid=9)]
        fetched = [row("2026-02-12", amount=2500, cp="Gym", rem="membership",
                       ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.updates, [])          # week 5 is never rewritten
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual(plan.inserts[0]["booking_date"], "2026-02-12")
        self.assertEqual([f["reason"] for f in plan.flags], ["provider_ref_reuse"])


class TestUnresolvedClusterDisclosure(unittest.TestCase):
    """TestOversizedCluster's own fixture happens to
    pair every row, so the unresolved_cluster flag branch never executes
    there and a typo in the reason string, or deleting the branch entirely,
    still leaves all 46 original tests green. This fixture leaves a genuine
    deficit inside an oversized cluster so the flag actually fires."""

    def test_a_genuine_deficit_in_an_oversized_cluster_is_flagged_unresolved(self):
        n = ingest.MAX_EXACT_CLUSTER + 1
        stored = [row("2026-02-%02d" % (1 + 2 * i), rid=i + 1) for i in range(n)]
        fetched = [row("2026-02-%02d" % (2 + 2 * i)) for i in range(n - 2)]
        plan = ingest.reconcile(stored, fetched, ("2026-01-01", "2026-04-01"), STABLE)
        self.assertEqual(len(plan.updates), n - 2)
        self.assertEqual(len(plan.flags), 2)
        self.assertEqual({f["reason"] for f in plan.flags}, {"unresolved_cluster"})
        self.assertEqual(plan.inserts, [])
        self.assertEqual(plan.tombstones, [])   # an unresolved cluster is never tombstoned


class TestTombstoneReasonIsAsserted(unittest.TestCase):
    """A tombstone test that does not assert the reason string leaves a typo
    in it green."""

    def test_the_tombstone_reason_is_absent_from_a_proven_interval(self):
        stored = [row("2026-03-01", rid=5)]
        plan = ingest.reconcile(stored, [], IV, STABLE)
        self.assertEqual(plan.tombstones[0]["reason"], "absent_from_a_proven_interval")


class TestReviewReasonsArePersisted(unittest.TestCase):
    """needs_review=1 with no cause is exactly the
    outcome the reason columns exist to prevent -- every Plan record that
    sets it must carry a `reason` key `apply` can write into
    review_reason/state_reason."""

    def test_an_inexact_fallback_update_carries_windowed_ambiguous(self):
        n = ingest.MAX_EXACT_CLUSTER + 1
        stored = [row("2026-02-%02d" % (1 + 2 * i), rid=i + 1) for i in range(n)]
        fetched = [row("2026-02-%02d" % (2 + 2 * i)) for i in range(n)]
        plan = ingest.reconcile(stored, fetched, ("2026-01-01", "2026-04-01"), STABLE)
        self.assertTrue(plan.updates)
        self.assertTrue(all(u["needs_review"] for u in plan.updates))
        self.assertTrue(all(u["reason"] == "windowed_ambiguous" for u in plan.updates))

    def test_an_inexact_fallback_surplus_insert_carries_windowed_ambiguous(self):
        n = ingest.MAX_EXACT_CLUSTER + 1        # 9: oversized on the fetched side
        stored = [row("2026-02-%02d" % (1 + 2 * i), rid=i + 1) for i in range(n - 2)]  # 7
        fetched = [row("2026-02-%02d" % (2 + 2 * i)) for i in range(n)]                # 9
        plan = ingest.reconcile(stored, fetched, ("2026-01-01", "2026-04-01"), STABLE)
        self.assertEqual(len(plan.inserts), 2)
        self.assertTrue(all(i["needs_review"] for i in plan.inserts))
        self.assertTrue(all(i["reason"] == "windowed_ambiguous" for i in plan.inserts))

    def test_a_disagreeing_shared_reference_flags_the_chosen_row(self):
        """The ambiguous sub-case: two DISTINCT fetched contents both share
        one trusted reference AND both corroborate the same stored row.
        ref_stable cannot tell us which is current, so the module keeps one
        deterministically and flags it, rather than silently picking."""
        stored = [row("2026-02-05", amount=1000, cp="Albert Heijn",
                      rem="rent", ref="R1", rid=1)]
        f1 = row("2026-02-05", amount=1000, cp="Someone Else",
                 rem="rent", ref="R1")            # corroborates via amount
        f2 = row("2026-02-06", amount=2000, cp="Albert Heijn",
                 rem="rent", ref="R1")             # corroborates via counterparty
        plan = ingest.reconcile(stored, [f1, f2], IV, STABLE)
        self.assertEqual(len(plan.updates), 1)
        self.assertTrue(plan.updates[0]["needs_review"])
        self.assertEqual(plan.updates[0]["reason"], "reference_shared_in_fetch")


class TestNormaliseCounterpartyDirection(unittest.TestCase):
    """`normalise`'s creditor/debtor selection is easy to leave unpinned:
    inverting the ternary keeps every other test in this module green while
    silently changing identity_key for every row in the ledger, because
    counterparty is hashed."""

    RAW = {"entry_reference": "R1", "booking_date": "2026-02-01",
           "value_date": "2026-01-31", "status": "BOOK",
           "transaction_amount": {"currency": "EUR", "amount": "12.34"},
           "creditor": {"name": "Creditor Co"},
           "debtor": {"name": "Debtor Co"}}

    def test_a_debit_takes_the_creditor_as_counterparty(self):
        out = ingest.normalise(dict(self.RAW, credit_debit_indicator="DBIT"), "acc1")
        self.assertEqual(out["counterparty"], "Creditor Co")

    def test_a_credit_takes_the_debtor_as_counterparty(self):
        out = ingest.normalise(dict(self.RAW, credit_debit_indicator="CRDT"), "acc1")
        self.assertEqual(out["counterparty"], "Debtor Co")


def apply_plan(stored, plan):
    """A deliberately naive in-memory `apply`, in the documented order:
    insert first, remember local_id -> row_id, then resolve the supersessions.

    Only used by the convergence test below: a fix that merely moves a defect
    from "wrong on pass 1" to "wrong for ever" is not a fix, and a single-pass
    assertion cannot tell those apart.
    """
    meta = ("local_id", "op", "match_method", "match_confidence", "reason",
            "superseded_by_local")
    rows = {s["row_id"]: dict(s) for s in stored}
    next_id = (max(rows) if rows else 0) + 1
    local = {}
    for ins in plan.inserts:
        rec = {k: v for k, v in ins.items() if k not in meta}
        rec["row_id"] = next_id
        rows[next_id] = rec
        local[ins["local_id"]] = next_id
        next_id += 1
    for upd in plan.updates:
        target = rows[upd["row_id"]]
        if upd["op"] == "update":
            target.update({k: v for k, v in upd.items() if k not in meta})
        else:
            target["state"] = "superseded"
            target["superseded_by"] = local[upd["superseded_by_local"]]
        if upd.get("needs_review"):
            target["needs_review"] = True
    for t in plan.tombstones:
        rows[t["row_id"]]["state"] = "vanished"
    for f in plan.flags:
        rows[f["row_id"]]["needs_review"] = True
    return [rows[k] for k in sorted(rows)]


class TestIntraFetchCollapseIsDateBound(unittest.TestCase):
    """Collapsing every fetched row sharing
    a trusted reference onto one representative per `identity_key` -- which is
    deliberately date-free and status-free. That merges restatements of ONE
    transaction (the duplicated page it was written for) but ALSO merges
    consecutive occurrences of a recurrence, because `ref_stable` records that
    references were observed UNIQUE, not that a provider never reuses one --
    the whole `provider_ref_reuse` apparatus exists precisely because trusted
    providers demonstrably do reuse references across recurrences.

    The collapse is therefore bounded by date proximity
    (AMOUNT_ONLY_MATCH_WINDOW_DAYS, the same constant that bounds
    corroboration): "never insert twice" means never twice for one
    TRANSACTION, and only the date can establish that two rows are one.
    """

    RENT = dict(amount=100000, cp="Verhuurder B.V.", rem="huur", ref="R1")

    def test_three_monthly_occurrences_under_one_reference_are_all_inserted(self):
        """EUR 2000 of rent used to vanish silently: one insert, no flag, no
        needs_review, nothing for the breakdown to surface."""
        fetched = [row("2026-01-05", **self.RENT), row("2026-02-05", **self.RENT),
                   row("2026-03-05", **self.RENT)]
        plan = ingest.reconcile([], fetched, IV, STABLE)
        self.assertEqual(len(plan.inserts), 3)
        self.assertEqual(sum(i["amount_minor"] for i in plan.inserts), 300000)
        self.assertEqual(sorted(i["booking_date"] for i in plan.inserts),
                         ["2026-01-05", "2026-02-05", "2026-03-05"])
        self.assertEqual(sorted(i["occurrence"] for i in plan.inserts), [0, 1, 2])
        self.assertEqual(plan.updates, [])
        self.assertEqual(plan.tombstones, [])

    def test_trusting_the_reference_is_never_worse_than_ignoring_it(self):
        """The property the docstrings claim and a weaker fixture
        falsified: a TRUSTED capability collapsed three months into one row
        while an UNTRUSTED one kept all three."""
        fetched = [row("2026-01-05", **self.RENT), row("2026-02-05", **self.RENT),
                   row("2026-03-05", **self.RENT)]
        trusted = ingest.reconcile([], fetched, IV, STABLE)
        untrusted = ingest.reconcile([], fetched, IV, UNSTABLE)
        self.assertEqual(sum(i["amount_minor"] for i in trusted.inserts),
                         sum(i["amount_minor"] for i in untrusted.inserts))
        self.assertEqual(len(trusted.inserts), len(untrusted.inserts))

    def test_a_duplicated_page_still_collapses_with_no_stored_anchor(self):
        """The genuine-duplicate case must keep working: a genuinely repeated
        page carries IDENTICAL dates, so it is still one transaction."""
        dup = row("2026-02-05", **self.RENT)
        plan = ingest.reconcile([], [dict(dup), dict(dup)], IV, STABLE)
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual(sum(i["amount_minor"] for i in plan.inserts), 100000)

    def test_a_restatement_inside_the_drift_bound_still_collapses(self):
        """Two days apart, same content, same trusted reference: that is a
        booking date the bank moved, not a second transaction."""
        fetched = [row("2026-02-05", **self.RENT), row("2026-02-07", **self.RENT)]
        plan = ingest.reconcile([], fetched, IV, STABLE)
        self.assertEqual(len(plan.inserts), 1)

    def test_the_surviving_occurrence_does_not_depend_on_provider_row_order(self):
        fetched = [row("2026-01-05", **self.RENT), row("2026-02-05", **self.RENT),
                   row("2026-03-05", **self.RENT)]

        def summary(plan):
            return (sorted(i["booking_date"] for i in plan.inserts),
                    sorted(i["occurrence"] for i in plan.inserts),
                    len(plan.updates), len(plan.tombstones),
                    sorted((f["row_id"], f["reason"]) for f in plan.flags))

        self.assertEqual(summary(ingest.reconcile([], fetched, IV, STABLE)),
                         summary(ingest.reconcile([], list(reversed(fetched)),
                                                  IV, STABLE)))

    def test_the_bound_is_measured_from_the_band_anchor_not_its_last_member(self):
        """Single-linkage chaining would let rows an ARBITRARY distance apart
        collapse transitively: 0 -> 3 -> 6 -> 9 days, each hop inside the
        bound, all one row. Bands are anchored on their earliest date, so this
        is two transactions (day 0/3 and day 6/9), not one."""
        fetched = [row("2026-02-05", **self.RENT), row("2026-02-08", **self.RENT),
                   row("2026-02-11", **self.RENT), row("2026-02-14", **self.RENT)]
        plan = ingest.reconcile([], fetched, IV, STABLE)
        self.assertEqual(sorted(i["booking_date"] for i in plan.inserts),
                         ["2026-02-05", "2026-02-11"])

    def test_which_restatement_survives_is_decided_by_the_dates(self):
        """Two same-status restatements inside the bound collapse to one row;
        which one survives must be decided by the dates, never by which one the
        provider's page happened to list first."""
        early = row("2026-02-05", **self.RENT)
        late = row("2026-02-07", **self.RENT)
        forward = ingest.reconcile([], [early, late], IV, STABLE)
        backward = ingest.reconcile([], [late, early], IV, STABLE)
        self.assertEqual([i["booking_date"] for i in forward.inserts],
                         [i["booking_date"] for i in backward.inserts])
        self.assertEqual(len(forward.inserts), 1)

    def test_two_bands_corroborating_one_stored_row_resolve_by_date(self):
        """A consequence of the date bound: two reps under one reference can
        now share an identity_key (same content, different bands) and BOTH
        corroborate one stored row from opposite sides of it. Fetch index alone
        would then have decided which, putting provider row order back into the
        answer."""
        stored = [row("2026-02-06", **dict(self.RENT, rid=4))]
        f_before = row("2026-02-03", **self.RENT)
        f_after = row("2026-02-09", **self.RENT)
        forward = ingest.reconcile(stored, [f_before, f_after], IV, STABLE)
        backward = ingest.reconcile(stored, [f_after, f_before], IV, STABLE)
        self.assertEqual([(u["row_id"], u["booking_date"], u["reason"])
                          for u in forward.updates],
                         [(u["row_id"], u["booking_date"], u["reason"])
                          for u in backward.updates])
        self.assertEqual(sorted(i["booking_date"] for i in forward.inserts),
                         sorted(i["booking_date"] for i in backward.inserts))

    def test_a_collapse_prefers_the_booked_row_and_records_the_supersession(self):
        """A page listing the pending restatement FIRST used to persist the
        PDNG row and drop the BOOK row with no supersession record at all."""
        pend = row("2026-02-05", ref="R1", rid=9, status="PDNG")
        fetched = [row("2026-02-05", ref="R1", status="PDNG"),
                   row("2026-02-06", ref="R1", status="BOOK")]
        plan = ingest.reconcile([pend], fetched, IV, STABLE)
        self.assertEqual(len(plan.inserts), 1)
        self.assertEqual(plan.inserts[0]["status"], "BOOK")
        self.assertEqual(plan.inserts[0]["booking_date"], "2026-02-06")
        sup = [u for u in plan.updates if u["op"] == "supersede"]
        self.assertEqual([s["row_id"] for s in sup], [9])
        self.assertEqual(sup[0]["state"], "superseded")
        self.assertEqual(sup[0]["superseded_by_local"], plan.inserts[0]["local_id"])
        self.assertEqual([u for u in plan.updates if u["op"] == "update"], [])
        self.assertEqual(plan.tombstones, [])
        self.assertEqual(plan.flags, [])

    def test_the_booked_row_wins_whichever_order_the_page_lists_them_in(self):
        pend = row("2026-02-05", ref="R1", rid=9, status="PDNG")
        fetched = [row("2026-02-06", ref="R1", status="BOOK"),
                   row("2026-02-05", ref="R1", status="PDNG")]
        plan = ingest.reconcile([pend], fetched, IV, STABLE)
        self.assertEqual([i["status"] for i in plan.inserts], ["BOOK"])
        self.assertEqual([u["op"] for u in plan.updates], ["supersede"])


class TestRefReuseExclusionIsPerPair(unittest.TestCase):
    """Keeping a `ref_reused` stored row out
    of rule 2's clustering pool WHOLESALE, on the premise that "that pairing
    already went through _corroborate under rule 1 and was rejected". That is
    only true of fetched rows carrying THAT reference. A fetched row with a
    different reference, or none, was never examined against the stored row --
    so the stored row's genuine continuation was blocked, inserted as a silent
    duplicate (needs_review False, reason None, confidence 1.0), and never
    converged: on the next pass the squatter's inserted row carries the
    reference too, the stored row is re-flagged, and the duplicate persists
    for ever. The exclusion is therefore per (fetched row, stored row) PAIR.
    """

    def fixture(self):
        stored = [row("2026-02-10", amount=1000, cp="Albert Heijn",
                      rem="groceries", ref="R1", rid=7)]
        squatter = row("2026-02-10", amount=9999, cp="Shell", rem="fuel",
                       ref="R1")                 # squats R1, fails corroboration
        correction = row("2026-02-11", amount=1000, cp="Albert Heijn",
                         rem="groceries", ref="R2")    # row 7's real 1-day fix
        return stored, [squatter, correction]

    def test_a_squatted_reference_does_not_block_a_genuine_correction(self):
        stored, fetched = self.fixture()
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual([(u["row_id"], u["booking_date"], u["match_method"])
                          for u in plan.updates],
                         [(7, "2026-02-11", "windowed")])
        self.assertEqual(len(plan.inserts), 1)       # the squatter, and only it
        self.assertEqual(plan.inserts[0]["amount_minor"], 9999)
        self.assertTrue(plan.inserts[0]["needs_review"])
        self.assertEqual(plan.inserts[0]["reason"], "provider_ref_reuse")
        self.assertEqual([(f["row_id"], f["reason"]) for f in plan.flags],
                         [(7, "provider_ref_reuse")])
        self.assertEqual(plan.tombstones, [])

    def test_the_squatter_changes_nothing_about_the_correction(self):
        """The control: with the squatter removed, the correction is an
        in-place windowed update. Adding an unrelated squatter must not turn
        that into a duplicate."""
        stored, fetched = self.fixture()
        plan = ingest.reconcile(stored, fetched[1:], IV, STABLE)
        self.assertEqual([(u["row_id"], u["booking_date"], u["match_method"])
                          for u in plan.updates],
                         [(7, "2026-02-11", "windowed")])
        self.assertEqual(plan.inserts, [])

    def test_the_pairing_that_actually_failed_is_still_blocked(self):
        """The narrower defect must stay closed: an identical-content
        weekly recurrence sharing the reference is the pair that DID go
        through _corroborate, so rule 2 must not rediscover it by content."""
        stored = [row("2026-02-05", amount=2500, cp="Gym", rem="membership",
                      ref="R1", rid=9)]
        fetched = [row("2026-02-12", amount=2500, cp="Gym", rem="membership",
                       ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.updates, [])
        self.assertEqual([i["booking_date"] for i in plan.inserts], ["2026-02-12"])
        self.assertEqual([f["reason"] for f in plan.flags], ["provider_ref_reuse"])
        self.assertEqual(plan.tombstones, [])

    def oversized(self, tail_dates):
        """One stored row whose trusted reference is squatted from 5 days away
        (inside match_window_days, outside the corroboration bound), in a
        cluster large enough to force _best_matching's greedy fallback."""
        stored = [row("2026-02-10", rid=1)]
        fetched = [row("2026-02-05", ref="R1")] + [row(d) for d in tail_dates]
        self.assertGreater(len(fetched), ingest.MAX_EXACT_CLUSTER)
        return [dict(s, provider_ref="R1") for s in stored], fetched

    def test_the_greedy_fallback_honours_the_blocked_pairing_too(self):
        """The fallback runs on clusters above MAX_EXACT_CLUSTER, and it walks
        the fetched rows in DATE order -- so the squatter, being the earliest,
        is exactly the row that would claim the stored row there. Without the
        per-pair block in the fallback the guarantee silently evaporates for
        every cluster above the cap."""
        stored, fetched = self.oversized(["2026-02-%02d" % d
                                          for d in (12, 14, 16, 18, 20, 22, 24, 26)])
        plan = ingest.reconcile(stored, fetched, ("2026-01-01", "2026-05-01"), STABLE)
        self.assertEqual([(u["row_id"], u["booking_date"]) for u in plan.updates],
                         [(1, "2026-02-12")])       # NOT 2026-02-05, the squatter
        squatter = [i for i in plan.inserts if i["booking_date"] == "2026-02-05"]
        self.assertEqual([i["reason"] for i in squatter], ["provider_ref_reuse"])

    def test_a_ref_reuse_victim_is_not_flagged_twice_in_one_plan(self):
        """The wholesale exclusion kept these rows out of rule 2's pool,
        so one row could not collect two flags. Now that they cluster here, an
        unresolved cluster could emit a second `flags` entry for the same
        row_id -- and the review breakdown is counted BY reason, so one row
        must not land in two buckets."""
        stored, fetched = self.oversized(["2026-02-%02d" % d
                                          for d in (20, 21, 22, 23, 24, 25, 26, 27)])
        plan = ingest.reconcile(stored, fetched, ("2026-01-01", "2026-05-01"), STABLE)
        self.assertEqual([(f["row_id"], f["reason"]) for f in plan.flags],
                         [(1, "provider_ref_reuse")])
        self.assertEqual(plan.updates, [])
        self.assertEqual(plan.tombstones, [])   # an unresolved cluster is retained

    def test_the_pass_converges_instead_of_re_flagging_for_ever(self):
        """Iterated, with the plan naively applied between passes. Pre-fix,
        pass 1 emitted a silent duplicate and every later pass re-flagged row
        7 (the squatter's inserted row now carries R1 too), so the row stayed
        out of rule 2 and exempt from rule 3 indefinitely."""
        stored, fetched = self.fixture()
        p1 = ingest.reconcile(stored, fetched, IV, STABLE)
        after = apply_plan(stored, p1)
        self.assertEqual(len(after), 2)          # the correction + the squatter
        self.assertEqual(sorted(r["amount_minor"] for r in after), [1000, 9999])
        p2 = ingest.reconcile(after, fetched, IV, STABLE)
        self.assertEqual(p2.inserts, [])
        self.assertEqual(p2.updates, [])
        self.assertEqual(p2.tombstones, [])
        self.assertEqual(p2.flags, [])           # nothing left to say: converged
        p3 = ingest.reconcile(apply_plan(after, p2), fetched, IV, STABLE)
        self.assertEqual((p3.inserts, p3.updates, p3.tombstones, p3.flags),
                         ([], [], [], []))


class TestCrossPairingReachesAFixedPoint(unittest.TestCase):
    """Two fetched rows a few days apart sharing one trusted
    reference each corroborate the OTHER's stored row via the amount arm -- a
    recurrence has the same amount every time -- and rule 1 ranked the
    corroborating reps by content hash and date, which is arbitrary with
    respect to the one signal that settles it: whether a rep IS this stored
    row's content. So it CROSS-PAIRED them, and because a cross-pair can land a
    pending stored row against a booked fetched row it hit emit_match's
    supersession branch and INSERTED.

    Re-fetching an unchanged interval therefore never reached a fixed point:
    one extra physical row and one extra occurrence per pass, for ever. The
    ACTIVE row count stayed pinned, which is precisely why a short-horizon
    check read as converged -- the growth is in the physical table, which is
    what `apply` makes durable.
    """

    # Empty ledger, two rows, one reference, 3 days apart. The counterparties
    # differ only as absent-vs-empty, so the two rows have distinct
    # identity_keys while sharing an amount -- the amount arm corroborates both
    # ways round.
    FETCHED = [row("2026-02-03", amount=2000, cp=None, rem=None, ref="R1",
                   status="PDNG"),
               row("2026-02-06", amount=2000, cp="", rem=None, ref="R1",
                   status="BOOK")]

    def iterate(self, passes):
        """Re-present the SAME fetch `passes` times, applying between passes.
        Returns per-pass (physical rows, active rows, max occurrence) plus the
        count of unreasoned re-keys after the first pass."""
        cur, curve, unreasoned = [], [], 0
        for p in range(passes):
            before = {s["row_id"]: s for s in cur}
            plan = ingest.reconcile(cur, self.FETCHED, IV, STABLE)
            if p:
                for u in plan.updates:
                    if (u["op"] == "update"
                            and u["identity_key"]
                            != before[u["row_id"]]["identity_key"]
                            and not u["needs_review"] and u["reason"] is None):
                        unreasoned += 1
            cur = apply_plan(cur, plan)
            active = [r for r in cur if r.get("state", "active") == "active"]
            curve.append((len(cur), len(active),
                          max(r["occurrence"] for r in cur)))
        return cur, curve, unreasoned

    def test_a_repeated_unchanged_fetch_reaches_a_fixed_point(self):
        """The horizon matters: a 5-pass window hid this entirely."""
        cur, curve, _ = self.iterate(80)
        physical, active, occurrence = zip(*curve)
        self.assertEqual(physical[0], 2)
        self.assertEqual(set(physical), {2})        # no growth, at any pass
        self.assertEqual(set(active), {2})
        self.assertEqual(set(occurrence), {0})      # no occurrence inflation
        self.assertEqual(sum(r["amount_minor"] for r in cur
                             if r.get("state", "active") == "active"), 4000)

    def test_the_steady_state_plan_is_empty(self):
        cur, _, _ = self.iterate(6)
        plan = ingest.reconcile(cur, self.FETCHED, IV, STABLE)
        self.assertEqual((plan.inserts, plan.updates, plan.tombstones,
                          plan.flags), ([], [], [], []))

    def test_no_unreasoned_rekey_on_a_repeated_fetch(self):
        """The safety net did NOT cover this shape: the cross-paired
        `op="update"` rewrote the row's amount, date, status AND identity_key
        while carrying needs_review=False, reason=None. A re-key is legitimate
        and legitimately unreviewed when a reference carries a genuine amount
        correction; a re-key on a fetch that changed NOTHING is not."""
        _, _, unreasoned = self.iterate(80)
        self.assertEqual(unreasoned, 0)

    def test_the_content_identical_pairing_is_preferred(self):
        """The mechanism, pinned directly: each stored row must be matched by
        the fetched row carrying ITS content, not the other one."""
        cur, _, _ = self.iterate(1)
        plan = ingest.reconcile(cur, self.FETCHED, IV, STABLE)
        self.assertEqual(plan.updates, [])     # no cross-pair, so nothing to write
        self.assertEqual(plan.inserts, [])
        for stored_row in cur:
            twin = [f for f in self.FETCHED
                    if ingest.identity_key(f) == stored_row["identity_key"]]
            self.assertEqual(len(twin), 1)     # each stored row has exactly one twin

    def test_a_genuine_amount_correction_is_still_carried(self):
        """The fallback must be untouched: when NO rep carries the stored row's
        content -- the ordinary correction a reference exists to carry --
        the reference still re-keys the row in place."""
        stored = [row("2026-02-05", amount=1000, ref="R1", rid=7)]
        fetched = [row("2026-02-05", amount=1200, ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual([(u["op"], u["row_id"], u["amount_minor"],
                           u["match_method"]) for u in plan.updates],
                         [("update", 7, 1200, "reference_corroborated")])
        self.assertEqual(plan.updates[0]["identity_key"],
                         ingest.identity_key(fetched[0]))
        self.assertEqual(plan.inserts, [])

    def test_an_identical_restatement_beats_a_second_row_under_one_reference(self):
        """Content genuinely differs on ONE of the two reps. A page shows
        current state, so a row identical to the stored one being present means
        that transaction still exists -- the differing row is a second
        transaction squatting the reference, not a correction of the first. The
        safe reading, and the safe direction: the stored row is left alone and
        the other row becomes a DISCLOSED insert rather than an in-place
        overwrite of a valid amount."""
        stored = [row("2026-02-05", amount=1000, cp="AH", ref="R1", rid=7)]
        identical = row("2026-02-05", amount=1000, cp="AH", ref="R1")
        different = row("2026-02-06", amount=1200, cp="AH", ref="R1")
        plan = ingest.reconcile(stored, [identical, different], IV, STABLE)
        self.assertEqual(plan.updates, [])          # row 7 keeps its amount
        self.assertEqual([(i["amount_minor"], i["needs_review"], i["reason"])
                          for i in plan.inserts],
                         [(1200, True, "provider_ref_reuse")])
        self.assertEqual(plan.tombstones, [])

    def test_genuine_ambiguity_is_still_disclosed(self):
        """Preferring content identity must not swallow the real ambiguity: when
        NO rep carries the stored row's content and more than one corroborates,
        this is still a disagreement one 'unique' reference cannot settle."""
        stored = [row("2026-02-05", amount=1000, cp="Albert Heijn",
                      rem="rent", ref="R1", rid=1)]
        f1 = row("2026-02-05", amount=1000, cp="Someone Else", rem="rent", ref="R1")
        f2 = row("2026-02-06", amount=2000, cp="Albert Heijn", rem="rent", ref="R1")
        plan = ingest.reconcile(stored, [f1, f2], IV, STABLE)
        self.assertEqual(len(plan.updates), 1)
        self.assertTrue(plan.updates[0]["needs_review"])
        self.assertEqual(plan.updates[0]["reason"], "reference_shared_in_fetch")

    def test_two_content_identical_bands_remain_ambiguous(self):
        """The other genuine case: SEVERAL reps carry this row's content (same
        content in two date bands, corroborating from opposite sides). Content
        identity cannot break that tie, so it stays disclosed."""
        stored = [row("2026-02-06", amount=100000, cp="V", rem="huur",
                      ref="R1", rid=4)]
        before = row("2026-02-03", amount=100000, cp="V", rem="huur", ref="R1")
        after = row("2026-02-09", amount=100000, cp="V", rem="huur", ref="R1")
        plan = ingest.reconcile(stored, [before, after], IV, STABLE)
        self.assertEqual(len(plan.updates), 1)
        self.assertTrue(plan.updates[0]["needs_review"])
        self.assertEqual(plan.updates[0]["reason"], "reference_shared_in_fetch")


def content_projection(plan):
    """A plan described by CONTENT rather than by row_id, so two ledgers holding
    the same transactions under different row_ids compare equal."""
    return (sorted((i["booking_date"], i["amount_minor"], i["remittance"],
                    i["needs_review"], i["reason"]) for i in plan.inserts),
            sorted((u["op"], u.get("booking_date"), u.get("amount_minor"),
                    u.get("remittance"), u["match_method"], u["needs_review"],
                    u["reason"]) for u in plan.updates),
            len(plan.tombstones), len(plan.flags))


def surviving_money(stored, plan):
    return sorted((r["amount_minor"], str(r["remittance"]))
                  for r in apply_plan(stored, plan)
                  if r.get("state", "active") == "active")


class TestContentIdentityOutranksIncidentalCorroboration(unittest.TestCase):
    """Preferring a content twin PER CANDIDATE is not enough while the
    assignment stayed greedy in row_id order, so a candidate could still take
    the rep a later candidate needed. Two stored rows under one reference, the
    first with no twin in the page and the second with one: the first goes
    first, sees a single corroborating rep -- the second row's twin -- and takes
    it on the 0.7 counterparty arm.

    Content identity is therefore RESERVED for its own row across every
    candidate before any candidate may claim a rep it merely corroborates.
    Greed was the mechanism; precedence is the defect.
    """

    # trusted R1 throughout; the counterparty is constant, which is what makes
    # the 0.7 arm corroborate almost everything within 3 days
    S1 = dict(amount=1000, cp="A", rem="x", ref="R1")     # no twin in the page
    S2 = dict(amount=2000, cp="A", rem="y", ref="R1")     # twin is Fa
    FA = dict(amount=2000, cp="A", rem="y", ref="R1")
    FB = dict(amount=3000, cp="A", rem="z", ref="R1")

    def fixture(self, first_id, second_id):
        stored = [row("2026-02-05", rid=first_id, **self.S1),
                  row("2026-02-09", rid=second_id, **self.S2)]
        fetched = [row("2026-02-06", **self.FA), row("2026-02-10", **self.FB)]
        return sorted(stored, key=lambda s: s["row_id"]), fetched

    def test_the_adverse_row_id_order_no_longer_destroys_money(self):
        """EUR 10.00 used to vanish with no tombstone, no supersession, no flag
        and no reason, while row 2's amount was overwritten 2000 -> 3000 with
        its exact content sitting in the same page."""
        stored, fetched = self.fixture(1, 2)
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(surviving_money(stored, plan),
                         [(1000, "x"), (2000, "y"), (3000, "z")])
        self.assertEqual(plan.tombstones, [])
        # row 2 keeps its own content, matched by its twin at conf 1.0
        self.assertEqual([(u["row_id"], u["amount_minor"], u["remittance"],
                           u["match_method"]) for u in plan.updates],
                         [(2, 2000, "y", "reference")])
        # and the third transaction is a DISCLOSED insert, not an overwrite
        self.assertEqual([(i["amount_minor"], i["needs_review"], i["reason"])
                          for i in plan.inserts],
                         [(3000, True, "provider_ref_reuse")])
        self.assertEqual([(f["row_id"], f["reason"]) for f in plan.flags],
                         [(1, "provider_ref_reuse")])

    def test_the_plan_no_longer_depends_on_which_row_id_came_first(self):
        """Two ledgers differing by EUR 10.00, decided by row_id alone."""
        adverse_stored, fetched = self.fixture(1, 2)
        swapped_stored, _ = self.fixture(2, 1)
        adverse = ingest.reconcile(adverse_stored, fetched, IV, STABLE)
        swapped = ingest.reconcile(swapped_stored, fetched, IV, STABLE)
        self.assertEqual(content_projection(adverse), content_projection(swapped))
        self.assertEqual(surviving_money(adverse_stored, adverse),
                         surviving_money(swapped_stored, swapped))

    def test_the_adverse_order_is_what_natural_evolution_produces(self):
        """No hand-placed row_ids: page 1 inserts the two rows in exactly the
        order that made page 2 adverse."""
        page1 = [row("2026-02-05", **self.S1), row("2026-02-09", **self.S2)]
        led = apply_plan([], ingest.reconcile([], page1, IV, STABLE))
        self.assertEqual([(r["row_id"], r["amount_minor"]) for r in led],
                         [(1, 1000), (2, 2000)])
        page2 = [row("2026-02-06", **self.FA), row("2026-02-10", **self.FB)]
        plan = ingest.reconcile(led, page2, IV, STABLE)
        self.assertEqual(surviving_money(led, plan),
                         [(1000, "x"), (2000, "y"), (3000, "z")])
        self.assertEqual(plan.tombstones, [])

    def test_a_present_row_is_never_tombstoned(self):
        """Construction 3: row 3 is byte-identical to a fetched row, on the same
        booking date, and used to be declared 'absent_from_a_proven_interval'
        because row 2 greedily claimed its only match. Zero disclosure."""
        stored, fetched = self.fixture(1, 2)
        stored = stored + [row("2026-02-10", amount=3000, cp="A", rem="z",
                               ref="R2", rid=3)]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.tombstones, [])
        self.assertEqual(surviving_money(stored, plan),
                         [(1000, "x"), (2000, "y"), (3000, "z")])
        self.assertEqual(plan.inserts, [])           # row 3 IS the third row
        self.assertIn((3, 3000, "windowed"),
                      [(u["row_id"], u["amount_minor"], u["match_method"])
                       for u in plan.updates])

    def test_the_invariant_itself_over_every_construction(self):
        """The invariant, named and asserted rather than left emergent: a stored
        row whose exact content is present in the fetch within the bound is
        never silently re-keyed and never tombstoned."""
        adverse, fetched = self.fixture(1, 2)
        cases = [
            (adverse, fetched),
            (self.fixture(2, 1)[0], fetched),
            (adverse + [row("2026-02-10", amount=3000, cp="A", rem="z",
                            ref="R2", rid=3)], fetched),
            # the cross-reference shape: the twin arrives under ANOTHER reference
            ([row("2026-02-05", amount=1000, cp="A", rem="x", ref="R1", rid=1)],
             [row("2026-02-06", amount=1200, cp="A", rem="x", ref="R1"),
              row("2026-02-06", amount=1000, cp="A", rem="x", ref="R2")]),
            # the rule-3 shape: rule 1 claims the twin for a different row
            ([row("2026-02-21", amount=9999, cp="Shell", rem="g", rid=1),
              row("2026-02-27", amount=9999, cp=None, rem=None, ref="R2",
                  rid=2, status="PDNG")],
             [row("2026-02-24", amount=9999, cp="Shell", rem="g", ref="R2")]),
        ]
        for stored, fetch in cases:
            plan = ingest.reconcile(stored, fetch, IV, STABLE)
            by_id = {s["row_id"]: dict(s) for s in stored}
            for s in by_id.values():
                s.setdefault("identity_key", ingest.identity_key(s))
            present = {rid for rid, s in by_id.items()
                       if any(ingest.identity_key(f) == s["identity_key"]
                              and ingest._days(s["booking_date"],
                                               f["booking_date"])
                              <= ingest.AMOUNT_ONLY_MATCH_WINDOW_DAYS
                              for f in fetch)}
            for t in plan.tombstones:
                self.assertNotIn(t["row_id"], present,
                                 "tombstoned a PRESENT row: %r" % (fetch,))
            for u in plan.updates:
                if u["op"] != "update":
                    continue
                rekeyed = u["identity_key"] != by_id[u["row_id"]]["identity_key"]
                if rekeyed and u["row_id"] in present:
                    self.assertTrue(u["needs_review"],
                                    "silent re-key of a PRESENT row: %r" % (fetch,))
                    self.assertIsNotNone(u["reason"])


class TestAmountRewritesOnTheCorroborationArmAreDisclosed(unittest.TestCase):
    """Fix 2 (operator-ruled). `reference_corroborated` means the
    amount arm did not fire, so amount_minor differs: the only evidence the two
    rows are one transaction is a counterparty name plus <= 3 days, which this
    module itself scores 0.7 -- and it then wrote needs_review=False while
    rewriting a MONEY field. Rule 2's greedy fallback discloses at 0.5 and
    reference_shared_in_fetch discloses at 1.0."""

    def test_a_corroborated_amount_rewrite_carries_amount_changed(self):
        stored = [row("2026-02-05", amount=1000, cp="A", rem="x", ref="R1", rid=7)]
        fetched = [row("2026-02-06", amount=1200, cp="A", rem="x", ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        upd = plan.updates[0]
        self.assertEqual(upd["match_method"], "reference_corroborated")
        self.assertEqual(upd["match_confidence"], 0.7)
        self.assertEqual(upd["amount_minor"], 1200)
        self.assertTrue(upd["needs_review"])
        self.assertEqual(upd["reason"], "amount_changed")

    def test_the_confident_arm_keeps_the_amount_and_stays_unflagged(self):
        """The conf=1.0 `reference` arm fires only when the amount is unchanged,
        so money is intact and flagging it would be noise."""
        stored = [row("2026-02-05", amount=1000, cp="A", rem="x", ref="R1", rid=7)]
        fetched = [row("2026-02-06", amount=1000, cp="A", rem="x", ref="R1")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        upd = plan.updates[0]
        self.assertEqual(upd["match_method"], "reference")
        self.assertEqual(upd["match_confidence"], 1.0)
        self.assertEqual(upd["amount_minor"], 1000)
        self.assertFalse(upd["needs_review"])
        self.assertIsNone(upd["reason"])


class TestContentPresentElsewhereIsDisclosed(unittest.TestCase):
    """The honest residue, disclosed rather than silently resolved.

    Reserving twins fixes candidate-order greed WITHIN one reference, but a twin
    carrying a DIFFERENT reference (or none at all) is not among that
    reference's representatives, so rule 1 can still re-key a row whose own
    content is in the page. Inverting rule 1 over rule 2 generally would close
    it -- and would contradict the occurrence rule, which
    test_the_vacated_occurrence_is_not_reissued_in_the_same_pass pins. So the
    pairing stands and the rewrite is never silent."""

    def test_a_rekey_over_present_content_is_flagged_at_the_reference_site(self):
        stored = [row("2026-02-05", amount=1000, cp="A", rem="x", ref="R1", rid=1)]
        fetched = [row("2026-02-06", amount=1200, cp="A", rem="x", ref="R1"),
                   row("2026-02-06", amount=1000, cp="A", rem="x", ref="R2")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        upd = plan.updates[0]
        self.assertEqual(upd["row_id"], 1)
        self.assertEqual(upd["amount_minor"], 1200)
        self.assertNotEqual(upd["identity_key"], ingest.identity_key(stored[0]))
        self.assertTrue(upd["needs_review"])
        self.assertEqual(upd["reason"], "content_present_elsewhere")

    def spared_fixture(self, drift):
        """One stored row whose content twin is `drift` days away in the page,
        plus a second stored row that claims that twin via rule 1's amount arm.
        The first row is then unmatched, and only the present-content guard
        decides whether it survives."""
        import datetime as _dt      # local: the module header is pre-existing
        fetch_date = _dt.date(2026, 2, 24)
        twin_date = (fetch_date - _dt.timedelta(days=drift)).isoformat()
        return ([row(twin_date, amount=9999, cp="Shell", rem="g", rid=1),
                 row("2026-02-27", amount=9999, cp=None, rem=None, ref="R2",
                     rid=2, status="PDNG")],
                [row(fetch_date.isoformat(), amount=9999, cp="Shell", rem="g",
                     ref="R2")])

    def test_the_guard_reaches_exactly_the_corroboration_drift_bound(self):
        """Pinned to the CONSTANT, not to a hardcoded number of days, so the
        test follows a deliberate change of the bound but still fails if the
        guard is switched to MATCH_WINDOW_DAYS. Measured trade-off if it ever
        is widened to 7: 5 fewer tombstones and 5 more flags per 6000 fixtures,
        with H unchanged at 0 either way -- so this is a noise-versus-retention
        choice, not a correctness one."""
        bound = ingest.AMOUNT_ONLY_MATCH_WINDOW_DAYS
        stored, fetched = self.spared_fixture(bound)
        at_bound = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(at_bound.tombstones, [])
        self.assertIn((1, "content_present_elsewhere"),
                      [(f["row_id"], f["reason"]) for f in at_bound.flags])
        stored, fetched = self.spared_fixture(bound + 1)
        beyond = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual([(t["row_id"], t["reason"]) for t in beyond.tombstones],
                         [(1, "absent_from_a_proven_interval")])

    def test_a_present_row_spared_from_tombstoning_is_flagged(self):
        """Sparing it is right -- a row whose content is in the page is not
        absent by any reading -- but the ledger then holds this row AND an
        insert of the same content, so somebody must be told. Measured: without
        this flag the fix converts one silent deletion into one UNDISCLOSED
        duplicate."""
        stored = [row("2026-02-21", amount=9999, cp="Shell", rem="g", rid=1),
                  row("2026-02-27", amount=9999, cp=None, rem=None, ref="R2",
                      rid=2, status="PDNG")]
        fetched = [row("2026-02-24", amount=9999, cp="Shell", rem="g", ref="R2")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(plan.tombstones, [])
        self.assertIn((1, "content_present_elsewhere"),
                      [(f["row_id"], f["reason"]) for f in plan.flags])


class TestMoneyBearingRewritesAreDisclosed(unittest.TestCase):
    """The conf=1.0 `reference` arm was left unflagged on
    the premise that it "keeps the amount by construction, so money is intact
    there". True of `amount_minor`, false of the money: `_corroborate` compares
    only `amount_minor`, while `identity_key` also hashes `currency` and
    `direction`. So a row whose SIGN changed corroborated at 1.0 -- because the
    magnitude matched -- and was re-keyed in place in total silence. `_MUTABLE`
    covers neither field either, so the write reached the row only via
    `rekeyed`, which is why it would leave no trace anywhere.

    Note what made this survivable for five rounds of measurement: every fuzz
    corpus used on this module inherited `row()`'s fixed `currency="EUR"` and
    `direction="DBIT"`, and a corpus that never varies a field cannot see a
    defect in it.
    """

    STORED = dict(amount=1000, cp="A", rem="x", ref="R1")

    def plan_for(self, **override):
        stored = [row("2026-02-05", rid=7, **self.STORED)]
        fetched = [dict(row("2026-02-06", **self.STORED), **override)]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        self.assertEqual(len(plan.updates), 1)
        upd = plan.updates[0]
        self.assertEqual(upd["op"], "update")
        self.assertEqual(upd["row_id"], 7)
        return stored, upd

    def test_a_sign_flip_is_disclosed(self):
        """DBIT -> CRDT at the same magnitude: a EUR 10 debit becomes a EUR 10
        credit, which is a EUR 20 swing in every total."""
        stored, upd = self.plan_for(direction="CRDT")
        self.assertEqual(upd["direction"], "CRDT")
        self.assertEqual(upd["amount_minor"], 1000)          # magnitude matched
        self.assertEqual(upd["match_confidence"], 1.0)       # so it scored 1.0
        self.assertNotEqual(upd["identity_key"], ingest.identity_key(stored[0]))
        self.assertTrue(upd["needs_review"])
        self.assertEqual(upd["reason"], "direction_or_currency_changed")

    def test_a_currency_change_is_disclosed(self):
        """EUR -> USD: the stored integer now means a different unit."""
        stored, upd = self.plan_for(currency="USD")
        self.assertEqual(upd["currency"], "USD")
        self.assertEqual(upd["match_confidence"], 1.0)
        self.assertTrue(upd["needs_review"])
        self.assertEqual(upd["reason"], "direction_or_currency_changed")

    def test_both_at_once_is_disclosed_once(self):
        _stored, upd = self.plan_for(direction="CRDT", currency="USD")
        self.assertTrue(upd["needs_review"])
        self.assertEqual(upd["reason"], "direction_or_currency_changed")

    def test_the_sign_outranks_an_amount_change_in_the_breakdown(self):
        """Ranked deliberately: a sign or unit change is rarer and more alarming
        than a value correction, so it must not be hidden inside the common
        bucket when the breakdown is reported by reason."""
        _stored, upd = self.plan_for(amount_minor=1200, direction="CRDT")
        self.assertEqual(upd["amount_minor"], 1200)
        self.assertEqual(upd["direction"], "CRDT")
        self.assertEqual(upd["reason"], "direction_or_currency_changed")

    def test_an_amount_only_change_still_says_amount_changed(self):
        _stored, upd = self.plan_for(amount_minor=1200)
        self.assertEqual(upd["reason"], "amount_changed")

    def test_a_relabelling_with_the_money_intact_stays_unflagged(self):
        """The operator scoped this out explicitly, and the fix must not creep
        into it: a conf-1.0 re-key that moves only `counterparty` and
        `remittance`, with amount, currency and direction all intact, is a
        relabelling and flagging the whole arm would be noise. This is a real
        re-key -- the identity_key genuinely moves -- not a no-op match."""
        stored, upd = self.plan_for(counterparty="B", remittance="y")
        self.assertNotEqual(upd["identity_key"], ingest.identity_key(stored[0]))
        self.assertEqual(upd["match_confidence"], 1.0)
        self.assertEqual((upd["amount_minor"], upd["currency"], upd["direction"]),
                         (1000, "EUR", "DBIT"))
        self.assertFalse(upd["needs_review"])
        self.assertIsNone(upd["reason"])

    def test_a_restated_currency_spelling_neither_rekeys_nor_flags(self):
        """The comparison runs through `_canon`, the same normalisation
        identity_key uses, so the flag can only fire where the identity
        genuinely moved -- never on a provider restating EUR as eur."""
        stored = [row("2026-02-05", rid=7, **self.STORED)]
        fetched = [dict(row("2026-02-06", **self.STORED), currency="eur",
                        direction="dbit")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        upd = plan.updates[0]
        self.assertEqual(upd["identity_key"], ingest.identity_key(stored[0]))
        self.assertFalse(upd["needs_review"])
        self.assertIsNone(upd["reason"])

    def test_a_superseding_sign_flip_is_disclosed_on_both_records(self):
        """pending -> booked routes through emit_match's supersession branch, so
        the reason must reach the insert AND the supersede record."""
        stored = [row("2026-02-05", rid=9, status="PDNG", **self.STORED)]
        fetched = [dict(row("2026-02-06", status="BOOK", **self.STORED),
                        direction="CRDT")]
        plan = ingest.reconcile(stored, fetched, IV, STABLE)
        sup = [u for u in plan.updates if u["op"] == "supersede"]
        self.assertEqual([s["row_id"] for s in sup], [9])
        self.assertTrue(sup[0]["needs_review"])
        self.assertEqual(sup[0]["reason"], "direction_or_currency_changed")
        self.assertEqual([(i["needs_review"], i["reason"]) for i in plan.inserts],
                         [(True, "direction_or_currency_changed")])


class TestASupersessionCarriesAStandingFinding(unittest.TestCase):
    """A supersession is the ONE match that moves the money to a
    different row, so it is the one place a standing `needs_review` can fall
    out of the operator's view — `list_transactions` filters `state='active'`,
    and the flagged row has just become `superseded`.

    Reproduced end to end through `sync` before the fix: a pending row flagged
    `provider_ref_reuse` by reconcile itself booked on the next pass, and the
    live view reported "none flagged for review" over money the system had
    marked as possibly duplicated or misattributed. Identical user-visible
    failure to the cross-pass overwrite, reached by a
    different route.
    """

    def _pend(self, **kw):
        base = dict(row("2026-02-05", rid=9, ref="R1", status="PDNG"),
                    needs_review=1, review_reason="provider_ref_reuse")
        base.update(kw)
        return base

    def test_the_replacement_inherits_the_flag(self):
        plan = ingest.reconcile(
            [self._pend()], [row("2026-02-07", ref="R1", status="BOOK")],
            IV, STABLE)
        self.assertEqual([(i["needs_review"], i["reason"])
                          for i in plan.inserts],
                         [(True, "provider_ref_reuse")])

    def test_the_superseded_row_keeps_it_too(self):
        # Both records, so the transition itself stays legible: the row that
        # was flagged still says so, and the row that replaced it says why.
        plan = ingest.reconcile(
            [self._pend()], [row("2026-02-07", ref="R1", status="BOOK")],
            IV, STABLE)
        sup = [u for u in plan.updates if u["op"] == "supersede"]
        self.assertEqual([(s["needs_review"], s["reason"]) for s in sup],
                         [(True, "provider_ref_reuse")])

    def test_a_finding_from_this_pass_wins_over_the_inherited_one(self):
        # Sticky is not the same as frozen. A sign flip detected NOW is more
        # specific than a reference finding from a previous week, and naming
        # the older one would hide it -- the same rule apply's
        # COALESCE(?, review_reason) applies one layer down.
        pend = self._pend(review_reason="windowed_ambiguous")
        flipped = dict(row("2026-02-06", ref="R1", status="BOOK"),
                       direction="CRDT")
        plan = ingest.reconcile([pend], [flipped], IV, STABLE)
        self.assertEqual([(i["needs_review"], i["reason"])
                          for i in plan.inserts],
                         [(True, "direction_or_currency_changed")])

    def test_an_unflagged_pending_row_still_books_clean(self):
        # The fix must not flag every supersession: PDNG -> BOOK is the most
        # ordinary transition a bank performs, and an always-on flag is a
        # disclosure nobody reads.
        plan = ingest.reconcile(
            [row("2026-02-05", rid=9, ref="R1", status="PDNG")],
            [row("2026-02-07", ref="R1", status="BOOK")], IV, STABLE)
        self.assertEqual([(i["needs_review"], i["reason"])
                          for i in plan.inserts], [(False, None)])
        sup = [u for u in plan.updates if u["op"] == "supersede"]
        self.assertEqual([(s["needs_review"], s["reason"]) for s in sup],
                         [(False, None)])

    def test_a_flag_with_no_recorded_cause_is_carried_without_inventing_one(self):
        # tools_read._reason_label renders None as "no reason recorded". That
        # is the honest rendering; synthesising a reason code here would put a
        # cause in the breakdown that no rule ever found.
        plan = ingest.reconcile(
            [self._pend(review_reason=None)],
            [row("2026-02-07", ref="R1", status="BOOK")], IV, STABLE)
        self.assertEqual([(i["needs_review"], i["reason"])
                          for i in plan.inserts], [(True, None)])

    def test_an_inherited_flag_does_not_chain_through_later_passes(self):
        """The bound on inheritance, asserted rather than argued.

        The branch requires `_is_pending(s)`, and the row it inserts carries
        the FETCHED row's status, which `_is_booked` has just asserted — so a
        booked replacement can never be the pending side of another
        supersession and an inherited flag cannot be handed down a chain.
        Driven here: book it, then keep re-fetching the booked row, including
        the case where the bank sends PDNG again afterwards.
        """
        plan = ingest.reconcile(
            [self._pend()], [row("2026-02-07", ref="R1", status="BOOK")],
            IV, STABLE)
        booked = dict(row("2026-02-07", rid=10, ref="R1", status="BOOK"),
                      needs_review=1, review_reason="provider_ref_reuse",
                      identity_key=plan.inserts[0]["identity_key"],
                      occurrence=plan.inserts[0]["occurrence"])
        for again in (row("2026-02-07", ref="R1", status="BOOK"),
                      row("2026-02-07", ref="R1", status="PDNG")):
            nxt = ingest.reconcile([booked], [again], IV, STABLE)
            self.assertEqual(
                [u for u in nxt.updates if u["op"] == "supersede"], [],
                "a booked row was superseded again: inheritance is no longer "
                "bounded at one hop")
            self.assertEqual(nxt.inserts, [])


if __name__ == "__main__":
    unittest.main()


class TestNormaliseMalformedText(unittest.TestCase):
    """A non-string scalar counterparty
    or remittance is malformed provider data — stored as None (absent,
    fail-closed), never str()-coerced, because SQLite TEXT affinity would
    erase the type and let '123' equal a rule anchor."""

    RAW = dict(TestNormalise.RAW)

    def test_numeric_counterparty_and_remittance_become_none(self):
        raw = dict(self.RAW, creditor={"name": 123},
                   remittance_information=456)
        out = ingest.normalise(raw, "acc1")
        self.assertIsNone(out["counterparty"])
        self.assertIsNone(out["remittance"])

    def test_remittance_list_still_flattens(self):
        out = ingest.normalise(dict(self.RAW), "acc1")
        self.assertIn("Betaalpas", out["remittance"])
