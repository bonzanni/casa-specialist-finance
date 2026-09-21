# tests/test_tag_namespaces.py
"""Issue #31: a tag written as `owner::name` belongs to another workflow.

It is never content classification, it has its own per-row budget, and
bank-feed's vocabulary tools (rename, merge, rules) cannot move one. Expected
states below are written out by hand, never computed through
rules.classification_state — the predicate is what is under test.
"""
import itertools
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))

import rules  # noqa: E402
import tools_annotate  # noqa: E402
import tools_rules  # noqa: E402,F401  (registers add_rule)
from test_tools_read import Base, call  # noqa: E402


class LedgerCase(Base):
    def setUp(self):
        super().setUp()
        self.account("a")
        self.synced("a", "transactions")
        self._n = 0

    def row(self):
        self._n += 1
        ik = "ik-%d" % self._n
        self.tx("a", ik)
        return self.conn.execute(
            "SELECT row_id FROM transactions WHERE identity_key=?",
            (ik,)).fetchone()[0]

    def store_tag(self, rid, tag):
        # Direct insert: the value a hand-edited or older ledger can hold,
        # bypassing the write-path grammar.
        self.conn.execute("INSERT INTO transaction_tags(row_id, tag, added_at)"
                          " VALUES (?,?,'t')", (rid, tag))

    def tags_of(self, rid):
        return [r[0] for r in self.conn.execute(
            "SELECT tag FROM transaction_tags WHERE row_id=? ORDER BY tag",
            (rid,))]

    def queue_ids(self):
        reply = call("list_transactions", untagged_only=True, limit=500)
        return {int(l.split()[0][1:]) for l in
                (x.strip() for x in reply.splitlines()) if l.startswith("#")}


class TestGrammar(unittest.TestCase):
    def norm(self, *tags):
        return tools_annotate._normalize_tags(list(tags))

    def test_namespaced_tags_are_accepted_and_normalized(self):
        self.assertEqual(self.norm(" ACCT::Matched ", "acct::no-invoice-expected"),
                         (["acct::matched", "acct::no-invoice-expected"], None))
        self.assertEqual(self.norm("a" * 16 + "::" + "b" * 32)[1], None)

    def test_malformed_namespaces_refuse(self):
        for bad in ("food:groceries", "acct:::x", "::x", "acct::", "a::b::c",
                    "1acct::x", "-acct::x", "a" * 17 + "::x",
                    "acct::" + "b" * 33, "acct::-x", "acct ::x"):
            tags, refusal = self.norm(bad)
            self.assertEqual(tags, [], bad)
            self.assertIn("Nothing was changed", refusal, bad)

    def test_single_colon_refusal_does_not_suggest_a_namespace(self):
        # The classifier must not be nudged into minting namespaces for
        # hierarchy ("food:groceries" -> "food::groceries").
        _, refusal = self.norm("food:groceries")
        self.assertNotIn("::", refusal)

    def test_one_tag_parser_uses_the_same_grammar(self):
        self.assertEqual(tools_annotate._one_tag("Acct::Matched"),
                         ("acct::matched", None))
        self.assertIsNotNone(tools_annotate._one_tag("food:groceries")[1])

    def test_rule_grammar_matches_the_write_grammar(self):
        self.assertEqual(rules.TAG_RE.pattern, tools_annotate.TAG_RE.pattern)


class TestClassificationState(unittest.TestCase):
    """Hand-written truth table; each row says why."""

    CASES = [
        ((), "workable"),
        (("acct::matched",), "workable"),            # symptom 1
        (("acct::matched", "tax::q3"), "workable"),
        (("food",), "classified"),
        (("food", "acct::matched"), "classified"),
        (("awaiting-operator",), "parked"),
        (("awaiting-operator", "acct::matched"), "parked"),
        (("awaiting-operator", "food"), "parked"),
        (("unclassifiable",), "terminal"),
        (("unclassifiable", "acct::matched"), "terminal"),
        (("acct-matched",), "classified"),          # no '::' = classification
        (("acct:matched",), "classified"),          # stray single colon: as today
    ]

    def test_truth_table(self):
        for tags, want in self.CASES:
            self.assertEqual(rules.classification_state(tags), want, tags)

    def test_is_classification_tag(self):
        self.assertTrue(rules.is_classification_tag("food"))
        self.assertTrue(rules.is_classification_tag("acct:matched"))
        self.assertFalse(rules.is_classification_tag("acct::matched"))
        for t in rules.WORKFLOW_TAGS:
            self.assertFalse(rules.is_classification_tag(t))

    def test_namespace_of(self):
        self.assertEqual(rules.tag_namespace("acct::matched"), "acct")
        self.assertIsNone(rules.tag_namespace("food"))
        self.assertIsNone(rules.tag_namespace("acct:matched"))


class TestQueue(LedgerCase):
    def test_foreign_tag_keeps_an_unclassified_row_in_the_queue(self):
        rid = self.row()
        self.assertEqual(rules.queue_totals(self.conn), (1, 0))
        out = call("tag_transaction", row_ids=[rid], tags=["acct::matched"])
        self.assertIn("Tagged 1 row", out)
        self.assertEqual(rules.queue_totals(self.conn), (1, 0))
        self.assertEqual(self.queue_ids(), {rid})
        call("tag_transaction", row_ids=[rid], tags=["food"])
        self.assertEqual(rules.queue_totals(self.conn), (0, 0))
        self.assertEqual(self.queue_ids(), set())

    def test_sql_queue_agrees_with_the_python_predicate(self):
        # Every subset of a vocabulary that covers each branch, stray
        # single-colon values included, one row per subset.
        vocab = ("food", "acct::matched", "acct:matched", "awaiting-operator",
                 "unclassifiable", "tax::q3")
        expected_queue, expected_totals = set(), [0, 0]
        for n in range(len(vocab) + 1):
            for subset in itertools.combinations(vocab, n):
                rid = self.row()
                for t in subset:
                    self.store_tag(rid, t)
                state = rules.classification_state(subset)
                if state in ("workable", "parked"):
                    expected_queue.add(rid)
                if state == "workable":
                    expected_totals[0] += 1
                elif state == "parked":
                    expected_totals[1] += 1
        self.assertEqual(self.queue_ids(), expected_queue)
        self.assertEqual(rules.queue_totals(self.conn), tuple(expected_totals))
        # Independent anchor for the loop above: 64 subsets, of which
        # terminal = 32 (unclassifiable present); of the other 32, parked =
        # 16; of the remaining 16 (no marker), workable = no 'food' and no
        # 'acct:matched' = 4.
        self.assertEqual(tuple(expected_totals), (4, 16))


class TestCapacity(LedgerCase):
    def test_classification_budget_is_not_consumed_by_foreign_tags(self):
        rid = self.row()
        call("tag_transaction", row_ids=[rid],
             tags=["acct::t%d" % i for i in range(16)])
        call("tag_transaction", row_ids=[rid], tags=["a%d" % i for i in range(16)])
        out = call("tag_transaction", row_ids=[rid],
                   tags=["b%d" % i for i in range(16)])
        self.assertIn("Tagged 1 row", out)
        self.assertEqual(len(self.tags_of(rid)), 48)

    def test_foreign_tag_fits_on_a_full_row(self):
        rid = self.row()
        for i in range(32):
            self.store_tag(rid, "c%d" % i)
        out = call("tag_transaction", row_ids=[rid], tags=["acct::matched"])
        self.assertIn("Tagged 1 row", out)
        refused = call("tag_transaction", row_ids=[rid], tags=["one-more"])
        self.assertIn("Nothing was changed", refused)

    def test_per_namespace_cap(self):
        rid = self.row()
        call("tag_transaction", row_ids=[rid],
             tags=["acct::t%d" % i for i in range(16)])
        out = call("tag_transaction", row_ids=[rid], tags=["acct::extra"])
        self.assertIn("Nothing was changed", out)
        self.assertIn("acct", out)
        # A different namespace has its own budget.
        out = call("tag_transaction", row_ids=[rid], tags=["tax::q3"])
        self.assertIn("Tagged 1 row", out)

    def test_total_namespaced_cap(self):
        rid = self.row()
        for ns in ("n1", "n2", "n3", "n4"):
            call("tag_transaction", row_ids=[rid],
                 tags=["%s::t%d" % (ns, i) for i in range(16)])
        self.assertEqual(len(self.tags_of(rid)), 64)
        out = call("tag_transaction", row_ids=[rid], tags=["n5::t"])
        self.assertIn("Nothing was changed", out)
        self.assertIn("64", out)


class TestRename(LedgerCase):
    def setUp(self):
        super().setUp()
        self.rid = self.row()

    def test_symptom_2_rename_out_of_a_namespace_refuses(self):
        call("tag_transaction", row_ids=[self.rid], tags=["acct::matched"])
        for merge in (False, True):
            out = call("rename_tag", old="acct::matched",
                       new="invoice-confirmed", merge=merge)
            self.assertIn("Nothing was changed", out)
            self.assertIn("acct", out)
        # The owner's retraction still lands.
        call("untag_transaction", row_ids=[self.rid], tags=["acct::matched"])
        self.assertEqual(self.tags_of(self.rid), [])

    def test_rename_into_a_namespace_refuses_even_when_unused(self):
        call("tag_transaction", row_ids=[self.rid], tags=["food"])
        rule_before = self.conn.execute("SELECT COUNT(*) FROM tag_rules"
                                        ).fetchone()[0]
        for merge in (False, True):
            out = call("rename_tag", old="food", new="acct::matched",
                       merge=merge)
            self.assertIn("Nothing was changed", out)
        self.assertEqual(self.tags_of(self.rid), ["food"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM tag_rules"
                                           ).fetchone()[0], rule_before)

    def test_rename_within_a_namespace_refuses(self):
        call("tag_transaction", row_ids=[self.rid], tags=["acct::matched"])
        out = call("rename_tag", old="acct::matched", new="acct::confirmed")
        self.assertIn("Nothing was changed", out)
        self.assertEqual(self.tags_of(self.rid), ["acct::matched"])

    def test_classification_rename_unaffected(self):
        call("tag_transaction", row_ids=[self.rid],
             tags=["ah", "acct::matched"])
        call("rename_tag", old="ah", new="groceries")
        self.assertEqual(self.tags_of(self.rid),
                         ["acct::matched", "groceries"])

    def test_delete_tag_on_a_namespaced_tag_is_allowed_and_named(self):
        call("tag_transaction", row_ids=[self.rid],
             tags=["acct::matched", "food"])
        out = call("delete_tag", tag="acct::matched")
        self.assertIn("acct", out)
        self.assertIn("reassert", out)
        self.assertEqual(self.tags_of(self.rid), ["food"])


class TestRules(LedgerCase):
    def test_rules_refuse_namespaced_tags(self):
        fields, refusal = rules.validate_rule(
            {"counterparty": "ACME BV", "tags": ["office", "acct::matched"]})
        self.assertIsNotNone(refusal)
        self.assertIn("acct::matched", refusal)

    def test_rule_application_counts_only_the_classification_budget(self):
        rid = self.row()
        for i in range(31):
            self.store_tag(rid, "c%d" % i)
        for i in range(16):
            self.store_tag(rid, "acct::t%d" % i)
        call("add_rule", counterparty="ACME BV", tags=["office"])
        out = rules.apply_to_rows(self.conn, [rid], "now")
        self.assertEqual(out["skipped_overcap"], [])
        self.assertIn("office", self.tags_of(rid))
        other = self.row()
        for i in range(32):
            self.store_tag(other, "c%d" % i)
        out = rules.apply_to_rows(self.conn, [other], "now")
        self.assertEqual(out["skipped_overcap"], [other])


class TestReads(LedgerCase):
    def test_list_tags_separates_other_workflows(self):
        rid = self.row()
        call("tag_transaction", row_ids=[rid], tags=["food", "acct::matched"])
        out = call("list_tags")
        head, _, tail = out.partition("Other workflows")
        self.assertIn("food", head)
        self.assertNotIn("acct::matched", head)
        self.assertIn("acct::matched", tail)
        self.assertIn("not classifications", tail)
        self.assertIn("1 tag(s) in use", head)

    def test_list_tags_with_only_foreign_tags(self):
        rid = self.row()
        call("tag_transaction", row_ids=[rid], tags=["acct::matched"])
        out = call("list_tags")
        self.assertIn("acct::matched", out.partition("Other workflows")[2])
        self.assertNotIn("No tags yet", out)

    def test_list_transactions_shows_foreign_tags_apart(self):
        rid = self.row()
        call("tag_transaction", row_ids=[rid], tags=["food", "acct::matched"])
        line = [l for l in call("list_transactions").splitlines()
                if l.strip().startswith("#%d " % rid)][0]
        self.assertIn("tags: food", line)
        self.assertNotIn("tags: acct", line)
        self.assertIn("other workflows: acct::matched", line)

    def test_get_transaction_shows_foreign_tags_apart(self):
        rid = self.row()
        call("tag_transaction", row_ids=[rid], tags=["acct::matched"])
        out = call("get_transaction", row_id=rid)
        self.assertIn("Tags: none", out)
        self.assertIn("acct::matched", out)

    def test_filters_accept_namespaced_names(self):
        a, b = self.row(), self.row()
        call("tag_transaction", row_ids=[a], tags=["acct::matched"])
        out = call("list_transactions", tags_any=["acct::matched"])
        self.assertIn("#%d " % a, out)
        self.assertNotIn("#%d " % b, out)

    def test_spend_by_tag_ignores_foreign_tags_by_default(self):
        a, b = self.row(), self.row()
        call("tag_transaction", row_ids=[a], tags=["acct::matched"])
        call("tag_transaction", row_ids=[b], tags=["food"])
        out = call("spend_by_tag")
        self.assertNotIn("acct::matched", out)
        untagged = [l for l in out.splitlines() if "(untagged)" in l]
        self.assertTrue(untagged)
        self.assertIn("1 row", " ".join(untagged))   # the foreign-only row

    def test_spend_by_tag_groups_a_named_foreign_tag(self):
        a = self.row()
        call("tag_transaction", row_ids=[a], tags=["acct::matched", "food"])
        out = call("spend_by_tag", tags=["acct::matched"])
        self.assertIn("acct::matched", out)
        self.assertNotIn("food", out)


if __name__ == "__main__":
    unittest.main()
