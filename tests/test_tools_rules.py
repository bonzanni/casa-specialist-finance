# tests/test_tools_rules.py
"""Rule tools: add/replace/list/remove/apply."""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))

import bank_feed_server  # noqa: E402
import store  # noqa: E402
import tools_read  # noqa: E402
import tools_rules  # noqa: E402  (registration side effect)
import rules  # noqa: E402


def call(name, **args):
    return bank_feed_server.TOOLS[name]["fn"](args)


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.conn = store.open_db(pathlib.Path(self.dir.name) / "f.sqlite")
        tools_read.CONN = self.conn

    def tearDown(self):
        tools_read.CONN = None
        self.dir.cleanup()

    def n_rules(self):
        return self.conn.execute(
            "SELECT COUNT(*) FROM tag_rules").fetchone()[0]


class TestAddRule(Base):
    def test_add_and_reply_names_rule_id(self):
        reply = call("add_rule", counterparty="Albert Heijn",
                     tags=["food", "groceries"],
                     rationale="operator confirmed 2026-08-05")
        self.assertIn("#1", reply)
        self.assertEqual(self.n_rules(), 1)

    def test_refusals_change_nothing(self):
        for bad in (dict(tags=["a"]),                       # no anchor
                    dict(counterparty="X", tags=[]),
                    dict(counterparty="X", tags=["awaiting-operator"]),
                    dict(counterparty="X", tags=["a"],
                         amount_min_minor=1),               # no currency
                    dict(counterparty="X", tags=["a"],
                         direction="DBIT")):
            reply = call("add_rule", **bad)
            self.assertIn("Nothing was changed.", reply)
        self.assertEqual(self.n_rules(), 0)

    def test_duplicate_signature_refused_with_pointer(self):
        call("add_rule", counterparty="Albert Heijn", tags=["food"])
        reply = call("add_rule", counterparty="ALBERT  heijn",
                     tags=["different"])
        self.assertIn("#1", reply)
        self.assertIn("Nothing was changed.", reply)
        self.assertEqual(self.n_rules(), 1)

    def test_rulebook_cap(self):
        self.conn.execute("BEGIN")
        for i in range(rules.RULEBOOK_CAP):
            self.conn.execute(
                "INSERT INTO tag_rules(signature, tags) VALUES (?,'a')",
                ("sig-%d" % i,))
        self.conn.execute("COMMIT")
        reply = call("add_rule", counterparty="X", tags=["a"])
        self.assertIn("500", reply)
        self.assertIn("Nothing was changed.", reply)


class TestRemoveRule(Base):
    def test_remove(self):
        call("add_rule", counterparty="X", tags=["a"])
        reply = call("remove_rule", rule_id=1)
        self.assertIn("Removed", reply)
        self.assertEqual(self.n_rules(), 0)

    def test_unknown_and_type_refusals(self):
        self.assertIn("Nothing was changed.",
                      call("remove_rule", rule_id=99))
        self.assertIn("Nothing was changed.",
                      call("remove_rule", rule_id=True))
        self.assertIn("Nothing was changed.",
                      call("remove_rule", rule_id="1"))


class TestReplaceRule(Base):
    def test_tag_only_change_keeps_signature(self):
        call("add_rule", counterparty="X", tags=["a"])
        reply = call("replace_rule", rule_id=1, counterparty="X",
                     tags=["a", "b"], rationale="extended 2026-08-05")
        self.assertIn("#1", reply)
        row = self.conn.execute(
            "SELECT tags, rationale FROM tag_rules").fetchone()
        self.assertEqual(row["tags"], "a b")
        self.assertEqual(self.n_rules(), 1)

    def test_atomic_validation_failure_keeps_old_rule(self):
        call("add_rule", counterparty="X", tags=["a"])
        reply = call("replace_rule", rule_id=1, counterparty="X",
                     tags=["awaiting-operator"])
        self.assertIn("Nothing was changed.", reply)
        self.assertEqual(self.conn.execute(
            "SELECT tags FROM tag_rules").fetchone()[0], "a")

    def test_signature_collision_with_other_rule_refused(self):
        call("add_rule", counterparty="X", tags=["a"])
        call("add_rule", counterparty="Y", tags=["b"])
        reply = call("replace_rule", rule_id=2, counterparty="X",
                     tags=["b"])
        self.assertIn("#1", reply)
        self.assertIn("Nothing was changed.", reply)

    def test_unknown_rule_id(self):
        self.assertIn("Nothing was changed.",
                      call("replace_rule", rule_id=9, counterparty="X",
                           tags=["a"]))


class TestListRules(Base):
    def test_lists_all_with_clipped_rationale(self):
        call("add_rule", counterparty="Albert Heijn",
             tags=["food", "groceries"], rationale="R" * 300)
        call("add_rule", counterparty="Basic Fit", tags=["sport"],
             direction="debit")
        reply = call("list_rules")
        self.assertIn("#1", reply)
        self.assertIn("#2", reply)
        self.assertIn("food groceries", reply)
        self.assertNotIn("R" * 300, reply)       # clipped in list view

    def test_single_rule_full_rationale(self):
        call("add_rule", counterparty="X", tags=["a"],
             rationale="R" * 300)
        reply = call("list_rules", rule_id=1)
        self.assertIn("R" * 300, reply)

    def test_hostile_counterparty_is_fenced(self):
        # canon_text at WRITE time flattens newlines/whitespace and
        # casefolds — so the newline can never be stored. The fence at
        # RENDER time is belt-and-braces; assert the stored value renders
        # inside the fence markers and forges no second line.
        hostile = "EVIL\nCorp"
        call("add_rule", counterparty=hostile, tags=["a"])
        reply = call("list_rules")
        self.assertNotIn("EVIL\nCorp", reply)         # never stored raw
        self.assertIn(tools_read.UNTRUSTED_OPEN + "evil corp"
                      + tools_read.UNTRUSTED_CLOSE, reply)

    def test_empty_rulebook_says_so(self):
        self.assertIn("No rules", call("list_rules"))

    def test_hostile_rationale_and_oversized_anchor(self):
        # Rationale quoting fence delimiters must be neutralized by the
        # note renderer, in both the clipped and full views.
        hostile = ("quoting " + tools_read.UNTRUSTED_CLOSE +
                   "\nforged line" + tools_read.UNTRUSTED_OPEN)
        call("add_rule", counterparty="X", tags=["a"],
             rationale=hostile)
        for reply in (call("list_rules"), call("list_rules", rule_id=1)):
            self.assertIn("[fence-close removed]", reply)
            self.assertNotIn("\nforged line", reply)
        # An anchor over the 128-char bound refuses without echoing raw.
        reply = call("add_rule", counterparty="y" * 200, tags=["a"])
        self.assertIn("128", reply)
        self.assertNotIn("y" * 200, reply)


class TestApplyRules(Base):
    def _tx(self, counterparty="ACME BV", booking_date="2026-02-01",
            account="acc1"):
        self.conn.execute(
            "INSERT OR IGNORE INTO accounts(account_id, currency,"
            " included, first_seen, last_seen)"
            " VALUES (?,'EUR',1,'x','x')", (account,))
        cur = self.conn.execute(
            "INSERT INTO transactions(account_id, identity_key,"
            " occurrence, booking_date, amount_minor, currency,"
            " direction, counterparty, state, match_method)"
            " VALUES (?,?,0,?,100,'EUR','DBIT',?,'active','reference')",
            (account, "k%d" % self.conn.execute(
                "SELECT COUNT(*) FROM transactions").fetchone()[0],
             booking_date, counterparty))
        return cur.lastrowid

    def test_row_ids_scope_and_per_rule_report(self):
        r1 = self._tx()
        r2 = self._tx(counterparty="Other")
        call("add_rule", counterparty="ACME BV", tags=["office"])
        reply = call("apply_rules", row_ids=[r1, r2])
        self.assertIn("rule #1", reply)
        self.assertIn("changed: 1", reply)
        self.assertIn("#%d" % r1, reply)

    def test_date_scope(self):
        r_in = self._tx(booking_date="2026-02-01")
        r_out = self._tx(booking_date="2026-05-01")
        call("add_rule", counterparty="ACME BV", tags=["office"])
        call("apply_rules", date_from="2026-01-01",
             date_to="2026-03-01")
        tags_in = self.conn.execute(
            "SELECT COUNT(*) FROM transaction_tags WHERE row_id=?",
            (r_in,)).fetchone()[0]
        tags_out = self.conn.execute(
            "SELECT COUNT(*) FROM transaction_tags WHERE row_id=?",
            (r_out,)).fetchone()[0]
        self.assertEqual((tags_in, tags_out), (1, 0))

    def test_no_rules_or_empty_scope_say_so(self):
        self.assertIn("No rules", call("apply_rules"))
        call("add_rule", counterparty="X", tags=["a"])
        self.assertIn("0 row(s)", call("apply_rules"))

    def test_overcap_rows_reported(self):
        rid = self._tx()
        self.conn.execute("BEGIN")
        for i in range(32):
            self.conn.execute(
                "INSERT INTO transaction_tags(row_id, tag, added_at)"
                " VALUES (?,?,'t')", (rid, "t%d" % i))
        self.conn.execute("COMMIT")
        call("add_rule", counterparty="ACME BV", tags=["office"])
        reply = call("apply_rules", row_ids=[rid])
        self.assertIn("32-tag cap", reply)


if __name__ == "__main__":
    unittest.main()


class TestRowScopedApplyIdReporting(Base):
    """Batch-close verification reads
    changed ∪ already ids, so a row_ids-scoped call must list BOTH in
    full — pre-fix the reply clipped changed at 20 and only counted
    already, hiding the evidence for batches of 21-100 and reading a
    hand-tagged row's success as failure."""

    def _tx(self, counterparty="ACME BV"):
        self.conn.execute(
            "INSERT OR IGNORE INTO accounts(account_id, currency,"
            " included, first_seen, last_seen)"
            " VALUES ('acc1','EUR',1,'x','x')")
        cur = self.conn.execute(
            "INSERT INTO transactions(account_id, identity_key,"
            " occurrence, booking_date, amount_minor, currency,"
            " direction, counterparty, state, match_method)"
            " VALUES ('acc1',?,0,'2026-02-01',100,'EUR','DBIT',?,"
            "'active','reference')",
            ("k%d" % self.conn.execute(
                "SELECT COUNT(*) FROM transactions").fetchone()[0],
             counterparty))
        return cur.lastrowid

    def test_row_scoped_apply_lists_all_changed_ids_past_twenty(self):
        ids = [self._tx() for _ in range(25)]
        call("add_rule", counterparty="ACME BV", tags=["food"])
        reply = call("apply_rules", row_ids=ids)
        for rid in ids:
            self.assertIn("#%d" % rid, reply)
        self.assertNotIn("more)", reply)

    def test_row_scoped_apply_lists_already_ids(self):
        rid = self._tx()
        self.conn.execute(
            "INSERT INTO transaction_tags(row_id, tag, added_at)"
            " VALUES (?,'food','t')", (rid,))
        call("add_rule", counterparty="ACME BV", tags=["food"])
        reply = call("apply_rules", row_ids=[rid])
        self.assertIn("already: 1 — #%d" % rid, reply)

    def test_broad_scope_keeps_the_clip(self):
        for _ in range(25):
            self._tx()
        call("add_rule", counterparty="ACME BV", tags=["food"])
        reply = call("apply_rules")   # whole-ledger scope
        self.assertIn("more)", reply)
