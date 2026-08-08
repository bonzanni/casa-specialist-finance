# tests/test_rules.py
"""Rule core: canonicalization, tokenizer, validation, signature."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))

import rules  # noqa: E402
import tools_annotate  # noqa: E402


def valid(**over):
    args = {"counterparty": "Albert Heijn", "tags": ["food", "groceries"]}
    args.update(over)
    return args


class TestCanon(unittest.TestCase):
    def test_canon_nfc_ws_case(self):
        self.assertEqual(rules.canon_text("  Café   BAR \n"),
                         "café bar")
        self.assertEqual(rules.canon_text(None), "")
        # Non-strings canonicalize to "" — coercion let a malformed
        # numeric provider value equal a rule anchor.
        self.assertEqual(rules.canon_text(123), "")

    def test_tokens_split_non_alnum(self):
        self.assertEqual(rules.tokens("SEPA: Basic-Fit B.V./Hoofddorp 42"),
                         ["sepa", "basic", "fit", "b", "v", "hoofddorp",
                          "42"])
        self.assertEqual(rules.tokens(None), [])
        # Unicode punctuation splits too — isalnum boundaries, not ASCII.
        self.assertEqual(rules.tokens("café—bar€9"),
                         ["café", "bar", "9"])


class TestValidate(unittest.TestCase):
    def test_minimal_counterparty_rule(self):
        fields, refusal = rules.validate_rule(valid())
        self.assertIsNone(refusal)
        self.assertEqual(fields["counterparty_canon"], "albert heijn")
        self.assertEqual(fields["tags"], "food groceries")
        self.assertIsNone(fields["direction"])

    def test_anchor_required(self):
        fields, refusal = rules.validate_rule(
            {"direction": "debit", "tags": ["snacks"]})
        self.assertIsNone(fields)
        self.assertIn("counterparty", refusal)
        self.assertIn("Nothing was changed.", refusal)

    def test_anchor_gap_reported_beside_other_problems(self):
        # A type-invalid anchor must NOT suppress the anchor problem — one
        # refusal names every failure.
        _, refusal = rules.validate_rule({"counterparty": 1,
                                          "tags": ["ok"]})
        self.assertIn("string", refusal)
        self.assertIn("anchor", refusal)

    def test_direction_maps_to_storage_vocab(self):
        fields, _ = rules.validate_rule(valid(direction="debit"))
        self.assertEqual(fields["direction"], "DBIT")
        fields, _ = rules.validate_rule(valid(direction="credit"))
        self.assertEqual(fields["direction"], "CRDT")
        _, refusal = rules.validate_rule(valid(direction="DBIT"))
        self.assertIn("debit", refusal)
        _, refusal = rules.validate_rule(valid(direction=["debit"]))
        self.assertIn("debit", refusal)

    def test_amount_requires_currency(self):
        _, refusal = rules.validate_rule(valid(amount_min_minor=100))
        self.assertIn("currency", refusal)
        fields, refusal = rules.validate_rule(
            valid(amount_min_minor=100, amount_max_minor=500,
                  currency="eur"))
        self.assertIsNone(refusal)
        self.assertEqual(fields["currency"], "EUR")

    def test_amount_band_sane(self):
        _, r = rules.validate_rule(valid(amount_min_minor=-1,
                                         currency="EUR"))
        self.assertIn("Nothing was changed.", r)
        _, r = rules.validate_rule(valid(amount_min_minor=500,
                                         amount_max_minor=100,
                                         currency="EUR"))
        self.assertIn("min", r)
        _, r = rules.validate_rule(valid(amount_min_minor=True,
                                         currency="EUR"))
        self.assertIn("integer", r)

    def test_dom_band(self):
        fields, r = rules.validate_rule(valid(dom_min=1, dom_max=3))
        self.assertIsNone(r)
        _, r = rules.validate_rule(valid(dom_min=3, dom_max=1))
        self.assertIn("dom", r)
        _, r = rules.validate_rule(valid(dom_min=0, dom_max=3))
        self.assertIn("dom", r)
        _, r = rules.validate_rule(valid(dom_min=1, dom_max=32))
        self.assertIn("dom", r)

    def test_weekdays_validated_deduped_canonical(self):
        fields, r = rules.validate_rule(valid(weekdays=["Tue", "mon",
                                                        "tue"]))
        self.assertIsNone(r)
        self.assertEqual(fields["weekdays"], "mon,tue")
        _, r = rules.validate_rule(valid(weekdays=["noday"]))
        self.assertIn("weekday", r)
        _, r = rules.validate_rule(valid(weekdays=[]))
        self.assertIn("weekday", r)

    def test_remittance_word_is_one_token(self):
        fields, r = rules.validate_rule(
            {"remittance_word": " Vattenfall ", "tags": ["home", "energy"]})
        self.assertIsNone(r)
        self.assertEqual(fields["remittance_token"], "vattenfall")
        _, r = rules.validate_rule(
            {"remittance_word": "two words", "tags": ["a"]})
        self.assertIn("single", r)
        _, r = rules.validate_rule({"remittance_word": "x", "tags": ["a"]})
        self.assertIn("2", r)   # min length 2

    def test_counterparty_bounded(self):
        _, r = rules.validate_rule(valid(counterparty="x" * 129))
        self.assertIn("128", r)

    def test_tags_reuse_row_tag_rules_and_refuse_workflow_tags(self):
        _, r = rules.validate_rule(valid(tags=["Bad Tag!"]))
        self.assertIn("Nothing was changed.", r)
        _, r = rules.validate_rule(valid(tags=[]))
        self.assertIn("Nothing was changed.", r)
        fields, r = rules.validate_rule(valid(tags=["food"]))
        self.assertIsNone(r)
        _, r = rules.validate_rule(valid(tags=["awaiting-operator"]))
        self.assertIn("workflow", r)
        _, r = rules.validate_rule(valid(tags=["unclassifiable"]))
        self.assertIn("workflow", r)

    def test_rationale_bounded(self):
        fields, r = rules.validate_rule(valid(rationale="why " * 10))
        self.assertIsNone(r)
        _, r = rules.validate_rule(valid(rationale="x" * 1001))
        self.assertIn("1000", r)
        _, r = rules.validate_rule(valid(rationale=7))
        self.assertIn("string", r)

    def test_tag_regex_parity_with_tools_annotate(self):
        self.assertEqual(rules.TAG_RE.pattern,
                         tools_annotate.TAG_RE.pattern)


class TestSignature(unittest.TestCase):
    def test_signature_stable_and_null_explicit(self):
        f1, _ = rules.validate_rule(valid())
        f2, _ = rules.validate_rule(
            {"counterparty": "ALBERT   HEIJN", "tags": ["other"]})
        self.assertEqual(rules.signature(f1), rules.signature(f2))
        f3, _ = rules.validate_rule(valid(direction="debit"))
        self.assertNotEqual(rules.signature(f1), rules.signature(f3))
        self.assertIn("null", rules.signature(f1))  # explicit NULLs (JSON)

    def test_signature_injective_against_hostile_values(self):
        fa, _ = rules.validate_rule({"counterparty": 'a","b',
                                     "tags": ["t"]})
        fb, _ = rules.validate_rule({"counterparty": "a",
                                     "remittance_word": "bb",
                                     "tags": ["t"]})
        self.assertNotEqual(rules.signature(fa), rules.signature(fb))

    def test_signature_excludes_tags_and_rationale(self):
        f1, _ = rules.validate_rule(valid(tags=["a"]))
        f2, _ = rules.validate_rule(valid(tags=["b"],
                                          rationale="different"))
        self.assertEqual(rules.signature(f1), rules.signature(f2))


import sqlite3  # noqa: E402
import tempfile  # noqa: E402

import store  # noqa: E402


class LedgerBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.conn = store.open_db(
            pathlib.Path(self.dir.name) / "f.sqlite")
        self.conn.execute(
            "INSERT INTO accounts(account_id, currency, included,"
            " first_seen, last_seen) VALUES ('acc1','EUR',1,'x','x')")

    def tearDown(self):
        self.dir.cleanup()

    def tx(self, counterparty="ACME BV", remittance="invoice 7",
           direction="DBIT", currency="EUR", amount=1000,
           booking_date="2026-02-03", state="active"):
        cur = self.conn.execute(
            "INSERT INTO transactions(account_id, identity_key,"
            " occurrence, booking_date, amount_minor, currency,"
            " direction, status, counterparty, remittance, state,"
            " match_method) VALUES ('acc1',?,0,?,?,?,?,'BOOK',?,?,?,"
            "'reference')",
            ("ik-%d" % self.conn.execute(
                "SELECT COUNT(*) FROM transactions").fetchone()[0],
             booking_date, amount, currency, direction, counterparty,
             remittance, state))
        return cur.lastrowid

    def rule(self, **over):
        fields, refusal = rules.validate_rule(
            dict({"counterparty": "ACME BV", "tags": ["office"]}, **over))
        assert refusal is None, refusal
        cur = self.conn.execute(
            "INSERT INTO tag_rules(signature, counterparty_canon,"
            " remittance_token, direction, currency, amount_min_minor,"
            " amount_max_minor, dom_min, dom_max, weekdays, tags,"
            " rationale, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,"
            "'2026-08-05')",
            (rules.signature(fields), fields["counterparty_canon"],
             fields["remittance_token"], fields["direction"],
             fields["currency"], fields["amount_min_minor"],
             fields["amount_max_minor"], fields["dom_min"],
             fields["dom_max"], fields["weekdays"], fields["tags"],
             fields["rationale"]))
        return cur.lastrowid

    def tags_of(self, rid):
        return sorted(r[0] for r in self.conn.execute(
            "SELECT tag FROM transaction_tags WHERE row_id=?", (rid,)))


class TestMatching(LedgerBase):
    def test_counterparty_canon_match(self):
        rid = self.tx(counterparty="  ALBERT   heijn ")
        self.rule(counterparty="Albert Heijn", tags=["food", "groceries"])
        out = rules.apply_to_rows(self.conn, [rid], "now")
        self.assertEqual(self.tags_of(rid), ["food", "groceries"])
        self.assertEqual(out["tagged_rows"], [rid])

    def test_null_counterparty_never_matches(self):
        rid = self.tx(counterparty=None)
        self.rule(counterparty="Albert Heijn", tags=["food"])
        rules.apply_to_rows(self.conn, [rid], "now")
        self.assertEqual(self.tags_of(rid), [])

    def test_remittance_token_word_not_substring(self):
        r1 = self.tx(remittance="SEPA Vattenfall NV termijn")
        r2 = self.tx(remittance="ALLVATTENFALLXX")
        self.rule(counterparty=None, remittance_word="vattenfall",
                  tags=["home", "energy"])
        rules.apply_to_rows(self.conn, [r1, r2], "now")
        self.assertEqual(self.tags_of(r1), ["energy", "home"])
        self.assertEqual(self.tags_of(r2), [])

    def test_direction_amount_currency_dom_weekday(self):
        # 2026-02-03 is a Tuesday
        rid = self.tx(direction="DBIT", amount=999,
                      booking_date="2026-02-03")
        self.rule(direction="debit", currency="EUR",
                  amount_min_minor=500, amount_max_minor=1500,
                  dom_min=1, dom_max=5, weekdays=["tue"],
                  tags=["subscription", "recurring"])
        rules.apply_to_rows(self.conn, [rid], "now")
        self.assertEqual(self.tags_of(rid), ["office"] if False else
                         ["recurring", "subscription"])

    def test_wrong_currency_amount_band_never_matches(self):
        rid = self.tx(currency="SEK", amount=1000)
        self.rule(currency="EUR", amount_min_minor=500,
                  amount_max_minor=1500, tags=["office"])
        rules.apply_to_rows(self.conn, [rid], "now")
        self.assertEqual(self.tags_of(rid), [])

    def test_malformed_date_fails_predicate_not_ingest(self):
        rid = self.tx(booking_date="03/02/2026")
        self.rule(dom_min=1, dom_max=31, tags=["office"])
        out = rules.apply_to_rows(self.conn, [rid], "now")  # no raise
        self.assertEqual(self.tags_of(rid), [])
        self.assertEqual(out["tagged_rows"], [])

    def test_superseded_never_fires_vanished_does(self):
        rs = self.tx(state="superseded")
        rv = self.tx(state="vanished")
        self.rule(tags=["office"])
        rules.apply_to_rows(self.conn, [rs, rv], "now")
        self.assertEqual(self.tags_of(rs), [])
        self.assertEqual(self.tags_of(rv), ["office"])


class TestApplication(LedgerBase):
    def test_additive_never_removes_idempotent(self):
        rid = self.tx()
        self.conn.execute("INSERT INTO transaction_tags(row_id, tag,"
                          " added_at) VALUES (?,'handmade','t')", (rid,))
        self.rule(tags=["office"])
        rules.apply_to_rows(self.conn, [rid], "now")
        rules.apply_to_rows(self.conn, [rid], "now")   # idempotent
        self.assertEqual(self.tags_of(rid), ["handmade", "office"])

    def test_per_rule_report_changed_vs_already(self):
        r1, r2 = self.tx(), self.tx()
        self.conn.execute("INSERT INTO transaction_tags(row_id, tag,"
                          " added_at) VALUES (?,'office','t')", (r1,))
        rule_id = self.rule(tags=["office"])
        out = rules.apply_to_rows(self.conn, [r1, r2], "now")
        rep = out["per_rule"][rule_id]
        self.assertEqual(rep["matched"], sorted([r1, r2]))
        self.assertEqual(rep["changed"], [r2])
        self.assertEqual(rep["already"], [r1])

    def test_overcap_union_skips_row_entirely_and_attributes_per_rule(self):
        rid = self.tx()
        for i in range(31):
            self.conn.execute(
                "INSERT INTO transaction_tags(row_id, tag, added_at)"
                " VALUES (?,?,'t')", (rid, "t%d" % i))
        r1 = self.rule(tags=["one", "two"])     # union would be 33
        out = rules.apply_to_rows(self.conn, [rid], "now")
        self.assertEqual(out["skipped_overcap"], [rid])
        rep = out["per_rule"][r1]
        self.assertEqual(rep["matched"], [rid])
        self.assertEqual(rep["skipped_overcap"], [rid])
        self.assertEqual(rep["changed"], [])
        self.assertEqual(len(self.tags_of(rid)), 31)   # untouched

    def test_changed_vs_already_is_order_independent(self):
        rid = self.tx()
        ra = self.rule(tags=["shared", "a"])
        rb = self.rule(tags=["shared", "b"],
                       remittance_word="invoice")
        out = rules.apply_to_rows(self.conn, [rid], "now")
        self.assertEqual(out["per_rule"][ra]["changed"], [rid])
        self.assertEqual(out["per_rule"][rb]["changed"], [rid])
        self.assertEqual(self.tags_of(rid), ["a", "b", "shared"])

    def test_amount_band_edges_and_mixed_exponent(self):
        edge_lo = self.tx(amount=500)
        edge_hi = self.tx(amount=1500)
        self.rule(currency="EUR", amount_min_minor=500,
                  amount_max_minor=1500, tags=["office"])
        rules.apply_to_rows(self.conn, [edge_lo, edge_hi], "now")
        self.assertEqual(self.tags_of(edge_lo), ["office"])
        self.assertEqual(self.tags_of(edge_hi), ["office"])
        jpy = self.tx(currency="JPY", amount=1000)
        self.rule(counterparty="Tokyo Shop", currency="JPY",
                  amount_min_minor=500, amount_max_minor=1500,
                  tags=["travel"])
        rules.apply_to_rows(self.conn, [jpy], "now")
        self.assertEqual(self.tags_of(jpy), [])   # counterparty differs

    def test_unknown_state_and_negative_amount_fail_closed(self):
        weird = self.tx(state="limbo")
        self.rule(tags=["office"])
        rules.apply_to_rows(self.conn, [weird], "now")
        self.assertEqual(self.tags_of(weird), [])
        # Distinct counterparty so ONLY the amount-band rule could match:
        # the malformed negative magnitude must fail that predicate closed.
        neg = self.tx(counterparty="Malformed Corp")
        self.conn.execute("UPDATE transactions SET amount_minor=-5"
                          " WHERE row_id=?", (neg,))
        self.rule(counterparty="Malformed Corp", currency="EUR",
                  amount_max_minor=1000, tags=["cheap"])
        rules.apply_to_rows(self.conn, [neg], "now")
        self.assertEqual(self.tags_of(neg), [])


    def test_malformed_row_text_never_matches(self):
        # A numeric or BLOB value that somehow reached the ledger must fail
        # every text predicate closed, not str()-match.
        rid = self.tx()
        self.conn.execute(
            "UPDATE transactions SET counterparty=CAST('ACME BV' AS BLOB)"
            " WHERE row_id=?", (rid,))
        self.rule(tags=["office"])
        rules.apply_to_rows(self.conn, [rid], "now")
        self.assertEqual(self.tags_of(rid), [])


class TestQueueTotals(LedgerBase):
    def test_workable_parked_terminal_classified(self):
        w = self.tx()                                   # workable
        p = self.tx()
        self.conn.execute("INSERT INTO transaction_tags VALUES"
                          " (?, 'awaiting-operator', 't')", (p,))
        t = self.tx()
        self.conn.execute("INSERT INTO transaction_tags VALUES"
                          " (?, 'unclassifiable', 't')", (t,))
        cl = self.tx()
        self.conn.execute("INSERT INTO transaction_tags VALUES"
                          " (?, 'food', 't')", (cl,))
        self.tx(state="superseded")                     # ignored
        workable, parked = rules.queue_totals(self.conn)
        self.assertEqual((workable, parked), (1, 1))

    def test_classification_state_precedence(self):
        self.assertEqual(rules.classification_state([]), "workable")
        self.assertEqual(rules.classification_state(
            ["awaiting-operator"]), "parked")
        self.assertEqual(rules.classification_state(
            ["unclassifiable", "awaiting-operator"]), "terminal")
        self.assertEqual(rules.classification_state(
            ["food", "awaiting-operator"]), "parked")
        self.assertEqual(rules.classification_state(["food"]),
                         "classified")


if __name__ == "__main__":
    unittest.main()
