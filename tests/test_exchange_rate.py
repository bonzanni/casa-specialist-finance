"""Issue #91: a foreign-currency payment's exchange rate leaves the ledger.

The provider's `exchange_rate` block is stored inside `raw_json`, which no
read surface ships. `get_transaction` and `export_history` now carry four
validated fields derived from it — the rate, its unit currency, the instructed
amount and its currency — and nothing else of the payload. A consumer pairs a
payment with a foreign-currency invoice on these values, so a wrong one is a
silent mispairing: the tests assert the exact values, end to end from a
provider-shaped payload through the real ingest and refresh path.
"""
import csv
import io
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))

import ingest  # noqa: E402
import tools_refresh  # noqa: E402
from _toolbase import call  # noqa: E402
from test_tools_refresh import Base  # noqa: E402

#: The block as the issue quotes it from a live card payment.
BLOCK = {"exchange_rate": "1.1608109839149589",
         "instructed_amount": {"amount": "9.48", "currency": "EUR"},
         "unit_currency": "EUR", "rate_type": None,
         "contract_identification": None}

FIELDS = {"exchange_rate": "1.1608109839149589",
          "exchange_unit_currency": "EUR",
          "instructed_amount": "9.48", "instructed_currency": "EUR"}

NONE = dict.fromkeys(ingest.EXCHANGE_RATE_FIELDS)


def payload(block=None, ref="R1", amount="9.48"):
    raw = {"entry_reference": ref, "booking_date": "2026-08-02",
           "value_date": "2026-08-02", "status": "BOOK",
           "credit_debit_indicator": "DBIT",
           "transaction_amount": {"currency": "EUR", "amount": amount},
           "creditor": {"name": "ACME"}, "remittance_information": ["x"]}
    if block is not None:
        raw["exchange_rate"] = block
    return raw


def stored(block):
    """The block as the ledger stores it: through the real normaliser."""
    return ingest.normalise(payload(block), "acc1")["raw_json"]


class TestExtraction(unittest.TestCase):
    def test_the_live_block_yields_its_four_fields(self):
        self.assertEqual(ingest.exchange_rate(stored(BLOCK)), FIELDS)

    def test_no_block_yields_no_field(self):
        self.assertEqual(ingest.exchange_rate(stored(None)), NONE)

    def test_an_unreadable_payload_yields_no_field_and_does_not_raise(self):
        for raw in (None, "", "{", "[]", "3", '"x"', b'{}',
                    json.dumps({"exchange_rate": "1.2"}),
                    json.dumps({"exchange_rate": None}),
                    json.dumps({"exchange_rate": [BLOCK]})):
            self.assertEqual(ingest.exchange_rate(raw), NONE, raw)

    def test_a_bad_rate_drops_the_rate_pair_and_keeps_the_instructed_pair(self):
        for rate in (1.16, "1e3", "-1.2", "+1.2", "0", "0.000", "1,16",
                     " 1.2", "1.2\n", "1.2 ", ".5", "5.", "NaN", "Infinity",
                     "1" * 16, "1." + "1" * 21, "\u0661.5", "", None,
                     True):
            block = dict(BLOCK, exchange_rate=rate)
            self.assertEqual(ingest.exchange_rate(stored(block)),
                             dict(FIELDS, exchange_rate=None,
                                  exchange_unit_currency=None), repr(rate))

    def test_a_rate_without_a_valid_unit_currency_is_not_exposed(self):
        # A rate with no unit does not say which way it converts.
        for unit in (None, "eur", "EU", "EURO", "E1R", "EUR\n", 978):
            block = dict(BLOCK, unit_currency=unit)
            out = ingest.exchange_rate(stored(block))
            self.assertIsNone(out["exchange_rate"], repr(unit))
            self.assertIsNone(out["exchange_unit_currency"], repr(unit))
            self.assertEqual(out["instructed_amount"], "9.48")

    def test_a_bad_instructed_amount_drops_that_pair_and_keeps_the_rate(self):
        for inst in (None, "9.48", {"amount": "9.48"}, {"currency": "EUR"},
                     {"amount": 9.48, "currency": "EUR"},
                     {"amount": "-9.48", "currency": "EUR"},
                     {"amount": "+9.48", "currency": "EUR"},
                     {"amount": "1e3", "currency": "EUR"},
                     {"amount": "9,48", "currency": "EUR"},
                     {"amount": "9.48", "currency": "eur"},
                     {"amount": "9.48", "currency": "EURO"},
                     {"amount": "\u0669.48", "currency": "EUR"},
                     {"amount": "1" * 16, "currency": "EUR"},
                     # Decimal's 28-digit context rounds this to "9.48".
                     {"amount": "9." + "4" + "7" + "9" * 28,
                      "currency": "EUR"},
                     # Overflows Decimal scaling, which raised out of a read.
                     {"amount": "1" + "0" * 999999, "currency": "EUR"}):
            block = dict(BLOCK, instructed_amount=inst)
            self.assertEqual(ingest.exchange_rate(stored(block)),
                             dict(FIELDS, instructed_amount=None,
                                  instructed_currency=None), repr(inst))

    def test_the_instructed_amount_is_carried_verbatim(self):
        # The provider's own string: no rounding, no re-rendering to a
        # currency precision this plugin may not know (CLF has four).
        for amount, currency in (("9.48", "EUR"), ("9.5", "EUR"),
                                 ("11.000", "USD"), ("1500", "JPY"),
                                 ("9.4812", "CLF"), ("0", "EUR"),
                                 ("9" * 15 + "." + "9" * 20, "EUR")):
            block = dict(BLOCK, instructed_amount={"amount": amount,
                                                   "currency": currency})
            out = ingest.exchange_rate(stored(block))
            self.assertEqual((out["instructed_amount"],
                              out["instructed_currency"]),
                             (amount, currency), amount)

    def test_the_rate_is_carried_verbatim(self):
        # A decimal string: no float round trip, no trailing-zero trim.
        for rate in ("1.1608109839149589", "0.86147", "1.10", "151",
                     "00001.5", "9" * 15 + "." + "9" * 20):
            block = dict(BLOCK, exchange_rate=rate)
            self.assertEqual(
                ingest.exchange_rate(stored(block))["exchange_rate"], rate)


class ExchangeRateBase(Base):
    """Rows reach the ledger through the real refresh path, so `raw_json` is
    exactly what ingest wrote, not a hand-made column value."""

    def setUp(self):
        super().setUp()
        self.account()

    def sync(self, *raws):
        self.ais.transactions = lambda uid, d, k=None: (
            [dict(r) for r in raws], None)
        tools_refresh._refresh_resource(self.conn, "acc1", "transactions",
                                        automatic=False)
        return {r[1]: r[0] for r in self.raw.execute(
            "SELECT row_id, provider_ref FROM transactions")}

    def export(self, fmt):
        out = call("export_history", format=fmt)
        path = pathlib.Path(out.strip().splitlines()[-1].split(": ", 1)[1])
        return path.read_text("utf-8")


class TestGetTransaction(ExchangeRateBase):
    def test_a_foreign_currency_payment_shows_its_rate_and_instructed_amount(
            self):
        rid = self.sync(payload(BLOCK))["R1"]
        out = call("get_transaction", row_id=rid)
        self.assertIn("\n  exchange rate 1.1608109839149589, unit currency "
                      "EUR\n", out)
        self.assertIn("\n  instructed amount 9.48 EUR\n", out)

    def test_a_row_without_the_block_shows_neither_line(self):
        rid = self.sync(payload())["R1"]
        out = call("get_transaction", row_id=rid)
        self.assertNotIn("exchange rate", out)
        self.assertNotIn("instructed amount", out)

    def test_an_oversized_instructed_amount_drops_the_pair_not_the_read(
            self):
        # A million-digit amount overflows Decimal scaling; neither
        # get_transaction nor the whole-ledger export may fail on it, and the
        # rate pair still shows.
        block = dict(BLOCK, instructed_amount={"amount": "1" + "0" * 999999,
                                               "currency": "EUR"})
        rid = self.sync(payload(block))["R1"]
        out = call("get_transaction", row_id=rid)
        self.assertIn("exchange rate 1.1608109839149589", out)
        self.assertNotIn("instructed amount", out)
        rows = list(csv.DictReader(io.StringIO(self.export("csv"))))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["instructed_amount"], "")
        self.assertEqual(rows[0]["exchange_rate"], "1.1608109839149589")

    def test_nothing_else_of_the_block_is_shown(self):
        block = dict(BLOCK, rate_type="SPOT",
                     contract_identification="CONTRACT-MARKER")
        rid = self.sync(payload(block))["R1"]
        out = call("get_transaction", row_id=rid)
        self.assertNotIn("CONTRACT-MARKER", out)
        self.assertNotIn("SPOT", out)


class TestExport(ExchangeRateBase):
    def setUp(self):
        super().setUp()
        self.rids = self.sync(
            payload(dict(BLOCK, contract_identification="CONTRACT-MARKER"),
                    ref="R1"),
            payload(None, ref="R2", amount="3.00"),
            payload(dict(BLOCK, exchange_rate="1e3"), ref="R3",
                    amount="4.00"))

    def test_the_four_fields_close_every_csv_row(self):
        rows = list(csv.DictReader(io.StringIO(self.export("csv"))))
        self.assertEqual(len(rows), 3)
        header = list(rows[0])
        self.assertEqual(header[-4:], list(ingest.EXCHANGE_RATE_FIELDS))
        by_ref = {r["provider_ref"]: r for r in rows}
        self.assertEqual({k: by_ref["R1"][k] for k in FIELDS}, FIELDS)
        self.assertEqual({k: by_ref["R2"][k] for k in FIELDS},
                         dict.fromkeys(FIELDS, ""))
        self.assertEqual({k: by_ref["R3"][k] for k in FIELDS},
                         dict(FIELDS, exchange_rate="",
                              exchange_unit_currency=""))

    def test_jsonl_carries_strings_and_nulls(self):
        rows = [json.loads(line) for line in
                self.export("jsonl").splitlines()]
        self.assertEqual(len(rows), 3)
        by_ref = {r["provider_ref"]: r for r in rows}
        self.assertEqual({k: by_ref["R1"][k] for k in FIELDS}, FIELDS)
        self.assertEqual({k: by_ref["R2"][k] for k in FIELDS}, NONE)
        self.assertEqual(list(by_ref["R1"])[-4:],
                         list(ingest.EXCHANGE_RATE_FIELDS))

    def test_no_other_part_of_the_payload_is_exported(self):
        for fmt in ("csv", "jsonl"):
            data = self.export(fmt)
            self.assertNotIn("CONTRACT-MARKER", data, fmt)
            self.assertNotIn("raw_json", data, fmt)
            self.assertNotIn("_raw", data, fmt)
            self.assertNotIn("remittance_information", data, fmt)

    def test_an_appended_field_that_clashes_with_a_ledger_column_refuses(self):
        self.raw.execute("ALTER TABLE transactions ADD COLUMN exchange_rate TEXT")
        with self.assertRaises(RuntimeError):
            call("export_history", format="csv")


if __name__ == "__main__":
    unittest.main()
