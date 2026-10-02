# tests/test_money.py
import sqlite3, unittest, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"))
import money


class TestMoney(unittest.TestCase):
    def test_two_decimal_default(self):
        self.assertEqual(money.to_minor("12.34", "EUR"), 1234)
        self.assertEqual(money.to_minor("0.05", "EUR"), 5)
        self.assertEqual(money.to_minor("1", "EUR"), 100)

    def test_zero_decimal_currency(self):
        self.assertEqual(money.to_minor("1234", "JPY"), 1234)

    def test_three_decimal_currency(self):
        self.assertEqual(money.to_minor("1.234", "BHD"), 1234)

    def test_excess_precision_is_an_error_not_a_round(self):
        with self.assertRaises(money.MoneyError):
            money.to_minor("12.345", "EUR")

    def test_no_binary_float_drift(self):
        # 0.1 + 0.2 style drift must be impossible
        total = sum(money.to_minor(x, "EUR") for x in ("0.10", "0.20"))
        self.assertEqual(total, 30)

    def test_rejects_junk(self):
        for bad in ("", "abc", "1,23", "nan", "Infinity", "1e3"):
            with self.assertRaises(money.MoneyError):
                money.to_minor(bad, "EUR")

    def test_a_long_fraction_is_refused_not_rounded(self):
        # Issue #92: a 28-digit Decimal context rounded this to 948 before the
        # precision check ran, so it was stored as 9.48.
        with self.assertRaises(money.MoneyError):
            money.to_minor("9.479999999999999999999999999999", "EUR")
        with self.assertRaises(money.MoneyError):
            money.to_minor("9.48" + "0" * 40 + "1", "EUR")

    def test_trailing_zeros_of_any_length_are_still_exact(self):
        self.assertEqual(money.to_minor("9.48" + "0" * 400, "EUR"), 948)
        self.assertEqual(money.to_minor("0" * 400 + "9.48", "EUR"), 948)
        self.assertEqual(money.to_minor("1500.000", "JPY"), 1500)

    def test_a_huge_amount_is_a_money_error_not_an_arithmetic_error(self):
        # Issue #92: Decimal scaling raised decimal.Overflow (an
        # ArithmeticError no caller catches); `int()` would raise its own
        # ValueError past 4,300 digits. Both are MoneyError now.
        for bad in ("1" + "0" * 999999, "9" * 5000, "-" + "9" * 19):
            with self.assertRaises(money.MoneyError):
                money.to_minor(bad, "EUR")

    def test_the_range_bound_is_exact(self):
        top = money.MAX_MINOR - 1
        self.assertEqual(money.to_minor(money.format_minor(top, "EUR"), "EUR"),
                         top)
        self.assertEqual(money.to_minor("-" + money.format_minor(top, "EUR"),
                                        "EUR"), -top)
        for amount in (money.format_minor(money.MAX_MINOR, "EUR"),
                       str(money.MAX_MINOR), "-" + str(money.MAX_MINOR)):
            with self.assertRaises(money.MoneyError):
                money.to_minor(amount, "JPY" if "." not in amount else "EUR")

    def test_the_largest_accepted_amount_stores_and_sums_in_sqlite(self):
        # What the bound is FOR: SQLite's INTEGER is 64-bit, and an amount
        # past it fails the insert, or a SUM, with an OverflowError.
        top = money.to_minor(money.format_minor(money.MAX_MINOR - 1, "EUR"),
                             "EUR")
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE t(a INTEGER)")
        db.executemany("INSERT INTO t VALUES (?)", [(top,), (-top,)] * 1000)
        db.executemany("INSERT INTO t VALUES (?)", [(top,)] * 1000)
        self.assertEqual(db.execute("SELECT SUM(a) FROM t").fetchone()[0],
                         1000 * top)

    def test_every_form_decimal_accepted_is_still_accepted(self):
        for amount, want in (("+1", 100), ("-1", -100), ("1.", 100),
                             (".5", 50), ("-.5", -50), ("-0", 0),
                             ("0.00", 0), ("007.10", 710)):
            self.assertEqual(money.to_minor(amount, "EUR"), want, amount)

    def test_every_form_decimal_refused_is_still_refused(self):
        for bad in (".", "+", "-", "+-1", "--1", "1.2.3", "1-2", "1+",
                    "..5", "-", "+."):
            with self.assertRaises(money.MoneyError):
                money.to_minor(bad, "EUR")

    def test_round_trip_format(self):
        self.assertEqual(money.format_minor(1234, "EUR"), "12.34")
        self.assertEqual(money.format_minor(-5, "EUR"), "-0.05")
        self.assertEqual(money.format_minor(1234, "JPY"), "1234")


if __name__ == "__main__":
    unittest.main()
