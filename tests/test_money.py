# tests/test_money.py
import unittest, sys, pathlib
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

    def test_round_trip_format(self):
        self.assertEqual(money.format_minor(1234, "EUR"), "12.34")
        self.assertEqual(money.format_minor(-5, "EUR"), "-0.05")
        self.assertEqual(money.format_minor(1234, "JPY"), "1234")


if __name__ == "__main__":
    unittest.main()
