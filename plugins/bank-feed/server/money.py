"""Money as integer minor units. Never binary float."""
from __future__ import annotations
import re

class MoneyError(ValueError):
    """Malformed amount, unknown currency, or precision beyond the currency."""

# ISO 4217 exponents that are not 2. Everything absent defaults to 2.
_EXPONENTS = {
    "JPY": 0, "KRW": 0, "CLP": 0, "ISK": 0, "VND": 0, "XAF": 0, "XOF": 0,
    "XPF": 0, "PYG": 0, "RWF": 0, "UGX": 0, "VUV": 0, "DJF": 0, "GNF": 0,
    "KMF": 0, "MGA": 0, "BIF": 0,
    "BHD": 3, "IQD": 3, "JOD": 3, "KWD": 3, "LYD": 3, "OMR": 3, "TND": 3,
}
_ALLOWED = set("0123456789+-.")


def exponent(currency: str) -> int:
    if not isinstance(currency, str) or len(currency) != 3 or not currency.isalpha():
        raise MoneyError(f"not an ISO 4217 code: {currency!r}")
    return _EXPONENTS.get(currency.upper(), 2)


# The grammar `Decimal` accepted over `_ALLOWED`: an optional sign, then
# digits with at most one dot and at least one digit ("1", "1.", ".5", "1.50").
_AMOUNT = re.compile(r"([+-]?)([0-9]*)(?:\.([0-9]*))?\Z")

#: Every amount's magnitude stays below this many minor units: 10 trillion in a
#: two-decimal currency. Far above any real transaction or balance, and far
#: enough below SQLite's 64-bit INTEGER that thousands of them still SUM.
MAX_MINOR = 10 ** 15
# An integer part longer than this already exceeds MAX_MINOR in every
# currency, and is refused before `int()` (which caps conversions at 4,300
# digits with a ValueError of its own) ever sees it.
_MAX_INT_DIGITS = 18


def to_minor(amount_str: str, currency: str) -> int:
    """An amount string as exact integer minor units, or MoneyError.

    Exact by construction: digits are parsed as integers, never through a
    `Decimal` context, whose 28-digit precision rounds a longer amount BEFORE
    any precision check could see it (issue #92) and whose scaling overflows
    with an ArithmeticError no caller expects.
    """
    exp = exponent(currency)
    if not isinstance(amount_str, str) or not amount_str:
        raise MoneyError("amount must be a non-empty string")
    if set(amount_str) - _ALLOWED:                 # bars nan/inf/1e3/1,23 outright
        raise MoneyError(f"illegal characters in amount: {amount_str!r}")
    m = _AMOUNT.match(amount_str)
    if m is None or not (m.group(2) or m.group(3)):
        raise MoneyError(f"unparseable amount: {amount_str!r}")
    sign, whole, frac = m.group(1), m.group(2).lstrip("0"), (m.group(3) or "").rstrip("0")
    if len(frac) > exp:
        raise MoneyError(
            f"amount {amount_str!r} has more precision than {currency} allows ({exp} dp)")
    if len(whole) > _MAX_INT_DIGITS:
        raise MoneyError(f"amount {amount_str!r} is out of range")
    minor = int(whole or "0") * 10 ** exp + int(frac.ljust(exp, "0") or "0")
    if minor >= MAX_MINOR:
        raise MoneyError(f"amount {amount_str!r} is out of range")
    return -minor if sign == "-" else minor


def format_minor(minor: int, currency: str) -> str:
    exp = exponent(currency)
    if exp == 0:
        return str(minor)
    sign = "-" if minor < 0 else ""
    digits = str(abs(minor)).rjust(exp + 1, "0")
    return f"{sign}{digits[:-exp]}.{digits[-exp:]}"
