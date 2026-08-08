"""Money as integer minor units. Never binary float."""
from __future__ import annotations
from decimal import Decimal, InvalidOperation

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


def to_minor(amount_str: str, currency: str) -> int:
    exp = exponent(currency)
    if not isinstance(amount_str, str) or not amount_str:
        raise MoneyError("amount must be a non-empty string")
    if set(amount_str) - _ALLOWED:                 # bars nan/inf/1e3/1,23 outright
        raise MoneyError(f"illegal characters in amount: {amount_str!r}")
    try:
        dec = Decimal(amount_str)
    except InvalidOperation:
        raise MoneyError(f"unparseable amount: {amount_str!r}") from None
    if not dec.is_finite():
        raise MoneyError("amount is not finite")
    scaled = dec.scaleb(exp)
    if scaled != scaled.to_integral_value():
        raise MoneyError(
            f"amount {amount_str!r} has more precision than {currency} allows ({exp} dp)")
    return int(scaled)


def format_minor(minor: int, currency: str) -> str:
    exp = exponent(currency)
    if exp == 0:
        return str(minor)
    sign = "-" if minor < 0 else ""
    digits = str(abs(minor)).rjust(exp + 1, "0")
    return f"{sign}{digits[:-exp]}.{digits[-exp:]}"
