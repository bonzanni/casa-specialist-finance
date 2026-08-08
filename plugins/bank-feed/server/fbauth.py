"""Firebase email-link auth for the Enable Banking control panel.

Enable Banking's control-panel login is Firebase passwordless email
magic-link; docs/reference/enable-banking-credentials.md walks the
exchange. This module owns the three Google endpoints and the ID-token
cache, and nothing else:

    send_signin_email  POST identitytoolkit /v1/accounts:sendOobCode
    exchange_link      POST identitytoolkit /v1/accounts:signInWithEmailLink
    mint_id_token      POST securetoken     /v1/token   (form-encoded)
    Minter             the ~55-minute cache eb_admin's bearer rides on

The API key is PUBLIC by design — it identifies the Firebase project and
ships in the control panel's own JavaScript. The refresh token, ID token
and oobCode are secrets and never appear in an exception or a log line;
AuthError carries the Firebase error CODE alone.

`send_signin_email` is safe to automate: an oobCode only signs into the
address it was delivered to, so the worst case is an email the operator
ignores. Reading the mailbox for the code is the account-takeover half and
lives in NO code path here — the operator ferries the link (copy, not
click: a browser visit consumes the single-use code without handing the
plugin anything).
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse

import httpx

API_KEY = "AIzaSyBn8fvjRYQKslskRaO3cblUjmcyl5b9o-c"     # public, not a secret
IDTK_HOST = "identitytoolkit.googleapis.com"
TOKEN_HOST = "securetoken.googleapis.com"
CONTINUE_URL = "https://enablebanking.com/cp/"

IDTK_ALLOW = {
    ("POST", r"^/v1/accounts:sendOobCode$"),
    ("POST", r"^/v1/accounts:signInWithEmailLink$"),
}
TOKEN_ALLOW = {("POST", r"^/v1/token$")}

# The oobCode alphabet: URL-safe base64. Mail connectors defang links in
# transit -- dropping leading characters and rewriting `=` -- so anything
# outside this set is a mangled link, not a code.
_CODE_RX = re.compile(r"^[A-Za-z0-9_-]{20,}$")

# Mint 5 minutes before Firebase's 3600 s expiry: never serve a token that
# could die mid-request.
_SKEW_S = 300.0

# A provider response is a CLAIM, not a fact. An id_token that is not shaped
# like a JWT — e.g. carrying a control character — later blows up urllib's
# header construction ("Authorization: Bearer <token>"), and bank_feed_server's
# generic renderer would put that ValueError's text, token fragment included,
# straight into tool output. Gate the shape here, at the boundary, before it
# ever reaches a header: exactly three non-empty base64url segments, and a sane
# length bound so nothing enormous gets this far either.
_ID_TOKEN_RX = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_ID_TOKEN_MAX_LEN = 8192


class AuthError(RuntimeError):
    """A Firebase failure, by CODE only (e.g. INVALID_OOB_CODE)."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"firebase: {code}")


class DefangedLink(ValueError):
    """The pasted link's code was mangled in transit."""


def _now() -> float:                        # clock seam
    return time.time()


def _idtk() -> httpx.Client:                # client seams, test-replaced
    return httpx.Client(IDTK_HOST, IDTK_ALLOW)


def _token_client() -> httpx.Client:
    return httpx.Client(TOKEN_HOST, TOKEN_ALLOW)


def _post(client, path, *, json_body=None, form_body=None,
          secrets=()) -> dict:
    """`secrets` lists the values THIS request submitted (oobCode,
    refresh token): whatever the provider's error text echoes, those
    exact values are banned from the extracted code."""
    status, raw = client.request("POST", path, json_body=json_body,
                                 form_body=form_body)
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        data = {}
    if status >= 400:
        message = str(((data.get("error") or {}).get("message"))
                      or f"HTTP_{status}")
        # The code is the first token — Firebase writes prose after a colon
        # ("INVALID_OOB_CODE : the code is malformed..."). But the message is
        # PROVIDER-CONTROLLED text and may echo what we submitted, and callers
        # interpolate AuthError.code into tool output — so two independent
        # gates apply: the SHAPE gate (real Firebase codes are SCREAMING_SNAKE
        # and short) kills mixed-case echoes, and the VALUE gate kills what
        # shape can't — a submitted secret that happens to be all-caps. The
        # value gate is BIDIRECTIONAL: a code that is a fragment OF a submitted
        # secret (a truncated echo — the full secret is not "in" its own
        # 40-char prefix) is as banned as one that contains it. False
        # flattening is the safe direction: PROVIDER_ERROR only costs message
        # quality, never a branch that matters — rung 3 treats every
        # non-INVALID_REFRESH_TOKEN code as a retryable outage.
        code = message.split()[0].split(":")[0]
        if (not re.fullmatch(r"[A-Z0-9_]{2,40}", code)
                or any(s and (s in code or code in s) for s in secrets)):
            code = "PROVIDER_ERROR"
        raise AuthError(code)
    return data


def send_signin_email(email: str) -> None:
    _post(_idtk(), f"/v1/accounts:sendOobCode?key={API_KEY}",
          json_body={"requestType": "EMAIL_SIGNIN", "email": email,
                     "continueUrl": CONTINUE_URL})


def parse_signin_link(text: str) -> str:
    """The oobCode from a pasted sign-in URL, or the bare code itself.

    Raises DefangedLink when the code is visibly mangled; the message
    repeats the copy-not-click instruction because a defanged paste means
    the operator relayed the link through a connector."""
    text = text.strip()
    code = text
    if "://" in text or "?" in text:
        query = urllib.parse.urlsplit(text).query
        codes = urllib.parse.parse_qs(query).get("oobCode") or []
        if not codes:
            raise DefangedLink(
                "that link carries no oobCode parameter — paste the full "
                "'Sign in to Enable Banking' URL, copied from your own "
                "mail client without clicking it")
        code = codes[0]
    if not _CODE_RX.match(code):
        raise DefangedLink(
            "the code in that link is mangled (defanged in transit). Copy "
            "the URL straight from your own mail client — do not click "
            "it, and do not relay it through a mail connector")
    return code


def exchange_link(email: str, oob_code: str) -> str:
    """Redeem the single-use code → the DURABLE refresh token."""
    data = _post(_idtk(), f"/v1/accounts:signInWithEmailLink?key={API_KEY}",
                 json_body={"email": email, "oobCode": oob_code},
                 secrets=(oob_code,))
    token = data.get("refreshToken")
    if not token:
        raise AuthError("NO_REFRESH_TOKEN_IN_RESPONSE")
    return token


def mint_id_token(refresh_token: str) -> tuple:
    """refresh token → (ID token, seconds it lives). Form-encoded, exactly
    as proven live (docs/reference/enable-banking-credentials.md)."""
    data = _post(_token_client(), f"/v1/token?key={API_KEY}",
                 form_body={"grant_type": "refresh_token",
                            "refresh_token": refresh_token},
                 secrets=(refresh_token,))
    token = data.get("id_token")
    if not token:
        raise AuthError("NO_ID_TOKEN_IN_RESPONSE")
    if (not isinstance(token, str) or len(token) > _ID_TOKEN_MAX_LEN
            or not _ID_TOKEN_RX.fullmatch(token)):
        raise AuthError("MALFORMED_ID_TOKEN_IN_RESPONSE")
    try:
        ttl = float(data.get("expires_in") or 3600)
    except (TypeError, ValueError):
        # float("<junk>") raises with the junk IN the message, and the junk is
        # provider-controlled — it could echo the submitted token. A malformed
        # TTL is not worth an exception at all: fall back to Firebase's fixed
        # 1-hour term.
        ttl = 3600.0
    return token, ttl


class Minter:
    """The bearer eb_admin rides on. Re-reads the refresh token through
    the injected callable on every mint — not once at construction — so a
    rotated vault value takes effect without a server restart."""

    def __init__(self, read_refresh) -> None:
        self._read_refresh = read_refresh
        self._token = None
        self._good_until = 0.0

    def token(self) -> str:
        if self._token is None or _now() >= self._good_until:
            self._token, ttl = mint_id_token(self._read_refresh())
            self._good_until = _now() + max(0.0, ttl - _SKEW_S)
        return self._token

    def invalidate(self) -> None:
        self._token = None
        self._good_until = 0.0
