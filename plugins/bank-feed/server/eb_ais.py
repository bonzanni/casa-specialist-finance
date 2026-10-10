# plugins/bank-feed/server/eb_ais.py
"""Enable Banking AIS calls. Credential: the application's own RS256 JWT.

`transactions()` returns ONE page plus the next continuation key. Paging to
exhaustion belongs to the caller that owns the coverage interval
(`flows.backfill`), because only that caller can say what was proved.

`ApiError` carries a status, a CLASS and, when the provider sent one, Enable
Banking's own error CODE (issue #100) — nothing else. Provider text is
attacker-controllable and any exception text can reach the model through the
server's error path, so `ApiError` deliberately has no body to leak and no
path (which would carry a session id) in its message. The code is the one
exception, and only because it is not text: it is a token from a closed
vocabulary (`EXPIRED_SESSION`, `REVOKED_SESSION`, `ASPSP_ERROR`, ...), kept
only when it is one of `ERROR_CODES`. The response's `message` and `detail` are free
text and are never read.

That is a claim about `ApiError`, NOT about every exception this module can
raise. A 2xx whose body is not JSON leaves `_call` as `json.JSONDecodeError`,
and that exception's `.doc` attribute holds the entire provider body. Latent
rather than live: its `str()` and `.args` are clean and `bank_feed_server`
renders `f"{type}: {exc}"`, so nothing prints `.doc` today — but any future
error path that renders exception ATTRIBUTES rather than their text would
surface a whole provider body, and this module's own guarantee would not stop
it.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import urllib.parse

import httpx
import jwtsign

API_HOST = "api.enablebanking.com"
CONSENT_DAYS = 179
CONSENT_CEILING_S = 15_552_000        # == 180 days; the provider check is STRICT

# Exactly the eight AIS calls this plugin makes. No `(\?.*)?` alternatives: the
# client strips the query string before matching, so a query alternative can
# never match and would only misrepresent how the decision is made.
ALLOW = {
    ("GET", r"^/application$"),
    ("GET", r"^/aspsps$"),
    ("POST", r"^/auth$"),
    ("POST", r"^/sessions$"),
    ("GET", r"^/sessions/[A-Za-z0-9-]+$"),
    ("DELETE", r"^/sessions/[A-Za-z0-9-]+$"),
    ("GET", r"^/accounts/[A-Za-z0-9-]+/balances$"),
    ("GET", r"^/accounts/[A-Za-z0-9-]+/transactions$"),
}

_KINDS = {400: "bad_request", 401: "unauthorized", 403: "forbidden",
          404: "not_found", 409: "conflict", 422: "unprocessable",
          429: "rate_limited"}

# `httpx.Client._check` strips a path at its FIRST `?` before matching, so a
# `?` inside a TRAILING interpolated identifier would truncate the checked
# path to something shorter and allowlisted, turning the rest into a query
# string the allowlist never inspects. TWO of the three identifiers are
# trailing and that is where the bug lived: `sid` in `/sessions/{sid}`, and
# `app_id` in eb_admin's `/api/application/{app_id}`.
#
# `uid` is NOT trailing at either of its call sites -- `/accounts/{uid}/
# balances` and `/accounts/{uid}/transactions` both put a static segment
# after it -- and it is validated for a DIFFERENT reason, on the same rule.
# A `?` ALONE in `uid` is already refused by the allowlist, because it takes
# the required `/balances` suffix out of the checked path
# (`/accounts/abc?x=1/balances` checks as `/accounts/abc`, matching nothing),
# so for that shape validation only changes the exception from
# `httpx.NotAllowed` to `ValueError`. But a `uid` carrying a `/` AND a `?`
# REBUILDS the suffix ahead of the truncation and IS allowlisted without
# validation: `/accounts/abc/balances?x=1/balances` checks as
# `/accounts/abc/balances`, which matches. Verified against `_check`, not
# argued. So the character class is what closes mid-path `uid`, not the
# allowlist -- one rule over every interpolated segment, so no call site has
# to re-derive which position happens to be safe.
#
# Validating each identifier against the same character class the allowlist
# patterns above already use rejects exactly what the allowlist already
# intended to reject -- a consistency fix, not a new refusal. Defined once
# here and imported by eb_admin so both clients enforce the identical rule.
_PATH_ID_RE = re.compile(r"^[A-Za-z0-9-]+$")


def validate_path_id(value: str) -> str:
    if not _PATH_ID_RE.fullmatch(value):
        raise ValueError("invalid path identifier")   # never the value itself
    return value


def error_kind(status: int) -> str:
    """Coarse, body-free classification. Defined once and imported by
    eb_admin so the two clients cannot drift apart."""
    if status in _KINDS:
        return _KINDS[status]
    return "provider_error" if status >= 500 else "http_error"


#: Enable Banking's error codes (`ErrorResponse.error`, from the API
#: reference). A closed list, not a shape: an upper-case string is still
#: provider text, so anything not named here is dropped, never printed.
ERROR_CODES = frozenset({
    "ACCESS_DENIED", "ACCOUNT_DOES_NOT_EXIST", "ALREADY_AUTHORIZED",
    "ASPSP_ACCOUNT_NOT_ACCESSIBLE", "ASPSP_ERROR", "ASPSP_TIMEOUT",
    "ASPSP_RATE_LIMIT_EXCEEDED", "AUTHORIZATION_NOT_PROVIDED",
    "CLOSED_SESSION", "DATE_TO_WITHOUT_DATE_FROM", "DATE_FROM_IN_FUTURE",
    "EXPIRED_AUTHORIZATION_CODE", "EXPIRED_SESSION", "INVALID_ACCOUNT_ID",
    "INVALID_HOST", "UNAUTHORIZED_IP", "NO_ACCOUNTS_ADDED",
    "PAYMENT_NOT_FOUND", "PSU_HEADER_NOT_PROVIDED", "PSU_HEADER_INVALID",
    "REDIRECT_URI_NOT_ALLOWED", "REVOKED_SESSION", "SESSION_DOES_NOT_EXIST",
    "UNAUTHORIZED_ACCESS", "UNTRUSTED_PAYMENT_PARTY",
    "WEBHOOK_URI_NOT_ALLOWED", "WRONG_ASPSP_PROVIDED",
    "WRONG_AUTHORIZATION_CODE", "WRONG_DATE_INTERVAL",
    "WRONG_CREDENTIALS_PROVIDED", "WRONG_REQUEST_PARAMETERS",
    "WRONG_SESSION_STATUS", "WRONG_TRANSACTIONS_PERIOD",
    "WRONG_CONTINUATION_KEY", "TRANSACTION_DOES_NOT_EXIST",
    "PAYMENT_LIMIT_EXCEEDED", "ASPSP_PAYMENT_NOT_ACCESSIBLE",
    "INVALID_PAYMENT", "ASPSP_PSU_ACTION_REQUIRED", "PAYMENT_NOT_FINALIZED",
    "PAYMENT_SUBMISSION_NOT_SUPPORTED", "PAYMENT_NOT_AUTHORIZED",
    "PAYMENT_SUBMISSION_NOT_DEFERRED"})


def error_code(raw) -> str | None:
    """Enable Banking's error code from an error response body, or None.

    Issue #100: the code is what tells an expired consent (`EXPIRED_SESSION`)
    from a revoked one or a bank outage — a 401 alone cannot. Only the `error`
    field is read; `ApiError` keeps it only when it is one of
    `ERROR_CODES`.
    """
    try:
        body = json.loads(raw or b"")
    except (ValueError, UnicodeDecodeError):
        return None
    code = body.get("error") if isinstance(body, dict) else None
    return code if isinstance(code, str) else None


class ApiError(RuntimeError):
    """A status, a class and the provider's error code. It has NO body
    attribute on purpose: there must be nothing here for a later caller to
    accidentally surface."""

    def __init__(self, status: int, op: str, code: str | None = None) -> None:
        self.status = int(status)
        self.kind = error_kind(self.status)
        self.op = op
        self.code = (code if isinstance(code, str) and code in ERROR_CODES
                     else None)
        super().__init__(f"Enable Banking AIS {op} failed: "
                         f"HTTP {self.status} ({self.kind}"
                         + (f", {self.code}" if self.code else "") + ")")


#: `failure_label`'s shape for an `ApiError`, and the only thing
#: `label_status` accepts. Anchored at both ends: a label is read back only
#: when it is exactly the string this module wrote.
_LABEL_RE = re.compile(r"ApiError: HTTP ([1-5][0-9]{2}) [a-z_]+"
                       r"(?: [A-Z][A-Z_]{2,63})?")


def failure_label(exc) -> str:
    """What a failed provider call is recorded and printed as.

    An `ApiError` becomes `ApiError: HTTP 401 unauthorized` — the status and
    the fixed `error_kind` vocabulary, which is what tells an unauthorized
    answer from a rate limit or an outage — followed by Enable Banking's error
    code when it sent one (`ApiError: HTTP 401 unauthorized EXPIRED_SESSION`,
    issue #100). So does any exception whose class
    declares `LABELS_STATUS = True` and carries the status it wraps
    (`tools_auth.WorldUnverified`, the application check, which this module
    cannot import). Anything else stays its class name, as it always was. Neither reads `str(exc)` or `args`, so no provider body
    can reach a ledger column or a reply through it. No parentheses: the label
    is printed inside the callers' own `(…)`.
    """
    if isinstance(exc, ApiError) or getattr(type(exc), "LABELS_STATUS",
                                            False) is True:
        status = getattr(exc, "status", None)
        if (isinstance(status, int) and not isinstance(status, bool)
                and 100 <= status <= 599):
            label = "%s: HTTP %d %s" % (type(exc).__name__, status,
                                         error_kind(status))
            code = exc.code if isinstance(exc, ApiError) else None
            return label + (" " + code if code else "")
    return type(exc).__name__


def label_status(label) -> int | None:
    """The HTTP status a `failure_label` recorded, or None.

    The exact inverse of `failure_label` for an `ApiError`, and nothing else:
    any text this module did not write that way — a class name, a note, a
    rate-limit label with its suffix — reads as None, never as a guess.
    """
    m = _LABEL_RE.fullmatch(str(label or ""))
    return int(m.group(1)) if m else None


def revocation_is_final(exc) -> bool:
    """Does this failed `delete_session` still prove the consent is gone?

    Exactly one failure does: a 404. The provider is stating authoritatively
    that the session it was asked to delete does not exist, which is the state
    a successful DELETE produces — refusing to close on it would leave a row
    that can never be cleared, asking for ever for a retry that will 404 again.

    Nothing else qualifies, and the distinction is the whole finding. A 429, a
    timeout, a dropped socket, a 5xx: the consent is very probably STILL LIVE
    at the bank, and treating "we could not tell" as "it is revoked" is what
    closed the local row and erased the operator's only retry handle. A 400, a
    401 or a 403 does not qualify on its own either — but `revocation_settled`
    settles one whose error code names the session gone (issue #106) and asks
    the provider about the session for the rest (issue #102).

    **It lives HERE, beside `ApiError` and `error_kind`, and the placement is
    load-bearing.** It is a statement about what a provider status *means*,
    which is this module's subject, and this is the only module both callers can
    reach: `flows._revoke` on the renewal path and
    `tools_destructive.unlink_bank` on the operator path. Defined in
    `tools_auth` it would sit ABOVE `flows` in the straight-line import graph,
    so the renewal path could not call it and would grow a second, different
    rule —
    every exception a failure, 404 included. A renewal against a consent the
    provider had already dropped therefore landed in `REVOKE_FAILED` for ever:
    visible, nagging, and unresolvable, because every retry can only 404 again.
    One predicate, two call sites, no second rule to drift.
    """
    return isinstance(exc, ApiError) and exc.kind == "not_found"


#: Enable Banking's session statuses (`GET /sessions/{id}`). A closed
#: vocabulary, so the provider's answer is used and printed only when it is
#: one of these words.
SESSION_STATUSES = frozenset({
    "INVALID", "PENDING_AUTHORIZATION", "RETURNED_FROM_BANK", "AUTHORIZED",
    "EXPIRED", "CLOSED", "REVOKED", "CANCELLED"})

#: The statuses that say the consent no longer exists at the bank.
SESSION_GONE_STATUSES = frozenset({"EXPIRED", "REVOKED", "CLOSED"})

#: The error codes that say the same thing on a failed call, and the status
#: word each one names. Enable Banking refuses the DELETE of a CLOSED session
#: with HTTP 400 `CLOSED_SESSION` (issue #106).
SESSION_GONE_CODES = {"EXPIRED_SESSION": "EXPIRED",
                      "REVOKED_SESSION": "REVOKED",
                      "CLOSED_SESSION": "CLOSED"}


def session_status(ais, session_id) -> str | None:
    """The provider's own status word for a session, or None when the call
    fails or answers anything outside `SESSION_STATUSES`. Best effort: it
    never raises."""
    try:
        answer = ais.get_session(session_id)
    except Exception:                            # noqa: BLE001 — best effort
        return None
    status = answer.get("status") if isinstance(answer, dict) else None
    return status if isinstance(status, str) and status in SESSION_STATUSES \
        else None


def revocation_settled(ais, session_id, exc) -> tuple[bool, str | None]:
    """Does this failed `delete_session` still prove the consent is gone, and
    on what word? `(final, status)`.

    `revocation_is_final` first: a 404 is final on its own. So is an error
    code that names the session gone (`SESSION_GONE_CODES`), whatever the
    status: Enable Banking refuses the DELETE of a CLOSED session with a 400
    `CLOSED_SESSION` (issue #106). A 400, a 401 or a 403 without such a code is
    not final on its own — but Enable Banking refuses a DELETE that way for a
    session it already considers EXPIRED (issue #102), so for those it is
    ASKED, with one `GET /sessions/{id}`: an EXPIRED, REVOKED or CLOSED answer
    is the provider stating the consent is gone, and the status is returned so
    the reply can say so. Anything else — no answer, AUTHORIZED, any other
    failure — stays "we could not tell". The one rule for every revocation
    path: the renewal's `flows._revoke`, `unlink_bank` and `delete_all_data`.
    """
    if revocation_is_final(exc):
        return True, None
    if not isinstance(exc, ApiError):
        return False, None
    if exc.code in SESSION_GONE_CODES:
        return True, SESSION_GONE_CODES[exc.code]
    if exc.status not in (400, 401, 403):
        return False, None
    status = session_status(ais, session_id)
    return (True, status) if status in SESSION_GONE_STATUSES else (False, None)


def _now() -> dt.datetime:
    """Clock seam. Production always reads the real clock; tests freeze it so
    the 179-day assertion can be exact instead of a range."""
    return dt.datetime.now(dt.timezone.utc)


class AIS:
    def __init__(self, app_id: str, key) -> None:
        self.app_id, self.key = app_id, key
        self.client = httpx.Client(API_HOST, ALLOW)

    def _token(self) -> str:
        return jwtsign.sign_jwt({"iss": "enablebanking.com",
                                 "aud": "api.enablebanking.com"},
                                self.key, kid=self.app_id)

    def _call(self, op: str, method: str, path: str, body=None):
        """The single place a status is checked. NEVER retries — POST /auth
        and POST /sessions are not idempotent and a retry burns a one-shot
        authorization code."""
        status, raw = self.client.request(
            method, path,
            headers={"Authorization": f"Bearer {self._token()}"},
            json_body=body)
        if status >= 400:
            # `op` is a literal, never a path; of the body, only the code.
            raise ApiError(status, op, error_code(raw))
        return json.loads(raw or b"{}")

    def application(self) -> dict:
        return self._call("application", "GET", "/application")

    def aspsps(self, country: str) -> list:
        path = "/aspsps?" + urllib.parse.urlencode({"country": country})
        return list(self._call("aspsps", "GET", path).get("aspsps") or [])

    def start_auth(self, aspsp: str, country: str, psu_type: str, state: str,
                   redirect_uri: str, valid_days: int = CONSENT_DAYS) -> dict:
        if valid_days * 86400 >= CONSENT_CEILING_S:
            raise ValueError(
                f"consent validity must be strictly under {CONSENT_CEILING_S}s; "
                f"{valid_days} days is not — request {CONSENT_DAYS}")
        valid_until = (_now() + dt.timedelta(days=valid_days)).isoformat()
        return self._call("start_auth", "POST", "/auth", {
            "access": {"valid_until": valid_until},
            "aspsp": {"name": aspsp, "country": country},
            "state": state, "redirect_url": redirect_uri, "psu_type": psu_type})

    def create_session(self, code: str) -> dict:
        return self._call("create_session", "POST", "/sessions", {"code": code})

    def get_session(self, sid: str) -> dict:
        return self._call("get_session", "GET", f"/sessions/{validate_path_id(sid)}")

    def delete_session(self, sid: str) -> dict:
        return self._call("delete_session", "DELETE",
                          f"/sessions/{validate_path_id(sid)}")

    def balances(self, uid: str) -> list:
        data = self._call("balances", "GET",
                          f"/accounts/{validate_path_id(uid)}/balances")
        return list(data.get("balances") or [])

    def transactions(self, uid: str, date_from: str,
                     continuation_key: str | None = None):
        """ONE page. Returns (rows, next_continuation_key | None)."""
        query = {"date_from": date_from}
        if continuation_key:
            query["continuation_key"] = continuation_key
        path = (f"/accounts/{validate_path_id(uid)}/transactions?" +
               urllib.parse.urlencode(query))
        page = self._call("transactions", "GET", path)
        return list(page.get("transactions") or []), page.get("continuation_key")
