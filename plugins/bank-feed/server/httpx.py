"""HTTPS clients whose allowlist is enforced at runtime, before credentials.

An exact (scheme, host, method, path) allowlist, HTTPS only, no
userinfo, redirects DISABLED (a redirect must never carry a bearer token to
another origin), size caps, and deadlines.

Rate limiting's persistent per-account cooldown counters and its
single-flight lock live in `tools_auth`; `Retry-After` handling lives HERE,
because discarding it leaves a fresh-SCA window that
ordinary reads could exhaust with no way for a later slice to restore it.
`request` NEVER retries — a caller who wants a retry issues a
fresh, deliberate call; a 429 is raised as `RateLimited` carrying no
provider body, never silently retried, so the non-idempotent `POST /auth`
and `POST /sessions` are never re-sent automatically; and `RateLimited`
carries the provider's parsed `Retry-After` delay (`retry_after_s`, either
wire form — delta-seconds or HTTP-date — or `None` when the header was
absent or unparseable) so a caller can persist a cooldown. It still never
triggers a retry here.
"""
from __future__ import annotations
import datetime as _dt
import email.utils
import json, re, urllib.error, urllib.parse, urllib.request


class NotAllowed(Exception):
    """The call is outside this client's contract. Raised before any I/O."""


class TooLarge(Exception):
    """Response exceeded the size cap."""


def _now() -> _dt.datetime:
    """Clock seam so the HTTP-date form of Retry-After can be tested with an
    exact assertion instead of a wall-clock-timing-dependent range."""
    return _dt.datetime.now(_dt.timezone.utc)


def _parse_retry_after(value, now=None):
    """Retry-After is either delta-seconds ("120") or an
    HTTP-date ("Mon, 03 Aug 2026 12:02:00 GMT"). Returns seconds until the
    provider says it is safe to retry, or None when the header is absent or
    unparseable — callers must treat None as "no information", never as
    "retry immediately"."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    return max(0.0, (when - (now or _now())).total_seconds())


class RateLimited(Exception):
    """The provider returned 429. Carries no provider body
    but does carry the parsed `Retry-After` delay so a caller can persist a
    cooldown. `retry_after_s` is `None` when the header was absent or
    unparseable; nothing here auto-retries either way."""

    def __init__(self, message: str, retry_after_s: float | None = None) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # No {newurl!r} here: a redirect Location is provider-supplied and,
        # by this module's own threat model, may itself carry a bearer
        # token or session-identifying query parameters -- the very reason
        # redirects are disabled at all. Interpolating it into the
        # exception would reopen through error text the channel this
        # module exists to close on the request side.
        raise NotAllowed("redirect refused")


class Client:
    def __init__(self, host: str, allow: set, timeout: float = 20.0,
                 max_bytes: int = 8 * 1024 * 1024) -> None:
        if "@" in host or "/" in host or ":" in host:
            # No {host!r} here: this branch is reached with userinfo-bearing
            # hosts by construction (spec test), so the value is
            # credential-shaped and must never be echoed into an exception.
            raise NotAllowed("host must be a bare hostname")
        self.host = host
        self.allow = [(m, re.compile(p)) for m, p in allow]
        self.timeout = timeout
        self.max_bytes = max_bytes
        # build_opener(_NoRedirect) REPLACES the stock HTTPRedirectHandler
        # with this one — passing a handler class to build_opener supersedes
        # any default handler that is its base class or a subclass of it, so
        # no further filtering of self._opener.handlers is needed or correct
        # (filtering by class name here would never match anything, since no
        # handler in the resulting opener is named "HTTPRedirectHandler").
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _check(self, method: str, path: str) -> None:
        # Up front, before any other check: refuse control characters (incl.
        # CR/LF/NUL) outright rather than relying on http.client.putrequest's
        # incidental rejection of them in the request line -- that backstop
        # is outside this module's declared contract (NotAllowed/TooLarge/
        # RateLimited) and no caller is told to expect or catch it.
        if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in path):
            raise NotAllowed("path contains a control character")
        if not path.startswith("/") or path.startswith("//"):
            raise NotAllowed("path must be site-relative")
        bare = path.split("?", 1)[0]
        if ".." in bare:
            raise NotAllowed("path traversal refused")
        for m, rx in self.allow:
            # fullmatch, not match: `$` without re.MULTILINE matches at
            # end-of-string OR immediately before one trailing newline, so
            # `match` would let '/application\n' through an `^/application$`
            # pattern. fullmatch requires the pattern to consume the whole
            # string, closing that gap. Existing ^...$ patterns stay valid
            # under fullmatch -- the anchors become redundant, not wrong.
            if m == method and rx.fullmatch(bare):
                return None
        raise NotAllowed("not on this client's allowlist")

    def request(self, method: str, path: str, *, headers: dict | None = None,
                json_body=None, form_body: dict | None = None) -> tuple[int, bytes]:
        """Makes exactly one attempt. NEVER retries — on a 429 or any other
        transport error, the exception propagates to the caller, who
        decides whether a fresh call is safe. This matters most for the
        non-idempotent POST /auth and POST /sessions: an automatic retry
        here would silently re-send them.
        """
        self._check(method, path)                     # BEFORE credentials attach
        data, hdrs = None, dict(headers or {})
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        elif form_body is not None:
            data = urllib.parse.urlencode(form_body).encode("utf-8")
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(f"https://{self.host}{path}", data=data,
                                     method=method, headers=hdrs)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    raise TooLarge(f"response exceeded {self.max_bytes} bytes")
                return resp.status, body
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                retry_after_s = _parse_retry_after(exc.headers.get("Retry-After"))
                raise RateLimited("provider returned 429", retry_after_s) from None
            body = exc.read(self.max_bytes)
            return exc.code, body
