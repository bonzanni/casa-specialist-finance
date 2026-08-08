# tests/test_httpx.py
import datetime as dt
import email.message
import io
import pathlib
import sys
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"))
import httpx

ALLOW = {("GET", r"^/application$"), ("GET", r"^/accounts/[0-9a-f-]+/balances$"),
         ("POST", r"^/auth$")}


class TestAllowlist(unittest.TestCase):
    def setUp(self):
        self.c = httpx.Client("api.enablebanking.com", ALLOW)

    def test_blocks_unlisted_path_before_any_network_call(self):
        with self.assertRaises(httpx.NotAllowed):
            self.c.request("GET", "/payments")

    def test_blocks_unlisted_method(self):
        with self.assertRaises(httpx.NotAllowed):
            self.c.request("DELETE", "/application")

    def test_blocks_path_traversal_and_absolute_urls(self):
        for bad in ("/application/../payments", "https://evil.example/application",
                    "//evil.example/application"):
            with self.assertRaises(httpx.NotAllowed):
                self.c.request("GET", bad)

    def test_rejects_userinfo_and_plain_http_hosts(self):
        with self.assertRaises(httpx.NotAllowed):
            httpx.Client("user:pw@api.enablebanking.com", ALLOW)
        with self.assertRaises(httpx.NotAllowed):
            httpx.Client("http://api.enablebanking.com", ALLOW)

    def test_allowed_path_passes_validation(self):
        # validation only — no network in unit tests
        self.assertIsNone(self.c._check("GET", "/application"))
        self.assertIsNone(
            self.c._check("GET", "/accounts/2b8d76d1-f60c-4ae3-a827-0eb4bb24b587/balances"))

    def test_no_credential_attached_on_refused_call(self):
        """Regression for a `$`-without-`re.MULTILINE` allowlist bypass:
        `^/application$` also matches '/application\\n' (the `$` anchor
        matches at end-of-string OR immediately before one trailing
        newline). If `_check` ever again treats that path as allowed, this
        test proves the concrete consequence -- an Authorization header
        reaching the opener on a call that should have been refused --
        rather than just re-asserting NotAllowed in the abstract. Uses a
        recording fake opener instead of inspecting exception types, so it
        would have caught the bypass even though the old code's `NotAllowed`
        vs. no-exception behavior alone could look correct at a glance."""
        class _RecordingOpener:
            def __init__(self):
                self.calls = []

            def open(self, req, timeout=None):
                self.calls.append(req)
                raise AssertionError(
                    "opener.open must never be called for a refused request")

        opener = _RecordingOpener()
        self.c._opener = opener
        for bad in ("/payments", "/application\n"):
            with self.assertRaises(httpx.NotAllowed):
                self.c.request("GET", bad,
                                headers={"Authorization": "Bearer super-secret-token"})
        self.assertEqual(opener.calls, [])

    def test_redirects_are_disabled(self):
        """Drives the opener's REAL redirect-handling path
        (OpenerDirector.error -> HTTPRedirectHandler.http_error_302 ->
        redirect_request) instead of inspecting a class name. If _NoRedirect
        were not the handler actually installed on this opener, the stock
        HTTPRedirectHandler.redirect_request would return a new Request
        instead of raising, and http_error_302 would then call fp.read() —
        fp is None here — raising AttributeError instead of NotAllowed. Either
        outcome proves the same underlying claim (the redirect target,
        https://evil.example, is never followed with this client's opener),
        but only a genuinely-installed _NoRedirect raises the specific,
        intended httpx.NotAllowed asserted below."""
        req = urllib.request.Request("https://api.enablebanking.com/application")
        headers = email.message.Message()
        headers["Location"] = "https://evil.example/steal-the-bearer-token"
        with self.assertRaises(httpx.NotAllowed):
            self.c._opener.error("http", req, None, 302, "Found", headers)

    def test_redirect_refusal_message_does_not_leak_the_redirect_url(self):
        """The Location header on a redirect is provider-supplied and, by
        this module's own threat model, may itself carry a bearer token or
        session-identifying query parameters -- the very reason redirects
        are disabled at all. Asserts on the ABSENCE of a marker drawn from
        the redirect URL, not merely on the presence of a fixed message
        string, so a future reintroduction of the URL into the exception
        text would be caught even if the fixed wording were kept alongside
        it."""
        marker = "tok_1a2b3c4d5e6f-do-not-leak"
        req = urllib.request.Request("https://api.enablebanking.com/application")
        headers = email.message.Message()
        headers["Location"] = f"https://evil.example/steal?token={marker}"
        with self.assertRaises(httpx.NotAllowed) as ctx:
            self.c._opener.error("http", req, None, 302, "Found", headers)
        self.assertNotIn(marker, str(ctx.exception))
        self.assertNotIn(marker, repr(ctx.exception))


class TestRateLimiting(unittest.TestCase):
    """The persistent per-account cooldown counters and the single-flight lock
    live in `tools_auth`; `Retry-After` handling lives HERE, because
    discarding it leaves a fresh-SCA window that ordinary
    reads could exhaust with no way to recover it later, and that is not
    something anything else can undo. `request` never
    retries; a 429 is a named failure carrying no provider body; and that
    failure carries the parsed `Retry-After` delay (both wire forms) so a
    caller can persist a cooldown -- it still never auto-retries."""

    def setUp(self):
        self.c = httpx.Client("api.enablebanking.com", ALLOW)
        self._real_now = httpx._now

    def tearDown(self):
        httpx._now = self._real_now

    def test_429_raises_rate_limited_without_leaking_the_provider_body(self):
        secret_body = b"account-holder-name-and-iban-in-the-error-page"

        class _FakeOpener:
            def open(self, req, timeout=None):
                raise urllib.error.HTTPError(
                    req.full_url, 429, "Too Many Requests", {}, io.BytesIO(secret_body))

        self.c._opener = _FakeOpener()
        try:
            self.c.request("POST", "/auth", form_body={"code": "abc"})
            self.fail("expected RateLimited")
        except httpx.RateLimited as exc:
            self.assertNotIn(secret_body.decode(), str(exc))
            self.assertNotIn(secret_body, repr(exc).encode())
            self.assertIsNone(exc.retry_after_s)   # no Retry-After header sent

    def test_retry_after_delta_seconds_form_is_parsed_and_carried(self):
        """The first Retry-After form: an integer count of
        seconds. This is the form that must not be discarded -- a caller
        needs it to persist a per-account cooldown."""
        class _FakeOpener:
            def open(self, req, timeout=None):
                raise urllib.error.HTTPError(
                    req.full_url, 429, "Too Many Requests",
                    {"Retry-After": "120"}, io.BytesIO(b""))

        self.c._opener = _FakeOpener()
        with self.assertRaises(httpx.RateLimited) as ctx:
            self.c.request("POST", "/auth", form_body={"code": "abc"})
        self.assertEqual(ctx.exception.retry_after_s, 120.0)

    def test_retry_after_http_date_form_is_parsed_and_carried(self):
        """The second Retry-After form: an HTTP-date. The
        clock is frozen so the parsed delay is an exact assertion instead of
        a wall-clock-timing-dependent range."""
        httpx._now = lambda: dt.datetime(2026, 8, 3, 12, 0, 0, tzinfo=dt.timezone.utc)

        class _FakeOpener:
            def open(self, req, timeout=None):
                raise urllib.error.HTTPError(
                    req.full_url, 429, "Too Many Requests",
                    {"Retry-After": "Mon, 03 Aug 2026 12:02:00 GMT"}, io.BytesIO(b""))

        self.c._opener = _FakeOpener()
        with self.assertRaises(httpx.RateLimited) as ctx:
            self.c.request("POST", "/auth", form_body={"code": "abc"})
        self.assertEqual(ctx.exception.retry_after_s, 120.0)

    def test_request_never_retries_even_on_a_transient_error(self):
        """POST /auth is non-idempotent: a second automatic send
        would start a second authorization attempt against the same code.
        This proves the client makes exactly one attempt no matter what the
        transport does — a retrying implementation would call `open` twice
        and the AssertionError below would fire instead of the expected
        URLError."""
        calls = []

        class _FlakyOpener:
            def open(self, req, timeout=None):
                calls.append(req.full_url)
                if len(calls) == 1:
                    raise urllib.error.URLError("connection reset")
                raise AssertionError("request() must not retry")

        self.c._opener = _FlakyOpener()
        with self.assertRaises(urllib.error.URLError):
            self.c.request("POST", "/auth", form_body={"code": "abc"})
        self.assertEqual(len(calls), 1)


class TestResponseHandling(unittest.TestCase):
    """The success branch (`with self._opener.open(...) as resp: body =
    resp.read(...)`) and the size-cap branch were previously unexercised --
    every other test in this file either fails validation before the opener
    is reached or drives the HTTPError branch. These drive a real fake
    response object through to a `(status, body)` return, and through the
    `TooLarge` raise."""

    def setUp(self):
        self.c = httpx.Client("api.enablebanking.com", ALLOW)

    def test_successful_response_returns_status_and_body(self):
        class _FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                return False

            def read(self, amt=-1):
                return b'{"ok": true}'

        class _FakeOpener:
            def open(self, req, timeout=None):
                return _FakeResponse()

        self.c._opener = _FakeOpener()
        status, body = self.c.request("GET", "/application")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"ok": true}')

    def test_response_over_the_size_cap_raises_too_large(self):
        class _FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                return False

            def read(self, amt=-1):
                # Mirrors http.client.HTTPResponse.read(amt): returns up to
                # `amt` bytes. The client asks for max_bytes + 1 so it can
                # tell "exactly at the cap" from "over the cap" without ever
                # buffering more than one byte past the limit.
                return b"x" * amt

        class _FakeOpener:
            def open(self, req, timeout=None):
                return _FakeResponse()

        small = httpx.Client("api.enablebanking.com", ALLOW, max_bytes=10)
        small._opener = _FakeOpener()
        with self.assertRaises(httpx.TooLarge):
            small.request("GET", "/application")


if __name__ == "__main__":
    unittest.main()
