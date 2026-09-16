# tests/test_casa_broker.py
"""`casa_broker` against a fake broker on a real Unix socket.

The fake speaks casa's deposit route the way casa's aiohttp handler does: one
HTTP POST, a JSON body in, a JSON object out. What it answers is chosen per
test, so the helper is exercised on every shape casa can send and on the
shapes a broken or hostile one could. It never echoes the value by default,
and a test that makes it echo checks the value does not come back out.

`fit_label` and `fit_caption` are held to casa's own acceptance rules, spelled
out below from the constants `casa_broker` copies (and that
`tests/test_component.py` cross-checks against casa's source).
"""
import http.server
import json
import os
import pathlib
import re
import socketserver
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))

import casa_broker  # noqa: E402

URL = "https://tpp.enablebanking.com/auth?state=" + "c" * 64
REFERENCE = "casa-cap-" + "0123456789abcdef" * 2
CLIENT = "0f" * 16


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = False

    def handle_error(self, request, client_address):
        pass                  # a client that timed out and left is the test


class FakeBroker:
    """A Unix-socket HTTP server. `answer(body) -> bytes` decides the reply."""

    def __init__(self, path, answer):
        self.requests = []            # (method, path, parsed body)
        broker = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def address_string(self):          # a Unix peer has no host
                return "unix"

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                broker.requests.append((self.command, self.path, body))
                data = answer(body)
                if data is None:                   # hang up without a reply
                    self.close_connection = True
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = _Server(path, Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.02},
                                       daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _json(obj):
    return json.dumps(obj).encode("utf-8")


class DepositTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.sock = os.path.join(self.dir.name, "internal.sock")
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        os.environ[casa_broker.ENV_SOCKET] = self.sock
        os.environ[casa_broker.ENV_CLIENT] = CLIENT

    def serve(self, answer):
        broker = FakeBroker(self.sock, answer)
        self.addCleanup(broker.close)
        return broker

    def deposit(self):
        return casa_broker.deposit_link(
            "approval_link", URL, label="Approve at Rabobank",
            caption="Rabobank, NL, personal — one-time link")

    def refused(self):
        with self.assertRaises(casa_broker.DepositFailed) as caught:
            self.deposit()
        code = caught.exception.code
        # Whatever the failure, the value never comes back out of the helper.
        self.assertNotIn(URL, code)
        self.assertNotIn(URL, str(caught.exception))
        self.assertNotIn("enablebanking", repr(caught.exception))
        return code

    def test_a_deposit_posts_casas_body_and_returns_the_reference(self):
        broker = self.serve(lambda body: _json({"reference": REFERENCE}))
        self.assertEqual(self.deposit(), REFERENCE)
        self.assertEqual(len(broker.requests), 1)
        method, path, body = broker.requests[0]
        self.assertEqual((method, path), ("POST", "/internal/broker/deposit"))
        self.assertEqual(body, {
            "client": CLIENT, "slot": "approval_link", "value": URL,
            "label": "Approve at Rabobank",
            "caption": "Rabobank, NL, personal — one-time link"})

    def test_casas_error_code_is_the_failure_code(self):
        for code in ("bad_link", "bad_caption", "bad_label",
                     "no_call_in_flight", "no_identity", "ambiguous_call",
                     "slot_already_deposited", "value_too_large"):
            with self.subTest(code=code):
                self.dir2 = tempfile.TemporaryDirectory()
                self.addCleanup(self.dir2.cleanup)
                os.environ[casa_broker.ENV_SOCKET] = os.path.join(
                    self.dir2.name, "s.sock")
                self.sock = os.environ[casa_broker.ENV_SOCKET]
                self.serve(lambda body, c=code: _json({"error": c}))
                self.assertEqual(self.refused(), code)

    def test_no_broker_in_the_environment_is_reported_without_connecting(self):
        broker = self.serve(lambda body: _json({"reference": REFERENCE}))
        for var in (casa_broker.ENV_SOCKET, casa_broker.ENV_CLIENT):
            with self.subTest(unset=var):
                saved = os.environ.pop(var)
                try:
                    self.assertEqual(self.refused(), "broker_env_missing")
                finally:
                    os.environ[var] = saved
        self.assertEqual(broker.requests, [])

    def test_an_absent_socket_is_unreachable_by_class_name(self):
        self.assertEqual(self.refused(),
                         "broker_unreachable:FileNotFoundError")

    def test_a_broker_that_hangs_up_is_unreachable(self):
        self.serve(lambda body: None)
        self.assertTrue(self.refused().startswith("broker_unreachable:"))

    def test_a_broker_that_never_answers_times_out(self):
        release = threading.Event()
        self.serve(lambda body: (release.wait(5), _json({}))[1])
        self.addCleanup(release.set)
        real = casa_broker.TIMEOUT_S
        casa_broker.TIMEOUT_S = 0.2
        self.addCleanup(setattr, casa_broker, "TIMEOUT_S", real)
        self.assertEqual(self.refused(), "broker_unreachable:TimeoutError")

    def test_an_answer_that_is_not_one_json_object_is_a_bad_response(self):
        for data in (b"not json", _json([REFERENCE]), _json(REFERENCE),
                     b"[" * 30000 + b"]" * 30000,   # under the size bound, past the parser depth
                     b"\xff\xfe", b"{" + b" " * (casa_broker.MAX_RESPONSE_BYTES + 1) + b"}"):
            with self.subTest(data=data[:20]):
                d = tempfile.TemporaryDirectory()
                self.addCleanup(d.cleanup)
                self.sock = os.environ[casa_broker.ENV_SOCKET] = os.path.join(d.name, "s")
                self.serve(lambda body, x=data: x)
                self.assertEqual(self.refused(), "broker_bad_response")

    def test_an_answer_over_the_size_bound_is_refused_even_when_well_formed(self):
        # Exactly one byte over the bound, a whole valid object with a good
        # reference: only the bound itself refuses it (a truncated read of a
        # longer answer would fail to parse anyway, and prove nothing).
        head = json.dumps({"reference": REFERENCE, "pad": ""})[:-2]
        pad = casa_broker.MAX_RESPONSE_BYTES + 1 - len(head) - 2
        data = (head + "x" * pad + '"}').encode("utf-8")
        self.assertEqual(len(data), casa_broker.MAX_RESPONSE_BYTES + 1)
        self.assertEqual(json.loads(data)["reference"], REFERENCE)
        self.serve(lambda body: data)
        self.assertEqual(self.refused(), "broker_bad_response")

    def test_nothing_the_broker_sends_back_is_echoed(self):
        # A broker that reflects the value, in either field, or in a
        # reference-shaped string with the value appended, is reported by a
        # fixed label: the helper returns only a reference of casa's exact
        # shape, and an error only when it looks like one of casa's codes.
        answers = (
            lambda body: _json({"reference": body["value"]}),
            lambda body: _json({"reference": REFERENCE + body["value"]}),
            lambda body: _json({"error": body["value"]}),
            lambda body: _json({"error": "bad_link " + body["value"]}),
            lambda body: _json({"error": "Bad_Link"}),
            lambda body: _json({}),
        )
        for i, answer in enumerate(answers):
            with self.subTest(answer=i):
                d = tempfile.TemporaryDirectory()
                self.addCleanup(d.cleanup)
                self.sock = os.environ[casa_broker.ENV_SOCKET] = os.path.join(d.name, "s")
                self.serve(answer)
                self.assertEqual(self.refused(), "unrecognized_error")


# casa's acceptance rules for a delivered link's label and caption
# (result_broker `_text_ok` / `_caption_ok` / `_label_ok`), spelled from the
# constants casa_broker copies.
def casa_accepts_caption(value):
    return (isinstance(value, str) and len(value) <= casa_broker.MAX_CAPTION_CHARS
            and value.isprintable() and "://" not in value.lower()
            and "www." not in value.lower())


def casa_accepts_label(value):
    return (isinstance(value, str) and len(value) <= casa_broker.MAX_LABEL_CHARS
            and value.isprintable() and "://" not in value.lower()
            and "www." not in value.lower()
            and not casa_broker.DOMAINISH_RE.search(value))


NASTY = [
    "", "Rabobank", "ING Bank N.V.", "ABN AMRO Bank N.V.",
    "https://evil.example/login", "Visit www.evil.example now",
    "WWW.EVIL", "wwww..x", "www.www.www.", ":://", "a:" + "/" * 5 + "b",
    "line one\nline two", "tab\tand\rreturn", "zero​width", "nul\x00byte",
    "bell\x07", " separator ", "x" * 500, "é" * 300,
    "Bank " + ".x" * 100, "trailing dot.", ". leading", "a.B.c.D",
    "emoji \U0001F3E6 bank", "  spaced   out  ",
    # A removed character joins its neighbours: sanitising first and removing
    # dots after would rebuild `://` and `www.` from these.
    "Bank:.//", "Bank:/./", "w.ww.x", "www..x", ":.:.//.//", "ww.w.evil",
]


class FitTests(unittest.TestCase):
    def test_every_label_casa_is_given_is_one_it_accepts(self):
        for prefix in ("Approve at ", "Whitelist at "):
            for name in NASTY:
                with self.subTest(prefix=prefix, name=name[:30]):
                    label = casa_broker.fit_label(prefix, name)
                    self.assertTrue(casa_accepts_label(label), repr(label))
                    self.assertTrue(label.startswith(prefix))

    def test_every_caption_casa_is_given_is_one_it_accepts(self):
        for text in NASTY + [n + ", NL, personal — one-time link" for n in NASTY]:
            for limit in (casa_broker.MAX_CAPTION_CHARS, 60, 8):
                with self.subTest(text=text[:30], limit=limit):
                    caption = casa_broker.fit_caption(text, limit)
                    self.assertTrue(casa_accepts_caption(caption), repr(caption))
                    self.assertLessEqual(len(caption), limit)

    def test_an_ordinary_name_is_left_as_it_is(self):
        self.assertEqual(casa_broker.fit_label("Approve at ", "Rabobank"),
                         "Approve at Rabobank")
        self.assertEqual(casa_broker.fit_label("Approve at ", "ING Bank N.V."),
                         "Approve at ING Bank NV")
        self.assertEqual(casa_broker.fit_caption("Rabobank, NL, personal"),
                         "Rabobank, NL, personal")

    def test_a_long_name_is_clipped_and_marked_never_silently_cut(self):
        label = casa_broker.fit_label("Approve at ", "x" * 100)
        self.assertEqual(len(label), casa_broker.MAX_LABEL_CHARS)
        self.assertTrue(label.endswith("…"))

    def test_the_rules_this_file_spells_refuse_what_casa_refuses(self):
        # Controls: without them, a predicate that accepted everything would
        # pass both fit tests above.
        for bad in ("x" * 41, "a\nb", "see https://x", "www.x", "Bank N.V"):
            self.assertFalse(casa_accepts_label(bad), bad)
        for bad in ("x" * 201, "a\nb", "https://x", "go to www.x"):
            self.assertFalse(casa_accepts_caption(bad), bad)
        self.assertTrue(re.fullmatch(r"[^.]*", casa_broker.fit_label("A ", "b.c.d")))


if __name__ == "__main__":
    unittest.main()
