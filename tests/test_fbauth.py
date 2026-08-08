import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
import fbauth   # noqa: E402
import httpx    # noqa: E402

FROZEN = 1_800_000_000.0

# A code shaped the way Firebase really shapes them (URL-safe base64).
CODE = "hDSGgqOc8W1oaWJqTEV0X2ZLpwFsSt1kBRTuJ9uNnQAAAGWpQxXQzA"
LINK = ("https://enablebanking.com/__/auth/action?mode=signIn&oobCode="
        + CODE + "&apiKey=" + fbauth.API_KEY
        + "&continueUrl=https%3A%2F%2Fenablebanking.com%2Fcp%2F&lang=en")


class StubClient:
    """Replays responses but runs the REAL allowlist first, so a test can
    never exercise a path production would refuse."""

    def __init__(self, real, responses):
        self.real, self.responses, self.calls = real, list(responses), []

    def request(self, method, path, **kw):
        self.real._check(method, path)
        self.calls.append((method, path, kw))
        return self.responses.pop(0)


class Base(unittest.TestCase):
    def idtk(self, *responses):
        stub = StubClient(httpx.Client(fbauth.IDTK_HOST, fbauth.IDTK_ALLOW),
                          responses)
        self.addCleanup(setattr, fbauth, "_idtk", fbauth._idtk)
        fbauth._idtk = lambda: stub
        return stub

    def token_client(self, *responses):
        stub = StubClient(httpx.Client(fbauth.TOKEN_HOST, fbauth.TOKEN_ALLOW),
                          responses)
        self.addCleanup(setattr, fbauth, "_token_client",
                        fbauth._token_client)
        fbauth._token_client = lambda: stub
        return stub

    def freeze(self, at=FROZEN):
        self.addCleanup(setattr, fbauth, "_now", fbauth._now)
        fbauth._now = lambda: at


class TestSendSigninEmail(Base):
    def test_posts_the_email_signin_request(self):
        stub = self.idtk((200, b'{"kind":"x","email":"me@example.com"}'))
        fbauth.send_signin_email("me@example.com")
        method, path, kw = stub.calls[0]
        self.assertEqual(path, "/v1/accounts:sendOobCode?key=" + fbauth.API_KEY)
        self.assertEqual(kw["json_body"],
                         {"requestType": "EMAIL_SIGNIN",
                          "email": "me@example.com",
                          "continueUrl": fbauth.CONTINUE_URL})

    def test_a_firebase_error_surfaces_its_code_only(self):
        self.idtk((400, json.dumps(
            {"error": {"message": "QUOTA_EXCEEDED : too many"}}).encode()))
        with self.assertRaises(fbauth.AuthError) as ctx:
            fbauth.send_signin_email("me@example.com")
        self.assertEqual(ctx.exception.code, "QUOTA_EXCEEDED")
        self.assertNotIn("me@example.com", str(ctx.exception))


class TestParseSigninLink(Base):
    def test_extracts_the_code_from_a_full_link(self):
        self.assertEqual(fbauth.parse_signin_link(LINK), CODE)

    def test_accepts_a_bare_code(self):
        self.assertEqual(fbauth.parse_signin_link(" " + CODE + "\n"), CODE)

    def test_a_defanged_link_is_refused_with_the_copy_instruction(self):
        # One shape a mail connector's defang takes: `=` rewritten to `~`.
        mangled = LINK.replace("oobCode=" + CODE,
                               "oobCode=" + CODE[3:] + "~x")
        with self.assertRaises(fbauth.DefangedLink) as ctx:
            fbauth.parse_signin_link(mangled)
        self.assertIn("mail client", str(ctx.exception))

    def test_a_url_without_a_code_is_refused(self):
        with self.assertRaises(fbauth.DefangedLink):
            fbauth.parse_signin_link("https://enablebanking.com/cp/?lang=en")


class TestExchangeLink(Base):
    def test_redeems_the_code_for_the_refresh_token(self):
        stub = self.idtk((200, json.dumps(
            {"refreshToken": "rt-1", "idToken": "it-1"}).encode()))
        self.assertEqual(fbauth.exchange_link("me@example.com", CODE), "rt-1")
        _, path, kw = stub.calls[0]
        self.assertEqual(path,
                         "/v1/accounts:signInWithEmailLink?key=" + fbauth.API_KEY)
        self.assertEqual(kw["json_body"],
                         {"email": "me@example.com", "oobCode": CODE})

    def test_an_expired_code_surfaces_as_its_firebase_code(self):
        self.idtk((400, json.dumps(
            {"error": {"message": "EXPIRED_OOB_CODE"}}).encode()))
        with self.assertRaises(fbauth.AuthError) as ctx:
            fbauth.exchange_link("me@example.com", CODE)
        self.assertEqual(ctx.exception.code, "EXPIRED_OOB_CODE")

    def test_the_error_never_carries_the_code_or_a_token(self):
        self.idtk((400, json.dumps(
            {"error": {"message": "INVALID_OOB_CODE"}}).encode()))
        try:
            fbauth.exchange_link("me@example.com", CODE)
        except fbauth.AuthError as exc:
            self.assertNotIn(CODE, str(exc))

    def test_a_hostile_error_message_cannot_leak_what_we_submitted(self):
        # error.message is provider-controlled and may echo the submitted code
        # (or a token) back at us — and callers interpolate AuthError.code into
        # tool output. Only a SCREAMING_SNAKE-shaped token survives; a canned
        # INVALID_OOB_CODE response could never exercise this.
        self.idtk((400, json.dumps(
            {"error": {"message": CODE + " : malformed"}}).encode()))
        with self.assertRaises(fbauth.AuthError) as ctx:
            fbauth.exchange_link("me@example.com", CODE)
        self.assertEqual(ctx.exception.code, "PROVIDER_ERROR")
        self.assertNotIn(CODE, str(ctx.exception))

    def test_an_all_caps_submitted_code_still_cannot_echo_back(self):
        # An oobCode of AAAA… is valid input AND SCREAMING_SNAKE-shaped, so the
        # shape gate alone would pass a provider echo of it. The VALUE gate
        # bans the submitted secret itself, whatever its shape.
        allcaps = "A" * 24
        self.idtk((400, json.dumps(
            {"error": {"message": allcaps + " : malformed"}}).encode()))
        with self.assertRaises(fbauth.AuthError) as ctx:
            fbauth.exchange_link("me@example.com", allcaps)
        self.assertEqual(ctx.exception.code, "PROVIDER_ERROR")
        self.assertNotIn(allcaps, str(ctx.exception))

    def test_a_truncated_echo_of_the_secret_is_still_banned(self):
        # The provider echoes only the first 40 chars of a 64-char all-caps
        # code. The fragment passes the shape gate, and the full secret is not
        # "in" its own prefix — so the value gate must cut BOTH ways: a code
        # that is a substring of a submitted secret is banned too.
        allcaps = "A" * 24 + "B" * 40                    # 64 chars, valid
        self.idtk((400, json.dumps(
            {"error": {"message": allcaps[:40] + " : malformed"}}).encode()))
        with self.assertRaises(fbauth.AuthError) as ctx:
            fbauth.exchange_link("me@example.com", allcaps)
        self.assertEqual(ctx.exception.code, "PROVIDER_ERROR")
        self.assertNotIn(allcaps[:40], str(ctx.exception))


class TestMintIdToken(Base):
    def test_is_form_encoded_against_securetoken(self):
        stub = self.token_client((200, json.dumps(
            {"id_token": "id-1.a.b", "expires_in": "3600"}).encode()))
        token, ttl = fbauth.mint_id_token("rt-1")
        self.assertEqual((token, ttl), ("id-1.a.b", 3600.0))
        _, path, kw = stub.calls[0]
        self.assertEqual(path, "/v1/token?key=" + fbauth.API_KEY)
        self.assertEqual(kw["form_body"],
                         {"grant_type": "refresh_token",
                          "refresh_token": "rt-1"})

    def test_a_malformed_expires_in_cannot_carry_provider_text(self):
        # float() over a malformed TTL raises a ValueError whose message
        # CONTAINS the provider-controlled value. The TTL falls back to
        # Firebase's fixed term instead.
        self.token_client((200, json.dumps(
            {"id_token": "id-1.a.b",
             "expires_in": "rt-1 : echoed back"}).encode()))
        token, ttl = fbauth.mint_id_token("rt-1")
        self.assertEqual((token, ttl), ("id-1.a.b", 3600.0))

    def test_a_revoked_token_is_its_firebase_code(self):
        self.token_client((400, json.dumps(
            {"error": {"message": "INVALID_REFRESH_TOKEN"}}).encode()))
        with self.assertRaises(fbauth.AuthError) as ctx:
            fbauth.mint_id_token("rt-1")
        self.assertEqual(ctx.exception.code, "INVALID_REFRESH_TOKEN")
        self.assertNotIn("rt-1", str(ctx.exception))

    def test_a_hostile_id_token_is_refused_and_never_leaks(self):
        # A provider response is a CLAIM, not a fact. A malformed id_token
        # carrying a control character later blows up urllib's header
        # construction (`Authorization: Bearer <token>`), and
        # bank_feed_server's generic renderer would put that ValueError's text
        # — the token fragment included — into tool output. The shape gate
        # closes this at the boundary: reject anything that is not exactly
        # three non-empty base64url segments, before it ever reaches a header.
        hostile = "aaa.bbb.SECRET\nX-Leak: yes"
        self.token_client((200, json.dumps(
            {"id_token": hostile, "expires_in": "3600"}).encode()))
        with self.assertRaises(fbauth.AuthError) as ctx:
            fbauth.mint_id_token("rt-1")
        self.assertEqual(ctx.exception.code, "MALFORMED_ID_TOKEN_IN_RESPONSE")
        self.assertNotIn("SECRET", str(ctx.exception))
        self.assertNotIn("X-Leak", str(ctx.exception))
        self.assertNotIn("\n", str(ctx.exception))

    def test_a_hostile_id_token_with_trailing_newline_is_refused(self):
        # `$` in Python's re matches at the end of the string OR just
        # before a trailing newline — so a pattern anchored with `$` and
        # checked via .match() lets "aaa.bbb.SECRET\n" through even
        # though it is not exactly three base64url segments. .fullmatch()
        # does not have this hole. Confirmed live: _ID_TOKEN_RX.match()
        # returns a Match object on this input; .fullmatch() returns
        # None.
        hostile = "aaa.bbb.SECRET\n"
        self.token_client((200, json.dumps(
            {"id_token": hostile, "expires_in": "3600"}).encode()))
        with self.assertRaises(fbauth.AuthError) as ctx:
            fbauth.mint_id_token("rt-1")
        self.assertEqual(ctx.exception.code, "MALFORMED_ID_TOKEN_IN_RESPONSE")
        self.assertNotIn("SECRET", str(ctx.exception))

    def test_a_well_shaped_three_segment_token_still_passes(self):
        # The gate must not be so tight it breaks the real shape.
        stub = self.token_client((200, json.dumps(
            {"id_token": "aaa.bbb.ccc", "expires_in": "3600"}).encode()))
        token, ttl = fbauth.mint_id_token("rt-1")
        self.assertEqual((token, ttl), ("aaa.bbb.ccc", 3600.0))
        self.assertEqual(len(stub.calls), 1)


class TestMinter(Base):
    def test_caches_until_five_minutes_before_expiry(self):
        self.freeze()
        self.token_client((200, b'{"id_token":"id-1.a.b","expires_in":"3600"}'),
                          (200, b'{"id_token":"id-2.a.b","expires_in":"3600"}'))
        reads = []

        def read_refresh():
            reads.append(1)
            return "rt-1"

        minter = fbauth.Minter(read_refresh)
        self.assertEqual(minter.token(), "id-1.a.b")
        self.assertEqual(minter.token(), "id-1.a.b")       # cached
        self.assertEqual(len(reads), 1)
        fbauth._now = lambda: FROZEN + 3600 - 299         # inside the skew
        self.assertEqual(minter.token(), "id-2.a.b")       # re-minted
        self.assertEqual(len(reads), 2)                   # re-READ too

    def test_invalidate_forces_a_fresh_mint(self):
        self.freeze()
        self.token_client((200, b'{"id_token":"id-1.a.b","expires_in":"3600"}'),
                          (200, b'{"id_token":"id-2.a.b","expires_in":"3600"}'))
        minter = fbauth.Minter(lambda: "rt-1")
        self.assertEqual(minter.token(), "id-1.a.b")
        minter.invalidate()
        self.assertEqual(minter.token(), "id-2.a.b")


if __name__ == "__main__":
    unittest.main()
