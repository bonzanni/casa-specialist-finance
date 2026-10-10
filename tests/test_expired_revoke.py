# tests/test_expired_revoke.py
"""Issue #102: withdrawing a consent the provider already reports EXPIRED,
REVOKED or CLOSED is settled on the provider's word, with no operator step.

Enable Banking refuses the DELETE of such a session with a 401. On a 401/403
every revocation path asks `GET /sessions/{id}` once (`eb_ais.revocation_settled`);
a gone status closes the row, anything else keeps today's "not confirmed".
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import apply  # noqa: E402
import eb_ais  # noqa: E402
import flows  # noqa: E402
import tools_auth  # noqa: E402
import tools_destructive  # noqa: E402,F401  (registers unlink_bank & erasers)
from _toolbase import SESSION_ID, Base, FakeAIS, call  # noqa: E402


class StatusAIS(FakeAIS):
    def __init__(self):
        super().__init__()
        self.session_status = "EXPIRED"
        self.session_calls = []

    def get_session(self, sid):
        self.session_calls.append(sid)
        return {"status": self.session_status}


class ExpiredBase(Base):
    def setUp(self):
        super().setUp()
        self.ais = StatusAIS()

    def ref(self):
        return tools_auth._consent_ref(SESSION_ID)

    def row(self):
        return dict(self.raw.execute(
            "SELECT status, closed_at FROM sessions WHERE session_id=?",
            (SESSION_ID,)).fetchone())


class TestUnlinkAnExpiredConsent(ExpiredBase):
    def test_a_401_on_an_expired_session_is_settled_at_once(self):
        self.session()
        self.account()
        self.ais.raise_on_delete = eb_ais.ApiError(401, "delete_session")
        out = call("unlink_bank", consent_ref=self.ref())
        self.assertEqual(self.ais.session_calls, [SESSION_ID])
        self.assertIsNotNone(self.row()["closed_at"])
        self.assertNotEqual(self.row()["status"],
                            apply.OPERATOR_WITHDRAWN_STATUS)
        self.assertIn("reported by the provider as EXPIRED", out)
        self.assertNotIn("STILL LIVE", out)
        self.assertNotIn("withdrawn_at_bank", out)
        bound = self.raw.execute("SELECT session_id FROM accounts").fetchone()
        self.assertIsNone(bound[0])

    def test_revoked_and_closed_settle_too(self):
        for word in ("REVOKED", "CLOSED"):
            with self.subTest(word=word):
                self.raw.execute("DELETE FROM sessions")
                self.session()
                self.ais.session_status = word
                self.ais.raise_on_delete = eb_ais.ApiError(403, "delete_session")
                out = call("unlink_bank", consent_ref=self.ref())
                self.assertIn("reported by the provider as %s" % word, out)
                self.assertIsNotNone(self.row()["closed_at"])

    def test_a_session_the_provider_still_authorizes_is_not_settled(self):
        self.session()
        self.ais.session_status = "AUTHORIZED"
        self.ais.raise_on_delete = eb_ais.ApiError(401, "delete_session")
        out = call("unlink_bank", consent_ref=self.ref())
        self.assertIn("NOT revoked", out)
        self.assertIsNone(self.row()["closed_at"])
        self.assertEqual(self.row()["status"], apply.REVOKE_FAILED_STATUS)

    def test_an_unknown_answer_is_not_settled(self):
        for word in ("Gone, trust me", None, ["EXPIRED"]):
            with self.subTest(word=word):
                self.raw.execute("DELETE FROM sessions")
                self.session()
                self.ais.session_status = word
                self.ais.raise_on_delete = eb_ais.ApiError(401, "delete_session")
                out = call("unlink_bank", consent_ref=self.ref())
                self.assertIn("NOT revoked", out)
                self.assertNotIn("trust me", out)
                self.assertIsNone(self.row()["closed_at"])

    def test_other_failures_never_ask(self):
        self.session()
        self.ais.raise_on_delete = eb_ais.ApiError(500, "delete_session")
        call("unlink_bank", consent_ref=self.ref())
        self.ais.raise_on_delete = OSError("reset")
        call("unlink_bank", consent_ref=self.ref())
        self.assertEqual(self.ais.session_calls, [])
        self.assertIsNone(self.row()["closed_at"])

    def test_a_404_needs_no_question(self):
        self.session()
        self.ais.raise_on_delete = eb_ais.ApiError(404, "delete_session")
        call("unlink_bank", consent_ref=self.ref())
        self.assertEqual(self.ais.session_calls, [])
        self.assertIsNotNone(self.row()["closed_at"])


class TestAGoneSessionCode(ExpiredBase):
    """Issue #106: Enable Banking refuses the DELETE of a CLOSED session with
    HTTP 400 `CLOSED_SESSION`. The code itself names the session gone, on any
    status; a 400 without one of those codes asks `GET /sessions/{id}`."""

    def test_a_400_closed_session_is_settled_without_a_question(self):
        self.session()
        self.account()
        self.ais.session_status = "AUTHORIZED"       # the code decides, not this
        self.ais.raise_on_delete = eb_ais.ApiError(400, "delete_session",
                                                   "CLOSED_SESSION")
        out = call("unlink_bank", consent_ref=self.ref())
        self.assertEqual(self.ais.session_calls, [])
        self.assertIsNotNone(self.row()["closed_at"])
        self.assertNotEqual(self.row()["status"],
                            apply.OPERATOR_WITHDRAWN_STATUS)
        self.assertIn("reported by the provider as CLOSED", out)
        self.assertNotIn("STILL LIVE", out)
        self.assertNotIn("NOT revoked", out)
        self.assertNotIn("withdrawn_at_bank", out)
        bound = self.raw.execute("SELECT session_id FROM accounts").fetchone()
        self.assertIsNone(bound[0])

    def test_every_gone_code_settles_on_any_status(self):
        cases = [(400, "EXPIRED_SESSION", "EXPIRED"),
                 (401, "REVOKED_SESSION", "REVOKED"),
                 (403, "CLOSED_SESSION", "CLOSED")]
        for status, code, word in cases:
            with self.subTest(code=code):
                self.raw.execute("DELETE FROM sessions")
                self.session()
                self.ais.session_status = "AUTHORIZED"
                self.ais.raise_on_delete = eb_ais.ApiError(
                    status, "delete_session", code)
                out = call("unlink_bank", consent_ref=self.ref())
                self.assertIn("reported by the provider as %s" % word, out)
                self.assertIsNotNone(self.row()["closed_at"])

    def test_a_400_without_a_gone_code_asks_once(self):
        for code in (None, "WRONG_REQUEST_PARAMETERS"):
            for word, settles in (("CLOSED", True), ("AUTHORIZED", False)):
                with self.subTest(code=code, word=word):
                    self.raw.execute("DELETE FROM sessions")
                    self.session()
                    self.ais.session_calls = []
                    self.ais.session_status = word
                    self.ais.raise_on_delete = eb_ais.ApiError(
                        400, "delete_session", code)
                    out = call("unlink_bank", consent_ref=self.ref())
                    self.assertEqual(self.ais.session_calls, [SESSION_ID])
                    if settles:
                        self.assertIn("reported by the provider as CLOSED", out)
                        self.assertIsNotNone(self.row()["closed_at"])
                    else:
                        self.assertIn("NOT revoked", out)
                        self.assertIsNone(self.row()["closed_at"])

    def test_the_renewal_revoke_settles_a_closed_session(self):
        self.session()
        self.ais.raise_on_delete = eb_ais.ApiError(400, "delete_session",
                                                   "CLOSED_SESSION")
        ok, label = flows._revoke(self.raw, self.ais, SESSION_ID)
        self.assertTrue(ok)
        self.assertIsNone(label)
        self.assertIsNotNone(self.row()["closed_at"])

    def test_the_erasers_withdrawal_pass_settles_a_closed_session(self):
        self.session()
        self.ais.raise_on_delete = eb_ais.ApiError(400, "delete_session",
                                                   "CLOSED_SESSION")
        gone, kept = tools_destructive._withdraw_open_consents(self.raw)
        self.assertEqual([g["session_id"] for g in gone], [SESSION_ID])
        self.assertEqual(kept, [])


class TestTheOtherRevocationPaths(ExpiredBase):
    def test_the_renewal_revoke_settles_an_expired_session(self):
        self.session()
        self.ais.raise_on_delete = eb_ais.ApiError(401, "delete_session")
        ok, label = flows._revoke(self.raw, self.ais, SESSION_ID)
        self.assertTrue(ok)
        self.assertIsNone(label)
        self.assertIsNotNone(self.row()["closed_at"])

    def test_the_renewal_revoke_keeps_a_live_one_failed(self):
        self.session()
        self.ais.session_status = "AUTHORIZED"
        self.ais.raise_on_delete = eb_ais.ApiError(401, "delete_session")
        ok, _ = flows._revoke(self.raw, self.ais, SESSION_ID)
        self.assertFalse(ok)
        self.assertEqual(self.row()["status"], apply.REVOKE_FAILED_STATUS)

    def test_the_erasers_withdrawal_pass_uses_the_same_rule(self):
        self.session()
        self.ais.raise_on_delete = eb_ais.ApiError(401, "delete_session")
        gone, kept = tools_destructive._withdraw_open_consents(self.raw)
        self.assertEqual([g["session_id"] for g in gone], [SESSION_ID])
        self.assertEqual(kept, [])


if __name__ == "__main__":
    unittest.main()
