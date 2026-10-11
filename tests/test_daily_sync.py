# tests/test_daily_sync.py
"""Issue #110: the daily background sync.

`daily_sync` refreshes every linked bank and hands casa one notice only when
a bank needs the operator: its consent is gone or expired (re-link), or its
routine sync has failed for days. A good day and a transient failure post
nothing. The notice carries casa's delivery key, the same for the same
findings, so casa posts it once.
"""
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import bank_feed_server  # noqa: E402
import casa_broker  # noqa: E402
import eb_ais  # noqa: E402
import tools_auth  # noqa: E402
import tools_refresh  # noqa: E402
from _toolbase import (FROZEN_NOW, SESSION_ID, call, iso_at)  # noqa: E402
from test_consent_refused import OTHER_SESSION, RefusedBase  # noqa: E402

REF = "casa-cap-" + "ab" * 16


class Base(RefusedBase):
    def setUp(self):
        super().setUp()
        self.notices = []                 # (slot, text, key)
        self.refuse_code = None

        def deposit(slot, text, *, key):
            if self.refuse_code is not None:
                raise casa_broker.DepositFailed(self.refuse_code)
            self.notices.append((slot, text, key))
            return REF
        self.addCleanup(setattr, tools_refresh, "DEPOSIT_MESSAGE",
                        tools_refresh.DEPOSIT_MESSAGE)
        tools_refresh.DEPOSIT_MESSAGE = deposit
        self.day = 0

    def daily(self):
        # Every run is the next day, as the schedule runs it: the 15-minute
        # cooldown of an automatic refresh is not what these tests are about.
        self.day += 1
        tools_auth._now_s = lambda d=self.day: FROZEN_NOW + d * 86400
        out = call("daily_sync")
        self.assertIsInstance(out, str)
        return out

    def first_failed(self, aid, seconds_ago):
        key = tools_auth.sync_health_key(aid)
        record = json.loads(self.raw.execute(
            "SELECT value FROM meta WHERE key=?", (key,)).fetchone()[0])
        # Measured from the NEXT run, which is a day later.
        record["fail"]["first"] = iso_at(
            tools_auth._now_s() + 86400 - seconds_ago)
        self.raw.execute("UPDATE meta SET value=? WHERE key=?",
                         (json.dumps(record), key))


class TestAGoodDayIsSilent(Base):
    def test_every_linked_bank_is_refreshed_and_nothing_is_posted(self):
        self.session()
        self.session(sid=OTHER_SESSION, aspsp="ING")
        self.account("acc1")
        self.account("acc2", session_id=OTHER_SESSION)
        out = self.daily()
        self.assertIsNone(out.result["notice"])
        self.assertEqual(self.notices, [])
        self.assertEqual(sorted(c[0] for c in self.ais.tx_calls),
                         ["uid-acc1", "uid-acc2"])
        self.assertEqual(self.ais.balance_calls, 2)
        self.assertIn("4 refresh(es) done", out)

    def test_an_unlinked_excluded_or_closed_account_is_left_alone(self):
        self.session()
        self.session(sid=OTHER_SESSION, aspsp="ING")
        self.raw.execute("UPDATE sessions SET closed_at='2026-09-01T00:00:00Z'"
                         " WHERE session_id=?", (OTHER_SESSION,))
        self.account("unbound", session_id=None)
        self.account("excluded", included=0)
        self.account("closed", session_id=OTHER_SESSION)
        out = self.daily()
        self.assertEqual(self.ais.tx_calls, [])
        self.assertEqual(self.ais.balance_calls, 0)
        self.assertIsNone(out.result["notice"])
        self.assertEqual(self.notices, [])

    def test_a_transient_failure_posts_nothing(self):
        self.session()
        self.account()
        self.ais.failing["uid-acc1"] = eb_ais.ApiError(500, "transactions")
        out = self.daily()
        self.assertIn("1 failed", out)
        self.assertIsNone(out.result["notice"])
        self.ais.failing["uid-acc1"] = eb_ais.ApiError(401, "transactions")
        self.assertIsNone(self.daily().result["notice"])
        self.assertEqual(self.notices, [])

    def test_a_deferred_refresh_posts_nothing(self):
        self.session()
        self.account()
        # An in-turn sync holds the claim when the next run starts.
        tools_auth._now_s = lambda: FROZEN_NOW + 86400
        tools_auth.claim_refresh(self.raw, "acc1")
        out = self.daily()
        self.assertIn("2 deferred", out)
        self.assertEqual(self.ais.tx_calls, [])
        self.assertIsNone(out.result["notice"])

    def test_the_result_is_casas_no_post_shape_through_the_dispatcher(self):
        self.session()
        self.account()
        resp = bank_feed_server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "daily_sync", "arguments": {}}})
        self.assertNotIn("isError", resp["result"])
        body = json.loads(resp["result"]["content"][0]["text"])
        self.assertIn("notice", body)
        self.assertIsNone(body["notice"])


class TestABankThatNeedsTheOperatorIsNamedOnce(Base):
    def test_a_consent_the_bank_ended_is_named_on_the_first_refusal(self):
        self.session()
        self.session(sid=OTHER_SESSION, aspsp="ING")
        self.account("acc1")
        self.account("acc2", session_id=OTHER_SESSION)
        self.refuse("acc1", code="EXPIRED_SESSION")
        out = self.daily()
        self.assertEqual(out.result["notice"], REF)
        self.assertEqual(len(self.notices), 1)
        slot, text, key = self.notices[0]
        self.assertEqual(slot, "notice")
        self.assertIn("Rabobank", text)
        self.assertIn("EXPIRED", text)
        self.assertIn("re-link Rabobank", text)
        self.assertNotIn("ING", text)
        self.assertRegex(key, r"^daily-sync:[0-9a-f]{16}$")

    def test_the_same_finding_carries_the_same_key_every_day(self):
        self.session()
        self.account()
        self.refuse(code="REVOKED_SESSION")
        self.daily()
        self.daily()
        self.daily()
        self.assertEqual(len({n[2] for n in self.notices}), 1, self.notices)
        self.assertEqual(len(self.notices), 3)

    def test_a_new_finding_is_a_new_key(self):
        self.session()
        self.session(sid=OTHER_SESSION, aspsp="ING")
        self.account("acc1")
        self.account("acc2", session_id=OTHER_SESSION)
        self.refuse("acc1", code="CLOSED_SESSION")
        self.daily()
        self.refuse("acc2", code="EXPIRED_SESSION")
        self.daily()
        first, second = self.notices
        self.assertNotEqual(first[2], second[2])
        self.assertIn("ING", second[1])
        self.assertIn("Rabobank", second[1])

    def test_the_providers_gone_status_is_named(self):
        # A refusal without a code: the #100 check asks after the second one.
        self.session()
        self.account()
        self.refuse(code=None)
        self.assertIsNone(self.daily().result["notice"])
        out = self.daily()
        self.assertEqual(out.result["notice"], REF)
        self.assertIn("EXPIRED", self.notices[0][1])

    def test_a_consent_whose_validity_passed_needs_relinking(self):
        self.session(days=-2)
        self.account()
        self.daily()
        self.assertEqual(len(self.notices), 1)
        self.assertIn("expired", self.notices[0][1])
        self.assertIn("re-link Rabobank", self.notices[0][1])

    def test_a_sync_failing_for_days_is_named_once_per_streak(self):
        self.session()
        self.account()
        self.ais.failing["uid-acc1"] = eb_ais.ApiError(500, "transactions")
        self.daily()
        self.first_failed("acc1", tools_refresh.STALLED_AFTER_S - 60)
        self.daily()
        self.assertEqual(self.notices, [])
        self.first_failed("acc1", tools_refresh.STALLED_AFTER_S + 60)
        self.daily()
        self.daily()
        self.assertEqual(len(self.notices), 2)
        self.assertEqual(self.notices[0][2], self.notices[1][2])
        self.assertIn("hasn't updated since", self.notices[0][1])

    def test_nothing_is_posted_while_a_bank_is_being_relinked(self):
        self.session()
        self.account()
        self.refuse(code="EXPIRED_SESSION")
        self.raw.execute(
            "INSERT INTO attempts(state_hash, lease_token, lease_expiry,"
            " created_at) VALUES (?,?,?,?)",
            ("h" * 64, "t", FROZEN_NOW + 600, FROZEN_NOW))
        self.assertTrue(tools_auth.authorization_in_progress(self.raw))
        self.assertIsNone(self.daily().result["notice"])
        self.assertEqual(self.notices, [])

    def test_a_bank_name_cannot_format_the_message(self):
        self.session(aspsp="*Bank*_[x](y)")
        self.account()
        self.refuse(code="EXPIRED_SESSION")
        self.daily()
        text = self.notices[0][1]
        for ch in "*_[]":
            self.assertNotIn(ch, text)
        self.assertIn("Bankx(y)", text)

    def test_a_refused_deposit_is_a_tool_error(self):
        self.session()
        self.account()
        self.refuse(code="EXPIRED_SESSION")
        self.refuse_code = "no_call_in_flight"
        out = call("daily_sync")
        self.assertNotIsInstance(out, dict)
        self.assertFalse(hasattr(out, "result"))
        self.assertIn("no_call_in_flight", out)


class TestTheJobIsDeclared(unittest.TestCase):
    def test_the_job_is_quiet_hosted_on_the_specialist_and_has_its_skill(self):
        root = pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed"
        manifest = json.loads((root / ".claude-plugin/plugin.json").read_text())
        jobs = manifest["casa"]["jobs"]
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job["name"], "daily-sync")
        self.assertIs(job["quietWhenScheduled"], True)
        self.assertEqual(job["host"], "specialist")
        self.assertTrue((root / "skills" / job["skill"] / "SKILL.md").is_file())
        contract = manifest["casa"]["resultContract"]["tools"]["daily_sync"]
        self.assertEqual(contract["delivers"],
                         {tools_refresh.NOTICE_SLOT: "operator_message"})
        self.assertTrue(bank_feed_server.TOOLS["daily_sync"]["capability"])
        # Unattended, so it holds every other call out for its run (a renewal
        # completing under it would otherwise race its old-consent fetch).
        self.assertIn("daily_sync", bank_feed_server.EXCLUSIVE_TOOLS)


if __name__ == "__main__":
    unittest.main()
