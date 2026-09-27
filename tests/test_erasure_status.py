"""`delete_all_data` is bank-feed's `casa.eraseTool`: when it runs to the end it
returns `{"erasure": "complete" | "incomplete", "report": <the prose>}`, and
casa removes the plugin at uninstall only on `complete`. So `complete` must mean
nothing it holds remains and every consent it tried to withdraw was confirmed
withdrawn; every other outcome of the call is `incomplete`. A refusal before
the erasure ran stays prose, which casa reads as not complete."""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from _toolbase import call, rate_limited  # noqa: E402  (puts the server on the path)
import backups  # noqa: E402
import bank_feed_server  # noqa: E402
import tools_destructive  # noqa: E402
from test_tools_destructive import Boom, DestructiveBase  # noqa: E402


class TestErasureStatus(DestructiveBase):
    def erase(self):
        out = tools_destructive.delete_all_data({})
        self.assertIsInstance(out, dict)
        self.assertEqual(set(out), {"erasure", "report"})
        self.assertIsInstance(out["report"], str)
        return out

    def test_a_clean_erasure_is_complete(self):
        self.session()
        self.account()
        self.tx()
        out = self.erase()
        self.assertEqual(out["erasure"], "complete")
        self.assertIn("Done.", out["report"])
        self.assertEqual(self.count("sessions"), 0)

    def test_a_consent_the_bank_would_not_withdraw_is_incomplete(self):
        self.session()
        self.ais.raise_on_delete = rate_limited(120)
        out = self.erase()
        self.assertEqual(out["erasure"], "incomplete")
        self.assertIn("NOT FULLY ERASED, DELIBERATELY", out["report"])
        self.assertEqual(self.count("sessions"), 1)

    def test_a_withdrawal_pass_that_came_apart_is_incomplete(self):
        self.session()
        with mock.patch.object(tools_destructive, "_withdraw_open_consents",
                               side_effect=Boom("record write failed")):
            out = self.erase()
        self.assertEqual(out["erasure"], "incomplete")

    def test_an_unfinished_reclaim_is_incomplete(self):
        """Design r1 (Astra): with the WAL held, a session id survives in
        `-wal` though every row is gone — the reclaim's own verdict decides."""
        self.session()
        self.break_vacuum()
        out = self.erase()
        self.assertEqual(out["erasure"], "incomplete")
        self.assertEqual(self.count("sessions"), 0)

    def test_a_backup_sweep_that_stopped_is_incomplete(self):
        self.account()
        with mock.patch.object(backups, "erase_backups",
                               side_effect=backups.BackupError("disk")):
            out = self.erase()
        self.assertEqual(out["erasure"], "incomplete")
        self.assertIn("WARNING", out["report"])

    def test_a_second_sweep_that_left_a_copy_is_incomplete(self):
        """Diff r1 (Astra S2): a copy taken while the banks answered holds the
        destroyed session rows; when the second sweep cannot remove it, the
        erasure is not complete."""
        self.session()
        real = backups.erase_backups
        calls = []

        def erase_backups(*a, **kw):
            calls.append(1)
            if len(calls) == 2:
                raise backups.BackupError("EACCES")
            return real(*a, **kw)
        with mock.patch.object(backups, "erase_backups", side_effect=erase_backups):
            out = self.erase()
        self.assertEqual(len(calls), 2)          # the second sweep did run
        self.assertEqual(self.count("sessions"), 0)
        self.assertEqual(out["erasure"], "incomplete")

    def test_the_call_helper_reads_the_report(self):
        self.account()
        self.assertIn("Done.", call("delete_all_data"))

    def test_the_dispatcher_puts_its_sentences_in_the_report(self):
        """The reply casa reads is one JSON object whose report carries the
        dispatcher's own sentences too — they are part of the account."""
        self.account()
        real_close = backups.close_log

        def close_log(token):
            real_close(token)                  # the reset still happens
            return "SETTLEMENT SENTENCE"
        with mock.patch.object(bank_feed_server.backups, "close_log",
                               side_effect=close_log):
            resp = bank_feed_server.handle({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "delete_all_data", "arguments": {}}})
        body = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(set(body), {"erasure", "report"})
        self.assertTrue(body["report"].startswith("SETTLEMENT SENTENCE\n"))
        self.assertNotIn("isError", resp["result"])
        self.assertIsNone(backups._LOG.get())


if __name__ == "__main__":
    unittest.main()
