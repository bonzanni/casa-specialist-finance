"""`delete_all_data` as the clean slate (issue #72): once no consent is left to
withdraw it removes the published exports, the vault items bank-feed created
and everything in the ledger that links it to its past, and it answers
`complete` only when all of that happened. Plus the lifecycle lock that keeps
every other call out while it runs."""
import fcntl
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))

import backups  # noqa: E402
import bank_feed_server  # noqa: E402
import opvault  # noqa: E402
import store  # noqa: E402
import tools_auth  # noqa: E402
import tools_backup  # noqa: E402,F401  (registers backup)
import tools_destructive  # noqa: E402
import tools_refresh  # noqa: E402,F401  (registers export_history)
from _toolbase import SESSION_ID, Base, call, dispatch  # noqa: E402
from test_tools_destructive import PickyAIS, rate_limited  # noqa: E402


class CleanSlateBase(Base):
    def exports(self):
        pdir = self.handoff / tools_destructive.EXPORT_PRODUCER
        return sorted(p.name for p in pdir.iterdir()) if pdir.exists() else []

    def erase(self):
        out = call("delete_all_data")
        return out, out.result["erasure"]


class TestTheCleanSlate(CleanSlateBase):
    def test_exports_go_and_are_counted(self):
        self.account()
        self.tx()
        call("export_history", format="csv")
        call("export_history", format="jsonl")
        self.assertEqual(len(self.exports()), 2)
        out, verdict = self.erase()
        self.assertEqual(self.exports(), [])
        self.assertFalse((self.handoff / "bank-feed").exists())
        self.assertIn("2 export file(s)", out)
        self.assertEqual(verdict, "complete")

    def test_another_producers_files_are_never_touched(self):
        other = self.handoff / "gmail" / "x"
        other.mkdir(parents=True)
        (other / "f.txt").write_text("keep")
        self.erase()
        self.assertEqual((other / "f.txt").read_text(), "keep")

    def test_an_export_that_cannot_be_removed_makes_it_incomplete(self):
        pdir = self.handoff / "bank-feed"
        pdir.mkdir()
        (pdir / "1234567890123-0123456789abcdef").mkdir()
        original = tools_destructive.shutil.rmtree

        def refuse(path, *a, **k):
            raise PermissionError(13, "Permission denied")
        tools_destructive.shutil.rmtree = refuse
        self.addCleanup(setattr, tools_destructive.shutil, "rmtree", original)
        out, verdict = self.erase()
        self.assertIn("removal of the published exports did not finish", out)
        self.assertEqual(verdict, "incomplete")

    def test_the_vault_items_bank_feed_created_are_deleted_and_named(self):
        self.vault.erase_gone = ["EnableBanking Key", "EnableBanking"]
        out, verdict = self.erase()
        self.assertEqual(self.vault.erase_calls, 1)
        self.assertIn("Deleted from 1Password, as items bank-feed created: "
                      "EnableBanking Key, EnableBanking.", out)
        self.assertNotIn("nothing here records bank-feed creating", out)
        self.assertEqual(verdict, "complete")

    def test_a_vault_item_it_could_not_delete_makes_it_incomplete(self):
        self.vault.erase_kept = [("EnableBanking Key", "no permission")]
        out, verdict = self.erase()
        self.assertIn("were NOT deleted: EnableBanking Key (no permission)",
                      out)
        self.assertEqual(verdict, "incomplete")

    def test_unrecorded_items_are_named_and_do_not_block_completion(self):
        # An item nothing records bank-feed creating is never deleted, is
        # named for deletion by hand, and does not make the answer
        # `incomplete`: nothing can tell it from one the operator made, and
        # failing on it would keep an uninstall from ever finishing.
        out, verdict = self.erase()
        self.assertIn("any 1Password item titled 'EnableBanking Key' or "
                      "'EnableBanking'", out)
        self.assertEqual(verdict, "complete")

    def test_no_autoincrement_counter_survives(self):
        # VACUUM keeps `sqlite_sequence`, so without the reset the next rule
        # of a "fresh" ledger would be #2 — allocation history of the erased
        # install.
        self.raw.execute(
            "INSERT INTO sqlite_sequence(name, seq) VALUES ('tag_rules', 7)")
        _, verdict = self.erase()
        self.assertEqual(
            self.raw.execute("SELECT COUNT(*) FROM sqlite_sequence").fetchone()[0],
            0)
        self.assertEqual(verdict, "complete")

    def test_the_answer_names_what_no_tool_can_erase(self):
        out, _ = self.erase()
        self.assertIn(tools_destructive._NOT_ERASABLE, out)

    def test_the_index_backups_and_snapshots_go(self):
        call("backup", reason="manual")
        paths = backups.paths_for(self.root / "f.sqlite")
        snap = self.root / (paths.snapshot_prefix + "5-20260101T000000Z")
        snap.write_bytes(b"x")
        self.assertTrue(paths.index.exists())
        _, verdict = self.erase()
        self.assertFalse(paths.index.exists())
        self.assertFalse(paths.backups_dir.exists())
        self.assertFalse(snap.exists())
        self.assertTrue((self.root / "f.sqlite").exists())   # reset in place
        self.assertEqual(verdict, "complete")

    def test_the_other_modes_orphans_go(self):
        other = store._other_db_filename()
        for name in (other + "-wal", other + ".backup-index"):
            (self.root / name).write_bytes(b"x")
        (self.root / (other + ".backups")).mkdir()
        _, verdict = self.erase()
        self.assertEqual([p for p in os.listdir(self.root)
                          if p.startswith(other)], [])
        self.assertEqual(verdict, "complete")

    def test_the_other_modes_ledger_itself_is_never_removed(self):
        # It can hold consents, and only that mode can withdraw them.
        other = self.root / store._other_db_filename()
        other.write_bytes(b"x")
        out, verdict = self.erase()
        self.assertTrue(other.exists())
        self.assertIn("run delete_all_data in that mode", out)
        self.assertEqual(verdict, "incomplete")


class TestNoCleanSlateWhileAConsentIsHeld(CleanSlateBase):
    """The vault half deletes the private key and the ledger half the app id:
    both are what a retry of the withdrawal needs."""

    def setUp(self):
        super().setUp()
        tools_auth._meta_set(self.raw, "setup.app_id", "app-in-meta")
        self.account()
        self.tx()
        call("export_history", format="csv")
        call("backup", reason="manual")
        self.session()
        self.ais = PickyAIS(failures={SESSION_ID: rate_limited(120)})

    def test_nothing_of_the_third_phase_runs(self):
        secret = store.local_secret(self.raw)
        out, verdict = self.erase()
        self.assertEqual(verdict, "incomplete")
        self.assertEqual(getattr(self.vault, "erase_calls", 0), 0)
        self.assertEqual(len(self.exports()), 1)
        self.assertEqual(tools_auth._meta_get(self.raw, "setup.app_id"),
                         "app-in-meta")
        self.assertEqual(store.local_secret(self.raw), secret)
        self.assertTrue(backups.paths_for(self.root / "f.sqlite").index.exists())
        self.assertIn("application id was kept", out)

    def test_a_retry_that_withdraws_it_finishes_the_clean_slate(self):
        self.erase()
        self.ais = PickyAIS()
        out, verdict = self.erase()
        self.assertEqual(verdict, "complete")
        self.assertEqual(self.exports(), [])
        self.assertIsNone(tools_auth._meta_get(self.raw, "setup.app_id"))
        self.assertEqual(self.vault.erase_calls, 1)


class TestTheLifecycleLock(CleanSlateBase):
    def setUp(self):
        super().setUp()
        self.addCleanup(setattr, bank_feed_server, "LOCK_WAIT_S",
                        bank_feed_server.LOCK_WAIT_S)
        bank_feed_server.LOCK_WAIT_S = 0.2

    def hold(self, how):
        fd = os.open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, how)
        return fd

    def test_a_running_call_makes_the_erasure_refuse_with_nothing_done(self):
        self.account()
        self.tx()
        self.hold(fcntl.LOCK_SH)             # another process mid-call
        out = dispatch("delete_all_data")
        self.assertIn("Refused, nothing was done", out)
        self.assertEqual(self.count("transactions"), 1)

    def test_a_running_erasure_makes_an_export_refuse(self):
        self.account()
        self.tx()
        self.hold(fcntl.LOCK_EX)             # an erasure mid-call
        out = dispatch("export_history", format="csv")
        self.assertIn("an erasure of all data", out)
        self.assertEqual(self.exports(), [])

    def test_a_data_directory_not_there_yet_is_created_and_locked(self):
        # The first call ever creates the ledger: it must hold the lock too,
        # or an erasure could run beside it.
        fresh = self.root / "fresh"
        seen = {}
        tool = bank_feed_server.TOOLS["consent_status"]
        original = tool["fn"]
        tool["fn"] = lambda args: seen.setdefault("fds", opvault.INHERIT_FDS) and "ok"
        self.addCleanup(tool.__setitem__, "fn", original)
        dispatch("consent_status", data_dir=fresh)
        self.assertTrue(fresh.is_dir())
        self.assertEqual(len(seen["fds"]), 1)

    def test_the_raw_path_is_the_one_locked(self):
        # A directory whose name ends in a space is a real directory; a lock
        # on the stripped spelling would lock nothing the ledger uses.
        spaced = self.root / "data "
        spaced.mkdir()
        fd = os.open(str(spaced), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.assertIn("Refused, nothing was done",
                      dispatch("consent_status", data_dir=spaced))

    def test_ordinary_calls_share_it(self):
        self.hold(fcntl.LOCK_SH)
        self.assertNotIn("Refused", dispatch("consent_status"))

    def test_the_call_holds_it_and_hands_it_to_every_op_child(self):
        seen = {}
        tool = bank_feed_server.TOOLS["consent_status"]
        original = tool["fn"]

        def probe(args):
            seen["fds"] = opvault.INHERIT_FDS
            fd = os.open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                seen["held"] = False
            except BlockingIOError:
                seen["held"] = True
            finally:
                os.close(fd)
            return "ok"
        tool["fn"] = probe
        self.addCleanup(tool.__setitem__, "fn", original)
        dispatch("consent_status")
        self.assertEqual(len(seen["fds"]), 1)
        self.assertTrue(seen["held"])
        self.assertEqual(opvault.INHERIT_FDS, ())

    def test_the_erasure_holds_it_exclusively(self):
        seen = {}
        tool = bank_feed_server.TOOLS["delete_all_data"]
        original = tool["fn"]

        def probe(args):
            fd = os.open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                seen["shared_ok"] = True
            except BlockingIOError:
                seen["shared_ok"] = False
            finally:
                os.close(fd)
            return "ok"
        tool["fn"] = probe
        self.addCleanup(tool.__setitem__, "fn", original)
        dispatch("delete_all_data")
        self.assertFalse(seen["shared_ok"])


if __name__ == "__main__":
    unittest.main()
