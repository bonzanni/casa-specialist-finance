"""Every settlement's work reaches a reply (issues #48, #53).

Settlement records what it writes into a log that lives for one dispatched
call, and the dispatcher renders it once, on every exit. These tests go through
`bank_feed_server.handle` — the only place the operator's reply is assembled —
and most start COLD, the way the first call of a process does: the ledger is
opened by the tool itself, and the open-time settlement runs inside that open.
"""
import ast
import json
import os
import pathlib
import re
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

SERVER = pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"
sys.path.insert(0, str(SERVER))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import backups  # noqa: E402
import store  # noqa: E402
import tools_backup  # noqa: E402  (registration side effect)
import tools_annotate  # noqa: E402  (registration side effect)
import tools_destructive  # noqa: E402  (registration side effect)
import tools_read  # noqa: E402
from _toolbase import call, dispatch  # noqa: E402

LEAD = "While settling the backup index, this call "
STATE = "When this call last released the backup index, "
ERASED_ONE = ("removed 1 backup copy; recorded the removal of 1 backup copy; "
              "recorded pending erasure abcdefabcdefabcd as complete.")


class Cold(unittest.TestCase):
    """A data directory whose ledger exists, with no connection open: the
    next dispatched call opens it, and settlement runs inside that open."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.data = pathlib.Path(self.dir.name)
        self.db = self.data / store.db_filename()
        self.paths = backups.paths_for(self.db)
        self.addCleanup(self._close)
        self._close()

    def _close(self):
        if tools_read.CONN is not None:
            tools_read.CONN.close()
        tools_read.CONN = None

    def warm(self):
        """Open the ledger as the process would, outside any dispatched
        call, so the open-time settlement records nothing."""
        tools_read.CONN = store.open_db(self.db)
        return tools_read.CONN

    def backups_taken(self, n):
        self.warm()
        ids = [call("backup", reason="manual").split()[1] for _ in range(n)]
        self._close()
        return ids

    def append_index(self, line):
        with open(self.paths.index, "a") as f:
            f.write("%s %s\n" % (backups.now_ts(), line))

    def index_lines(self):
        return self.paths.index.read_text().splitlines()


class TestTheOpenTimeSettlementIsReported(Cold):
    def test_a_read_that_opens_the_ledger_names_the_copies_it_removed(self):
        # Issue #48: a crash between delete_all_data's COMMIT and its sweep;
        # the first call of the next process is a read. It opens the ledger,
        # the open-time settlement finishes the sweep, and the reply used to
        # say nothing about the copy that went.
        [bid] = self.backups_taken(1)
        self.append_index("erase abcdefabcdefabcd pending")
        out = dispatch("list_accounts", data_dir=self.data)
        self.assertFalse(self.paths.backup_file(bid).exists())
        self.assertTrue(out.startswith(LEAD + ERASED_ONE + "\n"), out)
        # Said once: the next call in the same process has nothing to say.
        again = dispatch("list_accounts", data_dir=self.data)
        self.assertNotIn(LEAD, again)
        # And the log is gone with the call: a direct
        # call after it records into nothing, and its "nothing" is plain.
        self.assertIsNone(backups._LOG.get())

    def test_a_refusal_after_an_open_time_closure_does_not_say_nothing_changed(self):
        # Issue #53, reproduced as filed: a cold refusal after settlement
        # appended an `aborted` record. Index lines 2 -> 3, reply "Nothing was
        # changed.".
        self.backups_taken(1)
        self.append_index("backup 1111111111111111 pending reason=manual")
        before = len(self.index_lines())
        out = dispatch("add_note", data_dir=self.data, row_ids=[999],
                       note="x", author="agent")
        self.assertEqual(len(self.index_lines()), before + 1)
        self.assertTrue(out.startswith(
            LEAD + "recorded interrupted backup 1111111111111111 as "
            "aborted.\n"), out)
        self.assertNotIn("Nothing was changed", out)
        self.assertTrue(out.endswith("This call's own operation changed "
                                     "nothing."), out)

    def test_the_unfinished_copy_of_an_interrupted_backup_is_named(self):
        # A crash between the copy and its rename leaves `<op>.sqlite.partial`
        # — a full copy of the ledger's pages — and a `pending` record. The
        # open-time settlement removes the file and closes the record.
        self.backups_taken(1)
        op = "4444444444444444"
        self.append_index("backup %s pending reason=manual" % op)
        self.paths.partial_file(op).write_bytes(b"pages of the ledger")
        out = dispatch("list_accounts", data_dir=self.data)
        self.assertFalse(self.paths.partial_file(op).exists())
        self.assertTrue(out.startswith(
            LEAD + "removed 1 unfinished copy; recorded interrupted backup %s "
            "as aborted.\n" % op), out)

    def test_forgetting_an_unknown_account_does_not_deny_what_settlement_removed(self):
        # "so nothing was deleted" stood under a
        # settlement sentence naming a removed copy.
        [bid] = self.backups_taken(1)
        self.append_index("erase abcdefabcdefabcd pending")
        with mock.patch("tools_auth.protected_tools",
                        return_value={"forget_local_account"}):
            out = dispatch("forget_local_account", data_dir=self.data,
                           account_id="missing")
        self.assertFalse(self.paths.backup_file(bid).exists())
        self.assertIn(LEAD + ERASED_ONE, out)
        self.assertIn("so no account data was deleted", out)
        self.assertNotIn("nothing was deleted", out)

    def test_permissions_settlement_resets_are_reported(self):
        # settlement resets the backups directory to
        # 0700 and the index to 0600; a refusal then said "Nothing was
        # changed." over the reset.
        self.backups_taken(1)
        os.chmod(str(self.paths.backups_dir), 0o755)
        os.chmod(str(self.paths.index), 0o644)
        out = dispatch("add_note", data_dir=self.data, row_ids=[999],
                       note="x", author="agent")
        self.assertEqual(oct(self.paths.backups_dir.stat().st_mode & 0o777),
                         "0o700")
        self.assertTrue(out.startswith(
            LEAD + "reset the backups directory's permissions to 0700 (they "
            "were 0755); reset the backup index's permissions to 0600 (they "
            "were 0644).\n"), out)
        self.assertTrue(out.endswith("This call's own operation changed "
                                     "nothing."), out)

    def test_a_refusal_before_the_ledger_opens_says_only_what_it_did(self):
        # The argument check runs before the tool opens the ledger. The
        # claim is the always-scoped one (by design): true whatever
        # settlement did, and here nothing settled at all.
        self.backups_taken(1)
        self.append_index("backup 1111111111111111 pending reason=manual")
        out = dispatch("backup", data_dir=self.data, reason="daily")
        self.assertEqual(out, "reason must be 'weekly' or 'manual'. This "
                              "call's own operation changed nothing.")

    def test_an_open_time_sweep_that_stops_part_way_is_reported_and_the_open_succeeds(self):
        ids = self.backups_taken(2)
        self.append_index("erase abcdefabcdefabcd pending")
        real_unlink = pathlib.Path.unlink

        def selective(p, *a, **k):
            if p.name == ids[0] + ".sqlite":
                raise PermissionError(13, "Permission denied")
            return real_unlink(p, *a, **k)
        with mock.patch.object(pathlib.Path, "unlink", selective):
            out = dispatch("list_accounts", data_dir=self.data)
        self.assertIsNotNone(tools_read.CONN, "the ledger opened")
        self.assertTrue(out.startswith(
            LEAD + "removed 1 backup copy; recorded the removal of 1 backup "
            "copy. " + STATE + "a recorded erasure of the backup copies was "
            "not finished: 1 whole copy still present"), out)

    def test_a_torn_index_tail_cut_at_open_is_reported(self):
        self.backups_taken(1)
        with open(self.paths.index, "a") as f:
            f.write("20260101T000000Z backup 22222222")      # no newline
        out = dispatch("list_accounts", data_dir=self.data)
        self.assertTrue(out.startswith(
            LEAD + "cut an incomplete last line from the backup index.\n"),
            out)

    def test_an_open_time_commit_failure_does_not_fail_the_open(self):
        # SQLite can roll back by itself on a failed COMMIT,
        # and the unconditional ROLLBACK then raised out of the open.
        self.backups_taken(1)
        real = store.open_db

        class Proxy:
            def __init__(self, c):
                self._c = c

            def execute(self, sql, *a):
                if sql == "COMMIT":
                    self._c.execute("ROLLBACK")
                    raise sqlite3.OperationalError("disk I/O error")
                return self._c.execute(sql, *a)

            def __getattr__(self, name):
                return getattr(self._c, name)

        conn = real(self.db)
        self.addCleanup(conn.close)
        store._settle_best_effort(Proxy(conn), self.db)   # must not raise
        self.assertFalse(conn.in_transaction)


class TestEveryExitReportsTheWarmSettlement(Cold):
    def test_an_exception_after_settlement_still_names_what_went(self):
        # a failure after settlement (here the listing's own
        # rendering) reached the operator as a bare error, and the copy the
        # settlement removed went unmentioned.
        [bid] = self.backups_taken(1)
        self.warm()
        self.append_index("erase abcdefabcdefabcd pending")
        with mock.patch.object(tools_backup, "render_listing",
                               side_effect=RuntimeError("boom")):
            out = dispatch("list_backups", data_dir=self.data)
        self.assertFalse(self.paths.backup_file(bid).exists())
        self.assertTrue(out.startswith(
            LEAD + ERASED_ONE + "\nerror: RuntimeError: boom"), out)
        self.assertIsNone(backups._LOG.get(), "an exception exit resets too")

    def test_a_successful_restore_names_the_record_its_settlement_closed(self):
        # the restore's success reply never rendered any
        # settlement, so a record it closed went unmentioned.
        [bid] = self.backups_taken(1)
        self.warm()
        self.append_index("backup 3333333333333333 pending reason=manual")
        import tools_auth
        with mock.patch.object(tools_backup, "_require_declared",
                               return_value=None):
            out = dispatch("restore_backup", data_dir=self.data, backup_id=bid)
        self.assertIn("Restored backup %s" % bid, out)
        self.assertTrue(out.startswith(
            LEAD + "recorded interrupted backup 3333333333333333 as "
            "aborted.\n"), out)

    def test_a_backup_whose_rename_fails_closes_its_own_record(self):
        # the rename failing left this call's own `pending`
        # line behind, so "this call's own operation changed nothing" was
        # false of the index.
        self.warm()
        real_rename = os.rename

        def rename(src, dst):
            if str(src).endswith(".partial"):
                raise OSError(28, "No space left on device")
            return real_rename(src, dst)
        with mock.patch.object(backups.os, "rename", rename):
            out = dispatch("backup", data_dir=self.data, reason="manual")
        last = self.index_lines()[-1].split()
        self.assertEqual([last[1], last[3]], ["backup", "aborted"])
        self.assertIn("this call recorded the attempt as aborted. This call's "
                      "backup copy was not kept.", out)
        self.assertNotIn("changed nothing", out)
        self.assertEqual(list(self.paths.backups_dir.glob("*.partial")), [])

class TestUncertainWritesAreWordedAsUncertain(Cold):
    """a write whose outcome is unknown (`written`
    None) is reported as possible, never as done, and never counted twice."""

    def _gone_copy_and_pending_erasure(self):
        [bid] = self.backups_taken(1)
        self.paths.backup_file(bid).unlink()
        self.append_index("erase abcdefabcdefabcd pending")
        return bid

    def _prune_fails(self, times):
        real = backups.IndexHandle.append
        left = [times]

        def append(handle, *fields):
            if fields[:1] == ("prune",) and left[0]:
                left[0] -= 1
                raise backups.BackupError("torn", written=None)
            return real(handle, *fields)
        return mock.patch.object(backups.IndexHandle, "append", append)

    def test_a_prune_retried_in_the_same_call_is_counted_once(self):
        self._gone_copy_and_pending_erasure()
        with self._prune_fails(1):          # the open-time attempt only
            out = dispatch("list_backups", data_dir=self.data)
        # The open-time attempt left nothing (unknown outcome, no effect);
        # the retry's record is the one effect.
        self.assertIn(LEAD + "recorded the removal of 1 backup copy; "
                      "recorded pending erasure", out)
        self.assertNotIn("2 backup copies", out)

    def test_an_uncertain_write_that_left_nothing_is_not_claimed(self):
        self._gone_copy_and_pending_erasure()
        with self._prune_fails(1):
            out = dispatch("list_accounts", data_dir=self.data)
        # The failed prune left no bytes: no record is claimed, and the
        # state says what is true — the erasure is still pending.
        self.assertNotIn("recorded the removal", out)
        self.assertIn(STATE + "a recorded erasure of the backup copies was "
                      "not finished (every copy was gone", out)

    def test_a_header_that_could_not_be_cut_back_is_reported(self):
        self.warm()
        self._close()
        self.paths.backups_dir.mkdir(mode=0o700, exist_ok=True)
        self.paths.index.write_bytes(b"")
        os.chmod(str(self.paths.index), 0o600)
        real_write = backups._write_whole

        def write(fd, data):
            real_write(fd, data[:9])
            raise OSError(28, "No space left on device")

        def ftruncate(fd, n):
            raise OSError(5, "Input/output error")
        with mock.patch.object(backups, "_write_whole", write), \
                mock.patch.object(backups.os, "ftruncate", ftruncate):
            out = dispatch("list_accounts", data_dir=self.data)
        self.assertEqual(self.paths.index.read_bytes(), b"bank-feed")
        # The header write's outcome is unknown, so it is not an effect;
        # what it left is read from the file at the release.
        self.assertTrue(out.startswith(
            STATE + "the index ended in an incomplete line, which the next "
            "settlement cuts.\n"), out)

    def test_a_torn_header_repaired_later_in_the_call_is_not_reported(self):
        # the open-time pass tore the header, the
        # listing's own settlement wrote it whole, and the reply still
        # published the superseded residue.
        self.warm()
        self._close()
        self.paths.backups_dir.mkdir(mode=0o700, exist_ok=True)
        self.paths.index.write_bytes(b"")
        os.chmod(str(self.paths.index), 0o600)
        real_write, real_trunc = backups._write_whole, os.ftruncate
        armed = [True]

        def write(fd, data):
            if armed[0]:
                real_write(fd, data[:9])
                raise OSError(28, "No space left on device")
            return real_write(fd, data)

        def ftruncate(fd, n):
            if armed[0]:
                armed[0] = False
                raise OSError(5, "Input/output error")
            return real_trunc(fd, n)
        with mock.patch.object(backups, "_write_whole", write), \
                mock.patch.object(backups.os, "ftruncate", ftruncate):
            out = dispatch("list_backups", data_dir=self.data)
        self.assertEqual(self.index_lines()[0], backups.INDEX_HEADER)
        self.assertNotIn("ended in an incomplete line", out)
        self.assertIn("Restore generation: 0", out)

    def test_a_closure_retried_in_the_same_call_is_said_once(self):
        # the uncertain open-time closure and the
        # listing's successful retry were both published.
        self.backups_taken(1)
        self.append_index("backup 1111111111111111 pending reason=manual")
        real = backups.IndexHandle.append
        armed = [True]

        def append(handle, *fields):
            if fields[:1] == ("backup",) and fields[2:3] == ("aborted",) \
                    and armed[0]:
                armed[0] = False
                raise backups.BackupError("torn", written=None)
            return real(handle, *fields)
        with mock.patch.object(backups.IndexHandle, "append", append):
            out = dispatch("list_backups", data_dir=self.data)
        self.assertIn("recorded interrupted backup 1111111111111111 as "
                      "aborted", out)
        self.assertNotIn("may have recorded", out)
        self.assertEqual(out.count("1111111111111111 as aborted"), 1, out)

    def test_a_torn_header_the_retry_removed_is_not_reported(self):
        # both header writes tore; the first cut-back
        # failed, the retry's cut removed the fragment and its own cut-back
        # succeeded. The index is empty — nothing of it is residue.
        self.warm()
        self._close()
        self.paths.backups_dir.mkdir(mode=0o700, exist_ok=True)
        self.paths.index.write_bytes(b"")
        os.chmod(str(self.paths.index), 0o600)
        real_write, real_trunc = backups._write_whole, os.ftruncate
        first = [True]

        def write(fd, data):
            real_write(fd, data[:9])
            raise OSError(28, "No space left on device")

        def ftruncate(fd, n):
            if first[0] and n == 0:
                first[0] = False
                raise OSError(5, "Input/output error")
            return real_trunc(fd, n)
        with mock.patch.object(backups, "_write_whole", write), \
                mock.patch.object(backups.os, "ftruncate", ftruncate):
            out = dispatch("list_backups", data_dir=self.data)
        self.assertEqual(self.paths.index.read_bytes(), b"")
        self.assertIn("cut an incomplete last line from the backup index", out)
        self.assertNotIn("ended in an incomplete line", out)

    def test_a_failed_flush_a_later_flush_covered_is_not_reported(self):
        # an fsync flushes every earlier
        # write to the file, so a later successful one supersedes the
        # warning. Here the open-time cut's flush fails; the backup's own
        # appends then flush the index.
        self.backups_taken(1)
        with open(self.paths.index, "a") as f:
            f.write("20260101T000000Z backup 22222222")      # torn tail
        real = os.fsync
        armed = [True]

        def fsync(fd):
            if armed[0] and os.fstat(fd).st_size and \
                    os.readlink("/proc/self/fd/%d" % fd).endswith(
                        self.paths.index.name):
                armed[0] = False
                raise OSError(5, "Input/output error")
            return real(fd)
        with mock.patch.object(backups.os, "fsync", fsync):
            out = dispatch("backup", data_dir=self.data, reason="manual")
        self.assertFalse(armed[0], "the cut's flush did fail")
        self.assertIn("cut an incomplete last line", out)
        self.assertNotIn("had not been flushed", out)
        self.assertRegex(out, r"Backup [0-9a-f]{16} written")

    def test_an_unflushed_completion_a_later_flush_covered_is_not_reported(self):
        [bid] = self.backups_taken(1)
        self.append_index("erase abcdefabcdefabcd pending")
        # the fault goes into the REAL fsync of the
        # completion record, so the unflushed state is actually reached; the
        # backup's own appends then flush the index.
        real = os.fsync
        armed = [True]

        def fsync(fd):
            path = os.readlink("/proc/self/fd/%d" % fd)
            if (armed[0] and path.endswith(self.paths.index.name)
                    and self.paths.index.read_text().endswith(
                        "abcdefabcdefabcd committed\n")):
                armed[0] = False
                raise OSError(5, "Input/output error")
            return real(fd)
        with mock.patch.object(backups.os, "fsync", fsync):
            out = dispatch("backup", data_dir=self.data, reason="manual")
        self.assertFalse(armed[0], "the completion record's flush did fail")
        self.assertIn(LEAD + ERASED_ONE, out)
        self.assertNotIn("had not been flushed", out)
        self.assertRegex(out, r"Backup [0-9a-f]{16} written")

    def test_a_tools_own_unflushed_record_is_not_called_settlements(self):
        # Once `settle` returns, what the handle appends is the tool's own
        # operation, which its own reply reports; the settlement sentence
        # must not claim that write.
        self.backups_taken(1)
        self.warm()
        real = os.fsync

        def fsync(fd):
            path = os.readlink("/proc/self/fd/%d" % fd)
            if path.endswith(self.paths.index.name) and \
                    self.paths.index.read_text().endswith("reason=manual\n"):
                raise OSError(5, "Input/output error")
            return real(fd)
        with mock.patch.object(backups.os, "fsync", fsync):
            out = dispatch("backup", data_dir=self.data, reason="manual")
        self.assertIn("could not be flushed", out)       # the tool's own
        self.assertNotIn(LEAD, out)

    def test_a_flush_nothing_later_covered_is_reported(self):
        # The other half: with no later flush, the warning stands.
        self.backups_taken(1)
        self.append_index("backup 5555555555555555 pending reason=manual")
        real = os.fsync

        def fsync(fd):
            path = os.readlink("/proc/self/fd/%d" % fd)
            if path.endswith(self.paths.index.name) and \
                    self.paths.index.read_text().endswith("aborted\n"):
                raise OSError(5, "Input/output error")
            return real(fd)
        with mock.patch.object(backups.os, "fsync", fsync):
            out = dispatch("list_accounts", data_dir=self.data)
        self.assertIn(STATE + "its last write to the index had not been "
                      "flushed, so it may not survive a power loss.", out)

    def test_a_tools_own_torn_write_is_the_state_at_the_last_release(self):
        # state read only at settlement's exit was stale after
        # the tool's own later write. It is read at every release of the
        # index lock, so the backup's own torn `pending` line is what the
        # reply reports, as an observation.
        self.backups_taken(1)
        self.warm()
        real_write, real_trunc = backups._write_whole, os.ftruncate

        def write(fd, data):
            if b"pending" in data:
                real_write(fd, data[:7])
                raise OSError(28, "No space left on device")
            return real_write(fd, data)

        def ftruncate(fd, n):
            raise OSError(5, "Input/output error")
        with mock.patch.object(backups, "_write_whole", write), \
                mock.patch.object(backups.os, "ftruncate", ftruncate):
            out = dispatch("backup", data_dir=self.data, reason="manual")
        self.assertTrue(out.startswith(
            STATE + "the index ended in an incomplete line, which the next "
            "settlement cuts.\n"), out)
        self.assertNotIn(LEAD, out, "the torn write was the tool's own")

    def test_a_mode_reset_that_failed_is_not_claimed(self):
        # the reset was logged before the chmod.
        self.backups_taken(1)
        os.chmod(str(self.paths.backups_dir), 0o755)
        real = os.chmod

        def chmod(path, mode, *a, **k):
            if str(path) == str(self.paths.backups_dir):
                raise PermissionError(13, "Permission denied")
            return real(path, mode, *a, **k)
        with mock.patch.object(backups.os, "chmod", chmod):
            out = dispatch("list_accounts", data_dir=self.data)
        self.assertNotIn("reset the backups directory", out)
        self.assertEqual(oct(self.paths.backups_dir.stat().st_mode & 0o777),
                         "0o755")

    def test_an_unverified_write_is_reported_when_the_state_is_unreadable(self):
        # an unknown-outcome write, with the final read
        # failing too, went silent.
        self.backups_taken(1)
        self.append_index("backup 6666666666666666 pending reason=manual")
        real_write, real_trunc = backups._write_whole, os.ftruncate

        def write(fd, data):
            if b"aborted" in data:
                real_write(fd, data[:9])
                raise OSError(28, "No space left on device")
            return real_write(fd, data)

        def ftruncate(fd, n):
            raise OSError(5, "Input/output error")
        real_read = pathlib.Path.read_bytes

        def read_bytes(p):
            if p.name == self.paths.index.name:
                raise OSError(5, "Input/output error")
            return real_read(p)
        with mock.patch.object(backups, "_write_whole", write), \
                mock.patch.object(backups.os, "ftruncate", ftruncate), \
                mock.patch.object(pathlib.Path, "read_bytes", read_bytes):
            out = dispatch("list_accounts", data_dir=self.data)
        self.assertIn(STATE + "a write of settlement's to the index had "
                      "failed part way, and what it left could not be read "
                      "back.", out)
        self.assertNotIn("as aborted", out)

    def test_an_index_another_process_created_is_not_claimed(self):
        # creation was inferred from a pre-check,
        # so an index another process created in between was claimed. It is
        # now the exclusive create's own success, and a new index's header
        # write is logged as the effect it is.
        self.warm()
        real_open = os.open

        def racing(path, flags, *a):
            if str(path) == str(self.paths.index) and flags & os.O_EXCL:
                fd = real_open(path, os.O_WRONLY | os.O_CREAT, 0o600)
                os.write(fd, (backups.INDEX_HEADER + "\n").encode())
                os.close(fd)                 # "another process" made it
            return real_open(path, flags, *a)
        with mock.patch.object(backups.os, "open", racing):
            out = dispatch("backup", data_dir=self.data, reason="manual")
        self.assertNotIn("created the backup index", out)
        self.assertNotIn("wrote the backup index's header", out)

    def test_a_new_index_reports_its_creation_and_its_header(self):
        self.warm()
        out = dispatch("backup", data_dir=self.data, reason="manual")
        self.assertIn(LEAD + "created the backups directory; created the "
                      "backup index; wrote the backup index's header.", out)

    def test_a_release_after_a_failed_fchmod_is_observed(self):
        # `_acquire_index` released the lock on
        # its fchmod failure without the observation every release makes.
        [bid] = self.backups_taken(1)
        self.append_index("erase abcdefabcdefabcd pending")

        real = os.fchmod

        def fchmod(fd, mode):
            if os.readlink("/proc/self/fd/%d" % fd).endswith(
                    self.paths.index.name):
                raise OSError(5, "Input/output error")
            return real(fd, mode)
        with mock.patch.object(backups.os, "fchmod", fchmod):
            out = dispatch("list_backups", data_dir=self.data)
        self.assertTrue(self.paths.backup_file(bid).exists())
        self.assertIn(STATE + "a recorded erasure of the backup copies was "
                      "not finished: 1 whole copy still present", out)

    def test_a_directory_another_process_created_is_not_claimed(self):
        # creation was inferred from an existence
        # check that raced another process's mkdir.
        self.warm()
        real_mkdir = pathlib.Path.mkdir

        def racing(p, *a, **k):
            if p == self.paths.backups_dir and not p.exists():
                real_mkdir(p, mode=0o700)        # "another process" made it
            return real_mkdir(p, *a, **k)
        with mock.patch.object(pathlib.Path, "mkdir", racing):
            out = dispatch("backup", data_dir=self.data, reason="manual")
        self.assertNotIn("created the backups directory", out)
        self.assertRegex(out, r"Backup [0-9a-f]{16} written")

    def test_an_unreadable_mode_claims_no_reset_and_no_creation(self):
        # a failed existence check read as
        # "absent", inventing a creation and hiding a real reset.
        self.backups_taken(1)
        os.chmod(str(self.paths.backups_dir), 0o755)
        real = os.lstat
        seen = []

        def lstat(path, *a, **k):
            # The symlink guard's lstat passes; the MODE read fails.
            if str(path) == str(self.paths.backups_dir):
                seen.append(1)
                if len(seen) == 2:
                    raise OSError(5, "Input/output error")
            return real(path, *a, **k)
        with mock.patch.object(backups.os, "lstat", lstat):
            out = dispatch("list_accounts", data_dir=self.data)
        self.assertGreaterEqual(len(seen), 2, "the mode read was reached")
        self.assertNotIn("created the backups directory", out)
        self.assertNotIn("reset the backups directory", out)  # unmeasured
        self.assertEqual(oct(self.paths.backups_dir.stat().st_mode & 0o777),
                         "0o700", "the reset itself still happened")

    def test_an_append_cut_back_cleanly_is_not_written_whatever_the_flush(self):
        # the cut returned but its fsync failed,
        # and the refusal said the partial record "could not be removed" —
        # false: the file ends at its previous newline.
        self.backups_taken(1)
        conn = self.warm()
        conn.execute("BEGIN IMMEDIATE")
        _, handle = backups.settle(conn, self.paths)
        before = self.paths.index.read_bytes()
        real_write, real_fsync = backups._write_whole, os.fsync

        def write(fd, data):
            real_write(fd, data[:9])
            raise OSError(28, "No space left on device")
        armed = [True]

        def fsync(fd):
            if armed[0] and os.readlink("/proc/self/fd/%d" % fd).endswith(
                    self.paths.index.name):
                armed[0] = False
                raise OSError(5, "Input/output error")
            return real_fsync(fd)
        try:
            with mock.patch.object(backups, "_write_whole", write), \
                    mock.patch.object(backups.os, "fsync", fsync):
                with self.assertRaises(backups.BackupError) as cm:
                    handle.append("backup", "7777777777777777", "aborted")
        finally:
            conn.execute("ROLLBACK")
            handle.close()
        self.assertIs(cm.exception.written, False)
        self.assertNotIn("could not be removed", str(cm.exception))
        self.assertEqual(self.paths.index.read_bytes(), before)

    def test_settlements_cut_back_fragment_is_an_effect(self):
        # settlement's closure wrote nine bytes,
        # the rest failed, and the cut-back removed them: a cut, unreported.
        self.backups_taken(1)
        self.append_index("backup 8888888888888888 pending reason=manual")
        real_write = backups._write_whole

        real_os_write = os.write
        calls = []

        def oswrite(fd, data):
            # The closure's first write lands 9 bytes; the next one fails.
            if b"aborted" in data or calls:
                calls.append(1)
                if len(calls) == 1:
                    return real_os_write(fd, data[:9])
                raise OSError(28, "No space left on device")
            return real_os_write(fd, data)
        with mock.patch.object(backups.os, "write", oswrite):
            out = dispatch("list_accounts", data_dir=self.data)
        self.assertTrue(self.index_lines()[-1].endswith("reason=manual"))
        self.assertIn(LEAD + "cut an incomplete last line from the backup "
                      "index", out)

    def test_settlements_header_cut_back_is_an_effect(self):
        # the header path cut back nine landed
        # bytes and said nothing.
        self.warm()
        self._close()
        self.paths.backups_dir.mkdir(mode=0o700, exist_ok=True)
        self.paths.index.write_bytes(b"")
        os.chmod(str(self.paths.index), 0o600)
        real_os_write = os.write
        calls = []

        def oswrite(fd, data):
            if data.startswith(backups.INDEX_HEADER.encode()[:5]) or calls:
                calls.append(1)
                if len(calls) == 1:
                    return real_os_write(fd, data[:9])
                raise OSError(28, "No space left on device")
            return real_os_write(fd, data)
        with mock.patch.object(backups.os, "write", oswrite):
            out = dispatch("list_accounts", data_dir=self.data)
        self.assertEqual(self.paths.index.read_bytes(), b"")
        self.assertIn(LEAD + "cut an incomplete last line from the backup "
                      "index", out)

    def test_a_write_that_landed_nothing_claims_no_cut(self):
        # a write that failed before landing a
        # byte, with the post-failure fstat failing too, was claimed as a
        # cut. The proof is `os.write`'s own count.
        self.backups_taken(1)
        self.append_index("backup 9999999999999999 pending reason=manual")
        real_os_write = os.write

        def oswrite(fd, data):
            if b"aborted" in data:
                raise OSError(28, "No space left on device")
            return real_os_write(fd, data)
        real_fstat = os.fstat

        def fstat(fd):
            if os.readlink("/proc/self/fd/%d" % fd).endswith(
                    self.paths.index.name) and oswrite.failed:
                raise OSError(5, "Input/output error")
            return real_fstat(fd)
        oswrite.failed = False

        def oswrite2(fd, data):
            try:
                return oswrite(fd, data)
            except OSError:
                oswrite.failed = True
                raise
        with mock.patch.object(backups.os, "write", oswrite2), \
                mock.patch.object(backups.os, "fstat", fstat):
            out = dispatch("list_accounts", data_dir=self.data)
        self.assertNotIn("cut an incomplete last line", out)

    def test_an_invalid_index_is_not_read_as_a_pending_erasure(self):
        # a bad header followed by an
        # erasure-shaped line read as "a recorded erasure" at the release,
        # though settlement rejects that index.
        self.warm()
        self._close()
        self.paths.backups_dir.mkdir(mode=0o700, exist_ok=True)
        self.paths.index.write_text(
            "not the header\n20260101T000000Z erase abcdefabcdefabcd "
            "pending\n")
        os.chmod(str(self.paths.index), 0o600)
        out = dispatch("list_accounts", data_dir=self.data)
        self.assertNotIn("recorded erasure", out)
        self.assertNotIn("While an erasure is pending", out)

    def test_two_cuts_are_counted(self):
        # two successful cuts read as one.
        self.warm()
        self._close()
        self.paths.backups_dir.mkdir(mode=0o700, exist_ok=True)
        self.paths.index.write_bytes(b"bank-fe")     # a torn header
        os.chmod(str(self.paths.index), 0o600)
        real_write, real_trunc = backups._write_whole, os.ftruncate
        armed = [True]

        def write(fd, data):
            if armed[0]:
                real_write(fd, data[:5])
                raise OSError(28, "No space left on device")
            return real_write(fd, data)

        def ftruncate(fd, n):
            if armed[0] and n == 0 and os.fstat(fd).st_size == 5:
                armed[0] = False
                raise OSError(5, "Input/output error")
            return real_trunc(fd, n)
        with mock.patch.object(backups, "_write_whole", write), \
                mock.patch.object(backups.os, "ftruncate", ftruncate):
            out = dispatch("list_backups", data_dir=self.data)
        self.assertIn("cut 2 incomplete last lines from the backup index", out)

    def test_a_rename_failure_whose_abort_record_is_unflushed_says_so(self):
        self.warm()
        real_rename, real_append = os.rename, backups.IndexHandle.append

        def rename(src, dst):
            if str(src).endswith(".partial"):
                raise OSError(28, "No space left on device")
            return real_rename(src, dst)

        def append(handle, *fields):
            real_append(handle, *fields)
            if fields[:1] == ("backup",) and fields[2:3] == ("aborted",):
                raise backups.BackupError("fsync failed", written=True)
        with mock.patch.object(backups.os, "rename", rename), \
                mock.patch.object(backups.IndexHandle, "append", append):
            out = dispatch("backup", data_dir=self.data, reason="manual")
        last = self.index_lines()[-1].split()
        self.assertEqual([last[1], last[3]], ["backup", "aborted"])
        self.assertIn("its abort record was written but could not be "
                      "flushed", out)
        self.assertNotIn("pending index record stays", out)



class TestToolsWordTheirOwnWritesThroughOneRenderer(unittest.TestCase):
    """Tools report only their own events, never the index's state, and they
    may put a write outcome into words only through `backups.record_event`.
    Every read of `.written` or `.index_written` in a tool module is an
    argument to that call, or a
    comparison against False or a bare branch test (a branch, never a
    sentence). `index_warning` is the erasure's written-but-unflushed
    terminal record, the third carrier."""

    def test_every_written_outcome_goes_through_record_event(self):
        bad = []
        for path in sorted(SERVER.glob("tools_*.py")):
            tree = ast.parse(path.read_text())
            parents = {}
            for node in ast.walk(tree):
                for ch in ast.iter_child_nodes(node):
                    parents[ch] = node
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Attribute)
                        and node.attr in ("written", "index_written",
                                          "index_warning")):
                    continue
                up, ok = parents.get(node), False
                # A bare branch test (`if er.index_warning:`) chooses whether
                # to speak and words nothing.
                if isinstance(up, (ast.If, ast.IfExp)) and up.test is node:
                    ok = True
                while up is not None and not ok:
                    if (isinstance(up, ast.Call)
                            and isinstance(up.func, ast.Attribute)
                            and up.func.attr == "record_event"):
                        ok = True
                    elif (isinstance(up, ast.Compare) and any(
                            isinstance(c, ast.Constant) and c.value is False
                            for c in up.comparators)):
                        ok = True
                    up = parents.get(up)
                if not ok:
                    bad.append("%s:%d" % (path.name, node.lineno))
        self.assertEqual(bad, [])

if __name__ == "__main__":
    unittest.main()
