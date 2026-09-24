"""The backup subsystem: index grammar, settlement, the copy, the restore."""
import errno
import fcntl
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
import backups  # noqa: E402
import store  # noqa: E402

SRV = str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server")


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        self.db = self.root / "bank_feed.sqlite"
        self.conn = store.open_db(self.db)      # keeps sqlite3.Row: the tools index by name
        self.paths = backups.paths_for(self.db)

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    def seed(self, n_tx=3, notes=True):
        c = self.conn
        c.execute("INSERT INTO sessions(session_id, aspsp_name, status)"
                  " VALUES ('s1','Bank','AUTHORIZED')")
        c.execute("INSERT INTO accounts(account_id, uid, session_id, currency,"
                  " aspsp, incarnation) VALUES ('a1','uid-1','s1','EUR','Bank',"
                  " 'life-0000000001')")
        ids = []
        for i in range(n_tx):
            cur = c.execute(
                "INSERT INTO transactions(account_id, identity_key, occurrence,"
                " amount_minor, currency, direction, booking_date)"
                " VALUES ('a1', ?, 0, 100, 'EUR', 'DBIT', '2026-09-01')",
                ("k%d" % i,))
            ids.append(cur.lastrowid)
            if notes:
                c.execute("INSERT INTO transaction_notes(row_id, author, note,"
                          " created_at) VALUES (?,'agent',?,'2026-09-01')",
                          (cur.lastrowid, "invoice paid for widget %d" % i))
        return ids

    def index_lines(self):
        return self.paths.index.read_text().splitlines()

    def settled(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            state, handle = backups.settle(self.conn, self.paths)
            handle.close()
            return state
        finally:
            self.conn.execute("ROLLBACK")


class TestPaths(Base):
    def test_paths_derive_from_the_ledger_filename(self):
        p = backups.paths_for(self.root / "bank_feed.sandbox.sqlite")
        self.assertEqual(p.index.name, "bank_feed.sandbox.sqlite.backup-index")
        self.assertEqual(p.backups_dir.name, "bank_feed.sandbox.sqlite.backups")
        self.assertEqual(p.backup_file("0123456789abcdef").name,
                         "0123456789abcdef.sqlite")
        self.assertEqual(p.partial_file("0123456789abcdef").name,
                         "0123456789abcdef.sqlite.partial")

    def test_settle_without_an_index_creates_it_at_0600_and_the_dir_at_0700(self):
        state = self.settled()
        self.assertEqual(state.generation, 0)
        self.assertEqual(self.index_lines(), [backups.INDEX_HEADER])
        self.assertEqual(oct(self.paths.index.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(self.paths.backups_dir.stat().st_mode & 0o777),
                         "0o700")

    def test_a_symlink_at_the_index_path_is_refused(self):
        os.symlink(self.root / "elsewhere", self.paths.index)
        self.conn.execute("BEGIN IMMEDIATE")
        with self.assertRaises(backups.BackupError):
            backups.settle(self.conn, self.paths)
        self.conn.execute("ROLLBACK")


class TestGrammar(Base):
    def test_workflow_grammar(self):
        ok = ["acct@1.2.0", "a@1", "quarterly-accounting@2026.09.22+rc1"]
        bad = ["acct", "@1", "Acct@1", "acct@", "acct@1 2", "acct@1\n",
               "acct::x@1", "a" * 25 + "@1"]
        for w in ok:
            self.assertTrue(backups.WORKFLOW_RE.fullmatch(w), w)
        for w in bad:
            self.assertFalse(backups.WORKFLOW_RE.fullmatch(w), w)

    def test_op_id_is_sixteen_hex(self):
        self.assertRegex(backups.new_op_id(), r"^[0-9a-f]{16}$")

    def test_an_unparseable_line_makes_the_index_unreadable(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z bogus 0123456789abcdef pending\n")
        self.conn.execute("BEGIN IMMEDIATE")
        with self.assertRaises(backups.BackupError) as cm:
            backups.settle(self.conn, self.paths)
        self.conn.execute("ROLLBACK")
        self.assertIn("unreadable", str(cm.exception))

    def test_two_terminal_records_for_one_id_make_the_index_unreadable(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z backup 0123456789abcdef pending reason=manual\n"
                    "20260922T000001Z backup 0123456789abcdef committed\n"
                    "20260922T000002Z backup 0123456789abcdef aborted\n")
        with self.assertRaises(backups.BackupError):
            self.settled()

    def test_two_pending_records_for_one_id_make_the_index_unreadable(self):
        # Every op id is a fresh random mint; a second `pending` for the
        # SAME id is never legitimate. Without this guard `_derive` appends
        # a second entry to `st.restores` (restores are not dict-keyed by
        # id, unlike backups), settlement writes two terminal lines for one
        # id, and the index then refuses its own output on the next settle.
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z restore bbbbbbbbbbbbbbbb pending"
                    " backup=aaaaaaaaaaaaaaaa\n"
                    "20260922T000001Z restore bbbbbbbbbbbbbbbb pending"
                    " backup=cccccccccccccccc\n")
        with self.assertRaises(backups.BackupError):
            self.settled()

    def test_a_pending_record_with_more_than_one_extra_field_is_unreadable(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z backup 0123456789abcdef pending"
                    " reason=manual extra=1\n")
        with self.assertRaises(backups.BackupError):
            self.settled()

    def test_a_pending_record_with_a_bare_trailing_token_is_unreadable(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z backup 0123456789abcdef pending bogus\n")
        with self.assertRaises(backups.BackupError):
            self.settled()

    def test_both_erase_shapes_parse_and_an_erasure_is_not_a_restore(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z erase abcdefabcdefabcd pending\n"
                    "20260922T000001Z erase abcdefabcdefabcd committed\n")
        state = self.settled()
        self.assertEqual([(e["op_id"], e["state"], e["seq"]) for e in state.erasures],
                         [("abcdefabcdefabcd", "committed", 2)])
        # The generation counts committed RESTORES. An erasure that bumped it
        # would make every workflow's `expected_generation` fence fire on an
        # erasure, which restored nothing.
        self.assertEqual(state.generation, 0)

    def test_a_junk_field_or_an_unknown_erase_terminal_is_unreadable(self):
        # An erasure names no backup and no reason on either of its two lines,
        # so a field there is as unreadable as a missing one is elsewhere --
        # and `aborted` is not a terminal an erasure has at all: once its
        # pending record is durable, settlement always completes it.
        for line in ("20260922T000000Z erase abcdefabcdefabcd pending reason=manual\n",
                     "20260922T000000Z erase abcdefabcdefabcd pending backup=aaaaaaaaaaaaaaaa\n",
                     "20260922T000000Z erase abcdefabcdefabcd committed extra=1\n",
                     "20260922T000000Z erase abcdefabcdefabcd aborted\n"):
            with self.subTest(line=line):
                self.paths.index.write_text(backups.INDEX_HEADER + "\n" + line)
                with self.assertRaises(backups.BackupError):
                    self.settled()

    def test_a_second_pending_erase_record_is_unreadable(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z erase abcdefabcdefabcd pending\n"
                    "20260922T000001Z erase abcdefabcdefabcd pending\n")
        with self.assertRaises(backups.BackupError):
            self.settled()

    def test_a_second_terminal_erase_record_is_unreadable(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z erase abcdefabcdefabcd pending\n"
                    "20260922T000001Z erase abcdefabcdefabcd committed\n"
                    "20260922T000002Z erase abcdefabcdefabcd committed\n")
        with self.assertRaises(backups.BackupError):
            self.settled()

    def test_a_pending_record_with_the_wrong_key_is_unreadable(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z backup 0123456789abcdef pending cause=manual\n")
        with self.assertRaises(backups.BackupError):
            self.settled()

    def test_a_torn_header_alone_is_truncated_then_rewritten(self):
        # The whole file is a torn HEADER (no newline anywhere): truncation
        # cuts to nothing, and the historical bug left it that way -- the
        # caller's next append then landed on a headerless file, and every
        # later settle refused "bad header" for ever.
        self.paths.index.write_bytes(backups.INDEX_HEADER[:10].encode("ascii"))
        self.settled()
        self.assertEqual(self.index_lines(), [backups.INDEX_HEADER])
        state = self.settled()      # must succeed, not refuse "bad header"
        self.assertEqual(state.generation, 0)

    def test_settle_fsyncs_the_index_directory_on_creation(self):
        # `_fsync_dir` existed but nothing ever called it: index/dir
        # CREATION was not durable while every append already was.
        self.conn.execute("BEGIN IMMEDIATE")
        with mock.patch("backups._fsync_dir",
                        wraps=backups._fsync_dir) as spy:
            _, handle = backups.settle(self.conn, self.paths)
        handle.close()
        self.conn.execute("ROLLBACK")
        self.assertGreaterEqual(spy.call_count, 1)

    def test_a_torn_trailing_line_is_truncated_then_appends_cleanly(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z backup 0123456789abcdef pending reason=manual\n"
                    "20260922T000001Z backup 0123456789ab")      # torn
        # the pending backup has no file -> settlement appends `aborted`
        state = self.settled()
        lines = self.index_lines()
        self.assertEqual(lines[1].split()[1:],
                         ["backup", "0123456789abcdef", "pending", "reason=manual"])
        self.assertEqual(lines[2].split()[1:], ["backup", "0123456789abcdef", "aborted"])
        self.assertEqual(len(lines), 3)
        self.assertNotIn("\x00", self.paths.index.read_bytes().decode())
        self.assertEqual(state.backups["0123456789abcdef"]["state"], "aborted")

    def test_the_index_descriptor_is_append_only(self):
        self.conn.execute("BEGIN IMMEDIATE")
        _, handle = backups.settle(self.conn, self.paths)
        flags = fcntl.fcntl(handle.fd, fcntl.F_GETFL)
        handle.close()
        self.conn.execute("ROLLBACK")
        self.assertTrue(flags & os.O_APPEND)


class TestIndexLock(Base):
    def test_lock_order_is_ledger_then_index_and_settle_requires_the_ledger_lock(self):
        # No BEGIN IMMEDIATE -> refuse, so the order cannot be inverted by accident.
        with self.assertRaises(backups.BackupError) as cm:
            backups.settle(self.conn, self.paths)
        self.assertIn("BEGIN IMMEDIATE", str(cm.exception))

    def test_a_second_acquisition_in_one_process_refuses_within_the_bound(self):
        self.conn.execute("BEGIN IMMEDIATE")
        _, held = backups.settle(self.conn, self.paths)
        try:
            # simulate the double-acquire: same process, second descriptor
            backups.LOCK_WAIT_S = 0.3
            with self.assertRaises(backups.BackupError) as cm:
                backups._acquire_index(self.paths)
            self.assertIn("busy", str(cm.exception))
        finally:
            backups.LOCK_WAIT_S = 10.0
            held.close()
            self.conn.execute("ROLLBACK")


class TestSettlementTable(Base):
    """One row per line of the spec's settlement table."""

    def pending_backup(self, op_id, reason="manual", make_file=True, partial=False):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z backup %s pending reason=%s\n" % (op_id, reason))
        if make_file:
            self.paths.backup_file(op_id).write_bytes(b"x")
        if partial:
            self.paths.partial_file(op_id).write_bytes(b"x")

    def test_install_backup_with_file_and_registration_is_committed(self):
        op = "aaaaaaaaaaaaaaaa"
        self.pending_backup(op, reason="install:acct@1.0.0")
        self.conn.execute("INSERT INTO workflow_registrations(workflow, backup_id,"
                          " registered_at) VALUES ('acct@1.0.0', ?, 't')", (op,))
        state = self.settled()
        self.assertEqual(state.backups[op]["state"], "committed")
        self.assertEqual(state.registrations["acct@1.0.0"]["backup_id"], op)

    def test_install_backup_with_file_and_no_registration_is_orphan(self):
        op = "aaaaaaaaaaaaaaaa"
        self.pending_backup(op, reason="install:acct@1.0.0")
        state = self.settled()
        self.assertEqual(state.backups[op]["state"], "orphan")
        self.assertTrue(self.paths.backup_file(op).exists(), "orphans are kept")

    def test_weekly_backup_with_file_is_committed(self):
        op = "aaaaaaaaaaaaaaaa"
        self.pending_backup(op, reason="weekly")
        self.assertEqual(self.settled().backups[op]["state"], "committed")

    def test_backup_without_file_is_aborted_and_the_partial_is_removed(self):
        op = "aaaaaaaaaaaaaaaa"
        self.pending_backup(op, make_file=False, partial=True)
        state = self.settled()
        self.assertEqual(state.backups[op]["state"], "aborted")
        self.assertFalse(self.paths.partial_file(op).exists())

    def test_registration_whose_file_is_missing_is_broken(self):
        op = "aaaaaaaaaaaaaaaa"
        self.pending_backup(op, reason="install:acct@1.0.0")
        self.conn.execute("INSERT INTO workflow_registrations(workflow, backup_id,"
                          " registered_at) VALUES ('acct@1.0.0', ?, 't')", (op,))
        self.settled()
        self.paths.backup_file(op).unlink()
        state = self.settled()
        self.assertEqual(state.broken, {"acct@1.0.0"})

    def test_a_registrations_read_failure_other_than_missing_table_refuses(self):
        # The table EXISTS but the read fails for a different reason (here:
        # a schema drift makes the SELECT's column list unsatisfiable). The
        # narrow "no such table" catch must not treat this the same as "no
        # registrations" -- that would settle a legitimately-registered
        # install backup as an immutable `orphan` and silently empty
        # `broken`.
        op = "aaaaaaaaaaaaaaaa"
        self.pending_backup(op, reason="install:acct@1.0.0")
        self.conn.execute("DROP TABLE workflow_registrations")
        self.conn.execute(
            "CREATE TABLE workflow_registrations(workflow TEXT PRIMARY KEY"
            " NOT NULL, backup_id TEXT NOT NULL)")     # registered_at missing
        with self.assertRaises(backups.BackupError):
            self.settled()

    def test_pending_restore_settles_by_the_marker_holding_its_operation_id(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z restore bbbbbbbbbbbbbbbb pending"
                    " backup=aaaaaaaaaaaaaaaa\n")
        self.conn.execute("INSERT OR REPLACE INTO meta(key, value)"
                          " VALUES (?, 'bbbbbbbbbbbbbbbb')", (backups.MARKER_KEY,))
        state = self.settled()
        self.assertEqual(state.generation, 1)
        self.assertEqual(self.index_lines()[-1].split()[1:],
                         ["restore", "bbbbbbbbbbbbbbbb", "committed"])

    def test_pending_restore_with_another_marker_is_aborted(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z restore bbbbbbbbbbbbbbbb pending"
                    " backup=aaaaaaaaaaaaaaaa\n")
        self.conn.execute("INSERT OR REPLACE INTO meta(key, value)"
                          " VALUES (?, 'cccccccccccccccc')", (backups.MARKER_KEY,))
        state = self.settled()
        self.assertEqual(state.generation, 0)
        self.assertEqual(self.index_lines()[-1].split()[3], "aborted")

    def test_generation_counts_distinct_committed_restore_ids(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z restore bbbbbbbbbbbbbbbb pending backup=aaaaaaaaaaaaaaaa\n"
                    "20260922T000001Z restore bbbbbbbbbbbbbbbb committed\n"
                    "20260922T000002Z restore cccccccccccccccc pending backup=aaaaaaaaaaaaaaaa\n"
                    "20260922T000003Z restore cccccccccccccccc aborted\n"
                    "20260922T000004Z restore dddddddddddddddd pending backup=aaaaaaaaaaaaaaaa\n"
                    "20260922T000005Z restore dddddddddddddddd committed\n")
        self.assertEqual(self.settled().generation, 2)

    def test_pending_erasure_removes_every_copy_and_settles_committed(self):
        # The settlement-table row for the record kind a crash between
        # `delete_all_data`'s ledger COMMIT and `erase_backups` leaves behind.
        op = "aaaaaaaaaaaaaaaa"
        self.pending_backup(op, reason="weekly")
        self.settled()                                   # -> committed, present
        self.paths.partial_file("cccccccccccccccc").write_bytes(b"half a copy")
        with open(self.paths.index, "a") as f:
            f.write("20260922T000010Z erase abcdefabcdefabcd pending\n")
        state = self.settled()
        self.assertEqual(sorted(p.name for p in self.paths.backups_dir.iterdir()), [])
        lines = self.index_lines()
        # One `prune` per INDEXED copy, then the erasure's own terminal last:
        # the partial never had an index record to prune.
        self.assertEqual(lines[-2].split()[1:], ["prune", op, "done"])
        self.assertEqual(lines[-1].split()[1:],
                         ["erase", "abcdefabcdefabcd", "committed"])
        self.assertEqual([e["state"] for e in state.erasures], ["committed"])
        self.assertTrue(state.backups[op].get("pruned"))
        # Presence is re-read AFTER the copies go, because `restore`'s preflight
        # reads this same object: a stale `present` would send a restore on to
        # ATTACH a file that is not there and refuse for the wrong reason.
        self.assertFalse(state.backups[op]["present"])
        self.assertIsNone(state.backups[op]["size"])

    def test_a_completed_erasure_is_never_run_again(self):
        op = "aaaaaaaaaaaaaaaa"
        self.pending_backup(op, reason="weekly")
        with open(self.paths.index, "a") as f:
            f.write("20260922T000010Z erase abcdefabcdefabcd pending\n")
        self.settled()
        before = self.index_lines()
        self.settled()
        self.assertEqual(self.index_lines(), before)

    def test_a_registration_whose_copy_an_erasure_removed_reads_as_broken(self):
        # The ledger half of an erasure can fail and roll back with the pending
        # record already durable, so settlement can remove the copies while the
        # registrations are still there. `broken` is re-read with presence, so
        # the listing says FILE MISSING instead of pointing at a copy that went.
        op = "aaaaaaaaaaaaaaaa"
        self.pending_backup(op, reason="install:acct@1.0.0")
        self.conn.execute("INSERT INTO workflow_registrations(workflow,"
                          " backup_id, registered_at) VALUES ('acct@1.0.0', ?, 't')",
                          (op,))
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000010Z erase abcdefabcdefabcd pending\n")
        self.assertEqual(self.settled().broken, {"acct@1.0.0"})

    def test_settlement_appends_nothing_when_a_terminal_is_already_present(self):
        op = "aaaaaaaaaaaaaaaa"
        self.pending_backup(op, reason="weekly")
        self.settled()
        before = self.index_lines()
        self.settled()
        self.assertEqual(self.index_lines(), before)


class TestTheErasureIsDurableBeforeItsRecord(Base):
    """An unlink is not durable until the DIRECTORY holding the entry is.

    The terminal `erase <op> committed` record is what stops any later
    settlement from sweeping again, so writing it over unflushed directory
    entries is the one ordering under which a power loss brings every copy of
    an erased ledger back with nothing left that would remove them.
    """

    def pending_backup(self, op_id, reason="manual", make_file=True):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z backup %s pending reason=%s\n"
                    % (op_id, reason))
        if make_file:
            self.paths.backup_file(op_id).write_bytes(b"x")

    def _pending_erasure(self, op="aaaaaaaaaaaaaaaa"):
        """A committed backup with its file, plus a durable `erase` pending."""
        self.pending_backup(op, reason="weekly")
        self.settled()                                   # -> committed, present
        with open(self.paths.index, "a") as f:
            f.write("20260922T000010Z erase abcdefabcdefabcd pending\n")
        return op

    def test_the_directory_is_flushed_between_the_last_unlink_and_the_terminal(self):
        self._pending_erasure()
        events = []
        real_fsync_dir = backups._fsync_dir
        real_append = backups.IndexHandle.append
        real_unlink = pathlib.Path.unlink

        def fsync_dir(d):
            events.append(("fsync_dir", str(d)))
            return real_fsync_dir(d)

        def append(handle, *fields):
            events.append(("append", fields[0], fields[-1]))
            return real_append(handle, *fields)

        def unlink(p, *a, **k):
            events.append(("unlink", p.name))
            return real_unlink(p, *a, **k)
        self.addCleanup(setattr, backups, "_fsync_dir", real_fsync_dir)
        self.addCleanup(setattr, backups.IndexHandle, "append", real_append)
        self.addCleanup(setattr, pathlib.Path, "unlink", real_unlink)
        backups._fsync_dir = fsync_dir
        backups.IndexHandle.append = append
        pathlib.Path.unlink = unlink
        self.settled()
        backups._fsync_dir = real_fsync_dir
        backups.IndexHandle.append = real_append
        pathlib.Path.unlink = real_unlink
        last_unlink = max(i for i, e in enumerate(events) if e[0] == "unlink")
        flush = [i for i, e in enumerate(events)
                 if e == ("fsync_dir", str(self.paths.backups_dir))]
        terminal = [i for i, e in enumerate(events)
                    if e == ("append", "erase", "committed")]
        self.assertEqual(len(terminal), 1, events)
        self.assertEqual(len(flush), 1, events)
        # The whole ordering claim, in one line: the entries are on disk
        # before the record that says they are.
        self.assertLess(last_unlink, flush[0], events)
        self.assertLess(flush[0], terminal[0], events)

    def test_a_directory_flush_that_fails_leaves_the_erasure_pending(self):
        self._pending_erasure()
        real = backups._fsync_dir

        def fsync_dir(d):
            if d == self.paths.backups_dir:
                raise OSError(errno.EIO, "I/O error")
            return real(d)
        self.addCleanup(setattr, backups, "_fsync_dir", real)
        backups._fsync_dir = fsync_dir
        with self.assertRaises(backups.ErasureIncomplete) as cm:
            self.settled()
        backups._fsync_dir = real
        self.assertTrue(cm.exception.erasure.undurable)
        self.assertEqual(cm.exception.erasure.failed, 0)
        # No terminal record, so the erasure is still `pending` and the next
        # settlement sweeps again -- which is what removes a copy the
        # unflushed directory could have brought back.
        self.assertNotIn(["erase", "abcdefabcdefabcd", "committed"],
                         [l.split()[1:] for l in self.index_lines()])
        self.assertNotIn("0 backup file(s)", str(cm.exception))
        state = self.settled()
        self.assertEqual([e["state"] for e in state.erasures], ["committed"])

    def _snapshot(self, db_name=None):
        """A pre-migration snapshot beside a ledger, named the way
        `store._snapshot_name` names one."""
        f = self.root / ((db_name or self.db.name) + backups.SNAPSHOT_INFIX
                         + "20260922T000000Z")
        f.write_bytes(b"x")
        return f

    def test_an_erasure_removes_this_ledgers_pre_migration_snapshots(self):
        # Issue #44: a snapshot is a whole-ledger copy, sessions included.
        self._pending_erasure()
        mine, other = self._snapshot(), self._snapshot("bank_feed.sandbox.sqlite")
        state = self.settled()
        self.assertFalse(mine.exists())
        self.assertTrue(other.exists())      # the other mode's ledger's own
        self.assertEqual([e["state"] for e in state.erasures], ["committed"])
        self.assertEqual(state.settled.snapshots, 1)
        self.assertIn("removed 1 backup copy(ies) and 1 pre-migration snapshot(s)",
                      backups.settled_sentence(state.settled))

    def test_a_snapshot_only_sweep_is_still_reported(self):
        # No backup copy at all: the snapshot is the only thing that went,
        # and a reply built on `state.settled` must still say so.
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000010Z erase abcdefabcdefabcd pending\n")
        self._snapshot()
        state = self.settled()
        self.assertIsNotNone(state.settled)
        self.assertEqual(state.settled.snapshots, 1)

    def test_a_snapshot_that_cannot_be_removed_leaves_the_erasure_pending(self):
        self._pending_erasure()
        snap = self._snapshot()
        real_unlink = pathlib.Path.unlink

        def unlink(p, *a, **k):
            if p.name == snap.name:
                raise OSError(errno.EACCES, "Permission denied")
            return real_unlink(p, *a, **k)
        with mock.patch.object(pathlib.Path, "unlink", unlink), \
                self.assertRaises(backups.ErasureIncomplete) as cm:
            self.settled()
        self.assertEqual(cm.exception.erasure.failed_snapshots, 1)
        self.assertEqual(cm.exception.erasure.failed, 0)
        self.assertIn("1 pre-migration snapshot(s) beside the ledger could "
                      "not be removed", cm.exception.residue())
        self.assertNotIn(["erase", "abcdefabcdefabcd", "committed"],
                         [l.split()[1:] for l in self.index_lines()])
        state = self.settled()
        self.assertFalse(snap.exists())
        self.assertEqual([e["state"] for e in state.erasures], ["committed"])

    def test_the_ledger_directory_is_flushed_before_the_terminal(self):
        self._pending_erasure()
        self._snapshot()
        events = []
        real_fsync_dir = backups._fsync_dir
        real_append = backups.IndexHandle.append
        real_unlink = pathlib.Path.unlink

        def fsync_dir(d):
            events.append(("fsync_dir", str(d)))
            return real_fsync_dir(d)

        def append(handle, *fields):
            events.append(("append", fields[0], fields[-1]))
            return real_append(handle, *fields)

        def unlink(p, *a, **k):
            events.append(("unlink", p.name))
            return real_unlink(p, *a, **k)
        with mock.patch.object(backups, "_fsync_dir", fsync_dir), \
                mock.patch.object(backups.IndexHandle, "append", append), \
                mock.patch.object(pathlib.Path, "unlink", unlink):
            self.settled()
        snap_unlink = [i for i, e in enumerate(events)
                       if e[0] == "unlink" and backups.SNAPSHOT_INFIX in e[1]]
        flush = [i for i, e in enumerate(events)
                 if e == ("fsync_dir", str(self.root))]
        terminal = [i for i, e in enumerate(events)
                    if e == ("append", "erase", "committed")]
        # Setup flushes the directory too; the one that matters is the last
        # one before the terminal record.
        self.assertEqual((len(snap_unlink), len(terminal)), (1, 1), events)
        self.assertTrue([i for i in flush if snap_unlink[0] < i < terminal[0]],
                        events)

    def test_a_ledger_directory_flush_that_fails_leaves_the_erasure_pending(self):
        self._pending_erasure()
        snap = self._snapshot()
        real = backups._fsync_dir

        def fsync_dir(d):
            # Only the flush after the snapshot went: setup flushes this
            # directory too, and failing that refuses before any sweep.
            if d == self.paths.db.parent and not snap.exists():
                raise OSError(errno.EIO, "I/O error")
            return real(d)
        with mock.patch.object(backups, "_fsync_dir", fsync_dir), \
                self.assertRaises(backups.ErasureIncomplete) as cm:
            self.settled()
        self.assertTrue(cm.exception.erasure.undurable)
        self.assertIn("bank_feed.sqlite.pre-migration-*",
                      backups.by_hand(self.paths, cm.exception.erasure))
        state = self.settled()
        self.assertEqual([e["state"] for e in state.erasures], ["committed"])

    def test_a_placed_backup_reply_counts_what_settlement_removed(self):
        # `refusal_text`'s placed-but-unflushed branch has its own sentence
        # about settlement; it must count every shape the sweep removed.
        exc = backups.BackupError("EIO")
        exc.placed = "aaaaaaaaaaaaaaaa"
        exc.settled = backups.Erasure(removed=1, partials=1, snapshots=1,
                                      snapshot_sidecars=1, finished=True)
        text = backups.refusal_text(exc)
        self.assertIn("removed 1 backup copy(ies), 1 partial copy(ies), 1 "
                      "pre-migration snapshot(s) and 1 snapshot journal "
                      "file(s).", text)

    def test_a_removed_journal_is_named_when_the_flush_then_fails(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000010Z erase abcdefabcdefabcd pending\n")
        journal = self._snapshot()
        journal = journal.rename(journal.with_name(journal.name + "-journal"))
        real = backups._fsync_dir

        def fsync_dir(d):
            if d == self.paths.db.parent and not journal.exists():
                raise OSError(errno.EIO, "I/O error")
            return real(d)
        with mock.patch.object(backups, "_fsync_dir", fsync_dir), \
                self.assertRaises(backups.ErasureIncomplete) as cm:
            self.settled()
        self.assertEqual(cm.exception.erasure.snapshot_sidecars, 1)
        self.assertIn("1 snapshot journal file(s)", cm.exception.describe())

    def test_a_copy_whose_presence_cannot_be_read_is_never_recorded_as_pruned(self):
        # `Path.exists()` is `os.path.exists`, which answers False for ANY
        # OSError -- EACCES, EIO -- so a copy that is STILL THERE and merely
        # unreadable earned a `prune` record saying this erasure removed it,
        # and the erasure then closed `committed` over a directory it could not
        # read. The sweep passes this copy by: an unlink reporting the file
        # already gone is the one shape that leaves the audit record to the
        # presence pass, and that pass is where the false claim was written.
        op = self._pending_erasure()
        target = self.paths.backup_file(op)
        real_unlink, real_stat = pathlib.Path.unlink, os.stat

        def unlink(p, *a, **k):
            if p.name == target.name:
                raise FileNotFoundError(errno.ENOENT, "No such file")
            return real_unlink(p, *a, **k)

        def stat(path, *a, **k):
            if str(path) == str(target):
                raise OSError(errno.EIO, "I/O error")
            return real_stat(path, *a, **k)
        self.addCleanup(setattr, pathlib.Path, "unlink", real_unlink)
        pathlib.Path.unlink = unlink
        with mock.patch.object(backups.os, "stat", stat):
            with self.assertRaises(backups.ErasureIncomplete) as cm:
                self.settled()
        pathlib.Path.unlink = real_unlink
        self.assertEqual(cm.exception.erasure.failed, 1)
        self.assertEqual(cm.exception.erasure.removed, 0)
        # The copy is still there, and no record says otherwise; the erasure
        # stays pending, so a later settlement decides it on a readable disk.
        self.assertTrue(target.is_file())
        self.assertEqual([l for l in self.index_lines()
                          if l.split()[1:2] == ["prune"]], [])
        self.assertNotIn(["erase", "abcdefabcdefabcd", "committed"],
                         [l.split()[1:] for l in self.index_lines()])

    def test_an_unsearchable_directory_counts_each_copy_once(self):
        # The reproduction the finding was found with: a directory that lists
        # its copies and refuses every operation on them, so the unlink AND
        # the stat of the same file both fail. One file is one failure -- the
        # count is what the operator is told is left, and a copy counted twice
        # sends them looking for a file that is not there.
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        op = self._pending_erasure()
        real_prepare = backups._prepare

        def prepare_then_seal(paths):
            # 0600 AFTER `_prepare`, which chmods the directory back to 0700
            # at the top of every settle: readable, so the sweep still lists
            # the copy, and unsearchable, so both its unlink and its stat
            # fail EACCES.
            real_prepare(paths)
            os.chmod(str(paths.backups_dir), 0o600)
        def unseal():
            # Tolerant: cleanups run after tearDown has removed the tree, and
            # a chmod of a directory that is gone would mask the real result.
            if self.paths.backups_dir.is_dir():
                os.chmod(str(self.paths.backups_dir), 0o700)
        self.addCleanup(unseal)
        self.addCleanup(setattr, backups, "_prepare", real_prepare)
        backups._prepare = prepare_then_seal
        with self.assertRaises(backups.ErasureIncomplete) as cm:
            self.settled()
        backups._prepare = real_prepare
        os.chmod(str(self.paths.backups_dir), 0o700)
        # ONE failure for one file: the unlink counted it and the presence
        # pass must not count the same copy a second time.
        self.assertEqual(cm.exception.erasure.failed, 1)
        self.assertEqual(cm.exception.erasure.removed, 0)
        self.assertTrue(self.paths.backup_file(op).is_file())
        self.assertEqual([l for l in self.index_lines()
                          if l.split()[1:2] == ["prune"]], [])
        self.assertNotIn(["erase", "abcdefabcdefabcd", "committed"],
                         [l.split()[1:] for l in self.index_lines()])
        # And it really does complete once the directory is searchable again.
        state = self.settled()
        self.assertEqual([e["state"] for e in state.erasures], ["committed"])
        self.assertEqual([l.split()[1:] for l in self.index_lines()][-2],
                         ["prune", op, "done"])

    def test_an_aborted_backup_never_earns_a_prune_record(self):
        # A `prune` records the removal of a COPY. An `aborted` backup never
        # reached a final file -- settlement unlinks its `.partial` and
        # settles it aborted -- so a `prune` for one records the removal of a
        # file that never existed, and the listing then reads `pruned` for an
        # operation that produced nothing to prune.
        op = "aaaaaaaaaaaaaaaa"
        self.pending_backup(op, reason="weekly", make_file=False)
        state = self.settled()
        self.assertEqual(state.backups[op]["state"], "aborted")
        with open(self.paths.index, "a") as f:
            f.write("20260922T000010Z erase abcdefabcdefabcd pending\n")
        state = self.settled()
        self.assertEqual([l for l in self.index_lines()
                          if l.split()[1:2] == ["prune"]], [])
        self.assertFalse(state.backups[op].get("pruned"))
        self.assertEqual([e["state"] for e in state.erasures], ["committed"])

    def test_a_flush_failure_on_the_terminal_record_still_completes(self):
        # `append` writes and then flushes. A failed flush follows a write
        # that LANDED: the line is readable, so the erasure is complete and
        # the next settlement reads it as complete. Letting it leave as a
        # BackupError made the caller describe a directory it had emptied as
        # one whose sweep stopped part way.
        op = self._pending_erasure()
        real_write, real_fsync = os.write, os.fsync
        armed = []

        def write(fd, data):
            n = real_write(fd, data)
            if b" erase " in data and data.rstrip().endswith(b"committed"):
                armed.append(fd)
            return n

        def fsync(fd):
            if fd in armed:
                armed.clear()
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_fsync(fd)
        with mock.patch.object(backups.os, "write", write), \
                mock.patch.object(backups.os, "fsync", fsync):
            state = self.settled()
        self.assertEqual([e["state"] for e in state.erasures], ["committed"])
        self.assertFalse(self.paths.backup_file(op).exists())
        last = self.index_lines()[-1].split()
        self.assertEqual([last[1], last[3]], ["erase", "committed"])

    def test_a_write_failure_on_the_terminal_record_leaves_it_pending(self):
        # The other event: nothing landed, so no terminal record exists, the
        # erasure is still pending and the refusal is right.
        self._pending_erasure()
        real_write = os.write

        def write(fd, data):
            if b" erase " in data and data.rstrip().endswith(b"committed"):
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_write(fd, data)
        with mock.patch.object(backups.os, "write", write):
            with self.assertRaises(backups.BackupError) as cm:
                self.settled()
        self.assertNotIsInstance(cm.exception, backups.ErasureIncomplete)
        # A DISTINCT TYPE, not a bare BackupError: the sweep already unlinked
        # every file and flushed the directory before this append ran, so a
        # caller rendering this exactly like an unreadable-directory refusal
        # would describe an empty directory as one that still holds copies.
        self.assertIsInstance(cm.exception, backups.ErasureRecordUnwritten)
        self.assertNotIn(["erase", "abcdefabcdefabcd", "committed"],
                         [l.split()[1:] for l in self.index_lines()])
        self.assertEqual([e["state"] for e in self.settled().erasures],
                         ["committed"])

    def test_a_raw_oserror_never_escapes_the_erasure(self):
        # The module's contract at this one function: a caller's
        # `except BackupError` is the whole of its error handling.
        self._pending_erasure()
        with mock.patch.object(backups, "_erase",
                               side_effect=OSError(errno.EIO, "I/O error")):
            with self.assertRaises(backups.BackupError) as cm:
                self.settled()
        self.assertNotIsInstance(cm.exception, backups.ErasureIncomplete)
        self.assertIn("the backup copies could not be erased", str(cm.exception))


class TestIoFailuresBecomeBackupErrors(Base):
    """The module's own contract: every refusal is a BackupError, never a
    raw OSError -- so a caller (store._settle_best_effort included) that
    catches BackupError never sees ENOSPC/EIO leak through instead."""

    def test_a_pread_failure_during_settle_is_a_backup_error(self):
        self.settled()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            with mock.patch("os.pread",
                            side_effect=OSError(5, "I/O error")):
                with self.assertRaises(backups.BackupError):
                    backups.settle(self.conn, self.paths)
        finally:
            self.conn.execute("ROLLBACK")

    def test_an_append_io_failure_is_a_backup_error(self):
        self.conn.execute("BEGIN IMMEDIATE")
        _, handle = backups.settle(self.conn, self.paths)
        try:
            with mock.patch("os.fsync",
                            side_effect=OSError(28, "No space left on device")):
                with self.assertRaises(backups.BackupError):
                    handle.append("backup", "aaaaaaaaaaaaaaaa", "committed")
        finally:
            handle.close()
            self.conn.execute("ROLLBACK")


def torn_write(match, cut_fails=False):
    """An `os.write` double that lands HALF of the first buffer containing
    `match` and reports it, then raises ENOSPC on the continuation — the
    shape a full disk gives a real write. Returns (write, ftruncate) doubles;
    with `cut_fails`, the first ftruncate after the tear raises EIO."""
    real_write, real_trunc = os.write, os.ftruncate
    state = {"torn": False, "cut": False}

    def write(fd, data):
        if state["torn"] and not state.get("done"):
            state["done"] = True
            raise OSError(errno.ENOSPC, "No space left on device")
        if match in data and not state["torn"]:
            state["torn"] = True
            return real_write(fd, data[:len(data) // 2])
        return real_write(fd, data)

    def ftruncate(fd, size):
        if cut_fails and state["torn"] and not state["cut"]:
            state["cut"] = True
            raise OSError(errno.EIO, "Input/output error")
        return real_trunc(fd, size)
    return write, ftruncate


class TestAnAppendIsWholeOrAbsent(Base):
    """A write can land a prefix of a line and report it. The operation's
    next append then completes it into a complete, malformed line — every
    later settlement refuses the index for good — and a torn `pending` alone
    is cut by the next settlement, losing the record of an operation that
    went ahead on it."""

    def test_a_torn_append_is_cut_back_and_the_index_reads_clean(self):
        self.settled()
        before = self.paths.index.read_bytes()
        write, trunc = torn_write(b" backup ")
        self.conn.execute("BEGIN IMMEDIATE")
        _, h = backups.settle(self.conn, self.paths)
        try:
            with mock.patch.object(backups.os, "write", write), \
                    mock.patch.object(backups.os, "ftruncate", trunc):
                with self.assertRaises(backups.BackupError) as cm:
                    h.append("backup", "a" * 16, "pending", "reason=manual")
            self.assertIs(cm.exception.written, False)
            # Byte-identical: the record does not exist, and no prefix of it
            # is left for the next append to land on.
            self.assertEqual(self.paths.index.read_bytes(), before)
        finally:
            h.close()
            self.conn.execute("ROLLBACK")
        self.conn.execute("BEGIN IMMEDIATE")
        _, h = backups.settle(self.conn, self.paths)
        h.append("backup", "b" * 16, "pending", "reason=manual")
        h.close()
        self.conn.execute("ROLLBACK")
        st = self.settled()
        self.assertEqual(st.backups["b" * 16]["state"], "aborted")
        self.assertNotIn("a" * 16, st.backups)

    def test_a_tear_that_cannot_be_cut_poisons_the_handle_until_the_next_settle(self):
        self.settled()
        before = self.paths.index.read_bytes()
        write, trunc = torn_write(b" backup ", cut_fails=True)
        self.conn.execute("BEGIN IMMEDIATE")
        _, h = backups.settle(self.conn, self.paths)
        try:
            with mock.patch.object(backups.os, "write", write), \
                    mock.patch.object(backups.os, "ftruncate", trunc):
                with self.assertRaises(backups.BackupError) as cm:
                    h.append("backup", "a" * 16, "pending", "reason=manual")
            # "may hold a partial record": neither True nor False is honest.
            self.assertIsNone(cm.exception.written)
            torn = self.paths.index.read_bytes()
            self.assertGreater(len(torn), len(before))
            self.assertFalse(torn.endswith(b"\n"))
            # The handle writes NOTHING more: an append here would complete
            # the prefix into a malformed line no settlement can remove.
            with self.assertRaises(backups.BackupError) as cm2:
                h.append("backup", "c" * 16, "committed")
            self.assertIs(cm2.exception.written, False)
            self.assertEqual(self.paths.index.read_bytes(), torn)
        finally:
            h.close()
            self.conn.execute("ROLLBACK")
        # The next settlement cuts the tail and the index reads clean.
        st = self.settled()
        self.assertEqual(self.paths.index.read_bytes(), before)
        self.assertEqual(st.backups, {})

    def test_a_torn_header_write_leaves_no_header_prefix(self):
        # The index's creation is a write too. A prefix of the header followed
        # by a complete append is a malformed FIRST line — "bad header" for
        # ever, since the torn-tail cut only removes an unterminated tail.
        write, trunc = torn_write(backups.INDEX_HEADER.encode("ascii"))
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            with mock.patch.object(backups.os, "write", write), \
                    mock.patch.object(backups.os, "ftruncate", trunc):
                with self.assertRaises(backups.BackupError):
                    backups.settle(self.conn, self.paths)
        finally:
            self.conn.execute("ROLLBACK")
        self.assertEqual(self.paths.index.read_bytes(), b"")
        self.conn.execute("BEGIN IMMEDIATE")
        _, h = backups.settle(self.conn, self.paths)
        h.append("backup", "b" * 16, "pending", "reason=manual")
        h.close()
        self.conn.execute("ROLLBACK")
        self.assertEqual(self.index_lines()[0], backups.INDEX_HEADER)
        self.assertEqual(self.settled().backups["b" * 16]["state"], "aborted")


class TestOpenTimeSettlement(Base):
    def test_a_non_utf8_line_is_unreadable_and_never_fails_the_open(self):
        # A UnicodeDecodeError is a ValueError, which no `except BackupError`
        # catches: it left `open_db` and the finance ledger would not open.
        self.settled()
        with open(self.paths.index, "ab") as f:
            f.write(b"20260922T000000Z backup \xff\xfeaaaaaaaaaaaaaa pending"
                    b" reason=manual\n")
        conn = store.open_db(self.db)
        try:
            self.assertFalse(conn.in_transaction)
            import tools_read
            import tools_backup
            tools_read.CONN = conn
            try:
                out = tools_backup.list_backups({})
            finally:
                tools_read.CONN = None
            self.assertIn("the backup index is unreadable", out)
            self.assertFalse(conn.in_transaction)
        finally:
            conn.close()

    def test_open_db_settles_a_pending_record_when_an_index_exists(self):
        self.settled()
        with open(self.paths.index, "a") as f:
            f.write("20260922T000000Z backup aaaaaaaaaaaaaaaa pending reason=manual\n")
        self.conn.close()
        self.conn = store.open_db(self.db)
        self.assertEqual(self.index_lines()[-1].split()[1:],
                         ["backup", "aaaaaaaaaaaaaaaa", "aborted"])

    def test_open_db_does_not_create_an_index(self):
        self.assertFalse(self.paths.index.exists())

    @unittest.skipIf(os.geteuid() == 0, "root bypasses file permission checks")
    def test_open_db_never_fails_on_an_os_level_unreadable_index(self):
        self.settled()
        os.chmod(str(self.paths.index), 0o000)
        try:
            conn = store.open_db(self.db)
        finally:
            os.chmod(str(self.paths.index), 0o600)
        try:
            self.assertFalse(conn.in_transaction)
        finally:
            conn.close()

    def test_open_db_succeeds_while_another_process_holds_the_index_lock(self):
        self.settled()
        holder = subprocess.Popen(
            [sys.executable, "-c", textwrap.dedent("""
                import fcntl, os, sys, time
                fd = os.open(sys.argv[1], os.O_RDWR)
                fcntl.flock(fd, fcntl.LOCK_EX)
                print("held", flush=True)
                time.sleep(3)
            """), str(self.paths.index)], stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        backups.LOCK_WAIT_S = 0.2
        try:
            conn = store.open_db(self.db)
            conn.close()
        finally:
            backups.LOCK_WAIT_S = 10.0
            holder.kill(); holder.wait()
            holder.stdout.close()

    def test_open_db_succeeds_while_another_process_holds_the_ledger_lock(self):
        self.settled()
        holder = subprocess.Popen(
            [sys.executable, "-c", textwrap.dedent("""
                import sqlite3, sys, time
                c = sqlite3.connect(sys.argv[1], isolation_level=None)
                c.execute("BEGIN IMMEDIATE")
                print("held", flush=True)
                time.sleep(3)
            """), str(self.db)], stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        # Lower the settle-step busy timeout so this test does not wait out
        # the holder's full sleep: the BEGIN IMMEDIATE inside
        # _settle_best_effort hits sqlite3.OperationalError quickly instead.
        store._SETTLE_BUSY_MS = 200
        try:
            conn = sqlite3.connect(str(self.db), isolation_level=None, timeout=0.2)
            conn.close()
            conn = store.open_db(self.db)   # settlement skipped, open succeeds
            conn.close()
        finally:
            store._SETTLE_BUSY_MS = 10000
            holder.kill(); holder.wait()
            holder.stdout.close()


class TestTakeBackup(Base):
    def take(self, reason="manual", register=None, commit=True):
        self.conn.execute("BEGIN IMMEDIATE")
        state, handle = backups.settle(self.conn, self.paths)
        try:
            b = backups.take_backup(self.conn, self.paths, handle, reason,
                                    register=register)
            self.conn.execute("COMMIT" if commit else "ROLLBACK")
        except BaseException:
            self.conn.execute("ROLLBACK")
            handle.close()
            raise
        pruned = backups.finish_backup(self.paths, handle, b, committed=commit)
        handle.close()
        return b, pruned

    def test_the_copy_is_the_committed_state_not_the_writers_uncommitted_rows(self):
        ids = self.seed()
        self.conn.execute("BEGIN IMMEDIATE")
        self.conn.execute("INSERT INTO transaction_notes(row_id, author, note,"
                          " created_at) VALUES (?,'agent','UNCOMMITTED','t')", (ids[0],))
        _, handle = backups.settle(self.conn, self.paths)
        b = backups.take_backup(self.conn, self.paths, handle, "manual")
        self.conn.execute("COMMIT")
        backups.finish_backup(self.paths, handle, b, committed=True)
        handle.close()
        copy = sqlite3.connect(str(self.paths.backup_file(b.op_id)))
        self.addCleanup(copy.close)
        self.assertEqual(copy.execute("SELECT count(*) FROM transaction_notes"
                                      " WHERE note='UNCOMMITTED'").fetchone()[0], 0)
        self.assertEqual(copy.execute("SELECT count(*) FROM transaction_notes"
                                      ).fetchone()[0], 3)

    def test_index_records_pending_then_committed_and_the_file_is_0600(self):
        self.seed()
        b, _ = self.take("weekly")
        lines = [l.split()[1:] for l in self.index_lines()[1:]]
        self.assertEqual(lines, [["backup", b.op_id, "pending", "reason=weekly"],
                                 ["backup", b.op_id, "committed"]])
        self.assertEqual(oct(self.paths.backup_file(b.op_id).stat().st_mode & 0o777),
                         "0o600")
        self.assertFalse(self.paths.partial_file(b.op_id).exists())

    def test_a_mint_registers_the_workflow_in_the_same_transaction(self):
        self.seed()
        b, _ = self.take("install:acct@1.0.0", register="acct@1.0.0")
        self.assertEqual(self.settled().registrations["acct@1.0.0"]["backup_id"],
                         b.op_id)
        copy = sqlite3.connect(str(self.paths.backup_file(b.op_id)))
        self.addCleanup(copy.close)
        self.assertEqual(copy.execute("SELECT count(*) FROM workflow_registrations"
                                      ).fetchone()[0], 0, "the copy predates it")

    def test_a_rolled_back_mint_leaves_an_orphan_not_an_aborted(self):
        self.seed()
        b, _ = self.take("install:acct@1.0.0", register="acct@1.0.0", commit=False)
        st = self.settled()
        self.assertEqual(st.backups[b.op_id]["state"], "orphan")
        self.assertNotIn("acct@1.0.0", st.registrations)
        self.assertTrue(self.paths.backup_file(b.op_id).exists())

    def test_a_copy_failure_raises_and_leaves_no_partial_and_no_index_record(self):
        self.seed()
        self.conn.execute("BEGIN IMMEDIATE")
        _, handle = backups.settle(self.conn, self.paths)
        os.chmod(self.paths.backups_dir, 0o500)
        try:
            with self.assertRaises(backups.BackupError):
                backups.take_backup(self.conn, self.paths, handle, "manual")
        finally:
            os.chmod(self.paths.backups_dir, 0o700)
            self.conn.execute("ROLLBACK"); handle.close()
        self.assertEqual(len(self.index_lines()), 1)
        self.assertEqual(list(self.paths.backups_dir.iterdir()), [])

    def test_a_callable_reason_must_be_weekly_or_manual_and_install_needs_register(self):
        self.conn.execute("BEGIN IMMEDIATE")
        _, handle = backups.settle(self.conn, self.paths)
        try:
            for bad in ("daily", "install:acct@1.0.0", "weekly\n"):
                with self.assertRaises(backups.BackupError):
                    backups.take_backup(self.conn, self.paths, handle, bad)
        finally:
            self.conn.execute("ROLLBACK"); handle.close()

    def test_retention_keeps_eight_weekly_and_never_an_install_backup(self):
        self.seed()
        inst, _ = self.take("install:acct@1.0.0", register="acct@1.0.0")
        ids = [self.take("weekly")[0].op_id for _ in range(9)]
        st = self.settled()
        self.assertFalse(self.paths.backup_file(ids[0]).exists())
        self.assertTrue(all(self.paths.backup_file(i).exists() for i in ids[1:]))
        self.assertTrue(self.paths.backup_file(inst.op_id).exists())
        self.assertTrue(st.backups[ids[0]].get("pruned"))
        self.assertEqual(self.index_lines()[-1].split()[1:], ["prune", ids[0], "done"])

    def test_a_non_missing_unlink_failure_during_prune_is_a_backup_error(self):
        # The module's contract: every failure leaves as a BackupError
        # carrying our own text, never a raw OSError -- FileNotFoundError
        # (the file is already gone) is the one exception, not every OSError.
        self.seed()
        for _ in range(8):
            self.take("weekly")
        self.conn.execute("BEGIN IMMEDIATE")
        _, handle = backups.settle(self.conn, self.paths)
        b = backups.take_backup(self.conn, self.paths, handle, "weekly")
        self.conn.execute("COMMIT")
        handle.append("backup", b.op_id, "committed")
        try:
            with mock.patch("pathlib.Path.unlink",
                            side_effect=PermissionError(13, "Permission denied")):
                with self.assertRaises(backups.BackupError):
                    backups.prune(self.paths, handle)
        finally:
            handle.close()


class RestoreBase(Base):
    def backup(self, reason="manual", register=None):
        self.conn.execute("BEGIN IMMEDIATE")
        _, h = backups.settle(self.conn, self.paths)
        b = backups.take_backup(self.conn, self.paths, h, reason, register=register)
        self.conn.execute("COMMIT")
        backups.finish_backup(self.paths, h, b, committed=True); h.close()
        return b.op_id

    def restore(self, backup_id):
        self.conn.execute("BEGIN IMMEDIATE")
        state, h = backups.settle(self.conn, self.paths)
        try:
            return backups.restore(self.conn, self.paths, h, state, backup_id,
                                   schema_version=store.SCHEMA_VERSION)
        except BaseException:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        finally:
            h.close()

    def count(self, table):
        return self.conn.execute("SELECT count(*) FROM %s" % table).fetchone()[0]


class TestRestore(RestoreBase):
    def test_rows_come_back_sequence_last_and_fts_rebuilt(self):
        ids = self.seed()
        bid = self.backup()
        self.conn.execute("INSERT INTO transaction_notes(row_id, author, note,"
                          " created_at) VALUES (?,'agent','acct test note','t')", (ids[0],))
        self.conn.execute("INSERT INTO transactions(account_id, identity_key,"
                          " occurrence, amount_minor, currency, direction)"
                          " VALUES ('a1','late',0,5,'EUR','DBIT')")
        r = self.restore(bid)
        self.assertEqual(self.count("transaction_notes"), 3)
        self.assertEqual(self.count("transactions"), 3)
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM notes_fts WHERE notes_fts MATCH 'acct'").fetchone()[0], 0)
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM notes_fts WHERE notes_fts MATCH 'invoice'").fetchone()[0], 3)
        cur = self.conn.execute("INSERT INTO transactions(account_id, identity_key,"
                                " occurrence, amount_minor, currency, direction)"
                                " VALUES ('a1','new',0,7,'EUR','DBIT')")
        self.assertEqual(cur.lastrowid, 4, "row ids resume from the backup's counter")
        self.assertEqual(self.conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.assertEqual(r.replaced["transactions"], 3)
        lines = [l.split()[1:] for l in self.index_lines()]
        self.assertEqual(lines[-2], ["restore", r.op_id, "pending", "backup=" + bid])
        self.assertEqual(lines[-1], ["restore", r.op_id, "committed"])
        self.assertEqual(self.settled().generation, 1)

    def test_the_marker_holds_the_restore_operation_id_and_the_same_backup_restores_twice(self):
        self.seed(); bid = self.backup()
        r1 = self.restore(bid)
        self.assertEqual(self.conn.execute("SELECT value FROM meta WHERE key=?",
                                           (backups.MARKER_KEY,)).fetchone()[0], r1.op_id)
        r2 = self.restore(bid)
        self.assertNotEqual(r1.op_id, r2.op_id)
        self.assertEqual(self.settled().generation, 2)

    def test_a_failed_terminal_append_after_commit_is_carried_not_raised(self):
        # A failure appending the "committed" record happens AFTER the COMMIT
        # landed the restored data, so it must not leave as a BackupError: the
        # caller's `except BackupError` prints "Nothing was changed." for a
        # restore that replaced every ordinary table. It is carried on the
        # result instead. DETACH still runs either way -- otherwise the
        # attachment leaks onto this long-lived connection and every LATER
        # restore fails at ATTACH with "database bk is already in use",
        # which gets misreported as THAT backup being unreadable.
        self.seed(); bid = self.backup()
        self.conn.execute("BEGIN IMMEDIATE")
        state, h = backups.settle(self.conn, self.paths)
        orig_append = h.append

        def flaky(*fields):
            if fields[0] == "restore" and fields[-1] == "committed":
                raise backups.BackupError("simulated index failure")
            return orig_append(*fields)

        with mock.patch.object(h, "append", side_effect=flaky):
            r = backups.restore(self.conn, self.paths, h, state, bid,
                                schema_version=store.SCHEMA_VERSION)
        self.assertEqual(r.index_error, "simulated index failure")
        h.close()
        # The operation is not lost: its `pending` record plus the committed
        # marker settle it `committed`, so the generation is right anyway.
        self.assertEqual(self.settled().generation, 1)
        # the restore's writes committed even though the terminal append failed
        self.assertEqual(self.count("transactions"), 3)
        marker = self.conn.execute("SELECT value FROM meta WHERE key=?",
                                   (backups.MARKER_KEY,)).fetchone()[0]
        self.assertTrue(marker)
        # DETACH ran despite the failure: ATTACH on the SAME connection for a
        # second restore must not fail with "database bk is already in use"
        r2 = self.restore(bid)
        self.assertNotEqual(marker, r2.op_id)

    def test_sessions_attempts_and_meta_are_kept_live(self):
        self.seed(); bid = self.backup()
        self.conn.execute("INSERT INTO sessions(session_id, aspsp_name, status)"
                          " VALUES ('s2','Bank','AUTHORIZED')")
        self.conn.execute("INSERT INTO attempts(state_hash, phase) VALUES ('h1','minted')")
        self.conn.execute("INSERT INTO meta(key, value) VALUES ('setup.app_id','app-live')")
        self.restore(bid)
        self.assertEqual(self.count("sessions"), 2)
        self.assertEqual(self.count("attempts"), 1)
        self.assertEqual(self.conn.execute("SELECT value FROM meta WHERE"
                                           " key='setup.app_id'").fetchone()[0], "app-live")

    def test_live_bindings_are_written_back_and_every_survivor_gets_a_new_incarnation(self):
        self.seed(); bid = self.backup()
        self.conn.execute("UPDATE accounts SET session_id='s9', uid='uid-9' WHERE account_id='a1'")
        r = self.restore(bid)
        row = self.conn.execute("SELECT session_id, uid, incarnation FROM accounts"
                                " WHERE account_id='a1'").fetchone()
        self.assertEqual((row[0], row[1]), ("s9", "uid-9"))
        self.assertNotEqual(row[2], "life-0000000001")
        self.assertRegex(row[2], r"^[0-9a-f]{16}$")
        self.assertEqual(r.bindings_kept, 1)

    def test_every_survivor_including_accounts_created_after_the_backup_is_re_minted(self):
        # The re-mint covers EVERY row that survives the restore, not only the
        # rows the backup put back: an account created after the backup —
        # linked or not — is kept by the restore, and a refresh paused across
        # it must not find its old life token still valid.
        self.seed(); bid = self.backup()
        self.conn.execute("INSERT INTO accounts(account_id, uid, session_id,"
                          " currency, incarnation) VALUES"
                          " ('a2','uid-2','s1','EUR','life-0000000002'),"
                          " ('a3', NULL, NULL, 'EUR','life-0000000003')")
        before = {r[0]: r[1] for r in self.conn.execute(
            "SELECT account_id, incarnation FROM accounts")}
        self.assertEqual(set(before), {"a1", "a2", "a3"})
        self.restore(bid)
        after = {r[0]: r[1] for r in self.conn.execute(
            "SELECT account_id, incarnation FROM accounts")}
        self.assertEqual(set(after), set(before))
        for aid in before:
            self.assertNotEqual(after[aid], before[aid], aid)
            self.assertRegex(after[aid], r"^[0-9a-f]{16}$")

    def test_an_account_in_the_backup_but_unlinked_live_comes_back_needing_relink(self):
        self.seed(); bid = self.backup()
        self.conn.execute("DELETE FROM accounts WHERE account_id='a1'")
        r = self.restore(bid)
        row = self.conn.execute("SELECT session_id, uid FROM accounts"
                                " WHERE account_id='a1'").fetchone()
        self.assertEqual(tuple(row), (None, None))
        self.assertEqual(r.relink, ["a1"])

    def test_an_account_linked_live_but_absent_from_the_backup_keeps_its_row(self):
        self.seed(); bid = self.backup()
        self.conn.execute("INSERT INTO accounts(account_id, uid, session_id, currency,"
                          " incarnation) VALUES ('a2','uid-2','s1','EUR','life-2')")
        self.restore(bid)
        row = self.conn.execute("SELECT uid, session_id FROM accounts"
                                " WHERE account_id='a2'").fetchone()
        self.assertEqual(tuple(row), ("uid-2", "s1"))

    def test_an_account_absent_from_the_backup_and_already_unlinked_live_is_kept_and_relinked(self):
        # The fourth, implicit case of the spec's per-account table: absent
        # from the backup AND unlinked live (no session_id). The row is
        # still never dropped by a restore, but a NULL binding is the
        # derived "needs re-link" whichever branch produced it.
        self.seed(); bid = self.backup()
        self.conn.execute("INSERT INTO accounts(account_id, uid, session_id, currency,"
                          " incarnation) VALUES ('a2', NULL, NULL, 'EUR', 'life-2')")
        r = self.restore(bid)
        row = self.conn.execute("SELECT uid, session_id FROM accounts"
                                " WHERE account_id='a2'").fetchone()
        self.assertEqual(tuple(row), (None, None))
        self.assertIn("a2", r.relink)

    def test_registrations_at_or_after_the_restored_point_are_unregistered(self):
        self.seed()
        early = self.backup("install:acct@1.0.0", register="acct@1.0.0")
        mid = self.backup()
        late = self.backup("install:acct@1.1.0", register="acct@1.1.0")
        r = self.restore(mid)
        st = self.settled()
        self.assertIn("acct@1.0.0", st.registrations)
        self.assertNotIn("acct@1.1.0", st.registrations)
        self.assertEqual(r.unregistered, ["acct@1.1.0"])

    def test_refusals_write_nothing(self):
        self.seed(); bid = self.backup()
        for bad in ("0000000000000000", "not-an-id"):
            with self.assertRaises(backups.BackupError):
                self.restore(bad)
        self.paths.backup_file(bid).write_bytes(b"garbage")
        with self.assertRaises(backups.BackupError):
            self.restore(bid)
        self.assertEqual(self.count("transactions"), 3)
        self.assertNotIn("restore", self.paths.index.read_text())

    def test_a_backup_from_another_schema_version_is_refused(self):
        self.seed(); bid = self.backup()
        copy = sqlite3.connect(str(self.paths.backup_file(bid)))
        copy.execute("UPDATE meta SET value='8' WHERE key='schema_version'"); copy.commit(); copy.close()
        with self.assertRaises(backups.BackupError) as cm:
            self.restore(bid)
        self.assertIn("schema", str(cm.exception))

    def test_a_column_shape_mismatch_refuses_naming_the_table_and_writes_nothing(self):
        # Same schema_version as the live ledger -- only the column-shape
        # preflight can fire here.
        self.seed(); bid = self.backup()
        copy = sqlite3.connect(str(self.paths.backup_file(bid)))
        copy.execute("ALTER TABLE transaction_tags ADD COLUMN extra TEXT")
        copy.commit(); copy.close()
        with self.assertRaises(backups.BackupError) as cm:
            self.restore(bid)
        self.assertIn("transaction_tags", str(cm.exception))
        self.assertEqual(self.count("transactions"), 3)
        self.assertNotIn("restore", self.paths.index.read_text())

    def test_an_unexpired_attempts_lease_refuses(self):
        self.seed(); bid = self.backup()
        self.conn.execute("INSERT INTO attempts(state_hash, phase, lease_token,"
                          " lease_expiry) VALUES ('h','exchange_started','t', ?)",
                          (__import__("time").time() + 60,))
        with self.assertRaises(backups.BackupError) as cm:
            self.restore(bid)
        self.assertIn("authorization is in progress", str(cm.exception))
        self.conn.execute("UPDATE attempts SET lease_expiry=0")
        self.restore(bid)

    def test_attach_inside_begin_immediate_is_permitted_on_this_sqlite(self):
        self.seed(); bid = self.backup()
        self.conn.execute("BEGIN IMMEDIATE")
        self.conn.execute("ATTACH DATABASE ? AS probe",
                          (self.paths.backup_file(bid).resolve().as_uri() + "?mode=ro",))
        with self.assertRaises(sqlite3.OperationalError):
            self.conn.execute("INSERT INTO probe.meta(key, value) VALUES ('x','y')")
        self.conn.execute("DETACH DATABASE probe")
        self.conn.execute("ROLLBACK")


RESTORE_AND_DIE = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
import backups, store
c = store.open_db(sys.argv[2]); paths = backups.paths_for(sys.argv[2])
c.execute("BEGIN IMMEDIATE")
st, h = backups.settle(c, paths)
# restore() commits, then appends the terminal record; die in between by
# replacing append after the pending record has gone out.
real_append = h.append
def dying(*fields):
    if fields[0] == "restore" and fields[2] == "committed":
        os._exit(0)
    real_append(*fields)
h.append = dying
backups.restore(c, paths, h, st, sys.argv[3], schema_version=store.SCHEMA_VERSION)
'''

SETTLE_ONCE = r'''
import sys
sys.path.insert(0, sys.argv[1])
import backups, store
c = store.open_db(sys.argv[2])
c.execute("BEGIN IMMEDIATE")
st, h = backups.settle(c, backups.paths_for(sys.argv[2]))
h.close(); c.execute("ROLLBACK")
print(st.generation)
'''


#: A child that runs the REAL `delete_all_data` and dies at the one instant the
#: finding lives at: the ledger COMMIT has landed, the copies have not been
#: touched. Patching `backups.erase_backups` to `os._exit(0)` is how the crash
#: is placed exactly there — a signal would race the commit.
ERASE_AND_DIE = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
import backups, store, tools_read, tools_destructive
tools_read.CONN = store.open_db(sys.argv[2])
def die(*a, **k):
    os._exit(0)
backups.erase_backups = die
tools_destructive.delete_all_data({})
'''


class TestTwoProcesses(RestoreBase):
    def test_an_erasure_that_dies_after_its_commit_still_removes_every_copy(self):
        # THE FINDING, reproduced with a real process really killed. Before the
        # `erase` record existed the child left an empty ledger beside an intact
        # whole-ledger copy and `restore` brought the transaction back, undoing
        # the one thing `delete_all_data` promises cannot be undone.
        self.seed()
        bid = self.backup()
        # No live consent, so the child asks no bank and needs no credential.
        self.conn.execute("UPDATE sessions SET closed_at='t'")
        subprocess.run([sys.executable, "-c", ERASE_AND_DIE, SRV, str(self.db)],
                       check=False, capture_output=True, timeout=60)
        crashed = self.index_lines()[-1].split()
        self.assertEqual([crashed[1], crashed[3]], ["erase", "pending"])
        erase_op = crashed[2]
        self.assertTrue(self.paths.backup_file(bid).is_file(),
                        "the copy outlived the crash — that is the whole point")
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM transactions").fetchone()[0], 0)
        # Recovery by the ordinary route: opening the ledger settles best-effort.
        store.open_db(self.db).close()
        self.assertEqual(sorted(p.name for p in self.paths.backups_dir.iterdir()), [])
        lines = self.index_lines()
        self.assertEqual(lines[-1].split()[1:], ["erase", erase_op, "committed"])
        self.assertIn(["prune", bid, "done"], [l.split()[1:] for l in lines])
        # And the id the operator was handed no longer restores anything.
        import tools_read, tools_backup
        tools_read.CONN = self.conn
        try:
            out = tools_backup.restore_backup({"backup_id": bid})
        finally:
            tools_read.CONN = None
        self.assertIn("no restorable backup %s" % bid, out)
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM transactions").fetchone()[0], 0)

    def test_a_restore_after_an_interrupted_erasure_says_what_settlement_removed(self):
        # The already-open process never re-ran open_db: its restore's own
        # settlement completes the erasure (unlinking the copy) and THEN
        # refuses the id. "Nothing was changed." would be false of the copy
        # that settlement just removed.
        self.seed()
        bid = self.backup()
        self.conn.execute("UPDATE sessions SET closed_at='t'")
        subprocess.run([sys.executable, "-c", ERASE_AND_DIE, SRV, str(self.db)],
                       check=False, capture_output=True, timeout=60)
        self.assertTrue(self.paths.backup_file(bid).is_file())
        import tools_read, tools_backup
        tools_read.CONN = self.conn
        try:
            out = tools_backup.restore_backup({"backup_id": bid})
        finally:
            tools_read.CONN = None
        self.assertIn("no restorable backup %s" % bid, out)
        self.assertIn("This call did not run; settlement first completed an "
                      "interrupted erasure and removed 1 backup copy(ies).", out)
        self.assertNotIn("Nothing was changed.", out)
        self.assertFalse(self.paths.backup_file(bid).exists())
        self.assertFalse(self.conn.in_transaction)

    def test_a_pending_erasure_is_completed_once_by_two_settling_processes(self):
        self.seed()
        bid = self.backup()
        with open(self.paths.index, "a") as f:
            f.write("%s erase abcdefabcdefabcd pending\n" % backups.now_ts())
        procs = [subprocess.Popen([sys.executable, "-c", SETTLE_ONCE, SRV, str(self.db)],
                                  stdout=subprocess.PIPE, text=True) for _ in range(2)]
        gens = [p.communicate(timeout=30)[0].strip() for p in procs]
        self.assertEqual(gens, ["0", "0"])
        self.assertFalse(self.paths.backup_file(bid).exists())
        lines = self.index_lines()
        self.assertEqual(len([l for l in lines if l.split()[1:2] == ["erase"]
                              and l.split()[3] == "committed"]), 1)
        self.assertEqual(len([l for l in lines if l.split()[1:2] == ["prune"]]), 1)

    def test_a_restore_that_dies_after_commit_settles_committed_once(self):
        self.seed(); bid = self.backup()
        subprocess.run([sys.executable, "-c", RESTORE_AND_DIE, SRV, str(self.db), bid],
                       check=False, capture_output=True, timeout=30)
        self.assertEqual(self.index_lines()[-1].split()[3], "pending")
        # two processes settle at once: exactly one terminal record
        procs = [subprocess.Popen([sys.executable, "-c", SETTLE_ONCE, SRV, str(self.db)],
                                  stdout=subprocess.PIPE, text=True) for _ in range(2)]
        gens = [p.communicate(timeout=30)[0].strip() for p in procs]
        self.assertEqual(gens, ["1", "1"])
        terminals = [l for l in self.index_lines() if l.split()[1:2] == ["restore"]
                     and l.split()[3] == "committed"]
        self.assertEqual(len(terminals), 1)

    def test_an_already_open_process_learns_of_the_restore_at_its_next_workflow_write(self):
        import tools_read, tools_annotate, tools_backup  # noqa
        ids = self.seed(); bid = self.backup()
        tools_read.CONN = self.conn
        try:
            first = tools_annotate.add_note({"row_ids": [ids[0]], "note": "a", "author": "agent",
                                             "workflow": "acct@1.0.0", "expected_generation": 0})
            self.assertIn("Note added", first)
            subprocess.run([sys.executable, "-c", RESTORE_AND_DIE, SRV, str(self.db), bid],
                           check=False, capture_output=True, timeout=30)
            out = tools_annotate.add_note({"row_ids": [ids[0]], "note": "b", "author": "agent",
                                           "workflow": "acct@1.0.0", "expected_generation": 0})
            self.assertIn("restored since this pass began", out)
            self.assertIn("generation is 1", out)
        finally:
            tools_read.CONN = None

    def test_two_first_writes_of_one_workflow_mint_one_backup(self):
        ids = self.seed()
        script = r'''
import sys, time
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[3])
import tools_read, store, tools_annotate, tools_backup
tools_read.CONN = store.open_db(sys.argv[2])
print(tools_annotate.add_note({"row_ids": [int(sys.argv[4])], "note": "n", "author": "agent",
                               "workflow": "acct@1.0.0", "expected_generation": 0}))
'''
        procs = [subprocess.Popen([sys.executable, "-c", script, SRV, str(self.db), SRV, str(ids[0])],
                                  stdout=subprocess.PIPE, text=True) for _ in range(2)]
        outs = [p.communicate(timeout=30)[0] for p in procs]
        self.assertEqual(sum("Restore point minted" in o for o in outs), 1)
        self.assertEqual(sum("Note added" in o for o in outs), 2)
        st = self.settled()
        self.assertEqual([b for b in st.backups.values() if b["reason"].startswith("install:")].__len__(), 1)

    def test_a_prune_in_another_process_waits_for_the_real_restore_past_its_attach(self):
        # Drives the REAL restore in a child and synchronises AFTER its ATTACH
        # (the first `_tables` call follows the attach): a ninth manual backup
        # launched at that instant must stay blocked — its prune would unlink
        # the file the restore is reading — until the restore commits. Under
        # the mutation "attach before taking the locks", the ninth backup
        # proceeds during the attach window and the assertion fails.
        self.seed()
        ids = [self.backup("manual") for _ in range(8)]
        oldest = ids[0]
        # The pause sits on the ACTUAL ATTACH statement, via a Connection
        # subclass injected through sqlite3.connect — not on a later restore
        # step, which a mutated implementation could reach after re-taking
        # the locks.
        restorer = subprocess.Popen([sys.executable, "-c", r'''
import sqlite3, sys, time; sys.path.insert(0, sys.argv[1])
class Tracing(sqlite3.Connection):
    def execute(self, sql, *a, **k):
        cur = super().execute(sql, *a, **k)
        if sql.lstrip().upper().startswith("ATTACH"):
            print("attached", flush=True); time.sleep(2.0)
        return cur
real_connect = sqlite3.connect
sqlite3.connect = lambda *a, **k: real_connect(*a, factory=Tracing, **k)
import backups, store
c = store.open_db(sys.argv[2]); p = backups.paths_for(sys.argv[2])
c.execute("BEGIN IMMEDIATE"); st, h = backups.settle(c, p)
r = backups.restore(c, p, h, st, sys.argv[3], schema_version=store.SCHEMA_VERSION)
h.close(); print("restored", r.op_id, flush=True)
''', SRV, str(self.db), oldest], stdout=subprocess.PIPE, text=True)
        self.assertEqual(restorer.stdout.readline().strip(), "attached")
        ninth = subprocess.Popen([sys.executable, "-c", r'''
import sys; sys.path.insert(0, sys.argv[1])
import backups, store
c = store.open_db(sys.argv[2]); p = backups.paths_for(sys.argv[2])
c.execute("BEGIN IMMEDIATE"); _, h = backups.settle(c, p)
b = backups.take_backup(c, p, h, "manual"); c.execute("COMMIT")
print(backups.finish_backup(p, h, b, committed=True)); h.close()
''', SRV, str(self.db)], stdout=subprocess.PIPE, text=True)
        import time; time.sleep(0.7)
        self.assertIsNone(ninth.poll(), "the ninth backup must be blocked behind the restore")
        self.assertTrue(self.paths.backup_file(oldest).exists())
        rest_out, _ = restorer.communicate(timeout=30)
        self.assertIn("restored", rest_out)
        out, _ = ninth.communicate(timeout=30)
        self.assertIn(oldest, out, "and then the prune runs")
        self.assertFalse(self.paths.backup_file(oldest).exists())
        self.assertEqual(self.settled().generation, 1)


if __name__ == "__main__":
    unittest.main()
