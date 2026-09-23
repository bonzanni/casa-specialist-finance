"""backup / list_backups / restore_backup."""
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import backups  # noqa: E402
import tools_auth  # noqa: E402
import tools_backup  # noqa: E402  (registration side effect)
import tools_read  # noqa: E402
from _toolbase import Base as _ToolBase, call  # noqa: E402


class Base(_ToolBase):
    def setUp(self):
        super().setUp()
        self.paths = backups.paths_for(self.root / "f.sqlite")
        self.raw.execute("INSERT INTO accounts(account_id, uid, session_id, currency,"
                         " incarnation) VALUES ('a1','u','s1','EUR','life-1')")
        self.raw.execute("INSERT INTO sessions(session_id, aspsp_name, status)"
                         " VALUES ('s1','Bank','AUTHORIZED')")


class TestBackupTool(Base):
    def test_backup_takes_weekly_or_manual_only(self):
        out = call("backup", reason="manual")
        self.assertRegex(out, r"Backup [0-9a-f]{16} written \(manual, \d+ bytes\)")
        self.assertIn("Nothing was changed", call("backup", reason="install:acct@1.0.0"))
        self.assertIn("Nothing was changed", call("backup", reason="daily"))
        self.assertIn("Nothing was changed", call("backup"))

    def test_list_backups_shows_generation_backups_registrations_and_restores(self):
        call("backup", reason="weekly")
        out = call("list_backups")
        self.assertIn("Restore generation: 0", out)
        self.assertRegex(out, r"[0-9a-f]{16}  \d{8}T\d{6}Z  \d+ B  weekly  committed")
        self.assertIn("Registered workflows: none", out)
        self.assertIn("Restores: none", out)

    def test_list_backups_names_a_broken_registration(self):
        # a registration whose file is gone
        self.raw.execute("INSERT INTO workflow_registrations VALUES ('acct@1.0.0',"
                         " 'aaaaaaaaaaaaaaaa', 't')")
        out = call("list_backups")
        self.assertIn("acct@1.0.0 -> aaaaaaaaaaaaaaaa (FILE MISSING — this workflow's"
                      " next write mints a new restore point; its earlier writes"
                      " are not covered)", out)

    def test_list_backups_rolls_back_and_releases_both_locks_on_an_unexpected_error(self):
        # Anything render_listing (or settle) throws that is NOT a
        # BackupError must not leave the module-singleton connection
        # `in_transaction`, or leave the index handle held -- either one
        # wedges every later write tool in this process.
        call("backup", reason="weekly")
        with mock.patch.object(tools_backup, "render_listing",
                               side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                call("list_backups")
        self.assertFalse(tools_read.CONN.in_transaction)
        # Proves neither the ledger lock nor the index lock leaked: a fresh
        # backup right after this needs BOTH.
        out = call("backup", reason="manual")
        self.assertRegex(out, r"Backup [0-9a-f]{16} written \(manual, \d+ bytes\)")

    def test_backup_reports_completion_even_when_retention_pruning_fails(self):
        # finish_backup runs AFTER the COMMIT: the backup is already real and
        # durable by the time retention can fail, so the tool must say so
        # rather than surface a bare error.
        with mock.patch.object(backups, "prune",
                               side_effect=backups.BackupError("disk full")):
            out = call("backup", reason="manual")
        self.assertRegex(out, r"Backup [0-9a-f]{16} written \(manual, \d+ bytes\)")
        self.assertIn("Retention could not prune: disk full — the backup itself "
                      "is complete.", out)


class TestAnIncompleteErasureIsStillReported(Base):
    """Settlement that unlinks copies and cannot unlink them all.

    By the time it can raise, the ledger's own erasure is already committed and
    some whole-ledger copies are gone, so "Nothing was changed" — the sentence
    every one of these tools printed for it — was false about the one event the
    operator most needed to hear about. The call itself really did not run, and
    that is the second half of the sentence, not the whole of it.
    """

    def _stuck_erasure(self):
        """-> (doomed id, removed id). Two real copies, a durable `erase`
        record, and a directory in which exactly one of them cannot go."""
        call("backup", reason="manual")
        call("backup", reason="manual")
        ids = sorted(p.name[:-len(".sqlite")]
                     for p in self.paths.backups_dir.glob("*.sqlite"))
        doomed = ids[0]
        with open(self.paths.index, "a") as f:
            f.write("%s erase abcdefabcdefabcd pending\n" % backups.now_ts())
        real_unlink = pathlib.Path.unlink
        self.addCleanup(setattr, pathlib.Path, "unlink", real_unlink)

        def selective(p, *a, **k):
            if p.name == doomed + ".sqlite":
                raise PermissionError(13, "Permission denied")
            return real_unlink(p, *a, **k)
        pathlib.Path.unlink = selective
        return doomed, ids[1]

    def test_backup_reports_what_the_settlement_removed(self):
        doomed, removed = self._stuck_erasure()
        out = call("backup", reason="manual")
        self.assertNotIn("Nothing was changed", out)
        self.assertIn("settlement removed 1 backup copy(ies) and 0 partial(s)", out)
        self.assertIn("1 whole copy(ies) could not be removed — EVERY BACKUP "
                      "IS A WHOLE COPY OF THIS LEDGER, so the copies that may "
                      "still be on disk hold this ledger's data. This call "
                      "did not run.", out)
        # It really did not run: no third copy, and the doomed one is what is
        # left of the two that were there.
        self.assertEqual([p.name for p in self.paths.backups_dir.iterdir()],
                         [doomed + ".sqlite"])
        self.assertNotIn(removed, out)

    def test_restore_backup_reports_it_too(self):
        doomed, _ = self._stuck_erasure()
        out = call("restore_backup", backup_id=doomed)
        self.assertNotIn("Nothing was changed", out)
        self.assertIn("This call did not run.", out)

    def test_list_backups_shows_the_residue_the_count_refers_to(self):
        # THE ONE CALL THAT CHANGES NOTHING STILL ANSWERS. Refusing it left the
        # operator told that a copy could not be removed and denied the only
        # in-tool view of which copy that is — while every other call refuses.
        doomed, removed = self._stuck_erasure()
        out = call("list_backups")
        # Whole copies and copies in flight are counted APART: a `.partial`
        # never reached the index, so the listing below has no row for one and
        # a single lumped count promised the operator rows that are not there.
        # The set of calls that refuse is named exactly, and this listing --
        # answered rather than refused -- is the proof a read is not in it.
        self.assertIn("Backup erasure incomplete: 1 whole copy(ies) could not "
                      "be removed — EVERY BACKUP IS A WHOLE COPY OF THIS "
                      "LEDGER, so the copies that may still be on disk hold "
                      "this ledger's data. No backup, restore, total erasure "
                      "or workflow write runs until the erasure completes; "
                      "reads, this one included, still answer. Every INDEXED "
                      "copy is listed below — a copy in flight never reached "
                      "the index and has no row.", out)
        self.assertRegex(out, r"%s  \d{8}T\d{6}Z  \d+ B  manual  committed"
                         % doomed)
        self.assertIn("%s  " % removed, out)
        self.assertIn("pruned", out)
        self.assertIn("Restore generation: 0", out)

    def test_the_listing_counts_whole_copies_and_partials_apart(self):
        # One lumped total over a whole copy and a copy in flight promised two
        # rows below it, and only one is there: a `.partial` never reached the
        # index. The two also carry different weight -- only a whole copy is
        # restorable -- which the alarm sentence already depends on.
        call("backup", reason="manual")
        self.paths.partial_file("b" * 16).write_bytes(b"half a copy")
        with open(self.paths.index, "a") as f:
            f.write("%s erase abcdefabcdefabcd pending\n" % backups.now_ts())
        real_unlink = pathlib.Path.unlink
        self.addCleanup(setattr, pathlib.Path, "unlink", real_unlink)

        def refuse(p, *a, **k):
            raise PermissionError(13, "Permission denied")
        pathlib.Path.unlink = refuse
        out = call("list_backups")
        pathlib.Path.unlink = real_unlink
        self.assertIn("1 whole copy(ies) could not be removed", out)
        self.assertIn("1 unfinished copy(ies) could not be removed", out)
        self.assertNotIn("2 copy(ies) could not be removed", out)


class TestRestoreTool(Base):
    def test_restore_backup_is_protected_and_declared(self):
        from _toolbase import declared_protected
        self.assertIn("restore_backup", tools_auth.PROTECTED)
        self.assertIn("restore_backup", declared_protected())
        tools_auth._PROTECTED_CACHE = set()          # simulate a lost declaration
        out = call("restore_backup", backup_id="aaaaaaaaaaaaaaaa")
        self.assertIn("NOT declared", out)

    def test_restore_reports_what_it_did_and_the_stale_reports_line(self):
        bid = call("backup", reason="manual").split()[1]
        self.raw.execute("INSERT INTO transactions(account_id, identity_key, occurrence,"
                         " amount_minor, currency, direction) VALUES ('a1','k',0,1,'EUR','DBIT')")
        out = call("restore_backup", backup_id=bid)
        self.assertIn("Restored backup %s" % bid, out)
        self.assertIn("consent bindings kept live: 1 account(s)", out)
        self.assertIn("transactions: 0 row(s)", out)
        self.assertIn("Refresh reports produced while this restore ran may be stale; run sync.", out)
        self.assertIn("Restore generation: 1", call("list_backups"))

    def test_a_refusal_says_nothing_was_changed(self):
        out = call("restore_backup", backup_id="0000000000000000")
        self.assertIn("Nothing was changed", out)

    def test_a_committed_restore_whose_index_record_fails_is_not_reported_as_a_refusal(self):
        # `backups.restore` COMMITs and THEN appends the terminal record. A
        # failure there used to leave as a BackupError, land in the tool's
        # `except backups.BackupError` -- whose `c.in_transaction` guard is
        # already False because the COMMIT ran -- and print "Nothing was
        # changed." for a restore that had replaced every ordinary table.
        bid = call("backup", reason="manual").split()[1]
        self.raw.execute("INSERT INTO transactions(account_id, identity_key, occurrence,"
                         " amount_minor, currency, direction) VALUES ('a1','k',0,1,'EUR','DBIT')")
        real = backups.IndexHandle.append

        def append(handle, *fields):
            if fields[0] == "restore" and fields[-1] == "committed":
                raise backups.BackupError("the backup index could not be written: ENOSPC")
            return real(handle, *fields)
        with mock.patch.object(backups.IndexHandle, "append", append):
            out = call("restore_backup", backup_id=bid)
        self.assertNotIn("Nothing was changed", out)
        self.assertIn("Restored backup %s" % bid, out)
        self.assertIn("The restore is complete; its index record could not be "
                      "written (the backup index could not be written: ENOSPC) "
                      "— it settles at the next listing.", out)
        # The rows really are restored, and the generation the next listing
        # reports is 1: the `pending` record plus the committed marker settle
        # the operation the append could not record.
        self.assertEqual(self.raw.execute(
            "SELECT count(*) FROM transactions").fetchone()[0], 0)
        self.assertIn("Restore generation: 1", call("list_backups"))
