"""The ledger instance id and the `expected_ledger` fence (issue #69).

A workflow that keeps its own records about bank-feed rows binds to the id
`list_backups` reports, and fences its annotation writes with it. The id is
bound to the ledger's story: a restore and `purge` keep it,
`delete_all_data` (the uninstall eraser) replaces it, and a
recreated file has a new one.
"""
import pathlib
import re
import sqlite3
import subprocess
import sys
import textwrap
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import backups  # noqa: E402
import store  # noqa: E402
import tools_annotate  # noqa: E402,F401  (registers the annotation writes)
import tools_backup  # noqa: E402,F401  (registers backup/list_backups/restore_backup)
import tools_destructive  # noqa: E402,F401  (registers delete_all_data)
import tools_read  # noqa: E402
import tools_refresh  # noqa: E402  (registers export_history)
from _toolbase import Base, call, dispatch  # noqa: E402

HEX32 = r"[0-9a-f]{32}"
OTHER = "f" * 32


def listed_id(listing: str) -> str:
    """By label, as a consumer reads it — never by position: the dispatcher
    prepends settlement sentences and the sandbox banner. Exactly one line."""
    found = re.findall(r"^Ledger instance: (\S+)$", listing, re.M)
    assert len(found) == 1, listing
    return found[0]


class TestTheId(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = pathlib.Path(self.dir.name)

    def open(self, name="f.sqlite"):
        conn = store.open_db(self.root / name)
        self.addCleanup(conn.close)
        return conn

    def test_a_fresh_ledger_is_minted_an_id_at_creation(self):
        conn = self.open()
        self.assertRegex(store.ledger_instance(conn), "^%s$" % HEX32)

    def test_reopening_the_same_file_keeps_it(self):
        first = store.ledger_instance(self.open())
        self.assertEqual(store.ledger_instance(self.open()), first)

    def test_two_files_have_two_ids(self):
        self.assertNotEqual(store.ledger_instance(self.open("a.sqlite")),
                            store.ledger_instance(self.open("b.sqlite")))

    def test_a_ledger_from_before_the_id_existed_is_minted_one_on_open(self):
        # Every install that predates #69 has no row; its next open mints one,
        # once, and later opens keep it.
        conn = self.open()
        conn.execute("DELETE FROM meta WHERE key=?", (store.LEDGER_INSTANCE_KEY,))
        self.assertIsNone(store.ledger_instance(conn))
        minted = store.ledger_instance(self.open())
        self.assertRegex(minted, "^%s$" % HEX32)
        self.assertEqual(store.ledger_instance(self.open()), minted)

    def test_a_migration_mints_it_too(self):
        conn = self.open()
        conn.execute("DELETE FROM meta WHERE key=?", (store.LEDGER_INSTANCE_KEY,))
        conn.execute("UPDATE meta SET value='8' WHERE key='schema_version'")
        conn.close()
        self.assertRegex(store.ledger_instance(self.open()), "^%s$" % HEX32)

    def test_the_accessor_never_mints(self):
        conn = self.open()
        conn.execute("DELETE FROM meta WHERE key=?", (store.LEDGER_INSTANCE_KEY,))
        self.assertIsNone(store.ledger_instance(conn))
        self.assertEqual(conn.execute("SELECT count(*) FROM meta WHERE key=?",
                                      (store.LEDGER_INSTANCE_KEY,)).fetchone()[0], 0)


class ToolBase(Base):
    def setUp(self):
        super().setUp()
        self.paths = backups.paths_for(self.root / "f.sqlite")
        self.raw.execute(
            "INSERT INTO accounts(account_id, uid, iban_masked, name, currency,"
            " category, included, first_seen, last_seen) VALUES"
            " ('acc1','u1','NL••1234','Betaalrekening','EUR','personal',1,"
            " '2026-01-01','2026-08-01')")
        cur = self.raw.execute(
            "INSERT INTO transactions(account_id, identity_key, occurrence,"
            " booking_date, amount_minor, currency, direction, status,"
            " counterparty, remittance, state, match_method) VALUES"
            " ('acc1','t1',0,'2026-02-01',1000,'EUR','DBIT','BOOK','ACME BV',"
            " 'invoice 7','active','reference')")
        self.rid = cur.lastrowid
        self.id = store.ledger_instance(self.raw)

    def count(self, table):
        return self.raw.execute("SELECT count(*) FROM %s" % table).fetchone()[0]

    def backup_files(self):
        d = self.paths.backups_dir
        return sorted(p.name for p in d.iterdir()) if d.exists() else []


class TestABusyFirstOpen(ToolBase):
    """An open must not need the write lock: a steady-state open does not
    write, and the one open that must (a ledger that predates the id) does
    not fail when another process holds the lock — `list_backups` mints."""

    def hold_the_ledger(self):
        holder = subprocess.Popen(
            [sys.executable, "-c", textwrap.dedent("""
                import sqlite3, sys, time
                c = sqlite3.connect(sys.argv[1], isolation_level=None)
                c.execute("BEGIN IMMEDIATE")
                print("held", flush=True)
                sys.stdin.readline()
            """), str(self.root / "f.sqlite")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        self.addCleanup(holder.stdout.close)
        self.addCleanup(holder.stdin.close)
        self.addCleanup(holder.wait)
        self.addCleanup(holder.kill)
        self.addCleanup(setattr, store, "_SETTLE_BUSY_MS", store._SETTLE_BUSY_MS)
        store._SETTLE_BUSY_MS = 200
        return holder

    def release(self, holder):
        holder.stdin.write("go\n"); holder.stdin.flush(); holder.wait()

    def test_a_steady_state_open_does_not_try_to_mint(self):
        # Minting unconditionally is masked by the busy tolerance below — the
        # open still succeeds — but it waits out the busy timeout on every
        # open while another process writes. Only an absent id may write.
        from unittest import mock
        with mock.patch.object(store, "ensure_ledger_instance",
                               side_effect=AssertionError("minted on a steady-state open")):
            conn = store.open_db(self.root / "f.sqlite")
        self.addCleanup(conn.close)
        self.assertEqual(store.ledger_instance(conn), self.id)

    def test_a_busy_first_open_does_not_wait_for_the_writer(self):
        # Swallowing "database is locked" after the full busy timeout turned
        # "another process is writing" into a ten-second open. No backup
        # index exists here, so settlement is skipped and cannot wait either.
        import time
        self.raw.execute("DELETE FROM meta WHERE key=?", (store.LEDGER_INSTANCE_KEY,))
        self.hold_the_ledger()
        store._SETTLE_BUSY_MS = 10000
        t0 = time.monotonic()
        conn = store.open_db(self.root / "f.sqlite")
        elapsed = time.monotonic() - t0
        self.addCleanup(conn.close)
        self.assertLess(elapsed, 3.0)
        self.assertIsNone(store.ledger_instance(conn))
        # The connection keeps its ordinary busy timeout for everything else.
        self.assertEqual(conn.execute("PRAGMA busy_timeout").fetchone()[0], 10000)

    def test_a_steady_state_open_succeeds_under_the_lock_and_keeps_the_id(self):
        self.hold_the_ledger()
        conn = store.open_db(self.root / "f.sqlite")
        self.addCleanup(conn.close)
        self.assertEqual(store.ledger_instance(conn), self.id)

    def test_a_busy_first_open_opens_without_an_id_and_list_backups_mints_it(self):
        self.raw.execute("DELETE FROM meta WHERE key=?", (store.LEDGER_INSTANCE_KEY,))
        holder = self.hold_the_ledger()
        conn = store.open_db(self.root / "f.sqlite")     # must not raise
        self.addCleanup(conn.close)
        self.assertIsNone(store.ledger_instance(conn))
        # Meanwhile the fence fails closed: no id matches nothing.
        self.release(holder)
        out = call("add_note", row_ids=[self.rid], note="a", author="agent",
                   expected_ledger=OTHER)
        self.assertIn("instance none", out)
        minted = listed_id(call("list_backups"))
        self.assertRegex(minted, "^%s$" % HEX32)
        self.assertEqual(store.ledger_instance(conn), minted)
        self.assertEqual(listed_id(call("list_backups")), minted)


class TestEverySiteThatNamesTheIdHasOne(ToolBase):
    """A busy first open can leave a pre-#69 ledger without an id. Every site
    that reports the id while it can write mints it first, so no reply
    names an id that is not there."""

    def setUp(self):
        super().setUp()
        self.raw.execute("DELETE FROM meta WHERE key=?", (store.LEDGER_INSTANCE_KEY,))

    def stored(self):
        return store.ledger_instance(self.raw)

    def test_delete_all_data_leaves_a_new_id_even_from_none(self):
        out = call("delete_all_data")
        self.assertIn("The ledger instance id was replaced by a new one", out)
        self.assertRegex(self.stored(), "^%s$" % HEX32)
        self.assertEqual(listed_id(call("list_backups")), self.stored())

    def test_the_incomplete_erasure_listing_mints_it_too(self):
        call("backup", reason="manual")
        doomed = sorted(p.name for p in self.paths.backups_dir.glob("*.sqlite"))[0]
        with open(self.paths.index, "a") as f:
            f.write("%s erase abcdefabcdefabcd pending\n" % backups.now_ts())
        real_unlink = pathlib.Path.unlink
        self.addCleanup(setattr, pathlib.Path, "unlink", real_unlink)

        def selective(p, *a, **k):
            if p.name == doomed:
                raise PermissionError(13, "Permission denied")
            return real_unlink(p, *a, **k)
        pathlib.Path.unlink = selective
        self.raw.execute("DELETE FROM meta WHERE key=?", (store.LEDGER_INSTANCE_KEY,))
        out = call("list_backups")
        self.assertIn("A recorded erasure of the backup copies could not be finished", out)
        self.assertRegex(self.stored(), "^%s$" % HEX32)
        self.assertEqual(listed_id(out), self.stored())
        # ...and through the dispatcher, which prepends what settlement did.
        self.assertEqual(listed_id(dispatch("list_backups")), self.stored())
        self.assertFalse(self.raw.in_transaction)

    def test_export_history_mints_it_before_naming_it(self):
        out = call("export_history", format="csv")
        self.assertRegex(self.stored(), "^%s$" % HEX32)
        self.assertIn("Ledger instance: %s" % self.stored(), out)

    def test_an_export_that_cannot_record_the_id_writes_no_file(self):
        holder = subprocess.Popen(
            [sys.executable, "-c", textwrap.dedent("""
                import sqlite3, sys
                c = sqlite3.connect(sys.argv[1], isolation_level=None)
                c.execute("BEGIN IMMEDIATE")
                print("held", flush=True)
                sys.stdin.readline()
            """), str(self.root / "f.sqlite")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addCleanup(holder.stdout.close)
        self.addCleanup(holder.stdin.close)
        self.addCleanup(holder.wait)
        self.addCleanup(holder.kill)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        self.raw.execute("PRAGMA busy_timeout=200")
        out = call("export_history", format="csv")
        self.assertIn("The export was not written", out)
        self.assertNotIn("Ledger instance", out)
        self.assertEqual(list(self.handoff.rglob("ledger-export-*")), [])
        self.assertIsNone(self.stored())

    def test_a_steady_state_export_does_not_need_the_write_lock(self):
        call("list_backups")                     # the id exists from here on
        holder = subprocess.Popen(
            [sys.executable, "-c", textwrap.dedent("""
                import sqlite3, sys
                c = sqlite3.connect(sys.argv[1], isolation_level=None)
                c.execute("BEGIN IMMEDIATE")
                print("held", flush=True)
                sys.stdin.readline()
            """), str(self.root / "f.sqlite")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addCleanup(holder.stdout.close)
        self.addCleanup(holder.stdin.close)
        self.addCleanup(holder.wait)
        self.addCleanup(holder.kill)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        self.raw.execute("PRAGMA busy_timeout=200")
        out = call("export_history", format="csv")
        self.assertIn("Ledger instance: %s" % self.stored(), out)

    def test_ensure_never_replaces_an_id_another_process_minted(self):
        # The race: this process read "absent", another minted, this one
        # writes. INSERT OR IGNORE keeps the first; a check-then-replace would
        # give one file two ids. Simulated by a stale first read.
        from unittest import mock
        self.raw.execute("INSERT INTO meta(key, value) VALUES (?, ?)",
                         (store.LEDGER_INSTANCE_KEY, OTHER))
        real = store.ledger_instance
        reads = []

        def stale_first(conn):
            reads.append(1)
            return None if len(reads) == 1 else real(conn)
        with mock.patch.object(store, "ledger_instance", side_effect=stale_first):
            store.ensure_ledger_instance(self.raw)
        self.assertEqual(self.stored(), OTHER)
        self.assertEqual(store.ensure_ledger_instance(self.raw), OTHER)


class _AtStatement:
    """The connection the tools use, with one interleaving: just before (or,
    with `after`, just after) the first statement matching `when`, `then()`
    runs on a SECOND, real connection to the same file — another process's
    erasure landing at the worst moment."""

    def __init__(self, conn, when, then, after=False):
        self._conn, self._when, self._then, self._after = conn, when, then, after

    def execute(self, sql, *a, **k):
        if self._then is None or not self._when(sql):
            return self._conn.execute(sql, *a, **k)
        then, self._then = self._then, None
        if not self._after:
            then()
            return self._conn.execute(sql, *a, **k)
        cur = self._conn.execute(sql, *a, **k)
        then()
        return cur

    def __getattr__(self, name):
        return getattr(self._conn, name)


class TestAnErasureInAnotherProcess(ToolBase):
    NEW = "e" * 32

    def erase_elsewhere(self, insert_row=False):
        def run():
            other = sqlite3.connect(str(self.root / "f.sqlite"), isolation_level=None)
            try:
                other.execute("BEGIN IMMEDIATE")
                other.execute("UPDATE meta SET value=? WHERE key=?",
                              (self.NEW, store.LEDGER_INSTANCE_KEY))
                if insert_row:
                    other.execute(
                        "INSERT INTO transactions(account_id, identity_key, occurrence,"
                        " booking_date, amount_minor, currency, direction, status,"
                        " state, match_method) VALUES ('acc1','after',0,'2026-03-01',"
                        " 5,'EUR','DBIT','BOOK','active','reference')")
                other.execute("COMMIT")
            finally:
                other.close()
        return run

    def interleave(self, when, then, after=False):
        self.addCleanup(setattr, tools_read, "CONN", tools_read.CONN)
        tools_read.CONN = _AtStatement(tools_read.CONN, when, then, after)

    def test_the_fence_reads_the_id_under_its_own_lock(self):
        # The id read and the write are one atomic step only if the read is
        # INSIDE the write transaction: a new id committed just before
        # BEGIN IMMEDIATE must refuse a write fenced with the old one.
        self.interleave(lambda sql: sql.strip().startswith("BEGIN IMMEDIATE"),
                        self.erase_elsewhere())
        out = call("add_note", row_ids=[self.rid], note="a", author="agent",
                   expected_ledger=self.id)
        self.assertIn("this is a different ledger (instance %s" % self.NEW, out)
        self.assertEqual(self.count("transaction_notes"), 0)

    def export_under(self, when):
        self.interleave(when, self.erase_elsewhere(insert_row=True))
        out = call("export_history", format="jsonl")
        path = pathlib.Path(out.strip().splitlines()[-1].split(": ", 1)[1])
        keys = [__import__("json").loads(l)["identity_key"]
                for l in path.read_text("utf-8").splitlines()]
        labelled = re.search(r"^Ledger instance: (\S+)$", out, re.M).group(1)
        self.assertIn((labelled, keys), [(self.id, ["t1"]),
                                         (self.NEW, ["after", "t1"]),
                                         (self.NEW, ["t1", "after"])])
        self.assertFalse(self.raw.in_transaction)

    def test_an_incomplete_erasure_listing_labels_the_state_it_shows(self):
        # The listing's state is captured in its settlement transaction; an
        # erasure elsewhere right after that transaction rolls back must not
        # pair the new id with the old registrations.
        call("add_note", row_ids=[self.rid], note="a", author="agent",
             workflow="acct@1.0.0", expected_generation=0)
        doomed = sorted(p.name for p in self.paths.backups_dir.glob("*.sqlite"))[0]
        with open(self.paths.index, "a") as f:
            f.write("%s erase abcdefabcdefabcd pending\n" % backups.now_ts())
        real_unlink = pathlib.Path.unlink
        self.addCleanup(setattr, pathlib.Path, "unlink", real_unlink)

        def selective(p, *a, **k):
            if p.name == doomed:
                raise PermissionError(13, "Permission denied")
            return real_unlink(p, *a, **k)
        pathlib.Path.unlink = selective
        self.interleave(lambda sql: sql.strip() == "ROLLBACK", self.erase_elsewhere(),
                        after=True)
        out = call("list_backups")
        self.assertIn("A recorded erasure of the backup copies could not be finished", out)
        self.assertIn("acct@1.0.0 -> ", out)          # the captured, pre-erasure state
        self.assertEqual(listed_id(out), self.id)      # ...and ITS id
        self.assertEqual(store.ledger_instance(self.raw), self.NEW)

    def test_a_listing_labels_the_settled_state_with_the_id_inside_its_snapshot(self):
        # An erasure elsewhere just before the listing's BEGIN IMMEDIATE:
        # the listing's state is post-erasure, so its id must be too.
        self.interleave(lambda sql: sql.strip() == "BEGIN IMMEDIATE",
                        self.erase_elsewhere())
        self.assertEqual(listed_id(call("list_backups")), self.NEW)

    def test_a_listing_mints_inside_its_transaction_when_the_first_mint_cannot(self):
        # The mint before the snapshot fails (the ledger is busy); the
        # listing's own write transaction mints, and its COMMIT keeps it.
        from unittest import mock
        self.raw.execute("DELETE FROM meta WHERE key=?", (store.LEDGER_INSTANCE_KEY,))
        with mock.patch.object(store, "reported_ledger_instance", return_value=None):
            out = call("list_backups")
        self.assertRegex(listed_id(out), "^%s$" % HEX32)
        self.assertEqual(store.ledger_instance(self.raw), listed_id(out))

    def test_an_export_whose_id_vanished_before_the_snapshot_writes_no_file(self):
        def drop_id():
            other = sqlite3.connect(str(self.root / "f.sqlite"), isolation_level=None)
            try:
                other.execute("DELETE FROM meta WHERE key=?", (store.LEDGER_INSTANCE_KEY,))
            finally:
                other.close()
        self.interleave(lambda sql: sql.strip() == "BEGIN", drop_id)
        out = call("export_history", format="csv")
        self.assertIn("The export was not written", out)
        self.assertEqual(list(self.handoff.rglob("ledger-export-*")), [])
        self.assertFalse(self.raw.in_transaction)

    def test_an_export_that_fails_mid_snapshot_leaves_no_transaction_open(self):
        from unittest import mock
        with mock.patch.object(tools_refresh, "_export_columns",
                               side_effect=sqlite3.OperationalError("disk I/O error")):
            with self.assertRaises(sqlite3.OperationalError):
                call("export_history", format="csv")
        self.assertFalse(self.raw.in_transaction)
        self.assertIn("Ledger instance: %s" % self.id, call("export_history", format="csv"))

    def test_an_export_labels_exactly_the_rows_it_wrote(self):
        # Rows and id are one snapshot: an erasure (new id, new row)
        # committed while the export runs must never produce post-erasure
        # rows under the pre-erasure id — at the rows query...
        self.export_under(lambda sql: "FROM transactions ORDER BY" in sql)

    def test_an_erasure_just_before_the_snapshot_is_labelled_too(self):
        # ...or just before the snapshot opens, which catches an id read
        # outside it.
        self.export_under(lambda sql: sql.strip() == "BEGIN")


class TestReporting(ToolBase):
    def test_list_backups_names_the_instance(self):
        self.assertEqual(listed_id(call("list_backups")), self.id)

    def test_the_dispatched_listing_names_it_under_a_settlement_sentence(self):
        # A pending erase record settles at the next listing, and the
        # dispatcher prepends what that settlement did: the id line is found
        # by its label under it.
        call("backup", reason="manual")
        with open(self.paths.index, "a") as f:
            f.write("%s erase abcdefabcdefabcd pending\n" % backups.now_ts())
        out = dispatch("list_backups")
        self.assertFalse(out.startswith("Ledger instance"), out)   # something was prepended
        self.assertEqual(listed_id(out), self.id)

    def test_the_sandbox_listing_names_it_under_the_banner(self):
        import os
        import bank_feed_server
        import ebmode
        self.addCleanup(os.environ.pop, ebmode.ENV_MODE_VAR, None)
        self.addCleanup(ebmode._reset)
        os.environ[ebmode.ENV_MODE_VAR] = "SANDBOX"
        ebmode._reset()
        out = dispatch("list_backups")
        self.assertTrue(out.startswith(bank_feed_server.SANDBOX_BANNER), out)
        self.assertEqual(listed_id(out), self.id)

    def test_export_history_names_the_instance_and_keeps_the_path_last(self):
        out = call("export_history", format="csv")
        self.assertIn("Ledger instance: %s" % self.id, out)
        self.assertTrue(out.strip().splitlines()[-1].startswith("Path: "))


class TestLifetime(ToolBase):
    def test_delete_all_data_replaces_the_id(self):
        # The uninstall eraser: an erased ledger is not the same ledger
        # emptied, so a workflow bound to the old id must see a different one.
        out = call("delete_all_data")
        self.assertIn("The ledger instance id was replaced by a new one, so a "
                      "workflow bound to the old one now sees a different "
                      "ledger.", out)
        self.assertEqual(self.count("transactions"), 0)
        new = store.ledger_instance(self.raw)
        self.assertRegex(new, "^%s$" % HEX32)
        self.assertNotEqual(new, self.id)
        self.assertEqual(listed_id(call("list_backups")), new)
        self.assertEqual(self.raw.execute("SELECT count(*) FROM meta WHERE key=?",
                                          (store.LEDGER_INSTANCE_KEY,)).fetchone()[0], 1)

    def test_a_whole_ledger_purge_keeps_the_id(self):
        # The in-use reset: same ledger, started fresh.
        out = call("purge", before_date="all", user_work="erase")
        self.assertEqual(self.count("transactions"), 0, out)
        self.assertEqual(store.ledger_instance(self.raw), self.id)
        self.assertEqual(listed_id(call("list_backups")), self.id)

    def test_a_restore_keeps_the_live_id_not_the_backups(self):
        bid = call("backup", reason="manual").split()[1]
        copy = sqlite3.connect(str(self.paths.backup_file(bid)))
        with copy:
            copy.execute("UPDATE meta SET value=? WHERE key=?",
                         (OTHER, store.LEDGER_INSTANCE_KEY))
        copy.close()
        out = call("restore_backup", backup_id=bid)
        self.assertIn("Restored backup %s" % bid, out)
        self.assertEqual(store.ledger_instance(self.raw), self.id)


class TestTheFence(ToolBase):
    def notes(self):
        return self.count("transaction_notes")

    def test_the_matching_id_writes_with_or_without_a_workflow(self):
        out = call("add_note", row_ids=[self.rid], note="a", author="agent",
                   expected_ledger=self.id)
        self.assertIn("Note added", out)
        out = call("tag_transaction", row_ids=[self.rid], tags=["acct::x"],
                   workflow="acct@1.0.0", expected_generation=0,
                   expected_ledger=self.id)
        self.assertIn("Tagged 1 row(s)", out)
        out = call("untag_transaction", row_ids=[self.rid], tags=["acct::x"],
                   workflow="acct@1.0.0", expected_generation=0,
                   expected_ledger=self.id)
        self.assertIn("1 tag-row pair(s) removed", out)
        self.assertEqual(self.notes(), 1)

    def test_a_different_ledger_refuses_every_write_and_writes_nothing(self):
        for name, extra in (("add_note", {"note": "a", "author": "agent"}),
                            ("tag_transaction", {"tags": ["x"]}),
                            ("untag_transaction", {"tags": ["x"]})):
            self.raw.execute("INSERT OR IGNORE INTO transaction_tags"
                             "(row_id, tag, added_at) VALUES (?, 'x', 't')", (self.rid,))
            out = call(name, row_ids=[self.rid], expected_ledger=OTHER, **extra)
            self.assertIn("this is a different ledger (instance %s, the pass "
                          "expected %s)" % (self.id, OTHER), out, name)
            self.assertIn("This call's own operation changed nothing", out, name)
            self.assertNotIn("Nothing was changed", out, name)
        self.assertEqual(self.notes(), 0)
        self.assertEqual(self.count("transaction_tags"), 1)
        self.assertFalse(self.raw.in_transaction)

    def test_a_different_ledger_refuses_workflow_bearing_writes_too(self):
        self.raw.execute("INSERT INTO transaction_tags(row_id, tag, added_at)"
                         " VALUES (?, 'acct::held', 't')", (self.rid,))
        for name, extra in (("add_note", {"note": "a", "author": "agent"}),
                            ("tag_transaction", {"tags": ["acct::new"]}),
                            ("untag_transaction", {"tags": ["acct::held"]})):
            out = call(name, row_ids=[self.rid], workflow="acct@1.0.0",
                       expected_generation=0, expected_ledger=OTHER, **extra)
            self.assertIn("this is a different ledger", out, name)
        self.assertEqual(self.notes(), 0)
        self.assertEqual([r[0] for r in self.raw.execute(
            "SELECT tag FROM transaction_tags")], ["acct::held"])
        self.assertEqual(self.count("workflow_registrations"), 0)

    def test_a_different_ledger_with_a_workflow_mints_nothing_and_registers_nothing(self):
        out = call("add_note", row_ids=[self.rid], note="a", author="agent",
                   workflow="acct@1.0.0", expected_generation=0,
                   expected_ledger=OTHER)
        self.assertIn("this is a different ledger", out)
        self.assertEqual(self.notes(), 0)
        self.assertEqual(self.count("workflow_registrations"), 0)
        self.assertEqual(self.backup_files(), [])

    def test_the_ledger_check_precedes_the_generation_check(self):
        # A different ledger makes its generation meaningless: the refusal
        # names the ledger, not a restore.
        out = call("add_note", row_ids=[self.rid], note="a", author="agent",
                   workflow="acct@1.0.0", expected_generation=7,
                   expected_ledger=OTHER)
        self.assertIn("this is a different ledger", out)
        self.assertNotIn("restored since this pass began", out)

    def test_the_ledger_check_precedes_row_validation(self):
        out = call("add_note", row_ids=[999], note="a", author="agent",
                   expected_ledger=OTHER)
        self.assertIn("this is a different ledger", out)
        self.assertNotIn("#999", out)

    def test_an_absent_live_id_refuses(self):
        self.raw.execute("DELETE FROM meta WHERE key=?", (store.LEDGER_INSTANCE_KEY,))
        out = call("add_note", row_ids=[self.rid], note="a", author="agent",
                   expected_ledger=self.id)
        self.assertIn("this is a different ledger (instance none, the pass "
                      "expected %s)" % self.id, out)
        self.assertEqual(self.notes(), 0)

    def test_a_malformed_expected_ledger_refuses_before_the_ledger_is_read(self):
        for name, extra in (("add_note", {"note": "a", "author": "agent"}),
                            ("tag_transaction", {"tags": ["x"]}),
                            ("untag_transaction", {"tags": ["x"]})):
            for bad in (None, self.id.upper(), self.id[:-1], self.id + "0", "", 7,
                        True, ["x"], " " + self.id):
                out = call(name, row_ids=[self.rid], expected_ledger=bad, **extra)
                self.assertIn("expected_ledger must be", out, (name, repr(bad)))
                self.assertIn("This call's own operation changed nothing", out,
                              (name, repr(bad)))
        self.assertEqual(self.notes(), 0)
        self.assertEqual(self.count("transaction_tags"), 0)

    def test_a_malformed_expected_ledger_never_reaches_the_ledger(self):
        from unittest import mock
        with mock.patch.object(tools_read, "conn",
                               side_effect=AssertionError("ledger opened")):
            out = call("add_note", row_ids=[self.rid], note="a", author="agent",
                       expected_ledger="nope")
        self.assertIn("expected_ledger must be", out)

    def test_the_ledger_check_precedes_settlement(self):
        # A settlement that cannot finish refuses the write with its own
        # text. On a different ledger nothing this call would do is wanted,
        # settling included: the ledger refusal comes first.
        call("backup", reason="manual")
        doomed = sorted(p.name for p in self.paths.backups_dir.glob("*.sqlite"))[0]
        with open(self.paths.index, "a") as f:
            f.write("%s erase abcdefabcdefabcd pending\n" % backups.now_ts())
        real_unlink = pathlib.Path.unlink
        self.addCleanup(setattr, pathlib.Path, "unlink", real_unlink)

        def selective(p, *a, **k):
            if p.name == doomed:
                raise PermissionError(13, "Permission denied")
            return real_unlink(p, *a, **k)
        pathlib.Path.unlink = selective
        out = call("add_note", row_ids=[self.rid], note="a", author="agent",
                   workflow="acct@1.0.0", expected_generation=0,
                   expected_ledger=OTHER)
        self.assertIn("this is a different ledger", out)
        self.assertNotIn("erasure", out)
        # ...and the same write on THIS ledger does meet the settlement.
        out = call("add_note", row_ids=[self.rid], note="a", author="agent",
                   workflow="acct@1.0.0", expected_generation=0,
                   expected_ledger=self.id)
        self.assertIn("erasure", out)
        self.assertEqual(self.notes(), 0)

    def test_after_delete_all_data_the_old_id_is_refused_and_the_new_one_writes(self):
        call("delete_all_data")
        self.raw.execute(
            "INSERT INTO accounts(account_id, uid, iban_masked, name, currency,"
            " category, included, first_seen, last_seen) VALUES"
            " ('acc1','u1','NL••1234','B','EUR','personal',1,'2026-01-01','2026-08-01')")
        rid = self.raw.execute(
            "INSERT INTO transactions(account_id, identity_key, occurrence,"
            " booking_date, amount_minor, currency, direction, status, state,"
            " match_method) VALUES ('acc1','t2',0,'2026-02-01',1,'EUR','DBIT',"
            " 'BOOK','active','reference')").lastrowid
        out = call("add_note", row_ids=[rid], note="a", author="agent",
                   expected_ledger=self.id)
        self.assertIn("this is a different ledger", out)
        self.assertEqual(self.notes(), 0)
        out = call("add_note", row_ids=[rid], note="a", author="agent",
                   expected_ledger=listed_id(call("list_backups")))
        self.assertIn("Note added", out)

    def test_every_annotation_write_declares_the_argument(self):
        import bank_feed_server
        for name in ("tag_transaction", "untag_transaction", "add_note"):
            props = bank_feed_server.TOOLS[name]["schema"]["properties"]
            self.assertEqual(props["expected_ledger"], {"type": "string"}, name)
            self.assertIn("expected_ledger", bank_feed_server.TOOLS[name]["description"], name)


if __name__ == "__main__":
    unittest.main()
