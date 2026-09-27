"""The ledger instance id and the `expected_ledger` fence (issue #69).

A workflow that keeps its own records about bank-feed rows binds to the id
`list_backups` reports, and fences its annotation writes with it. The id is
bound to the database FILE: a restore and `delete_all_data` keep it, a
recreated file has a new one.
"""
import pathlib
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
import tools_refresh  # noqa: E402,F401  (registers export_history)
from _toolbase import Base, call  # noqa: E402

HEX32 = r"[0-9a-f]{32}"
OTHER = "f" * 32


def listed_id(listing: str) -> str:
    first = listing.splitlines()[0]
    assert first.startswith("Ledger instance: "), first
    return first.split(": ", 1)[1]


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

    def test_delete_all_data_mints_the_id_it_says_remains(self):
        out = call("delete_all_data")
        self.assertIn("the ledger instance id remain", out)
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
        self.assertIn("Ledger instance: %s" % self.stored(), out)
        self.assertFalse(self.raw.in_transaction)

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


class TestReporting(ToolBase):
    def test_list_backups_names_the_instance_first(self):
        self.assertEqual(listed_id(call("list_backups")), self.id)

    def test_export_history_names_the_instance_and_keeps_the_path_last(self):
        out = call("export_history", format="csv")
        self.assertIn("Ledger instance: %s" % self.id, out)
        self.assertTrue(out.strip().splitlines()[-1].startswith("Path: "))


class TestLifetime(ToolBase):
    def test_delete_all_data_keeps_the_id(self):
        out = call("delete_all_data")
        self.assertIn("the ledger instance id", out)
        self.assertEqual(self.count("transactions"), 0)
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
        for bad in (self.id.upper(), self.id[:-1], self.id + "0", "", 7, True,
                    ["x"], " " + self.id):
            out = call("add_note", row_ids=[self.rid], note="a", author="agent",
                       expected_ledger=bad)
            self.assertIn("expected_ledger must be", out, repr(bad))
            self.assertIn("This call's own operation changed nothing", out, repr(bad))
        self.assertEqual(self.notes(), 0)

    def test_a_write_after_delete_all_data_still_matches(self):
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
        self.assertIn("Note added", out)

    def test_every_annotation_write_declares_the_argument(self):
        import bank_feed_server
        for name in ("tag_transaction", "untag_transaction", "add_note"):
            props = bank_feed_server.TOOLS[name]["schema"]["properties"]
            self.assertEqual(props["expected_ledger"], {"type": "string"}, name)
            self.assertIn("expected_ledger", bank_feed_server.TOOLS[name]["description"], name)


if __name__ == "__main__":
    unittest.main()
