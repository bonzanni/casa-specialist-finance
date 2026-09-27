"""The open lock (issues #74, #76): every open of either mode's ledger in one
data directory is one critical section.

The races are between processes, so the cases that matter run real
subprocesses against the real modules, released at the same instant. A
single-process test cannot show either defect.
"""
import fcntl
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

SERVER = pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"
sys.path.insert(0, str(SERVER))

import backups  # noqa: E402
import ebmode  # noqa: E402
import store  # noqa: E402

TRIALS = 12

#: argv: server dir, release time, "db" or "ledger". Prints OK or the refusal.
CHILD = textwrap.dedent("""
    import os, sys, time
    sys.path.insert(0, sys.argv[1])
    import store
    release = float(sys.argv[2])
    while time.time() < release:
        pass
    try:
        if sys.argv[3] == "db":
            c = store.open_db()
        else:
            c = store.open_ledger(os.environ["CLAUDE_PLUGIN_DATA"])
        c.close()
        print("OK")
    except Exception as exc:
        print("FAIL %s: %s" % (type(exc).__name__, exc))
""")


def race(data, modes, entry):
    """Start one child per mode on `data`, all released at one instant."""
    release = repr(time.time() + 0.5)
    children = []
    for mode in modes:
        env = dict(os.environ, CLAUDE_PLUGIN_DATA=data)
        env[ebmode.ENV_MODE_VAR] = mode
        children.append(subprocess.Popen(
            [sys.executable, "-c", CHILD, str(SERVER), release, entry],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True))
    return [c.communicate(timeout=120)[0].strip() for c in children]


class TestTwoFirstOpens(unittest.TestCase):
    """#74: two processes opening a ledger that does not exist yet."""

    def test_both_open_and_the_file_is_created_once(self):
        for _ in range(TRIALS):
            with tempfile.TemporaryDirectory() as data:
                outcomes = race(data, ["", ""], "db")
                self.assertEqual(outcomes, ["OK", "OK"])
                names = os.listdir(data)
                # A loser that read the half-built schema as a pre-versioning
                # ledger took a migration snapshot of it.
                self.assertEqual(
                    [n for n in names if backups.SNAPSHOT_INFIX in n], [])
                c = sqlite3.connect(os.path.join(data, "bank_feed.sqlite"))
                try:
                    version = c.execute("SELECT value FROM meta WHERE"
                                        " key='schema_version'").fetchone()
                finally:
                    c.close()
                self.assertEqual(version, (str(store.SCHEMA_VERSION),))


class TestTwoModesFirstOpens(unittest.TestCase):
    """#76: a production and a sandbox process first-opening one directory."""

    def test_exactly_one_mode_owns_the_directory(self):
        for _ in range(TRIALS):
            with tempfile.TemporaryDirectory() as data:
                outcomes = race(data, ["", "SANDBOX"], "ledger")
                self.assertEqual(sorted(o == "OK" for o in outcomes),
                                 [False, True], outcomes)
                loser = [o for o in outcomes if o != "OK"][0]
                self.assertTrue(loser.startswith("FAIL StoreError"), loser)
                self.assertNotIn("unreadable", loser)
                ledgers = sorted(n for n in os.listdir(data)
                                 if n.endswith(".sqlite"))
                self.assertEqual(len(ledgers), 1, ledgers)
                winner = ("SANDBOX" if ledgers == ["bank_feed.sandbox.sqlite"]
                          else "PRODUCTION")
                self.assertEqual(
                    pathlib.Path(data, "eb-environment").read_text().strip(),
                    winner)


class InProcess(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = pathlib.Path(d.name)
        self.addCleanup(os.environ.pop, ebmode.ENV_MODE_VAR, None)
        self.addCleanup(ebmode._reset)
        os.environ.pop(ebmode.ENV_MODE_VAR, None)
        ebmode._reset()


class TestABusyLedgerIsNotACorruptOne(InProcess):
    def test_a_lock_in_the_pragma_block_says_busy(self):
        # A rollback-journal file under another connection's EXCLUSIVE lock:
        # the WAL switch cannot proceed, and SQLite says SQLITE_BUSY.
        db = self.root / "f.sqlite"
        holder = sqlite3.connect(str(db), isolation_level=None)
        self.addCleanup(holder.close)
        holder.execute("CREATE TABLE t(x)")
        holder.execute("BEGIN EXCLUSIVE")
        self.addCleanup(setattr, store, "_SETTLE_BUSY_MS",
                        store._SETTLE_BUSY_MS)
        store._SETTLE_BUSY_MS = 100
        with self.assertRaises(store.StoreError) as caught:
            store.open_db(db)
        text = str(caught.exception)
        self.assertIn("the ledger is busy", text)
        self.assertNotIn("unreadable", text)
        self.assertNotIn("re-link", text)

    def test_damage_keeps_the_corruption_wording(self):
        db = self.root / "f.sqlite"
        db.write_bytes(b"not a database" * 512)
        with self.assertRaises(store.StoreError) as caught:
            store.open_db(db)
        self.assertIn("unreadable", str(caught.exception))


class TestTheOpenLockWaitIsBounded(InProcess):
    def hold(self):
        fd = os.open(str(self.root / store._OPEN_LOCK_FILENAME),
                     os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.addCleanup(setattr, store, "OPEN_LOCK_WAIT_S",
                        store.OPEN_LOCK_WAIT_S)
        store.OPEN_LOCK_WAIT_S = 0.2

    def test_open_db_refuses_as_busy_and_creates_nothing(self):
        self.hold()
        with self.assertRaises(store.StoreError) as caught:
            store.open_db(self.root / "bank_feed.sqlite")
        self.assertIn("another process is opening it", str(caught.exception))
        self.assertFalse((self.root / "bank_feed.sqlite").exists())

    def test_open_ledger_refuses_as_busy_and_claims_nothing(self):
        self.hold()
        with self.assertRaises(store.StoreError):
            store.open_ledger(str(self.root))
        self.assertFalse((self.root / "bank_feed.sqlite").exists())
        self.assertFalse((self.root / "eb-environment").exists())

    def test_the_lock_is_released_after_an_open(self):
        store.open_db(self.root / "bank_feed.sqlite").close()
        store.open_ledger(str(self.root)).close()
        fd = os.open(str(self.root / store._OPEN_LOCK_FILENAME), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)


class TestAWriterDoesNotQueueHealthyOpens(InProcess):
    def test_concurrent_opens_wait_for_the_writer_side_by_side(self):
        # The open-time settlement pass waits out another process's writer
        # for the busy timeout. Under the open lock those waits would queue
        # one behind another until the open lock's own wait refused the
        # later opens; outside it they overlap. flock conflicts between open
        # file descriptions, so threads contend exactly as processes do.
        import threading
        db = self.root / "bank_feed.sqlite"
        store.open_db(db).close()
        backups.paths_for(db).index.touch()      # settlement is attempted
        holder = subprocess.Popen(
            [sys.executable, "-c", textwrap.dedent("""
                import sqlite3, sys
                c = sqlite3.connect(sys.argv[1], isolation_level=None)
                c.execute("BEGIN IMMEDIATE")
                print("held", flush=True)
                sys.stdin.readline()
            """), str(db)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addCleanup(holder.wait)
        self.addCleanup(holder.stdin.close)
        self.addCleanup(holder.stdout.close)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        self.addCleanup(setattr, store, "_SETTLE_BUSY_MS",
                        store._SETTLE_BUSY_MS)
        self.addCleanup(setattr, store, "OPEN_LOCK_WAIT_S",
                        store.OPEN_LOCK_WAIT_S)
        store._SETTLE_BUSY_MS = 400
        store.OPEN_LOCK_WAIT_S = 1.0             # < four serialized waits
        outcomes = []

        def one_open():
            try:
                store.open_db(db).close()
                outcomes.append("OK")
            except store.StoreError as exc:
                outcomes.append(str(exc))

        threads = [threading.Thread(target=one_open) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(outcomes, ["OK"] * 4)


class TestOpenLedgerChecksUnderTheLock(InProcess):
    def test_the_other_modes_ledger_refuses_before_creating_this_ones(self):
        # The dispatch-time check passed before the other mode's ledger
        # appeared; the check inside the lock is the one that holds.
        (self.root / "bank_feed.sandbox.sqlite").write_bytes(b"")
        with self.assertRaises(store.StoreError) as caught:
            store.open_ledger(str(self.root))
        self.assertIn("other mode's ledger", str(caught.exception))
        self.assertFalse((self.root / "bank_feed.sqlite").exists())
        self.assertFalse((self.root / "eb-environment").exists())


if __name__ == "__main__":
    unittest.main()
