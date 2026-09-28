"""Issue #89: `export_history` carries a per-row note revision beside the
tag revision.

The contract a consumer relies on: for one ledger instance id and one row_id,
an EQUAL `note_revision` means an EQUAL note journal. Notes are not exported,
so a missed bump is silent twice over — the export stays well-formed and
nothing in it shows the journal. Every test here drives a real tool (or the
real `apply_plan`) and asserts the revision moved for exactly the rows whose
notes changed, and stayed for every other row.
"""
import csv
import io
import json
import pathlib
import sqlite3
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))

import apply  # noqa: E402
import backups  # noqa: E402
import ingest  # noqa: E402
import store  # noqa: E402
import tools_annotate  # noqa: E402,F401  (registers add_note)
import tools_backup  # noqa: E402,F401  (registers backup/restore_backup)
import tools_destructive  # noqa: E402
import tools_read  # noqa: E402
import tools_refresh  # noqa: E402,F401  (registers export_history)
from _toolbase import call  # noqa: E402
from test_apply import CAP_STABLE, IV, row  # noqa: E402
from test_tools_destructive import DestructiveBase, pre_erasure_id  # noqa: E402


class RevisionBase(DestructiveBase):
    def setUp(self):
        super().setUp()
        self.session()
        self.account()
        for ik in ("ik1", "ik2", "ik3"):
            self.tx(ik=ik)
        self.a, self.b, self.c = [r[0] for r in self.raw.execute(
            "SELECT row_id FROM transactions ORDER BY row_id")]

    def note(self, *rids, text="n"):
        out = call("add_note", row_ids=list(rids), note=text, author="agent")
        self.assertEqual(self.notes_of(rids[0])[-1], text, out)

    def rev(self, rid):
        r = self.raw.execute("SELECT revision FROM note_revisions WHERE row_id=?",
                             (rid,)).fetchone()
        return 0 if r is None else r[0]

    def tag_rev(self, rid):
        r = self.raw.execute("SELECT revision FROM tag_revisions WHERE row_id=?",
                             (rid,)).fetchone()
        return 0 if r is None else r[0]

    def revs(self):
        return {rid: self.rev(rid) for rid in (self.a, self.b, self.c)}

    def seq(self):
        r = self.raw.execute("SELECT value FROM meta WHERE key=?",
                             (store.NOTE_REVISION_SEQ_KEY,)).fetchone()
        return None if r is None else int(r[0])

    def notes_of(self, rid):
        return [r[0] for r in self.raw.execute(
            "SELECT note FROM transaction_notes WHERE row_id=? ORDER BY note_id",
            (rid,))]

    def assertMoved(self, before, moved):
        after = self.revs()
        for rid in before:
            if rid in moved:
                self.assertGreater(after[rid], before[rid], rid)
            else:
                self.assertEqual(after[rid], before[rid], rid)
        return after

    def export(self, fmt):
        out = call("export_history", format=fmt)
        path = pathlib.Path(out.strip().splitlines()[-1].split(": ", 1)[1])
        text = path.read_text("utf-8")
        if fmt == "csv":
            return list(csv.DictReader(io.StringIO(text)))
        return [json.loads(line) for line in text.splitlines()]


class TestEveryWriterMovesTheRevision(RevisionBase):
    def test_a_note_moves_only_its_row(self):
        before, seq = self.revs(), self.seq()
        self.note(self.a)
        self.assertMoved(before, {self.a})
        self.assertGreater(self.seq(), seq or 0)

    def test_a_note_on_several_rows_moves_each(self):
        before = self.revs()
        self.note(self.a, self.c)
        self.assertMoved(before, {self.a, self.c})

    def test_every_further_note_moves_it_again(self):
        # The issue's first residual: the accounting note drops out of
        # get_transaction's newest-20 window once 20 more are appended. A
        # consumer holding the revision it confirmed the note at must see a
        # different one after ANY append, not only after the 20th.
        self.note(self.a, text="acct note")
        confirmed = self.rev(self.a)
        seen = {confirmed}
        for i in range(20):
            self.note(self.a, text="later %d" % i)
            self.assertNotIn(self.rev(self.a), seen)
            seen.add(self.rev(self.a))
        out = call("get_transaction", row_id=self.a)
        self.assertNotIn("acct note", out)

    def test_tags_and_notes_move_independently(self):
        self.note(self.a)
        notes, tags = self.rev(self.a), self.tag_rev(self.a)
        call("tag_transaction", row_ids=[self.a], tags=["software"])
        self.assertEqual(self.rev(self.a), notes)
        tagged = self.tag_rev(self.a)
        self.assertGreater(tagged, tags)
        self.note(self.a)
        self.assertEqual(self.tag_rev(self.a), tagged)

    def test_an_edit_of_any_note_column_moves_it(self):
        # Nothing edits a note today; if something ever does, the journal
        # changed and the revision must say so, whichever column it was.
        self.note(self.a)
        for col, value in (("note", "edited"), ("author", "user"),
                           ("created_at", "2000-01-01T00:00:00Z")):
            before = self.revs()
            self.raw.execute("UPDATE transaction_notes SET %s=? WHERE row_id=?"
                             % col, (value, self.a))
            self.assertMoved(before, {self.a})

    def test_a_purge_that_erases_user_work_moves_the_rows_it_stripped(self):
        # The issue's second residual: a note stripped from a row that
        # carries no tags at all. The purge deletes no row (none is booked
        # before the date) but strips every note.
        self.note(self.a)
        before, seq = self.revs(), self.seq()
        instance = store.ledger_instance(self.raw)
        call("purge", before_date="2000-01-01", user_work="erase")
        self.assertEqual(self.notes_of(self.a), [])
        self.assertEqual(self.count("transactions"), 3)
        self.assertMoved(before, {self.a})
        self.assertGreater(self.seq(), seq)
        self.assertEqual(store.ledger_instance(self.raw), instance)

    def test_a_purge_that_keeps_user_work_moves_nothing_it_kept(self):
        self.note(self.a)
        before, seq = self.revs(), self.seq()
        call("purge", before_date="2000-01-01", user_work="keep")
        self.assertEqual(self.notes_of(self.a), ["n"])
        self.assertMoved(before, set())
        self.assertEqual(self.seq(), seq)

    def test_a_forget_moves_the_forgotten_rows_and_keeps_the_count(self):
        self.note(self.a)
        seq = self.seq()
        before = self.revs()
        instance = store.ledger_instance(self.raw)
        call("forget_local_account", account_id="acc1")
        self.assertGreater(self.rev(self.a), before[self.a])
        self.assertGreater(self.seq(), seq)
        self.assertEqual(store.ledger_instance(self.raw), instance)


class TestSupersede(RevisionBase):
    def test_a_supersede_moves_the_old_row_and_its_replacement(self):
        plan = ingest.reconcile([], [row("2026-02-05", ref="R1", status="PDNG")],
                                IV, CAP_STABLE)
        apply.apply_plan(self.raw, "acc1", plan)
        old = self.raw.execute("SELECT row_id FROM transactions"
                               " WHERE provider_ref='R1'").fetchone()[0]
        self.note(old, text="acct")
        rows = [dict(r) for r in self.raw.execute(
            "SELECT * FROM transactions WHERE account_id='acc1'"
            " AND provider_ref='R1'")]
        plan2 = ingest.reconcile(
            rows, [row("2026-02-06", ref="R1", status="BOOK")], IV, CAP_STABLE)
        self.assertEqual([u["op"] for u in plan2.updates], ["supersede"])
        before_old, before_others = self.rev(old), self.revs()
        apply.apply_plan(self.raw, "acc1", plan2)
        new = self.raw.execute("SELECT superseded_by FROM transactions"
                               " WHERE row_id=?", (old,)).fetchone()[0]
        self.assertIsNotNone(new)
        self.assertEqual(self.notes_of(new), ["acct"])
        self.assertEqual(self.notes_of(old), [])
        self.assertGreater(self.rev(old), before_old)
        self.assertGreater(self.rev(new), 0)
        self.assertMoved(before_others, set())


class TestRestoreNeverReissuesARevision(RevisionBase):
    def test_a_restore_moves_every_row_whose_notes_it_rewrote(self):
        # a: one note at backup time, a second after it. The restore takes
        # the second away; the revision must differ from BOTH values a
        # consumer may hold.
        self.note(self.a, text="first")
        at_backup = self.rev(self.a)
        bid = call("backup", reason="manual").split()[1]
        self.note(self.a, text="second")
        after_note = self.rev(self.a)
        untouched = self.rev(self.c)
        call("restore_backup", backup_id=bid)
        self.assertEqual(self.notes_of(self.a), ["first"])
        self.assertGreater(self.rev(self.a), max(at_backup, after_note))
        # c never had a note on either side: its (empty) journal is unchanged.
        self.assertEqual(self.rev(self.c), untouched)

    def test_the_count_and_revisions_are_not_rolled_back(self):
        self.note(self.a)
        bid = call("backup", reason="manual").split()[1]
        for text in ("x1", "x2", "x3"):
            self.note(self.b, text=text)
        seq = self.seq()
        call("restore_backup", backup_id=bid)
        self.assertGreater(self.seq(), seq)
        self.assertGreater(self.rev(self.b), seq)
        self.assertEqual(self.notes_of(self.b), [])

    def test_a_backup_from_before_the_revision_restores(self):
        # A pre-upgrade backup has no note_revisions table and no triggers.
        self.note(self.a, text="first")
        bid = call("backup", reason="manual").split()[1]
        path = backups.paths_for(self.root / "f.sqlite").backup_file(bid)
        old = sqlite3.connect(path)
        for name in store.NOTE_REVISION_TRIGGERS:
            old.execute("DROP TRIGGER %s" % name)
        old.execute("DROP TABLE note_revisions")
        old.commit()
        old.close()
        self.note(self.a, text="second")
        after_note = self.rev(self.a)
        out = call("restore_backup", backup_id=bid)
        self.assertNotIn("does not match", out)
        self.assertEqual(self.notes_of(self.a), ["first"])
        self.assertGreater(self.rev(self.a), after_note)

    def test_a_purge_and_its_restore_keep_the_count_rising(self):
        self.note(self.a)
        seq = self.seq()
        instance = store.ledger_instance(self.raw)
        out = call("purge", before_date="all", user_work="erase")
        self.assertEqual(store.ledger_instance(self.raw), instance)
        self.assertGreater(self.seq(), seq)
        purged = self.seq()
        call("restore_backup", backup_id=pre_erasure_id(out))
        self.assertEqual(self.notes_of(self.a), ["n"])
        self.assertGreater(self.rev(self.a), purged)


class TestTheCountRestartsOnlyWithANewInstance(RevisionBase):
    def _check(self, tool):
        self.note(self.a)
        instance = store.ledger_instance(self.raw)
        self.assertIsNotNone(self.seq())
        call(tool)
        self.assertEqual(self.count("transaction_notes"), 0)
        self.assertEqual(self.count(store.NOTE_REVISIONS_TABLE), 0)
        self.assertIsNone(self.seq())
        self.assertNotEqual(store.ledger_instance(self.raw), instance)

    def test_delete_all_data(self):
        self._check("delete_all_data")

    def test_delete_data_keep_signins(self):
        self._check("delete_data_keep_signins")

    def test_every_meta_whitelist_that_keeps_the_instance_keeps_the_count(self):
        for kept in (tools_destructive.STRUCTURAL_META_KEYS,
                     tools_destructive.STRUCTURAL_META_KEYS
                     + tools_destructive.WITHDRAWAL_META_KEYS):
            self.assertEqual(store.LEDGER_INSTANCE_KEY in kept,
                             store.NOTE_REVISION_SEQ_KEY in kept)
        for prefix in tools_destructive.SIGNIN_META_PREFIXES:
            self.assertFalse(store.NOTE_REVISION_SEQ_KEY.startswith(prefix))

    def test_the_revision_table_is_live_state_for_a_restore(self):
        self.assertIn(store.NOTE_REVISIONS_TABLE, backups.KEEP_LIVE_TABLES)
        data = tools_destructive._DATA_TABLES
        self.assertGreater(data.index(store.NOTE_REVISIONS_TABLE),
                           data.index("transaction_notes"))


class TestInstall(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.db = pathlib.Path(self.dir.name) / "f.sqlite"
        store.open_db(self.db).close()
        # A ledger from 0.21.0: the tag revision installed, the note one not.
        raw = sqlite3.connect(self.db)
        for name in store.NOTE_REVISION_TRIGGERS:
            raw.execute("DROP TRIGGER %s" % name)
        raw.execute("DROP TABLE note_revisions")
        raw.commit()
        raw.close()

    def insert(self, conn, rid):
        conn.execute("INSERT INTO transaction_notes(row_id, author, note,"
                     " created_at) VALUES (?, 'agent', 'x', 't')", (rid,))

    def test_an_open_installs_it_on_a_ledger_from_before_it(self):
        conn = store.open_db(self.db)
        self.addCleanup(conn.close)
        self.assertEqual(self.installed(conn), self.expected())
        self.insert(conn, 7)
        self.assertEqual(self.revision(conn, 7), 1)

    def test_an_open_that_cannot_install_it_fails_closed(self):
        holder = sqlite3.connect(self.db, isolation_level=None)
        self.addCleanup(holder.close)
        holder.execute("BEGIN IMMEDIATE")
        with mock.patch.object(store, "_SETTLE_BUSY_MS", 50):
            with self.assertRaises(store.StoreError) as caught:
                store.open_db(self.db)
        self.assertIn("busy", str(caught.exception))
        holder.execute("ROLLBACK")
        conn = store.open_db(self.db)
        self.addCleanup(conn.close)
        self.assertEqual(self.installed(conn), self.expected())

    def test_each_missing_trigger_alone_is_reinstalled(self):
        store.open_db(self.db).close()
        for name in store.NOTE_REVISION_TRIGGERS:
            raw = sqlite3.connect(self.db)
            raw.execute("DROP TRIGGER %s" % name)
            raw.commit()
            raw.close()
            conn = store.open_db(self.db)
            # Read independently of `_revisions_missing`, which is what
            # decides the install.
            self.assertEqual(self.installed(conn), self.expected(), name)
            conn.close()

    def expected(self):
        return {"note_revisions"} | set(store.NOTE_REVISION_TRIGGERS)

    def installed(self, conn):
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE name='note_revisions'"
            " OR (type='trigger' AND name LIKE 'trg_note_rev_%')")}

    def revision(self, conn, rid):
        return conn.execute("SELECT revision FROM note_revisions WHERE row_id=?",
                            (rid,)).fetchone()[0]


class TestExport(RevisionBase):
    def setUp(self):
        super().setUp()
        self.note(self.a, text="acct")
        self.note(self.a, text="later")
        self.note(self.b)
        call("purge", before_date="2000-01-01", user_work="erase")
        self.note(self.a, text="after purge")

    def _get(self, rid):
        out = call("get_transaction", row_id=rid)
        line = [l for l in out.splitlines() if l.startswith("Note revision: ")]
        self.assertEqual(len(line), 1, out)
        return int(line[0].split()[2])

    def test_csv_carries_the_revision_as_get_transaction_reads_it(self):
        rows = {int(r["row_id"]): r for r in self.export("csv")}
        for rid in (self.a, self.b, self.c):
            rev = self._get(rid)
            self.assertEqual(int(rows[rid]["note_revision"]), rev)
            self.assertEqual(rev, self.rev(rid))
        # b's note was stripped: no notes, but a revision above 0 — the
        # removal is visible.
        self.assertEqual(self.notes_of(self.b), [])
        self.assertGreater(int(rows[self.b]["note_revision"]), 0)
        self.assertEqual(rows[self.c]["note_revision"], "0")

    def test_jsonl_carries_an_integer(self):
        rows = {r["row_id"]: r for r in self.export("jsonl")}
        for rid in (self.a, self.b, self.c):
            self.assertIs(type(rows[rid]["note_revision"]), int)
            self.assertEqual(rows[rid]["note_revision"], self._get(rid))

    def test_the_revision_comes_from_the_rows_snapshot(self):
        # Another process appends a note after the export read its rows: the
        # export must still describe one moment.
        other = store.open_db(self.root / "f.sqlite")
        self.addCleanup(other.close)
        before = self.rev(self.c)
        real = tools_read.CONN
        target = self.c

        class Racing:
            def __getattr__(self, name):
                return getattr(real, name)

            def execute(self, sql, *a):
                cur = real.execute(sql, *a)
                if sql.startswith("SELECT") and "FROM transactions ORDER BY" in sql:
                    rows = cur.fetchall()
                    other.execute("INSERT INTO transaction_notes(row_id, author,"
                                  " note, created_at) VALUES (?, 'agent',"
                                  " 'late', 't')", (target,))
                    return iter(rows)
                return cur

        tools_read.CONN = Racing()
        self.addCleanup(setattr, tools_read, "CONN", real)
        rows = {r["row_id"]: r for r in self.export("jsonl")}
        self.assertEqual(rows[self.c]["note_revision"], before)
        self.assertGreater(self.rev(self.c), before)

    def test_the_appended_column_cannot_shadow_a_ledger_column(self):
        self.raw.execute("ALTER TABLE transactions ADD COLUMN note_revision"
                         " INTEGER")
        with self.assertRaises(RuntimeError):
            call("export_history", format="csv")


if __name__ == "__main__":
    unittest.main()
