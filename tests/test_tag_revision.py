"""Issue #86: `export_history` carries each row's current tags and a per-row
tag revision.

The contract a consumer relies on: for one ledger instance id and one row_id,
an EQUAL `tag_revision` means an EQUAL tag set. A missed bump is silent — the
export stays well-formed — so every test here drives a real tool (or the real
`apply_plan`) and asserts the revision moved for exactly the rows whose tags
changed, and stayed for every other row.
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
import tools_annotate  # noqa: E402,F401  (registers the tag tools)
import tools_backup  # noqa: E402,F401  (registers backup/restore_backup)
import tools_destructive  # noqa: E402
import tools_read  # noqa: E402
import tools_refresh  # noqa: E402
import tools_rules  # noqa: E402,F401  (registers add_rule/apply_rules)
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

    def rev(self, rid):
        r = self.raw.execute("SELECT revision FROM tag_revisions WHERE row_id=?",
                             (rid,)).fetchone()
        return 0 if r is None else r[0]

    def revs(self):
        return {rid: self.rev(rid) for rid in (self.a, self.b, self.c)}

    def seq(self):
        r = self.raw.execute("SELECT value FROM meta WHERE key=?",
                             (store.TAG_REVISION_SEQ_KEY,)).fetchone()
        return None if r is None else int(r[0])

    def tags_of(self, rid):
        return [r[0] for r in self.raw.execute(
            "SELECT tag FROM transaction_tags WHERE row_id=? ORDER BY tag",
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
    def test_a_tag_moves_only_its_row(self):
        before = self.revs()
        call("tag_transaction", row_ids=[self.a], tags=["software"])
        self.assertMoved(before, {self.a})

    def test_tagging_a_tag_the_row_already_has_moves_nothing(self):
        call("tag_transaction", row_ids=[self.a], tags=["software"])
        before, seq = self.revs(), self.seq()
        call("tag_transaction", row_ids=[self.a], tags=["software"])
        self.assertMoved(before, set())
        self.assertEqual(self.seq(), seq)

    def test_an_untag_moves_its_row(self):
        call("tag_transaction", row_ids=[self.a, self.b], tags=["software"])
        before = self.revs()
        call("untag_transaction", row_ids=[self.a], tags=["software"])
        self.assertMoved(before, {self.a})
        self.assertEqual(self.tags_of(self.a), [])

    def test_a_rename_moves_every_row_carrying_the_tag(self):
        call("tag_transaction", row_ids=[self.a, self.b], tags=["softwre"])
        call("tag_transaction", row_ids=[self.b], tags=["software"])
        before = self.revs()
        # b already has the new name: its old tag is DELETED, not renamed.
        out = call("rename_tag", old="softwre", new="software", merge=True)
        self.assertIn("Renamed", out)
        self.assertMoved(before, {self.a, self.b})
        self.assertEqual(self.tags_of(self.b), ["software"])

    def test_a_tag_deletion_moves_every_row_carrying_it(self):
        call("tag_transaction", row_ids=[self.a, self.c], tags=["refund"])
        before = self.revs()
        call("delete_tag", tag="refund")
        self.assertMoved(before, {self.a, self.c})

    def test_a_rule_application_moves_only_the_rows_it_tagged(self):
        call("add_rule", counterparty="ACME BV", tags=["office"])
        self.raw.execute("UPDATE transactions SET counterparty='ACME BV'"
                         " WHERE row_id=?", (self.b,))
        before = self.revs()
        call("apply_rules", row_ids=[self.a, self.b, self.c])
        self.assertMoved(before, {self.b})
        # Applying again inserts nothing: `INSERT OR IGNORE` must not bump.
        again = self.revs()
        call("apply_rules", row_ids=[self.a, self.b, self.c])
        self.assertMoved(again, set())

    def test_a_forget_moves_the_forgotten_rows_and_keeps_the_count(self):
        call("tag_transaction", row_ids=[self.a], tags=["software"])
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
        call("tag_transaction", row_ids=[old], tags=["software"])
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
        self.assertEqual(self.tags_of(new), ["software"])
        self.assertGreater(self.rev(old), before_old)
        self.assertGreater(self.rev(new), 0)
        self.assertMoved(before_others, set())


class TestRestoreNeverReissuesARevision(RevisionBase):
    def test_a_restore_moves_every_row_whose_tags_it_rewrote(self):
        # a: software at backup time, untagged after it. The restore brings
        # "software" back; the revision must differ from BOTH values a
        # consumer may hold.
        call("tag_transaction", row_ids=[self.a], tags=["software"])
        at_backup = self.rev(self.a)
        bid = call("backup", reason="manual").split()[1]
        call("untag_transaction", row_ids=[self.a], tags=["software"])
        after_untag = self.rev(self.a)
        untouched = self.rev(self.c)
        call("restore_backup", backup_id=bid)
        self.assertEqual(self.tags_of(self.a), ["software"])
        self.assertGreater(self.rev(self.a), max(at_backup, after_untag))
        # c never had a tag on either side: its (empty) set is unchanged.
        self.assertEqual(self.rev(self.c), untouched)

    def test_the_count_and_revisions_are_not_rolled_back(self):
        call("tag_transaction", row_ids=[self.a], tags=["software"])
        bid = call("backup", reason="manual").split()[1]
        for tag in ("x1", "x2", "x3"):
            call("tag_transaction", row_ids=[self.b], tags=[tag])
        seq = self.seq()
        call("restore_backup", backup_id=bid)
        self.assertGreater(self.seq(), seq)
        self.assertGreater(self.rev(self.b), seq - 3)
        self.assertEqual(self.tags_of(self.b), [])

    def test_a_backup_from_before_the_revision_restores(self):
        # A pre-upgrade backup has no tag_revisions table and no triggers.
        call("tag_transaction", row_ids=[self.a], tags=["software"])
        bid = call("backup", reason="manual").split()[1]
        path = backups.paths_for(self.root / "f.sqlite").backup_file(bid)
        old = sqlite3.connect(path)
        for name in store.TAG_REVISION_TRIGGERS:
            old.execute("DROP TRIGGER %s" % name)
        old.execute("DROP TABLE tag_revisions")
        old.commit()
        old.close()
        call("untag_transaction", row_ids=[self.a], tags=["software"])
        after_untag = self.rev(self.a)
        out = call("restore_backup", backup_id=bid)
        self.assertNotIn("does not match", out)
        self.assertEqual(self.tags_of(self.a), ["software"])
        self.assertGreater(self.rev(self.a), after_untag)

    def test_a_purge_and_its_restore_keep_the_count_rising(self):
        call("tag_transaction", row_ids=[self.a], tags=["software"])
        seq = self.seq()
        instance = store.ledger_instance(self.raw)
        out = call("purge", before_date="all", user_work="erase")
        self.assertEqual(store.ledger_instance(self.raw), instance)
        self.assertGreater(self.seq(), seq)
        purged = self.seq()
        call("restore_backup", backup_id=pre_erasure_id(out))
        self.assertEqual(self.tags_of(self.a), ["software"])
        self.assertGreater(self.rev(self.a), purged)


class TestTheCountRestartsOnlyWithANewInstance(RevisionBase):
    def _check(self, tool):
        call("tag_transaction", row_ids=[self.a], tags=["software"])
        instance = store.ledger_instance(self.raw)
        self.assertIsNotNone(self.seq())
        call(tool)
        self.assertEqual(self.count(store.TAG_REVISIONS_TABLE), 0)
        self.assertIsNone(self.seq())
        self.assertNotEqual(store.ledger_instance(self.raw), instance)

    def test_delete_all_data(self):
        self._check("delete_all_data")

    def test_delete_data_keep_signins(self):
        self._check("delete_data_keep_signins")

    def test_every_meta_whitelist_that_keeps_the_instance_keeps_the_count(self):
        # The counter and `ledger_instance` go together: a meta whitelist that
        # kept the instance id and dropped the counter would restart the
        # count under the same id, and re-issue exported values.
        for kept in (tools_destructive.STRUCTURAL_META_KEYS,
                     tools_destructive.STRUCTURAL_META_KEYS
                     + tools_destructive.WITHDRAWAL_META_KEYS):
            self.assertEqual(store.LEDGER_INSTANCE_KEY in kept,
                             store.TAG_REVISION_SEQ_KEY in kept)
        for prefix in tools_destructive.SIGNIN_META_PREFIXES:
            self.assertFalse(store.TAG_REVISION_SEQ_KEY.startswith(prefix))
            self.assertFalse(store.LEDGER_INSTANCE_KEY.startswith(prefix))

    def test_the_revision_table_is_live_state_for_a_restore(self):
        self.assertIn(store.TAG_REVISIONS_TABLE, backups.KEEP_LIVE_TABLES)
        self.assertIn("meta", backups.KEEP_LIVE_TABLES)
        data = tools_destructive._DATA_TABLES
        self.assertGreater(data.index(store.TAG_REVISIONS_TABLE),
                           data.index("transaction_tags"))


class TestInstall(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.db = pathlib.Path(self.dir.name) / "f.sqlite"
        store.open_db(self.db).close()
        raw = sqlite3.connect(self.db)
        for name in store.TAG_REVISION_TRIGGERS:
            raw.execute("DROP TRIGGER %s" % name)
        raw.execute("DROP TABLE tag_revisions")
        raw.commit()
        raw.close()

    def test_an_open_installs_it_on_a_ledger_from_before_it(self):
        conn = store.open_db(self.db)
        self.addCleanup(conn.close)
        self.assertEqual(self.installed(conn),
                         {"tag_revisions"} | set(store.TAG_REVISION_TRIGGERS))
        conn.execute("INSERT INTO transaction_tags(row_id, tag) VALUES (7, 'x')")
        self.assertEqual(conn.execute(
            "SELECT revision FROM tag_revisions WHERE row_id=7").fetchone()[0], 1)

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
        self.assertEqual(self.installed(conn),
                         {"tag_revisions"} | set(store.TAG_REVISION_TRIGGERS))

    def test_a_missing_trigger_alone_is_reinstalled(self):
        raw = sqlite3.connect(self.db)
        store.open_db(self.db).close()
        raw.execute("DROP TRIGGER trg_tag_rev_ad")
        raw.commit()
        raw.close()
        conn = store.open_db(self.db)
        self.addCleanup(conn.close)
        # Read independently of `_tag_revision_missing`, which is what
        # decides the install: a helper that saw only the table would pass
        # its own check with the delete trigger still gone.
        self.assertEqual(self.installed(conn),
                         {"tag_revisions"} | set(store.TAG_REVISION_TRIGGERS))
        conn.execute("INSERT INTO transaction_tags(row_id, tag) VALUES (7, 'x')")
        tagged = self.revision(conn, 7)
        conn.execute("DELETE FROM transaction_tags WHERE row_id=7")
        self.assertGreater(self.revision(conn, 7), tagged)

    def installed(self, conn):
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE name='tag_revisions'"
            " OR (type='trigger' AND tbl_name='transaction_tags')")}

    def revision(self, conn, rid):
        return conn.execute("SELECT revision FROM tag_revisions WHERE row_id=?",
                            (rid,)).fetchone()[0]


class TestExport(RevisionBase):
    def setUp(self):
        super().setUp()
        call("tag_transaction", row_ids=[self.a], tags=["software"])
        # A namespaced tag is written through its workflow's fence; the
        # revision does not care which writer, so plain DML stands in.
        self.raw.execute("INSERT INTO transaction_tags(row_id, tag)"
                         " VALUES (?, 'acct::q3')", (self.a,))
        call("tag_transaction", row_ids=[self.b], tags=["refund"])
        call("untag_transaction", row_ids=[self.b], tags=["refund"])

    def _get(self, rid):
        out = call("get_transaction", row_id=rid)
        own = [l for l in out.splitlines() if l.startswith("Tags: ")][0][6:]
        foreign = [l.split(": ", 1)[1] for l in out.splitlines()
                   if l.startswith("Other workflows' tags")]
        rev = [l for l in out.splitlines() if l.startswith("Tag revision: ")][0]
        tags = [] if own == "none" else own.split(", ")
        if foreign:
            tags += foreign[0].split(", ")
        return sorted(tags), int(rev.split()[2])

    def test_csv_carries_tags_and_revision_as_get_transaction_reads_them(self):
        rows = {int(r["row_id"]): r for r in self.export("csv")}
        for rid in (self.a, self.b, self.c):
            tags, rev = self._get(rid)
            self.assertEqual(rows[rid]["tags"], ",".join(tags))
            self.assertEqual(int(rows[rid]["tag_revision"]), rev)
            self.assertEqual(rev, self.rev(rid))
        self.assertEqual(rows[self.a]["tags"], "acct::q3,software")
        # b was tagged and untagged: no tags, but a revision above 0 — the
        # removal is visible.
        self.assertEqual(rows[self.b]["tags"], "")
        self.assertGreater(int(rows[self.b]["tag_revision"]), 0)
        self.assertEqual(rows[self.c]["tag_revision"], "0")

    def test_jsonl_carries_a_list_and_an_integer(self):
        rows = {r["row_id"]: r for r in self.export("jsonl")}
        for rid in (self.a, self.b, self.c):
            tags, rev = self._get(rid)
            self.assertEqual(rows[rid]["tags"], tags)
            self.assertIs(type(rows[rid]["tag_revision"]), int)
            self.assertEqual(rows[rid]["tag_revision"], rev)
        self.assertEqual(rows[self.c]["tags"], [])

    def test_tags_and_revisions_come_from_the_rows_snapshot(self):
        # Another process commits a tag change after the export read its
        # rows: the export must still describe one moment.
        other = store.open_db(self.root / "f.sqlite")
        self.addCleanup(other.close)
        before = (self.tags_of(self.c), self.rev(self.c))
        real = tools_read.CONN

        class Racing:
            def __getattr__(self, name):
                return getattr(real, name)

            def execute(self, sql, *a):
                cur = real.execute(sql, *a)
                if sql.startswith("SELECT") and "FROM transactions ORDER BY" in sql:
                    rows = cur.fetchall()
                    other.execute("INSERT INTO transaction_tags(row_id, tag)"
                                  " VALUES (?, 'late')", (self_c,))
                    return iter(rows)
                return cur

        self_c = self.c
        tools_read.CONN = Racing()
        self.addCleanup(setattr, tools_read, "CONN", real)
        rows = {r["row_id"]: r for r in self.export("jsonl")}
        self.assertEqual((rows[self.c]["tags"], rows[self.c]["tag_revision"]),
                         before)
        self.assertEqual(self.tags_of(self.c), ["late"])

    def test_the_appended_columns_cannot_shadow_a_ledger_column(self):
        self.raw.execute("ALTER TABLE transactions ADD COLUMN tags TEXT")
        with self.assertRaises(RuntimeError):
            call("export_history", format="csv")


if __name__ == "__main__":
    unittest.main()
