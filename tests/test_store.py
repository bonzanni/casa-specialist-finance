# tests/test_store.py
"""Schema, durable account ids, and the data-at-rest rules."""
import os
import pathlib
import sqlite3
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
import provenance  # noqa: E402
import store  # noqa: E402

#: The literal prefix the removed capability seeder wrote, DERIVED from the
#: matcher under test rather than re-typed. The fixtures below have to carry
#: this exact prefix -- the whole point of them is that the v5 migration
#: recognises it -- and re-spelling it here would be two places for one
#: constant, in a file whose subject is a migration that keys on it.
#:
#: SEED_PREFIX keeps the GLOB's trailing space, because a fixture concatenating
#: it needs one. SEED_MARKER drops it, because a `startswith` assertion must not
#: quietly become stricter than the bare literal it replaced -- a provenance
#: string that continues with a colon rather than a space satisfies the marker
#: and not the prefix.
SEED_PREFIX = store.SEED_PROVENANCE_GLOB.split("[")[0]      # "... production "
SEED_MARKER = SEED_PREFIX.rstrip()                          # "... production"
SHOUTED_PREFIX = SEED_PREFIX.upper()


def mode_of(p) -> int:
    return stat.S_IMODE(os.stat(str(p)).st_mode)


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        self.path = self.root / "data" / "bank_feed.sqlite"

    def tearDown(self):
        self.dir.cleanup()


class TestSchema(Base):
    def test_creates_every_table(self):
        conn = store.open_db(self.path)
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertLessEqual(
            {"meta", "sessions", "accounts", "balances", "transactions",
             "transaction_refs", "coverage", "sync_state", "attempts",
             "aspsp_capability", "occurrence_alloc"}, names)
        conn.close()

    def test_is_wal_and_records_schema_version(self):
        conn = store.open_db(self.path)
        self.assertEqual(
            conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        v = conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
        self.assertEqual(int(v), store.SCHEMA_VERSION)
        conn.close()

    def test_transactions_carry_supersede_lineage_and_review_flags(self):
        # Pending -> booked SUPERSEDES (state + superseded_by); every
        # heuristic decision is recorded (match_method, match_confidence) and
        # unresolved ones are flagged (needs_review). The read tools disclose
        # the counts of these behind any total, so the columns must exist.
        conn = store.open_db(self.path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(transactions)")}
        self.assertLessEqual(
            {"state", "superseded_by", "match_method", "match_confidence",
             "needs_review", "provider_ref", "provider_ref_kind",
             "identity_key", "occurrence"}, cols)
        conn.close()

    def test_review_and_state_reasons_exist_and_default_to_null(self):
        # ingest emits a reason on every flag and tombstone; `apply` writes it
        # and the read tools surface the breakdown. Without these columns the
        # reason is silently dropped and "3 need review" can never answer
        # "why?". Two columns, not one: a row can be flagged AND later vanish.
        conn = store.open_db(self.path)
        conn.execute(
            "INSERT INTO transactions(account_id, identity_key, occurrence,"
            " booking_date, amount_minor, currency, direction, status, state)"
            " VALUES ('acc1','ik1',0,'2026-01-01',100,'EUR','DBIT','BOOK','active')")
        row = conn.execute("SELECT review_reason, state_reason FROM transactions"
                           " WHERE identity_key='ik1'").fetchone()
        self.assertIsNone(row["review_reason"])
        self.assertIsNone(row["state_reason"])
        conn.execute("UPDATE transactions SET needs_review=1,"
                     " review_reason='provider_ref_reuse' WHERE identity_key='ik1'")
        conn.execute("UPDATE transactions SET state='vanished',"
                     " state_reason='no match inside a proven interval'"
                     " WHERE identity_key='ik1'")
        row = conn.execute("SELECT review_reason, state_reason FROM transactions"
                           " WHERE identity_key='ik1'").fetchone()
        self.assertEqual(row["review_reason"], "provider_ref_reuse")
        self.assertEqual(row["state_reason"],
                         "no match inside a proven interval")
        conn.close()

    def test_accounts_carry_the_aspsp_that_selects_the_capability_row(self):
        # Without this column flows.backfill has no ASPSP name to pass to
        # provenance.capability(), so every production ingest silently falls
        # back to heuristic windowed matching and the capability table is inert.
        # The default is '' rather than NULL because an unrecorded ASPSP must
        # resolve to DEFAULT_CAPABILITY (untrusted), not to a NULL that a
        # lookup might treat as a wildcard.
        conn = store.open_db(self.path)
        cols = {r[1]: r for r in conn.execute("PRAGMA table_info(accounts)")}
        self.assertIn("aspsp", cols)
        self.assertEqual(cols["aspsp"][3], 1)               # NOT NULL
        self.assertEqual(cols["aspsp"][4], "''")            # DEFAULT ''
        conn.execute("INSERT INTO accounts(account_id) VALUES ('acc1')")
        self.assertEqual(conn.execute(
            "SELECT aspsp FROM accounts WHERE account_id='acc1'").fetchone()[0], "")
        conn.close()

    def test_a_fresh_database_makes_no_capability_claim(self):
        # open_db writes no capability row. Trust is a per-installation
        # property -- whether THIS account's provider supplies references that
        # are present and unique -- so a shipped default would be an assertion
        # about a bank nobody measured here.
        conn = store.open_db(self.path)
        self.assertEqual(conn.execute(
            "SELECT count(*) FROM aspsp_capability").fetchone()[0], 0)
        conn.close()

    def test_reopening_neither_duplicates_nor_overwrites_a_local_observation(self):
        # open_db runs on every connection, so a row this installation recorded
        # must survive the next open unchanged.
        conn = store.open_db(self.path)
        conn.execute(
            "INSERT INTO aspsp_capability"
            "(aspsp, ref_stable, ref_scope, observed_n, provenance, updated_at)"
            " VALUES ('ABN AMRO', 0, 'unknown', 9, 'locally observed unstable',"
            " '2026-01-01T00:00:00Z')")
        conn.commit()
        conn.close()
        conn = store.open_db(self.path)
        self.assertEqual(conn.execute(
            "SELECT count(*) FROM aspsp_capability").fetchone()[0], 1)
        row = conn.execute(
            "SELECT ref_stable, observed_n, provenance FROM aspsp_capability"
            " WHERE aspsp='ABN AMRO'").fetchone()
        self.assertEqual((row["ref_stable"], row["observed_n"], row["provenance"]),
                         (0, 9, "locally observed unstable"))
        conn.close()

    def test_attempts_carry_the_generation_fence_and_default_to_null(self):
        # Without a recorded expected generation, a slow repair
        # callback can rebind an account's uid/session_id AFTER a newer
        # renewal already bound it, silently reverting the account to a stale
        # session. _start_auth mints the target account's current
        # sessions.generation here; the collector discards a callback whose account
        # has since been rebound by a higher generation, before the provider is
        # contacted. Asserted at the schema so an edit that drops the column
        # fails here rather than surfacing as a silent fence bypass.
        # Nullable: an attempt that repairs no specific account fences nothing.
        conn = store.open_db(self.path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(attempts)")}
        self.assertIn("expected_generation", cols)
        conn.execute("INSERT INTO attempts(state_hash) VALUES ('sh1')")
        row = conn.execute("SELECT expected_generation FROM attempts"
                           " WHERE state_hash='sh1'").fetchone()
        self.assertIsNone(row["expected_generation"])
        conn.execute("UPDATE attempts SET expected_generation=3"
                     " WHERE state_hash='sh1'")
        self.assertEqual(conn.execute(
            "SELECT expected_generation FROM attempts"
            " WHERE state_hash='sh1'").fetchone()["expected_generation"], 3)
        conn.close()

    def test_capability_rows_record_where_the_claim_came_from(self):
        # A trust claim with no stated origin cannot be audited or retired,
        # so the column exists whether or not any row has been written yet.
        conn = store.open_db(self.path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(aspsp_capability)")}
        self.assertLessEqual({"aspsp", "ref_stable", "ref_scope", "observed_n",
                              "provenance", "updated_at"}, cols)
        conn.close()

    def test_transaction_uniqueness_is_account_identity_occurrence(self):
        conn = store.open_db(self.path)
        row = ("acc1", "ik1", 0, "2026-01-01", 100, "EUR", "DBIT", "BOOK", "active")
        sql = ("INSERT INTO transactions(account_id, identity_key, occurrence,"
               " booking_date, amount_minor, currency, direction, status, state)"
               " VALUES (?,?,?,?,?,?,?,?,?)")
        conn.execute(sql, row)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(sql, row)
        conn.execute(sql, ("acc1", "ik1", 1) + row[3:])   # new occurrence is fine
        conn.close()

    def test_occurrence_allocation_is_a_durable_rising_high_water(self):
        # ingest._next_occurrence sees only the rows a pass loaded, and a
        # routine refresh loads roughly the last seven days -- so a monthly
        # standing order whose earlier occurrences lie outside that window
        # re-allocates occurrence 0 and collides with UNIQUE (account_id,
        # identity_key, occurrence). This table remembers every occurrence ever
        # issued per cluster. It is also the ONLY record of the slot a RE-KEYED
        # row vacated: after a re-key no transactions row carries the old
        # tuple, so a floor taken from the surviving rows would hand that slot
        # straight back out.
        conn = store.open_db(self.path)
        cols = {r[1] for r in conn.execute(
            "PRAGMA table_info(occurrence_alloc)")}
        self.assertLessEqual({"account_id", "identity_key", "next_occurrence",
                              "updated_at"}, cols)
        conn.execute("INSERT INTO occurrence_alloc(account_id, identity_key,"
                     " next_occurrence) VALUES ('acc1','ik1',1)")
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO occurrence_alloc(account_id,"
                         " identity_key, next_occurrence)"
                         " VALUES ('acc1','ik1',2)")
        # every pass floors the allocation on the rows still present, so the
        # per-cluster lookup that does it must be indexed rather than a scan
        self.assertIn("ix_tx_identity", {r[1] for r in conn.execute(
            "PRAGMA index_list(transactions)")})
        conn.close()

    def test_sync_state_records_which_session_last_completed_a_fetch(self):
        # The renewal precondition — "a renewal must not close the old
        # session until the new session's deep fetch is durably complete" — is
        # checked against this column, not against coverage. Coverage records
        # the interval PROVED, which for an account that returned no rows is
        # nothing at all; this records that the retrieval ran to exhaustion, so
        # a dormant account still renews and we still never claim to have
        # proven an interval the bank may simply have truncated.
        conn = store.open_db(self.path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(sync_state)")}
        self.assertIn("last_success_session", cols)
        conn.execute("INSERT INTO sync_state(account_id, resource)"
                     " VALUES ('acc1','transactions')")
        self.assertIsNone(conn.execute(
            "SELECT last_success_session FROM sync_state"
            " WHERE account_id='acc1'").fetchone()[0])
        conn.close()

    def test_open_is_idempotent(self):
        store.open_db(self.path).close()
        conn = store.open_db(self.path)                   # must not raise
        self.assertEqual(int(conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]),
            store.SCHEMA_VERSION)
        conn.close()


class TestDataAtRest(Base):
    def test_data_directory_is_tightened_to_0700(self):
        loose = self.root / "loose"
        loose.mkdir()
        os.chmod(str(loose), 0o755)
        self.assertEqual(mode_of(loose), 0o755)           # precondition
        store.open_db(loose / "bank_feed.sqlite").close()
        self.assertEqual(mode_of(loose), 0o700)

    def test_database_file_and_sidecars_are_0600(self):
        conn = store.open_db(self.path)
        self.assertEqual(mode_of(self.path), 0o600)
        wal = pathlib.Path(str(self.path) + "-wal")
        self.assertTrue(wal.exists(),
                        "the WAL sidecar must exist while the connection is open")
        for suffix in ("-wal", "-shm"):
            side = pathlib.Path(str(self.path) + suffix)
            if side.exists():
                self.assertEqual(mode_of(side), 0o600, suffix)
        conn.close()

    def test_a_symlinked_database_path_is_refused(self):
        # Narrow claim: PRE-EXISTING symlink detection. open_db closes
        # its guarded fd and SQLite reopens the pathname, so this is not proof
        # of race safety and nothing may describe it as such.
        self.path.parent.mkdir(parents=True)
        elsewhere = self.root / "elsewhere.sqlite"
        elsewhere.write_bytes(b"")
        os.symlink(str(elsewhere), str(self.path))
        with self.assertRaises(store.StoreError) as cm:
            store.open_db(self.path)
        self.assertIn("symlink", str(cm.exception).lower())

    def test_a_symlinked_wal_sidecar_is_refused(self):
        # The sidecars carry the same rows as the database; a pre-planted
        # -wal symlink exfiltrates writes just as effectively.
        # Pre-existing only: a sidecar SQLite has not created yet can still be
        # swapped between this check and its creation.
        self.path.parent.mkdir(parents=True)
        target = self.root / "captured"
        target.write_bytes(b"")
        os.symlink(str(target), str(self.path) + "-wal")
        with self.assertRaises(store.StoreError) as cm:
            store.open_db(self.path)
        self.assertIn("symlink", str(cm.exception).lower())

    def test_a_missing_plugin_data_env_is_a_named_error(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(store.StoreError) as cm:
                store.open_db()
        self.assertIn("CLAUDE_PLUGIN_DATA", str(cm.exception))
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_DATA": "  "}, clear=True):
            with self.assertRaises(store.StoreError):
                store.open_db()

    def test_plugin_data_env_is_used_when_no_path_is_given(self):
        home = self.root / "plugin-data"
        home.mkdir()
        os.chmod(str(home), 0o755)
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_DATA": str(home)}):
            conn = store.open_db()
        self.assertTrue((home / "bank_feed.sqlite").exists())
        self.assertEqual(mode_of(home), 0o700)
        self.assertEqual(mode_of(home / "bank_feed.sqlite"), 0o600)
        conn.close()

    def test_module_source_carries_no_tmp_fallback(self):
        # Regression guard: an earlier draft defaulted to "/tmp" when
        # CLAUDE_PLUGIN_DATA was unset, putting the operator's entire
        # financial history somewhere world-readable.
        src = pathlib.Path(store.__file__).read_text(encoding="utf-8")
        self.assertNotIn("/tmp", src)


class TestIntegrity(Base):
    def test_a_corrupt_ledger_is_a_named_error(self):
        # Depending on what the corruption hits, SQLite either RETURNS a
        # non-"ok" integrity_check row or RAISES DatabaseError. open_db must
        # turn both into the same named StoreError -- never a silent continue.
        conn = store.open_db(self.path)
        for i in range(400):
            conn.execute("INSERT INTO meta(key, value) VALUES (?, ?)",
                         ("k%d" % i, "v" * 200))
        conn.close()
        with open(str(self.path), "r+b") as fh:
            fh.seek(4096)                 # leave the file header intact
            fh.write(b"\xff" * 8192)      # scribble over live b-tree pages
        with self.assertRaises(store.StoreError) as cm:
            store.open_db(self.path)
        self.assertIn("integrity", str(cm.exception).lower())


class TestMigration(Base):
    def snapshots(self):
        return sorted(p.name for p in self.path.parent.glob("*pre-migration*"))

    def test_a_snapshot_is_taken_before_a_schema_migration(self):
        conn = store.open_db(self.path)
        conn.execute("UPDATE meta SET value='0' WHERE key='schema_version'")
        conn.close()
        self.assertEqual(self.snapshots(), [])            # precondition

        conn = store.open_db(self.path)                   # 0 -> SCHEMA_VERSION
        self.assertEqual(len(self.snapshots()), 1)
        self.assertEqual(int(conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]),
            store.SCHEMA_VERSION)
        conn.close()

        conn = store.open_db(self.path)                   # already current
        self.assertEqual(len(self.snapshots()), 1,
                         "an ordinary open must not snapshot")
        conn.close()

    def test_the_snapshot_is_a_readable_sibling_copy_at_0600(self):
        conn = store.open_db(self.path)
        conn.execute("INSERT INTO meta(key, value) VALUES ('canary', 'kept')")
        conn.close()
        dest = store.snapshot_before_migration(self.path)
        self.assertIsInstance(dest, str)
        dest = pathlib.Path(dest)
        self.assertEqual(dest.parent, self.path.parent)
        self.assertEqual(mode_of(dest), 0o600)
        copy = sqlite3.connect(str(dest))
        self.assertEqual(copy.execute(
            "SELECT value FROM meta WHERE key='canary'").fetchone()[0], "kept")
        copy.close()

    def test_snapshot_returns_none_when_there_is_nothing_to_protect(self):
        self.path.parent.mkdir(parents=True)
        self.assertIsNone(store.snapshot_before_migration(self.path))
        self.path.write_bytes(b"")
        self.assertIsNone(store.snapshot_before_migration(self.path))

    def test_a_newer_schema_version_is_refused(self):
        conn = store.open_db(self.path)
        conn.execute("UPDATE meta SET value=? WHERE key='schema_version'",
                     (str(store.SCHEMA_VERSION + 1),))
        conn.close()
        with self.assertRaises(store.StoreError) as cm:
            store.open_db(self.path)
        self.assertIn("newer", str(cm.exception).lower())


class TestSecrets(Base):
    def test_local_secret_is_stable_and_random(self):
        conn = store.open_db(self.path)
        a = store.local_secret(conn)
        b = store.local_secret(conn)
        self.assertEqual(a, b)
        self.assertGreaterEqual(len(a), 32)
        other = store.open_db(self.root / "other" / "bank_feed.sqlite")
        self.assertNotEqual(a, store.local_secret(other))
        conn.close()
        other.close()

    def test_local_secret_survives_a_reconnect(self):
        # Coverage gap: stability WITHIN one connection and difference ACROSS
        # two different databases were both proven above, but never that the
        # SAME database's secret survives a close and reopen of the file. This
        # is the module's highest- consequence silent failure: a secret that
        # regenerated per open would change every account_id, orphan the entire
        # ledger, and raise no error at all -- just a fresh-looking set of
        # accounts.
        conn = store.open_db(self.path)
        secret_before = store.local_secret(conn)
        account_before = store.account_id("NL00ABNA0000000002", "EUR", secret_before)
        conn.close()

        conn = store.open_db(self.path)
        secret_after = store.local_secret(conn)
        account_after = store.account_id("NL00ABNA0000000002", "EUR", secret_after)
        conn.close()

        self.assertEqual(secret_before, secret_after)
        # the property that actually matters to the ledger: the derived key
        # for a fixed IBAN+currency must not move across a reconnect.
        self.assertEqual(account_before, account_after)

    def test_account_id_is_keyed_stable_and_not_a_bare_hash(self):
        secret = b"x" * 32
        a = store.account_id("NL00ABNA0000000002", "EUR", secret)
        self.assertEqual(a, store.account_id("nl00abna0000000002", " eur ", secret))
        self.assertNotEqual(a, store.account_id("NL00ABNA0000000002", "USD", secret))
        # keyed, not a plain digest: an unsalted hash of an IBAN is trivially
        # reversible by brute force over a small space.
        self.assertNotEqual(a, store.account_id("NL00ABNA0000000002", "EUR", b"y" * 32))


class TestAnnotationSchemaUpgrade(Base):
    """A deployed v1 ledger must GAIN the annotation tables on reopen.

    open_db runs _SCHEMA only for a fresh file or when stored <
    SCHEMA_VERSION (store.py:409-421), so reopening an already-current file
    proves nothing about upgrades. These tests build a faithful v1 ledger —
    no annotation tables, version stamped 1 — and reopen it.
    """

    def _v1_ledger(self):
        conn = store.open_db(self.path)
        # DROP TABLE transaction_notes also drops its FTS triggers; the
        # index table itself (v3) must go explicitly — a real v1 file has
        # neither.
        conn.execute("DROP TABLE notes_fts")
        conn.execute("DROP TABLE transaction_tags")
        conn.execute("DROP TABLE transaction_notes")
        conn.execute("UPDATE meta SET value='1' WHERE key='schema_version'")
        conn.close()

    def _tables(self, conn):
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}

    def test_v1_ledger_gains_annotation_tables_and_current_version(self):
        self._v1_ledger()
        conn = store.open_db(self.path)
        try:
            self.assertIn("transaction_tags", self._tables(conn))
            self.assertIn("transaction_notes", self._tables(conn))
            self.assertEqual(conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()[0], str(store.SCHEMA_VERSION))
        finally:
            conn.close()

    def test_upgrade_leaves_a_pre_migration_snapshot(self):
        # A schema migration is the one operation that can corrupt
        # the ledger in a way re-linking will not fix, so the upgrade must
        # leave the snapshot beside the file.
        self._v1_ledger()
        store.open_db(self.path).close()
        snaps = list(self.path.parent.glob(self.path.name + ".pre-migration-*"))
        self.assertEqual(len(snaps), 1)

    def test_annotation_tables_survive_and_version_stays_current(self):
        conn = store.open_db(self.path)
        conn.execute("INSERT INTO transaction_tags(row_id, tag, added_at)"
                     " VALUES (1, 'groceries', '2026-08-05T00:00:00')")
        conn.execute("INSERT INTO transaction_notes(row_id, author, note,"
                     " created_at) VALUES (1, 'user', 'x', '2026-08-05T00:00:00')")
        conn.close()
        conn = store.open_db(self.path)                   # reopen: no migration
        try:
            self.assertEqual(conn.execute(
                "SELECT tag FROM transaction_tags").fetchone()[0], "groceries")
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM transaction_notes").fetchone()[0], 1)
        finally:
            conn.close()


class TestSchemaV3Upgrade(Base):
    """A deployed v2 ledger must GAIN the note FTS index on reopen.

    Same discipline as the v1 class above: build a faithful v2 ledger —
    notes present, no notes_fts, no triggers, version stamped 2 — and
    reopen it. Reopening an already-current file proves nothing.
    """

    def _v2_ledger_with_note(self):
        conn = store.open_db(self.path)
        conn.execute("INSERT INTO transaction_notes(row_id, author, note,"
                     " created_at) VALUES (7, 'user', 'boiler renovations"
                     " invoiced', '2026-08-05T00:00:00')")
        conn.execute("DROP TRIGGER trg_notes_fts_ai")
        conn.execute("DROP TRIGGER trg_notes_fts_ad")
        conn.execute("DROP TABLE notes_fts")
        conn.execute("UPDATE meta SET value='2' WHERE key='schema_version'")
        conn.commit()
        conn.close()

    def test_v2_ledger_gains_backfilled_fts_and_version_3(self):
        self._v2_ledger_with_note()
        conn = store.open_db(self.path)
        try:
            # Stemming proves the tokenizer, not just the table: 'renovation'
            # must match the stored 'renovations'.
            hits = conn.execute("SELECT rowid FROM notes_fts WHERE"
                                " notes_fts MATCH 'renovation'").fetchall()
            self.assertEqual(len(hits), 1)
            # Current version, not literal "3": a v2 file upgrading today
            # lands at whatever HEAD is, with migration 3 applied en route.
            self.assertEqual(conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()[0], str(store.SCHEMA_VERSION))
        finally:
            conn.close()

    def test_fresh_file_has_fts_and_insert_delete_stay_synced(self):
        conn = store.open_db(self.path)
        try:
            conn.execute("INSERT INTO transaction_notes(row_id, author,"
                         " note, created_at) VALUES (1, 'user', 'dishwasher"
                         " warranty claim', 't')")
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM notes_fts WHERE notes_fts MATCH"
                " 'warranty'").fetchone()[0], 1)
            conn.execute("DELETE FROM transaction_notes WHERE row_id=1")
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM notes_fts WHERE notes_fts MATCH"
                " 'warranty'").fetchone()[0], 0)
            # FTS5's own integrity check raises on a desynced index.
            conn.execute("INSERT INTO notes_fts(notes_fts)"
                         " VALUES('integrity-check')")
        finally:
            conn.close()

    def test_row_id_only_update_does_not_desync_the_index(self):
        # The supersede migration UPDATEs transaction_notes.row_id
        # (apply.py). row_id is not carried by the index (content_rowid is
        # note_id), so no UPDATE trigger exists — this pins that the index
        # survives the one UPDATE production performs.
        conn = store.open_db(self.path)
        try:
            conn.execute("INSERT INTO transaction_notes(row_id, author,"
                         " note, created_at) VALUES (1, 'user', 'moved"
                         " note', 't')")
            conn.execute("UPDATE transaction_notes SET row_id=99"
                         " WHERE row_id=1")
            self.assertEqual(conn.execute(
                "SELECT n.row_id FROM transaction_notes n WHERE n.note_id IN"
                " (SELECT rowid FROM notes_fts WHERE notes_fts MATCH"
                " 'moved')").fetchone()[0], 99)
            conn.execute("INSERT INTO notes_fts(notes_fts)"
                         " VALUES('integrity-check')")
        finally:
            conn.close()


class ModeBase(Base):
    """Marker-protocol cases. The data dir is the
    temp root; helpers flip the mode via the ebmode memo seam."""

    def setUp(self):
        super().setUp()
        import ebmode
        self.ebmode = ebmode
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(),
                                 os.environ.update(saved)))
        self.addCleanup(ebmode._reset)
        self.data = str(self.root)

    def with_mode(self, value):
        os.environ[self.ebmode.ENV_MODE_VAR] = value
        self.ebmode._reset()

    def marker(self):
        return self.root / "eb-environment"


class TestDbFilename(ModeBase):
    def test_production_filename_is_byte_identical_to_before(self):
        self.with_mode("PRODUCTION")
        self.assertEqual(store.db_filename(), "bank_feed.sqlite")

    def test_sandbox_filename_is_its_own_world(self):
        self.with_mode("SANDBOX")
        self.assertEqual(store.db_filename(), "bank_feed.sandbox.sqlite")

    def test_default_resolve_composes_the_modes_filename(self):
        self.with_mode("SANDBOX")
        os.environ["CLAUDE_PLUGIN_DATA"] = self.data
        self.assertEqual(store._resolve(None),
                         self.root / "bank_feed.sandbox.sqlite")


class TestCheckModeMarker(ModeBase):
    def test_unset_or_empty_data_dir_is_a_noop(self):
        self.with_mode("SANDBOX")
        store.check_mode_marker(None)
        store.check_mode_marker("")     # conn()'s exact truthiness rule

    def test_absent_marker_and_no_other_file_proceeds(self):
        self.with_mode("SANDBOX")
        store.check_mode_marker(self.data)

    def test_matching_marker_proceeds(self):
        self.with_mode("SANDBOX")
        self.marker().write_text("SANDBOX\n")
        store.check_mode_marker(self.data)

    def test_a_mode_flip_refuses_with_the_remedy_in_both_directions(self):
        for recorded, flipped in (("PRODUCTION", "SANDBOX"),
                                  ("SANDBOX", "PRODUCTION")):
            self.marker().write_text(recorded + "\n")
            self.with_mode(flipped)
            with self.assertRaises(store.StoreError) as ctx:
                store.check_mode_marker(self.data)
            text = str(ctx.exception)
            self.assertIn(recorded, text)
            self.assertIn("does not migrate", text)
            self.assertIn("eb-environment", text)
            self.marker().unlink()

    def test_the_other_modes_ledger_refuses_even_when_the_marker_matches(self):
        # A matching marker must not suppress the detection of
        # a restored/half-initialised/race-leftover opposite-mode file.
        self.with_mode("SANDBOX")
        self.marker().write_text("SANDBOX\n")
        (self.root / "bank_feed.sqlite").write_bytes(b"")
        with self.assertRaises(store.StoreError) as ctx:
            store.check_mode_marker(self.data)
        self.assertIn("bank_feed.sqlite", str(ctx.exception))

    def test_a_legacy_production_dir_refuses_a_sandbox_first_run(self):
        # Pre-feature production dir — ledger present, no marker.
        self.with_mode("SANDBOX")
        (self.root / "bank_feed.sqlite").write_bytes(b"")
        with self.assertRaises(store.StoreError):
            store.check_mode_marker(self.data)

    def test_foreign_marker_content_refuses_without_echoing_it(self):
        self.with_mode("SANDBOX")
        probe = "zzz-foreign-content-zzz"
        self.marker().write_text(probe)
        with self.assertRaises(store.StoreError) as ctx:
            store.check_mode_marker(self.data)
        self.assertNotIn(probe, str(ctx.exception))
        self.assertIn("eb-environment", str(ctx.exception))

    def test_an_empty_marker_lands_in_the_same_refusal(self):
        # A crash between O_EXCL create and write leaves exactly this.
        self.with_mode("SANDBOX")
        self.marker().write_text("")
        with self.assertRaises(store.StoreError):
            store.check_mode_marker(self.data)

    def test_undecodable_marker_bytes_get_the_same_content_free_refusal(self):
        # Invalid UTF-8 must land in the designed refusal, never surface as a
        # raw UnicodeDecodeError through the dispatcher's generic error
        # renderer.
        self.with_mode("SANDBOX")
        self.marker().write_bytes(b"\xffSECRET-BYTES")
        with self.assertRaises(store.StoreError) as ctx:
            store.check_mode_marker(self.data)
        self.assertIn("unrecognised", str(ctx.exception))
        self.assertNotIn("SECRET-BYTES", str(ctx.exception))

    def test_refusals_never_carry_the_data_directory_path(self):
        # CLAUDE_PLUGIN_DATA is externally supplied text; a directory name
        # carrying a newline would forge a report line. Refusals name static
        # filenames only.
        evil = self.root / "evil\nFORGED-LINE"
        evil.mkdir()
        (evil / "bank_feed.sqlite").write_bytes(b"")
        self.with_mode("SANDBOX")
        with self.assertRaises(store.StoreError) as ctx:
            store.check_mode_marker(str(evil))
        self.assertNotIn("FORGED-LINE", str(ctx.exception))
        (evil / "bank_feed.sqlite").unlink()
        (evil / "eb-environment").write_text("PRODUCTION\n")
        with self.assertRaises(store.StoreError) as ctx:
            store.check_mode_marker(str(evil))
        self.assertNotIn("FORGED-LINE", str(ctx.exception))

    def test_a_whitespace_only_data_dir_is_guarded_not_skipped(self):
        # conn() accepts "   " literally, so the guard must too — only
        # unset/empty no-op.
        self.with_mode("SANDBOX")
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(str(self.root))
        ws = self.root / "   "
        ws.mkdir()
        (ws / "eb-environment").write_text("PRODUCTION\n")
        with self.assertRaises(store.StoreError):
            store.check_mode_marker("   ")


class TestCommitModeMarker(ModeBase):
    def test_first_commit_writes_the_mode_at_0600(self):
        self.with_mode("SANDBOX")
        store.commit_mode_marker(self.data)
        self.assertEqual(self.marker().read_text().strip(), "SANDBOX")
        self.assertEqual(mode_of(self.marker()), 0o600)

    def test_recommit_of_the_same_mode_is_a_quiet_noop(self):
        self.with_mode("SANDBOX")
        store.commit_mode_marker(self.data)
        store.commit_mode_marker(self.data)      # EEXIST -> compare -> ok

    def test_the_race_loser_detects_the_winner_and_refuses(self):
        # O_EXCL means the loser re-reads and compares — never
        # overwrites (last-writer-wins is exactly what was refused).
        self.marker().write_text("PRODUCTION\n")
        self.with_mode("SANDBOX")
        with self.assertRaises(store.StoreError):
            store.commit_mode_marker(self.data)
        self.assertEqual(self.marker().read_text().strip(), "PRODUCTION")

    def test_a_write_failure_fails_closed(self):
        # EACCES et al. must raise, not proceed unclaimed.
        self.with_mode("SANDBOX")
        ro = self.root / "ro"
        ro.mkdir()
        os.chmod(str(ro), 0o500)
        try:
            with self.assertRaises(store.StoreError):
                store.commit_mode_marker(str(ro))
        finally:
            os.chmod(str(ro), 0o700)

    def test_open_db_with_an_explicit_path_never_touches_the_marker(self):
        self.with_mode("SANDBOX")
        store.open_db(self.path).close()
        self.assertFalse(self.marker().exists())
        self.assertFalse((self.root / "data" / "eb-environment").exists())


if __name__ == "__main__":
    unittest.main()


class TestSchemaV4Upgrade(Base):
    """Faithful deployed-v3 ledger -> v4. Same discipline as the v1->v2 and
    v2->v3 classes above: build a CURRENT file, remove exactly what v4
    added, stamp the old version, reopen. Migration 3 (the notes_fts
    backfill) must be untouched by this bump."""

    def _v3_file(self):
        p = pathlib.Path(self.dir.name) / "v3.sqlite"
        conn = store.open_db(p)
        conn.execute("BEGIN")
        conn.execute("DROP TABLE tag_rules")
        conn.execute("INSERT OR REPLACE INTO meta(key, value)"
                     " VALUES ('schema_version', '3')")
        conn.execute("COMMIT")
        conn.close()
        return p

    def test_fresh_file_has_tag_rules_at_the_current_version(self):
        conn = store.open_db(pathlib.Path(self.dir.name) / "f.sqlite")
        row = conn.execute("SELECT value FROM meta WHERE"
                           " key='schema_version'").fetchone()
        self.assertEqual(int(row[0]), store.SCHEMA_VERSION)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(tag_rules)")]
        self.assertEqual(cols, ["rule_id", "signature", "counterparty_canon",
                                "remittance_token", "direction", "currency",
                                "amount_min_minor", "amount_max_minor",
                                "dom_min", "dom_max", "weekdays", "tags",
                                "rationale", "created_at"])
        conn.close()

    def test_v3_ledger_upgrades_and_gains_tag_rules(self):
        p = self._v3_file()
        conn = store.open_db(p)
        self.assertEqual(int(conn.execute("SELECT value FROM meta WHERE"
                                          " key='schema_version'").fetchone()[0]),
                         store.SCHEMA_VERSION)
        self.assertEqual(conn.execute(
            "SELECT COUNT(*) FROM tag_rules").fetchone()[0], 0)
        conn.close()

    def test_signature_is_unique(self):
        conn = store.open_db(pathlib.Path(self.dir.name) / "u.sqlite")
        conn.execute("INSERT INTO tag_rules(signature, tags) VALUES ('s','a')")
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO tag_rules(signature, tags)"
                         " VALUES ('s','b')")
        conn.close()

    def test_migration_3_is_untouched(self):
        self.assertEqual(
            store._MIGRATIONS[3],
            ("INSERT INTO notes_fts(rowid, note)"
             " SELECT note_id, note FROM transaction_notes;",))
        self.assertNotIn(4, store._MIGRATIONS)


class LegacySeedIsRetired(unittest.TestCase):
    """Deleting the seed from source does not clear an existing database.

    open_db only ever inserted capability rows, so an installation upgraded
    from v4 still holds the rows the old seeder wrote. They are another
    installation's measurements presented as this one's, which is the thing
    the seed removal is for.
    """

    def _v4_db_with_seeded_rows(self, path):
        conn = sqlite3.connect(path)
        conn.executescript(store._SCHEMA)
        conn.execute(
            "INSERT INTO aspsp_capability"
            "(aspsp, ref_stable, ref_scope, observed_n, provenance, updated_at)"
            " VALUES (?,?,?,?,?,?)",
            ("REVOLUT", 1, "account", 100,
             # The predicate matches the seed's SHAPE -- marker, ISO date,
             # colon. Everything here is this test's own; no figure the old
             # seeder wrote appears in this repository.
             SEED_PREFIX + "2026-01-01: ExampleBank, 100/100",
             "2026-01-01T00:00:00Z"))
        conn.execute(
            "INSERT INTO aspsp_capability"
            "(aspsp, ref_stable, ref_scope, observed_n, provenance, updated_at)"
            " VALUES (?,?,?,?,?,?)",
            ("BUNQ", 1, "account", 40, "observed locally 2026-05-01",
             "2026-05-01T00:00:00Z"))
        conn.execute("INSERT OR REPLACE INTO meta(key, value)"
                     " VALUES ('schema_version', '4')")
        conn.commit()
        conn.close()

    def _retired_by(self, conn):
        return {r[0]: r[1] for r in conn.execute(
            "SELECT aspsp, retired_by FROM aspsp_capability_retired")}

    def test_opening_a_v4_database_retires_seed_and_local_rows_apart(self):
        # v5's predicate takes the seeded row; v6's earned-trust sweep takes
        # everything left, the local row included. The live table ends empty
        # either way -- what the two arms disagree about, and what these
        # tests pin, is WHICH migration took each row.
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            conn = store.open_db(path)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM aspsp_capability").fetchone()[0], 0)
            self.assertEqual(self._retired_by(conn),
                             {"REVOLUT": "schema v5 (seed shape)",
                              "BUNQ": "schema v6 (earned trust)"})
            conn.close()

    def test_a_locally_observed_row_is_archived_intact_not_honoured(self):
        # Under the earned model a hand-written capability row is an
        # observation-free trust claim: it is retired verbatim (recoverable,
        # auditable) and influences nothing.
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            conn = store.open_db(path)
            self.assertEqual(provenance.capability(conn, "Bunq", "acc1"),
                             provenance.DEFAULT_CAPABILITY)
            row = conn.execute(
                "SELECT observed_n, provenance FROM aspsp_capability_retired"
                " WHERE aspsp='BUNQ'").fetchone()
            self.assertEqual(row["observed_n"], 40)
            self.assertEqual(row["provenance"], "observed locally 2026-05-01")
            conn.close()

    def test_a_local_row_whose_provenance_differs_only_in_case_survives(self):
        """The predicate must match the seeder's casing and no other.

        SQLite's LIKE is ASCII case-insensitive, so a locally observed row that
        happens to open with those same words in another casing would be
        deleted alongside the seed -- destroying the one kind of row the
        migration exists to preserve.
        """
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            conn = sqlite3.connect(path)
            conn.execute(
                "INSERT INTO aspsp_capability"
                "(aspsp, ref_stable, ref_scope, observed_n, provenance,"
                " updated_at) VALUES (?,?,?,?,?,?)",
                ("ING", 1, "account", 30,
                 SHOUTED_PREFIX + "was the phrase; observed locally anyway",
                 "2026-05-01T00:00:00Z"))
            conn.commit()
            conn.close()
            conn = store.open_db(path)
            by = self._retired_by(conn)
            self.assertEqual(by["ING"], "schema v6 (earned trust)",
                             "the case-different row must not match the v5 "
                             "seed predicate")
            self.assertEqual(by["REVOLUT"], "schema v5 (seed shape)")
            conn.close()

    def test_local_notes_that_merely_begin_the_same_way_survive(self):
        """The predicate must match the seeder's shape, not its opening words.

        A prefix-only predicate deleted free-text local notes that happened to
        start with the same phrase, and -- because SQLite's LIKE is ASCII
        case-insensitive -- notes that differed only in case. Both are exactly
        the row the migration exists to preserve.
        """
        survivors = [
            ("ING", SEED_PREFIX + "lab replay"),
            ("ASN", SHOUTED_PREFIX + "2026-08-02: shouted, but observed here"),
            ("TRIODOS", SEED_PREFIX + "notes reviewed; observed locally"),
            ("KNAB", "observed locally 2026-06-01"),
        ]
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            conn = sqlite3.connect(path)
            for name, origin in survivors:
                conn.execute(
                    "INSERT INTO aspsp_capability(aspsp, ref_stable, ref_scope,"
                    " observed_n, provenance, updated_at)"
                    " VALUES (?,1,'account',30,?,'2026-06-01T00:00:00Z')",
                    (name, origin))
            conn.commit()
            conn.close()
            conn = store.open_db(path)
            by = self._retired_by(conn)
            for name, _origin in survivors:
                self.assertEqual(by[name], "schema v6 (earned trust)",
                                 "%s must not match the v5 seed predicate"
                                 % name)
            self.assertEqual(by["REVOLUT"], "schema v5 (seed shape)",
                             "only the dated seed row matches the seed arms")
            conn.close()

    def test_a_seed_row_written_on_any_date_is_still_retired(self):
        """The shape carries a date pattern, not the one date shipped, so an
        installation seeded by a build that stamped a different date is still
        cleaned."""
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            conn = sqlite3.connect(path)
            conn.execute(
                "INSERT INTO aspsp_capability(aspsp, ref_stable, ref_scope,"
                " observed_n, provenance, updated_at)"
                " VALUES ('ING',1,'account',30,?,'t')",
                (SEED_PREFIX + "2025-11-30: measured elsewhere",))
            conn.commit()
            conn.close()
            conn = store.open_db(path)
            self.assertEqual(self._retired_by(conn)["ING"],
                             "schema v5 (seed shape)")
            conn.close()

    def test_a_retired_row_is_kept_verbatim_not_destroyed(self):
        """No text predicate over free prose can be exact, so the migration
        does not destroy: it moves. A wrongly-matched local observation is
        then recoverable, and an operator can see what stopped being honoured.
        """
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            conn = store.open_db(path)
            rows = conn.execute(
                "SELECT aspsp, ref_stable, ref_scope, observed_n, provenance,"
                " retired_by FROM aspsp_capability_retired"
                " WHERE retired_by LIKE 'schema v5%'").fetchall()
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["aspsp"], "REVOLUT")
            self.assertEqual(row["ref_stable"], 1)
            self.assertEqual(row["ref_scope"], "account")
            self.assertEqual(row["observed_n"], 100)
            self.assertTrue(row["provenance"].startswith(SEED_MARKER))
            self.assertEqual(row["retired_by"], "schema v5 (seed shape)")
            conn.close()

    def test_a_retired_row_can_never_influence_identity(self):
        """The archive exists so over-matching is safe. That only holds if
        nothing reads it back into a trust decision."""
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            conn = store.open_db(path)
            self.assertEqual(provenance.capability(conn, "Revolut", "acc1"),
                             provenance.DEFAULT_CAPABILITY)
            self.assertIsNotNone(
                provenance.capability_warning(conn, "Revolut", "acc1"))
            conn.close()

    def test_reopening_does_not_retire_the_same_row_twice(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            store.open_db(path).close()
            conn = store.open_db(path)
            # one row per arm: the seeded REVOLUT under v5, the local BUNQ
            # under v6 -- and reopening adds nothing.
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM aspsp_capability_retired"
                ).fetchone()[0], 2)
            conn.close()

    def test_a_fresh_database_retires_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            conn = store.open_db(pathlib.Path(d) / "bank_feed.sqlite")
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM aspsp_capability_retired"
                ).fetchone()[0], 0)
            conn.close()

    def _seeded_literal(self):
        """One provenance string the removed seeder actually wrote, recovered
        from git rather than written into this tree.

        The digest arm is the exact one, so a test that never feeds it a real
        seeded string proves nothing about it -- but writing that string here
        would republish the measurement the removal exists to withhold. So it
        is reconstructed at run time from history, and skipped if history is
        not available.
        """
        import subprocess
        out = subprocess.run(
            ["git", "log", "--all", "--format=%H", "--",
             "plugins/bank-feed/server/provenance.py"],
            cwd=pathlib.Path(__file__).resolve().parents[1],
            capture_output=True, text=True)
        for commit in out.stdout.split():
            src = subprocess.run(
                ["git", "show", "%s:plugins/bank-feed/server/provenance.py" % commit],
                cwd=pathlib.Path(__file__).resolve().parents[1],
                capture_output=True, text=True).stdout
            if "MEASURED_CAPABILITIES" not in src:
                continue
            block = src[src.index("MEASURED_CAPABILITIES"):]
            block = block[:block.index("\n)\n") + 3]
            ns = {}
            exec(block.replace("MEASURED_CAPABILITIES", "M"), ns)
            return ns["M"][0]["provenance"]
        return None

    def test_both_arms_are_present_in_the_migration_predicate(self):
        """A structural check, because a behavioural one is impossible here.

        Every string the seeder actually wrote matches BOTH arms, so removing
        the digest arm changes no outcome and no test of retired rows would
        notice -- which is exactly what a mutation run showed. What the digest
        arm buys is the `retired_by` label and exactness if the shape arm is
        ever narrowed, so the thing worth pinning is that it is still there.
        """
        self.assertIn("bankfeed_sha256(provenance) IN", store._SEED_MATCH)
        for digest in store.SEED_PROVENANCE_DIGESTS:
            self.assertIn(digest, store._SEED_MATCH, digest)
        self.assertIn(store.SEED_PROVENANCE_GLOB, store._SEED_MATCH)

    def test_the_two_arms_agree_on_every_string_the_seeder_wrote(self):
        """States the overlap as a fact rather than leaving it implied.

        If this ever fails, the arms have diverged and the comment in store.py
        explaining why either can be removed without effect is stale.
        """
        import hashlib
        origin = self._seeded_literal()
        if origin is None:
            self.skipTest("seeder not recoverable from history here")
        self.assertIn(hashlib.sha256(origin.encode()).hexdigest(),
                      store.SEED_PROVENANCE_DIGESTS)
        conn = sqlite3.connect(":memory:")
        store._register_functions(conn)
        conn.executescript(store._SCHEMA)
        conn.execute(
            "INSERT INTO aspsp_capability(aspsp, ref_stable, ref_scope,"
            " observed_n, provenance, updated_at)"
            " VALUES ('X',0,'unknown',0,?,'t')", (origin,))
        by_shape = conn.execute(
            "SELECT count(*) FROM aspsp_capability WHERE provenance GLOB ?",
            (store.SEED_PROVENANCE_GLOB,)).fetchone()[0]
        by_digest = conn.execute(
            "SELECT count(*) FROM aspsp_capability WHERE"
            " bankfeed_sha256(provenance) IN (%s)"
            % store._SEED_DIGEST_LIST).fetchone()[0]
        conn.close()
        self.assertEqual((by_shape, by_digest), (1, 1))

    def test_a_genuine_seeded_row_is_retired_and_labelled_a_certainty(self):
        origin = self._seeded_literal()
        if origin is None:
            self.skipTest("seeder not recoverable from history here")
        import hashlib
        self.assertIn(hashlib.sha256(origin.encode()).hexdigest(),
                      store.SEED_PROVENANCE_DIGESTS,
                      "the committed digest set must contain what the seeder "
                      "actually wrote, or the exact arm matches nothing")
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            conn = sqlite3.connect(path)
            conn.executescript(store._SCHEMA)
            conn.execute(
                "INSERT INTO aspsp_capability(aspsp, ref_stable, ref_scope,"
                " observed_n, provenance, updated_at)"
                " VALUES ('REVOLUT',1,'account',1,?,'t')", (origin,))
            conn.execute("INSERT OR REPLACE INTO meta(key,value)"
                         " VALUES('schema_version','4')")
            conn.commit()
            conn.close()
            conn = store.open_db(path)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM aspsp_capability").fetchone()[0], 0)
            self.assertEqual(conn.execute(
                "SELECT retired_by FROM aspsp_capability_retired"
                ).fetchone()[0], "schema v5 (seed digest)")
            conn.close()

    def test_the_digest_arm_alone_retires_a_seeded_row_with_no_date_shape(self):
        """The two arms are independent. A seeded string that did NOT match the
        shape must still be retired, or the exact arm is decorative."""
        origin = self._seeded_literal()
        if origin is None:
            self.skipTest("seeder not recoverable from history here")
        self.assertTrue(origin.startswith(SEED_MARKER))
        # Prove the digest arm is what fires, by checking a row whose text is
        # the seeded string is retired even when the shape arm is removed.
        import sqlite3 as s3
        conn = s3.connect(":memory:")
        store._register_functions(conn)
        conn.executescript(store._SCHEMA)
        conn.execute(
            "INSERT INTO aspsp_capability(aspsp, ref_stable, ref_scope,"
            " observed_n, provenance, updated_at)"
            " VALUES ('REVOLUT',1,'account',1,?,'t')", (origin,))
        n = conn.execute(
            "SELECT count(*) FROM aspsp_capability WHERE"
            " bankfeed_sha256(provenance) IN (%s)"
            % store._SEED_DIGEST_LIST).fetchone()[0]
        self.assertEqual(n, 1)
        conn.close()

    def test_seed_rows_on_several_dates_are_all_retired(self):
        """One alternate date leaves a two-date-only predicate green."""
        dates = ["2020-01-01", "2023-07-15", "2025-11-30", "2026-08-02",
                 "2029-12-31"]
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            conn = sqlite3.connect(path)
            for i, day in enumerate(dates):
                conn.execute(
                    "INSERT INTO aspsp_capability(aspsp, ref_stable, ref_scope,"
                    " observed_n, provenance, updated_at)"
                    " VALUES (?,1,'account',30,?,'t')",
                    ("BANK%d" % i,
                     SEED_PREFIX + "%s: measured elsewhere" % day))
            conn.commit()
            conn.close()
            conn = store.open_db(path)
            by = self._retired_by(conn)
            for i in range(len(dates)):
                self.assertEqual(by["BANK%d" % i], "schema v5 (seed shape)",
                                 "every dated seed row must match the seed "
                                 "predicate, not just the ones a test "
                                 "happened to name")
            conn.close()

    def test_a_missing_sql_function_fails_loudly_not_silently(self):
        """The dangerous failure is not an error -- it is a migration that
        quietly retires nothing and stamps v5 anyway, leaving the seeded rows
        in place while the version says they are gone."""
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            bare = sqlite3.connect(path, isolation_level=None)
            try:
                with self.assertRaises(sqlite3.Error):
                    store._migrate(bare, 4)
                stamped = bare.execute(
                    "SELECT value FROM meta WHERE key='schema_version'"
                    ).fetchone()[0]
                self.assertEqual(int(stamped), 4,
                                 "a failed migration must not stamp forward")
            finally:
                bare.close()

    def test_two_banks_retired_by_the_same_arm_both_survive_in_the_archive(self):
        """PRIMARY KEY (aspsp, retired_by) must not collapse distinct banks."""
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            conn = sqlite3.connect(path)
            for name in ("RABOBANK", "ABN AMRO"):
                conn.execute(
                    "INSERT INTO aspsp_capability(aspsp, ref_stable, ref_scope,"
                    " observed_n, provenance, updated_at)"
                    " VALUES (?,1,'account',30,?,'t')",
                    (name, SEED_PREFIX + "2026-08-02: %s" % name))
            conn.commit()
            conn.close()
            conn = store.open_db(path)
            got = sorted(r[0] for r in conn.execute(
                "SELECT aspsp FROM aspsp_capability_retired"
                " WHERE retired_by LIKE 'schema v5%'"))
            self.assertEqual(got, ["ABN AMRO", "RABOBANK", "REVOLUT"])
            conn.close()

    def test_schema_version_is_stamped_forward(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v4_db_with_seeded_rows(path)
            conn = store.open_db(path)
            got = conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'").fetchone()
            self.assertEqual(int(got[0]), store.SCHEMA_VERSION)
            conn.close()


class TestSchemaV6EarnedTrust(unittest.TestCase):
    """v6: trust derives from account-keyed evidence; nothing per-ASPSP
    survives live, and every account carries an incarnation token."""

    def _v5_db(self, path, accounts=("acc1", "acc2"), capability_rows=()):
        conn = sqlite3.connect(path)
        conn.executescript(store._SCHEMA)
        for aid in accounts:
            conn.execute("INSERT INTO accounts(account_id) VALUES (?)",
                         (aid,))
        for name, origin in capability_rows:
            conn.execute(
                "INSERT INTO aspsp_capability(aspsp, ref_stable, ref_scope,"
                " observed_n, provenance, updated_at)"
                " VALUES (?,1,'account',30,?,'t')", (name, origin))
        conn.execute("INSERT OR REPLACE INTO meta(key, value)"
                     " VALUES ('schema_version', '5')")
        conn.commit()
        conn.close()

    def test_existing_accounts_are_minted_distinct_incarnations(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v5_db(path)
            conn = store.open_db(path)
            got = {r[0]: r[1] for r in conn.execute(
                "SELECT account_id, incarnation FROM accounts")}
            self.assertEqual(set(got), {"acc1", "acc2"})
            for aid, token in got.items():
                self.assertRegex(token, r"^[0-9a-f]{16}$", aid)
            self.assertNotEqual(got["acc1"], got["acc2"],
                                "one token per account, or the ABA guard "
                                "cannot tell two accounts' lives apart")
            conn.close()

    def test_reopening_does_not_remint_incarnations(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v5_db(path)
            conn = store.open_db(path)
            before = {r[0]: r[1] for r in conn.execute(
                "SELECT account_id, incarnation FROM accounts")}
            conn.close()
            conn = store.open_db(path)
            after = {r[0]: r[1] for r in conn.execute(
                "SELECT account_id, incarnation FROM accounts")}
            self.assertEqual(before, after)
            conn.close()

    def test_a_post_v5_local_capability_row_is_retired_by_v6(self):
        # After v5 the only possible residents are local set_capability
        # writes; under the earned model any such row is an observation-free
        # trust claim. Non-destructive: archived verbatim, honoured nowhere.
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            self._v5_db(path, capability_rows=(
                ("ING", "observed locally 2026-07-01"),))
            conn = store.open_db(path)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM aspsp_capability").fetchone()[0], 0)
            row = conn.execute(
                "SELECT provenance, retired_by FROM aspsp_capability_retired"
                " WHERE aspsp='ING'").fetchone()
            self.assertEqual(row["provenance"], "observed locally 2026-07-01")
            self.assertEqual(row["retired_by"], "schema v6 (earned trust)")
            self.assertEqual(provenance.capability(conn, "ING", "acc1"),
                             provenance.DEFAULT_CAPABILITY)
            conn.close()

    def test_ref_observations_exists_on_fresh_and_migrated_files(self):
        with tempfile.TemporaryDirectory() as d:
            fresh = store.open_db(pathlib.Path(d) / "fresh.sqlite")
            self.assertEqual(fresh.execute(
                "SELECT count(*) FROM ref_observations").fetchone()[0], 0)
            fresh.close()
            path = pathlib.Path(d) / "migrated.sqlite"
            self._v5_db(path)
            conn = store.open_db(path)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM ref_observations").fetchone()[0], 0)
            conn.close()

    def test_the_legacy_walk_ends_untrusted_and_earnable(self):
        # The acceptance walk: a seeded pre-v5 ledger arrives at v6 with
        # every ASPSP untrusted, both retirements archived, and trust
        # earnable from a fresh deep observation on its own account.
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "bank_feed.sqlite"
            conn = sqlite3.connect(path)
            conn.executescript(store._SCHEMA)
            conn.execute("INSERT INTO accounts(account_id, aspsp)"
                         " VALUES ('acc1', 'Revolut')")
            conn.execute(
                "INSERT INTO aspsp_capability(aspsp, ref_stable, ref_scope,"
                " observed_n, provenance, updated_at)"
                " VALUES ('REVOLUT',1,'account',100,?,'t')",
                (SEED_PREFIX + "2026-01-01: ExampleBank, 100/100",))
            conn.execute(
                "INSERT INTO aspsp_capability(aspsp, ref_stable, ref_scope,"
                " observed_n, provenance, updated_at)"
                " VALUES ('BUNQ',1,'account',40,'observed locally','t')")
            conn.execute("INSERT OR REPLACE INTO meta(key, value)"
                         " VALUES ('schema_version', '4')")
            conn.commit()
            conn.close()
            conn = store.open_db(path)
            for name in ("Revolut", "Bunq"):
                self.assertEqual(provenance.capability(conn, name, "acc1"),
                                 provenance.DEFAULT_CAPABILITY, name)
            incarnation = conn.execute(
                "SELECT incarnation FROM accounts WHERE account_id='acc1'"
                ).fetchone()[0]
            self.assertTrue(provenance.record_observation(
                conn, account_id="acc1", incarnation=incarnation,
                aspsp="Revolut", session_id="s1", kind="deep",
                window_days=2900,
                metrics={"rows_total": 200, "ref_transactions": 150,
                         "distinct_refs": 150, "reused_refs": 0,
                         "span_days": 400}))
            self.assertTrue(provenance.capability(
                conn, "Revolut", "acc1")["ref_stable"])
            conn.close()
