"""`delete_data_keep_signins` is bank-feed's `casa.eraseDataOnlyTool` (issue
#73): uninstall's "Erase data, keep sign-ins". Every piece of money data and
every copy of it goes; the bank sessions, the accounts bound to them and the
setup state stay, so a reinstall syncs again with no re-approval. Then the
uninstall fence keeps every other call out until `setup_bank_feed` runs, so
the erased data cannot come back before casa removes the plugin."""
import fcntl
import json
import os
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))

import apply  # noqa: E402
import backups  # noqa: E402
import bank_feed_server  # noqa: E402
import callbacks  # noqa: E402
import store  # noqa: E402
import tools_auth  # noqa: E402
import tools_backup  # noqa: E402,F401  (registers backup)
import tools_destructive  # noqa: E402
import tools_read  # noqa: E402
import tools_refresh  # noqa: E402,F401  (registers export_history, sync)
from _toolbase import (LINKED_IBAN, PLUGIN_ROOT, SESSION_ID, call,  # noqa: E402
                       dispatch)
from test_tools_destructive import DestructiveBase  # noqa: E402

TOOL = "delete_data_keep_signins"


class DataOnlyBase(DestructiveBase):
    def erase(self):
        out = call(TOOL)
        self.assertIsInstance(out.result, dict, out)
        self.assertEqual(set(out.result), {"erasure", "report"})
        return out, out.result["erasure"]

    def attempt(self, state_hash, phase, aspsp="Rabobank", lease_token=None,
                lease_expiry=None, created_at=None):
        self.raw.execute(
            "INSERT INTO attempts(state_hash, aspsp_name, country, psu_type,"
            " purpose, phase, created_at, lease_token, lease_expiry)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (state_hash, aspsp, "NL", "personal", "link", phase,
             created_at if created_at is not None else 1.0, lease_token,
             lease_expiry))

    def phases(self):
        return sorted(r[0] for r in self.raw.execute(
            "SELECT phase FROM attempts"))

    def money(self):
        """Every kind of money data, one row each."""
        self.tx()
        row = self.raw.execute("SELECT row_id FROM transactions").fetchone()[0]
        self.raw.execute("INSERT INTO transaction_refs(row_id, provider_ref)"
                         " VALUES (?, 'ref-1')", (row,))
        self.raw.execute("INSERT INTO transaction_tags(row_id, tag)"
                         " VALUES (?, 'groceries')", (row,))
        self.raw.execute(
            "INSERT INTO transaction_notes(row_id, author, note, created_at)"
            " VALUES (?, 'user', 'paid back by Sam', '2026-08-01')", (row,))
        self.raw.execute(
            "INSERT INTO tag_rules(signature, tags) VALUES ('sig', 'groceries')")
        self.raw.execute(
            "INSERT INTO balances(account_id, balance_type, amount_minor,"
            " currency) VALUES ('acc1','CLBD',100,'EUR')")
        apply.record_coverage(self.raw, "acc1", "2026-01-01", "2026-02-01",
                              "s1", incarnation="")
        self.alloc("acc1", "ik-hash", 3)
        self.raw.execute(
            "INSERT INTO ref_observations(account_id, aspsp, kind, observed_at,"
            " window_days, rows_total, ref_transactions, distinct_refs,"
            " reused_refs, span_days) VALUES"
            " ('acc1','Rabobank','deep','2026-08-01',90,1,1,1,0,1)")
        self.raw.execute(
            "INSERT INTO aspsp_capability_retired(aspsp, retired_by)"
            " VALUES ('Rabobank', 'v5')")
        self.raw.execute(
            "INSERT INTO workflow_registrations(workflow, backup_id,"
            " registered_at) VALUES ('wf', 'b', '2026-08-01')")


class TestWhatGoes(DataOnlyBase):
    def test_every_money_table_is_emptied(self):
        self.session()
        self.account()
        self.money()
        # Nothing vacuous: every table but the retired-at-v6 live capability
        # table (nothing writes it) holds a row before the erasure.
        for table in tools_destructive._DATA_ONLY_TABLES:
            if table != "aspsp_capability":
                self.assertGreater(self.count(table), 0, table)
        _, verdict = self.erase()
        for table in tools_destructive._DATA_ONLY_TABLES:
            self.assertEqual(self.count(table), 0, table)
        self.assertEqual(self.count("notes_fts"), 0)
        self.assertEqual(verdict, "complete")

    def test_the_erased_tables_are_every_data_table_but_the_signin_ones(self):
        # A data table added to `_DATA_TABLES` later is erased here by
        # default; only these three are kept, and `sessions` is in neither.
        self.assertEqual(set(tools_destructive.SIGNIN_TABLES),
                         {"accounts", "sync_state", "attempts"})
        self.assertEqual(
            set(tools_destructive._DATA_ONLY_TABLES),
            set(tools_destructive._DATA_TABLES)
            - set(tools_destructive.SIGNIN_TABLES))
        self.assertNotIn("sessions", tools_destructive._DATA_TABLES)

    def test_no_autoincrement_counter_of_the_erased_tables_survives(self):
        self.session()
        self.account()
        self.money()
        _, verdict = self.erase()
        left = {r[0] for r in self.raw.execute(
            "SELECT name FROM sqlite_sequence")}
        self.assertEqual(left & set(tools_destructive._DATA_ONLY_TABLES),
                         set())
        self.assertEqual(verdict, "complete")

    def test_account_user_work_is_reset_and_the_incarnation_rotated(self):
        self.session()
        self.account(included=0)
        self.raw.execute("UPDATE accounts SET label='Joint', incarnation='old'")
        self.erase()
        row = self.raw.execute(
            "SELECT label, category, included, incarnation FROM accounts"
        ).fetchone()
        self.assertIsNone(row["label"])
        self.assertIsNone(row["category"])
        self.assertEqual(row["included"], 1)
        self.assertNotIn(row["incarnation"], ("old", ""))

    def test_history_is_marked_partial_and_retry_holds_kept(self):
        self.session()
        self.account()
        self.synced(resource="transactions", next_retry_after="2099-01-01",
                    last_success_session=SESSION_ID)
        self.synced(resource="balances", last_success_at="2026-08-01")
        self.erase()
        tx = self.raw.execute(
            "SELECT * FROM sync_state WHERE resource='transactions'").fetchone()
        self.assertEqual(tx["completeness"], "partial")
        self.assertIsNone(tx["last_success_session"])
        self.assertIn("history erased at uninstall", tx["last_error"])
        self.assertEqual(tx["next_retry_after"], "2099-01-01")
        bal = self.raw.execute(
            "SELECT * FROM sync_state WHERE resource='balances'").fetchone()
        self.assertIsNone(bal["last_success_at"])

    def test_an_account_never_synced_is_marked_partial_too(self):
        # An UPDATE alone would skip it, leaving a routine refresh free to
        # record the erased history as complete.
        self.session()
        self.account()
        self.erase()
        self.assertEqual(self.raw.execute(
            "SELECT completeness FROM sync_state WHERE account_id='acc1'"
            " AND resource='transactions'").fetchone()[0], "partial")

    def test_meta_keeps_setup_and_renewal_state_and_nothing_else(self):
        self.session()
        tools_auth._meta_set(self.raw, "setup.app_id", "app-1")
        tools_auth._meta_set(self.raw, "setup.oob_email", "op@example.org")
        tools_auth.record_renewal_handoff(self.raw, SESSION_ID,
                                          "2026-12-01T00:00:00Z")
        tools_auth._meta_set(self.raw, "renewal_mismatch|" + SESSION_ID,
                             json.dumps({"unlinked": ["Joint"]}))
        tools_auth.claim_refresh(self.raw, "acc1")
        tools_auth._meta_set(self.raw, "some_future_key", "x")
        # `_` is a LIKE wildcard: a key that differs only there must not
        # pass as a renewal handoff.
        tools_auth._meta_set(self.raw, "renewalXhandoff|x", "x")
        secret = store.local_secret(self.raw)
        instance = store.ledger_instance(self.raw)
        self.erase()
        keys = {r[0] for r in self.raw.execute("SELECT key FROM meta")}
        self.assertEqual(keys, {
            "schema_version", "account_secret", "setup.app_id",
            "setup.oob_email", "renewal_handoff|" + SESSION_ID,
            store.LEDGER_INSTANCE_KEY, store.UNINSTALL_FENCE_KEY})
        self.assertEqual(store.local_secret(self.raw), secret)
        self.assertNotEqual(store.ledger_instance(self.raw), instance)

    def test_backups_and_snapshots_go_and_the_index_stays(self):
        self.session()
        self.account()
        self.tx()
        call("backup", reason="manual")
        paths = backups.paths_for(self.root / "f.sqlite")
        self.assertTrue(any(paths.backups_dir.iterdir()))
        snap = self.root / (paths.snapshot_prefix + "5-20260101T000000Z")
        snap.write_bytes(b"x")
        out, verdict = self.erase()
        self.assertEqual(list(paths.backups_dir.iterdir()), [])
        self.assertFalse(snap.exists())
        self.assertTrue(paths.index.exists())
        self.assertIn("were erased too", out)
        self.assertEqual(verdict, "complete")

    def test_a_backup_sweep_that_stopped_is_incomplete(self):
        self.account()
        with mock.patch.object(backups, "erase_backups",
                               side_effect=backups.BackupError("disk")):
            out, verdict = self.erase()
        self.assertEqual(verdict, "incomplete")
        self.assertIn("WARNING", out)

    def test_exports_go(self):
        self.session()
        self.account()
        self.tx()
        call("export_history", format="csv")
        out, verdict = self.erase()
        self.assertFalse((self.handoff / "bank-feed").exists())
        self.assertIn("1 export file(s)", out)
        self.assertEqual(verdict, "complete")

    def test_an_export_that_cannot_be_removed_makes_it_incomplete(self):
        pdir = self.handoff / "bank-feed"
        (pdir / "1234567890123-0123456789abcdef").mkdir(parents=True)

        def refuse(path, *a, **k):
            raise PermissionError(13, "Permission denied")
        with mock.patch.object(tools_destructive.shutil, "rmtree", refuse):
            out, verdict = self.erase()
        self.assertIn("removal of the published exports did not finish", out)
        self.assertEqual(verdict, "incomplete")

    def test_an_unfinished_reclaim_is_incomplete(self):
        self.account()
        self.break_vacuum()
        _, verdict = self.erase()
        self.assertEqual(verdict, "incomplete")

    def test_the_other_modes_ledger_makes_it_incomplete(self):
        other = self.root / store._other_db_filename()
        other.write_bytes(b"x")
        out, verdict = self.erase()
        self.assertTrue(other.exists())
        self.assertIn("run delete_data_keep_signins in that mode", out)
        self.assertEqual(verdict, "incomplete")

    def test_a_retry_is_complete_and_mints_another_instance(self):
        self.session()
        self.account()
        self.tx()
        self.erase()
        first = store.ledger_instance(self.raw)
        _, verdict = self.erase()
        self.assertEqual(verdict, "complete")
        self.assertNotEqual(store.ledger_instance(self.raw), first)


class TestWhatStays(DataOnlyBase):
    def test_sessions_and_bindings_survive_and_no_bank_is_asked(self):
        self.session()
        self.session(sid="1b7c0f42-5e18-42a9-9d3c-2a6e4f8b1c05",
                     aspsp="ABN AMRO")
        self.account()
        self.account(aid="acc2",
                     session_id="1b7c0f42-5e18-42a9-9d3c-2a6e4f8b1c05")
        before = self.bindings()
        sessions = self.raw.execute(
            "SELECT * FROM sessions ORDER BY session_id").fetchall()
        out, _ = self.erase()
        self.assertEqual(self.bindings(), before)
        self.assertEqual([tuple(r) for r in self.raw.execute(
            "SELECT * FROM sessions ORDER BY session_id")],
            [tuple(r) for r in sessions])
        self.assertEqual(self.ais.deleted, [])
        self.assertIn("the 2 bank consent(s) held open here, the 2 "
                      "account(s) bound to them", out)

    def test_a_relinked_account_derives_the_same_id(self):
        # The kept secret is what keeps a renewal from forking the account.
        self.session()
        aid = self.expected_account_id()
        self.account(aid=aid)
        self.erase()
        self.assertEqual(self.expected_account_id(LINKED_IBAN), aid)

    def test_attempts_that_never_exchanged_a_code_are_cancelled(self):
        # A kept `minted` attempt's callback, arriving after the erasure,
        # would bind a session and backfill the erased ledger.
        for i, phase in enumerate(("minted", "held", "exchange_started",
                                   "exchanged", "indeterminate",
                                   "review_required", "abandoned")):
            self.attempt("sh%d" % i, phase, aspsp="Bank %d" % i)
        out, verdict = self.erase()
        self.assertEqual(self.phases(), sorted(
            ("exchange_started", "exchanged", "indeterminate",
             "review_required", "abandoned")))
        self.assertIn("Cancelled 2 authorization(s) that had not been "
                      "completed (Bank 0, Bank 1)", out)
        self.assertEqual(verdict, "complete")

    def test_the_kept_phases_are_the_settled_ones_and_exchange_started(self):
        self.assertEqual(set(tools_destructive._EXCHANGED_PHASES),
                         callbacks.SETTLED_PHASES | {"exchange_started"})

    def test_a_cancelled_attempts_callback_is_not_ours_any_more(self):
        self.attempt(self.state_hash, "minted")
        self.erase()
        self.assertIsNone(self.raw.execute(
            "SELECT 1 FROM attempts WHERE state_hash=?",
            (self.state_hash,)).fetchone())

    def test_an_authorization_in_progress_refuses_with_nothing_erased(self):
        self.session()
        self.account()
        self.tx()
        self.attempt("sh", "exchange_started", lease_token="t",
                     lease_expiry=tools_auth._now_s() + 60,
                     created_at=tools_auth._now_s())
        out = call(TOOL)
        self.assertNotIsInstance(out, dict)
        self.assertFalse(hasattr(out, "result"))
        self.assertIn("Nothing was erased: a bank authorization is in "
                      "progress", out)
        self.assertEqual(self.count("transactions"), 1)
        self.assertIsNone(store.uninstall_fence(self.raw))
        self.assertFalse(self.raw.in_transaction)


class TestTheUninstallFence(DataOnlyBase):
    def fenced(self):
        self.session()
        self.account()
        self.tx()
        self.erase()
        self.assertIsNotNone(store.uninstall_fence(self.raw))

    def test_every_call_but_the_exempt_ones_refuses(self):
        self.fenced()
        ran = []
        for name, tool in bank_feed_server.TOOLS.items():
            if name in bank_feed_server.FENCE_EXEMPT:
                continue
            original = tool["fn"]
            tool["fn"] = lambda args, name=name: ran.append(name) or "ran"
            self.addCleanup(tool.__setitem__, "fn", original)
            out = dispatch(name)
            self.assertIn("Refused, nothing was done: bank-feed's data was "
                          "erased", out, name)
        self.assertEqual(ran, [])

    def test_the_exempt_list_is_the_one_the_design_names(self):
        self.assertEqual(bank_feed_server.FENCE_EXEMPT, {
            "delete_data_keep_signins", "delete_all_data", "setup_bank_feed",
            "bank_feed_signin", "consent_status", "unlink_bank"})

    def test_a_sync_writes_nothing(self):
        self.fenced()
        out = dispatch("sync")
        self.assertIn("setup_bank_feed", out)
        self.assertEqual(self.count("transactions"), 0)
        self.assertEqual(self.ais.tx_calls, [])

    def test_exempt_calls_run(self):
        self.fenced()
        self.assertNotIn("Refused", dispatch("consent_status"))

    def test_setup_lifts_it(self):
        self.fenced()
        dispatch("setup_bank_feed")
        self.assertIsNone(store.uninstall_fence(self.raw))
        self.assertNotIn("data was erased", dispatch("list_accounts"))

    def test_delete_all_data_runs_under_it_and_clears_it(self):
        self.fenced()
        out = dispatch("delete_all_data")
        self.assertNotIn("data was erased at", out)
        self.assertIsNone(store.uninstall_fence(self.raw))

    def test_no_ledger_means_no_fence_and_none_is_created(self):
        tools_read.CONN = None
        fresh = self.root / "fresh"
        fresh.mkdir()
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_DATA": str(fresh)}):
            self.assertIsNone(tools_read.existing_conn())
            self.assertIsNone(bank_feed_server._fenced("sync"))
        self.assertEqual(os.listdir(fresh), [])

    def test_a_process_with_no_ledger_open_reads_the_fence_from_the_file(self):
        # A fresh process: nothing opened yet, so the dispatcher reads the
        # mode's ledger file directly, and runs no settlement doing it.
        data = self.root / "d"
        data.mkdir()
        conn = store.open_db(data / store.db_filename())
        conn.execute("INSERT INTO meta(key, value) VALUES (?, ?)",
                     (store.UNINSTALL_FENCE_KEY, "2026-09-27T10:00:00Z"))
        conn.close()
        tools_read.CONN = None
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_DATA": str(data)}):
            self.assertEqual(bank_feed_server._fenced("sync"),
                             "2026-09-27T10:00:00Z")
            self.assertIsNone(bank_feed_server._fenced("consent_status"))
        self.assertIsNone(tools_read.CONN)
        for suffix in ("-wal", "-shm"):
            side = data / (store.db_filename() + suffix)
            if side.exists():
                self.assertEqual(side.stat().st_mode & 0o777, 0o600)

    def test_the_erasure_holds_the_lifecycle_lock_exclusively(self):
        self.assertIn(TOOL, bank_feed_server.EXCLUSIVE_TOOLS)
        seen = {}
        tool = bank_feed_server.TOOLS[TOOL]
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
        dispatch(TOOL)
        self.assertFalse(seen["shared_ok"])


class TestTheManifest(unittest.TestCase):
    def test_it_is_declared_as_the_data_only_eraser(self):
        casa = json.loads((PLUGIN_ROOT / ".claude-plugin/plugin.json")
                          .read_text("utf-8"))["casa"]
        self.assertEqual(casa["eraseDataOnlyTool"], TOOL)
        self.assertNotEqual(casa["eraseDataOnlyTool"], casa["eraseTool"])
        self.assertNotEqual(casa["eraseDataOnlyTool"], casa["setupTool"])
        self.assertEqual(casa["resultContract"]["tools"][TOOL],
                         {"result": "safe"})
        self.assertIn(TOOL, {p["name"] for p in casa["protectedTools"]})
        self.assertIn(TOOL, tools_auth.PROTECTED)
        self.assertIn(TOOL, tools_destructive.DESTRUCTIVE_TOOLS)
        self.assertEqual(bank_feed_server.TOOLS[TOOL]["schema"],
                         {"type": "object", "properties": {}})


if __name__ == "__main__":
    unittest.main()
