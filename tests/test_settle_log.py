"""Every settlement's work reaches a reply (issues #48, #53).

Settlement records what it writes into a log that lives for one dispatched
call, and the dispatcher renders it once, on every exit. These tests go through
`bank_feed_server.handle` — the only place the operator's reply is assembled —
and most start COLD, the way the first call of a process does: the ledger is
opened by the tool itself, and the open-time settlement runs inside that open.
"""
import ast
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
        self.assertTrue(out.startswith(
            LEAD + "completed a pending erasure, removing 1 backup "
            "copy(ies).\n"), out)
        # Said once: the next call in the same process has nothing to say.
        again = dispatch("list_accounts", data_dir=self.data)
        self.assertNotIn(LEAD, again)
        # And the log is gone with the call (Astra, code round 1): a direct
        # call after it records into nothing, and its "nothing" is plain.
        self.assertIsNone(backups._LOG.get())
        self.assertEqual(backups.unchanged(), "Nothing was changed.")

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
            LEAD + "removed the unfinished copy of interrupted backup %s; "
            "recorded interrupted backup %s as aborted.\n" % (op, op)), out)

    def test_forgetting_an_unknown_account_does_not_deny_what_settlement_removed(self):
        # Terra, code round 1: "so nothing was deleted" stood under a
        # settlement sentence naming a removed copy.
        [bid] = self.backups_taken(1)
        self.append_index("erase abcdefabcdefabcd pending")
        with mock.patch("tools_auth.protected_tools",
                        return_value={"forget_local_account"}):
            out = dispatch("forget_local_account", data_dir=self.data,
                           account_id="missing")
        self.assertFalse(self.paths.backup_file(bid).exists())
        self.assertIn(LEAD + "completed a pending erasure, removing 1 backup "
                      "copy(ies).", out)
        self.assertIn("so no account data was deleted", out)
        self.assertNotIn("nothing was deleted", out)

    def test_a_refusal_before_the_ledger_opens_still_says_nothing_changed(self):
        # The argument check runs before the tool opens the ledger: nothing,
        # settlement included, has run — the plain sentence is the true one.
        self.backups_taken(1)
        self.append_index("backup 1111111111111111 pending reason=manual")
        out = dispatch("backup", data_dir=self.data, reason="daily")
        self.assertEqual(out, "reason must be 'weekly' or 'manual'. Nothing "
                              "was changed.")

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
            LEAD + "resumed a pending erasure, removing 1 backup copy(ies); "
            "it is not finished: 1 whole copy(ies) could not be removed"), out)

    def test_a_torn_index_tail_cut_at_open_is_reported(self):
        self.backups_taken(1)
        with open(self.paths.index, "a") as f:
            f.write("20260101T000000Z backup 22222222")      # no newline
        out = dispatch("list_accounts", data_dir=self.data)
        self.assertTrue(out.startswith(
            LEAD + "cut an incomplete last line from the backup index.\n"),
            out)

    def test_an_open_time_commit_failure_does_not_fail_the_open(self):
        # Terra, round 2: SQLite can roll back by itself on a failed COMMIT,
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
        # Astra, round 1: a failure after settlement (here the listing's own
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
            LEAD + "completed a pending erasure, removing 1 backup "
            "copy(ies).\nerror: RuntimeError: boom"), out)
        self.assertIsNone(backups._LOG.get(), "an exception exit resets too")

    def test_a_successful_restore_names_the_record_its_settlement_closed(self):
        # Astra, round 1: the restore's success reply never rendered any
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
        # Astra, round 3: the rename failing left this call's own `pending`
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
        self.assertIn("its index records the attempt as aborted. This call's "
                      "backup copy was not kept.", out)
        self.assertNotIn("changed nothing", out)
        self.assertEqual(list(self.paths.backups_dir.glob("*.partial")), [])

class TestUncertainWritesAreWordedAsUncertain(Cold):
    """Astra, code round 1: a write whose outcome is unknown (`written`
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
        self.assertIn("recording the earlier removal of 1 backup copy", out)
        self.assertNotIn("2 backup copies", out)
        self.assertNotIn("may have been recorded", out)

    def test_a_prune_that_may_not_have_landed_is_not_claimed(self):
        self._gone_copy_and_pending_erasure()
        with self._prune_fails(1):
            out = dispatch("list_accounts", data_dir=self.data)
        self.assertIn("the earlier removal of 1 backup copy may have been "
                      "recorded", out)
        self.assertNotIn("recording the earlier removal", out)

    def test_a_header_that_could_not_be_cut_back_is_reported(self):
        self.warm()
        self._close()
        self.paths.backups_dir.mkdir(mode=0o700, exist_ok=True)
        self.paths.index.write_bytes(b"")
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
        self.assertTrue(out.startswith(
            LEAD + "may have left part of a header in the backup index "
            "(the next settlement cuts it).\n"), out)

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
        self.assertIn("its index records the attempt as aborted, though that "
                      "record could not be flushed", out)
        self.assertNotIn("pending index record stays", out)


class TestTheClaimHasOneSpelling(unittest.TestCase):
    """A reply may claim "nothing was changed" only through
    `backups.unchanged`, which scopes the claim once settlement has written
    anything in the call. A literal anywhere else would say it unscoped."""

    # Every verb settlement can make false — it creates, writes, removes
    # and changes files and index records — in the report tenses. Terra's
    # round-1 finding was a "nothing was deleted" the first gate, which knew
    # only "changed" and "erased", could not see.
    CLAIM = re.compile(r"(?i)\b(nothing|no other [a-z ]+?) (was|were|has "
                       r"been|have been|had been) (changed|erased|deleted|"
                       r"removed|written|created|modified|touched)")
    ALLOWED = {("backups.py", "unchanged"),
               ("backups.py", "no_other_copy_changed")}

    def _docstrings(self, tree):
        out = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
                body = node.body
                if (body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)):
                    out.add(id(body[0].value))
        return out

    def _functions(self, tree):
        spans = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                spans.append((node.lineno, node.end_lineno, node.name))
        return spans

    HOLE = "\x00"

    def _static(self, node):
        """The text a string expression renders, with every part that is not
        a constant as HOLE; None for anything that is not one. Folds what a
        claim can be built from: `+`, `%`, `.format` and f-strings — Astra's
        code round 1 built all three past a constants-only gate."""
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self._static(node.left), self._static(node.right)
            if left is None and right is None:
                return None
            return (left or self.HOLE) + (right or self.HOLE)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            fmt = self._static(node.left)
            if fmt is None:
                return None
            args = (node.right.elts if isinstance(node.right, ast.Tuple)
                    else [node.right])
            vals = iter([self._static(a) or self.HOLE for a in args])
            return re.sub(r"%[-#0 +]*\d*(?:\.\d+)?[sdrfx]",
                          lambda m: next(vals, self.HOLE), fmt)
        if isinstance(node, ast.JoinedStr):
            return "".join(
                v.value if isinstance(v, ast.Constant)
                else (self._static(v.value) or self.HOLE)
                for v in node.values)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"):
            fmt = self._static(node.func.value)
            if fmt is None:
                return None
            vals = iter([self._static(a) or self.HOLE for a in node.args])
            return re.sub(r"\{[^{}]*\}", lambda m: next(vals, self.HOLE), fmt)
        return None

    def _claims(self, source, name="<test>"):
        tree = ast.parse(source)
        docs, funcs = self._docstrings(tree), self._functions(tree)
        hits = set()
        for node in ast.walk(tree):
            if id(node) in docs or not hasattr(node, "lineno"):
                continue
            text = self._static(node)
            if text is None or not self.CLAIM.search(text):
                continue
            inside = {n for s, e, n in funcs if s <= node.lineno <= e}
            if any((name, f) in self.ALLOWED for f in inside):
                continue
            hits.add("%s:%d" % (name, node.lineno))
        return hits

    def test_no_literal_claims_nothing_changed_outside_the_one_function(self):
        hits = set()
        for path in sorted(SERVER.glob("*.py")):
            hits |= self._claims(path.read_text(), path.name)
        self.assertEqual(sorted(hits), [])

    def test_the_gate_sees_every_way_the_claim_can_be_built(self):
        # Mutation check of the gate itself, one construction per line.
        for source in ('x = ("a. Nothing was "\n     "changed.")',
                       'x = "Nothing" + " was changed."',
                       'x = "{} was changed.".format("Nothing")',
                       "x = f\"{'Nothing'} was changed.\"",
                       'x = "%s was deleted." % "nothing"',
                       'x = "a; nothing has been " + "removed"'):
            with self.subTest(source=source):
                self.assertTrue(self._claims(source), source)
        self.assertFalse(self._claims('x = "a " + backups.unchanged()'))

    def test_no_tool_renders_settlement_itself(self):
        # The dispatcher is the ONE renderer of settlement's work; a tool
        # reading `.settled` or `describe()` would say it a second time.
        hits = []
        for path in sorted(SERVER.glob("*.py")):
            if path.name == "backups.py":
                continue
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Attribute) and node.attr in (
                        "settled", "describe"):
                    hits.append("%s:%d .%s" % (path.name, node.lineno,
                                               node.attr))
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
