import ast, json, pathlib, re, subprocess, sys, textwrap, unittest

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"
SERVER = SERVER_DIR / "bank_feed_server.py"
PLUGIN_JSON = (pathlib.Path(__file__).resolve().parents[1] /
               "plugins/bank-feed/.claude-plugin/plugin.json")

# A throwaway stand-in for the real tool modules, planted under the exact name
# main() imports so the test drives the REAL registration path end to end, in a
# real subprocess. The bug this guards against: `bank_feed_server.main()` doing
# `import tools` (or any import of a module that itself does `import
# bank_feed_server`) executes THIS file a second time under a second module
# name when the server is launched as a script (Python names the running script
# "__main__", not "bank_feed_server"). The second copy's TOOLS dict is empty
# and is not the one handle() reads, so the live process would answer
# tools/list with an empty registry no matter what tools_read.py registers --
# and an in-process unit test that imports the module directly (skipping the
# __main__ launch path entirely) can never observe this.
_FAKE_TOOL_MODULE = textwrap.dedent("""
    import bank_feed_server

    def _echo(args):
        return "ok"

    bank_feed_server.TOOLS["_smoke_probe"] = {
        "description": "smoke-test probe, registered as an import side effect",
        "schema": {"type": "object", "properties": {}},
        "fn": _echo,
    }
""")


class TestServerSmoke(unittest.TestCase):
    """unittest, not pytest-style free functions: `unittest discover` finds zero
    tests in a module with only bare `def test_*` functions."""

    def setUp(self):
        self._planted = SERVER_DIR / "tools_read.py"
        self._pre_existing = self._planted.exists()
        if not self._pre_existing:
            self._planted.write_text(_FAKE_TOOL_MODULE)

    def tearDown(self):
        if not self._pre_existing:
            self._planted.unlink(missing_ok=True)

    def _rpc(self, proc, payload):
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())

    def test_initialize_and_list_tools_in_a_real_process(self):
        proc = subprocess.Popen([sys.executable, str(SERVER)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, text=True, cwd=str(SERVER_DIR))
        try:
            out = self._rpc(proc, {"jsonrpc": "2.0", "id": 1,
                                   "method": "initialize", "params": {}})
            self.assertEqual(out["result"]["serverInfo"]["name"], "bank-feed")
            out = self._rpc(proc, {"jsonrpc": "2.0", "id": 2,
                                   "method": "tools/list", "params": {}})
            tools = out["result"]["tools"]
            self.assertIsInstance(tools, list)
            names = {t["name"] for t in tools}
            if self._pre_existing:
                # The real modules have shipped by the time this runs; the
                # specific defect above is about the registry staying
                # EMPTY, so a non-empty live registry is the falsifiable
                # check.
                self.assertGreater(len(tools), 0,
                    "TOOLS is empty in the live process -- main()'s import did "
                    "not populate the registry handle() reads from")
            else:
                self.assertIn("_smoke_probe", names,
                    "the planted tools_read.py never reached the live "
                    "process's TOOLS dict -- main()'s import is populating a "
                    "different module object than the one handle() reads")
        finally:
            proc.stdin.close()
            proc.wait(timeout=5)


class TestManifestToolsMatchLiveRegistry(unittest.TestCase):
    """An import loop that swallows every ImportError, including one raised
    INSIDE an existing tools_read.py/tools_auth.py/tools_refresh.py/
    tools_destructive.py, leaves a live process that answers tools/list with
    fewer tools than casa.provides_tools declares and nothing to point at. Only
    a subprocess exercising the real __main__ launch path can observe that --
    an in-process import test never calls main() at all.

    Skips explicitly, with a stated reason, rather than passing vacuously: with
    any of the four real tool modules absent there is nothing real to compare
    against. The throwaway tools_read.py that
    TestServerSmoke plants above registers exactly one tool under a name
    provides_tools does not declare -- treating that fixture as "the real
    modules" would fail this assertion for a reason that has nothing to do
    with the defect it exists to catch, which is worse than skipping."""

    _REAL_MODULES = ("tools_read.py", "tools_auth.py", "tools_refresh.py",
                      "tools_destructive.py")

    def _rpc(self, proc, payload):
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())

    def test_tools_list_equals_manifest_provides_tools(self):
        missing = [m for m in self._REAL_MODULES if not (SERVER_DIR / m).exists()]
        if missing:
            self.skipTest(
                "real tool modules not shipped yet (missing: "
                f"{', '.join(missing)}) -- meaningful only once all four "
                "are present; see class docstring")
        manifest = json.loads(PLUGIN_JSON.read_text())
        declared = {t.rsplit("__", 1)[-1]
                    for t in manifest["casa"]["provides_tools"]}
        proc = subprocess.Popen([sys.executable, str(SERVER)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, text=True, cwd=str(SERVER_DIR))
        try:
            self._rpc(proc, {"jsonrpc": "2.0", "id": 1,
                             "method": "initialize", "params": {}})
            out = self._rpc(proc, {"jsonrpc": "2.0", "id": 2,
                                   "method": "tools/list", "params": {}})
            names = {t["name"] for t in out["result"]["tools"]}
            self.assertEqual(
                names, declared,
                "live tools/list must equal casa.provides_tools exactly -- a "
                "mismatch means a tool module failed to import (or "
                "over-registered) and main()'s fail-closed startup did not "
                "stop it")
        finally:
            proc.stdin.close()
            proc.wait(timeout=5)


class TestPluginManifest(unittest.TestCase):
    def test_protected_tools_are_exactly_the_six_protected_tools(self):
        manifest = json.loads(PLUGIN_JSON.read_text())
        protected = manifest["casa"]["protectedTools"]
        names = {p if isinstance(p, str) else p["name"] for p in protected}
        # unlink_bank/purge/forget_local_account/delete_all_data are
        # destructive and gated by casa's fail-closed PreToolUse hook.
        # label_account is NOT destructive but is still protected: it can set
        # included=false, an inference-only path for attacker-controlled bank
        # text to remove an account from every balance and total shown to the
        # operator -- money-relevant, even though it is reversible.
        # accept_app_reregistration is the ONLY key to the vanished-app gate --
        # no model-suppliable argument may authorize a registration that
        # orphans every bank session, so casa's own operator-confirmation hook
        # has to gate it. collect_authorization is EXCLUDED deliberately:
        # casa's nudge dispatches carry no operator sender, and a protected
        # call from such a turn is denied outright -- protecting it would
        # deadlock every link. setup_bank_feed is also excluded.
        self.assertEqual(names, {"unlink_bank", "purge", "forget_local_account",
                                 "delete_all_data", "label_account",
                                 "accept_app_reregistration"})
        self.assertNotIn("collect_authorization", names)
        self.assertNotIn("setup_bank_feed", names)
        for p in protected:
            if isinstance(p, dict):
                self.assertLessEqual(len(p.get("summary", "")), 200)

    def test_protected_tool_summaries_only_placeholder_their_own_arguments(self):
        """casa's authz_grants._interpolate_summary renders `summary` as a
        template interpolated with the call's canonical arguments before
        showing it to the operator in the approval challenge (`{identifier}`
        tokens -> argument values). Its parser silently falls back to a
        generic headline -- no error -- on `{{`/`}}`, a conversion (`{x!r}`),
        a format spec (`{x:>10}`), indexing/attribute access, or a
        placeholder that does not name a declared argument. A silent
        fallback is exactly the failure mode this test exists to catch: a
        template that degrades leaves no trace except a less specific
        sentence at the one moment the operator is deciding whether to
        approve an irreversible (or, for label_account, money-relevant)
        action. The tools' own schemas are the ground truth for each tool's
        argument names."""
        manifest = json.loads(PLUGIN_JSON.read_text())
        protected = {p["name"]: p for p in manifest["casa"]["protectedTools"]
                    if isinstance(p, dict)}
        # ground truth: each tool's declared inputSchema.properties
        declared_args = {
            "unlink_bank": {"consent_ref"},
            "purge": {"before_date"},
            "forget_local_account": {"account_id"},
            "delete_all_data": set(),
            "label_account": {"account_id"},
        }
        placeholder_re = re.compile(r"\{([^{}]*)\}")
        for name, allowed in declared_args.items():
            summary = protected[name]["summary"]
            self.assertNotIn("{{", summary)
            self.assertNotIn("}}", summary)
            self.assertEqual(summary.count("{"), summary.count("}"),
                             f"{name}: unbalanced brace voids the whole template")
            placeholders = placeholder_re.findall(summary)
            for p in placeholders:
                self.assertRegex(p, r"^[A-Za-z_][A-Za-z0-9_]*$",
                                 f"{name}: {p!r} is not a bare identifier "
                                 "(no !conversion, no :format spec, no indexing)")
                self.assertIn(p, allowed,
                             f"{name}: summary placeholders must be a subset of "
                             f"{sorted(allowed)} or the template silently voids")
            self.assertTrue(summary.isascii())
            self.assertLessEqual(len(summary), 200)
        # delete_all_data takes no arguments, so it must carry no placeholder
        # at all -- its static text is the only thing the operator reads.
        self.assertEqual(re.findall(r"\{[^{}]*\}", protected["delete_all_data"]["summary"]), [])


class TestPython311Compatible(unittest.TestCase):
    """The container runs Debian bookworm's Python 3.11; development happens
    on a newer interpreter (this repair round: 3.14). 3.12+-only syntax (PEP
    695 type-parameter syntax, `except*`, etc.) parses cleanly and passes
    every test on the dev interpreter, then fails at IMPORT time inside the
    container -- surfacing as a dead MCP server with no failing test to point
    at, not a test failure. This walks every server module and parses it
    targeting 3.11 specifically, so the mismatch is caught here instead."""

    def test_every_server_module_parses_under_python_3_11(self):
        failures = []
        for path in sorted(SERVER_DIR.glob("*.py")):
            src = path.read_text()
            try:
                ast.parse(src, filename=str(path), feature_version=(3, 11))
            except SyntaxError as exc:
                failures.append(f"{path.name}: {exc}")
        self.assertEqual(failures, [], "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
