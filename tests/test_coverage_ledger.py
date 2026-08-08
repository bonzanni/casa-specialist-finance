"""The code-derived coverage ledger.

The ledger's value is entirely in its enumeration: the check half is a set
difference, and a set difference against a list that cannot see a surface
reports HEALTHY. So most of these tests are about what the enumerator finds --
against the real tree where the surface exists today, and against a synthetic
one for the shapes this tree does not currently contain but the enumerator must
still see the day someone writes them.
"""
import importlib.util
import json
import pathlib
import sys
import tempfile
import textwrap
import unittest

_spec = importlib.util.spec_from_file_location(
    "sf_coverage_ledger",
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "coverage_ledger.py",
)
ledger = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ledger)

ROOT = pathlib.Path(__file__).resolve().parents[1]


class EnumerationAgainstTheRealTree(unittest.TestCase):
    def setUp(self):
        self.items = set(ledger.enumerate_items(ROOT))

    def test_every_server_module_is_enumerated(self):
        on_disk = {
            str(p.relative_to(ROOT)) for p in ROOT.glob("plugins/*/server/*.py")
        }
        self.assertTrue(on_disk, "the glob found no server modules at all")
        self.assertEqual(on_disk - self.items, set())
        self.assertIn("plugins/bank-feed/server/store.py", self.items)

    def test_the_smallest_module_is_still_enumerated(self):
        """A size floor is how a ledger stops seeing the modules easiest to forget."""
        self.assertEqual(ledger.MIN_MODULE_LINES, 0)
        self.assertIn("plugins/bank-feed/server/money.py", self.items)

    def test_a_registered_tool_is_enumerated(self):
        for name in ("tool:list_accounts", "tool:sync", "tool:delete_all_data"):
            self.assertIn(name, self.items)

    def test_a_protected_tool_is_enumerated(self):
        self.assertIn("protected:delete_all_data", self.items)

    def test_every_protected_tool_is_also_a_registered_tool(self):
        """A protected name nothing registers protects nothing."""
        protected = {i.split(":", 1)[1] for i in self.items if i.startswith("protected:")}
        tools = {i.split(":", 1)[1] for i in self.items if i.startswith("tool:")}
        self.assertEqual(protected - tools, set())

    def test_every_role_allowlist_entry_is_enumerated(self):
        self.assertIn("role:Read", self.items)
        self.assertIn("role:mcp__plugin_bank-feed_bank-feed__list_accounts", self.items)

    def test_an_environment_variable_read_by_the_server_is_enumerated(self):
        self.assertIn("env:BANKFEED_OP_VAULT", self.items)

    def test_an_environment_variable_declared_only_in_the_mcp_manifest_is_enumerated(self):
        """The declaration side of the contract: what casa is asked to pass in."""
        declared = ledger.enumerate_env(ROOT)
        self.assertIn("env:OP_SERVICE_ACCOUNT_TOKEN", declared)

    def test_a_skill_is_enumerated(self):
        self.assertIn("skill:plugins/bank-feed/skills/bank-accounts/SKILL.md", self.items)

    def test_the_config_schema_and_its_secrets_are_enumerated(self):
        self.assertIn("config:secret_names", self.items)
        self.assertIn("secret:CASA_PLUGIN_BANKFEED_EB_PRIVATE_KEY", self.items)


class Synthetic(unittest.TestCase):
    """Shapes the enumerator must see whether or not this tree writes them today."""

    def tree(self, files):
        root = pathlib.Path(tempfile.mkdtemp())
        for rel, body in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
        return root

    def test_an_env_read_through_an_alias_is_enumerated(self):
        """`env = os.environ` then `env.get("X")`. The day someone writes this,
        a trimmed walker stops seeing X and the ledger still reports green."""
        root = self.tree({"plugins/p/server/t.py":
                          "import os\n\n\ndef f():\n    env = os.environ\n"
                          "    return env.get('ALIASED')\n"})
        self.assertIn("env:ALIASED", ledger.enumerate_env(root))

    def test_an_env_read_through_a_module_constant_is_enumerated(self):
        root = self.tree({"plugins/p/server/t.py":
                          "import os\nVAULT_ENV = 'VIA_CONSTANT'\n"
                          "V = os.environ.get(VAULT_ENV)\n"})
        self.assertIn("env:VIA_CONSTANT", ledger.enumerate_env(root))

    def test_a_subscript_read_is_enumerated(self):
        root = self.tree({"plugins/p/server/t.py": "import os\nV = os.environ['SUBSCRIPT']\n"})
        self.assertIn("env:SUBSCRIPT", ledger.enumerate_env(root))

    def test_a_decoy_environ_attribute_is_not_enumerated(self):
        root = self.tree({"plugins/p/server/t.py":
                          "V = fake.environ.get('DECOY')\n"})
        self.assertEqual(ledger.enumerate_env(root), [])

    # --- the demonstrated bypasses -----------------------------------------
    #
    # Each of these was a real hole: the enumerator returned nothing for the
    # shape and `check` exited 0, so the corpus's completeness claim was false
    # and a new surface could ship behind a green gate.

    def test_a_module_nested_under_server_is_enumerated(self):
        root = self.tree({"plugins/p/server/pkg/m.py": "x = 1\n"})
        self.assertEqual(ledger.enumerate_modules(root), ["plugins/p/server/pkg/m.py"])

    def test_a_skill_in_a_grouping_directory_is_enumerated(self):
        root = self.tree({"plugins/p/skills/group/name/SKILL.md": "# S\n"})
        self.assertEqual(ledger.enumerate_skills(root),
                         ["skill:plugins/p/skills/group/name/SKILL.md"])

    def test_a_protected_tool_declared_as_a_bare_string_is_enumerated(self):
        """casa accepts both forms; reading only the one this tree uses would
        let the other ship unledgered."""
        root = self.tree({"plugins/p/.claude-plugin/plugin.json":
                          '{"casa": {"protectedTools": ["erase", {"name": "wipe"}]}}'})
        self.assertEqual(ledger.enumerate_protected_tools(root),
                         ["protected:erase", "protected:wipe"])

    def test_an_env_read_through_an_ordinarily_named_wrapper_is_enumerated(self):
        """The wrapper is recognised by SHAPE -- it forwards its own parameter
        into an environment read -- not by a naming convention it might not
        follow."""
        root = self.tree({"plugins/p/server/m.py":
                          "import os\n\n\ndef read_env(name):\n"
                          "    return os.environ.get(name)\n\n\n"
                          'V = read_env("HIDDEN_ENV")\n'})
        self.assertIn("env:HIDDEN_ENV", ledger.enumerate_env(root))

    def test_an_env_read_through_an_imported_getenv_is_enumerated(self):
        root = self.tree({"plugins/p/server/m.py":
                          "from os import getenv as env\n"
                          'V = env("IMPORTED_GETENV")\n'})
        self.assertIn("env:IMPORTED_GETENV", ledger.enumerate_env(root))

    def test_an_env_read_through_an_imported_environ_is_enumerated(self):
        root = self.tree({"plugins/p/server/m.py":
                          "from os import environ\n"
                          'V = environ["IMPORTED_ENVIRON"]\n'
                          'W = environ.get("IMPORTED_GET")\n'})
        found = ledger.enumerate_env(root)
        self.assertIn("env:IMPORTED_ENVIRON", found)
        self.assertIn("env:IMPORTED_GET", found)

    def test_a_setup_provided_declaration_is_enumerated(self):
        """A third side of the environment contract: the name casa RESERVES,
        which is not the name the server reads."""
        root = self.tree({"plugins/p/.claude-plugin/plugin.json":
                          '{"casa": {"setupProvides": ["CASA_PLUGIN_X"]}}'})
        self.assertEqual(ledger.enumerate_declared_env(root),
                         ["declared:CASA_PLUGIN_X"])

    def test_a_script_is_enumerated(self):
        root = self.tree({"scripts/gate.py": "x = 1\n",
                          "scripts/exceptions.txt": "# none\n"})
        self.assertEqual(ledger.enumerate_scripts(root),
                         ["script:scripts/exceptions.txt", "script:scripts/gate.py"])

    # --- the sibling shapes -------------------------------------------------
    #
    # Every one of these is one step to the side of a bypass that was already
    # fixed. A fix keyed to the reproduction rather than to the shape leaves the
    # gate exactly as green as it was, now with a passing test beside it.

    def test_a_script_nested_below_scripts_is_enumerated(self):
        root = self.tree({"scripts/nested/gate.py": "x = 1\n"})
        self.assertEqual(ledger.enumerate_scripts(root),
                         ["script:scripts/nested/gate.py"])

    def test_a_wrapper_called_with_a_keyword_argument_is_enumerated(self):
        root = self.tree({"plugins/p/server/m.py":
                          "import os\n\n\ndef read_env(name):\n"
                          "    return os.environ.get(name)\n\n\n"
                          'V = read_env(name="KEYWORD_HIDDEN")\n'})
        self.assertIn("env:KEYWORD_HIDDEN", ledger.enumerate_env(root))

    def test_a_chain_of_wrappers_is_resolved_to_a_fixed_point(self):
        root = self.tree({"plugins/p/server/m.py":
                          "import os\n\n\ndef direct(k):\n    return os.getenv(k)\n\n\n"
                          "def read(k):\n    return direct(k)\n\n\n"
                          'V = read("CHAINED")\n'})
        self.assertIn("env:CHAINED", ledger.enumerate_env(root))

    def test_a_keyword_only_wrapper_parameter_is_resolved(self):
        root = self.tree({"plugins/p/server/m.py":
                          "import os\n\n\ndef read(*, name):\n"
                          "    return os.environ.get(name)\n\n\n"
                          'V = read(name="KWONLY")\n'})
        self.assertIn("env:KWONLY", ledger.enumerate_env(root))

    def test_getenv_called_with_its_keyword_is_enumerated(self):
        root = self.tree({"plugins/p/server/m.py":
                          'import os\nV = os.getenv(key="KEYWORD_GETENV")\n'})
        self.assertIn("env:KEYWORD_GETENV", ledger.enumerate_env(root))

    def test_a_parameter_shadowing_an_environ_alias_is_not_the_environment(self):
        """The other direction again: `def read(environ)` binds an ordinary
        mapping, and enumerating what it is asked for would put a request field
        in the environment contract."""
        root = self.tree({"plugins/p/server/m.py":
                          "from os import environ\n\n\ndef read(environ):\n"
                          '    return environ.get("REQUEST_FIELD")\n'})
        self.assertNotIn("env:REQUEST_FIELD", ledger.enumerate_env(root))

    def test_a_parameter_defaulted_to_an_imported_environ_alias_counts(self):
        """`from os import environ` then `def read(env=environ)`. The add-back
        after shadowing knew only the `os.environ` spelling."""
        root = self.tree({"plugins/p/server/m.py":
                          "from os import environ\n\n\ndef read(env=environ):\n"
                          '    return env.get("ALIAS_DEFAULTED")\n'})
        self.assertIn("env:ALIAS_DEFAULTED", ledger.enumerate_env(root))

    def test_a_shadowed_environ_parameter_does_not_make_a_wrapper(self):
        """Shadowing has to apply while DISCOVERING wrappers, not only while
        reading: otherwise `def field(environ, key)` is classified as an
        environment reader and every call to it enumerates a request field."""
        root = self.tree({"plugins/p/server/m.py":
                          "from os import environ\n\n\ndef field(environ, key):\n"
                          "    return environ.get(key)\n\n\n"
                          'V = field({}, "REQUEST_FIELD")\n'})
        self.assertNotIn("env:REQUEST_FIELD", ledger.enumerate_env(root))

    def test_a_local_rebind_shadows_an_imported_environ_alias(self):
        """`environ = {}` inside a function is that function's mapping. Shadowing by
        parameter alone was not enough -- an ordinary local rebind is commoner."""
        root = self.tree({"plugins/p/server/m.py":
                          "from os import environ\n\n\ndef request_field():\n"
                          "    environ = {}\n"
                          '    return environ.get("REQUEST_FIELD")\n'})
        self.assertNotIn("env:REQUEST_FIELD", ledger.enumerate_env(root))

    def test_a_local_rebind_shadows_an_imported_getenv_alias(self):
        root = self.tree({"plugins/p/server/m.py":
                          "from os import getenv\n\n\ndef request_field(row):\n"
                          "    getenv = row.get\n"
                          '    return getenv("REQUEST_FIELD")\n'})
        self.assertNotIn("env:REQUEST_FIELD", ledger.enumerate_env(root))

    def test_an_annotated_environ_alias_is_still_the_environment(self):
        """`env: object = os.environ` binds the same thing as the unannotated form."""
        root = self.tree({"plugins/p/server/m.py":
                          "import os\nenv: object = os.environ\n"
                          'V = env.get("ANNOTATED_ENV")\n'})
        self.assertIn("env:ANNOTATED_ENV", ledger.enumerate_env(root))

    def test_a_read_through_an_aliased_os_import_is_enumerated(self):
        """`import os as system`. Recognising the literal name `os` was the last
        spelling the environment arm enumerated."""
        root = self.tree({"plugins/p/server/m.py":
                          "import os as system\n"
                          'V = system.environ.get("OS_IMPORT_ALIAS")\n'})
        self.assertIn("env:OS_IMPORT_ALIAS", ledger.enumerate_env(root))

    def test_a_parameter_named_os_shadows_the_module(self):
        """The other direction: `def f(os)` binds a parameter, not the stdlib."""
        root = self.tree({"plugins/p/server/m.py":
                          "import os\n\n\ndef request_field(os):\n"
                          '    return os.environ.get("REQUEST_FIELD")\n'})
        self.assertNotIn("env:REQUEST_FIELD", ledger.enumerate_env(root))

    def test_a_read_through_pop_is_enumerated(self):
        """Any method on a proven environment mapping reads it. Listing `get`,
        `getenv` and subscript was one more enumeration of spellings."""
        root = self.tree({"plugins/p/server/m.py":
                          'import os\nos.environ.pop("POPPED_ENV", None)\n'
                          'os.environ.setdefault("DEFAULTED_ENV", "x")\n'})
        found = ledger.enumerate_env(root)
        self.assertIn("env:POPPED_ENV", found)
        self.assertIn("env:DEFAULTED_ENV", found)

    def test_a_parameter_defaulted_to_the_environment_still_counts(self):
        """...but shadowing must not swallow the honest case: a parameter whose
        DEFAULT is os.environ is the environment."""
        root = self.tree({"plugins/p/server/m.py":
                          "import os\n\n\ndef read(env=os.environ):\n"
                          '    return env.get("DEFAULTED")\n'})
        self.assertIn("env:DEFAULTED", ledger.enumerate_env(root))

    def test_a_binding_in_one_function_does_not_leak_into_another(self):
        root = self.tree({"plugins/p/server/t.py":
                          "import os\n\n\ndef a():\n    env = os.environ\n"
                          "    return env.get('REAL')\n\n\n"
                          "def b(env):\n    return env.get('NOT_AN_ENV_VAR')\n"})
        found = ledger.enumerate_env(root)
        self.assertIn("env:REAL", found)
        self.assertNotIn("env:NOT_AN_ENV_VAR", found)


class ToolRegistry(unittest.TestCase):
    """The tool surface is what the SERVER ANSWERS, not what its syntax suggests.

    Four review rounds found four generations of the same defect in the syntactic
    version, and a fifth in the version that read the registry by importing the
    server's modules: importing every file REIMPLEMENTED startup, so a tool the
    entrypoint registered itself was invisible and a module the entrypoint never
    imports could change what the gate read. These fixtures are therefore real
    servers, launched and asked `tools/list` over the protocol casa uses.
    """

    #: A minimal but genuine MCP server, shaped like the real one: a registry, a
    #: dispatcher that answers tools/list from it, and an entrypoint that imports
    #: its sibling modules before serving.
    ENTRY = textwrap.dedent("""
        import json, pathlib, sys
        TOOLS: dict = {}

        def STARTUP():
            pass

        def handle(req):
            if req.get("method") == "tools/list":
                return {"jsonrpc": "2.0", "id": req.get("id"),
                        "result": {"tools": [{"name": n} for n in sorted(TOOLS)]}}
            return {"jsonrpc": "2.0", "id": req.get("id"), "result": {}}

        def main():
            here = pathlib.Path(__file__).resolve().parent
            sys.path.insert(0, str(here))
            sys.modules.setdefault("srv", sys.modules[__name__])
            for name in IMPORTS:
                __import__(name)
            STARTUP()
            for line in sys.stdin:
                line = line.strip()
                if line:
                    print(json.dumps(handle(json.loads(line))), flush=True)

        if __name__ == "__main__":
            main()
    """)

    def server(self, modules, imports=("t",), startup="", entry="srv.py"):
        root = pathlib.Path(tempfile.mkdtemp())
        server = root / "plugins/p/server"
        server.mkdir(parents=True)
        # The launch command comes from the manifest, exactly as casa's does.
        (root / "plugins/p/.mcp.json").write_text(json.dumps({"mcpServers": {"p": {
            "command": sys.executable,
            "args": ["${CLAUDE_PLUGIN_ROOT}/server/" + entry],
        }}}))
        body = "IMPORTS = %r\n" % (list(imports),) + self.ENTRY
        if startup:
            # Redefined AFTER main is defined but BEFORE it runs, so the
            # registration happens during startup exactly as the entrypoint's own
            # code would do it.
            body += "\ndef STARTUP():\n    " + startup + "\n"
            body = body.replace('if __name__ == "__main__":\n    main()\n', "")
            body += '\nif __name__ == "__main__":\n    main()\n'
        (server / "srv.py").write_text(body)
        for name, body in modules.items():
            (server / name).write_text(body)
        return root

    def test_a_tool_registered_through_any_shape_at_all_is_enumerated(self):
        """Deliberately perverse: an alias of an alias of a module object, called
        with a keyword argument. Syntax cannot hide a tool from the server's own
        answer."""
        root = self.server({
            "reg.py": "import srv\n\n\ndef register(name):\n"
                      "    def deco(fn):\n        srv.TOOLS[name] = fn\n        return fn\n"
                      "    return deco\n",
            "t.py": "import reg as r\nregistry = r\nhook = registry.register\n\n\n"
                    '@hook(name="perverse")\ndef f():\n    pass\n',
        })
        self.assertEqual(ledger.enumerate_tools(root), ["tool:perverse"])

    def test_a_tool_the_entrypoint_registers_itself_is_enumerated(self):
        """The defect that killed the import-every-module approach: a registration
        performed by the entrypoint's own startup code, which no reimplementation
        of startup sees."""
        root = self.server({"t.py": "x = 1\n"},
                           startup='TOOLS["startup_only"] = None')
        self.assertEqual(ledger.enumerate_tools(root), ["tool:startup_only"])

    def test_a_module_the_entrypoint_does_not_import_cannot_change_the_answer(self):
        """The other half of it: importing a file the server never imports let an
        unrelated side effect rewrite the registry the gate then read."""
        root = self.server({
            "t.py": 'import srv\nsrv.TOOLS["real"] = None\n',
            "z_unused.py": "import srv\nsrv.TOOLS.clear()\n",
        })
        self.assertEqual(ledger.enumerate_tools(root), ["tool:real"])

    def test_a_commented_out_registration_is_not_a_tool(self):
        root = self.server({"t.py": 'import srv\n# srv.TOOLS["ghost"] = None\n'})
        self.assertEqual(ledger.enumerate_tools(root), [])

    def test_an_unrelated_registry_is_not_a_tool(self):
        """Somebody else's `register` decorator is not an MCP tool, and counting it
        would refuse honest code."""
        root = self.server({
            "metrics.py": "def register(name):\n"
                          "    def deco(fn):\n        return fn\n    return deco\n",
            # The decorator starts a source line of its own so that no single line here
            # reads as an address to the deny sweep -- a module name, an at-sign and a
            # dotted attribute have exactly that shape. The fixture is unchanged.
            "t.py": "import metrics\n\n\n"
                    '@metrics.register("latency")\n'
                    "def f():\n    pass\n",
        }, imports=("t",))
        self.assertEqual(ledger.enumerate_tools(root), [])

    def test_a_server_that_will_not_start_is_reported_not_swallowed(self):
        """"No tools" and "the server is broken" must not look the same to a gate."""
        root = self.server({"t.py": "raise RuntimeError('boom')\n"})
        found = ledger.enumerate_tools(root)
        self.assertTrue(found, "a broken server must produce an item")
        self.assertIn("exited", found[0])

    def test_a_server_that_does_not_answer_is_reported(self):
        root = self.server({"t.py": "x = 1\n"})
        (root / "plugins/p/server/srv.py").write_text(
            'TOOLS: dict = {}\nif __name__ == "__main__":\n    pass\n')
        found = ledger.enumerate_tools(root)
        self.assertTrue(found)
        self.assertIn("did not answer", found[0])

    def test_a_second_answer_cannot_hide_tools(self):
        """A server that answers correctly and then answers again with less used to
        have the last word."""
        root = self.server({"t.py": 'import srv\nsrv.TOOLS["real"] = None\n'},
                           startup='import json, sys; '
                                   'print(json.dumps({"jsonrpc": "2.0", "id": 2, '
                                   '"result": {"tools": []}}), flush=True)')
        found = ledger.enumerate_tools(root)
        self.assertTrue(any("answered tools/list" in f for f in found), found)

    def test_an_error_response_is_not_an_empty_tool_list(self):
        root = self.server({"t.py": "x = 1\n"})
        (root / "plugins/p/server/srv.py").write_text(
            "import json, sys\n"
            "for line in sys.stdin:\n"
            "    line = line.strip()\n"
            "    if line and json.loads(line).get('id') == 2:\n"
            "        print(json.dumps({'jsonrpc': '2.0', 'id': 2, "
            "'error': {'code': -1}}), flush=True)\n")
        found = ledger.enumerate_tools(root)
        self.assertTrue(any("with an error" in f for f in found), found)

    def test_the_command_comes_from_the_manifest_not_from_a_guess(self):
        """casa reads `.mcp.json`; a probe that picks a plausible file instead can
        inspect a different process from the one that serves."""
        root = self.server({"t.py": 'import srv\nsrv.TOOLS["live"] = None\n'},
                           entry="srv.py")
        (root / "plugins/p/server/decoy.py").write_text(
            "TOOLS: dict = {}\nif __name__ == '__main__':\n    pass\n")
        self.assertEqual(ledger.enumerate_tools(root), ["tool:live"])

    def test_a_server_module_with_no_declaration_is_not_probed(self):
        """casa launches what the manifest declares and nothing else. The fixture
        carries a perfectly launchable server module with NO `.mcp.json`, so a
        probe that guessed an entrypoint would find its tool and this one must
        not -- which is what distinguishes the two behaviours."""
        root = self.server({"t.py": 'import srv\nsrv.TOOLS["undeclared"] = None\n'})
        (root / "plugins/p/.mcp.json").unlink()
        self.assertEqual(ledger.enumerate_tools(root), [])

    def test_a_top_level_manifest_shape_is_read_too(self):
        """casa accepts the wrapper AND the top-level map real plugins use; reading
        only the wrapper let a legal declaration go unprobed."""
        root = self.server({"t.py": 'import srv\nsrv.TOOLS["top_level"] = None\n'})
        (root / "plugins/p/.mcp.json").write_text(json.dumps({"p": {
            "command": sys.executable,
            "args": ["${CLAUDE_PLUGIN_ROOT}/server/srv.py"],
        }}))
        self.assertEqual(ledger.enumerate_tools(root), ["tool:top_level"])

    def test_a_remote_server_is_reported_rather_than_passed_over(self):
        root = self.server({"t.py": "x = 1\n"})
        (root / "plugins/p/.mcp.json").write_text(json.dumps({"mcpServers": {
            "remote": {"url": "https://example.test/mcp"}}}))
        found = ledger.enumerate_tools(root)
        self.assertTrue(any("cannot be probed" in f for f in found), found)

    def test_a_response_without_a_jsonrpc_envelope_is_refused(self):
        self.assertIn("JSON-RPC envelope",
                      ledger._listed_tools('{"id": 2, "result": {"tools": []}}'))

    def test_a_malformed_result_is_an_item_not_a_crash(self):
        self.assertIn("without a tool list", ledger._listed_tools(
            '{"jsonrpc": "2.0", "id": 2, "result": "malformed"}'))

    def test_a_declared_command_that_cannot_run_is_reported(self):
        root = self.server({"t.py": "x = 1\n"}, entry="missing.py")
        found = ledger.enumerate_tools(root)
        self.assertTrue(found)
        self.assertTrue(any("exited" in f or "did not run" in f for f in found), found)


class Check(unittest.TestCase):
    """The bidirectional match, on a synthetic tree so the assertions are exact."""

    def build(self, ledger_yaml, manifest_yaml="- doc: architecture/x.md\n  summary: s\n"):
        root = pathlib.Path(tempfile.mkdtemp())
        (root / "plugins/p/server").mkdir(parents=True)
        # A real, empty entrypoint so the tool arm enumerates cleanly (zero tools)
        # rather than reporting a server it could not reach.
        (root / "plugins/p/server/m.py").write_text(
            'import json, sys\nTOOLS: dict = {}\n'
            'def main():\n'
            '    for line in sys.stdin:\n'
            '        line = line.strip()\n'
            '        if not line:\n            continue\n'
            '        req = json.loads(line)\n'
            '        out = {"jsonrpc": "2.0", "id": req.get("id"), "result": {}}\n'
            '        if req.get("method") == "tools/list":\n'
            '            out["result"] = {"tools": []}\n'
            '        sys.stdout.write(json.dumps(out) + "\\n")\n'
            '        sys.stdout.flush()\n'
            'if __name__ == "__main__":\n    main()\n')
        (root / "docs").mkdir()
        (root / "docs/manifest.yaml").write_text(manifest_yaml)
        (root / "docs/coverage.yaml").write_text(ledger_yaml)
        return root

    def test_a_clean_ledger_passes(self):
        root = self.build("- item: plugins/p/server/m.py\n  doc: architecture/x.md\n")
        self.assertEqual(ledger.check(root), [])

    def test_an_item_in_the_code_but_not_the_ledger_is_refused(self):
        root = self.build("[]\n")
        problems = ledger.check(root)
        self.assertTrue(any("m.py" in p and "not in docs/coverage.yaml" in p
                            for p in problems), problems)

    def test_an_item_in_the_ledger_but_not_the_code_is_refused(self):
        root = self.build(
            "- item: plugins/p/server/m.py\n  doc: architecture/x.md\n"
            "- item: plugins/p/server/gone.py\n  doc: architecture/x.md\n")
        self.assertTrue(any("gone.py" in p and "no longer enumerated" in p
                            for p in ledger.check(root)))

    def test_an_entry_with_both_a_doc_and_an_exclusion_is_refused(self):
        root = self.build(
            "- item: plugins/p/server/m.py\n  doc: architecture/x.md\n  excluded: because\n")
        self.assertTrue(any("exactly one" in p for p in ledger.check(root)))

    def test_an_entry_with_neither_is_refused(self):
        root = self.build("- item: plugins/p/server/m.py\n")
        self.assertTrue(any("exactly one" in p for p in ledger.check(root)))

    def test_an_exclusion_without_a_reason_is_refused(self):
        root = self.build("- item: plugins/p/server/m.py\n  excluded: '   '\n")
        self.assertTrue(any("without a reason" in p for p in ledger.check(root)))

    def test_a_doc_the_manifest_does_not_know_is_refused(self):
        root = self.build("- item: plugins/p/server/m.py\n  doc: architecture/ghost.md\n")
        self.assertTrue(any("not in the manifest" in p for p in ledger.check(root)))

    def test_a_duplicate_item_is_refused(self):
        root = self.build(
            "- item: plugins/p/server/m.py\n  doc: architecture/x.md\n"
            "- item: plugins/p/server/m.py\n  doc: architecture/x.md\n")
        self.assertTrue(any("listed twice" in p for p in ledger.check(root)))

    def test_a_missing_ledger_is_a_finding_not_a_traceback(self):
        root = self.build("[]\n")
        (root / "docs/coverage.yaml").unlink()
        self.assertTrue(any("missing" in p for p in ledger.check(root)))

    def test_malformed_yaml_is_a_finding_not_a_traceback(self):
        root = self.build("- item: [unclosed\n")
        self.assertTrue(any("not valid YAML" in p for p in ledger.check(root)))


if __name__ == "__main__":
    unittest.main()
