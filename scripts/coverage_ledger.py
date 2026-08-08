#!/usr/bin/env python3
"""The code-derived coverage ledger.

The corpus can only claim completeness against a surface list that comes from the code
itself — a hand-maintained list rots the day after it is written. This script enumerates,
mechanically:

* every ``.py`` under ``plugins/*/server/`` (no size floor),
* every MCP tool, read from the registry the server builds when it starts — not
  inferred from decorator syntax; see ``enumerate_tools``,
* every protected tool declared in a plugin's ``.claude-plugin/plugin.json``, in either
  form casa accepts,
* every entry of ``role/role.yaml``'s ``tools.allowed`` list,
* every name in ``casa.setupProvides``,
* every environment variable the server code reads by literal name, and every variable
  a plugin's ``.mcp.json`` declares,
* every skill (``SKILL.md`` at any depth under a plugin's ``skills/``),
* every file under ``scripts/``,
* every key of ``config-schema.json`` and every secret it names.

``docs/coverage.yaml`` must map every enumerated item to the corpus document that covers
it, or exclude it with a one-line reason. The check is bidirectional, like the manifest:
an enumerated item absent from the ledger fails, a ledger item no longer enumerated
fails, and a ``doc:`` the manifest does not know fails.

Usage:
    python3 scripts/coverage_ledger.py enumerate [repo_root]
    python3 scripts/coverage_ledger.py check [repo_root]
"""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

PLUGINS_ROOT = "plugins"
SCRIPTS_ROOT = "scripts"
PLUGIN_MANIFEST = ".claude-plugin/plugin.json"
MCP_MANIFEST = ".mcp.json"
ROLE_YAML = "role/role.yaml"
CONFIG_SCHEMA = "config-schema.json"
#: Every module counts. A size floor is how small modules become invisible to a
#: ledger, and small is not the same as uninteresting — `money.py` is 49 lines
#: and owns every rounding decision in the ledger.
MIN_MODULE_LINES = 0


def _plugin_dirs(repo_root: Path) -> list[Path]:
    root = repo_root / PLUGINS_ROOT
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir())


def _server_modules(repo_root: Path) -> list[Path]:
    """Every `.py` beneath any plugin's `server/`, at ANY depth.

    Recursive, not one level: an exact-depth glob stops seeing a module the
    moment someone makes a package out of part of the server, and a ledger that
    stops enumerating reports green.
    """
    out: list[Path] = []
    for plugin in _plugin_dirs(repo_root):
        out.extend((plugin / "server").rglob("*.py"))
    return sorted(p for p in out if "__pycache__" not in p.parts)


def _read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def enumerate_modules(repo_root: Path) -> list[str]:
    out = []
    for path in _server_modules(repo_root):
        try:
            loc = len(path.read_text(errors="replace").splitlines())
        except OSError:
            continue
        if loc >= MIN_MODULE_LINES:
            out.append(str(path.relative_to(repo_root)))
    return out


#: Ask the running server what tools it serves, over the protocol casa uses, having
#: launched it with the command casa launches.
#:
#: Four review rounds found four generations of the same defect while this was
#: syntactic — each fix recognised the demonstrated spelling and the next round found
#: its neighbour. Reading the registry by importing the server's modules was the same
#: mistake one level up: it REIMPLEMENTED startup, so a tool the entrypoint registered
#: itself was invisible and a module the entrypoint never imports could change what the
#: gate read. Choosing the entrypoint structurally was that mistake once more: casa does
#: not guess which file is the server, it reads `.mcp.json`, and a probe inspecting a
#: different process from casa is authoritative-looking and wrong.
#:
#: So every step here comes from the contract rather than from inference: the command
#: from `.mcp.json`, the answer from `tools/list`.
_INITIALIZE = '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}'
_LIST = '{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}'
_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(text: str, plugin: Path, data: str) -> str:
    """casa's `.mcp.json` interpolation: `${VAR}` and `${VAR:-default}`, plus the two
    paths casa itself supplies."""
    supplied = {"CLAUDE_PLUGIN_ROOT": str(plugin), "CLAUDE_PLUGIN_DATA": data}

    def one(match: "re.Match") -> str:
        name, default = match.group(1), match.group(2)
        if name in supplied:
            return supplied[name]
        return os.environ.get(name, default if default is not None else "")

    return _REFERENCE.sub(one, text)


def _mcp_servers(plugin: Path) -> dict:
    """Every server a plugin's `.mcp.json` declares, in BOTH shapes casa accepts:
    the `{"mcpServers": {…}}` wrapper, and the top-level map real plugins use.

    Reading only the wrapper meant a legal manifest declared a server this gate
    never saw, and its tools went through green. A server is one whose config
    carries a launch field — a `command` or a `url`; `args` and `env` alone do not
    make one, which is casa's rule too.
    """
    data = _read_json(plugin / MCP_MANIFEST)
    if not isinstance(data, dict):
        return {}
    wrapped = data.get("mcpServers")
    candidates = wrapped if isinstance(wrapped, dict) else {
        name: config for name, config in data.items() if name != "mcpServers"
    }
    return {
        name: config for name, config in candidates.items()
        if isinstance(config, dict)
        and (isinstance(config.get("command"), str)
             or isinstance(config.get("url"), str))
    }


def _declared_servers(plugin: Path, data: str) -> list[tuple[str, list[str], dict]]:
    """`(name, argv, env)` for every stdio server the plugin declares. A server with
    no `command` is remote and cannot be probed; `enumerate_tools` reports it rather
    than passing over it."""
    out = []
    for name, config in _mcp_servers(plugin).items():
        if not isinstance(config.get("command"), str):
            out.append((name, [], {}))
            continue
        argv = [_expand(config["command"], plugin, data)]
        argv += [_expand(a, plugin, data)
                 for a in (config.get("args") or []) if isinstance(a, str)]
        env = {k: _expand(v, plugin, data)
               for k, v in (config.get("env") or {}).items() if isinstance(v, str)}
        out.append((name, argv, env))
    return out


def _listed_tools(stdout: str) -> "list | str":
    """The tools from a `tools/list` response, or a string saying what was wrong.

    Exactly one well-formed response for the request id, and no error envelope. A
    second response used to overwrite the first, so a server that answered correctly
    and then answered again with less could hide tools behind a green gate.
    """
    answers = []
    for line in stdout.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if isinstance(message, dict) and message.get("id") == 2:
            answers.append(message)
    if not answers:
        return "did not answer tools/list"
    if len(answers) > 1:
        return f"answered tools/list {len(answers)} times"
    answer = answers[0]
    if answer.get("jsonrpc") != "2.0":
        return "answered tools/list without a JSON-RPC envelope"
    if "error" in answer:
        return f"answered tools/list with an error: {answer['error']}"
    result = answer.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        return "answered tools/list without a tool list"
    return result["tools"]


def enumerate_tools(repo_root: Path) -> list[str]:
    """Every MCP tool, as the server itself reports them.

    Launches each server a plugin's `.mcp.json` declares, with that manifest's own
    command and environment, and asks `tools/list`. Anything that goes wrong — will not
    start, will not answer, answers twice, answers with an error — is reported as an
    item rather than swallowed: "no tools" and "the server is broken" must not look the
    same to a gate, and only one of them may be green.
    """
    found: set[str] = set()
    for plugin in _plugin_dirs(repo_root):
        with tempfile.TemporaryDirectory() as data:
            for name, argv, declared in _declared_servers(plugin, data):
                if not argv:
                    found.add(f"tool:<{plugin.name}/{name} declares no command; a "
                              f"remote server cannot be probed from here>")
                    continue
                env = dict(os.environ, **declared)
                env.setdefault("CLAUDE_PLUGIN_DATA", data)
                env.setdefault("CLAUDE_PLUGIN_ROOT", str(plugin))
                env["CLAUDE_PLUGIN_DATA"] = env["CLAUDE_PLUGIN_DATA"] or data
                label = f"{plugin.name}/{name}"
                try:
                    result = subprocess.run(
                        argv, input=f"{_INITIALIZE}\n{_LIST}\n",
                        capture_output=True, text=True, env=env, timeout=120,
                        cwd=str(plugin),
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    found.add(f"tool:<{label} did not run: {type(exc).__name__}>")
                    continue
                if result.returncode != 0:
                    tail = (result.stderr or "").strip().splitlines()
                    found.add(f"tool:<{label} exited {result.returncode}: "
                              f"{tail[-1] if tail else 'no error output'}>")
                    continue
                listed = _listed_tools(result.stdout)
                if isinstance(listed, str):
                    found.add(f"tool:<{label} {listed}>")
                    continue
                for tool in listed:
                    tool_name = tool.get("name") if isinstance(tool, dict) else None
                    found.add(f"tool:{tool_name}"
                              if isinstance(tool_name, str) and tool_name
                              else f"tool:<{label} listed a nameless tool>")
    return sorted(found)


def enumerate_protected_tools(repo_root: Path) -> list[str]:
    """The tools casa gates behind an operator confirmation.

    Enumerated separately from `tool:` because being protected is its own
    contract — the summary shown to the operator is part of the plugin
    manifest, and a tool silently losing its protection is exactly the change
    a reader of the docs would want to have been told about.

    BOTH declaration forms casa accepts: an object with a `name` (and the
    operator-facing `summary` this repository uses), and a bare string. Reading
    only the form this tree happens to use today would let the other one ship
    unledgered.
    """
    found: set[str] = set()
    for plugin in _plugin_dirs(repo_root):
        data = _read_json(plugin / PLUGIN_MANIFEST) or {}
        for entry in (data.get("casa") or {}).get("protectedTools") or []:
            if isinstance(entry, str) and entry:
                found.add(f"protected:{entry}")
            elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
                found.add(f"protected:{entry['name']}")
    return sorted(found)


def enumerate_role_tools(repo_root: Path) -> list[str]:
    """`role/role.yaml`'s allow-list: what the specialist may actually call.

    A tool the server registers but the role does not allow is unreachable, and
    a role entry naming a tool nothing registers is a typo that fails silently
    at runtime. Both are visible only if both lists are enumerated.
    """
    try:
        data = yaml.safe_load((repo_root / ROLE_YAML).read_text()) or {}
    except (OSError, yaml.YAMLError):
        return []
    allowed = ((data.get("tools") or {}).get("allowed")) or []
    return sorted(f"role:{name}" for name in allowed if isinstance(name, str))


def enumerate_skills(repo_root: Path) -> list[str]:
    """Every `SKILL.md` beneath a plugin's `skills/`, at any depth — a skill in
    a grouping directory is still shipped prose a model reads at runtime."""
    found: set[str] = set()
    for plugin in _plugin_dirs(repo_root):
        for path in (plugin / "skills").rglob("SKILL.md"):
            found.add(f"skill:{path.relative_to(repo_root)}")
    return sorted(found)


def enumerate_scripts(repo_root: Path) -> list[str]:
    """Every file beneath `scripts/`, at any depth. These are the gates a
    contributor runs, and their exception lists; each is a surface the corpus
    has to own or explain.

    Repo-relative, not a bare filename: two files of the same name in different
    subdirectories would otherwise collapse into one ledger entry, and one of
    them would be documented by accident.
    """
    root = repo_root / SCRIPTS_ROOT
    if not root.is_dir():
        return []
    return sorted(
        f"script:{p.relative_to(repo_root)}"
        for p in root.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    )


def enumerate_config(repo_root: Path) -> list[str]:
    data = _read_json(repo_root / CONFIG_SCHEMA)
    if not isinstance(data, dict):
        return []
    out = {f"config:{key}" for key in data}
    for name in data.get("secret_names") or []:
        if isinstance(name, str):
            out.add(f"secret:{name}")
    return sorted(out)


# --- environment variables --------------------------------------------------------------

def _walk_scope(scope: ast.AST):
    """Walk a scope's own statements WITHOUT descending into nested function
    definitions — each function is analysed as its own scope, so an inner
    binding must not leak outward and an inner read must not be judged by an
    outer scope's bindings."""
    stack = list(getattr(scope, "body", []))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # A nested function is its own scope: yield the definition node
            # itself but never its interior.
            yield node
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _os_aliases(tree: ast.Module) -> set[str]:
    """Local names bound to the `os` MODULE: `import os`, `import os as system`.

    Recognising the literal name `os` was the environment arm's last enumerated
    spelling — an ordinary alias made every read through it invisible.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    names.add(alias.asname or "os")
    return names


def _is_os_environ(node: ast.AST, os_names: set[str] = frozenset({"os"})) -> bool:
    """The ``<os>.environ`` attribute chain, through any binding of the os module —
    a decoy object whose attribute happens to be named ``environ`` must not
    enumerate."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "environ"
        and isinstance(node.value, ast.Name)
        and node.value.id in os_names
    )


def _param_names(node) -> list[str]:
    """Every parameter this function binds, in positional order first. Keyword-only
    parameters have no index but are still bindable by name."""
    args = node.args
    return (
        [a.arg for a in args.posonlyargs + args.args]
        + [a.arg for a in args.kwonlyargs]
    )


def _positional_params(node) -> list[str]:
    return [a.arg for a in node.args.posonlyargs + node.args.args]


def _assigned_names(target: ast.AST) -> set[str]:
    """Every plain name this assignment target binds, unpacking tuples and stars."""
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        found: set[str] = set()
        for element in target.elts:
            found |= _assigned_names(element)
        return found
    if isinstance(target, ast.Starred):
        return _assigned_names(target.value)
    return set()


def _scope_bindings(scope: ast.AST) -> set[str]:
    """Every name bound inside this scope's own statements: assignments (plain and
    annotated), imports, `for` targets, `with … as`, `except … as`, comprehension
    targets, and parameters.

    Needed because a binding SHADOWS an outer environment alias. `environ = {}`
    inside a function makes `environ.get("x")` an ordinary mapping read, and
    enumerating it puts a request field in the environment contract. Shadowing by
    parameter alone was not enough — an ordinary local rebind is the commoner shape.
    """
    found: set[str] = set()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        found |= set(_param_names(scope))
    for node in _walk_scope(scope):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                found |= _assigned_names(target)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            found |= _assigned_names(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            found |= _assigned_names(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    found |= _assigned_names(item.optional_vars)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            found.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                found.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.comprehension):
            found |= _assigned_names(node.target)
    return found


def _scope_env_names(scope: ast.AST, environ_names: set[str] = frozenset(),
                     os_names: set[str] = frozenset({"os"})) -> set[str]:
    """Names bound to the environment MAPPING within one scope: a parameter defaulted
    to it, a direct alias (`env = os.environ`, `env: object = os.environ`), or the
    self-referential rebind. Literal reads through such a name are env reads too.

    `raw = os.environ.get(…)` binds a VALUE, not the mapping, and is not tracked; nor
    does one function's `env` contaminate another's.
    """
    def is_environ(node: ast.AST) -> bool:
        return _is_os_environ(node, os_names) or (
            isinstance(node, ast.Name) and node.id in environ_names
        )

    found: set[str] = set()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = scope.args
        positional = args.posonlyargs + args.args
        for arg, default in zip(
            positional[len(positional) - len(args.defaults):], args.defaults
        ):
            if any(is_environ(n) for n in ast.walk(default)):
                found.add(arg.arg)
        for arg, default in zip(args.kwonlyargs, args.kw_defaults):
            if default is not None and any(is_environ(n) for n in ast.walk(default)):
                found.add(arg.arg)
    for node in _walk_scope(scope):
        # Annotated as well as plain: `env: object = os.environ` is the same binding,
        # and reading only one spelling is how the alias hid.
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        value_names = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
        is_alias = is_environ(value)
        for target in targets:
            for name in _assigned_names(target):
                if is_alias or (
                    name in value_names
                    and any(is_environ(n) for n in ast.walk(value))
                ):
                    found.add(name)
    return found


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` bindings, so a call site passing the
    CONSTANT (``os.environ.get(VAULT_ENV)``) rather than the literal is still
    enumerated. One level of indirection only — no re-assignment tracing."""
    out: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            out[node.targets[0].id] = node.value.value
    return out


def _getenv_aliases(tree: ast.Module) -> set[str]:
    """Local names bound to ``os.getenv``: ``from os import getenv`` and
    ``from os import getenv as env``. Without this an ordinary import spelling
    reads no environment variables as far as the ledger can tell."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                if alias.name == "getenv":
                    names.add(alias.asname or alias.name)
    return names


def _environ_aliases(tree: ast.Module) -> set[str]:
    """Local names bound to the ``os.environ`` MAPPING by import:
    ``from os import environ`` / ``… as env``."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                if alias.name == "environ":
                    names.add(alias.asname or alias.name)
    return names


def _bound_argument(call: ast.Call, param: str, positional: list[str]):
    """The AST node bound to `param` at this call site, by keyword or position.

    Binding by NAME as well as by index matters: `read_env(name="X")` is the same
    read as `read_env("X")`, and a fix that only understood one spelling would
    leave the other invisible — the exact shape review keeps finding.
    """
    for keyword in call.keywords:
        if keyword.arg == param:
            return keyword.value
    if param in positional:
        index = positional.index(param)
        if len(call.args) > index:
            return call.args[index]
    return None


def _env_wrappers(tree: ast.Module, environ_names: set[str],
                  getenv_names: set[str], os_names: set[str]) -> dict[str, str]:
    """Local functions that ARE environment readers: `{function: parameter}`.

    A function whose body reads the environment using one of its own parameters
    as the variable name is a wrapper, and a call to it with a literal is an
    environment read. Casa's original recognised one naming convention
    (`_env_*`); a helper called anything else was invisible, and the ledger
    reported green while an environment contract grew. This recognises the
    SHAPE instead of the name — which is the same reason the lineage gate keys
    its exceptions on sites rather than on phrases.

    Resolved to a FIXED POINT: a function forwarding its parameter into a
    known wrapper is itself a wrapper. Both spellings of the forward count,
    positional and keyword, because a fix that understands one and not the
    other leaves the sibling shape invisible.
    """
    wrappers: dict[str, str] = {}
    functions = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    def reads_env(call: ast.Call, local_env: set[str],
                  local_os: set[str]) -> "tuple[list[str], list[str]] | None":
        """(parameter names of the callee, positional order) if this call reads the
        environment by its first/`key` argument, else None."""
        func = call.func
        if isinstance(func, ast.Attribute):
            if _is_os_environ(func.value, local_os) or (
                isinstance(func.value, ast.Name) and func.value.id in local_env
            ):
                return (["key"], ["key"])
            if (func.attr == "getenv" and isinstance(func.value, ast.Name)
                    and func.value.id in local_os):
                return (["key"], ["key"])
        elif isinstance(func, ast.Name):
            if func.id in getenv_names:
                return (["key"], ["key"])
            if func.id in wrappers:
                target = wrappers[func.id]
                callee = next((f for f in functions if f.name == func.id), None)
                if callee is not None:
                    return ([target], _positional_params(callee))
        return None

    changed = True
    while changed:
        changed = False
        for node in functions:
            if node.name in wrappers:
                continue
            params = set(_param_names(node))
            if not params:
                continue
            # Lexical shadowing here too, not only in the read pass: `def
            # field(environ, key)` binds an ordinary mapping, and without this the
            # function is classified as an environment wrapper and every call to it
            # enumerates an unrelated field.
            bound = _scope_bindings(node)
            local_env = ((environ_names - bound)
                         | _scope_env_names(node, environ_names, os_names))
            # A parameter named `os` is that function's parameter, not the module.
            local_os = os_names - bound
            forwarded: str | None = None
            for inner in ast.walk(node):
                candidate = None
                if isinstance(inner, ast.Call):
                    reads = reads_env(inner, local_env, local_os)
                    if reads is not None:
                        param, positional = reads[0][0], reads[1]
                        candidate = _bound_argument(inner, param, positional)
                elif isinstance(inner, ast.Subscript) and (
                    _is_os_environ(inner.value, local_os)
                    or (isinstance(inner.value, ast.Name)
                        and inner.value.id in local_env)
                ):
                    candidate = inner.slice
                if isinstance(candidate, ast.Name) and candidate.id in params:
                    forwarded = candidate.id
                    break
            if forwarded is not None:
                wrappers[node.name] = forwarded
                changed = True
    return wrappers


def _env_reads_in_source(text: str) -> set[str]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set()
    names: set[str] = set()
    constants = _module_string_constants(tree)
    getenv_names = _getenv_aliases(tree)
    environ_names = _environ_aliases(tree)
    os_names = _os_aliases(tree)
    wrappers = _env_wrappers(tree, environ_names, getenv_names, os_names)

    def literal(arg: ast.AST) -> str | None:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
        if isinstance(arg, ast.Name) and arg.id in constants:
            return constants[arg.id]
        return None

    module_env = _scope_env_names(tree, environ_names, os_names) | environ_names
    functions = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    for scope in [tree] + functions:
        env_names = (module_env if scope is tree
                     else module_env | _scope_env_names(scope, environ_names,
                                                        os_names))
        if scope is not tree:
            # Lexical shadowing. A name bound inside this function -- a parameter,
            # a local rebind, an import, a loop variable -- is that function's
            # name, not the module's `os.environ` alias, and treating it as the
            # environment enumerates whatever an ordinary mapping is asked for. A
            # binding that IS the environment is added back afterwards.
            bound = _scope_bindings(scope)
            env_names = ((env_names - bound)
                         | _scope_env_names(scope, environ_names, os_names))
            local_getenv = getenv_names - bound
            local_os = os_names - bound
        else:
            local_getenv = getenv_names
            local_os = os_names

        def is_env_base(base: ast.AST, _names=env_names, _os=local_os) -> bool:
            return _is_os_environ(base, _os) or (
                isinstance(base, ast.Name) and base.id in _names
            )

        for node in _walk_scope(scope):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in wrappers:
                    callee = next((f for f in functions if f.name == func.id), None)
                    positional = _positional_params(callee) if callee else []
                    bound = _bound_argument(node, wrappers[func.id], positional)
                    name = literal(bound) if bound is not None else None
                    if name:
                        names.add(name)
                    continue
                # `key` is the parameter name in every environment-read signature
                # here (`os.getenv`, `Mapping.get`), so one binding rule covers
                # the positional and the keyword spelling alike.
                bound = _bound_argument(node, "key", ["key"])
                name = literal(bound) if bound is not None else None
                if not name:
                    continue
                if isinstance(func, ast.Attribute):
                    # ANY method on a proven environment mapping, not a list of
                    # method names: `.get`, `.pop` and `.setdefault` all read the
                    # variable, and the next one would have been invisible.
                    is_env_method = is_env_base(func.value)
                    is_getenv = (
                        func.attr == "getenv"
                        and isinstance(func.value, ast.Name)
                        and func.value.id in local_os
                    )
                    if is_env_method or is_getenv:
                        names.add(name)
                elif isinstance(func, ast.Name) and (
                    func.id.startswith("_env_") or func.id in local_getenv
                ):
                    # A local wrapper by the old naming convention, or a
                    # directly imported `getenv`.
                    names.add(name)
            elif isinstance(node, ast.Subscript) and is_env_base(node.value):
                name = literal(node.slice)
                if name:
                    names.add(name)
    return names


def enumerate_env(repo_root: Path) -> list[str]:
    """Both sides of the environment contract.

    The AST arm finds what the server READS. The `.mcp.json` arm finds what
    casa is asked to PASS IN. They are enumerated together because each catches
    what the other cannot: a variable declared and never read is a dead
    contract, and one read but never declared is a variable that is empty in
    every production install. Only the union tells the truth about the surface.
    """
    names: set[str] = set()
    for path in _server_modules(repo_root):
        try:
            names |= _env_reads_in_source(path.read_text(errors="replace"))
        except OSError:
            continue
    for plugin in _plugin_dirs(repo_root):
        for server in _mcp_servers(plugin).values():
            if isinstance(server.get("env"), dict):
                names |= set(server["env"])
    return [f"env:{name}" for name in sorted(names)]


def enumerate_declared_env(repo_root: Path) -> list[str]:
    """`casa.setupProvides` — the names casa RESERVES for this plugin because
    setup provisions their values.

    A third, separate side of the environment contract: a declared name is not
    the name the server reads (casa fences the declaration namespace behind its
    own prefix), so enumerating it under `env:` would claim the code reads a
    variable it never sees.
    """
    found: set[str] = set()
    for plugin in _plugin_dirs(repo_root):
        data = _read_json(plugin / PLUGIN_MANIFEST) or {}
        for name in (data.get("casa") or {}).get("setupProvides") or []:
            if isinstance(name, str) and name:
                found.add(f"declared:{name}")
    return sorted(found)


def enumerate_items(repo_root: Path) -> list[str]:
    return (
        enumerate_modules(repo_root)
        + enumerate_tools(repo_root)
        + enumerate_protected_tools(repo_root)
        + enumerate_role_tools(repo_root)
        + enumerate_env(repo_root)
        + enumerate_declared_env(repo_root)
        + enumerate_skills(repo_root)
        + enumerate_scripts(repo_root)
        + enumerate_config(repo_root)
    )


# --- the check ------------------------------------------------------------------------

def _load_ledger(repo_root: Path) -> tuple[list[dict], list[str]]:
    path = repo_root / "docs" / "coverage.yaml"
    try:
        raw = yaml.safe_load(path.read_text())
    except OSError:
        return [], ["docs/coverage.yaml is missing — the coverage ledger is mandatory"]
    except yaml.YAMLError as exc:
        return [], [f"docs/coverage.yaml is not valid YAML: {exc}"]
    if not isinstance(raw, list):
        return [], ["docs/coverage.yaml must be a list of entries"]
    entries, problems = [], []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict) or not isinstance(entry.get("item"), str):
            problems.append(f"coverage entry {index} is not a mapping with a string `item`")
            continue
        entries.append(entry)
    return entries, problems


def _manifest_docs(repo_root: Path) -> set[str]:
    docs_dir = repo_root / "docs"
    # Read the root manifest plus every docs/manifest.d/*.yaml shard, mirroring
    # verify_docs._manifest_files.
    sources = [docs_dir / "manifest.yaml"] + sorted((docs_dir / "manifest.d").glob("*.yaml"))
    out: set[str] = set()
    for source in sources:
        try:
            raw = yaml.safe_load(source.read_text())
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(raw, list):
            continue
        out |= {e["doc"] for e in raw if isinstance(e, dict) and isinstance(e.get("doc"), str)}
    return out


def check(repo_root: Path) -> list[str]:
    """Return every coverage problem. Empty list means every surface is accounted for."""
    entries, problems = _load_ledger(repo_root)
    if problems and not entries:
        return problems
    manifest = _manifest_docs(repo_root)
    enumerated = set(enumerate_items(repo_root))

    seen: set[str] = set()
    for entry in entries:
        item = entry["item"]
        if item in seen:
            problems.append(f"coverage: {item!r} is listed twice")
        seen.add(item)
        doc, excluded = entry.get("doc"), entry.get("excluded")
        if (doc is None) == (excluded is None):
            problems.append(
                f"coverage: {item!r} must carry exactly one of `doc` or `excluded`"
            )
            continue
        if doc is not None and doc not in manifest:
            problems.append(
                f"coverage: {item!r} is assigned to {doc!r}, which is not in the manifest"
            )
        if excluded is not None and (not isinstance(excluded, str) or not excluded.strip()):
            problems.append(
                f"coverage: {item!r} is excluded without a reason — every exclusion "
                f"states one"
            )

    for item in sorted(enumerated - seen):
        problems.append(
            f"coverage: {item!r} exists in the code but is not in docs/coverage.yaml — "
            f"assign it to a document or exclude it with a reason"
        )
    for item in sorted(seen - enumerated):
        problems.append(
            f"coverage: {item!r} is in the ledger but no longer enumerated from the "
            f"code — remove the stale entry"
        )
    return problems


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] not in ("enumerate", "check"):
        print(__doc__)
        return 2
    root = Path(args[1] if len(args) > 1 else ".").resolve()
    if args[0] == "enumerate":
        for item in enumerate_items(root):
            print(item)
        return 0
    problems = check(root)
    for problem in problems:
        print(f"✗ {problem}")
    if problems:
        print(f"\n{len(problems)} coverage problem(s).")
        return 1
    print("✓ coverage ledger verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
