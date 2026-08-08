#!/usr/bin/env python3
# plugins/bank-feed/server/bank_feed_server.py
"""casa bank-feed MCP server. Stdlib-only stdio JSON-RPC.

bank_feed_server.py only dispatches; every behaviour lives in a focused module
(money.py, jwtsign.py, httpx.py, eb_ais.py, eb_admin.py, store.py,
provenance.py, ingest.py, callbacks.py, apply.py, flows.py, tools_read.py,
tools_auth.py, tools_refresh.py, tools_destructive.py) that is testable
without a running MCP session.
"""
from __future__ import annotations
import importlib.util, json, os, sys

import ebmode
import store

TOOLS: dict = {}          # name -> {"description": str, "schema": {...}, "fn": callable}
PROTOCOL_VERSION = "2024-11-05"

#: Static literal on purpose: the banner interpolates nothing, so there is
#: nothing to neutralise.
SANDBOX_BANNER = ("[SANDBOX] Disposable test world — sandbox application, "
                  "sandbox vault items, sandbox ledger. No real money.")


def _result(id_, payload):
    return {"jsonrpc": "2.0", "id": id_, "result": payload}


def _error(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def handle(req: dict) -> dict | None:
    method, id_ = req.get("method"), req.get("id")
    if method == "initialize":
        return _result(id_, {"protocolVersion": PROTOCOL_VERSION,
                             "capabilities": {"tools": {}},
                             "serverInfo": {"name": "bank-feed", "version": "0.1.0"}})
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _result(id_, {"tools": [
            {"name": n, "description": t["description"], "inputSchema": t["schema"]}
            for n, t in sorted(TOOLS.items())]})
    if method == "tools/call":
        params = req.get("params") or {}
        tool = TOOLS.get(params.get("name"))
        if tool is None:
            return _error(id_, -32601, f"unknown tool {params.get('name')!r}")
        # In this exact order. (1) The mode: an unrecognised
        # BANKFEED_EB_ENVIRONMENT refuses EVERY tool uniformly — never a silent
        # fall-back to the real-money world — and the refusal is unbannered
        # because with an unparseable mode there is no truthful banner to
        # print. (2) The install marker, BEFORE the tool body: the flip refusal
        # must fire before setup_bank_feed can touch vault state, and its
        # StoreError rides the existing error rendering below. (3) The tool.
        # (4) The banner, over success AND error alike — a wrapper inside
        # register() would never see the rendered exception, which is why the
        # banner lives here at the dispatcher.
        try:
            sandbox = ebmode.is_sandbox()
        except ebmode.ModeError as exc:
            return _result(id_, {"content": [{"type": "text",
                                              "text": str(exc)}]})
        try:
            store.check_mode_marker(os.environ.get("CLAUDE_PLUGIN_DATA"))
            text = tool["fn"](params.get("arguments") or {})
        except Exception as exc:                       # surfaced, never swallowed
            text = f"error: {type(exc).__name__}: {exc}"
        if sandbox:
            text = SANDBOX_BANNER + "\n" + text
        return _result(id_, {"content": [{"type": "text", "text": text}]})
    return _error(id_, -32601, f"unknown method {method!r}")


def main() -> None:
    # When this file is launched as a script (the real deployment), Python
    # loads it as module "__main__" -- NOT as "bank_feed_server". tools_read.py,
    # tools_auth.py, tools_refresh.py and tools_destructive.py all
    # do `import bank_feed_server` to reach the shared TOOLS dict; without the
    # alias below that import would execute THIS SAME FILE a second time
    # under the distinct module name "bank_feed_server", handing them an empty
    # TOOLS dict of their own while handle() above keeps reading the
    # __main__ one. The live process would then answer tools/list with an
    # empty registry regardless of what those four modules registered.
    # Aliasing sys.modules first makes both names resolve to the one module
    # object that is actually running, so registration lands in the dict
    # handle() reads.
    sys.modules.setdefault("bank_feed_server", sys.modules[__name__])
    # Fail closed on a broken module, fail open only on a MISSING one
    # -- find_spec() only locates a module on sys.path, and never executes
    # it, so a module that genuinely does not exist yet returns None here and is
    # the ONE case this loop may skip. Once a module IS findable, __import__
    # runs with no except around it: any exception raised while running
    # it -- including a real ImportError the module itself trips over --
    # propagates out of main() and kills the process. A live MCP server
    # that answers tools/list with fewer tools than the manifest declares,
    # silently and with nothing to point at, is strictly worse than a dead
    # process with a traceback: the crash is loud, the partial registry
    # was not.
    for _mod in ("tools_read", "tools_auth", "tools_refresh",
                 "tools_destructive", "tools_annotate", "tools_aggregate",
                 "tools_rules"):
        if importlib.util.find_spec(_mod) is None:
            continue                                     # not shipped yet -- acceptable
        __import__(_mod)                                 # populates TOOLS; any failure here is fatal
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
