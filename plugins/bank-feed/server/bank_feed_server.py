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

import backups
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
        #
        # A `capability` tool (casa's result contract, see `register`) has one
        # success shape: a dict, sent as ONE JSON object, because casa parses
        # the whole result text as JSON and checks the reference in it. Its
        # banner therefore goes INSIDE the object, into its `text` field, and
        # never in front of it. Anything else such a tool produces (a refusal
        # it returns as prose, or an exception) is an MCP tool error: casa
        # passes an error's text to the model unchanged, whereas a non-error
        # result without the reference would be withheld as a broken plugin.
        try:
            sandbox = ebmode.is_sandbox()
        except ebmode.ModeError as exc:
            payload = {"content": [{"type": "text", "text": str(exc)}]}
            if tool.get("capability"):
                payload["isError"] = True
            return _result(id_, payload)
        # (5) What settlement wrote during this call, in ONE sentence after
        # the banner (issues #48, #53). Settlement records each write into
        # a log that lives exactly as long as this call — including the
        # open-time pass inside the first `tools_read.conn()`, which has no
        # reply of its own — and this is the only place that log is
        # rendered: on success, refusal and exception alike.
        token = backups.open_log()
        try:
            try:
                store.check_mode_marker(os.environ.get("CLAUDE_PLUGIN_DATA"))
                out = tool["fn"](params.get("arguments") or {})
            except Exception as exc:                   # surfaced, never swallowed
                # A capability tool's link exists as bytes on its own path,
                # and a stdlib parser quotes the bytes it chokes on (a status
                # line, a redirect host). So its exception text is rendered
                # only for the types it declares as speaking in its own words
                # (`register`).
                if tool.get("capability") and not isinstance(
                        exc, tool.get("error_text_types") or ()):
                    out = f"error: {type(exc).__name__}"
                else:
                    out = f"error: {type(exc).__name__}: {exc}"
        finally:
            settled = backups.close_log(token)
        head = "\n".join(p for p in (SANDBOX_BANNER if sandbox else "",
                                     settled) if p)
        if isinstance(out, dict):
            if head:
                out = dict(out, text=head + "\n" + str(out.get("text") or ""))
            payload = {"content": [{"type": "text", "text": json.dumps(out)}]}
        else:
            text = head + "\n" + out if head else out
            payload = {"content": [{"type": "text", "text": text}]}
            if tool.get("capability"):
                payload["isError"] = True
        return _result(id_, payload)
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
                 "tools_rules", "tools_backup"):
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
