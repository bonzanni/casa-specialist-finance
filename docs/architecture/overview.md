# Overview

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

This repository is one casa **specialist component**: a role, a persona, and two
bundled plugins, published as a single versioned bundle with pinned digests.

```
manifest.json          the component: version, persona, plugin dependencies, digests
config-schema.json     what the installer must supply, and which of it is secret
role/role.yaml         the specialist: model, tool allow-list, limits, launch gate
role/doctrine.md       the standing instructions the specialist runs under
persona/               the persona pack, checksummed independently
plugins/bank-feed/     an MCP server (Python 3.11 standard library only) + a skill
plugins/tx-classifier/ a skill, and nothing else
tests/                 the suite; unittest, not pytest
scripts/               the gates: identifier scan, lineage scan, docs verifier, ledger
docs/                  this corpus
```

## The two plugins, and why there are two

**`bank-feed`** is the substrate. It owns every durable thing: the SQLite ledger, the
provider credentials, the MCP tools, the rule engine, the annotation store. It is a
stdio JSON-RPC MCP server started by casa from `.mcp.json`, and it is deliberately
standard-library-only — casa's install-time provisioning stays a no-op and the committed
tree is byte-identical to the installed artifact.

**`tx-classifier`** is the intelligence half of transaction classification: a skill, no
server and no storage. Every piece of state it works with — the review queue, the
workflow tags, the notes, the rule rationales — lives in bank-feed. The split exists so
that the judgement calls are a prompt someone can read and change, while the
deterministic half stays testable.

Each plugin ships one skill. `bank-feed`'s **bank-accounts** skill is the operating
manual for the tool surface — how to link a bank, what to do when a consent is expiring,
how to read a balance honestly. `tx-classifier`'s **classify-transactions** skill is the
classification workflow. Both are prose a model reads at runtime, so they are part of
the shipped behaviour rather than documentation about it.

Neither plugin can schedule anything. A specialist has no turn to sleep in, so nothing
in this repository polls or waits: continuation is always either the operator calling a
tool again or casa's own nudge ladder delivering a callback.

## The shape of a request

```
casa  ──stdio JSON-RPC──▶  bank_feed_server.handle()
                              │  mode check, install marker, dispatch, banner
                              ▼
                           a tool module (tools_read, tools_auth, tools_refresh,
                           tools_annotate, tools_rules, tools_aggregate,
                           tools_destructive)
                              │
                              ├─▶ store.py        the SQLite ledger
                              ├─▶ eb_ais.py       provider data calls  (RS256 app JWT)
                              └─▶ eb_admin.py     control-panel calls  (minted ID token)
```

Tools register themselves with a `@register(...)` decorator as an import side effect;
`handle()` reads the resulting table. Everything a tool does that is worth testing lives
outside the dispatcher, in a module that can be exercised without an MCP session.

## Which document owns what

| Subject | Document |
|---|---|
| Getting a bank connected: link, authorize, consent, renewal, callbacks | `bank-linking.md` |
| Turning provider pages into ledger rows: identity, matching, coverage, the schema | `ingestion-and-identity.md` |
| Tags, notes, search, the rule engine, and the classifier split | `annotations-and-rules.md` |
| Keys, tokens, the vault, mode selection, and what is a secret | `credentials.md` |
| The tool-by-tool surface, and which tools are protected | `../reference/tool-surface.md` |
| Environment variables and the installation contract | `../reference/configuration.md` |
| Constants copied out of casa, and the version range they came from | `../reference/casa-compatibility.md` |
| Installing: the reconcile ladder and the one human step | `../reference/setup-flow.md` |

## Two properties that hold everywhere

**Provider text is untrusted, and is always neutralised.** No string that came from a
bank or from Enable Banking reaches a tool's output as written: the delimiter and any
newlines are neutralised first, so a value cannot forge an output line or its own fence.
That applies to fields that look innocuous — an account name, a currency, a booking date
— not only to remittance text.

Whether the neutralised value also gets a **visible** fence depends on what it is.
Prose-like fields a reader might mistake for our own text are wrapped by `_untrusted()`
in `tools_read.py`. Short structured values printed inside a sentence — a bank name in
`list_banks`, a status, a date — go through the same neutralising path without the
visible wrapper, because the fence would clutter output that is otherwise clean and
closes nothing the neutralising has not already closed.

**Destructive operations are gated by casa, not here.** The irreversible tools are
declared in the plugin manifest's `protectedTools`, and casa's fail-closed hook demands
an operator grant bound to the exact arguments before the call reaches this process. No
tool takes a `confirm` argument, because a model-supplied boolean is inference
satisfying itself. The in-process check is defence in depth: a tool that finds itself
undeclared refuses, so deleting a declaration disables the tool rather than ungating it.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `manifest.json`
- `role/role.yaml`
- `plugins/bank-feed/server/bank_feed_server.py::handle`
- `plugins/bank-feed/server/tools_read.py::register`

**Tests**
- `tests/test_component.py`
- `tests/test_server_smoke.py`

**Related**
- [`architecture/bank-linking.md`](../architecture/bank-linking.md)
- [`architecture/ingestion-and-identity.md`](../architecture/ingestion-and-identity.md)
- [`architecture/annotations-and-rules.md`](../architecture/annotations-and-rules.md)
- [`architecture/credentials.md`](../architecture/credentials.md)
<!-- END SOURCEMAP -->
