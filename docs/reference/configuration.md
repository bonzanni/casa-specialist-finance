# Configuration

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

There is exactly **one** thing an installer must choose: which 1Password vault the
plugin may use. Everything else is either provided by casa, forged by the plugin at
setup, or an explicit break-glass override.

Regenerate the list this page describes with:

```
python3 scripts/coverage_ledger.py enumerate . | grep -E '^(env|config|secret):'
```

## The installation contract

`config-schema.json` is what casa reads at install time:

- **`required`** — empty. Nothing must be supplied by hand for the component to install.
- **`secret_names`** — the values casa must treat as secrets: the application signing
  key it provisions, and the optional pasted control-panel token.

The plugin declares what it needs passed into the server process in
`plugins/bank-feed/.claude-plugin/plugin.json` (`setupProvides`) and
`plugins/bank-feed/.mcp.json` (the `env` block). Those two declarations, and what the
code actually reads, are enumerated separately by the coverage ledger — a variable
declared but never read is a dead contract, and one read but never declared is empty in
every real install.

**A declared name is not the name the server reads.** casa reserves a prefix for
names a plugin declares in `setupProvides`, so the two setup-provisioned
credentials have one name in the declaration and another in `os.environ`. The
ledger keeps them apart (`declared:` against `env:`) rather than conflating them,
because they are different halves of the contract and either can rot alone.

| the server reads | casa reserves |
|---|---|
| `CASA_BANKFEED_EB_PRIVATE_KEY` | `CASA_PLUGIN_BANKFEED_EB_PRIVATE_KEY` |
| `CASA_BANKFEED_EB_APP_ID` | `CASA_PLUGIN_BANKFEED_EB_APP_ID` |

## Variables declared in `.mcp.json`

| Variable | Set by | Absent means |
|---|---|---|
| `BANKFEED_OP_VAULT` | the installer — **the one choice** | the vault seam refuses; nothing can be read or forged |
| `OP_SERVICE_ACCOUNT_TOKEN` | the operator's environment | the vault command-line tool cannot authenticate |
| `CASA_BANKFEED_EB_PRIVATE_KEY` | provisioned by setup, via casa | no signing key; the data API cannot be called |
| `CASA_BANKFEED_EB_APP_ID` | provisioned by setup, via casa | no application identity to sign as |
| `CASA_BANKFEED_EB_CP_TOKEN` | the operator, break-glass only | the normal path: the stored refresh token is used instead |
| `BANKFEED_EB_ENVIRONMENT` | the installer, only to ask for sandbox | production, which is the default |

**An empty `BANKFEED_OP_VAULT` is the same as an unset one.** Both are absent, and the
seam refuses rather than guessing a name — a wrong vault name is not a failure anyone
would notice quickly.

**`BANKFEED_EB_ENVIRONMENT` unset or empty means production.** Sandbox is entered only
by asking for it explicitly at install time. An *unrecognised* value is not a fallback
to production: every tool refuses uniformly, because a process that cannot say which
world it is in has no truthful thing to print. See `sandbox-mode.md`.

The environment-variable **names** are load-bearing, not incidental. Each is declared in
exactly one place and read through one accessor. This repository has already shipped the
failure where the manifest declared one name and the code read another, which made a
whole setup path unreachable in production while every test passed.

## Variables casa supplies to any plugin

These are not this plugin's to configure; it reads them, and the coverage ledger
enumerates them so they cannot be forgotten.

| Variable | Used for |
|---|---|
| `CLAUDE_PLUGIN_DATA` | where the ledger lives. **Refused when unset** — the ledger is durable data and must never land in a temporary directory. |
| `CLAUDE_PLUGIN_ROOT` | locating files that ship with the plugin |
| `CASA_ROOT` | importing casa runtime modules for the callback contract; defaults to the standard install path |
| `CASA_VERSION` | recording which casa produced a callback |
| `CASA_HOST_ID` | identifying this host; falls back to the machine name |
| `CASA_CALLBACK_SPOOL_ROOT` | overriding the callback spool location; defaults to casa's |

## What is a secret and what is a reference

| Value | Kind |
|---|---|
| The application signing key | secret — lives in the vault, passed in by casa, never logged |
| The control-panel refresh token | secret — vault only |
| A minted ID token, a one-time sign-in code | secret — never in an exception or a log line |
| The vault **name** | a reference; it names where secrets live and is not one |
| An item name inside the vault | a reference, derived from the mode |
| The Firebase API key | public by design; it ships in the provider's own web page |

The vault command-line seam carries the rule: no secret **value** ever appears in an
exception. Its error type carries the tool's standard-error tail only.

## Development dependencies

The plugin runtime is Python 3.11 standard library only, so that casa's install-time
provisioning stays a no-op and the committed tree is byte-identical to the installed
artifact. `requirements-dev.txt` pins what `scripts/` and `tests/` need — currently
PyYAML — and is installed by CI, never into the plugin.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `config-schema.json`
- `plugins/bank-feed/.mcp.json`
- `plugins/bank-feed/server/opvault.py`
- `plugins/bank-feed/server/ebmode.py`
- `plugins/bank-feed/server/store.py`

**Tests**
- `tests/test_opvault.py`
- `tests/test_ebmode.py`
- `tests/test_component.py`

**Related**
- [`architecture/credentials.md`](../architecture/credentials.md)
- [`reference/sandbox-mode.md`](../reference/sandbox-mode.md)
<!-- END SOURCEMAP -->
