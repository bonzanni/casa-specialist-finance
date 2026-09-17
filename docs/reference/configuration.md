# Configuration

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

There is **nothing** an installer must choose for this plugin. The one choice it
depends on — which 1Password vault it may use — is made once in casa, through casa's
`onepassword_default_vault` app option, and reaches the plugin as
`ONEPASSWORD_DEFAULT_VAULT`. Everything else is either provided by casa, forged by the
plugin at setup, an optional override, or an explicit break-glass value.

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
| `ONEPASSWORD_DEFAULT_VAULT` | casa, from its `onepassword_default_vault` app option — **the vault** | casa withholds the plugin; without a vault the seam refuses and nothing can be read or forged |
| `BANKFEED_OP_VAULT` | the operator, only to use a different vault than casa's default | the normal path: casa's default vault is used |
| `OP_SERVICE_ACCOUNT_TOKEN` | casa, from its `onepassword_service_account_token` app option | the vault command-line tool cannot authenticate |
| `CASA_BANKFEED_EB_PRIVATE_KEY` | forged by setup; wired by casa's configurator on setup's instruction | no signing key; the data API cannot be called |
| `CASA_BANKFEED_EB_APP_ID` | discovered by setup; wired by casa's configurator on setup's instruction | no application identity to sign as |
| `CASA_BANKFEED_EB_CP_TOKEN` | the operator, break-glass only | the normal path: the stored refresh token is used instead |
| `BANKFEED_EB_ENVIRONMENT` | the installer, only to ask for sandbox | production, which is the default |

**"Wired by casa's configurator" is a two-actor handoff, not a provisioning promise.**
Setup forges the key and discovers the app id, then *names the references it needs
wired* — writing `plugin-env.conf` is casa's configurator's job, and no
`set_plugin_env_reference` call exists in this plugin's source. Until that wiring lands
and the server restarts with it, casa reports the two declared credentials
`unprovisioned`: that is the designed handoff mid-flight, not a setup step that claimed
success and failed to deliver. `setup-flow.md` states the contract.

**The vault is resolved in one place, `opvault.py`'s `_vault()`:** `BANKFEED_OP_VAULT`
when it is set and non-empty, otherwise `ONEPASSWORD_DEFAULT_VAULT`. An empty value of
either is the same as an unset one — `.mcp.json` wires the override as
`${BANKFEED_OP_VAULT:-}`, so an install that never set it hands the server an empty
string, and that falls through to casa's default. With neither set, the seam refuses
rather than guessing a name — a wrong vault name is not a failure anyone would notice
quickly — and its refusal names both the app option and the override.

**Both vault variables are plain settings, never secrets.** A vault name is where
secrets live, not one of them, so neither is wired from a vault item. Casa's
install-time vault exploration still runs for the two `casa.setupProvides`
credentials, which nothing here wires; the vault name itself is no longer
something an install must ask about. `ONEPASSWORD_DEFAULT_VAULT` is a bare reference on purpose: casa
withholds the plugin until a default vault is configured, which is correct rather than
a deadlock, because a plugin loaded without a vault could only answer every vault step
"1Password unreachable".

**The override does not stand alone.** casa's withholding gate reads the bare
reference, so `onepassword_default_vault` must be set for the plugin to load at all —
`BANKFEED_OP_VAULT` then chooses a DIFFERENT vault, it does not substitute for the app
option. An install upgrading from 0.7.0 that wired the override while leaving the app
option empty is withheld until the option is set, and casa's remediation names that
option. Accepting either variable alone would need casa to express "one of these two",
which no manifest declaration does today.

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
