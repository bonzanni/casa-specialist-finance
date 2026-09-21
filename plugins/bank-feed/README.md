# bank-feed

Read-only bank account information (PSD2 AIS via Enable Banking) for the
finance specialist. Stdlib-only Python 3.11; no third-party packages,
vendored or otherwise.

## Environment variables

Declared in `.mcp.json`, resolved by casa from `op://` references into
`os.environ` at boot and on every reload. The plugin never shells out to
`op` for these.

**It normally sees only the resolved value — but not always, and the
exception differs by declaration** (verified in casa v0.155.0; see
issue #4). When a reload-time `op://` resolution FAILS, casa
keeps the raw reference in the environment. For a name declared in
`casa.setupProvides` it then sanitises the value to empty, so this plugin
sees absence and falls back (vault read for the key, local meta for the app
id). For a DEFAULTED reference there is no such sanitisation, so the raw
`op://…` text can reach the server. Both outcomes fail closed: a raw
reference as the control-panel token produces a provider authentication
failure, and a raw reference as the mode makes every tool refuse uniformly
rather than guess a world. Neither is reachable unless those two are wired
through `op://`, which nothing here asks for — the CP token is pasted and
the mode is a plain word.

**Requires casa v0.318.0 or later.** It relies on the `casa.setupProvides`
declaration and on defaulted references being shippable in a bundled plugin
tree (casa v0.155.0, issue #4). It also relies on casa delivering the link
`link_bank` produces (casa v0.318.0, ha-casa-app#1015): an older casa refuses
the manifest's `delivers` declaration at install.

`export_history` needs **casa v0.326.0 or later**: it publishes the export into
casa's plugin file handoff folder (ha-casa-app#486), which an older casa does not
create. There the tool answers that the export could not be written.

Under **casa v0.290.0 or later** the manifest's `casa.resultContract` is what
lets any tool but `setup_bank_feed` run at all: casa refuses a call to a
non-setup tool the declaration omits, before it runs. Every bank-feed tool but
`link_bank` is declared `safe`. `link_bank` is a `capability` whose link casa
posts in the operator's chat itself, so the URL never passes through the
assistant; `docs/reference/casa-compatibility.md` says how.

Every entry has a KEY and a reference. The **key** is what this server reads
out of `os.environ`. The **reference** is the name casa resolves out of
`plugin-env.conf` — the name `set_plugin_env_reference` writes and
`verify_plugin_state` grades. For five of the seven they are the same string;
for the two `casa.setupProvides` credentials they are not, because casa
reserves the `CASA_PLUGIN_` prefix for declared names (a declared name is
bound for the whole session, so the namespace is fenced). **Wire the
reference.**

| the server reads | wire this in `plugin-env.conf` | if unwired |
|---|---|---|
| `CASA_BANKFEED_EB_PRIVATE_KEY` | `CASA_PLUGIN_BANKFEED_EB_PRIVATE_KEY` | declared `setupProvides` — loads, reports `unprovisioned` |
| `CASA_BANKFEED_EB_APP_ID` | `CASA_PLUGIN_BANKFEED_EB_APP_ID` | declared `setupProvides` — loads, reports `unprovisioned` |
| `CASA_BANKFEED_EB_CP_TOKEN` | `CASA_BANKFEED_EB_CP_TOKEN` | optional (its reference carries an empty default) — loads, no row at all |
| `BANKFEED_EB_ENVIRONMENT` | `BANKFEED_EB_ENVIRONMENT` | optional (empty default) — loads as PRODUCTION |
| `BANKFEED_OP_VAULT` | `BANKFEED_OP_VAULT` | optional (empty default) — loads, uses casa's default vault |
| `ONEPASSWORD_DEFAULT_VAULT` | *(not here)* — casa exports it from the `onepassword_default_vault` app option | **withholds the plugin** |
| `OP_SERVICE_ACCOUNT_TOKEN` | *(not here)* — casa exports it from the `onepassword_service_account_token` app option | **withholds the plugin** |

- `CASA_BANKFEED_EB_PRIVATE_KEY` — the Enable Banking application's PKCS#8
  PEM private key (RSA, 4096-bit). Used only to sign the app's own RS256
  JWTs (`jwtsign.py`); never written to disk by the plugin. `setup_bank_feed`
  forges it inside 1Password when absent, which is why it is declared:
  casa must let the plugin load without it, or setup could never run to
  create it. Absent, the key ladder reads the vault directly instead.
- `CASA_BANKFEED_EB_APP_ID` — the Enable Banking application id, used as the
  JWT `iss`/`kid`. Also setup-provided: the registration returns it. Absent,
  `_resolved_app_id` falls back to the id setup recorded in local meta.
- `CASA_BANKFEED_EB_CP_TOKEN` — the Enable Banking control-panel token.
  Optional; only consulted for admin-client mutations (application
  registration, account whitelisting/unlinking during setup and repair).
  The steady-state AIS client never holds this credential, and the stored
  refresh token supersedes it.
- `BANKFEED_EB_ENVIRONMENT` — `PRODUCTION` (the default when unset or
  empty) or `SANDBOX`. Its reference carries an EMPTY default, never
  `sandbox`: a non-empty one would silently put a production install in the
  wrong world.
- `ONEPASSWORD_DEFAULT_VAULT` — the 1Password vault, a casa-owned variable
  exported from casa's `onepassword_default_vault` app option. Neither
  declared nor defaulted: `opvault.status()` refuses without a vault, so being
  withheld until casa has a default vault is correct rather than a deadlock.
  An EMPTY value counts as unset. It is a vault NAME, a plain setting — never
  something to search the vault for.
- `BANKFEED_OP_VAULT` — an optional override of that vault; it chooses a different
  vault, it does not stand in for the app option, which casa's withholding gate still
  reads. When set and
  non-empty it wins; unset or empty, casa's default vault is used. Also a
  plain setting.

Until the two declared credentials are wired, `verify_plugin_state` reports
them `unprovisioned` and the plugin **not ready**. That is the intended,
visible state of an install whose setup has not run (or has run and is
awaiting the wiring), not a fault — and the plugin still loads and works
throughout, on its fallbacks.

## Persistent state

`CLAUDE_PLUGIN_DATA/bank_feed.sqlite` — a local SQLite ledger of balances and
transactions. `CLAUDE_PLUGIN_DATA` is CLI-injected and must not be declared
in `.mcp.json`.

## No system packages required

Every dependency (`sqlite3`, `urllib.request`, `hashlib`, `hmac`, `decimal`,
`json`, `base64`) is in the Python 3.11 standard library. Casa performs no
dependency provisioning at install, so this plugin's committed tree is
exactly its installed artifact.
