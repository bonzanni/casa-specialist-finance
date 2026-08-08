# Credentials

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

Four credentials, two provider surfaces, one vault, and one rule: the plugin forges and
stores everything it can, and the only irreducibly human steps are the ones that
*should* be human.

| Credential | Reaches | Lives in | Made by |
|---|---|---|---|
| Application signing key (RSA) | the data API, as an RS256 assertion | the vault | the plugin, at setup |
| Application id | the data API, as the assertion's subject | casa's environment, with setup's own record in the ledger's `meta` table | the plugin, at setup |
| Control-panel refresh token | the control panel, via a minted ID token | the vault | the operator's one sign-in |
| Control-panel token (pasted) | the control panel directly | the environment | the operator, break-glass only |

## The two provider surfaces

Only two of those live in the vault. The application id is not a secret and is not
kept there: casa passes it in, and setup records the binding it created in the ledger's
`meta` table so a later run can tell which application this install is bound to.

**Data (`eb_ais.py`)** runs on the application's own signed assertion. It is the
steady-state path: sessions, accounts, balances, transactions. `transactions()` returns
one page plus a continuation key; paging to exhaustion belongs to the caller that owns
the coverage interval, because only that caller can say what was proved.

Its error type carries a status and a class and nothing else. Provider text is
attacker-controllable and any exception text can reach the model through the server's
error path, so the error deliberately has no body to leak and no path — a path would
carry a session id. That guarantee is about *that* error type, not about every exception
the module can raise: a success response whose body is not JSON raises a decode error
whose attributes still hold the provider body. Nothing renders exception attributes
today; a future error path that did would surface a whole provider body, and this
module's own guarantee would not stop it.

**Control panel (`eb_admin.py`)** runs on a minted ID token from the stored refresh
token, or — as a fallback — on a token the operator pasted. It is loaded for setup and
repair only and is never held by the steady-state data path.

The environment variable naming this credential is declared once, in the plugin's
`.mcp.json`, and `from_env()` is the single place an admin client is constructed from
the environment. That single construction point is not tidiness: this codebase has
already shipped the failure where the manifest declared one name and the client read
another, so production could never populate the token the code actually read and
whitelisting could never start.

## The sign-in ladder

`fbauth.py` owns the three-call Firebase exchange behind the control-panel login:
`send_signin_email()` sends the magic link, `exchange_link()` turns the pasted link into
a refresh token, and `mint_id_token()` turns that refresh token into a short-lived ID
token. `Minter` caches the ID token for roughly its lifetime so a repair session does
not mint one per call.

The Firebase API key is **public by design** — it identifies the project and ships in
the control panel's own JavaScript. The refresh token, the ID token and the one-time
sign-in code are secrets and never appear in an exception or a log line.

`reference/enable-banking-credentials.md` walks the whole exchange by hand, as the
break-glass path.

## Signing

`jwtsign.py` implements RS256 with the standard library only, because the plugin ships
no third-party packages. The construction is the one the provider mandates, followed
literally, with no Chinese-remainder optimisation: this is a handful of signatures a
day.

## The vault

`opvault.py` is the 1Password command-line seam and the plugin's **only** subprocess
target. Everything shaped like a vault call lives there so its rules exist in one place:

- every call passes an empty standard input, because under a heredoc the child inherits
  exhausted input and the tool then reports a malformed-request error, which reads as a
  bad call rather than as a stdin problem;
- a read appends exactly one trailing newline and exactly one is stripped: a refresh
  token is rejected with it attached, and a key's interior newlines must survive;
- no secret value ever appears in an exception; the error type carries the tool's
  standard-error tail only;
- key items are generate-once — editing one is refused by the tool — which is why there
  is a create call and no rotation call.

The vault name is the plugin's one configuration element, `BANKFEED_OP_VAULT`. See
`../reference/configuration.md` for what an empty value means and who sets it.

## Mode

`ebmode.py` decides which Enable Banking world the process lives in. **One authority,
one spelling**: every mode-derived surface — the application name, the vault item names,
the ledger filename and install marker, the dispatcher banner — branches on `mode()` and
never re-reads the environment variable itself. A second reader is how two spellings
drift apart.

The mode is resolved once per process and memoized. A server process's environment is
fixed at spawn, so the memo turns that deployment fact into an in-process guarantee: the
cached database connection, the cached token minter and the world guard can never
straddle two modes inside one process. An unrecognised value refuses every tool
uniformly rather than falling back to the real-money world, and that refusal is
unbannered, because with an unparseable mode there is no truthful banner to print.

`../reference/sandbox-mode.md` is the operator-facing half.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `plugins/bank-feed/server/fbauth.py::Minter`
- `plugins/bank-feed/server/eb_admin.py::from_env`
- `plugins/bank-feed/server/jwtsign.py`
- `plugins/bank-feed/server/opvault.py::upsert_field`
- `plugins/bank-feed/server/ebmode.py::mode`

**Tests**
- `tests/test_fbauth.py`
- `tests/test_eb.py`
- `tests/test_jwtsign.py`
- `tests/test_opvault.py`
- `tests/test_ebmode.py`

**Related**
- [`reference/enable-banking-credentials.md`](../reference/enable-banking-credentials.md)
- [`reference/sandbox-mode.md`](../reference/sandbox-mode.md)
- [`reference/configuration.md`](../reference/configuration.md)
<!-- END SOURCEMAP -->
