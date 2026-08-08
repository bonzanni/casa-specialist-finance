# The tool surface

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

Thirty-one MCP tools, all served by `bank-feed`. `tx-classifier` adds none — it is a
skill and calls these.

Regenerate the list this table describes with:

```
python3 scripts/coverage_ledger.py enumerate . | grep -E '^(tool|protected|role):'
```

## Three lists that must stay in step

A tool is only usable if it appears in all three of:

1. **The server's own `tools/list` answer** — what it actually serves. Every tool below
   gets there through a `@register(...)` decorator in a `tools_*.py` module, but that is
   how this code registers them, not what makes them served: anything in the registry
   when the server answers is a tool.
2. **`provides_tools`** in `plugins/bank-feed/.claude-plugin/plugin.json` — what the
   plugin advertises to casa.
3. **`tools.allowed`** in `role/role.yaml` — what the specialist is permitted to call.

A tool missing from the third is unreachable; a name in the third that nothing registers
reads as authoritative and grants nothing. Two checks keep them in step, and neither
alone is enough:

- `tests/test_component.py` matches the manifest against the role, **both directions** —
  every advertised tool is allowed, and the allow-list names no plugin tool the manifest
  does not advertise.
- The coverage ledger runs the command `.mcp.json` declares and asks it `tools/list`,
  and reads the protected declarations and the role allow-list, so a tool added without
  a document is a failing gate — and no way of registering one can hide from it, because
  the answer comes from the same process casa talks to.

## Reading

| Tool | Does |
|---|---|
| `list_accounts` | Cached accounts with label, category and include flag. |
| `get_balances` | Cached balances, one selected type per account, with cache age. |
| `balance_total` | Sum of the selected balance per account, grouped by currency. Never converted. |
| `list_transactions` | Cached transactions for included accounts, filtered and bounded. |
| `get_transaction` | One transaction in full, minus the raw provider payload, with tags and the latest notes. |
| `list_tags` | Every tag in use with its transaction count. |
| `spend_by_tag` | Signed spend per tag and currency, plus an untagged bucket. A lens, not a ledger — groups overlap. |
| `list_rules` | The auto-tagging rulebook, one line per rule. |
| `consent_status` | Per-bank consent expiry, days remaining, in-flight authorizations, restore detection. |
| `list_banks` | Banks available in a country, with their consent ceiling. |

## Writing, and refreshing

| Tool | Does |
|---|---|
| `tag_transaction` / `untag_transaction` | Attach or remove tags on up to 100 rows. |
| `add_note` | Append one note to each listed row. Notes are append-only. |
| `rename_tag` / `delete_tag` | Vocabulary edits: every row carrying the tag, superseded history included. |
| `add_rule` / `replace_rule` / `remove_rule` | Maintain the rulebook. Replace is the only edit — there is no partial rule update. |
| `apply_rules` | Re-run the whole rulebook over stored rows. Additive and idempotent. |
| `sync` | Force a refresh now, regardless of cache age. Goes through the one rate-controlled funnel. |
| `export_history` | Write the whole local ledger to a file under the plugin's data directory. |

## Setup and authorization

| Tool | Does |
|---|---|
| `setup_bank_feed` | The reconcile ladder: callback routing, signing key, control-panel credential, application registration, redirect URI. **Argument-free** by casa's setup-tool contract. |
| `bank_feed_signin` | The one human step: the account email, the pasted sign-in link, or a request for a fresh one. Then the same ladder. |
| `link_bank` | Start a bank authorization; returns the URL to tap. Call it again after whitelisting to continue. |
| `collect_authorization` | Collect and exchange an authorization result casa has published. |

`collect_authorization` is deliberately **never protected**: casa's nudge turns have no
operator sender, so a protected call would be denied and every authorization would
strand.

`setup_bank_feed` and `bank_feed_signin` are not protected either. The ladder's writes
are broad, but it is dispatched unprompted by casa after the install consent settles —
there is no approval round in which an operator could be asked, and a schema advertising
arguments would only invite an agent to invent values for them.

## Protected — casa demands an operator grant

These six are declared in `casa.protectedTools`. casa's fail-closed hook demands a grant
**bound to the exact arguments** before the call reaches this process, and the summary
the operator sees is the one in the plugin manifest. No tool takes a `confirm` argument:
a model-supplied boolean is inference satisfying itself.

| Tool | Irreversible effect |
|---|---|
| `unlink_bank` | Revokes a bank consent. Refresh stops for that bank until it is re-linked; local history stays. |
| `purge` | Deletes every transaction booked before a date, trims the proven-coverage intervals to match, then reclaims the space. |
| `forget_local_account` | Erases one account's local history and drops the account. Revokes nothing — this does not disconnect the bank. |
| `delete_all_data` | Erases the entire local ledger for every account, **then attempts to withdraw every open bank consent**. Consents it cannot prove withdrawn keep their handles so they can be revoked by hand. |
| `label_account` | Changes an account's label, category or inclusion. Excluding it removes the account from every total shown. |
| `accept_app_reregistration` | Authorizes registering a **replacement** Enable Banking application. Every bank must be re-linked afterwards. |

`label_account` is protected despite not deleting anything: silently excluding an
account changes every number the specialist reports afterwards, which is
indistinguishable from data loss to whoever reads the answer.

The in-process check is a tripwire, not the boundary — a tool that finds itself
undeclared refuses, so removing a declaration disables the tool rather than ungating it.

## What else the role grants

The allow-list is not only this plugin's tools. Seven of its entries come from casa or
the harness, and each is there for a named reason:

| Grant | Why |
|---|---|
| `Read` | the skills read their own material |
| `Skill` | the specialist invokes its two skills |
| `WebSearch` | the classifier's evidence ladder, for counterparty lookups only |
| `mcp__casa-framework__recall_memory` | the classifier's evidence ladder, one rung below the web |
| `mcp__casa-framework__ask_user` | the one question the classifier cannot answer alone |
| `mcp__casa-framework__get_schedule`, `…__send_media` | reporting: when to report, and sending a rendered answer |

`Bash`, `Write` and `Edit` are explicitly disallowed, and a test pins that.

## Output discipline, on every read

- Numeric limits and clipped fields; a truncation notice **only** when something was
  truncated.
- Provider text inside an explicit untrusted delimiter, neutralised before wrapping so a
  value cannot forge its own fence.
- No raw provider payload ever leaves the process.
- Freshness and excluded-account notes on aggregate reads, so a total is never quietly
  partial.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `plugins/bank-feed/.claude-plugin/plugin.json`
- `role/role.yaml`
- `plugins/bank-feed/server/tools_read.py`
- `plugins/bank-feed/server/tools_auth.py`
- `plugins/bank-feed/server/tools_destructive.py`
- `plugins/bank-feed/server/tools_refresh.py`

**Tests**
- `tests/test_component.py`
- `tests/test_tools_read.py`
- `tests/test_tools_destructive.py`
- `tests/test_server_smoke.py`

**Related**
- [`architecture/overview.md`](../architecture/overview.md)
- [`reference/configuration.md`](../reference/configuration.md)
<!-- END SOURCEMAP -->
