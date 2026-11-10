# casa-specialist-finance

A household finance specialist for **casa**, a Home Assistant application that runs
Claude Code agents:
it reads your bank accounts, keeps a local ledger of the transactions, lets you tag
and annotate them, and answers questions about them with arithmetic rather than
recollection.

**Read-only.** It uses PSD2 account-information access through
[Enable Banking](https://enablebanking.com/). It cannot move money, and there is no
code here that could.

## What it is, concretely

One casa **specialist component** — a role, a persona, and two bundled plugins:

- **`bank-feed`** — an MCP server (Python 3.11 standard library only) that owns the
  bank connection, the SQLite ledger, the annotation store, the auto-tagging rulebook,
  and 37 tools.
- **`tx-classifier`** — a skill that decides how transactions should be classified and
  works the queue the rules cannot settle. No server, no storage of its own.

Everything is installed and versioned as one bundle with pinned content digests.

## What you need

| | |
|---|---|
| **casa** | v0.355.0 or later. Both plugins' background jobs use the declaration casa v0.355.0 introduced, where a job is one long session; an older casa refuses them, and casa v0.355.0 refuses finance 0.27.x, so upgrade finance right after casa. A job running under the old version does not carry over: start it again after the upgrade. The role also grants casa's memory tools (`search_memory`, `browse_memory_day`, `open_memory`), held from v0.347.0. Nothing else declares the version, and no casa source ships here — `docs/reference/casa-compatibility.md` gives the floor and why. |
| **Python** | 3.11. The plugin runtime uses no third-party packages at all. |
| **An Enable Banking account** | The setup tool registers the *application* for you. Signing in to the provider's control panel to authorize that is the step it cannot do. |
| **1Password** | A service account and a vault, both configured in casa (its `onepassword_service_account_token` and `onepassword_default_vault` app options); without them casa withholds `bank-feed`. The plugin forges and stores its own credentials in that vault; the vault is the one thing you choose. |
| **A bank Enable Banking covers** | And the ability to complete strong customer authentication for the accounts you link. |

## Installing

Ask casa's assistant in chat, for example: *"Install the finance specialist from
bonzanni/casa-specialist-finance"*. Casa's configurator takes the latest published release
and tells you what it brings, and one consent message covers the specialist, its persona
and both plugins. Approve it and the assistant can delegate to the specialist. To update
later, ask the assistant to upgrade the finance specialist; it asks for consent the same way.

This repository is the component, not an installer: casa installs and versions it, and
casa's configurator wires the credentials setup provisions. Once it is installed, ask the
specialist to run its setup tool. It is argument-free and idempotent — re-run it any time:

```
setup_bank_feed
```

It reconciles the whole install: callback routing, a signing key (forged in your
vault when absent), the durable control-panel credential, the Enable Banking
application (registered when absent), and casa's callback redirect URI. When it
reaches the one step a person has to do — a sign-in link emailed to you — it says
so and names `bank_feed_signin`, which takes the link — from the vault drop-off
casa's assistant stores it in when you paste it there, or pasted to the specialist directly.

Setup stops short of finishing on its own in one place: the references it provisions
have to be wired into `plugin-env.conf` by casa's configurator, and the server restarted
with them, before `link_bank` has an application id to work with. Setup names the
references it needs wired rather than reporting success.

Then link a bank with `link_bank`. That takes two approvals: the account is added
to your Enable Banking application, and then you authorize it at your bank. Each
link arrives from casa itself, in your chat with the assistant, never in a task
topic.

Then ask casa's configurator for the daily sync, a job trigger on the assistant:
`name: bank-sync, type: cron, schedule: "0 7 * * *", channel: telegram, job: "bank-feed:daily-sync"`.
Every linked bank with an included account then syncs once a day without a finance conversation. The run is
silent; you hear from it only when a bank needs you (its consent ended or expired, or it
has failed to sync for three days), once, in your chat.

`docs/reference/setup-flow.md` walks the whole thing; `docs/reference/configuration.md`
is where the vault comes from and every environment variable;
`docs/reference/sandbox-mode.md` is how to try it against a disposable test world
instead of real accounts.

## Scope limits, stated up front

- **Read-only account information.** No payments, no transfers, no standing orders.
- **Transaction identity starts out heuristic, and references have to earn their way in.**
  Where a bank supplies stable transaction references, the code can use them as identity,
  but only for an account this installation has measured itself: a deep read at linking or
  renewal showing at least 100 distinct referenced transactions over 180 days with no reuse.
  No such evidence ships, because an earlier version shipped one household's measurements
  as every installation's defaults, which is worse. Until an account earns it, and for any
  bank that cannot show it, matching uses windowed nearest-date heuristics.
  `docs/architecture/ingestion-and-identity.md` explains what this costs.
- **"Paged to exhaustion" is not "we have everything."** The ledger records which date
  ranges it has actually observed, so it can distinguish "this range was read" from
  "this range has never been looked at". It never concludes that a transaction which
  stopped appearing was deleted.
- **The backfill runs immediately, because it assumes deep history may stop being
  available minutes after authentication.** What it could not reach then, it may not be
  able to reach later without re-authorizing.
- **No scheduling of its own.** Neither plugin runs itself on a timer. The daily bank
  sync is a casa job, `bank-feed:daily-sync`, that a job trigger on the assistant starts
  (see Installing); any other recurring work is a casa reminder you create.
- **Money is never converted.** Totals are per currency.

## Documentation

`docs/README.md` routes by what you are about to change. In short:

- `docs/architecture/` — how it works: linking, ingestion and identity, annotations and
  rules, credentials.
- `docs/reference/` — the tool surface, configuration, casa compatibility, setup, sandbox.
- `docs/doctrine/publishing.md` — the rule about what may be written down in this
  public repository, and what nothing enforces.
- `docs/contributing/` — the documentation contract, how account data is kept out, and
  the guards that refuse a commit or a push.

## Contributing

Install the hooks first — `core.hooksPath` is local git configuration, so a fresh clone
has none of them until this runs:

```
./scripts/setup-dev.sh
```

`git commit` then refuses staged account data and staged denied content, and `git push`
sweeps the tree, the commits the destination does not already have, their messages and
identities, and the destination branch name, and runs the pinned secret scanner.

Everything the hooks run can also be run by hand:

```
pip install -r requirements-dev.txt          # only the two scripts/ gates need this
python3 -m unittest discover -s tests
python3 scripts/scan_identifiers.py .
python3 scripts/scan_lineage.py .
python3 -m scripts.verify_docs .
python3 scripts/coverage_ledger.py check .
scripts/deny-sweep.sh tree
scripts/run-gitleaks.sh tree                 # needs gitleaks 8.28.0
```

All of them run in CI, which installs the pinned scanner itself.
`AGENTS.md` is the short version of what to know before editing;
`docs/contributing/protecting-account-data.md` and
`docs/contributing/publication-guards.md` explain the guards and why they exist.

## Licence

MIT — see `LICENSE`.
