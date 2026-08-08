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
  and 31 tools.
- **`tx-classifier`** — a skill that decides how transactions should be classified and
  works the queue the rules cannot settle. No server, no storage of its own.

Everything is installed and versioned as one bundle with pinned content digests.

## What you need

| | |
|---|---|
| **casa** | v0.155.0 is the version this component is written and tested against. Nothing here declares or enforces it, and no casa source ships here — under an older casa the install fails when it reaches the behaviour that is missing. |
| **Python** | 3.11. The plugin runtime uses no third-party packages at all. |
| **An Enable Banking account** | The setup tool registers the *application* for you. Signing in to the provider's control panel to authorize that is the step it cannot do. |
| **1Password** | A service account and a vault. The plugin forges and stores its own credentials there; this is the one thing you choose. |
| **A bank Enable Banking covers** | And the ability to complete strong customer authentication for the accounts you link. |

## Installing

This repository is the component, not an installer: casa installs and versions it, and
casa's configurator wires the credentials setup provisions. Once it is installed, run
the setup tool. It is argument-free and idempotent — re-run it any time:

```
setup_bank_feed
```

It reconciles the whole install: callback routing, a signing key (forged in your
vault when absent), the durable control-panel credential, the Enable Banking
application (registered when absent), and casa's callback redirect URI. When it
reaches the one step a person has to do — a sign-in link emailed to you — it says
so and names `bank_feed_signin`, which takes the pasted link.

Setup stops short of finishing on its own in one place: the references it provisions
have to be wired into `plugin-env.conf` by casa's configurator, and the server restarted
with them, before `link_bank` has an application id to work with. Setup names the
references it needs wired rather than reporting success.

Then link a bank with `link_bank`. That takes two approvals: the account is added
to your Enable Banking application, and then you authorize it at your bank.

`docs/reference/setup-flow.md` walks the whole thing; `docs/reference/configuration.md`
is the one configuration choice and every environment variable;
`docs/reference/sandbox-mode.md` is how to try it against a disposable test world
instead of real accounts.

## Scope limits, stated up front

- **Read-only account information.** No payments, no transfers, no standing orders.
- **Transaction identity is currently heuristic.** Where a bank supplies stable
  transaction references, the code can use them as identity — but that path depends on
  a per-installation capability record, and **none ships**. In every installation today
  matching falls back to windowed nearest-date heuristics. This is deliberate: an
  earlier version shipped one household's measurements as every installation's
  defaults, which is worse. Earning that trust locally is designed and not built, and
  is tracked as [issue #1](https://github.com/bonzanni/casa-specialist-finance/issues/1).
  `docs/architecture/ingestion-and-identity.md` explains what this costs.
- **"Paged to exhaustion" is not "we have everything."** The ledger records which date
  ranges it has actually observed, so it can distinguish "this range was read" from
  "this range has never been looked at". It never concludes that a transaction which
  stopped appearing was deleted.
- **The backfill runs immediately, because it assumes deep history may stop being
  available minutes after authentication.** What it could not reach then, it may not be
  able to reach later without re-authorizing.
- **No scheduling.** Neither plugin can run itself on a timer; recurring work is a casa
  reminder you create.
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
