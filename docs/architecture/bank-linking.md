# Bank linking

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

Getting one bank connected takes **two approvals**, in this order, and they are not the
same kind of thing.

1. **Whitelisting** — the account is added to the Enable Banking *application*, in the
   control panel, on the admin credential. This ends on Enable Banking's own page. Its
   redirect is fixed by the provider and cannot be pointed at this software, so nothing
   comes back to us.
2. **API authorization** — the account holder authorizes the application at their bank,
   with strong customer authentication. This one *does* come back, through casa's
   authorization-callback contract.

**Both approvals exist only in production.** In sandbox mode the whitelist
step does not exist at all — whitelisting is the provider's activation
mechanism for production applications (sandbox ones activate automatically),
and the Control-Panel call behind it initiates a session under the Control
Panel's own application, which routes to the real bank's live login
(issue #10). So a sandbox `link_bank` is single-tap: straight to the API
authorization, and `verify_accounts()` runs with `whitelist_gated=False` —
see `reference/sandbox-mode.md`.

`flows.py` orchestrates both, and between them it **waits for nothing**. There is no
sleep loop and no poll: a specialist has no turn to sleep in. The continuation is the
operator calling `link_bank` again, which re-reads the whitelist and goes straight to
the second approval once the entry has appeared.

## The callback

casa owns the callback machinery: minting, collection, acknowledgement, the spool
grammars, the time-to-live values, and redelivery. This repository owns the durable
attempt row, the lease on it, validation before the provider is contacted, and the
recorded outcome. `reference/casa-compatibility.md` states the division in full.

`callbacks.py` never waits, polls or schedules either. casa's nudge ladder — a sequence
of dispatches spread over the following hours, resuming across restarts — is the
continuation mechanism, and `run_collection()` is simply what a nudged turn calls.

**The generation fence.** An attempt records the target account's session generation at
the moment authorization starts. A callback whose account has since been rebound by a
higher-generation session is discarded *before* the provider is contacted. Without the
fence, a slow repair callback can overwrite an account's session binding after a newer
renewal already replaced it.

**`collect_authorization` is never a protected tool.** casa's nudge turns have no
operator sender, so a protected call would be denied outright and every authorization
would strand. This is a deliberate exception to the rule that state-changing tools are
gated; the compensating control is that the tool acts only on an attempt casa already
minted.

## Backfill happens immediately, and synchronously

The code is built on an assumption about the provider that this commit cannot prove and
that shapes everything below: **deep history is available only inside the fresh
strong-authentication window, and that window may close within minutes.** The dangerous
part of the assumption is that a later, narrower answer is indistinguishable from a
complete one — no error, nothing in the response to mark it short.

If the assumption is wrong, the cost is one redundant early fetch. If it is right and the
code deferred, history would be lost silently. So `backfill()` runs first, before mapping
review or any other interactive step. It pages to exhaustion, stages every page, and
commits them in one transaction. It records the interval it actually **observed** —
bounded below by the oldest row the response returned, which is a claim about existence
and never about completeness.

Two honesty rules follow, and both are load-bearing:

- *Paged to exhaustion* proves a response set was consumed. It does not prove the
  provider returned everything that exists, and it never licenses concluding that a row
  now absent was deleted — see `ingestion-and-identity.md`.
- When pagination does **not** complete, nothing canonical is touched at all. A partial
  page set is not evidence that anything vanished.

## Renewal, and identity across it

A renewal mints new provider handles for the same real accounts. The provider's
per-session account handle is therefore never a durable key; `account_id` is, and it is
assigned locally. `complete_renewal()` rebinds accounts from the old session to the new
one, and revocation of the old session is a separate, explicit step.

`verify_accounts()` compares what the new session offers against what the application is
whitelisted for, so an account that quietly disappeared from the whitelist is a reported
mismatch rather than a silent gap in the ledger.

## Rate control

Every **cached-data refresh** — balances and transactions, the calls a routine question
provokes — goes through one funnel, `_refresh_resource()` in `tools_refresh.py`, so there
is exactly one place ordinary reads can burn quota. A fresh authentication window
exhausted by routine questions cannot be reopened by anything, which is the whole reason
the control set exists.

Two kinds of provider call are deliberately outside it: the authorization exchanges, and
the calls setup and the catalogue make directly — `list_banks` asks the provider for a
country's banks, and setup talks to the control panel. They are operator-initiated, they
do not run on a cache, and putting them behind a refresh cooldown would block the repair
paths.

The primitives — the minimum interval, the backoff, the in-flight lease, and
`admit_refresh()` / `claim_refresh()` / `release_refresh()` — live in `tools_auth.py`
and are imported, never re-spelled. Two modules spelling one constant independently is a
drift this codebase has had before, and a cooldown constant that drifts fails silently:
the guard simply stops engaging. A test greps for a second declaration.

`httpx.py` owns the transport half: an exact allowlist of scheme, host, method and path;
HTTPS only; redirects disabled, so a redirect can never carry a bearer token to another
origin; size caps and deadlines. It never retries. A rate-limited response is raised as
an exception carrying the parsed retry delay and no provider body, so the
non-idempotent authorization calls are never re-sent automatically.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `plugins/bank-feed/server/flows.py::backfill`
- `plugins/bank-feed/server/flows.py::complete_renewal`
- `plugins/bank-feed/server/flows.py::verify_accounts`
- `plugins/bank-feed/server/callbacks.py::run_collection`
- `plugins/bank-feed/server/eb_ais.py`
- `plugins/bank-feed/server/httpx.py`
- `plugins/bank-feed/server/tools_refresh.py::_refresh_resource`

**Tests**
- `tests/test_flows.py`
- `tests/test_callbacks.py`
- `tests/test_eb.py`
- `tests/test_httpx.py`
- `tests/test_tools_refresh.py`

**Related**
- [`architecture/ingestion-and-identity.md`](../architecture/ingestion-and-identity.md)
- [`architecture/credentials.md`](../architecture/credentials.md)
<!-- END SOURCEMAP -->
