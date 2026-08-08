# Sandbox rehearsal

`rehearsal.py` links a bank for real, ingests its transactions, and re-ingests
them. It is not part of `python3 -m unittest discover -s tests` — it needs a
live credential and one human tap, so it is run by hand.

## SANDBOX ONLY

Your production application has live consents against real accounts. This
script must never touch it.

The guard is not a naming convention: `_client()` reads `environment` back
**from the live provider** and exits unless it reads `SANDBOX`. That survives a
mistyped or stale `CASA_BANKFEED_EB_APP_ID`, which a check against a name in a
variable would not.

Note also that `delete_all_data` — a different tool, not used here — now issues
real `DELETE /sessions/{id}` calls. Never point it at production either.

## What this proves that the unit suite cannot

- The stdlib RS256 signer (`jwtsign`) is accepted by the real API.
- The allowlisted HTTP client reaches every endpoint the flow needs.
- The CSRF `state` round-trips through a real bank's redirect.
- An authorization code exchanges into a session with real accounts.
- **Re-ingest is idempotent** — the second pass inserts nothing and tombstones
  nothing. Every fake in the unit suite is written by the same people who wrote
  the code; this is the only place the property is tested against a bank.

## Credentials

Both live in 1Password, in the vault `BANKFEED_OP_VAULT` names. Load a
1Password service-account token into the environment first, however your
installation supplies one.

    op://$VAULT/EnableBanking Key Sandbox/private key -> CASA_BANKFEED_EB_PRIVATE_KEY
    op://$VAULT/EnableBanking/credential              -> control-panel token, 1h TTL

The item layout is `EnableBanking Key` / `EnableBanking Key Sandbox` for the
signing keys and `EnableBanking` / `EnableBanking Sandbox` for the
credentials.

`CASA_BANKFEED_EB_APP_ID` is the sandbox application's `kid`, readable from
`GET https://enablebanking.com/api/applications` with the control-panel token.

## Run it

    VAULT="${BANKFEED_OP_VAULT:?set this to your 1Password vault}"
    export CASA_BANKFEED_EB_APP_ID="<sandbox kid>"
    export CASA_BANKFEED_EB_PRIVATE_KEY="$(op read "op://$VAULT/EnableBanking Key Sandbox/private key")"
    export CASA_ROOT="<path to a casa checkout>/casa/rootfs/opt/casa"

    python3 tests/e2e/rehearsal.py start
    # open the printed URL, approve as a PERSONAL PSU, copy the
    # https://localhost/callback?... URL you land on (it will not load —
    # nothing is listening there, and that is correct)
    python3 tests/e2e/rehearsal.py finish '<that URL>'

`finish` revokes the sandbox session in a `finally`, so a failure anywhere in
the ingest still withdraws the grant. If a run is killed outright:

    python3 tests/e2e/rehearsal.py revoke

## Which bank

Default `Rabobank` (`CASA_E2E_ASPSP` overrides). It is in **both** the sandbox
and production, so it exercises a real bank's payload shape.

**`Mock ASPSP` cannot be linked and this is not a bug in the plugin.** Verified
live 2026-08-04: it returns `account_id = {}` with no IBAN under any key, while
the ledger keys every account on `HMAC(IBAN, currency)`. An account with no
IBAN has no identity to key on.

## What you should see

The run prints, in order: the application's name and environment (which must
read `SANDBOX`); the NL ASPSPs it found and the one it is linking; how many
accounts the session came back with; a first-ingest line carrying the row
count, the interval it proved, and the completeness signals; a re-ingest line;
the idempotence verdict; the coverage intervals; and the revocation.

The row counts and dates are whatever your sandbox account holds — they are
not fixed, and a different figure is not a failure.

The only assertion that matters is the idempotence one: re-ingest must insert
nothing and tombstone nothing. If it fails, stop — ingest identity is broken
and every later refresh would duplicate history.

## If it refuses to run

- `refusing to run against environment 'PRODUCTION'` — working as designed.
  You exported the wrong `CASA_BANKFEED_EB_APP_ID`.
- `state mismatch` — the callback came from a different `start` run. Re-run
  `start` and use the URL it prints.
- `AUTHORIZED with zero accounts` — the account is not whitelisted.
- `upsert_account needs an IBAN` — the bank returned no IBAN. See `Mock ASPSP`
  above.

## Two provider facts this rehearsal settled

Both had been reasoned about rather than observed, and one was wrong.

- **`GET /application` (app JWT) DOES return `redirect_urls`.** It had been
  assumed not to, and the redirect check was routed through the control panel
  on that basis. The routing is still correct — the control panel is the only
  place that can *write* — but the reason recorded for it was false.
- **`GET /sessions` is 405.** There is no way to enumerate sessions, so the
  local `sessions` table is the *only* handle to a live grant. This is the
  premise `delete_all_data` rests on when it revokes before erasing, and it is
  now verified rather than assumed. This script proved it the hard way: an
  early run crashed between the exchange and the revoke and stranded a consent
  that could not be found again.
