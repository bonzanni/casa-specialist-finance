# The autonomous setup flow

Status: **built**, and this describes what the code does.

`setup_bank_feed` drives the credential and application work itself: no key
creation by hand, no application registration by hand, no hourly token pastes.

**It does not finish the install on its own.** Two things it cannot do are left
to somebody else, and both are named in its own output: the copy/pasted sign-in
link (below), and wiring the references it provisions into `plugin-env.conf` —
which is casa's configurator's job, not this plugin's. Setup names the
references it needs wired rather than reporting success.

Until that wiring lands and the server restarts with it, casa reports the two
declared credentials `unprovisioned` and the plugin **not ready**. The plugin
itself keeps working meanwhile, on its fallbacks: `_resolved_app_id()` reads the
id setup recorded in `meta` when the environment has none, and the key ladder
reads the vault directly. So an unwired install is not a broken one — it is one
casa will not call ready, and whose steady-state configuration is still
missing.

## The principle

The plugin forges and stores everything it can. The irreducible human step in
**credential acquisition** is copying the intact sign-in URL out of the mailbox
and pasting it back — a copy/paste, not a click: mail connectors defang the
link in transit, and clicking it in a browser consumes the single-use code
without handing the plugin anything. It is irreducible because "software
triggers a sign-in email *and* reads the mailbox for the code" is an
account-takeover primitive that the safety layers correctly refuse — so the
human ferries the link, and software does everything on either side.

**That is NOT the only human touch in the install.** "Exactly one human touch"
would be false. The full install keeps: approving the callback consent DM, the
credential copy/paste above, supplying the account email once (the sign-in email
is recorded to the vault on first use, so it is asked for only when no
`username` field is stored yet), **two approvals per bank** (whitelist tap, then
bank SCA), labelling each discovered account once, and a bank re-approval at or
before the consent's expiry, forever — the plugin requests 179 days, but what it
records and acts on is the `valid_until` the provider actually returned, which
may be shorter or missing. None of those is plumbing.

## The flow, with branches

### Phase 0 — preflight (no human)

1. `callbacks.discover()` — is casa routing our callback? No → stop, ask for the
   callback consent.
2. **Private key** — present and loadable by `jwtsign.load_pkcs8`?
   - No → **forge it, autonomously, via 1Password itself**: `op item create
     --category ssh --ssh-generate-key rsa,4096` → `op read .../private key`
     returns a PKCS#8 PEM → confirm it loads and signs. **No openssl**:
     1Password generates the key, and no key material ever exists outside the
     vault. The signing-key items are `EnableBanking Key` / `EnableBanking Key
     Sandbox` and the API-credential items are `EnableBanking` / `EnableBanking
     Sandbox`; the vault itself comes from `BANKFEED_OP_VAULT`, the plugin's one
     configuration element, supplied by the configurator. A key created this way
     reads back as a PKCS#8 PEM, which is what `jwtsign.load_pkcs8` accepts.
     Two caveats on record: `op item edit` refuses SSH-key items,
     so the item is generate-once/read-only; and the item's `public key` field is
     **OpenSSH format**, while application registration (Phase 2) needs a bare
     **SPKI PEM** — so the public half is *derived* from the private key (a
     small stdlib DER construction from `n, e`; `jwtsign` already parses to
     those). No human.
   - Yes → use it.
3. **Durable credential** — read `op://$BANKFEED_OP_VAULT/EnableBanking/refresh token`
   (which removes exactly one trailing newline — never a general strip, or a
   secret with meaningful trailing whitespace is silently altered), and exchange
   it at `securetoken.googleapis.com`.
   - Mints an ID token → good, skip Phase 1.
   - Missing / `INVALID_REFRESH_TOKEN` → Phase 1.

Phase 0 is what makes setup idempotent: a second run is a no-op.

### Phase 1 — acquire the durable credential

- **Account email**: from 1Password, else ask once.
- **The copy/paste, and nothing else.** There is one path, and no automatic
  mailbox branch exists — see "the principle" above for why, and the
  bank-accounts skill, which instructs the specialist never to read that email
  on the operator's behalf even where it could.
  1. plugin calls `sendOobCode`, at most one email per 15 minutes unless the
     operator asks for a resend.
  2. plugin prints step-by-step instructions naming `bank_feed_signin`.
  3. operator **copies** the intact URL out of their own mail client and pastes
     it back as `signin_link` (not a click — a browser visit consumes the
     single-use code without handing the plugin anything).
  4. plugin extracts the code, exchanges, stores, and runs the rest of the
     ladder itself.

- **The store:** `signInWithEmailLink` → refreshToken → prove it mints an ID
  token → write to 1Password → read back and confirm.

### Phase 2 — the production application (no human)

1. `GET /api/applications` with a fresh ID token.
2. **Does our production app exist?** (match by name, `casa-finance`)
   - Yes → read `kid` → that is the app id.
   - No → **create it**: `POST /api/applications` with `{certificate: <bare
     SPKI public-key PEM>, environment, name, redirect_urls}` → the response
     carries the app id. Three assumptions this step is built on, each with what
     happens when it is wrong: a bare SPKI PEM is accepted with no X.509 wrapper
     (if not, registration fails with the provider's error and setup stops before
     recording an app id); linking activates an application that registered
     inactive (if not, it stays inactive and phase 4 reports it, which is why
     activation is reported and not required); and `DELETE` with `{"appId": …}`
     works, which only a throwaway probe relies on — nothing in the shipped
     ladder deletes an application.

`eb_admin.ALLOW` carries POST on the collection URL narrowly, for exactly this,
and carries no DELETE at all — see learning 4.

### Phase 3 — callback redirect (no human)

3. `add_redirect_url` — register `<PUBLIC_URL>/callback/plg-bank-feed--authorize`.
   Idempotent.
4. Sanity: `environment == PRODUCTION` — a mismatch stops setup, because an
   application in the wrong world is not the one this install means. Activation
   is **reported, not required**: a freshly registered production application
   starts inactive, and completing the first link is what activates it. Setup
   says which state it found and points at `list_banks`; inactive at this point
   is the normal first-run state, not a failure to diagnose.

### Phase 4 — ready

5. Report state, point the operator at `list_banks` then `link_bank`, **one bank
   at a time**, starting with a single bank.

## The one cross-phase invariant

`generate keypair → store private key → confirm read-back → register app with the
public key → store app id`. Never create an application before its private key is
persisted and verified; an app whose key was never saved cannot be authenticated
against.

## What this design assumes about the provider

Each of these is an **assumption the code is built on**, not something this
commit can show to be true — see `../doctrine/publishing.md` on how that
distinction is drawn. What matters to a maintainer is the second half of each
one: what the code does if the assumption turns out to be wrong. Every one of
them fails closed.

- **The credential mechanism, end to end.** `sendOobCode` (email-link) →
  `signInWithEmailLink` → refresh token → stored at
  `op://$BANKFEED_OP_VAULT/EnableBanking/refresh token` → mints a fresh 1h ID token from the
  stored copy. This is the durable replacement for the 1-hour
  `CASA_BANKFEED_EB_CP_TOKEN`.
- **Firebase config** (public): project `enablebanking`, web apiKey
  `AIzaSyBn8fvjRYQKslskRaO3cblUjmcyl5b9o-c`, sign-in method **email magic link**.
- **`GET /application` (app JWT) returns `redirect_urls`.** Reading them does not
  need the control panel; only *writing* one does, which is why redirect
  registration is routed there and reads are not.
- **`GET /sessions` is 405** — no session enumeration, so the local table is the
  only handle to a live grant. This is the premise behind revoke-before-erase.

## Learnings that shape the build

1. **The login is email magic link, not password.** Firebase reports
   `sign_in_provider: "password"` for *both*, so the token does not prove
   password auth; `EMAIL_SIGNIN` is the enabled method (verified). An
   email+password recipe is simply wrong for this provider.

2. **Do not let software read the link from a mailbox.** "Trigger a sign-in email
   *and* read the mailbox for the code" is an account-takeover primitive
   regardless of who consented, and mail connectors defang the link in transit
   anyway — they rewrite characters inside the code, so what arrives is not what
   was sent. Both point the same way: the human ferries the link. The skill says
   so, and there is no code that could do otherwise.

3. **Autonomous key generation needs no host tooling.** 1Password generates the
   keypair (`op item create --category ssh --ssh-generate-key rsa,4096`),
   so the plugin needs `op` — which it shells out to anyway — and
   no openssl at all. Whether the forge runs in the plugin or in the
   configurator agent is a deployment choice, not a feasibility one. The one
   derived piece is the SPKI public key for Phase 2: the `op` item's public-key
   field is OpenSSH-format, not SPKI.

4. **The one path to exercise carefully.** The `POST /api/applications` code path is
     guarded by the `GET /api/applications` existence/duplicate check and the
     key-before-app invariant, and it should be exercised against a
     **throwaway** app first — `DELETE {"appId": …}` lets the probe clean up
     after itself — never against the real `casa-finance`.

## Implementer notes for `eb_admin.from_env()`

- Read the **refresh token**, exchange it for an ID token, use that as the
  bearer, refresh on a 401. Cache the ID token ~55 minutes.
- `op` subprocess calls **must** pass `stdin=subprocess.DEVNULL` — under a
  heredoc the child inherits exhausted stdin, `op` reads EOF and reports
  "invalid JSON provided", which reads as a malformed request rather than as a
  stdin problem.
- `op read` **appends a trailing newline**; the refresh token is rejected with
  it attached. Remove exactly one — never a general strip, which would also eat
  trailing whitespace that is part of a secret.
- The refresh token is the durable secret. Treat it like a password: never
  logged, never echoed; revoke by signing out all sessions in the control panel.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `plugins/bank-feed/server/tools_auth.py::setup_bank_feed`
- `plugins/bank-feed/server/tools_auth.py::bank_feed_signin`
- `plugins/bank-feed/server/eb_admin.py::Admin`
- `plugins/bank-feed/server/opvault.py::upsert_field`

**Tests**
- `tests/test_tools_auth.py`
- `tests/test_opvault.py`

**Related**
- [`reference/enable-banking-credentials.md`](../reference/enable-banking-credentials.md)
- [`reference/sandbox-mode.md`](../reference/sandbox-mode.md)
<!-- END SOURCEMAP -->
