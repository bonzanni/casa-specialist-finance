# Operator setup: a control-panel credential that does not expire

**The plugin drives this flow itself.** Run `setup_bank_feed`;
it sends the sign-in email and tells you exactly what to paste back (into
`bank_feed_signin`, the argument-carrying sibling — `setup_bank_feed` itself
is argument-free, per casa's setup-tool contract) — no manual `curl`/python
required. The recipe below is the **break-glass path**:
keep it for repair, for auditing what the plugin actually does, or for
running the exchange by hand if `setup_bank_feed` cannot.

**Do this once, at install time.** It replaces the hourly copy-paste with a
credential that keeps working on its own.

## Why this exists

The plugin needs Enable Banking's **control panel** API — to whitelist
accounts and register its own callback URL. That API takes a Firebase ID token
as its bearer.

The whole design rests on one assumption about that token: **it is short-lived,
on the order of an hour**, while the refresh token issued beside it is not. If
that holds, a token copied out of a browser is useless to an unattended
installation and a stored refresh token is the only workable credential — which
is what this page sets up. If it turned out not to hold, nothing here breaks:
the plugin would simply be re-minting a token that did not need re-minting. The
code does not depend on the exact lifetime; `Minter` re-mints on expiry and on a
401 either way.

This is Enable Banking's own login mechanism used the way Firebase intends —
nothing is worked around.

## Constants this recipe uses

These are the values the implementation is written against — assumptions about
the provider, not things this commit can show to be true (see
`../doctrine/publishing.md`). If one is wrong the exchange below fails with the
provider's own error rather than doing something silently different:

| | |
|---|---|
| Firebase project | `enablebanking` |
| Web API key | `AIzaSyBn8fvjRYQKslskRaO3cblUjmcyl5b9o-c` |
| Sign-in method | **email magic link** (passwordless) |

The web API key is **public by design** — it identifies the project and ships
in the control panel's own JavaScript. It is not a secret. Your **refresh
token** is; treat it like a password.

## The flow, and why it is split the way it is

An agent that both triggers a sign-in email *and* reads the mailbox for the
code is, mechanically, an account-takeover tool — so the safe machinery (this
harness, and mail connectors) correctly refuses to let software do both halves.
The design respects that instead of fighting it:

1. **The plugin triggers the email** — safe to automate. `sendOobCode` can only
   deliver a code that signs into *the same address it was sent to*; you cannot
   have someone else's link delivered to your mailbox. Worst case is an email
   you can ignore.
2. **You copy the link out of your own mail client, without opening it** — this
   is the human-in-the-loop step, and it is the one that must stay manual. Do
   **not** click it. The code is assumed single-use, so a browser visit spends
   it and hands nothing back — and the cost of being wrong about that is one
   wasted email, against a stranded setup if it is right. Copy the URL, or the
   `oobCode` out of it.
3. **The plugin exchanges the code and stores the token** — safe to automate.

> **Do not rely on an AI assistant reading the link out of your inbox.** Mail
> connectors defang authentication links in transit — observed live: the
> `oobCode` came through with its leading characters dropped and `=` rewritten
> to `~`, i.e. deliberately broken. Copy the intact URL, unopened,
> from your own mail client.

## Step 1 — trigger the email

```bash
curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=AIzaSyBn8fvjRYQKslskRaO3cblUjmcyl5b9o-c" \
  -H 'Content-Type: application/json' \
  -d '{"requestType":"EMAIL_SIGNIN","email":"YOU@example.com","continueUrl":"https://enablebanking.com/cp/"}'
```

Expect `{"kind":"...","email":"YOU@example.com"}`. A "Sign in to Enable Banking"
email arrives within seconds.

## Step 2 — get the intact link

Open the email **in your own mail client** and copy the full URL behind
"Sign in to Enable Banking". It looks like:

```
https://enablebanking.com/__/auth/action?mode=signIn&oobCode=<CODE>&apiKey=AIza...&continueUrl=...&lang=en
```

The link is **single-use and time-limited** (about an hour). Do step 3 promptly;
if it fails as expired or invalid, re-run step 1 for a fresh one.

## Step 3 — exchange and store

Paste the `<CODE>` (the `oobCode` value) into `OOB` below. This redeems it,
proves it mints a working token, and stores the durable refresh token in
1Password.

Two details the shipped code gets right and a hand-written recipe easily does
not: the credential item has to be **created when it is absent**, because a fresh
vault has no item to edit; and the token must be **redacted out of `op`'s error
output**, because a failing assignment can be echoed back in it. The item name is
mode-dependent — `EnableBanking` in production, `EnableBanking Sandbox` in
sandbox (see `sandbox-mode.md`).

The recipe below is a **simplification** of `opvault.upsert_field()`, not a copy
of it. The shipped version creates only after proving absence twice — a
recognised not-found from the edit, then an `op item get` that also finds
nothing — and raises on anything ambiguous, so an authentication failure or a
timeout never becomes a duplicate item. Use the plugin's own path where you can;
if you run this by hand and the edit fails for any reason other than a missing
item, stop and read the error rather than letting it create.

The `op` calls below need a 1Password service-account token in the
environment. Load it however your installation supplies one — a service
account, `op signin`, or exporting `OP_SERVICE_ACCOUNT_TOKEN` yourself — and
set `VAULT` to the vault the plugin is configured with (`BANKFEED_OP_VAULT`).

```bash
VAULT="${BANKFEED_OP_VAULT:?set this to your 1Password vault}" \
OOB='<paste the oobCode here>' EB_EMAIL='YOU@example.com' python3 - <<'PY'
import json, os, subprocess, urllib.request, urllib.parse, urllib.error
K = "AIzaSyBn8fvjRYQKslskRaO3cblUjmcyl5b9o-c"
def post(url, payload, form=False):
    body = urllib.parse.urlencode(payload).encode() if form else json.dumps(payload).encode()
    ct = "application/x-www-form-urlencoded" if form else "application/json"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": ct})
    try:
        with urllib.request.urlopen(req, timeout=25) as r: return json.loads(r.read())
    except urllib.error.HTTPError as e: return json.loads(e.read())

r = post(f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithEmailLink?key={K}",
         {"email": os.environ["EB_EMAIL"], "oobCode": os.environ["OOB"]})
if r.get("error"): raise SystemExit("exchange failed: " + r["error"]["message"])
rt = r["refreshToken"]

v = post(f"https://securetoken.googleapis.com/v1/token?key={K}",
         {"grant_type": "refresh_token", "refresh_token": rt}, form=True)
if not v.get("id_token"): raise SystemExit("refresh proof failed")

# stdin=DEVNULL is REQUIRED: under a heredoc the child would inherit exhausted
# stdin, op would read EOF and report "invalid JSON provided".
vault = os.environ["VAULT"]
item = os.environ.get("EB_ITEM", "EnableBanking")   # "EnableBanking Sandbox" in sandbox

def op(args):
    w = subprocess.run(["op", *args], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL)
    # NEVER print op's stderr raw: a failing field assignment can be echoed back
    # with the value in it. opvault.OpError redacts for the same reason.
    return w.returncode, w.stderr.strip().replace(rt, "<redacted>")

field = f"refresh token[password]={rt}"
rc, err = op(["item", "edit", item, "--vault", vault, field])
if rc:
    # Create ONLY on proven absence, the way upsert_field() does: an ambiguous
    # failure (auth, timeout) must not become a duplicate item.
    if "isn't an item" not in err and "not found" not in err.lower():
        raise SystemExit("store failed: " + err)
    probe, probe_err = op(["item", "get", item, "--vault", vault])
    if probe == 0: raise SystemExit("item exists but the edit failed: " + err)
    rc, err = op(["item", "create", "--category", "API Credential",
                  "--title", item, "--vault", vault, field])
if rc: raise SystemExit("store failed: " + err)
print(f"stored op://{vault}/{item}/refresh token — mints a fresh token,"
      " expires_in", v["expires_in"])
PY
```

Then delete the old 1-hour `credential` field so nothing keeps using the stale
path.

## Verifying and revoking

Verify (the stored token must mint a fresh ID token):

```bash
RT="$(op read "op://${BANKFEED_OP_VAULT}/EnableBanking/refresh token")"
curl -s -X POST \
  "https://securetoken.googleapis.com/v1/token?key=AIzaSyBn8fvjRYQKslskRaO3cblUjmcyl5b9o-c" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$RT" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('expires_in:',d.get('expires_in'),'ok:',bool(d.get('id_token')))"
```

Expect `expires_in: 3600 ok: True`. `INVALID_REFRESH_TOKEN` means it was
revoked or is stale — redo from step 1.

To **revoke**: sign out of all sessions in the Enable Banking control panel.
That invalidates every refresh token the account has issued.

## Note for the implementer

`op read` appends a trailing newline and the refresh token is **rejected** with
it attached, so the value must be read through `opvault.read()`, which removes
**exactly one** trailing newline. Never a general strip: a secret may legitimately
end in whitespace, and a key's interior newlines have to survive.

The refresh path **is** wired: `from_env()`'s rung 1 reads the stored refresh
token, exchanges it at `securetoken.googleapis.com` for an ID token, caches that
for roughly its lifetime, and refreshes on a 401. It falls back to a pasted
`CASA_BANKFEED_EB_CP_TOKEN` (rung 2) whenever no stored token can be proven
usable — not only when none is stored.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `plugins/bank-feed/server/fbauth.py::send_signin_email`
- `plugins/bank-feed/server/fbauth.py::exchange_link`
- `plugins/bank-feed/server/fbauth.py::mint_id_token`
- `plugins/bank-feed/server/fbauth.py::Minter`
- `plugins/bank-feed/server/eb_admin.py::from_env`

**Tests**
- `tests/test_fbauth.py`
- `tests/test_eb.py`

**Related**
- [`reference/setup-flow.md`](../reference/setup-flow.md)
<!-- END SOURCEMAP -->
