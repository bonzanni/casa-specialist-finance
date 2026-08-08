# plugins/bank-feed/server/eb_admin.py
"""Enable Banking control-panel calls. Credential: a minted ID token from
the stored refresh token (rung 1), or the operator's pasted CP token
(rung 2).

Loaded for setup and repair only, and never held by the steady-state data
path. The link redirect is fixed by the provider — every alternative
was rejected with REDIRECT_URI_NOT_ALLOWED, including URLs correctly
registered in the application's own redirect_urls.

The manifest's `.mcp.json` declares this credential as
`CASA_BANKFEED_EB_CP_TOKEN` — that is the ONLY name production may read for
it. `from_env()` below is the one place an `Admin` is constructed from the
environment; a caller that instead does `Admin(os.environ["SOME_OTHER_NAME"])`
would silently reintroduce the exact defect a previous round shipped
(manifest declared `CASA_BANKFEED_EB_CP_TOKEN`, the admin client read
`CASA_BANKFEED_EB_ADMIN_TOKEN`, so production could never populate the token
the code actually read and tap 1 — whitelisting — could never start).
"""
from __future__ import annotations

import json
import os

import eb_ais            # one error taxonomy, defined once (see error_kind)
import httpx
import fbauth
import opvault

CP_HOST = "enablebanking.com"
LINK_REDIRECT = "https://enablebanking.com/api/auth_redirect"
ENV_TOKEN_VAR = "CASA_BANKFEED_EB_CP_TOKEN"     # must equal .mcp.json's declared name


class AdminTokenMissing(RuntimeError):
    """No usable Enable Banking admin credential: no working refresh token
    is stored in 1Password -- `from_env`'s rung 2,
    adopted only once it is PROVEN to mint -- AND CASA_BANKFEED_EB_CP_TOKEN
    is unset. Setup and repair cannot proceed -- tap 1 (whitelisting) can
    never start without one of the two."""

# The allowlist. Application DELETE is absent on purpose: it is the
# genuinely session-orphaning operation (Enable Banking does not document the
# application<->session binding, and re-registration very likely orphans every
# existing bank session). The allowlist is the mechanism that makes
# that true rather than a convention someone can forget.
#
# PATCH on the COLLECTION url (`/api/applications`, id in the body as `appId`)
# IS allowed, narrowly: it is the only way this plugin can self-register casa's
# AIS callback redirect URI, which is why `add_redirect_url` below exists. It
# is still not a general-purpose application editor -- see that method's
# docstring for the read-modify-write contract it enforces on every call.
#
# POST on the COLLECTION url admits application REGISTRATION -- the reconcile
# rung that creates the app when none exists yet. It is existence-checked and
# duplicate-guarded by `create_application`'s caller contract, and key-first
# per the cross-phase invariant (private key persisted and re-read from the
# vault before this is ever called). DELETE remains absent ON PURPOSE: deletion
# orphans every session riding the app and stays operator-only, and this
# allowlist is still the mechanism that makes that true rather than a
# convention someone can forget.
ALLOW = {
    ("GET", r"^/api/applications$"),
    ("GET", r"^/api/application/[A-Za-z0-9-]+$"),
    ("PATCH", r"^/api/applications$"),
    ("POST", r"^/api/applications$"),
    ("POST", r"^/api/link_accounts$"),
    ("POST", r"^/api/unlink_accounts$"),
}


class AdminError(RuntimeError):
    """Status and class only — same rule and same taxonomy as ApiError."""

    def __init__(self, status: int, op: str) -> None:
        self.status = int(status)
        self.kind = eb_ais.error_kind(self.status)
        self.op = op
        super().__init__(f"Enable Banking admin {op} failed: "
                         f"HTTP {self.status} ({self.kind})")


class Admin:
    def __init__(self, token: str | None = None, minter=None) -> None:
        if (token is None) == (minter is None):
            raise ValueError("exactly one of token= or minter= is required")
        self.token = token
        self.minter = minter
        self.client = httpx.Client(CP_HOST, ALLOW)

    def _bearer(self) -> str:
        return self.token if self.token is not None else self.minter.token()

    def _send(self, op: str, method: str, path: str, *,
              json_body=None, form_body=None):
        """The ONE status check in this module. link/unlink are
        form-encoded and the reads are JSON; that is a parameter, not a
        reason to re-implement the error path once per verb.

        A 401 under a minted bearer is re-minted and re-sent EXACTLY once:
        the cached ID token can expire between our cache check and the
        provider's clock, and a Bearer 401 means the request was rejected
        before acting, so one re-send is safe even for the non-idempotent
        POSTs. A second 401 is a real authorization failure and raises.
        A pasted token is never retried — there is nothing to re-mint."""
        status, raw = self.client.request(
            method, path,
            headers={"Authorization": f"Bearer {self._bearer()}"},
            json_body=json_body, form_body=form_body)
        if status == 401 and self.minter is not None:
            self.minter.invalidate()
            status, raw = self.client.request(
                method, path,
                headers={"Authorization": f"Bearer {self._bearer()}"},
                json_body=json_body, form_body=form_body)
        if status >= 400:
            raise AdminError(status, op)
        return json.loads(raw or b"{}")

    def applications(self) -> list:
        data = self._send("applications", "GET", "/api/applications")
        # The provider has been observed to answer with a bare list and with
        # an {"applications": [...]} envelope, so tolerate both shapes.
        return list(data.get("applications") or []) if isinstance(data, dict) else list(data)

    def application(self, app_id: str) -> dict:
        return self._send("application", "GET",
                          f"/api/application/{eb_ais.validate_path_id(app_id)}")

    def whitelisted(self, app_id: str) -> list:
        """The authoritative "is this account linked?" check.

        `whitelisted_accounts` is exposed ONLY here: the app-key
        GET /application does not carry it, which is why bank linking is
        admin-credentialed end to end. The `identification_hash` here is
        opaque to us -- we make no claim about how the provider derives it or
        whether it is guessable. What actually secures `unlink_account` is
        sourcing, not the hash's shape: a hash must be read from THIS
        method's output and never accepted as a bare caller-supplied value.
        """
        return list(self.application(app_id).get("whitelisted_accounts") or [])

    def link_accounts(self, app_id: str, aspsp: str, country: str,
                      psu_type: str) -> dict:
        return self._send("link_accounts", "POST", "/api/link_accounts",
                          form_body={"country": country, "aspsp": aspsp,
                                     "appId": app_id, "psuType": psu_type,
                                     "redirectUrl": LINK_REDIRECT})

    def unlink_account(self, app_id: str, identification_hash: str) -> dict:
        return self._send("unlink_account", "POST", "/api/unlink_accounts",
                          form_body={"appId": app_id,
                                     "identificationHash": identification_hash})

    # Fields never written back on a repair: `whitelisted_accounts` is
    # read-only administrative state, and the id travels as `appId` in the body
    # -- not the pre-existing `app_id` key, and never in the path (both
    # `PATCH/PUT /api/application/{id}` and `PATCH /api/applications/{id}` were
    # probed live and both 4xx).
    _NOT_WRITABLE = {"whitelisted_accounts", "app_id"}

    def add_redirect_url(self, app_id: str, redirect_uri: str) -> dict:
        """Self-register casa's AIS callback redirect URI.

        Read-modify-write, and the ONLY
        write this module performs against `/api/applications`.

        Read: `GET /api/application/{app_id}`. If `redirect_uri` is already
        in the application's `redirect_urls`, this is a no-op -- no write
        request is made, nothing changes, and the caller can tell exactly
        that from the returned `changed: False`.

        Write (only when absent): `PATCH /api/applications` with the
        COMPLETE object read above, `redirect_urls` replaced by the
        COMPLETE desired set (every existing URL plus this one -- a PATCH
        replaces the list wholesale, so a partial send would silently drop
        working callbacks), and every other field round-tripped verbatim
        except `_NOT_WRITABLE` above. Round-tripping unconditionally (rather
        than hand-picking `description`/`gdpr_email`/`privacy_url`/
        `terms_url`) is what a production PATCH needs to avoid "Description
        must be set", and hand-picking is exactly how a field gets left out
        and silently written back as undefined.

        Never registers a new application, never deletes one, never touches
        any field but `redirect_urls` -- both by contract here and because
        POST/DELETE on this path are simply not in `ALLOW`.
        """
        app = self.application(app_id)
        existing = list(app.get("redirect_urls") or [])
        if redirect_uri in existing:
            return {"changed": False, "redirect_urls": existing}
        desired = existing + [redirect_uri]
        body = {k: v for k, v in app.items() if k not in self._NOT_WRITABLE}
        body["appId"] = app_id
        body["redirect_urls"] = desired
        self._send("update_application", "PATCH", "/api/applications",
                   json_body=body)
        return {"changed": True, "redirect_urls": desired}

    def create_application(self, name: str, certificate: str,
                           redirect_urls: list,
                           environment: str = "PRODUCTION") -> str:
        """Register a NEW application, in the shape verified live:
        POST /api/applications {certificate, environment, name,
        redirect_urls} → {"app_id": …}. The certificate is a bare SPKI
        public-key PEM (no X.509 — verified). The new app starts Inactive
        and the first completed link_accounts flips it active, so
        creation needs no control-panel visit.

        Caller contract, and it is an invariant rather than a preference:
        never call this before the private key is PERSISTED AND RE-READ
        from the vault, and never without first checking applications()
        for an existing app of this name — duplicate registration is how
        repeated repairs silently accumulate applications."""
        data = self._send("create_application", "POST", "/api/applications",
                          json_body={"certificate": certificate,
                                     "environment": environment,
                                     "name": name,
                                     "redirect_urls": list(redirect_urls)})
        app_id = data.get("app_id")
        if not app_id:
            raise RuntimeError(
                "application registration returned no app_id — the app may "
                "or may not exist; check GET /api/applications before "
                "retrying, and do NOT re-register blindly")
        return str(app_id)


_MINTER = None            # process-wide: the ~55-min cache must survive
                          # across tool calls; tests reset it to None


def prime_minter(refresh_token: str) -> None:
    """Adopt an in-memory, ALREADY-PROVEN refresh token for the rest of
    this process. setup_bank_feed calls this when it acquired and proved a
    token but could not store it durably — without this, 'the run
    continues on the in-memory credential' would be a report line with no
    mechanism behind it. The primed minter
    does not re-read the vault; durability still requires a successful
    store on a later run."""
    global _MINTER
    _MINTER = fbauth.Minter(lambda: refresh_token)


def drop_minter() -> None:
    """Forget the process's adopted/primed minter. setup calls this the
    moment it PROVES the stored refresh token is revoked — a cached
    minter would otherwise keep re-minting the dead token on every 401,
    and from_env, which returns the cached minter first, would never
    fall through to the pasted CP token. After the
    drop, the next construction re-proves the vault token, fails, and
    lands on the env-token rung."""
    global _MINTER
    _MINTER = None


def from_env() -> Admin:
    """The ladder, durable rung first:

    1. an already-proven minter for this process (primed by setup, or
       adopted below on a previous construction) -- but only after it is
       RE-proven here too: a cached minter whose
       refresh token was revoked since adoption (e.g. the vault token
       rotated after adoption) would otherwise be returned on mere
       EXISTENCE forever, permanently shadowing a working rotated vault
       token or a pasted CP token. The re-proof is `.token()`, which is
       cache-aware and costs nothing while the cached ID token is still
       fresh -- so the common case pays no extra mint;
    2. a refresh token stored in the vault — adopted ONLY after it is
       PROVEN to mint. Adopting on mere presence would let a stored-but-
       REVOKED token shadow a perfectly good pasted CP token forever
       -- the ladder's whole point is falling through to
       the next rung when a rung is broken, and presence is a proxy --
       minting is the truth;
    3. the declared env token (CASA_BANKFEED_EB_CP_TOKEN -- the ONLY env
       name this module may read), pasted and ~1 h-lived;
    4. else refuse, naming both remedies.

    The rung-2 proof is one mint per process (the adopted Minter starts
    with that token cached ~55 min) -- setup and link paths only, never
    the steady-state data path."""
    global _MINTER
    if _MINTER is not None:
        try:
            _MINTER.token()                    # RE-prove the cache, not just its presence
        except (fbauth.AuthError, opvault.OpError):
            _MINTER = None                     # corpse -- fall through the ladder
        else:
            return Admin(minter=_MINTER)
    if opvault.status() is None:
        try:
            opvault.read(opvault.REF_REFRESH_TOKEN)
        except opvault.OpError:
            pass
        else:
            candidate = fbauth.Minter(
                lambda: opvault.read(opvault.REF_REFRESH_TOKEN))
            try:
                candidate.token()          # PROVE it mints before adopting
            except (fbauth.AuthError, opvault.OpError):
                pass                       # revoked/stale -- next rung
            else:
                _MINTER = candidate
                return Admin(minter=_MINTER)
    token = os.environ.get(ENV_TOKEN_VAR)
    if token:
        return Admin(token=token)
    raise AdminTokenMissing(
        "no Enable Banking admin credential: no working refresh token is "
        "stored in 1Password (run setup_bank_feed to acquire one -- durable, "
        f"one copy/paste) and {ENV_TOKEN_VAR} is not set (a pasted "
        "control-panel token lasts ~1 h). Bank whitelisting and "
        "application repair cannot proceed")
