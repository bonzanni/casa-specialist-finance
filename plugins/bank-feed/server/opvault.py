"""The 1Password CLI seam — the plugin's ONLY subprocess target.

Setup forges and stores its own secrets, and `op` is the mechanism.
Everything op-shaped lives here so the rules below exist in exactly one
place:

- every call passes stdin=subprocess.DEVNULL — under a heredoc the child
  inherits exhausted stdin and op reports "invalid JSON provided" (this
  cost one single-use sign-in code, live);
- `op read` appends one trailing newline; exactly one is stripped (the
  refresh token is rejected by Firebase with it attached; a PEM's interior
  newlines must survive);
- no secret VALUE ever appears in an exception — OpError carries op's
  stderr tail only;
- SSH-key items are generate-once: `op item edit` refuses them (verified
  on CLI 2.34.0), which is why there is a create call and no key-rotation
  call.

The vault is the plugin's ONE configuration element: `BANKFEED_OP_VAULT`,
set by the configurator at install time (it discovers the vault via its own
1Password tools — the operator is never asked). Item names are plugin-internal
constants; the operator never addresses the items directly. Vault layout
renamed 2026-08-05 (was `EnableBanking Production` / `Enable Banking`).
"""
from __future__ import annotations

import os
import re
import subprocess

import ebmode

ENV_VAULT_VAR = "BANKFEED_OP_VAULT"         # must equal .mcp.json's declared name

# Item names are mode-derived: one suffix rule over both items, so a sandbox
# run structurally cannot address production's items. `EnableBanking Key
# Sandbox` is the item name expected in whichever vault BANKFEED_OP_VAULT
# names; the sandbox credential item is created on first store by
# `upsert_field`. These are FUNCTIONS (and `__getattr__` names) rather than
# constants because module `__getattr__` is not consulted for the module's own
# internal global reads — both the attribute surface and the internal uses must
# go through the same helpers or they drift.
_SANDBOX_SUFFIX = " Sandbox"


def _key_item() -> str:
    base = "EnableBanking Key"               # SSH-key item; generate-once
    return base + _SANDBOX_SUFFIX if ebmode.is_sandbox() else base


def _cred_item() -> str:
    base = "EnableBanking"                   # API-credential item; editable
    return base + _SANDBOX_SUFFIX if ebmode.is_sandbox() else base


def __getattr__(name: str) -> str:
    """`VAULT`, the item names and the `REF_*` names resolve at access
    time, so the status() guard and every reference are derived from the
    same live values — an import-time snapshot could disagree with the env
    the guard checks. (The mode itself is memoized per process, so within
    one process these never change; access-time resolution is
    for the VAULT name and for tests that reset the memo.)"""
    if name == "VAULT":
        return os.environ.get(ENV_VAULT_VAR, "")
    if name == "KEY_ITEM":
        return _key_item()
    if name == "CRED_ITEM":
        return _cred_item()
    vault = os.environ.get(ENV_VAULT_VAR, "")
    if name == "REF_PRIVATE_KEY":
        return f"op://{vault}/{_key_item()}/private key"
    if name == "REF_REFRESH_TOKEN":
        return f"op://{vault}/{_cred_item()}/refresh token"
    if name == "REF_EMAIL":
        return f"op://{vault}/{_cred_item()}/username"
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

RUN = subprocess.run        # the ONE subprocess seam; tests replace it
_TIMEOUT_S = 60


# op's own not-found wordings, the ONLY evidence that may authorize a create or
# start credential acquisition: anything else (timeout, auth, rate limit)
# raises with not_found=False, because "absent" mis-read from a transient
# failure is what forges a duplicate key item over the real one. BOTH
# granularities are absence: a missing ITEM ("isn't an item") and a missing
# FIELD on an existing item — the latter is exactly what a fresh credential
# item looks like before the first store, and treating it as a fault would
# mean the sign-in dance never starts. The field wording differs per
# subcommand: `op item edit` says '"refresh token" isn't a field', while
# `op read` says "item '…' does not have a field '…'" (op CLI 2.34.0) —
# both must match.
_NOT_FOUND_RX = re.compile(
    r"isn't an item|isn't a field|does not have a field"
    r"|no item[s]? (?:found|matched)",
    re.IGNORECASE)


class OpError(RuntimeError):
    """op failed. Carries op's stderr tail (secrets redacted), never a
    field value. `not_found` is True ONLY when op explicitly said the item
    or reference does not exist."""

    def __init__(self, message: str, not_found: bool = False) -> None:
        super().__init__(message)
        self.not_found = not_found


def status():
    """None when op is usable, else one human sentence saying why not.

    The env check runs FIRST and without a subprocess: an unset service
    token is a configuration gap the operator fixes in .mcp.json wiring,
    and naming it precisely beats a generic op authentication error.
    """
    if not os.environ.get(ENV_VAULT_VAR):
        return (ENV_VAULT_VAR + " is not set — the configurator supplies "
                "the 1Password vault name at install time; without it no "
                "op:// reference can be addressed")
    if not os.environ.get("OP_SERVICE_ACCOUNT_TOKEN"):
        return ("OP_SERVICE_ACCOUNT_TOKEN is not set — the configurator "
                "must wire it through .mcp.json before setup can reach "
                "1Password")
    try:
        proc = RUN(["op", "--version"], capture_output=True, text=True,
                   stdin=subprocess.DEVNULL, timeout=_TIMEOUT_S)
    except FileNotFoundError:
        return "the `op` CLI is not installed on this host"
    except Exception:                        # noqa: BLE001
        return "the `op` CLI did not answer"
    if proc.returncode != 0:
        return "the `op` CLI is present but not functional"
    return None


def _op(args, redact=()):
    """Run op. `redact` lists secret strings that must never survive into
    the exception — op can echo a failing assignment (which carries the
    value) back through stderr, so the scrub is unconditional."""
    try:
        proc = RUN(["op", *args], capture_output=True, text=True,
                   stdin=subprocess.DEVNULL, timeout=_TIMEOUT_S)
    except FileNotFoundError:
        raise OpError("the `op` CLI is not installed") from None
    except subprocess.TimeoutExpired:
        # NEVER re-raise: TimeoutExpired carries `cmd` — the full argv,
        # including a `field[password]=<secret>` assignment. `from None` severs
        # the chain so the original exception (and its argv) cannot surface
        # through __context__.
        raise OpError("op timed out after %d s" % _TIMEOUT_S) from None
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        # Redact BEFORE selecting or truncating the tail: a refresh token
        # is longer than the 200-char error budget, and a cut taken first
        # would leave a secret PREFIX the replace can no longer match.
        for secret in redact:
            if secret:
                stderr = stderr.replace(secret, "<redacted>")
        tail = stderr.splitlines()[-1][:200] if stderr else \
            "op failed with no error output"
        raise OpError(tail, not_found=bool(_NOT_FOUND_RX.search(stderr)))
    return proc.stdout


def read(ref: str) -> str:
    """`op read <ref>`, with exactly one trailing newline removed."""
    out = _op(["read", ref])
    return out[:-1] if out.endswith("\n") else out


def item_exists(item: str, vault: str) -> bool:
    """Whether the ITEM exists at all — the forge rung's second, independent
    negative: a create is authorized only when read() said not_found AND
    this says False. A transient failure RAISES rather than answering
    "absent" — absent is a create-authorizing answer and must never come
    from a timeout."""
    try:
        _op(["item", "get", item, "--vault", vault, "--format", "json"])
    except OpError as exc:
        if exc.not_found:
            return False
        raise
    return True


def set_field(item: str, vault: str, field: str, value: str,
              concealed: bool = True) -> None:
    """`op item edit` one field. Concealed fields use the [password]
    designator (the live-proven refresh-token store); plain ones [text].
    The value rides argv — the pattern the operator recipe proved; op
    offers no stdin route for `item edit` assignments — and is redacted
    from any error text."""
    kind = "password" if concealed else "text"
    _op(["item", "edit", item, "--vault", vault,
         f"{field}[{kind}]={value}"], redact=(value,))


def upsert_field(item: str, vault: str, field: str, value: str,
                 concealed: bool = True) -> None:
    """`set_field`, creating the item when it provably does not exist.

    The credential rung's ONLY writer, in BOTH modes: the sandbox credential
    item exists in no vault yet, and a FRESH production vault
    has the same missing-item gap — without the create, an empty-vault
    dance can never go durable and every run needs a fresh sign-in email.

    The create-authorizing evidence follows this module's one rule, at
    both granularities: `_NOT_FOUND_RX` deliberately
    matches a missing ITEM and a missing FIELD alike, so the edit's own
    not_found cannot distinguish "no item" from "item without the field"
    — and `op item edit` ADDS a missing field to an existing item anyway
    (the live-proven refresh-token store), so an existing item should
    never land here. The second, independent negative is `item_exists`:
      - edit not_found AND item_exists False  -> create, field inline;
      - edit not_found BUT item_exists True   -> raise — an ambiguous
        state this function must never resolve by forging a same-titled
        sibling item;
      - any other edit failure                -> raise unchanged; a
        timeout mis-read as absence is what forges duplicates.
    """
    try:
        set_field(item, vault, field, value, concealed=concealed)
    except OpError as exc:
        if not exc.not_found:
            raise
        if item_exists(item, vault):
            raise OpError(
                "op item edit reported not-found but the item '%s' exists "
                "— refusing to create a same-titled sibling; inspect it in "
                "1Password" % item) from None
        kind = "password" if concealed else "text"
        _op(["item", "create", "--category", "API Credential",
             "--title", item, "--vault", vault,
             f"{field}[{kind}]={value}"], redact=(value,))


def create_ssh_key(title: str, vault: str) -> None:
    """Forge an RSA-4096 keypair INSIDE 1Password. The private
    key never exists outside the vault; the caller re-reads it with read()
    and must confirm it loads and signs before relying on it (the
    cross-phase invariant)."""
    _op(["item", "create", "--category", "ssh", "--title", title,
         "--vault", vault, "--ssh-generate-key", "rsa,4096"])
