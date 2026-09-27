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

The vault comes from casa: `ONEPASSWORD_DEFAULT_VAULT`, a casa-owned variable
exported from casa's `onepassword_default_vault` app option, so the vault name
is no longer something an install has to wire or ask about (casa's own
exploration still searches for the setup-provisioned credentials, which nothing
here wires). `BANKFEED_OP_VAULT` is an optional override:
when it is set and non-empty it wins, and an empty one is the same as an unset
one. `_vault()` is the one place that choice is made. Item names are
plugin-internal constants; the operator never addresses the items directly. Vault layout
renamed 2026-08-05 (was `EnableBanking Production` / `Enable Banking`).
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import subprocess

import ebmode

ENV_VAULT_VAR = "BANKFEED_OP_VAULT"         # optional override; must equal .mcp.json's key
ENV_DEFAULT_VAULT_VAR = "ONEPASSWORD_DEFAULT_VAULT"   # casa-owned; the default

# Item names are mode-derived: one suffix rule over both items, so a sandbox
# run structurally cannot address production's items. `EnableBanking Key
# Sandbox` is the item name expected in whichever vault `_vault()` resolves
# to; the sandbox credential item is created on first store by
# `upsert_field`. These are FUNCTIONS (and `__getattr__` names) rather than
# constants because module `__getattr__` is not consulted for the module's own
# internal global reads — both the attribute surface and the internal uses must
# go through the same helpers or they drift.
_SANDBOX_SUFFIX = " Sandbox"


def _vault() -> str:
    """The vault every op:// reference is built from: the override when it is
    set and non-empty, else casa's default vault, else empty. Read at every
    call — `VAULT`, each `REF_*` and `status()` all come through here, so the
    guard and the references can never disagree about which vault is in
    play."""
    return (os.environ.get(ENV_VAULT_VAR)
            or os.environ.get(ENV_DEFAULT_VAULT_VAR)
            or "")


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
        return _vault()
    if name == "KEY_ITEM":
        return _key_item()
    if name == "CRED_ITEM":
        return _cred_item()
    vault = _vault()
    if name == "REF_PRIVATE_KEY":
        return f"op://{vault}/{_key_item()}/private key"
    if name == "REF_REFRESH_TOKEN":
        return f"op://{vault}/{_cred_item()}/refresh token"
    if name == "REF_EMAIL":
        return f"op://{vault}/{_cred_item()}/username"
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

RUN = subprocess.run        # the ONE subprocess seam; tests replace it
_TIMEOUT_S = 60

#: The descriptors every `op` child inherits: the dispatcher sets the call's
#: lifecycle-lock descriptor here (`bank_feed_server.handle`). A lock is held
#: by an open file description, so the child holding it keeps the call's
#: shared lock alive after its parent dies, and `delete_all_data` cannot list
#: the vault while an `op item create` it would have to see is still running.
INHERIT_FDS: tuple = ()


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
    if not _vault():
        return ("no 1Password vault is configured — casa's "
                "onepassword_default_vault app option supplies it (as "
                + ENV_DEFAULT_VAULT_VAR + ") and " + ENV_VAULT_VAR +
                " overrides it; without one no op:// reference can be "
                "addressed")
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
    extra = {"pass_fds": INHERIT_FDS} if INHERIT_FDS else {}
    try:
        proc = RUN(["op", *args], capture_output=True, text=True,
                   stdin=subprocess.DEVNULL, timeout=_TIMEOUT_S, **extra)
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
        tag = _record_creation(item, vault)
        _op(["item", "create", "--category", "API Credential",
             "--title", item, "--vault", vault, "--tags", tag,
             f"{field}[{kind}]={value}"], redact=(value,))


def create_ssh_key(title: str, vault: str) -> None:
    """Forge an RSA-4096 keypair INSIDE 1Password. The private
    key never exists outside the vault; the caller re-reads it with read()
    and must confirm it loads and signs before relying on it (the
    cross-phase invariant)."""
    tag = _record_creation(title, vault)
    _op(["item", "create", "--category", "ssh", "--title", title,
         "--vault", vault, "--tags", tag, "--ssh-generate-key", "rsa,4096"])


# THE CREATION RECORD (issue #72). `delete_all_data` is the clean slate, and
# it deletes the vault items bank-feed created and ONLY those: an item the
# operator made by hand is never touched. So a creation is recorded, and the
# record is written BEFORE the create. Written after it, a process ending
# between the two would leave an item bank-feed made that no erasure could
# know about.
#
# A line alone does not prove an item is ours: the process may have ended
# before the create ran. So the item carries the line's nonce as a tag, and
# the erasure deletes only items whose tags contain that exact tag. An empty
# listing means the create never landed or the item is already gone, and
# either way the line has nothing left to do.
#
# The record lives in the plugin's data directory, OUTSIDE the ledger:
# `restore_backup`, `purge` and the row erasure rewrite the ledger's rows and
# must never be able to drop a line.
RECORD_FILENAME = "vault-items.jsonl"
NONCE_TAG_PREFIX = "bank-feed-"
_NONCE_RX = re.compile(r"[0-9a-f]{16}")


class RecordError(OpError):
    """The creation record could not be read or written. No create runs."""


def record_path():
    # The RAW variable, as the dispatcher's lock and `tools_read.conn()` read
    # it: a normalised spelling could name another directory.
    data = os.environ.get("CLAUDE_PLUGIN_DATA") or ""
    if not data:
        raise RecordError("CLAUDE_PLUGIN_DATA is not set, so a vault item "
                          "created now could not be recorded for the erasure "
                          "to find; nothing was created")
    return os.path.join(data, RECORD_FILENAME)


def _open_record(create: bool):
    """The record, locked exclusively, with a torn tail cut off. -> fd, or
    None when it does not exist and `create` is False.

    A line is whole or absent. A process that ended part way through an
    append leaves bytes with no newline, and the next append would complete
    them into a malformed line that hides a real nonce. So every opener cuts
    back to the last newline first, under the lock, before anything else."""
    flags = os.O_RDWR | (os.O_CREAT if create else 0)
    try:
        fd = os.open(record_path(), flags | os.O_NOFOLLOW, 0o600)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RecordError("the vault creation record could not be opened "
                          "(%s)" % os.strerror(exc.errno)) from None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        data = _read_all(fd)
        if data and not data.endswith(b"\n"):
            os.ftruncate(fd, data.rfind(b"\n") + 1)
            os.fsync(fd)
    except OSError as exc:
        os.close(fd)
        raise RecordError("the vault creation record could not be prepared "
                          "(%s)" % os.strerror(exc.errno)) from None
    return fd


def _read_all(fd) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _parse(data: bytes) -> list:
    """Every line, parsed. A complete line that is not a record refuses:
    skipping it would drop the one proof that an item is ours."""
    lines = []
    for raw in data.split(b"\n"):
        if not raw:
            continue
        try:
            line = json.loads(raw.decode("utf-8"))
            ok = (isinstance(line, dict)
                  and all(isinstance(line.get(k), str) and line.get(k)
                          for k in ("nonce", "vault", "title"))
                  and _NONCE_RX.fullmatch(line["nonce"]))
        except (UnicodeDecodeError, ValueError):
            ok = False
        if not ok:
            raise RecordError("the vault creation record holds a line that "
                              "is not a record")
        lines.append(line)
    return lines


def _record_creation(title: str, vault: str) -> str:
    """Append and flush one line; -> the tag the create must carry. Raises
    RecordError, and then no create runs."""
    nonce = secrets.token_hex(8)
    line = (json.dumps({"nonce": nonce, "vault": vault, "title": title,
                        "mode": ebmode.mode()}, sort_keys=True) + "\n"
            ).encode("utf-8")
    fd = _open_record(create=True)
    try:
        _parse(_read_all(fd))            # a record that is not whole refuses
        start = os.fstat(fd).st_size
        try:
            os.lseek(fd, start, os.SEEK_SET)
            view = memoryview(line)
            while view:
                n = os.write(fd, view)
                if n <= 0:
                    raise OSError(5, "a write made no progress")
                view = view[n:]
            os.fsync(fd)
        except OSError as exc:
            try:
                os.ftruncate(fd, start)
                os.fsync(fd)
            except OSError:
                pass                     # the next opener cuts the torn tail
            raise RecordError("the vault creation record could not be "
                              "written (%s); nothing was created"
                              % os.strerror(exc.errno)) from None
    finally:
        os.close(fd)
    return NONCE_TAG_PREFIX + nonce


def _tagged(vault: str, tag: str) -> list:
    """The ids of the items carrying `tag` EXACTLY. op also returns items
    tagged `<tag>/<sub>`, and excludes archived items unless asked."""
    out = _op(["item", "list", "--vault", vault, "--tags", tag,
               "--include-archive", "--format", "json"])
    # ANY SHAPE BUT THE EXPECTED ONE IS A FAILURE, never an empty answer: an
    # empty listing is what drops a record line, so reading one into silence
    # (no output, an item without tags) would lose the proof that an item
    # still standing is ours. And membership is tested on a list of strings
    # only: `in` on a string is a substring test, which a nested tag passes.
    try:
        items = json.loads(out)
    except (TypeError, ValueError):
        raise OpError("op item list did not answer with JSON") from None
    if not isinstance(items, list):
        raise OpError("op item list did not answer with a list")
    ids = []
    for item in items:
        tags = item.get("tags") if isinstance(item, dict) else None
        if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                or not item["id"] or not isinstance(tags, list)
                or not all(isinstance(t, str) for t in tags)):
            raise OpError("op item list answered an item of an unexpected "
                          "shape")
        if tag in tags:
            ids.append(item["id"])
    return ids


def erase_recorded() -> tuple:
    """Delete every item the record proves bank-feed created. -> `(gone,
    kept)`: titles proven gone, and `(title, reason)` for what is not. Never
    raises. Each line is dropped only once a listing shows no item carries
    its tag, so a failure keeps it for the next call."""
    try:
        fd = _open_record(create=False)
    except RecordError as exc:
        return [], [("the vault creation record", str(exc))]
    if fd is None:
        return [], []
    try:
        try:
            lines = _parse(_read_all(fd))
        except (RecordError, OSError) as exc:
            return [], [("the vault creation record", str(exc))]
        gone, kept, left = [], [], []
        reason = status() if lines else None
        for line in lines:
            tag = NONCE_TAG_PREFIX + line["nonce"]
            if reason is not None:
                kept.append((line["title"], reason))
                left.append(line)
                continue
            try:
                ids = _tagged(line["vault"], tag)
                for item_id in ids:
                    _op(["item", "delete", item_id, "--vault", line["vault"]])
                if ids and _tagged(line["vault"], tag):
                    raise OpError("an item is still listed after its deletion")
            except OpError as exc:
                kept.append((line["title"], str(exc)))
                left.append(line)
                continue
            if ids:
                gone.append(line["title"])
        # Replaced whole, never truncated in place: a rewrite that failed
        # part way would otherwise lose the very lines it was keeping. The
        # caller holds the exclusive lifecycle lock, so no append can land
        # on the old file between the read above and the rename.
        try:
            path = record_path()
            if left:
                body = "".join(json.dumps(x, sort_keys=True) + "\n"
                               for x in left).encode("utf-8")
                tmp = path + ".tmp"
                tfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                              | os.O_NOFOLLOW, 0o600)
                try:
                    view = memoryview(body)
                    while view:
                        view = view[os.write(tfd, view):]
                    os.fsync(tfd)
                finally:
                    os.close(tfd)
                os.replace(tmp, path)
            else:
                os.unlink(path)
            dfd = os.open(os.path.dirname(path), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError as exc:
            kept.append(("the vault creation record",
                         "it could not be rewritten (%s)"
                         % os.strerror(exc.errno)))
        return gone, kept
    finally:
        os.close(fd)
