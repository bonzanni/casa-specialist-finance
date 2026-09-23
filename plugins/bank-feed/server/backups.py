"""Backups, the event index beside the ledger, settlement, and the restore.

Standard library only, and it imports NO other plugin module: `store.open_db`
calls `settle`, so an import of `store` from here would be a cycle.

THE INDEX IS BESIDE THE DATABASE so a restore cannot erase the record of
itself. Append-only, one record per line, every append fsynced, and no field
may contain whitespace: ids are hex, timestamps basic-ISO UTC, reasons a
closed set plus a charset-constrained workflow string (WORKFLOW_RE).

LOCK ORDER, FIXED EVERYWHERE: the ledger's writer lock (BEGIN IMMEDIATE on the
caller's connection) FIRST, the index lock SECOND. `settle` is the ONE place
the index lock is taken; every other operation receives the handle it
returns. flock is not re-entrant within a process (a second descriptor
blocks), so the acquisition is non-blocking with a bounded wait and a second
attempt is a refusal, never a hang.
"""
from __future__ import annotations

import errno
import fcntl
import os
import re
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path


class BackupError(Exception):
    """Every refusal this module makes. Text is ours; never a provider's.

    `written` is the one fact a caller cannot recover from the text: whether
    the bytes of a failed `append` REACHED THE FILE before the failure. An
    fsync that fails after its write leaves a readable line, so the operation
    that line records is still going to happen — at the next settlement, in
    whatever process gets there first. A caller that reports "nothing
    happened" off a failed append is right only when `written` is False.
    """

    def __init__(self, message: str = "", *, written: bool = False):
        super().__init__(message)
        self.written = written


INDEX_HEADER = "bank-feed backup index v1"
OP_ID_RE = re.compile(r"^[0-9a-f]{16}$")
TS_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
WORKFLOW_RE = re.compile(
    r"^[a-z][a-z0-9_-]{0,23}@[A-Za-z0-9][A-Za-z0-9.+_-]{0,31}$")
REASONS = ("weekly", "manual")
INSTALL_PREFIX = "install:"
MARKER_KEY = "backup_restore_op"
REGISTRATIONS_TABLE = "workflow_registrations"
LOCK_WAIT_S = 10.0
_LOCK_POLL_S = 0.05

_TERMINAL = {"backup": ("committed", "aborted", "orphan"),
             "restore": ("committed", "aborted"),
             # An erasure has NO `aborted`. Its `pending` record is written as
             # the last statement before the erasure's ledger COMMIT, so by
             # the time the record is durable the operator has already
             # authorised the erasure; a terminal that could cancel one would
             # be a way for a crash to leave a restorable whole-ledger copy
             # behind, which is the single thing an erasure promises cannot
             # survive it. Once pending, an erasure is always completed.
             "erase": ("committed",)}


def now_ts() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def new_op_id() -> str:
    return secrets.token_hex(8)


def reason_is_valid(reason: str) -> bool:
    if reason in REASONS:
        return True
    return (reason.startswith(INSTALL_PREFIX)
            and WORKFLOW_RE.fullmatch(reason[len(INSTALL_PREFIX):]) is not None)


class Paths:
    def __init__(self, db_path):
        self.db = Path(db_path)
        self.index = self.db.parent / (self.db.name + ".backup-index")
        self.backups_dir = self.db.parent / (self.db.name + ".backups")

    def backup_file(self, op_id: str) -> Path:
        return self.backups_dir / ("%s.sqlite" % op_id)

    def partial_file(self, op_id: str) -> Path:
        return self.backups_dir / ("%s.sqlite.partial" % op_id)


def paths_for(db_path) -> Paths:
    return Paths(db_path)


def _oserr(exc) -> str:
    return errno.errorcode.get(getattr(exc, "errno", None), str(exc))


def _refuse_symlink(p: Path) -> None:
    try:
        st = os.lstat(str(p))
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise BackupError("refusing %s: it is a symlink" % p.name)


def _fsync_dir(d: Path) -> None:
    fd = os.open(str(d), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _prepare(paths: Paths) -> None:
    _refuse_symlink(paths.backups_dir)
    _refuse_symlink(paths.index)
    try:
        paths.backups_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(str(paths.backups_dir), 0o700)
        # A freshly-created directory ENTRY is not durable until its PARENT
        # is fsynced -- that metadata lives in the parent's own blocks, not
        # the new directory's. Harmless to call unconditionally when the
        # directory already existed.
        _fsync_dir(paths.backups_dir.parent)
    except OSError as exc:
        raise BackupError("cannot prepare the backups directory: %s"
                          % _oserr(exc)) from None


def _acquire_index(paths: Paths) -> int:
    """The ONE acquisition site. O_APPEND so a write after the torn-tail
    truncation lands at the real end, never past a NUL hole. Non-blocking,
    bounded: flock is not re-entrant in-process, and a blocking call from a
    path that already holds it would hang the MCP server for ever."""
    try:
        fd = os.open(str(paths.index),
                     os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise BackupError("refusing %s: it is a symlink" % paths.index.name
                              ) from None
        raise BackupError("cannot open the backup index: %s" % _oserr(exc)
                          ) from None
    deadline = time.monotonic() + LOCK_WAIT_S
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() >= deadline:
                os.close(fd)
                raise BackupError(
                    "the backup index is busy (another backup, restore or "
                    "listing holds it); nothing was changed — try again"
                    ) from None
            time.sleep(_LOCK_POLL_S)
    try:
        os.fchmod(fd, 0o600)
        # Same durability note as `_prepare`: a freshly-CREATED index
        # file's directory entry needs its parent fsynced, or a crash right
        # after can lose the entry even though the header write below is
        # itself fsynced.
        _fsync_dir(paths.index.parent)
    except OSError as exc:
        os.close(fd)
        raise BackupError("cannot prepare the backup index: %s" % _oserr(exc)
                          ) from None
    return fd


class IndexHandle:
    """The held index lock plus the parsed records. Appends go through it."""

    def __init__(self, fd: int, paths: Paths, records: list):
        self.fd = fd
        self.paths = paths
        self.records = records
        self._open = True

    def append(self, *fields: str) -> None:
        for f in fields:
            if not f or any(ch.isspace() for ch in f):
                raise BackupError("index field is empty or carries whitespace")
        line = now_ts() + " " + " ".join(fields) + "\n"
        # THE TWO FAILURES ARE NOT THE SAME EVENT, so they do not leave the
        # same exception. A failed `write` wrote nothing (O_APPEND, one line,
        # one call) and the record does not exist. A failed `fsync` follows a
        # write that LANDED: the line is already readable by the next process
        # to parse this file, which will act on it, so a caller reporting
        # "nothing happened" would be describing an operation still in flight.
        try:
            os.write(self.fd, line.encode("ascii"))
        except OSError as exc:
            raise BackupError("the backup index could not be written: %s"
                              % _oserr(exc), written=False) from None
        try:
            os.fsync(self.fd)
        except OSError as exc:
            raise BackupError("the backup index could not be flushed: %s"
                              % _oserr(exc), written=True) from None

    def close(self) -> None:
        if self._open:
            self._open = False
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _parse(raw: bytes) -> list:
    """-> records; raises BackupError on anything that does not parse.
    A trailing partial line (no newline) is tolerated ONLY as the last
    line — the caller truncates it. Fail closed on everything else: a
    generation that cannot be computed is never guessed."""
    text = raw.decode("utf-8", errors="strict") if raw else ""
    lines = text.split("\n")
    complete, torn = lines[:-1], lines[-1]
    if not complete and not torn:
        return []
    if complete[0] != INDEX_HEADER:
        raise BackupError("the backup index is unreadable (bad header)")
    records = []
    seen_terminal = set()
    seen_pending = set()
    for n, line in enumerate(complete[1:], start=2):
        parts = line.split(" ")
        if len(parts) < 4 or not TS_RE.fullmatch(parts[0]) \
                or parts[1] not in _TERMINAL or not OP_ID_RE.fullmatch(parts[2]):
            raise BackupError("the backup index is unreadable (line %d)" % n)
        ts, kind, op, state = parts[0], parts[1], parts[2], parts[3]
        # `seq` is the record's position in the index: the durable ORDER of
        # events. Timestamps are second-resolution and two backups in one
        # second are ordinary; every "before/after" and every retention sort
        # uses seq, never ts.
        rec = {"ts": ts, "kind": kind, "op_id": op, "state": state, "seq": n}
        if kind == "prune":
            if state != "done" or len(parts) != 4:
                raise BackupError("the backup index is unreadable (line %d)" % n)
        elif state == "pending":
            # Every op id is a fresh secrets.token_hex(8) mint -- a SECOND
            # pending record for the same (kind, op_id) is never
            # legitimate, only corruption or a forged line. Reject it
            # exactly like a second terminal: without this, `_derive`
            # appends a second entry to `st.restores` (restores are not
            # dict-keyed by id, unlike backups), settlement writes two
            # terminal lines for one id, and the index then refuses its
            # own output on the very next settle.
            if (kind, op) in seen_pending:
                raise BackupError("the backup index is unreadable (line %d:"
                                  " a second pending record)" % n)
            seen_pending.add((kind, op))
            if kind == "erase":
                # An erasure carries NO extra field on either of its lines: it
                # names no backup and no reason, because what it removes is
                # every copy there is. A junk field is unreadable here for the
                # same reason a missing one is unreadable below.
                if len(parts) != 4:
                    raise BackupError("the backup index is unreadable (line %d)" % n)
            else:
                # The grammar is closed, not best-effort: exactly one extra
                # field, exactly the key this record kind takes, nothing else.
                # A dict comprehension over `key=value` pairs would silently
                # drop a bare trailing token and let a duplicate key win last --
                # both wrong for a field whose absence this same function
                # already calls unreadable.
                expected_key = "reason" if kind == "backup" else "backup"
                extra = parts[4:]
                if len(extra) != 1 or "=" not in extra[0]:
                    raise BackupError("the backup index is unreadable (line %d)" % n)
                key, _, value = extra[0].partition("=")
                if key != expected_key or not value:
                    raise BackupError("the backup index is unreadable (line %d)" % n)
                if kind == "backup":
                    if not reason_is_valid(value):
                        raise BackupError("the backup index is unreadable (line %d)" % n)
                    rec["reason"] = value
                else:
                    if not OP_ID_RE.fullmatch(value):
                        raise BackupError("the backup index is unreadable (line %d)" % n)
                    rec["backup_id"] = value
        elif state in _TERMINAL[kind] and len(parts) == 4:
            if (kind, op) in seen_terminal:
                raise BackupError("the backup index is unreadable (line %d:"
                                  " a second terminal record)" % n)
            seen_terminal.add((kind, op))
        else:
            raise BackupError("the backup index is unreadable (line %d)" % n)
        records.append(rec)
    return records


# `prune` is parsed above with kind "prune"; make the table know it.
_TERMINAL["prune"] = ("done",)


@dataclass
class LedgerState:
    generation: int = 0
    backups: dict = field(default_factory=dict)
    restores: list = field(default_factory=list)
    #: The `erase` operations the index carries, oldest first. An entry still
    #: `pending` is an erasure whose ledger half is durable and whose copies
    #: are not yet gone — settlement completes it.
    erasures: list = field(default_factory=list)
    registrations: dict = field(default_factory=dict)
    broken: set = field(default_factory=set)


def _registrations(conn) -> dict:
    try:
        rows = conn.execute("SELECT workflow, backup_id, registered_at FROM %s"
                            % REGISTRATIONS_TABLE).fetchall()
    except sqlite3.OperationalError as exc:
        # A pre-v9 ledger has no such table -- that is the ONE
        # OperationalError this reads as "no registrations". Anything else
        # (a corrupt table, a locked read) must not be swallowed the same
        # way: it would settle a legitimately-registered install backup as
        # an immutable `orphan` and silently empty `broken`.
        if "no such table" in str(exc):
            return {}
        raise BackupError("the registrations table could not be read: %s"
                          % exc) from None
    return {r[0]: {"backup_id": r[1], "registered_at": r[2]} for r in rows}


def _marker(conn):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (MARKER_KEY,)).fetchone()
    return row[0] if row else None


def _derive(records: list, paths: Paths, regs: dict) -> LedgerState:
    st = LedgerState(registrations=regs)
    for rec in records:
        if rec["kind"] == "backup":
            if rec["state"] == "pending":
                st.backups[rec["op_id"]] = {"ts": rec["ts"], "reason": rec["reason"],
                                            "state": "pending", "seq": rec["seq"]}
            elif rec["op_id"] in st.backups:
                st.backups[rec["op_id"]]["state"] = rec["state"]
        elif rec["kind"] == "restore":
            if rec["state"] == "pending":
                st.restores.append({"op_id": rec["op_id"], "backup_id": rec["backup_id"],
                                    "ts": rec["ts"], "state": "pending", "seq": rec["seq"]})
            else:
                for r in st.restores:
                    if r["op_id"] == rec["op_id"]:
                        r["state"] = rec["state"]
        elif rec["kind"] == "erase":
            if rec["state"] == "pending":
                st.erasures.append({"op_id": rec["op_id"], "ts": rec["ts"],
                                    "state": "pending", "seq": rec["seq"]})
            else:
                for e in st.erasures:
                    if e["op_id"] == rec["op_id"]:
                        e["state"] = rec["state"]
        elif rec["kind"] == "prune" and rec["op_id"] in st.backups:
            st.backups[rec["op_id"]]["pruned"] = True
    _restat(st, paths)
    # `generation` is computed exactly once, by settle() itself, AFTER it
    # has written any newly-settled terminal records into `st.restores` --
    # not here, where a still-pending restore this same settle() is about
    # to terminate would be undercounted.
    return st


def _restat(st: LedgerState, paths: Paths) -> None:
    """Re-read every fact in `st` that the FILESYSTEM owns: which copies are
    present, how big each one is, and which registrations point at a copy that
    is gone. `_derive` calls it once. Settlement calls it again after it
    completes an erasure, because every rule below that point — and
    `restore`'s own preflight, which reads this same object — has to branch on
    the directory as it is once the copies are gone, not as it was before."""
    for op, b in st.backups.items():
        f = paths.backup_file(op)
        b["present"] = f.is_file()
        b["size"] = f.stat().st_size if b["present"] else None
    st.broken = {wf for wf, reg in st.registrations.items()
                 if not paths.backup_file(reg["backup_id"]).is_file()}


def settle(conn, paths: Paths, *, hold: bool = True):
    """Recovery. PRECONDITION: the caller holds BEGIN IMMEDIATE on `conn`.
    -> (LedgerState, IndexHandle-or-None). With hold=True the index lock is
    returned still held and the caller MUST close the handle."""
    if not conn.in_transaction:
        raise BackupError("settle() needs the caller's BEGIN IMMEDIATE: the "
                          "ledger lock is taken before the index lock, always")
    _prepare(paths)
    fd = _acquire_index(paths)
    handle = None
    try:
        try:
            raw = os.pread(fd, os.fstat(fd).st_size, 0)
            if raw and not raw.endswith(b"\n"):
                # The one sanctioned exception to append-only: the torn
                # tail never formed a record. Truncate to the last newline,
                # then fsync. A torn HEADER (no newline anywhere in the
                # file) truncates to nothing -- the check right after this
                # one re-writes it exactly as for a fresh file, instead of
                # leaving a headerless file that every later settle would
                # refuse ("bad header") for ever.
                cut = raw.rfind(b"\n") + 1
                os.ftruncate(fd, cut)
                os.fsync(fd)
                raw = raw[:cut]
            if not raw:
                os.write(fd, (INDEX_HEADER + "\n").encode("ascii"))
                os.fsync(fd)
                raw = (INDEX_HEADER + "\n").encode("ascii")
        except OSError as exc:
            raise BackupError(
                "the backup index could not be read or written: %s"
                % _oserr(exc)) from None
        records = _parse(raw)
        handle = IndexHandle(fd, paths, records)
        regs = _registrations(conn)
        state = _derive(records, paths, regs)
        marker = _marker(conn)
        # AN ERASURE IS COMPLETED BEFORE THE TABLE'S OTHER ROWS ARE APPLIED.
        # A pending `erase` means a `delete_all_data` whose ledger COMMIT
        # landed died before its copies went, and every copy is a whole
        # ledger — sessions, the renewal-handoff `meta` keys, `accounts.uid`,
        # every transaction — so until they are gone one `restore` puts the
        # erased ledger back. Completing it first also makes the state the
        # rules below read (and `restore`'s preflight, which reads this same
        # object) describe the directory as it is AFTER the copies went.
        #
        # A file that cannot be unlinked leaves the pending record in place and
        # this settlement refusing, which wedges every backup, restore and
        # workflow write until the directory is writable again. That is the
        # intended posture, the same one an unreadable index takes: the
        # alternative is answering `restore_backup` normally while copies of a
        # ledger the operator was told was erased are still sitting there. The
        # refusal carries the state it had built, so the one caller that
        # changes nothing can still show the operator the residue.
        for e in state.erasures:
            if e["state"] != "pending":
                continue
            try:
                erase_backups(paths, handle, state, e["op_id"])
            except ErasureIncomplete as exc:
                # THE STATE TRAVELS WITH THE REFUSAL. Every caller here is
                # about to be refused, and the one that only ever reads
                # (`list_backups`) is the operator's only in-tool view of the
                # residue this exception is about — refusing it too left them
                # with a count and no way to see what the count referred to.
                # The generation is the one derived field not yet computed at
                # this point, so it is computed here: only committed restores
                # count, and no write can run to add one while this stands.
                _restat(state, paths)
                state.generation = len({r["op_id"] for r in state.restores
                                        if r["state"] == "committed"})
                exc.state = state
                raise
            _restat(state, paths)
            e["state"] = "committed"
        for op, b in list(state.backups.items()):
            if b["state"] != "pending":
                continue
            if b["present"]:
                if b["reason"].startswith(INSTALL_PREFIX):
                    wf = b["reason"][len(INSTALL_PREFIX):]
                    reg = regs.get(wf)
                    terminal = ("committed" if reg and reg["backup_id"] == op
                                else "orphan")
                else:
                    terminal = "committed"
            else:
                try:
                    paths.partial_file(op).unlink()
                except FileNotFoundError:
                    pass
                terminal = "aborted"
            handle.append("backup", op, terminal)
            b["state"] = terminal
        for r in state.restores:
            if r["state"] != "pending":
                continue
            terminal = "committed" if marker == r["op_id"] else "aborted"
            handle.append("restore", r["op_id"], terminal)
            r["state"] = terminal
        state.generation = len({r["op_id"] for r in state.restores
                                if r["state"] == "committed"})
    except BaseException:
        if handle is not None:
            handle.close()
        else:
            os.close(fd)
        raise
    if not hold:
        handle.close()
        return state, None
    return state, handle


WEEKLY_KEEP = 8
MANUAL_KEEP = 8
ORPHAN_KEEP = 4


@dataclass
class Backup:
    op_id: str
    reason: str
    ts: str
    size: int
    pruned: list = field(default_factory=list)


def abort_partial(paths: Paths, op_id: str) -> None:
    try:
        paths.partial_file(op_id).unlink()
    except FileNotFoundError:
        pass


def take_backup(conn, paths: Paths, handle: IndexHandle, reason: str,
                *, register=None) -> Backup:
    """Copy → fsync → `pending` → rename → fsync dir → (register). The
    CALLER commits, then calls finish_backup. PRECONDITION: BEGIN IMMEDIATE
    held on `conn`, `handle` from settle(). The copy goes through a SEPARATE
    read connection: a same-connection VACUUM INTO fails inside an open
    transaction, and under WAL the reader sees the last COMMITTED state —
    for a mint, the ledger as it was before the write that is minting."""
    if not conn.in_transaction or not handle._open:
        raise BackupError("take_backup needs the ledger lock and the index handle")
    if reason.startswith(INSTALL_PREFIX):
        if register != reason[len(INSTALL_PREFIX):] or not WORKFLOW_RE.fullmatch(register):
            raise BackupError("an install backup is minted, never requested")
    elif reason not in REASONS or register is not None:
        raise BackupError("reason must be 'weekly' or 'manual'")
    if sqlite3.sqlite_version_info < (3, 27, 0):
        raise BackupError("VACUUM INTO needs SQLite 3.27+; this build is %s"
                          % sqlite3.sqlite_version)
    op_id = new_op_id()
    partial, final = paths.partial_file(op_id), paths.backup_file(op_id)
    prev = os.umask(0o077)
    try:
        reader = sqlite3.connect(str(paths.db), isolation_level=None)
        try:
            reader.execute("VACUUM INTO ?", (str(partial),))
        finally:
            reader.close()
        fd = os.open(str(partial), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(str(partial), 0o600)
    except (sqlite3.Error, OSError) as exc:
        abort_partial(paths, op_id)
        raise BackupError("the backup copy failed: %s" % type(exc).__name__) from None
    finally:
        os.umask(prev)
    try:
        handle.append("backup", op_id, "pending", "reason=" + reason)
        os.rename(str(partial), str(final))
        _fsync_dir(paths.backups_dir)
    except OSError as exc:
        abort_partial(paths, op_id)
        raise BackupError("the backup could not be placed: %s" % _oserr(exc)) from None
    if register is not None:
        # INSERT OR REPLACE, not INSERT: a workflow whose registered backup
        # file is gone re-mints at its next write, and the row has to be able
        # to move to the new copy. Nothing else can delete one registration,
        # so a plain INSERT here would refuse the re-mint and wedge that
        # workflow's writes for good.
        conn.execute("INSERT OR REPLACE INTO %s(workflow, backup_id,"
                     " registered_at) VALUES (?,?,?)" % REGISTRATIONS_TABLE,
                     (register, op_id, now_ts()))
    return Backup(op_id=op_id, reason=reason, ts=now_ts(),
                  size=final.stat().st_size)


def finish_backup(paths: Paths, handle: IndexHandle, backup: Backup,
                  *, committed: bool) -> list:
    """After the caller's COMMIT or ROLLBACK. A rolled-back mint leaves a
    consistent copy with no registration — the crash rule's `orphan`."""
    handle.append("backup", backup.op_id, "committed" if committed else "orphan")
    backup.pruned = prune(paths, handle)
    return backup.pruned


def prune(paths: Paths, handle: IndexHandle) -> list:
    """Bounded retention for weekly / manual / orphan; NEVER an install
    backup: its registration is a promise that the copy behind it is still
    there, and retention is the one thing in this tree that would break that
    promise silently. (A registration whose copy has gone for any other reason
    does not fail closed — the workflow's next write re-mints and says what the
    new point does not cover.) Unlink, then the audit record. Re-derives from
    the handle's records plus what settle appended."""
    state = _derive(handle.records + _appended_since(handle), paths, {})
    keep = {"weekly": WEEKLY_KEEP, "manual": MANUAL_KEEP}
    classes = {"weekly": [], "manual": [], "orphan": []}
    for op, b in state.backups.items():
        if not b["present"] or b.get("pruned"):
            continue
        if b["state"] == "orphan":
            classes["orphan"].append((b["seq"], op))
        elif b["state"] == "committed" and b["reason"] in keep:
            classes[b["reason"]].append((b["seq"], op))
    pruned = []
    for cls, entries in classes.items():
        bound = ORPHAN_KEEP if cls == "orphan" else keep[cls]
        # Index order, never the second-resolution timestamp: nine backups in
        # one second sorted by (ts, random id) pruned the newest.
        for _, op in sorted(entries)[:-bound] if len(entries) > bound else []:
            try:
                paths.backup_file(op).unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                # The module's contract: every failure leaves as a
                # BackupError carrying our own text, never a raw OSError.
                raise BackupError("retention could not remove backup %s: %s"
                                  % (op, _oserr(exc))) from None
            handle.append("prune", op, "done")
            pruned.append(op)
    return pruned


def _appended_since(handle: IndexHandle) -> list:
    """Records appended through this handle after settle parsed the file."""
    try:
        raw = os.pread(handle.fd, os.fstat(handle.fd).st_size, 0)
    except OSError as exc:
        # The module's contract, as everywhere else here: a failure leaves
        # carrying our own text, never a raw OSError a caller's
        # `except BackupError` would miss.
        raise BackupError("the backup index could not be read: %s"
                          % _oserr(exc)) from None
    return _parse(raw)[len(handle.records):]


@dataclass
class Erasure:
    """What an erasure removed, counted the way a reply may state it."""
    #: Indexed copies (`<op>.sqlite`) unlinked. Each one either gets a `prune`
    #: record from this call or already carried one, so this number is never a
    #: claim the audit trail does not carry.
    removed: int = 0
    #: Copies in flight (`<op>.sqlite.partial`) unlinked. A partial never
    #: reached the index, so it earns no `prune` record — which is exactly why
    #: it is counted apart instead of inflating `removed`.
    partials: int = 0
    #: WHOLE copies (`<op>.sqlite`) that could not be unlinked, OR whose
    #: presence on disk could not even be READ back (the three-state presence
    #: check below folds an unreadable stat into this same count, never into
    #: a `prune`). A COUNT, never a path. Kept apart from the partials below
    #: because the two carry different weight: a whole copy is restorable, so
    #: one left on disk undoes the erasure outright, and that is what the
    #: alarm sentence is about.
    failed: int = 0
    #: Copies in flight (`<op>.sqlite.partial`) that could not be unlinked.
    #: `restore` refuses anything not in `state.backups`, and a partial never
    #: reached the index, so it cannot be restored — but the file still holds
    #: this ledger's pages, so it is named, in its own clause.
    failed_partials: int = 0
    #: The DIRECTORY holding the entries could not be flushed. An entry's
    #: removal lives in the directory's own blocks, so until that flush lands a
    #: power loss can bring every unlinked copy back — including copies an
    #: earlier attempt unlinked, which is why it is a flag and not a fifth
    #: number: no count this call can measure describes what is at risk.
    undurable: bool = False
    #: Set when every copy went AND the terminal `erase <op> committed` record
    #: was written but not flushed (`BackupError.written`). The line is
    #: readable, so the erasure is complete and the next settlement reads it as
    #: such; only the flush is missing, and the caller says that rather than
    #: describing a sweep that did finish as one that stopped part way.
    index_warning: str | None = None


class ErasureIncomplete(BackupError):
    """Some copies went and some did not.

    A `BackupError`, so every caller's existing refusal or warning branch still
    catches it, and it carries the counts: by the time this can be raised the
    ledger itself is already erased, so what DID go is part of the account the
    operator gets rather than a detail discarded with the exception.

    `state` is the `LedgerState` settlement had built when it raised, attached
    so a read-only caller can still render what it knows (`list_backups` does);
    it is None when the erasure was not run by settlement.
    """

    def __init__(self, erasure: Erasure):
        # A flush that failed over a sweep that removed everything has NO
        # failed file to count: "0 backup file(s) could not be erased" would
        # read as a call that succeeded and then refused for nothing.
        lost = erasure.failed + erasure.failed_partials
        super().__init__(
            "%d backup file(s) could not be erased" % lost if lost else
            "the removal of the backup copies could not be made durable")
        self.erasure = erasure
        self.state = None

    def residue(self) -> str:
        """What is STILL THERE, one clause per weight. The alarm names whole
        copies only: it used to fire for a `.partial` too, telling an operator
        that an unfinished copy nothing can restore was a whole ledger."""
        clauses = []
        if self.erasure.failed:
            clauses.append(
                "%d whole copy(ies) could not be removed — EVERY BACKUP IS A "
                "WHOLE COPY OF THIS LEDGER, so the copies that may still be "
                "on disk hold this ledger's data" % self.erasure.failed)
        if self.erasure.failed_partials:
            clauses.append(
                "%d unfinished copy(ies) could not be removed — a partial "
                "cannot be restored, but it still holds this ledger's pages"
                % self.erasure.failed_partials)
        if self.erasure.undurable:
            # Not a file that is still there: a file that is gone and might
            # come back. The operator cannot act on it per file — there is no
            # path to look at — so it is stated as the one thing they can act
            # on, which is that the erasure has not finished yet.
            # No count: an earlier attempt's unlinks are as much at risk as
            # this one's, and this call cannot know how many those were.
            clauses.append(
                "the directory holding them could not be flushed, so "
                "removals made in this attempt are not yet durable")
        return "; ".join(clauses)

    def describe(self) -> str:
        """The whole account, for a caller whose own reply says nothing else
        about the erasure. Settlement removing copies is not "nothing was
        changed", which is what every one of those callers used to print."""
        parts = []
        if self.erasure.removed or self.erasure.partials:
            parts.append("settlement removed %d backup copy(ies) and %d "
                         "partial(s)" % (self.erasure.removed,
                                         self.erasure.partials))
        residue = self.residue()
        if residue:
            parts.append(residue)
        return "; ".join(parts)


class ErasureRecordUnwritten(BackupError):
    """Every copy was already unlinked and the directory already flushed;
    only the terminal `erase <op> committed` record's WRITE failed (as
    opposed to its flush, which leaves `Erasure.index_warning` instead — see
    `_erase`'s two-failures comment).

    Raised from `_erase`'s terminal append, and ONLY from there: a plain
    `BackupError` out of `erase_backups` also covers a sweep that never got
    to try any file at all (an unreadable backups directory), and a caller
    that cannot tell the two apart has no honest way to say whether the
    copies are still there. This type always means they are not — the sweep
    ran to completion, and the next settlement (any backup, restore, listing
    or workflow write) re-checks the directory, finds it already empty, and
    writes the record then.
    """


def refusal_text(exc: BackupError) -> str:
    """What a tool says when `exc` made it refuse. Shared by the three tools
    that refuse on one, because the branch is about the exception's meaning,
    not about any one tool: an `ErasureIncomplete` out of settlement has
    ALREADY unlinked copies, so "Nothing was changed" is false — what it did
    leads, and this call's own no-op follows it."""
    if isinstance(exc, ErasureIncomplete):
        return exc.describe() + ". This call did not run."
    return "%s. Nothing was changed." % exc


def erase_backups(paths: Paths, handle: IndexHandle, state: LedgerState,
                  op_id: str) -> Erasure:
    """Unlink every backup copy beside the ledger, then commit the erasure.

    A BACKUP IS A WHOLE-LEDGER COPY — sessions, the `meta` renewal-handoff
    keys, `accounts.uid`, every transaction — so "erase the entire local
    ledger" has to mean the copies too: one restore from a surviving file
    undoes the erasure the caller just promised was permanent.

    `op_id` is the erasure whose `pending` record is already durable in the
    index. Every copy goes, one `prune <op> done` is appended per indexed copy —
    whether this call unlinked it or found it already absent — and
    `erase <op_id> committed` closes the operation, so a crash anywhere in here
    leaves the pending record and settlement in any later process finishes the
    job.

    A FAILURE ON ONE FILE NEVER STOPS THE SWEEP. It used to, and the reply then
    told the operator to run the call again: the retry met the same file first
    and made no progress on any of the others, while every copy behind it
    stayed a restorable whole ledger. The failures are counted and one
    `ErasureIncomplete` is raised after the loop — a count, never a path.

    THE DIRECTORY IS FLUSHED BEFORE THE TERMINAL RECORD, because an unlink is
    not durable until the directory holding the entry is and the terminal is
    what stops a later settlement from sweeping again.

    PRECONDITION: the caller's ledger COMMIT has already happened (or
    settlement is completing an erasure whose COMMIT did) and `handle` (from
    the same settle, with `state`) is still held. The INDEX itself is NOT
    deleted: it is append-only, so the record of what existed and what was
    removed survives the erasure and the restore generation stays monotonic
    across it.
    """
    if not handle._open:
        raise BackupError("erase_backups needs the index handle")
    if not OP_ID_RE.fullmatch(op_id or ""):
        raise BackupError("an erasure needs the operation id its pending "
                          "record carries")
    try:
        return _erase(paths, handle, state, op_id)
    except OSError as exc:
        # The module's contract, as everywhere else here: nothing leaves as a
        # raw OSError. Every I/O site below has its own wrapper; this is the
        # backstop for one added later without one, because every caller's
        # `except BackupError` is the whole of its error handling and an
        # OSError past it reaches the operator as a traceback.
        raise BackupError("the backup copies could not be erased: %s"
                          % _oserr(exc)) from None


def _erase(paths: Paths, handle: IndexHandle, state: LedgerState,
           op_id: str) -> Erasure:
    """The body of `erase_backups`, which holds the contract and the guards."""
    try:
        entries = sorted(paths.backups_dir.iterdir())
    except FileNotFoundError:
        entries = []
    except OSError as exc:
        raise BackupError("the backups directory could not be read: %s"
                          % _oserr(exc)) from None
    out = Erasure()
    #: Indexed copies the sweep below already counted into `out.failed`. The
    #: presence pass re-reads every indexed copy and counts what it cannot
    #: resolve; without this set the ordinary shape of an unsearchable
    #: directory — the unlink fails EACCES and so does the stat — counted one
    #: file twice, and the operator was told two copies are left where one is.
    stuck = set()
    for f in entries:
        for suffix in (".sqlite", ".sqlite.partial"):
            if f.name.endswith(suffix):
                copy_id = f.name[:-len(suffix)]
                break
        else:
            continue
        try:
            f.unlink()
        except FileNotFoundError:
            continue
        except OSError:
            if suffix == ".sqlite.partial":
                out.failed_partials += 1
            else:
                out.failed += 1
                stuck.add(copy_id)
            continue
        if suffix == ".sqlite.partial":
            out.partials += 1
            continue
        out.removed += 1
        # One audit record per INDEXED backup. A `.partial` never reached the
        # index (settle unlinks it and settles the operation `aborted`), and a
        # copy already recorded pruned needs no second line.
        b = state.backups.get(copy_id)
        if b is not None and not b.get("pruned"):
            handle.append("prune", copy_id, "done")
            b["pruned"] = True
    # AN INDEXED COPY WHOSE FILE IS ALREADY GONE IS AN ERASED ONE, and it gets
    # its audit record here. The sweep above can only record what it unlinks,
    # so an `append` that failed right after an unlink (a full disk takes the
    # record, not the unlink) left that copy with no `prune` line for ever:
    # this erasure's pending record was completed by the next settlement, which
    # found an empty directory and nothing to record, and the listing then
    # showed `FILE MISSING` — indistinguishable from a copy something outside
    # this plugin deleted. Inside an authorised erasure it is not ambiguous, so
    # the record is written whether or not the file was there to unlink, and
    # every indexed copy carries exactly one `prune` afterwards.
    #
    # Presence is RE-READ per copy rather than inferred from the sweep's
    # bookkeeping: a copy the sweep could not unlink is still on disk, and a
    # `prune` record for it would be the audit trail asserting the one thing
    # the failure means is untrue.
    for op, b in state.backups.items():
        if b.get("pruned") or op in stuck:
            continue
        # A backup that never reached a final file is not a COPY: settlement
        # unlinks its `.partial` and settles it `aborted`, so a `prune` line
        # for it would record the removal of a file that never existed. One
        # `prune` per indexed COPY is the property; `aborted` is not one.
        if b["state"] not in ("committed", "orphan"):
            continue
        # THREE STATES, NOT TWO. `Path.exists()` is `os.path.exists`, which
        # answers False for EVERY OSError — EACCES under a directory that
        # cannot be searched, EIO on a failing disk — so a copy that is still
        # there and merely unstattable earned a `prune` record saying it had
        # been erased, and the listing then showed it `pruned`. Absent is a
        # `prune`; unreadable is a failure, counted like an unlink that
        # failed, so the erasure stays pending and the next settlement looks
        # again instead of the audit trail closing over a file that is there.
        try:
            os.stat(str(paths.backup_file(op)))
        except FileNotFoundError:
            handle.append("prune", op, "done")
            b["pruned"] = True
        except OSError:
            out.failed += 1
    # THE UNLINKS ARE NOT DURABLE UNTIL THE DIRECTORY IS. An entry's removal
    # lives in the directory's own blocks, not in the file's, so without this
    # flush a power loss after `erase <op> committed` can bring every unlinked
    # copy back — and the terminal record is exactly what stops a later
    # settlement from ever sweeping again. The result would be whole restorable
    # copies of a ledger the operator was told was erased, with nothing left
    # that would remove them.
    #
    # It runs whenever the terminal is about to, NOT only when this call
    # unlinked something: an earlier attempt can have done the unlinking and
    # failed here, and this call then sees an empty directory whose entry
    # removals are still only in memory. Flushing on "did I remove anything"
    # would write the terminal over exactly that state.
    #
    # A failure joins the sweep's failures instead of raising on its own: the
    # erasure stays `pending`, so the next settlement unlinks whatever came
    # back and flushes again.
    try:
        _fsync_dir(paths.backups_dir)
    except FileNotFoundError:
        pass                        # no directory, so no entry to make durable
    except OSError:
        out.undurable = True
    if out.failed or out.failed_partials or out.undurable:
        raise ErasureIncomplete(out)
    try:
        handle.append("erase", op_id, "committed")
    except BackupError as exc:
        if not exc.written:
            # THE SWEEP ALREADY FINISHED — every copy is gone and the
            # directory is already flushed, by the two guards just above —
            # so this is not the sweep stopping part way, it is the record OF
            # a finished sweep failing to write. A bare `raise` would leave a
            # plain `BackupError` indistinguishable from the directory never
            # having been readable at all, and a caller rendering that as
            # "stopped part way, cannot say which of them are still there"
            # would describe a directory it had just emptied.
            raise ErasureRecordUnwritten(str(exc)) from exc
        # THE BYTES LANDED AND ONLY THE FLUSH FAILED, so the terminal line is
        # already readable by anything that parses this index: every copy is
        # gone, the erasure IS complete, and the next settlement reads it as
        # complete. Letting this leave as a BackupError made the caller
        # describe a sweep that finished as one that "stopped part way" and
        # could not say which copies were still there — of a directory it had
        # just emptied. A failed WRITE is the other event: no terminal record
        # exists, the erasure is still pending, and the refusal is right.
        out.index_warning = str(exc)
    return out


KEEP_LIVE_TABLES = frozenset({"sessions", "attempts", "meta"})
FTS_TABLES = frozenset({"notes_fts", "notes_fts_data", "notes_fts_idx",
                        "notes_fts_docsize", "notes_fts_config"})
_SPECIAL_TABLES = frozenset({"sqlite_sequence"})


@dataclass
class RestoreResult:
    op_id: str
    backup_id: str
    replaced: dict
    bindings_kept: int
    relink: list
    unregistered: list
    #: Set when the COMMIT landed but the terminal index record could not be
    #: written. The restore HAPPENED; only its audit line is missing, and the
    #: next settle writes it. The caller renders it, never a refusal.
    index_error: str | None = None


def _tables(conn, schema: str) -> list:
    return [r[0] for r in conn.execute(
        "SELECT name FROM %s.sqlite_master WHERE type='table' ORDER BY name" % schema)]


def _columns(conn, schema: str, table: str) -> list:
    return [(r[1], r[2]) for r in conn.execute('PRAGMA %s.table_info("%s")' % (schema, table))]


def restore(conn, paths: Paths, handle: IndexHandle, state: LedgerState,
            backup_id: str, *, schema_version: int) -> RestoreResult:
    """Replace the ledger's ordinary tables from a backup, in place.
    PRECONDITION: BEGIN IMMEDIATE held, handle from settle(). COMMITS
    itself, then appends the terminal record — the record has to follow
    the commit while the index lock is still held."""
    if not conn.in_transaction or not handle._open:
        raise BackupError("restore needs the ledger lock and the index handle")
    if not OP_ID_RE.fullmatch(backup_id or ""):
        raise BackupError("backup ids are 16 hex characters, as list_backups prints them")
    b = state.backups.get(backup_id)
    if b is None or not b["present"] or b["state"] not in ("committed", "orphan"):
        raise BackupError("no restorable backup %s — list_backups shows the ones "
                          "that are" % backup_id)
    leased = conn.execute("SELECT count(*) FROM attempts WHERE lease_token IS NOT NULL"
                          " AND COALESCE(lease_expiry, 0) > ?", (time.time(),)).fetchone()[0]
    if leased:
        raise BackupError("an authorization is in progress (a bank link or renewal "
                          "holds its lease); nothing was changed — try again in a minute")
    try:
        # as_uri(): percent-encoded, so the backup path can never be read as
        # a query string. The ledger connection is opened uri=True (store).
        conn.execute("ATTACH DATABASE ? AS bk",
                     (paths.backup_file(backup_id).resolve().as_uri() + "?mode=ro",))
    except sqlite3.DatabaseError:
        raise BackupError("backup %s is not a readable database; refusing to "
                          "write it in" % backup_id) from None
    # DETACH must run on every path once ATTACH has succeeded — otherwise the
    # attachment leaks onto this (long-lived) ledger connection and every
    # LATER restore on it fails at ATTACH with "database bk is already in
    # use", which the except-DatabaseError wrapper above then misreports as
    # THAT backup being unreadable. Everything from here to the end,
    # including the terminal index append, lives inside this try/finally.
    try:
        try:
            regs_before = _registrations(conn)
            if conn.execute("PRAGMA bk.integrity_check").fetchone()[0] != "ok":
                raise BackupError("backup %s fails its integrity check; refusing to "
                                  "write it in" % backup_id)
            row = conn.execute("SELECT value FROM bk.meta WHERE key='schema_version'").fetchone()
            if row is None or str(row[0]) != str(schema_version):
                raise BackupError("backup %s carries schema v%s and this ledger is v%d; a "
                                  "backup from before a schema upgrade cannot be restored"
                                  % (backup_id, row[0] if row else "?", schema_version))
            live, bk = _tables(conn, "main"), _tables(conn, "bk")
            ordinary = [t for t in live if t not in KEEP_LIVE_TABLES | FTS_TABLES | _SPECIAL_TABLES]
            for t in ordinary:
                if t not in bk or _columns(conn, "main", t) != _columns(conn, "bk", t):
                    raise BackupError("backup %s's table %s does not match this ledger's"
                                      % (backup_id, t))
            op_id = new_op_id()
            handle.append("restore", op_id, "pending", "backup=" + backup_id)
            live_accounts = {r[0]: dict(zip([c[0] for c in _columns(conn, "main", "accounts")], r))
                             for r in conn.execute("SELECT * FROM accounts")}
            replaced = {}
            for t in ordinary:
                cols = ", ".join('"%s"' % c[0] for c in _columns(conn, "main", t))
                conn.execute('DELETE FROM main."%s"' % t)
                cur = conn.execute('INSERT INTO main."%s"(%s) SELECT %s FROM bk."%s"'
                                   % (t, cols, cols, t))
                replaced[t] = cur.rowcount
            conn.execute("INSERT INTO notes_fts(notes_fts) VALUES('rebuild')")
            conn.execute("DELETE FROM main.sqlite_sequence")
            conn.execute("INSERT INTO main.sqlite_sequence(name, seq)"
                         " SELECT name, seq FROM bk.sqlite_sequence")
            restored_ids = {r[0] for r in conn.execute("SELECT account_id FROM accounts")}
            kept, relink = 0, []
            for aid, acc in live_accounts.items():
                if aid in restored_ids:
                    if acc.get("session_id") is not None:
                        conn.execute("UPDATE accounts SET session_id=?, uid=? WHERE account_id=?",
                                     (acc["session_id"], acc["uid"], aid))
                        kept += 1
                else:
                    # The spec's table names three cases for an account
                    # present in the backup; this is the fourth, implicit
                    # one — absent from the backup AND already unlinked live
                    # (no session_id). The row is never dropped by a
                    # restore, but a NULL binding is the derived "needs
                    # re-link" regardless of which branch produced it.
                    cols = list(acc)
                    conn.execute('INSERT INTO accounts(%s) VALUES (%s)'
                                 % (", ".join('"%s"' % c for c in cols), ",".join("?" * len(cols))),
                                 [acc[c] for c in cols])
                    if acc.get("session_id") is not None:
                        kept += 1
                    else:
                        relink.append(aid)
            for aid in restored_ids:
                live = live_accounts.get(aid)
                if live is None or live.get("session_id") is None:
                    conn.execute("UPDATE accounts SET session_id=NULL, uid=NULL WHERE account_id=?",
                                 (aid,))
                    relink.append(aid)
            conn.execute("UPDATE accounts SET incarnation = lower(hex(randomblob(8)))")
            # "At or after the restored point" is INDEX ORDER (seq), never the
            # second-resolution timestamp: an install backup minted in the same
            # second as the restored backup but before it is before it.
            point = b["seq"]
            at_or_after = [op for op, x in state.backups.items()
                           if x["reason"].startswith(INSTALL_PREFIX) and x["seq"] >= point]
            if at_or_after:
                conn.execute("DELETE FROM %s WHERE backup_id IN (%s)"
                             % (REGISTRATIONS_TABLE, ",".join("?" * len(at_or_after))), at_or_after)
            # What the operator is told was unregistered: every workflow that was
            # registered BEFORE this restore and is not after it — the table was
            # replaced from the backup above, so a query against it now would
            # name nothing; regs_before, captured before the replace, is the
            # only record of what used to be there.
            regs_after = _registrations(conn)
            unregistered = sorted(wf for wf in regs_before if wf not in regs_after)
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (MARKER_KEY, op_id))
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        index_error = None
        try:
            handle.append("restore", op_id, "committed")
        except BackupError as exc:
            # THE COMMIT ABOVE HAS LANDED. Letting this leave as a BackupError
            # put the caller's `except BackupError` — whose text is "nothing
            # was changed" — in charge of reporting a restore that had already
            # replaced every ordinary table. The missing line is an audit gap,
            # not a failed restore: the `pending` record plus the committed
            # marker settle `committed` at the next settle, so the generation
            # is right either way, and the caller says so instead.
            index_error = str(exc)
        return RestoreResult(op_id=op_id, backup_id=backup_id, replaced=replaced,
                             bindings_kept=kept, relink=sorted(relink),
                             unregistered=unregistered, index_error=index_error)
    finally:
        try:
            conn.execute("DETACH DATABASE bk")
        except sqlite3.Error:
            pass
