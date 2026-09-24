# Settlement of the backup index

Settlement is the recovery pass over the backup index: it gives every operation left
`pending` its terminal record. This document is that part of
[`architecture/backups-and-restore.md`](../architecture/backups-and-restore.md); an
interrupted erasure's half is
[`architecture/backups-erasure.md`](../architecture/backups-erasure.md).

## What settlement does

`backups.settle(conn, paths)` is recovery: the caller must already hold
`BEGIN IMMEDIATE`, and it raises if they do not. It reads the index, truncates a torn
tail if there is one, and appends the terminal record for every operation that has a
`pending` line and no terminal one yet:

| Operation | Condition | Terminal |
|---|---|---|
| `backup`, reason `install:<w>` | final file present, `<w>` registered against this op | `committed` |
| `backup`, reason `install:<w>` | final file present, no such registration | `orphan` — the copy is consistent, so it is kept |
| `backup`, other reasons | final file present | `committed` |
| `backup`, any reason | final file absent | `aborted`, and the `.partial` file is removed |
| `restore` | the ledger's `meta.backup_restore_op` marker equals this operation id | `committed` |
| `restore` | anything else | `aborted` |
| `erase` | always | `committed`, once every copy and partial is unlinked, the backups directory is flushed, and every *indexed* copy carries a `prune` — written for one this settlement removed and for one it can read as already gone |

**A pending `erase` is completed before any other row of that table is applied** — until the
copies are gone a `restore` could put an erased ledger back. Settlement then re-reads
presence, size and `broken` (`backups._restat`), so the rest of the table and `restore`'s
preflight see the directory *after* the copies went. An erasure never moves `generation`,
which counts committed *restores*. A copy that cannot be unlinked leaves the `pending` record
and makes settlement itself refuse — fail closed, as an unreadable index does, rather than
answer normally while copies of a supposedly erased ledger sit beside it. The refusal carries the
state settlement built, so `list_backups`, which changes nothing, still renders the listing
rather than hiding the residue. What completing an erasure removed, and what it left, is
reported the way everything settlement does is: see *What settlement reports* below.

Exactly one terminal record is ever appended per operation id — a process finding one
already present appends nothing — and since every appender holds the ledger writer lock
first, the appends are serialized by that lock alone; the index lock is the second belt.

`settle` returns a `LedgerState`: `generation`, `backups` (op id to time, reason, state,
presence and size), `restores`, `registrations` (workflow to backup id and time), and
`broken` — the set of workflows whose registered backup file is gone. Settlement runs
at every `open_db` — best effort: skipped when there is no index file or either lock is
unavailable, never failing the open, because every consumer settles under both locks
itself — and at the start of every mint, restore, `backup(reason)` and workflow-bearing
write, and before `list_backups` answers.

## What settlement reports

Settlement changes the index and the directory before the tool that triggered it does
anything, and the first call of a process triggers it with no reply of its own: the
open-time pass runs inside `store.open_db`, inside that call's `tools_read.conn()` (issues
#48, #53). What it did is kept in a `backups.SettleLog` that lives for exactly one
dispatched `tools/call`, and `bank_feed_server.handle` renders it once, on every exit
(success, refusal or exception), after the sandbox banner. No tool renders settlement.

The log holds two kinds of fact and never mixes them:

- **Effects** are events: the backups directory or the index created; a mode reset (only
  when it had drifted); the index header written into an empty index; a torn tail cut; a
  copy, `.partial`, snapshot or journal unlinked; a record settlement appended (a
  closure, a `prune`, an erasure's completion). Each is logged by the code that performed
  it, **once, after the syscall that makes the change returned**: never before it, and
  never on an uncertain outcome. Whether it was flushed is state, not part of the effect.
  Effects are counted, not de-duplicated, and only settlement logs them. A tool's own
  writes are the tool's to report.
- **State** is read, never recorded: whether the index ends in an incomplete line,
  whether a recorded erasure is still pending and what is still present. It is read at
  **every release of the index lock**. Every writer holds that lock, so the last release
  follows the call's last write, whether the write was settlement's or the tool's own.
  The state is worded as what the call *saw* then ("When this call last released the
  backup index, …"), because another process can change it the moment the lock is gone.
  A part that cannot be read claims nothing, and never cancels an effect.
  **Durability** is the one state no read can see. A failed index flush by settlement
  sets it, and any later successful index flush in the call clears it.

A write whose outcome is unknown (`BackupError.written` None) is not an effect. What it
left is read back as the tail state, and it is mentioned only when that read fails.
Tools report only their own events, never state. `delete_all_data`'s warning says what
its own sweep could not remove *when it ran*; whether copies are still there, what that
blocks and how to finish it is the lock-release sentence, because a later settlement in
the same call can finish the erasure.

**A refusal claims only what is always true.** `backups.unchanged` is a constant: "This
call's own operation changed nothing." It is true whatever settlement did, so no
refusal's claim can contradict the settlement sentence, and nothing needs to recognize
English to enforce it. `take_backup` closes its own `pending` record when its rename
fails, and its refusal says the copy was not kept.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `plugins/bank-feed/server/backups.py::settle`
- `plugins/bank-feed/server/store.py::_settle_best_effort`
- `plugins/bank-feed/server/bank_feed_server.py::handle`

**Tests**
- `tests/test_backups.py`
- `tests/test_store.py`
- `tests/test_settle_log.py`

**Related**
- [`architecture/backups-and-restore.md`](../architecture/backups-and-restore.md)
- [`architecture/backups-erasure.md`](../architecture/backups-erasure.md)
<!-- END SOURCEMAP -->
