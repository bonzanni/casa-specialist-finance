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
open-time pass runs inside `store.open_db`, inside that call's `tools_read.conn()`. So
settlement's work is not carried on what it returns or raises — an exit that drops those
(a raw `OSError`, a failed COMMIT after settlement, the open-time pass swallowing its own
failure so the ledger still opens) would drop the account with them (issues #48, #53).

**Each write is recorded where it happens** into a `backups.SettleLog` that lives for
exactly one dispatched `tools/call` (`backups.open_log`, a context variable; no call, no
log). Recorded: the backups directory, index or index header it created; a torn tail it
cut (as soon as the cut is made, with whether its flush landed); each `.partial` it
unlinked; each pending `backup` or `restore` record it closed, when the append returned
or failed with the line readable; and per erasure, what every attempt removed, the
`prune` records for copies already gone, and whether the terminal record landed.

**It is rendered once, by `bank_feed_server.handle`, on every exit** — success, refusal
or exception — as one sentence after the sandbox banner: "While settling the backup
index, this call …" (`backups.render_log`). It makes no ordering claim, because
`delete_all_data` settles again after its own sweep. An erasure's removals are summed
across attempts and its residue is the latest attempt's, so a retry that succeeded
supersedes an earlier attempt's alarm. No tool renders settlement itself.

**"Nothing was changed" has one spelling, `backups.unchanged`.** It is evaluated when a
reply is built; once the call's log holds anything it says "This call's own operation
changed nothing." instead, because the call did change something. A refusal built before
the ledger opens keeps the plain sentence, which is then true. `tests/test_settle_log.py`
fails on any literal of the claim outside that function, and on any tool that reads
settlement's account itself. A `take_backup` whose rename fails closes its own `pending`
record `aborted`, and its refusal says the copy was not kept.

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
