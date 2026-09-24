# Backups and restore points

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

Tags are cheap to reverse, but nothing undoes a mistaken batch of writes across many rows,
and a workflow that annotates the ledger on its own initiative — an `owner::name` tag, say —
needs a way back that does not depend on the operator asking for one. `backups.py` is that: a
copy taken automatically before a workflow's first write, and a protected tool that puts the
whole ledger back to one, in place.

## What a backup is

A backup is a `VACUUM INTO` copy of the ledger file, taken through a **separate read
connection**: a same-connection `VACUUM INTO` fails inside an open transaction, and under WAL
the separate reader sees the last *committed* state — for a mint, the ledger as it stood
*before* the write that is minting it.

Every path is **mode-scoped**, derived from the ledger's filename, so a sandbox and a
production install sharing a data directory cannot see each other's backups:

```
bank_feed.sqlite                     the ledger
bank_feed.sqlite.backup-index        the event index          (0600)
bank_feed.sqlite.backups/            the backups directory     (0700)
  <op_id>.sqlite                     a backup                  (0600)
  <op_id>.sqlite.partial             a copy in flight
```

`<op_id>` is `secrets.token_hex(8)`. The index sits **beside** the database, never inside
it, so a restore — which replaces the database's own rows — cannot erase the record of
itself, and the restore generation stays monotonic no matter what a restore does to the
tables next to it.

## The event index

Append-only, one record per line, every append written and then `fsync`ed — two events: a
flush that fails after its write leaves a line the next reader acts on, so
`backups.BackupError.written` says which failed. The records that follow something
irreversible honour it — a restore's terminal one (`backups.RestoreResult.index_error`)
and both of an erasure's — so none of them reports "nothing happened" over a readable
line. A `backup`'s `pending` record does not have to: no copy was placed, so nothing was
changed, and settlement writes that operation's `aborted` line.

**An append is whole or absent.** A write can land a prefix of a line and report it; the
next append would complete it into a malformed line every settlement refuses. So the size
is taken first, the write loops until every byte lands, and a failure cuts the file back to
that size and flushes it: `written=False`, the record does not exist. If the cut fails too,
the `IndexHandle` refuses every later append and the failure carries `written=None` — the
index may end in a partial record, which the next settlement cuts as a torn tail. Callers
word None like a readable line and act on it like an absent one. The header is written the
same way, cut back to empty on a failure. No field may contain
whitespace — operation ids are hex, timestamps are `strftime("%Y%m%dT%H%M%SZ", gmtime())`,
reasons are a closed set plus a charset-constrained workflow string
(`backups.WORKFLOW_RE`) — which is what makes a line-oriented durable record safe to
build from caller-supplied text at all. The grammar:

```
bank-feed backup index v1
<ts> backup  <op_id> pending reason=<weekly|manual|pre-erasure|install:<workflow>>
<ts> backup  <op_id> <committed|aborted|orphan>
<ts> restore <op_id> pending backup=<backup_id>
<ts> restore <op_id> <committed|aborted>
<ts> erase   <op_id> pending
<ts> erase   <op_id> committed
<ts> prune   <op_id> done
```

**A mint is an ordinary `backup` record**, not a separate kind — `install:<workflow>` is
just a reason. That is what makes "every `backup(reason)` follows the same protocol" true
by construction: there is one protocol, because there is one record shape.

**An `erase` record carries no extra field and no `aborted`.** It names no backup and no
reason — what it removes is every copy there is, so a field on either line is unreadable —
and once its `pending` record is durable, settlement always completes it: a terminal that
could cancel one would let a crash leave a restorable whole-ledger copy behind.

**Reading it fails closed.** A line that does not parse — not UTF-8, an unknown kind, a malformed id,
a second `pending` or a second terminal for one operation — makes the whole index unreadable,
and an unreadable index refuses every backup, restore and workflow-bearing write. `backups._parse` never guesses a generation it cannot compute.

**The one tolerated damage is a trailing partial line** with no newline — the shape a
crash mid-append leaves. `backups.settle` truncates to the last complete newline and
`fsync`s *before any append*, through an `O_APPEND` descriptor, so the next write lands at
the true end rather than past what was cut. The bytes removed never formed a record: this is
the single sanctioned exception to append-only.

`prune` is not part of the state machine — it is an audit line appended after a file is
already unlinked. Whether a backup's file exists is read from the filesystem, the only place
that fact can be true.

## Locks

Two locks, taken in one fixed order everywhere: the ledger's own writer lock
(`BEGIN IMMEDIATE` on the caller's connection) **first**, the index lock
(`fcntl.flock` on the index file) **second**. Every site that touches both takes them in
that order and never the other — the one thing between two processes and a deadlock.

**`backups.settle` is the one acquisition site.** It takes the index lock and returns an
`IndexHandle`; the mint, the restore, `list_backups` and `prune` all append through that
handle rather than opening the index themselves. The lock is non-blocking with a bounded wait
(`backups.LOCK_WAIT_S`): `flock` is not re-entrant, so a second descriptor on the same file
in the same process would block forever, and a lock not taken within the bound is a refusal —
"the backup index is busy" — never a hang.

Settlement, every mint, `backup(reason)` and every restore hold both locks from
settlement through their own commit. `list_backups` holds both from settlement through
capturing its answer, so a restore cannot land and finish in the gap between settling
and rendering the reply it would have changed. The terminal index record is appended
*after* the ledger commit, while the index lock is still held — the ledger lock is
released by the commit itself, an ordering release rather than a second acquisition.

## Settlement

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
rather than hiding the residue. What completing an erasure removed is carried too
(`LedgerState.settled`, or `BackupError.settled` when settlement then refuses), so a call that
refuses after it — a restore of an id that erasure just removed — says "This call did not
run; settlement first completed an interrupted erasure and removed N backup copy(ies).",
never "Nothing was changed." (`backups.refusal_text`).

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

## The mint

Every workflow-bearing write to `tag_transaction`, `untag_transaction` or `add_note`
goes through `tools_annotate.py`'s `_fenced_write()`, which fixes the order for all
three:

1. `BEGIN IMMEDIATE`
2. settle, under both locks
3. compare `expected_generation` against the **settled** generation — a mismatch rolls
   the whole transaction back and mints nothing: "the ledger was restored since this
   pass began"
4. row-state and cap validation (reads; a refusal here mints nothing)
5. the mint, if the workflow string is not registered **or its registered copy is gone**
6. the write
7. `COMMIT`, then the terminal index record

**A broken registration re-mints before the write; it does not refuse it.** A workflow
whose registered copy has been deleted is treated exactly like one writing for the first
time: `backups.take_backup` registers with `INSERT OR REPLACE`, so the row moves onto the new
copy, and the reply says what that new point does not cover — "The earlier restore point for
`<workflow>` was missing; a new one was minted now… It does not undo `<workflow>`'s earlier
writes." Refusing wedged that workflow for good: nothing here deletes a registration, so
re-minting was impossible precisely *because* the registration was still there, and the
remedy both the refusal and `list_backups` named did not exist. Re-minting costs one
disclosed gap — the writes made under the missing copy are not covered — where refusing cost
the workflow every future write.

Two callers racing under one new workflow string serialize on the ledger lock; the loser
finds the string already registered and writes without a second mint. A write carrying no
`workflow` skips to a plain transaction — the annotation write every non-workflow caller has
always made.

`_namespaced_without_workflow()` refuses an `owner::name` tag written with no `workflow`:
a namespaced tag is another workflow's vocabulary, and writing it unattributed would let it
in without the restore point its owner is promised. `_workflow_args()` enforces the companion
rule — `workflow` and `expected_generation` arrive together or not at all, and a `bool` is
not an integer here any more than anywhere else in this tree.

A mint that is rolled back — the write it preceded refused, or failed for any other
reason — leaves the copy on disk as an `orphan`, not `aborted`: the file is still a
consistent backup, the transaction that would have registered it never committed, and the
next write mints afresh.

## Restore

`restore_backup(backup_id)` is protected: casa demands an operator grant bound to the
exact backup id before the call reaches this process. `backups.restore` then runs
inside one `BEGIN IMMEDIATE`, condensed:

1. Settle; keep both locks. Refuse unless the backup is known, present, and
   `committed` or `orphan`.
2. Refuse while any `attempts` row holds an unexpired lease — an authorization is in
   progress, and its own backfill runs under incarnation guards a restore would trip.
3. `ATTACH` the backup read-only, now that both locks are held — a prune cannot unlink
   the file the restore is about to attach, because every prune holds the same index
   lock.
4. `PRAGMA bk.integrity_check`, then a schema preflight: `bk.meta.schema_version` must
   equal `store.SCHEMA_VERSION`, and every **ordinary** table's `PRAGMA table_info` (the
   ones step 7 replaces) must match column-for-column — `sessions`, `attempts`, `meta`, the
   full-text shadow tables and `sqlite_sequence` are never compared, because they are never
   replaced either. Either failure refuses, naming the mismatch, before anything is written.
5. Mint the restore operation id and append `restore <op> pending backup=<id>` — after
   every preflight, before the first replacement write.
6. Read the whole live `accounts` table before anything is replaced, so its bindings can
   be written back over the restored rows afterwards (below). `sessions`, `attempts` and
   `meta` need no such capture — the replacement never touches them.
7. Replace every **ordinary** table: `DELETE FROM main.<t>` then `INSERT INTO
   main.<t>(<cols>) SELECT <cols> FROM bk.<t>`, with the table list enumerated from
   `main.sqlite_master` rather than maintained by hand — a table a later schema adds is
   restored by default; a table that must not be is named in an explicit exclusion set.
   The tables are visited in alphabetical order (`main.sqlite_master`'s own `ORDER BY
   name`), never dependency order — which holds only because this schema declares no
   `FOREIGN KEY` (`PRAGMA foreign_keys=ON` is set and has nothing to enforce). One added
   later would need this step reordered.
8. `notes_fts` is **rebuilt, never copied**: `notes_fts` itself and its four shadow
   tables (`notes_fts_data`, `notes_fts_idx`, `notes_fts_docsize`, `notes_fts_config`)
   are excluded from the table list, and after the content table lands, `INSERT INTO
   notes_fts(notes_fts) VALUES('rebuild')` regenerates the index.
9. `sqlite_sequence` is replaced **last**, so row ids resume from the backup's own
   counter rather than being reallocated by the deletes and inserts that ran before it.
10. Re-apply the live consent bindings, mint a fresh `incarnation` for every surviving
    account, unregister every workflow whose install backup is at or after the restored
    point, then write the `meta.backup_restore_op` marker.
11. `COMMIT`; append `restore <op> committed`; `fsync`; `DETACH`.

A failure on that final append is **carried, not raised**: the `COMMIT` has already
replaced every ordinary table, so leaving as a `BackupError` put the tool's own "Nothing was
changed." in charge of reporting a restore that had happened. `RestoreResult.index_error`
carries the message, and `index_written` which failure it was: a failed flush is "was written
but could not be flushed … it is readable now"; a failed write is "could not be written… — it
settles at the next listing"; a partial line is "may be partially written; the next
settlement recovers it". The last two are literally true: the `pending` record plus the committed
`meta.backup_restore_op` marker settle the operation `committed` at the next settlement,
so the generation is right either way.

`backups.restore` is not built on SQLite's own backup API: that API refuses a
destination holding an open transaction, and releasing the lock to use it would split
the preflight from the replacement — exactly the gap step 3 above exists to close.

### What is kept live

A consent is a fact about the bank, not about the ledger's history, and a consent
revoked at the bank cannot be brought back by restoring rows. `backups.KEEP_LIVE_TABLES`
— `sessions`, `attempts` and `meta` — are never taken from a backup. Per account:

| Case | What happens |
|---|---|
| In the backup **and** linked live | Restored, then its live `session_id` and `uid` are written back over the restored ones. |
| In the backup, **not** linked live | Restored with `session_id` and `uid` `NULL` — which **is** needs-relink. |
| **Not** in the backup, linked live | Its live row is re-inserted verbatim; history is empty and the next `sync` refills it. |
| **Not** in the backup, **not** linked live | Its live row is re-inserted verbatim too, and it is reported as needing a re-link — a NULL binding is the derived needs-relink whichever branch produced it. |

`needs-relink` is never a stored flag: an account with no live `session_id` *is* one that
needs re-linking, read straight off the row. `restore_backup`'s reply names the accounts that
came back this way, and `tools_read.py`'s `list_accounts()` marks any account with no live
binding `not linked — re-link needed`, so the fact does not go stale once the reply scrolls
past.

### The incarnation re-mint

Every surviving account gets a fresh `incarnation` inside the restore transaction, after
the account merge above. A restore puts the row-id counter back, so a row id already
allocated after the backup can be allocated again for a different payment. Every late write
this tree fences — a refresh plan's application, a coverage record, a provenance
observation — conditions itself on the `incarnation` its own read captured, so the re-mint
makes a plan built before the restore fail closed after one: the guard that was already there
is now the guard against a restore landing underneath it, with nothing new to remember.

### The authorization refusal

A restore refuses while a bank authorization may still be completing, on the predicate
`purge` uses too (`tools_auth.authorization_in_progress`, asked under the ledger lock before
settling; `backups-erasure.md` states the horizon). An expired lease alone is not a finished
renewal: a stalled collector resumes, or casa redelivers and a successor steals the lease.
The re-mint above is right for a stale refresh plan, which the next `sync` rebuilds, and
wrong for a renewal in flight: its backfill runs under the same incarnation guards, so a
restore underneath it reads as "this account was erased", and a renewal between its binding
switch and its reply reads the rotation as "nothing switched" and points `unlink_bank` at the
consent that is now live. The remedy is to retry once the authorization finishes.

## Retention

| Reason | Kept |
|---|---|
| `install:<workflow>` | Every one, until the operator deletes the file by hand or `delete_all_data` erases it — retention never prunes one: its registration promises the copy behind it is still there. |
| `weekly` | The 8 most recent. |
| `manual` | The 8 most recent. |
| `pre-erasure` | The 8 most recent. Taken only by `purge` and `forget_local_account` (see below); the `backup` tool refuses the reason. |
| orphan | The 4 most recent — **including an orphaned install backup**: a consistent copy, but bounded like every other orphan rather than for ever. |

`backups.prune` runs inside `backups.finish_backup`, so it runs at the end of every
`backup(reason)` call **and every mint** — both the committed branch and the rolled-back
one, which settles its copy `orphan` and prunes with the same call. It holds the index lock
throughout: unlink the file, then append `prune <op_id> done`. Ordering is by index sequence,
never the second-resolution timestamp — several backups can land in one second, and sorting
by timestamp there pruned the newest instead of the oldest.

**An erasure's prune touches its own class only.** `prune` sweeps every class on every call,
so the copy a scoped erasure takes would otherwise remove the oldest `manual` copy whenever
that class stood over its bound — a scoped eraser deleting a recovery point the operator
took. `finish_backup` and `prune` therefore take `classes`, and the two scoped erasers pass
only `pre-erasure` (no `orphan` either). Every other caller keeps the all-class prune,
which bounds `pre-erasure` at 8 too.

### Scoped erasures back up first

`purge` and `forget_local_account` take a `pre-erasure` copy before they erase anything, and
`purge` waits for an authorization in flight on a wider rule than a restore does;
[`architecture/backups-erasure.md`](../architecture/backups-erasure.md) has both.

### The erasure covers the copies

**`delete_all_data` erases every backup file**, because a backup is a copy of the *whole*
ledger and one left beside the erased ledger is the erased ledger.
[`architecture/backups-erasure.md`](../architecture/backups-erasure.md) is that half of this
document: the order, what is durable when, which calls a pending erasure stops, and what each
failure is allowed to say.

## What a refresh crossing a restore reports

A routine `sync` holds no lease, so a restore does not wait for it: the refresh's own
writes fail closed on the re-minted incarnation, the binding stays live, and the next
`sync` succeeds. `tools_refresh.py`'s `_do_refresh()` decides what to report from **one
terminal check**, after the fetch and after any failure is recorded: it re-reads
`accounts.incarnation` for this account and compares it against the token the run captured
at its own start. A mismatch — the row gone, or its incarnation moved —
means this run's outcome belongs to a life that no longer exists, so `_do_refresh`
swallows whatever it wrote or raised and returns `False`; when the caller passed an
`out` dict (`sync` and the inline refresher both do), it also sets `out["erased"] = True`
so the caller can tell this `False` apart from an ordinary one. `sync` reads that flag
and renders "LEDGER CHANGED — the ledger was restored, or had history erased, while this
refresh was in flight. Run sync again." — no claim about which rows or which completion
state remain, because a purge (which rotates the incarnation too) can leave rows the run
committed before it — adding "This account is not linked — a
re-link is needed." when the row's binding is gone — rather than crediting a false
"refreshed". `tools_read.py`'s `_freshness()` inline refresh reads the same flag and
appends the parallel clause to its freshness note: the account's ledger life changed
during this refresh — restored or erased — run `sync`. Neither path claims the account
was refreshed successfully. A genuinely erased account — no row left to re-read — is a
different branch: `sync` renders the ordinary erasure line, which still names `link_bank` as
the way back, correctly, because the row really is gone. Every intermediate read — a balance
count, a completeness stamp, a failure note — is dominated by this one exit: the terminal
check decides the words.

That check cannot close every window by itself — the report is rendered outside any lock,
so a restore can land between the check and the text reaching the operator. What holds there
is narrower: **no string this plugin renders from a refresh outcome names a destructive
tool.** `NO_BALANCES_EXIT` points the operator at two reads, `sync` and `consent_status`,
never at a tool that erases or revokes; a cached balance is never itself evidence for erasing
history, because a restore is exactly what can put a healthy cache back. A report may be
stale by one restore that landed after its terminal check, but a stale report from this
subsystem is never a *dangerous* one.

## Invariants

**INV-BACKUP-001**: the ledger writer lock is taken before the index lock at every site.

**INV-BACKUP-002**: the restore generation is derived from the index and never from the ledger.

**INV-BACKUP-003**: sessions, attempts and meta are never taken from a backup.

**INV-BACKUP-004**: no string rendered from a refresh outcome names a destructive tool.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `plugins/bank-feed/server/backups.py`
- `plugins/bank-feed/server/tools_backup.py`
- `plugins/bank-feed/server/tools_annotate.py::_fenced_write`

**Tests**
- `tests/test_backups.py`
- `tests/test_tools_backup.py`
- `tests/test_tools_annotate.py`

**Related**
- [`architecture/annotations-and-rules.md`](../architecture/annotations-and-rules.md)
- [`architecture/backups-erasure.md`](../architecture/backups-erasure.md)
- [`architecture/ingestion-and-identity.md`](../architecture/ingestion-and-identity.md)
- [`reference/tool-surface.md`](../reference/tool-surface.md)
<!-- END SOURCEMAP -->
