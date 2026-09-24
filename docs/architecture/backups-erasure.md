# The erasure of the backup copies

`delete_all_data` erases the backup files as well as the ledger's rows, through the same
index protocol a mint and a restore already use. This document is that half of
[`architecture/backups-and-restore.md`](../architecture/backups-and-restore.md): what is
removed, in what order, what is durable when, and what each failure is allowed to say.

## Why the copies go

**A backup is a copy of the *whole* ledger** — sessions, the `meta` renewal-handoff keys
whose own key embeds a bank session identifier, `accounts.uid`, every transaction — so a
copy left beside the erased ledger *is* the erased ledger, and one `restore_backup` undid
the erasure the tool had just called permanent.

`backups.erase_backups` runs after the erasure's `COMMIT`, while the index handle from the
same settlement is still held: it unlinks every `*.sqlite` and `*.sqlite.partial` under the
backups directory, appends one `prune <op_id> done` per *indexed* copy — removed here or
already absent, since inside an authorised erasure an absent indexed copy is an erased
one — flushes the directory, and closes the operation with `erase <op_id> committed`. The
**index itself is kept**: append-only, so the record of what existed and what went survives
the erasure it describes and the generation stays monotonic across it.

An `aborted` backup earns no `prune`. It never reached a final file — settlement unlinks its
`.partial` and settles it `aborted` — so a record of its removal would describe a file that
never existed. Exactly one `prune` per indexed *copy* is the property, and an `aborted`
operation produced no copy.

## The pre-migration snapshots go with them

`store.open_db` takes a snapshot beside the ledger before a schema migration
(`store.snapshot_before_migration`, a `VACUUM INTO` named
`<ledger>.pre-migration-<stamp>`). It is a whole-ledger copy like a backup, so a total
erasure that left it behind left the destroyed session identifiers on disk. `_erase`
therefore also unlinks every file whose name starts with this ledger's own
`<ledger>.pre-migration-` prefix (`backups.SNAPSHOT_INFIX`, the same constant
`store._snapshot_name` builds the name from), inside the same recorded erasure. The other
mode's ledger shares the directory, and its snapshots are left alone because its name leads
theirs. No index record ever named a snapshot, so a removed one earns no `prune` and is
counted apart (`Erasure.snapshots`). A file under the prefix whose remainder is not a stamp
(`backups.SNAPSHOT_STAMP_RE`) is a snapshot's journal: it holds pages of the ledger, not a
whole copy, and is counted and described as that (`Erasure.snapshot_sidecars`). One that
cannot be unlinked (`Erasure.failed_snapshots`, `Erasure.failed_snapshot_sidecars`) keeps the
erasure `pending` exactly as a stuck backup copy does, and gets its own clause naming the
files beside the ledger, because they are not in the backups directory. A sweep that cannot
list the ledger's directory at all counts nothing, so its by-hand instruction names the
snapshots too. The
ledger's directory is flushed before the terminal record on the same rule as the backups
directory. Only the total eraser does this: `purge` and `forget_local_account` leave every
copy, snapshots included, because backups are recovery — they take a `pre-erasure` copy of
their own first, and the only copies they can ever remove are older `pre-erasure` copies past
that class's retention bound (see "Scoped erasures back up first" below).

## Scoped erasures back up first

**Erasers touch the live ledger only; backups are recovery.** `purge` and
`forget_local_account` never modify or remove a `weekly`, `manual`, `install` or orphan copy,
and each takes a `pre-erasure` copy before it erases anything: under its own
`BEGIN IMMEDIATE` it settles, calls `take_backup` — whose separate reader sees the last
committed state, which with nothing written yet is the ledger exactly before this erasure —
then erases, commits, and finishes the copy with the class-restricted prune. A refusal
anywhere up to and including the copy rolls back: **nothing is erased without its backup.**
A failure of the erasure itself rolls back too, and the copy is finished `orphan`, still a
valid restore point of the unchanged ledger. The reply names the copy and what
`restore_backup` of it brings back — for `forget_local_account`, the account returns bound to
whatever it is bound to live when the restore runs, and the authorization attempts it erased
stay erased, because a restore keeps bindings and attempts live. It says "No other backup
copy was changed" only when retention pruned nothing and this call's settlement completed no
earlier interrupted erasure; otherwise it names what went. `delete_all_data` stays the one
total eraser.

`purge` also rotates every account's incarnation, as a restore does, so a refresh that read
the ledger before it cannot record coverage or sync state over the rows it removed. For the
same reason as a restore it waits for an authorization in flight, on the same predicate
(`tools_auth.authorization_in_progress`), because a renewal between its binding switch and its
reply reads the rotation as "nothing switched": it refuses while any attempt carries a `lease_token` whose lease is unexpired
(however old the attempt), or whose lease expired while casa could still redeliver the
attempt (`created_at` within `PENDING_TTL_S + RESULT_TTL_S + LEASE_TTL_S`). Past that horizon
the purge proceeds and leaves the attempt row untouched: clearing a dead token strands a
collector that was only stalled, with a half-written binding. The accepted residual is a
renewal collector stalled for longer than the whole horizon, about 45 minutes, that then
resumes across a purge.

## The order, and what is durable when

**The erasure goes through the index, so a crash cannot outlive it.** `delete_all_data`
mints an erasure id and appends `erase <op> pending` as the **last statement before its
ledger `COMMIT`** — the only order with no gap. A failure *above* it rolls the ledger back
with nothing recorded, so "nothing was erased" still covers the copies. The `append` is
whole or absent (see the event index in the parent document): a failed *write* leaves no
byte of the record and refuses the whole call before the `COMMIT` — with no durable record
nothing would ever finish the file erasure — and a torn record whose bytes cannot be cut
back (`written=None`) refuses the same way, saying the ledger was rolled back and the index
may hold a partial record the next settlement removes, never "nothing was erased". A torn
`pending` can therefore no longer sit under a committed ledger erasure, to be cut as a torn
tail and take the erasure's only recovery record with it. A failed *flush* is a different outcome — the line landed and the next
settlement acts on it — so the reply says the copies are still going, never "nothing was
erased". A failure of the `COMMIT` rolls the ledger back with the record already durable;
holding an erasure id discriminates that case exactly, the `append` being the last statement
before the `COMMIT`, so the tool states both halves instead of raising, and the copies go at
the next settlement anyway — an erasure the operator authorised is not cancelled by its
ledger half failing, and leaving the copies would leave the data in the one place they were
told it would not be. And the crash this record exists for — *between* the `COMMIT` and the
unlinking — leaves the `pending` record for the next settlement to finish.

**The unlinks are durable before the record that closes them.** A directory entry's removal
lives in the directory's own blocks, not in the file's, so `erase_backups` flushes the
backups directory (`backups._fsync_dir`) before it appends `erase <op> committed`. Without
that flush a power loss after the terminal record brings every unlinked copy back — and the
terminal record is precisely what stops a later settlement from sweeping again, so the
copies would be whole restorable ledgers with nothing left that would remove them. The flush
runs whenever the terminal is about to, not only when this call unlinked something: an
earlier attempt can have done the unlinking and failed here, and this call then sees an empty
directory whose entry removals exist only in memory. A failure joins the sweep's failures
rather than raising on its own, so the erasure stays `pending` and the next settlement
unlinks whatever came back and flushes again.

**The terminal record's two failures are not the same event**, exactly as the `pending`
record's are not — and both happen only *after* the sweep above has already unlinked every
file and flushed the directory, never before. A failed *write* of `erase <op> committed`
raises `backups.ErasureRecordUnwritten` (carrying `written`, False or None, and the counts of
what the sweep removed): the line never landed as a record, so the erasure is still
`pending` in the index and a settlement that reads the file right now redoes the (idempotent)
sweep — but every copy is already gone, so `delete_all_data` says every copy was erased and
the directory flushed, and that the index record confirming it could not be *written*, never
that the sweep stopped part way, which would describe a directory it has just emptied as one
still holding copies. A failed *flush* (`backups.BackupError.written`) follows a line that DID
land: it is readable right now by anything that parses the index, so `_erase` returns
normally — carrying `Erasure.index_warning` instead of raising — and this same settlement
already reads the erasure as **committed**; `delete_all_data` reports it as a success with
that one line unflushed, not as a refusal. Only an actual crash before the kernel's own
writeback catches up can lose that unflushed line; if that happens, the record is gone from
what any later settlement reads, the erasure reads `pending` again exactly as the write
failure does, and the same idempotent sweep and re-append are what finish it.

## The session rows go with a second sweep

The banks are asked to withdraw their consents after the first sweep, outside every lock,
so another process can take a backup while they answer — and that copy holds the `sessions`
rows, bank-session identifiers, that the erasure destroys a moment later. So the rows the
provider proved gone are destroyed in their own transaction (`_destroy_proven_handles`):
`BEGIN IMMEDIATE`, settle, delete the proven rows, append `erase <op> pending` as the last
statement before the `COMMIT`, then sweep the copies under the still-held index handle and
append `erase <op> committed`. A copy taken before that `COMMIT` is in the directory when
the sweep runs; one taken after it copies a ledger without the rows. When the delete removes
no row, no record is written and no sweep runs: nothing was destroyed, so no copy can hold
what the ledger lost. If the settlement or the `pending` append fails, the delete rolls back
and the rows stay — a copy cannot then hold an identifier the ledger no longer has — and the
reply's WARNING says the rows were kept, why, and that `delete_all_data` again clears them. A
crash after the `COMMIT` leaves the `pending` record for the next settlement. A failure of the
sweep itself is a line after the erasure naming what went and what is left, never a raise.
That settlement also completes any erasure still pending — the first sweep's, when it stopped
— and the reply says what it removed, below the warning that it had stopped.

## Presence is three-state

`Path.exists()` is `os.path.exists`, which answers `False` for *every* `OSError` — `EACCES`
under a directory that cannot be searched, `EIO` on a failing disk — not only for a file
that is not there. The pass that records an already-absent indexed copy therefore wrote a
`prune` for a copy that was still on disk and merely unreadable, and the listing then showed
it `pruned` beside the file. It asks the filesystem instead: absent (`FileNotFoundError`) is
a `prune`; unreadable is counted like an unlink that failed, so the erasure stays `pending`
and a later settlement decides it on a readable disk; readable and present is neither. A
copy whose unlink already failed is not counted a second time here — one file is one
failure, and the count is what the operator is told is left.

## What a failure may say

**One file it cannot unlink never stops the sweep.** `backups.erase_backups` counts the
failures, keeps going, appends the audit records for what did go, and raises one
`backups.ErasureIncomplete` — a `BackupError` carrying a `backups.Erasure` with the counts.
Stopping at the first failure made "run it again" useless: the retry met the same file first.
The reply counts only what was removed, per audit shape — indexed copies (a `prune` record
each) apart from copies in flight (which never had one to prune) — names what could not go by
count and never by path, and says nothing rather than "0 backup file(s)". What is left is
counted by weight: a whole copy is restorable, so it carries the alarm; a `.partial` is not
in the index and `restore` refuses anything that is not, so it gets its own clause naming the
pages it still holds; an unflushed directory is neither, and is stated as what it is rather
than as a count of files. Every reply renders what went through one phrase, `Erasure.went()`, and asks whether
anything went through `Erasure.removed_any()`: replies that formatted the fields themselves
each left out whichever shape was added after them. `backups.settled_note` is the sentence
a call that *succeeded* adds when its settlement removed files on the way (`backup`,
`list_backups`). `ErasureIncomplete.describe()` is what the callers that changed
nothing themselves print — settlement removed copies, so "Nothing was changed." is false.
The same holds when settlement completed an erasure and something *else* refused afterwards:
`refusal_text` names what it removed, and `delete_all_data`, whose own settlement can complete
an earlier erasure and then fail on the record closing it, says the copies went and the
record follows at the next settlement, never "Nothing was erased". The
`WARNING` is reported, never raised: the ledger is already gone, and raising would discard
the only account of it.

## The calls a pending erasure stops

While an erasure is pending, `backups.settle` refuses, so every call that settles the index
refuses with it: `backup`, `restore_backup`, `delete_all_data`, and a write that carries a
workflow string (`_fenced_write`). **Nothing else.** Reads mostly answer: `sync` runs
regardless, and a write that carries no workflow never settles the index at all.
`list_backups` answers with the residue too, and is the operator's only in-tool view of it —
but only when the settlement failure is an `ErasureIncomplete` carrying a `state`; a plain
`BackupError` (the index or the backups directory itself unreadable) makes it refuse, the
same as the four writes above. Every reply about a stuck erasure
names that set and no wider: "every other bank-feed call refuses" was false of most of the
surface, and an operator told the plugin was wholly wedged goes looking for a fault that is
not there.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `plugins/bank-feed/server/backups.py`
- `plugins/bank-feed/server/tools_backup.py`
- `plugins/bank-feed/server/tools_destructive.py`

**Tests**
- `tests/test_backups.py`
- `tests/test_tools_backup.py`
- `tests/test_tools_destructive.py`

**Related**
- [`architecture/backups-and-restore.md`](../architecture/backups-and-restore.md)
- [`reference/tool-surface.md`](../reference/tool-surface.md)
<!-- END SOURCEMAP -->
