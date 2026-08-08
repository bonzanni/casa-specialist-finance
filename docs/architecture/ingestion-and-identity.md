# Ingestion and identity

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

A provider page is not a ledger row. Between them sits the question this document is
about: **is this transaction one I already have?** Getting it wrong in one direction
duplicates a payment; in the other, it silently drops one.

The work splits in two, deliberately:

- `ingest.py` decides. It is **pure** — no I/O — and produces a *plan*.
- `apply.py` writes. It takes the plan and lands it whole or not at all.

Nothing else writes transactions.

## The identity rules, in order

0. **`account_id` is the durable key**, assigned locally. The provider's per-session
   account handle is *never* a durable key: a renewal mints new handles for the same
   real accounts.
1. **A provider reference is identity where present** — corroborated, never blind, and
   only for a bank *observed* to supply stable references, within the scope in which
   they were observed unique. Global uniqueness is never assumed.
2. **Reference-less rows use windowed nearest-date matching**, not multiset equality.
3. **A deficit tombstones only well inside an interval something licensed it to** — see
   coverage, below. Like rule 1, this rule is currently **switched off**, and
   unconditionally so: nothing is ever tombstoned in any installation.
4. **Occurrence is monotonic per account and identity key, and never reused.** It is
   allocated above every occurrence ever issued, including tombstoned rows and
   occurrences no longer visible in the current pass, which is why `reconcile()` takes a
   durable high-water map rather than looking at what it can currently see.
5. **Matching is deterministic, and every heuristic decision is recorded** on the row it
   produced.

## Rule 1 trust is earned, per account, from local evidence

Reference-based identity depends on a record saying that this account's provider has
been observed to supply stable references. **No such record ships.** A fresh install
trusts nothing and every reconcile is heuristic windowed matching, until the
installation earns trust on its own accounts:

- **Evidence is measured before every reconcile.** `measure_references()` reduces a
  completed run's fetched rows to aggregate metrics — distinct referenced
  *transactions* (restatements collapse, so fifty copies of one row are one
  transaction), reference reuse (one reference on more than one transaction — the
  standing-order shape), and the span the referenced transactions cover.
- **Only a labelled deep run can grant.** The two fresh-SCA backfills (first link,
  renewal) file a `deep` observation; a qualifying one needs at least 100 distinct
  referenced transactions spanning at least 180 days with zero measured reuse. The
  span floor is what makes silence meaningful: 180 days contains every monthly
  recurrence at least six times, so recurrence reuse cannot hide outside the sample.
  A narrow routine refresh can never grant — but *any* completed run that measures
  reuse files a `reuse_event`, because sample size bounds what silence proves, never
  what a sighting proves.
- **Trust is derived at read time**, per `(bank, account)`, from the append-only
  `ref_observations` table: one qualifying observation and no reuse sighting. There is
  no cached verdict to drift, and no manual switch — the old `capability()` writer is
  gone, because a trust claim an operator cannot trace to an observation is exactly
  what the removed seeder was.
- **A run that measures reuse reconciles untrusted itself**, files the sighting in the
  same transaction that applies its plan, and the withdrawal is disclosed on the sync
  note line. Rows already matched by reference keep their recorded match method: those
  labels are true statements about how the row was matched at the time, and rewriting
  committed identity on a later opinion is the history rewrite this module refuses
  everywhere. A plan built under trust is revalidated inside the apply transaction and
  rebuilt heuristically if a concurrent run demoted the account in between.
- **Erasure follows the account.** `forget_local_account` and `delete_all_data` take
  the evidence with them; `purge` retains it and says so — the evidence describes the
  bank's behaviour, not the purged rows. Because an account's id is a deterministic
  HMAC of IBAN and currency, each account life carries a random *incarnation* token,
  and an evidence write requires the token its run captured — a run paused across a
  forget-and-relink cannot attach stale evidence to the account's new life.

This replaced a seeder that wrote one installation's measurements into every
installation's database at open. Schema version 5 **retires** rows that seeder wrote,
and version 6 retires everything else still resident in the old per-bank table — under
the earned model any per-bank row is an observation-free trust claim. Retirement moves
rows into a separate table rather than deleting them, because the seeded rows can only
be recognised from their provenance text and no text predicate is exact. Moving makes
over-matching recoverable, which is what makes it the safe direction to err in.
Nothing reads the retired table.

## Coverage: the difference between "nothing happened" and "we do not know"

`coverage` holds, per account, the date intervals history has been **observed** over:
bounded below by the oldest row a response actually returned. Intervals are merged **on
write**, so the table is a set of disjoint intervals rather than an append log that only
looks correct when read through the right function.

**Read that bound precisely, because the imprecise reading is the dangerous one.** A
clean paginated response proves the **existence** of the rows it returned. It does not
prove the **completeness** of the interval between them. A pass whose oldest row sits
years before a row that later goes missing looks like it proved that whole span, and it
did not.

So coverage is what lets the ledger say "this range has never been looked at" as
distinct from "this range was read". It is **not** a licence to conclude that a row now
absent was deleted. Computing a deletion licence from the response under reconciliation
is a structural error no matter how wide or well-evidenced the licence looks: two
derivations were tried, and each destroys real history — one tombstones everything a
truncated-but-clean response did not repeat, the other widens straight back out the
moment such a response happens to carry one old, unrelated row.

So **rule 3 is switched off, unconditionally**. Every path through the backfill hands
reconciliation the same degenerate, no-licence interval, so the rule cannot fire, and
nothing is tombstoned in any installation. `TOMBSTONE_LICENSED_ASPSPS` in `flows.py` is
an empty documentary placeholder: nothing consults it, and filling it in changes
nothing on its own. It marks where a per-bank re-listing measurement would attach if one
were ever built — the same missing measurement, and the same missing per-installation
observation, that leaves rule 1 inert.

`purge` still maintains coverage, for the reason coverage exists. A purge that erased
rows and left the interval asserting they had been observed would report the deleted
years as quiet ones.

## Applying a plan

Three rules govern `apply_plan()`:

- **A plan lands whole or not at all.** A half-applied page set would leave coverage
  attesting to rows that are not in the ledger.
- **Inserts run first**, because a supersede points a stored pending row at a booked row
  the same plan is inserting, and only the database knows that row's id.
- **Counts describe writes, not intentions.** Every update, supersede, tombstone and
  flag names a row id read at some earlier point; a row deleted underneath the plan in
  between makes that write affect nothing. Such an entry counts as nothing, rather than
  being reported as a change that did not happen.

## Money

`money.py` is 49 lines and holds every rounding decision: money is integer minor units,
never a binary float. Sums are per currency and are never converted.

## The schema

SQLite, forward-only migrations, currently version 6. `open_db()` applies migrations,
checks the file modes, and refuses a pre-existing symlink at the database or sidecar
paths — those checks are part of opening the database rather than something applied
afterwards. They detect an existing symlink; they are not symlink-race safe, and the
code says so where it matters.

| Table | Holds |
|---|---|
| `meta` | schema version, restore fingerprint, install marker |
| `sessions` | provider sessions and their generation |
| `accounts` | the durable account records, their labels and inclusion |
| `balances` | the latest balances per account |
| `transactions` | the ledger itself, with identity key, occurrence and match evidence |
| `transaction_refs` | provider references seen for a row |
| `occurrence_alloc` | the durable high-water mark rule 4 depends on |
| `coverage` | disjoint observed intervals per account |
| `sync_state` | per account and resource, the last successful refresh |
| `ref_observations` | append-only reference evidence per account; trust derives from it |
| `aspsp_capability` | the retired per-bank model; empty, nothing reads or writes it |
| `aspsp_capability_retired` | rows the version 5 and 6 migrations took out, kept verbatim |
| `attempts` | our half of the callback contract |
| `transaction_tags`, `transaction_notes`, `notes_fts` | annotations and their index |
| `tag_rules` | the deterministic auto-tagging rulebook |

Restore provenance and capability both live in these tables, and neither ever holds key
material. What `provenance.py` builds is the restore *check* and its report:
re-validating key-to-application identity, re-checking session status against the
provider, and marking cached data stale are not automatic — a mismatch is reported and
the remedy is the operator's.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `plugins/bank-feed/server/ingest.py::reconcile`
- `plugins/bank-feed/server/apply.py::apply_plan`
- `plugins/bank-feed/server/provenance.py::capability`
- `plugins/bank-feed/server/money.py`
- `plugins/bank-feed/server/store.py::open_db`

**Tests**
- `tests/test_ingest.py`
- `tests/test_apply.py`
- `tests/test_provenance.py`
- `tests/test_store.py`
- `tests/test_money.py`

**Related**
- [`architecture/bank-linking.md`](../architecture/bank-linking.md)
- [`architecture/annotations-and-rules.md`](../architecture/annotations-and-rules.md)
<!-- END SOURCEMAP -->
