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

## Rule 1 is currently inert — a known limitation

Reference-based identity depends on a per-bank capability record saying that this bank's
references have been observed stable. **No such record ships, and no shipped tool earns
one.** `capability()` reads the `aspsp_capability` table, which starts empty and which
nothing in the product writes; an absent row reads as untrusted, so identity falls
through to rule 2 — heuristic windowed matching.

The table is a real table, not a stub: `set_capability()` exists, and a row put there by
hand, or one surviving in an old database that the version 5 migration did not match,
*would* be honoured. So the accurate statement is that reference identity is inert in
any installation that has not been given a capability row from outside the product.

This is deliberate, not an oversight. An earlier version seeded the capability table at
database open with one installation's measurements, which made one household's account
statistics every installation's trust defaults. That seeder is gone, and schema version
5 **retires** rows it previously wrote: removing the seed from the source would
otherwise have left the figures sitting in every already-deployed database.

Retirement moves rows into a separate table rather than deleting them, because the rows
can only be recognised from their provenance text and no text predicate is exact — a
local note deliberately shaped like the seed's would match. Moving makes over-matching
recoverable, which is what makes it the safe direction to err in. Nothing reads the
retired table; `capability()` looks only at the live one.

Earning trust locally — what counts as an observation, how observations aggregate across
accounts at one bank, what threshold is enough, how trust is demoted, and what happens
to rows already ingested under it — is designed but not built. It is tracked as **issue
#1** on this repository.

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

SQLite, forward-only migrations, currently version 5. `open_db()` applies migrations,
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
| `aspsp_capability` | per-bank reference behaviour; no row ships |
| `aspsp_capability_retired` | rows the version 5 migration took out, kept verbatim |
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
