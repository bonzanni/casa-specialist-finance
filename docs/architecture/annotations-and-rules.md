# Annotations and rules

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

Three layers sit on top of the ledger, in increasing order of judgement:

1. **Annotations** — tags and notes a person or an agent attaches to a transaction.
2. **Rules** — a deterministic rulebook that applies tags automatically at ingest.
3. **The classifier** — a skill in the `tx-classifier` plugin that decides what the
   rules should be, and works the queue the rules cannot settle.

Everything durable belongs to layer 1 and 2, in `bank-feed`. Layer 3 owns no state at
all.

## Annotations

`tools_annotate.py` owns the writes. Tags are constrained to a safe character set and
are therefore printed raw; note text is untrusted prose and is fenced by the *readers*,
never by the writer — this module never prints a stored note back.

Notes are **append-only in their content**: nothing rewrites a note's text, author or
timestamp, and nothing deletes a note row except the deletion paths that erase its whole
transaction. One field does change — when a pending transaction is superseded by the
booked row it became, `apply_plan()` repoints its notes at the replacement, so the
journal follows the transaction rather than being stranded on a row nobody reads. Tags are deletable, and that asymmetry is a stated
trade: `untag_transaction` does destroy a stored classification, but a tag is one cheap
write to restore, and annotation has to be usable inside an ordinary conversation or it
is pointless. That is why none of these are protected tools.

Every annotation write performs its state check and its write inside a single immediate
transaction, so a concurrent `apply_plan()` cannot supersede the row between the check
and the write and strand the annotation on a row whose annotations have already
migrated.

`tag_transaction`, `untag_transaction` and `add_note` take two further optional
arguments, `workflow` and `expected_generation`, for a caller that is itself a workflow
rather than the resident: the first write of a new `workflow` string mints a restore
point before the write lands, and every later write on that string is refused if the
ledger's restore generation has moved since the pass began. `owner::name` tags — another
workflow's own vocabulary — may only be written this way. `architecture/backups-and-restore.md`
is where the mint, the fence and the restore itself are described.

Note search is a full-text index maintained alongside the notes table. The best-ranked
match is not necessarily the latest word on a row, so each hit carries the matched note's
date and how many notes follow it, and the journal header says the latest note reflects
the outcome. Aggregation lives
in `tools_aggregate.py`, and `spend_by_tag` is explicitly a **lens, not a ledger**: a
row carrying several tags appears in several groups, so groups overlap and never sum to
an account total. Every call says so. Sums are per currency and never converted; a
currency that fails validation becomes a counted, text-free gap rather than a guess,
because a sum of unknown denomination is a gap.

## The rule engine

`rules.py` is the pure core, importable by both the ingest path (`apply.py`) and the
tool layer (`tools_rules.py`), and it never imports the tool layer.

**All text matching happens in Python, with one canonicalizer.** Never SQLite's own
lowercasing or pattern matching: rule values are canonicalized at write time and row
values at match time, by `canon_text()`, the same function in both directions. Two
canonicalizers is how a rulebook starts matching in the editor and not at ingest.

Rules are validated on write (`validate_rule()`), matched by `rule_matches()`, and
applied to a set of rows by `apply_to_rows()`. The rulebook survives independently of
the rows it has tagged — it is row-independent, and a schema migration exists for
precisely that table.

**A rule can be scoped to where a transaction lives.** Two optional predicates, never
together: `account` names one account by the same `account_id` every other tool takes,
and `account_category` names `personal` or `company`. Neither is an anchor — a rule still
needs a counterparty or a remittance word, because "every company-account debit" is the
mislabeling machine the anchor requirement exists to refuse. The category is read from
the account each time the rulebook runs, not copied into the rule, so recategorizing an
account (an operator-granted `label_account`) re-scopes category rules from the next
application on; an unlabelled account matches no category rule. An account rule
survives `forget_local_account` and matches nothing until that same account is linked
again, which brings it back, since the id is a keyed hash of IBAN and currency.

The signature is the duplicate check, and it serializes every predicate, so adding the
two predicates changed its shape. Schema v8 rewrites each stored signature to the new
form in the same transaction that adds the columns — without it, re-minting an existing
rule would pass the check — and does so on the string Python wrote rather than
rebuilding it in SQL, whose JSON output escapes non-ASCII differently.

**Reserved workflow tags are machinery, not classifications.** A rule that could mint
one would mechanically park or terminalize every matching row, which is the state
machine the classifier owns. Rules cannot mint them.

## The classifier split

`tx-classifier` is a skill, and nothing else: no server, no storage, no MCP
configuration. Its manifest declares one casa key, `casa.jobs`, naming that skill as
the background job "Classify transactions" (unlimited batches, 30 turns each): from
casa v0.321.0 the assistant can start it, and casa then drives one batch per turn in
the specialist's own topic until the workable queue is empty. A casa before v0.321.0
ignores the declaration and the workflow runs as it always has. It is bundled as a dependency of the same component, so `bank-feed` is
always present by construction, and the role's launch gate refuses to start the
specialist without it.

What the classifier does with bank-feed's primitives:

- reads the queue of rows the rulebook could not settle,
- asks the operator about the ones that need a person,
- writes the answer back as tags, notes and — where the answer generalises — a new rule
  with its rationale recorded as a note.

Its durable state is entirely bank-feed's: the queue is a query over workflow tags, the
rationale is a note, the decision is a tag or a rule row. Nothing is remembered in the
skill, because a skill has nowhere to remember it.

**Neither plugin can schedule.** There is no timer here: recurring classification is a
casa reminder the operator creates, which produces a turn in which the skill runs.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `plugins/bank-feed/server/rules.py::canon_text`
- `plugins/bank-feed/server/rules.py::validate_rule`
- `plugins/bank-feed/server/rules.py::apply_to_rows`
- `plugins/bank-feed/server/tools_annotate.py`
- `plugins/bank-feed/server/tools_aggregate.py`
- `plugins/bank-feed/server/tools_rules.py`
- `plugins/tx-classifier/skills/classify-transactions/SKILL.md`

**Tests**
- `tests/test_rules.py`
- `tests/test_tools_annotate.py`
- `tests/test_tools_aggregate.py`
- `tests/test_tools_rules.py`
- `tests/test_tx_classifier.py`

**Related**
- [`architecture/ingestion-and-identity.md`](../architecture/ingestion-and-identity.md)
- [`reference/tool-surface.md`](../reference/tool-surface.md)
- [`architecture/backups-and-restore.md`](../architecture/backups-and-restore.md)
<!-- END SOURCEMAP -->
