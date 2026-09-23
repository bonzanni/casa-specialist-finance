# plugins/bank-feed/server/tools_annotate.py
"""Annotation write tools: tags and an append-only note journal.

Ordinary (non-protected) tools by design — the annotation spec states
the tradeoff honestly: `untag_transaction` DOES delete a stored
classification, but a tag is one cheap write to restore, and annotation has
to be usable inside engagements or it is pointless. Notes are append-only;
nothing here (or anywhere) edits or deletes a note row outside the deletion
sites that erase its whole transaction.

Every write performs its state check and its write inside ONE
`BEGIN IMMEDIATE` transaction, so `apply_plan` cannot supersede the row
between the check and the write and strand a late annotation on a row whose
annotations already migrated.

Tags are charset-constrained (`TAG_RULE`) and therefore safe to print raw;
note text is untrusted prose and is fenced BY THE READERS (`tools_read`) —
this module never prints a stored note back.

`author` is a VALIDATED enum, not fenced text: attribution, not
authentication — it records who was speaking, on the caller's word.

`tag_transaction`, `untag_transaction` and `add_note` accept an optional
`workflow` + `expected_generation` pair (issue #39): a write that carries
one is fenced through `_fenced_write`, which mints that workflow's install
backup on its first write — the restore point a later `restore_backup`
would undo it to — before the write itself lands. `expected_generation`
guards against writing atop a ledger this pass has not re-read since a
restore; `_namespaced_without_workflow` refuses an `owner::` tag with no
workflow, since it is not this module's classification vocabulary to write
unattributed.
"""
from __future__ import annotations

import datetime as _dt
import re

import backups
import rules
import tools_read
from tools_read import register

# Same pattern as rules.TAG_RE (asserted equal by test). An optional
# `owner::` prefix marks another workflow's tag (issue #31).
TAG_RE = re.compile(r"^(?:[a-z][a-z0-9-]{0,15}::)?[a-z0-9][a-z0-9-]{0,31}$")
TAG_RULE = ("tags must be 1-32 characters of a-z, 0-9 or '-', starting with "
            "a letter or digit (they are lowercased and trimmed first)")
MAX_TAGS_PER_CALL = 16
MAX_TAGS_PER_ROW = 32
NOTE_MAX = 1000
AUTHORS = ("user", "agent")

_TAGS_SCHEMA = {"type": "array", "items": {"type": "string"},
                "minItems": 1, "maxItems": MAX_TAGS_PER_CALL}

MAX_ROWS_PER_CALL = 100

_ROW_IDS_SCHEMA = {"type": "array", "items": {"type": "integer"},
                   "minItems": 1, "maxItems": MAX_ROWS_PER_CALL}


def _now() -> str:
    # Same clock and format apply.py stamps first_seen/last_seen with.
    return _dt.datetime.now().isoformat()


def _invalid_tag(raw_value) -> str:
    """Refusal text for a tag outside the grammar. Deliberately silent about
    the `owner::` form: it must not nudge a classifier that wrote
    'food:groceries' into minting a namespace for hierarchy."""
    return "invalid tag %r: %s. Nothing was changed." % (raw_value, TAG_RULE)


def _normalize_tags(raw):
    """-> (ordered unique normalized tags, refusal-or-None).

    All-or-nothing: one bad tag refuses the whole call before anything is
    written, so a partially-applied tag set cannot exist.
    Duplicates collapsing AFTER normalization (' A ' and 'a') is fine.
    """
    if not isinstance(raw, list) or not raw:
        return [], "tags must be a non-empty array. Nothing was changed."
    if len(raw) > MAX_TAGS_PER_CALL:
        return [], ("at most %d tags per call (%d given). Nothing was "
                    "changed." % (MAX_TAGS_PER_CALL, len(raw)))
    seen, out = set(), []
    for t in raw:
        # Type-checked, not coerced: the server invokes tool functions without
        # schema validation, and str() would silently mint tags 'none', 'true'
        # and '123' from JSON null/true/123.
        if not isinstance(t, str):
            return [], ("tags must be strings (got %r). Nothing was changed."
                        % (t,))
        norm = t.strip().lower()
        if not TAG_RE.fullmatch(norm):
            return [], _invalid_tag(t)
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out, None


def _normalize_row_ids(raw):
    """-> (ordered unique ids, refusal-or-None). Python enforces what the
    JSON Schema only documents — the server invokes tool functions without
    schema validation. The cap fires on the RAW length,
    before dedupe, so the documented bound is the enforced one."""
    if not isinstance(raw, list) or not raw:
        return [], "row_ids must be a non-empty array. Nothing was changed."
    if len(raw) > MAX_ROWS_PER_CALL:
        return [], ("at most %d row_ids per call (%d given). Nothing was "
                    "changed." % (MAX_ROWS_PER_CALL, len(raw)))
    seen, out = set(), []
    for rid in raw:
        # bool is an int subclass: True would silently address row #1.
        if isinstance(rid, bool) or not isinstance(rid, int):
            return [], ("row_ids must be integers (got %r). Nothing was "
                        "changed." % (rid,))
        if rid not in seen:
            seen.add(rid)
            out.append(rid)
    return out, None


def _load_row(c, row_id):
    """-> (row, refusal-or-None), enforcing the row-state table for
    WRITES: active and vanished rows are annotatable (a tombstone is real
    history), a superseded row refuses with a pointer at its replacement,
    an unknown row_id refuses. Callers hold BEGIN IMMEDIATE while calling.
    """
    # bool is an int subclass: True would silently address row #1.
    if isinstance(row_id, bool) or not isinstance(row_id, int):
        return None, "row_id must be an integer. Nothing was changed."
    rid = row_id
    row = c.execute(
        "SELECT row_id, account_id, state, superseded_by, booking_date,"
        " amount_minor, currency, direction, counterparty FROM transactions"
        " WHERE row_id=?", (rid,)).fetchone()
    if row is None:
        return None, ("no transaction #%d — row handles come from "
                      "list_transactions. Nothing was changed." % rid)
    if row["state"] == "superseded":
        return None, ("row #%d was superseded by #%s; annotate that row "
                      "instead. Nothing was changed."
                      % (rid, row["superseded_by"]))
    if row["state"] not in ("active", "vanished"):
        # An ALLOWLIST, not "anything that is not superseded": a
        # state this module has never heard of is a row whose semantics it
        # cannot vouch for — fail closed, the codebase's dominant-bug-shape
        # lesson (a guard must branch on the truth, not a proxy for it).
        return None, ("row #%d is in state %s, which the annotation tools "
                      "do not touch. Nothing was changed."
                      % (rid, row["state"] if isinstance(row["state"], str)
                         and row["state"].isalnum() else "?"))
    return row, None


def _load_rows(c, row_ids):
    """-> (state-valid rows, [problem, ...]). Collects EVERY state failure
    AND still returns the rows that passed, so a caller can run its own
    per-row validations and name every problem — state and otherwise — in
    ONE refusal: discarding the valid rows on the first state failure hides
    an independent cap failure from the same refusal. Callers hold
    BEGIN IMMEDIATE while calling and
    write nothing when problems is non-empty."""
    rows, problems = [], []
    for rid in row_ids:
        row, refusal = _load_row(c, rid)
        if refusal:
            problems.append(refusal.replace(" Nothing was changed.", ""))
        else:
            rows.append(row)
    return rows, problems


def _echo(rows):
    """One bounded line per touched row — the transcription-error tripwire
    — a wrong-but-existing id renders as an alien row when the caller reads
    this back. dict(row) because sqlite3.Row has no .get and
    tools_read._signed calls row.get. Counterparty is provider
    text: neutralized, clipped SHORT (40), and fenced. Callers run this
    BEFORE COMMIT so a render error (e.g. a stored currency
    money.exponent rejects) aborts the whole call with nothing written."""
    lines = []
    for r in rows:
        d = dict(r)
        counterparty = tools_read._clip_to(tools_read._neutralize(
            "" if d.get("counterparty") is None
            else str(d.get("counterparty"))), 40)
        lines.append("  #%d  %s  %s %s  %s%s%s" % (
            d["row_id"],
            tools_read._neutralized(d.get("booking_date")),
            tools_read._signed(d),
            tools_read._safe_currency(d.get("currency")),
            tools_read.UNTRUSTED_OPEN, counterparty,
            tools_read.UNTRUSTED_CLOSE))
    return lines


WORKFLOW_RULE = ("workflow must look like owner@version (a-z owner up to 24 chars, "
                 "'@', a version of letters, digits, '.', '+', '_' or '-' up to 32)")


def _workflow_args(args):
    """-> (workflow|None, expected_generation|None, refusal|None). Both or
    neither: a workflow string without the generation it read, or a
    generation without a workflow, is refused. bool is not an int here."""
    wf, eg = args.get("workflow"), args.get("expected_generation")
    if wf is None and eg is None:
        return None, None, None
    if wf is None:
        return None, None, ("expected_generation is only meaningful with a workflow "
                            "string. Nothing was changed.")
    if not isinstance(wf, str) or not backups.WORKFLOW_RE.fullmatch(wf):
        return None, None, "invalid workflow %r: %s. Nothing was changed." % (wf, WORKFLOW_RULE)
    if eg is None:
        return None, None, ("a write carrying workflow %s must carry expected_generation "
                            "— the restore generation list_backups reported to this pass. "
                            "Nothing was changed." % wf)
    if isinstance(eg, bool) or not isinstance(eg, int) or eg < 0:
        return None, None, ("expected_generation must be a non-negative integer. "
                            "Nothing was changed.")
    return wf, eg, None


def _namespaced_without_workflow(tags, workflow):
    """A tag written `owner::name` is not this module's classification
    vocabulary — it belongs to whichever workflow owns that namespace, and
    writing it unattributed would let it sneak in as one. Refused only
    when no `workflow` is carried; a fenced write may write it (issue #39)."""
    if workflow is None:
        for t in tags:
            ns = rules.tag_namespace(t)
            if ns is not None:
                return ("%r belongs to another workflow (the '%s' namespace); writing "
                        "it needs that workflow's string in `workflow` and its "
                        "expected_generation, so a restore point precedes the first "
                        "write. Nothing was changed." % (t, ns))
    return None


def _mint_line(workflow, minted, remint):
    """The one sentence about the restore point this write took, in the one
    place both the ordinary reply and the retention-failure reply read it
    from. A RE-MINT says what it does not cover: the writes that happened
    under the registration whose copy went missing are not in the new copy."""
    if remint:
        return ("The earlier restore point for %s was missing; a new one was "
                "minted now (backup %s). It does not undo %s's earlier writes."
                % (workflow, minted.op_id, workflow))
    return "Restore point minted for %s: backup %s." % (workflow, minted.op_id)


def _orphan_quietly(paths, handle, minted):
    """The rolled-back mint's orphan record, on a path that is already
    reporting a failure. A second failure here must not REPLACE the original
    cause with its own — the caller's `except` is mid-flight."""
    try:
        backups.finish_backup(paths, handle, minted, committed=False)
    except backups.BackupError:
        pass


def _fenced_write(c, workflow, expected, validate, write):
    """The fixed order: BEGIN IMMEDIATE -> settle -> compare
    expected_generation with the SETTLED generation -> validate (reads; a
    refusal mints nothing) -> mint if the string is new OR its registered
    copy is gone -> write -> COMMIT -> terminal index record.

    `validate(c) -> (refusal_text | None, ctx)` performs every read-only
    check (row state, caps, the echo) and hands what the write needs;
    `write(c, ctx) -> reply_text` performs the INSERT/DELETE loop. Neither
    commits. Without a workflow this is the plain transaction every write
    always had, in two named halves."""
    c.execute("BEGIN IMMEDIATE")
    handle = minted = paths = state = None
    remint = False
    # ONE outer finally releases the index lock on EVERY exit — a refusal
    # that returns early would otherwise leak it, and flock is not
    # re-entrant, so the next backup, restore, listing or workflow write in
    # this process would refuse as busy for ever.
    try:
        try:
            if workflow is not None:
                paths = backups.paths_for(tools_read.ledger_path(c))
                state, handle = backups.settle(c, paths)
                if expected != state.generation:
                    c.execute("ROLLBACK")
                    return ("the ledger was restored since this pass began (restore "
                            "generation is %d, the pass expected %d) — re-read the "
                            "ledger before writing. Nothing was changed."
                            % (state.generation, expected))
            refusal, ctx = validate(c)
            if refusal:
                c.execute("ROLLBACK")
                return refusal
            if workflow is not None and (workflow not in state.registrations
                                         or workflow in state.broken):
                # A REGISTRATION WHOSE COPY IS GONE RE-MINTS HERE. Refusing
                # instead wedged that workflow for good: nothing in this tree
                # deletes one registration, and re-minting was impossible
                # precisely because the registration was still there — so the
                # remedy both texts named did not exist. A missing copy is
                # therefore treated exactly like an unregistered string, and
                # `take_backup`'s INSERT OR REPLACE moves the row onto the new
                # copy. The reply says what the new point does not cover.
                #
                # The restore point precedes the write: the copy is taken by a
                # separate reader and sees only committed state, so nothing this
                # transaction has read or will write is in it.
                remint = workflow in state.broken
                minted = backups.take_backup(c, paths, handle, "install:" + workflow,
                                             register=workflow)
            reply = write(c, ctx)
            c.execute("COMMIT")
        except backups.BackupError as exc:
            # A refusal here must not silently keep a successful mint alive:
            # if take_backup already landed before something later in THIS
            # try raised, the ROLLBACK undoes its registration INSERT, and
            # the copy on disk needs its own orphan record so settle() never
            # mistakes it for a live, registered install backup — structural,
            # not dependent on which exception raised or where in the try.
            if c.in_transaction:
                c.execute("ROLLBACK")
            if minted is not None:
                _orphan_quietly(paths, handle, minted)
            # An ErasureIncomplete out of `settle` above is not "nothing was
            # changed": that settlement unlinked copies before it refused, and
            # the text for what it did travels with the exception.
            return backups.refusal_text(exc)
        except Exception:
            # SQLite auto-rolls-back on SQLITE_FULL/IOERR: a bare ROLLBACK
            # after one of those would itself raise "cannot rollback -- no
            # transaction is active", masking the real exception and
            # skipping the orphan step below.
            if c.in_transaction:
                c.execute("ROLLBACK")
            if minted is not None:
                _orphan_quietly(paths, handle, minted)
            raise
        if minted is not None:
            line = _mint_line(workflow, minted, remint)
            try:
                backups.finish_backup(paths, handle, minted, committed=True)
            except backups.BackupError as exc:
                # finish_backup runs AFTER the COMMIT above: the write and
                # the mint are both already durable by the time retention
                # can fail, so this is never "nothing was changed" -- the
                # operator needs the reply AND the restore point id either
                # way (tools_backup.backup does the same thing one file
                # over).
                return (reply + "\n" + line + " Retention could not prune: %s "
                        "— the write and the restore point are complete." % exc)
            reply += "\n" + line
        return reply
    finally:
        if handle is not None:
            handle.close()


@register("tag_transaction",
          "Attach short classification tags to cached transactions "
          "(1-100 #row_id handles from list_transactions). Tags are "
          "normalized: lowercase, a-z 0-9 and '-', max 32 chars, at most "
          "32 per transaction. A tag written owner::name belongs to "
          "another workflow: it is not a classification, and has its own "
          "budget (16 per owner, 64 per transaction). All-or-nothing: one "
          "refusing row refuses the whole call and nothing is written. "
          "Idempotent per row. Writes for another workflow (owner::name "
          "tags, or notes a workflow makes) carry `workflow` (e.g. "
          "acct@1.2.0) and `expected_generation` from list_backups; the "
          "first write of a new workflow string mints its restore point.",
          {"type": "object", "properties": {
              "row_ids": _ROW_IDS_SCHEMA, "tags": _TAGS_SCHEMA,
              "workflow": {"type": "string"},
              "expected_generation": {"type": "integer", "minimum": 0}},
           "required": ["row_ids", "tags"]})
def tag_transaction(args: dict) -> str:
    tags, refusal = _normalize_tags(args.get("tags"))
    if refusal:
        return refusal
    workflow, expected, refusal = _workflow_args(args)
    if refusal:
        return refusal
    refusal = _namespaced_without_workflow(tags, workflow)
    if refusal:
        return refusal
    row_ids, refusal = _normalize_row_ids(args.get("row_ids"))
    if refusal:
        return refusal
    c = tools_read.conn()

    def validate(c):
        rows, problems = _load_rows(c, row_ids)
        # Cap checks run over the state-valid rows EVEN WHEN state
        # problems exist, so one refusal names every failure of both
        # kinds.
        existing_by_row = {}
        for row in rows:
            existing = {r[0] for r in c.execute(
                "SELECT tag FROM transaction_tags WHERE row_id=?",
                (row["row_id"],))}
            existing_by_row[row["row_id"]] = existing
            why = rules.cap_problem(existing, tags)
            if why is not None:
                problems.append("row #%d %s" % (row["row_id"], why))
        if problems:
            return "; ".join(problems) + " Nothing was changed.", None
        echo = _echo(rows)                     # before COMMIT, see _echo
        return None, {"rows": rows, "echo": echo,
                      "existing_by_row": existing_by_row}

    def write(c, ctx):
        rows, echo = ctx["rows"], ctx["echo"]
        existing_by_row = ctx["existing_by_row"]
        now = _now()
        for row in rows:
            for tag in tags:
                c.execute("INSERT OR IGNORE INTO transaction_tags"
                          "(row_id, tag, added_at) VALUES (?,?,?)",
                          (row["row_id"], tag, now))
        all_present = [row_id for row_id, existing in existing_by_row.items()
                       if set(tags) <= existing]
        lines = ["Tagged %d row(s) with %s." % (len(rows), ", ".join(tags))]
        if all_present:
            lines.append("On %d row(s) every listed tag was already present: %s."
                         % (len(all_present),
                            ", ".join("#%d" % rid for rid in all_present)))
        lines.append("Rows touched:")
        lines += echo
        return "\n".join(lines)

    return _fenced_write(c, workflow, expected, validate, write)


@register("untag_transaction",
          "Remove tags from cached transactions (1-100 #row_id handles "
          "from list_transactions; same normalization as tag_transaction, "
          "at most 16 tags per call). Removing a tag deletes that stored "
          "classification (cheap to re-add with tag_transaction). "
          "All-or-nothing: one refusing row refuses the whole call. Writes "
          "for another workflow (owner::name tags, or notes a workflow "
          "makes) carry `workflow` (e.g. acct@1.2.0) and "
          "`expected_generation` from list_backups; the first write of a "
          "new workflow string mints its restore point.",
          {"type": "object", "properties": {
              "row_ids": _ROW_IDS_SCHEMA, "tags": _TAGS_SCHEMA,
              "workflow": {"type": "string"},
              "expected_generation": {"type": "integer", "minimum": 0}},
           "required": ["row_ids", "tags"]})
def untag_transaction(args: dict) -> str:
    tags, refusal = _normalize_tags(args.get("tags"))
    if refusal:
        return refusal
    workflow, expected, refusal = _workflow_args(args)
    if refusal:
        return refusal
    refusal = _namespaced_without_workflow(tags, workflow)
    if refusal:
        return refusal
    row_ids, refusal = _normalize_row_ids(args.get("row_ids"))
    if refusal:
        return refusal
    c = tools_read.conn()

    def validate(c):
        rows, problems = _load_rows(c, row_ids)
        if problems:
            return "; ".join(problems) + " Nothing was changed.", None
        echo = _echo(rows)                     # before COMMIT, see _echo
        return None, {"rows": rows, "echo": echo}

    def write(c, ctx):
        rows, echo = ctx["rows"], ctx["echo"]
        removed = 0
        for row in rows:
            for tag in tags:
                cur = c.execute(
                    "DELETE FROM transaction_tags WHERE row_id=? AND tag=?",
                    (row["row_id"], tag))
                removed += cur.rowcount
        lines = ["Untagged: %d tag-row pair(s) removed (listed tags: %s)."
                 % (removed, ", ".join(tags))]
        if removed < len(rows) * len(tags):
            lines.append("%d pair(s) were not present to begin with."
                         % (len(rows) * len(tags) - removed))
        lines.append("Rows touched:")
        lines += echo
        return "\n".join(lines)

    return _fenced_write(c, workflow, expected, validate, write)


@register("add_note",
          "Append one free-text note to the journal of each listed cached "
          "transaction (1-100 #row_id handles). Notes are append-only — a "
          "correction is a new note. Max 1000 characters. author records "
          "who is speaking: 'user' (the operator actually said it) or "
          "'agent'. All-or-nothing across the listed rows. Writes for "
          "another workflow (owner::name tags, or notes a workflow makes) "
          "carry `workflow` (e.g. acct@1.2.0) and `expected_generation` "
          "from list_backups; the first write of a new workflow string "
          "mints its restore point.",
          {"type": "object", "properties": {
              "row_ids": _ROW_IDS_SCHEMA,
              "note": {"type": "string"},
              "author": {"type": "string", "enum": list(AUTHORS)},
              "workflow": {"type": "string"},
              "expected_generation": {"type": "integer", "minimum": 0}},
           "required": ["row_ids", "note", "author"]})
def add_note(args: dict) -> str:
    author = args.get("author")
    if author not in AUTHORS:
        return ("author must be 'user' or 'agent' — it records who is "
                "speaking. Nothing was changed.")
    note = args.get("note")
    if not isinstance(note, str):
        # Type-checked, not coerced: str() would store JSON true as
        # "True", and `or ""` branched numeric zero into "empty".
        return "note must be a string. Nothing was changed."
    if not note.strip():
        return "the note is empty. Nothing was changed."
    if len(note) > NOTE_MAX:
        return ("notes are capped at %d characters (this one is %d). "
                "Nothing was changed." % (NOTE_MAX, len(note)))
    workflow, expected, refusal = _workflow_args(args)
    if refusal:
        return refusal
    row_ids, refusal = _normalize_row_ids(args.get("row_ids"))
    if refusal:
        return refusal
    c = tools_read.conn()

    def validate(c):
        rows, problems = _load_rows(c, row_ids)
        if problems:
            return "; ".join(problems) + " Nothing was changed.", None
        echo = _echo(rows)                     # before COMMIT, see _echo
        return None, {"rows": rows, "echo": echo}

    def write(c, ctx):
        rows, echo = ctx["rows"], ctx["echo"]
        now = _now()
        for row in rows:
            c.execute(
                "INSERT INTO transaction_notes(row_id, author, note,"
                " created_at) VALUES (?,?,?,?)",
                (row["row_id"], author, note, now))
        lines = ["Note added to %d row(s) (author: %s). get_transaction shows "
                 "each journal." % (len(rows), author), "Rows touched:"]
        lines += echo
        return "\n".join(lines)

    return _fenced_write(c, workflow, expected, validate, write)


def _one_tag(value):
    """Normalize a single tag argument by the exact rules written tags
    obey. -> (tag, refusal-or-None)."""
    if not isinstance(value, str):
        return None, ("tag names must be strings (got %r). Nothing was "
                      "changed." % (value,))
    norm = value.strip().lower()
    if not TAG_RE.fullmatch(norm):
        return None, _invalid_tag(value)
    return norm, None


def _rule_tag_count(c, tag):
    """How many rules carry `tag` in their space-joined set. Tags are
    charset-safe (no %/_), so the LIKE needs no escaping."""
    return c.execute("SELECT COUNT(*) FROM tag_rules WHERE"
                     " ' '||tags||' ' LIKE ?",
                     ("% " + tag + " %",)).fetchone()[0]


def _rewrite_rule_tags(c, old, new):
    """Rename (new=str) or remove (new=None) a tag inside every rule's
    tag set, deduping within a set; a rule left tagless is deleted (a
    rule that tags nothing matches for nothing). Returns
    (rules_changed, rules_deleted). Caller holds the transaction —
    without this, the next apply_rules would resurrect the old tag on
    every matching row."""
    changed = deleted = 0
    for rule_id, tags in list(c.execute(
            "SELECT rule_id, tags FROM tag_rules")):
        parts = tags.split()
        if old not in parts:
            continue
        out = []
        for t in parts:
            t2 = new if t == old else t
            if t2 is not None and t2 not in out:
                out.append(t2)
        if out:
            c.execute("UPDATE tag_rules SET tags=? WHERE rule_id=?",
                      (" ".join(out), rule_id))
            changed += 1
        else:
            c.execute("DELETE FROM tag_rules WHERE rule_id=?", (rule_id,))
            deleted += 1
    return changed, deleted


@register("rename_tag",
          "Rename a tag on EVERY row that carries it — all states, "
          "superseded history included (a vocabulary edit, not a row "
          "edit). If the new name is already in use the call refuses "
          "unless merge is true; merging folds the two tags together "
          "IRREVERSIBLY (no record remains of which rows carried the old "
          "name). Refused for owner::name tags on either side: those belong "
          "to another workflow.",
          {"type": "object", "properties": {
              "old": {"type": "string"}, "new": {"type": "string"},
              "merge": {"type": "boolean"}},
           "required": ["old", "new"]})
def rename_tag(args: dict) -> str:
    old, refusal = _one_tag(args.get("old"))
    if refusal:
        return refusal
    new, refusal = _one_tag(args.get("new"))
    if refusal:
        return refusal
    if old == new:
        return ("old and new normalize to the same tag %r. Nothing was "
                "changed." % old)
    # Checked on the NAMES, before any lookup: moving a tag into, out of or
    # within another workflow's namespace would change what that workflow
    # asserts behind its back (issue #31) — including onto an unused name.
    for name in (old, new):
        ns = rules.tag_namespace(name)
        if ns is not None:
            return ("%r belongs to the '%s' workflow's namespace; rename_tag "
                    "only edits the classification vocabulary. Change it "
                    "through the workflow that owns it. Nothing was changed."
                    % (name, ns))
    merge = args.get("merge", False)
    if not isinstance(merge, bool):
        # Only a JSON boolean enables the irreversible path. isinstance,
        # not `in (True, False)`: Python equates 1 == True, so a numeric
        # merge would slip the membership check and WRITE.
        return "merge must be boolean true or false. Nothing was changed."
    c = tools_read.conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        old_n = c.execute("SELECT COUNT(*) FROM transaction_tags WHERE"
                          " tag=?", (old,)).fetchone()[0]
        if not old_n and not _rule_tag_count(c, old):
            c.execute("ROLLBACK")
            return "tag %r is not in use. Nothing was changed." % old
        new_n = c.execute("SELECT COUNT(*) FROM transaction_tags WHERE"
                          " tag=?", (new,)).fetchone()[0]
        new_rules_n = _rule_tag_count(c, new)
        # The destination existing ANYWHERE — rows or rule tag sets —
        # makes this a merge.
        if (new_n or new_rules_n) and merge is not True:
            c.execute("ROLLBACK")
            return ("tag %r is already in use on %d row(s) and %d "
                    "rule(s) (%r is on %d row(s)). Renaming onto it "
                    "MERGES the two tags, which is irreversible — call "
                    "again with merge: true if that is what you mean. "
                    "Nothing was changed."
                    % (new, new_n, new_rules_n, old, old_n))
        c.execute("UPDATE OR IGNORE transaction_tags SET tag=? WHERE tag=?",
                  (new, old))
        collapsed = c.execute(
            "DELETE FROM transaction_tags WHERE tag=?", (old,)).rowcount
        rules_changed, _ = _rewrite_rule_tags(c, old, new)
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    renamed = old_n - collapsed
    lines = ["Renamed %r to %r on %d row(s)." % (old, new, renamed)]
    if rules_changed:
        lines.append("%d auto-tagging rule(s) now say %r."
                     % (rules_changed, new))
    if collapsed:
        lines.append("%d row(s) carried both tags and collapsed to one "
                     "(merge). %r now spans %d row(s)."
                     % (collapsed, new, new_n + renamed))
    return "\n".join(lines)


@register("delete_tag",
          "Remove a tag from EVERY row that carries it — all states, "
          "superseded history included. This deletes a stored "
          "classification everywhere and cannot be undone: no record "
          "remains of which rows had it. untag_transaction removes it "
          "from specific rows instead.",
          {"type": "object", "properties": {"tag": {"type": "string"}},
           "required": ["tag"]})
def delete_tag(args: dict) -> str:
    tag, refusal = _one_tag(args.get("tag"))
    if refusal:
        return refusal
    c = tools_read.conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        # FOUR fixed buckets: state has no CHECK constraint, so
        # three named states cannot account for every row, and an unknown
        # state's TEXT never reaches output — only its count, as 'other'.
        # LEFT JOIN so a tag row whose transaction is somehow gone still
        # counts rather than silently vanishing from the report.
        buckets = {"active": 0, "vanished": 0, "superseded": 0, "other": 0}
        for state, n in c.execute(
                "SELECT CASE WHEN t.state IN ('active','vanished',"
                "'superseded') THEN t.state ELSE 'other' END, COUNT(*)"
                " FROM transaction_tags tt LEFT JOIN transactions t"
                " ON t.row_id = tt.row_id WHERE tt.tag=? GROUP BY 1",
                (tag,)):
            buckets[state] += n
        total = sum(buckets.values())
        if not total and not _rule_tag_count(c, tag):
            c.execute("ROLLBACK")
            return "tag %r is not in use. Nothing was changed." % tag
        c.execute("DELETE FROM transaction_tags WHERE tag=?", (tag,))
        rules_changed, rules_deleted = _rewrite_rule_tags(c, tag, None)
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    parts = ["%d %s" % (buckets[k], k) for k in
             ("active", "vanished", "superseded", "other") if buckets[k]]
    reply = ("Deleted tag %r from %d row(s) (%s). This classification is "
             "gone; there is no record of which rows carried it."
             % (tag, total, ", ".join(parts) or "none"))
    ns = rules.tag_namespace(tag)
    if ns is not None:
        reply += (" It belonged to the '%s' workflow, which will reassert it "
                  "wherever it still holds." % ns)
    if rules_changed or rules_deleted:
        reply += (" Removed from %d rule(s); %d rule(s) were left "
                  "tagless and deleted."
                  % (rules_changed + rules_deleted, rules_deleted))
    return reply
