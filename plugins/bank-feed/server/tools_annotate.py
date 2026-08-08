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
"""
from __future__ import annotations

import datetime as _dt
import re

import tools_read
from tools_read import register

TAG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
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
            return [], ("invalid tag %r: %s. Nothing was changed."
                        % (t, TAG_RULE))
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


@register("tag_transaction",
          "Attach short classification tags to cached transactions "
          "(1-100 #row_id handles from list_transactions). Tags are "
          "normalized: lowercase, a-z 0-9 and '-', max 32 chars, at most "
          "32 per transaction. All-or-nothing: one refusing row refuses "
          "the whole call and nothing is written. Idempotent per row.",
          {"type": "object", "properties": {
              "row_ids": _ROW_IDS_SCHEMA, "tags": _TAGS_SCHEMA},
           "required": ["row_ids", "tags"]})
def tag_transaction(args: dict) -> str:
    tags, refusal = _normalize_tags(args.get("tags"))
    if refusal:
        return refusal
    row_ids, refusal = _normalize_row_ids(args.get("row_ids"))
    if refusal:
        return refusal
    c = tools_read.conn()
    c.execute("BEGIN IMMEDIATE")
    try:
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
            if len(existing | set(tags)) > MAX_TAGS_PER_ROW:
                problems.append(
                    "row #%d already carries %d tags and this call "
                    "would push it past the cap of %d"
                    % (row["row_id"], len(existing), MAX_TAGS_PER_ROW))
        if problems:
            c.execute("ROLLBACK")
            return "; ".join(problems) + " Nothing was changed."
        echo = _echo(rows)                     # before COMMIT, see _echo
        now = _now()
        for row in rows:
            for tag in tags:
                c.execute("INSERT OR IGNORE INTO transaction_tags"
                          "(row_id, tag, added_at) VALUES (?,?,?)",
                          (row["row_id"], tag, now))
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
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


@register("untag_transaction",
          "Remove tags from cached transactions (1-100 #row_id handles "
          "from list_transactions; same normalization as tag_transaction, "
          "at most 16 tags per call). Removing a tag deletes that stored "
          "classification (cheap to re-add with tag_transaction). "
          "All-or-nothing: one refusing row refuses the whole call.",
          {"type": "object", "properties": {
              "row_ids": _ROW_IDS_SCHEMA, "tags": _TAGS_SCHEMA},
           "required": ["row_ids", "tags"]})
def untag_transaction(args: dict) -> str:
    tags, refusal = _normalize_tags(args.get("tags"))
    if refusal:
        return refusal
    row_ids, refusal = _normalize_row_ids(args.get("row_ids"))
    if refusal:
        return refusal
    c = tools_read.conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        rows, problems = _load_rows(c, row_ids)
        if problems:
            c.execute("ROLLBACK")
            return "; ".join(problems) + " Nothing was changed."
        echo = _echo(rows)                     # before COMMIT, see _echo
        removed = 0
        for row in rows:
            for tag in tags:
                cur = c.execute(
                    "DELETE FROM transaction_tags WHERE row_id=? AND tag=?",
                    (row["row_id"], tag))
                removed += cur.rowcount
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    lines = ["Untagged: %d tag-row pair(s) removed (listed tags: %s)."
             % (removed, ", ".join(tags))]
    if removed < len(rows) * len(tags):
        lines.append("%d pair(s) were not present to begin with."
                     % (len(rows) * len(tags) - removed))
    lines.append("Rows touched:")
    lines += echo
    return "\n".join(lines)


@register("add_note",
          "Append one free-text note to the journal of each listed cached "
          "transaction (1-100 #row_id handles). Notes are append-only — a "
          "correction is a new note. Max 1000 characters. author records "
          "who is speaking: 'user' (the operator actually said it) or "
          "'agent'. All-or-nothing across the listed rows.",
          {"type": "object", "properties": {
              "row_ids": _ROW_IDS_SCHEMA,
              "note": {"type": "string"},
              "author": {"type": "string", "enum": list(AUTHORS)}},
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
    row_ids, refusal = _normalize_row_ids(args.get("row_ids"))
    if refusal:
        return refusal
    c = tools_read.conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        rows, problems = _load_rows(c, row_ids)
        if problems:
            c.execute("ROLLBACK")
            return "; ".join(problems) + " Nothing was changed."
        echo = _echo(rows)                     # before COMMIT, see _echo
        now = _now()
        for row in rows:
            c.execute(
                "INSERT INTO transaction_notes(row_id, author, note,"
                " created_at) VALUES (?,?,?,?)",
                (row["row_id"], author, note, now))
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    lines = ["Note added to %d row(s) (author: %s). get_transaction shows "
             "each journal." % (len(rows), author), "Rows touched:"]
    lines += echo
    return "\n".join(lines)


def _one_tag(value):
    """Normalize a single tag argument by the exact rules written tags
    obey. -> (tag, refusal-or-None)."""
    if not isinstance(value, str):
        return None, ("tag names must be strings (got %r). Nothing was "
                      "changed." % (value,))
    norm = value.strip().lower()
    if not TAG_RE.fullmatch(norm):
        return None, ("invalid tag %r: %s. Nothing was changed."
                      % (value, TAG_RULE))
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
          "name).",
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
    if rules_changed or rules_deleted:
        reply += (" Removed from %d rule(s); %d rule(s) were left "
                  "tagless and deleted."
                  % (rules_changed + rules_deleted, rules_deleted))
    return reply
