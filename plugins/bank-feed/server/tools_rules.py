# plugins/bank-feed/server/tools_rules.py
"""Auto-tagging rule tools. Ordinary tools.

Validation and matching live in rules.py (the pure core apply_plan also
uses); this module owns transactions, refusal wording, and rendering.
Rule anchors are provider-derived text and render through the
tools_read._untrusted fence; rationale is untrusted prose and renders
through the note fence. Tags and validated enums render raw.
"""
from __future__ import annotations

import datetime as _dt

import rules
import tools_read
from tools_read import register

_RULE_ARGS = {
    "counterparty": {"type": "string"},
    "remittance_word": {"type": "string"},
    "direction": {"type": "string", "enum": ["debit", "credit"]},
    "currency": {"type": "string"},
    "amount_min_minor": {"type": "integer"},
    "amount_max_minor": {"type": "integer"},
    "dom_min": {"type": "integer"}, "dom_max": {"type": "integer"},
    "weekdays": {"type": "array", "items": {"type": "string"}},
    "tags": {"type": "array", "items": {"type": "string"},
             "minItems": 1, "maxItems": rules.MAX_TAGS_PER_RULE},
    "rationale": {"type": "string"},
}


def _now() -> str:
    # Same clock and format apply.py stamps first_seen/last_seen with.
    return _dt.datetime.now().isoformat()


def _rule_id_arg(value):
    # bool is an int subclass: True would silently address rule #1.
    if isinstance(value, bool) or not isinstance(value, int):
        return None, "rule_id must be an integer. Nothing was changed."
    return value, None


def _sentence(rule: dict) -> str:
    """One human-readable line per rule. Anchors are provider-derived:
    fenced. Everything else is validated storage: raw."""
    preds = []
    if rule["counterparty_canon"] is not None:
        preds.append("counterparty %s"
                     % tools_read._untrusted(rule["counterparty_canon"]))
    if rule["remittance_token"] is not None:
        preds.append("remittance word %s"
                     % tools_read._untrusted(rule["remittance_token"]))
    if rule["direction"] is not None:
        preds.append({"DBIT": "debits", "CRDT": "credits"}.get(
            rule["direction"], "?"))
    if rule["amount_min_minor"] is not None or \
            rule["amount_max_minor"] is not None:
        preds.append("amount %s..%s minor %s"
                     % (rule["amount_min_minor"],
                        rule["amount_max_minor"],
                        rule["currency"] or ""))
    elif rule["currency"] is not None:
        preds.append(rule["currency"])
    if rule["dom_min"] is not None or rule["dom_max"] is not None:
        preds.append("day %s..%s" % (rule["dom_min"], rule["dom_max"]))
    if rule["weekdays"] is not None:
        preds.append("on %s" % rule["weekdays"])
    return "#%d  %s -> %s" % (rule["rule_id"], "; ".join(preds),
                              rule["tags"])


@register("add_rule",
          "Mint a deterministic auto-tagging rule: a conjunction of "
          "simple predicates (counterparty and/or remittance_word "
          "anchor; optional direction debit/credit, currency, "
          "amount_min/max_minor band (currency required with amounts), "
          "dom_min/dom_max day-of-month band, weekdays) that additively "
          "tags every matching transaction at ingest and on "
          "apply_rules. Strict by design: rules only ADD tags, never "
          "remove. rationale (recommended, max 1000 chars) records how "
          "the rule came about.",
          {"type": "object", "properties": dict(_RULE_ARGS),
           "required": ["tags"]})
def add_rule(args: dict) -> str:
    fields, refusal = rules.validate_rule(args)
    if refusal:
        return refusal
    sig = rules.signature(fields)
    c = tools_read.conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        dup = c.execute("SELECT rule_id FROM tag_rules WHERE"
                        " signature=?", (sig,)).fetchone()
        if dup:
            c.execute("ROLLBACK")
            return ("a rule with this exact predicate set already "
                    "exists: rule #%d — replace_rule can change its "
                    "tags or rationale. Nothing was changed."
                    % dup["rule_id"])
        n = c.execute("SELECT COUNT(*) FROM tag_rules").fetchone()[0]
        if n >= rules.RULEBOOK_CAP:
            c.execute("ROLLBACK")
            return ("the rulebook is at its cap of %d rules — if it got "
                    "here, something is minting junk; review with the "
                    "operator rather than pruning silently. Nothing was "
                    "changed." % rules.RULEBOOK_CAP)
        cur = c.execute(
            "INSERT INTO tag_rules(signature, counterparty_canon,"
            " remittance_token, direction, currency, amount_min_minor,"
            " amount_max_minor, dom_min, dom_max, weekdays, tags,"
            " rationale, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sig, fields["counterparty_canon"],
             fields["remittance_token"], fields["direction"],
             fields["currency"], fields["amount_min_minor"],
             fields["amount_max_minor"], fields["dom_min"],
             fields["dom_max"], fields["weekdays"], fields["tags"],
             fields["rationale"], _now()))
        rule_id = cur.lastrowid
        rule = dict(c.execute("SELECT * FROM tag_rules WHERE rule_id=?",
                              (rule_id,)).fetchone())
        sentence = _sentence(rule)      # render before COMMIT
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    return ("Rule #%d added:\n  %s\nIt applies to future ingests "
            "automatically; run apply_rules to tag existing rows."
            % (rule_id, sentence))


@register("remove_rule",
          "Delete an auto-tagging rule by rule_id (from list_rules). "
          "Already-applied tags stay on their rows; only the rule goes. "
          "Cheap to re-mint with add_rule.",
          {"type": "object",
           "properties": {"rule_id": {"type": "integer"}},
           "required": ["rule_id"]})
def remove_rule(args: dict) -> str:
    rid, refusal = _rule_id_arg(args.get("rule_id"))
    if refusal:
        return refusal
    c = tools_read.conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        row = c.execute("SELECT * FROM tag_rules WHERE rule_id=?",
                        (rid,)).fetchone()
        if row is None:
            c.execute("ROLLBACK")
            return ("no rule #%d — rule ids come from list_rules. "
                    "Nothing was changed." % rid)
        sentence = _sentence(dict(row))
        c.execute("DELETE FROM tag_rules WHERE rule_id=?", (rid,))
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    return ("Removed rule #%d:\n  %s\nTags it already applied remain on "
            "their rows." % (rid, sentence))


_RATIONALE_CLIP = 120


@register("replace_rule",
          "Atomically replace a rule (by rule_id from list_rules) with a "
          "fully-specified new version — same argument set as add_rule; "
          "this is the ONLY rule edit. Update the rationale to reflect "
          "the new understanding: it is the rule's working memory.",
          {"type": "object",
           "properties": dict(_RULE_ARGS, rule_id={"type": "integer"}),
           "required": ["rule_id", "tags"]})
def replace_rule(args: dict) -> str:
    rid, refusal = _rule_id_arg(args.get("rule_id"))
    if refusal:
        return refusal
    fields, refusal = rules.validate_rule(args)
    if refusal:
        return refusal
    sig = rules.signature(fields)
    c = tools_read.conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        row = c.execute("SELECT rule_id FROM tag_rules WHERE rule_id=?",
                        (rid,)).fetchone()
        if row is None:
            c.execute("ROLLBACK")
            return ("no rule #%d — rule ids come from list_rules. "
                    "Nothing was changed." % rid)
        dup = c.execute("SELECT rule_id FROM tag_rules WHERE"
                        " signature=? AND rule_id != ?",
                        (sig, rid)).fetchone()
        if dup:
            c.execute("ROLLBACK")
            return ("that predicate set already belongs to rule #%d. "
                    "Nothing was changed." % dup["rule_id"])
        c.execute(
            "UPDATE tag_rules SET signature=?, counterparty_canon=?,"
            " remittance_token=?, direction=?, currency=?,"
            " amount_min_minor=?, amount_max_minor=?, dom_min=?,"
            " dom_max=?, weekdays=?, tags=?, rationale=? WHERE"
            " rule_id=?",
            (sig, fields["counterparty_canon"],
             fields["remittance_token"], fields["direction"],
             fields["currency"], fields["amount_min_minor"],
             fields["amount_max_minor"], fields["dom_min"],
             fields["dom_max"], fields["weekdays"], fields["tags"],
             fields["rationale"], rid))
        rule = dict(c.execute("SELECT * FROM tag_rules WHERE rule_id=?",
                              (rid,)).fetchone())
        sentence = _sentence(rule)
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    return ("Rule #%d replaced:\n  %s\nApplies to future ingests; run "
            "apply_rules to catch existing rows." % (rid, sentence))


@register("list_rules",
          "The auto-tagging rulebook: every rule as one line "
          "(predicates -> tags) with its rationale clipped. Pass "
          "rule_id for one rule with its FULL rationale — read it "
          "before changing a rule; restrictions may be deliberate.",
          {"type": "object",
           "properties": {"rule_id": {"type": "integer"}}})
def list_rules(args: dict) -> str:
    c = tools_read.conn()
    rid = args.get("rule_id")
    if rid is not None:
        rid, refusal = _rule_id_arg(rid)
        if refusal:
            return refusal.replace(" Nothing was changed.", "")
        row = c.execute("SELECT * FROM tag_rules WHERE rule_id=?",
                        (rid,)).fetchone()
        if row is None:
            return "no rule #%d — rule ids come from list_rules." % rid
        rule = dict(row)
        lines = [_sentence(rule),
                 "created: %s" % (rule["created_at"] or "?")]
        if rule["rationale"]:
            lines.append("rationale: %s"
                         % tools_read._untrusted_note(rule["rationale"]))
        else:
            lines.append("rationale: (none recorded)")
        return "\n".join(lines)
    rows = [dict(r) for r in c.execute(
        "SELECT * FROM tag_rules ORDER BY rule_id")]
    if not rows:
        return ("No rules yet. add_rule mints one; ingest applies the "
                "rulebook automatically.")
    lines = ["%d rule(s):" % len(rows)]
    for rule in rows:
        lines.append(_sentence(rule))
        if rule["rationale"]:
            # Clip the RAW text first, then the note fence renders it —
            # never hand-compose fence markers.
            lines.append("    rationale: %s" % tools_read._untrusted_note(
                rule["rationale"][:_RATIONALE_CLIP]))
    lines.append("list_rules with rule_id shows one rule's full "
                 "rationale.")
    return "\n".join(lines)


_APPLY_ROW_IDS = {"type": "array", "items": {"type": "integer"},
                  "minItems": 1, "maxItems": 100}


@register("apply_rules",
          "Re-run the whole rulebook over stored transactions — "
          "additive and idempotent, so always safe. Scope: row_ids "
          "(exact, wins), or account and/or booking-date range, or the "
          "whole ledger. Reports per rule: matched / changed / already. "
          "A row_ids-scoped call lists changed AND already row ids in "
          "full — the audit surface for verifying a new or fixed rule "
          "caught its intended rows (intent = changed ∪ already); "
          "broader scopes clip the changed list.",
          {"type": "object", "properties": {
              "account": {"type": "string"},
              "date_from": {"type": "string"},
              "date_to": {"type": "string"},
              "row_ids": _APPLY_ROW_IDS}})
def apply_rules(args: dict) -> str:
    c = tools_read.conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        if not c.execute("SELECT 1 FROM tag_rules LIMIT 1").fetchone():
            c.execute("ROLLBACK")
            return "No rules to apply — add_rule mints one."
        raw_ids = args.get("row_ids")
        if raw_ids is not None:
            if (not isinstance(raw_ids, list) or not raw_ids
                    or len(raw_ids) > 100
                    or any(isinstance(i, bool) or not isinstance(i, int)
                           for i in raw_ids)):
                c.execute("ROLLBACK")
                return ("row_ids must be 1-100 integers. Nothing was "
                        "changed.")
            row_ids = sorted(set(raw_ids))
        else:
            where, params = ["state IN ('active','vanished')"], []
            if args.get("account") is not None:
                if not isinstance(args["account"], str):
                    c.execute("ROLLBACK")
                    return ("account must be a string. Nothing was "
                            "changed.")
                where.append("account_id=?")
                params.append(args["account"])
            for key, op in (("date_from", ">="), ("date_to", "<")):
                v = args.get(key)
                if v is not None:
                    if not isinstance(v, str):
                        c.execute("ROLLBACK")
                        return ("%s must be a string. Nothing was "
                                "changed." % key)
                    where.append("booking_date %s ?" % op)
                    params.append(v)
            row_ids = [r[0] for r in c.execute(
                "SELECT row_id FROM transactions WHERE %s"
                % " AND ".join(where), params)]
        out = rules.apply_to_rows(c, row_ids, _now())
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    lines = ["Applied %d rule(s) to %d row(s); %d row(s) changed."
             % (len(out["per_rule"]), len(row_ids),
                len(out["tagged_rows"]))]
    # Row-scoped calls (≤100 ids by validation) render changed AND already ids
    # in full: batch-close verifies intent against changed ∪ already, and a row
    # hand-tagged earlier in the turn lands in `already` — clipping or counting
    # would hide the verification evidence. Broader scopes keep the bounded
    # rendering.
    row_scoped = args.get("row_ids") is not None
    for rule_id, rep in sorted(out["per_rule"].items()):
        if not rep["matched"]:
            continue
        clip = None if row_scoped else 20
        shown = ", ".join("#%d" % i for i in rep["changed"][:clip])
        more = ("" if clip is None or len(rep["changed"]) <= clip
                else " (+%d more)" % (len(rep["changed"]) - clip))
        already_ids = ("" if not (row_scoped and rep["already"])
                       else " — " + ", ".join("#%d" % i
                                              for i in rep["already"]))
        skipped = ("" if not rep["skipped_overcap"]
                   else ", skipped at cap: %d"
                   % len(rep["skipped_overcap"]))
        lines.append("  rule #%d: matched: %d, changed: %d%s, "
                     "already: %d%s%s"
                     % (rule_id, len(rep["matched"]),
                        len(rep["changed"]),
                        (" — " + shown + more) if rep["changed"] else "",
                        len(rep["already"]), already_ids, skipped))
    if out["skipped_overcap"]:
        lines.append("  %d row(s) skipped at the 32-tag cap: %s"
                     % (len(out["skipped_overcap"]),
                        ", ".join("#%d" % i
                                  for i in out["skipped_overcap"][:20])))
    return "\n".join(lines)
