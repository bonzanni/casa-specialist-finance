# plugins/bank-feed/server/rules.py
"""Deterministic auto-tagging rule core.

Pure core: importable by apply.py (ingest) and tools_rules.py (tools)
alike, so it must never import the tool layer. All text matching happens
HERE, in Python, with ONE canonicalizer — never SQLite lower()/LIKE: rule
values are canonicalized at write time and row values at match time, by the
same function.

Reserved workflow tags are machinery, not classifications: a rule that
minted them would park or terminalize every matching row mechanically,
which is exactly the state machine the classifier owns.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import unicodedata

WORKFLOW_TAGS = ("awaiting-operator", "unclassifiable")
RULEBOOK_CAP = 500
RATIONALE_MAX = 1000
COUNTERPARTY_MAX = 128
TOKEN_MIN, TOKEN_MAX = 2, 32
MAX_TAGS_PER_RULE = 16
MAX_TAGS_PER_ROW = 32          # parity-tested against tools_annotate

# Same pattern as tools_annotate.TAG_RE — asserted equal by test, not
# imported: this module must not drag the tool layer into apply.py.
# An optional `owner::` prefix marks a tag another workflow owns (issue #31).
# ':' was never admitted before, so no stored tag changes meaning.
TAG_RE = re.compile(r"^(?:[a-z][a-z0-9-]{0,15}::)?[a-z0-9][a-z0-9-]{0,31}$")
TAG_RULE = ("tags must be 1-32 characters of a-z, 0-9 or '-', starting "
            "with a letter or digit (they are lowercased and trimmed "
            "first)")
NAMESPACE_SEP = "::"
MAX_TAGS_PER_NAMESPACE = 16    # per row, per owner
MAX_NAMESPACED_PER_ROW = 64    # per row, all owners together

_WS = re.compile(r"\s+")
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CURRENCY_RE = re.compile(r"^[A-Za-z]{3}$")
WEEKDAY_ORDER = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_DIRECTION_API = {"debit": "DBIT", "credit": "CRDT"}

# Same values as tools_refresh.CATEGORIES (what label_account writes) —
# asserted equal by test, not imported, for the same reason as TAG_RE.
ACCOUNT_CATEGORIES = ("personal", "company")

# Order is part of the stored signature. The two account fields are APPENDED:
# the v8 migration turns every stored 9-field signature into this 11-field
# form by rewriting its closing bracket, which is only right while new fields
# go at the end.
PREDICATE_FIELDS = ("counterparty_canon", "remittance_token", "direction",
                    "currency", "amount_min_minor", "amount_max_minor",
                    "dom_min", "dom_max", "weekdays", "account_id",
                    "account_category")


def canon_text(value) -> str:
    """One canonicalizer for every rule/row text comparison: NFC, trim,
    internal-whitespace collapse, casefold. '' for None (a NULL row field
    can then never equal a non-empty rule value — gap, not guess).

    Deliberately NOT ingest._canon, and the divergence is stated rather than
    reconciled: that function is identity-hashing machinery with an
    ABSENT sentinel and .lower(); this is a matching contract and uses
    casefold. The two must never be mixed; rules.py owns this one.

    Non-strings canonicalize to '' — NOT str(value): coercion would let a
    malformed numeric provider value equal a rule anchor. A malformed field
    fails every predicate closed."""
    if not isinstance(value, str):
        return ""
    text = unicodedata.normalize("NFC", value).strip()
    return _WS.sub(" ", text).casefold()


def tokens(value) -> list:
    """Canonical tokens of a text: maximal alphanumeric runs (Unicode
    str.isalnum) after canon_text. The ONLY definition of 'word' for
    remittance matching — no regex."""
    out, cur = [], []
    for ch in canon_text(value):
        if ch.isalnum():
            cur.append(ch)
        elif cur:
            out.append("".join(cur))
            cur = []
    if cur:
        out.append("".join(cur))
    return out


def _int_or_refusal(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        return None, "%s must be an integer (got %r)" % (name, value)
    return value, None


def validate_rule(args: dict):
    """-> (fields, refusal-or-None). fields maps EXACTLY the tag_rules
    predicate/tags/rationale column names to validated, canonicalized
    values (None where unconstrained). Typed validation, no coercion;
    every problem collected into one refusal."""
    problems = []
    fields = {k: None for k in PREDICATE_FIELDS}
    fields["tags"] = None
    fields["rationale"] = None

    cp = args.get("counterparty")
    if cp is not None:
        if not isinstance(cp, str):
            problems.append("counterparty must be a string")
        else:
            canon = canon_text(cp)
            if not canon:
                problems.append("counterparty is empty after normalization")
            elif len(canon) > COUNTERPARTY_MAX:
                problems.append("counterparty is capped at %d characters "
                                "after normalization (this one is %d)"
                                % (COUNTERPARTY_MAX, len(canon)))
            else:
                fields["counterparty_canon"] = canon

    rw = args.get("remittance_word")
    if rw is not None:
        if not isinstance(rw, str):
            problems.append("remittance_word must be a string")
        else:
            toks = tokens(rw)
            if len(toks) != 1:
                problems.append("remittance_word must be a single word "
                                "(got %d after normalization)" % len(toks))
            elif not (TOKEN_MIN <= len(toks[0]) <= TOKEN_MAX):
                problems.append("remittance_word must be %d-%d characters"
                                % (TOKEN_MIN, TOKEN_MAX))
            else:
                fields["remittance_token"] = toks[0]

    if fields["counterparty_canon"] is None and \
            fields["remittance_token"] is None:
        # Reported even beside other problems: one refusal names EVERY
        # failure, the anchor gap included.
        problems.append("a rule needs an anchor: counterparty or "
                        "remittance_word — direction/amount/date "
                        "predicates alone would be a mislabeling machine")

    d = args.get("direction")
    if d is not None:
        if not isinstance(d, str) or d not in _DIRECTION_API:
            problems.append("direction must be 'debit' or 'credit'")
        else:
            fields["direction"] = _DIRECTION_API[d]

    cur = args.get("currency")
    if cur is not None:
        if not isinstance(cur, str) or not _CURRENCY_RE.fullmatch(
                cur.strip()):
            problems.append("currency must be a three-letter code")
        else:
            fields["currency"] = cur.strip().upper()

    for name in ("amount_min_minor", "amount_max_minor"):
        v = args.get(name)
        if v is not None:
            v, err = _int_or_refusal(v, name)
            if err:
                problems.append(err)
            elif v < 0:
                problems.append("%s must be >= 0 (amounts are stored "
                                "magnitudes; direction carries the sign)"
                                % name)
            else:
                fields[name] = v
    lo, hi = fields["amount_min_minor"], fields["amount_max_minor"]
    if (lo is not None or hi is not None) and fields["currency"] is None:
        problems.append("an amount band needs a currency — minor units "
                        "mean different money in different currencies")
    if lo is not None and hi is not None and lo > hi:
        problems.append("amount_min_minor must be <= amount_max_minor")

    for name in ("dom_min", "dom_max"):
        v = args.get(name)
        if v is not None:
            v, err = _int_or_refusal(v, name)
            if err:
                problems.append(err)
            elif not (1 <= v <= 31):
                problems.append("%s must be between 1 and 31 (dom = day "
                                "of month)" % name)
            else:
                fields[name] = v
    dl, dh = fields["dom_min"], fields["dom_max"]
    if dl is not None and dh is not None and dl > dh:
        problems.append("dom_min must be <= dom_max (dom bands do not "
                        "wrap)")

    wd = args.get("weekdays")
    if wd is not None:
        if not isinstance(wd, list) or not wd:
            problems.append("weekdays must be a non-empty array of "
                            "weekday names (mon..sun)")
        else:
            seen = set()
            for w in wd:
                norm = w.strip().lower() if isinstance(w, str) else None
                if norm not in WEEKDAY_ORDER:
                    problems.append("invalid weekday %r (use mon..sun)"
                                    % (w,))
                    break
                seen.add(norm)
            else:
                fields["weekdays"] = ",".join(
                    w for w in WEEKDAY_ORDER if w in seen)

    # Account scope. Neither is an anchor: "every company debit -> X" is the
    # mislabeling machine the anchor requirement refuses. Both together are
    # refused: an account already has one category, so the pair only adds a
    # way for the rule to stop matching silently when that account is
    # recategorized.
    acc = args.get("account")
    if acc is not None:
        if not isinstance(acc, str) or not acc.strip():
            problems.append("account must be a non-empty account_id string "
                            "(from list_accounts)")
        else:
            fields["account_id"] = acc.strip()
    cat = args.get("account_category")
    if cat is not None:
        norm = cat.strip().lower() if isinstance(cat, str) else None
        if norm not in ACCOUNT_CATEGORIES:
            problems.append("account_category must be one of: %s"
                            % ", ".join(ACCOUNT_CATEGORIES))
        else:
            fields["account_category"] = norm
    if acc is not None and cat is not None:
        problems.append("pass account or account_category, not both — an "
                        "account already has exactly one category")

    raw_tags = args.get("tags")
    if not isinstance(raw_tags, list) or not raw_tags:
        problems.append("tags must be a non-empty array")
    elif len(raw_tags) > MAX_TAGS_PER_RULE:
        problems.append("at most %d tags per rule (%d given)"
                        % (MAX_TAGS_PER_RULE, len(raw_tags)))
    else:
        seen, out = set(), []
        for t in raw_tags:
            if not isinstance(t, str):
                problems.append("tags must be strings (got %r)" % (t,))
                break
            norm = t.strip().lower()
            if not TAG_RE.fullmatch(norm):
                problems.append("invalid tag %r: %s" % (t, TAG_RULE))
                break
            if norm in WORKFLOW_TAGS:
                problems.append("%r is a reserved workflow tag — rules "
                                "must not mint workflow state" % norm)
                break
            if tag_namespace(norm) is not None:
                problems.append("%r belongs to another workflow's "
                                "namespace — rules mint classification "
                                "tags only" % norm)
                break
            if norm not in seen:
                seen.add(norm)
                out.append(norm)
        else:
            fields["tags"] = " ".join(out)

    rat = args.get("rationale")
    if rat is not None:
        if not isinstance(rat, str):
            problems.append("rationale must be a string")
        elif len(rat) > RATIONALE_MAX:
            problems.append("rationale is capped at %d characters (this "
                            "one is %d)" % (RATIONALE_MAX, len(rat)))
        elif rat.strip():
            fields["rationale"] = rat

    if problems:
        return None, "; ".join(problems) + ". Nothing was changed."
    return fields, None


def signature(fields: dict) -> str:
    """Canonical predicate-set serialization: JSON array of the values in
    PREDICATE_FIELDS order — injective by construction, unlike a
    delimiter-joined string, which a value containing the delimiter can forge.
    NULL is explicit so SQLite NULL-distinctness cannot
    defeat UNIQUE. Tags and rationale are deliberately excluded: two
    rules that match identically ARE duplicates whatever they tag."""
    return json.dumps([fields.get(k) for k in PREDICATE_FIELDS],
                      ensure_ascii=True, separators=(",", ":"))


def _parse_iso(text):
    """Strict ISO date or None — a malformed provider date fails the
    predicate closed, never the ingest."""
    if not isinstance(text, str) or not _ISO_DATE.fullmatch(text):
        return None
    try:
        return _dt.date.fromisoformat(text)
    except ValueError:
        return None


def rule_matches(rule: dict, row: dict) -> bool:
    """Conjunction over the stored predicates; a NULL rule field is
    unconstrained, a NULL/malformed row field never satisfies a present
    predicate.

    The account category is the account's category NOW (apply_to_rows reads
    it with the row), so recategorizing an account re-scopes category rules
    from the next application on; tags already applied stay. An unlabelled
    account, or a row with no accounts row, has no category and fails a
    category predicate closed."""
    v = rule.get("account_id")
    if v is not None and row.get("account_id") != v:
        return False
    v = rule.get("account_category")
    if v is not None and row.get("account_category") != v:
        return False
    v = rule.get("counterparty_canon")
    if v is not None and canon_text(row.get("counterparty")) != v:
        return False
    v = rule.get("remittance_token")
    if v is not None and v not in tokens(row.get("remittance")):
        return False
    v = rule.get("direction")
    if v is not None and row.get("direction") != v:
        return False
    v = rule.get("currency")
    if v is not None:
        rc = row.get("currency")
        if not isinstance(rc, str) or rc.strip().upper() != v:
            return False
    lo, hi = rule.get("amount_min_minor"), rule.get("amount_max_minor")
    if lo is not None or hi is not None:
        amt = row.get("amount_minor")
        if not isinstance(amt, int) or isinstance(amt, bool) or amt < 0:
            return False       # malformed magnitude fails closed
        if lo is not None and amt < lo:
            return False
        if hi is not None and amt > hi:
            return False
    dl, dh, wd = rule.get("dom_min"), rule.get("dom_max"), \
        rule.get("weekdays")
    if dl is not None or dh is not None or wd is not None:
        date_obj = _parse_iso(row.get("booking_date"))
        if date_obj is None:
            return False
        if dl is not None and date_obj.day < dl:
            return False
        if dh is not None and date_obj.day > dh:
            return False
        if wd is not None and WEEKDAY_ORDER[date_obj.weekday()] not in \
                wd.split(","):
            return False
    return True


def load_rules(conn) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM tag_rules ORDER BY rule_id")]


def apply_to_rows(conn, row_ids, now: str) -> dict:
    """Additive rule application to exactly `row_ids`. The CALLER holds
    the transaction (apply_plan's, or a tool's BEGIN IMMEDIATE) — this
    function never begins or commits.

    Per row: snapshot initial tags, collect ALL matching rules, compute
    the full union ONCE. Over the 32 cap the row is skipped whole — the
    skip lands in EVERY matching rule's report, never
    partial, never aborting ingest. Otherwise changed/already are judged
    against the INITIAL snapshot (order-independent) and the union is
    written in one additive pass; nothing is ever removed."""
    all_rules = load_rules(conn)
    out = {"per_rule": {r["rule_id"]: {"matched": [], "changed": [],
                                       "already": [],
                                       "skipped_overcap": []}
                        for r in all_rules},
           "tagged_rows": [], "skipped_overcap": []}
    if not all_rules or not row_ids:
        return out
    for rid in sorted(set(row_ids)):
        row = conn.execute(
            "SELECT t.row_id, t.state, t.counterparty, t.remittance,"
            " t.direction, t.currency, t.amount_minor, t.booking_date,"
            " t.account_id, a.category AS account_category"
            " FROM transactions t LEFT JOIN accounts a"
            " ON a.account_id = t.account_id WHERE t.row_id=?",
            (rid,)).fetchone()
        if row is None or row["state"] not in ("active", "vanished"):
            continue                       # allowlist: fail closed
        row_d = dict(row)
        matching = [r for r in all_rules if rule_matches(r, row_d)]
        if not matching:
            continue
        initial = {t[0] for t in conn.execute(
            "SELECT tag FROM transaction_tags WHERE row_id=?", (rid,))}
        union = set(initial)
        for r in matching:
            union |= set(r["tags"].split())
        if cap_problem(initial, union) is not None:
            out["skipped_overcap"].append(rid)
            for r in matching:
                rep = out["per_rule"][r["rule_id"]]
                rep["matched"].append(rid)
                rep["skipped_overcap"].append(rid)
            continue
        for r in matching:
            rep = out["per_rule"][r["rule_id"]]
            rep["matched"].append(rid)
            if set(r["tags"].split()) <= initial:
                rep["already"].append(rid)
            else:
                rep["changed"].append(rid)
        to_add = sorted(union - initial)
        if to_add:
            for tag in to_add:
                conn.execute(
                    "INSERT OR IGNORE INTO transaction_tags(row_id, tag,"
                    " added_at) VALUES (?,?,?)", (rid, tag, now))
            out["tagged_rows"].append(rid)
    return out


def tag_namespace(tag):
    """The owning workflow of an `owner::name` tag, else None."""
    if NAMESPACE_SEP in tag:
        return tag.split(NAMESPACE_SEP, 1)[0]
    return None


def is_classification_tag(tag) -> bool:
    """Content classification: neither a workflow marker nor another
    workflow's `owner::name` assertion. Tests '::', not ':' — a stray
    single-colon value (never writable) keeps exactly its old meaning."""
    return NAMESPACE_SEP not in tag and tag not in WORKFLOW_TAGS


# The SQL rendering of is_classification_tag over `tt.tag`, parity-tested
# against the Python predicate. Literals come from module constants, never
# from input.
CLASSIFICATION_TAG_SQL = (
    "(instr(tt.tag, '%s') = 0 AND tt.tag NOT IN (%s))"
    % (NAMESPACE_SEP, ",".join("'%s'" % t for t in WORKFLOW_TAGS)))


def cap_problem(existing, adding):
    """-> None, or why adding `adding` to a row carrying `existing` breaks a
    per-row budget.

    Two budgets: MAX_TAGS_PER_ROW over un-namespaced tags (workflow markers
    included, as before), and MAX_TAGS_PER_NAMESPACE per owner plus
    MAX_NAMESPACED_PER_ROW over all owners — so neither side can starve the
    other. Only a budget the call actually adds to is checked: a row already
    over one budget (a supersede can merge two rows' tags) must not block
    writes to the other."""
    existing = set(existing)
    new = set(adding) - existing
    union = existing | new
    if any(tag_namespace(t) is None for t in new):
        plain = [t for t in existing if tag_namespace(t) is None]
        if len(plain) + sum(tag_namespace(t) is None for t in new) \
                > MAX_TAGS_PER_ROW:
            return ("already carries %d tags and this would push it past "
                    "the cap of %d" % (len(plain), MAX_TAGS_PER_ROW))
    touched = {tag_namespace(t) for t in new} - {None}
    for ns in sorted(touched):
        n = sum(tag_namespace(t) == ns for t in union)
        if n > MAX_TAGS_PER_NAMESPACE:
            return ("would carry %d '%s::' tags, past the cap of %d per "
                    "namespace" % (n, ns, MAX_TAGS_PER_NAMESPACE))
    if touched:
        n = sum(tag_namespace(t) is not None for t in union)
        if n > MAX_NAMESPACED_PER_ROW:
            return ("would carry %d namespaced tags, past the cap of %d"
                    % (n, MAX_NAMESPACED_PER_ROW))
    return None


def classification_state(tags) -> str:
    """The ONE precedence predicate: terminal > parked >
    classified > workable. Every consumer (queue_totals, batch buckets,
    untagged_only) derives from this, so the definitions cannot drift.
    Another workflow's `owner::name` tag counts toward none of the four."""
    tags = set(tags)
    if "unclassifiable" in tags:
        return "terminal"
    if "awaiting-operator" in tags:
        return "parked"
    if any(is_classification_tag(t) for t in tags):
        return "classified"
    return "workable"


def queue_totals(conn):
    """(workable, parked) over non-superseded rows, via
    classification_state — counts span ALL accounts, included or not."""
    # One (row, tag) pair per result row, grouped here: joining tags into
    # one string and splitting it again would cut a stored value that
    # contains the separator into tags the SQL queue never sees.
    tags_by_row: dict = {}
    for rid, tag in conn.execute(
            "SELECT t.row_id, tt.tag"
            " FROM transactions t LEFT JOIN transaction_tags tt"
            " ON tt.row_id = t.row_id"
            " WHERE t.state IN ('active','vanished')"):
        bucket = tags_by_row.setdefault(rid, [])
        if tag is not None:
            bucket.append(tag)
    workable = parked = 0
    for tags in tags_by_row.values():
        state = classification_state(tags)
        if state == "workable":
            workable += 1
        elif state == "parked":
            parked += 1
    return workable, parked
