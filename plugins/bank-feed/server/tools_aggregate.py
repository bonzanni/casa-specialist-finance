# plugins/bank-feed/server/tools_aggregate.py
"""Aggregation read tools.

A separate module so tools_read.py stops growing; it reuses that module's
helpers the same way tools_annotate does. Same read discipline: one BEGIN
snapshot, freshness note, excluded-accounts note, bounded output.

spend_by_tag is a LENS, not a ledger: a row carrying N tags appears in N
groups, so groups overlap and never sum to an account total — disclosed on
every call. Sums are per currency and never converted (balance_total's
contract). Tags and currencies are STORED strings: tags render through
_neutralized (the column has no CHECK constraint), currencies must pass
_safe_currency or their group becomes a counted, text-free gap: a sum of
unknown denomination is a gap, not a guess.
"""
from __future__ import annotations

import apply
import money
import tools_read
from tools_read import register

MAX_GROUPS = 200

_SIGNED_SUM = ("SUM(CASE WHEN upper(ifnull(t.direction,''))='DBIT'"
               " THEN -ifnull(t.amount_minor,0)"
               " ELSE ifnull(t.amount_minor,0) END)")


def _ages_only(c, account_ids, provisional):
    """Freshness entries for exactly `account_ids`, reusing the
    pre-snapshot entries (which reflect any inline refresh) and reading
    ages from the snapshot for accounts the provisional pass never saw.
    Never refreshes: this runs inside the read snapshot."""
    by_id = {f["account_id"]: f for f in provisional}
    out = []
    for aid in account_ids:
        if aid in by_id:
            out.append(by_id[aid])
            continue
        row = tools_read._sync_row(c, aid, "transactions")
        stamp = (tools_read._parse_ts(row.get("last_success_at"))
                 if row else None)
        age = ((tools_read._now() - stamp).total_seconds()
               if stamp else None)
        out.append({"account_id": aid, "age_s": age, "refreshed": False,
                    "error": None, "exit_hint": "",
                    "completeness": (row or {}).get("completeness")})
    return out



@register("spend_by_tag",
          "Signed spend per (tag, currency) over the cached ACTIVE "
          "transactions of included accounts, plus an (untagged) bucket. "
          "Groups overlap when rows carry several tags — this is a lens, "
          "not a total. Sums are per currency, never converted. Optional "
          "filters: scope, account, date_from, date_to, tags (subset), "
          "direction.",
          {"type": "object", "properties": {
              "scope": {"type": "string",
                        "enum": ["all", "personal", "company"]},
              "account": {"type": "string"},
              "date_from": {"type": "string"},
              "date_to": {"type": "string"},
              "tags": {"type": "array", "items": {"type": "string"},
                       "maxItems": 16},
              "direction": {"type": "string", "enum": ["DBIT", "CRDT"]}}})
def spend_by_tag(args: dict) -> str:
    # Late import: tools_annotate imports tools_read at load time, and this
    # module is loaded alongside both — same seam list_transactions uses.
    from tools_annotate import _normalize_tags
    c = tools_read.conn()
    tag_filter = None
    if args.get("tags"):
        tag_filter, refusal = _normalize_tags(args["tags"])
        if refusal:
            return "tags: " + refusal.replace(" Nothing was changed.", "")
    # Inline refresh may WRITE through the REFRESHER seam, so it cannot run
    # inside a read snapshot: it runs first, against a PROVISIONAL account
    # list. The population the answer describes is re-read INSIDE the snapshot
    # below — with the pre-snapshot list driving the queries, an account
    # excluded between the two reads is still summed.
    provisional = tools_read._included_accounts(c, args)
    fresh_pre = (tools_read._freshness(
        c, [a["account_id"] for a in provisional], "transactions")
        if provisional else [])

    # One read snapshot: the population, the cache ages it discloses, the
    # effective range, the tagged groups, the untagged bucket and the
    # coverage holes must describe the SAME ledger state.
    c.execute("BEGIN")
    try:
        accounts = tools_read._included_accounts(c, args)
        excluded = tools_read._excluded_count(c, args)
        if not accounts:
            c.execute("ROLLBACK")
            msg = ("No included accounts match. Link a bank with "
                   "link_bank, or check the include flags with "
                   "list_accounts.")
            if excluded:
                msg += " " + tools_read._excluded_note(excluded)
            return msg
        account_ids = [a["account_id"] for a in accounts]
        fresh = _ages_only(c, account_ids, fresh_pre)
        if not any(f["age_s"] is not None for f in fresh):
            c.execute("ROLLBACK")
            # No cache at all is an ERROR, never an empty answer — an empty
            # spend table would read as "you spent nothing".
            return ("no data cached yet for these accounts — refusing to "
                    "answer from an empty cache, because an empty answer "
                    "would read as 'you had no spend'. Run sync to fetch, "
                    "or link_bank if this bank was never authorized.")
        date_from, date_to = tools_read._effective_range(c, account_ids,
                                                         args)
        where = ["t.account_id IN (%s)" % ",".join("?" * len(account_ids)),
                 "t.state='active'", "t.booking_date >= ?",
                 "t.booking_date < ?"]
        params: list = list(account_ids) + [date_from, date_to]
        if args.get("direction"):
            where.append("t.direction=?")
            params.append(str(args["direction"]).upper())
        clause = " AND ".join(where)
        tag_where, tag_params = "", []
        if tag_filter:
            tag_where = (" AND tt.tag IN (%s)"
                         % ",".join("?" * len(tag_filter)))
            tag_params = list(tag_filter)
        grouped = list(c.execute(
            "SELECT tt.tag, t.currency, %s, COUNT(*)"
            " FROM transactions t JOIN transaction_tags tt"
            " ON tt.row_id = t.row_id WHERE %s%s"
            " GROUP BY tt.tag, t.currency" % (_SIGNED_SUM, clause,
                                              tag_where),
            params + tag_params))
        untagged = list(c.execute(
            "SELECT t.currency, %s, COUNT(*) FROM transactions t"
            " WHERE %s AND NOT EXISTS (SELECT 1 FROM transaction_tags tt"
            " WHERE tt.row_id = t.row_id)"
            " GROUP BY t.currency" % (_SIGNED_SUM, clause), params))
        # ROW count per stored currency, each row once — the unusable- currency
        # disclosure must count transactions, not tag-group memberships: one
        # bad-currency row with two tags would otherwise report "2 row(s)".
        # Scoped to the tags subset when one is given, since only those rows
        # could have rendered.
        cur_where, cur_params = clause, list(params)
        if tag_filter:
            cur_where += (" AND EXISTS (SELECT 1 FROM transaction_tags tt"
                          " WHERE tt.row_id = t.row_id AND tt.tag IN (%s))"
                          % ",".join("?" * len(tag_filter)))
            cur_params += list(tag_filter)
        rows_by_currency = list(c.execute(
            "SELECT t.currency, COUNT(*) FROM transactions t WHERE %s"
            " GROUP BY t.currency" % cur_where, cur_params))
        holes_by_account = [(a, apply.holes(c, a["account_id"], date_from,
                                            date_to)) for a in accounts]
    except Exception:
        c.execute("ROLLBACK")
        raise
    c.execute("COMMIT")

    rows = ([(tag, cur, s, n) for tag, cur, s, n in grouped]
            + [(None, cur, s, n) for cur, s, n in untagged])
    if tag_filter:
        # A tags subset asks about THOSE tags; the untagged bucket would
        # answer a question nobody asked and read as one of them.
        rows = [r for r in rows if r[0] is not None]
    rows.sort(key=lambda r: (str(r[1]), -abs(int(r[2] or 0))))
    lines = ["Spend by tag, %s to %s (exclusive), over %d account(s)."
             % (date_from, date_to, len(account_ids)),
             tools_read._freshness_note(accounts, fresh)]
    if excluded:
        lines.append(tools_read._excluded_note(excluded))
    def _usable(currency) -> bool:
        try:
            tools_read._safe_currency(currency)
            return True
        except Exception:
            return False

    # Rows, not tag-group memberships: count each bad-currency transaction
    # ONCE, from the per-currency population query, never from the overlapping
    # groups.
    bad_currency_rows = sum(n for currency, n in rows_by_currency
                            if not _usable(currency))
    shown = 0
    for tag, currency, total, n in rows:
        if not _usable(currency):
            # A stored currency money.exponent rejects: the group becomes
            # a counted gap (see bad_currency_rows above); its TEXT never
            # renders: a sum of unknown denomination is a gap, not a
            # guess.
            continue
        code = tools_read._safe_currency(currency)
        amount = money.format_minor(int(total or 0), currency)
        if shown >= MAX_GROUPS:
            shown += 1                 # count what the cap hides, render nothing
            continue
        label = "(untagged)" if tag is None else tools_read._neutralized(tag)
        lines.append("  %s  %s %s  (%d row(s))" % (label, amount, code, n))
        shown += 1
    if shown > MAX_GROUPS:
        lines.append("Truncated at %d groups; %d omitted — narrow the "
                     "range or pass a tags subset."
                     % (MAX_GROUPS, shown - MAX_GROUPS))
    if bad_currency_rows:
        lines.append("%d row(s) carry an unusable stored currency and are "
                     "EXCLUDED from every sum above — a gap, not zero."
                     % bad_currency_rows)
    lines.append("A row carrying N tags appears in N groups: groups "
                 "overlap and do NOT sum to any account total.")
    lines.append("Sums are per currency; this tool never converts and "
                 "never adds across currencies.")
    for a, holes in holes_by_account:
        for hole in holes:
            # Same neutralization as list_transactions' Coverage line: the
            # bounds can carry a raw booking_date.
            lines.append("Coverage: %s has a gap %s to %s inside the "
                         "requested range — spend over that span is NOT "
                         "proven complete."
                         % (tools_read._label(a),
                            tools_read._neutralized(hole[0]),
                            tools_read._neutralized(hole[1])))
    return "\n".join(lines)
