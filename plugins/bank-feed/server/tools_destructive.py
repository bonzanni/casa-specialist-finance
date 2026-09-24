# plugins/bank-feed/server/tools_destructive.py
"""The four irreversible tools.

THE GATE IS CASA'S, NOT OURS: every tool here is
declared in `casa.protectedTools` and casa's fail-closed PreToolUse hook
demands an operator grant bound to the exact arguments before the call reaches
this process. `_require_declared` is a tripwire, not the boundary — a tool that
finds itself undeclared refuses, so deleting the declaration disables it rather
than silently ungating it.

`purge` maintains coverage. Coverage exists to keep "nothing
happened" apart from "we do not know"; a purge that erased rows and left the
interval asserting proof would collapse the second into the first, and the
ledger would report the deleted years as quiet ones.

NO CONTROL-PANEL WRITE happens from here. Removing an account from the
application's Enable Banking whitelist takes an `identification_hash`, whose
only legitimate source is `eb_admin.Admin.whitelisted()`; a caller-supplied one
would be an inference-only path from attacker-controlled text to deleting the
wrong account's entry, exactly as a caller-supplied `redirect_uri` would be. So
no tool here accepts one, this module imports no admin client at all, and
provider-side unlink is not built.
"""
from __future__ import annotations

import datetime as _dt
import re
import time as _time

import apply
import backups
import callbacks
import tools_auth
import tools_read
from tools_auth import (GATE_NOTE, _conn, _require_declared,
                        _resolve_consent_ref, _safe, _vacuum)
from tools_read import register

#: The tools this module registers. Named here so a test can check them
#: against `tools_auth.PROTECTED` — which is spelled ONCE, there — instead of
#: this module re-declaring that set and the two drifting apart.
DESTRUCTIVE_TOOLS = ("unlink_bank", "purge", "forget_local_account",
                     "delete_all_data")

#: The ONLY `meta` keys that survive `delete_all_data`. All three are
#: structural, not data: `schema_version` is what `store.open_db` migrates
#: against; `account_secret` is the local HMAC key `store.account_id` derives
#: every account id from — regenerating it would silently re-key the whole
#: ledger on the next link; and `backup_restore_op` (`backups.MARKER_KEY` —
#: the same spelling, cross-checked by test) belongs to the backup crash
#: protocol, not to this ledger's own data: it is the id `backups.settle`
#: reads to decide whether a still-pending restore record terminates
#: `committed` or `aborted`, and erasing it here could settle a restore that
#: actually committed as `aborted` instead. Everything else in `meta` is
#: erasable data, and the renewal-handoff keys in particular EMBED a raw
#: session identifier, which is bearer-equivalent. The list is a whitelist on
#: purpose: a key added by a later feature is deleted by default.
STRUCTURAL_META_KEYS = ("schema_version", "account_secret", "backup_restore_op")

#: Every table `delete_all_data` empties unconditionally. `occurrence_alloc` is
#: on the list because it is per-account data — an unsalted sha256 over amount,
#: currency, direction, counterparty and remittance (`ingest.identity_key`)
#: beside the account it belongs to — and "erase the entire local ledger" has
#: to mean it. `meta` is handled separately, by whitelist. `sessions` is
#: handled separately too, and that is the whole point: a session row is the
#: ONLY handle this plugin has on a live PSD2 grant, so a row is destroyed only
#: once the provider has confirmed the grant is gone — which is
#: `_destroy_proven_handles`, AFTER this transaction has committed and after
#: the banks have been asked. Everything on this list is reversible by a
#: rollback; that one statement is not, so it does not travel with them.
#: `aspsp_capability` and `aspsp_capability_retired` ARE data and are erased
#: with everything else. They were excluded while a seeder re-populated the
#: first on every open, so leaving it cost nothing; nothing populates it now. A
#: capability row is this installation's own observation of its own bank, and a
#: retired row is a verbatim copy of one, so "erase the entire local ledger"
#: has to mean them too -- and the retired table is precisely where another
#: installation's measurements would be sitting. `ref_observations` is the
#: earned-trust evidence (issue #1) and goes for the same reason: every row is
#: a measurement OF this installation's own accounts. `workflow_registrations`
#: (`backups.REGISTRATIONS_TABLE`, cross-checked by test) is data too, not
#: structural: after a total erasure there are no workflow writes left to
#: bind an install backup to, so unregistering every workflow is right, and
#: the next write a workflow makes mints its own install backup afresh.
_DATA_TABLES = ("transaction_refs", "transaction_tags", "transaction_notes",
                "tag_rules", "transactions", "occurrence_alloc",
                "balances", "coverage", "sync_state", "accounts", "attempts",
                "aspsp_capability", "aspsp_capability_retired",
                "ref_observations", "workflow_registrations")

#: `account_id`-scoped tables for `forget_local_account`.
#: `transaction_refs` is keyed by a GLOBAL `row_id` and is therefore the one
#: table that cannot be scoped by a column of its own — it goes through a
#: subquery, below.
#:
#: `attempts` is here because an attempt row carries the `account_id` a renewal
#: was fenced against, plus the bank name and the attempt's `state_secret`, and
#: nothing else in the plugin ever prunes one. A tool that enumerates what it
#: erased has to erase what it names. A first-link attempt carries no
#: `account_id` and is untouched, which is correct: it is not about this
#: account.
#:
#: `ref_observations` is account data -- counts and dates measured FROM this
#: account's history -- so forgetting the account erases its evidence, and
#: earned reference trust dies with it. Correct, not incidental: re-linking
#: re-observes on its own deep run, and the new incarnation token means a run
#: still in flight across the erasure cannot re-file the old life's evidence.
_ACCOUNT_TABLES = ("transactions", "occurrence_alloc", "balances", "coverage",
                   "sync_state", "attempts", "accounts", "ref_observations")

#: `purge` deletes by lexical comparison against `transactions.booking_date`,
#: which SQLite stores as the ISO string `ingest` wrote. So the cutoff must BE
#: an ISO date and not merely parse as one.
#:
#: `[0-9]`, NOT `\d`. On a `str` pattern `\d` is Unicode-wide,
#: so `٢٠٢٥-٠١-٠١` matches — and every ASCII date sorts BELOW an Arabic-Indic
#: one, which makes `booking_date < ?` true for the entire ledger. Today
#: `date.fromisoformat` happens to reject those digits, so the composition is
#: safe; but that made an undocumented second check the only thing standing
#: between a Unicode-digit argument and erasing everything, and this file's own
#: rule is that the guard reads the value that matters. The character class
#: costs nothing and carries the guarantee its docstring claims for it.
_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _cutoff(raw) -> str | None:
    """The `before_date` argument, or None if it is not exactly YYYY-MM-DD.

    THE GUARD HAS TO BRANCH ON THE VALUE THAT DELETES. Validating
    `date.fromisoformat(before[:10])` and then handing the RAW string to the
    delete is this codebase's dominant defect shape — a check on a derivative
    that drifts in exactly the failure mode the check exists for — and here it
    silently over-deletes:

    * `2025-01-01T00:00:00Z` parses to 1 January, but sorts ABOVE the string
      `2025-01-01`, so every row booked ON the cutoff is erased too;
    * `20250101` parses to 1 January on Python 3.11+ (ISO basic format), and
      sorts above every `2025-…` date, so it erases the whole year.

    Neither prints a warning, and neither is recoverable. Refusing anything
    that is not already canonical is also what keeps the tool honest about
    casa's approval challenge, which interpolates the LITERAL argument the
    operator approved: the string they read is then exactly the cutoff applied.
    """
    text = str(raw or "")
    if not _ISO_DATE.fullmatch(text):
        return None
    try:
        _dt.date.fromisoformat(text)       # rejects 2025-13-40 and friends
    except ValueError:
        return None
    return text


#: The reclaim claim, made in ONE place — the place that knows whether it is
#: true. As line 1 of each tool it would be built before the VACUUM ran and
#: left unchanged when it failed, so one message would assert the reclaim and
#: then retract it.
_RECLAIMED = ("Real deletes plus VACUUM, not tombstones: the rows "
              "are gone from the ledger database, its note index and its "
              "write-ahead log, and the freed pages have been reclaimed.")


def _reclaim(c):
    """VACUUM after a committed erasure. Returns `(ok, the sentence to print)`.

    Erasure means real deletes PLUS `VACUUM`, not tombstones, and the
    VACUUM is the half that stops the erased bytes from sitting in free pages
    of a file HA backups capture. It cannot run inside a transaction, so it
    runs after the COMMIT — which means it can fail with the deletion already
    durable. Raising then would report a failure for rows that ARE gone;
    swallowing it would report a complete erasure that is not complete. So it
    is neither: the deletion is reported truthfully and the missing half is
    named.

    Both branches are driven by tests that patch `_vacuum` to raise. Without
    those, every mutation of this function — swallowing the failure, or
    returning the success sentence from the failure branch — is killed by
    nothing, on the guarantee that separates "the rows are gone" from
    "the rows are unreferenced but still in the file Home Assistant backs up".
    """
    try:
        _vacuum(c)
    except Exception as exc:                 # noqa: BLE001 — class name only
        return False, (
            "WARNING — the rows are deleted and the deletion is committed, but "
            "the reclaim did not finish (%s): the freed pages or the "
            "write-ahead log have NOT been cleared, and the erased data may "
            "still be recoverable from the database files (and from any Home "
            "Assistant backup taken since). "
            "Run this call again with the same arguments to finish the "
            "reclaim: every tool here re-runs it, including when there is "
            "nothing left to delete." % type(exc).__name__)
    return True, _RECLAIMED


@register("unlink_bank",
          "Revoke a bank consent. Stops refreshing; does NOT erase local "
          "history. Protected: casa demands an operator grant.",
          {"type": "object",
           "properties": {"consent_ref": {"type": "string"}},
           "required": ["consent_ref"]})
def unlink_bank(args: dict) -> str:
    refusal = _require_declared("unlink_bank")
    if refusal:
        return refusal
    c = _conn()
    session_id = _resolve_consent_ref(c, args.get("consent_ref"))
    if session_id is None:
        return ("No consent matches that consent_ref. Run consent_status to see "
                "the current refs. Nothing has been changed.")
    row = c.execute("SELECT aspsp_name, status, closed_at, valid_until"
                    " FROM sessions WHERE session_id=?",
                    (session_id,)).fetchone()
    bank = _safe(row["aspsp_name"] if row else None) or "that bank"
    # Re-derived rather than echoed back: it is what a retry must be told, and
    # it is stable because it is a digest of the session id.
    ref = tools_auth._consent_ref(session_id)
    if row is not None and row["closed_at"]:
        # `_resolve_consent_ref` scans every session, closed ones included, and
        # `_mismatch_lines` prints an OLD ref the operator may still be
        # holding. `closed_at` is written by `apply.record_revocation` on a
        # CONFIRMED revocation and by nothing else, so it is already the proof
        # this tool would go and ask for: the provider can only answer 404, and
        # asking spends a live API call to learn what the row already records.
        return ("%s: that consent has already been withdrawn and the provider "
                "confirmed it. Nothing has been changed and nothing local was "
                "lost by it. consent_status lists the consents that still "
                "exist." % bank)
    # A quarantined consent is exactly what this tool has to be able to
    # revoke — it is a live consent at the bank that nothing is bound to, and
    # it was previously unreachable because only `attempts.session_id` held it.
    quarantined = (row is not None
                   and str(row["status"] or "") == callbacks.REVIEW_REQUIRED_STATUS)
    # The local session is closed ONLY when the revocation is known
    # to have happened — a success, or a 404, which is the provider stating
    # authoritatively that the session is already gone. Everything else leaves
    # the consent live at the bank, and closing the row anyway hid it from
    # `consent_status` (which lists open sessions only) and took away the one
    # handle the operator had for retrying.
    absent, failure = False, None
    try:
        tools_auth._ais().delete_session(session_id)
        revoked = True
    except Exception as exc:                     # noqa: BLE001
        absent = tools_auth.revocation_is_final(exc)
        revoked = absent
        failure = type(exc).__name__            # a CLASS name, never a body

    kept = c.execute(
        "SELECT COUNT(*) FROM transactions WHERE account_id IN"
        " (SELECT account_id FROM accounts WHERE session_id=?)",
        (session_id,)).fetchone()[0]

    # `apply.record_revocation` is the ONLY writer of `closed_at` anywhere in
    # this plugin, and therefore also the authority on what is written instead
    # when the provider did not confirm. Doing it with our own UPDATE here
    # would put the rule in two places and let them drift — which is how the
    # local row and the bank came to disagree in the first place.
    #
    # It moves in ONE transaction with the binding release below, because
    # "this consent is gone" and "these accounts are no longer bound to it" are
    # one statement: a crash between them leaves accounts pointing at a closed
    # consent, which is the dead end the release exists to prevent.
    c.execute("BEGIN IMMEDIATE")
    try:
        apply.record_revocation(c, session_id, revoked=revoked)
        if revoked:
            # THE CONTRACT WITH THE COLLECTOR, probed rather than reasoned
            # about. Closing the session row alone leaves every account
            # still pointing at a dead consent, so the escape this plugin
            # prints in three places — unlink the old consent, then link as a
            # FIRST link — hits `apply.upsert_account`'s rebinding backstop and
            # raises `RebindRefused`. The operator is then back in the loop
            # with nothing left to try. `callbacks._contain` already releases
            # `session_id` AND `uid` exactly this way for a quarantined
            # consent, so this is the same statement, not a new mechanism.
            #
            # Only on a revocation we are sure of: while the consent may still
            # be live at the bank, the accounts really are still bound to it.
            c.execute("UPDATE accounts SET session_id=NULL, uid=NULL"
                      " WHERE session_id=?", (session_id,))
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise

    if not revoked:
        # Nothing else changes: a half-applied unlink — permission still live
        # at the bank, accounts dropped from every total — is worse than either
        # end, and nothing would tell the operator which half took.
        # Issue #6, and the sibling of `consent_status`'s revocation branch —
        # the same sentence about the same row, from the other tool. Nothing
        # here flips `status` when a consent lapses, so this row can be
        # AUTHORIZED with its validity behind it; "very likely STILL LIVE at
        # the bank" then sends the operator to a bank consent screen to
        # withdraw something that lapsed on its own. The predicate is
        # `tools_auth._expiry_state`, the one every branch shares, so the two
        # tools cannot disagree about one row.
        state, value = tools_auth._expiry_state(
            row["valid_until"] if row else None)
        # Three states, and the expired one states two weak facts without
        # promoting either: the withdrawal was NOT confirmed, and the recorded
        # validity is behind us. The retry line below is unchanged in every
        # state, including the bank's own consent screen — which is the one
        # place that can actually settle it. A dict literal builds every arm,
        # chosen or not, so the lapse is rendered once HERE where `value` is
        # known to be a number — `_ago(None)` raises, and it would raise on the
        # exact rows this branch exists for.
        lapse = tools_auth._ago(value) if state == tools_auth.EXPIRED else ""
        outcome = {
            tools_auth.LIVE: "the consent is very likely STILL LIVE at the bank.",
            tools_auth.EXPIRED:
                "its recorded validity had already passed (%s), so the "
                "withdrawal was never confirmed but the bank most likely holds "
                "nothing." % lapse,
            tools_auth.UNKNOWN:
                "how long that consent is valid for is not recorded here, so "
                "whether the bank still holds it cannot be said from here.",
        }[state]
        return "\n".join([
            "%s: the consent was NOT revoked (%s). Nothing has been changed "
            "locally and %s" % (bank, failure, outcome),
            "Run unlink_bank consent_ref=%s again — the handle has not "
            "changed, so a retry reaches the same consent. consent_status "
            "lists it as needing attention until it succeeds; if it keeps "
            "failing, withdraw it from %s's own consent screen." % (ref, bank),
            GATE_NOTE,
        ])

    lines = ["%s: consent %s. Its accounts are no longer bound to any consent, "
             "so nothing refreshes them until you link the bank again."
             % (bank, "reported by the provider as already gone — treated as "
                      "revoked at the provider" if absent
                      else "revoked at the provider")]
    if quarantined:
        # A successful DELETE establishes that the request succeeded; it does
        # not establish that the consent was LIVE immediately before it — and
        # whether the provider 204s or 404s an already-expired session is not
        # something this code can verify. So the claim comes from the validity,
        # which is the only evidence we hold, and the tidy-up half is true in
        # every state. `_expiry_state` again, so this line and
        # `consent_status`'s quarantine branch cannot describe one row
        # differently.
        state, _ = tools_auth._expiry_state(row["valid_until"] if row else None)
        lines.append(
            "That consent was QUARANTINED: it was created at the bank but "
            "nothing was ever linked from it, so %s and it loses no local "
            "history at all. This is the tidy-up consent_status was asking for."
            % {tools_auth.LIVE: "revoking it removes a live permission",
               tools_auth.EXPIRED: "its recorded validity had already passed, "
                                   "so this most likely settled a record "
                                   "rather than a standing permission",
               tools_auth.UNKNOWN: "how long it was valid for was not recorded "
                                   "here, so whether it was still a standing "
                                   "permission cannot be said",
               }[state])
    lines.append(
        "Unlink is not erase: %d transaction%s of local history "
        "survive%s and stay queryable, with every label, category, include "
        "flag and proven-coverage interval untouched. Use purge, "
        "forget_local_account or delete_all_data if you actually want the data "
        "gone." % (kept, "" if kept == 1 else "s", "s" if kept == 1 else ""))
    lines.append(GATE_NOTE)
    return "\n".join(lines)


#: `purge`'s `user_work` values. Required, no default: the choice is all or
#: nothing, and an erasure the operator did not choose explicitly is the one
#: thing this tool must not infer.
USER_WORK = ("keep", "erase")

#: The `sync_state.last_error` a whole-ledger purge leaves on every account's
#: transactions row, beside `completeness='partial'`. It is what the reads and
#: `sync` print about the gap, so it names both ways back.
PURGED_NOTE = ("history purged (purge before_date=all) on %s: restore_backup "
               "backup_id=%s puts it back locally; a fresh bank approval "
               "refetches what lies inside the plugin's request window and "
               "the bank's own retention")


def _authorization_in_progress(c) -> bool:
    """Is any bank authorization possibly still completing? (issue #47)

    A purge rotates every account's incarnation, and a renewal between its
    binding switch and its reply reads that rotation as "nothing switched" --
    telling the operator to unlink the consent that is now live. So a purge
    waits while any attempt carries a lease token that a collector holds
    (lease unexpired, however old the attempt) or that a successor could
    still steal (expired, but casa can still redeliver: the attempt can be
    answered up to PENDING_TTL_S after minting, the result artifact lives
    RESULT_TTL_S after that, and a steal needs the lease expired for a
    LEASE_TTL_S). Past that horizon nothing can resume the attempt, and the
    row is left exactly as it is: clearing its token would strand a collector
    that was only stalled, with a half-written binding.
    """
    now = _time.time()
    horizon = (tools_auth.PENDING_TTL_S + callbacks.RESULT_TTL_S
               + callbacks.LEASE_TTL_S)
    return c.execute(
        "SELECT 1 FROM attempts WHERE lease_token IS NOT NULL AND"
        " (COALESCE(lease_expiry, 0) > ? OR COALESCE(created_at, 0) > ?)"
        " LIMIT 1", (now, now - horizon)).fetchone() is not None


def _finish_pre_erasure(paths, handle, b, *, committed: bool):
    """Record the copy's terminal state, then prune its OWN class only -- and
    only after an erasure that committed: a call that erased nothing must not
    have removed an older copy either, or "nothing was erased" is false of
    the backups directory.

    -> `(pruned ids, retention error or None, index error or None)`; the
    index error is `(text, written)` with `BackupError.written`'s three
    states, because "not written", "written but not flushed" and "possibly
    torn" are three different states of the index and each needs its own
    sentence. The two
    failures are different facts: a terminal record that could not be written
    leaves the copy `pending`, which the next settlement closes `committed`
    because its file is present, and NO prune ran; a prune that failed ran
    after a recorded copy. Never raises: the copy is already real.

    `backups.finish_backup` is the same two steps; they are taken apart here
    only so a failure of each can be told apart."""
    try:
        try:
            handle.append("backup", b.op_id,
                          "committed" if committed else "orphan")
        except backups.BackupError as exc:
            return [], None, (str(exc), exc.written)
        if not committed:
            return [], None, None
        try:
            b.pruned = backups.prune(paths, handle,
                                     classes=(backups.ERASURE_REASON,))
            return b.pruned, None, None
        except backups.BackupError as exc:
            # Copies removed before the failure are still removed.
            return list(getattr(exc, "pruned", None) or []), str(exc), None
    finally:
        handle.close()


def _rolled_back(head: str, b, state) -> str:
    """A scoped erasure that rolled back: nothing of the ledger went, and no
    backup copy was pruned (`_finish_pre_erasure` prunes nothing then) -- but
    this call's settlement may have completed an earlier interrupted erasure
    on the way, and that is said rather than covered by "nothing"."""
    text = ("%s Backup %s, taken for it, is kept (it is a copy of the "
            "unchanged ledger)." % (head, b.op_id))
    settled = backups.settled_note(state.settled if state is not None else None)
    return text + " " + settled if settled else text


def _backup_line(b, state, finished, restores) -> str:
    """The reply's account of the backup copies (issue #47): the copy this
    call took and what a restore of it brings back, and what else changed in
    the backups directory -- which is nothing, unless retention pruned an
    older pre-erasure copy or this call's settlement completed an earlier
    interrupted total erasure. "No other backup copy was changed" is said
    only when both are false."""
    pruned, retention_error, index_error = finished
    line = ("Backup %s was taken just before this erasure: restore_backup "
            "backup_id=%s puts back %s." % (b.op_id, b.op_id, restores))
    if index_error:
        text, written = index_error
        if written is True:
            line += (" Its index record was written but could not be flushed "
                     "(%s); it is readable now." % text)
        elif written is None:
            line += (" Its index record may be partially written (%s); the "
                     "copy is complete, and the next settlement (any backup, "
                     "restore, listing or workflow write) recovers the "
                     "record." % text)
        else:
            line += (" Its index record could not be written (%s); the copy "
                     "is complete, and the next settlement (any backup, "
                     "restore, listing or workflow write) records it." % text)
    settled = backups.settled_note(state.settled if state is not None else None)
    if retention_error:
        line += (" Retention stopped part way (%s)%s; the backup itself is "
                 "complete." % (retention_error,
                                ", after removing the oldest pre-erasure "
                                "cop%s %s" % ("y" if len(pruned) == 1 else
                                              "ies", ", ".join(pruned))
                                if pruned else ""))
    elif pruned:
        line += (" Retention removed the oldest pre-erasure cop%s: %s."
                 % ("y" if len(pruned) == 1 else "ies", ", ".join(pruned)))
    if settled:
        line += " " + settled
    elif not pruned and not retention_error and not index_error:
        # With the terminal record missing no prune ran, so nothing else
        # changed then either -- but the sentence would sit beside a warning
        # about this very copy, and it is only said when all went to plan.
        line += " No other backup copy was changed."
    return line


def _reapproval_lines(c) -> list:
    """Per bank, what brings deep history back from the bank after a
    whole-ledger purge -- derived from the binding state with the predicate
    `link_bank` itself uses (`tools_auth.renewal_target`), because telling
    the operator to renew a consent `link_bank` will refuse to renew sends
    them into a refusal."""
    lines = []
    triples = c.execute(
        "SELECT DISTINCT aspsp_name, country, psu_type FROM sessions"
        " WHERE closed_at IS NULL ORDER BY aspsp_name, country, psu_type"
    ).fetchall()
    for aspsp, country, psu_type in triples:
        bank = _safe(aspsp) or "an unnamed bank"
        target, prior = tools_auth.renewal_target(c, aspsp, country, psu_type)
        if target is not None:
            lines.append("  %s: run link_bank for it — a renewal, which "
                         "reopens the deep-history window." % bank)
        elif prior is not None:
            lines.append(
                "  %s: its consent has no account bound to it, so link_bank "
                "will not renew it — run unlink_bank consent_ref=%s, then "
                "link_bank (a first link)."
                % (bank, tools_auth._consent_ref(prior["session_id"])))
    unbound = [_safe(r[0]) or "an unnamed bank" for r in c.execute(
        "SELECT DISTINCT aspsp FROM accounts WHERE session_id IS NULL"
        " OR session_id = '' ORDER BY aspsp")]
    for bank in unbound:
        lines.append("  %s: an account is bound to no consent — run link_bank "
                     "for it." % bank)
    if not lines:
        return []
    return (["History older than the routine 90-day refresh window comes "
             "back from a bank only after a fresh approval, and only as far "
             "back as the plugin's request window and the bank's own "
             "retention reach:"] + lines)


@register("purge",
          "Really delete transactions — every one booked before a date, or "
          "the whole ledger with before_date='all' — with their notes and "
          "tags, trim or drop the proven-coverage intervals to match, then "
          "VACUUM. user_work is required: 'keep' keeps auto-tagging rules and "
          "account labels, categories and include flags; 'erase' erases ALL "
          "of them and every note and tag, on surviving rows too. A backup is "
          "taken first; restore_backup undoes the purge. Protected: casa "
          "demands an operator grant.",
          {"type": "object",
           "properties": {"before_date": {"type": "string"},
                          "user_work": {"type": "string",
                                        "enum": list(USER_WORK)}},
           "required": ["before_date", "user_work"]})
def purge(args: dict) -> str:
    refusal = _require_declared("purge")
    if refusal:
        return refusal
    raw = args.get("before_date")
    whole = raw == "all"
    before = None if whole else _cutoff(raw)
    if not whole and before is None:
        return ("before_date must be exactly an ISO date, YYYY-MM-DD, or "
                "'all' — not a timestamp and not a compact form. Rows are "
                "compared to it as text, so anything else would silently "
                "erase MORE than the date names. Nothing has been changed.")
    user_work = args.get("user_work")
    if user_work not in USER_WORK:
        # Never echoed back: an arbitrary string in a line-oriented reply.
        return ("user_work must be 'keep' (keep auto-tagging rules and account "
                "labels, categories and include flags) or 'erase' (erase all "
                "of them, and every note and tag). There is no default. "
                "Nothing has been changed.")
    erase = user_work == "erase"
    c = _conn()
    paths = backups.paths_for(tools_read.ledger_path(c))
    c.execute("BEGIN IMMEDIATE")
    state = handle = None
    try:
        if _authorization_in_progress(c):
            c.execute("ROLLBACK")
            return ("A bank authorization is in progress (a link or renewal "
                    "is completing), and a purge now could make its reply "
                    "wrong about which consent is live. Try again in a few "
                    "minutes. Nothing has been changed.")
        # Settle, then copy the ledger as it stands. `take_backup` copies
        # through a separate reader, which under WAL sees the last COMMITTED
        # state: with the write lock held and nothing written yet, that is
        # exactly the ledger before this erasure.
        state, handle = backups.settle(c, paths)
        b = backups.take_backup(c, paths, handle, backups.ERASURE_REASON)
    except backups.BackupError as exc:
        # NOTHING IS ERASED WITHOUT ITS BACKUP. `refusal_text` says what a
        # settlement on the way removed, when it removed anything.
        if c.in_transaction:
            c.execute("ROLLBACK")
        if handle is not None:
            handle.close()
        return backups.refusal_text(exc, state)
    except Exception:
        if c.in_transaction:
            c.execute("ROLLBACK")
        if handle is not None:
            handle.close()
        raise

    try:
        notes_before = c.execute(
            "SELECT COUNT(*) FROM transaction_notes").fetchone()[0]
        tags_before = c.execute(
            "SELECT COUNT(*) FROM transaction_tags").fetchone()[0]
        # One transaction across rows, references and coverage — and it
        # lives in `apply`, beside `apply_plan` and `record_coverage`, because
        # those three tables are three views of the same claim and one owner
        # is what keeps them from disagreeing.
        stats = apply.purge_rows(c, before)
        balances = 0
        if whole:
            balances = c.execute("DELETE FROM balances").rowcount
            # No row remains that a reused occurrence slot could collide with.
            c.execute("DELETE FROM occurrence_alloc")
            note = PURGED_NOTE % (_dt.date.today().isoformat(), b.op_id)
            # UPSERT, not UPDATE: an account whose first backfill was
            # interrupted has no transactions row, and an UPDATE would skip
            # it -- leaving a later routine refresh free to record the
            # erased history as complete. The retry and success timestamps
            # of an existing row stay: Retry-After still binds, and the last
            # successful fetch really happened when it says.
            c.execute(
                "INSERT INTO sync_state(account_id, resource, completeness,"
                " last_error) SELECT account_id, 'transactions', 'partial', ?"
                " FROM accounts WHERE 1 ON CONFLICT(account_id, resource) DO"
                " UPDATE SET completeness='partial',"
                " last_error=excluded.last_error, last_success_session=NULL,"
                " oldest_fetched=NULL", (note,))
            c.execute("UPDATE sync_state SET last_success_at=NULL"
                      " WHERE resource='balances'")
        rules = relabelled = 0
        reincluded = []
        if erase:
            c.execute("DELETE FROM transaction_notes")
            c.execute("DELETE FROM transaction_tags")
            rules = c.execute("DELETE FROM tag_rules").rowcount
            reincluded = [_safe(r[0] or r[1]) or _safe(r[2][:10])
                          for r in c.execute(
                              "SELECT label, name, account_id FROM accounts"
                              " WHERE included=0 ORDER BY account_id")]
            relabelled = c.execute(
                "UPDATE accounts SET label=NULL, category=NULL, included=1"
                " WHERE label IS NOT NULL OR category IS NOT NULL"
                " OR included=0").rowcount
        notes_after = c.execute(
            "SELECT COUNT(*) FROM transaction_notes").fetchone()[0]
        tags_after = c.execute(
            "SELECT COUNT(*) FROM transaction_tags").fetchone()[0]
        # THE LIFE FENCE. A sync or backfill that read the ledger before
        # this purge and applies after it must not record coverage or sync
        # state over rows the purge removed; every late write in `flows` and
        # `tools_refresh` is conditioned on the incarnation it captured, as
        # for a restore, which rotates it the same way.
        c.execute("UPDATE accounts SET incarnation = lower(hex(randomblob(8)))")
        c.execute("COMMIT")
    except Exception as exc:                 # noqa: BLE001 — class name only
        if c.in_transaction:
            c.execute("ROLLBACK")
        # The copy stands for a ledger that did not change: an `orphan`, as a
        # rolled-back mint is, and still a valid restore point.
        _finish_pre_erasure(paths, handle, b, committed=False)
        return _rolled_back("The purge failed (%s) and was rolled back: "
                            "nothing was erased." % type(exc).__name__,
                            b, state)
    finished = _finish_pre_erasure(paths, handle, b, committed=True)

    gone_notes, gone_tags = notes_before - notes_after, tags_before - tags_after
    if whole:
        lines = [
            "Purged the whole ledger: %d transaction(s) and %d stored provider "
            "reference(s), with %d note(s) and %d tag(s)%s. Every "
            "proven-coverage interval (%d) was dropped, so no span reads as "
            "PROVEN until a fetch proves it again."
            % (stats["transactions"], stats["refs"], gone_notes, gone_tags,
               "" if erase else " — notes and tags go with their rows",
               stats["coverage_dropped"]),
            "Reset: %d cached balance(s) and the sync state — every account's "
            "transaction history is marked partial until a completed deep "
            "fetch. Provider Retry-After holds were kept." % balances,
        ]
    else:
        lines = [
            "Purged %d transaction(s) booked before %s, and %d stored provider "
            "reference(s) with them."
            % (stats["transactions"], before, stats["refs"]),
            "Proven-coverage intervals were corrected to match: %d dropped and "
            "%d trimmed to start at %s. Every span before that date now reads "
            "as NOT PROVEN rather than as a period with no transactions — "
            "erased history must never come back as a confident answer."
            % (stats["coverage_dropped"], stats["coverage_trimmed"], before),
        ]
    if erase:
        lines.append(
            "Erased with user_work=erase: %d note(s) and %d tag(s)%s, %d "
            "auto-tagging rule(s), and every account label, category and "
            "include flag (%d account(s) changed)."
            % (gone_notes, gone_tags,
               "" if whole else ", on surviving rows too", rules, relabelled))
        if reincluded:
            lines.append(
                "These accounts were excluded and are included again, so the "
                "next sync refreshes them: %s." % ", ".join(reincluded))
    else:
        lines.append(
            "Kept with user_work=keep: auto-tagging rules and account labels, "
            "categories and include flags. Notes and tags go with their rows"
            "%s." % ("" if whole else
                     ": %d note(s) and %d tag(s) went with the purged rows, "
                     "and the surviving rows keep theirs"
                     % (gone_notes, gone_tags)))
    # An evidence row is a measurement of the bank's reference behaviour --
    # aggregate counts and dates, no transaction content -- and purging
    # history does not un-measure it. forget_local_account and
    # delete_all_data are the erasers that take evidence with them.
    lines.append("Reference-trust evidence is unaffected: it describes the "
                 "bank's reference behaviour, not the purged rows.")
    lines.append(_backup_line(b, state, finished,
                              "everything this call erased"))
    if whole:
        lines.extend(_reapproval_lines(c))
    # `occurrence_alloc` is deliberately NOT purged by a date purge. It is the
    # only record of the occurrence slots a re-keyed row vacated (store.py),
    # the accounts are still here and still ingesting, and handing a purged
    # slot back out would collide with UNIQUE (account_id, identity_key,
    # occurrence). A whole-ledger purge empties it: no row is left to collide.
    lines.append(_reclaim(c)[1])
    lines.append(GATE_NOTE)
    return "\n".join(lines)


def _bank_access_note(session) -> str:
    """What `forget_local_account` may claim about the BANK (issue #6).

    Three states, because three things are true in different worlds and this
    line is the one that can still cost the operator money.

    * A consent whose validity is behind it: the erasure still does not revoke
      anything, and `unlink_bank` is still the tool that withdraws it, but the
      permission is very likely already gone and "the bank still serves this
      account" is the wrong thing to leave someone with.
    * No session at all — the account was unbound, or its consent row is gone.
      Nothing here knows what the bank holds, and the fail-safe direction is to
      name `unlink_bank` anyway rather than to imply there is nothing to do.
    * Otherwise the original sentence, unchanged.

    Expiry is stated as a recorded date, never as a refusal at the bank:
    `tools_refresh` binds to the session and never reads `valid_until`, so
    whether the bank still answers is the bank's to say.
    """
    valid_until = session["valid_until"] if session is not None else None
    state, value = tools_auth._expiry_state(valid_until)
    tail = ("Run unlink_bank if you want the bank's own permission withdrawn.")
    if session is None or not session["session_id"]:
        return ("Bank access: this erased the local copy only, and nothing was "
                "revoked. This account was not bound to any consent here, so "
                "what the bank still holds for it is not something this call "
                "can tell you — run consent_status. " + tail)
    if state == tools_auth.EXPIRED:
        return ("Bank access: this erased the local copy only — the consent "
                "was not revoked. Its recorded validity passed %s, so the bank "
                "very likely no longer serves this account to this "
                "application; a future link can bring the account back. %s"
                % (tools_auth._ago(value), tail))
    if state == tools_auth.UNKNOWN:
        return ("Bank access: this erased the local copy only — the consent was "
                "not revoked, and how long it is valid for is not recorded "
                "here, so whether the bank still serves this account cannot be "
                "said from here. A future link can bring the account back. "
                + tail)
    return ("Bank access is STILL ACTIVE. This erased the local copy only: the "
            "consent was not revoked, the bank still serves this account to "
            "this application, and a future link can bring the account back. "
            + tail)


@register("forget_local_account",
          "Erase one account's LOCAL history and drop the account. The bank "
          "consent is untouched: nothing is revoked here. Protected: "
          "casa demands an operator grant.",
          {"type": "object", "properties": {"account_id": {"type": "string"}},
           "required": ["account_id"]})
def forget_local_account(args: dict) -> str:
    refusal = _require_declared("forget_local_account")
    if refusal:
        return refusal
    c = _conn()
    account_id = str(args.get("account_id") or "")
    # Issue #6. The bank-access sentence below LEADS this report because it is
    # the part that can still cost the operator money, and it asserts that the
    # bank still serves this account — a claim about the consent, read here
    # from the consent's own validity rather than from the fact that a session
    # row exists. A LEFT JOIN, because an unbound account is a real state and
    # must not make the account itself unfindable.
    session = c.execute(
        "SELECT s.valid_until AS valid_until, a.session_id AS session_id"
        " FROM accounts a LEFT JOIN sessions s ON s.session_id = a.session_id"
        " WHERE a.account_id = ?", (account_id,)).fetchone()
    row = c.execute("SELECT label, name FROM accounts WHERE account_id=?",
                    (account_id,)).fetchone()
    if row is None:
        # Returning here, before the reclaim, is a trap: the reclaim is exactly
        # what the VACUUM-failure warning sends the operator back to run. The
        # lookup it short-circuits on is the row the FIRST call just deleted,
        # so the one documented remedy answers "Nothing has been changed"
        # (which reads as "there was nothing left to do") while the erased rows
        # sat in free pages indefinitely. The delete half was idempotent; the
        # tool was not. Nothing else offers a non-destructive reclaim, so this
        # is the only route there is.
        ok, note = _reclaim(c)
        if not ok:
            return "No account with that account_id, so nothing was deleted.\n" + note
        return ("No account with that account_id, so nothing was deleted. The "
                "database's free pages have been reclaimed (VACUUM), which is "
                "what finishes an earlier erasure of this account whose VACUUM "
                "did not run.")
    # `label` is the OPERATOR's own text; `name` is the provider's. Both go
    # through the neutralising path, because this output is line-oriented and
    # an embedded newline forges a whole line the operator reads as ours. The
    # fallback is the CALLER's string, so it goes through it too — today it can
    # only be an `account_id` we minted (an unnamed account has no row for the
    # lookup above to find), but "it is safe because of a check somewhere else"
    # is the reasoning this codebase has had to retract repeatedly.
    named = _safe(row["label"] or row["name"]) or _safe(account_id[:10])
    paths = backups.paths_for(tools_read.ledger_path(c))
    c.execute("BEGIN IMMEDIATE")
    state = handle = None
    try:
        # THE BACKUP COMES FIRST, under the same write lock as the erasure
        # (issue #47): the separate reader `take_backup` copies through sees
        # the last committed state, which with nothing written yet is the
        # ledger exactly before this call. No copy, no erasure.
        state, handle = backups.settle(c, paths)
        b = backups.take_backup(c, paths, handle, backups.ERASURE_REASON)
    except backups.BackupError as exc:
        if c.in_transaction:
            c.execute("ROLLBACK")
        if handle is not None:
            handle.close()
        return backups.refusal_text(exc, state)
    except Exception:
        if c.in_transaction:
            c.execute("ROLLBACK")
        if handle is not None:
            handle.close()
        raise
    try:
        # Counted inside the lock, so the report names what this
        # transaction erased and nothing a concurrent write added after it.
        count = c.execute("SELECT COUNT(*) FROM transactions WHERE"
                          " account_id=?", (account_id,)).fetchone()[0]
        attempts = c.execute("SELECT COUNT(*) FROM attempts WHERE"
                             " account_id=?", (account_id,)).fetchone()[0]
        # `transaction_refs` — and now the two annotation tables — are keyed
        # by a GLOBAL row_id, so they are the tables here that cannot be
        # scoped by a column of their own: a row-keyed write that is not
        # scoped to the account it was given reaches other accounts' rows,
        # and the subquery is what keeps these scoped.
        for table in ("transaction_refs", "transaction_tags",
                      "transaction_notes"):
            c.execute("DELETE FROM %s WHERE row_id IN (SELECT row_id"
                      " FROM transactions WHERE account_id=?)" % table,
                      (account_id,))
        for table in _ACCOUNT_TABLES:
            c.execute("DELETE FROM %s WHERE account_id=?" % table, (account_id,))
        # Rules are row-independent and survive, account-scoped ones included:
        # the account id is a keyed hash of IBAN+currency, so the same account
        # linked again brings them back into force. Counted in the same
        # transaction, so the disclosure names what was actually kept.
        scoped_rules = c.execute(
            "SELECT COUNT(*) FROM tag_rules WHERE account_id=?",
            (account_id,)).fetchone()[0]
        c.execute("COMMIT")
    except Exception as exc:                 # noqa: BLE001 — class name only
        if c.in_transaction:
            c.execute("ROLLBACK")
        _finish_pre_erasure(paths, handle, b, committed=False)
        return _rolled_back("Erasing %s failed (%s) and was rolled back: "
                            "nothing was erased."
                            % (named, type(exc).__name__), b, state)
    finished = _finish_pre_erasure(paths, handle, b, committed=True)
    # What a restore of the copy brings back, and what it does not: a
    # restore keeps bindings and authorization attempts LIVE, so the account
    # comes back bound to whatever it is bound to when the restore runs, and
    # the attempts this call erased stay erased.
    restores = ("this account's transactions, notes, tags, balances, "
                "coverage and sync state; the account comes back bound to "
                "whatever consent it is bound to when the restore runs — "
                "unbound, needing a re-link, if it has not been linked again "
                "by then")
    if attempts:
        restores += (", and the %d authorization attempt(s) erased here stay "
                     "erased, because a restore keeps attempts live" % attempts)
    lines = [
        "Erased %s LOCALLY: %d transaction(s), its balances, its coverage, its "
        "sync state, its occurrence allocations and any authorization attempt "
        "fenced against it." % (named, count),
        _bank_access_note(session),
        "Removing the account from the application's Enable Banking whitelist "
        "needs its identification hash, which is not stored here; do that "
        "in the control panel if you want it gone provider-side too.",
        # Forgetting an account keeps the learned rulebook, disclosed; rules
        # scoped to this account are kept too, and named, because they now
        # match nothing until the account comes back.
        "Auto-tagging rules are unaffected." if not scoped_rules else
        "%d auto-tagging rule(s) scoped to this account were kept: they "
        "match nothing until the same account is linked again, and "
        "remove_rule removes them. Other rules are unaffected."
        % scoped_rules,
        _backup_line(b, state, finished, restores),
    ]
    lines.append(_reclaim(c)[1])
    lines.append(GATE_NOTE)
    return "\n".join(lines)


def _withdraw_open_consents(c):
    """Ask each bank to withdraw its consent, BEFORE the handle is destroyed.

    Emptying `sessions` without ever calling the provider leaves the 179-day
    AIS grants live at the banks, while
    every route to them — `consent_status`, `unlink_bank`, `link_bank`'s
    accumulation warning — resolves through the table that had just been
    emptied. The operator was then told "every bank must be approved again",
    which reads as *the consents are gone*, and each re-link silently added a
    SECOND live grant per bank. `flows.complete_renewal`'s own docstring names
    that harm as the reason `_revoke` exists — "live grants the operator can
    neither see nor revoke" — and this reproduced it for every consent at once,
    in the tool whose entire purpose is erasure.

    The rule is the ledger's, not this module's: a consent is proven gone by a
    success or by a 404 (`eb_ais.revocation_is_final`), and by nothing else. A
    429, a timeout, a 5xx, a 401/403 all mean "we could not tell", and
    destroying a handle on "we could not tell" erases the operator's only retry
    handle.

    Returns `(gone, kept)`. Both outcomes are recorded through
    `apply.record_revocation` — the one writer of `closed_at` — as they happen
    and OUTSIDE the erasure transaction, so a later failure in that transaction
    cannot lose the record of a revocation that really did occur.

    Called AFTER the local erasure has committed. Running it before is half
    right — network work must not hold the write transaction, and a live
    consent's handle must not be destroyed before the consent is — and half
    wrong: it makes the IRREVERSIBLE half the FIRST half, so an erasure that
    fails and rolls back has already withdrawn every consent while reporting
    only an error.
    """
    # `valid_until` travels with each row: the report built from `kept` states
    # what destroying a row would cost, and that cost is a standing grant only
    # while the grant stands. It has to be read here, BEFORE
    # `_destroy_proven_handles` removes the rows it was read from.
    rows = [dict(r) for r in c.execute(
        "SELECT session_id, aspsp_name, valid_until FROM sessions"
        " WHERE closed_at IS NULL ORDER BY aspsp_name, session_id")]
    if not rows:
        return [], []                        # no consents, so no provider call
    try:
        ais = tools_auth._ais()
    except Exception as exc:                 # noqa: BLE001 — e.g. no credential
        # Nothing was asked, so nothing is proven gone. Every row is kept.
        return [], [dict(r, failure=type(exc).__name__) for r in rows]
    gone, kept = [], []
    for row in rows:
        try:
            ais.delete_session(row["session_id"])
            proven, failure = True, None
        except Exception as exc:             # noqa: BLE001
            proven = tools_auth.revocation_is_final(exc)
            failure = type(exc).__name__     # a CLASS name, never a body
        apply.record_revocation(c, row["session_id"], revoked=proven)
        (gone if proven else kept).append(dict(row, failure=failure))
    return gone, kept


def _destroy_proven_handles(c, paths):
    """Delete the session rows the provider PROVED gone — and only those.

    THE PREDICATE IS `closed_at`, NOT A LIST BUILT IN THIS MODULE. Deleting
    `WHERE session_id NOT IN (the ids we could not withdraw)` is the complement
    of a Python list and therefore a DERIVATIVE of the fact that matters. It
    agrees with the fact on every path that runs to completion — and disagrees
    on exactly the path where it counts: if the withdrawal pass stops
    part way, that list is empty, the complement is EVERY ROW, and the delete
    would destroy the handles of consents nobody ever asked about. Branching on
    `closed_at` cannot drift, because `apply.record_revocation` is the one
    writer of that column in the whole plugin and writes it only on a
    revocation the provider confirmed (a success or a 404). A row nobody asked
    about still has `closed_at IS NULL` and therefore survives by construction.

    Rows already closed BEFORE this call are deleted too, and correctly: the
    same single writer put that timestamp there, on the same proof.

    Returns `(ok, warning or None, [lines about the backup copies])`. It
    does not raise: the erasure is already
    committed and the consents are already withdrawn by the time this runs, so
    an exception here would once again hand the operator an error for a call
    that did the irreversible half. Same trade as `_reclaim`, same answer — the
    residue is named instead of being either hidden or thrown.

    AND THE MESSAGE BRANCHES ON THE SAME FACT AS THE QUERY. It
    used to branch on whether the `DELETE` RAISED, and said, whenever it did,
    that "the session row of every consent proven gone could not be removed …
    consent_status does not list it and there is nothing left to revoke". On
    the halted path NOTHING is proven gone, so the delete would have removed
    ZERO rows and that sentence described an empty set in language implying a
    full one — one line under a warning telling the operator to go and run
    `consent_status` because live consents are still listed there. Two
    individually truthful lines that contradict each other is exactly as
    useless to an operator as one false one.

    So the count comes from the sweep's OWN PREDICATE, read from the ledger.
    Not `len(gone)`: a consent closed by an EARLIER call is due for removal
    now and appears in no list this call built, so a message keyed to the
    withdrawal pass's return value would fall silent about a row that really
    did survive — the complement-of-a-Python-list defect, re-entered in prose.
    And when the same fault takes out the count as well, the tool says it does
    not know rather than guessing either way: "nothing happened" and "we cannot
    tell" are different answers.
    """
    try:
        due = c.execute("SELECT COUNT(*) FROM sessions"
                        " WHERE closed_at IS NOT NULL").fetchone()[0]
    except Exception:                        # noqa: BLE001 — see `due is None`
        due = None
    # THE ROWS GO IN ONE TRANSACTION WITH THE RECORD OF A SECOND SWEEP OF THE
    # COPIES. The banks are asked outside every lock, after the first sweep,
    # so another process can take a backup while they answer — and that copy
    # holds these very session rows (bank-session identifiers). Destroying the
    # rows and leaving that copy would leave the one identifier the erasure
    # promised gone, restorable. So: settle, delete the proven rows, append
    # `erase <op> pending` as the LAST statement before the COMMIT, then sweep
    # under the still-held index handle. A copy taken before this COMMIT is in
    # the directory and goes; one taken after it copies the ledger without the
    # rows. A failed append rolls the DELETE back: the rows stay, so no copy
    # can hold an identifier the ledger no longer has, and the reply says why.
    handle = state = erase_op = None
    try:
        c.execute("BEGIN IMMEDIATE")
        state, handle = backups.settle(c, paths)
        destroyed = c.execute(
            "DELETE FROM sessions WHERE closed_at IS NOT NULL").rowcount
        if destroyed:
            # Only when rows really went in THIS transaction: with none
            # destroyed no copy can hold an identifier the ledger lost.
            erase_op = backups.new_op_id()
            handle.append("erase", erase_op, "pending")
        c.execute("COMMIT")
    except backups.BackupError as exc:
        if c.in_transaction:
            c.execute("ROLLBACK")
        if handle is not None:
            handle.close()
        # Settlement succeeded when `state` is set, so the failure is the
        # sweep's own `pending` append.
        return (False, _handles_kept_note(due, exc, state is not None),
                _settled_lines(exc.settled
                               or (state.settled if state else None)))
    except Exception as exc:                 # noqa: BLE001 — class name only
        if c.in_transaction:
            c.execute("ROLLBACK")
        if handle is not None:
            handle.close()
        failure = type(exc).__name__
        extra = _settled_lines(state.settled if state else None)
        if due is None:
            return False, (
                "WARNING — the local ledger IS erased, but the sweep of "
                "session rows could not run (%s) and this call could not read "
                "how many were due, so it cannot tell you whether an inert row "
                "was left behind. Run consent_status to see what is still "
                "listed, and delete_all_data again to finish." % failure), extra
        if not due:
            # Not a WARNING: there is no residue and nothing to do about it.
            # Still said out loud, because a write that failed is never
            # silently swallowed here — the operator seeing a disk give way in
            # three places at once is reading a different problem.
            return False, (
                "Note — the sweep of session rows could not run (%s), but "
                "NOTHING WAS DUE for removal: no consent is recorded here as "
                "proven gone, so this call destroyed no handle and left none "
                "behind. There is nothing to clear." % failure), extra
        # EVERY CLAIM HERE IS SCOPED TO THE ROWS IT COUNTS. This warning can
        # stand beside the halted-pass warning, which is about the DISJOINT
        # set of consents nobody could prove dead — so an unscoped "there is
        # nothing left to revoke" reads, one line down, as a denial of the
        # sentence above it. "Those" and a count are what keep the two sets
        # apart on the page.
        return False, (
            "WARNING — the local ledger IS erased, but %d session row(s) "
            "belonging to consents ALREADY PROVEN GONE could not be removed "
            "(%s). Those rows are inert: the provider confirmed those consents "
            "gone, so consent_status does not list them and there is nothing "
            "left to revoke at those banks. Run delete_all_data again to clear "
            "the residue." % (due, failure)), extra
    lines = _settled_lines(state.settled)
    try:
        if erase_op is not None:
            swept = _second_sweep(paths, handle, state, erase_op)
            if swept:
                lines.append(swept)
        return True, None, lines
    finally:
        handle.close()


def _settled_tail(state) -> str:
    """" <sentence>" naming what this call's settlement removed when it
    completed an interrupted erasure, or "" when it removed nothing."""
    if state is None or state.settled is None:
        return ""
    return " " + backups.settled_note(state.settled)


def _settled_lines(settled) -> list:
    """The settlement that opens the row sweep completes any erasure still
    pending — the first sweep's, when it stopped above — and removing copies
    there is part of this call's account: a reply that said the erasure had
    not finished must also say that it then did."""
    if settled is None:
        return []
    if not settled.finished:
        return ["Settlement then resumed the pending erasure of the backup "
                "copies and removed %s before it refused; the erasure is not "
                "finished." % settled.went()]
    return ["Settlement then completed the pending erasure of the backup "
            "copies: it removed %s." % settled.went()]


def _handles_kept_note(due, exc, appending: bool) -> str:
    """The rows were kept because the index could not settle or record the
    sweep that has to go with them. `exc` is our own text, never a body."""
    if due == 0:
        return ("Note — the sweep of session rows could not run (%s), but "
                "NOTHING WAS DUE for removal: no consent is recorded here as "
                "proven gone, so this call destroyed no handle and left none "
                "behind. There is nothing to clear." % exc)
    counted = ("%d session row(s)" % due if due is not None
               else "the session rows")
    note = ("WARNING — the local ledger IS erased, but %s belonging to "
            "consents ALREADY PROVEN GONE were kept: the backup index could "
            "not settle or record the sweep of the backup copies that has to "
            "go with them (%s), and destroying the rows without it could "
            "leave a copy holding an identifier this ledger no longer has. "
            "Those rows are "
            "inert: the provider confirmed those consents gone, so "
            "consent_status does not list them and there is nothing left to "
            "revoke at those banks. Run delete_all_data again to clear them."
            % (counted, exc))
    if appending and exc.written is not False:
        # True: the line landed and only its flush failed. None: it may stand
        # part-written. Either way this call cannot say it is absent.
        note += (" A record of that sweep may already be in the index; if "
                 "so, the next settlement removes the backup copies.")
    return note


def _second_sweep(paths, handle, state, erase_op):
    """Sweep the copies after the session rows went; -> a reply line or None.
    Never raises: the rows are already destroyed and the banks already asked,
    so a failure is reported after the erasure, with its count."""
    try:
        er = backups.erase_backups(paths, handle, state, erase_op)
    except backups.ErasureRecordUnwritten as exc:
        er = exc.erasure or backups.Erasure()
        return ("Every backup copy found after the banks were asked (%s) "
                "was erased with the session rows destroyed here, but the "
                "index record confirming it could not be written (%s); the "
                "next settlement (any backup, restore, listing or workflow "
                "write) writes it." % (er.went(), exc))
    except backups.ErasureIncomplete as exc:
        return ("WARNING — the session rows of consents proven gone were "
                "destroyed, but the sweep of the backup copies found after the "
                "banks were asked did not finish: %s went, and %s. No "
                "backup, restore, total erasure or workflow write runs until "
                "the erasure completes; every other call, reads included, is "
                "unaffected. Run delete_all_data again to retry, or delete %s "
                "by hand." % (exc.erasure.went(), exc.residue(),
                              backups.by_hand(paths, exc.erasure)))
    except backups.BackupError as exc:
        return ("WARNING — the session rows of consents proven gone were "
                "destroyed, but the sweep of the backup copies found after the "
                "banks were asked stopped part way (%s), and this call "
                "cannot say which of them are still there. The sweep is "
                "recorded as pending, so the next settlement (any backup, "
                "restore, listing or workflow write) finishes it." % exc)
    line = None
    if er.removed_any():
        line = ("%s found after the banks were asked were erased too: a copy "
                "taken while they answered holds the session rows destroyed "
                "here." % er.went())
    if er.index_warning:
        line = ((line + " ") if line else "") + (
            "The index record closing that sweep could not be flushed (%s) — "
            "it is readable and settles at the next listing."
            % er.index_warning)
    return line


@register("delete_all_data",
          "Erase the entire local ledger. Protected: casa demands an operator "
          "grant bound to this exact call.",
          {"type": "object", "properties": {}})
def delete_all_data(args: dict) -> str:
    refusal = _require_declared("delete_all_data")
    if refusal:
        return refusal
    c = _conn()
    # Counted BEFORE the deletion, deliberately: this tool has to name what
    # re-linking would and would not restore, and a count read afterwards would
    # name three zeroes. Consents are counted `closed_at IS NULL` — the same
    # set `consent_status` shows and the same set this tool tries to withdraw.
    # Counting closed ones inflates the stated cost of the call in the one
    # sentence that has to be accurate.
    counts = {"sessions": c.execute("SELECT COUNT(*) FROM sessions WHERE"
                                    " closed_at IS NULL").fetchone()[0]}
    for table in ("transactions", "accounts"):
        counts[table] = c.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0]
    # Read here, BEFORE the transaction, for the same reason as `counts`
    # above: the "Done." message has to say whether the backup crash-recovery
    # marker was actually there to keep. Reading it after the erasure would
    # always say "kept" whenever it is present at all — STRUCTURAL_META_KEYS
    # keeps it unconditionally — which cannot distinguish the common case (no
    # unsettled restore, so no marker) from the rare one this whitelist entry
    # exists for.
    marker_was_present = c.execute(
        "SELECT 1 FROM meta WHERE key=?", (backups.MARKER_KEY,)).fetchone() is not None

    # THE REVERSIBLE HALF GOES FIRST, AND IT IS DURABLE BEFORE THE FIRST BANK
    # IS ASKED. Withdrawing the consents first makes the IRREVERSIBLE half the
    # first half: an erasure that then fails and rolls back leaves the ledger
    # whole, the operator's bank access gone at every bank at once, and a
    # message saying only that the erasure failed — which reads as "nothing
    # happened". The truth would be that the half that cannot be undone had
    # happened and the half that can had not.
    #
    # `sessions` is NOT in this transaction. A session row is the only handle
    # this plugin has on a live PSD2 grant, so it is destroyed only after the
    # provider has proved the grant gone. Everything else about a consent
    # goes here, before anything is irreversible.
    #
    # The provider calls stay OUTSIDE any transaction: network work inside a
    # write transaction holds the ledger locked for as long as the bank
    # takes.
    c.execute("BEGIN IMMEDIATE")
    # Settle the backup index under both locks BEFORE erasing the
    # registrations: a mint committed by a process that died before its
    # terminal record would otherwise settle `orphan` once its
    # registration is gone. A settlement refusal leaves the erasure
    # unapplied.
    paths = backups.paths_for(tools_read.ledger_path(c))
    try:
        backup_state, handle = backups.settle(c, paths)
    except backups.BackupError as exc:
        c.execute("ROLLBACK")
        if isinstance(exc, backups.ErasureIncomplete):
            # Settlement was completing an erasure an EARLIER call recorded,
            # and it just retried every remaining copy. "Nothing was erased"
            # would be false about this call's own attempt on those files and
            # says nothing about the only residue there is, so the residue is
            # named instead. No claim is made about the ledger's rows: whether
            # that earlier call's ledger half landed is its own report to give.
            #
            # `describe()` carries the alarm, and carries it only for the
            # copies it is true of: a `.partial` is not restorable, so telling
            # an operator that one is a whole copy of their ledger sends them
            # after the wrong file with the wrong urgency.
            #
            # The consequence is stated as the set it really is. "Nothing else
            # here can proceed" was false of every read, of `sync`, and of
            # every write that carries no workflow: only the four calls that
            # settle the index — `backup`, `restore_backup`, `delete_all_data`
            # and a workflow-bearing write — refuse, and an operator told the
            # plugin was wholly wedged goes looking for a different fault.
            return ("An erasure recorded earlier is not finished: %s. No "
                    "backup, restore, total erasure or workflow write runs "
                    "until the erasure completes. Check the backups "
                    "directory (%s)%s: make it writable, repair the disk it "
                    "is on, or delete its contents by hand; then run any "
                    "backup, restore, listing or workflow write to finish "
                    "the erasure."
                    % (exc.describe(), paths.backups_dir.name,
                       " and the %s* files beside the ledger"
                       % paths.snapshot_prefix
                       if backups.snapshots_at_risk(exc.erasure) else ""))
        if isinstance(exc, backups.ErasureRecordUnwritten):
            # Settlement COMPLETED an earlier erasure's sweep — every copy is
            # gone and the directory flushed — and only the record confirming
            # it failed. "Nothing was erased" would be false of the copies
            # this very call just unlinked.
            er = exc.erasure or backups.Erasure()
            return ("An erasure recorded earlier was completed by this call's "
                    "settlement: every backup copy is gone (%s removed now), "
                    "but the index record confirming it could not be written "
                    "(%s)%s; it will be written at the next settlement (any "
                    "backup, restore, listing or workflow write). This call's "
                    "own erasure did not run: the ledger was not erased."
                    % (er.went(),
                       exc,
                       " and may stand part-written until then"
                       if exc.written is None else ""))
        if exc.settled is not None:
            # Any other refusal raised AFTER settlement unlinked copies: the
            # ledger half did not run, the copies that went are gone.
            return ("%s. The ledger was not erased; %s"
                    % (exc, backups.settled_sentence(exc.settled)))
        return "%s. Nothing was erased." % exc
    except Exception:
        # Anything that is NOT a BackupError — a bug, an OOM, a
        # KeyboardInterrupt — would otherwise leave the module-singleton
        # connection `in_transaction` for ever: the next BEGIN IMMEDIATE any
        # write tool issues in this process fails "cannot start a transaction
        # within a transaction", and every write tool is wedged until the
        # process restarts. Same shape as list_backups' and restore_backup's
        # catch-alls, for the same reason.
        if c.in_transaction:
            c.execute("ROLLBACK")
        raise
    erased_backups, backups_warning, erase_op = None, None, None
    try:
        for table in _DATA_TABLES:
            c.execute("DELETE FROM %s" % table)
        # `meta` is where the renewal handoff lives, under a key that EMBEDS
        # THE RAW SESSION ID (`renewal_handoff|<session_id>`), alongside the
        # single-flight claims and the provenance fingerprint. Excluding `meta`
        # would contradict the full-erasure claim and retain bearer-equivalent
        # identifiers. Everything non-structural goes; the structural keys are
        # named explicitly, so a key added later is deleted by default rather
        # than surviving because nobody remembered it.
        c.execute("DELETE FROM meta WHERE key NOT IN (%s)"
                  % ", ".join("?" * len(STRUCTURAL_META_KEYS)),
                  tuple(STRUCTURAL_META_KEYS))
        # THE ERASURE OF THE COPIES IS RECORDED BEFORE IT HAPPENS, through the
        # same index protocol a mint and a restore already use. Without this
        # record a crash between the COMMIT below and `erase_backups` left an
        # empty ledger beside an intact whole-ledger copy, and `restore_backup`
        # brought the erased transaction straight back — the one outcome this
        # call promises cannot happen. `append` fsyncs, so settlement in ANY
        # later process finishes the file erasure from the record alone.
        #
        # It is the LAST statement before the COMMIT on purpose. A failure
        # above it rolls the ledger back with nothing recorded and nothing
        # erased. A failure of the COMMIT itself rolls the ledger back with the
        # record already durable, and the copies then go at the next
        # settlement anyway: an erasure the operator authorised is not
        # cancelled by its ledger half failing, and the honest report of that
        # case is "the ledger erasure failed and the copies are gone", never
        # copies left sitting in the one place the operator was told they
        # would not be.
        erase_op = backups.new_op_id()
        handle.append("erase", erase_op, "pending")
        c.execute("COMMIT")
    except backups.BackupError as exc:
        # Only the `append` above raises this here, and it raises BEFORE the
        # COMMIT: with no durable pending record nothing would ever complete
        # the erasure of the copies, so the whole call refuses rather than
        # empty a ledger whose whole-ledger copies would outlive it.
        if c.in_transaction:
            c.execute("ROLLBACK")
        # This call's settlement ran before the refusal, and when it completed
        # an interrupted erasure it removed copies: every branch below says
        # so, and none of them says "Nothing was erased" then.
        done_by_settle = _settled_tail(backup_state)
        if exc.written is None:
            # THE WRITE FAILED PART WAY AND ITS BYTES COULD NOT BE CUT BACK.
            # The ledger rolled back, so nothing of it was erased; but the
            # index may end in a partial record until the next settlement
            # removes it, and "Nothing was erased" is a claim this call
            # cannot make about a file it may have left a partial line in.
            return ("%s. The ledger was not erased: its erasure was rolled "
                    "back. The index may hold a partial record of the backup "
                    "erasure; the next settlement (any backup, restore, "
                    "listing or workflow write) recovers it.%s"
                    % (exc, done_by_settle))
        if exc.written:
            # THE BYTES LANDED AND ONLY THE FLUSH FAILED. The line is readable
            # right now by anything that parses this index, so the next settle
            # in any process completes the erasure of the copies — "Nothing was
            # erased" would be a promise about files this call has already
            # scheduled for removal, and the operator would go looking for
            # backups that are about to disappear.
            return ("%s. The ledger was not erased. A record of the backup "
                    "erasure may already be durable: the backup copies will be "
                    "removed at the next settlement (any backup, restore, "
                    "listing or workflow write).%s" % (exc, done_by_settle))
        if done_by_settle:
            return "%s. The ledger was not erased.%s" % (exc, done_by_settle)
        return "%s. Nothing was erased." % exc
    except Exception as exc:                 # noqa: BLE001 — class name only
        if c.in_transaction:
            c.execute("ROLLBACK")
        if erase_op is not None:
            # THE APPEND IS THE LAST STATEMENT BEFORE THE COMMIT, so reaching
            # here with an erasure id in hand means the COMMIT itself is what
            # failed — an exact discriminator, not a guess at the exception's
            # class. The ledger rolled back intact and the pending record is
            # durable, so the copies go at the next settlement regardless.
            # Raising here handed the operator a generic error for a state
            # with two specific halves, both of which they need to know.
            return ("The ledger erasure failed (%s) and was rolled back — the "
                    "ledger is intact. The backup copies are still scheduled "
                    "for erasure and will be removed at the next settlement.%s"
                    % (type(exc).__name__, _settled_tail(backup_state)))
        raise
    else:
        # THE BACKUP FILES ARE PART OF "THE ENTIRE LOCAL LEDGER". Each
        # `<db>.backups/*.sqlite` is a whole-ledger copy — sessions, the
        # renewal-handoff `meta` keys, `accounts.uid`, every transaction — so
        # leaving them behind made every sentence below false: one
        # `restore_backup` put the erased ledger back. This runs AFTER the
        # COMMIT, while the index handle from the settle above is still held;
        # the index itself is kept, append-only, so the record of the erasure
        # survives it and the restore generation stays monotonic.
        try:
            erased_backups = backups.erase_backups(paths, handle, backup_state,
                                                   erase_op)
        except backups.BackupError as exc:
            # Reported, never raised: the ledger is already erased by the
            # COMMIT above, and raising here would discard the whole account
            # of what this call did — the same rule the "PAST THIS LINE"
            # contract below states for the bank half.
            #
            # The copies that DID go are still counted, from the exception
            # itself: the sweep no longer stops at the first file it cannot
            # unlink, so "some went and some did not" is now the ordinary
            # shape of this failure and a reply that counted none of them
            # would understate what the retry still has to do.
            erased_backups = (exc.erasure
                              if isinstance(exc, (backups.ErasureIncomplete,
                                                  backups.ErasureRecordUnwritten))
                              else None)
            # `residue()`, not the whole account: the count sentences below
            # already say what went, so this line says only what is left — and
            # it splits whole copies from partials, because the alarm is true
            # of one and not the other.
            #
            # The consequence for the OTHER calls that settle is stated here
            # too. It used to appear only in the message a RETRY got, which the
            # operator sees only if they run one: until the erasure completes
            # the pending erase record makes settlement refuse, so the next
            # backup, restore or workflow write fails with no hint that this
            # call is why. It is named as that set and no wider: a read, a
            # `sync` and every write that carries no workflow never settle the
            # index and are untouched, and claiming otherwise sent an operator
            # after a fault that is not there.
            if isinstance(exc, backups.ErasureIncomplete) and (
                    exc.erasure.failed or exc.erasure.failed_partials
                    or exc.erasure.failed_snapshots
                    or exc.erasure.failed_snapshot_sidecars):
                left = ("at least one backup file beside it could not be "
                        "removed: %s" % exc.residue())
            elif isinstance(exc, backups.ErasureIncomplete):
                # Every copy WAS unlinked and what failed is the flush that
                # makes the unlinks outlive a power loss. "Could not be
                # removed" would send the operator looking for a file that is
                # not there; what is true is that the erasure is not finished.
                left = ("the removal of the backup copies is not durable yet: "
                        "%s" % exc.residue())
            elif isinstance(exc, backups.ErasureRecordUnwritten):
                # NOT A STALLED SWEEP. `ErasureRecordUnwritten` is raised only
                # once every copy is already gone and the directory already
                # flushed, so it neither shares the generic template below
                # (there is nothing here for the operator to retry or delete
                # by hand) nor the `else` branch's "stopped part way" wording,
                # which would describe a directory this call has just emptied
                # as one still holding copies.
                backups_warning = (
                    "Every backup copy was erased and the directory "
                    "flushed, but the index record confirming it could not "
                    "be written (%s); the next settlement (any backup, "
                    "restore, listing or workflow write) re-checks the "
                    "directory and writes it." % exc)
                left = None
            else:
                # The sweep did not finish rather than failing on named files,
                # so what went and what is left is precisely what this
                # exception cannot say — and a count that was not measured is
                # the one thing this reply must not invent.
                left = ("the erasure of the backup files stopped part way "
                        "(%s), and this call cannot say which of them are "
                        "still there" % exc)
            if left is not None:
                backups_warning = (
                    "WARNING — the local ledger IS erased, but %s. No backup, "
                    "restore, total erasure or workflow write runs until the "
                    "erasure completes; every other call, reads included, is "
                    "unaffected. Run delete_all_data again to retry, or delete "
                    "%s by hand." % (left, backups.by_hand(
                        paths, erased_backups)))
    finally:
        handle.close()
    # THE SURVIVOR LIST NAMES EXACTLY WHAT SURVIVES, NEVER "ONLY" TWO OF
    # THEM. `backup_restore_op` (`backups.MARKER_KEY`) is in
    # STRUCTURAL_META_KEYS beside `schema_version` and `account_secret`, so a
    # restore that left it behind means a THIRD row remains — "only the
    # schema version and the local account_id secret remain" was then false
    # of the row sitting right there in `meta`. The marker only ever exists
    # at all when an unsettled restore needed it, so it is named here only
    # when `marker_was_present` — read BEFORE the erasure, for the same
    # reason as `counts` above.
    survivors = ("the schema version, the local account_id secret and the "
                "backup subsystem's crash-recovery marker remain (none of "
                "them carries bank data)" if marker_was_present else
                "the schema version and the local account_id secret remain "
                "(neither carries bank data)")
    # "The restore fingerprint" here is `provenance.py`'s environment
    # fingerprint (`provenance_fp`), which this DELETE always erases -- it is
    # NOT in STRUCTURAL_META_KEYS and is a different key from the backup
    # subsystem's crash-recovery marker named in `survivors` above.
    done = ("Done. Every non-structural metadata row went with the data, "
            "including the renewal-handoff records whose keys embed a bank "
            "session identifier; %s, so the database is immediately usable "
            "again. The restore fingerprint is gone too: the next run "
            "records a fresh one, which is correct — this ledger has no "
            "past to be restored from any more." % survivors)
    if marker_was_present:
        # The marker's own survival is already named in `survivors` above —
        # saying it was "kept" a second time here would restate the same
        # fact under a different word. What this sentence adds is what the
        # sentence above does NOT cover: the registrations that pointed at
        # backups are gone, so the next workflow write starts a fresh one.
        done += (" The workflow registrations were erased, so a workflow's "
                "next write mints a fresh restore point.")
    # A RETRY'S OWN SETTLEMENT CAN FINISH THE EARLIER CALL'S SWEEP before this
    # call's sweep runs, and what it removed there is in `backup_state`, not in
    # `erased_backups`: without this sentence the files the retry actually
    # removed went unmentioned in a reply that succeeded.
    done += _settled_tail(backup_state)
    if erased_backups is not None:
        # EVERY NUMBER HERE COUNTS ONLY WHAT WENT, one per shape
        # (`Erasure.went`): an indexed copy leaves a `prune` record, a copy in
        # flight and a snapshot never had one, and a file the sweep could not
        # unlink is the warning's subject, not this sentence's. A single total
        # would be a number the index cannot corroborate. Nothing there to
        # erase says nothing at all — "0 backup file(s) were erased" reads as
        # a failure of a call that succeeded.
        if erased_backups.removed_any():
            done += (" %s were erased too — each is a copy, or part of a copy, "
                     "of this ledger." % erased_backups.went())
        if erased_backups.index_warning:
            # The sweep finished and only the terminal record's FLUSH did not.
            # The line is readable, so the erasure is complete and the next
            # settlement reads it as complete; the gap is in the audit trail's
            # durability, not in the erasure, and saying the sweep "stopped
            # part way" — which is what this used to print — described an empty
            # directory as one still holding copies.
            done += (" Every backup copy was erased; the index record "
                     "confirming it could not be flushed (%s) — it is readable "
                     "and settles at the next listing."
                     % erased_backups.index_warning)

    # PAST THIS LINE THIS TOOL DOES NOT RAISE. Everything below is either
    # irreversible at a bank or already committed here, so an exception would
    # discard the only account the operator ever gets of what was done to their
    # bank access — which is precisely the defect this reorder exists to close,
    # re-entered one statement later. Each remaining step therefore reports its
    # own failure the way `_reclaim` does.
    try:
        gone, kept = _withdraw_open_consents(c)
        halted = None
    except Exception as exc:                 # noqa: BLE001 — class name only
        # The provider loop itself came apart — e.g. the local record of a
        # revocation could not be written. Some banks may already have acted
        # and this process no longer knows which, so it claims NOTHING: no
        # consent is reported withdrawn, and `_destroy_proven_handles` reads
        # `closed_at` rather than this function's return value, so every row
        # nobody proved dead survives and stays revocable.
        gone, kept, halted = [], [], type(exc).__name__

    handles_ok, handles_note, sweep_lines = _destroy_proven_handles(c, paths)

    # THE ITEM THAT COSTS MONEY LEADS. What became of the banks'
    # own permissions is the only part of this call that can still cost the
    # operator anything — a consent this call could not withdraw keeps serving
    # this application for the rest of its 179 days — so it is assembled here
    # and printed directly under the headline. It used to sit on line 5 of 8,
    # UNDER a line that reads "Done.", between a paragraph about metadata keys
    # and a warning about free pages; a reader who skimmed the first line and
    # the last concluded the call had worked.
    consents = []
    if halted:
        consents.append(
            "WARNING — the withdrawal pass did not finish (%s). One or more "
            "bank consents MAY ALREADY HAVE BEEN WITHDRAWN at their banks, and "
            "this call cannot tell you which: the local record of the pass "
            "failed part way. No consent's handle was destroyed on a guess, so "
            "every consent this call could not prove dead is still listed. Run "
            "consent_status to see what is left, unlink_bank to withdraw any "
            "that survived, and delete_all_data again once it is clean."
            % halted)
    if gone:
        # THE SAME COMPOSITION AGAIN, one output further on (see
        # `_destroy_proven_handles`). "their local rows went with the rest" is
        # a claim about the sweep, made by the branch that knows only what the
        # BANKS said — so with the sweep broken this line would assert the rows
        # were gone four lines above the line saying they could not be
        # removed.
        consents.append(
            "Withdrawn at the bank: %d consent(s) — %s. The provider confirmed "
            "each one%s"
            % (len(gone), ", ".join(_safe(r["aspsp_name"]) or "an unnamed bank"
                                    for r in gone),
               ", so their local rows went with the rest." if handles_ok else
               ". Their local rows could not be removed with the rest — the "
               "note below says what is left and how to clear it."))
    if kept:
        # Saying "erased everything" here would be the lie this whole
        # ordering exists to avoid.
        #
        # ONE value behind both numbers in this paragraph. It reported "%d bank
        # consent(s) could not be withdrawn" and then, in the same breath,
        # "Leaving ONE row behind is the honest outcome" — a sentence that
        # silently disagreed with the count four clauses earlier whenever two
        # or more consents survived, in the paragraph whose whole job is to
        # make an operator accept the survivors as deliberate.
        survivors = len(kept)
        # The rationale for keeping the rows is a claim about what destroying
        # them would cost, and for a consent whose validity has passed "would
        # leave the bank serving this application for the rest of the consent's
        # 179 days" is not that cost. The POLICY does not change and must not:
        # the rows are kept on the same rule either way, because the local date
        # is not proof and `closed_at` is written only on a confirmed
        # withdrawal. Only the reason given for it is measured against the rows
        # actually in hand — `any`, because one standing grant among them is
        # enough to justify keeping all of them, and because "some of these may
        # still be standing" is the honest summary when the terms differ.
        standing = any(tools_auth._expiry_state(r.get("valid_until"))[0]
                       != tools_auth.EXPIRED for r in kept)
        consents.append(
            "NOT FULLY ERASED, DELIBERATELY — %d bank consent(s) could not be "
            "withdrawn, so their session row was KEPT. Everything else about "
            "them is gone. A consent row is the ONLY handle this plugin has on "
            "a PSD2 grant, and %s "
            "Leaving %d row%s behind is the honest outcome and it is strictly "
            "the better one."
            % (survivors,
               "destroying one we could not prove is dead would leave the bank "
               "serving this application for the rest of that consent's term "
               "with nothing here able to see or revoke it."
               if standing else
               "the recorded validity of every one of them has already passed "
               "— so the bank most likely holds nothing, but that was never "
               "confirmed, and destroying the only handle to a grant that may "
               "yet be standing is not a risk worth taking to tidy a row.",
               survivors, "" if survivors == 1 else "s"))
        for row in kept:
            consents.append(
                "  %s — consent_ref %s (%s). Run unlink_bank consent_ref=%s to "
                "retry; consent_status lists it until it succeeds. If it keeps "
                "failing, withdraw it from that bank's own consent screen, then "
                "run delete_all_data again to clear the row."
                % (_safe(row["aspsp_name"]) or "an unnamed bank",
                   tools_auth._consent_ref(row["session_id"]), row["failure"],
                   tools_auth._consent_ref(row["session_id"])))

    # THE HEADLINE STATES NO OUTCOME IT DOES NOT YET KNOW. It used to say
    # "…and withdrawing %d bank consent(s)" — an INTENTION, built before a
    # single bank had been asked and left standing four lines above the truth
    # that none of them were withdrawn. The count itself stays: this tool has
    # to name what the call costs, and `closed_at IS NULL` read
    # before the erasure is the honest cost. What goes is the verb.
    #
    # The pointer is added only when there IS a line to point at, and it
    # branches on the assembled report rather than on `counts["sessions"]`:
    # the count is read before the erasure and the report is built after the
    # banks answer, so they are two facts, and this sentence is a claim about
    # the second one.
    # Issue #6 trims the same word here. The count is `closed_at IS NULL` —
    # every consent this plugin still holds a handle on — and some of those
    # rows can be past their `valid_until`, because nothing flips a status when
    # a consent lapses. "live at the banks" is therefore a claim the count
    # cannot support for every row it includes. Splitting a headline COUNT by
    # expiry would be worse than the word it replaces (two numbers to reconcile
    # against a per-consent report four lines down), so the count stays exactly
    # as it is and only the claim about the banks is dropped; the per-consent
    # lines above are where liveness is stated, one row at a time.
    head = ("Erasing the entire local ledger: %d transaction(s) across %d "
            "account(s), with %d bank consent(s) still held open here when "
            "this call started." % (counts["transactions"], counts["accounts"],
                                    counts["sessions"]))
    if consents:
        head += " The next line, not this one, says what became of them."

    notice = [head] + consents + [
        "What re-linking WOULD restore: a fresh SCA reopens each bank's "
        "deep-history window, so re-linking recovers that bank's history as "
        "far back as that bank itself retains it — which differs per bank and "
        "is not something this plugin can promise in advance. Losing this "
        "database costs a re-link and some tapping, not the history.",
        # The cross-reference is a claim about the layout of THIS message, so
        # it is made only when there is something up there to read. It used to
        # say "below" and pointed past the end of the message on a ledger with
        # no consents at all.
        "What it would NOT restore: your labels, categories and include flags; "
        "the bank authorizations (every bank must be approved again before "
        "anything refreshes%s); and — the only genuinely unrecoverable part — "
        "anything that predates a bank's retention AND was captured here "
        "before it aged out. That is a narrow, years-away sliver today."
        % (" — and the withdrawal report above says which of the banks' own "
           "permissions this call actually managed to withdraw" if consents
           else ""),
        done,
    ]
    if backups_warning:
        notice.append(backups_warning)
    if not handles_ok:
        notice.append(handles_note)
    notice.extend(sweep_lines)
    notice.append(_reclaim(c)[1])
    notice.append(GATE_NOTE)
    return "\n".join(notice)
