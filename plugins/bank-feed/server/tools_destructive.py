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

import apply
import callbacks
import tools_auth
from tools_auth import (GATE_NOTE, _conn, _require_declared,
                        _resolve_consent_ref, _safe, _vacuum)
from tools_read import register

#: The tools this module registers. Named here so a test can check them
#: against `tools_auth.PROTECTED` — which is spelled ONCE, there — instead of
#: this module re-declaring that set and the two drifting apart.
DESTRUCTIVE_TOOLS = ("unlink_bank", "purge", "forget_local_account",
                     "delete_all_data")

#: The ONLY `meta` keys that survive `delete_all_data`. Both are structural,
#: not data: `schema_version` is what `store.open_db` migrates against, and
#: `account_secret` is the local HMAC key `store.account_id` derives every
#: account id from — regenerating it would silently re-key the whole ledger on
#: the next link. Everything else in `meta` is erasable data, and the
#: renewal-handoff keys in particular EMBED a raw session identifier, which is
#: bearer-equivalent. The list is a whitelist on purpose: a key added by a
#: later feature is deleted by default.
STRUCTURAL_META_KEYS = ("schema_version", "account_secret")

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
#: a measurement OF this installation's own accounts.
_DATA_TABLES = ("transaction_refs", "transaction_tags", "transaction_notes",
                "tag_rules", "transactions", "occurrence_alloc",
                "balances", "coverage", "sync_state", "accounts", "attempts",
                "aspsp_capability", "aspsp_capability_retired",
                "ref_observations")

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
              "are gone from the file and the freed pages have been reclaimed.")


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
            "VACUUM did not run (%s), so the freed pages have NOT been "
            "reclaimed and the erased data may still be recoverable from the "
            "database file (and from any Home Assistant backup taken since). "
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


@register("purge",
          "Really delete every transaction booked before a date, trim the "
          "proven-coverage intervals to match, then VACUUM. Protected: casa "
          "demands an operator grant.",
          {"type": "object",
           "properties": {"before_date": {"type": "string"}},
           "required": ["before_date"]})
def purge(args: dict) -> str:
    refusal = _require_declared("purge")
    if refusal:
        return refusal
    before = _cutoff(args.get("before_date"))
    if before is None:
        return ("before_date must be exactly an ISO date, YYYY-MM-DD — not a "
                "timestamp and not a compact form. Rows are compared to it as "
                "text, so anything else would silently erase MORE than the "
                "date names. Nothing has been changed.")
    c = _conn()
    # One transaction across rows, references and coverage — and it lives in
    # `apply`, beside `apply_plan` and `record_coverage`, because those three
    # tables are three views of the same claim and one owner is what keeps them
    # from disagreeing.
    stats = apply.purge_before(c, before)
    lines = [
        "Purged %d transaction(s) booked before %s, and %d stored provider "
        "reference(s) with them."
        % (stats["transactions"], before, stats["refs"]),
        "Proven-coverage intervals were corrected to match: %d dropped and %d "
        "trimmed to start at %s. Every span before that date now reads as NOT "
        "PROVEN rather than as a period with no transactions — erased history "
        "must never come back as a confident answer."
        % (stats["coverage_dropped"], stats["coverage_trimmed"], before),
        "Re-linking the bank can restore anything still inside that bank's own "
        "retention window; anything older is gone for good.",
        # Rules are counterparty knowledge, not row data: purge erases
        # history, not the learned rulebook.
        "Auto-tagging rules are unaffected.",
        # Same decision, disclosed the same way: an evidence row is a
        # measurement of the bank's reference behaviour -- aggregate counts
        # and dates, no transaction content -- and purging history does not
        # un-measure it. Revoking trust on a purge would demote for a reason
        # that says nothing about the bank. forget_local_account and
        # delete_all_data are the erasers that take evidence with them.
        "Reference-trust evidence is unaffected: it describes the bank's "
        "reference behaviour, not the purged rows.",
    ]
    # `occurrence_alloc` is deliberately NOT purged. It is the only record of
    # the occurrence slots a re-keyed row vacated (store.py), the accounts are
    # still here and still ingesting, and handing a purged slot back out would
    # collide with UNIQUE (account_id, identity_key, occurrence).
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
    count = c.execute("SELECT COUNT(*) FROM transactions WHERE account_id=?",
                      (account_id,)).fetchone()[0]
    c.execute("BEGIN IMMEDIATE")
    try:
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
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    lines = [
        "Erased %s LOCALLY: %d transaction(s), its balances, its coverage, its "
        "sync state, its occurrence allocations and any authorization attempt "
        "fenced against it." % (named, count),
        _bank_access_note(session),
        "Removing the account from the application's Enable Banking whitelist "
        "needs its identification hash, which is not stored here; do that "
        "in the control panel if you want it gone provider-side too.",
        # Rules carry no per-account ownership: forgetting an account keeps
        # the learned rulebook, disclosed.
        "Auto-tagging rules are unaffected.",
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


def _destroy_proven_handles(c):
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

    Returns `(ok, warning or None)`. It does not raise: the erasure is already
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
    try:
        c.execute("DELETE FROM sessions WHERE closed_at IS NOT NULL")
    except Exception as exc:                 # noqa: BLE001 — class name only
        failure = type(exc).__name__
        if due is None:
            return False, (
                "WARNING — the local ledger IS erased, but the sweep of "
                "session rows could not run (%s) and this call could not read "
                "how many were due, so it cannot tell you whether an inert row "
                "was left behind. Run consent_status to see what is still "
                "listed, and delete_all_data again to finish." % failure)
        if not due:
            # Not a WARNING: there is no residue and nothing to do about it.
            # Still said out loud, because a write that failed is never
            # silently swallowed here — the operator seeing a disk give way in
            # three places at once is reading a different problem.
            return False, (
                "Note — the sweep of session rows could not run (%s), but "
                "NOTHING WAS DUE for removal: no consent is recorded here as "
                "proven gone, so this call destroyed no handle and left none "
                "behind. There is nothing to clear." % failure)
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
            "the residue." % (due, failure))
    return True, None


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
    try:
        for table in _DATA_TABLES:
            c.execute("DELETE FROM %s" % table)
        # `meta` is where the renewal handoff lives, under a key that EMBEDS
        # THE RAW SESSION ID (`renewal_handoff|<session_id>`), alongside the
        # single-flight claims and the provenance fingerprint. Excluding `meta`
        # would contradict the full-erasure claim and retain bearer-equivalent
        # identifiers. Everything non-structural goes; the two structural keys
        # are named explicitly, so a key added later is deleted by default
        # rather than surviving because nobody remembered it.
        c.execute("DELETE FROM meta WHERE key NOT IN (%s)"
                  % ", ".join("?" * len(STRUCTURAL_META_KEYS)),
                  tuple(STRUCTURAL_META_KEYS))
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    done = ("Done. Every metadata row went with the data, including the "
            "renewal-handoff records whose keys embed a bank session "
            "identifier; only the schema version and the local "
            "account_id secret remain, so the database is immediately "
            "usable again. The restore fingerprint is gone too: the next "
            "run records a fresh one, which is correct — this ledger has "
            "no past to be restored from any more.")

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

    handles_ok, handles_note = _destroy_proven_handles(c)

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
    if not handles_ok:
        notice.append(handles_note)
    notice.append(_reclaim(c)[1])
    notice.append(GATE_NOTE)
    return "\n".join(notice)
