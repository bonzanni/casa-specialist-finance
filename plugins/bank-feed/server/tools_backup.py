"""backup / list_backups / restore_backup (issue #39).

The mechanism is `backups`; this module is the text. `restore_backup` is
PROTECTED: casa demands an operator grant bound to the exact `backup_id`
before the call reaches this process, and `_require_declared` is the
tripwire behind that gate, as for the other six.

Everything printed here is our own text: ids are hex, reasons a closed set,
workflow strings charset-constrained (backups.WORKFLOW_RE) — nothing needs
the untrusted fence, for the same reason tags do not.
"""
from __future__ import annotations

import backups
import store
import tools_auth
import tools_read
from tools_auth import _require_declared
from tools_read import register

STALE_LINE = "Refresh reports produced while this restore ran may be stale; run sync."


def render_listing(state: backups.LedgerState) -> str:
    lines = ["Restore generation: %d" % state.generation]
    rows = sorted(state.backups.items(), key=lambda kv: kv[1]["seq"], reverse=True)
    lines.append("Backups (newest first): %s" % ("none" if not rows else ""))
    # EVERY indexed backup is listed, including one whose file is gone: a
    # pruned or missing backup is part of the inventory the operator reads,
    # and hiding it would hide exactly the "FILE MISSING" a broken
    # registration points at.
    for op, b in rows:
        if b.get("pruned"):
            where = "pruned"
        elif not b["present"]:
            where = "FILE MISSING"
        else:
            where = ("%d B" % b["size"] if b["size"] is not None
                     else "size unreadable")
        lines.append("  %s  %s  %s  %s  %s" % (op, b["ts"], where, b["reason"], b["state"]))
    if state.registrations:
        lines.append("Registered workflows:")
        for wf, reg in sorted(state.registrations.items()):
            missing = (" (FILE MISSING — this workflow's next write mints a new restore "
                       "point; its earlier writes are not covered)"
                       if wf in state.broken else "")
            lines.append("  %s -> %s%s" % (wf, reg["backup_id"], missing))
    else:
        lines.append("Registered workflows: none")
    done = [r for r in state.restores if r["state"] != "pending"]
    if done:
        lines.append("Restores:")
        for r in done:
            lines.append("  %s  %s  of %s  %s" % (r["op_id"], r["ts"], r["backup_id"], r["state"]))
    else:
        lines.append("Restores: none")
    return "\n".join(lines)


@register("backup",
          "Take a consistent copy of the whole finance ledger. reason is "
          "'weekly' (taken by the finance pass) or 'manual'. Retention keeps "
          "the 8 most recent of each; install backups are never pruned.",
          {"type": "object", "properties": {
              "reason": {"type": "string", "enum": list(backups.REASONS)}},
           "required": ["reason"]})
def backup(args: dict) -> str:
    reason = args.get("reason")
    if reason not in backups.REASONS:
        return "reason must be 'weekly' or 'manual'. Nothing was changed."
    c = tools_read.conn()
    paths = backups.paths_for(tools_read.ledger_path(c))
    c.execute("BEGIN IMMEDIATE")
    handle = state = None
    try:
        state, handle = backups.settle(c, paths)
        b = backups.take_backup(c, paths, handle, reason)
        c.execute("COMMIT")
    except backups.BackupError as exc:
        # Guarded like every sibling: SQLite auto-rolls-back on SQLITE_FULL
        # and SQLITE_IOERR, and a bare ROLLBACK after one of those raises
        # "cannot rollback — no transaction is active", which masks the real
        # cause and leaks the index lock with it.
        if c.in_transaction:
            c.execute("ROLLBACK")
        if handle is not None:
            handle.close()
        # Neither an ErasureIncomplete out of `settle` nor a refusal after a
        # settlement that completed an erasure is "nothing was changed": the
        # settlement this call triggered removed copies, and the text for
        # that lives with the exception and the settled state.
        return backups.refusal_text(exc, state)
    except Exception:
        if c.in_transaction:
            c.execute("ROLLBACK")
        if handle is not None:
            handle.close()
        raise
    try:
        pruned = backups.finish_backup(paths, handle, b, committed=True)
    except backups.BackupError as exc:
        # finish_backup runs AFTER the COMMIT above: the backup itself is
        # already real and durable by the time retention can fail, so this
        # is never "nothing was changed" -- it is "one more thing than
        # retention managed to do", and the operator needs the id either way.
        return _with_settled(
            "Backup %s written (%s, %d bytes). %s; the backup itself is "
            "complete." % (b.op_id, reason, b.size,
                           backups.retention_failed(exc)), state)
    finally:
        handle.close()
    out = "Backup %s written (%s, %d bytes)." % (b.op_id, reason, b.size)
    if pruned:
        out += " Retention pruned %s." % ", ".join(pruned)
    return _with_settled(out, state)


def _with_settled(text: str, state) -> str:
    """A reply that SUCCEEDED still says what its settlement removed on the
    way: completing an interrupted erasure changed the directory, and a
    reply silent about it leaves the operator looking for files that went."""
    note = backups.settled_note(state.settled if state is not None else None)
    return text + " " + note if note else text


@register("list_backups",
          "Every backup (id, time, size, reason, state), the registered "
          "workflow strings and the backup each one minted, the restore "
          "events, and the restore generation. Settles pending operations "
          "first.", {"type": "object", "properties": {}})
def list_backups(args: dict) -> str:
    c = tools_read.conn()
    paths = backups.paths_for(tools_read.ledger_path(c))
    c.execute("BEGIN IMMEDIATE")
    handle = None
    try:
        state, handle = backups.settle(c, paths)
        text = render_listing(state)          # captured under both locks
        note = backups.settled_note(state.settled)
        if note:
            text = note + "\n" + text
        c.execute("COMMIT")
    except backups.BackupError as exc:
        # Guarded like every sibling: SQLite auto-rolls-back on SQLITE_FULL and
        # SQLITE_IOERR, and a bare ROLLBACK after one of those raises "cannot
        # rollback — no transaction is active" out of the except clause, which
        # masks the real cause and turns a refusal into an exception.
        if c.in_transaction:
            c.execute("ROLLBACK")
        if isinstance(exc, backups.ErasureIncomplete) and exc.state is not None:
            # THE ONE CALL THAT CHANGES NOTHING STILL ANSWERS. Refusing here
            # hid the residue behind a count: the operator was told copies
            # could not be removed and then denied the only in-tool view of
            # which copies those are. Settlement attached the state it had
            # built, and rendering it needs no lock — it is a snapshot object,
            # already detached from the index and the directory it was read
            # from, so nothing it prints can change under it.
            #
            # `residue()` carries the counts, which is what keeps whole copies
            # and copies in flight apart here: one lumped total promised rows
            # that are not below it, because a `.partial` never reached the
            # index and the listing has no line for one. The set of calls that
            # refuse is named exactly — this listing is itself the proof that a
            # read is not in it.
            #
            # The generation it prints counts committed restores only, and that
            # is complete here because a pending restore cannot coexist with a
            # pending erase: the `erase <op> pending` line is appended on the
            # handle of a settle that has already terminated every pending
            # restore, and no restore can start one while that record stands.
            return ("Backup erasure incomplete: %s. No backup, restore, total "
                    "erasure or workflow write runs until the erasure "
                    "completes; reads, this one included, still answer. Every "
                    "INDEXED copy is listed below — a copy in flight never "
                    "reached the index and has no row.\n%s"
                    % (exc.describe(), render_listing(exc.state)))
        if exc.settled is not None:
            return "%s. %s" % (exc, backups.settled_sentence(exc.settled))
        return "%s." % exc
    except Exception:
        # Without this, anything render_listing (or settle) throws that is
        # NOT a BackupError -- a bug, an OOM, a KeyboardInterrupt -- leaves
        # the module-singleton connection `in_transaction` forever: the next
        # `BEGIN IMMEDIATE` any write tool issues in this same process fails
        # "cannot start a transaction within a transaction", and every write
        # tool is wedged until the process restarts. Same shape as
        # `restore_backup`'s catch-all, for the same reason.
        if c.in_transaction:
            c.execute("ROLLBACK")
        raise
    finally:
        if handle is not None:
            handle.close()
    return text


@register("restore_backup",
          "PROTECTED. Replace the ledger's rows in place from a backup: "
          "transactions, tags, notes, rules, registrations. Consent bindings "
          "(bank links) are kept live, never taken from the backup. An "
          "account in the backup but not linked live comes back needing a "
          "re-link.",
          {"type": "object", "properties": {"backup_id": {"type": "string"}},
           "required": ["backup_id"]})
def restore_backup(args: dict) -> str:
    refusal = _require_declared("restore_backup")
    if refusal:
        return refusal
    backup_id = args.get("backup_id")
    if not isinstance(backup_id, str):
        return "backup_id must be a string. Nothing was changed."
    c = tools_read.conn()
    paths = backups.paths_for(tools_read.ledger_path(c))
    c.execute("BEGIN IMMEDIATE")
    handle = state = None
    try:
        if tools_auth.authorization_in_progress(c):
            c.execute("ROLLBACK")
            return ("A bank authorization is in progress (a link or renewal "
                    "is completing), and a restore now could make its reply "
                    "wrong about which consent is live. Try again in a few "
                    "minutes. Nothing was changed.")
        state, handle = backups.settle(c, paths)
        r = backups.restore(c, paths, handle, state, backup_id,
                            schema_version=store.SCHEMA_VERSION)
    except backups.BackupError as exc:
        if c.in_transaction:
            c.execute("ROLLBACK")
        # `state` is the settlement's: when it completed an interrupted
        # erasure the copies it removed are gone whatever refused next — the
        # restore of an id that erasure just removed is the ordinary case.
        return backups.refusal_text(exc, state)
    except Exception:
        if c.in_transaction:
            c.execute("ROLLBACK")
        raise
    finally:
        if handle is not None:
            handle.close()
    groups = ["%s: %d row(s)" % (t, n) for t, n in sorted(r.replaced.items())]
    lines = ["Restored backup %s (restore %s)." % (backup_id, r.op_id),
             "Replaced: " + "; ".join(groups) + ".",
             "consent bindings kept live: %d account(s)." % r.bindings_kept]
    if r.relink:
        lines.append("Restored but not linked live — re-link needed: %s."
                     % ", ".join(r.relink))
    if r.unregistered:
        lines.append("Unregistered workflows (their writes are gone): %s."
                     % ", ".join(r.unregistered))
    if r.index_error:
        # The restore committed and only its terminal index record did not
        # land. Saying "nothing was changed" here — which is what a
        # BackupError out of that append used to produce — would be the one
        # untrue sentence this whole subsystem exists to avoid. The three
        # outcomes of the append are three different states of the index:
        # a line that is readable now, a line that is absent, and a line
        # that may stand part-written until a settlement cuts it.
        if r.index_written is True:
            lines.append("The restore is complete; its index record was "
                         "written but could not be flushed (%s); it is "
                         "readable now." % r.index_error)
        elif r.index_written is None:
            lines.append("The restore is complete; its index record may be "
                         "partially written (%s); the next settlement "
                         "recovers it." % r.index_error)
        else:
            lines.append("The restore is complete; its index record could "
                         "not be written (%s) — it settles at the next "
                         "listing." % r.index_error)
    lines.append(STALE_LINE)
    return "\n".join(lines)
