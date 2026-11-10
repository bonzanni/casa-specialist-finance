---
name: daily-sync
description: The "Bank sync" job's procedure (bank-feed:daily-sync), for the finance specialist — only for a turn whose brief says it is the background job "Bank sync" and carries a `Job id:` line. A question about the banks or a request to sync now is not the job; use the bank-accounts skill and its sync tool.
---

# The daily bank sync (a job)

**Only with a `Job id:` line in your brief.** Without one, load the bank-accounts skill.

This job runs once a day, usually started by a schedule and unseen. Its whole work is one
tool call; the tool decides whether the operator needs to hear anything and hands that
notice to Casa itself.

The job is one turn:

1. Call `daily_sync` once, with no arguments.
2. Call `emit_completion` with `status="ok"` and, as its `text`, one line taken from the
   tool's `text` (or its error). If `emit_completion` is refused because a message has not
   reached you yet, read the message that arrives, then call `emit_completion` again. Do
   not call `daily_sync` again.

Then end the turn without writing anything. Do not retry the sync, call `sync`, start a
re-link or write to the operator: a failed sync is retried by tomorrow's run, and a bank
that needs the operator is already in the notice `daily_sync` handed to Casa.
