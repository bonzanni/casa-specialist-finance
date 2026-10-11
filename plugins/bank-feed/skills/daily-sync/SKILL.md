---
name: daily-sync
description: The "Bank sync" job's procedure (bank-feed:daily-sync), for the finance specialist — only for a turn whose brief says it is the background job "Bank sync" and carries a `Job id:` line. A question about the banks or a request to sync now is not the job; use the bank-accounts skill and its sync tool.
---

# The daily bank sync (a job)

**Only with a `Job id:` line in your brief.** Without one, load the bank-accounts skill.

This job runs once a day, usually started by a schedule and unseen. Its whole work is one
tool call; the tool decides whether the operator needs to hear anything and hands that
notice to Casa itself.

On the launch turn, acknowledge in one line and do nothing else.

On a batch turn:

1. Call `daily_sync` once, with no arguments.
2. Call `report_job_progress` with a one-line summary taken from the tool's `text`
   (or its error) and `progressed=true`.
3. Call `emit_completion` with `status="ok"` and that same line as its `text`.

Then end the turn without writing anything. Do not retry the sync, call `sync`, start a
re-link or write to the operator: a failed sync is retried by tomorrow's run, and a bank
that needs the operator is already in the notice `daily_sync` handed to Casa.
