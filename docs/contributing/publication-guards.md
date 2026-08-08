# The publication guards

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

A push to a public remote cannot be undone. The branch can be deleted and the commit can
be rewritten, and the object stays fetchable by its hash in every clone and fork that
already has it. So the things that must never be published are refused by a program
rather than remembered by a person.

Account data is the asset, and it has a guard of its own — see
[`protecting-account-data.md`](protecting-account-data.md). This file is about the rest:
credentials, addresses, private paths and the metadata a push carries along with its
commits.

## Install them — one command, once per clone

```
./scripts/setup-dev.sh
```

It sets `core.hooksPath` and makes the hooks executable. `core.hooksPath` is *local* git
configuration, so a fresh clone has none of this until somebody runs it, and a hook left
without its executable bit is silently not run at all. The workflows under
`.github/workflows/` are the backstop that no local setting can reach.

## What refuses, and when

| When | What runs |
|---|---|
| `git commit` | the staged account-identifier scan, then `scripts/deny-sweep.sh staged` |
| `git push` | `scripts/deny-sweep.sh` over the tree, the introduced commits, their messages and their identities; the destination branch name; `scripts/run-gitleaks.sh` over the tree and the range |
| CI | the suite, the four gates, and the secret scan at the pinned version |

`git commit --no-verify` and `git push --no-verify` skip hooks, as they skip every hook.

## The deny sweep

`scripts/deny-sweep.sh` is the one implementation of the deny-pattern grammar. Three
consumers call it, so a rule cannot mean one thing at commit time and another at push
time. `.githooks/deny-patterns.txt` is the policy, in four sections:

| Section | Meaning |
|---|---|
| `[not-swept]` | paths excluded from every content rule, each stating a reason |
| `[paths]` | file paths that may not be committed at all |
| `[content]` | value shapes that may not appear in content, messages or metadata |
| `[allow-content]` | exactly one permitted value each, exempted from `[content]` |

Run it by hand:

```
scripts/deny-sweep.sh tree                  # every tracked file at HEAD
scripts/deny-sweep.sh staged                # what is in the index right now
scripts/deny-sweep.sh range <rev>...        # content introduced by those commits
scripts/deny-sweep.sh messages <rev>...     # their commit messages
scripts/deny-sweep.sh text                  # stdin: a branch name, an identity
```

Three properties are worth knowing because they explain refusals that look odd:

- **It fails closed.** A missing, blank or malformed policy file, an invalid regular
  expression, or an exclusion with no stated reason all make it refuse to run rather
  than run with fewer rules. Exit 2 is "I did not check", which is not the same as
  exit 0.
- **An allow entry is a whole-match exemption.** It either *is* the finding or is
  irrelevant to it, so an allowed address cannot be a substring of a denied one. An
  allow rule broad enough to match an arbitrary canary is refused outright.
- **`range` mode walks every commit,** not the endpoint diff. A value added in one
  commit and deleted in the next is gone from `git diff base..HEAD` and its blob is
  published all the same.
- **A `[not-swept]` entry names a directory or one exact file, never a prefix.** A
  directory entry ends in `/`; anything else has to be an existing file, and the sweep
  refuses the policy otherwise. Without that rule `working` would also exempt
  `working-copy/` — a sibling tree nobody named and nobody reads.
- **The policy applied has to be the policy in the commit.** Every gate reads its
  pattern file, root allowlist, scanner config and exception inventory from the *working
  tree*, and what a push publishes is a *commit*. `.githooks/pre-push` refuses when those
  differ, because otherwise an inventory line added while investigating something — and
  never committed — makes a published ref carrying a private key scan clean.
- **The exclusion list has one parser.** `scripts/run-gitleaks.sh` and
  `.githooks/pre-push` both need it, and both get it from `scripts/deny-sweep.sh
  not-swept`, which prints the list only after validating it. Parsing the same file
  three times produced three answers, one of which honoured an entry the other two
  refused.
- **The hooks ignore `FINANCE_DENY_FILE`.** The override exists so the sweep's own tests
  can drive a throwaway policy; honoured at commit or push time it would let a variable
  left in a shell decide what gets published.

## The secret scanner

`scripts/run-gitleaks.sh` runs gitleaks at a pinned version, against `.gitleaks.toml`.
Two things happen before any result is believed:

1. **The version is checked.** The default ruleset and the config surface both change
   between releases, so a clean result from an unexpected build is not the result CI
   produces.
2. **Detection is demonstrated.** The wrapper scans a fixture it knows should fire and
   refuses if it does not. An ineffective config reports zero findings, which is
   indistinguishable from a clean tree.

Accepted findings are declared in `.githooks/gitleaks-allow-sites.txt`, one line per
`<path> <rule-id> <count>`, with the reason in prose above each group. The check runs in
both directions: a finding nobody declared fails, and a declared line that matches
nothing fails as a stale entry — so a fix leaves a line that complains rather than one
that silently covers whatever appears at that path next.

The inline `gitleaks` allow-marker is **not** a channel here. The scanner honours it
natively, which would let a real credential plus a comment produce a clean scan with no
record of what was silenced, so the deny sweep refuses that marker wherever it appears.

There is no baseline file. Stored verbatim it carries the findings and trips the scan
itself; stored redacted it suppresses nothing.

The scanner's own suppression channels are refused outright — an `[[allowlists]]` table
in `.gitleaks.toml`, a `.gitleaksignore`, a baseline. Each of them empties the inventory
of meaning: a finding suppressed inside the scanner is never reported, so nothing is ever
declared for it and the scan passes with no record of what was hidden.

A git symlink is restored as a symlink by `git archive`, and the scanner does not read
its target — so a credential stored *as a link target* scanned clean. Symlink targets are
materialised as text before scanning.

In `tree` mode the config and the inventory are read from the **revision being scanned**,
not from the checkout, because the answer is about that commit.

## The push hook

`.githooks/pre-push` refuses more than file content, because a push publishes more than
files:

- **Only `refs/heads/*`.** A tag publishes an annotation, a tagger identity and a name,
  none of them a commit and none covered by any sweep here.
- **The destination branch name**, checked before any commit enumeration. Pushing
  already-published objects under a new name introduces no commits at all, so a check
  placed after the enumeration never runs for the one case it exists for.
- **The introduced set, relative to the destination.** It asks that remote what it has,
  rather than reading this clone's tracking refs — repoint a remote at a fresh
  repository and a stale `refs/remotes/…` makes whole ancestries look published.
- **Commit messages, and author and committer identities.** An empty commit changes no
  file and publishes all three.
- **Tree-entry names, as data.** A filename is published text, and every other check
  treats a path as a path — so an account number written as a *filename* went out
  unexamined until this was added.
- **The raw commit objects.** Those two are renderings; a commit carries more than they
  show — `gpgsig`, `mergetag`, `encoding` — and whatever is in the object is published.
  Every introduced object goes through the sweep, the account-identifier scan, and the
  secret scanner — the last via `run-gitleaks.sh dir`, because `gitleaks git` examines
  patch content and never sees a message or a header.
- **Account data, in the published tree and in every blob the introduced commits
  carry.** The commit hook sees only the index, and CI sees the objects only after they
  have reached the remote — by which time publication is irreversible. A range imported
  from elsewhere, or committed with `--no-verify`, has never met the commit hook at all.
- **The tree of the ref being published**, which need not be the checked-out `HEAD`:
  `git push payload:published` publishes a tree the checkout may know nothing about, and
  when the destination already holds those objects it introduces no commits either.

There is no override: `git push --no-verify` is already the door, and a second one would
be a branch in the hook that nothing forces anyone to explain.

## What a push publishes, and what reads it

Most defects found in these guards were not wrong logic. They were a surface nobody had
thought to examine — a filename read as a path but never as data, a symlink target, a
commit header that no rendering shows. So the surface is enumerated here rather than
rediscovered. If you add a check, add its row; if you find a row that is wrong, that is a
defect in the guards, not in the table.

| What a push transfers | Read by |
|---|---|
| Blob contents (regular files) | the sweep, the secret scanner, the account-identifier scan |
| Symlink targets | the same three; `run-gitleaks.sh` materialises the target as text first |
| Binary blobs | refused unless named in `.githooks/binary-allowlist.txt` — nothing can read them |
| Tree-entry names, including directory names | the sweep, the secret scanner, the identifier scan |
| Tree-entry modes | a gitlink (`160000`) is refused outright; the remaining modes are a fixed set |
| Commit messages | the sweep, the secret scanner, the identifier scan |
| Author and committer identities | the sweep, and the raw-object passes below |
| Every other commit header (`encoding`, `gpgsig`, `mergetag`, unknown round-tripped ones) | the raw commit object goes through all three |
| Destination branch name | the sweep, before any commit enumeration |
| A deleted ref's name | the sweep — it reaches the server's event log even though no object does |
| Tag objects and non-branch refs | **refused**, not scanned: nothing here reads a tag object |
| Pack encoding: deltas, framing, checksums, object counts | nothing — git generates these from objects already read |
| Protocol extras: capabilities, push options, signed-push certificates, shallow lines | nothing — none are sent by an ordinary `git push`, and a certificate's contents are the identity and refs already checked |

The last two rows are the honest ones. They are unread, they are listed anyway, and the
reason they are acceptable is that their bytes are generated from content the rows above
have already been through — not that nobody looked.

## The exception lists are judgement

`.githooks/gitleaks-allow-sites.txt`, and the `[not-swept]` and `[allow-content]`
sections of `.githooks/deny-patterns.txt`, are claims someone made. No program checks
whether a reason is honest — only a reader can. That is why every entry has to carry
one, why the sweep announces its exclusions on every run, and why
[`../doctrine/publishing.md`](../doctrine/publishing.md) counts reading them as a
named human gate rather than a machine one.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `scripts/deny-sweep.sh`
- `scripts/run-gitleaks.sh`
- `scripts/setup-dev.sh`
- `.githooks/pre-push`
- `.githooks/deny-patterns.txt`
- `.githooks/gitleaks-allow-sites.txt`
- `.gitleaks.toml`

**Tests**
- `tests/test_deny_sweep.py`
- `tests/test_run_gitleaks.py`
- `tests/test_pre_push.py`
- `tests/test_setup_dev.py`

**Related**
- [`contributing/protecting-account-data.md`](../contributing/protecting-account-data.md)
- [`doctrine/publishing.md`](../doctrine/publishing.md)
<!-- END SOURCEMAP -->
