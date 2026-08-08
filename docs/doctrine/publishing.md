# Publishing

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

This repository is public. Everything in it — source, comments, tests, documents,
commit messages — is readable by someone who has this commit and nothing else: no
operator to ask, no production install to inspect, no private repository to open.
That reader is who the rules below are written for.

## The rules

**INV-PUB-001**: a fact belongs in this repository only if it is verifiable from the public commit alone.

**INV-PUB-002**: doctrine states the mechanism, never the incident.

**INV-PUB-003**: when a claim cannot be checked from the commit, stop and ask — do not guess, and do not paraphrase around it.

## What each one refuses

**INV-PUB-001** refuses a fact that only exists somewhere else. An account number, a
vault's current contents, a local file path, a measurement from one installation's
database, a link into a repository the reader cannot open — each reads as
information and carries none, because nothing here substantiates it. The rule also
applies to links: a document citing an issue is only honest if the issue is
reachable from the same place the document is.

Two gates enforce the shapes of it that a machine can see. `scan_identifiers.py`
extracts every account-number-shaped token from the tracked tree and computes its
checksum, so a value that could be someone's real account fails the build unless it
is checksum-invalid or carries a committed citation naming a public source.
`verify_docs.py` refuses a documentation anchor that git does not track, a link that
leaves the published tree, and prose naming code that does not exist.

**INV-PUB-002** refuses the story of how the code got here. The reason a rule exists
is a fact about the code and stays; who asked for it, in which review round, at what
severity, citing which unpublished document, is a fact about a process the reader
cannot see. `scan_lineage.py` commits the patterns — the names of people who reviewed
a change, round numbers,
severity labels, task and slice numbers, decision codes, private section references —
and fails on any hit outside a committed exception list that states, per site, why
the site is not lineage.

**INV-PUB-003** is the one no gate can enforce. It says what to do at the moment of
writing a sentence you cannot check: stop. Not soften it, not restate it at a safe
altitude, not attach a hedge — ask, or leave it out. Both times this repository's own
design document broke the rule it did so by restating a number nobody re-derived,
which is why the corpus generates every index it can rather than maintaining one by
hand.

## How this applies to somebody else's software

This component talks to casa, to Enable Banking and to a password manager, and
none of them is in this commit. Read literally, INV-PUB-001 would forbid saying
anything about them at all — which would leave the corpus unable to describe the
integration that is most of what the code does.

The rule that resolves it: **an external behaviour may be written down as an
assumption this code is built on, together with what the code does when the
assumption is false. It may not be written down as a verified observation.**

The difference is not a hedge, and labelling does not bridge it — INV-PUB-003
says so. "Deep history stops being available minutes after authentication" is a
claim about a service, and no reader of this commit can check it. "The backfill
runs immediately and synchronously because it assumes that window closes within
minutes; if the assumption is wrong the cost is a redundant early fetch, and if
it is right, deferring would silently lose history" is a claim about **this
code**, it is checkable here, and it is the one a maintainer can act on.

So provider facts appear as premises with consequences, never as findings. The
one place a copy of somebody else's constant is kept — `reference/casa-compatibility.md` —
says plainly that it is a copy, and the `$CASA_ROOT` arm of the suite is what
makes it checkable against the real thing when a checkout is available.

## What is deliberately not excluded

Authorship. The author's name, the MIT copyright line, and the GitHub no-reply commit
address are verifiable from the public commit and stay. No personal email address
appears anywhere.

Versions of the software this component is built against. `casa`'s version is a real
compatibility fact; where a constant is copied out of casa, the published contract in
`reference/casa-compatibility.md` carries the version and the module it came from.

## What is not enforced, and what that costs

Stating this plainly is INV-PUB-003 applied to this file.

- **No attestation.** Nothing records that a human read the range of commits being
  pushed. `.githooks/pre-push` sweeps that range mechanically — its content, its commit
  messages, its author and committer identities, and the destination branch name — but
  no receipt binds a reading of it to the commits that go out. The gates check shapes;
  they do not check judgement.
- **A confidential paragraph containing no secret passes every check.** The scanners
  match value shapes and lineage shapes, not confidentiality.
- **An exact private literal is caught only if a generic pattern happens to match
  it.** There is no exact-literal supplement.
- **A hook is only as trustworthy as the environment it runs in.** `.githooks/pre-commit`
  and `.githooks/pre-push` invoke `python3`, `git` and `gitleaks` by name, so whatever is
  earliest on `PATH` is what checks the commit; and `BASH_ENV` names a file the shell
  sources *before the hook's first line*, which can end the hook before any check runs.
  Neither is closed here, and both were measured rather than assumed:

  - Pinning an absolute `PATH` inside the hooks refuses every push on a machine where the
    pinned scanner is installed under a user-local prefix — which is where it normally is.
    Refusing a legitimate push is the failure these guards are least allowed to have.
  - `unset BASH_ENV` *inside* a hook does nothing for that hook: the file is already
    sourced by the time the line runs. A startup file containing `exit 0` ends the hook
    with a success status either way. Adding the line would have been a defence that does
    not defend, which is worse than none, because it reads like one.

  An environment that hostile can run `git push --no-verify` instead, so this is not the
  boundary these hooks are for. They are local controls in a local environment; the
  workflows under `.github/workflows/` are the backstop no local environment reaches.
- **A pathname git has to quote is refused rather than parsed.** Git renders a name
  containing a double quote or a control character in its C-quoted form, and the path
  lists here are line-oriented, so such a name is refused with a request to rename it.
  For a control character that is the intended answer — the quoting defeats anchored path
  rules. For a legal name that merely contains a quote it is a false refusal, accepted
  because making every path consumer NUL-safe is a larger change than the risk warrants,
  and because the failure is a refusal with an obvious remedy rather than a pass.
- **The exception lists are judgement, not computation.** Every entry in
  `scripts/identifier-exceptions.txt`, `scripts/lineage-exceptions.txt`,
  `.githooks/gitleaks-allow-sites.txt`, and the `[not-swept]` and `[allow-content]`
  sections of `.githooks/deny-patterns.txt` is a claim someone made, and only a reader
  can check it. The programs check the *shape* of an entry — that it names a reason,
  that it is not broad enough to exempt anything, that it still matches something — and
  none of them can check whether the reason is true.

In a single-committer repository these are a deliberate trade: the alternative is
ceremony that one person performs on themselves. They are written down so the trade
is visible rather than assumed, and so that the first additional committer is a
reason to revisit it.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `scripts/scan_identifiers.py`
- `scripts/scan_lineage.py`
- `scripts/verify_docs.py`
- `.githooks/pre-commit`

**Tests**
- `tests/test_scan_identifiers.py`
- `tests/test_scan_lineage.py`
- `tests/test_commit_guard.py`
- `tests/test_verify_docs.py`

**Related**
- [`contributing/doc-contract.md`](../contributing/doc-contract.md)
<!-- END SOURCEMAP -->
