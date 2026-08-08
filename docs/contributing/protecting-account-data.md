# Keeping account data out of this repository

This repository is public. An account number committed here cannot be taken
back: it is in every clone and every fork the moment it is pushed. So the
protection is a guard that runs by itself, not a habit.

This file is about account data specifically. The guards that keep credentials,
addresses and private paths out — the deny sweep, the pinned secret scanner and the
push hook — are in [`publication-guards.md`](publication-guards.md).

## Install the hook — one command, once per clone

    ./scripts/setup-dev.sh

or, equivalently, the one line it exists to run:

    git config core.hooksPath .githooks

`.githooks/pre-commit` then refuses any commit that stages:

* a checksum-valid IBAN, in any ordinary rendering — grouped, wrapped across
  lines, lowercase, hyphenated, pasted with non-breaking or zero-width spaces,
  base64-encoded once, or escaped the way a source file escapes things;
* a ledger or an export — `*.sqlite`, `*.csv`, `*.ofx`, `*.qif`, `*.mt940`,
  `*.camt`, `*.xls[x]`;
* an image or PDF, because a screenshot of a bank page is not text-scannable;
* a `.env` or token file;
* any file that is not text, unless it is recorded in
  `scripts/identifier-exceptions.txt` with the reason it carries no identifier.

"Checksum-valid" is three tests, not one: the mod-97 checksum, a length that is
registered for that country, and the country's national BBAN structure. All three are
definitional rather than heuristic, and the third exists because the first two are not
enough — a run of hexadecimal spells `AD`, `AE`, `BA`, `BE`, `DE` or `EE` often enough
that about one commit object in 117 carried a checksum-valid token, and the push hook
scans commit objects. Such a token cannot be declared: a random substring of a hash has
no public source to cite in the exception file. The remedy is to amend the commit, which
changes the object and therefore the hash — cheap for unpushed work, and worth knowing
before the refusal arrives rather than after.

The structure table is generated from `scripts/iban-registry.txt`, which carries the
registry notation for each country and the BBAN of a real published example — committed
so the table can be regenerated and disagreement refused, rather than asserted once and
trusted. The example carries no country code and no check digits, because 89 whole
example IBANs would be 89 findings in the tree of the scanner that exists to find them.

The structure table **fails open per country**. A country it does not describe is
checked on length alone, exactly as before, because a wrong pattern would stop
reporting real account numbers for that country — the one error this scanner must never
make. Every entry was admitted only after its length agreed with the registered length
and a real published example for that country matched it.

It checks the **staged** bytes, not the working tree — those differ whenever
something is staged with `git add -p` or edited afterwards.

It **fails closed**: if `python3` is missing or the scan errors, the commit is
refused rather than assumed clean. A guard that waves things through when it
breaks is worse than none, because it is trusted.

## The backstop

`git commit --no-verify` skips every hook, and a clone where nobody ran the
config command has no hook at all. `.github/workflows/no-account-data.yml`
runs the same scan on the server for every push and pull request, where
neither applies, and additionally checks **every blob ever committed** — which
is what "public forever" actually means.

## If the guard stops you

* **A real identifier.** Replace it with a synthetic. The convention is `NL00`
  check digits: mod-97 can never produce `00`, so a fixture cannot silently
  become a real account.
* **A file that should not be here.** Unstage it and add it to `.gitignore`.
  Real ledgers live in the plugin's data directory, never in the repository.
* **Something genuinely public** — a published example from a specification or
  a vendor document. Add it to `scripts/identifier-exceptions.txt` with a
  citation naming that source. An entry without a citation is refused: the
  file promises every value names its source, and a promise nothing enforces
  is how an uncited value gets in.
* **A false positive.** Reword the prose. There is deliberately no "this is
  not really an account number" exemption: it would take an assertion rather
  than evidence, and any real value could be silenced by making it.

## What the guard does not do

It catches a value left in by **accident**, which is the failure this
repository actually had. It is not an adversary detector — a repository's
author is not hiding account numbers from themselves — so it does not chase
values encoded twice or escaped through several layers. `scripts/scan_identifiers.py`
states that boundary in its docstring; if you widen the scope, change the
docstring in the same commit so the next reader knows what the exit code means.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `.githooks/pre-commit`
- `scripts/scan_identifiers.py`
- `scripts/iban-registry.txt`
- `.github/workflows/no-account-data.yml`

**Tests**
- `tests/test_commit_guard.py`

**Related**
- [`doctrine/publishing.md`](../doctrine/publishing.md)
- [`contributing/publication-guards.md`](../contributing/publication-guards.md)
<!-- END SOURCEMAP -->
