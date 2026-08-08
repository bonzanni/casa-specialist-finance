# Working in this repository

A casa specialist component: a role, a persona, and two bundled plugins. `README.md`
says what it does; this file says how to change it without breaking the things that
cannot be un-broken.

## First

```bash
./scripts/setup-dev.sh
```

It installs the git hooks. `core.hooksPath` is local git configuration, so a fresh
clone has no hooks until this runs.

## The one rule

**A fact belongs in this repository only if it is verifiable from the public commit
alone.** No account numbers, no personal data, no private development history. This is
not a style preference — those values are unrecoverable once published, and the
repository is public. `docs/doctrine/publishing.md` is the long form.

## What refuses, and when

| When | What runs | What it refuses |
|---|---|---|
| `git commit` | `.githooks/pre-commit` | a staged account identifier; a staged address, assigned token literal, private path, root-level stray, unscannable binary, or scanner allow-marker |
| `git push` | `.githooks/pre-push` | the same over the tree, over every commit the destination does not already have, and over those commits' messages and identities; the destination branch name; anything the pinned secret scanner reports and the inventory does not declare |
| CI | `.github/workflows/` | the suite, the four gates, the secret scan, and an account identifier anywhere in history |

`git commit --no-verify` and `git push --no-verify` skip the hooks, as they skip every
hook. CI is the backstop a local flag cannot reach.

## Running things

```bash
python3 -m unittest discover -s tests          # the suite; no third-party packages
python3 scripts/scan_identifiers.py .          # no account identifier in the tree
python3 scripts/scan_lineage.py .              # no private development history
scripts/deny-sweep.sh tree                     # the deny sweep over the whole tree
scripts/run-gitleaks.sh tree                   # the secret scanner (gitleaks 8.28.0)
python3 -m scripts.verify_docs .               # the docs corpus
python3 scripts/coverage_ledger.py check .     # every code surface is claimed
```

The two `scripts/` gates need PyYAML, pinned in `requirements-dev.txt`. Nothing under
`plugins/` may use a third-party package: the committed plugin tree has to stay
byte-identical to the installed artifact, so casa's install-time provisioning stays a
no-op.

## Constraints worth knowing before you edit

- **`plugins/` is Python 3.11, standard library only.** CI runs 3.11 for the same reason.
- **Pinned digests.** Any change under `plugins/`, `persona/`, `role/` or
  `config-schema.json` invalidates the digests in `manifest.json` and
  `persona/manifest.json`. Recompute them **last**, after the content is final;
  `tests/test_component.py` is what checks them and holds the algorithms.
- **The docs corpus is checked, not just written.** Every file under `docs/` is
  allowlisted in `docs/manifest.yaml`, every anchor has to resolve, and a backticked
  symbol that does not exist in the tree is an error. After editing a document or the
  manifest: `python3 -m scripts.verify_docs . --write-nav`, then `git add`, then run it
  again bare. `docs/contributing/doc-contract.md` is the contract.
- **Every file under `scripts/` needs a `docs/coverage.yaml` entry** naming a document
  that actually describes it. Adding a script without one turns the ledger red.
- **Exception lists are judgement.** `scripts/identifier-exceptions.txt`,
  `scripts/lineage-exceptions.txt`, the `[not-swept]` and `[allow-content]` sections of
  `.githooks/deny-patterns.txt`, and `.githooks/gitleaks-allow-sites.txt` are claims
  someone made. Only a reader can check them. Add an entry deliberately, with the
  reason, or fix the thing instead.
