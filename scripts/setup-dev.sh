#!/usr/bin/env bash
# One-time developer setup. Idempotent -- safe to re-run.
#
#     ./scripts/setup-dev.sh
#
# It installs the shared git hooks, and that is all it does. There is no virtual
# environment to build: the test suite is `unittest` from the standard library, and the
# one development dependency is pinned in requirements-dev.txt for whoever wants it. A
# setup script that also installs packages tends to be the only place a dependency is
# written down, and then nothing else knows about it.
#
# `core.hooksPath` is LOCAL git configuration. A fresh clone has no hooks until this runs,
# which is a property of git rather than a choice made here -- and it is why
# .github/workflows/ is the backstop that a local setting cannot reach.
set -euo pipefail

if ! root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "✋ setup-dev: not inside a git repository, so there is nothing to configure." >&2
  exit 1
fi
cd "$root"

echo "==> git hooks"
git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true
echo "    core.hooksPath = $(git config --get core.hooksPath)"

cat <<'DONE'

Setup complete. What now runs by itself:

  git commit    refuses staged account data (scripts/scan_identifiers.py)
                and staged denied content (scripts/deny-sweep.sh)
  git push      sweeps the tree, the introduced commits, their messages,
                the author and committer identities and the destination
                branch name, and runs the pinned secret scanner

By hand, any time:

  python3 -m unittest discover -s tests    the suite
  scripts/deny-sweep.sh tree               the deny sweep, whole tree
  scripts/run-gitleaks.sh tree             the secret scanner (needs gitleaks 8.28.0)
  python3 -m scripts.verify_docs .         the docs corpus
  python3 scripts/coverage_ledger.py check .   every code surface is claimed

Optional, for nothing but the two `scripts/` gates above:

  python3 -m pip install -r requirements-dev.txt
DONE
