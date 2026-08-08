#!/usr/bin/env bash
# Pinned secret scanner. One invocation, one exit status -- never a `||` fallback, which
# cannot tell "unsupported subcommand" from "leak found" or "invalid config".
#
#   scripts/run-gitleaks.sh tree [<rev>]      scan a checkout of <rev> (default HEAD)
#   scripts/run-gitleaks.sh range <git-range> scan the history a push would publish
#   scripts/run-gitleaks.sh dir <path>        scan a prepared directory of published text
#
# `dir` exists because a push publishes more than file contents. Commit messages, extra
# commit headers, identities and tree-entry NAMES are all published, and `gitleaks git`
# examines patch content only -- so a credential in any of them reached no secret scan at
# all. The caller materialises those bytes and points this at them.
#
# `tree` scans a `git archive` of HEAD rather than the working directory: `gitleaks dir .`
# also reads ignored local material, none of which is published, and which makes the
# result machine-dependent.
#
# ACCEPTED FINDINGS are declared in .githooks/gitleaks-allow-sites.txt, one line per
# (path, rule, count), and subtracted here. The inline `gitleaks` allow-marker is NOT a
# channel in this repository -- scripts/deny-sweep.sh refuses it wherever it appears --
# because it silences the scanner with no record of what it silenced.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

REQUIRED="8.28.0"
mode="${1:-tree}"
range="${2:-}"
# `tree` takes an optional revision, for the same reason the deny sweep does: a push
# publishes a NAMED ref, which need not be the checked-out HEAD.
tree_rev="${2:-HEAD}"
config="$PWD/.gitleaks.toml"
inventory=".githooks/gitleaks-allow-sites.txt"
work="$(mktemp -d)"
trap 'rm -rf "$work" "${export_dir:-}"' EXIT

case "$mode" in
  dir)
    [ -n "${2:-}" ] && [ -d "$2" ] || {
      echo "✋ run-gitleaks.sh dir needs a directory" >&2; exit 2; }
    scan_dir="$2"; tree_rev="HEAD" ;;
  tree) git rev-parse --verify -q "$tree_rev^{commit}" >/dev/null 2>&1 || {
          echo "✋ run-gitleaks.sh: tree mode was given '$tree_rev', not a commit" >&2
          exit 2; } ;;
  range)
    [ -n "$range" ] || { echo "✋ run-gitleaks.sh range needs a git range" >&2; exit 2; }
    # An unresolvable range made the scanner walk nothing and report a clean history --
    # the same answer a genuinely clean range gives. The sweep refuses this; so does this.
    git rev-list $range >/dev/null 2>&1 || {
      echo "✋ run-gitleaks.sh: '$range' is not a resolvable revision range, so nothing" >&2
      echo "        was scanned. Refusing rather than returning the answer a clean" >&2
      echo "        range would give." >&2
      exit 2; } ;;
  *) echo "✋ run-gitleaks.sh: unknown mode '$mode' (expected tree|range|dir)" >&2; exit 2 ;;
esac

# In `tree` mode the config and the inventory come from the REVISION being scanned, not
# from the checkout. This program answers a question about a commit, and an uncommitted
# inventory line changed that answer from refusal to success. `range` mode has no single
# revision to read them from and uses the checkout, which is stated where it matters.
if [ "$mode" = "tree" ] || [ "$mode" = "dir" ]; then
  for from_rev in ".gitleaks.toml" "$inventory"; do
    if ! git cat-file -e "$tree_rev:$from_rev" 2>/dev/null; then
      echo "✋ run-gitleaks.sh: $tree_rev does not contain $from_rev, so the scan would" >&2
      echo "        apply a policy that commit does not carry. Refusing." >&2
      exit 2
    fi
    git show "$tree_rev:$from_rev" > "$work/$(basename "$from_rev")"
  done
  config="$work/.gitleaks.toml"
  inventory="$work/$(basename "$inventory")"
fi

if [ ! -r "$inventory" ]; then
  echo "✋ run-gitleaks.sh: $inventory is missing or unreadable -- refusing to run." >&2
  echo "        Without it every accepted finding reads as a new one, and the usual fix" >&2
  echo "        for that is to stop running the scanner." >&2
  exit 2
fi

# The scanner has suppression channels of its own, and every one of them empties this
# program's exception inventory of meaning: a finding suppressed inside gitleaks is never
# reported, so nothing is ever declared for it and the scan passes. The inventory is the
# only exception mechanism here, so the others are refused rather than trusted.
#
# PARSED, not pattern-matched. A textual check for `[[allowlists]]` missed the quoted,
# dotted and inline-table spellings TOML also accepts, and the scanner honours those.
python3 - "$config" <<'TOML' || exit 2
import sys, tomllib

with open(sys.argv[1], "rb") as handle:
    try:
        config = tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        print(f"\u270b run-gitleaks.sh: {sys.argv[1]} is not valid TOML: {error}",
              file=sys.stderr)
        sys.exit(2)

BANNED = {"allowlist", "allowlists"}


def walk(node, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in BANNED:
                print(f"\u270b run-gitleaks.sh: {sys.argv[1]} declares "
                      f"{path}{key} -- a scanner-native allowlist. A finding suppressed "
                      "inside the scanner is never reported, so nothing is ever declared "
                      "for it and this scan passes with no record of what was hidden.",
                      file=sys.stderr)
                sys.exit(2)
            walk(value, f"{path}{key}.")
    elif isinstance(node, list):
        for item in node:
            walk(item, path)


walk(config)
TOML

# In tree mode only the REVISION decides: an untracked local .gitleaksignore does not
# exist in the exported revision, and refusing on it would block legitimate work.
for suppressor in .gitleaksignore .gitleaksbaseline; do
  if [ "$mode" = "tree" ]; then
    git cat-file -e "$tree_rev:$suppressor" 2>/dev/null || continue
  else
    [ -e "$suppressor" ] || continue
  fi
  echo "✋ run-gitleaks.sh: $suppressor exists. It silences findings before this" >&2
  echo "        program can see them, which makes the declared inventory meaningless." >&2
  exit 2
done

have="$(gitleaks version 2>/dev/null | tr -d 'v[:space:]')" || {
  echo "✋ gitleaks is not installed. Install $REQUIRED -- the gate does not run without it." >&2
  exit 1
}
if [ "$have" != "$REQUIRED" ]; then
  echo "✋ gitleaks $have installed, $REQUIRED pinned. The config surface and the default" >&2
  echo "        ruleset both change between versions; a scan with an unexpected build is" >&2
  echo "        not the scan CI runs, and its clean result means less." >&2
  exit 1
fi

# An ineffective config reports zero findings, which is indistinguishable from a clean
# tree. Prove detection works before trusting a clean result. This is the repository's
# doctrine on third-party facts as code: what the scanner detects is an assumption, and
# this is what happens when the assumption is false.
#
# The fixture was chosen by EXPERIMENT against this exact version: the canonical AWS
# secret-key example does NOT fire under the 8.28.0 default ruleset, and a wrapper built
# on it would have failed closed on every invocation.
probe="$work/probe"; mkdir -p "$probe"
report="$work/report"
probe_tok="xoxb-"                       # split so this tracked file holds no whole token
probe_tok="${probe_tok}123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
printf 'slack_token = "%s"\n' "$probe_tok" > "$probe/probe.txt"
set +e
gitleaks dir "$probe" --config "$config" --no-banner --exit-code 9 >/dev/null 2>&1
probe_status=$?
set -e
if [ "$probe_status" -ne 9 ]; then
  echo "✋ gitleaks probe returned $probe_status, expected 9. Either the config is not" >&2
  echo "        effective or the fixture no longer matches a default rule. Both are fatal:" >&2
  echo "        a clean scan proves nothing unless detection is demonstrated first." >&2
  exit 1
fi

# `--exit-code 0` so that FINDINGS are not an error here: the report is the output, and
# the inventory below decides. A non-zero status now means the scanner itself failed --
# a bad config, an unreadable path -- and that is fatal rather than clean.
# `--redact` so the report on disk never carries a secret; the filter needs only the path
# and the rule.
if [ "$mode" = "dir" ]; then
  ( cd "$scan_dir" && gitleaks dir . --config "$config" --redact --no-banner \
      --exit-code 0 --report-format json --report-path "$report" )
elif [ "$mode" = "range" ]; then
  # -m for the same reason the deny sweep needs it: git emits no patch for a merge by
  # default, so a value created by conflict resolution and removed later is invisible.
  gitleaks git . --config "$config" --redact --no-banner --exit-code 0 \
    --report-format json --report-path "$report" --log-opts="-m $range"
else
  root="$PWD"
  export_dir="$work/export"; mkdir -p "$export_dir"
  git archive --format=tar "$tree_rev" | tar -x -C "$export_dir"
  # A git symlink is restored as a symlink and `gitleaks dir` does not read its target,
  # so a credential stored AS a link target received a clean scan. The target is text
  # that the commit publishes, so it is materialised as text.
  find "$export_dir" -type l -print0 | while IFS= read -r -d "" link; do
    target="$(readlink "$link")"
    rm -f "$link"
    printf '%s\n' "$target" > "$link"
  done
  # Scan from INSIDE the export root so reported paths are repo-relative.
  ( cd "$export_dir" && gitleaks dir . --config "$config" --redact --no-banner \
      --exit-code 0 --report-format json --report-path "$report" )
fi

# The declared exclusions come from the ONE implementation of the grammar, already
# validated by it -- not from a second parse here. Two parsers of one policy file
# disagreed about whether it was valid at all: the sweep refused an entry naming a file
# that no longer exists, and this script accepted the same entry and reported a tree
# carrying a live token as clean. This has been demonstrated against this code.
# In `range` mode $2 is the range, not a revision, so the exclusions are validated
# against HEAD there. In `tree` mode they are validated against the revision being
# scanned, which is the artifact the answer is about.
policy_rev="HEAD"
[ "$mode" = "tree" ] && policy_rev="$tree_rev"
if ! not_swept="$(scripts/deny-sweep.sh not-swept "$policy_rev" 2>/dev/null)"; then
  echo "✋ run-gitleaks.sh: the deny sweep refused the policy, so the declared" >&2
  echo "        exclusions could not be read. Refusing rather than scanning with an" >&2
  echo "        exclusion list nothing validated." >&2
  exit 2
fi

# Via a file, not a pipe: the heredoc below already owns this process's stdin.
not_swept_file="$work/not-swept"
printf '%s\n' "$not_swept" > "$not_swept_file"

python3 - "$report" "$inventory" "$mode" "$not_swept_file" <<'PY'
"""Subtract the declared inventory from the scanner's report.

Two directions, both failing:
  * a finding no line declares  -- something new, and nobody has looked at it;
  * a line no finding matches   -- a stale exemption, left behind by a fix, which would
    otherwise sit there silently covering whatever appears at that path next.

The COUNT is pinned in `tree` mode only. In `range` mode an accepted finding recurs once
per commit that touches its file, so the count there is a property of the history rather
than of the file, and the line is a membership test instead. Said plainly rather than
quietly applied, because a count that means two things is worse than one that means one.
"""
import collections
import json
import pathlib
import sys

report_path, inventory_path, mode, not_swept_path = sys.argv[1:5]

# The declared exclusions, as `deny-sweep.sh not-swept` printed them, which has
# already validated them. One list, one parser, one set of semantics: a directory entry
# ends in `/` and covers what is beneath it, and anything else names one exact path.
excluded = []
for line in pathlib.Path(not_swept_path).read_text().splitlines():
    # Never `.strip()`. The sweep refuses an entry with surrounding whitespace, so a
    # path arriving here is exact -- and trimming it anyway would reintroduce the
    # disagreement that rejection exists to prevent.
    if not line or " -- " not in line:
        continue
    path, reason = line.split(" -- ", 1)
    excluded.append(path)
    print(f"not scanned: {path} -- {reason}", file=sys.stderr)


def is_excluded(name):
    return any(name.startswith(p) if p.endswith("/") else name == p for p in excluded)

raw = pathlib.Path(report_path).read_text().strip()
findings = [f for f in (json.loads(raw) if raw else [])
            if not is_excluded(f.get("File", ""))]
seen = collections.Counter(
    (f.get("File", ""), f.get("RuleID", "")) for f in findings)

declared, problems = {}, []
for lineno, line in enumerate(pathlib.Path(inventory_path).read_text().splitlines(), 1):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    # From the RIGHT. A pathname may contain spaces -- git allows it and the sweep only
    # refuses control characters -- so splitting from the left made a legal accepted
    # finding impossible to declare, and the push stayed refused with no way forward.
    parts = line.rsplit(None, 2)
    if len(parts) != 3 or not parts[2].isdigit():
        problems.append(f"{inventory_path}:{lineno}: not '<path> <rule-id> <count>': {line}")
        continue
    path, rule, count = parts[0], parts[1], int(parts[2])
    if (path, rule) in declared:
        problems.append(f"{inventory_path}:{lineno}: {path} {rule} declared twice")
    declared[(path, rule)] = count

for key, actual in sorted(seen.items()):
    path, rule = key
    if key not in declared:
        problems.append(f"undeclared finding: {path}  rule={rule}  n={actual}")
    elif mode == "tree" and declared[key] != actual:
        problems.append(
            f"count moved: {path}  rule={rule}  declared={declared[key]}  found={actual}")

# Stale entries are `tree` mode only, for the same reason the count is. A history scan
# reports findings only from files the range touches, so in `range` mode every declared
# line for an untouched file matches nothing -- and treating that as stale made
# .githooks/pre-push refuse EVERY push, which is how this was found: by running it.
if mode == "tree":
    for key in sorted(declared):
        if key not in seen:
            path, rule = key
            problems.append(
                f"stale entry: {path}  rule={rule}  matches nothing -- delete the line")

if problems:
    print("✋ secret scanner:", file=sys.stderr)
    for problem in problems:
        print(f"   {problem}", file=sys.stderr)
    print("   A new finding is fixed, or declared in the inventory with the reason it is",
          file=sys.stderr)
    print("   not a credential of ours. Nothing else silences this scan.", file=sys.stderr)
    sys.exit(1)

print(f"✓ secret scan clean ({len(findings)} finding(s), all declared)")
PY
