#!/usr/bin/env bash
# The one implementation of the deny-pattern grammar. The pre-commit hook, the pre-push
# hook and CI all go through this file, so that a rule cannot mean one thing at commit
# time and another at push time.
#
#   scripts/deny-sweep.sh staged            (pre-commit: added lines in the index)
#   scripts/deny-sweep.sh tree [<rev>]      (whole tree at <rev>, default HEAD)
#   scripts/deny-sweep.sh range <rev>...    (content introduced by every commit named)
#   scripts/deny-sweep.sh messages <rev>...  (commit messages -- they are published too)
#   scripts/deny-sweep.sh text              (stdin, content rules only)
#   scripts/deny-sweep.sh not-swept [<rev>] (print the declared exclusions, one per line)
#
# `text` exists because a push publishes more than commits: the destination branch name
# and the author and committer identities are published text that no other mode covers.
#
# It operates on the repository containing the CURRENT DIRECTORY, not the one containing
# this script: the tests drive it against a throwaway repository, and a `cd` to the
# script's own root would silently scan this project instead.
#
# Exit 0 clean, 1 finding, 2 refusing to run.
#
# FINANCE_DENY_FILE   override the pattern file (tests)
# FINANCE_SWEEP_LIB=1 source instead of run: defines the pattern arrays, scans nothing
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

mode="${1:-tree}"
# The revision arguments are taken as a LIST, not one string: a destination-relative
# enumeration is `<tip> --not <advertised>...`, which cannot be passed as a single
# `A..B` token, and quoting it as one would make git read it as a bad revision.
shift || true
range_args=("$@")
# `tree` takes an optional revision. The push hook needs it: it publishes a NAMED ref,
# which is not necessarily the checked-out HEAD -- `git push payload:published` scans the
# wrong tree entirely if this is hard-coded.
tree_rev="${1:-HEAD}"
deny_file="${FINANCE_DENY_FILE:-.githooks/deny-patterns.txt}"
# In `tree` and `not-swept` mode the policy comes from the REVISION being assessed, not
# from the checkout. `tree <rev>` answers a question about a commit, and reading the
# working-tree policy meant an uncommitted edit changed that answer -- the same defect
# already fixed in the scanner's config and inventory. FINANCE_DENY_FILE still wins, so
# the sweep can be driven against a policy that is not in any repository, which is how
# its own tests work.
policy_from_rev=""

if [ "$mode" = "tree" ] || [ "$mode" = "not-swept" ]; then
  git rev-parse --verify -q "$tree_rev^{commit}" >/dev/null 2>&1 || {
    echo "✋ deny-sweep: $mode was given '$tree_rev', which is not a commit." >&2
    exit 2; }
  if [ -z "${FINANCE_DENY_FILE:-}" ]; then
    policy_from_rev="$(mktemp -d)"
    trap 'rm -rf "$policy_from_rev"' EXIT
    for from_rev in .githooks/deny-patterns.txt .githooks/root-allowlist.txt \
                    .githooks/binary-allowlist.txt; do
      git cat-file -e "$tree_rev:$from_rev" 2>/dev/null || continue
      mkdir -p "$policy_from_rev/$(dirname "$from_rev")"
      git show "$tree_rev:$from_rev" > "$policy_from_rev/$from_rev"
    done
    if [ -f "$policy_from_rev/.githooks/deny-patterns.txt" ]; then
      deny_file="$policy_from_rev/.githooks/deny-patterns.txt"
    else
      echo "✋ deny-sweep: $tree_rev does not contain .githooks/deny-patterns.txt, so" >&2
      echo "        the scan would apply a policy that commit does not carry." >&2
      exit 2
    fi
  fi
fi
# Exclude whichever pattern file is actually in use, not just the canonical path: an
# override pointing at a file inside the repository would otherwise be swept and match its
# own rules. Resolved repo-relative; an override outside the repository excludes nothing,
# which is correct.
deny_rel="$(realpath --relative-base="$PWD" -- "$deny_file" 2>/dev/null || echo "$deny_file")"
case "$deny_rel" in /*) deny_rel=".githooks/deny-patterns.txt" ;; esac

path_pats=(); allow_pats=(); content_pats=(); not_swept=(); not_swept_why=()
read_patterns() {
  local file="$1" section="" line
  # Fail CLOSED. An unreadable policy file used to load zero rules and exit 0, so a commit
  # that deleted the pattern file disabled its own guard -- and in staged mode a deletion
  # is not even in --diff-filter=ACMR, so nothing else would have noticed.
  if [ -z "$file" ] || [ ! -r "$file" ]; then
    echo "✋ deny-sweep: pattern file ${file:-<unset>} is missing or unreadable -- refusing" >&2
    echo "        to run with no policy. This is the guard failing closed, as designed." >&2
    exit 2
  fi
  while IFS= read -r line; do
    case "$line" in
      ""|\#*) continue ;;
      "[paths]")         section=paths;     continue ;;
      "[content]")       section=content;   continue ;;
      "[allow-content]") section=allow;     continue ;;
      "[not-swept]")     section=notswept;  continue ;;
    esac
    case "$section" in
      paths)   path_pats+=("$line") ;;
      allow)   allow_pats+=("$line") ;;
      content) content_pats+=("$line") ;;
      notswept)
        # `<path> -- <reason>`. A path with no stated reason is refused: an undocumented
        # exclusion is indistinguishable from a hiding place, and the reason is the only
        # part of it a reader can check.
        case "$line" in
          *" -- "*)
            entry="${line%% -- *}"
            # No surrounding whitespace. One consumer trimmed and another did not, so
            # ` docs/leak` validated here and became `docs/leak` in the scanner -- a
            # different exclusion, which suppressed a detected credential. The entry is
            # rejected rather than trimmed, so there is exactly one spelling of it.
            case "$entry" in
              *[[:space:]]) ;;&               [[:space:]]*|*[[:space:]])
                echo "✋ deny-sweep: [not-swept] entry '$entry' has leading or trailing" >&2
                echo "        whitespace. Trimming it in one consumer and not another" >&2
                echo "        makes the same line mean two different paths." >&2
                exit 2 ;;
            esac
            # CANONICAL, or the consumers disagree. Git normalises `./working/` for a
            # literal pathspec and excludes what is beneath it; the scanner's filter and
            # the push hook's blob filter compare the string as written and do not. The
            # set of files actually checked then depends on which program is asking.
            case "$entry" in
              ""|/*|./*|../*|*/./*|*/../*|*//*|*/.|*/..)
                echo "✋ deny-sweep: [not-swept] entry '$entry' is not a canonical" >&2
                echo "        repo-relative path. Leading './' or '/', doubled slashes," >&2
                echo "        and '.' or '..' components are normalised by git and not" >&2
                echo "        by the filters beside it, so the same entry would exclude" >&2
                echo "        different files in different checks." >&2
                exit 2 ;;
            esac
            # A directory entry MUST end in `/`. Without it the exclusion is a bare
            # string prefix, so `working` also exempts `working-copy/` -- a sibling tree
            # nobody named and nobody reads. A file entry has no trailing slash and
            # matches that exact path and nothing else.
            case "$entry" in
              */) ;;
              # Existence is checked below, against the artifact being assessed rather
              # than against whatever is checked out.
              *) ;;
            esac
            not_swept+=("$entry"); not_swept_why+=("${line#* -- }") ;;
          *) echo "✋ deny-sweep: [not-swept] entry '$line' states no reason. Write" >&2
             echo "        '<path> -- <why nothing in it needs sweeping>'." >&2
             exit 2 ;;
        esac ;;
    esac
  done < "$file"
}
read_patterns "$deny_file"

# "Fails closed" has to cover an INVALID policy, not only an unreadable one. A blank or
# malformed pattern file parses into empty arrays, and the file is itself excluded from
# the primary content sweep -- so a committed blank policy would disable the guard while
# every check still reported success.
for required in '[paths]' '[content]' '[allow-content]'; do
  grep -qxF -- "$required" "$deny_file" || {
    echo "✋ deny-sweep: $deny_file has no $required section -- refusing to run on a" >&2
    echo "        malformed policy. An empty policy is indistinguishable from no rules." >&2
    exit 2
  }
done
if [ "${#content_pats[@]}" -eq 0 ] || [ "${#path_pats[@]}" -eq 0 ]; then
  echo "✋ deny-sweep: $deny_file declares no path or content rules -- refusing to run." >&2
  exit 2
fi

[ -n "${FINANCE_SWEEP_LIB:-}" ] && return 0   # sourced as a library: patterns only

# Declared exclusions, announced on every run. The two other gates in this repository
# print theirs the same way, for the same reason: an exclusion nobody sees is an exclusion
# nobody checks, and these are judgement rather than computation.
# `:(literal,exclude)`, never `:!`. Without `literal`, git treats `*` and `?` in a
# pathspec as wildcards while the awk filter and the scanner's python filter treat the
# same entry as one exact name -- so an exclusion for a file literally called `work*`
# silently removed `working` from the content pass alone. Demonstrated with an
# added-then-removed credential there, which no mode reported.
# An exact-file entry has to name a file in the ARTIFACT BEING ASSESSED -- the index for
# `staged`, the named revision for `tree` and `not-swept`. Checking the checked-out index
# instead let an unrelated branch validate an exclusion for a path the published commit
# does not contain, so the exemption applied to whatever appeared there next.
artifact_has() {                         # $1=path; 0 when the assessed artifact has it
  case "$mode" in
    staged) git cat-file -e ":$1" 2>/dev/null ;;
    tree|not-swept) git cat-file -e "$tree_rev:$1" 2>/dev/null ;;
    *)      git cat-file -e "HEAD:$1" 2>/dev/null ;;
  esac
}
if [ "${#not_swept[@]}" -gt 0 ]; then
  for i in "${!not_swept[@]}"; do
    case "${not_swept[$i]}" in
      */) continue ;;
    esac
    artifact_has "${not_swept[$i]}" || {
      echo "✋ deny-sweep: [not-swept] entry '${not_swept[$i]}' is neither a directory" >&2
      echo "        (ending in '/') nor a file the assessed revision contains. A bare" >&2
      echo "        prefix exempts every sibling that starts with it, and a name the" >&2
      echo "        artifact does not have exempts whatever appears there next." >&2
      exit 2; }
  done
fi

ns_excludes=()
if [ "${#not_swept[@]}" -gt 0 ]; then
  for i in "${!not_swept[@]}"; do
    ns_excludes+=(":(literal,exclude)${not_swept[$i]}")
    # Not in `not-swept` mode: there the list IS the output, and announcing it on stderr
    # as well makes every consumer print it twice.
    [ "$mode" = "not-swept" ] || echo "not swept: ${not_swept[$i]} -- ${not_swept_why[$i]}" >&2
  done
fi
# The pattern file is excluded from the CONTENT pass only -- it necessarily contains the
# rules it defines -- and its residue is swept separately below. It is not excluded from
# anything else, so it cannot become a hiding place for a marker or a binary.
excludes=(":(literal,exclude)$deny_rel" ${ns_excludes[@]+"${ns_excludes[@]}"})
# The same list, as a prefix filter for the path list, which is built without pathspecs.
not_swept_prefixed() {                   # reads a path list on stdin, drops excluded ones
  local p
  if [ "${#not_swept[@]}" -eq 0 ]; then cat; return 0; fi
  # A directory entry (trailing `/`) matches anything beneath it; a file entry matches
  # that path exactly. Never a bare string prefix -- see the parse above.
  awk -v n="${#not_swept[@]}" '
    BEGIN { for (i = 1; i < ARGC; i++) { pre[i] = ARGV[i]; ARGV[i] = "" } }
    { keep = 1
      for (i = 1; i <= n; i++) {
        if (pre[i] ~ /\/$/) { if (index($0, pre[i]) == 1) keep = 0 }
        else if ($0 == pre[i]) keep = 0
      }
      if (keep) print }
  ' "${not_swept[@]}" -
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# grep exits 0=match, 1=no match, 2=bad expression. Never capture $? after `!` -- the
# negation rewrites it to 0, so a perfectly good pattern reads as invalid and the whole
# sweep fails closed on its first real rule.
: > "$work/empty"
die_on_bad_pattern() {
  set +e
  grep -E "$1" "$work/empty" >/dev/null 2>&1
  local status=$?
  set -e
  [ "$status" -le 1 ] || { echo "✋ deny-sweep: invalid pattern /$1/" >&2; exit 2; }
}
for pat in ${path_pats[@]+"${path_pats[@]}"} ${content_pats[@]+"${content_pats[@]}"} \
           ${allow_pats[@]+"${allow_pats[@]}"}; do
  die_on_bad_pattern "$pat"
done

# An allow rule is a whole-match exemption, so `.*` under [allow-content] would exempt
# every finding there is. Refuse any allow rule that whole-matches an arbitrary canary.
for pat in ${allow_pats[@]+"${allow_pats[@]}"}; do
  # Assembled at runtime: written literally, these canaries are themselves findings and
  # this file could not be committed.
  canary_mail="nobody@nowhere"".invalid"
  canary_addr="10.11.12"".13"
  for canary in 'CANARY-9f3c' "$canary_mail" "$canary_addr"; do
    if printf '%s' "$canary" | grep -qxE -- "$pat" 2>/dev/null; then
      echo "✋ deny-sweep: allow rule /$pat/ matches the canary '$canary' -- it is broad" >&2
      echo "        enough to exempt unrelated findings. Allow rules name ONE value." >&2
      exit 2
    fi
  done
done

fail=0

# An allow entry exempts a match only when it covers the match ENTIRELY.
#
# Deleting allow matches from the text with `sed s///g` is an unanchored substring
# rewrite: a broader match ending in an allowed value has that value deleted, and the
# remainder no longer matches -- a real address passes. Whole-match semantics cannot do
# that: an allow rule either IS the finding, or is irrelevant to it.
allowed_match() {                        # $1=the matched text; 0 when wholly allowed
  local text="$1" pat
  for pat in ${allow_pats[@]+"${allow_pats[@]}"}; do
    printf '%s' "$text" | grep -qxE -- "$pat" && return 0
  done
  return 1
}

scan() {                                 # $1=pattern $2=input file $3=label $4=1 to skip allow
  local pat="$1" file="$2" label="$3" skip_allow="${4:-0}" status text hit=0 lineno
  set +e
  grep -noE -- "$pat" "$file" > "$work/matches"
  status=$?
  set -e
  if [ "$status" -ge 2 ]; then
    echo "✋ deny-sweep: pattern /$pat/ failed at runtime" >&2
    exit 2
  fi
  while IFS= read -r line; do
    text="${line#*:}"
    if [ "$skip_allow" = 0 ] && allowed_match "$text"; then
      continue
    fi
    if [ "$hit" -eq 0 ]; then
      echo "✋ deny $label /$pat/:" >&2
      hit=1
    fi
    # `grep -oE` gives the fragment, which is what the allow decision needs; the operator
    # needs the whole line to know WHICH file. Report both.
    lineno="${line%%:*}"
    printf '   %s\n' "$(sed -n "${lineno}p" "$file" | cut -c1-160)" >&2
  done < "$work/matches"
  [ "$hit" -eq 1 ] && fail=1
  return 0
}

case "$mode" in
  staged|tree|text) ;;
  # So that a third consumer does not reimplement the parse and drift from it. The push
  # hook needs this list to filter the blobs it feeds the identifier scan, which sees
  # object contents and has no path to exclude by.
  not-swept)
    # `<path> -- <reason>`, one per line, AFTER the validation above. The reason travels
    # with the path so the consumer can announce it the way this script does.
    if [ "${#not_swept[@]}" -gt 0 ]; then
      for i in "${!not_swept[@]}"; do
        printf '%s -- %s\n' "${not_swept[$i]}" "${not_swept_why[$i]}"
      done
    fi
    exit 0 ;;
  range|messages)
    [ "${#range_args[@]}" -gt 0 ] || {
      echo "✋ deny-sweep: $mode needs at least one revision argument. With none, git" >&2
      echo "        would walk the whole history and report findings from commits this" >&2
      echo "        push does not publish -- or, worse, none at all." >&2
      exit 2; }
    # An unresolvable revision made `git log` fail and print nothing, and the `|| true`
    # on that pipeline turned the failure into a clean, empty scan with exit 0 -- the
    # same answer a genuinely clean range gives.
    git rev-list "${range_args[@]}" >/dev/null 2>&1 || {
      echo "✋ deny-sweep: ${range_args[*]} is not a resolvable revision range, so there" >&2
      echo "        is nothing to report and nothing was checked. Refusing rather than" >&2
      echo "        returning the answer a clean range would give." >&2
      exit 2; } ;;
  *) echo "✋ deny-sweep: unknown mode $mode" >&2; exit 2 ;;
esac

# --- paths ---
# `range` enumerates EVERY commit, not the endpoint diff: a denied path added in one
# commit and deleted in the next vanishes from `git diff base..HEAD` while its blob is
# published all the same.
: > "$work/paths"
case "$mode" in
  # `T` alongside A, C, M and R: a symlink replaced by a regular file is a TYPE CHANGE,
  # and its record is absent from a filter that does not name it.
  staged) git diff --cached --name-only --diff-filter=ACMRT | not_swept_prefixed > "$work/paths" ;;
  # ls-TREE, not ls-files: the index describes the checkout, and what is published is a
  # commit. They differ whenever anything is staged or in progress.
  tree)   git ls-tree -r --name-only "$tree_rev" | not_swept_prefixed > "$work/paths" ;;
  range)  # -m: emit a diff against EACH parent. Without it git prints no file list at all
          # for a merge, so a denied path introduced by conflict resolution and removed
          # later is invisible to both this and the content pass.
          # `--diff-filter=ACMRT` per commit, not per range. An addition in one commit
          # and a deletion in the next are both seen, because each commit is enumerated
          # on its own -- but a commit that only REMOVES an already-public denied path
          # publishes neither the path nor its contents, and refusing it left no way
          # forward but --no-verify.
          git rev-list "${range_args[@]}" | while read -r commit; do
            git show --name-only --format= -m --diff-filter=ACMRT "$commit"
          done | sort -u | not_swept_prefixed > "$work/paths" ;;
esac
# A path containing a newline is C-quoted by git, so anchored path rules stop matching and
# such a commit could evade both path denial and the root-file check. Refuse the name
# rather than try to parse it.
if grep -q '^"' "$work/paths" 2>/dev/null; then
  echo "✋ deny-sweep: path name(s) containing control characters:" >&2
  grep '^"' "$work/paths" | head -5 | sed 's/^/   /' >&2
  echo "   git C-quotes these, which defeats anchored path rules. Rename them." >&2
  fail=1
fi
for pat in ${path_pats[@]+"${path_pats[@]}"}; do
  scan "$pat" "$work/paths" "path" 1
done

# --- root-file allowlist ---
if [ "$mode" != "messages" ] && [ "$mode" != "text" ]; then
  root_allowlist=".githooks/root-allowlist.txt"
  [ -n "$policy_from_rev" ] && root_allowlist="$policy_from_rev/.githooks/root-allowlist.txt"
  if [ ! -r "$root_allowlist" ]; then
    echo "✋ deny-sweep: .githooks/root-allowlist.txt is missing -- refusing to run with" >&2
    echo "        the root-file check silently disabled." >&2
    exit 2
  fi
  # Strip comments and blanks first. `grep -f` reads every line as a pattern, so each
  # explanatory `#` line in the allowlist was itself an allowed filename -- an exemption
  # nobody declared, for a path nobody would notice.
  grep -vE '^[[:space:]]*(#|$)' "$root_allowlist" > "$work/root-allow" || true
  grep -vE '/' "$work/paths" | grep -vxF -f "$work/root-allow" > "$work/strays" || true
  if [ -s "$work/strays" ]; then
    echo "✋ root-level file(s) outside .githooks/root-allowlist.txt:" >&2
    cat "$work/strays" >&2
    fail=1
  fi
fi

# --- binary blobs: unscannable, therefore not publishable without an explicit decision ---
# `git grep -I` skips binaries and patches say only "Binary files differ", so one NUL byte
# would otherwise make any payload invisible to every content rule below.
if [ "$mode" != "messages" ] && [ "$mode" != "text" ]; then
  : > "$work/binaries"
  case "$mode" in
    tree)
      git ls-tree -r --name-only "$tree_rev" | not_swept_prefixed | sort > "$work/all"
      # `git grep -Il` exits 1 when NOTHING is textual; under `pipefail` that would kill
      # the whole sweep with an empty message -- a silent failure in the guard itself.
      { git grep -Il '' "$tree_rev" -- . ${ns_excludes[@]+"${ns_excludes[@]}"} 2>/dev/null || true; } \
        | sed "s|^$tree_rev:||" | sort > "$work/textual"
      comm -23 "$work/all" "$work/textual" > "$work/maybe-binary"
      # An EMPTY file is not textual to `git grep -Il` and not binary either: it carries
      # nothing and can hide nothing. Without this, every zero-byte marker file -- and any
      # empty __init__.py -- is reported as an unscannable blob.
      # Emptiness is read from the REVISION, not from the checkout: a file that is empty
      # at $tree_rev and non-empty on disk (or missing entirely) was classified by
      # whatever happened to be in the working tree, which is not what is published.
      while IFS= read -r candidate; do
        size="$(git cat-file -s "$tree_rev:$candidate" 2>/dev/null || echo 0)"
        [ "$size" -gt 0 ] && printf '%s\n' "$candidate" >> "$work/binaries"
      done < "$work/maybe-binary" ;;
    range)
      # numstat prints `-\t-\t<path>` for a binary change. `--diff-filter=ACMR` excludes
      # DELETIONS, matching the staged branch below: this guard exists because an added
      # binary can hide a payload from every content rule, and a removal publishes nothing
      # to hide. Without the filter the two halves of one guard disagree about the same
      # change, and the only ways past are to keep the file or keep a stale allowlist entry.
      { git log --numstat --format= -m --no-textconv --diff-filter=ACMRT "${range_args[@]}" 2>/dev/null || true; } \
        | awk -F'\t' '$1=="-" && $2=="-" {print $3}' | not_swept_prefixed | sort -u > "$work/binaries" ;;
    staged)
      { git diff --cached --numstat --no-textconv --diff-filter=ACMRT || true; } \
        | awk -F'\t' '$1=="-" && $2=="-" {print $3}' | not_swept_prefixed | sort -u > "$work/binaries" ;;
  esac
  if [ -s "$work/binaries" ]; then
    binary_allowlist=".githooks/binary-allowlist.txt"
    [ -n "$policy_from_rev" ] && binary_allowlist="$policy_from_rev/.githooks/binary-allowlist.txt"
    if [ -f "$binary_allowlist" ]; then
      grep -vxF -f "$binary_allowlist" "$work/binaries" > "$work/new-binaries" || true
    else
      cp "$work/binaries" "$work/new-binaries"
    fi
    if [ -s "$work/new-binaries" ]; then
      echo "✋ binary blob(s) no content rule can inspect:" >&2
      sed 's/^/   /' "$work/new-binaries" >&2
      echo "   A binary cannot be swept or read in review. This tree has none, so there" >&2
      echo "   is no .githooks/binary-allowlist.txt; adding one is a decision to publish" >&2
      echo "   something nobody can read in a diff." >&2
      fail=1
    fi
  fi
fi

# --- the inline scanner allow-marker is never valid here ---
# gitleaks honours the marker natively, so a real credential plus that comment produces a
# clean secret scan. This repository's only exception channel is the declared inventory in
# .githooks/gitleaks-allow-sites.txt, which names a path, a rule and a count and is
# subtracted by scripts/run-gitleaks.sh. A marker bypasses all of that silently, so it is
# refused wherever it appears.
if [ "$mode" != "messages" ] && [ "$mode" != "text" ]; then
  # Assembled at runtime: written literally, this file would be a bypass site by its own
  # rule -- and would silence the scanner on itself.
  marker="gitleaks"":""allow"
  : > "$work/marker-sites"
  case "$mode" in
    staged) { git grep -lI --cached -- "$marker" -- . ${ns_excludes[@]+"${ns_excludes[@]}"} 2>/dev/null || true; } \
              | sort -u > "$work/marker-sites" ;;
    range)  for commit in $(git rev-list "${range_args[@]}"); do
              { git grep -lI -- "$marker" "$commit" -- . ${ns_excludes[@]+"${ns_excludes[@]}"} 2>/dev/null || true; } \
                | sed 's|^[0-9a-f]*:||'
            done | sort -u > "$work/marker-sites" ;;
    *)      { git grep -lI -- "$marker" "$tree_rev" -- . ${ns_excludes[@]+"${ns_excludes[@]}"} 2>/dev/null || true; } \
              | sed "s|^$tree_rev:||" | sort -u > "$work/marker-sites" ;;
  esac
  if [ -s "$work/marker-sites" ]; then
    echo "✋ inline scanner allow-marker in file(s):" >&2
    sed 's/^/   /' "$work/marker-sites" >&2
    echo "   That marker silences the secret scanner wherever it is written, with no" >&2
    echo "   record of what it silenced. Declare the finding in" >&2
    echo "   .githooks/gitleaks-allow-sites.txt instead: path, rule and count." >&2
    fail=1
  fi
fi

# --- content ---
# Added lines are extracted with a STATE MACHINE, not by pattern-matching the diff text.
#
# `grep -vE '^\+\+\+'` was meant to drop the `+++ b/path` header, but a real added line
# whose content begins `++` renders as `+++content` and was dropped with it -- so a denied
# value could be added in one commit, removed in the next, and evade the range sweep while
# the endpoint tree stayed clean.
#
# A `+++` line is a header only when it sits between `diff --git` and the first `@@`. That
# is structural and cannot be spoofed by content. The leading `+` is then stripped, because
# it is a legal e-mail local-part character and would otherwise turn an added line starting
# with a decorator into an apparent address.
added_lines() { awk '
  /^diff --git /   { inheader = 1; next }
  /^@@/            { inheader = 0; next }
  inheader         { next }
  /^\+/           { print substr($0, 2) }
'; }
case "$mode" in
  # `--no-textconv` on every diff: a `diff` driver declared in .gitattributes makes git
  # show CONVERTED content, so a credential in a file with a textconv filter is absent
  # from the diff while its bytes go out in the commit. `git grep` does not apply
  # textconv unless asked, so tree mode needs nothing.
  staged)   git diff --cached --no-textconv -U0 -- . "${excludes[@]}" | added_lines > "$work/body" || true ;;
  tree)     git grep -I --no-color -n '' "$tree_rev" -- . "${excludes[@]}" > "$work/body" || true ;;
  range)    git log -p -m --no-textconv --no-color "${range_args[@]}" -- . "${excludes[@]}" \
              | added_lines > "$work/body" || true ;;
  messages) git log --format='%B' "${range_args[@]}" > "$work/body" || true ;;
  text)     cat > "$work/body" || true ;;
esac
for pat in ${content_pats[@]+"${content_pats[@]}"}; do
  scan "$pat" "$work/body" "content" 0
done

# --- the pattern file: exclude only its DECLARED PATTERN LINES, not the whole file ---
# It is excluded from the sweep above because it necessarily contains the rules it
# defines. Excluding the entire file makes it a hiding place for anything else, so the
# residue -- comments, blank lines, and any stray content -- is scanned with the content
# rules like any other file.
#
# The residue must come from the version being ASSESSED. Reading the working-tree copy
# would let a leaking version be staged behind a clean worktree file, and would leave
# every historical version of the file unexamined in range mode.
: > "$work/denyfile-src"
case "$mode" in
  staged) git show ":$deny_rel" >> "$work/denyfile-src" 2>/dev/null || true ;;
  tree)   git show "$tree_rev:$deny_rel" >> "$work/denyfile-src" 2>/dev/null || true ;;
  range)  git rev-list "${range_args[@]}" | while read -r commit; do
            git show "$commit:$deny_rel" 2>/dev/null || true
          done >> "$work/denyfile-src" ;;
esac
if [ -s "$work/denyfile-src" ]; then
  {
    printf '%s\n' ${path_pats[@]+"${path_pats[@]}"} ${content_pats[@]+"${content_pats[@]}"} \
                   ${allow_pats[@]+"${allow_pats[@]}"}
    printf '[paths]\n[content]\n[allow-content]\n'
  } > "$work/declared"
  grep -vxF -f "$work/declared" "$work/denyfile-src" > "$work/deny-residue" || true
  for pat in ${content_pats[@]+"${content_pats[@]}"}; do
    scan "$pat" "$work/deny-residue" "content(pattern-file residue)" 0
  done
fi

exit "$fail"
