#!/usr/bin/env python3
"""Refuse to ship this project's private development lineage.

A reader of a public repository can verify what the code does. They cannot open
a private design document, look up a numbered task, or find out who "sol" was
and what a "round 4" finding said. Comments that cite those things state facts
this repository cannot substantiate, and they read as one person's private
workspace regardless of whether any personal fact remains.

So every mechanism stays and every attribution goes. This script enumerates the
attributions by category so that "is the sweep finished" has an answer, and it
is the gate that keeps the answer at zero.

**Counts are non-overlapping.** A line matching two categories is counted once,
under the first category in `CATEGORIES` order, and that order is committed
below. An earlier estimate summed overlapping matchers and had to be withdrawn:
a count that does not add up cannot say whether the sweep is done.

**Exceptions are keyed on the site, not on a phrase.** A phrase-shaped
exemption always loses -- a reworded site walks past it, and an unrelated new
site containing the phrase is exempted for free. Keying on `(path, line)` means
an exception cannot spread, and a line that moves needs its exception approved
again, which is the correct direction to be wrong in.

**What this is not.** It is not a language model. It cannot tell a citation of
a private section from a citation of a published RFC, or a decision code from a
fixture value that looks like one. Both kinds of false positive exist in this
tree and both are answered in the exception file with a reason. The categories
are tuned to keep that file short enough to read.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

#: Declaration order IS the attribution order for overlapping matches. Most
#: specific first, so a compound site is attributed to its narrowest category
#: rather than to whichever pattern happens to be broadest.
#:
#: Separators inside a phrase are `[\s_-]`, not `\s`. Lineage reaches source
#: code through identifiers as well as prose -- `test_fix_round_1_shape` is a
#: review round, and a pattern anchored on whitespace cannot see it. For the
#: same reason every boundary here is a non-letter assertion rather than `\b`,
#: which does not fire against an underscore.
CATEGORIES = {
    "ruling":        re.compile(r"(?i)\brulings?\b"),
    "reviewer":      re.compile(r"(?i)(?<![A-Za-z])(?:sol|terra|reviewers?)"
                                r"(?![A-Za-z])"),
    "review_round":  re.compile(r"(?i)(?<![A-Za-z])rounds?[\s_-]*[0-9]"),
    #: Two spellings of the same thing: the `P0`-`P3` labels, and the worded
    #: `MAJOR 1` / `Minor 2` / `CRITICAL 1` / `Important 3` forms. The worded arm
    #: was missing from the first version of this scan and 48 sites across 11
    #: files went unreported while the gate exited 0 -- a category set is only
    #: worth the shapes it enumerates, and this is the one it did not.
    #:
    #: The worded arm requires an initial capital, so ordinary prose ("a minor
    #: 2-day gap") does not match. A determiner before a `P` label means the
    #: token is a noun, not a label ("the P0 postcode"); Python requires each
    #: lookbehind to be fixed width, hence one per determiner.
    "severity":      re.compile(r"(?<![A-Za-z0-9])(?:"
                                r"(?<![Tt]he )(?<![Aa] )(?<![Aa]n )"
                                r"(?<![Tt]his )(?<![Tt]hat )(?<![Ii]ts )P[0-3]"
                                r"|(?:MAJOR|MINOR|CRITICAL|IMPORTANT"
                                r"|Major|Minor|Critical|Important)\s*[0-9]+"
                                r")(?![A-Za-z0-9])"),
    "task_number":   re.compile(r"(?i)(?<![A-Za-z])tasks?[\s_-]*[0-9]+[a-z]?"
                                r"(?![A-Za-z0-9])"),
    "work_slice":    re.compile(r"(?i)(?<![A-Za-z])slices?[\s_-]*[0-9]"),
    #: A section sign is the citation, whatever introduces it: `spec §8.1`,
    #: `design §7`, `§13`, `§8/§8.1`. Two sites cite RFC 9110 §10.2.3, which is
    #: public; they are in the exception file rather than carved out here,
    #: because a pattern that tries to know which specifications are public is
    #: a pattern that will be wrong about the next one. The introducing word
    #: and the section number are carried into the report so a hit can be acted
    #: on without opening the file. A section sign, or "the brief" -- the two
    #: ways this tree cited a document the reader cannot open. `brief` is
    #: matched only in its definite/possessive sense: "a brief window" is
    #: ordinary English and must not fire.
    #:
    #: Deliberately NOT here: "the plan" and "the report". Both were audited and
    #: both are this codebase's OWN vocabulary -- `Plan` is the type `ingest`
    #: hands `apply`, and "the report" is the operator-facing text a tool
    #: returns. Matching them would have flagged ~28 legitimate sites to catch
    #: three, which is how a gate becomes a list nobody reads.
    "private_spec":  re.compile(r"(?:[A-Za-z]+\s*)?§\s*[0-9.]*"
                                r"|(?i:\bthe briefs?\b|\bbrief's\b)"),
    #: Repair and defect codes. `R` is deliberately absent from the letter set:
    #: `ref="R1"` is a rule identifier in this project's own test data, in 174
    #: places, and an R-coded finding has never appeared without a reviewer
    #: name or another code on the same line. Including R would have made the
    #: report unreadable and bought nothing.
    "decision_code": re.compile(r"(?<![A-Za-z0-9])"
                                r"(?:[CDEFM][0-9]{1,2}|T1[0-9]-[a-z])"
                                r"(?![A-Za-z0-9])"),
}

EXCEPTIONS_FILE = "scripts/lineage-exceptions.txt"

#: `exclude-tree:<prefix>` -- a subtree the scan does not cover. There is no
#: hardcoded exclusion. The identifier gate that came before this one skipped a
#: directory in silence, and that directory held dozens of real account
#: numbers, so the gate reported clean while the tree was not. An exclusion
#: must be written down, carry its reason, and is PRINTED on every run, because
#: the danger of an exclusion is that it is easy to forget.
EXCLUDE_PREFIX = "exclude-tree:"

#: The category for a file that cannot be read as text. Reported rather than
#: skipped: a file nobody could read is an unanswered question, not a clean
#: result.
UNSCANNABLE = "unscannable"


def _entries(root: pathlib.Path):
    """(lineno, entry, reason) for every non-blank exception-file line.

    Every entry must carry a reason after a `#`. "It reads fine" is not a
    reason, but a reason that has to be typed at all is a reason someone has to
    defend in review, and that is most of the value.
    """
    path = root / EXCEPTIONS_FILE
    if not path.exists():
        return
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        entry, _, reason = raw.partition("#")
        entry = entry.strip()
        if not entry:
            continue
        if not reason.strip():
            raise ValueError(
                "%s:%d: %r has no reason. Every entry must say why the site is "
                "not private lineage, on the same line after a '#'."
                % (EXCEPTIONS_FILE, lineno, entry))
        yield lineno, entry, reason.strip()


def load_exceptions(root: pathlib.Path) -> set:
    """Permitted sites, as `{(path, lineno)}`."""
    out = set()
    for lineno, entry, _ in _entries(root):
        if entry.startswith(EXCLUDE_PREFIX):
            continue
        path, _, line = entry.rpartition(":")
        if not path or not line.strip().isdigit():
            raise ValueError(
                "%s:%d: %r is not `path:line`. An exception names one site."
                % (EXCEPTIONS_FILE, lineno, entry))
        out.add((path.strip(), int(line)))
    return out


def load_exclusions(root: pathlib.Path) -> dict:
    """Excluded subtrees, as `{prefix: reason}`."""
    return {entry[len(EXCLUDE_PREFIX):].strip(): reason
            for _, entry, reason in _entries(root)
            if entry.startswith(EXCLUDE_PREFIX)}


def categorize(line: str):
    """(category, matched text) for `line`, or None.

    First match in declaration order wins, so a line is counted once.
    """
    for name, pattern in CATEGORIES.items():
        found = pattern.search(line)
        if found:
            return name, found.group(0)
    return None


def _tracked(root: pathlib.Path) -> list:
    try:
        out = subprocess.run(["git", "ls-files"], cwd=root, check=True,
                             capture_output=True, text=True).stdout
        files = [f for f in out.splitlines() if f]
        if files:
            return files
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return sorted(str(p.relative_to(root))
                  for p in root.rglob("*") if p.is_file())


def scan(root: pathlib.Path, exceptions=None, excluded=None) -> list:
    """(path, lineno, category, matched_text) per site lacking a decision."""
    root = pathlib.Path(root)
    if exceptions is None:
        exceptions = load_exceptions(root)
    if excluded is None:
        excluded = load_exclusions(root)
    hits = []
    for rel in _tracked(root):
        if any(rel.startswith(prefix) for prefix in excluded):
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            if (rel, 0) not in exceptions:
                hits.append((rel, 0, UNSCANNABLE, "cannot be read as text"))
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if (rel, lineno) in exceptions:
                continue
            found = categorize(line)
            if found:
                hits.append((rel, lineno, found[0], found[1]))
    return hits


def counts(hits) -> dict:
    """Per-category totals. These add up to `len(hits)`, by construction."""
    out = {}
    for _, _, category, _ in hits:
        out[category] = out.get(category, 0) + 1
    return out


def main(argv: list) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    root = pathlib.Path(args[0] if args else ".").resolve()
    paths = [pathlib.Path(a) for a in args[1:]]
    excluded = load_exclusions(root)
    # Printed on EVERY run, clean or not. An exclusion the reader never sees is
    # how "the gate exits 0" comes to mean less than it sounds.
    for prefix, reason in sorted(excluded.items()):
        n = sum(1 for f in _tracked(root) if f.startswith(prefix))
        print("not scanned: %s (%d tracked file(s)) -- %s" % (prefix, n, reason))
    hits = scan(root, excluded=excluded)
    if paths:
        wanted = tuple(str(p) for p in paths)
        hits = [h for h in hits if h[0].startswith(wanted)]
    if "--counts" in argv:
        per_file = {}
        for rel, _, _, _ in hits:
            per_file[rel] = per_file.get(rel, 0) + 1
        for category, n in sorted(counts(hits).items(), key=lambda kv: -kv[1]):
            print("%6d  %s" % (n, category))
        print()
        for rel, n in sorted(per_file.items(), key=lambda kv: -kv[1]):
            print("%6d  %s" % (n, rel))
        print("\n%d site(s) across %d file(s)." % (len(hits), len(per_file)))
    else:
        for rel, lineno, category, matched in hits:
            print("%s:%d: %s: %s" % (rel, lineno, category, matched))
    if hits:
        print("\n%d private-lineage site(s) without a committed decision.\n"
              "Rewrite each one to state the mechanism and drop the "
              "attribution, or add it to %s with the reason it is not private "
              "lineage." % (len(hits), EXCEPTIONS_FILE))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
