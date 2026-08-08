#!/usr/bin/env python3
"""Refuse to ship a checksum-valid account number.

Every IBAN-shaped token in the tracked tree is checked against mod-97. A value
that passes must be dealt with before the repository is published: replaced
with a checksum-invalid synthetic (`NL00...` by convention, since `00` check
digits are never valid), or listed in scripts/identifier-exceptions.txt with a
citation naming the public source it comes from.

**What this is for, and what it is not.**

This gate catches a value left in by ACCIDENT -- a fixture nobody sanitised, a
doc quoting a real statement, a value written in a rendering the author did not
think of. That is the failure this repository actually had: four real account
numbers across nine files, plus three more found later in renderings the first
pass missed.

It is NOT an adversary detector. A repository's author is not hiding values
from themselves, so a value encoded, re-encoded and escaped to evade this scan
is not a threat model that exists here. Earlier versions grew machinery for
exactly that, and the machinery became the defect: a rule excluding long hex
runs -- meant to skip hash digests -- hid a real Belgian IBAN, because Belgian
IBANs are made entirely of hexadecimal characters.

Coverage is therefore bounded to renderings a value reaches without anyone
trying: whitespace and punctuation between groups, line wraps, case, escapes a
source file introduces on its own, and one layer of base64. Beyond that the
answer is to read the diff, which the release checklist requires anyway.

**How a candidate is found.** From every `LLDD` start, up to 34 alphanumerics
are read forward with separators skipped, and every length from 15 up is
checked -- so neither a leading identifier nor a trailing label can hide a
value inside a longer run.

**How a candidate qualifies.** Both of:

* its separators fall the way a written value's do -- compact, wrapped once, or
  grouped in fours. Prose breaks at word boundaries, which land anywhere;
  without this, ordinary sentences pass mod-97 roughly one time in ninety-seven
  and the gate becomes unreadable;
* its country is in the ISO 13616 registry and its length is exactly what that
  country registers. This is definitional -- an IBAN exists only for a
  registered country -- and it is also what keeps high-entropy content out,
  since a PEM body or a hash digest is a compact run that the layout rule
  alone would pass. The maintenance cost is real and is the table's job: a
  country that joins the scheme must be added here or its values are missed.
"""
from __future__ import annotations

import base64
import binascii
import pathlib
import re
import subprocess
import sys
import urllib.parse
import warnings

#: Anything that can sit between the characters of a written IBAN: every
#: Unicode space (U+00A0 is what a value pasted from a bank's web page
#: carries), the dash range, the delimiters a value picks up in CSV, paths and
#: identifiers, and the zero-width characters that survive a copy-paste looking
#: clean.
SEP = "[\\s\\-‐-―./,_​‌‍﻿]"

_SEP_CHARS = re.compile(SEP)

#: Invisible characters. Skipped WITHOUT counting as separators: they carry no
#: layout information, so a value peppered with them is still "written
#: compactly" and must not be judged as irregularly spaced.
_ZERO_WIDTH = re.compile("[​‌‍﻿]")

#: Where a candidate can start: two letters then two digits. Separators are
#: allowed between them, because a value carrying zero-width characters has
#: them there too. No boundary anchor on either side -- a boundary rule only
#: decides what the checksum never gets to see.
TOKEN_START = re.compile(r"[A-Za-z]{s}*[A-Za-z]{s}*[0-9]{s}*[0-9]".format(s=SEP))

MAX_IBAN_LEN = 34
MIN_IBAN_LEN = 15

#: The 89 nationally agreed formats of the ISO 13616 registry, whose registrar
#: is SWIFT. Two independent publications were compared and agree on every
#: entry.
#:
#: Registry ONLY. A wider list circulates that adds countries with partial or
#: experimental adoption, and using it was a mistake: each extra country is a
#: two-letter prefix ordinary prose can start with, and adding twenty-two of
#: them made twenty-two new sentences scan as account numbers.
#:
#: A MISSING country is the dangerous error here, not merely a wrong length:
#: nothing is reported for a country that is not here. That is the price of
#: not drowning in coincidence, and it is stated rather than hidden.
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22,
    "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20,
    "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22,
    "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HN": 28, "HR": 21,
    "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30,
    "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20,
    "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
    "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "RU": 33, "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24,
    "SM": 27, "SO": 23, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26,
    "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}

#: The national BBAN structure for each registered country, as a regular
#: expression over the characters AFTER the four-character header.
#:
#: Length alone lets a run of hexadecimal spell an account number. A commit
#: object is mostly hex -- `tree <sha>`, `parent <sha>` -- and hex uses a-f, so
#: `AD`, `AE`, `BA`, `BE`, `DE` and `EE` are all spellable by accident. Measured
#: before this existed: about one commit object in 117 carried a checksum-valid
#: token, and a push carrying one was refused with no remedy, because a random
#: substring of a sha has no public source to cite in the exception file.
#:
#: FAILS OPEN, per country. A country absent from this table is checked on
#: length alone, exactly as before. That direction is deliberate: a wrong
#: pattern here would stop reporting real account numbers for that country,
#: which is the one error this scanner must never make. Every entry below was
#: admitted only after passing three independent checks -- parsed from the
#: registry structure, its total length agreeing with IBAN_LENGTHS above, and
#: a real published example IBAN for that country matching it. Any country
#: failing any of the three is omitted rather than guessed at.
IBAN_BBAN = {
    "AD": "[0-9]{4}[0-9]{4}[0-9A-Z]{12}", "AE": "[0-9]{3}[0-9]{16}",
    "AL": "[0-9]{8}[0-9A-Z]{16}", "AT": "[0-9]{5}[0-9]{11}",
    "AZ": "[A-Z]{4}[0-9A-Z]{20}", "BA": "[0-9]{3}[0-9]{3}[0-9]{8}[0-9]{2}",
    "BE": "[0-9]{3}[0-9]{7}[0-9]{2}",
    "BG": "[A-Z]{4}[0-9]{4}[0-9]{2}[0-9A-Z]{8}",
    "BH": "[A-Z]{4}[0-9A-Z]{14}", "BI": "[0-9]{5}[0-9]{5}[0-9]{11}[0-9]{2}",
    "BR": "[0-9]{8}[0-9]{5}[0-9]{10}[A-Z]{1}[0-9A-Z]{1}",
    "BY": "[0-9A-Z]{4}[0-9]{4}[0-9A-Z]{16}", "CH": "[0-9]{5}[0-9A-Z]{12}",
    "CR": "[0-9]{4}[0-9]{14}", "CY": "[0-9]{3}[0-9]{5}[0-9A-Z]{16}",
    "CZ": "[0-9]{4}[0-9]{16}", "DE": "[0-9]{8}[0-9]{10}",
    "DJ": "[0-9]{5}[0-9]{5}[0-9]{11}[0-9]{2}",
    "DK": "[0-9]{4}[0-9]{9}[0-9]{1}", "DO": "[0-9A-Z]{4}[0-9]{20}",
    "EE": "[0-9]{2}[0-9]{14}", "EG": "[0-9]{4}[0-9]{4}[0-9]{17}",
    "ES": "[0-9]{4}[0-9]{4}[0-9]{1}[0-9]{1}[0-9]{10}",
    "FI": "[0-9]{3}[0-9]{11}", "FK": "[A-Z]{2}[0-9]{12}",
    "FO": "[0-9]{4}[0-9]{9}[0-9]{1}",
    "FR": "[0-9]{5}[0-9]{5}[0-9A-Z]{11}[0-9]{2}",
    "GB": "[A-Z]{4}[0-9]{6}[0-9]{8}", "GE": "[A-Z]{2}[0-9]{16}",
    "GI": "[A-Z]{4}[0-9A-Z]{15}", "GL": "[0-9]{4}[0-9]{9}[0-9]{1}",
    "GR": "[0-9]{3}[0-9]{4}[0-9A-Z]{16}", "GT": "[0-9A-Z]{4}[0-9A-Z]{20}",
    "HN": "[A-Z]{4}[0-9]{20}", "HR": "[0-9]{7}[0-9]{10}",
    "HU": "[0-9]{3}[0-9]{4}[0-9]{1}[0-9]{15}[0-9]{1}",
    "IE": "[A-Z]{4}[0-9]{6}[0-9]{8}", "IL": "[0-9]{3}[0-9]{3}[0-9]{13}",
    "IQ": "[A-Z]{4}[0-9]{3}[0-9]{12}",
    "IS": "[0-9]{4}[0-9]{2}[0-9]{6}[0-9]{10}",
    "IT": "[A-Z]{1}[0-9]{5}[0-9]{5}[0-9A-Z]{12}",
    "JO": "[A-Z]{4}[0-9]{4}[0-9A-Z]{18}", "KW": "[A-Z]{4}[0-9A-Z]{22}",
    "KZ": "[0-9]{3}[0-9A-Z]{13}", "LB": "[0-9]{4}[0-9A-Z]{20}",
    "LC": "[A-Z]{4}[0-9A-Z]{24}", "LI": "[0-9]{5}[0-9A-Z]{12}",
    "LT": "[0-9]{5}[0-9]{11}", "LU": "[0-9]{3}[0-9A-Z]{13}",
    "LV": "[A-Z]{4}[0-9A-Z]{13}", "LY": "[0-9]{3}[0-9]{3}[0-9]{15}",
    "MC": "[0-9]{5}[0-9]{5}[0-9A-Z]{11}[0-9]{2}",
    "MD": "[0-9A-Z]{2}[0-9A-Z]{18}", "ME": "[0-9]{3}[0-9]{13}[0-9]{2}",
    "MK": "[0-9]{3}[0-9A-Z]{10}[0-9]{2}", "MN": "[0-9]{4}[0-9]{12}",
    "MR": "[0-9]{5}[0-9]{5}[0-9]{11}[0-9]{2}",
    "MT": "[A-Z]{4}[0-9]{5}[0-9A-Z]{18}",
    "MU": "[A-Z]{4}[0-9]{2}[0-9]{2}[0-9]{12}[0-9]{3}[A-Z]{3}",
    "NI": "[A-Z]{4}[0-9]{20}", "NL": "[A-Z]{4}[0-9]{10}",
    "NO": "[0-9]{4}[0-9]{6}[0-9]{1}", "OM": "[0-9]{3}[0-9A-Z]{16}",
    "PK": "[A-Z]{4}[0-9A-Z]{16}", "PL": "[0-9]{8}[0-9]{16}",
    "PS": "[A-Z]{4}[0-9A-Z]{21}", "PT": "[0-9]{4}[0-9]{4}[0-9]{11}[0-9]{2}",
    "QA": "[A-Z]{4}[0-9A-Z]{21}", "RO": "[A-Z]{4}[0-9A-Z]{16}",
    "RS": "[0-9]{3}[0-9]{13}[0-9]{2}", "RU": "[0-9]{9}[0-9]{5}[0-9A-Z]{15}",
    "SA": "[0-9]{2}[0-9A-Z]{18}",
    "SC": "[A-Z]{4}[0-9]{2}[0-9]{2}[0-9]{16}[A-Z]{3}",
    "SD": "[0-9]{2}[0-9]{12}", "SE": "[0-9]{3}[0-9]{16}[0-9]{1}",
    "SI": "[0-9]{5}[0-9]{8}[0-9]{2}", "SK": "[0-9]{4}[0-9]{6}[0-9]{10}",
    "SM": "[A-Z]{1}[0-9]{5}[0-9]{5}[0-9A-Z]{12}",
    "SO": "[0-9]{4}[0-9]{3}[0-9]{12}",
    "ST": "[0-9]{4}[0-9]{4}[0-9]{11}[0-9]{2}", "SV": "[A-Z]{4}[0-9]{20}",
    "TL": "[0-9]{3}[0-9]{14}[0-9]{2}",
    "TN": "[0-9]{2}[0-9]{3}[0-9]{13}[0-9]{2}",
    "TR": "[0-9]{5}[0-9]{1}[0-9A-Z]{16}", "UA": "[0-9]{6}[0-9A-Z]{19}",
    "VA": "[0-9]{3}[0-9]{15}", "VG": "[A-Z]{4}[0-9]{16}",
    "XK": "[0-9]{4}[0-9]{10}[0-9]{2}", "YE": "[A-Z]{4}[0-9]{4}[0-9A-Z]{18}",
}

#: An 18-character IBAN base64-encodes to 24 characters, so 24 is the shortest
#: run worth decoding.
B64_MIN_LEN = 24

#: A region of base64-alphabet characters, both the standard (`+/`) and
#: URL-safe (`-_`) variants, with whitespace allowed inside because MIME wraps
#: at 76 columns. A candidate region, not a token.
B64_RUN = re.compile(r"[A-Za-z0-9+/\-_](?:[\s]*[A-Za-z0-9+/\-_]){15,}"
                     r"(?:[\s]*=){0,2}")

EXCEPTIONS_FILE = "scripts/identifier-exceptions.txt"

#: `unscannable:<path>` -- a tracked file that cannot be decoded as text, with
#: the reason it carries no identifier. Reported rather than skipped: a file
#: nobody could read is an unanswered question, not a clean result.
UNSCANNABLE_PREFIX = "unscannable:"

#: `exclude-tree:<prefix>` -- a tracked subtree the scan does not cover. There
#: is no hardcoded exclusion: an earlier version skipped the design directory
#: in silence, and that directory holds dozens of checksum-valid identifiers,
#: so the gate reported clean while tracked files carried real account numbers.
#: An exclusion must be written down, carry its reason, and is PRINTED on every
#: run, because the danger of an exclusion is that it is easy to forget.
EXCLUDE_PREFIX = "exclude-tree:"


def _normalize(raw: str) -> str:
    return _SEP_CHARS.sub("", raw).upper()


def _plausible(token: str) -> bool:
    """Shape checks every IBAN satisfies, applied after separators are gone."""
    return (MIN_IBAN_LEN <= len(token) <= MAX_IBAN_LEN
            and token[:2].isalpha()
            and token[2:4].isdigit()
            and token[4:].isalnum())


def mod97(iban: str) -> int:
    s = _normalize(iban)
    rotated = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) if c.isalpha() else c for c in rotated)
    return int(digits) % 97


def _run_from(text: str, start: int):
    """(run, seps) from `start`.

    `run` is up to MAX_IBAN_LEN alphanumerics with separators removed; `seps[i]`
    is how many separators were seen before character i, so a caller can ask
    how a candidate of length n was written without re-walking the text.
    """
    out, seps = [], []
    i, seen = start, 0
    while i < len(text) and len(out) < MAX_IBAN_LEN:
        ch = text[i]
        if ch.isalnum() and ch.isascii():
            out.append(ch.upper())
            seps.append(seen)
        elif _ZERO_WIDTH.match(ch):
            pass                       # invisible: no layout information
        elif _SEP_CHARS.match(ch):
            seen += 1
        else:
            break
        i += 1
    return "".join(out), seps


def _iban_like_layout(seps, n: int) -> bool:
    """Do the separators inside the first `n` characters look written-down?

    Compact, wrapped once, or grouped in fours. Prose breaks at word
    boundaries, which land anywhere -- "At 24 days ...", "Audit 37 checks ...",
    "So 22 rows ..." -- and roughly one such sentence in ninety-seven passes
    mod-97 at a registered length.
    """
    breaks = [i for i in range(1, n) if seps[i] != seps[i - 1]]
    if len(breaks) <= 1:
        return True
    return all(b % 4 == 0 for b in breaks)


def _valid_tokens(text: str):
    """(offset, token) for every checksum-valid identifier in `text`.

    The ONE implementation: `scan` used to repeat this logic, which is two
    places for the same rule to be wrong in, and they had begun to diverge.
    """
    seen = set()
    for match in TOKEN_START.finditer(text):
        run, seps = _run_from(text, match.start())
        if len(run) < MIN_IBAN_LEN:
            continue
        registered = IBAN_LENGTHS.get(run[:2])
        for n in range(MIN_IBAN_LEN, len(run) + 1):
            candidate = run[:n]
            if not (_plausible(candidate) and mod97(candidate) == 1):
                continue
            if not _iban_like_layout(seps, n):
                continue
            # An IBAN exists only for a country in the registry, and only at
            # that country's registered length. This is definitional, not a
            # heuristic -- and it is what keeps high-entropy content out: a
            # PEM body or a hash digest is a compact alphanumeric run, so the
            # layout rule alone passes it, and about one such run in
            # ninety-seven satisfies mod-97.
            if registered is None or n != registered:
                continue
            # ...and only in that country's national BBAN structure. Length
            # alone admits a hexadecimal run: see IBAN_BBAN. Absent country =>
            # no structure check, so this can only ever narrow a false
            # positive, never silence a country it does not describe.
            structure = IBAN_BBAN.get(candidate[:2])
            if structure is not None and not re.fullmatch(structure, candidate[4:]):
                continue
            if candidate not in seen:
                seen.add(candidate)
                yield match.start(), candidate
            break


def iban_tokens(text: str) -> list[str]:
    """Every checksum-valid identifier in `text`, compact and upper case."""
    return [token for _, token in _valid_tokens(text)]


def _unescape(text: str) -> list[str]:
    """Alternative readings under escaping a SOURCE FILE introduces on its own.

    Not evasion coverage. `"NL14ABNA\\n0509423841"` in a Python test is a broken
    run in the file text and the real account number at run time; it sat in this
    suite from the beginning and no matcher over file text could see it.
    """
    views = []
    try:
        views.append(urllib.parse.unquote(text))
    except (ValueError, UnicodeDecodeError):
        pass
    if "\\" in text:
        # `unicode_escape` warns on every sequence it does not know, and a tree
        # full of regexes has thousands. The warnings are about the INPUT, and
        # drowning the gate's own output is how a real line goes unread.
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                views.append(text.encode("utf-8", "surrogatepass")
                             .decode("unicode_escape"))
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
    return [v for v in views if v != text]


def _decoded_blobs(text: str) -> list[str]:
    """Text recovered from base64 runs, one layer.

    Each run is decoded both whole -- the MIME case, where a payload must be
    rejoined across wrapped lines -- and per whitespace segment, so an adjacent
    word cannot spoil the decode and hide what follows it.
    """
    out, seen = [], set()
    for match in B64_RUN.finditer(text):
        segments = [s for s in re.split(r"\s+", match.group(0)) if s]
        for candidate in ["".join(segments)] + segments:
            if len(candidate) < B64_MIN_LEN or candidate in seen:
                continue
            seen.add(candidate)
            for alphabet in (candidate,
                             candidate.replace("-", "+").replace("_", "/")):
                try:
                    out.append(base64.b64decode(
                        alphabet + "=" * (-len(alphabet) % 4), validate=True
                    ).decode("utf-8"))
                    break
                except (binascii.Error, ValueError, UnicodeDecodeError):
                    continue
    return out


def _derived_views(text: str) -> list[str]:
    """Every reading reachable by unescaping and by one base64 layer."""
    views, seen = [], {text}
    for view in _unescape(text) + _decoded_blobs(text):
        if view and view not in seen:
            seen.add(view)
            views.append(view)
    return views


def load_exceptions(root: pathlib.Path):
    """(permitted identifiers, undecodable-ok paths, excluded subtrees).

    There is exactly ONE way to permit a value and it requires naming the
    public source the value comes from. A softer marker was tried -- "this is
    prose, not an account number" -- and it was a bypass: an arbitrary reason
    and no verifiable basis, so any real account number could be silenced by
    asserting it was prose. A false positive is answered by rewording the
    prose.
    """
    path = root / EXCEPTIONS_FILE
    if not path.exists():
        return set(), set(), {}
    values, unscannable, excluded = set(), set(), {}
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        entry, _, citation = raw.partition("#")
        entry = entry.strip()
        if not entry:
            continue
        if not citation.strip():
            raise ValueError(
                "%s:%d: %r has no citation. Every entry must name the public "
                "source it comes from, on the same line after a '#'."
                % (EXCEPTIONS_FILE, lineno, entry))
        if entry.startswith(UNSCANNABLE_PREFIX):
            unscannable.add(entry[len(UNSCANNABLE_PREFIX):].strip())
        elif entry.startswith(EXCLUDE_PREFIX):
            prefix = entry[len(EXCLUDE_PREFIX):].strip()
            # An EMPTY prefix matched every tracked path, so one stray line silenced the
            # whole scan while every check still reported success. A directory entry ends
            # in `/` and covers what is beneath it; anything else names one exact file.
            # A bare prefix would also cover every sibling path that starts with it.
            if not prefix or prefix.startswith(("/", "./")) or "//" in prefix \
                    or "/./" in prefix or "/../" in prefix or prefix != prefix.strip():
                raise ValueError(
                    "%s:%d: %r is not a canonical repo-relative path. An empty or "
                    "non-canonical entry silences more than it names."
                    % (EXCEPTIONS_FILE, lineno, entry))
            excluded[prefix] = citation.strip()
        else:
            values.add(_normalize(entry))
    return values, unscannable, excluded


#: Paths that must never be committed at all, whatever is inside them. A
#: checksum scan reads text; a ledger, an export or a screenshot can carry
#: account data in a form no text scan sees, and the cheapest correct answer
#: is that they do not belong in this repository in the first place.
FORBIDDEN_PATHS = (
    (re.compile(r"\.sqlite(-wal|-shm)?$|\.db$"),
     "a ledger database -- it holds real transactions and account ids"),
    (re.compile(r"(?i)\.(csv|ofx|qif|mt940|camt|xlsx?)$"),
     "a statement or export format -- these are account data by definition"),
    (re.compile(r"(?i)\.(png|jpe?g|gif|webp|pdf)$"),
     "an image or PDF -- a screenshot of a bank page is not text-scannable"),
    (re.compile(r"(?i)(^|/)\.env(\.|$)|(^|/)\.op-token$"),
     "an environment or token file -- these carry credentials"),
    (re.compile(r"(?i)bank_feed.*\.sqlite|pre-migration"),
     "a ledger or a ledger snapshot"),
)


def forbidden_path(rel: str):
    """The reason `rel` may never be committed, or None."""
    for pattern, reason in FORBIDDEN_PATHS:
        if pattern.search(rel):
            return reason
    return None


def staged_files(root: pathlib.Path) -> list[str]:
    """Paths staged for commit (added, copied, modified, renamed)."""
    out = subprocess.run(
        # `T` alongside A, C, M and R. A symlink replaced by a regular file carrying an
        # account number is a TYPE CHANGE, and without `T` its record is absent from the
        # list entirely -- so the commit went through with nothing having read the file.
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMRT"],
        cwd=root, check=True, capture_output=True, text=True).stdout
    return [f for f in out.splitlines() if f]


def staged_text(root: pathlib.Path, rel: str):
    """The STAGED content of `rel` as text, or None if it is not text.

    The staged blob, not the file on disk: those differ whenever something is
    added with `git add -p` or edited after staging, and it is the staged
    bytes that are about to become a public commit.
    """
    proc = subprocess.run(["git", "show", ":" + rel], cwd=root,
                          capture_output=True)
    if proc.returncode != 0:
        return None
    try:
        return proc.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_staged(root: pathlib.Path) -> list:
    """(path, lineno, finding) for everything staged that must not be committed.

    Deliberately does NOT honour `exclude-tree:`. An exclusion says "this part
    of the published tree was reviewed and is not scanned"; it must not become
    a place new account data can be added without anyone noticing.
    """
    exceptions, unscannable_ok, _ = load_exceptions(root)
    findings = []
    for rel in staged_files(root):
        reason = forbidden_path(rel)
        if reason is not None:
            findings.append((rel, 0, "must not be committed: " + reason))
            continue
        text = staged_text(root, rel)
        if text is None:
            if rel not in unscannable_ok:
                findings.append(
                    (rel, 0, "is not text, so it cannot be checked"))
            continue
        seen = set()
        for offset, token in _valid_tokens(text):
            if token not in exceptions and token not in seen:
                seen.add(token)
                findings.append((rel, _lineno(text, offset), token))
        for view in _derived_views(text):
            for token in iban_tokens(view):
                if token not in exceptions and token not in seen:
                    seen.add(token)
                    findings.append((rel, 0, token + " (encoded or escaped)"))
    return findings


def _tracked(root: pathlib.Path) -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files"], cwd=root, check=True,
                             capture_output=True, text=True).stdout
        return [f for f in out.splitlines() if f]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return sorted(str(p.relative_to(root))
                      for p in root.rglob("*") if p.is_file())


def _is_excluded(rel: str, excluded) -> bool:
    """A directory entry ends in `/` and covers what is beneath it; anything else names
    one exact path. Never a bare string prefix -- `manifest.json` must not also cover
    `manifest.json.bak`, and an empty entry must not cover everything."""
    return any(rel.startswith(p) if p.endswith("/") else rel == p for p in excluded)


def _files(root: pathlib.Path, excluded=()) -> list[str]:
    """Every tracked file minus the DECLARED exclusions. Nothing is skipped
    that the exception file has not written down."""
    return [f for f in _tracked(root)
            if not _is_excluded(f, excluded)]


def _lineno(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan(root: pathlib.Path, exceptions=None, unscannable_ok=None,
         excluded=None) -> list:
    """(path, lineno, token) per checksum-valid identifier lacking a decision."""
    if exceptions is None or unscannable_ok is None or excluded is None:
        loaded_values, loaded_unscannable, loaded_excluded = \
            load_exceptions(root)
        if exceptions is None:
            exceptions = loaded_values
        if unscannable_ok is None:
            unscannable_ok = loaded_unscannable
        if excluded is None:
            excluded = loaded_excluded
    hits = []
    for rel in _files(root, excluded or ()):
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            if rel not in unscannable_ok:
                hits.append((rel, 1, "<undecodable>"))
            continue
        for offset, token in _valid_tokens(text):
            if token not in exceptions:
                hits.append((rel, _lineno(text, offset), token))
        for view in _derived_views(text):
            for token in iban_tokens(view):
                if token not in exceptions:
                    hits.append((rel, 0, token + " (encoded or escaped)"))
    return hits


def _main_staged(root: pathlib.Path) -> int:
    findings = scan_staged(root)
    for rel, lineno, what in findings:
        where = "%s:%d" % (rel, lineno) if lineno else rel
        print("%s: %s" % (where, what))
    if findings:
        print("\nRefusing to commit. This repository is public: an account "
              "number or a ledger committed here cannot be taken back.\n"
              "If a finding is a real identifier, replace it with a synthetic "
              "(NL00... check digits are never valid).\n"
              "If it is a file that should never be here, unstage it and add "
              "it to .gitignore.\n"
              "If it is genuinely public, add it to %s with its source."
              % EXCEPTIONS_FILE)
    return 1 if findings else 0


def _main_stdin(root: pathlib.Path) -> int:
    """Scan one blob arriving on stdin. Used by CI to check every object that
    has ever been committed, which is what "public forever" actually means."""
    exceptions, _, _ = load_exceptions(root)
    # See _main_blobs: replace, never discard. One undecodable byte used to clear the
    # whole document, and a mostly-text blob is exactly where a value hides.
    text = sys.stdin.buffer.read().decode("utf-8", "replace")
    found = sorted({t for t in iban_tokens(text) if t not in exceptions}
                   | {t for v in _derived_views(text) for t in iban_tokens(v)
                      if t not in exceptions})
    for token in found:
        print("checksum-valid identifier %s" % token)
    return 1 if found else 0


def _main_blobs(root: pathlib.Path) -> int:
    """Scan each object named on stdin as a document of ITS OWN.

    Not one concatenated document. `git cat-file --batch` joins every payload, and a
    single blob that is not valid UTF-8 -- an image, an allowlisted binary -- makes the
    whole join undecodable, which this scanner correctly reports as "nothing textual to
    find". One binary anywhere in a push therefore cleared every text blob beside it.

    Reading them here rather than spawning this program per blob keeps a push fast enough
    that nobody is tempted to skip it, which is its own kind of correctness.
    """
    exceptions, _, _ = load_exceptions(root)
    shas = [line.strip() for line in sys.stdin.read().split() if line.strip()]
    if not shas:
        return 0
    proc = subprocess.run(["git", "cat-file", "--batch"],
                          input=("\n".join(shas) + "\n").encode("ascii"),
                          capture_output=True)
    if proc.returncode != 0:
        print("could not read %d blob(s) from git; refusing rather than assuming"
              " they are clean" % len(shas))
        return 1
    found = 0
    stream = proc.stdout
    offset = 0
    for sha in shas:
        header_end = stream.find(b"\n", offset)
        if header_end == -1:
            print("truncated output from git cat-file; refusing")
            return 1
        header = stream[offset:header_end].split()
        # `<sha> missing` for an object git does not have. Skipping it would be a silent
        # pass for a blob nobody read -- the shape this whole scan exists to prevent.
        if len(header) == 2 and header[1] == b"missing":
            print("blob %s is missing from this repository; refusing rather than"
                  " assuming it is clean" % sha)
            return 1
        # A commit or tag object counts. A commit message is published text and until
        # this accepted one, an account number written in a message reached no scanner
        # at all: the deny sweep has no checksum rule, and this program was only ever
        # handed file blobs.
        if len(header) < 3 or header[1] not in (b"blob", b"commit", b"tag"):
            offset = header_end + 1
            continue
        size = int(header[2])
        body = stream[header_end + 1:header_end + 1 + size]
        offset = header_end + 1 + size + 1        # payload, then its trailing newline
        # `errors="replace"`, not a skip. Discarding the whole object on any decoding
        # error meant one stray byte beside an account number removed it from the scan,
        # and git still treats such a file as textual so nothing else refused it. A
        # replacement character cannot create a checksum-valid identifier, and it cannot
        # hide one either.
        text = body.decode("utf-8", "replace")
        hits = sorted({t for t in iban_tokens(text) if t not in exceptions}
                      | {t for v in _derived_views(text) for t in iban_tokens(v)
                         if t not in exceptions})
        for token in hits:
            print("blob %s: checksum-valid identifier %s" % (sha, token))
            found += 1
    return 1 if found else 0


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    root = pathlib.Path(args[0] if args else ".").resolve()
    if "--stdin" in argv:
        return _main_stdin(root)
    if "--blobs" in argv:
        return _main_blobs(root)
    if "--staged" in argv:
        return _main_staged(root)
    _, _, excluded = load_exceptions(root)
    # Printed on EVERY run, clean or not. An exclusion the reader never sees is
    # how "the gate exits 0" comes to mean less than it sounds.
    for prefix, reason in sorted(excluded.items()):
        n = sum(1 for f in _tracked(root) if f.startswith(prefix))
        print("not scanned: %s (%d tracked file(s)) -- %s" % (prefix, n, reason))
    hits = scan(root)
    for rel, lineno, token in hits:
        if token == "<undecodable>":
            print("%s: cannot be read as text, so it was not scanned" % rel)
        else:
            print("%s:%d: checksum-valid identifier %s" % (rel, lineno, token))
    if hits:
        print("\n%d checksum-valid identifier(s) or unscannable file(s) without"
              " a committed decision.\nReplace an identifier with a"
              " checksum-invalid synthetic, or add it to %s with a citation"
              " naming the public source. Record an unscannable path there as"
              " `%s<path>` with the reason it carries no identifier."
              % (len(hits), EXCEPTIONS_FILE, UNSCANNABLE_PREFIX))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
