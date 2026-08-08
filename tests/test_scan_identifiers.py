"""The identifier scan is the deliverable, not a list of known-bad values.

A hand-maintained list of real IBANs was wrong twice: it missed a third
valid value and three files carrying one it already knew about. Enumerating
every IBAN-shaped token and checking mod-97 cannot miss one that way.

This module needs a checksum-VALID token to prove the scan reports one, and
a checksum-valid token written as a literal is exactly what the scan exists
to forbid -- it would need an entry in the exception file, and the exception
file is for values with a citable public source, which a value invented for
a test does not have. So the valid token is COMPUTED here instead: nothing
checksum-valid is ever written to disk, and the scan's own gate stays clean.
"""
import re
import pathlib
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import scan_identifiers as si

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _with_valid_check_digits(country: str, bban: str) -> str:
    """Return the IBAN for `bban` carrying the check digits that make it valid.

    ISO 7064 mod-97-10: move country + "00" to the end, map letters to their
    two-digit values, and the check digits are 98 minus the remainder.
    """
    rearranged = bban + country + "00"
    digits = "".join(str(int(c, 36)) if c.isalpha() else c for c in rearranged)
    return "%s%02d%s" % (country, 98 - int(digits) % 97, bban)


#: Valid by construction, never a real account -- the body is the same all-zero
#: synthetic shape the fixtures use, only with correct check digits.
VALID = _with_valid_check_digits("NL", "REVO0000000001")

#: A 16-character valid value (Belgian length). Length matters: the matcher
#: joins groups of four, so a trailing label absorbs into the run only when the
#: value's length is a multiple of four. The 18-character NL value above is
#: never absorbed, so a greedy-absorption test written with it stays green
#: even with the fix removed.
VALID_ALIGNED = _with_valid_check_digits("BE", "539000000034")

#: The convention for fixtures: `00` check digits, which mod-97 can never
#: produce (a valid remainder yields 02-98), so a fixture cannot silently
#: become a real account.
SYNTHETIC = "NL00REVO0000000001"


class Mod97(unittest.TestCase):
    def test_a_valid_iban_has_remainder_one(self):
        self.assertEqual(si.mod97(VALID), 1)

    def test_a_synthetic_iban_does_not(self):
        self.assertNotEqual(si.mod97(SYNTHETIC), 1)

    def test_zero_check_digits_are_never_valid(self):
        # NL00 is the marker this repo uses for synthetic fixtures; the point
        # is that it can never accidentally become a real account.
        for body in ("REVO0000000001", "ABNA0000000002", "RABO0000000003"):
            self.assertNotEqual(si.mod97("NL00" + body), 1)

    def test_the_computed_check_digits_are_not_the_synthetic_marker(self):
        # Guards the helper itself: if it ever returned "00" the valid-token
        # tests above would be asserting nothing.
        self.assertNotEqual(VALID[2:4], "00")


class Tokens(unittest.TestCase):
    def test_plain_token_is_found(self):
        self.assertEqual(si.iban_tokens("iban %s here" % VALID), [VALID])

    def test_spaced_form_is_found_and_normalized(self):
        # A naive matcher misses the grouped form banks actually print.
        text = " ".join(VALID[i:i + 4] for i in range(0, len(VALID), 4))
        self.assertEqual(si.iban_tokens(text), [VALID])

    def test_lowercase_form_is_found_and_normalized(self):
        self.assertEqual(si.iban_tokens(VALID.lower()), [VALID])

    def test_a_checksum_invalid_value_is_not_a_token(self):
        # `iban_tokens` reports only checksum-valid values: the separator class
        # is broad enough that an invalid run says nothing on its own.
        self.assertEqual(si.iban_tokens("iban %s here" % SYNTHETIC), [])

    def test_a_bare_word_is_not_a_token(self):
        self.assertEqual(si.iban_tokens("NOTANIBAN and ABCD"), [])


class Renderings(unittest.TestCase):
    """Every rendering a checksum-valid value can take and still be read back.

    The first version of the scan matched one line at a time, required a word
    boundary, and allowed only a space between groups. Files
    carrying VALID in several of these shapes and the gate exited 0 on all of
    them. Each case below is one of those shapes; a matcher that loses any of
    them reports clean over a real account number.
    """

    def _found(self, text):
        """Through scan(), because scan() is the gate.

        Replacing the whole-file scan with a line-at-a-time one and
        every test here stayed green: they called `iban_tokens`, which reads
        whatever string it is handed, while the bypass lived in how `scan`
        feeds it. A test of a helper is not a test of a gate.
        """
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.txt").write_text(text)
            return [h[2] for h in si.scan(root, exceptions=set(),
                                          unscannable_ok=set(), excluded={})]

    def test_plain(self):
        self.assertEqual(self._found(VALID), [VALID])

    def test_space_grouped(self):
        text = " ".join(VALID[i:i + 4] for i in range(0, len(VALID), 4))
        self.assertEqual(self._found(text), [VALID])

    def test_hyphen_grouped(self):
        text = "-".join(VALID[i:i + 4] for i in range(0, len(VALID), 4))
        self.assertEqual(self._found(text), [VALID])

    def test_typographic_dash_grouped(self):
        # A document that has been through a word processor or a Markdown
        # renderer carries en and em dashes, not the ASCII hyphen every other
        # test here uses -- so the ASCII case passing says nothing about these.
        for dash in ("\u2010", "\u2011", "\u2012", "\u2013", "\u2014",
                     "\u2015"):
            text = dash.join(VALID[i:i + 4] for i in range(0, len(VALID), 4))
            self.assertEqual(self._found(text), [VALID], repr(dash))

    def test_split_across_two_lines(self):
        text = VALID[:8] + "\n" + VALID[8:]
        self.assertEqual(self._found(text), [VALID])

    def test_preceded_by_an_underscore(self):
        # `_` is a word character, so `\b` never fires against it and the
        # boundary-anchored matcher could not see this at all.
        self.assertEqual(self._found("iban_" + VALID), [VALID])

    def test_followed_by_an_underscore(self):
        self.assertEqual(self._found(VALID + "_field"), [VALID])

    def test_lowercase(self):
        self.assertEqual(self._found(VALID.lower()), [VALID])

    def test_inside_json(self):
        self.assertEqual(self._found('{"iban": "%s"}' % VALID), [VALID])

    def test_inside_a_url_path(self):
        self.assertEqual(self._found("https://x/a/%s?q=1" % VALID), [VALID])

    def test_a_non_breaking_space_between_groups(self):
        # U+00A0 is what a value pasted out of a bank's web page carries, and
        # it is invisible in every editor.
        text = "\u00a0".join(VALID[i:i + 4] for i in range(0, len(VALID), 4))
        self.assertEqual(self._found(text), [VALID])

    def test_zero_width_characters_between_characters(self):
        for zw in ("\u200b", "\u200c", "\u200d", "\ufeff"):
            text = zw.join(VALID)
            self.assertEqual(self._found(text), [VALID], repr(zw))

    def test_double_spaced_grouping(self):
        text = "  ".join(VALID[i:i + 4] for i in range(0, len(VALID), 4))
        self.assertEqual(self._found(text), [VALID])

    def test_delimiter_separated(self):
        for sep in (".", ",", "/", "_"):
            text = sep.join(VALID[i:i + 4] for i in range(0, len(VALID), 4))
            self.assertEqual(self._found(text), [VALID], sep)

    def test_a_value_that_is_not_at_the_start_of_its_run(self):
        # A prefix-only check never looks past its own head. Every offset,
        # not one: a single four-character prefix leaves a matcher that only
        # handles four-character offsets green.
        for prefix in ("x", "xx", "xy9", "XX99", "abcdefg", "a" * 13,
                       "0", "9z", "deadbeef"):
            self.assertEqual(self._found(prefix + VALID), [VALID], prefix)

    def test_a_value_wrapped_mid_group_across_lines(self):
        for cut in range(1, len(VALID)):
            self.assertEqual(self._found(VALID[:cut] + "\n" + VALID[cut:]),
                             [VALID], cut)

    def test_a_bare_word_is_still_not_a_token(self):
        self.assertEqual(si.iban_tokens("NOTANIBAN and ABCD"), [])


class GreedyAbsorption(unittest.TestCase):
    """A trailing word of the right length must not hide the value before it.

    The matcher is greedy, so a valid IBAN followed by a label matched as ONE
    long run; the run failed mod-97 and the account number at its head was
    never tested. It is demonstrable with a real Belgian IBAN and the
    gate exited 0.
    """

    def _scanned(self, body):
        """Through scan(), not iban_tokens(): replacing
        the whole-file scan with a line-at-a-time one left every scanner test
        green, because the tests exercised the helper and the gate is scan()."""
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.txt").write_text(body)
            return [h[2] for h in si.scan(root, exceptions=set(),
                                          unscannable_ok=set(), excluded={})]

    def test_an_aligned_value_with_a_trailing_label(self):
        # 16 characters + a 4-character label: the run the matcher builds is a
        # clean multiple of four, so the label really is absorbed. This is the
        # case that goes red when substring enumeration is removed.
        self.assertEqual(self._scanned(VALID_ALIGNED + " spaar"),
                         [VALID_ALIGNED])

    def test_an_aligned_value_with_labels_of_every_length(self):
        for n in range(1, 13):
            self.assertEqual(self._scanned(VALID_ALIGNED + " " + "a" * n),
                             [VALID_ALIGNED], n)

    def test_an_aligned_value_with_a_leading_token(self):
        self.assertEqual(self._scanned("ref99 " + VALID_ALIGNED),
                         [VALID_ALIGNED])

    def test_a_trailing_label_does_not_hide_an_unaligned_value_either(self):
        for label in ("huishouden", "spaar", "abcd", "x", "12345678"):
            self.assertEqual(self._scanned(VALID + " " + label), [VALID], label)

    def test_a_run_with_no_valid_substring_yields_nothing(self):
        self.assertEqual(self._scanned(SYNTHETIC + " huishouden"), [])


class ExceptionCitations(unittest.TestCase):
    """An entry with no citation is refused, not quietly honoured.

    The file promises every value names the public source it comes from. A
    promise nothing enforces is how an uncited value gets in.
    """

    def _write(self, root, body):
        (root / "scripts").mkdir(exist_ok=True)
        (root / si.EXCEPTIONS_FILE).write_text(body)

    def test_an_uncited_entry_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self._write(root, VALID + "\n")
            with self.assertRaises(ValueError) as ctx:
                si.load_exceptions(root)
            self.assertIn("no citation", str(ctx.exception))

    def test_a_cited_entry_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self._write(root, "%s  # ISO 13616 published example\n" % VALID)
            values, _, _ = si.load_exceptions(root)
            self.assertEqual(values, {VALID})

    def test_a_comment_only_line_is_not_an_entry(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self._write(root, "# just a comment\n\n")
            self.assertEqual(si.load_exceptions(root), (set(), set(), {}))

    def test_an_uncited_unscannable_path_is_refused_too(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self._write(root, si.UNSCANNABLE_PREFIX + "blob.bin\n")
            with self.assertRaises(ValueError):
                si.load_exceptions(root)


class Base64(unittest.TestCase):
    def test_an_encoded_identifier_is_reported(self):
        import base64
        blob = base64.b64encode(('{"iban": "%s"}' % VALID).encode()).decode()
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.json").write_text('{"payload": "%s"}\n' % blob)
            hits = si.scan(root, exceptions=set(), unscannable_ok=set(), excluded={})
            self.assertTrue(any(VALID in h[2] for h in hits), hits)

    def test_an_encoded_synthetic_is_not_reported(self):
        import base64
        blob = base64.b64encode(('{"iban": "%s"}' % SYNTHETIC).encode()).decode()
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.json").write_text('{"payload": "%s"}\n' % blob)
            self.assertEqual(
                si.scan(root, exceptions=set(), unscannable_ok=set(), excluded={}), [])


class Escaped(unittest.TestCase):
    """A value written through an escaping scheme is still the value."""

    def _scan_text(self, body, name="f.txt"):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / name).write_text(body)
            return si.scan(root, exceptions=set(), unscannable_ok=set(),
                           excluded={})

    def test_a_percent_escaped_value_is_reported(self):
        body = "".join("%%%02X" % ord(c) for c in VALID)
        self.assertTrue(any(VALID in h[2] for h in self._scan_text(body)))

    def test_a_partly_percent_escaped_value_is_reported(self):
        body = "%4E%4C" + VALID[2:]
        self.assertTrue(any(VALID in h[2] for h in self._scan_text(body)))

    def test_a_backslash_u_escaped_value_is_reported(self):
        body = "".join("\\u%04x" % ord(c) for c in VALID)
        self.assertTrue(any(VALID in h[2] for h in self._scan_text(body)))

    def test_a_synthetic_written_the_same_way_is_not_reported(self):
        body = "".join("%%%02X" % ord(c) for c in SYNTHETIC)
        self.assertEqual(self._scan_text(body), [])


    def test_a_value_hidden_by_a_source_level_escape_is_reported(self):
        # The shape that survived every earlier pass: in a Python source file
        # `"NL91ABNA\\n0417164300"` reads as backslash-n in the FILE TEXT, which
        # breaks the run, while the runtime string is the account number. It
        # sat in the suite from the beginning and no matcher over file text
        # could see it.
        body = 'for bad in ("%s\\n%s",):\n    pass\n' % (VALID[:8], VALID[8:])
        self.assertTrue(any(VALID in h[2] for h in self._scan_text(body, "t.py")),
                        body)


class NestedEncoding(unittest.TestCase):
    """One layer of base64, in the renderings a payload really takes."""

    def _scan_blob(self, blob):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.txt").write_text(blob + "\n")
            return [h[2] for h in si.scan(root, exceptions=set(),
                                          unscannable_ok=set(), excluded={})]

    def _payload(self, pad=90):
        # Long enough that a 76-column wrap actually splits it.
        return ('{"iban":"%s","note":"%s"}' % (VALID, "x" * pad)).encode()

    def _decode_prefix(self, chunk):
        import base64, binascii
        for n in range(len(chunk), 0, -1):
            try:
                return base64.b64decode(
                    chunk[:n] + "=" * (-n % 4), validate=True).decode(
                        "utf-8", "replace")
            except (binascii.Error, ValueError):
                continue
        return ""

    def test_a_url_safe_encoded_value_is_reported(self):
        # The fixture must actually CONTAIN a URL-safe-only character, or
        # removing URL-safe support leaves this green: standard and URL-safe
        # base64 differ in two characters and most payloads use neither.
        import base64
        # Search for a payload whose encoding actually uses index 62 or 63 --
        # the only two characters where the alphabets differ. Non-ASCII text
        # is what reaches them; plain ASCII JSON almost never does.
        payload = blob = None
        for cp in range(0x80, 0x2000):
            candidate = ('{"iban":"%s","n":"%s"}'
                         % (VALID, chr(cp) * 8)).encode()
            encoded = base64.urlsafe_b64encode(candidate).decode()
            if "-" in encoded or "_" in encoded:
                payload, blob = candidate, encoded
                break
        if blob is None:
            self.fail("could not construct a URL-safe-distinct fixture")
        self.assertNotEqual(blob, base64.b64encode(payload).decode(),
                            "the fixture must differ between the alphabets, "
                            "or dropping URL-safe support leaves this green")
        self.assertTrue(any(VALID in h for h in self._scan_blob(blob)))

    def test_a_mime_wrapped_encoded_value_is_reported(self):
        # The identifier must STRADDLE a wrap, or a contiguous-only matcher
        # decodes the first line alone and stays green.
        import base64, textwrap
        for lead in range(0, 120, 3):
            payload = ('{"lead":"%s","iban":"%s"}' % ("x" * lead, VALID)).encode()
            std = base64.b64encode(payload).decode()
            first = std[:76]
            decoded_first = self._decode_prefix(first)
            if len(std) > 76 and VALID not in decoded_first:
                break
        else:
            self.fail("could not construct a straddling fixture")
        wrapped = "\n".join(textwrap.wrap(std, 76))
        self.assertNotIn(VALID, decoded_first)
        self.assertTrue(any(VALID in h for h in self._scan_blob(wrapped)))

    def _decode_prefix(self, chunk):
        import base64, binascii
        for n in range(len(chunk), 0, -1):
            try:
                return base64.b64decode(
                    chunk[:n] + "=" * (-n % 4), validate=True).decode(
                        "utf-8", "replace")
            except (binascii.Error, ValueError):
                continue
        return ""

    def test_a_wrapped_synthetic_is_not_reported(self):
        import base64, textwrap
        payload = ('{"iban":"%s","note":"%s"}' % (SYNTHETIC, "x" * 90)).encode()
        std = base64.b64encode(payload).decode()
        self.assertEqual(self._scan_blob("\n".join(textwrap.wrap(std, 76))), [])

    def test_a_word_in_front_of_an_encoded_value_does_not_hide_it(self):
        """A run matcher that joins across whitespace swallows the preceding
        word, the enlarged run decodes to nothing usable, and the value is
        never seen -- a real identifier hides behind the word `junk`.
        """
        import base64
        blob = base64.b64encode(self._payload()).decode()
        for lead in ("junk", "payload", "x", "the quick brown fox jumped",
                     "AAAA", "data:"):
            body = lead + " " + blob
            self.assertTrue(any(VALID in h for h in self._scan_blob(body)),
                            "hidden behind %r" % lead)

    def test_a_word_after_an_encoded_value_does_not_hide_it(self):
        import base64
        blob = base64.b64encode(self._payload()).decode()
        for trail in ("junk", "trailing", "AAAA"):
            self.assertTrue(
                any(VALID in h for h in self._scan_blob(blob + " " + trail)),
                "hidden behind %r" % trail)

    def test_a_word_in_front_of_a_wrapped_value_does_not_hide_it(self):
        import base64, textwrap
        blob = base64.b64encode(self._payload(pad=200)).decode()
        body = "junk\n" + "\n".join(textwrap.wrap(blob, 76))
        self.assertTrue(any(VALID in h for h in self._scan_blob(body)))

    def _scanned(self, body):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.txt").write_text(body)
            return [h[2] for h in si.scan(root, exceptions=set(),
                                          unscannable_ok=set(), excluded={})]

    def test_one_layer_of_base64_is_covered(self):
        import base64
        blob = base64.b64encode(
            ('{"iban":"%s"}' % VALID).encode()).decode()
        self.assertTrue(any(VALID in h for h in self._scanned(blob)))

    def test_source_level_escaping_is_covered(self):
        # The case that was real: a broken run in the file text and the account
        # number at run time.
        body = 'bad = "%s\\n%s"\n' % (VALID[:8], VALID[8:])
        self.assertTrue(any(VALID in h for h in self._scanned(body)))

    def test_two_layers_of_encoding_are_NOT_covered_and_that_is_the_scope(self):
        import base64
        once = base64.b64encode(('{"iban":"%s"}' % VALID).encode()).decode()
        twice = base64.b64encode(once.encode()).decode()
        self.assertEqual(self._scanned(twice), [],
                         "if this starts passing, the scope changed -- decide "
                         "that deliberately and update the module docstring")

    def test_the_docstring_states_the_limit(self):
        self.assertIn("NOT an adversary detector", si.__doc__)


class DeclaredExclusions(unittest.TestCase):
    """A subtree the scan skips must be written down, not hardcoded.

    An earlier version skipped the design directory in silence. That directory
    holds dozens of checksum-valid identifiers, so the gate exited 0 while
    tracked files carried real account numbers.
    """

    def test_nothing_is_excluded_unless_declared(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "docs").mkdir()
            (root / "docs" / "superpowers").mkdir()
            (root / "docs" / "superpowers" / "s.md").write_text(VALID + "\n")
            hits = si.scan(root, exceptions=set(), unscannable_ok=set(),
                           excluded={})
            self.assertEqual([h[2] for h in hits], [VALID],
                             "no path is skipped by default")

    def test_a_declared_exclusion_is_honoured(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "docs").mkdir()
            (root / "docs" / "superpowers").mkdir()
            (root / "docs" / "superpowers" / "s.md").write_text(VALID + "\n")
            hits = si.scan(root, exceptions=set(), unscannable_ok=set(),
                           excluded={"docs/superpowers/": "declared"})
            self.assertEqual(hits, [])

    def test_an_uncited_exclusion_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "scripts").mkdir()
            (root / si.EXCEPTIONS_FILE).write_text(
                si.EXCLUDE_PREFIX + "docs/superpowers/\n")
            with self.assertRaises(ValueError):
                si.load_exceptions(root)

    def test_every_exclusion_this_repository_declares_carries_a_reason(self):
        _, _, excluded = si.load_exceptions(
            pathlib.Path(__file__).resolve().parents[1])
        self.assertEqual(sorted(excluded),
                         ["manifest.json", "persona/manifest.json"])
        for prefix, reason in excluded.items():
            self.assertTrue(reason.strip(), prefix)


class Undecodable(unittest.TestCase):
    """A file the scan cannot read is an unanswered question, not a pass."""

    def test_an_undecodable_file_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "blob.bin").write_bytes(b"\xff\xfe\x00\x01binary")
            hits = si.scan(root, exceptions=set(), unscannable_ok=set(), excluded={})
            self.assertEqual([(h[0], h[2]) for h in hits],
                             [("blob.bin", "<undecodable>")])

    def test_an_undecodable_file_with_a_recorded_decision_is_not_reported(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "blob.bin").write_bytes(b"\xff\xfe\x00\x01binary")
            self.assertEqual(
                si.scan(root, exceptions=set(), unscannable_ok={"blob.bin"}, excluded={}), [])


class Scan(unittest.TestCase):
    def test_valid_token_without_an_exception_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.txt").write_text(VALID + "\n")
            hits = si.scan(root, exceptions=set(), unscannable_ok=set(), excluded={})
            self.assertEqual([(h[0], h[2]) for h in hits], [("f.txt", VALID)])

    def test_the_reported_line_number_is_the_line_the_value_starts_on(self):
        # Reported from a whole-file offset now, not a per-line loop, so this
        # is the assertion that keeps the offset arithmetic honest.
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.txt").write_text("a\nb\nc\n" + VALID + "\n")
            hits = si.scan(root, exceptions=set(), unscannable_ok=set(), excluded={})
            self.assertEqual([(h[0], h[1]) for h in hits], [("f.txt", 4)])

    def test_valid_token_with_an_exception_is_not_reported(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.txt").write_text(VALID + "\n")
            hits = si.scan(root, exceptions={VALID}, unscannable_ok=set(), excluded={})
            self.assertEqual(hits, [])

    def test_invalid_token_is_never_reported(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.txt").write_text(SYNTHETIC + "\n")
            self.assertEqual(si.scan(root, exceptions=set(), unscannable_ok=set(), excluded={}), [])


class NationalStructure(unittest.TestCase):
    """Length alone lets a run of HEX spell an account number.

    A commit object is mostly hex -- `tree <sha>`, `parent <sha>` -- and hex uses
    a-f, so AD, AE, BA, BE, DE and EE are spellable by accident. `.githooks/pre-push`
    feeds raw commit objects to this scanner, so before the structure check about one
    commit object in 117 carried a checksum-valid token and refused the push. There
    was no remedy: a random substring of a sha has no public source to cite in the
    exception file, and a commit object cannot be excluded by path.

    The asset here is BOTH directions. Narrowing a scan is how it stops finding
    things, so every case below that removes a false positive is paired with one
    proving a real identifier is still reported.
    """

    #: The exact token that refused a push, taken from the failure. `EE` at
    #: Estonia's registered length of 20, checksum-valid, and impossible: Estonia's
    #: BBAN is sixteen digits and this one carries `F` and `D`.
    HEX_COLLISION = "EE5949859FD11189FD34"

    def test_the_hex_collision_is_checksum_valid_and_still_not_reported(self):
        """Both halves matter. If it were not checksum-valid the case would pass
        for the wrong reason and would keep passing with the structure check gone."""
        self.assertEqual(si.mod97(self.HEX_COLLISION), 1, "premise: it IS checksum-valid")
        self.assertEqual(len(self.HEX_COLLISION), si.IBAN_LENGTHS["EE"])
        self.assertEqual(si.iban_tokens(self.HEX_COLLISION), [])

    def test_a_real_identifier_is_still_reported_in_every_structure_shape(self):
        """The other direction, across the three BBAN shapes: all-numeric,
        letters-then-digits, and free alphanumeric. A structure table that silenced
        any of these would be worse than the false positive it removed."""
        # COMPUTED, never written out. A checksum-valid value typed into this file
        # is a finding in this repository's own tree -- the scan reported exactly
        # that when these four were literals, which is the rule working.
        for value in (VALID,                                          # NL, letters
                      VALID_ALIGNED,                                  # BE, all digits
                      _with_valid_check_digits("AD", "00080001" + "0" * 8 + "1234"),
                      _with_valid_check_digits("GB", "ZZZZ" + "0" * 6 + "1" * 8)):
            with self.subTest(value=value):
                self.assertEqual(si.iban_tokens("account %s here" % value), [value])

    def test_an_all_numeric_country_is_not_silenced_wholesale(self):
        """Belgium is the country that killed the obvious fix. An earlier attempt
        excluded long hex runs and hid a real Belgian IBAN, because a Belgian BBAN
        is entirely digits and digits are hex. The structure rule must reject the
        LETTERS, never the country."""
        self.assertEqual(si.iban_tokens(VALID_ALIGNED), [VALID_ALIGNED])
        letters = VALID_ALIGNED[:4] + "A" + VALID_ALIGNED[5:]
        self.assertEqual(si.iban_tokens(letters), [],
                         "a letter in an all-numeric BBAN is not an account number")

    def test_a_country_with_no_declared_structure_falls_back_to_length(self):
        """FAILS OPEN, per country. A wrong pattern would stop reporting real
        account numbers, which is the one error this scanner must never make -- so
        an absent country is checked on length alone, exactly as before."""
        removed = dict(si.IBAN_BBAN)
        removed.pop("EE")
        with unittest.mock.patch.object(si, "IBAN_BBAN", removed):
            self.assertEqual(si.iban_tokens(self.HEX_COLLISION), [self.HEX_COLLISION],
                             "without a declared structure it is length-checked only")

    def test_the_table_is_regenerated_from_its_committed_evidence(self):
        """The table only agreeing with ITSELF is not evidence.

        `scripts/iban-registry.txt` carries the registry notation each pattern was
        generated from and a real published example BBAN for each country. This
        regenerates IBAN_BBAN from that notation and refuses any disagreement, so a
        character class cannot be edited -- or mis-generated -- without the evidence
        moving with it. Review found the original change asserting these checks in a
        commit message while shipping neither the inputs nor a way to repeat them."""
        classes = {"n": "[0-9]", "a": "[A-Z]", "c": "[0-9A-Z]"}
        rows = 0
        for line in (ROOT / "scripts" / "iban-registry.txt").read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            country, notation, example = line.split()
            rows += 1
            with self.subTest(country=country):
                fields = re.findall(r"(\d+)!?([nac])", notation)
                self.assertEqual("".join(f"{n}!{k}" for n, k in fields), notation,
                                 "the notation did not parse cleanly")
                expected = "".join(f"{classes[k]}{{{n}}}" for n, k in fields)
                self.assertEqual(si.IBAN_BBAN.get(country), expected,
                                 "IBAN_BBAN disagrees with its committed evidence")
                width = sum(int(n) for n, _ in fields)
                self.assertEqual(width + 4, si.IBAN_LENGTHS[country],
                                 "notation width disagrees with the registered length")
                if example != "-":
                    self.assertRegex(example, f"^{expected}$",
                                     "a REAL published example fails its own pattern")
        self.assertEqual(rows, len(si.IBAN_BBAN),
                         "every enforced country needs committed evidence, and vice versa")

    def test_every_declared_structure_agrees_with_the_declared_length(self):
        """The table is generated, and two generated tables that disagree are worse
        than one. A pattern whose fields do not sum to the registered length would
        reject every real identifier for that country."""
        for country, pattern in sorted(si.IBAN_BBAN.items()):
            with self.subTest(country=country):
                self.assertIn(country, si.IBAN_LENGTHS,
                              "a structure for a country the scanner does not know")
                width = sum(int(n) for n in re.findall(r"\{(\d+)\}", pattern))
                self.assertEqual(width + 4, si.IBAN_LENGTHS[country])


class ProseIsNotAnIdentifier(unittest.TestCase):
    """Ordinary prose passes mod-97 about one time in ninety-seven.

    Reaching values padded by alphanumerics once cost 185 false positives on
    this tree, and a gate nobody reads catches nothing. A candidate in a
    country the registry does not list must be delimited AND written
    compactly, which prose never is.
    """

    def test_the_repository_itself_is_clean(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        self.assertEqual(si.scan(root), [],
                         "a false positive here is not cosmetic: the gate "
                         "stops being read")

    def test_a_checksum_valid_prose_run_is_not_reported(self):
        # Constructed, not hypothetical: this exact shape appeared in the
        # scanner's own docstring and the gate reported it.
        body = "encodes to 24 characters, so 24 is the shortest run\n"
        self.assertEqual(
            [h for h in si.scan(self._tmp(body), exceptions=set(),
                                unscannable_ok=set(), excluded={})],
            [])

    def test_the_generated_manifests_are_excluded_not_special_cased(self):
        """Digests are high-entropy hex, so every recompute has a fresh chance
        of containing a checksum-valid substring at some registered length --
        one duly did. The answer is the declared-exclusion mechanism that
        already exists and prints itself, not a rule about hex runs: the rule
        that was tried excluded long hex runs and hid a real Belgian IBAN,
        because Belgian IBANs are entirely hexadecimal."""
        _, _, excluded = si.load_exceptions(
            pathlib.Path(__file__).resolve().parents[1])
        self.assertIn("manifest.json", excluded)
        self.assertIn("persona/manifest.json", excluded)

    def test_a_belgian_iban_in_hex_padding_is_still_reported(self):
        # The bypass the removed rule created, pinned so it cannot come back.
        self.assertTrue(all(c in "0123456789abcdefABCDEF"
                            for c in VALID_ALIGNED))
        for body in ("deadbeef" + VALID_ALIGNED + "a" * 40,
                     "sha256:" + VALID_ALIGNED + "a" * 40):
            hits = si.scan(self._tmp(body + "\n"), exceptions=set(),
                           unscannable_ok=set(), excluded={})
            self.assertEqual([h[2] for h in hits], [VALID_ALIGNED], body[:20])

    def test_the_length_table_is_the_registry_and_not_a_wider_list(self):
        """Coverage is not free. Each country here is matched in EVERY
        rendering, so a two-letter code that is not really in the scheme is
        pure noise -- adding twenty-two of them made twenty-two ordinary
        sentences scan as account numbers."""
        self.assertEqual(len(si.IBAN_LENGTHS), 89)
        for absent in ("NE", "MA", "SN", "IR", "DZ", "CM"):
            self.assertNotIn(absent, si.IBAN_LENGTHS, absent)
        for present, length in (("NL", 18), ("BE", 16), ("ES", 24),
                                ("NO", 15), ("RU", 33)):
            self.assertEqual(si.IBAN_LENGTHS[present], length, present)

    def test_prose_starting_with_an_unlisted_code_is_not_reported(self):
        """One shape per extra country, of which a wider list has twenty-two."""
        for code in ("NE", "MA", "SN", "IR", "DZ", "CM", "TG", "ML"):
            body = ("%s 12-day correction still corroborates the window\n"
                    % code)
            hits = si.scan(self._tmp(body), exceptions=set(),
                           unscannable_ok=set(), excluded={})
            self.assertEqual(hits, [], code)

    def test_there_is_no_way_to_exempt_a_value_without_citing_a_source(self):
        """A softer marker was tried -- "this is prose, not an account number"
        -- and it took an arbitrary reason and no verifiable basis, so any real
        account number could be silenced by asserting it was prose. A false
        positive is answered by rewording the prose."""
        self.assertFalse(hasattr(si, "NOT_AN_IDENTIFIER_PREFIX"))
        text = (pathlib.Path(__file__).resolve().parents[1]
                / si.EXCEPTIONS_FILE).read_text()
        self.assertNotIn("not-an-identifier", text)

    def test_an_unregistered_country_is_not_reported_and_that_is_the_rule(self):
        """An IBAN exists only for a registered country. Reporting values with
        unassigned prefixes is what let a PEM body and a hash digest through:
        both are compact alphanumeric runs, so the layout rule alone passes
        them, and about one in ninety-seven satisfies mod-97."""
        unlisted = _with_valid_check_digits("ZZ", "REVO0000000001")
        self.assertNotIn("ZZ", si.IBAN_LENGTHS)
        self.assertEqual(
            si.scan(self._tmp("iban " + unlisted + "\n"), exceptions=set(),
                    unscannable_ok=set(), excluded={}), [])

    def test_a_pem_body_is_not_reported(self):
        # Concretely: tests/fixtures carries PEM keys, and their base64 bodies
        # are exactly this shape.
        import base64, hashlib
        body = "\n".join(
            base64.b64encode(hashlib.sha256(bytes([i])).digest()).decode()
            for i in range(40))
        self.assertEqual(
            si.scan(self._tmp(body), exceptions=set(), unscannable_ok=set(),
                    excluded={}), [])

    def _tmp(self, body):
        d = tempfile.mkdtemp()
        root = pathlib.Path(d)
        (root / "f.txt").write_text(body)
        return root


if __name__ == "__main__":
    unittest.main()
