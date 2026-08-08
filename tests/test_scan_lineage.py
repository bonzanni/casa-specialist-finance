"""The lineage scan is the gate for removing private development lineage.

The identifier gate that came before this one shipped with four demonstrated
bypasses -- a value split across two lines, hyphen-grouped, underscore-prefixed,
or base64-encoded all passed it silently. The lesson generalizes: a gate is
worth only what it catches when nobody is thinking about it, so each category
below is tested against the renderings it will actually meet, including inside a
docstring, inside a test name, and separated by an underscore rather than a
space.

The negative tests matter as much as the positive ones. This tree contains a
rule-reference fixture `ref="R1"` in 174 places and cites `RFC 9110 §10.2.3`
twice; a gate that reported those would be a list nobody reads.
"""
import contextlib
import io
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import scan_lineage as sl


class Categories(unittest.TestCase):
    def test_every_category_has_a_committed_pattern(self):
        self.assertEqual(
            sorted(sl.CATEGORIES),
            ["decision_code", "private_spec", "review_round", "reviewer",
             "ruling", "severity", "task_number", "work_slice"])

    def test_a_private_spec_section_is_found(self):
        for text in ("see spec §8.1 here", "design §7", "§13; and", "§8/§8.1"):
            self.assertTrue(sl.CATEGORIES["private_spec"].search(text), text)

    def test_a_reference_to_the_private_brief_is_found(self):
        for text in ("the brief's own tests", "The brief shipped a list",
                     "left as the brief specifies"):
            self.assertTrue(sl.CATEGORIES["private_spec"].search(text), text)

    def test_an_ordinary_use_of_brief_is_not_a_hit(self):
        # "a brief window" is English. So is "Brief-literal". Matching them
        # would flag legitimate prose to catch a citation.
        for text in ("a brief window exists", "Brief-literal and recorded",
                     "after a brief pause"):
            self.assertIsNone(sl.CATEGORIES["private_spec"].search(text), text)

    def test_the_codebases_own_vocabulary_is_not_a_hit(self):
        # `Plan` is the type `ingest` hands `apply`; "the report" is what a tool
        # returns to the operator. Both were audited and deliberately excluded:
        # gating them would flag ~28 legitimate sites to catch three.
        for text in ("underneath the plan between two reads",
                     "the plan is inconsistent",
                     "silently vanishing from the report"):
            self.assertIsNone(sl.CATEGORIES["private_spec"].search(text), text)

    def test_a_task_number_is_found(self):
        for text in ("Task 10 owns this", "task 2b", "test_task_17_shape"):
            self.assertTrue(sl.CATEGORIES["task_number"].search(text), text)

    def test_a_task_shaped_identifier_is_not_a_hit(self):
        # `tasks[0]`, `task_id=1` and `taskset2` are code, not lineage.
        for text in ("tasks[0]", "task_id=1", "taskset2"):
            self.assertIsNone(sl.CATEGORIES["task_number"].search(text), text)

    def test_a_reviewer_name_is_found_in_either_case(self):
        for text in ("sol P0", "terra found", "Sol and Terra", "(sol/terra P1)",
                     "both reviewers asked", "the reviewer looks"):
            self.assertTrue(sl.CATEGORIES["reviewer"].search(text), text)

    def test_a_bare_word_containing_a_reviewer_name_is_not_a_hit(self):
        # "solid", "console", "terraform" must not match, or the gate becomes
        # noise nobody reads. `needs_review` is a real column in this schema.
        for text in ("solid ground", "the console", "terraform state",
                     "resolution", "absolute", "needs_review = 1"):
            self.assertIsNone(sl.CATEGORIES["reviewer"].search(text), text)

    def test_a_review_round_is_found(self):
        for text in ("round 4", "review round 1", "rounds 1-3",
                     "test_fix_round_1_shape"):
            self.assertTrue(sl.CATEGORIES["review_round"].search(text), text)

    def test_a_severity_label_is_found_only_as_a_label(self):
        self.assertTrue(sl.CATEGORIES["severity"].search("sol P0 #6"))
        self.assertTrue(sl.CATEGORIES["severity"].search("(P2), granted"))
        # A determiner in front means the token is being used as a noun.
        for text in ("the P0 postcode", "a P1 district", "this P3 form"):
            self.assertIsNone(sl.CATEGORIES["severity"].search(text), text)

    def test_a_worded_severity_label_is_found(self):
        # The arm the first version of this scan lacked: 48 sites in 11 files
        # carried these and the gate still exited 0.
        for text in ("Review Minor 2: this asserted", "MAJOR 3 -- the range is",
                     "Fix round 3, NEW CRITICAL 2", "IMPORTANT 4 (amount arm)",
                     "Task 17 review, MINOR 1"):
            self.assertTrue(sl.CATEGORIES["severity"].search(text), text)

    def test_an_ordinary_lowercase_adjective_is_not_a_severity_label(self):
        # "a minor 2-day gap" is prose. The worded arm needs an initial capital.
        for text in ("a minor 2-day gap", "one critical 3-hour window",
                     "an important 4th case"):
            self.assertIsNone(sl.CATEGORIES["severity"].search(text), text)

    def test_a_decision_code_is_found(self):
        for text in ("(D3)", "E7", "T14-b", "M1", "F4", "C1: a fetched row",
                     "T11-a (carried forward)"):
            self.assertTrue(sl.CATEGORIES["decision_code"].search(text), text)

    def test_a_rule_reference_is_not_read_as_a_decision_code(self):
        # `ref="R1"` is a rule id in this project's own test data and appears
        # 174 times. R-coded findings always share a line with a reviewer name
        # or another code, so dropping R from the letter set loses no site and
        # removes the largest false-positive source in the tree.
        for text in ('ref="R1"', 'ref="R2", rid=4', "R4"):
            self.assertIsNone(sl.CATEGORIES["decision_code"].search(text), text)

    def test_a_ruling_is_found_however_it_is_worded(self):
        for text in ("Operator ruling 2026-08-06", "Ruling review, sol/terra",
                     "The earlier ruling refused", "the tombstone ruling"):
            self.assertTrue(sl.CATEGORIES["ruling"].search(text), text)

    def test_a_work_slice_is_found(self):
        for text in ("slice 2", "slices 1-3", "Slice 3 adds"):
            self.assertTrue(sl.CATEGORIES["work_slice"].search(text), text)

    def test_a_public_issue_reference_is_not_a_hit_in_any_category(self):
        # Issue references are public and stay; issue #7 is transferred to the
        # public repository at publication. A gate that flagged them would
        # train the executor to ignore it.
        for text in ("issue #7", "ha-casa-app#419", "casa#401"):
            for name, pattern in sl.CATEGORIES.items():
                self.assertIsNone(pattern.search(text), (name, text))


class Counts(unittest.TestCase):
    def test_a_line_matching_two_categories_is_counted_once(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.py").write_text("# Task 10 (sol P0, round 2)\n")
            hits = sl.scan(root, exceptions=set())
            self.assertEqual(len(hits), 1, hits)
            self.assertEqual(sum(sl.counts(hits).values()), 1)

    def test_the_attributed_category_is_the_first_in_declaration_order(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.py").write_text("# Task 10 (sol P0)\n")
            order = list(sl.CATEGORIES)
            hit = sl.scan(root, exceptions=set())[0]
            self.assertEqual(
                hit[2],
                next(n for n in order if sl.CATEGORIES[n].search("# Task 10 (sol P0)")))


class Exceptions(unittest.TestCase):
    def test_an_exception_is_keyed_on_path_and_line(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.py").write_text("ok\n# Task 10\n")
            self.assertEqual(sl.scan(root, exceptions={("f.py", 2)}), [])

    def test_an_exception_does_not_cover_the_same_text_elsewhere(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.py").write_text("# Task 10\n")
            (root / "g.py").write_text("# Task 10\n")
            hits = sl.scan(root, exceptions={("f.py", 1)})
            self.assertEqual([h[0] for h in hits], ["g.py"])

    def test_an_entry_without_a_reason_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "scripts").mkdir()
            (root / sl.EXCEPTIONS_FILE).write_text("f.py:2\n")
            with self.assertRaises(ValueError):
                sl.load_exceptions(root)

    def test_an_entry_with_a_reason_is_loaded(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "scripts").mkdir()
            (root / sl.EXCEPTIONS_FILE).write_text(
                "# a header comment\n\nf.py:2  # RFC 9110 is public\n")
            self.assertEqual(sl.load_exceptions(root), {("f.py", 2)})


class Exclusions(unittest.TestCase):
    """A subtree the scan does not cover must be declared, never hardcoded."""

    def test_an_undeclared_subtree_is_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "sub").mkdir()
            (root / "sub/f.py").write_text("# Task 10\n")
            self.assertEqual([h[0] for h in sl.scan(root, exceptions=set())],
                             ["sub/f.py"])

    def test_a_declared_subtree_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "scripts").mkdir()
            (root / "sub").mkdir()
            (root / "sub/f.py").write_text("# Task 10\n")
            (root / sl.EXCEPTIONS_FILE).write_text(
                "exclude-tree: sub/  # never shipped\n")
            self.assertEqual(sl.load_exclusions(root), {"sub/": "never shipped"})
            self.assertEqual(sl.scan(root, exceptions=set()), [])

    def test_an_exclusion_without_a_reason_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "scripts").mkdir()
            (root / sl.EXCEPTIONS_FILE).write_text("exclude-tree: sub/\n")
            with self.assertRaises(ValueError):
                sl.load_exclusions(root)


class Coverage(unittest.TestCase):
    def test_an_undecodable_file_is_reported_not_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "b.bin").write_bytes(b"\xff\xfe\x00")
            hits = sl.scan(root, exceptions=set())
            self.assertEqual([(h[0], h[2]) for h in hits],
                             [("b.bin", "unscannable")])

    def test_the_scan_covers_docstrings_and_test_names(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "t.py").write_text(
                'def test_fix_round_1_shape():\n    """Per spec §8.1."""\n')
            hits = sl.scan(root, exceptions=set())
            self.assertEqual(len(hits), 2, hits)

    def test_the_matched_text_is_reported_so_a_hit_can_be_acted_on(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "f.py").write_text("# see spec §8.1\n")
            path, lineno, category, matched = sl.scan(root, exceptions=set())[0]
            self.assertEqual((path, lineno, category), ("f.py", 1, "private_spec"))
            self.assertIn("spec §", matched)


class Main(unittest.TestCase):
    """The exit status is the gate. Output is captured, because a test that
    prints its fixture's findings makes the suite's own output unreadable."""

    def _run(self, text):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "f.py").write_text(text)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                status = sl.main(["scan_lineage.py", d])
            return status, out.getvalue()

    def test_a_clean_tree_exits_zero(self):
        self.assertEqual(self._run("# nothing to see\n")[0], 0)

    def test_a_dirty_tree_exits_one_and_names_the_site(self):
        status, printed = self._run("# Task 10\n")
        self.assertEqual(status, 1)
        self.assertIn("f.py:1", printed)


if __name__ == "__main__":
    unittest.main()
