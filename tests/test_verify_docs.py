"""The docs-corpus verifier.

A clean pass proves nothing on its own. Every case here demonstrates that one
check BITES: it builds the smallest corpus that violates one rule and asserts
the verifier says so. A gate's zero measures only the shapes its author
enumerated, so a suite that exercised the happy path would report a healthy
corpus for exactly as long as nobody looked.

The corpus fixture is a real git repository, because the allowlist's ground
truth is `git ls-files`. In a plain temp directory every allowlist check
passes vacuously -- git tracks nothing there, so nothing is ever missing.
"""
import contextlib
import importlib.util
import io
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

# Loaded by explicit path rather than `from scripts import verify_docs`: a test must not
# depend on sys.path ordering to import the thing it is testing.
_spec = importlib.util.spec_from_file_location(
    "sf_verify_docs",
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "verify_docs.py",
)
verify_docs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_docs)

SOURCEMAP = "\n## Source & test map\n\n<!-- BEGIN SOURCEMAP -->\n<!-- END SOURCEMAP -->\n"
CODE_WINS = verify_docs.CODE_WINS + "\n"

ENTRY = """
- doc: architecture/ingestion.md
  summary: How a provider page becomes a ledger row.
  when_changing: the ingest pipeline or the ledger schema
  covers: [src/a.py::A.b]
  tests: [tests/test_a.py::test_b]
  related: [doctrine/publishing.md]
"""

SKELETON_MANIFEST = """
- doc: manifest.yaml
  kind: meta
  summary: The publication allowlist.
- doc: coverage.yaml
  kind: meta
  summary: The code-derived coverage ledger.
- doc: README.md
  kind: index
  summary: Routing map.
- doc: llms.txt
  kind: generated
  summary: Generated index.
- doc: doctrine/invariants.md
  kind: generated
  summary: Generated invariant index.
- doc: doctrine/publishing.md
  summary: What may be written down here.
  when_changing: anything published
- doc: contributing/doc-contract.md
  summary: How to keep this corpus true.
  when_changing: the documentation rules themselves
"""

SKELETON_FILES = {
    "README.md": "# Docs\n\n<!-- BEGIN ROUTING -->\n<!-- END ROUTING -->\n",
    "llms.txt": "",
    "coverage.yaml": "[]\n",
    "doctrine/invariants.md": "",
    "doctrine/publishing.md": CODE_WINS + SOURCEMAP,
    "contributing/doc-contract.md": CODE_WINS + SOURCEMAP,
}

DOC = {"architecture/ingestion.md": "# Ingestion\n" + CODE_WINS + SOURCEMAP}


class CorpusCase(unittest.TestCase):
    """Base class owning the throwaway-repository fixture."""

    def corpus(self, manifest=ENTRY, docs=None, *, skeleton=True, stage=True):
        root = pathlib.Path(
            self.enterContext(tempfile.TemporaryDirectory())
            if hasattr(self, "enterContext")
            else tempfile.mkdtemp()
        )
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        for key, value in (("user.email", "t@t"), ("user.name", "t")):
            subprocess.run(["git", "-C", str(root), "config", key, value], check=True)

        files = {**(SKELETON_FILES if skeleton else {}), **(DOC if docs is None else docs)}
        (root / "docs").mkdir()
        (root / "docs" / "manifest.yaml").write_text(
            manifest + (SKELETON_MANIFEST if skeleton else "")
        )
        for rel, body in files.items():
            target = root / "docs" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)

        (root / "src").mkdir()
        (root / "src" / "a.py").write_text("class A:\n    def b(self):\n        pass\n")
        (root / "src" / "conf.yaml").write_text("schema:\n  foo: str\n")
        (root / "tests").mkdir()
        (root / "tests" / "test_a.py").write_text("def test_b():\n    pass\n")
        if stage:
            self.stage(root)
        return root

    @staticmethod
    def stage(root):
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)

    def assertProblem(self, problems, *fragments):
        self.assertTrue(
            any(all(f in p for f in fragments) for p in problems),
            f"no problem matched {fragments}: {problems}",
        )


# --- anchor primitives ----------------------------------------------------------------

class AnchorPrimitives(CorpusCase):
    def test_parse_anchor_splits_the_symbol_off(self):
        self.assertEqual(verify_docs.parse_anchor("src/a.py::C.d"), ("src/a.py", "C.d"))
        self.assertEqual(verify_docs.parse_anchor("src/a.py"), ("src/a.py", None))

    def test_symbol_exists_resolves_a_nested_async_method(self):
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d) / "m.py"
            src.write_text("class A:\n    async def b(self):\n        pass\n")
            self.assertTrue(verify_docs.symbol_exists(src, "A.b"))
            self.assertFalse(verify_docs.symbol_exists(src, "A.c"))

    def test_yaml_key_exists_resolves_a_dotted_key(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = pathlib.Path(d) / "c.yaml"
            cfg.write_text("schema:\n  foo: str\n")
            self.assertTrue(verify_docs.yaml_key_exists(cfg, "schema.foo"))
            self.assertFalse(verify_docs.yaml_key_exists(cfg, "schema.bar"))


# --- the allowlist, both directions ----------------------------------------------------

class Allowlist(CorpusCase):
    def test_a_clean_corpus_verifies(self):
        self.assertEqual(verify_docs.verify(self.corpus()), [])

    def test_a_tracked_doc_absent_from_the_manifest_is_refused(self):
        root = self.corpus(docs={**DOC, "architecture/stray.md": "# S\n" + SOURCEMAP})
        self.assertProblem(verify_docs.verify(root), "stray.md", "not in the manifest")

    def test_a_manifest_entry_naming_an_untracked_file_is_refused(self):
        """The direction that passes locally and publishes a corpus without the file."""
        root = self.corpus()
        (root / "docs" / "architecture" / "ghost.md").write_text("# G\n" + SOURCEMAP)
        manifest = root / "docs" / "manifest.yaml"
        manifest.write_text(
            manifest.read_text()
            + "\n- doc: architecture/ghost.md\n  summary: s\n  when_changing: w\n"
        )
        self.assertProblem(verify_docs.verify(root), "ghost.md", "does not track it")

    def test_a_binary_under_docs_is_refused(self):
        root = self.corpus(docs={**DOC, "architecture/diagram.png": "\x89PNG\r\n"})
        self.assertProblem(verify_docs.verify(root), "diagram.png", "not admitted")

    def test_a_duplicate_manifest_entry_is_refused(self):
        self.assertProblem(verify_docs.verify(self.corpus(ENTRY + ENTRY)), "listed twice")

    def test_a_missing_skeleton_file_is_refused(self):
        """A manifest holding only its own entry passes every other check."""
        self.assertProblem(
            verify_docs.verify(self.corpus(skeleton=False)),
            "required by the corpus contract",
        )

    def test_a_root_level_document_is_refused(self):
        """It verifies cleanly but the generated index emits only the four prefixes."""
        manifest = ENTRY + "\n- doc: stray.md\n  summary: s\n  when_changing: w\n"
        root = self.corpus(manifest, docs={**DOC, "stray.md": "# S\n" + SOURCEMAP})
        self.assertProblem(verify_docs.verify(root), "root-level document is omitted")

    def test_a_document_outside_the_admitted_directories_is_refused(self):
        manifest = ENTRY.replace("architecture/ingestion.md", "notes/scratch.md")
        root = self.corpus(manifest, docs={"notes/scratch.md": "# S\n" + SOURCEMAP})
        self.assertProblem(verify_docs.verify(root), "not an admitted corpus directory")


# --- the excluded tree ------------------------------------------------------------------

class ExcludedTrees(CorpusCase):
    def test_the_excluded_trees_are_exactly_the_declared_ones(self):
        """One tree, committed. An exclusion that can grow by edit alone is how a
        gate stops measuring what it was written to measure."""
        self.assertEqual(verify_docs.EXCLUDED_TREES, ("superpowers/",))

    def test_a_tracked_file_under_an_excluded_tree_is_not_demanded(self):
        root = self.corpus(docs={**DOC, "superpowers/plan.md": "# Private plan\n"})
        self.assertEqual(verify_docs.verify(root), [])

    def test_a_file_under_an_excluded_tree_may_not_be_manifested(self):
        """Excluded in BOTH directions: not demanded, and not admissible either."""
        manifest = ENTRY + "\n- doc: superpowers/plan.md\n  summary: s\n  when_changing: w\n"
        root = self.corpus(manifest, docs={**DOC, "superpowers/plan.md": "# P\n"})
        self.assertProblem(verify_docs.verify(root), "superpowers/plan.md", "must not be manifested")

    def test_a_markdown_link_into_an_excluded_tree_is_refused(self):
        """The anchor rule covers covers:/tests:; a link in the prose is the same
        promise in the form a reader actually clicks, and it could not fire."""
        root = self.corpus(docs={
            "architecture/ingestion.md":
                "# I\n" + CODE_WINS + "See [the plan](../superpowers/plan.md).\n" + SOURCEMAP,
            "superpowers/plan.md": "# P\n"})
        self.assertProblem(verify_docs.verify(root), "excluded working material",
                           "superpowers/plan.md")

    def test_an_angle_bracket_link_into_an_excluded_tree_is_refused(self):
        """`](<dest>)` is the same link CommonMark-wise, and it walked past the
        inline-only pattern."""
        root = self.corpus(docs={
            "architecture/ingestion.md":
                "# I\n" + CODE_WINS + "See [plan](<../superpowers/plan.md>).\n" + SOURCEMAP,
            "superpowers/plan.md": "# P\n"})
        self.assertProblem(verify_docs.verify(root), "links to",
                           "../superpowers/plan.md")

    def test_a_reference_style_link_into_an_excluded_tree_is_refused(self):
        """Where a document's destinations usually live once it has more than a
        couple of them.

        Asserting the LINK diagnostic by its destination, not merely that some
        excluded-tree problem was reported: the looser assertion passed against a
        verifier that could not parse reference definitions at all, which made the
        test evidence of nothing.
        """
        text = ("# I\n" + CODE_WINS + "See [the plan][plan].\n\n"
                "[plan]: ../superpowers/plan.md\n" + SOURCEMAP)
        self.assertProblem(verify_docs._check_links(text, "architecture/ingestion.md"),
                           "links to", "../superpowers/plan.md")
        root = self.corpus(docs={"architecture/ingestion.md": text,
                                 "superpowers/plan.md": "# P\n"})
        self.assertProblem(verify_docs.verify(root), "links to",
                           "../superpowers/plan.md")

    def test_a_reference_label_containing_an_escaped_bracket_is_still_parsed(self):
        text = ("# I\n" + CODE_WINS + "See [the plan][plan\\]].\n\n"
                "[plan\\]]: ../superpowers/plan.md\n" + SOURCEMAP)
        self.assertProblem(verify_docs._check_links(text, "architecture/ingestion.md"),
                           "links to", "../superpowers/plan.md")

    def test_a_raw_html_link_into_an_excluded_tree_is_refused(self):
        """Markdown admits raw HTML, and `<a href>` is a link a reader clicks."""
        text = ("# I\n" + CODE_WINS
                + 'See <a href="../superpowers/plan.md">the plan</a>.\n' + SOURCEMAP)
        self.assertProblem(verify_docs._check_links(text, "architecture/ingestion.md"),
                           "links to", "../superpowers/plan.md")

    def test_a_raw_html_link_with_an_unquoted_href_is_refused(self):
        """Unquoted attribute values are legal HTML and just as clickable."""
        self.assertProblem(
            verify_docs._check_links("<a href=../superpowers/plan.md>plan</a>",
                                     "architecture/ingestion.md"),
            "links to", "../superpowers/plan.md")

    def test_an_ordinary_link_between_documents_passes(self):
        root = self.corpus(docs={
            "architecture/ingestion.md":
                "# I\n" + CODE_WINS
                + "See [doctrine](../doctrine/publishing.md) and [the web](https://x.test).\n"
                + SOURCEMAP})
        self.assertEqual(verify_docs.verify(root), [])

    def test_an_anchor_into_an_excluded_tree_is_refused(self):
        """A link a reader of the public commit cannot follow."""
        manifest = ENTRY.replace("src/a.py::A.b", "docs/superpowers/plan.md")
        root = self.corpus(manifest, docs={**DOC, "superpowers/plan.md": "# P\n"})
        self.assertProblem(verify_docs.verify(root), "excluded working material")


# --- anchors ----------------------------------------------------------------------------

class Anchors(CorpusCase):
    def test_a_line_number_anchor_is_refused(self):
        root = self.corpus(ENTRY.replace("src/a.py::A.b", "src/a.py:12"))
        self.assertProblem(verify_docs.verify(root), "line-number anchor")

    def test_an_anchor_outside_the_repository_is_refused(self):
        root = self.corpus(ENTRY.replace("src/a.py::A.b", "/etc/passwd"))
        self.assertProblem(verify_docs.verify(root), "outside the repository")

    def test_an_untracked_anchor_is_refused(self):
        """It would pass locally while being absent from the published commit."""
        root = self.corpus(ENTRY.replace("src/a.py::A.b", "src/ignored.py"))
        (root / "src" / "ignored.py").write_text("x = 1\n")
        self.assertProblem(verify_docs.verify(root), "not tracked by git")

    def test_a_dead_symbol_anchor_is_refused(self):
        root = self.corpus(ENTRY.replace("A.b", "A.gone"))
        self.assertProblem(verify_docs.verify(root), "A.gone", "does not resolve")

    def test_an_anchor_through_a_tracked_symlink_is_refused(self):
        """The lexical path is tracked, so the tracked-set check passes -- and then symbol
        resolution reads the destination, which may not be in the commit at all."""
        root = self.corpus(ENTRY.replace("src/a.py::A.b", "src/link.py::A.b"))
        (root / "src" / "hidden.py").write_text("class A:\n    def b(self):\n        pass\n")
        (root / "src" / "link.py").symlink_to("hidden.py")
        self.stage(root)
        self.assertProblem(verify_docs.verify(root), "is a symlink")

    def test_a_symlinked_document_is_refused(self):
        root = self.corpus(docs={})
        target = root / "docs" / "architecture"
        target.mkdir(parents=True, exist_ok=True)
        (target / "ingestion.md").symlink_to("/etc/passwd")
        self.stage(root)
        self.assertProblem(verify_docs.verify(root), "symlink")

    def test_path_traversal_in_the_manifest_is_refused(self):
        root = self.corpus(ENTRY.replace("architecture/ingestion.md", "../../etc/passwd"))
        self.assertProblem(verify_docs.verify(root), "outside")

    def test_related_must_name_a_document_not_an_index(self):
        root = self.corpus(
            ENTRY.replace("related: [doctrine/publishing.md]", "related: [llms.txt]"))
        self.assertProblem(verify_docs.verify(root), "not a manifested document")


# --- manifest schema ----------------------------------------------------------------------

class ManifestSchema(CorpusCase):
    def test_required_fields_are_enforced(self):
        problems = verify_docs.verify(self.corpus("\n- doc: architecture/ingestion.md\n  covers: []\n"))
        self.assertProblem(problems, "`summary` is required")
        self.assertProblem(problems, "`when_changing` is required")

    def test_a_pipe_in_a_table_rendered_field_is_refused(self):
        root = self.corpus(ENTRY.replace("the ingest pipeline or the ledger schema", "a | b"))
        self.assertProblem(verify_docs.verify(root), "free of `|`")

    def test_a_malformed_kind_is_a_finding_not_a_traceback(self):
        """`kind: []` is unhashable and verify() builds sets before per-entry validation."""
        self.assertProblem(
            verify_docs.verify(self.corpus(ENTRY + "  kind: []\n")), "`kind` must be a string")

    def test_invalid_yaml_is_a_finding_not_a_traceback(self):
        self.assertProblem(
            verify_docs.verify(self.corpus("- doc: [unclosed\n", skeleton=False)),
            "not valid YAML")

    def test_a_duplicate_yaml_key_in_an_entry_is_refused(self):
        """PyYAML keeps the LAST of a duplicate key, so an entry can carry two `covers`
        blocks and quietly publish only one."""
        root = self.corpus(ENTRY + "  covers: [src/a.py]\n")
        self.assertProblem(verify_docs.verify(root), "duplicate key")


# --- size budget ----------------------------------------------------------------------------

class SizeBudget(CorpusCase):
    def test_a_document_over_the_ceiling_is_refused(self):
        body = "# I\n" + CODE_WINS + "x" * 26_000 + SOURCEMAP
        root = self.corpus(docs={"architecture/ingestion.md": body})
        self.assertProblem(verify_docs.verify(root), "exceeds the 25 KB ceiling")

    def test_a_generated_index_gets_the_larger_budget(self):
        self.assertEqual(
            verify_docs.verify(self.corpus(docs={**DOC, "llms.txt": "x" * 30_000})), [])

    def test_a_near_ceiling_document_warns_without_failing(self):
        body = "# I\n" + CODE_WINS + "x" * 21_000 + SOURCEMAP
        root = self.corpus(docs={"architecture/ingestion.md": body})
        self.assertEqual(verify_docs.verify(root), [])
        self.assertTrue(any("approaching the ceiling" in w for w in verify_docs.warnings(root)))


# --- structure ---------------------------------------------------------------------------

class Structure(CorpusCase):
    def test_a_missing_sourcemap_pair_is_refused(self):
        root = self.corpus(docs={"architecture/ingestion.md": "# I\n" + CODE_WINS})
        self.assertProblem(verify_docs.verify(root), "SOURCEMAP", "exactly one")

    def test_reversed_sourcemap_markers_are_refused(self):
        body = "# I\n<!-- END SOURCEMAP -->\n<!-- BEGIN SOURCEMAP -->\n"
        root = self.corpus(docs={"architecture/ingestion.md": body})
        self.assertProblem(verify_docs.verify(root), "reversed")


# --- invariants -----------------------------------------------------------------------------

INV_DOC = {"architecture/ingestion.md":
           "# I\n" + CODE_WINS + "**INV-X-001**: one statement.\n" + SOURCEMAP}


def _inv_manifest(binding=""):
    return ENTRY.replace(
        "  related: [doctrine/publishing.md]",
        "  related: []\n  defines_invariants: [INV-X-001]" + binding,
    )


class Invariants(CorpusCase):
    def test_an_invariant_defined_twice_is_refused(self):
        inv = "**INV-X-001**: one statement.\n"
        manifest = (
            _inv_manifest("\n  invariant_tests:\n    INV-X-001: [tests/test_a.py::test_b]")
            + "\n- doc: architecture/other.md\n  summary: Other.\n  when_changing: else\n"
            + "  covers: [src/a.py]\n  defines_invariants: [INV-X-001]\n"
            + "  invariant_tests:\n    INV-X-001: [tests/test_a.py::test_b]\n"
        )
        root = self.corpus(manifest, docs={
            "architecture/ingestion.md": "# I\n" + CODE_WINS + inv + SOURCEMAP,
            "architecture/other.md": "# O\n" + CODE_WINS + inv + SOURCEMAP,
        })
        self.assertProblem(verify_docs.verify(root), "defined 2 times")

    def test_an_undefined_invariant_reference_is_refused(self):
        root = self.corpus(docs={
            "architecture/ingestion.md":
                "# I\n" + CODE_WINS + "See INV-GHOST-009.\n" + SOURCEMAP})
        self.assertProblem(verify_docs.verify(root), "INV-GHOST-009", "never defined")

    def test_a_declaration_mismatch_is_refused_both_ways(self):
        manifest = ENTRY.replace(
            "  related: [doctrine/publishing.md]",
            "  related: []\n  defines_invariants: [INV-X-002]")
        root = self.corpus(manifest, docs=INV_DOC)
        problems = verify_docs.verify(root)
        self.assertProblem(problems, "declares INV-X-002")
        self.assertProblem(problems, "does not declare", "INV-X-001")

    def test_a_wrapped_invariant_statement_is_refused(self):
        """It renders TRUNCATED into the generated index -- only the definition line
        is captured, so the qualification on the next line silently disappears."""
        wrapped = "**INV-X-001**: this statement continues on\nthe following line.\n"
        root = self.corpus(_inv_manifest(), docs={
            "architecture/ingestion.md": "# I\n" + CODE_WINS + wrapped + SOURCEMAP})
        self.assertProblem(verify_docs.verify(root), "complete on ONE line")

    def test_an_invariant_with_no_statement_is_refused(self):
        root = self.corpus(_inv_manifest(), docs={
            "architecture/ingestion.md": "# I\n" + CODE_WINS + "**INV-X-001**:\n" + SOURCEMAP})
        self.assertProblem(verify_docs.verify(root), "no statement on its definition line")

    def test_an_invariant_with_no_pinning_test_is_refused(self):
        self.assertProblem(
            verify_docs.verify(self.corpus(_inv_manifest(), docs=INV_DOC)),
            "INV-X-001", "no pinning test")

    def test_the_pinning_sentinel_keeps_the_verifier_red(self):
        """The sentinel makes the missing-test backlog mechanical rather than a promise."""
        manifest = _inv_manifest(
            "\n  invariant_tests:\n    INV-X-001: [tests/PINNING-TEST-MISSING]")
        self.assertProblem(
            verify_docs.verify(self.corpus(manifest, docs=INV_DOC)),
            "INV-X-001", "PINNING-TEST-MISSING")

    def test_a_binding_naming_an_untracked_test_file_is_refused(self):
        manifest = _inv_manifest("\n  invariant_tests:\n    INV-X-001: [tests/test_ghost.py]")
        self.assertProblem(
            verify_docs.verify(self.corpus(manifest, docs=INV_DOC)),
            "INV-X-001", "does not track")

    def test_a_binding_node_absent_from_the_file_is_refused(self):
        manifest = _inv_manifest(
            "\n  invariant_tests:\n    INV-X-001: [tests/test_a.py::test_vanished]")
        self.assertProblem(
            verify_docs.verify(self.corpus(manifest, docs=INV_DOC)),
            "test_vanished", "does not appear")

    def test_a_class_qualified_binding_resolves_structurally(self):
        """`Class::method` never appears literally in Python source, so the substring
        search the bare-function case uses can never match it."""
        manifest = _inv_manifest(
            "\n  invariant_tests:\n    INV-X-001: [tests/test_a.py::TestC::test_b]")
        root = self.corpus(manifest, docs=INV_DOC)
        (root / "tests" / "test_a.py").write_text(
            "def test_b():\n    pass\n\n\nclass TestC:\n    def test_b(self):\n        pass\n")
        self.stage(root)
        self.assertEqual(verify_docs.verify(root), [])

    def test_a_binding_for_an_undeclared_invariant_is_refused(self):
        """Bidirectional: a binding surviving its invariant's removal would keep a dead
        test looking load-bearing."""
        manifest = _inv_manifest(
            "\n  invariant_tests:\n"
            "    INV-X-001: [tests/test_a.py::test_b]\n"
            "    INV-X-009: [tests/test_a.py::test_b]")
        self.assertProblem(
            verify_docs.verify(self.corpus(manifest, docs=INV_DOC)),
            "INV-X-009", "does not declare")

    def test_a_malformed_binding_field_is_a_finding_not_a_traceback(self):
        manifest = _inv_manifest("\n  invariant_tests: [not, a, mapping]")
        self.assertProblem(
            verify_docs.verify(self.corpus(manifest, docs=INV_DOC)),
            "invariant_tests", "mapping")

    def test_an_invariant_without_a_source_anchor_is_refused(self):
        manifest = _inv_manifest(
            "\n  invariant_tests:\n    INV-X-001: [tests/test_a.py::test_b]"
        ).replace("  covers: [src/a.py::A.b]\n", "")
        self.assertProblem(
            verify_docs.verify(self.corpus(manifest, docs=INV_DOC)), "anchors no source")

    def test_a_correct_binding_passes(self):
        manifest = _inv_manifest(
            "\n  invariant_tests:\n    INV-X-001: [tests/test_a.py::test_b]")
        self.assertEqual(verify_docs.verify(self.corpus(manifest, docs=INV_DOC)), [])


# --- prose must name real code -----------------------------------------------------------
#
# Anchor verification passes when the anchors are right and only the sentence is wrong,
# which is the shape this check exists for: a published sentence naming a closure as
# though it were a method of the class it is nested in.

MODULES = {"ingest.py", "store.py"}
# What `_defined_symbols` produces for a tree containing:
#     class Base:            def commit(self)
#     class Store(Base):     def open_db(self)          -> inherits commit
#     class Ledger:          def apply(self)            -> closed, inherits nothing
#     class Session(Client): def begin(self)            -> Client is not in the tree
#     def _reconcile_window(...)                        -> a plain function
NAMES = {
    "Ledger", "Ledger.apply", "apply",
    "_reconcile_window",
    "Base", "Base.commit", "commit",
    "Store", "Store.open_db", "Store.commit", "open_db",
    "Session", "Session.begin", "begin",
}
OPEN_CLASSES = {"Session"}


class ProseCode(unittest.TestCase):
    def _prose(self, text):
        return verify_docs._check_prose_code(text, "d.md", MODULES, NAMES, OPEN_CLASSES)

    def test_a_closure_named_as_a_method_is_refused(self):
        problems = self._prose("see `Ledger._reconcile_window` for the window")
        self.assertTrue(problems, "a closure dressed up as a method must not pass")
        self.assertIn("not a member of", problems[0])

    def test_a_real_method_passes(self):
        self.assertFalse(self._prose("`Ledger.apply` writes the plan"))

    def test_a_genuinely_inherited_method_passes(self):
        """`Store(Base)` inherits `commit`; the expansion resolves it, so honest
        prose about an inherited member is not refused."""
        self.assertFalse(self._prose("`Store.commit` closes the transaction"))

    def test_a_method_of_an_unrelated_class_is_refused(self):
        """The bare name `apply` exists -- on Ledger. Accepting it as a member of
        Store because SOME class defines it is precisely the false ownership
        claim this check advertises catching."""
        problems = self._prose("`Store.apply` writes the plan")
        self.assertTrue(problems, "an unrelated class's method must not pass")
        self.assertIn("not a member of", problems[0])

    def test_a_member_of_a_class_with_an_unresolvable_base_passes(self):
        """Three states, not two: `Session(Client)` inherits from outside the
        tree, so its membership is unknowable and refusing would flag honest
        prose. Unknowable is not the same as absent."""
        self.assertFalse(self._prose("`Session.anything_at_all` may exist"))

    def test_a_module_that_does_not_exist_is_refused(self):
        problems = self._prose("configured in `marketplace_ops.py`")
        self.assertTrue(problems)
        self.assertIn("does not exist", problems[0])

    def test_a_live_module_passes(self):
        self.assertFalse(self._prose("configured in `store.py`"))

    def test_an_invented_function_is_refused(self):
        problems = self._prose("call `totally_made_up_thing()` first")
        self.assertTrue(problems)
        self.assertIn("does not exist", problems[0])

    def test_an_exempted_prose_token_passes(self):
        self.assertFalse(self._prose("declared in `plugin.json` and `role.yaml`"))


class SymbolResolution(CorpusCase):
    """`_defined_symbols` built from a real tree, since the three states above
    are only as good as what produces them."""

    def symbols(self, source):
        root = self.corpus(docs={})
        (root / "src" / "a.py").write_text(source)
        self.stage(root)
        return verify_docs._defined_symbols(root, verify_docs.tracked_files(root))

    def test_an_inherited_member_is_expanded_onto_the_subclass(self):
        _, names, open_classes = self.symbols(
            "class Base:\n    def commit(self):\n        pass\n\n\n"
            "class Store(Base):\n    def open_db(self):\n        pass\n")
        self.assertIn("Store.commit", names)
        self.assertEqual(open_classes, set())

    def test_a_class_whose_base_leaves_the_tree_is_open(self):
        _, _, open_classes = self.symbols(
            "class Session(Client):\n    def begin(self):\n        pass\n")
        self.assertIn("Session", open_classes)

    def test_an_imported_base_opens_the_class_even_when_the_name_collides(self):
        """The bare-name merge accepted a false member: a class inheriting an
        IMPORTED `Base` was credited with the members of an unrelated local class
        that happened to be called `Base` too. An imported base is unresolvable,
        whatever a same-named local class defines."""
        _, names, open_classes = self.symbols(
            "from elsewhere import ActualBase as Base\n\n\n"
            "class Store(Base):\n    def open_db(self):\n        pass\n\n\n"
            "class Base:\n    def ghost(self):\n        pass\n")
        self.assertIn("Store", open_classes)
        self.assertNotIn("Store.ghost", names)

    def test_an_instance_attribute_is_a_member(self):
        """`self.value = …` in a method is as real as a class-level binding, and
        refusing prose that names one would train a reader to ignore the check."""
        _, names, _ = self.symbols(
            "class A:\n    def __init__(self):\n        self.value = 1\n")
        self.assertIn("A.value", names)

    def test_a_base_imported_from_a_TRACKED_module_is_resolved_not_opened(self):
        """Opening the class for any imported base hid a decidable false claim:
        the base is right there in the repository. Resolve what resolves."""
        root = self.corpus(docs={})
        (root / "src" / "base.py").write_text(
            "class Base:\n    def commit(self):\n        pass\n")
        (root / "src" / "a.py").write_text(
            "from base import Base\n\n\nclass Store(Base):\n"
            "    def open_db(self):\n        pass\n")
        self.stage(root)
        _, names, open_classes = verify_docs._defined_symbols(
            root, verify_docs.tracked_files(root))
        self.assertIn("Store.commit", names)
        self.assertNotIn("Store", open_classes)
        self.assertNotIn("Store.ghost", names)

    def test_a_nested_class_attribute_is_not_credited_to_the_outer_class(self):
        _, names, _ = self.symbols(
            "class A:\n    class Inner:\n        def __init__(self):\n"
            "            self.inner_only = 1\n")
        self.assertIn("Inner.inner_only", names)
        self.assertNotIn("A.inner_only", names)

    def test_a_destructured_instance_attribute_is_a_member(self):
        _, names, _ = self.symbols(
            "class A:\n    def __init__(self):\n        self.value, other = (1, 2)\n")
        self.assertIn("A.value", names)

    def test_two_classes_of_one_name_in_different_packages_do_not_pool(self):
        """The bare-name merge credited a class with a NAMESAKE's members. The
        earlier version of this test asserted only that both classes' own members
        resolved, which was true before the fix too -- it was evidence of nothing.
        This one gives one namesake a subclass and asserts the other namesake's
        member is not inherited into it."""
        root = self.corpus(docs={})
        for pkg, member in (("pkg_one", "actual"), ("pkg_two", "ghost")):
            (root / "src" / pkg).mkdir(parents=True)
            (root / "src" / pkg / "base.py").write_text(
                f"class Base:\n    def {member}(self):\n        pass\n")
        (root / "src" / "store.py").write_text(
            "from pkg_one.base import Base\n\n\nclass Store(Base):\n"
            "    def open_db(self):\n        pass\n")
        self.stage(root)
        _, names, open_classes = verify_docs._defined_symbols(
            root, verify_docs.tracked_files(root))
        self.assertIn("Store.actual", names)
        self.assertNotIn("Store.ghost", names)
        self.assertNotIn("Store", open_classes)
        self.assertTrue(
            verify_docs._check_prose_code("`Store.ghost` exists", "d.md",
                                          set(), names, open_classes))

    def test_a_base_reached_through_a_module_attribute_is_resolved(self):
        """`import base` then `class Store(base.Base)` -- an ordinary shape that
        opened the class and accepted anything."""
        root = self.corpus(docs={})
        (root / "src" / "base.py").write_text(
            "class Base:\n    def real(self):\n        pass\n")
        (root / "src" / "store.py").write_text(
            "import base\n\n\nclass Store(base.Base):\n    pass\n")
        self.stage(root)
        _, names, open_classes = verify_docs._defined_symbols(
            root, verify_docs.tracked_files(root))
        self.assertIn("Store.real", names)
        self.assertNotIn("Store", open_classes)
        self.assertTrue(
            verify_docs._check_prose_code("`Store.ghost` exists", "d.md",
                                          set(), names, open_classes))

    def test_a_relative_import_resolves_within_its_own_package(self):
        """`from .base import Base` resolves exactly, so a same-named module in
        another package must not make it ambiguous -- and must not make the class
        unknowable when Python knows precisely which one it is."""
        root = self.corpus(docs={})
        for pkg, member in (("pkg_one", "real"), ("pkg_two", "ghost")):
            (root / "src" / pkg).mkdir(parents=True)
            (root / "src" / pkg / "base.py").write_text(
                f"class Base:\n    def {member}(self):\n        pass\n")
        (root / "src" / "pkg_one" / "store.py").write_text(
            "from .base import Base\n\n\nclass Store(Base):\n    pass\n")
        self.stage(root)
        _, names, open_classes = verify_docs._defined_symbols(
            root, verify_docs.tracked_files(root))
        self.assertIn("Store.real", names)
        self.assertNotIn("Store.ghost", names)
        self.assertNotIn("Store", open_classes)

    def test_an_indirect_unresolvable_base_still_opens_the_class(self):
        _, _, open_classes = self.symbols(
            "class Mid(Outside):\n    pass\n\n\n"
            "class Leaf(Mid):\n    def go(self):\n        pass\n")
        self.assertIn("Leaf", open_classes)


class ProseAgainstTheRealTree(CorpusCase):
    def test_prose_naming_a_module_that_does_not_exist_is_refused(self):
        root = self.corpus(docs={
            "architecture/ingestion.md":
                "# I\n" + CODE_WINS + "See `no_such_module.py`.\n" + SOURCEMAP})
        self.assertProblem(verify_docs.verify(root), "no_such_module.py", "does not exist")

    def test_prose_naming_a_tracked_module_passes(self):
        root = self.corpus(docs={
            "architecture/ingestion.md": "# I\n" + CODE_WINS + "See `a.py`.\n" + SOURCEMAP})
        self.assertEqual(verify_docs.verify(root), [])


# --- generated navigation -------------------------------------------------------------------

class GeneratedNavigation(CorpusCase):
    def test_index_links_resolve_relative_to_the_docs_directory(self):
        """Emitting `docs/...` from inside docs/ would resolve to docs/docs/..."""
        root = self.corpus()
        targets = re.findall(r"\]\(([^)]+)\)", verify_docs.render_llms(root))
        self.assertTrue(targets)
        for target in targets:
            self.assertFalse(target.startswith("docs/"))
            self.assertTrue((root / "docs" / target).exists())

    def test_routing_is_keyed_on_the_task_and_omits_indexes(self):
        out = verify_docs.render_routing(self.corpus())
        self.assertIn("the ingest pipeline or the ledger schema", out)
        self.assertNotIn("llms.txt", out)

    def test_checking_staleness_writes_nothing(self):
        root = self.corpus()
        before = {p: p.read_bytes() for p in (root / "docs").rglob("*") if p.is_file()}
        self.assertTrue(verify_docs.stale_nav(root), "the seeded corpus must start stale")
        after = {p: p.read_bytes() for p in (root / "docs").rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_writing_the_nav_is_idempotent_and_keeps_handwritten_text(self):
        root = self.corpus()
        readme = root / "docs" / "README.md"
        readme.write_text(
            "# Docs\n\nRead me first.\n\n<!-- BEGIN ROUTING -->\nstale\n"
            "<!-- END ROUTING -->\n\nFooter.\n")
        verify_docs.write_nav(root)
        self.assertEqual(verify_docs.write_nav(root), [])
        self.assertEqual(verify_docs.stale_nav(root), [])
        text = readme.read_text()
        self.assertIn("Read me first.", text)
        self.assertIn("Footer.", text)
        self.assertNotIn("stale", text)

    def test_the_sourcemap_is_injected_from_the_manifest(self):
        root = self.corpus()
        verify_docs.write_nav(root)
        text = (root / "docs" / "architecture" / "ingestion.md").read_text()
        self.assertIn("src/a.py::A.b", text)
        self.assertIn("tests/test_a.py::test_b", text)

    def test_reversed_routing_markers_are_reported_not_raised(self):
        root = self.corpus()
        (root / "docs" / "README.md").write_text(
            "# Docs\n\n<!-- END ROUTING -->\n<!-- BEGIN ROUTING -->\n")
        with self.assertRaises(SystemExit) as caught:
            verify_docs.nav_targets(root)
        self.assertIn("reversed", str(caught.exception))

    def test_an_unknown_flag_is_refused_rather_than_ignored(self):
        """`--impact` was casa's; dropping it while still accepting the flag meant
        a caller asking which documents claim a changed path got a green corpus
        verdict instead of an answer."""
        root = self.corpus()
        verify_docs.write_nav(root)
        argv = sys.argv
        sys.argv = ["verify_docs", str(root), "--impact"]
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                code = verify_docs.main()
        finally:
            sys.argv = argv
        self.assertEqual(code, 2)
        self.assertIn("unknown option", buffer.getvalue())

    def test_the_bare_invocation_fails_on_a_stale_generated_surface(self):
        """The documented keep-me-green command is the bare one; a local green must mean
        gate green, or the mismatch surfaces only at push time."""
        root = self.corpus()
        self.assertTrue(verify_docs.stale_nav(root))
        argv = sys.argv
        sys.argv = ["verify_docs", str(root)]
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                code = verify_docs.main()
        finally:
            sys.argv = argv
        self.assertEqual(code, 1)
        self.assertIn("generated navigation is stale", buffer.getvalue())


# --- manifest shards ---------------------------------------------------------------------------

SHARD_META = """
- doc: manifest.d/architecture.yaml
  kind: meta
  summary: Manifest shard - architecture documents.
"""


class ManifestShards(CorpusCase):
    def sharded(self, shard_body):
        root = self.corpus(manifest=SHARD_META, stage=False)
        shard_dir = root / "docs" / "manifest.d"
        shard_dir.mkdir()
        (shard_dir / "architecture.yaml").write_text(shard_body)
        self.stage(root)
        return root

    def test_a_shard_contributes_entries(self):
        self.assertEqual(verify_docs.verify(self.sharded(ENTRY)), [])

    def test_a_dead_anchor_in_a_shard_is_refused(self):
        """Shard entries are verified, not merely admitted."""
        root = self.sharded(ENTRY.replace("src/a.py::A.b", "src/a.py::A.zzz"))
        self.assertProblem(verify_docs.verify(root), "A.zzz")

    def test_a_shard_over_the_index_ceiling_is_refused(self):
        root = self.sharded(ENTRY + ("# pad\n" * 7000))
        self.assertProblem(verify_docs.verify(root), "40 KB", "architecture.yaml")

    def test_a_document_may_not_hide_under_manifest_d(self):
        rogue = "- doc: manifest.d/rogue.md\n  summary: s\n  when_changing: nothing\n"
        root = self.corpus(manifest=rogue,
                           docs={"manifest.d/rogue.md": "# R\n" + CODE_WINS + SOURCEMAP})
        self.assertProblem(verify_docs.verify(root), "manifest.d", "rogue.md")

    def test_a_doc_duplicated_between_root_and_shard_is_refused(self):
        root = self.corpus(manifest=SHARD_META + ENTRY, stage=False)
        shard_dir = root / "docs" / "manifest.d"
        shard_dir.mkdir()
        (shard_dir / "architecture.yaml").write_text(ENTRY)
        self.stage(root)
        self.assertProblem(verify_docs.verify(root), "listed twice")


if __name__ == "__main__":
    unittest.main()
