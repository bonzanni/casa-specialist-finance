"""The guard that keeps account data out of a public repository.

The scan is only worth what runs it. This module tests the parts that decide
whether a future commit is refused: the staged-content scan, the paths that may
never be committed at all, and the hook and workflow that invoke them.

Every test drives a REAL git repository. A guard tested against a fake index
proves nothing about the one that will run.
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import scan_identifiers as si


def _valid_iban(country="NL", bban="REVO0000000001"):
    """Computed, never a literal: a checksum-valid value written into this
    file would be the thing the gate reports."""
    rearranged = bban + country + "00"
    digits = "".join(str(int(c, 36)) if c.isalpha() else c
                     for c in rearranged)
    return "%s%02d%s" % (country, 98 - int(digits) % 97, bban)


VALID = _valid_iban()
SYNTHETIC = "NL00REVO0000000001"


class Repo:
    """A throwaway git repository with this repository's scripts available."""

    def __init__(self, tmp):
        self.path = pathlib.Path(tmp)
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "T")
        (self.path / "scripts").mkdir()
        (self.path / "scripts" / "scan_identifiers.py").write_text(
            (ROOT / "scripts/scan_identifiers.py").read_text())
        (self.path / "scripts" / "identifier-exceptions.txt").write_text(
            "# none\n")

    def git(self, *args):
        return subprocess.run(("git",) + args, cwd=self.path,
                              capture_output=True, text=True)

    def write(self, rel, body):
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)

    def stage(self, rel):
        self.git("add", "-f", rel)

    def scan_staged(self):
        return si.scan_staged(self.path)


class StagedScan(unittest.TestCase):
    """The staged bytes are what becomes the commit."""

    def repo(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: None)
        return Repo(d)

    def test_a_staged_identifier_is_reported(self):
        r = self.repo()
        r.write("f.py", 'iban = "%s"\n' % VALID)
        r.stage("f.py")
        self.assertTrue(any(VALID in f[2] for f in r.scan_staged()))

    def test_a_staged_synthetic_is_not_reported(self):
        r = self.repo()
        r.write("f.py", 'iban = "%s"\n' % SYNTHETIC)
        r.stage("f.py")
        self.assertEqual(r.scan_staged(), [])

    def test_an_unstaged_file_is_not_scanned(self):
        # Only what is about to be committed. Reporting the working tree would
        # make the guard fire on work in progress and train people past it.
        r = self.repo()
        r.write("f.py", 'iban = "%s"\n' % VALID)
        self.assertEqual(r.scan_staged(), [])

    def test_the_staged_version_is_scanned_not_the_file_on_disk(self):
        """`git add` then edit: the clean file on disk hides the staged leak.

        This is the case a working-tree scan gets wrong, and it is not exotic
        -- it is what `git add -p` does every time.
        """
        r = self.repo()
        r.write("f.py", 'iban = "%s"\n' % VALID)
        r.stage("f.py")
        r.write("f.py", 'iban = "%s"\n' % SYNTHETIC)   # cleaned AFTER staging
        self.assertTrue(any(VALID in f[2] for f in r.scan_staged()),
                        "the staged blob still carries the real value")

    def test_a_grouped_identifier_is_reported(self):
        r = self.repo()
        grouped = " ".join(VALID[i:i + 4] for i in range(0, len(VALID), 4))
        r.write("doc.md", "Account %s\n" % grouped)
        r.stage("doc.md")
        self.assertTrue(any(VALID in f[2] for f in r.scan_staged()))

    def test_a_type_change_is_scanned(self):
        """`--diff-filter=ACMR` omits git status `T`. A symlink replaced by a regular
        file carrying an account number is a TYPE CHANGE, so its record was absent from
        the staged list entirely and the commit went through with nothing having read
        the file."""
        r = self.repo()
        (r.path / "thing").symlink_to("README.md")
        r.stage("thing")
        r.git("commit", "-q", "-m", "a symlink")
        (r.path / "thing").unlink()
        r.write("thing", 'iban = "%s"\n' % VALID)
        r.stage("thing")
        self.assertTrue(any(VALID in f[2] for f in r.scan_staged()),
                        "a type change must not be invisible to the staged scan")

    def test_a_deleted_file_is_not_scanned(self):
        r = self.repo()
        r.write("f.py", "ok\n")
        r.stage("f.py")
        r.git("commit", "-q", "-m", "x")
        (r.path / "f.py").unlink()
        r.git("add", "-A")
        self.assertEqual(r.scan_staged(), [])


class BlobScanning(unittest.TestCase):
    """`--blobs` reads each named object as a document of its own. The push hook uses it
    for everything a push would publish, so what it does with an object it cannot read
    decides whether that object is checked at all."""

    def run_blobs(self, repo, stdin):
        return subprocess.run(
            (sys.executable, str(ROOT / "scripts/scan_identifiers.py"), "--blobs", "."),
            cwd=repo, input=stdin, capture_output=True, text=True)

    def test_a_missing_object_is_refused_not_skipped(self):
        """`git cat-file --batch` answers `<sha> missing` and exits 0. Skipping that line
        is a silent pass for a blob nobody read."""
        d = tempfile.mkdtemp()
        r = Repo(d)
        r.write("f.txt", "ok\n")
        r.stage("f.txt")
        r.git("commit", "-q", "-m", "x")
        result = self.run_blobs(r.path, "0" * 40 + "\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing", result.stdout)

    def test_a_binary_blob_does_not_hide_a_text_blob(self):
        """Concatenated, one undecodable payload made the whole join undecodable, which
        this scanner correctly calls "nothing textual to find"."""
        d = tempfile.mkdtemp()
        r = Repo(d)
        (r.path / "blob.bin").write_bytes(b"\xff\x00binary\n")
        r.write("account.txt", VALID + "\n")
        r.git("add", "-A")
        r.git("commit", "-q", "-m", "x")
        shas = r.git("ls-tree", "-r", "HEAD", "--format=%(objectname)").stdout
        result = self.run_blobs(r.path, shas)
        self.assertEqual(result.returncode, 1)
        self.assertIn(VALID, result.stdout)


class ForbiddenPaths(unittest.TestCase):
    """Some files carry account data in a form no text scan can see."""

    def test_a_ledger_is_refused(self):
        for name in ("bank_feed.sqlite", "data/ledger.db",
                     "bank_feed.sqlite-wal"):
            self.assertIsNotNone(si.forbidden_path(name), name)

    def test_an_export_is_refused(self):
        for name in ("statement.csv", "export.OFX", "a/b/rekening.mt940",
                     "book.xlsx"):
            self.assertIsNotNone(si.forbidden_path(name), name)

    def test_an_image_or_pdf_is_refused(self):
        for name in ("screenshot.png", "scan.PDF", "shot.jpeg"):
            self.assertIsNotNone(si.forbidden_path(name), name)

    def test_a_credential_file_is_refused(self):
        for name in (".env", "config/.env.local", ".op-token"):
            self.assertIsNotNone(si.forbidden_path(name), name)

    def test_ordinary_source_and_docs_are_allowed(self):
        for name in ("scripts/scan_identifiers.py", "docs/readme.md",
                     "tests/fixtures/session.json", "manifest.json",
                     "plugins/bank-feed/server/store.py"):
            self.assertIsNone(si.forbidden_path(name), name)

    def test_every_refusal_states_a_reason(self):
        for pattern, reason in si.FORBIDDEN_PATHS:
            self.assertTrue(reason.strip(), pattern.pattern)

    def test_a_staged_ledger_is_reported_without_reading_it(self):
        d = tempfile.mkdtemp()
        r = Repo(d)
        (r.path / "bank_feed.sqlite").write_bytes(b"SQLite format 3\x00\xff")
        r.stage("bank_feed.sqlite")
        findings = r.scan_staged()
        self.assertEqual(len(findings), 1)
        self.assertIn("must not be committed", findings[0][2])


class NonText(unittest.TestCase):
    def test_a_binary_file_is_reported_not_skipped(self):
        d = tempfile.mkdtemp()
        r = Repo(d)
        (r.path / "blob.bin").write_bytes(b"\xff\xfe\x00\x01")
        r.stage("blob.bin")
        findings = r.scan_staged()
        self.assertEqual(len(findings), 1)
        self.assertIn("cannot be checked", findings[0][2])


class ExclusionsDoNotApplyToNewCommits(unittest.TestCase):
    """`exclude-tree:` says "this reviewed area is not scanned". It must not
    become a place new account data can be added unnoticed."""

    def test_a_staged_identifier_under_an_excluded_tree_is_still_reported(self):
        d = tempfile.mkdtemp()
        r = Repo(d)
        (r.path / "scripts" / "identifier-exceptions.txt").write_text(
            "exclude-tree:docs/private/  # reviewed, not published\n")
        r.write("docs/private/note.md", "iban %s\n" % VALID)
        r.stage("docs/private/note.md")
        self.assertTrue(any(VALID in f[2] for f in r.scan_staged()),
                        "an exclusion must not license NEW account data")


class ExclusionGrammar(unittest.TestCase):
    """`exclude-tree:` is a second exception grammar, separate from the deny sweep's."""

    def load(self, line):
        d = tempfile.mkdtemp()
        repo = Repo(d)
        (repo.path / "scripts" / "identifier-exceptions.txt").write_text(line)
        return repo

    def test_an_empty_prefix_is_refused(self):
        """It matched every tracked path, so one stray line silenced the entire scan
        while every check still reported success."""
        repo = self.load("exclude-tree:  # nothing in particular\n")
        with self.assertRaises(ValueError):
            si.load_exceptions(repo.path)

    def test_a_non_canonical_prefix_is_refused(self):
        for entry in ("exclude-tree:./docs/  # x\n", "exclude-tree:/docs/  # x\n",
                      "exclude-tree:docs//a/  # x\n"):
            with self.subTest(entry=entry):
                repo = self.load(entry)
                with self.assertRaises(ValueError):
                    si.load_exceptions(repo.path)

    def test_a_file_entry_does_not_cover_a_path_that_extends_it(self):
        """`manifest.json` must not also cover `manifest.json.bak`."""
        self.assertTrue(si._is_excluded("manifest.json", {"manifest.json": ""}))
        self.assertFalse(si._is_excluded("manifest.json.bak", {"manifest.json": ""}))
        self.assertTrue(si._is_excluded("docs/x/y.md", {"docs/x/": ""}))
        self.assertFalse(si._is_excluded("docs/xtra/y.md", {"docs/x/": ""}))


class NonTextBytes(unittest.TestCase):
    """Two different correct answers, and the difference is what the alternative was.

    A staged file that will not decode is REFUSED as unscannable -- that is a deliberate
    guard and it must stay. But `--blobs` and `--stdin` returned 0 for the same input, so
    a stray byte beside an account number removed it from the scan while every check
    reported success. Those two decode leniently; nothing is discarded silently."""

    def test_a_staged_undecodable_file_is_still_refused(self):
        d = tempfile.mkdtemp()
        r = Repo(d)
        (r.path / "mixed.txt").write_bytes(b"\xff " + VALID.encode() + b"\n")
        r.stage("mixed.txt")
        findings = r.scan_staged()
        self.assertEqual(len(findings), 1)
        self.assertIn("cannot be checked", findings[0][2])

    def test_one_undecodable_byte_does_not_clear_an_identifier_from_a_blob(self):
        d = tempfile.mkdtemp()
        r = Repo(d)
        (r.path / "mixed.txt").write_bytes(b"\xff " + VALID.encode() + b"\n")
        r.git("add", "-A")
        r.git("commit", "-q", "-m", "x")
        shas = r.git("ls-tree", "-r", "HEAD", "--format=%(objectname)").stdout
        result = subprocess.run(
            (sys.executable, str(ROOT / "scripts/scan_identifiers.py"), "--blobs", "."),
            cwd=r.path, input=shas, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn(VALID, result.stdout)


class TheGuardIsWiredUp(unittest.TestCase):
    """A guard nobody runs is not a guard."""

    def test_the_hook_exists_and_is_executable(self):
        hook = ROOT / ".githooks/pre-commit"
        self.assertTrue(hook.exists())
        self.assertTrue(hook.stat().st_mode & 0o111, "must be executable")

    def test_the_hook_runs_the_staged_scan(self):
        text = (ROOT / ".githooks/pre-commit").read_text()
        self.assertIn("scan_identifiers.py", text)
        self.assertIn("--staged", text)

    def test_the_hook_fails_closed_when_python_is_missing(self):
        text = (ROOT / ".githooks/pre-commit").read_text()
        self.assertIn("exit 1", text)
        self.assertIn("python3", text)

    def test_ci_runs_the_same_scan(self):
        workflow = ROOT / ".github/workflows/no-account-data.yml"
        self.assertTrue(workflow.exists())
        text = workflow.read_text()
        self.assertIn("scan_identifiers.py", text)
        self.assertIn("fetch-depth: 0", text,
                      "the history check needs full history")

    def test_the_install_step_is_documented(self):
        doc = (ROOT / "docs/contributing/protecting-account-data.md").read_text()
        self.assertIn("core.hooksPath .githooks", doc)

    def test_the_hook_runs_the_deny_sweep(self):
        text = (ROOT / ".githooks/pre-commit").read_text()
        self.assertIn("deny-sweep.sh", text)


class TheHookActuallyRefuses(unittest.TestCase):
    """The wiring tests above read the hook as text. These RUN it, against a real
    repository with a real index, because a hook that mentions a script and a hook
    that is stopped by it are different things -- and only the second one is a guard.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = pathlib.Path(self._tmp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "T")
        self.git("config", "core.hooksPath", ".githooks")
        for rel in (".githooks/pre-commit", ".githooks/deny-patterns.txt",
                    ".githooks/root-allowlist.txt", "scripts/scan_identifiers.py",
                    "scripts/deny-sweep.sh", "scripts/identifier-exceptions.txt"):
            target = self.path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((ROOT / rel).read_text())
            target.chmod(0o755)
        # The real allowlist names files this fixture does not have; keep only the
        # ones it will actually create, so a stray is a stray for the right reason.
        (self.path / ".githooks/root-allowlist.txt").write_text("README.md\n")
        # Committed, so the index and the working tree agree about the policy. The hook
        # refuses a mismatch: the scan reads the index while the policy reads the working
        # tree, so a result computed across the two describes neither.
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "policy")

    def git(self, *args):
        return subprocess.run(("git",) + args, cwd=self.path,
                              capture_output=True, text=True)

    def commit(self, rel, body):
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        self.git("add", "-f", rel)
        return self.git("commit", "-m", "attempt")

    def test_a_clean_commit_succeeds(self):
        """Without this, every other case here is satisfied by a hook that always
        refuses -- which is not a guard, it is a broken repository."""
        result = self.commit("README.md", "ordinary prose\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_denied_content_shape_is_refused(self):
        address = "192.168." + "1.77"       # assembled: see tests/test_deny_sweep.py
        result = self.commit("docs/notes.md", f"the box is at {address}\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deny content", result.stdout + result.stderr)

    def test_a_root_level_stray_is_refused(self):
        result = self.commit("scratch.txt", "ordinary prose\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root-allowlist", result.stdout + result.stderr)

    def test_an_account_identifier_is_still_refused(self):
        """The first half of the hook, end to end -- the asset this whole phase is
        about, refused by the thing that will actually run."""
        result = self.commit("docs/notes.md", f"account {VALID}\n")
        self.assertNotEqual(result.returncode, 0)

    def test_an_environment_policy_override_does_not_relax_the_hook(self):
        """The sweep's test-only override, honoured from the hook, would let a variable
        left over in a shell decide what this repository publishes."""
        permissive = self.path / "permissive.txt"
        permissive.write_text("[not-swept]\ndocs/ -- anything at all\n"
                              "[paths]\nzz-never\n[content]\nzz-never\n"
                              "[allow-content]\nzz-never\n")
        address = "192.168." + "1.77"
        target = self.path / "docs" / "notes.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"the box is at {address}\n")
        self.git("add", "-f", "docs/notes.md")
        result = subprocess.run(
            ("git", "commit", "-m", "attempt"), cwd=self.path, capture_output=True,
            text=True, env={**os.environ, "FINANCE_DENY_FILE": str(permissive)})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deny content", result.stdout + result.stderr)

    def test_an_unstaged_policy_change_is_refused(self):
        """The scan reads the INDEX and the policy reads the WORKING TREE, so a result
        computed across the two describes neither: a staged identifier passed because
        only the working tree declared its exception."""
        exceptions = self.path / "scripts" / "identifier-exceptions.txt"
        exceptions.write_text(exceptions.read_text() + f"{VALID}  # asserted public\n")
        result = self.commit("docs/notes.md", f"account {VALID}\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs between the index and the working tree",
                      result.stdout + result.stderr)

    def test_a_missing_deny_sweep_fails_closed(self):
        """Deleting the sweep must not be the one commit it cannot refuse."""
        (self.path / "scripts/deny-sweep.sh").unlink()
        result = self.commit("README.md", "ordinary prose\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deny-sweep.sh is missing", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
