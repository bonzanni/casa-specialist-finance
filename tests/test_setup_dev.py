"""Hook installation.

A guard nobody runs is not a guard, and `core.hooksPath` is LOCAL git configuration: a
fresh clone has none of this until somebody runs the script. So the thing worth testing
is that running it in a clone actually leaves the hooks installed -- and that running it
somewhere it cannot work says so rather than reporting success.
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "scripts" / "setup-dev.sh"


class SetupCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        hooks = self.repo / ".githooks"
        hooks.mkdir()
        for name in ("pre-commit", "pre-push"):
            target = hooks / name
            target.write_text((ROOT / ".githooks" / name).read_text())
            target.chmod(0o644)          # not executable yet: the script fixes that
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts" / "setup-dev.sh").write_text(SETUP.read_text())

    def run_setup(self, cwd=None):
        return subprocess.run(["bash", str(self.repo / "scripts" / "setup-dev.sh")],
                              cwd=cwd or self.repo, capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "HOME": str(self.tmp)})

    def hooks_path(self):
        return subprocess.run(["git", "-C", str(self.repo), "config", "--get",
                               "core.hooksPath"], capture_output=True, text=True).stdout.strip()


class ItInstallsTheHooks(SetupCase):
    def test_it_sets_the_hooks_path(self):
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.hooks_path(), ".githooks")

    def test_it_makes_the_hooks_executable(self):
        """A hook without the executable bit is silently not run by git -- no error, no
        output, and every check this repository has appears to pass."""
        self.run_setup()
        for name in ("pre-commit", "pre-push"):
            mode = (self.repo / ".githooks" / name).stat().st_mode
            self.assertTrue(mode & 0o111, f"{name} is not executable")

    def test_it_is_idempotent(self):
        self.run_setup()
        second = self.run_setup()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(self.hooks_path(), ".githooks")

    def test_it_works_from_a_subdirectory(self):
        """`cd` to the script's directory, not to the repository root, would set the
        configuration on whatever repository happened to be there."""
        deep = self.repo / "a" / "b"
        deep.mkdir(parents=True)
        result = self.run_setup(cwd=deep)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.hooks_path(), ".githooks")

    def test_it_refuses_outside_a_repository(self):
        """Not "quietly do nothing": somebody who ran it and saw no error would believe
        the hooks were installed."""
        outside = self.tmp / "elsewhere"
        outside.mkdir()
        result = subprocess.run(["bash", str(self.repo / "scripts" / "setup-dev.sh")],
                                cwd=outside, capture_output=True, text=True,
                                env={"PATH": "/usr/bin:/bin", "HOME": str(self.tmp),
                                     "GIT_CEILING_DIRECTORIES": str(self.tmp)})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not inside a git repository", result.stderr)


class TheRootDocuments(unittest.TestCase):
    """`AGENTS.md` and `CLAUDE.md` are read before anything else is touched. What they
    have to get right is the part that cannot be recovered from."""

    def test_both_exist_and_are_allowlisted(self):
        allowlist = (ROOT / ".githooks/root-allowlist.txt").read_text().split()
        for name in ("AGENTS.md", "CLAUDE.md"):
            self.assertTrue((ROOT / name).exists(), name)
            self.assertIn(name, allowlist, f"{name} would be refused as a root stray")

    def test_agents_names_the_setup_step(self):
        text = (ROOT / "AGENTS.md").read_text()
        self.assertIn("scripts/setup-dev.sh", text)
        self.assertIn("core.hooksPath", text)

    def test_agents_names_every_gate_a_contributor_has_to_pass(self):
        text = (ROOT / "AGENTS.md").read_text()
        for command in ("scan_identifiers.py", "deny-sweep.sh", "run-gitleaks.sh",
                        "verify_docs", "coverage_ledger.py"):
            self.assertIn(command, text, f"{command} is unmentioned")

    def test_claude_points_at_agents_rather_than_repeating_it(self):
        """Two files describing the same rules drift, and the one that drifts is the one
        nobody is reading at the time."""
        text = (ROOT / "CLAUDE.md").read_text()
        self.assertIn("AGENTS.md", text)
        self.assertLess(len(text.split()), 120, "this is meant to be a pointer")

    def test_the_readme_names_the_install_step_that_exists(self):
        """The cold-reader gate caught this one: the README told a newcomer to run the
        line setup-dev.sh runs, which installed the commit hook and left the push hook
        unmentioned. Nothing checks the README's prose, so this pins the part that
        decides whether a contributor's guards are installed at all."""
        text = (ROOT / "README.md").read_text()
        self.assertIn("scripts/setup-dev.sh", text)

    def test_the_readme_names_no_command_that_does_not_exist(self):
        import re
        text = (ROOT / "README.md").read_text()
        for script in re.findall(r"\b(?:python3 )?(scripts/[A-Za-z0-9_.-]+)", text):
            self.assertTrue((ROOT / script).exists(), f"README names missing {script}")

    def test_no_root_document_names_a_file_that_does_not_exist(self):
        """The corpus verifier checks this for documents under docs/. These two sit
        outside it, so nothing else would notice a stale path here."""
        import re
        for name in ("AGENTS.md", "CLAUDE.md"):
            text = (ROOT / name).read_text()
            for path in re.findall(r"`([A-Za-z0-9_./-]+\.(?:py|sh|md|yaml|yml|json|txt))`",
                                   text):
                if path.endswith("/"):
                    continue
                self.assertTrue((ROOT / path).exists(), f"{name} names missing {path}")


if __name__ == "__main__":
    unittest.main()
