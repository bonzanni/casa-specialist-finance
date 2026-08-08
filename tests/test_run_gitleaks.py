"""The pinned secret scanner's wrapper, and the exception inventory it subtracts.

The asset: a scanner that reports CLEAN while a credential sits in the tree. Every case
here makes one way of reaching that state impossible -- an undeclared finding passing, a
declared count silently growing, a stale exemption covering whatever appears at that path
next, an absent inventory, an absent or wrong-version scanner, a scanner whose config
detects nothing, and the inline allow-marker, which the real scanner honours natively.

The scanner is a STUB on PATH: a small matcher that reports a version, honours
`--exit-code`, writes the same report shape, and -- deliberately -- honours the inline
allow-marker exactly as the real one does, so that the marker case is a real test rather
than a tautology. The stub proves the wrapper's logic and nothing about gitleaks itself;
`.github/workflows/ci.yml` installs the pinned binary and runs the real scan, so the stub
can never be the only thing that has ever run.
"""
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "run-gitleaks.sh"
SWEEP = ROOT / "scripts" / "deny-sweep.sh"

MARKER = "gitleaks" ":" "allow"
FAKE_SECRET = "ZZ" "-FAKE-SECRET-ZZ"        # what the stub matches; not a real shape

STUB = textwrap.dedent('''\
    #!/usr/bin/env python3
    """A stand-in for gitleaks, for the wrapper's tests only."""
    import json, os, pathlib, re, sys

    args = sys.argv[1:]
    if args and args[0] == "version":
        print(os.environ.get("GLSTUB_VERSION", "8.28.0"))
        sys.exit(0)

    def flag(name, default=None):
        for a in args:
            if a.startswith(name + "="):
                return a.split("=", 1)[1]
        return args[args.index(name) + 1] if name in args else default

    mode, target = args[0], args[1]
    exit_code = int(flag("--exit-code", "1"))
    report = flag("--report-path")
    MARK = "gitleaks" ":" "allow"

    RULES = {
        "private-key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "gcp-api-key": re.compile(r"AIzaSy[0-9A-Za-z_-]{33}"),
        "generic-api-key": re.compile(r"xoxb-[0-9A-Za-z-]{20,}|ZZ-FAKE-SECRET-ZZ"),
    }
    if os.environ.get("GLSTUB_BLIND"):
        RULES = {}

    findings = []
    if mode == "git":
        # Honour --log-opts, so a range scan sees what a range scan sees: content
        # introduced by those commits, including content the endpoint no longer has.
        # A stub that scanned the working directory instead would report a removed
        # secret as absent, and every range case built on it would be a tautology.
        import subprocess
        opts = (flag("--log-opts", "") or "").split()
        patch = subprocess.run(["git", "-C", target, "log", "-p", *opts],
                               capture_output=True, text=True).stdout
        current = "?"
        for line in patch.splitlines():
            if line.startswith("+++ b/"):
                current = line[6:]
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue
            body = line[1:]
            if MARK in body:
                continue
            for rule, pattern in RULES.items():
                if pattern.search(body):
                    findings.append({"File": current, "RuleID": rule,
                                     "StartLine": 1, "Secret": "REDACTED"})
        if report:
            pathlib.Path(report).write_text(json.dumps(findings))
        sys.exit(exit_code if findings else 0)

    root = pathlib.Path(target)
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if MARK in line:
                continue
            for rule, pattern in RULES.items():
                if pattern.search(line):
                    findings.append({"File": str(path.relative_to(root)),
                                     "RuleID": rule, "StartLine": lineno,
                                     "Secret": "REDACTED"})
    if report:
        pathlib.Path(report).write_text(json.dumps(findings))
    sys.exit(exit_code if findings else 0)
    ''')

# The probe the wrapper runs before trusting any clean result, reproduced so a fixture can
# satisfy it. Split so this file holds no whole token.
PROBE_TOKEN = "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"

DENY_PATTERNS = """\
[not-swept]
working/ -- scratch material, never published
[paths]
(^|/)zzforbidden-
[content]
ZZ-DENIED-LITERAL-ZZ
[allow-content]
zz-never-matches-anything
"""


class WrapperCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        stub = self.bin / "gitleaks"
        stub.write_text(STUB)
        stub.chmod(0o755)

        self.repo = self.tmp / "repo"
        (self.repo / ".githooks").mkdir(parents=True)
        self.git("init", "-q", ".")
        self.git("config", "user.email", "t@t")
        self.git("config", "user.name", "t")
        (self.repo / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
        # The wrapper asks the sweep for the validated exclusion list, so the sweep has
        # to be present in the repository it runs against -- as it is in a real clone.
        (self.repo / "scripts").mkdir(exist_ok=True)
        sweep_copy = self.repo / "scripts" / "deny-sweep.sh"
        sweep_copy.write_text(SWEEP.read_text())
        sweep_copy.chmod(0o755)
        (self.repo / ".githooks" / "deny-patterns.txt").write_text(DENY_PATTERNS)
        self.inventory(())

    def git(self, *args, check=True):
        return subprocess.run(["git", "-C", str(self.repo), *args],
                              capture_output=True, text=True, check=check)

    def inventory(self, lines):
        """Written AND committed. `tree` mode reads the inventory and the config from the
        revision it is scanning, because the answer is about that commit -- so a fixture
        that only wrote them to disk would be testing a policy the revision does not
        carry, which is the defect this behaviour exists to prevent."""
        (self.repo / ".githooks" / "gitleaks-allow-sites.txt").write_text(
            "# reasons live here\n" + "".join(f"{line}\n" for line in lines))
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", "policy")

    def commit(self, rel, body):
        target = self.repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        self.git("add", "-A")
        self.git("commit", "-qm", rel)
        return self.git("rev-parse", "HEAD").stdout.strip()

    def run_wrapper(self, *args, env_extra=None):
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.repo)}
        env.update(env_extra or {})
        return subprocess.run(["bash", str(WRAPPER), *(args or ("tree",))],
                              cwd=self.repo, capture_output=True, text=True, env=env)


class TheInventoryDecides(WrapperCase):
    def test_an_undeclared_finding_is_refused(self):
        self.commit("src/config.py", f'token = "{FAKE_SECRET}"\n')
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("undeclared finding", result.stderr)
        self.assertIn("src/config.py", result.stderr)

    def test_a_declared_finding_passes(self):
        self.commit("src/config.py", f'token = "{FAKE_SECRET}"\n')
        self.inventory(("src/config.py generic-api-key 1",))
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_declared_count_that_grows_is_refused(self):
        """The reason the count is pinned at all: a file allowed one finding must not
        silently start carrying two."""
        self.commit("src/config.py", f'a = "{FAKE_SECRET}"\nb = "{FAKE_SECRET}"\n')
        self.inventory(("src/config.py generic-api-key 1",))
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("count moved", result.stderr)

    def test_a_declared_count_higher_than_reality_is_refused(self):
        self.commit("src/config.py", f'a = "{FAKE_SECRET}"\n')
        self.inventory(("src/config.py generic-api-key 4",))
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("count moved", result.stderr)

    def test_a_stale_entry_is_refused(self):
        """A fix removes the finding and leaves the line. Without this the line sits there
        covering whatever appears at that path next."""
        self.commit("src/config.py", "token = read_from_vault()\n")
        self.inventory(("src/config.py generic-api-key 1",))
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("stale entry", result.stderr)

    def test_a_declared_entry_matching_nothing_is_not_stale_in_range_mode(self):
        """The inventory is a TREE inventory. A history scan reports findings only from
        the files the range touches, so every declared line for an untouched file matches
        nothing -- and calling that stale made the push hook refuse EVERY push. Found by
        running it against this repository, not by reading it."""
        base = self.commit("src/config.py", f'token = "{FAKE_SECRET}"\n')
        self.commit("docs/unrelated.md", "nothing here\n")
        self.inventory(("src/config.py generic-api-key 1",
                        "src/absent.py private-key 1"))
        result = self.run_wrapper("range", f"{base}..HEAD")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_declared_entry_matching_nothing_is_still_stale_in_tree_mode(self):
        """The other direction, so narrowing the check cannot quietly disable it."""
        self.commit("src/config.py", f'token = "{FAKE_SECRET}"\n')
        self.inventory(("src/config.py generic-api-key 1",
                        "src/absent.py private-key 1"))
        result = self.run_wrapper("tree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("stale entry", result.stderr)

    def test_a_finding_in_a_path_containing_spaces_can_be_declared(self):
        """A pathname may contain spaces -- git allows it, and the sweep refuses only
        control characters. Splitting the inventory line from the left made such a
        finding impossible to declare, so a legitimately accepted one left the push
        refused with no way forward but bypassing the hook."""
        self.commit("docs/my notes.py", f'token = "{FAKE_SECRET}"\n')
        self.inventory(("docs/my notes.py generic-api-key 1",))
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_malformed_entry_is_refused(self):
        self.commit("src/config.py", "clean\n")
        self.inventory(("src/config.py generic-api-key",))
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("not '<path> <rule-id> <count>'", result.stderr)

    def test_a_duplicated_entry_is_refused(self):
        """Two lines for one group make the count meaningless: whichever is read last
        wins, and the other is a comment nobody notices."""
        self.commit("src/config.py", f'a = "{FAKE_SECRET}"\n')
        self.inventory(("src/config.py generic-api-key 1",
                        "src/config.py generic-api-key 9"))
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("declared twice", result.stderr)

    def test_an_entry_does_not_cover_a_different_rule_in_the_same_file(self):
        key = "AIzaSy" + "B" * 33
        self.commit("src/config.py", f'a = "{FAKE_SECRET}"\nb = "{key}"\n')
        self.inventory(("src/config.py generic-api-key 1",))
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("gcp-api-key", result.stderr)

    def test_an_entry_does_not_cover_the_same_rule_in_a_different_file(self):
        self.commit("src/config.py", f'a = "{FAKE_SECRET}"\n')
        self.commit("src/other.py", f'a = "{FAKE_SECRET}"\n')
        self.inventory(("src/config.py generic-api-key 1",))
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("src/other.py", result.stderr)


class ScannerNativeSuppression(WrapperCase):
    """gitleaks has suppression channels of its own, and each empties the declared
    inventory of meaning: a finding suppressed inside the scanner is never reported, so
    nothing is ever declared for it and the scan passes with no record of what was
    hidden. The inventory is the only exception mechanism here."""

    def test_an_allowlist_in_the_config_is_refused(self):
        (self.repo / ".gitleaks.toml").write_text(
            "[extend]\nuseDefault = true\n\n[[allowlists]]\nregexes = ['''ZZ-FAKE''']\n")
        self.commit("src/config.py", f'token = "{FAKE_SECRET}"\n')
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("scanner-native allowlist", result.stderr)

    def test_a_quoted_toml_key_is_also_refused(self):
        """TOML accepts quoted, dotted and inline-table spellings of the same key, and
        the scanner honours all of them. A textual check for `[[allowlists]]` saw only
        one spelling -- so the config is PARSED now, not pattern-matched."""
        for body in ('[extend]\nuseDefault = true\n\n[["allowlists"]]\nregexes = []\n',
                     '[extend]\nuseDefault = true\n\n[rules.allowlist]\nregexes = []\n'):
            with self.subTest(body=body.splitlines()[-2]):
                (self.repo / ".gitleaks.toml").write_text(body)
                self.git("add", "-A")
                self.git("commit", "-q", "--allow-empty", "-m", "config")
                result = self.run_wrapper()
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("scanner-native allowlist", result.stderr)

    def test_an_untracked_suppressor_does_not_block_a_revision_scan(self):
        """Tree mode scans an exported revision, where an untracked local file does not
        exist. Refusing on it blocked legitimate work for a file the commit never had."""
        self.commit("src/config.py", "clean\n")
        (self.repo / ".gitleaksignore").write_text("some:finding:1\n")   # untracked
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_gitleaksignore_file_is_refused(self):
        """Committed, so the revision being scanned carries it."""
        (self.repo / ".gitleaksignore").write_text("some:finding:1\n")
        self.commit("src/config.py", "clean\n")
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 2)
        self.assertIn(".gitleaksignore", result.stderr)


class TheRevisionDecides(WrapperCase):
    def test_tree_mode_takes_its_exclusions_from_the_revision(self):
        """The config and inventory were revision-bound, but the `[not-swept]` exclusions
        still came from the checkout, so an uncommitted exclusion removed a real finding
        from the named revision."""
        self.commit("secret/creds.py", f'token = "{FAKE_SECRET}"\n')
        self.assertEqual(self.run_wrapper().returncode, 1, "undeclared, so refused")
        policy = self.repo / ".githooks" / "deny-patterns.txt"
        lines = policy.read_text().splitlines(keepends=True)
        lines.insert(lines.index("[not-swept]\n") + 1, "secret/ -- uncommitted\n")
        policy.write_text("".join(lines))                       # never committed
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1,
                         "an uncommitted exclusion must not change the answer")

    def test_tree_mode_reads_the_inventory_from_the_revision(self):
        """The standalone program answers a question about a commit. An uncommitted
        inventory line changed that answer from refusal to success."""
        self.commit("src/config.py", f'token = "{FAKE_SECRET}"\n')
        self.assertEqual(self.run_wrapper().returncode, 1, "undeclared, so refused")
        inventory = self.repo / ".githooks" / "gitleaks-allow-sites.txt"
        inventory.write_text(inventory.read_text() + "src/config.py generic-api-key 1\n")
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1,
                         "an uncommitted exemption must not change the answer")


class SymlinkTargets(WrapperCase):
    def test_a_credential_in_a_symlink_target_is_found(self):
        """`git archive | tar -x` restores a git symlink AS a symlink, and `gitleaks dir`
        does not read its target -- so a credential stored as a link target received a
        clean scan. The target is text the commit publishes, so it is materialised as
        text before scanning."""
        (self.repo / "link").symlink_to(FAKE_SECRET)
        self.git("add", "-A")
        self.git("commit", "-qm", "a link whose target is the credential")
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("undeclared finding", result.stderr)


class ItFailsClosed(WrapperCase):
    def test_a_missing_inventory_is_refused(self):
        """Removed from the REVISION, since that is where tree mode reads it. Without an
        inventory every accepted finding reads as a new one, and the usual response to
        that is to stop running the scanner."""
        self.commit("src/config.py", "clean\n")
        (self.repo / ".githooks" / "gitleaks-allow-sites.txt").unlink()
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "drop the inventory")
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 2)
        self.assertIn("does not contain", result.stderr)

    def test_a_wrong_scanner_version_is_refused(self):
        """The default ruleset and the config surface both move between versions, so a
        clean result from an unexpected build is not the result CI produces."""
        self.commit("src/config.py", "clean\n")
        result = self.run_wrapper(env_extra={"GLSTUB_VERSION": "8.29.0"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("pinned", result.stderr)

    def test_an_absent_scanner_is_refused(self):
        self.commit("src/config.py", "clean\n")
        # The system PATH without the stub directory: git and bash are still reachable,
        # so this is "no scanner", not "no shell".
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.repo)}
        result = subprocess.run(["bash", str(WRAPPER), "tree"], cwd=self.repo,
                                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not installed", result.stderr)

    def test_a_scanner_that_detects_nothing_is_refused(self):
        """A clean report from an ineffective config is indistinguishable from a clean
        tree. The probe is what tells them apart, and it runs before every scan."""
        self.commit("src/config.py", "clean\n")
        result = self.run_wrapper(env_extra={"GLSTUB_BLIND": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("probe", result.stderr)

    def test_the_probe_fixture_still_matches_a_rule(self):
        """If the probe token stops being a finding, every scan fails closed -- which is
        safe but useless. This case says so out loud rather than leaving it to be
        discovered when the gate can no longer pass."""
        self.commit("src/config.py", f'slack = "{PROBE_TOKEN}"\n')
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("undeclared finding", result.stderr)

    def test_an_unknown_mode_is_refused(self):
        self.commit("src/config.py", "clean\n")
        self.assertEqual(self.run_wrapper("sideways").returncode, 2)

    def test_range_mode_without_a_range_is_refused(self):
        self.commit("src/config.py", "clean\n")
        self.assertEqual(self.run_wrapper("range").returncode, 2)


class TheInlineMarker(WrapperCase):
    """gitleaks honours `<marker>` natively: a real credential plus that comment produces
    a clean report. The wrapper cannot tell that apart from a clean file -- which is
    exactly why the marker is refused by the deny sweep instead. This case drives BOTH
    scripts and asserts the pair is not silent."""

    def test_the_pair_refuses_a_marker_silenced_credential(self):
        self.commit("src/config.py", f'token = "{FAKE_SECRET}"  # {MARKER}\n')
        (self.repo / ".githooks" / "root-allowlist.txt").write_text("")

        scan = self.run_wrapper()
        self.assertEqual(scan.returncode, 0,
                         "the scanner honours the marker -- that is the premise")

        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.repo),
               "FINANCE_DENY_FILE": str(self.repo / ".githooks" / "deny-patterns.txt")}
        sweep = subprocess.run(["bash", str(SWEEP), "tree"], cwd=self.repo,
                               capture_output=True, text=True, env=env)
        self.assertEqual(sweep.returncode, 1, "the sweep must refuse what the scanner cannot see")
        self.assertIn("src/config.py", sweep.stderr)


class DeclaredExclusions(WrapperCase):
    def test_a_not_swept_tree_is_not_scanned(self):
        """One declared list, read from the deny sweep's own policy file. A tree excluded
        from one scanner and not the other is a gap nobody would notice."""
        self.commit("working/notes.md", f'token = "{FAKE_SECRET}"\n')
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not scanned: working/", result.stderr)

    def test_the_exclusion_does_not_cover_a_sibling_path(self):
        self.commit("not-working/notes.md", f'token = "{FAKE_SECRET}"\n')
        self.assertEqual(self.run_wrapper().returncode, 1)

    def test_a_policy_the_sweep_refuses_is_refused_here_too(self):
        """The disagreement, demonstrated: an entry naming a file that no longer
        exists made the SWEEP refuse the policy and made this script accept it, so a tree
        carrying a live token scanned clean. Two parsers of one file disagreed about
        whether the file was even valid. The list now comes from the sweep, already
        validated, so there is one parser and one answer."""
        policy = self.repo / ".githooks" / "deny-patterns.txt"
        policy.write_text(policy.read_text().replace(
            "working/ -- scratch material, never published",
            "gone.txt -- an exclusion naming a file that no longer exists", 1))
        self.commit("gone.txt", f'token = "{FAKE_SECRET}"\n')
        (self.repo / "gone.txt").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "remove it from the worktree")

        sweep = subprocess.run(
            ["bash", str(SWEEP), "tree"], cwd=self.repo, capture_output=True, text=True,
            env={"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.repo)})
        self.assertEqual(sweep.returncode, 2, "the sweep refuses this policy")

        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0,
                            "and so must this, rather than honouring the same entry")

    def test_a_file_exclusion_does_not_cover_a_path_that_extends_it(self):
        """Same boundary rule as the sweep: a directory entry ends in `/` and covers what
        is beneath it, anything else is one exact path. A bare string prefix would exempt
        every sibling that happens to start with it."""
        policy = self.repo / ".githooks" / "deny-patterns.txt"
        policy.write_text(policy.read_text().replace(
            "working/ -- scratch material, never published",
            "src/keep-out.py -- a declared single-file exclusion", 1))
        # The named file has to exist, or the policy is refused before the boundary
        # question is reached -- which is the validation the case below this one pins.
        self.commit("src/keep-out.py", "nothing here\n")
        self.commit("src/keep-out.py.bak", f'token = "{FAKE_SECRET}"\n')
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("src/keep-out.py.bak", result.stderr)

    def test_tree_mode_scans_the_revision_it_is_given(self):
        """A push publishes a NAMED ref, not necessarily the checkout. Scanning HEAD when
        asked about another commit examines a tree nobody is publishing."""
        self.commit("src/config.py", f'token = "{FAKE_SECRET}"\n')
        dirty = self.git("rev-parse", "HEAD").stdout.strip()
        (self.repo / "src" / "config.py").unlink()
        self.commit("src/gone.py", "nothing here\n")
        self.assertEqual(self.run_wrapper("tree").returncode, 0, "the checkout is clean")
        result = self.run_wrapper("tree", dirty)
        self.assertEqual(result.returncode, 1)
        self.assertIn("src/config.py", result.stderr)


class TheRealRepository(unittest.TestCase):
    def test_the_committed_inventory_parses(self):
        """Every line is `<path> <rule> <count>`, and every path exists. A typo here
        reads as a stale entry at scan time, which is a confusing way to learn it."""
        inventory = ROOT / ".githooks" / "gitleaks-allow-sites.txt"
        entries = 0
        for lineno, line in enumerate(inventory.read_text().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            self.assertEqual(len(parts), 3, f"{inventory.name}:{lineno}: {line}")
            self.assertTrue(parts[2].isdigit(), f"{inventory.name}:{lineno}: {line}")
            self.assertTrue((ROOT / parts[0]).exists(),
                            f"{inventory.name}:{lineno}: no such path {parts[0]}")
            entries += 1
        self.assertGreater(entries, 0, "an empty inventory would make every case vacuous")

    def test_the_inventory_carries_no_key_shaped_value(self):
        """It records why a shape is accepted, never a value -- and a value written here
        would be a finding in the file that exists to declare findings."""
        text = (ROOT / ".githooks" / "gitleaks-allow-sites.txt").read_text()
        self.assertNotIn("AIzaSy", text)
        self.assertNotIn("BEGIN PRIVATE KEY", text)

    def test_ci_installs_the_version_the_wrapper_requires(self):
        """Two pins for one fact. If they drift, CI installs a build the wrapper then
        refuses, and the failure names the version rather than the drift."""
        wrapper = (ROOT / "scripts" / "run-gitleaks.sh").read_text()
        required = next(line.split('"')[1] for line in wrapper.splitlines()
                        if line.startswith("REQUIRED="))
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn(f'GITLEAKS_VERSION: "{required}"', workflow)

    def test_ci_runs_both_publication_gates(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("scripts/run-gitleaks.sh tree", workflow)
        self.assertIn("scripts/deny-sweep.sh tree", workflow)
        self.assertIn("sha256sum --check", workflow,
                      "an unverified download is a third-party fact taken on trust")

    @unittest.skipUnless(os.environ.get("FINANCE_REAL_SCANNER"),
                         "needs the pinned gitleaks binary; CI sets FINANCE_REAL_SCANNER")
    def test_the_real_scan_is_clean(self):
        result = subprocess.run(["bash", str(WRAPPER), "tree"], cwd=ROOT,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
