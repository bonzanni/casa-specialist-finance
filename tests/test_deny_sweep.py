"""The deny-pattern grammar, exercised the way all three consumers use it.

A clean sweep proves nothing on its own. Every case here demonstrates that one rule BITES,
or that one malformed input makes the sweep REFUSE rather than pass: a missing pattern
file, a blank one, a policy with no rules, an invalid regex, a path name git C-quotes, an
allow rule broad enough to exempt anything, an exclusion with no stated reason.

Every fixture uses SYNTHETIC values. The real pattern file denies addresses and private
ranges, and the real hooks sweep this file at commit time and at push time -- so a real
literal here would make the guard refuse its own test suite, and would be a leak in its
own right.

The sweep is driven against a throwaway repository built by the test, never against this
one: a script that scanned the repository it lives in rather than the one it runs in would
pass every case here while checking the wrong tree.
"""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWEEP = ROOT / "scripts" / "deny-sweep.sh"
REAL_DENY = ROOT / ".githooks" / "deny-patterns.txt"

# Models the real shape: a BROAD deny rule and a NARROW allow rule for one exact value.
# That is the only shape in which whole-match allow semantics matter -- and the shape in
# which destructive substring substitution leaks.
PATTERNS = """
[paths]
(^|/)zzforbidden-
[content]
[A-Za-z0-9]+@zztest\\.zzdomain
ZZ-DENIED-LITERAL-ZZ
[allow-content]
allowed@zztest\\.zzdomain
"""

MARKER = "gitleaks" ":" "allow"      # assembled: written whole, this file would be a site


class SweepCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.deny = self.tmp / "deny.txt"     # OUTSIDE the repo: `git add -A` must not stage it
        self.deny.write_text(PATTERNS)
        self.git("init", "-q", ".")
        self.git("config", "user.email", "t@t")
        self.git("config", "user.name", "t")

    def git(self, *args, check=True):
        return subprocess.run(["git", "-C", str(self.repo), *args],
                              capture_output=True, text=True, check=check)

    def head(self, ref="HEAD"):
        return self.git("rev-parse", ref).stdout.strip()

    def write(self, rel, body):
        target = self.repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)

    def commit(self, rel, body, message=None):
        self.write(rel, body)
        self.git("add", "-A")
        self.git("commit", "-qm", message or rel)
        return self.git("rev-parse", "HEAD").stdout.strip()

    def policy(self):
        """The companion policy files a real checkout has. Both fail closed when absent,
        which is the point -- so every fixture supplies them, exactly as a clone does."""
        hooks = self.repo / ".githooks"
        hooks.mkdir(exist_ok=True)
        roots = self.git("ls-files").stdout.split()
        (hooks / "root-allowlist.txt").write_text(
            "".join(f"{r}\n" for r in sorted(roots) if "/" not in r))

    def sweep(self, *args, deny=None, stdin=None, with_policy=True):
        """`deny=False` runs WITHOUT FINANCE_DENY_FILE, which is the only way to exercise
        the committed-policy path: the override exists so the sweep can be driven against
        a policy that is not in any repository, and setting it skips materialising the
        policy from the revision."""
        if with_policy:
            self.policy()
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.repo)}
        if deny is not False:
            env["FINANCE_DENY_FILE"] = str(deny if deny is not None else self.deny)
        return subprocess.run(["bash", str(SWEEP), *args], cwd=self.repo,
                              capture_output=True, text=True, env=env, input=stdin)


class TheSweepScansWhatItIsPointedAt(SweepCase):
    def test_it_scans_the_repository_it_is_run_in(self):
        self.commit("docs/zzforbidden-marker.md", "x\n")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("zzforbidden-marker", result.stderr)

    def test_staged_mode_sees_the_index(self):
        self.write("README.md", "contact: ZZ-DENIED-LITERAL-ZZ\n")
        self.git("add", "-A")
        self.assertEqual(self.sweep("staged").returncode, 1)

    def test_range_mode_catches_content_added_then_removed(self):
        """The whole point: the endpoint tree is clean, but the blob is published.

        The file lives in a subdirectory on purpose. At the root it would ALSO be a stray
        against an allowlist rebuilt from the post-removal index, and the case would pass
        without the content rule ever firing."""
        base = self.commit("a.txt", "benign\n")
        self.commit("src/leak.txt", "ZZ-DENIED-LITERAL-ZZ\n")
        (self.repo / "src" / "leak.txt").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "remove")
        self.assertEqual(self.sweep("tree").returncode, 0, "endpoint really is clean")
        self.assertEqual(self.sweep("range", f"{base}..HEAD").returncode, 1)

    def test_range_mode_catches_a_path_added_then_removed(self):
        base = self.commit("a.txt", "benign\n")
        self.commit("docs/zzforbidden-note.md", "harmless\n")
        (self.repo / "docs" / "zzforbidden-note.md").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "remove")
        self.assertEqual(self.sweep("tree").returncode, 0)
        self.assertEqual(self.sweep("range", f"{base}..HEAD").returncode, 1)

    def test_range_mode_allows_removing_an_already_public_denied_path(self):
        """A commit that only REMOVES a denied path publishes neither the path nor its
        contents. Refusing it left no way forward but --no-verify -- the same shape the
        binary check already had, where a removal was refused while the staged half
        allowed it."""
        self.commit("docs/zzforbidden-old.md", "long since public\n")
        base = self.head()
        (self.repo / "docs" / "zzforbidden-old.md").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "remove it")
        result = self.sweep("range", f"{base}..HEAD")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_range_mode_still_refuses_adding_a_denied_path(self):
        """The other direction, so narrowing the enumeration cannot quietly disable it."""
        base = self.commit("a.txt", "benign\n")
        self.commit("docs/zzforbidden-new.md", "just added\n")
        self.assertEqual(self.sweep("range", f"{base}..HEAD").returncode, 1)

    def test_messages_mode_sweeps_commit_messages(self):
        base = self.commit("a.txt", "benign\n")
        self.commit("b.txt", "x\n", message="leak ZZ-DENIED-LITERAL-ZZ in the subject")
        self.assertEqual(self.sweep("messages", f"{base}..HEAD").returncode, 1)

    def test_text_mode_sweeps_stdin(self):
        """A branch name and an author identity are published text that no other mode
        covers: neither is a file and neither is in a commit's content."""
        self.commit("a.txt", "benign\n")
        clean = self.sweep("text", stdin="feature/ordinary-name\n")
        self.assertEqual(clean.returncode, 0, clean.stderr)
        dirty = self.sweep("text", stdin="feature/ZZ-DENIED-LITERAL-ZZ\n")
        self.assertEqual(dirty.returncode, 1)
        self.assertIn("ZZ-DENIED-LITERAL-ZZ", dirty.stderr)

    def test_text_mode_does_not_apply_path_rules_to_the_text(self):
        """Path rules describe file names. Applying them to a branch name would refuse
        `zzforbidden-` as a word, which is not what the rule means."""
        self.commit("a.txt", "benign\n")
        result = self.sweep("text", stdin="zzforbidden-but-only-a-path-rule\n")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_tree_mode_scans_the_revision_it_is_given(self):
        """A push publishes a NAMED ref, which need not be the checked-out HEAD. Scanning
        HEAD when asked about another commit checks a tree nobody is publishing."""
        clean = self.commit("a.txt", "benign\n")
        self.git("checkout", "-qb", "payload")
        dirty = self.commit("docs/leak.md", "ZZ-DENIED-LITERAL-ZZ\n")
        self.git("checkout", "-q", "-")
        self.assertEqual(self.sweep("tree").returncode, 0, "the checkout is clean")
        self.assertEqual(self.sweep("tree", clean).returncode, 0)
        result = self.sweep("tree", dirty)
        self.assertEqual(result.returncode, 1)
        self.assertIn("ZZ-DENIED-LITERAL-ZZ", result.stderr)

    def test_the_root_allowlist_also_comes_from_the_revision(self):
        """Not only the pattern file. An uncommitted allowlist line would decide which
        root-level files the published commit is allowed to contain."""
        self.write("README.md", "ok\n")
        self.write("stray.txt", "a root-level file\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "two root files")
        hooks = self.repo / ".githooks"
        hooks.mkdir(exist_ok=True)
        (hooks / "deny-patterns.txt").write_text(PATTERNS)
        (hooks / "root-allowlist.txt").write_text("README.md\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "allowlist without the stray")
        rev = self.head()
        (hooks / "root-allowlist.txt").write_text("README.md\nstray.txt\n")   # uncommitted
        result = self.sweep("tree", rev, deny=False, with_policy=False)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("stray.txt", result.stderr)

    def test_tree_mode_refuses_a_revision_that_is_not_a_commit(self):
        self.commit("a.txt", "benign\n")
        self.assertEqual(self.sweep("tree", "no-such-rev").returncode, 2)

    def test_an_unresolvable_revision_is_refused_not_reported_clean(self):
        """`git log` fails and prints nothing, and a `|| true` on that pipeline turned
        the failure into a clean, empty scan -- the same exit 0 a genuinely clean range
        gives. A caller cannot tell those apart."""
        self.commit("a.txt", "benign\n")
        for mode in ("range", "messages"):
            result = self.sweep(mode, "no-such-revision")
            self.assertEqual(result.returncode, 2, f"{mode}: {result.stderr}")
            self.assertIn("not a resolvable revision range", result.stderr)

    def test_an_unknown_mode_is_refused(self):
        self.commit("a.txt", "benign\n")
        self.assertEqual(self.sweep("sideways").returncode, 2)


class ItFailsClosed(SweepCase):
    def test_a_missing_pattern_file_fails_closed(self):
        """It must not load zero rules and exit 0 -- a commit deleting the policy file
        would disable its own guard, and in staged mode a deletion is not even in the
        ACMR filter that would otherwise have shown it."""
        self.commit("README.md", "fine\n")
        result = self.sweep("tree", deny=self.tmp / "does-not-exist.txt")
        self.assertEqual(result.returncode, 2)
        self.assertIn("failing closed", result.stderr)

    def test_a_structurally_invalid_policy_fails_closed(self):
        """"Fails closed" covers an INVALID policy, not only an unreadable one: a blank
        file parses into empty arrays while every check still reports success, and the
        policy file is itself excluded from the primary content sweep."""
        self.commit("README.md", "fine\n")
        self.deny.write_text("")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 2)
        self.assertTrue("malformed policy" in result.stderr
                        or "no path or content rules" in result.stderr, result.stderr)

    def test_a_policy_missing_a_section_fails_closed(self):
        self.commit("README.md", "fine\n")
        self.deny.write_text("[content]\nZZ-DENIED-LITERAL-ZZ\n")
        self.assertEqual(self.sweep("tree").returncode, 2)

    def test_an_invalid_pattern_is_fatal_not_silent(self):
        self.deny.write_text("[paths]\nzz-never\n[content]\n[unclosed\n[allow-content]\n")
        self.commit("README.md", "fine\n")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid pattern", result.stderr)

    def test_a_valid_pattern_is_not_reported_invalid(self):
        """`status=$?` captured after `!` is always 0, which makes every real rule read as
        invalid and the whole sweep fail closed on its first rule."""
        self.deny.write_text("[paths]\nzz-never\n[content]\n"
                             "^definitely-not-present-anywhere$\n[allow-content]\n")
        self.commit("README.md", "fine\n")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_missing_root_allowlist_fails_closed(self):
        """Not "skip the root check": a root-level stray is exactly what this catches, and
        an absent allowlist would silently disable it."""
        self.commit("README.md", "fine\n")
        result = self.sweep("tree", with_policy=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("root-allowlist", result.stderr)

    def test_a_comment_in_the_root_allowlist_is_not_an_allowed_filename(self):
        """`grep -f` reads every line as a pattern, so each explanatory `#` line in the
        allowlist was itself an allowed filename -- an exemption nobody declared, for a
        path nobody would notice."""
        self.write("README.md", "ok\n")
        self.write("# policy explanation", "a stray hiding behind a comment\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "root files")
        hooks = self.repo / ".githooks"
        hooks.mkdir(exist_ok=True)
        (hooks / "root-allowlist.txt").write_text("# policy explanation\nREADME.md\n")
        result = self.sweep("tree", with_policy=False)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("# policy explanation", result.stderr)

    def test_a_root_level_stray_is_refused(self):
        self.commit("README.md", "fine\n")
        self.policy()                                  # allowlist written from ls-files...
        self.commit("scratch-notes.txt", "x\n")        # ...before this file existed
        result = self.sweep("tree", with_policy=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("scratch-notes.txt", result.stderr)


class AllowRules(SweepCase):
    def test_allow_content_exempts_the_exact_allowed_value(self):
        self.commit("README.md", "maintainer: allowed@zztest.zzdomain\n")
        self.assertEqual(self.sweep("tree").returncode, 0)

    def test_an_allow_rule_cannot_exempt_a_value_it_merely_prefixes(self):
        """Deleting allow matches with `sed s///g` is an unanchored substring rewrite: a
        broader match ending in an allowed value has that value removed and the remainder
        no longer matches, so a distinct address passes. An allow rule must cover the
        WHOLE match or be irrelevant to it."""
        self.commit("README.md", "contact: notallowed@zztest.zzdomain\n")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 1, "a distinct address must not inherit it")
        self.assertIn("notallowed@zztest.zzdomain", result.stderr)

    def test_a_trivially_broad_allow_rule_is_refused(self):
        """One `.*` under [allow-content] would exempt every finding there is."""
        self.deny.write_text("[paths]\nzz-never\n[content]\nZZ-DENIED-LITERAL-ZZ\n"
                             "[allow-content]\n.*\n")
        self.commit("README.md", "contact: ZZ-DENIED-LITERAL-ZZ\n")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 2)
        self.assertIn("broad", result.stderr)


class DeclaredExclusions(SweepCase):
    """`[not-swept]` is the only way a tracked file escapes the content rules. It is the
    same mechanism the identifier and lineage scans use, and it carries the same risk, so
    the sweep refuses an entry that does not say why."""

    def policy_with_exclusion(self, entry):
        self.deny.write_text(f"[not-swept]\n{entry}\n" + PATTERNS)

    def test_an_excluded_tree_is_not_swept(self):
        self.policy_with_exclusion("working/ -- scratch material, never published")
        self.commit("working/notes.md", "ZZ-DENIED-LITERAL-ZZ\n")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not swept: working/", result.stderr)

    def test_an_exclusion_with_no_reason_is_refused(self):
        self.policy_with_exclusion("working/")
        self.commit("working/notes.md", "ZZ-DENIED-LITERAL-ZZ\n")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 2)
        self.assertIn("states no reason", result.stderr)

    def test_an_exclusion_does_not_cover_a_sibling_path(self):
        """Prefix matching, not substring: `working/` must not exempt `not-working/`."""
        self.policy_with_exclusion("working/ -- scratch material, never published")
        self.commit("not-working/notes.md", "ZZ-DENIED-LITERAL-ZZ\n")
        self.assertEqual(self.sweep("tree").returncode, 1)

    def test_a_directory_exclusion_must_end_in_a_slash(self):
        """`working` as a bare prefix also exempted
        `working-copy/`, a sibling tree nobody named -- and a credential committed there
        passed the staged sweep, the scanner and an actual push. An entry now names a
        directory (trailing slash) or one exact existing file, and nothing else."""
        self.policy_with_exclusion("working -- scratch material, never published")
        self.commit("working-copy/notes.md", "ZZ-DENIED-LITERAL-ZZ\n")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 2)
        self.assertIn("neither a directory", result.stderr)

    def test_a_directory_exclusion_does_not_reach_a_sibling_tree(self):
        self.policy_with_exclusion("working/ -- scratch material, never published")
        self.commit("working-copy/notes.md", "ZZ-DENIED-LITERAL-ZZ\n")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("working-copy/notes.md", result.stderr)

    def test_a_non_canonical_entry_is_refused(self):
        """Git normalises `./working/` for a literal pathspec and excludes what is
        beneath it; the scanner's filter and the push hook's blob filter compare the
        string as written and do not. Which files get checked would then depend on which
        program is asking."""
        self.commit("a.txt", "benign\n")
        for entry in ("./working/", "/working/", "working//sub/", "working/./sub/",
                      "a/../working/"):
            with self.subTest(entry=entry):
                self.policy_with_exclusion(f"{entry} -- scratch material")
                result = self.sweep("tree")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("not a canonical", result.stderr)

    def test_an_entry_with_surrounding_whitespace_is_refused(self):
        """One consumer trimmed and another did not, so ` docs/leak` validated in the
        sweep and became `docs/leak` in the scanner -- a different exclusion, which
        suppressed a detected credential. Rejected rather than trimmed, so the line has
        exactly one spelling."""
        self.commit("a.txt", "benign\n")
        for entry in (" working/", "working/ "):
            with self.subTest(entry=entry):
                self.policy_with_exclusion(f"{entry} -- scratch material")
                result = self.sweep("tree")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("whitespace", result.stderr)

    def test_a_file_entry_is_validated_against_the_revision_being_assessed(self):
        """Not against the checked-out index: an unrelated branch validated an exclusion
        for a path the published commit does not contain, and the exemption then applied
        to whatever appeared at that path next."""
        self.commit("docs/exact", "the declared file\n")
        with_file = self.head()
        (self.repo / "docs" / "exact").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "the file goes away")
        without_file = self.head()
        self.policy_with_exclusion("docs/exact -- one exact declared file")

        self.assertEqual(self.sweep("tree", with_file).returncode, 0,
                         "the revision that has it validates")
        result = self.sweep("tree", without_file)
        self.assertEqual(result.returncode, 2,
                         "the revision that does not have it must refuse")

    def test_a_canonical_entry_is_accepted(self):
        """The other direction: the ordinary form has to keep working."""
        self.policy_with_exclusion("working/ -- scratch material, never published")
        self.commit("working/notes.md", "ZZ-DENIED-LITERAL-ZZ\n")
        self.assertEqual(self.sweep("tree").returncode, 0)

    def test_an_untracked_file_does_not_validate_an_exclusion(self):
        """An untracked working-tree file validated an entry that named nothing in the
        repository, so the exemption applied to whatever later appeared at that path."""
        self.commit("a.txt", "benign\n")
        (self.repo / "keep-out.md").write_text("present but never added\n")
        self.policy_with_exclusion("keep-out.md -- a file that is not tracked")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 2)
        self.assertIn("nor a file the assessed revision contains", result.stderr)

    def test_a_file_exclusion_covers_that_file_and_no_other(self):
        self.write("keep-out.md", "ZZ-DENIED-LITERAL-ZZ\n")
        self.write("keep-out.md.bak", "ZZ-DENIED-LITERAL-ZZ\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "two files")
        self.policy_with_exclusion("keep-out.md -- a declared single-file exclusion")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("keep-out.md.bak", result.stderr)

    def test_a_file_exclusion_does_not_reach_a_path_that_extends_it(self):
        """Pinned through a PATH rule on purpose. The content pass excludes with git
        pathspecs, which are already boundary-aware, so it hides a bare-prefix bug in the
        path list -- where the path rules, the root allowlist and the binary check live."""
        self.write("docs/zzforbidden-a.md", "x\n")
        self.write("docs/zzforbidden-a.md.bak", "x\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "two")
        self.policy_with_exclusion(
            "docs/zzforbidden-a.md -- a declared single-file exclusion")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("zzforbidden-a.md.bak", result.stderr)

    def test_a_metacharacter_in_a_file_entry_is_not_a_wildcard(self):
        """Without `literal` pathspec magic, git reads `*` in an exclusion as a wildcard
        while the awk filter and the scanner's filter read the same entry as one exact
        name. An exclusion for a file literally called `work*` then removed `working`
        from the content pass alone, and an added-then-removed credential there was
        reported by no mode at all."""
        self.write("docs/work*", "the declared exact file\n")
        self.write("docs/working", "ZZ-DENIED-LITERAL-ZZ\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "a starred name and its neighbour")
        self.policy_with_exclusion("docs/work* -- an exact file whose name has a star")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("ZZ-DENIED-LITERAL-ZZ", result.stderr)

    def test_the_exclusions_can_be_asked_for(self):
        """One implementation of the parse. The push hook needs this list to filter the
        blobs it feeds the identifier scan, which reads content and has no path."""
        self.policy_with_exclusion("working/ -- scratch material, never published")
        self.commit("a.txt", "benign\n")
        result = self.sweep("not-swept")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ["working/ -- scratch material, never published"])
        self.assertNotIn("not swept:", result.stderr,
                         "in this mode the list IS the output; announcing it as well "
                         "makes every consumer print it twice")

    def test_the_exclusions_cannot_be_asked_for_when_the_policy_is_invalid(self):
        """The consumers rely on this call to validate. If it printed a list for a policy
        the sweep would refuse, the second consumer would honour an entry the first one
        rejects -- which is exactly the disagreement demonstrated below."""
        self.policy_with_exclusion("gone.txt -- names a file that does not exist")
        self.commit("a.txt", "benign\n")
        result = self.sweep("not-swept")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout.strip(), "")

    def test_an_exclusion_covers_the_staged_and_range_modes_too(self):
        """A file the tree pass skips but the staged pass reports would make the commit
        hook and the push hook disagree about the same file."""
        self.policy_with_exclusion("working/ -- scratch material, never published")
        base = self.commit("a.txt", "benign\n")
        self.write("working/notes.md", "ZZ-DENIED-LITERAL-ZZ\n")
        self.git("add", "-A")
        self.assertEqual(self.sweep("staged").returncode, 0)
        self.git("commit", "-qm", "notes")
        self.assertEqual(self.sweep("range", f"{base}..HEAD").returncode, 0)


class TheScannerMarker(SweepCase):
    """gitleaks honours an inline allow-marker natively, so a real credential plus that
    comment produces a clean secret scan with no record of what was silenced. This
    repository's only exception channel is the declared inventory that
    scripts/run-gitleaks.sh subtracts, so the marker is refused wherever it appears."""

    def test_the_marker_is_refused_in_the_tree(self):
        self.commit("sneaky.py", f"token = 'x'  # {MARKER}\n")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("sneaky.py", result.stderr)

    def test_the_marker_is_refused_in_the_index(self):
        self.write("sneaky.py", f"token = 'x'  # {MARKER}\n")
        self.git("add", "-A")
        self.assertEqual(self.sweep("staged").returncode, 1)

    def test_the_marker_is_refused_in_a_commit_that_later_removes_it(self):
        """In a subdirectory, so that the removal does not also register as a root-level
        stray -- which is how this case first passed with the marker check disabled."""
        base = self.commit("a.txt", "benign\n")
        self.commit("src/sneaky.py", f"token = 'x'  # {MARKER}\n")
        (self.repo / "src" / "sneaky.py").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "remove it again")
        self.assertEqual(self.sweep("tree").returncode, 0, "endpoint is clean")
        result = self.sweep("range", f"{base}..HEAD")
        self.assertEqual(result.returncode, 1)
        self.assertIn("src/sneaky.py", result.stderr)


class BinaryBlobs(SweepCase):
    def test_a_binary_blob_is_refused(self):
        """`git grep -I` skips binaries and patches say only "Binary files differ", so one
        NUL byte would make any payload invisible to every content rule."""
        (self.repo / "payload.bin").write_bytes(b"\x00\x01secret-in-a-binary\x00")
        self.git("add", "-A")
        self.git("commit", "-qm", "binary")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("payload.bin", result.stderr)
        self.assertIn("no content rule can inspect", result.stderr)

    def test_an_empty_file_is_not_treated_as_a_binary_blob(self):
        """`git grep -Il` does not list an empty file, so it falls into the binary set --
        every zero-byte marker and any empty __init__.py would be reported unscannable."""
        self.write("pkg/__init__.py", "")
        self.commit("a.txt", "benign\n")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("__init__.py", result.stderr)

    def test_range_mode_allows_removing_a_binary(self):
        """The guard exists because an ADDED binary can hide a payload. A removal
        publishes nothing to hide, and refusing it would make the two halves of one guard
        disagree about the same change."""
        (self.repo / "art").mkdir()
        (self.repo / "art" / "payload.bin").write_bytes(b"\x00\x01reviewed\x00")
        base = self.commit("a.txt", "benign\n")
        (self.repo / "art" / "payload.bin").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "drop binary")
        result = self.sweep("range", f"{base}..HEAD")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_range_mode_still_refuses_an_added_binary(self):
        base = self.commit("a.txt", "benign\n")
        (self.repo / "art").mkdir()
        (self.repo / "art" / "payload.bin").write_bytes(b"\x00\x01secret\x00")
        self.git("add", "-A")
        self.git("commit", "-qm", "add binary")
        result = self.sweep("range", f"{base}..HEAD")
        self.assertEqual(result.returncode, 1)
        self.assertIn("art/payload.bin", result.stderr)


class TheDiffStateMachine(SweepCase):
    def test_an_added_line_beginning_with_plus_plus_is_not_mistaken_for_a_header(self):
        """`grep -vE '^\\+\\+\\+'` drops a real added line whose content starts `++`, so a
        denied value could be added in one commit, removed in the next, and evade the
        range sweep while the endpoint tree stayed clean."""
        base = self.commit("src/a.txt", "benign\n")
        self.commit("src/leak.txt", "++ZZ-DENIED-LITERAL-ZZ\n")
        (self.repo / "src" / "leak.txt").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "remove")
        self.assertEqual(self.sweep("tree").returncode, 0, "the endpoint really is clean")
        result = self.sweep("range", f"{base}..HEAD")
        self.assertEqual(result.returncode, 1)
        self.assertIn("ZZ-DENIED-LITERAL-ZZ", result.stderr)

    def test_a_real_diff_header_is_still_ignored(self):
        base = self.commit("src/a.txt", "benign\n")
        self.commit("src/b.txt", "harmless\n")
        self.assertEqual(self.sweep("range", f"{base}..HEAD").returncode, 0)

    def test_a_textconv_driver_cannot_hide_content_from_the_diff(self):
        """A `diff` driver declared in .gitattributes makes git show CONVERTED content,
        so a value in a file with a textconv filter is absent from the diff while its
        bytes go out in the commit. The staged and range passes read diffs; `git grep`
        does not apply textconv unless asked, so tree mode is unaffected."""
        self.write(".gitattributes", "*.secret diff=scrub\n")
        self.git("config", "diff.scrub.textconv", "printf 'redacted\\n'")
        base = self.commit("a.txt", "benign\n")
        self.write("docs/keys.secret", "ZZ-DENIED-LITERAL-ZZ\n")
        self.git("add", "-A")
        staged = self.sweep("staged")
        self.assertEqual(staged.returncode, 1, staged.stdout + staged.stderr)

        self.git("commit", "-qm", "the converted file")
        (self.repo / "docs" / "keys.secret").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "remove it again")
        result = self.sweep("range", f"{base}..HEAD")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_a_diff_marker_does_not_manufacture_a_match(self):
        """`+` is a legal address local-part character, so an added line beginning with a
        decorator reads as local-part plus domain. The marker makes it look like an
        address; the code never did."""
        email_rule = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
        self.deny.write_text(
            f"[paths]\nzz-never\n[content]\n{email_rule}\n[allow-content]\nzz-never\n")
        self.write("t.py", '@register.mark("p")\ndef f(): ...\n')
        self.git("add", "-A")
        result = self.sweep("staged")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_range_mode_sees_content_introduced_by_a_merge_resolution(self):
        """`git log -p` emits no diff at all for a merge, so a value created only by
        conflict resolution -- and removed afterwards -- is invisible to both range
        passes."""
        base = self.commit("f.txt", "base\n")
        self.git("checkout", "-qb", "side")
        self.commit("f.txt", "side\n")
        self.git("checkout", "-q", "-")
        self.commit("f.txt", "main\n")
        self.git("merge", "--no-commit", "side", check=False)
        self.write("f.txt", "resolved ZZ-DENIED-LITERAL-ZZ\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "merge")
        self.commit("f.txt", "cleaned\n")
        self.assertEqual(self.sweep("tree").returncode, 0, "endpoint is clean")
        self.assertEqual(self.sweep("range", f"{base}..HEAD").returncode, 1)


class ThePatternFileItself(SweepCase):
    def test_the_pattern_file_in_use_is_excluded_from_the_content_sweep(self):
        """Whichever file FINANCE_DENY_FILE names, not just the canonical path.

        The appended literal goes under an explicit [content] header: appended after
        [allow-content] it would become an ALLOW rule, and the case would pass for a
        reason unrelated to the exclusion it claims to prove."""
        inside = self.repo / "patterns.txt"
        inside.write_text(PATTERNS + "\n[content]\nZZ-DENIED-LITERAL-ZZ\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "patterns")
        self.assertEqual(self.sweep("tree", deny=inside).returncode, 0)

    def test_a_value_hidden_in_the_pattern_file_is_caught(self):
        """The file is excluded because it holds the rules themselves. Excluding the WHOLE
        file makes it a hiding place; only its declared rule lines are exempt, and the
        residue is scanned like any other file."""
        hooks = self.repo / ".githooks"
        hooks.mkdir(exist_ok=True)
        (hooks / "deny-patterns.txt").write_text(
            PATTERNS + "\n# innocuous looking comment: notallowed@zztest.zzdomain\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "patterns")
        result = self.sweep("tree", deny=hooks / "deny-patterns.txt")
        self.assertEqual(result.returncode, 1)
        self.assertIn("pattern-file residue", result.stderr)


class ControlCharacters(SweepCase):
    def test_a_path_with_a_control_character_is_refused(self):
        """git C-quotes such a name, which silently defeats anchored path rules."""
        self.commit("a.txt", "benign\n")
        (self.repo / "line\nbreak.txt").write_bytes(b"x\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "weird")
        result = self.sweep("tree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("control characters", result.stderr)


def _sections(text):
    out, current = {}, None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in ("[paths]", "[content]", "[allow-content]", "[not-swept]"):
            current = stripped
            out.setdefault(current, [])
        elif current:
            out[current].append(stripped)
    return out


class TheRealPatternFile(unittest.TestCase):
    """The file this repository actually enforces, checked as data."""

    def setUp(self):
        self.sections = _sections(REAL_DENY.read_text())

    def test_it_parses_into_populated_sections(self):
        self.assertTrue(self.sections.get("[paths]"), "no path patterns")
        self.assertTrue(self.sections.get("[content]"), "no content patterns")
        self.assertTrue(self.sections.get("[allow-content]"), "no allow patterns")

    def test_every_pattern_compiles_under_the_enforcing_engine(self):
        """`grep -E` is what enforces these; Python's `re` accepts a different grammar."""
        for section in ("[paths]", "[content]", "[allow-content]"):
            for pattern in self.sections.get(section, []):
                result = subprocess.run(["grep", "-E", pattern], input="",
                                        capture_output=True, text=True)
                self.assertLessEqual(result.returncode, 1,
                                     f"grep -E rejects /{pattern}/: {result.stderr}")

    def test_no_allow_rule_is_trivially_broad(self):
        canaries = ["CANARY-9f3c", "nobody@nowhere" + ".invalid", "10.11.12" + ".13"]
        for pattern in self.sections.get("[allow-content]", []):
            for canary in canaries:
                result = subprocess.run(["grep", "-qxE", "--", pattern], input=canary,
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0,
                                    f"/{pattern}/ whole-matches {canary!r}")

    def test_every_exclusion_states_a_reason(self):
        for entry in self.sections.get("[not-swept]", []):
            self.assertIn(" -- ", entry, f"exclusion with no reason: {entry}")
            path, reason = entry.split(" -- ", 1)
            self.assertGreater(len(reason.split()), 5,
                               f"exclusion reason too thin to check: {entry}")
            self.assertTrue((ROOT / path).exists(),
                            f"exclusion names a path that does not exist: {path}")

    def test_the_working_material_rule_catches_the_dot_prefixed_form(self):
        """`(^|/)superpowers/` requires a `/` or the start of the path immediately before
        the match, and `.superpowers/` has a `.` there instead -- so the un-prefixed rule
        misses a plugin's scratch directory entirely."""
        rule = next((p for p in self.sections["[paths]"] if "superpowers" in p), None)
        self.assertIsNotNone(rule, "no working-material path rule")
        for candidate in ("superpowers/state.md", ".superpowers/sdd/plan.md",
                          "some/dir/.superpowers/notes.md"):
            result = subprocess.run(["grep", "-E", "-q", "--", rule], input=candidate,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"/{rule}/ does not match {candidate!r}")

    def test_the_public_pattern_file_carries_no_address_or_private_range(self):
        """Its declared rule lines are exempt from the content sweep; keep the rest of it
        from becoming a hiding place."""
        for line in REAL_DENY.read_text().splitlines():
            if not line.strip().startswith("#"):
                continue
            self.assertIsNone(
                re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", line),
                f"comment carries an address: {line}")
            self.assertIsNone(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line),
                              line)


class TheRealSweepAgainstAFixture(SweepCase):
    """End-to-end: the real pattern file, not a synthetic one, against a throwaway repo."""

    def test_it_refuses_a_committed_dot_superpowers_path(self):
        self.commit(".superpowers/sdd/plan.md", "internal notes\n")
        result = self.sweep("tree", deny=REAL_DENY)
        self.assertEqual(result.returncode, 1)
        self.assertIn("superpowers", result.stderr)

    def test_it_refuses_a_private_address_in_content(self):
        # Assembled at runtime. Written whole, this line would be a finding in this
        # repository's own tree, and the sweep would refuse the test that proves it works.
        address = "192.168." + "1.77"
        self.commit("README.md", f"the box is at {address}\n")
        result = self.sweep("tree", deny=REAL_DENY)
        self.assertEqual(result.returncode, 1)

    def test_it_refuses_an_assigned_token_literal(self):
        self.commit("cfg.py",
                    'webhook_secret = "' + "z" * 40 + '"\n')
        self.assertEqual(self.sweep("tree", deny=REAL_DENY).returncode, 1)

    def test_it_does_not_refuse_this_project_s_own_commit_message_trailers(self):
        """The push hook sweeps commit MESSAGES, and every commit here carries a
        co-author trailer with a no-reply address. Without an allow entry for it the
        sweep refuses every push -- which no fixture with a one-word commit
        message could show."""
        base = self.commit("a.txt", "benign\n")
        self.commit("b.txt", "more\n", message=(
            "feat: something\n\n"
            "Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"))
        result = self.sweep("messages", f"{base}..HEAD", deny=REAL_DENY)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_it_still_refuses_an_unrelated_address_in_a_commit_message(self):
        base = self.commit("a.txt", "benign\n")
        denied = "someone@zztest" + ".zzdomain.invalid"
        self.commit("b.txt", "more\n", message=f"feat: mail {denied}")
        self.assertEqual(self.sweep("messages", f"{base}..HEAD", deny=REAL_DENY).returncode, 1)

    def test_it_does_not_refuse_a_config_lookup(self):
        """`$` is excluded from the value class so that indirection through a variable or
        a config call is not a hit. Without that, the rule refuses honest code and gets
        turned off."""
        self.commit("cfg.py", 'webhook_secret = os.environ["BANKFEED_WEBHOOK_SECRET"]\n')
        result = self.sweep("tree", deny=REAL_DENY)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
