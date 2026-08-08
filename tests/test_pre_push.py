"""The push-time refusal.

The asset, both directions: a push that publishes something nobody swept, and a refusal
of a legitimate push. The second matters as much as the first -- a hook that refuses
everything is uninstalled within a day, and then the first one is unguarded too.

Every case builds a real origin repository and a real clone, and invokes the hook the way
git does: destination remote as the argument, ref lines on stdin. Calling the pieces
directly would test an arrangement of code that git never produces -- and the enumeration
bugs this hook exists to avoid all live in what git passes it.

The scanner is the stub from tests/test_run_gitleaks.py, on PATH. The deny patterns are
this repository's real ones, because the hook's job is to hand git's output to them.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_run_gitleaks import STUB       # noqa: E402  -- one stub, defined once

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / ".githooks" / "pre-push"
ZERO = "0" * 40


class PrePushCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        stub = self.bin / "gitleaks"
        stub.write_text(STUB)
        stub.chmod(0o755)

        self.origin = self.tmp / "origin.git"
        subprocess.run(["git", "init", "-q", "--bare", str(self.origin)], check=True)

        self.repo = self.tmp / "clone"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main", ".")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "T")
        self.git("remote", "add", "origin", str(self.origin))

        for rel in (".githooks/pre-push", ".githooks/deny-patterns.txt",
                    "scripts/deny-sweep.sh", "scripts/run-gitleaks.sh",
                    "scripts/scan_identifiers.py", "scripts/identifier-exceptions.txt"):
            target = self.repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((ROOT / rel).read_text())
            target.chmod(0o755)
        (self.repo / ".githooks" / "root-allowlist.txt").write_text("README.md\n")
        (self.repo / ".githooks" / "gitleaks-allow-sites.txt").write_text("# none\n")
        (self.repo / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
        # The root allowlist above names only README.md, so everything else this fixture
        # commits lives in a subdirectory. The alternative -- allowlisting the fixture's
        # own files -- would make a stray impossible to test here.
        (self.repo / ".githooks" / "root-allowlist.txt").write_text(
            "README.md\n.gitleaks.toml\n")
        self.commit("README.md", "ordinary prose\n")

    def git(self, *args, check=False):
        return subprocess.run(["git", "-C", str(self.repo), *args],
                              capture_output=True, text=True, check=check)

    def commit(self, rel, body, message="ordinary"):
        target = self.repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        self.git("add", "-A")
        self.git("commit", "-qm", message)
        return self.head()

    def head(self, ref="HEAD"):
        return self.git("rev-parse", ref).stdout.strip()

    def push_line(self, local_sha=None, remote_ref="refs/heads/main", remote_sha=ZERO,
                  local_ref="refs/heads/main"):
        return f"{local_ref} {local_sha or self.head()} {remote_ref} {remote_sha}\n"

    def hook(self, stdin, destination="origin"):
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.repo)}
        return subprocess.run(
            ["bash", str(self.repo / ".githooks" / "pre-push"), destination,
             str(self.origin)],
            cwd=self.repo, input=stdin, capture_output=True, text=True, env=env)

    def push(self, *args):
        """A real `git push`, with the hook installed -- the end-to-end path."""
        self.git("config", "core.hooksPath", ".githooks")
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.repo)}
        return subprocess.run(["git", "-C", str(self.repo), "push", *args],
                              capture_output=True, text=True, env=env)


class LegitimatePushesArePermitted(PrePushCase):
    def test_a_clean_first_push_is_allowed(self):
        """Without this every other case here is satisfied by `exit 1`."""
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_clean_push_through_git_itself_is_allowed(self):
        result = self.push("origin", "main")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_ref_deletion_is_allowed(self):
        """Deleting a ref transfers no objects: there is no tree and no commit to sweep."""
        result = self.hook(f"(delete) {ZERO} refs/heads/old {self.head()}\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_deleted_ref_name_is_still_swept(self):
        """The name goes to the server and into its event log even though no object does.
        Both surface enumerations marked this UNCHECKED: the hook skipped a deletion
        before it looked at the name."""
        address = "192.168." + "3.3"
        result = self.hook(f"(delete) {ZERO} refs/heads/host-{address} {self.head()}\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_a_second_push_of_already_published_commits_is_allowed(self):
        self.push("origin", "main")
        result = self.hook(self.push_line(remote_sha=self.head()))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class OnlyBranchesArePublishable(PrePushCase):
    def test_a_tag_is_refused(self):
        """A tag publishes an annotation, a tagger identity and a name, none of them a
        commit and none of them covered by any sweep here."""
        result = self.hook(self.push_line(remote_ref="refs/tags/v1",
                                          local_ref="refs/tags/v1"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("only refs/heads/*", result.stderr)

    def test_an_arbitrary_namespace_is_refused(self):
        """refs/archive/* can carry an object that is already reachable, so it introduces
        no commits and would slip past the enumeration entirely."""
        result = self.hook(self.push_line(remote_ref="refs/archive/x"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("only refs/heads/*", result.stderr)


class TheBranchNameIsPublishedText(PrePushCase):
    def test_a_denied_branch_name_is_refused(self):
        address = "192.168." + "1.77"
        result = self.hook(self.push_line(remote_ref=f"refs/heads/host-{address}"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("branch name", result.stderr)

    def test_the_name_is_checked_even_when_no_commits_are_introduced(self):
        """`git push <published-sha>:refs/heads/<name>` publishes a NAME while adding no
        objects. A name check placed after the enumeration never runs for this case, which
        is the one it exists for."""
        self.push("origin", "main")
        address = "10.1." + "2.3"
        result = self.hook(self.push_line(remote_ref=f"refs/heads/host-{address}",
                                          remote_sha=ZERO))
        self.assertEqual(result.returncode, 1)
        self.assertIn("branch name", result.stderr)


class TheIntroducedSetIsDestinationRelative(PrePushCase):
    def test_a_commit_the_destination_lacks_is_swept(self):
        """The enumeration asks the REMOTE what it has. A tracking-ref-based one would
        call these commits already-published -- refs/remotes/origin/main exists locally
        and points at them -- while THIS destination has never seen any of it.

        The value is added and then removed, so the endpoint tree is clean and only the
        range pass can report it. With the leak still in the tree, the tree sweep would
        refuse the push no matter how the range was enumerated, and this case would pass
        against the very bug it exists to catch."""
        address = "172.16." + "5.5"
        self.commit("docs/leak.md", f"the box is at {address}\n")
        (self.repo / "docs" / "leak.md").unlink()
        self.commit("docs/gone.md", "removed again\n")
        subprocess.run(["git", "-C", str(self.repo), "push", "-q", "origin", "main"],
                       check=True)                      # no hook: this is the fixture
        self.assertEqual(self.hook(self.push_line(remote_sha=self.head())).returncode, 0,
                         "nothing new for origin, and its tree is clean")

        other = self.tmp / "other.git"
        subprocess.run(["git", "init", "-q", "--bare", str(other)], check=True)
        self.git("remote", "add", "other", str(other))
        result = self.hook(self.push_line(remote_sha=ZERO), destination="other")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("deny content", result.stderr)

    def test_a_remote_with_less_history_gets_the_whole_ancestry_swept(self):
        """Pushing to a destination that has never seen this branch publishes every
        commit behind it, not just the ones since some local marker. Added and removed
        again, so only the range pass can see it."""
        address = "10.9." + "8.7"
        self.commit("docs/leak.md", f"the box is at {address}\n")
        (self.repo / "docs" / "leak.md").unlink()
        self.commit("docs/clean.md", "nothing here\n")
        result = self.hook(self.push_line(remote_sha=ZERO))
        self.assertEqual(result.returncode, 1)
        self.assertIn("deny content", result.stderr)

    def test_a_commit_already_public_on_another_branch_is_not_reintroduced(self):
        """A false refusal, which is as much a defect as a miss. `remote_sha..local_sha`
        also sweeps the destination's OTHER branches' commits, so a legitimate update
        whose parent is already public elsewhere is blocked with no remedy but
        --no-verify. The introduced set is destination-relative for updates too."""
        base = self.head()
        subprocess.run(["git", "-C", str(self.repo), "push", "-q", "--no-verify",
                        "origin", f"{base}:refs/heads/main"], check=True)
        address = "192.168." + "9.9"
        leak = self.commit("docs/note.md", f"the box is at {address}\n")
        subprocess.run(["git", "-C", str(self.repo), "push", "-q", "--no-verify",
                        "origin", f"{leak}:refs/heads/other"], check=True)
        (self.repo / "docs" / "note.md").unlink()
        clean = self.commit("docs/clean.md", "nothing here\n")

        result = self.hook(self.push_line(local_sha=clean, remote_sha=base))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 commit(s) introduced", result.stdout)

    def test_a_commit_outside_the_introduced_range_is_not_reported(self):
        """The other direction: content already at the destination is not this push's to
        refuse, or every push after a mistake is blocked forever."""
        address = "10.9." + "8.7"
        self.commit("docs/leak.md", f"the box is at {address}\n")
        published = self.head()
        subprocess.run(["git", "-C", str(self.repo), "push", "-q", "origin", "main"],
                       check=True)                      # no hook: this is the fixture
        self.commit("docs/clean.md", "nothing here\n")
        result = self.hook(self.push_line(remote_sha=published))
        self.assertIn("deny content", result.stderr + result.stdout,
                      "the tree scan still sees it, which is correct")
        # ...but the RANGE pass must not be what reports it. Prove the range is narrow by
        # removing the file so the tree is clean, and confirming the push then passes.
        (self.repo / "docs" / "leak.md").unlink()
        self.commit("docs/removed.md", "gone\n")
        result = self.hook(self.push_line(remote_sha=published))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class MetadataIsPublishedToo(PrePushCase):
    def test_a_denied_commit_message_is_refused(self):
        address = "192.168." + "4.4"
        self.commit("docs/note.md", "text\n", message=f"work at {address}")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1)

    def test_an_empty_commit_with_a_denied_message_is_refused(self):
        """An empty commit changes no file, so every content-only check passes it, and it
        publishes its message and its identities all the same."""
        address = "192.168." + "4.4"
        self.git("commit", "-q", "--allow-empty", "-m", f"work at {address}")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1)

    def test_a_value_in_an_extra_commit_header_is_refused(self):
        """The message and identity checks are RENDERINGS. A commit object carries more
        than they show -- `gpgsig`, `mergetag`, `encoding`, and any other header git will
        round-trip -- and whatever is in the object is what gets published. The raw object
        is swept, so a value hidden in a header nobody renders is still found."""
        address = "192.168." + "5.5"
        raw = self.git("cat-file", "commit", self.head()).stdout
        head, _, message = raw.partition("\n\n")
        doctored = f"{head}\nencoding note-{address}\n\n{message}"
        sha = subprocess.run(["git", "-C", str(self.repo), "hash-object", "-t", "commit",
                              "-w", "--stdin"], input=doctored, capture_output=True,
                             text=True, check=True).stdout.strip()
        result = self.hook(self.push_line(local_sha=sha))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_an_account_identifier_in_a_commit_message_is_refused(self):
        """The identifier scan saw file blobs only, so a commit MESSAGE carrying an
        account number reached neither scanner: the deny sweep has no checksum rule and
        the identifier scan was never given the object."""
        self.git("commit", "-q", "--allow-empty", "-m",
                 f"tidy up account {AccountDataIsCheckedAtPushTime.valid_iban()}")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_a_denied_author_identity_is_refused(self):
        """An identity lives in the commit header, so no diff and no file content carries
        it -- the only thing that sees it is a check that asks for it."""
        # Assembled, like every other denied value in these tests: written whole, this
        # line is a finding in this repository's own tree and the sweep refuses the file
        # that proves the sweep works. The `.invalid` suffix puts it outside the allow
        # entry for the synthetic fixture domain, which is what makes it bite here.
        denied = "someone@zztest" + ".zzdomain.invalid"
        self.git("config", "user.email", denied)
        self.commit("docs/note.md", "text\n")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1)

    def test_an_ordinary_identity_is_not_refused(self):
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class AccountDataIsCheckedAtPushTime(PrePushCase):
    """The asset. Nothing used to check account data at push time: the
    commit hook sees the index, and CI sees the objects only AFTER they reached the
    remote, when publication is already irreversible."""

    @staticmethod
    def valid_iban(country="NL", bban="REVO0000000001"):
        """Computed, never a literal -- a checksum-valid value written into this file is
        the thing the gate reports."""
        digits = "".join(str(int(c, 36)) if c.isalpha() else c
                         for c in bban + country + "00")
        return "%s%02d%s" % (country, 98 - int(digits) % 97, bban)

    def test_an_identifier_in_the_published_tree_is_refused(self):
        self.commit("docs/account.md", f"account {self.valid_iban()}\n")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1)
        self.assertIn("account identifier", result.stderr)

    def test_an_identifier_added_then_removed_is_still_refused(self):
        """The endpoint tree is clean and the blob is published all the same. This is the
        case the tree scan cannot see and CI can only report afterwards."""
        self.commit("docs/account.md", f"account {self.valid_iban()}\n")
        (self.repo / "docs" / "account.md").unlink()
        self.commit("docs/gone.md", "removed again\n")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1)
        self.assertIn("introduced commits", result.stderr)

    def test_an_identifier_in_an_already_published_tree_is_still_refused(self):
        """Isolates the TREE blob scan: the commit is already at the destination, so
        there are no introduced commits and the range scan has nothing to look at. With
        the identifier in the range too, this case passed with the tree scan deleted."""
        self.commit("docs/account.md", f"account {self.valid_iban()}\n")
        subprocess.run(["git", "-C", str(self.repo), "push", "-q", "--no-verify",
                        "origin", "main"], check=True)          # fixture, not the test
        result = self.hook(self.push_line(remote_sha=self.head()))
        self.assertEqual(result.returncode, 1)
        self.assertIn("that tree", result.stderr)

    def test_a_synthetic_identifier_is_not_refused(self):
        """`NL00` check digits can never be valid, so a fixture cannot silently become a
        real account -- and a guard that refused them would be uninstalled."""
        self.commit("docs/account.md", "account NL00REVO0000000001\n")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_pathname_containing_a_space_is_not_truncated_into_an_exclusion(self):
        """Demonstrated against this code. `awk '{print $6}'` reduced
        `docs/file stolen` to `docs/file`, which is a DIFFERENT, excluded path -- so an
        included account identifier was dropped from the scan as if it were the exempt
        file. The endpoint tree is clean, so nothing else would have looked at it."""
        policy = self.repo / ".githooks" / "deny-patterns.txt"
        lines = policy.read_text().splitlines(keepends=True)
        lines.insert(lines.index("[not-swept]\n") + 1,
                     "docs/file -- one exact, harmless, declared file\n")
        policy.write_text("".join(lines))
        (self.repo / "docs").mkdir(parents=True, exist_ok=True)
        (self.repo / "docs" / "file").write_text("harmless\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "the declared file")

        (self.repo / "docs" / "file stolen").write_text(self.valid_iban() + "\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "an account number in a path with a space")
        (self.repo / "docs" / "file stolen").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "remove it again")

        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("account identifier", result.stderr)

    def test_an_account_identifier_in_a_filename_is_refused(self):
        """A tree-entry name is published text. Every check treated a path as a path --
        used for policy and exclusions, never read as data -- so an account number
        written as a FILENAME went out unexamined."""
        (self.repo / "docs").mkdir(parents=True, exist_ok=True)
        (self.repo / "docs" / f"{self.valid_iban()}.md").write_text("nothing here\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "a name that is an account number")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FILENAME", result.stderr)

    def test_an_account_identifier_in_an_already_published_filename_is_refused(self):
        """Isolates the TREE side. With the commit already at the destination there are
        no introduced commits, so the range check has nothing to look at and only the
        published tree's names can catch it."""
        (self.repo / "docs").mkdir(parents=True, exist_ok=True)
        (self.repo / "docs" / f"{self.valid_iban()}.md").write_text("nothing here\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "a name that is an account number")
        subprocess.run(["git", "-C", str(self.repo), "push", "-q", "--no-verify",
                        "origin", "main"], check=True)          # fixture, not the test
        result = self.hook(self.push_line(remote_sha=self.head()))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FILENAME", result.stderr)

    def test_a_binary_blob_does_not_clear_the_text_blobs_beside_it(self):
        """`git cat-file --batch` concatenates payloads, and one blob that is not valid
        UTF-8 makes the join undecodable -- which the scanner correctly reports as
        "nothing textual to find". So a single image or allowlisted fixture cleared every
        text blob in the same push. Each blob is now a document of its own."""
        (self.repo / "fixtures").mkdir(parents=True, exist_ok=True)
        (self.repo / "fixtures" / "blob.bin").write_bytes(b"\xff\x00binary\n")
        (self.repo / ".githooks" / "binary-allowlist.txt").write_text("fixtures/blob.bin\n")
        (self.repo / "docs").mkdir(parents=True, exist_ok=True)
        (self.repo / "docs" / "account.txt").write_text(self.valid_iban() + "\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "a binary and an account number together")

        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("account identifier", result.stderr)

    def test_a_submodule_entry_is_refused(self):
        """A gitlink publishes a commit id belonging to a repository nothing here can
        read. This component has no submodules, so one appearing is a change of kind."""
        other = self.tmp / "other"
        other.mkdir()
        subprocess.run(["git", "init", "-q", str(other)], check=True)
        (other / "f.txt").write_text("x\n")
        subprocess.run(["git", "-C", str(other), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(other), "-c", "user.email=t@t", "-c",
                        "user.name=t", "commit", "-qm", "x"], check=True)
        sha = subprocess.run(["git", "-C", str(other), "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
        self.git("update-index", "--add", "--cacheinfo", f"160000,{sha},vendor/other")
        self.git("commit", "-qm", "add a submodule entry")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("submodule", result.stderr)

    def test_a_type_change_blob_is_scanned(self):
        """`--diff-filter=AMR` omits git status `T`. A symlink replaced by a regular file
        carrying an account number is a type change, so its record was absent from the
        enumeration and the blob was published with nothing having read it."""
        (self.repo / "docs").mkdir(parents=True, exist_ok=True)
        (self.repo / "docs" / "thing").symlink_to("README.md")
        self.git("add", "-A")
        self.git("commit", "-qm", "a symlink")
        (self.repo / "docs" / "thing").unlink()
        (self.repo / "docs" / "thing").write_text(self.valid_iban() + "\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "the symlink becomes a file")
        (self.repo / "docs" / "thing").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "gone again")

        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("account identifier", result.stderr)

    def test_an_uncommitted_guard_script_cannot_clear_a_published_ref(self):
        """The programs are the largest policy input there is. An uncommitted
        run-gitleaks.sh reduced to `exit 0` published a committed private key while the
        hook reported success."""
        self.commit("keys/test.pem", "-----BEGIN PRIVATE" " KEY-----\nAAAA\n")
        scanner = self.repo / "scripts" / "run-gitleaks.sh"
        scanner.write_text("#!/usr/bin/env bash\nexit 0\n")
        scanner.chmod(0o755)
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not the policy in the commit", result.stderr)

    def test_an_excluded_alias_cannot_hide_an_included_blob(self):
        """`git rev-list --objects` prints ONE pathname per deduplicated object. With the
        same bytes at an excluded path and an included one, the excluded name can be the
        name it prints -- and a filter keyed on that name then drops the only record of a
        blob that IS being published. Demonstrated: the account number went out with no refusal."""
        policy = self.repo / ".githooks" / "deny-patterns.txt"
        lines = policy.read_text().splitlines(keepends=True)
        lines.insert(lines.index("[not-swept]\n") + 1,
                     "aaa/ -- declared working material, never published\n")
        policy.write_text("".join(lines))

        value = self.valid_iban()
        for rel in ("aaa/a.md", "zzz/account.md"):     # identical bytes, one object
            target = self.repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(value + "\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "the same blob at two paths")
        for rel in ("aaa/a.md", "zzz/account.md"):
            (self.repo / rel).unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "remove both again")

        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("account identifier", result.stderr)

    def test_an_uncommitted_identifier_exception_cannot_clear_a_committed_ref(self):
        """scripts/identifier-exceptions.txt is a policy input like any other, and it was
        missing from the list -- so an uncommitted citation cleared a checksum-valid
        account number out of a committed ref, which is the asset this phase is for."""
        value = self.valid_iban()
        self.commit("docs/account.md", value + "\n")
        exceptions = self.repo / "scripts" / "identifier-exceptions.txt"
        exceptions.write_text(exceptions.read_text()
                              + f"{value}  # asserted public source\n")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not the policy in the commit", result.stderr)

    def test_a_declared_not_swept_tree_is_not_scanned_for_identifiers(self):
        """The identifier scan reads object content and has no path to exclude by, so the
        filtering happens before the blobs reach it. Without that, every push refuses on
        the working material the sweep already declares it does not read."""
        policy = self.repo / ".githooks" / "deny-patterns.txt"
        lines = policy.read_text().splitlines(keepends=True)
        at = lines.index("[not-swept]\n")
        lines.insert(at + 1, "working/ -- declared working material, never published\n")
        policy.write_text("".join(lines))
        self.commit("working/notes.md", f"account {self.valid_iban()}\n")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ThePublishedRefIsWhatIsScanned(PrePushCase):
    """`git push payload:published` publishes a tree the
    checkout knows nothing about, and when the destination already has those objects
    there are no introduced commits either -- so a tree scan pinned to HEAD examined a
    tree nobody was publishing."""

    def test_the_secret_scanner_reads_the_ref_being_published(self):
        """The other half of the same defect: not only the deny sweep but the pinned
        scanner was reading HEAD rather than the revision on the ref line."""
        self.push("origin", "main")
        self.git("checkout", "-qb", "payload")
        payload = self.commit("src/config.py", 'token = "ZZ' '-FAKE-SECRET-ZZ"\n')
        self.git("checkout", "-q", "main")
        subprocess.run(["git", "-C", str(self.repo), "push", "-q", "--no-verify",
                        "origin", "payload:refs/heads/hidden"], check=True)
        result = self.hook(f"refs/heads/payload {payload} refs/heads/published {ZERO}\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("secret scanner", result.stderr)

    def test_every_ref_in_a_multi_ref_push_is_scanned_at_its_own_revision(self):
        """`git push --all` hands the hook several ref lines at once. Each is a distinct
        tree, and a child process reading the hook's stdin would silently swallow the
        lines after the first -- which would publish them unexamined."""
        clean = self.head()
        self.git("checkout", "-qb", "second")
        address = "192.168." + "7.7"
        dirty = self.commit("docs/leak.md", f"the box is at {address}\n")
        self.git("checkout", "-q", "main")
        result = self.hook(
            f"refs/heads/main {clean} refs/heads/main {ZERO}\n"
            f"refs/heads/second {dirty} refs/heads/second {ZERO}\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("docs/leak.md", result.stderr)
        self.assertIn(clean, result.stdout, "the first ref was processed too")

    def test_a_ref_other_than_head_is_scanned(self):
        self.push("origin", "main")
        self.git("checkout", "-qb", "payload")
        address = "192.168." + "44.55"
        payload = self.commit("docs/leak.md", f"the box is at {address}\n")
        self.git("checkout", "-q", "main")
        # --no-verify: this is the fixture putting the objects at the destination, not
        # the behaviour under test. self.push() above installed the hook, which would
        # (correctly) refuse this one.
        subprocess.run(["git", "-C", str(self.repo), "push", "-q", "--no-verify",
                        "origin", "payload:refs/heads/hidden"], check=True)

        result = self.hook(f"refs/heads/payload {payload} refs/heads/published {ZERO}\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("deny content", result.stderr)


class ThePolicyIsTheCommittedOne(PrePushCase):
    """the sweep's test-only policy override was honoured
    from the hook, so an environment variable -- left over in a shell from an afternoon
    of testing, or set deliberately -- decided what this repository publishes."""

    def test_an_uncommitted_inventory_line_cannot_clear_a_published_ref(self):
        """Every gate reads its policy from the WORKING TREE, and the thing published is
        a commit. An inventory line added while investigating and never committed made a
        published ref carrying a private key scan clean -- this has been
        demonstrated."""
        self.commit("keys/test.pem", "-----BEGIN PRIVATE" " KEY-----\nAAAA\n")
        refused = self.hook(self.push_line())
        self.assertEqual(refused.returncode, 1, "the committed inventory declares nothing")

        inventory = self.repo / ".githooks" / "gitleaks-allow-sites.txt"
        inventory.write_text(inventory.read_text() + "keys/test.pem private-key 1\n")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1,
                         "an uncommitted exemption must not clear a committed ref")
        self.assertIn("not the policy in the commit", result.stderr)

    def test_a_committed_policy_change_is_accepted(self):
        """The other direction. A hook that refused a legitimately committed policy
        change would make the policy unchangeable, which is its own kind of broken."""
        self.commit("keys/test.pem", "-----BEGIN PRIVATE" " KEY-----\nAAAA\n")
        inventory = self.repo / ".githooks" / "gitleaks-allow-sites.txt"
        inventory.write_text(inventory.read_text() + "keys/test.pem private-key 1\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "declare the fixture")
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_policy_file_missing_from_the_ref_is_refused(self):
        """Publishing a ref that predates the policy would apply rules the commit does
        not carry -- and the reader of that commit could not reproduce the result."""
        (self.repo / ".githooks" / "deny-patterns.txt").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "drop the policy from the tree")
        (self.repo / ".githooks" / "deny-patterns.txt").write_text(
            (ROOT / ".githooks" / "deny-patterns.txt").read_text())
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1)
        self.assertIn("absent in the commit", result.stderr)

    def test_an_environment_override_does_not_relax_the_hook(self):
        permissive = self.tmp / "permissive.txt"
        permissive.write_text("[not-swept]\ndocs/ -- anything at all\n"
                              "[paths]\nzz-never\n[content]\nzz-never\n"
                              "[allow-content]\nzz-never\n")
        address = "192.168." + "44.55"
        self.commit("docs/leak.md", f"the box is at {address}\n")
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.repo),
               "FINANCE_DENY_FILE": str(permissive)}
        result = subprocess.run(
            ["bash", str(self.repo / ".githooks" / "pre-push"), "origin", str(self.origin)],
            cwd=self.repo, input=self.push_line(), capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("deny content", result.stderr)


class ItFailsClosed(PrePushCase):
    def test_a_missing_sweep_is_refused(self):
        (self.repo / "scripts" / "deny-sweep.sh").unlink()
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing or not executable", result.stderr)

    def test_a_missing_scanner_is_refused(self):
        (self.repo / "scripts" / "run-gitleaks.sh").unlink()
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing or not executable", result.stderr)

    def test_a_secret_in_the_tree_is_refused_even_with_nothing_new_to_publish(self):
        """The tree scan is unconditional, and this is the only shape that isolates it:
        the commit is ALREADY at the destination, so the range passes have nothing to
        look at and every other check falls through. A push that adds no objects while
        the published tree still carries a secret is still a push worth refusing."""
        self.commit("src/config.py", 'token = "ZZ' '-FAKE-SECRET-ZZ"\n')
        subprocess.run(["git", "-C", str(self.repo), "push", "-q", "origin", "main"],
                       check=True)                      # no hook: this is the fixture
        result = self.hook(self.push_line(remote_sha=self.head()))
        self.assertEqual(result.returncode, 1)
        self.assertIn("secret scanner", result.stderr)

    def test_a_secret_in_a_commit_message_reaches_the_secret_scanner(self):
        """`gitleaks git` examines patch content, so a credential in a message, an extra
        header or a non-email identity reached no secret scan at all. The raw objects go
        to the scanner as a prepared directory."""
        self.git("commit", "-q", "--allow-empty", "-m",
                 'cleanup token = "ZZ' '-FAKE-SECRET-ZZ"')
        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("secret scanner", result.stderr)

    def test_a_secret_introduced_by_the_push_is_refused(self):
        """Added and removed again, so the endpoint tree is clean and only the RANGE scan
        can report it. With the secret left in place this case passed with the range
        scanner deleted from the hook -- this has been demonstrated."""
        self.commit("src/config.py", 'token = "ZZ' '-FAKE-SECRET-ZZ"\n')
        (self.repo / "src" / "config.py").unlink()
        self.commit("src/gone.py", "nothing here\n")

        clean = subprocess.run(["bash", str(self.repo / "scripts" / "run-gitleaks.sh"),
                                "tree"], cwd=self.repo, capture_output=True, text=True,
                               env={"PATH": f"{self.bin}:/usr/bin:/bin",
                                    "HOME": str(self.repo)})
        self.assertEqual(clean.returncode, 0, "the endpoint tree really is clean")

        result = self.hook(self.push_line())
        self.assertEqual(result.returncode, 1)
        self.assertIn("secret scanner", result.stderr)


class TheRealHook(unittest.TestCase):
    def test_it_exists_and_is_executable(self):
        self.assertTrue(HOOK.exists())
        self.assertTrue(HOOK.stat().st_mode & 0o111, "must be executable")

    def test_it_has_no_override_variable(self):
        """`git push --no-verify` is already the door. A second one would be a branch in
        this hook that no test covers and that nothing forces anyone to explain. Checked
        as an environment-variable name rather than as the word, which the comments
        legitimately use when explaining why FINANCE_DENY_FILE is unset here."""
        import re
        text = HOOK.read_text()
        self.assertIsNone(re.search(r"\$\{?[A-Z_]*OVERRIDE", text))
        self.assertIn("unset FINANCE_DENY_FILE", text)


if __name__ == "__main__":
    unittest.main()
