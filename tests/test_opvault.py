import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
import opvault  # noqa: E402


class Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class Runner:
    """Records every subprocess invocation; replays canned results."""

    def __init__(self, results):
        self.results, self.calls = list(results), []

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class Base(unittest.TestCase):
    def runner(self, *results):
        r = Runner(results)
        self.addCleanup(setattr, opvault, "RUN", opvault.RUN)
        opvault.RUN = r
        return r

    def with_token(self):
        import os
        self.addCleanup(os.environ.pop, "OP_SERVICE_ACCOUNT_TOKEN", None)
        os.environ["OP_SERVICE_ACCOUNT_TOKEN"] = "ops_fake"

    def with_vault(self, name="ExampleVault"):
        import os
        self.addCleanup(os.environ.pop, "BANKFEED_OP_VAULT", None)
        os.environ["BANKFEED_OP_VAULT"] = name


class TestSubprocessHygiene(Base):
    def test_every_call_passes_devnull_stdin_and_text_mode(self):
        # The DEVNULL rule is load-bearing: under a heredoc the child
        # inherits exhausted stdin and op reports "invalid JSON provided"
        # — this cost one single-use sign-in code live.
        r = self.runner(Proc(stdout="v\n"))
        opvault.read("op://ExampleVault/Enable Banking/refresh token")
        _, kw = r.calls[0]
        self.assertIs(kw["stdin"], subprocess.DEVNULL)
        self.assertTrue(kw["text"])
        self.assertTrue(kw["capture_output"])

    def test_read_strips_exactly_one_trailing_newline(self):
        # `op read` appends one; the refresh token is REJECTED with it
        # attached. A PEM's own interior newlines must survive.
        self.runner(Proc(stdout="-----BEGIN X-----\nAAA\n-----END X-----\n"))
        out = opvault.read("op://ExampleVault/EnableBanking Production/private key")
        self.assertEqual(out, "-----BEGIN X-----\nAAA\n-----END X-----")

    def test_read_builds_the_op_read_argv(self):
        r = self.runner(Proc(stdout="v\n"))
        opvault.read(opvault.REF_REFRESH_TOKEN)
        self.assertEqual(r.calls[0][0],
                         ["op", "read", opvault.REF_REFRESH_TOKEN])


class TestErrors(Base):
    def test_a_failed_call_raises_operror_with_the_stderr_tail(self):
        self.runner(Proc(returncode=1,
                         stderr='[ERROR] "refresh token" isn\'t a field\n'))
        with self.assertRaises(opvault.OpError) as ctx:
            opvault.read(opvault.REF_REFRESH_TOKEN)
        self.assertIn("isn't a field", str(ctx.exception))

    def test_operror_never_carries_the_written_value_even_when_op_echoes_it(self):
        # HOSTILE stderr: op may echo the failing assignment argv, which
        # contains the secret. The redaction must hold against exactly
        # that, not only against benign messages.
        self.runner(Proc(returncode=1, stderr=(
            '[ERROR] invalid assignment '
            '"refresh token[password]=SECRET-VALUE-1"\n')))
        with self.assertRaises(opvault.OpError) as ctx:
            opvault.set_field("Enable Banking", "ExampleVault", "refresh token",
                              "SECRET-VALUE-1")
        self.assertNotIn("SECRET-VALUE-1", str(ctx.exception))
        self.assertIn("<redacted>", str(ctx.exception))

    def test_redaction_survives_truncation_of_a_long_secret(self):
        # A refresh token is longer than the 200-char error budget; if the tail
        # were truncated BEFORE redaction, only an unmatchable prefix would
        # remain and the secret would leak. The secret here must exceed the
        # budget for this test to mean anything — a short one passes against
        # the broken order too.
        secret = "S3CR" * 100                            # 400 chars
        self.runner(Proc(returncode=1, stderr=(
            '[ERROR] invalid assignment "refresh token[password]=%s"\n'
            % secret)))
        with self.assertRaises(opvault.OpError) as ctx:
            opvault.set_field("Enable Banking", "ExampleVault", "refresh token",
                              secret)
        self.assertNotIn(secret, str(ctx.exception))
        self.assertNotIn(secret[:50], str(ctx.exception))  # no prefix either

    def test_a_missing_op_binary_is_an_operror_not_a_crash(self):
        self.runner(FileNotFoundError("op"))
        with self.assertRaises(opvault.OpError):
            opvault.read(opvault.REF_REFRESH_TOKEN)

    def test_a_timeout_never_leaks_the_argv_it_interrupted(self):
        # subprocess.TimeoutExpired carries `cmd` — the full argv, including
        # the secret assignment. It must be swallowed into a value-free
        # OpError, with the cause chain severed so tracebacks cannot resurface
        # it.
        secret = "S3CR" * 100
        argv = ["op", "item", "edit", "Enable Banking", "--vault", "ExampleVault",
                "refresh token[password]=" + secret]
        self.runner(subprocess.TimeoutExpired(cmd=argv, timeout=60))
        with self.assertRaises(opvault.OpError) as ctx:
            opvault.set_field("Enable Banking", "ExampleVault", "refresh token",
                              secret)
        self.assertNotIn(secret[:20], str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIn("timed out", str(ctx.exception))

    def test_not_found_is_distinguished_from_every_other_failure(self):
        # The forge rung branches on THIS flag: a transient op failure mis-read
        # as absence would forge a duplicate key item over the real one. Only
        # op's explicit not-found wording sets it.
        self.runner(Proc(returncode=1, stderr=(
            '[ERROR] "EnableBanking Production" isn\'t an item in the '
            '"ExampleVault" vault\n')))
        with self.assertRaises(opvault.OpError) as ctx:
            opvault.read(opvault.REF_PRIVATE_KEY)
        self.assertTrue(ctx.exception.not_found)

    def test_a_missing_field_on_an_existing_item_is_also_not_found(self):
        # A fresh credential item carries no "refresh token" field until the
        # first store, and op reports that as ISN'T A FIELD — item-level
        # wording alone would misread it as a fault and the sign-in dance would
        # never start.
        self.runner(Proc(returncode=1,
                         stderr='[ERROR] "refresh token" isn\'t a field\n'))
        with self.assertRaises(opvault.OpError) as ctx:
            opvault.read(opvault.REF_REFRESH_TOKEN)
        self.assertTrue(ctx.exception.not_found)

    def test_a_timeout_or_auth_failure_is_NOT_not_found(self):
        for stderr in ("[ERROR] error initializing client: timed out\n",
                       "[ERROR] 401: authentication required\n",
                       ""):
            self.runner(Proc(returncode=1, stderr=stderr))
            with self.assertRaises(opvault.OpError) as ctx:
                opvault.read(opvault.REF_PRIVATE_KEY)
            self.assertFalse(ctx.exception.not_found)


class TestItemExists(Base):
    def test_true_when_op_item_get_succeeds(self):
        r = self.runner(Proc(stdout="{}\n"))
        self.assertTrue(opvault.item_exists("EnableBanking Production",
                                            "ExampleVault"))
        self.assertEqual(r.calls[0][0][:3], ["op", "item", "get"])

    def test_false_only_on_explicit_not_found(self):
        self.runner(Proc(returncode=1, stderr=(
            '[ERROR] "EnableBanking Production" isn\'t an item. Specify '
            'the item with its UUID, name, or domain.\n')))
        self.assertFalse(opvault.item_exists("EnableBanking Production",
                                             "ExampleVault"))

    def test_a_transient_failure_raises_instead_of_reporting_absent(self):
        # "absent" is a CREATE-authorizing answer; a timeout must never
        # produce it.
        self.runner(Proc(returncode=1,
                         stderr="[ERROR] error initializing client\n"))
        with self.assertRaises(opvault.OpError):
            opvault.item_exists("EnableBanking Production", "ExampleVault")


class TestWrites(Base):
    def test_set_field_concealed_uses_the_password_assignment(self):
        r = self.runner(Proc())
        opvault.set_field("Enable Banking", "ExampleVault", "refresh token", "tok")
        self.assertEqual(r.calls[0][0],
                         ["op", "item", "edit", "Enable Banking",
                          "--vault", "ExampleVault", "refresh token[password]=tok"])

    def test_set_field_plain_uses_the_text_assignment(self):
        r = self.runner(Proc())
        opvault.set_field("Enable Banking", "ExampleVault", "username",
                          "me@example.com", concealed=False)
        self.assertEqual(r.calls[0][0][-1], "username[text]=me@example.com")

    def test_create_ssh_key_forges_rsa_4096_inside_the_vault(self):
        # The verified route: 1Password generates the key; no key material ever
        # exists outside the vault.
        r = self.runner(Proc())
        opvault.create_ssh_key("EnableBanking Production", "ExampleVault")
        self.assertEqual(r.calls[0][0],
                         ["op", "item", "create", "--category", "ssh",
                          "--title", "EnableBanking Production",
                          "--vault", "ExampleVault",
                          "--ssh-generate-key", "rsa,4096"])


class TestStatus(Base):
    def test_usable_when_vault_and_token_set_and_binary_answers(self):
        self.with_vault()
        self.with_token()
        self.runner(Proc(stdout="2.34.0\n"))
        self.assertIsNone(opvault.status())

    def test_missing_vault_is_named_before_token_and_any_subprocess(self):
        # The vault is the plugin's one configuration element; an unset
        # BANKFEED_OP_VAULT must be named precisely — not surface later as
        # a malformed op:// read against `op:///…`.
        import os
        os.environ.pop("BANKFEED_OP_VAULT", None)
        self.with_token()
        r = self.runner()                       # would raise if consulted
        self.assertIn("BANKFEED_OP_VAULT", opvault.status())
        self.assertEqual(r.calls, [])

    def test_missing_token_is_named_before_any_subprocess_runs(self):
        import os
        self.with_vault()
        os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
        r = self.runner()                       # would raise if consulted
        self.assertIn("OP_SERVICE_ACCOUNT_TOKEN", opvault.status())
        self.assertEqual(r.calls, [])

    def test_missing_binary_is_a_reason_not_an_exception(self):
        self.with_vault()
        self.with_token()
        self.runner(FileNotFoundError("op"))
        self.assertIn("not installed", opvault.status())


class TestConstants(Base):
    def test_the_refs_derive_from_the_configured_vault(self):
        # VAULT and every REF_* resolve from BANKFEED_OP_VAULT at access
        # time: the status() guard and the references must never disagree
        # about which vault is in play.
        self.with_vault("ExampleVault")
        self.assertEqual(opvault.VAULT, "ExampleVault")
        self.assertEqual(opvault.REF_PRIVATE_KEY,
                         "op://ExampleVault/EnableBanking Key/private key")
        self.assertEqual(opvault.REF_REFRESH_TOKEN,
                         "op://ExampleVault/EnableBanking/refresh token")
        self.assertEqual(opvault.REF_EMAIL,
                         "op://ExampleVault/EnableBanking/username")

    def test_the_refs_track_a_vault_change_without_reimport(self):
        self.with_vault("Other")
        self.assertEqual(opvault.REF_PRIVATE_KEY,
                         "op://Other/EnableBanking Key/private key")


class SandboxBase(Base):
    def with_mode(self, value):
        import os
        import ebmode
        self.addCleanup(os.environ.pop, ebmode.ENV_MODE_VAR, None)
        self.addCleanup(ebmode._reset)
        os.environ[ebmode.ENV_MODE_VAR] = value
        ebmode._reset()


class TestModeDerivedNames(SandboxBase):
    def test_sandbox_items_carry_the_suffix_and_production_ones_do_not(self):
        # One suffix rule over both items: the sandbox world structurally
        # cannot spell a production item name.
        self.with_vault("ExampleVault")
        self.with_mode("SANDBOX")
        self.assertEqual(opvault.KEY_ITEM, "EnableBanking Key Sandbox")
        self.assertEqual(opvault.CRED_ITEM, "EnableBanking Sandbox")
        self.assertEqual(opvault.REF_PRIVATE_KEY,
                         "op://ExampleVault/EnableBanking Key Sandbox/private key")
        self.assertEqual(opvault.REF_REFRESH_TOKEN,
                         "op://ExampleVault/EnableBanking Sandbox/refresh token")
        self.assertEqual(opvault.REF_EMAIL,
                         "op://ExampleVault/EnableBanking Sandbox/username")

    def test_production_names_are_byte_identical_to_before(self):
        self.with_vault("ExampleVault")
        self.with_mode("PRODUCTION")
        self.assertEqual(opvault.KEY_ITEM, "EnableBanking Key")
        self.assertEqual(opvault.CRED_ITEM, "EnableBanking")
        self.assertEqual(opvault.REF_PRIVATE_KEY,
                         "op://ExampleVault/EnableBanking Key/private key")


class TestUpsertField(SandboxBase):
    def test_a_successful_edit_never_creates(self):
        r = self.runner(Proc(0))
        opvault.upsert_field("EnableBanking Sandbox", "ExampleVault",
                             "refresh token", "rt-1")
        self.assertEqual(len(r.calls), 1)
        self.assertEqual(r.calls[0][0][:3], ["op", "item", "edit"])

    def test_edit_not_found_plus_item_absent_creates_with_the_field_inline(self):
        # The two-negative rule: the edit's not_found AND an independent
        # item_exists False — only then is a create authorized.
        r = self.runner(
            Proc(1, stderr='"EnableBanking Sandbox" isn\'t an item'),
            Proc(1, stderr='"EnableBanking Sandbox" isn\'t an item'),  # item get
            Proc(0))                                                   # create
        opvault.upsert_field("EnableBanking Sandbox", "ExampleVault",
                             "refresh token", "rt-1")
        self.assertEqual(len(r.calls), 3)
        create_argv = r.calls[2][0]
        self.assertEqual(create_argv[:3], ["op", "item", "create"])
        self.assertIn("API Credential", create_argv)
        self.assertIn("refresh token[password]=rt-1", create_argv)

    def test_edit_not_found_but_item_present_raises_and_never_creates(self):
        # An ambiguous state must never be resolved by forging a sibling.
        r = self.runner(
            Proc(1, stderr='"refresh token" isn\'t a field'),
            Proc(0, stdout="{}"))                                      # item get: exists
        with self.assertRaises(opvault.OpError) as ctx:
            opvault.upsert_field("EnableBanking Sandbox", "ExampleVault",
                                 "refresh token", "rt-1")
        self.assertEqual(len(r.calls), 2)          # no create call
        self.assertNotIn("rt-1", str(ctx.exception))

    def test_a_transient_edit_failure_raises_without_consulting_existence(self):
        # A timeout mis-read as absence is what forges duplicates.
        r = self.runner(subprocess.TimeoutExpired(["op"], 60))
        with self.assertRaises(opvault.OpError):
            opvault.upsert_field("EnableBanking Sandbox", "ExampleVault",
                                 "refresh token", "rt-1")
        self.assertEqual(len(r.calls), 1)

    def test_the_created_value_is_redacted_from_a_failing_create(self):
        r = self.runner(
            Proc(1, stderr='"EnableBanking Sandbox" isn\'t an item'),
            Proc(1, stderr='"EnableBanking Sandbox" isn\'t an item'),
            Proc(1, stderr="cannot create: refresh token[password]=rt-secret"))
        with self.assertRaises(opvault.OpError) as ctx:
            opvault.upsert_field("EnableBanking Sandbox", "ExampleVault",
                                 "refresh token", "rt-secret")
        self.assertNotIn("rt-secret", str(ctx.exception))
        self.assertEqual(len(r.calls), 3)


if __name__ == "__main__":
    unittest.main()
