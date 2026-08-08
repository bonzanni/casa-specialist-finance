# tests/test_ebmode.py
"""The mode authority. Small module, but every
isolation property downstream leans on these exact semantics: unset means
production, garbage refuses (never falls back), and one process resolves
the mode exactly once."""
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))

import ebmode  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        os.environ.pop(ebmode.ENV_MODE_VAR, None)
        ebmode._reset()
        self.addCleanup(ebmode._reset)


class TestResolution(Base):
    def test_unset_means_production(self):
        self.assertEqual(ebmode.mode(), ebmode.PRODUCTION)
        self.assertFalse(ebmode.is_sandbox())

    def test_empty_and_whitespace_mean_production(self):
        for value in ("", "   "):
            os.environ[ebmode.ENV_MODE_VAR] = value
            ebmode._reset()
            self.assertEqual(ebmode.mode(), ebmode.PRODUCTION, repr(value))

    def test_sandbox_variants_mean_sandbox(self):
        for value in ("SANDBOX", "sandbox", " Sandbox "):
            os.environ[ebmode.ENV_MODE_VAR] = value
            ebmode._reset()
            self.assertEqual(ebmode.mode(), ebmode.SANDBOX, repr(value))
            self.assertTrue(ebmode.is_sandbox())

    def test_explicit_production_variants(self):
        for value in ("PRODUCTION", "production", " Production "):
            os.environ[ebmode.ENV_MODE_VAR] = value
            ebmode._reset()
            self.assertEqual(ebmode.mode(), ebmode.PRODUCTION, repr(value))

    def test_unrecognised_value_refuses_it_never_defaults(self):
        # A typo defaulting to the real-money world is the failure this
        # mode exists to prevent.
        for value in ("staging", "SANDBOX!", "PROD", "true"):
            os.environ[ebmode.ENV_MODE_VAR] = value
            ebmode._reset()
            with self.assertRaises(ebmode.ModeError, msg=repr(value)):
                ebmode.mode()

    def test_the_refusal_never_echoes_the_value(self):
        # Refusal text carries our words, not input. The probe
        # value is chosen to be found nowhere in legitimate message text.
        probe = "zzz-not-a-mode-zzz"
        os.environ[ebmode.ENV_MODE_VAR] = probe
        ebmode._reset()
        try:
            ebmode.mode()
        except ebmode.ModeError as exc:
            self.assertNotIn(probe, str(exc))
            self.assertIn(ebmode.ENV_MODE_VAR, str(exc))
        else:
            self.fail("ModeError not raised")


class TestMemo(Base):
    def test_first_resolution_wins_until_reset(self):
        # One process, one world: env mutations after the first
        # resolution are invisible — that is the guarantee the unkeyed
        # process caches (CONN, _MINTER, _WORLD_OK) lean on.
        self.assertEqual(ebmode.mode(), ebmode.PRODUCTION)
        os.environ[ebmode.ENV_MODE_VAR] = "SANDBOX"
        self.assertEqual(ebmode.mode(), ebmode.PRODUCTION)
        ebmode._reset()
        self.assertEqual(ebmode.mode(), ebmode.SANDBOX)

    def test_a_refusal_is_not_memoized(self):
        # The refusal must clear the moment the operator fixes the value —
        # a memoized ModeError would demand a process restart the refusal
        # text never asks for.
        os.environ[ebmode.ENV_MODE_VAR] = "garbage"
        ebmode._reset()
        with self.assertRaises(ebmode.ModeError):
            ebmode.mode()
        os.environ[ebmode.ENV_MODE_VAR] = "SANDBOX"
        self.assertEqual(ebmode.mode(), ebmode.SANDBOX)


if __name__ == "__main__":
    unittest.main()
