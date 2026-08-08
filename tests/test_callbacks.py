# tests/test_callbacks.py
"""Our half of casa's v0.147 callback contract. Nothing here talks to a real
casa: the module surface is stubbed on disk (there is no /opt/casa on a dev
box) and the spool is a plain object, because what we are pinning is OUR
fail-closed behaviour, not casa's byte grammars."""
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import types
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
import callbacks  # noqa: E402
import store      # noqa: E402

PLUGIN = "finance.bank-feed"
EFFECTIVE = "plg-finance.bank-feed--authorize"
REDIRECT = "https://casa.example/callback/plg-finance.bank-feed--authorize"

#: casa's `callback_attempts` reduced to what we gate on.
_STUB_ATTEMPTS = """
SCHEMA_VERSION = 1
ENVELOPE_MAX_BYTES = 4096
"""

#: casa's `callback_spool` reduced to the consumer surface we call. It
#: deliberately does NOT define `REMOVAL_SCHEMA_VERSION`: that constant versions
#: plugin-removal records, we never read them, and a stub carrying it would let
#: a dependency on it creep back unnoticed.
_STUB_SPOOL = """
RESULT_TTL_S = 900
COLLECT_PREFIX = ".collect-"
ACK_PREFIX = ".ack-"


def state_hash(state):
    return "0" * 64


def mint(plugin_dir, state, meta=None):
    return None


def collect(plugin_dir, state_hash_hex):
    return {}, "held"


def ack(plugin_dir, state_hash_hex):
    return True
"""

_STUB_TWO_ARG_MINT = _STUB_SPOOL.replace(
    "def mint(plugin_dir, state, meta=None):", "def mint(plugin_dir, state):")


class EnvCase(unittest.TestCase):
    """Restores every environment variable this suite touches."""

    KEYS = ("CASA_ROOT", "CASA_VERSION", "CASA_CALLBACK_SPOOL_ROOT",
            "CLAUDE_PLUGIN_ROOT")

    def setUp(self):
        saved = {k: os.environ.get(k) for k in self.KEYS}

        def restore():
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

        self.addCleanup(restore)
        # Every test that imports a stub must leave the module table clean, or
        # the next one silently reuses the cached stub.
        for module in ("callback_spool", "callback_attempts"):
            self.addCleanup(sys.modules.pop, module, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)


class TestSchemaGuard(EnvCase):
    """The compatibility gate is casa's in-band attempt-record schema PLUS the
    consumer surface we call — never CASA_VERSION, which is exported into
    casa's service environment and reaches us by process inheritance alone, and
    never REMOVAL_SCHEMA_VERSION, which versions records we do not read."""

    def _stub_root(self, spool_body=_STUB_SPOOL):
        casa = self.root / "casa"
        casa.mkdir(exist_ok=True)
        (casa / "callback_spool.py").write_text(spool_body, encoding="utf-8")
        (casa / "callback_attempts.py").write_text(_STUB_ATTEMPTS,
                                                   encoding="utf-8")
        os.environ["CASA_ROOT"] = str(casa)
        self.addCleanup(lambda: sys.path.remove(str(casa))
                        if str(casa) in sys.path else None)
        return casa

    def test_the_tested_schemas_yield_the_protocol_version(self):
        self._stub_root()
        self.assertEqual(callbacks.check_supported(),
                         callbacks.PROTOCOL_VERSION)

    def test_a_missing_casa_version_disables_nothing(self):
        """A guard keyed on an inherited env var would brick a healthy
        deployment; the schemas are what decide."""
        self._stub_root()
        os.environ.pop("CASA_VERSION", None)
        self.assertEqual(callbacks.check_supported(),
                         callbacks.PROTOCOL_VERSION)
        self.assertTrue(callable(callbacks.spool().ack))

    def test_an_unexpected_attempt_schema_fails_closed(self):
        self._stub_root()
        callbacks.check_supported()                  # the stub is accepted
        import callback_attempts                     # noqa: E402
        callback_attempts.SCHEMA_VERSION = 2
        with self.assertRaises(callbacks.Unsupported):
            callbacks.check_supported()

    def test_the_removal_schema_is_not_consulted_at_all(self):
        """It versions PLUGIN-REMOVAL records, which this consumer never reads.
        Gating on it was a reading of an unrelated file, so
        a spool that lacks it entirely — as the stub does — must still pass, and
        a wrong value must change nothing."""
        self._stub_root()
        self.assertEqual(callbacks.check_supported(),
                         callbacks.PROTOCOL_VERSION)
        module = callbacks.spool()
        self.assertFalse(hasattr(module, "REMOVAL_SCHEMA_VERSION"))
        module.REMOVAL_SCHEMA_VERSION = 99
        self.assertEqual(callbacks.check_supported(),
                         callbacks.PROTOCOL_VERSION)
        self.assertNotIn("REMOVAL_SCHEMA_VERSION",
                         [c for _m, c, _e in callbacks.EXPECTED_SCHEMAS])

    def test_check_supported_also_gates_on_the_consumer_surface(self):
        """Half two of the gate, and it runs inside check_supported() — not
        only inside spool(). A matching schema constant next to a renamed
        entry point is not compatibility."""
        for missing in sorted(callbacks._REQUIRED_ARITY):
            with self.subTest(missing=missing):
                body = _STUB_SPOOL.replace(f"def {missing}(",
                                           f"def _was_{missing}(")
                self._stub_root(body)
                with self.assertRaises(callbacks.Unsupported):
                    callbacks.check_supported()
                sys.modules.pop("callback_spool", None)
                sys.modules.pop("callback_attempts", None)

    def test_a_drifted_ttl_we_copy_fails_closed(self):
        """A duplicated timeout is the one thing that drifts in total silence:
        casa changes RESULT_TTL_S, our copy does not, and a flow expires while
        we still believe we have time to exchange. Cheap to check, so checked."""
        self._stub_root()
        callbacks.check_supported()                  # the stub is accepted
        import callback_spool                        # noqa: E402
        for bad in (600, None):
            with self.subTest(value=bad):
                callback_spool.RESULT_TTL_S = bad
                with self.assertRaises(callbacks.Unsupported) as caught:
                    callbacks.check_supported()
                self.assertIn("RESULT_TTL_S", str(caught.exception))

    def test_the_refusal_names_the_casa_release_for_diagnostics(self):
        """CASA_VERSION never decides; it only helps the operator see which
        casa they are on."""
        self._stub_root()
        os.environ["CASA_VERSION"] = "0.149.7"
        callbacks.check_supported()      # puts $CASA_ROOT on the import path
        import callback_attempts                     # noqa: E402
        callback_attempts.SCHEMA_VERSION = 99
        with self.assertRaises(callbacks.Unsupported) as caught:
            callbacks.check_supported()
        self.assertIn("0.149.7", str(caught.exception))

    def test_an_absent_module_fails_closed(self):
        empty = self.root / "empty"
        empty.mkdir()
        os.environ["CASA_ROOT"] = str(empty)
        self.addCleanup(lambda: sys.path.remove(str(empty))
                        if str(empty) in sys.path else None)
        with self.assertRaises(callbacks.Unsupported):
            callbacks.spool()

    def test_a_two_argument_mint_fails_closed(self):
        self._stub_root(_STUB_TWO_ARG_MINT)
        with self.assertRaises(callbacks.Unsupported):
            callbacks.spool()


class TestDiscover(EnvCase):
    def _publish(self, entry):
        spool_root = self.root / "spool"
        artifact = self.root / "artifact"
        artifact.mkdir(exist_ok=True)
        index = spool_root / ".index"
        index.mkdir(parents=True, exist_ok=True)
        key = hashlib.sha256(
            os.path.realpath(artifact).encode("utf-8")).hexdigest()
        (index / f"{key}.json").write_text(json.dumps(entry), encoding="utf-8")
        os.environ["CASA_CALLBACK_SPOOL_ROOT"] = str(spool_root)
        return str(artifact), spool_root

    @staticmethod
    def _entry(**over):
        entry = {"v": 1, "base_url": "https://casa.example",
                 "callbacks": {"authorize": {"effective": EFFECTIVE,
                                             "redirect_uri": REDIRECT}},
                 "plugin_dir": PLUGIN}
        entry.update(over)
        return entry

    def test_the_entry_yields_the_spool_dir_and_the_exact_redirect_uri(self):
        artifact, spool_root = self._publish(self._entry())
        got = callbacks.discover(artifact)
        self.assertEqual(got["plugin"], PLUGIN)
        self.assertEqual(got["plugin_dir"], str(spool_root / PLUGIN))
        self.assertEqual(got["effective"], EFFECTIVE)
        self.assertEqual(got["redirect_uri"], REDIRECT)

    def test_a_missing_entry_means_callbacks_are_unavailable(self):
        artifact, _ = self._publish(self._entry())
        os.environ["CASA_CALLBACK_SPOOL_ROOT"] = str(self.root / "nowhere")
        with self.assertRaises(callbacks.Unsupported):
            callbacks.discover(artifact)

    def test_a_route_we_cannot_bind_is_refused(self):
        cases = {
            "our declared callback is not routed":
                self._entry(callbacks={"other": {"effective": "plg-x--other",
                                                 "redirect_uri": REDIRECT}}),
            "the routed name is not the one we derive":
                self._entry(callbacks={"authorize": {
                    "effective": "plg-somebody-else--authorize",
                    "redirect_uri": REDIRECT}}),
        }
        for why, entry in cases.items():
            with self.subTest(why):
                artifact, _ = self._publish(entry)
                with self.assertRaises(callbacks.Unsupported):
                    callbacks.discover(artifact)


class DbCase(EnvCase):
    def setUp(self):
        super().setUp()
        self.conn = store.open_db(self.root / "f.sqlite")
        self.addCleanup(self.conn.close)


class TestMint(DbCase):
    def _spool(self, minted):
        """A stand-in for casa's module-level mint: writes a real artifact so
        the mtime re-stamp has something to read."""
        pending = self.root / PLUGIN / "pending"
        pending.mkdir(parents=True, exist_ok=True)

        def _mint(plugin_dir, state, meta=None):
            row = self.conn.execute(
                "SELECT phase FROM attempts WHERE state_hash=?",
                (hashlib.sha256(state.encode()).hexdigest(),)).fetchone()
            minted.append((row["phase"] if row else None, meta))
            path = pending / f"{hashlib.sha256(state.encode()).hexdigest()}.json"
            path.write_text(json.dumps({"v": 2, "meta": meta}), encoding="utf-8")
            os.utime(path, (1_700_000_000.0, 1_700_000_000.0))
            return path

        return types.SimpleNamespace(
            state_hash=lambda s: hashlib.sha256(s.encode()).hexdigest(),
            mint=_mint)

    @staticmethod
    def _meta(**over):
        meta = {"purpose": "link", "aspsp": "Revolut", "country": "NL",
                "psu_type": "business", "account_id": None, "generation": None}
        meta.update(over)
        return meta

    def test_the_row_is_written_before_the_envelope(self):
        minted = []
        state = callbacks.mint(self.conn, self._spool(minted),
                               str(self.root / PLUGIN), self._meta(), REDIRECT)
        self.assertEqual(minted[0][0], "minted")   # the row existed already
        self.assertEqual(minted[0][1], self._meta())
        row = self.conn.execute(
            "SELECT * FROM attempts WHERE state_hash=?",
            (hashlib.sha256(state.encode()).hexdigest(),)).fetchone()
        self.assertEqual(row["redirect_uri"], REDIRECT)
        self.assertEqual(row["plugin_dir"], str(self.root / PLUGIN))
        self.assertEqual(row["aspsp_name"], "Revolut")

    def test_created_at_is_restamped_from_the_minted_artifact(self):
        """casa echoes the pending inode's mtime back as minted_ts, so that is
        the clock we must be able to match."""
        state = callbacks.mint(self.conn, self._spool([]),
                               str(self.root / PLUGIN), self._meta(), REDIRECT)
        row = self.conn.execute(
            "SELECT created_at FROM attempts WHERE state_hash=?",
            (hashlib.sha256(state.encode()).hexdigest(),)).fetchone()
        self.assertAlmostEqual(row["created_at"], 1_700_000_000.0, places=3)

    def test_the_state_is_a_legal_callback_state(self):
        state = callbacks.mint(self.conn, self._spool([]),
                               str(self.root / PLUGIN), self._meta(), REDIRECT)
        self.assertRegex(state, r"^[A-Za-z0-9._~-]{22,256}$")

    def test_the_generation_fence_is_minted_into_meta_and_persisted(self):
        """A repair or renewal names the account it targets AND the session
        generation it expected to find there; the collector refuses a callback
        that arrives after a newer session already rebound it."""
        minted = []
        meta = self._meta(purpose="repair", account_id="acc1", generation=3)
        state = callbacks.mint(self.conn, self._spool(minted),
                               str(self.root / PLUGIN), meta, REDIRECT)
        self.assertEqual(minted[0][1], meta)          # echoed back verbatim
        row = self.conn.execute(
            "SELECT account_id, expected_generation FROM attempts"
            " WHERE state_hash=?",
            (hashlib.sha256(state.encode()).hexdigest(),)).fetchone()
        self.assertEqual(row["account_id"], "acc1")
        self.assertEqual(row["expected_generation"], 3)

    def test_an_omitted_generation_is_minted_as_an_explicit_null(self):
        """An absent key would compare unequal to the echoed meta forever, so
        `_normalised_meta` fills it in rather than dropping it."""
        minted = []
        callbacks.mint(self.conn, self._spool(minted),
                       str(self.root / PLUGIN),
                       {"purpose": "link", "aspsp": "Revolut",
                        "country": "NL", "psu_type": "business"}, REDIRECT)
        self.assertIn("generation", minted[0][1])
        self.assertIsNone(minted[0][1]["generation"])

    def test_the_minted_row_round_trips_through_meta_columns(self):
        """`mint`'s INSERT and `_meta_of`'s SELECT must agree on every one of
        `META_COLUMNS`' six keys: a hand-typed INSERT that drops, renames or
        misaligns one column would break that agreement permanently — passing
        `TestValidation`'s hand-built fixtures (which never mint) while
        rejecting every real callback, with a fully green suite otherwise.
        Minting for real and reading the row back is the only thing that would
        catch that.

        Only two of those three causes produce a NULL. A dropped or renamed
        column leaves `_meta_of` reading a column `mint` never wrote, so it
        echoes `None`; a misaligned pair echoes the OTHER key's real value
        instead — not `None`, and plausible enough to read as correct. This
        test catches both because the fixture gives all six keys MUTUALLY
        DISTINCT values, so a transposition surfaces as a value mismatch and
        not merely as an absence."""
        meta = self._meta(purpose="repair", account_id="acc1", generation=3)
        state = callbacks.mint(self.conn, self._spool([]),
                               str(self.root / PLUGIN), meta, REDIRECT)
        row = self.conn.execute(
            "SELECT * FROM attempts WHERE state_hash=?",
            (hashlib.sha256(state.encode()).hexdigest(),)).fetchone()
        self.assertEqual(callbacks._meta_of(dict(row)),
                         callbacks._normalised_meta(meta))

    def test_a_failed_envelope_marks_the_row_abandoned(self):
        def _boom(plugin_dir, state, meta=None):
            raise FileExistsError("state already minted")

        sp = types.SimpleNamespace(
            state_hash=lambda s: hashlib.sha256(s.encode()).hexdigest(),
            mint=_boom)
        with self.assertRaises(FileExistsError):
            callbacks.mint(self.conn, sp, str(self.root / PLUGIN),
                           self._meta(), REDIRECT)
        row = self.conn.execute(
            "SELECT phase, outcome FROM attempts").fetchone()
        self.assertEqual(row["phase"], "abandoned")
        self.assertEqual(row["outcome"], "mint_failed")


class TestLease(DbCase):
    def setUp(self):
        super().setUp()
        self.conn.execute(
            "INSERT INTO attempts(state_hash, phase, created_at)"
            " VALUES ('h1','minted',0)")

    def test_the_first_owner_wins_and_the_second_is_refused(self):
        self.assertIsNotNone(callbacks.take_lease(self.conn, "h1", "A"))
        self.assertIsNone(callbacks.take_lease(self.conn, "h1", "B"))

    def test_an_expired_lease_can_be_taken_over(self):
        callbacks.take_lease(self.conn, "h1", "A", ttl_s=-1)
        self.assertIsNotNone(callbacks.take_lease(self.conn, "h1", "B"))

    def test_expiry_does_not_authorise_a_second_exchange(self):
        """The provider has no idempotency key, so a lapsed lease must never
        licence a second POST."""
        callbacks.take_lease(self.conn, "h1", "A", ttl_s=-1)
        self.conn.execute(
            "UPDATE attempts SET phase='exchange_started' WHERE state_hash='h1'")
        fence = callbacks.take_lease(self.conn, "h1", "B")
        with self.assertRaises(callbacks.Indeterminate):
            callbacks.begin_exchange(self.conn, "h1", fence)

    def test_begin_exchange_restamps_the_lease(self):
        fence = callbacks.take_lease(self.conn, "h1", "A", ttl_s=5)
        before = self.conn.execute(
            "SELECT lease_expiry FROM attempts WHERE state_hash='h1'"
        ).fetchone()["lease_expiry"]
        callbacks.begin_exchange(self.conn, "h1", fence)
        after = self.conn.execute(
            "SELECT lease_expiry FROM attempts WHERE state_hash='h1'"
        ).fetchone()["lease_expiry"]
        self.assertGreaterEqual(after - before, callbacks.LEASE_TTL_S - 10)

    def test_begin_exchange_refuses_a_stale_fence(self):
        callbacks.take_lease(self.conn, "h1", "A")
        with self.assertRaises(callbacks.Indeterminate):
            callbacks.begin_exchange(self.conn, "h1", "not-the-token")


class TestValidation(unittest.TestCase):
    STATE = "S" * 43

    def _attempt(self, **over):
        att = {"state_hash": hashlib.sha256(self.STATE.encode()).hexdigest(),
               "state_secret": self.STATE, "aspsp_name": "Revolut",
               "country": "NL", "psu_type": "business", "purpose": "link",
               "account_id": None, "expected_generation": None,
               "plugin_dir": f"/data/callbacks/{PLUGIN}",
               "redirect_uri": REDIRECT, "created_at": 1_700_000_000.0}
        att.update(over)
        return att

    def _record(self, **over):
        rec = {"v": 1, "plugin": PLUGIN, "effective": EFFECTIVE,
               "received_at": 1_700_000_100.0,
               "raw_query": f"state={self.STATE}&code=AUTHCODE",
               "query": [["state", self.STATE], ["code", "AUTHCODE"]],
               "meta": {"purpose": "link", "aspsp": "Revolut", "country": "NL",
                        "psu_type": "business", "account_id": None,
                        "generation": None},
               "minted_ts": 1_700_000_000.0}
        rec.update(over)
        return rec

    def test_accepts_a_well_formed_record(self):
        out = callbacks.validate_record(self._record(), self._attempt())
        self.assertEqual(out["code"], "AUTHCODE")
        self.assertIsNone(out["error"])

    def test_rejects_a_result_record_of_an_unexpected_version(self):
        """v2 is the MINT ENVELOPE's version; the result record stays v1."""
        with self.assertRaises(callbacks.Invalid):
            callbacks.validate_record(self._record(v=2), self._attempt())

    def test_rejects_a_foreign_plugin(self):
        with self.assertRaises(callbacks.Invalid):
            callbacks.validate_record(self._record(plugin="other.other"),
                                      self._attempt())

    def test_rejects_a_foreign_effective_name(self):
        """A suffix check would pass this; the FULL name is the binding."""
        with self.assertRaises(callbacks.Invalid):
            callbacks.validate_record(
                self._record(effective="plg-someone-else--authorize"),
                self._attempt())

    def test_rejects_a_foreign_meta(self):
        bad = self._record()
        bad["meta"] = dict(bad["meta"], aspsp="ABN AMRO")
        with self.assertRaises(callbacks.Invalid):
            callbacks.validate_record(bad, self._attempt())

    def test_rejects_a_record_echoing_a_different_generation(self):
        """The generation is part of `meta`, so it is bound by the same
        equality the aspsp is — a record that claims a different expected
        generation is not this flow's record."""
        bad = self._record()
        bad["meta"] = dict(bad["meta"], generation=4)
        with self.assertRaises(callbacks.Invalid):
            callbacks.validate_record(
                bad, self._attempt(expected_generation=3))

    def test_rejects_a_foreign_mint_clock(self):
        with self.assertRaises(callbacks.Invalid):
            callbacks.validate_record(self._record(minted_ts=1_700_003_600.0),
                                      self._attempt())

    def test_rejects_a_state_that_is_not_ours(self):
        bad = self._record(query=[["state", "OTHER"], ["code", "AUTHCODE"]])
        with self.assertRaises(callbacks.Invalid):
            callbacks.validate_record(bad, self._attempt())

    def test_rejects_a_state_that_does_not_hash_to_the_attempt(self):
        with self.assertRaises(callbacks.Invalid):
            callbacks.validate_record(self._record(),
                                      self._attempt(state_hash="0" * 64))

    def test_rejects_duplicate_state_or_code(self):
        for query in ([["state", self.STATE], ["code", "AUTHCODE"], ["code", "OTHERCODE"]],
                      [["state", self.STATE], ["state", self.STATE],
                       ["code", "AUTHCODE"]]):
            with self.subTest(query=len(query)):
                with self.assertRaises(callbacks.Invalid):
                    callbacks.validate_record(self._record(query=query),
                                              self._attempt())

    def test_rejects_code_and_error_together(self):
        bad = self._record(query=[["state", self.STATE], ["code", "AUTHCODE"],
                                  ["error", "access_denied"]])
        with self.assertRaises(callbacks.Invalid):
            callbacks.validate_record(bad, self._attempt())

    def test_rejects_neither_code_nor_error(self):
        with self.assertRaises(callbacks.Invalid):
            callbacks.validate_record(
                self._record(query=[["state", self.STATE]]), self._attempt())

    def test_a_provider_refusal_is_declined_not_invalid(self):
        rec = self._record(query=[["state", self.STATE],
                                  ["error", "access_denied"]])
        out = callbacks.validate_record(rec, self._attempt())
        self.assertEqual(out["error"], "access_denied")
        self.assertIsNone(out["code"])


if __name__ == "__main__":
    unittest.main()
