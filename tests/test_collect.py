# tests/test_collect.py
"""The collection loop: our half of casa's ordering contract.

The fake spool models casa's v0.147 artifacts — an `attempts/` ledger, a
collect that RENAMES `results/<h>.json` to a held `.collect-<h>-<uuid>`, and an
ack that RENAMES `attempts/<h>.json` to `.ack-<h>`. It honours the `plugin_dir`
argument exactly as casa's module-level helpers do, so a caller that passes the
wrong directory finds nothing (which is what the previous revision of these
tests silently did).

**Every exchange double here writes to the ledger, or tries to.** A double that
performs no writes cannot prove writes are prevented, which is what a
"binds nothing" double amounts to.
"""
import hashlib
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
import callbacks  # noqa: E402
import store      # noqa: E402

PLUGIN = "finance.bank-feed"
EFFECTIVE = "plg-finance.bank-feed--authorize"
REDIRECT = "https://casa.example/callback/plg-finance.bank-feed--authorize"
MINTED_TS = 1_700_000_000.0
META = {"purpose": "link", "aspsp": "Revolut", "country": "NL",
        "psu_type": "business", "account_id": None, "generation": None}

#: The provider's account shape: the IBAN NESTS under `account_id`. A flat
#: "iban" key does not exist in the payload, and a double that
#: invents one proves nothing about production.
PROVIDER_ACCOUNT = {
    "uid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    "identification_hash": "0" * 63 + "1",
    "account_id": {"iban": "NL00REVO0000000001"},
    "all_account_ids": [{"identification": "NL00REVO0000000001",
                         "scheme_name": "IBAN"}],
    "currency": "EUR", "name": "N. Voorbeeld", "product": "Business EUR",
    "usage": "ORGA"}


class FakeSpool:
    """casa v0.147's consumer-facing surface, on real files."""

    COLLECT_PREFIX = ".collect-"
    ACK_PREFIX = ".ack-"

    def __init__(self, root):
        self.root = pathlib.Path(root)
        (self.root / "attempts").mkdir(parents=True, exist_ok=True)
        (self.root / "results").mkdir(parents=True, exist_ok=True)
        self.acked = []
        self.collected = []

    # -- test helpers (casa-side writes) --------------------------------
    def state_hash(self, state):
        return hashlib.sha256(state.encode("utf-8")).hexdigest()

    def write_attempt(self, h, status, outcome=None, claimed=False):
        (self.root / "attempts" / f"{h}.json").write_text(json.dumps(
            {"v": 1, "state_hash": h, "minted_ts": MINTED_TS, "status": status,
             "outcome": outcome, "claimed": claimed, "meta": META,
             "nudges": 0, "last_nudge_ts": None, "next_nudge_ts": None,
             "deferrals": 0, "noted": False, "ended_ts": None}),
            encoding="utf-8")

    def publish(self, h, record, age_s=0.0):
        path = self.root / "results" / f"{h}.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        if age_s:
            stamp = time.time() - age_s
            os.utime(path, (stamp, stamp))

    # -- the consumer contract ------------------------------------------
    def collect(self, plugin_dir, h):
        src = pathlib.Path(plugin_dir) / "results" / f"{h}.json"
        held = src.with_name(f"{self.COLLECT_PREFIX}{h}-abcd")
        src.rename(held)                     # the rename is the pickup arbiter
        self.collected.append(h)
        return json.loads(held.read_text(encoding="utf-8")), held

    def ack(self, plugin_dir, h):
        attempts = pathlib.Path(plugin_dir) / "attempts"
        src = attempts / f"{h}.json"
        if src.exists():
            src.rename(attempts / f"{self.ACK_PREFIX}{h}")
        self.acked.append(h)
        return True


class Base(unittest.TestCase):
    def setUp(self):
        saved = {k: os.environ.get(k)
                 for k in ("CASA_CALLBACK_SPOOL_ROOT", "CLAUDE_PLUGIN_ROOT")}

        def restore():
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

        self.addCleanup(restore)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)

        self.spool_root = root / "spool"
        self.artifact = root / "artifact"
        self.artifact.mkdir()
        self.sp = FakeSpool(self.spool_root / PLUGIN)
        self.pd = str(self.sp.root)
        os.environ["CASA_CALLBACK_SPOOL_ROOT"] = str(self.spool_root)
        os.environ["CLAUDE_PLUGIN_ROOT"] = str(self.artifact)
        self._publish_index(REDIRECT)

        self.conn = store.open_db(root / "f.sqlite")
        self.addCleanup(self.conn.close)
        self.state = "S" * 43
        self.h = self.sp.state_hash(self.state)
        self._row(self.h, self.state)

    def _publish_index(self, redirect_uri):
        index = self.spool_root / ".index"
        index.mkdir(parents=True, exist_ok=True)
        key = hashlib.sha256(
            os.path.realpath(self.artifact).encode("utf-8")).hexdigest()
        (index / f"{key}.json").write_text(json.dumps(
            {"v": 1, "base_url": "https://casa.example",
             "callbacks": {"authorize": {"effective": EFFECTIVE,
                                         "redirect_uri": redirect_uri}},
             "plugin_dir": PLUGIN}), encoding="utf-8")

    def _row(self, h, state, redirect_uri=REDIRECT, plugin_dir=None,
             purpose="link", account_id=None, generation=None):
        self.conn.execute(
            "INSERT INTO attempts(state_hash, state_secret, aspsp_name,"
            " country, psu_type, purpose, account_id, expected_generation,"
            " plugin_dir, redirect_uri, created_at, phase)"
            " VALUES (?,?,'Revolut','NL','business',?,?,?,?,?,?,'minted')",
            (h, state, purpose, account_id, generation,
             plugin_dir or self.pd, redirect_uri, MINTED_TS))

    def _record(self, code="CODE1", **over):
        rec = {"v": 1, "plugin": PLUGIN, "effective": EFFECTIVE,
               "received_at": MINTED_TS + 100.0,
               "raw_query": f"state={self.state}&code={code}",
               "query": [["state", self.state], ["code", code]],
               "meta": META, "minted_ts": MINTED_TS}
        rec.update(over)
        return rec

    def _phase(self, h=None):
        return self.conn.execute(
            "SELECT * FROM attempts WHERE state_hash=?",
            (h or self.h,)).fetchone()

    def _sessions(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT session_id, status, generation FROM sessions"
            " ORDER BY session_id").fetchall()]

    def _accounts(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT account_id, session_id FROM accounts"
            " ORDER BY account_id").fetchall()]

    # -- the exchange doubles -------------------------------------------
    def _compliant(self, session_id="sess-1", *, partial=False):
        """What a COMPLIANT `exchange` does: note the provider session
        the moment it exists, declare the account set verified only after
        checking it, and only THEN write to the ledger — which is the only
        order in which those writes can succeed at all."""

        def _exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, session_id)
            callbacks.declare_verified(self.conn, attempt)
            callbacks.heartbeat(self.conn, attempt["state_hash"],
                                attempt["lease_fence"])
            self._write_ledger(session_id)
            if partial:
                callbacks.declare_partial(self.conn, attempt)

        return _exchange

    def _write_ledger(self, session_id):
        """The binding writes, in PRODUCTION's shape: a STAGED session row and
        an account bound to it. Every one of these is banned until a verdict is
        declared — and even after the verdict, the session goes in
        `REVIEW_REQUIRED` at generation 0, because an exchange never makes a
        consent live. `collect_one` promotes it once the exchange has
        returned."""
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions(session_id, aspsp_name, country,"
            " psu_type, status, generation)"
            " VALUES (?,'Revolut','NL','business',?,?)",
            (session_id, callbacks.REVIEW_REQUIRED_STATUS,
             callbacks.REVIEW_REQUIRED_GENERATION))
        self.conn.execute(
            "INSERT OR REPLACE INTO accounts(account_id, uid, session_id,"
            " currency, aspsp) VALUES ('acc-linked',?,?,'EUR','Revolut')",
            (PROVIDER_ACCOUNT["uid"], session_id))

    @staticmethod
    def _never(code, attempt):
        raise AssertionError("the code must not be exchanged here")


class TestCollectionLoop(Base):
    def test_result_ready_is_collected_exchanged_committed_then_acked(self):
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record())
        seen = {}

        def exchange(code, attempt):
            seen["code"] = code
            seen["aspsp"] = attempt["aspsp_name"]
            seen["fence"] = attempt["lease_fence"]
            self._compliant()(code, attempt)

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertTrue(seen["fence"])      # the exchange can fence its writes
        self.assertEqual(seen["code"], "CODE1")
        self.assertEqual(seen["aspsp"], "Revolut")
        self.assertEqual([o.status for o in out], ["succeeded"])
        self.assertEqual(self.sp.acked, [self.h])
        row = self._phase()
        self.assertEqual(row["phase"], "exchanged")
        self.assertEqual(row["session_id"], "sess-1")
        self.assertEqual(row["outcome"], "collected")
        self.assertIsNone(row["lease_token"])
        # the declared writes SURVIVE: the ban is lifted, never permanent
        self.assertEqual(self._accounts(),
                         [{"account_id": "acc-linked", "session_id": "sess-1"}])

    def test_commit_happens_before_ack(self):
        """If we ack first and then crash, the payload is gone forever."""
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record())
        order = []
        original = self.sp.ack

        def ack(plugin_dir, h):
            order.append(("ack", self._phase()["phase"]))
            return original(plugin_dir, h)

        self.sp.ack = ack

        def exchange(code, attempt):
            order.append(("exchange", self._phase()["phase"]))
            self._compliant()(code, attempt)

        callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual([step for step, _ in order], ["exchange", "ack"])
        # the commit is durable BEFORE the ack is attempted
        self.assertEqual(order[1][1], "exchanged")

    def test_never_unlinks_the_hold(self):
        """The `.collect-*` entry is the flow's crash journal; casa's
        ack-teardown owns it and we never remove it."""
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record())
        callbacks.run_collection(self.conn, self.sp, self.pd,
                                 self._compliant("s"))
        holds = list((self.sp.root / "results").glob(".collect-*"))
        self.assertEqual(len(holds), 1)

    def test_file_not_found_is_retryable_never_ackable(self):
        """casa writes the attempt before the result link lands."""
        self.sp.write_attempt(self.h, "result_ready")
        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual([o.status for o in out], ["retry"])
        self.assertEqual(self.sp.acked, [])
        self.assertEqual(self._phase()["phase"], "minted")
        self.assertIsNone(self._phase()["lease_token"])   # released for the next nudge

    def test_provider_refusal_is_declined_and_acked(self):
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record(
            query=[["state", self.state], ["error", "access_denied"]]))
        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual([o.status for o in out], ["declined"])
        self.assertEqual(self.sp.acked, [self.h])
        self.assertEqual(self._phase()["outcome"], "access_denied")

    def test_terminal_outcomes_are_recorded_and_acked(self):
        for outcome in ("expired", "expired_unread", "publish_failed",
                        "evicted"):
            state = f"{outcome}-{'x' * 30}"
            self._row(self.sp.state_hash(state), state)
            self.sp.write_attempt(self.sp.state_hash(state), "done",
                                  outcome=outcome)
        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual(sorted(o.status for o in out), ["terminal"] * 4)
        rows = self.conn.execute(
            "SELECT outcome FROM attempts WHERE phase='closed'").fetchall()
        self.assertEqual(sorted(r["outcome"] for r in rows),
                         ["evicted", "expired", "expired_unread",
                          "publish_failed"])
        self.assertEqual(len(self.sp.acked), 4)

    def test_a_second_pass_is_idempotent(self):
        """The nudge is at-least-once, so a repeat turn must be harmless."""
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record())
        calls = []

        def exchange(code, attempt):
            calls.append(code)
            self._compliant("s")(code, attempt)

        first = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        second = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual(calls, ["CODE1"])         # the code is spent once
        self.assertEqual([o.status for o in first], ["succeeded"])
        self.assertEqual(second, [])               # nothing left to collect

    def test_successor_recovers_an_existing_hold(self):
        """A previous life renamed the result and died: the payload lives only
        in `.collect-<h>-*`, and `results/<h>.json` never reappears."""
        self.sp.write_attempt(self.h, "result_ready", claimed=True)
        held = self.sp.root / "results" / f".collect-{self.h}-abcd"
        held.write_text(json.dumps(self._record()), encoding="utf-8")
        out = callbacks.run_collection(self.conn, self.sp, self.pd,
                                       self._compliant("s2"))
        self.assertEqual([o.status for o in out], ["succeeded"])
        self.assertEqual(self.sp.collected, [])    # no second pickup attempt
        self.assertEqual(self.sp.acked, [self.h])

    def test_a_foreign_effective_name_is_invalid_and_acked(self):
        """A suffix check would accept this name; the full one is the binding."""
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h,
                        self._record(effective="plg-someone-else--authorize"))
        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual([o.status for o in out], ["invalid"])
        self.assertEqual(self.sp.acked, [self.h])
        self.assertEqual(self._phase()["outcome"], "invalid")

    def test_the_result_ttl_we_age_holds_against_is_the_one_under_the_gate(self):
        """It is a value COPIED from casa, so it must be the same object the
        compatibility guard cross-checks — a second literal 900 here would sit
        outside the gate and drift unnoticed."""
        self.assertEqual(callbacks.RESULT_TTL_S,
                         dict(callbacks.EXPECTED_SPOOL_TTLS)["RESULT_TTL_S"])

    def test_nothing_to_collect_is_a_quiet_no_op(self):
        self.assertEqual(
            callbacks.run_collection(self.conn, self.sp, self.pd, self._never),
            [])

    def test_awaiting_redirect_waits_while_the_context_is_unchanged(self):
        self.sp.write_attempt(self.h, "awaiting_redirect")
        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual([o.status for o in out], ["waiting"])
        self.assertEqual(self.sp.acked, [])        # the redirect may still land
        self.assertEqual(self._phase()["phase"], "minted")

    def test_a_changed_redirect_uri_abandons_the_in_flight_authorization(self):
        """A pending minted under a previous redirect_uri can never complete;
        acking an awaiting_redirect record is the abort verb."""
        self._publish_index("https://casa.example/callback/moved")
        self.sp.write_attempt(self.h, "awaiting_redirect")
        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual([o.status for o in out], ["abandoned"])
        self.assertEqual(self.sp.acked, [self.h])
        self.assertEqual(self._phase()["phase"], "abandoned")
        self.assertIn("fresh", out[0].detail)      # the operator is told what to do

    def test_too_little_result_lifetime_left_refuses_the_exchange(self):
        """Under the 60 s floor we do not start: record, ack, offer a fresh
        link — two clocks, and the shorter one governs."""
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record(),
                        age_s=callbacks.RESULT_TTL_S - 10)
        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual([o.status for o in out], ["expired"])
        self.assertEqual(self.sp.acked, [self.h])
        self.assertEqual(self._phase()["outcome"], "expired_budget")

    def test_no_outcome_detail_carries_a_session_id(self):
        """Session identifiers are bearer-equivalent."""
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record())
        out = callbacks.run_collection(self.conn, self.sp, self.pd,
                                       self._compliant("sess-bearer-secret"))
        self.assertEqual(out[0].status, "succeeded")
        self.assertNotIn("sess-bearer-secret", out[0].detail)
        self.assertNotIn("CODE1", out[0].detail)
        self.assertEqual(self._phase()["session_id"], "sess-bearer-secret")

    def test_a_stale_fence_cannot_commit_or_ack(self):
        """Every write re-checks the fencing token, including the commit."""
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record())

        def exchange(code, attempt):
            self.conn.execute(
                "UPDATE attempts SET lease_owner='B', lease_token='stolen',"
                " lease_expiry=? WHERE state_hash=?",
                (time.time() + 90, self.h))

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual([o.status for o in out], ["skipped"])
        self.assertEqual(self.sp.acked, [])
        self.assertNotEqual(self._phase()["phase"], "exchanged")
        self.assertEqual(self._sessions(), [])     # and no quarantine row

    def test_a_failing_exchange_is_indeterminate_and_never_acked(self):
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record())

        def exchange(code, attempt):
            raise OSError("connection reset")

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual([o.status for o in out], ["indeterminate"])
        self.assertEqual(self.sp.acked, [])
        self.assertEqual(self._phase()["phase"], "indeterminate")
        self.assertNotIn("connection reset", out[0].detail)

    def test_pending_attempts_skips_ack_tokens_and_residue(self):
        attempts = self.sp.root / "attempts"
        self.sp.write_attempt(self.h, "result_ready")
        (attempts / f".ack-{'a' * 64}").write_text("{}", encoding="utf-8")
        (attempts / "notahash.json").write_text("{}", encoding="utf-8")
        (attempts / f"{'b' * 64}.json").write_text("{", encoding="utf-8")
        self.sp.write_attempt("c" * 64, "result_ready")   # never minted by us
        got = callbacks.pending_attempts(self.conn, self.sp, self.pd)
        self.assertEqual([r["state_hash"] for r in got], [self.h])

    def test_collect_one_refuses_a_hash_that_is_not_ours(self):
        record = {"v": 1, "state_hash": "d" * 64, "status": "result_ready"}
        out = callbacks.collect_one(self.conn, self.sp, self.pd, record,
                                    "fence", self._never)
        self.assertEqual(out.status, "skipped")
        self.assertEqual(self.sp.acked, [])


class Ready(Base):
    """A collectable `result_ready` flow, already published."""

    def setUp(self):
        super().setUp()
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record())


class TestLedgerIsClosedUntilVerified(Ready):
    """A post-return boolean cannot enforce ordering: an exchange can write and
    THEN say it never verified, and the loop only observes the marker
    afterwards. So there is no boolean. The canonical tables are shut for the
    whole call, `declare_verified` is the only thing that reopens them, and the
    declaration itself is fenced and durable."""

    def test_a_write_before_the_verdict_fails_at_the_database(self):
        attempted = []

        def exchange(code, attempt):
            for sql in (
                "INSERT INTO sessions(session_id, status, generation)"
                " VALUES ('sess-9','AUTHORIZED',1)",
                "INSERT INTO accounts(account_id, uid, session_id, currency)"
                " VALUES ('acc-x','uid-x','sess-9','EUR')",
                "INSERT INTO coverage(account_id, interval_start, interval_end)"
                " VALUES ('acc-x','2020-01-01','2026-01-01')",
            ):
                try:
                    self.conn.execute(sql)
                    attempted.append("WROTE")
                except sqlite3.IntegrityError as exc:
                    attempted.append(str(exc))

        callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual(len(attempted), 3)
        self.assertNotIn("WROTE", attempted)
        for message in attempted:
            self.assertIn("ledger is closed", message)

    def test_an_exchange_that_writes_then_lies_binds_nothing(self):
        """The double DOES attempt to bind, and then claims it verified. The
        claim is not read at all, and the writes never happened."""
        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, "sess-9")
            try:
                self._write_ledger("sess-9")
            except sqlite3.IntegrityError:
                pass
            return {"verified": True, "accounts": [PROVIDER_ACCOUNT]}  # a lie

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual([o.status for o in out], ["review_required"])
        self.assertEqual(self._accounts(), [])          # nothing bound
        self.assertEqual(self._phase()["outcome"], "unverified_accounts")

    def test_the_returned_verified_flag_is_never_consulted(self):
        """The shape reduced to its smallest form: a mapping that says
        `verified: True`, and a collector with no interest in it."""
        out = callbacks.run_collection(
            self.conn, self.sp, self.pd,
            lambda code, attempt: {"session_id": "s", "verified": True})
        self.assertEqual([o.status for o in out], ["review_required"])
        self.assertEqual(self._phase()["outcome"], "unverified_accounts")

    def test_the_ban_lifts_only_once_a_verdict_is_declared(self):
        order = []

        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, "sess-1")
            try:
                self._write_ledger("sess-1")
            except sqlite3.IntegrityError:
                order.append("blocked")
            callbacks.declare_verified(self.conn, attempt)
            self._write_ledger("sess-1")
            order.append("allowed")

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual(order, ["blocked", "allowed"])
        self.assertEqual([o.status for o in out], ["succeeded"])

    def test_the_ban_is_gone_by_the_time_the_collector_writes(self):
        """`_open_ledger` runs from a `finally`, because the collector's own
        quarantine INSERT is one of the writes the ban blocks."""
        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, "sess-9")
            raise OSError("boom")

        callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS c FROM sqlite_temp_master WHERE type='trigger'"
        ).fetchone()["c"], 0)

    def test_a_verdict_declared_without_a_noted_session_is_refused(self):
        raised = []

        def exchange(code, attempt):
            try:
                callbacks.declare_verified(self.conn, attempt)
            except callbacks.Invalid as exc:
                raised.append(str(exc))

        callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual(len(raised), 1)
        self.assertIn("note_session", raised[0])

    def test_a_verdict_declared_under_a_stolen_lease_is_indeterminate(self):
        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, "sess-9")
            self.conn.execute(
                "UPDATE attempts SET lease_token='stolen' WHERE state_hash=?",
                (self.h,))
            callbacks.declare_verified(self.conn, attempt)   # raises

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual([o.status for o in out], ["skipped"])
        self.assertEqual(self._accounts(), [])


class TestQuarantinedConsent(Ready):
    """A failed verification leaves a real AIS consent at the bank. Recording
    it only in `attempts.session_id` makes it invisible: `consent_status` and
    `consent_ref` resolution read `sessions` and nothing else, so the
    collector's own advice to run `consent_status` was advice to run a tool
    that could not see it. It is now a real, degenerate `sessions` row."""

    def _fail_after_creating_the_consent(self, session_id="sess-9"):
        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, session_id)
            # verification fails here: nothing declared, nothing bound
        return exchange

    def test_the_stranded_consent_becomes_a_visible_session_row(self):
        out = callbacks.run_collection(
            self.conn, self.sp, self.pd,
            self._fail_after_creating_the_consent())
        self.assertEqual([o.status for o in out], ["review_required"])
        self.assertEqual(self._sessions(),
                         [{"session_id": "sess-9",
                           "status": callbacks.REVIEW_REQUIRED_STATUS,
                           "generation": callbacks.REVIEW_REQUIRED_GENERATION}])

    def test_the_quarantined_consent_binds_no_account(self):
        callbacks.run_collection(
            self.conn, self.sp, self.pd,
            self._fail_after_creating_the_consent())
        self.assertEqual(self._accounts(), [])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS c FROM accounts WHERE session_id='sess-9'"
        ).fetchone()["c"], 0)

    def test_it_is_reachable_the_way_consent_status_reaches_a_consent(self):
        """`consent_status` and `unlink_bank` resolve an opaque
        `sha256("consent-ref|" + session_id)[:8]` against `sessions`. This is
        that lookup, and it is the one that used to come back empty."""
        callbacks.run_collection(
            self.conn, self.sp, self.pd,
            self._fail_after_creating_the_consent())
        rows = self.conn.execute(
            "SELECT session_id FROM sessions WHERE status <> 'CLOSED'"
        ).fetchall()
        refs = {hashlib.sha256(("consent-ref|" + r["session_id"]).encode()
                               ).hexdigest()[:8]: r["session_id"] for r in rows}
        wanted = hashlib.sha256(b"consent-ref|sess-9").hexdigest()[:8]
        self.assertEqual(refs.get(wanted), "sess-9")

    def test_the_quarantined_row_can_never_win_the_generation_fence(self):
        """Generation 0 sits below every real session's default of 1."""
        callbacks.run_collection(
            self.conn, self.sp, self.pd,
            self._fail_after_creating_the_consent())
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency)"
            " VALUES ('acc1','uid-1','sess-9','EUR')")
        self.assertIsNone(callbacks.fence_verdict(
            self.conn, {"account_id": "acc1", "expected_generation": 1,
                        "purpose": "repair"}))

    def test_each_stranded_consent_gets_its_own_row(self):
        """A retry creates a SECOND consent at the bank; both must be
        revocable, so both are listed."""
        callbacks.run_collection(
            self.conn, self.sp, self.pd,
            self._fail_after_creating_the_consent())
        second = "T" * 43
        h2 = self.sp.state_hash(second)
        self._row(h2, second)
        self.sp.write_attempt(h2, "result_ready")
        rec = self._record()
        rec["query"] = [["state", second], ["code", "CODE2"]]
        rec["raw_query"] = f"state={second}&code=CODE2"
        self.sp.publish(h2, rec)
        callbacks.run_collection(
            self.conn, self.sp, self.pd,
            self._fail_after_creating_the_consent("sess-10"))
        self.assertEqual([s["session_id"] for s in self._sessions()],
                         ["sess-10", "sess-9"])

    def test_an_indeterminate_exchange_also_quarantines_its_consent(self):
        """A consent that exists because the exchange got that far and then
        died is exactly as stranded as one that failed verification."""
        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, "sess-9")
            raise OSError("connection reset")

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual([o.status for o in out], ["indeterminate"])
        self.assertEqual([s["session_id"] for s in self._sessions()],
                         ["sess-9"])
        self.assertNotIn("sess-9", out[0].detail)

    def test_an_exchange_that_never_reached_the_provider_strands_nothing(self):
        def exchange(code, attempt):
            raise OSError("connection reset")

        callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual(self._sessions(), [])

    def test_no_detail_discloses_the_stranded_session_id(self):
        out = callbacks.run_collection(
            self.conn, self.sp, self.pd,
            self._fail_after_creating_the_consent())
        self.assertNotIn("sess-9", out[0].detail)
        self.assertIn("consent_status", out[0].detail)
        self.assertIn("unlink_bank", out[0].detail)

    def test_review_required_is_durable_across_a_later_nudge(self):
        callbacks.run_collection(
            self.conn, self.sp, self.pd,
            self._fail_after_creating_the_consent())
        self.sp.write_attempt(self.h, "result_ready")     # casa re-dispatches
        again = callbacks.run_collection(self.conn, self.sp, self.pd,
                                         self._never)
        self.assertEqual([o.status for o in again], ["skipped"])
        self.assertEqual(self._phase()["phase"], "review_required")
        self.assertEqual(len(self._sessions()), 1)


class TestStagedUntilPromoted(Ready):
    """Closing the ledger until the verdict relocates the hole to immediately
    after it.

    Every double here does what the real `_exchange` does, in its order — note
    the session, declare the verdict, insert the session row, bind an account,
    then page a backfill. A double that only calls `note_session` and raises
    exercises the early-failure shape and nothing else, which is precisely how
    this goes unseen.
    """

    SID = "sess-new"
    OLD = "sess-old"

    def _link_shaped(self, *, bind=("acc-1", "acc-2"), fail_at=None):
        """A FIRST LINK, in production's order. `fail_at` names the account
        whose backfill dies AFTER the session row and that account's binding
        already exist."""

        def _exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, self.SID)
            callbacks.declare_verified(self.conn, attempt)   # verify_accounts ok
            self.conn.execute(
                "INSERT OR REPLACE INTO sessions(session_id, aspsp_name,"
                " country, psu_type, status, authorized_at, valid_until,"
                " generation) VALUES (?,'Revolut','NL','business',?,?,?,?)",
                (self.SID, callbacks.REVIEW_REQUIRED_STATUS,
                 "2026-08-03T09:00:00Z", "2027-01-29",
                 callbacks.REVIEW_REQUIRED_GENERATION))
            for index, account_id in enumerate(bind):
                callbacks.heartbeat(self.conn, attempt["state_hash"],
                                    attempt["lease_fence"])
                self.conn.execute(
                    "INSERT OR REPLACE INTO accounts(account_id, uid,"
                    " session_id, currency, aspsp)"
                    " VALUES (?,?,?,'EUR','Revolut')",
                    (account_id, "uid-%d" % index, self.SID))
                self.conn.execute(
                    "INSERT INTO coverage(account_id, interval_start,"
                    " interval_end, session_id) VALUES (?,?,?,?)",
                    (account_id, "2026-01-01", "2026-08-01", self.SID))
                if fail_at == account_id:
                    raise OSError("the provider dropped the connection")

        return _exchange

    #: `apply.switch_bindings`' retired status, spelled out because this suite
    #: cannot import `apply` (see `_renewal_shaped`). `apply.RETIRED_STATUS` is
    #: the authority; `test_apply` and `test_flows` are where it is exercised.
    RETIRED = "REVOKE_PENDING"

    def _renewal_shaped(self, *, fail_after_switch=False):
        """A RENEWAL, narrowed DELIBERATELY to `apply.switch_bindings`' output
        and modelling NOTHING BEYOND IT.

        What this reproduces is that one transaction, in its order: promote the
        staged session while the consent it replaces is still live — the single
        write the staging gate exists to permit — move the binding, bump the
        generation to `old + 1`, and retire the old row to `RETIRED`.

        What it deliberately does NOT reproduce, and does not assert:
        **`closed_at`**. `apply.record_revocation` is the sole writer of that
        column and it runs only after `flows._revoke` has actually asked the
        provider, so a double that stamped it by hand would certify a lifecycle
        no production path produces — a renewal whose revocation was refused
        leaves the old row `REVOKE_FAILED` with `closed_at` NULL, and one whose
        revocation 404s or succeeds closes it. Neither is this suite's subject.

        Driving the real `apply.switch_bindings` would be better still and is
        not available here: this module tests the callback consumer, and
        `apply` sits a layer below it. The real renewal
        lifecycle is `test_flows.TestCompleteRenewal` and `test_tools_auth`'s
        renewal tests, both of which drive `flows.complete_renewal` end to end
        against the real `switch_bindings` and the real `record_revocation`.

        What this suite actually observes is narrower than either: `_promote`,
        `_live_link` and `_contain` read the NEW session's status and whether
        it owns an account, and read nothing whatever about the old one.
        """

        def _exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, self.SID)
            callbacks.declare_verified(self.conn, attempt)
            self.conn.execute(
                "INSERT OR REPLACE INTO sessions(session_id, aspsp_name,"
                " country, psu_type, status, generation)"
                " VALUES (?,'Revolut','NL','business',?,?)",
                (self.SID, callbacks.REVIEW_REQUIRED_STATUS,
                 callbacks.REVIEW_REQUIRED_GENERATION))
            # switch_bindings' order: promote FIRST, while the old consent is
            # still live — that is the only shape the staging trigger passes —
            # and take the generation from the row being replaced rather than
            # hard-coding it, because `old + 1` is the rule.
            self.conn.execute(
                "UPDATE sessions SET status=?, generation="
                " (SELECT generation + 1 FROM sessions WHERE session_id=?)"
                " WHERE session_id=?",
                (callbacks.LIVE_SESSION_STATUS, self.OLD, self.SID))
            self.conn.execute(
                "UPDATE accounts SET uid='uid-new', session_id=?"
                " WHERE account_id='acc-1' AND session_id=?",
                (self.SID, self.OLD))
            self.conn.execute(
                "UPDATE sessions SET status=? WHERE session_id=?",
                (self.RETIRED, self.OLD))       # NOT closed: see the docstring
            if fail_after_switch:
                raise OSError("the provider dropped the connection")

        return _exchange

    def _live_old_consent(self):
        self.conn.execute(
            "INSERT INTO sessions(session_id, aspsp_name, country, psu_type,"
            " status, generation) VALUES (?,'Revolut','NL','business',?,4)",
            (self.OLD, callbacks.LIVE_SESSION_STATUS))
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency)"
            " VALUES ('acc-1','uid-old',?,'EUR')", (self.OLD,))

    def _staged_row(self):
        return {"session_id": self.SID,
                "status": callbacks.REVIEW_REQUIRED_STATUS,
                "generation": callbacks.REVIEW_REQUIRED_GENERATION}

    def _live_count(self):
        return self.conn.execute(
            "SELECT COUNT(*) AS c FROM sessions WHERE status=?",
            (callbacks.LIVE_SESSION_STATUS,)).fetchone()["c"]

    def _bound_count(self):
        return self.conn.execute(
            "SELECT COUNT(*) AS c FROM accounts WHERE session_id IS NOT NULL"
        ).fetchone()["c"]

    # -- failure after the first binding --------------------------------
    def test_a_failure_after_the_first_binding_leaves_no_live_link(self):
        out = callbacks.run_collection(self.conn, self.sp, self.pd,
                                       self._link_shaped(fail_at="acc-1"))
        self.assertEqual([o.status for o in out], ["indeterminate"])
        self.assertEqual(self._live_count(), 0)          # no live link
        self.assertEqual(self._bound_count(), 0)         # nothing bound to it
        self.assertEqual(self._sessions(), [self._staged_row()])
        self.assertEqual(self.sp.acked, [])

    def test_the_stranded_consent_is_visible_and_revocable(self):
        out = callbacks.run_collection(self.conn, self.sp, self.pd,
                                       self._link_shaped(fail_at="acc-1"))
        rows = self.conn.execute(
            "SELECT session_id FROM sessions WHERE status <> 'CLOSED'"
        ).fetchall()
        refs = {hashlib.sha256(("consent-ref|" + r["session_id"]).encode()
                               ).hexdigest()[:8]: r["session_id"] for r in rows}
        wanted = hashlib.sha256(
            ("consent-ref|" + self.SID).encode()).hexdigest()[:8]
        self.assertEqual(refs.get(wanted), self.SID)
        self.assertNotIn(self.SID, out[0].detail)
        self.assertIn("consent_status", out[0].detail)

    def test_the_released_account_can_be_bound_again_without_a_refusal(self):
        """`apply.upsert_account` refuses a rebinding by comparing the OFFERED
        uid and session id against the recorded ones, so containment has to
        clear BOTH — a row left carrying a dead uid would make the operator's
        retry fail as an unexplained rebinding instead of linking."""
        callbacks.run_collection(self.conn, self.sp, self.pd,
                                 self._link_shaped(fail_at="acc-1"))
        row = self.conn.execute(
            "SELECT uid, session_id FROM accounts WHERE account_id='acc-1'"
        ).fetchone()
        self.assertIsNone(row["session_id"])
        self.assertIsNone(row["uid"])

    def test_a_failure_between_two_bindings_releases_both(self):
        callbacks.run_collection(
            self.conn, self.sp, self.pd,
            self._link_shaped(bind=("acc-1", "acc-2"), fail_at="acc-2"))
        self.assertEqual(self._bound_count(), 0)
        self.assertEqual(sorted(a["account_id"] for a in self._accounts()),
                         ["acc-1", "acc-2"])

    # -- prevention, not cleanup ----------------------------------------
    def test_an_exchange_cannot_make_its_own_session_live(self):
        """Not "must not" — CANNOT, while the bank has no live consent already
        (the `Ready` fixture's case, and the ordinary first link). Both shapes
        fail inside SQLite: inserting an already-live row, and promoting the
        staged one it just wrote.

        **This is not the whole story.** The trigger
        that stops the third case can only ask "does a live consent for this
        bank exist right now" — a `BEFORE UPDATE` trigger sees no more than
        that — and when the answer is already yes (a re-link), the same
        UPDATE is indistinguishable from `apply.switch_bindings`' legitimate
        replacement and is allowed through. See
        `test_a_staged_session_can_self_promote_when_the_bank_is_already_live`
        for that traced boundary, asserted rather than assumed away."""
        tried = []

        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, self.SID)
            callbacks.declare_verified(self.conn, attempt)
            for sql, args in (
                ("INSERT INTO sessions(session_id, aspsp_name, status,"
                 " generation) VALUES ('sess-live','Revolut',?,1)",
                 (callbacks.LIVE_SESSION_STATUS,)),
                ("INSERT INTO sessions(session_id, aspsp_name, status,"
                 " generation) VALUES (?,'Revolut',?,?)",
                 (self.SID, callbacks.REVIEW_REQUIRED_STATUS,
                  callbacks.REVIEW_REQUIRED_GENERATION)),
                ("UPDATE sessions SET status=?, generation=1"
                 " WHERE session_id=?",
                 (callbacks.LIVE_SESSION_STATUS, self.SID)),
            ):
                try:
                    self.conn.execute(sql, args)
                    tried.append("WROTE")
                except sqlite3.IntegrityError as exc:
                    tried.append(str(exc))

        callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertIn("live consent", tried[0])   # the AUTHORIZED insert
        self.assertEqual(tried[1], "WROTE")       # the STAGED insert is fine
        self.assertIn("promote", tried[2])        # the self-promotion
        self.assertEqual(self._live_count(), 0)

    def test_an_exchange_that_still_writes_a_live_session_links_nothing(self):
        """Run against the gate: an exchange that has NOT been taught to
        stage — it inserts an AUTHORIZED session directly, binds an account
        and then dies. The insert aborts in
        SQLite, so the failure is loud and total rather than a live consent with
        a partial binding — WHILE the bank has no live consent already (the
        `Ready` fixture's case).

        **The guarantee is NOT independent of the exchange's own discipline
        once the bank already has a live consent.**
        The insert this test relies on aborting is exactly the case
        `_stage_ledger`'s trigger can tell apart from a legitimate replacement
        (nothing exists yet to replace); once something does, the trigger
        cannot tell the two apart and a self-promoting UPDATE succeeds. See
        `test_a_staged_session_can_self_promote_when_the_bank_is_already_live`."""
        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, self.SID)
            callbacks.declare_verified(self.conn, attempt)
            self.conn.execute(
                "INSERT INTO sessions(session_id, aspsp_name, country,"
                " psu_type, status, generation)"
                " VALUES (?,'Revolut','NL','business',?,1)",
                (self.SID, callbacks.LIVE_SESSION_STATUS))
            self.conn.execute(                       # never reached
                "INSERT INTO accounts(account_id, uid, session_id, currency)"
                " VALUES ('acc-1','uid-0',?,'EUR')", (self.SID,))
            raise OSError("the provider dropped the connection")

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual([o.status for o in out], ["indeterminate"])
        self.assertEqual(self._live_count(), 0)
        self.assertEqual(self._bound_count(), 0)
        self.assertEqual(self._sessions(), [self._staged_row()])

    # -- the re-link residual, named and pinned ----------------------------
    def test_a_staged_session_can_self_promote_when_the_bank_is_already_live(self):
        """The residual `_stage_ledger`'s docstring now names instead of
        overclaiming past. A `BEFORE UPDATE` trigger sees only the PRE-state
        of a write: it can ask "does a live consent for this bank exist right
        now", never "is THIS write the one replacing it". Those two questions
        coincide for `apply.switch_bindings` (the only thing that needs a live
        consent to exist in order to run), but not for an untrusted exchange
        that just happens to write while the bank already has one on file.

        This asserts the REAL behaviour: with a live consent already recorded
        for `self.OLD`'s bank, a plain UPDATE promoting a DIFFERENT staged
        session for the SAME bank SUCCEEDS — the trigger has nothing left to
        refuse, because something already exists for it to mistake for the
        thing being replaced."""
        self._live_old_consent()      # a live consent already exists (OLD, gen 4)
        tried = []

        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, self.SID)
            callbacks.declare_verified(self.conn, attempt)
            self.conn.execute(
                "INSERT INTO sessions(session_id, aspsp_name, status,"
                " generation) VALUES (?,'Revolut',?,?)",
                (self.SID, callbacks.REVIEW_REQUIRED_STATUS,
                 callbacks.REVIEW_REQUIRED_GENERATION))
            try:
                self.conn.execute(
                    "UPDATE sessions SET status=?, generation=1"
                    " WHERE session_id=?",
                    (callbacks.LIVE_SESSION_STATUS, self.SID))
                tried.append("WROTE")
            except sqlite3.IntegrityError as exc:
                tried.append(str(exc))

        callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        # unlike test_an_exchange_cannot_make_its_own_session_live (no prior
        # live consent), this self-promotion is NOT blocked:
        self.assertEqual(tried, ["WROTE"])
        # the ledger now holds two live sessions for one bank — the residual,
        # not a guarantee anything here closed:
        self.assertEqual(self._live_count(), 2)

    def test_a_promotion_over_an_existing_live_session_lands_above_it(self):
        """Pinned as a property. Writing the literal `FIRST_GENERATION`
        unconditionally puts a first link promoted while the bank already
        holds a live session at generation 4 at generation 1 — BELOW it —
        which inverts the generation fence:
        `fence_verdict` against `expected_generation=4` read as current again,
        which is precisely the silent rebind onto a stale consent the fence
        exists to prevent. `_promote` takes `MAX(generation) + 1` over the
        bank's
        other sessions, so the new live session lands ABOVE the old one and
        the old generation no longer reads as current.

        This drives `_promote` itself — an ordinary, non-self-promoting first
        link (`_link_shaped`) — not the trigger residual
        `test_a_staged_session_can_self_promote_when_the_bank_is_already_live`
        exercises. The two are independent."""
        self._live_old_consent()      # OLD is AUTHORIZED at generation 4
        out = callbacks.run_collection(self.conn, self.sp, self.pd,
                                       self._link_shaped(bind=("acc-1",)))
        self.assertEqual([o.status for o in out], ["succeeded"])
        new_row = self.conn.execute(
            "SELECT status, generation FROM sessions WHERE session_id=?",
            (self.SID,)).fetchone()
        old_row = self.conn.execute(
            "SELECT status, generation FROM sessions WHERE session_id=?",
            (self.OLD,)).fetchone()
        self.assertEqual(new_row["status"], callbacks.LIVE_SESSION_STATUS)
        self.assertGreater(new_row["generation"], old_row["generation"])
        self.assertEqual(new_row["generation"], 5)     # MAX(4) + 1, not 1
        # a repair minted against the OLD consent's generation must no longer
        # read as current: it is stale, not silently applied.
        self.assertEqual(callbacks.fence_verdict(
            self.conn, {"account_id": "acc-1", "expected_generation": 4,
                        "purpose": "repair"}), "stale_generation")

    def test_a_transaction_the_exchange_left_open_blocks_nothing(self):
        """`apply.apply_plan` and `apply.switch_bindings` both take a
        transaction. One that dies inside its own would leave it open, and the
        collector's `BEGIN IMMEDIATE` would then raise on top of the failure it
        was recording. The uncommitted writes are discarded — which is exactly
        the work that must not survive — and the noted consent is still
        quarantined, because `note_session` committed before any of it."""
        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, self.SID)
            callbacks.declare_verified(self.conn, attempt)
            self.conn.execute("BEGIN IMMEDIATE")
            self.conn.execute(
                "INSERT INTO sessions(session_id, aspsp_name, country,"
                " psu_type, status, generation)"
                " VALUES (?,'Revolut','NL','business',?,?)",
                (self.SID, callbacks.REVIEW_REQUIRED_STATUS,
                 callbacks.REVIEW_REQUIRED_GENERATION))
            self.conn.execute(
                "INSERT INTO accounts(account_id, uid, session_id, currency)"
                " VALUES ('acc-1','uid-0',?,'EUR')", (self.SID,))
            raise OSError("the provider dropped the connection")

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual([o.status for o in out], ["indeterminate"])
        self.assertEqual(self._live_count(), 0)
        self.assertEqual(self._accounts(), [])       # never committed
        self.assertEqual(self._sessions(), [self._staged_row()])

    def test_the_collector_promotes_only_after_the_exchange_has_returned(self):
        seen = {}

        def exchange(code, attempt):
            self._link_shaped(bind=("acc-1",))(code, attempt)
            seen["at_return"] = self.conn.execute(
                "SELECT status, generation FROM sessions WHERE session_id=?",
                (self.SID,)).fetchone()

        original = self.sp.ack

        def ack(plugin_dir, h):
            seen["at_ack"] = self.conn.execute(
                "SELECT status, generation FROM sessions WHERE session_id=?",
                (self.SID,)).fetchone()
            return original(plugin_dir, h)

        self.sp.ack = ack
        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual([o.status for o in out], ["succeeded"])
        self.assertEqual(
            (seen["at_return"]["status"], seen["at_return"]["generation"]),
            (callbacks.REVIEW_REQUIRED_STATUS,
             callbacks.REVIEW_REQUIRED_GENERATION))
        self.assertEqual(
            (seen["at_ack"]["status"], seen["at_ack"]["generation"]),
            (callbacks.LIVE_SESSION_STATUS, callbacks.FIRST_GENERATION))
        self.assertEqual(self._accounts(),
                         [{"account_id": "acc-1", "session_id": self.SID}])

    def test_a_declared_exchange_that_bound_nothing_is_not_a_success(self):
        """A consent nothing is bound to is not a link: it is not promoted, and
        it is not reported as one."""
        out = callbacks.run_collection(self.conn, self.sp, self.pd,
                                       self._link_shaped(bind=()))
        self.assertEqual([o.status for o in out], ["review_required"])
        self.assertNotIn(out[0].status, callbacks.SUCCESS_STATUSES)
        self.assertEqual(self._phase()["outcome"], "unbound_link")
        self.assertEqual(self._sessions(), [self._staged_row()])
        self.assertEqual(self.sp.acked, [self.h])

    def test_no_temp_trigger_outlives_a_declared_exchange(self):
        callbacks.run_collection(self.conn, self.sp, self.pd,
                                 self._link_shaped(bind=("acc-1",)))
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS c FROM sqlite_temp_master WHERE type='trigger'"
        ).fetchone()["c"], 0)

    # -- the renewal shape must still work ------------------------------
    def test_a_renewal_switch_may_still_promote_inside_the_exchange(self):
        """The gate forbids CREATING a live consent, not REPLACING one. The
        renewal switch promotes while the consent it replaces is still live, and
        that is the only shape allowed through — which is why first link and
        renewal converge instead of needing an escape hatch.

        The end state asserted here is `apply.switch_bindings`' and stops
        exactly where it stops: the old row is RETIRED, not closed. Closing it
        is `apply.record_revocation`'s, after `flows._revoke` has actually
        asked the provider, and this suite neither models nor asserts that."""
        self._live_old_consent()
        out = callbacks.run_collection(self.conn, self.sp, self.pd,
                                       self._renewal_shaped())
        self.assertEqual([o.status for o in out], ["succeeded"])
        self.assertEqual(self._sessions(), [
            {"session_id": self.SID, "status": callbacks.LIVE_SESSION_STATUS,
             "generation": 5},
            {"session_id": self.OLD, "status": self.RETIRED, "generation": 4}])
        self.assertEqual(self._accounts(),
                         [{"account_id": "acc-1", "session_id": self.SID}])
        # the double did not write `closed_at`, and nothing here may: a switch
        # is not a revocation, and the column has exactly one writer
        self.assertIsNone(self.conn.execute(
            "SELECT closed_at FROM sessions WHERE session_id=?",
            (self.OLD,)).fetchone()["closed_at"])

    def test_a_completed_renewal_is_never_demoted_by_a_late_failure(self):
        """Containment is not a sweep. A renewal that finished its switch and
        then lost the connection is a FINISHED renewal — its predecessor is
        already retired — so demoting it would break a working consent."""
        self._live_old_consent()
        out = callbacks.run_collection(
            self.conn, self.sp, self.pd,
            self._renewal_shaped(fail_after_switch=True))
        self.assertEqual([o.status for o in out], ["indeterminate"])
        self.assertEqual(self._sessions(), [
            {"session_id": self.SID, "status": callbacks.LIVE_SESSION_STATUS,
             "generation": 5},
            {"session_id": self.OLD, "status": self.RETIRED, "generation": 4}])
        self.assertEqual(self._accounts(),
                         [{"account_id": "acc-1", "session_id": self.SID}])

    # -- the collector that never came back -----------------------------
    def test_a_killed_collector_is_contained_by_the_next_nudge(self):
        """Nothing runs in a killed process, so containment has to be something
        a LATER turn does. This is exactly what such a collector leaves behind:
        `exchange_started`, a noted session, a staged session row, one bound
        account, an expired lease, and the result already renamed into a hold."""
        self.conn.execute(
            "UPDATE attempts SET phase='exchange_started', session_id=?,"
            " lease_owner='dead', lease_token='gone', lease_expiry=?"
            " WHERE state_hash=?", (self.SID, time.time() - 1.0, self.h))
        self.conn.execute(
            "INSERT INTO sessions(session_id, aspsp_name, country, psu_type,"
            " status, generation) VALUES (?,'Revolut','NL','business',?,?)",
            (self.SID, callbacks.REVIEW_REQUIRED_STATUS,
             callbacks.REVIEW_REQUIRED_GENERATION))
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency)"
            " VALUES ('acc-1','uid-0',?,'EUR')", (self.SID,))
        (self.sp.root / "results" / f".collect-{self.h}-dead").write_text(
            json.dumps(self._record()), encoding="utf-8")

        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual([o.status for o in out], ["indeterminate"])
        self.assertEqual(self._live_count(), 0)
        self.assertEqual(self._bound_count(), 0)
        self.assertEqual(self._sessions(), [self._staged_row()])
        self.assertEqual(self.sp.acked, [])
        self.assertIn("unlink_bank", out[0].detail)


class TestCappedBackfillIsNotSuccess(Ready):
    """A cap path that returns an ordinary result makes authorization record a
    successful collection, leaving the fresh-SCA loss silent at the one call
    that could still fix it."""

    def test_a_capped_run_is_reported_as_partial_not_succeeded(self):
        out = callbacks.run_collection(self.conn, self.sp, self.pd,
                                       self._compliant("sess-1", partial=True))
        self.assertEqual([o.status for o in out], ["partial"])
        self.assertNotIn(out[0].status, callbacks.SUCCESS_STATUSES)

    def test_the_partial_run_persists_its_own_outcome(self):
        callbacks.run_collection(self.conn, self.sp, self.pd,
                                 self._compliant("sess-1", partial=True))
        row = self._phase()
        self.assertEqual(row["phase"], "exchanged")
        self.assertEqual(row["outcome"], "collected_partial")
        self.assertEqual(row["session_id"], "sess-1")     # carried internally

    def test_the_partial_detail_never_reads_as_success_or_a_renewal(self):
        out = callbacks.run_collection(self.conn, self.sp, self.pd,
                                       self._compliant("sess-1", partial=True))
        lowered = out[0].detail.lower()
        for word in ("success", "renew", "refreshed", "linked", "recorded"):
            self.assertNotIn(word, lowered)
        self.assertIn("incomplete", lowered)
        self.assertIn("sync", lowered)
        self.assertNotIn("sess-1", out[0].detail)

    def test_the_consent_itself_is_still_bound(self):
        """Partial means the HISTORY is short, not that the link failed: the
        accounts were verified, so they stay bound and usable."""
        callbacks.run_collection(self.conn, self.sp, self.pd,
                                 self._compliant("sess-1", partial=True))
        self.assertEqual(self._accounts(),
                         [{"account_id": "acc-linked", "session_id": "sess-1"}])

    def test_partial_cannot_be_declared_without_a_verdict(self):
        raised = []

        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, "sess-9")
            try:
                callbacks.declare_partial(self.conn, attempt)
            except callbacks.Indeterminate as exc:
                raised.append(str(exc))

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual(len(raised), 1)
        self.assertEqual([o.status for o in out], ["review_required"])

    def test_success_statuses_is_the_only_set_a_caller_may_branch_on(self):
        self.assertEqual(callbacks.SUCCESS_STATUSES, frozenset({"succeeded"}))


class TestGenerationFence(Base):
    """The consumer side of the generation fence. A repair or renewal names
    the account it is for and the generation it
    expected to find there; a callback arriving after a newer session already
    rebound that account must not roll it back, and one carrying no fence at
    all cannot be proved current and is refused outright."""

    def _bind(self, expected, current, purpose="repair", account_id="acc1"):
        self.conn.execute(
            "INSERT INTO sessions(session_id, aspsp_name, country, psu_type,"
            " status, generation) VALUES ('sess-current','Revolut','NL',"
            "'business','AUTHORIZED',?)", (current,))
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency)"
            " VALUES ('acc1','uid-1','sess-current','EUR')")
        self.conn.execute(
            "UPDATE attempts SET purpose=?, account_id=?,"
            " expected_generation=? WHERE state_hash=?",
            (purpose, account_id, expected, self.h))
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record(
            meta=dict(META, purpose=purpose, account_id=account_id,
                      generation=expected)))

    def test_a_late_generation_callback_never_reaches_the_exchange(self):
        self._bind(expected=3, current=4)
        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual([o.status for o in out], ["stale"])
        row = self._phase()
        self.assertEqual(row["phase"], "closed")
        self.assertEqual(row["outcome"], "stale_generation")
        self.assertIsNone(row["session_id"])
        # the newer binding is untouched
        self.assertEqual(self.conn.execute(
            "SELECT session_id FROM accounts WHERE account_id='acc1'"
        ).fetchone()["session_id"], "sess-current")
        self.assertEqual(self.sp.acked, [self.h])

    def test_the_current_generation_is_allowed_through(self):
        """The fence must stop stale callbacks, not every repair."""
        self._bind(expected=4, current=4)
        out = callbacks.run_collection(self.conn, self.sp, self.pd,
                                       self._compliant("s2"))
        self.assertEqual([o.status for o in out], ["succeeded"])
        self.assertEqual(self._phase()["session_id"], "s2")

    def test_a_repair_with_no_expected_generation_is_refused(self):
        """An absent generation is a HARD refusal for a repair, not a soft
        pass. A producer that forgets to mint the fence cannot be waved
        through — that omission is exactly what the fence exists to catch."""
        self._bind(expected=None, current=4)
        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual([o.status for o in out], ["stale"])
        self.assertEqual(self._phase()["outcome"], "unfenced_repair")
        self.assertEqual(self.sp.acked, [self.h])
        self.assertIn("Start the repair again", out[0].detail)

    def test_a_repair_naming_no_account_is_refused(self):
        self._bind(expected=4, current=4, account_id=None)
        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual([o.status for o in out], ["stale"])
        self.assertEqual(self._phase()["outcome"], "unfenced_repair")

    def test_a_repair_whose_account_no_longer_resolves_is_refused(self):
        """`forget_local_account` ran while the repair was in flight, so there
        is no generation left to compare against. Fail closed."""
        self._bind(expected=4, current=4)
        self.conn.execute("DELETE FROM accounts WHERE account_id='acc1'")
        out = callbacks.run_collection(self.conn, self.sp, self.pd, self._never)
        self.assertEqual([o.status for o in out], ["stale"])
        self.assertEqual(self._phase()["outcome"], "unfenced_repair")

    def test_a_first_link_needs_no_fence_at_all(self):
        """The refusal keys on PURPOSE. A link has no prior binding to be
        stale against, and requiring one would break every first link."""
        self.sp.write_attempt(self.h, "result_ready")
        self.sp.publish(self.h, self._record())
        out = callbacks.run_collection(self.conn, self.sp, self.pd,
                                       self._compliant())
        self.assertEqual([o.status for o in out], ["succeeded"])

    def test_the_fenced_purposes_are_named_not_inferred(self):
        self.assertEqual(callbacks.FENCED_PURPOSES,
                         frozenset({"repair", "renew"}))


class TestWriteFencing(Ready):
    """Every state transition and ledger write is fenced, including the
    injected exchange's own writes."""

    def _expiry(self):
        return self._phase()["lease_expiry"]

    def test_the_exchange_extends_its_own_lease_through_heartbeat(self):
        seen = {}

        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, "sess-1")
            self.conn.execute(
                "UPDATE attempts SET lease_expiry=? WHERE state_hash=?",
                (time.time() + 1.0, self.h))     # nearly out of time
            callbacks.heartbeat(self.conn, attempt["state_hash"],
                                attempt["lease_fence"])
            seen["after"] = self._expiry()
            callbacks.declare_verified(self.conn, attempt)
            self._write_ledger("sess-1")

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual([o.status for o in out], ["succeeded"])
        self.assertGreater(seen["after"],
                           time.time() + callbacks.LEASE_TTL_S - 10)

    def test_a_stolen_lease_stops_the_exchange_at_its_next_write(self):
        wrote = []

        def exchange(code, attempt):
            callbacks.note_session(self.conn, attempt, "sess-1")
            self.conn.execute(
                "UPDATE attempts SET lease_owner='B', lease_token='stolen',"
                " lease_expiry=? WHERE state_hash=?",
                (time.time() + 90, self.h))
            callbacks.heartbeat(self.conn, attempt["state_hash"],
                                attempt["lease_fence"])
            wrote.append("upserted the accounts")     # must never run
            self._write_ledger("sess-1")

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual(wrote, [])
        self.assertEqual([o.status for o in out], ["skipped"])
        self.assertEqual(self.sp.acked, [])
        self.assertNotEqual(self._phase()["phase"], "exchanged")
        self.assertEqual(self._accounts(), [])

    def test_a_stale_fence_cannot_even_record_the_failure(self):
        """The indeterminate write used to ignore its own rowcount, so a
        successor's flow could be reported on by a collector that had already
        lost the lease."""
        def exchange(code, attempt):
            self.conn.execute(
                "UPDATE attempts SET lease_token='stolen', lease_expiry=?"
                " WHERE state_hash=?", (time.time() + 90, self.h))
            raise OSError("connection reset")

        out = callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual([o.status for o in out], ["skipped"])
        self.assertEqual(self.sp.acked, [])
        self.assertEqual(self._phase()["phase"], "exchange_started")

    def test_a_noted_session_under_a_stale_fence_is_refused(self):
        raised = []

        def exchange(code, attempt):
            self.conn.execute(
                "UPDATE attempts SET lease_token='stolen' WHERE state_hash=?",
                (self.h,))
            try:
                callbacks.note_session(self.conn, attempt, "sess-9")
            except callbacks.Indeterminate as exc:
                raised.append(str(exc))

        callbacks.run_collection(self.conn, self.sp, self.pd, exchange)
        self.assertEqual(len(raised), 1)
        self.assertIsNone(self._phase()["session_id"])


if __name__ == "__main__":
    unittest.main()
