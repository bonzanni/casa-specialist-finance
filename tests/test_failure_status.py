# tests/test_failure_status.py
"""Issues #83 and #84: a failing provider call keeps its HTTP status, a
routine sync that keeps failing shows in consent_status, and a consent the
provider will not let go of has an operator settlement path.

Every scenario runs through the real tools (`sync`, `consent_status`,
`unlink_bank`, the erasers) against the real ledger; only the provider is a
double, and it fails per account uid so two banks can disagree.
"""
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]
                       / "plugins/bank-feed/server"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import apply  # noqa: E402
import callbacks  # noqa: E402
import eb_ais  # noqa: E402
import flows  # noqa: E402
import tools_auth  # noqa: E402
import tools_destructive  # noqa: E402,F401  (registers unlink_bank & erasers)
import tools_refresh  # noqa: E402,F401  (registers sync)
import tools_backup  # noqa: E402,F401
from _toolbase import SESSION_ID, Base, FakeAIS, call  # noqa: E402

OTHER_SESSION = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
HTTP_401 = "ApiError: HTTP 401 unauthorized"


class PerUidAIS(FakeAIS):
    """Transactions fail for the uids in `failing`, with the exception given."""

    def __init__(self):
        super().__init__()
        self.failing = {}
        self.delete_calls = 0

    def transactions(self, uid, date_from, continuation_key=None):
        if uid in self.failing:
            self.tx_calls.append((uid, date_from, continuation_key))
            raise self.failing[uid]
        return super().transactions(uid, date_from, continuation_key)

    def delete_session(self, sid):
        self.delete_calls += 1
        return super().delete_session(sid)


class FailureBase(Base):
    def setUp(self):
        super().setUp()
        self.ais = PerUidAIS()

    def two_banks(self):
        self.session()                                       # Rabobank
        self.session(sid=OTHER_SESSION, aspsp="ING")
        self.account("acc1")
        self.account("acc2", session_id=OTHER_SESSION)

    def refuse(self, aid="acc1", status=401):
        self.ais.failing["uid-" + aid] = eb_ais.ApiError(status, "transactions")

    def sync_tx(self, **kw):
        return call("sync", resource="transactions", **kw)

    def ref(self, session_id=SESSION_ID):
        return tools_auth._consent_ref(session_id)

    def health(self, aid="acc1"):
        row = self.raw.execute("SELECT value FROM meta WHERE key=?",
                               (tools_auth.sync_health_key(aid),)).fetchone()
        return json.loads(row[0]) if row else None

    def session_row(self, sid=SESSION_ID):
        row = self.raw.execute("SELECT status, closed_at FROM sessions"
                               " WHERE session_id=?", (sid,)).fetchone()
        return dict(row) if row else None

    def revoke_key(self, sid=SESSION_ID):
        return self.raw.execute(
            "SELECT value FROM meta WHERE key=?",
            (apply.revoke_failure_key(sid),)).fetchone()


# ---------------------------------------------------------------- issue #83

class TestSyncFailureCarriesItsStatus(FailureBase):
    def test_the_sync_reply_and_the_ledger_name_the_status(self):
        self.session()
        self.account()
        self.refuse()
        out = self.sync_tx()
        self.assertIn("FAILED (%s)" % HTTP_401, out)
        last_error = self.raw.execute(
            "SELECT last_error FROM sync_state WHERE account_id='acc1'"
            " AND resource='transactions'").fetchone()[0]
        self.assertEqual(last_error, HTTP_401)

    def test_a_non_api_failure_stays_its_class_name(self):
        self.session()
        self.account()
        self.ais.failing["uid-acc1"] = OSError("reset by peer, body text")
        out = self.sync_tx()
        self.assertIn("FAILED (OSError)", out)
        self.assertNotIn("body text", out)


class TestConsentStatusShowsAFailingSync(FailureBase):
    def test_an_authorized_consent_whose_sync_keeps_failing_says_so(self):
        self.session()
        self.account()
        self.sync_tx()                                       # one success
        self.refuse()
        self.sync_tx()
        self.sync_tx()
        out = call("consent_status")
        self.assertIn("status AUTHORIZED", out)
        lines = [l for l in out.split("\n") if "SYNC FAILING" in l]
        self.assertEqual(len(lines), 1, out)
        self.assertIn("2 attempt(s)", lines[0])
        self.assertIn(HTTP_401, lines[0])
        self.assertNotIn("not recorded", lines[0])           # the success was
        self.assertEqual(self.health()["fail"]["count"], 2)

    def test_a_success_clears_it(self):
        self.session()
        self.account()
        self.refuse()
        self.sync_tx()
        self.assertIn("SYNC FAILING", call("consent_status"))
        self.ais.failing.clear()
        self.sync_tx()
        self.assertNotIn("SYNC FAILING", call("consent_status"))
        self.assertIsNone(self.health()["fail"])

    def test_a_healthy_ledger_says_nothing(self):
        self.two_banks()
        self.sync_tx()
        self.assertNotIn("SYNC FAILING", call("consent_status"))

    def test_the_line_sits_under_the_consent_it_belongs_to(self):
        self.two_banks()
        self.refuse("acc2")
        self.sync_tx()
        out = call("consent_status").split("\n")
        heads = [i for i, l in enumerate(out) if " — status " in l]
        failing = [i for i, l in enumerate(out) if "SYNC FAILING" in l]
        self.assertEqual(len(failing), 1)
        ing = [i for i in heads if out[i].startswith("ING")][0]
        self.assertGreater(failing[0], ing)
        later_heads = [i for i in heads if i > ing]
        if later_heads:
            self.assertLess(failing[0], later_heads[0])

    def test_an_incarnation_rotation_does_not_hide_it(self):
        # Purge and restore rotate `accounts.incarnation`; neither changes the
        # consent or what the provider answers it.
        self.session()
        self.account()
        self.refuse()
        self.sync_tx()
        self.raw.execute("UPDATE accounts SET incarnation='rotated'")
        self.assertIn("SYNC FAILING", call("consent_status"))

    def test_a_record_for_another_binding_is_ignored(self):
        # A renewal re-binds the account; the old consent's record no longer
        # describes it.
        self.session()
        self.session(sid=OTHER_SESSION)
        self.account()
        self.refuse()
        self.sync_tx()
        self.raw.execute("UPDATE accounts SET session_id=?", (OTHER_SESSION,))
        self.assertNotIn("SYNC FAILING", call("consent_status"))

    def test_a_record_prints_only_under_the_consent_it_names(self):
        # consent_status read the OLD consent's accounts; a renewal then
        # re-bound the account and its new consent's sync failed. The new
        # record must not print under the old consent.
        self.session()
        self.session(sid=OTHER_SESSION)
        self.account(session_id=OTHER_SESSION)
        tools_auth.record_sync_health(self.raw, "acc1", OTHER_SESSION,
                                      eb_ais.ApiError(403, "transactions"), 1.0)
        old = {"session_id": SESSION_ID, "aspsp_name": "Rabobank"}
        new = {"session_id": OTHER_SESSION, "aspsp_name": "Rabobank"}
        self.assertEqual(tools_auth.sync_failure_lines(self.raw, "acc1", "a", old), [])
        self.assertIsNone(tools_auth.refusal_hint(self.raw, "acc1", old))
        self.assertEqual(len(tools_auth.sync_failure_lines(
            self.raw, "acc1", "a", new)), 1)

    def test_the_writer_is_fenced_on_the_session_alone(self):
        self.session()
        self.session(sid=OTHER_SESSION)
        self.account()
        exc = eb_ais.ApiError(401, "transactions")
        # A fetch captured under the old session, finishing after a renewal:
        self.raw.execute("UPDATE accounts SET session_id=?", (OTHER_SESSION,))
        tools_auth.record_sync_health(self.raw, "acc1", SESSION_ID, exc, 1.0)
        self.assertIsNone(self.health())
        # …and one for an account a forget has removed:
        tools_auth.record_sync_health(self.raw, "gone", OTHER_SESSION, exc, 1.0)
        self.assertIsNone(self.health("gone"))
        # A purge or restore rotates the incarnation and changes neither the
        # consent nor its answer, so a failure crossing one IS recorded.
        self.raw.execute("UPDATE accounts SET incarnation='rotated'")
        tools_auth.record_sync_health(self.raw, "acc1", OTHER_SESSION, exc, 2.0)
        self.assertEqual(self.health()["fail"]["count"], 1)

    def test_a_late_stale_observation_cannot_overwrite_a_newer_one(self):
        self.session()
        self.account()
        exc = eb_ais.ApiError(401, "transactions")
        tools_auth.record_sync_health(self.raw, "acc1", SESSION_ID, None, 20.0)
        # A failing fetch that STARTED earlier lands after the success:
        tools_auth.record_sync_health(self.raw, "acc1", SESSION_ID, exc, 10.0)
        self.assertIsNone(self.health()["fail"])
        self.assertNotIn("SYNC FAILING", call("consent_status"))
        # A later one does land.
        tools_auth.record_sync_health(self.raw, "acc1", SESSION_ID, exc, 30.0)
        self.assertEqual(self.health()["fail"]["count"], 1)
        # And a stale success cannot clear it either.
        tools_auth.record_sync_health(self.raw, "acc1", SESSION_ID, None, 25.0)
        self.assertEqual(self.health()["fail"]["count"], 1)

    def test_the_real_purge_does_not_hide_a_failure(self):
        self.session()
        self.account()
        self.refuse()
        self.sync_tx()
        call("purge", before_date="all", user_work="keep")
        self.assertIn("SYNC FAILING", call("consent_status"))
        self.sync_tx()
        self.assertEqual(self.health()["fail"]["count"], 2)

    def test_a_renewal_backfill_failure_is_not_a_routine_failure(self):
        # `flows.backfill` run by link/renewal must not write the record.
        self.session()
        self.account()
        self.refuse()
        account = dict(self.raw.execute(
            "SELECT * FROM accounts WHERE account_id='acc1'").fetchone())
        with self.assertRaises(eb_ais.ApiError):
            flows.backfill(self.ais, self.raw, account, OTHER_SESSION,
                           incarnation=account["incarnation"])
        self.assertIsNone(self.health())


class TestRefusalHint(FailureBase):
    def setUp(self):
        super().setUp()
        # The base freezes `_now_s` to one whole second; production reads
        # `time.time()`. The hint orders two answers strictly, so these tests
        # need a clock that moves — a millisecond per read, from the frozen one.
        frozen = tools_auth._now_s
        ticks = iter(range(1, 10 ** 6))
        self.addCleanup(setattr, tools_auth, "_now_s", frozen)
        tools_auth._now_s = lambda: frozen() + next(ticks) / 1000.0
    def test_a_refusal_while_another_consent_works_is_named_in_both_places(self):
        self.two_banks()
        self.refuse("acc1")
        out = self.sync_tx()
        hint = [l for l in out.split("\n") if "refused this consent's data" in l]
        self.assertEqual(len(hint), 1, out)
        self.assertIn("HTTP 401", hint[0])
        self.assertIn("(ING)", hint[0])
        self.assertIn("re-link Rabobank with link_bank", hint[0])
        self.assertIn("Nothing here was closed or revoked", hint[0])
        status = call("consent_status")
        self.assertEqual(status.count("refused this consent's data"), 1)
        # A report, not a state change.
        self.assertEqual(self.session_row()["status"],
                         callbacks.LIVE_SESSION_STATUS)

    def test_403_counts_too(self):
        self.two_banks()
        self.refuse("acc1", status=403)
        self.assertIn("HTTP 403", self.sync_tx())

    def test_no_hint_for_an_outage(self):
        self.two_banks()
        self.refuse("acc1", status=503)
        out = self.sync_tx()
        self.assertIn("ApiError: HTTP 503 provider_error", out)
        self.assertNotIn("refused this consent's data", out)
        self.assertNotIn("refused this consent's data", call("consent_status"))

    def test_no_hint_when_every_consent_is_refused(self):
        # Then the credential is the suspect, and the hint would be wrong.
        self.two_banks()
        self.refuse("acc1")
        self.refuse("acc2")
        out = self.sync_tx()
        self.assertEqual(out.count("FAILED (%s)" % HTTP_401), 2)
        self.assertNotIn("refused this consent's data", out)
        self.assertNotIn("refused this consent's data", call("consent_status"))

    def test_no_hint_when_the_other_success_is_older_than_the_refusal(self):
        self.two_banks()
        self.sync_tx(account="acc2")                         # ING ok first
        self.raw.execute(
            "UPDATE meta SET value=json_set(value, '$.ok_s', 1.0) WHERE key=?",
            (tools_auth.sync_health_key("acc2"),))
        self.refuse("acc1")
        self.refuse("acc2")                                  # ING fails now
        self.sync_tx(account="acc1")
        self.assertNotIn("refused this consent's data", call("consent_status"))


class TestRefusalHintOrdering(FailureBase):
    """Whole-second stamps cannot order two answers in one second, so the
    evidence is compared on full-precision `_now_s()` floats, strictly."""

    def at(self, t):
        self.patch(tools_auth, "_now_s", lambda: t)

    def patch(self, module, attr, value):
        self.addCleanup(setattr, module, attr, getattr(module, attr))
        setattr(module, attr, value)

    def test_an_earlier_success_in_the_same_second_is_not_evidence(self):
        self.two_banks()
        exc = eb_ais.ApiError(401, "transactions")
        self.at(1000.1)
        tools_auth.record_sync_health(self.raw, "acc2", OTHER_SESSION, None, 1000.0)
        self.at(1000.9)
        tools_auth.record_sync_health(self.raw, "acc1", SESSION_ID, exc, 1000.8)
        self.assertEqual(self.health("acc1")["fail"]["last"],
                         self.health("acc2")["ok_at"])        # same second
        self.assertIsNone(tools_auth.refusal_hint(
            self.raw, "acc1", {"aspsp_name": "Rabobank", "session_id": SESSION_ID}))

    def test_an_identical_instant_is_not_evidence_either(self):
        self.two_banks()
        exc = eb_ais.ApiError(401, "transactions")
        self.at(1000.5)
        tools_auth.record_sync_health(self.raw, "acc1", SESSION_ID, exc, 1000.0)
        tools_auth.record_sync_health(self.raw, "acc2", OTHER_SESSION, None, 1000.0)
        self.assertIsNone(tools_auth.refusal_hint(
            self.raw, "acc1", {"aspsp_name": "Rabobank", "session_id": SESSION_ID}))

    def test_a_later_success_in_the_same_second_is(self):
        self.two_banks()
        exc = eb_ais.ApiError(401, "transactions")
        self.at(1000.1)
        tools_auth.record_sync_health(self.raw, "acc1", SESSION_ID, exc, 1000.0)
        self.at(1000.9)
        tools_auth.record_sync_health(self.raw, "acc2", OTHER_SESSION, None, 1000.8)
        self.assertIn("(ING)", tools_auth.refusal_hint(
            self.raw, "acc1", {"aspsp_name": "Rabobank", "session_id": SESSION_ID}))


class TestSyncHealthAndTheErasers(FailureBase):
    def failing(self):
        self.two_banks()
        self.refuse("acc1")
        self.sync_tx()
        self.assertIsNotNone(self.health("acc1"))

    def test_forget_local_account_deletes_it(self):
        self.failing()
        call("forget_local_account", account_id="acc1")
        self.assertIsNone(self.health("acc1"))
        self.assertIsNotNone(self.health("acc2"))

    def test_delete_all_data_deletes_it(self):
        self.failing()
        call("delete_all_data")
        self.assertEqual(self.raw.execute(
            "SELECT COUNT(*) FROM meta WHERE key LIKE 'sync_health|%'"
        ).fetchone()[0], 0)

    def test_the_data_only_eraser_keeps_it_with_the_binding(self):
        self.failing()
        call("delete_data_keep_signins")
        self.assertEqual(self.health("acc1")["fail"]["label"], HTTP_401)
        self.assertIn("SYNC FAILING", call("consent_status"))


# ---------------------------------------------------------------- issue #84

class TestRevokeFailureCarriesItsStatus(FailureBase):
    def test_unlink_names_the_status_and_consent_status_keeps_it(self):
        self.session()
        self.ais.raise_on_delete = eb_ais.ApiError(401, "delete_session")
        out = call("unlink_bank", consent_ref=self.ref())
        self.assertIn("NOT revoked (%s)" % HTTP_401, out)
        self.assertIn("withdrawn_at_bank=true", out)
        self.assertEqual(self.revoke_key()[0], HTTP_401)
        status = call("consent_status")
        self.assertIn("status REVOKE_FAILED", status)
        self.assertIn("(last answer: %s)" % HTTP_401, status)
        self.assertIn("unlink_bank consent_ref=%s withdrawn_at_bank=true"
                      % self.ref(), status)

    def test_the_renewal_revoke_keeps_its_status(self):
        self.session()
        ok, label = flows._revoke(self.raw, _Refusing(401), SESSION_ID)
        self.assertFalse(ok)
        self.assertEqual(label, HTTP_401)
        self.assertEqual(self.revoke_key()[0], HTTP_401)
        self.assertEqual(self.session_row()["status"], apply.REVOKE_FAILED_STATUS)

    def test_a_confirmed_revocation_drops_the_note(self):
        self.session()
        self.ais.raise_on_delete = eb_ais.ApiError(500, "delete_session")
        call("unlink_bank", consent_ref=self.ref())
        self.assertIsNotNone(self.revoke_key())
        self.ais.raise_on_delete = None
        call("unlink_bank", consent_ref=self.ref())
        self.assertIsNone(self.revoke_key())
        self.assertEqual(self.session_row()["status"], "CLOSED")

    def test_delete_all_data_names_the_status_and_leaves_no_note(self):
        # meta is emptied BEFORE the withdrawal, so a note written by the
        # withdrawal would outlive the erasure.
        self.session()
        self.account()
        self.ais.raise_on_delete = eb_ais.ApiError(401, "delete_session")
        out = call("delete_all_data")
        self.assertIn(HTTP_401, out)
        self.assertIn("withdrawn_at_bank=true", out)
        self.assertEqual(self.raw.execute(
            "SELECT COUNT(*) FROM meta WHERE key LIKE 'revoke_failure|%'"
        ).fetchone()[0], 0)
        self.assertEqual(self.session_row()["status"],
                         apply.REVOKE_FAILED_STATUS)


class _Refusing:
    def __init__(self, status):
        self.status = status

    def delete_session(self, sid):
        raise eb_ais.ApiError(self.status, "delete_session")


class TestOperatorSettlement(FailureBase):
    def failed_once(self, status=401):
        self.session()
        self.account()
        self.ais.raise_on_delete = eb_ais.ApiError(status, "delete_session")
        call("unlink_bank", consent_ref=self.ref())
        self.assertEqual(self.session_row()["status"],
                         apply.REVOKE_FAILED_STATUS)

    def bindings(self):
        return [tuple(r) for r in self.raw.execute(
            "SELECT account_id, session_id, uid FROM accounts")]

    def test_the_flag_settles_a_consent_whose_withdrawal_already_failed(self):
        self.failed_once()
        out = call("unlink_bank", consent_ref=self.ref(),
                   withdrawn_at_bank=True)
        self.assertIn("WITHDRAWN BY YOU, not confirmed by the provider", out)
        self.assertIn(HTTP_401, out)
        row = self.session_row()
        self.assertEqual(row["status"], apply.OPERATOR_WITHDRAWN_STATUS)
        self.assertIsNotNone(row["closed_at"])
        self.assertEqual(self.bindings(), [("acc1", None, None)])
        self.assertIsNone(self.revoke_key())
        self.assertNotIn("REVOKE_FAILED", call("consent_status"))
        # The provider was still asked first, both times.
        self.assertEqual(self.ais.delete_calls, 2)

    def test_the_flag_on_a_first_attempt_is_not_applied(self):
        self.session()
        self.account()
        self.ais.raise_on_delete = eb_ais.ApiError(401, "delete_session")
        out = call("unlink_bank", consent_ref=self.ref(),
                   withdrawn_at_bank=True)
        self.assertIn("withdrawn_at_bank was NOT applied", out)
        row = self.session_row()
        self.assertEqual(row["status"], apply.REVOKE_FAILED_STATUS)
        self.assertIsNone(row["closed_at"])
        self.assertEqual(self.bindings(), [("acc1", SESSION_ID, "uid-acc1")])

    def test_without_the_flag_a_repeat_failure_settles_nothing(self):
        self.failed_once()
        call("unlink_bank", consent_ref=self.ref())
        self.assertIsNone(self.session_row()["closed_at"])

    def test_a_provider_confirmation_wins_over_the_flag(self):
        self.failed_once()
        self.ais.raise_on_delete = None
        out = call("unlink_bank", consent_ref=self.ref(),
                   withdrawn_at_bank=True)
        self.assertIn("revoked at the provider", out)
        self.assertEqual(self.session_row()["status"], "CLOSED")

    def test_a_non_boolean_flag_is_refused_before_any_call(self):
        self.failed_once()
        for value in ("true", 1, "yes"):
            with self.subTest(value=value):
                calls = self.ais.delete_calls
                out = call("unlink_bank", consent_ref=self.ref(),
                           withdrawn_at_bank=value)
                self.assertIn("must be true or false", out)
                self.assertEqual(self.ais.delete_calls, calls)
                self.assertIsNone(self.session_row()["closed_at"])

    def test_later_replies_never_call_it_provider_confirmed(self):
        self.failed_once()
        call("unlink_bank", consent_ref=self.ref(), withdrawn_at_bank=True)
        out = call("unlink_bank", consent_ref=self.ref())
        self.assertIn("you recorded that you withdrew it", out)
        self.assertIn("never confirmed", out)
        self.assertNotIn("the provider confirmed it", out)
        self.assertEqual(callbacks.left_behind(self.raw, SESSION_ID),
                         "withdrawn_by_operator")
        # Every renderer of `left_behind` knows the new value.
        detail = callbacks._indeterminate_detail(
            {"aspsp_name": "Rabobank"}, "a cause", "withdrawn_by_operator")
        self.assertIn("recorded as withdrawn at the bank by you", detail)

    def test_a_failure_recorded_while_the_flagged_call_waits_does_not_qualify_it(self):
        # A flagged call starts on a consent whose withdrawal has never
        # failed; while it waits on the provider, an unflagged call alongside
        # records REVOKE_FAILED; then the flagged call's own attempt fails too.
        # The flag was given before any failure, so nothing may close.
        self.session()
        self.account()
        raw = self.raw

        class Overlapping(FakeAIS):
            overlapped = 0

            def delete_session(self, sid):
                apply.record_revocation(raw, sid, revoked=False,
                                        failure=HTTP_401)
                Overlapping.overlapped += 1
                raise eb_ais.ApiError(401, "delete_session")
        self.ais_factory(Overlapping())
        out = call("unlink_bank", consent_ref=self.ref(),
                   withdrawn_at_bank=True)
        # The interleaving really happened, and this call's own attempt was
        # the provider's 401 — not some earlier failure of the double.
        self.assertEqual(Overlapping.overlapped, 1)
        self.assertIn("NOT revoked (%s)" % HTTP_401, out)
        self.assertIn("withdrawn_at_bank was NOT applied", out)
        row = self.session_row()
        self.assertIsNone(row["closed_at"])
        self.assertEqual(row["status"], apply.REVOKE_FAILED_STATUS)
        self.assertEqual(self.bindings(), [("acc1", SESSION_ID, "uid-acc1")])

    def test_a_close_by_another_call_meanwhile_is_reported_as_closed(self):
        # While this call waits on the provider, another unlink gets the
        # provider's confirmation and closes the row. This call's own attempt
        # then fails — and must not call the consent "NOT revoked".
        self.failed_once()
        raw = self.raw

        class ClosedMeanwhile(FakeAIS):
            def delete_session(self, sid):
                apply.record_revocation(raw, sid, revoked=True)
                raise eb_ais.ApiError(500, "delete_session")
        self.ais_factory(ClosedMeanwhile())
        out = call("unlink_bank", consent_ref=self.ref(),
                   withdrawn_at_bank=True)
        self.assertIn("already been withdrawn and the provider confirmed it", out)
        self.assertNotIn("NOT revoked", out)
        self.assertNotIn("STILL LIVE", out)
        self.assertEqual(self.session_row()["status"], "CLOSED")
        self.assertIsNone(self.revoke_key())

    def test_a_provider_confirmation_after_a_settlement_upgrades_it(self):
        # Another call settles on the operator's word while this one waits;
        # then the provider confirms this call's DELETE. The stronger
        # provenance wins, and the original close time stays.
        self.failed_once()
        raw = self.raw

        class SettledMeanwhile(FakeAIS):
            def delete_session(self, sid):
                assert apply.record_revocation(raw, sid, revoked=False,
                                               operator_withdrawn=True)
                return {"deleted": True}
        self.ais_factory(SettledMeanwhile())
        call("unlink_bank", consent_ref=self.ref())
        settled_at = self.session_row()["closed_at"]
        self.assertEqual(self.session_row()["status"], "CLOSED")
        self.assertEqual(self.session_row()["closed_at"], settled_at)
        out = call("unlink_bank", consent_ref=self.ref())
        self.assertIn("the provider confirmed it", out)
        self.assertEqual(callbacks.left_behind(self.raw, SESSION_ID), "closed")

    def test_the_history_count_survives_a_concurrent_release(self):
        # A settlement alongside releases the bindings while this call waits;
        # this call's success reply still counts the history that survives.
        self.failed_once()
        self.tx("acc1")
        raw = self.raw

        class SettledMeanwhile(FakeAIS):
            def delete_session(self, sid):
                apply.record_revocation(raw, sid, revoked=False,
                                        operator_withdrawn=True)
                raw.execute("UPDATE accounts SET session_id=NULL, uid=NULL"
                            " WHERE session_id=?", (sid,))
                return {"deleted": True}
        self.ais_factory(SettledMeanwhile())
        out = call("unlink_bank", consent_ref=self.ref())
        self.assertIn("1 transaction of local history survives", out)

    def test_a_binding_added_meanwhile_is_counted_too(self):
        # A collection alongside binds another account while this call waits.
        self.session()
        self.account("acc1")
        self.tx("acc1", ik="a")
        test = self

        class BoundMeanwhile(FakeAIS):
            def delete_session(self, sid):
                test.account("acc2")
                test.tx("acc2", ik="b")
                return {"deleted": True}
        self.ais_factory(BoundMeanwhile())
        out = call("unlink_bank", consent_ref=self.ref())
        self.assertIn("2 transactions of local history survive", out)
        self.assertEqual(self.bindings(),
                         [("acc1", None, None), ("acc2", None, None)])

    def test_a_row_erased_meanwhile_is_not_called_listed_or_live(self):
        self.failed_once()
        raw = self.raw

        class ErasedMeanwhile(FakeAIS):
            def delete_session(self, sid):
                # What delete_all_data leaves: meta emptied, the row gone.
                raw.execute("DELETE FROM meta WHERE key=?",
                            (apply.revoke_failure_key(sid),))
                raw.execute("DELETE FROM sessions WHERE session_id=?", (sid,))
                raise eb_ais.ApiError(500, "delete_session")
        self.ais_factory(ErasedMeanwhile())
        out = call("unlink_bank", consent_ref=self.ref(),
                   withdrawn_at_bank=True)
        self.assertIn("removed by another call", out)
        self.assertIn("ApiError: HTTP 500 provider_error", out)
        self.assertNotIn("STILL LIVE", out)
        self.assertNotIn("lists it", out)
        self.assertIsNone(self.revoke_key())

    def test_a_confirmation_keeps_the_first_close_time(self):
        self.failed_once()
        call("unlink_bank", consent_ref=self.ref(), withdrawn_at_bank=True)
        first = self.session_row()["closed_at"]
        self.raw.execute("UPDATE sessions SET closed_at='2000-01-01T00:00:00Z'")
        self.assertTrue(apply.record_revocation(self.raw, SESSION_ID,
                                                revoked=True))
        row = self.session_row()
        self.assertEqual(row["status"], "CLOSED")
        self.assertEqual(row["closed_at"], "2000-01-01T00:00:00Z")
        self.assertIsNotNone(first)

    def ais_factory(self, ais):
        self.addCleanup(setattr, tools_auth, "AIS_FACTORY", tools_auth.AIS_FACTORY)
        tools_auth.AIS_FACTORY = lambda: ais

    def test_apply_refuses_to_settle_a_row_that_never_failed(self):
        self.session()
        self.assertFalse(apply.record_revocation(
            self.raw, SESSION_ID, revoked=False, operator_withdrawn=True))
        self.assertIsNone(self.session_row()["closed_at"])

    def test_the_erasure_then_completes(self):
        self.failed_once()
        call("unlink_bank", consent_ref=self.ref(), withdrawn_at_bank=True)
        out = call("delete_all_data")
        self.assertEqual(self.raw.execute(
            "SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        self.assertNotIn("could not be withdrawn", out)


if __name__ == "__main__":
    unittest.main()
