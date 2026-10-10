# tests/test_cancelled_pending.py
"""Issue #99: a pending payment the bank stops listing, or reports CNCL/RJCT,
is kept and marked cancelled — never left pending for ever, never deleted.

Pure `ingest.reconcile` cases first, then the same sequences end to end
through `flows.backfill` -> `apply.apply_plan` on a real ledger, counting
the active rows and their money rather than reading statuses.
"""
import datetime as dt
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))   # _toolbase

import apply            # noqa: E402
import flows            # noqa: E402
import ingest           # noqa: E402
import store            # noqa: E402
import tools_annotate   # noqa: E402,F401  (registers add_note)
import tools_read       # noqa: E402
import tools_refresh    # noqa: E402

from _toolbase import Base as _ToolBase, call   # noqa: E402

# The interval flows.backfill really passes: degenerate, so rule 3 never fires.
IV = ("2026-10-11", "2026-10-11")
WINDOW_FROM = "2026-09-20"
UNSTABLE = {"ref_stable": False, "ref_scope": "unknown", "observed_n": 0}
STABLE = {"ref_stable": True, "ref_scope": "account", "observed_n": 500}


def row(date, amount=1234, cp="Voorbeeld Cafe", rem="card", ref=None, rid=None,
        status="PDNG", state="active", occurrence=0, state_reason=None):
    r = {"row_id": rid, "account_id": "acc1", "booking_date": date,
         "value_date": date, "amount_minor": amount, "currency": "EUR",
         "direction": "DBIT", "counterparty": cp, "remittance": rem,
         "provider_ref": ref, "status": status}
    if rid is not None:
        r.update(state=state, occurrence=occurrence, state_reason=state_reason)
    return r


def cancels(plan):
    return [(t["row_id"], t["reason"]) for t in plan.tombstones
            if t["state"] == "cancelled"]


class TestInferredCancellation(unittest.TestCase):
    def test_a_pending_row_absent_from_the_fetch_is_cancelled(self):
        pend = row("2026-09-30", rid=7)
        other = row("2026-10-09", amount=500, cp="Shop", status="BOOK")
        plan = ingest.reconcile([pend], [other], IV, UNSTABLE,
                                window_from=WINDOW_FROM)
        self.assertEqual(cancels(plan), [(7, "pending_absent_from_fetch")])
        self.assertEqual(len(plan.inserts), 1)

    def test_an_empty_complete_fetch_also_cancels(self):
        pend = row("2026-09-30", rid=7, status="HOLD")
        plan = ingest.reconcile([pend], [], IV, UNSTABLE, window_from=WINDOW_FROM)
        self.assertEqual(cancels(plan), [(7, "pending_absent_from_fetch")])

    def test_a_booked_row_absent_from_the_fetch_is_untouched(self):
        booked = row("2026-09-30", rid=7, status="BOOK")
        plan = ingest.reconcile([booked], [], IV, UNSTABLE, window_from=WINDOW_FROM)
        self.assertEqual(plan.tombstones, [])
        self.assertEqual(plan.flags, [])

    def test_a_pending_row_near_the_window_start_is_not_cancelled(self):
        # Within MATCH_WINDOW_DAYS of the requested start: not well inside it.
        pend = row("2026-09-26", rid=7)
        plan = ingest.reconcile([pend], [], IV, UNSTABLE, window_from=WINDOW_FROM)
        self.assertEqual(plan.tombstones, [])
        pend = row("2026-09-27", rid=7)
        plan = ingest.reconcile([pend], [], IV, UNSTABLE, window_from=WINDOW_FROM)
        self.assertEqual(cancels(plan), [(7, "pending_absent_from_fetch")])

    def test_no_window_means_no_cancellation(self):
        pend = row("2026-09-30", rid=7)
        plan = ingest.reconcile([pend], [], IV, UNSTABLE)
        self.assertEqual(plan.tombstones, [])

    def test_a_pending_row_that_booked_supersedes_and_is_not_cancelled(self):
        pend = row("2026-09-30", rid=7, ref="REF-PEND")
        booked = row("2026-10-02", ref="B9", status="BOOK")   # new reference
        for cap in (UNSTABLE, STABLE):
            plan = ingest.reconcile([pend], [booked], IV, cap,
                                    window_from=WINDOW_FROM)
            self.assertEqual(plan.tombstones, [])
            self.assertEqual([u["op"] for u in plan.updates], ["supersede"])

    def test_a_pending_row_matched_with_a_corrected_amount_is_not_cancelled(self):
        # Rule 1 carries the correction under a trusted reference; the row's
        # old content is no longer in the page, but it was matched.
        pend = row("2026-09-30", rid=7, ref="REF-PEND")
        plan = ingest.reconcile([pend], [row("2026-09-30", amount=1300,
                                             ref="REF-PEND")],
                                IV, STABLE, window_from=WINDOW_FROM)
        self.assertEqual(plan.tombstones, [])
        self.assertEqual([u["row_id"] for u in plan.updates], [7])

    def test_a_still_listed_pending_row_is_not_cancelled(self):
        pend = row("2026-09-30", rid=7, ref="REF-PEND")
        again = row("2026-09-30", ref="REF-PEND")
        plan = ingest.reconcile([pend], [again], IV, STABLE,
                                window_from=WINDOW_FROM)
        self.assertEqual(plan.tombstones, [])

    def test_a_pending_row_whose_content_is_in_the_page_is_not_cancelled(self):
        # Two identical pending payments; the bank lists one copy. Rule 2
        # pairs one, and the other's content is in the page: spared.
        a = row("2026-09-30", rid=7)
        b = row("2026-10-01", rid=8, occurrence=1)
        plan = ingest.reconcile([a, b], [row("2026-09-30")], IV, UNSTABLE,
                                window_from=WINDOW_FROM)
        self.assertEqual(cancels(plan), [])


class TestExplicitCancellation(unittest.TestCase):
    def test_a_cncl_restatement_cancels_the_pending_row(self):
        pend = row("2026-09-30", rid=7, ref="REF-PEND")
        cncl = row("2026-09-30", ref="REF-PEND", status="CNCL")
        for cap in (UNSTABLE, STABLE):
            plan = ingest.reconcile([pend], [cncl], IV, cap,
                                    window_from=WINDOW_FROM)
            self.assertEqual(cancels(plan), [(7, "cancelled_by_bank")])
            self.assertEqual(plan.inserts, [])

    def test_a_cncl_record_is_never_a_payment_of_its_own(self):
        plan = ingest.reconcile([], [row("2026-09-30", status="CNCL"),
                                     row("2026-09-30", status="RJCT")], IV,
                                UNSTABLE, window_from=WINDOW_FROM)
        self.assertEqual((plan.inserts, plan.updates, plan.tombstones),
                         ([], [], []))

    def test_a_still_listed_pending_record_wins_over_a_cncl(self):
        # The bank still lists the payment as pending: it is still pending.
        pend = row("2026-09-30", rid=7, ref="REF-PEND")
        for cap in (UNSTABLE, STABLE):
            plan = ingest.reconcile(
                [pend], [row("2026-09-30", ref="REF-PEND"),
                         row("2026-09-30", ref="REF-PEND", status="CNCL")],
                IV, cap, window_from=WINDOW_FROM)
            self.assertEqual(plan.tombstones, [])
            self.assertEqual(plan.inserts, [])

    def test_a_replayed_cncl_is_consumed_not_inserted_again(self):
        done = row("2026-09-30", rid=7, status="CNCL", state="cancelled",
                   state_reason="cancelled_by_bank")
        plan = ingest.reconcile([done], [row("2026-09-30", status="CNCL")], IV,
                                UNSTABLE, window_from=WINDOW_FROM)
        self.assertEqual((plan.inserts, plan.updates, plan.tombstones),
                         ([], [], []))

    def test_a_replayed_cncl_below_the_window_is_consumed(self):
        done = row("2026-09-10", rid=7, status="CNCL", state="cancelled",
                   state_reason="cancelled_by_bank")
        plan = ingest.reconcile([], [row("2026-09-10", status="CNCL")], IV,
                                UNSTABLE, below=[done], window_from=WINDOW_FROM)
        self.assertEqual((plan.inserts, plan.updates, plan.tombstones),
                         ([], [], []))

    def test_a_replayed_cncl_does_not_cancel_a_different_live_payment(self):
        # The old payment's CNCL keeps being listed; a different payment with
        # identical content (another reference) is live and pending.
        done = row("2026-09-26", rid=7, ref="OLD", status="CNCL",
                   state="cancelled", state_reason="cancelled_by_bank")
        live = row("2026-09-30", rid=8, ref="LIVE", occurrence=1)
        plan = ingest.reconcile([done, live],
                                [row("2026-09-26", ref="OLD", status="CNCL"),
                                 row("2026-09-30", ref="LIVE")],
                                IV, UNSTABLE, window_from=WINDOW_FROM)
        self.assertEqual(cancels(plan), [])
        self.assertEqual(plan.inserts, [])

    def test_a_cncl_cancels_the_relisted_live_row_before_any_replay(self):
        # PDNG was inferred-cancelled, then re-listed (a new active row), and
        # the bank now says CNCL for that exact booking.
        old = row("2026-09-30", rid=7, ref="REF-PEND", state="cancelled",
                  state_reason="pending_absent_from_fetch")
        relisted = row("2026-09-30", rid=8, ref="REF-PEND", occurrence=1)
        for cap in (UNSTABLE, STABLE):
            plan = ingest.reconcile([old, relisted],
                                    [row("2026-09-30", ref="REF-PEND", status="CNCL")],
                                    IV, cap, window_from=WINDOW_FROM)
            self.assertEqual(cancels(plan), [(8, "cancelled_by_bank")])
            self.assertEqual(plan.inserts, [])

    def test_a_row_its_booking_superseded_is_not_also_cancelled(self):
        pend = row("2026-09-30", rid=8, ref="REF-PEND")
        plan = ingest.reconcile(
            [pend], [row("2026-09-30", ref="REF-PEND", status="CNCL"),
                     row("2026-10-01", amount=999, ref="REF-PEND", status="BOOK")],
            IV, STABLE, window_from=WINDOW_FROM)
        self.assertEqual(cancels(plan), [])
        self.assertEqual([u["row_id"] for u in plan.updates
                          if u["op"] == "supersede"], [8])

    def test_a_booked_row_restated_cncl_is_not_cancelled(self):
        booked = row("2026-09-30", rid=7, ref="REF-PEND", status="BOOK")
        plan = ingest.reconcile([booked],
                                [row("2026-09-30", ref="REF-PEND", status="CNCL")],
                                IV, STABLE, window_from=WINDOW_FROM)
        self.assertEqual(cancels(plan), [])


TODAY = dt.date(2026, 10, 10)


def raw(date, amount="12.34", ref=None, status="PDNG", name="Voorbeeld Cafe"):
    return {"booking_date": date, "value_date": date,
            "transaction_amount": {"currency": "EUR", "amount": amount},
            "credit_debit_indicator": "DBIT", "status": status,
            "creditor": {"name": name}, "remittance_information": ["card"],
            "entry_reference": ref}


class OnePage:
    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def transactions(self, uid, date_from, continuation_key=None):
        self.calls.append(date_from)
        return [r for r in self.rows if r["booking_date"] >= date_from], None


class WholeHistory(OnePage):
    """A bank that ignores date_from (issue #59)."""

    def transactions(self, uid, date_from, continuation_key=None):
        self.calls.append(date_from)
        return list(self.rows), None


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.open_db(pathlib.Path(self.tmp.name) / "f.sqlite")
        self._today = flows._today
        flows._today = lambda: TODAY
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency, aspsp)"
            " VALUES ('acc1','uid-1','s1','EUR','Revolut')")

    def tearDown(self):
        flows._today = self._today
        self.tmp.cleanup()

    def sync(self, rows, floor_days=30):
        return flows.backfill(OnePage(rows), self.conn,
                              {"account_id": "acc1", "uid": "uid-1"}, "s1",
                              floor_days=floor_days, incarnation="")

    def active(self):
        r = self.conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(amount_minor),0) FROM transactions"
            " WHERE state='active'").fetchone()
        return tuple(r)

    def states(self):
        return [tuple(r) for r in self.conn.execute(
            "SELECT state, state_reason, status FROM transactions"
            " ORDER BY row_id")]

    def test_the_issue_sequence(self):
        shop = raw("2026-10-08", amount="5.00", ref="B1", status="BOOK", name="Shop")
        self.sync([raw("2026-09-26", ref="REF-PEND"), shop])
        self.assertEqual(self.active(), (2, 1734))
        out = self.sync([shop])
        self.assertEqual(out["cancelled"], 1)
        self.assertEqual(self.active(), (1, 500))
        self.assertIn(("cancelled", "pending_absent_from_fetch", "PDNG"),
                      self.states())
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM transactions").fetchone()[0], 2)   # kept
        self.sync([shop])                                          # stable
        self.assertEqual(self.active(), (1, 500))
        self.assertEqual(len(self.states()), 2)

    def test_a_transient_omission_heals_when_the_bank_lists_it_again(self):
        p = raw("2026-09-26", ref="REF-PEND")
        self.sync([p])
        self.sync([])
        self.assertEqual(self.active(), (0, 0))
        self.sync([p])
        self.assertEqual(self.active(), (1, 1234))
        self.sync([raw("2026-09-28", ref="REF-PEND", status="BOOK")])
        self.assertEqual(self.active(), (1, 1234))

    def test_an_explicit_cncl_cancels_once_and_replays_change_nothing(self):
        self.sync([raw("2026-09-26", ref="REF-PEND")])
        self.sync([raw("2026-09-26", ref="REF-PEND", status="CNCL")])
        self.assertEqual(self.active(), (0, 0))
        self.assertEqual(self.states(),
                         [("cancelled", "cancelled_by_bank", "PDNG")])
        for _ in range(2):
            self.sync([raw("2026-09-26", ref="REF-PEND", status="CNCL")])
        self.assertEqual(self.states(),
                         [("cancelled", "cancelled_by_bank", "PDNG")])

    def test_identical_twins_never_lose_the_listed_one(self):
        # Two pending payments with identical content, one cancelled. Content
        # cannot tell them apart (references count only under earned trust),
        # so the module's doctrine holds: the payment the bank still lists is
        # never lost, and an extra row is kept and flagged for review.
        for refs in (("REF-A", "REF-B"), (None, None)):
            self.setUp()
            a = raw("2026-09-26", ref=refs[0])
            b = raw("2026-09-26", ref=refs[1])
            self.sync([a, b])
            for status in ("CNCL", "RJCT"):
                self.sync([raw("2026-09-26", ref=refs[0], status=status), b])
                count, _ = self.active()
                self.assertGreaterEqual(count, 1)
                if count == 2:
                    flagged = self.conn.execute(
                        "SELECT review_reason FROM transactions WHERE"
                        " state='active' AND needs_review=1").fetchall()
                    self.assertEqual([r[0] for r in flagged],
                                     ["content_present_elsewhere"])
            self.tearDown()
        self.setUp()

    def test_a_legacy_active_cncl_row_is_cancelled(self):
        # An older release wrote a pending row's CNCL restatement in place
        # and left it active.
        self.sync([raw("2026-09-26", ref="REF-PEND")])
        self.conn.execute("UPDATE transactions SET status='CNCL'")
        self.assertEqual(self.active(), (1, 1234))
        for _ in range(2):
            self.sync([raw("2026-09-26", ref="REF-PEND", status="CNCL")])
        self.assertEqual(self.states(),
                         [("cancelled", "cancelled_by_bank", "CNCL")])

    def test_a_cncl_with_no_pending_row_stores_nothing(self):
        for _ in range(3):
            self.sync([raw("2026-09-26", ref="REF-CNCL", status="CNCL")])
        self.assertEqual(self.states(), [])

    def test_a_bank_listing_both_records_keeps_it_pending_and_stays_put(self):
        p = raw("2026-09-26", ref="REF-PEND")
        c = raw("2026-09-26", ref="REF-PEND", status="CNCL")
        self.sync([p])
        for _ in range(4):
            self.sync([p, c])
        self.assertEqual(self.states(), [("active", None, "PDNG")])

    def test_a_cncl_for_a_relisted_payment_under_another_date_cancels_it(self):
        shop = raw("2026-10-08", amount="5.00", ref="B1", status="BOOK", name="Shop")
        self.sync([raw("2026-09-20", ref="REF-PEND"), shop])
        self.sync([shop])                                  # inferred cancel
        self.sync([raw("2026-09-21", ref="REF-PEND"), shop])   # re-listed, re-dated
        self.assertEqual(self.active(), (2, 1734))
        for status in ("CNCL", "RJCT"):
            self.sync([raw("2026-09-20", ref="REF-PEND", status=status), shop])
            self.assertEqual(self.active(), (1, 500))
        self.assertEqual(len(self.states()), 3)            # nothing inserted

    def test_a_payment_cancelled_relisted_and_cancelled_again(self):
        # The second CNCL is for the re-listed live row, not a replay of the
        # first cancellation, though both carry the same exact booking.
        p = raw("2026-09-26", ref="REF-PEND")
        c = raw("2026-09-26", ref="REF-PEND", status="CNCL")
        self.sync([p])
        self.sync([c])
        self.sync([p])
        self.assertEqual(self.active(), (1, 1234))
        self.sync([c])
        self.sync([c])
        self.assertEqual(self.active(), (0, 0))
        self.assertEqual(len(self.states()), 2)

    def test_a_cncl_after_an_inferred_cancel_is_stored_once(self):
        self.sync([raw("2026-09-26", ref="REF-PEND")])
        self.sync([])
        for _ in range(3):
            self.sync([raw("2026-09-26", ref="REF-PEND", status="CNCL")])
        self.assertEqual(self.active(), (0, 0))
        self.assertEqual(self.states(),
                         [("cancelled", "pending_absent_from_fetch", "PDNG")])

    def test_a_cncl_replayed_from_before_the_window_is_not_inserted_again(self):
        cncl = raw("2026-09-26", ref="REF-CNCL", status="CNCL")
        self.sync([raw("2026-09-26", ref="REF-CNCL")])
        self.sync([cncl])
        for _ in range(2):
            flows.backfill(WholeHistory([cncl]), self.conn,
                           {"account_id": "acc1", "uid": "uid-1"}, "s1",
                           floor_days=3, incarnation="")
        self.assertEqual(self.states(),
                         [("cancelled", "cancelled_by_bank", "PDNG")])

    def test_cancelling_never_flips_a_row_another_run_superseded(self):
        self.sync([raw("2026-09-26", ref="REF-PEND")])
        rid = self.conn.execute("SELECT row_id FROM transactions").fetchone()[0]
        plan = ingest.Plan([], [], [{"row_id": rid, "state": "cancelled",
                                     "reason": "pending_absent_from_fetch"}], [])
        self.conn.execute("UPDATE transactions SET state='superseded'")
        stats = apply.apply_plan(self.conn, "acc1", plan)
        self.assertEqual(stats["cancelled"], 0)
        self.assertEqual(self.states()[0][0], "superseded")


class TestRefreshWindowReachesPending(_ToolBase):
    def use_recording_backfill(self):
        calls = []

        def recorder(ais, conn, account, session_id, **kw):
            calls.append(kw.get("floor_days"))
            return {"inserted": 0, "capped": False, "completeness": "complete",
                    "cancelled": 0}
        self.addCleanup(setattr, flows, "backfill", flows.backfill)
        flows.backfill = recorder
        return calls

    def put(self, days_ago, status="BOOK", state="active", reason=None, ik=None):
        date = (dt.date.today() - dt.timedelta(days=days_ago)).isoformat()
        self.raw.execute(
            "INSERT INTO transactions(account_id, identity_key, occurrence,"
            " booking_date, amount_minor, currency, direction, status, state,"
            " state_reason) VALUES ('acc1',?,0,?,100,'EUR','DBIT',?,?,?)",
            (ik or "ik-%d-%s" % (days_ago, status), date, status, state, reason))

    def window(self):
        return tools_refresh._refresh_window_days(self.raw, "acc1")

    def test_the_window_reaches_back_to_the_oldest_pending_row(self):
        self.account()
        self.put(2)
        self.assertEqual(self.window(), 9)
        self.put(20, status="PDNG")
        self.assertEqual(self.window(), 27)
        self.put(25, status=" hold ")
        self.assertEqual(self.window(), 32)

    def test_a_legacy_active_cncl_row_anchors_the_window(self):
        self.account()
        self.put(2)
        self.put(20, status="CNCL")
        self.assertEqual(self.window(), 27)

    def test_an_inferred_cancelled_row_keeps_the_window_open(self):
        self.account()
        self.put(2)
        self.put(30, status="PDNG", state="cancelled",
                 reason="pending_absent_from_fetch")
        self.assertEqual(self.window(), 37)

    def test_an_explicit_cancellation_anchors_too(self):
        self.account()
        self.put(2)
        self.put(30, status="PDNG", state="cancelled", reason="cancelled_by_bank")
        self.assertEqual(self.window(), 37)

    def test_a_vanished_or_superseded_pending_row_does_not_anchor(self):
        self.account()
        self.put(2)
        self.put(30, status="PDNG", state="superseded")
        self.put(31, status="PDNG", state="vanished", ik="ik-v")
        self.assertEqual(self.window(), 9)

    def test_an_anchor_beyond_the_default_window_is_ignored(self):
        self.account()
        self.put(2)
        self.put(84, status="PDNG")
        self.assertEqual(self.window(), 9)
        self.put(83, status="PDNG")
        self.assertEqual(self.window(), tools_refresh.DEFAULT_WINDOW_DAYS)

    def test_a_malformed_pending_date_is_ignored(self):
        self.account()
        self.put(2)
        self.raw.execute(
            "INSERT INTO transactions(account_id, identity_key, occurrence,"
            " booking_date, amount_minor, currency, direction, status, state)"
            " VALUES ('acc1','bad',0,'0000-pending',100,'EUR','DBIT',"
            "'PDNG','active')")
        self.assertEqual(self.window(), 9)


class TestOperatorSees(_ToolBase):
    def test_get_transaction_says_cancelled(self):
        self.account()
        self.raw.execute(
            "INSERT INTO transactions(account_id, identity_key, occurrence,"
            " booking_date, amount_minor, currency, direction, status, state,"
            " state_reason) VALUES ('acc1','ik',0,'2026-09-26',1234,'EUR',"
            "'DBIT','PDNG','cancelled','pending_absent_from_fetch')")
        rid = self.raw.execute("SELECT row_id FROM transactions").fetchone()[0]
        out = call("get_transaction", row_id=rid)
        self.assertIn("STATE: cancelled", out)
        self.assertIn("not counted", out)

    def test_a_cancelled_payment_can_still_carry_a_note(self):
        self.account()
        self.raw.execute(
            "INSERT INTO transactions(account_id, identity_key, occurrence,"
            " booking_date, amount_minor, currency, direction, status, state,"
            " state_reason) VALUES ('acc1','ik',0,'2026-09-26',1234,'EUR',"
            "'DBIT','PDNG','cancelled','pending_absent_from_fetch')")
        rid = self.raw.execute("SELECT row_id FROM transactions").fetchone()[0]
        call("add_note", row_ids=[rid], note="merchant refunded", author="user")
        self.assertEqual(self.raw.execute(
            "SELECT COUNT(*) FROM transaction_notes WHERE row_id=?",
            (rid,)).fetchone()[0], 1)

    def test_sync_names_the_cancellations(self):
        self.account()

        def fake(ais, conn, account, session_id, **kw):
            conn.execute(
                "INSERT INTO sync_state(account_id, resource, last_attempt_at,"
                " last_success_at, completeness, last_success_session)"
                " VALUES (?, 'transactions', 'x', 'x', 'complete', ?)"
                " ON CONFLICT(account_id, resource) DO UPDATE SET"
                " completeness='complete',"
                " last_success_session=excluded.last_success_session",
                (account["account_id"], session_id))
            return {"inserted": 0, "capped": False, "completeness": "complete",
                    "cancelled": 2}
        self.addCleanup(setattr, flows, "backfill", flows.backfill)
        flows.backfill = fake
        out = call("sync", account="acc1", resource="transactions")
        self.assertIn("2 pending payment(s) the bank no longer lists", out)


if __name__ == "__main__":
    unittest.main()
