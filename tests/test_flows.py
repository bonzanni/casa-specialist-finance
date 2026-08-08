import datetime as dt
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"))
import apply            # noqa: E402
import eb_ais           # noqa: E402
import flows            # noqa: E402
import ingest           # noqa: E402
import provenance       # noqa: E402
import store            # noqa: E402

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
TODAY = dt.date(2026, 8, 3)
IBAN_R = "NL00REVO0000000001"
IBAN_R2 = "NL00REVO0000000005"
IBAN_A = "NL00ABNA0000000002"
def observe(conn, aspsp="Revolut", n=100):
    """Record a local observation of `aspsp`'s reference behaviour.

    Nothing is trusted until this installation observes it, so a test that
    needs the reference-as-identity path has to write the row itself. The
    figure is the test's own; no capability value ships.
    """
    provenance.set_capability(conn, aspsp, ref_stable=True,
                              ref_scope="account", observed_n=n,
                              provenance="observed locally by this test")


#: Deliberately WITHOUT an "aspsp" key: the bank name is read from the account
#: row, and a dict that carries it would hide a broken lookup.
ACCOUNT = {"account_id": "acc1", "uid": "uid-1"}

WL_REVOLUT = [{"aspsp": {"name": "Revolut", "country": "NL"},
               "title": f"IBAN {IBAN_R}", "identification_hash": "H1"}]


def wl(iban, aspsp="Revolut", country="NL"):
    return {"aspsp": {"name": aspsp, "country": country},
            "title": f"IBAN {iban}", "identification_hash": "H-" + iban[-4:]}


def acct(iban, uid="u1"):
    """Provider shape: the IBAN is NESTED under account_id."""
    return {"uid": uid, "identification_hash": "H-" + iban[-4:],
            "account_id": {"iban": iban},
            "all_account_ids": [{"identification": iban, "scheme_name": "IBAN"}],
            "currency": "EUR", "name": "N. Voorbeeld", "usage": "PRIV"}


def raw_tx(date, amount="12.34", ref=None, remittance="boodschappen"):
    return {"booking_date": date, "value_date": date,
            "transaction_amount": {"currency": "EUR", "amount": amount},
            "credit_debit_indicator": "DBIT", "status": "BOOK",
            "creditor": {"name": "Voorbeeld Supermarkt"},
            "remittance_information": [remittance],
            "entry_reference": ref}


class FakeAdmin:
    def __init__(self, sequence):
        self.sequence, self.calls = sequence, 0

    def whitelisted(self, app_id):
        out = self.sequence[min(self.calls, len(self.sequence) - 1)]
        self.calls += 1
        return out


class FakeAIS:
    """Pages exactly as eb_ais.AIS does: one page per call, plus the next key.

    `delete_session` is here because the real client has it and the renewal
    path really calls it: a double that cannot be asked to revoke
    could not tell us whether the old consent was ever closed at the bank.
    """

    def __init__(self, pages):
        self.pages, self.calls = pages, []
        self.deleted = []

    def transactions(self, uid, date_from, continuation_key=None):
        self.calls.append((uid, date_from, continuation_key))
        return self.pages[len(self.calls) - 1]

    def delete_session(self, sid):
        self.deleted.append(sid)
        return {"deleted": True}


class RefusingAIS(FakeAIS):
    """Answers every page, then refuses the revocation — a 429 or a dead
    socket on `DELETE /sessions/{id}`, which is the one call in a renewal that
    happens after everything else has already succeeded."""

    def delete_session(self, sid):
        self.deleted.append(sid)
        raise OSError("connection reset")


class GoneAIS(FakeAIS):
    """Answers every page, then 404s the revocation: the provider has already
    dropped this consent. It is the ONE failure that still proves the grant is
    gone, and `eb_ais.revocation_is_final` is the one place that says so."""

    def delete_session(self, sid):
        self.deleted.append(sid)
        raise eb_ais.ApiError(404, "delete_session")


class EndlessAIS:
    """Always hands back another continuation key — the pagination-cap case."""

    def __init__(self):
        self.calls = 0
        self.deleted = []

    def delete_session(self, sid):        # never reached: nothing is switched
        self.deleted.append(sid)
        return {"deleted": True}

    def transactions(self, uid, date_from, continuation_key=None):
        self.calls += 1
        return ([raw_tx("2026-07-01", ref=f"P{self.calls}",
                        remittance=f"page {self.calls}")],
                f"k{self.calls}")


class BrokenAIS:
    """Answers one page, then stops — a 429 or a reset socket mid-pagination."""

    def __init__(self):
        self.calls = 0
        self.deleted = []

    def transactions(self, uid, date_from, continuation_key=None):
        self.calls += 1
        if self.calls == 1:
            return ([raw_tx("2024-08-05", ref="R1")], "k1")
        raise OSError("connection reset")

    def delete_session(self, sid):        # never reached: nothing is switched
        self.deleted.append(sid)
        return {"deleted": True}


class TestWhitelist(unittest.TestCase):
    def test_detects_missing_bank(self):
        self.assertTrue(flows.needs_whitelist(FakeAdmin([WL_REVOLUT]), "a",
                                              "ABN AMRO", "NL"))

    def test_detects_present_bank(self):
        self.assertFalse(flows.needs_whitelist(FakeAdmin([WL_REVOLUT]), "a",
                                               "Revolut", "NL"))

    def test_the_module_never_waits_for_a_whitelist_entry(self):
        """A ten-minute blocking poll has no turn to run in: a specialist never
        waits, and nothing called it. The operator
        coming back and calling link_bank again IS the continuation."""
        self.assertFalse(hasattr(flows, "await_whitelist"))
        self.assertFalse(hasattr(flows, "POLL_INTERVAL_S"))
        self.assertNotIn("time", dir(flows))


class TestVerifyAccounts(unittest.TestCase):
    def test_the_iban_is_read_from_the_nested_account_id(self):
        """The single worst bug in the previous plan: reading a flat
        account["iban"] found nothing in production, so every successful link
        reported the zero-accounts failure."""
        session = json.loads((FIX / "session_revolut.json").read_text())
        accounts = session["accounts"]
        self.assertNotIn("iban", accounts[0])          # the shape, verified
        v = flows.verify_accounts(session_accounts=accounts,
                                  whitelisted=[wl(IBAN_R)], intended=[IBAN_R],
                                  aspsp="Revolut", country="NL")
        self.assertTrue(v.ok, v.message)
        self.assertIn(IBAN_R, v.message)

    def test_zero_accounts_reports_evidence_not_a_single_cause(self):
        v = flows.verify_accounts(session_accounts=[], whitelisted=[],
                                  intended=[IBAN_A],
                                  aspsp="ABN AMRO", country="NL")
        self.assertFalse(v.ok)
        self.assertIn("whitelist", v.message.lower())
        # must NOT claim the whitelist is definitely the cause
        self.assertIn("psu type", v.message.lower())

    def test_non_zero_but_incomplete_is_still_a_failure(self):
        """Per-account filtering can return one account and silently drop
        another, so "non-zero" does not establish success."""
        v = flows.verify_accounts(session_accounts=[acct(IBAN_R)],
                                  whitelisted=[wl(IBAN_R), wl(IBAN_A, "ABN AMRO")],
                                  intended=[IBAN_R, IBAN_A],
                                  aspsp="Revolut", country="NL")
        self.assertFalse(v.ok)
        self.assertIn(IBAN_A, v.message)

    def test_iban_is_parsed_from_the_whitelist_title(self):
        self.assertEqual(flows._iban_of({"title": f"IBAN {IBAN_R}"}), IBAN_R)
        self.assertEqual(flows._iban_of({"title": "no identifier here"}), "")

    def test_whitelist_derived_intent_is_scoped_to_the_bank_being_linked(self):
        """With no explicit list the intent is the whitelist — but only THIS
        bank's part of it. Two Revolut accounts are approved and the consent
        returns one, so the missing one is named; the ABN AMRO entry is
        another bank's business and is not."""
        v = flows.verify_accounts(
            session_accounts=[acct(IBAN_R)],
            whitelisted=[wl(IBAN_R), wl(IBAN_R2), wl(IBAN_A, "ABN AMRO")],
            intended=[], aspsp="Revolut", country="NL")
        self.assertFalse(v.ok)
        self.assertIn(IBAN_R2, v.message)
        self.assertNotIn(IBAN_A, v.message)

    def test_an_account_nobody_approved_is_also_a_failure(self):
        """The third case, and the one the old code missed entirely: a consent
        that returns MORE than was approved. Binding it would ingest an account
        the operator never agreed to expose."""
        v = flows.verify_accounts(
            session_accounts=[acct(IBAN_R), acct(IBAN_A, uid="u2")],
            whitelisted=[wl(IBAN_R)], intended=[IBAN_R],
            aspsp="Revolut", country="NL")
        self.assertFalse(v.ok)
        self.assertIn(IBAN_A, v.message)
        self.assertIn("unexpected", v.message.lower())

    def test_complete_match_passes(self):
        v = flows.verify_accounts(session_accounts=[acct(IBAN_R)],
                                  whitelisted=[wl(IBAN_R)], intended=[IBAN_R],
                                  aspsp="Revolut", country="NL")
        self.assertTrue(v.ok, v.message)


class TestVerificationIsBoundToTheAttempt(unittest.TestCase):
    """`whitelisted()` answers for the whole APPLICATION, so every
    entry ever approved is in every later answer. Verifying a consent against
    all of them reported the FIRST bank's IBANs as missing from the SECOND
    bank's session — and the second bank could never link. "One bank at a
    time" does not help: old entries persist."""

    def test_a_second_bank_links_with_the_first_banks_entries_still_present(self):
        # both banks are whitelisted, exactly as they are after bank A linked
        listed = [wl(IBAN_R), wl(IBAN_A, "ABN AMRO")]
        first = flows.verify_accounts(session_accounts=[acct(IBAN_R)],
                                      whitelisted=listed, intended=[],
                                      aspsp="Revolut", country="NL")
        self.assertTrue(first.ok, first.message)
        second = flows.verify_accounts(session_accounts=[acct(IBAN_A, uid="u2")],
                                       whitelisted=listed, intended=[],
                                       aspsp="ABN AMRO", country="NL")
        self.assertTrue(second.ok, second.message)
        self.assertIn(IBAN_A, second.message)
        self.assertNotIn(IBAN_R, second.message)

    def test_the_bank_being_linked_cannot_be_left_out_of_the_call(self):
        """Keyword-only and no defaults, deliberately: a caller that still
        passes the application-wide whitelist and nothing else must fail here,
        loudly, rather than silently verifying against every bank."""
        with self.assertRaises(TypeError):
            flows.verify_accounts([acct(IBAN_R)], [wl(IBAN_R)], [])


class TestBackfill(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.open_db(pathlib.Path(self.tmp.name) / "f.sqlite")
        self._real_today = flows._today
        flows._today = lambda: TODAY
        # The account row carries the bank name, and the capability row is
        # written here because nothing is trusted until observed locally.
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency, aspsp)"
            " VALUES ('acc1','uid-1','s1','EUR','Revolut')")
        observe(self.conn)

    def tearDown(self):
        flows._today = self._real_today
        self.tmp.cleanup()

    def _coverage(self):
        return [(r["interval_start"], r["interval_end"]) for r in self.conn.execute(
            "SELECT interval_start, interval_end FROM coverage ORDER BY interval_start")]

    def _sync(self):
        return self.conn.execute(
            "SELECT * FROM sync_state WHERE account_id='acc1'"
            " AND resource='transactions'").fetchone()

    def test_pages_to_exhaustion_and_records_the_interval_it_proved(self):
        ais = FakeAIS([([raw_tx("2024-08-05", ref="R1"),
                         raw_tx("2025-01-09", ref="R2", remittance="huur")], "k1"),
                       ([raw_tx("2026-08-01", ref="R3", remittance="energie")], None)])
        out = flows.backfill(ais, self.conn, ACCOUNT, "s1")
        self.assertEqual(out["pages"], 2)
        self.assertEqual(out["inserted"], 3)
        self.assertEqual(ais.calls[1][2], "k1")        # the key is handed back
        self.assertFalse(out["shallow"])
        # It records what it PROVED — the oldest row actually returned — never
        # the requested floor, which the bank may not have honoured at all.
        self.assertEqual((out["proved_from"], out["proved_to"]),
                         ("2024-08-05", "2026-08-04"))
        self.assertNotEqual(out["proved_from"], ais.calls[0][1])
        self.assertEqual(self._coverage(), [("2024-08-05", "2026-08-04")])
        self.assertEqual(self._sync()["completeness"], "complete")

    def test_date_from_sits_at_the_provider_floor(self):
        ais = FakeAIS([([], None)])
        flows.backfill(ais, self.conn, ACCOUNT, "s1")
        self.assertEqual(ais.calls[0][1], "2018-08-25")     # TODAY − 2900 days
        # 8 years back is rejected outright, so the floor keeps a margin.
        self.assertLess(flows.BACKFILL_FLOOR_DAYS, 8 * 365)

    def test_a_shallow_window_is_reported_as_shallow(self):
        """A handful of rows over a recent window is what a MISSED
        deep-history window looks like; it must never read as a quiet
        success."""
        ais = FakeAIS([([raw_tx("2026-05-05", ref="R1"),
                         raw_tx("2026-08-01", ref="R2", remittance="huur")], None)])
        out = flows.backfill(ais, self.conn, ACCOUNT, "s1")
        self.assertTrue(out["shallow"])
        self.assertEqual(out["proved_from"], "2026-05-05")
        self.assertEqual(self._coverage(), [("2026-05-05", "2026-08-04")])
        self.assertEqual(self._sync()["last_error"], flows.SHALLOW_NOTE)

    def test_the_page_cap_fails_loudly_and_proves_nothing(self):
        out = flows.backfill(EndlessAIS(), self.conn, ACCOUNT, "s1")
        self.assertEqual(out["pages"], flows.MAX_PAGES)
        self.assertIsNone(out["proved_from"])
        self.assertIsNone(out["proved_to"])
        self.assertTrue(out["shallow"])
        self.assertEqual(out["inserted"], 0)
        self.assertEqual(self._coverage(), [])          # nothing proven, nothing claimed
        row = self._sync()
        self.assertEqual(row["completeness"], "partial")
        self.assertIsNone(row["last_success_at"])       # no successful sync stamp
        self.assertEqual(row["last_error"], flows.CAPPED_NOTE)

    def test_the_capped_return_carries_both_completeness_signals(self):
        """The contract says every `backfill` return carries `capped` and
        `completeness`, and that a missing signal means incomplete — but the
        consumer defaults a missing `completeness` to "complete", so the one
        branch that omitted them was the branch where omitting them reads as
        success. The durable row masked it; a signal that survives only by
        accident is not a signal."""
        out = flows.backfill(EndlessAIS(), self.conn, ACCOUNT, "s1")
        self.assertIn("capped", out)
        self.assertIn("completeness", out)
        self.assertTrue(out["capped"])
        self.assertEqual(out["completeness"], "partial")
        # the returned pair and the durable row say the same thing
        self.assertEqual(out["completeness"], self._sync()["completeness"])

    def test_a_completed_run_carries_both_signals_affirmatively(self):
        """The other half of the same rule: "complete" must be stated, not
        inferred from an absence."""
        out = flows.backfill(FakeAIS([([raw_tx("2024-08-05", ref="R1")], None)]),
                             self.conn, ACCOUNT, "s1")
        self.assertIs(out["capped"], False)
        self.assertEqual(out["completeness"], "complete")
        self.assertEqual(out["completeness"], self._sync()["completeness"])

    def test_a_capped_run_never_tombstones_a_row_from_an_unconsumed_page(self):
        """The P0, stated as a test. Reconciliation tombstones every stored
        row it cannot match inside the requested interval, so running it on a
        partial page set marks rows that merely live on page 61 as `vanished`.
        Nothing destructive may run until pagination completes; calling the
        sync partial afterwards does not bring the row back."""
        self.conn.execute(
            "INSERT INTO transactions(account_id, identity_key, occurrence,"
            " booking_date, value_date, amount_minor, currency, direction,"
            " status, counterparty, remittance, state, match_method,"
            " first_seen, last_seen)"
            " VALUES ('acc1','k-page-61',0,'2025-03-04','2025-03-04',-1234,"
            "'EUR','DBIT','BOOK','Voorbeeld Supermarkt','huur','active',"
            "'inserted','2025-03-04','2025-03-04')")
        flows.backfill(EndlessAIS(), self.conn, ACCOUNT, "s1")
        row = self.conn.execute(
            "SELECT state, state_reason FROM transactions"
            " WHERE identity_key='k-page-61'").fetchone()
        self.assertEqual(row["state"], "active")
        self.assertIsNone(row["state_reason"])
        # and nothing from the 60 consumed pages was written either
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS c FROM transactions").fetchone()["c"], 1)

    def test_a_failed_page_fetch_proves_nothing_and_re_raises(self):
        """A 429 or a dropped socket is the same incomplete fetch as the cap.
        It re-raises so the caller cannot read a silent zero as an empty
        account."""
        with self.assertRaises(OSError):
            flows.backfill(BrokenAIS(), self.conn, ACCOUNT, "s1")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS c FROM transactions").fetchone()["c"], 0)
        self.assertEqual(self._coverage(), [])
        row = self._sync()
        self.assertEqual(row["completeness"], "partial")
        self.assertIsNone(row["last_success_at"])
        self.assertEqual(row["last_error"], flows.FAILED_NOTE)

    def test_an_incomplete_run_does_not_erase_an_earlier_success(self):
        """One bad page must not look like a total loss."""
        ais = FakeAIS([([raw_tx("2024-08-05", ref="R1")], None)])
        flows.backfill(ais, self.conn, ACCOUNT, "s1")
        good = self._sync()["last_success_at"]
        flows.backfill(EndlessAIS(), self.conn, ACCOUNT, "s1")
        row = self._sync()
        self.assertEqual(row["completeness"], "partial")
        self.assertEqual(row["last_success_at"], good)
        self.assertEqual(row["oldest_fetched"], "2024-08-05")

    def test_a_completed_run_stamps_which_session_did_the_fetching(self):
        """The durable fact a renewal switch stands on. It is written
        after apply_plan committed, and a capped run never writes it — which is
        what lets apply.switch_bindings check the ledger instead of trusting
        that its caller backfilled first."""
        flows.backfill(FakeAIS([([raw_tx("2024-08-05", ref="R1")], None)]),
                       self.conn, ACCOUNT, "s1")
        self.assertEqual(self._sync()["last_success_session"], "s1")
        flows.backfill(EndlessAIS(), self.conn, ACCOUNT, "s2")
        row = self._sync()
        self.assertEqual(row["completeness"], "partial")
        self.assertEqual(row["last_success_session"], "s1")   # NOT s2

    def test_the_capability_is_read_from_the_account_row(self):
        """Without this, nothing supplies the ASPSP, `capability()` is asked
        about "" for ever, and every production ingest falls back to
        heuristics."""
        seen = {}
        real = ingest.reconcile

        def spy(stored, fetched, interval, capability, **kw):
            seen["capability"] = capability
            return real(stored, fetched, interval, capability, **kw)

        ingest.reconcile = spy
        self.addCleanup(setattr, ingest, "reconcile", real)
        flows.backfill(FakeAIS([([raw_tx("2024-08-05", ref="R1")], None)]),
                       self.conn, ACCOUNT, "s1")
        self.assertTrue(seen["capability"]["ref_stable"])
        self.assertEqual(seen["capability"]["ref_scope"], "account")
        self.assertIsNone(self._sync()["last_error"])

    def test_an_unmeasured_aspsp_is_reported_not_silently_downgraded(self):
        """A spelling drift and a genuinely unmeasured bank look identical from
        here, so the name is named rather than quietly disabling references."""
        self.conn.execute(
            "UPDATE accounts SET aspsp='Revolut NL' WHERE account_id='acc1'")
        flows.backfill(FakeAIS([([raw_tx("2024-08-05", ref="R1")], None)]),
                       self.conn, ACCOUNT, "s1")
        note = self._sync()["last_error"]
        self.assertIn("Revolut NL", note)
        self.assertIn("no capability row", note)


    def test_a_narrow_refresh_does_not_reissue_an_occurrence_it_cannot_see(self):
        """The P0, driven through the public backfill rather than beside the
        allocator. A routine refresh asks for roughly the last week (`sync`
        narrows `floor_days` exactly this way), so a monthly standing order's
        earlier occurrences are NOT in the rows backfill loads. Allocating from
        those rows alone hands out occurrence 0 again and apply_plan dies on
        UNIQUE (account_id, identity_key, occurrence). Reference-less on
        purpose: identical amount, counterparty and remittance every month is
        what a standing order looks like."""
        deep = FakeAIS([([raw_tx("2026-06-05", remittance="huur"),
                          raw_tx("2026-07-05", remittance="huur")], None)])
        self.assertEqual(flows.backfill(deep, self.conn, ACCOUNT, "s1")["inserted"], 2)

        narrow = FakeAIS([([raw_tx("2026-08-01", remittance="huur")], None)])
        out = flows.backfill(narrow, self.conn, ACCOUNT, "s1", floor_days=7)
        self.assertEqual(narrow.calls[0][1], "2026-07-27")   # the older two are out of view
        self.assertEqual(out["inserted"], 1)
        rows = [dict(r) for r in self.conn.execute(
            "SELECT booking_date, identity_key, occurrence, state FROM"
            " transactions ORDER BY booking_date")]
        self.assertEqual(len({r["identity_key"] for r in rows}), 1)
        self.assertEqual([r["occurrence"] for r in rows], [0, 1, 2])
        self.assertEqual({r["state"] for r in rows}, {"active"})

    def test_a_rekey_across_two_passes_never_reissues_the_vacated_tuple(self):
        """The re-key ghost, made durable. A corroborated amount correction
        moves the row into a new identity cluster and LEAVES its old
        (identity_key, occurrence) behind — and after the commit no row carries
        that tuple any more, so nothing derived from the surviving rows
        remembers it is spent. A later pass carrying the original content must
        allocate above it, not step into it."""
        first = FakeAIS([([raw_tx("2026-07-01", "12.34", ref="R1")], None)])
        flows.backfill(first, self.conn, ACCOUNT, "s1")
        original = self.conn.execute(
            "SELECT identity_key, occurrence FROM transactions").fetchone()

        corrected = FakeAIS([([raw_tx("2026-07-02", "15.00", ref="R1")], None)])
        flows.backfill(corrected, self.conn, ACCOUNT, "s1")
        moved = self.conn.execute(
            "SELECT identity_key, occurrence FROM transactions").fetchone()
        self.assertNotEqual(moved["identity_key"], original["identity_key"])

        # a third pass in which the ORIGINAL content arrives again, reference-less
        again = FakeAIS([([raw_tx("2026-07-02", "15.00", ref="R1"),
                           raw_tx("2026-07-02", "12.34")], None)])
        flows.backfill(again, self.conn, ACCOUNT, "s1")
        rows = [dict(r) for r in self.conn.execute(
            "SELECT identity_key, occurrence, state FROM transactions")]
        self.assertEqual(len(rows), 2)
        revived = [r for r in rows
                   if r["identity_key"] == original["identity_key"]]
        self.assertEqual(len(revived), 1)
        self.assertGreater(revived[0]["occurrence"], original["occurrence"])


class TestCompleteRenewal(unittest.TestCase):
    """Driven through the entry point `tools_auth` actually calls.
    Renewal must COMPLETE — the resident is asked, they tap, the system keeps
    working — and the order is what makes completing safe: the new
    session's deep fetch must be durably committed BEFORE anything switches."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.open_db(pathlib.Path(self.tmp.name) / "f.sqlite")
        self._real_today = flows._today
        flows._today = lambda: TODAY
        observe(self.conn)
        self.secret = store.local_secret(self.conn)
        self.aid = store.account_id(IBAN_R, "EUR", self.secret)
        self.conn.execute(
            "INSERT INTO sessions(session_id, aspsp_name, status, generation)"
            " VALUES ('s-old','Revolut','AUTHORIZED',4)")
        # quarantined until the switch promotes it, so an interrupted renewal
        # never leaves two consents claiming to be live for one bank
        self.conn.execute(
            "INSERT INTO sessions(session_id, aspsp_name, status, generation)"
            " VALUES ('s-new','Revolut','REVIEW_REQUIRED',0)")
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency, aspsp,"
            " label) VALUES (?, 'uid-old', 's-old', 'EUR', 'Revolut',"
            " 'huishouden')", (self.aid,))

    def tearDown(self):
        flows._today = self._real_today
        self.tmp.cleanup()

    def records(self):
        """The shape tools_auth builds: the durable id already derived."""
        return [{"uid": "uid-new", "iban": IBAN_R, "currency": "EUR",
                 "aspsp": "Revolut", "account_id": self.aid}]

    def renew(self, ais):
        return flows.complete_renewal(
            self.conn, ais, old_session_id="s-old", new_session_id="s-new",
            accounts=self.records(), secret=self.secret)

    def account(self):
        return dict(self.conn.execute("SELECT * FROM accounts").fetchone())

    def session(self, sid):
        return dict(self.conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (sid,)).fetchone())

    def test_it_fetches_the_new_session_before_it_switches_anything(self):
        """The ordering assertion, not merely the end state: while the new
        session is being paged the account must still be bound to the OLD one,
        with the old consent still live. A renewal that switched first and
        fetched second would strand the operator on a consent whose history
        never arrived — and every end-state assertion would still pass."""
        seen = {}

        class WatchingAIS(FakeAIS):
            def transactions(inner, uid, date_from, continuation_key=None):
                row = self.conn.execute(
                    "SELECT a.uid, a.session_id, s.status, s.closed_at"
                    " FROM accounts a JOIN sessions s"
                    " ON s.session_id=a.session_id").fetchone()
                seen["during"] = tuple(row)
                return FakeAIS.transactions(inner, uid, date_from,
                                            continuation_key)

        out = self.renew(WatchingAIS([([raw_tx("2024-08-05", ref="R1"),
                                        raw_tx("2026-07-01", ref="R2")], None)]))
        self.assertEqual(seen["during"],
                         ("uid-old", "s-old", "AUTHORIZED", None))
        self.assertEqual((out["retired"], out["accounts"], out["generation"]),
                         (True, 1, 5))
        self.assertEqual(out["inserted"], 2)
        acct = self.account()
        self.assertEqual((acct["uid"], acct["session_id"]), ("uid-new", "s-new"))
        self.assertEqual(acct["label"], "huishouden")     # carried forward
        new = self.session("s-new")
        self.assertEqual((new["status"], new["generation"]), ("AUTHORIZED", 5))
        self.assertIsNotNone(self.session("s-old")["closed_at"])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM transactions").fetchone()[0], 2)

    def test_a_capped_fetch_reports_retired_false_and_switches_nothing(self):
        """A capped run writes no coverage — it proved nothing — so the switch
        never begins. Reported rather than raised: the caller turns this into a
        durable "come back and finish this". Retiring the old consent on the
        strength of a partial fetch loses history for good, and the fresh-SCA
        window that would have got it does not reopen."""
        ais = EndlessAIS()
        out = self.renew(ais)
        self.assertFalse(out["retired"])
        # nothing switched, so nothing may be revoked either: the old consent
        # is still the one serving every answer
        self.assertEqual(ais.deleted, [])
        self.assertFalse(out["revoked"])
        self.assertEqual(out["accounts"], 0)
        self.assertEqual(out["incomplete"], [self.aid])
        # the caller's two-signal completeness check reads this exactly as it
        # reads a plain backfill result
        self.assertTrue(out["capped"])
        self.assertEqual(out["completeness"], "partial")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM coverage").fetchone()[0], 0)
        acct = self.account()
        self.assertEqual((acct["uid"], acct["session_id"]), ("uid-old", "s-old"))
        self.assertEqual(self.session("s-old")["status"], "AUTHORIZED")
        self.assertIsNone(self.session("s-old")["closed_at"])
        # the renewed consent stays quarantined: visible, and revocable
        self.assertEqual(self.session("s-new")["status"], "REVIEW_REQUIRED")

    def test_a_dormant_account_renews_normally(self):
        """The consequence of stamping the FETCH rather than the coverage. The
        bank returns nothing, so no interval is proved and no coverage row is
        written — "dormant" and "silently truncated to nothing" are
        indistinguishable from here — but the retrieval completed, so the
        renewal goes through. Refusing it would strand the operator on a
        consent about to expire because one of their accounts is idle."""
        out = self.renew(FakeAIS([([], None)]))
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM coverage").fetchone()[0], 0)
        self.assertTrue(out["retired"])
        acct = self.account()
        self.assertEqual((acct["uid"], acct["session_id"]), ("uid-new", "s-new"))
        self.assertEqual(self.session("s-new")["status"], "AUTHORIZED")
        self.assertIsNotNone(self.session("s-old")["closed_at"])

    def test_a_successful_renewal_revokes_the_old_consent_at_the_bank(self):
        """End to end through the entry point tools_auth calls. The old session
        is closed with `DELETE /sessions/{id}` once the new one is mapped. Retiring it only in our own database leaves the grant live
        at the bank for the rest of its 179 days while `closed_at` hides it
        from `consent_status` and takes its `consent_ref` with it — a renewal a
        year across three banks quietly accumulates them."""
        ais = FakeAIS([([raw_tx("2024-08-05", ref="R1")], None)])
        out = self.renew(ais)
        self.assertTrue(out["retired"])
        self.assertEqual(ais.deleted, ["s-old"])         # at the PROVIDER
        self.assertTrue(out["revoked"])
        self.assertIsNone(out["revoke_error"])
        old = self.session("s-old")
        self.assertEqual(old["status"], "CLOSED")
        self.assertIsNotNone(old["closed_at"])           # only now
        # and the ordering: the revocation happens after the switch, never
        # before, so a refusal cannot strand accounts on a dead consent
        self.assertEqual(self.account()["session_id"], "s-new")

    def test_a_failed_revocation_keeps_the_renewal_and_stays_revocable(self):
        """The other side. A 429 on the DELETE must not throw away a
        completed renewal — the new consent is live, mapped and fully fetched —
        and must not be recorded as a revocation either. The old row therefore
        stays visible with its consent_ref intact; hiding a consent we did not
        revoke on the SUCCESS
        path is the same defect as hiding one on the failure path."""
        ais = RefusingAIS([([raw_tx("2024-08-05", ref="R1")], None)])
        out = self.renew(ais)

        # the renewal itself stands
        self.assertTrue(out["retired"])
        acct = self.account()
        self.assertEqual((acct["uid"], acct["session_id"]), ("uid-new", "s-new"))
        self.assertEqual(acct["label"], "huishouden")
        new = self.session("s-new")
        self.assertEqual((new["status"], new["generation"]), ("AUTHORIZED", 5))
        self.assertFalse(out["revoked"])
        self.assertEqual(out["revoke_error"], "OSError")

        # the old grant is still live at the bank, so it is still in front of
        # the operator: `consent_status` lists `closed_at IS NULL`, and
        # `unlink_bank` resolves the same sha256("consent-ref|"+id)[:8]
        old = self.session("s-old")
        self.assertEqual(old["status"], apply.REVOKE_FAILED_STATUS)
        self.assertIsNone(old["closed_at"])
        listed = {r["session_id"] for r in self.conn.execute(
            "SELECT session_id FROM sessions WHERE closed_at IS NULL")}
        self.assertIn("s-old", listed)
        refs = {hashlib.sha256(("consent-ref|" + s).encode()).hexdigest()[:8]: s
                for s in listed}
        self.assertEqual(
            refs.get(hashlib.sha256(b"consent-ref|s-old").hexdigest()[:8]),
            "s-old")
        # it is also NOT the live consent any more: one bank, one live session
        self.assertEqual([r["session_id"] for r in self.conn.execute(
            "SELECT session_id FROM sessions WHERE aspsp_name='Revolut'"
            " AND closed_at IS NULL AND status='AUTHORIZED'")], ["s-new"])

    def test_a_404_on_the_revocation_closes_the_old_consent(self):
        """Treating EVERY exception as a refusal, 404 included, lands a renewal
        against a consent the provider has already dropped in `REVOKE_FAILED`
        for ever — visible,
        nagging, and unresolvable, because every retry can only 404 again.

        It reads the finality rule from `eb_ais` now, which is the same
        predicate `unlink_bank` calls, so the two paths cannot answer
        differently again. A 404 is what a successful DELETE produces."""
        ais = GoneAIS([([raw_tx("2024-08-05", ref="R1")], None)])
        out = self.renew(ais)
        self.assertEqual(ais.deleted, ["s-old"])
        self.assertTrue(out["revoked"])
        self.assertIsNone(out["revoke_error"])
        old = self.session("s-old")
        self.assertEqual(old["status"], "CLOSED")
        self.assertIsNotNone(old["closed_at"])
        # and it is gone from the nag list rather than pinned in it for ever
        self.assertNotIn("s-old", {r["session_id"] for r in self.conn.execute(
            "SELECT session_id FROM sessions WHERE closed_at IS NULL")})

    def test_the_one_finality_rule_is_the_shared_one(self):
        """The rule itself, asserted against the module that owns it rather
        than restated here — a second copy of "only a 404" in this file is
        exactly the drift that produced the defect."""
        self.assertTrue(eb_ais.revocation_is_final(
            eb_ais.ApiError(404, "delete_session")))
        for status in (401, 403, 429, 500):
            self.assertFalse(eb_ais.revocation_is_final(
                eb_ais.ApiError(status, "delete_session")))
        self.assertFalse(eb_ais.revocation_is_final(OSError("connection reset")))

    def test_a_capped_renewal_tells_the_operator_to_reauthorize_not_to_sync(self):
        """A capped renewal is NOT resumable here, because the candidate session
        stays quarantined and its `uid`s are never written down. `sync` can
        only refresh the still-bound OLD session, so pointing the operator at
        it reports progress on the wrong consent. The honest remedy is to
        revoke the quarantined candidate and authorize again, and the caller
        can only say so if this return says so."""
        out = self.renew(EndlessAIS())
        self.assertFalse(out["retired"])
        self.assertEqual(out["remedy"], flows.REAUTHORIZE_REMEDY)
        self.assertNotIn("sync", out["remedy"])
        # present on the completing path too, so a caller cannot forget to read
        # a key that only exists on failure
        done = self.renew(FakeAIS([([raw_tx("2024-08-05", ref="R1")], None)]))
        self.assertTrue(done["retired"])
        self.assertIsNone(done["remedy"])

    def test_a_failure_mid_pagination_leaves_the_old_consent_live_and_bound(self):
        """A dropped socket re-raises out of backfill exactly as it always did:
        the caller must not read a silent zero as an empty account."""
        with self.assertRaises(OSError):
            self.renew(BrokenAIS())
        acct = self.account()
        self.assertEqual((acct["uid"], acct["session_id"]), ("uid-old", "s-old"))
        self.assertIsNone(self.session("s-old")["closed_at"])
        self.assertEqual(self.session("s-new")["generation"], 0)


class TestAccountScopingAcrossFlows(unittest.TestCase):
    """`account_id` is the one identity-hashed field no helper compares, and a
    suite that never varies it cannot see a scoping mistake. These tests wire
    multiple accounts through `flows` at once — `backfill` scoping
    `stored`/coverage/sync_state by `account_id`, and `complete_renewal`
    building one `(account_id, uid)`
    binding per account in a loop — so this is the first corpus that can
    actually catch a mixed-up or hard-coded account_id in either path. Every
    other test in `TestBackfill`/`TestCompleteRenewal` holds `account_id`
    constant at "acc1" or a single derived `aid`, and that corpus shape is
    exactly what lets a scoping defect hide."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.open_db(pathlib.Path(self.tmp.name) / "f.sqlite")
        self._real_today = flows._today
        flows._today = lambda: TODAY
        observe(self.conn)

    def tearDown(self):
        flows._today = self._real_today
        self.tmp.cleanup()

    def test_backfill_scopes_transactions_coverage_and_sync_state_by_account_id(self):
        """Two accounts, same bank, DIFFERENT account_id, backfilled with
        content-identical transactions (same amount/counterparty/remittance,
        different dates). identity_key hashes account_id in, so a mix-up here
        would either collide on write (UNIQUE) or leak one account's rows,
        coverage or sync_state into the other's read."""
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency, aspsp)"
            " VALUES ('acc-A','uid-A','s1','EUR','Revolut')")
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency, aspsp)"
            " VALUES ('acc-B','uid-B','s1','EUR','Revolut')")

        ais_a = FakeAIS([([raw_tx("2024-08-05", "12.34", ref="RA")], None)])
        out_a = flows.backfill(ais_a, self.conn, {"account_id": "acc-A",
                                                   "uid": "uid-A"}, "s1")
        ais_b = FakeAIS([([raw_tx("2024-09-09", "12.34", ref="RB")], None)])
        out_b = flows.backfill(ais_b, self.conn, {"account_id": "acc-B",
                                                   "uid": "uid-B"}, "s1")

        self.assertEqual(out_a["inserted"], 1)
        self.assertEqual(out_b["inserted"], 1)
        self.assertEqual(ais_a.calls[0][0], "uid-A")
        self.assertEqual(ais_b.calls[0][0], "uid-B")

        rows_a = [dict(r) for r in self.conn.execute(
            "SELECT * FROM transactions WHERE account_id='acc-A'")]
        rows_b = [dict(r) for r in self.conn.execute(
            "SELECT * FROM transactions WHERE account_id='acc-B'")]
        self.assertEqual(len(rows_a), 1)
        self.assertEqual(len(rows_b), 1)
        self.assertEqual(rows_a[0]["booking_date"], "2024-08-05")
        self.assertEqual(rows_b[0]["booking_date"], "2024-09-09")
        # content-identical (amount, counterparty, remittance) rows in two
        # accounts must NOT collapse onto the same identity_key.
        self.assertNotEqual(rows_a[0]["identity_key"], rows_b[0]["identity_key"])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS c FROM transactions").fetchone()["c"], 2)

        cov_a = [dict(r) for r in self.conn.execute(
            "SELECT * FROM coverage WHERE account_id='acc-A'")]
        cov_b = [dict(r) for r in self.conn.execute(
            "SELECT * FROM coverage WHERE account_id='acc-B'")]
        self.assertEqual(len(cov_a), 1)
        self.assertEqual(len(cov_b), 1)
        self.assertEqual(cov_a[0]["interval_start"], "2024-08-05")
        self.assertEqual(cov_b[0]["interval_start"], "2024-09-09")

        sync_a = self.conn.execute(
            "SELECT oldest_fetched FROM sync_state WHERE account_id='acc-A'"
            " AND resource='transactions'").fetchone()
        sync_b = self.conn.execute(
            "SELECT oldest_fetched FROM sync_state WHERE account_id='acc-B'"
            " AND resource='transactions'").fetchone()
        self.assertEqual(sync_a["oldest_fetched"], "2024-08-05")
        self.assertEqual(sync_b["oldest_fetched"], "2024-09-09")

    def test_complete_renewal_switches_each_of_several_accounts_to_its_own_uid(self):
        """Two accounts under the SAME renewal, each with a distinct
        account_id and a distinct new uid. A copy-paste in the
        account_id/uid binding loop (e.g. reusing the last account's id or
        uid for both) would only be visible with more than one account
        wired through `complete_renewal` at once."""
        secret = store.local_secret(self.conn)
        aid1 = store.account_id(IBAN_R, "EUR", secret)
        aid2 = store.account_id(IBAN_R2, "EUR", secret)
        self.conn.execute(
            "INSERT INTO sessions(session_id, aspsp_name, status, generation)"
            " VALUES ('s-old','Revolut','AUTHORIZED',1)")
        self.conn.execute(
            "INSERT INTO sessions(session_id, aspsp_name, status, generation)"
            " VALUES ('s-new','Revolut','REVIEW_REQUIRED',0)")
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency, aspsp,"
            " label) VALUES (?, 'uid-old-1', 's-old', 'EUR', 'Revolut', 'one')",
            (aid1,))
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency, aspsp,"
            " label) VALUES (?, 'uid-old-2', 's-old', 'EUR', 'Revolut', 'two')",
            (aid2,))

        class TwoAccountAIS:
            """One page per uid, keyed by which account is being fetched —
            so handing `backfill` the wrong uid for an account_id would
            insert the OTHER account's transaction under this one."""

            def __init__(self):
                self.calls = []
                self.deleted = []

            def transactions(self, uid, date_from, continuation_key=None):
                self.calls.append((uid, date_from, continuation_key))
                if uid == "uid-new-1":
                    return ([raw_tx("2024-08-05", "10.00", ref="ONE")], None)
                if uid == "uid-new-2":
                    return ([raw_tx("2024-08-06", "20.00", ref="TWO")], None)
                raise AssertionError("unexpected uid %r" % (uid,))

            def delete_session(self, sid):
                self.deleted.append(sid)
                return {"deleted": True}

        ais = TwoAccountAIS()
        records = [
            {"uid": "uid-new-1", "iban": IBAN_R, "currency": "EUR",
             "aspsp": "Revolut", "account_id": aid1},
            {"uid": "uid-new-2", "iban": IBAN_R2, "currency": "EUR",
             "aspsp": "Revolut", "account_id": aid2},
        ]
        out = flows.complete_renewal(
            self.conn, ais, old_session_id="s-old", new_session_id="s-new",
            accounts=records, secret=secret)

        self.assertTrue(out["retired"])
        self.assertEqual(out["accounts"], 2)
        self.assertEqual(out["inserted"], 2)

        row1 = dict(self.conn.execute(
            "SELECT uid, session_id, label FROM accounts WHERE account_id=?",
            (aid1,)).fetchone())
        row2 = dict(self.conn.execute(
            "SELECT uid, session_id, label FROM accounts WHERE account_id=?",
            (aid2,)).fetchone())
        self.assertEqual(row1, {"uid": "uid-new-1", "session_id": "s-new",
                                "label": "one"})
        self.assertEqual(row2, {"uid": "uid-new-2", "session_id": "s-new",
                                "label": "two"})

        tx1 = [dict(r) for r in self.conn.execute(
            "SELECT booking_date FROM transactions WHERE account_id=?",
            (aid1,))]
        tx2 = [dict(r) for r in self.conn.execute(
            "SELECT booking_date FROM transactions WHERE account_id=?",
            (aid2,))]
        self.assertEqual(tx1, [{"booking_date": "2024-08-05"}])
        self.assertEqual(tx2, [{"booking_date": "2024-08-06"}])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS c FROM transactions").fetchone()["c"], 2)


class TestBackfillAndWhitelistSafety(unittest.TestCase):
    """Four independent ways `backfill` and whitelist verification go wrong.

    1. **The tombstone licence.** A truncated-but-CLEAN fetch (not capped, not
       an exception) tombstones real history it never re-proved, if `backfill`
       licenses `ingest.reconcile` to tombstone across the REQUESTED span rather
       than the span the response actually proved. No span derived from the
       response is safe, which is why no ASPSP is licensed at all.
    2. **Shallow reporting.** A genuinely-empty fetch must not be durably told
       to "re-link" a bank that has nothing to re-link.
    3. **Whitelist IBAN parsing.** The entry title is parsed before it is
       canonicalised, never after.
    4. **Account identity.** The extra-account check compares
       `(iban, currency)`, because that is what the ledger keys on -- comparing
       IBANs alone silently links a second currency."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.open_db(pathlib.Path(self.tmp.name) / "f.sqlite")
        self._real_today = flows._today
        flows._today = lambda: TODAY
        self.conn.execute(
            "INSERT INTO accounts(account_id, uid, session_id, currency, aspsp)"
            " VALUES ('acc1','uid-1','s1','EUR','Revolut')")
        observe(self.conn)

    def tearDown(self):
        flows._today = self._real_today
        self.tmp.cleanup()

    def _rows(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT booking_date, state, state_reason FROM transactions"
            " ORDER BY booking_date")]

    def _coverage(self):
        return [(r["interval_start"], r["interval_end"]) for r in self.conn.execute(
            "SELECT interval_start, interval_end FROM coverage ORDER BY interval_start")]

    # ---- A RESPONSE NEVER LICENSES A TOMBSTONE INTERVAL BY ITSELF. ------
    # ---- A clean paginated ------------------------------------------------
    # ---- response proves the EXISTENCE of the rows it returned, never the --
    # ---- COMPLETENESS of an interval; backfill now licenses reconcile's ----
    # ---- rule 3 with NOTHING for every ASPSP (TOMBSTONE_LICENSED_ASPSPS ----
    # ---- is empty), regardless of what was fetched. -------------------------

    def test_a_truncated_but_clean_fetch_does_not_tombstone_history_it_never_re_proved(self):
        """The provider's own behaviour: one session can return deep history
        and then, asked again on that same session after the SCA window has
        closed, return only the most recent months -- both times paginating
        CLEANLY (key=None). `capped` and the mid-pagination exception are
        proxies for
        "the fetch was complete"; a fetch that is neither capped nor failed,
        merely SHORT, satisfies both proxies while proving far less than the
        2900-day span it would otherwise be reconciled against. Bounding the
        licence to what the response proved is not enough either; the licence
        is empty for every ASPSP, which subsumes that bound."""
        deep = FakeAIS([([raw_tx("2024-08-05", ref="R1"),
                          raw_tx("2025-02-02", ref="R2", remittance="huur"),
                          raw_tx("2026-07-20", ref="R3", remittance="energie")],
                         None)])
        out1 = flows.backfill(deep, self.conn, ACCOUNT, "s1")
        self.assertEqual(out1["inserted"], 3)

        # the SAME session, thirty minutes later: only the most recent row
        # comes back, paginating CLEANLY -- not capped, not an exception.
        truncated = FakeAIS([([raw_tx("2026-07-20", ref="R3",
                                      remittance="energie")], None)])
        out2 = flows.backfill(truncated, self.conn, ACCOUNT, "s1")
        self.assertFalse(out2["capped"])
        self.assertEqual(out2["completeness"], "complete")

        rows = self._rows()
        self.assertEqual({r["booking_date"] for r in rows},
                         {"2024-08-05", "2025-02-02", "2026-07-20"})
        # the two older rows must still be ACTIVE: they were never re-proven
        # absent, only omitted from a response that was short, not complete.
        for r in rows:
            if r["booking_date"] != "2026-07-20":
                self.assertEqual(r["state"], "active", r)
                self.assertIsNone(r["state_reason"], r)
        # and coverage must not claim MORE than pass 2 actually proved on its
        # own -- it may legitimately still show the full span, because pass 1
        # genuinely proved that span and record_coverage MERGES; what it must
        # never do is claim it on pass 2's evidence while the rows pass 2
        # would have destroyed are gone. With the rows intact, the merged
        # claim is honest again.
        self.assertEqual(self._coverage(), [("2024-08-05", "2026-08-04")])

    def test_backfill_never_tombstones_a_stored_row_regardless_of_interval_width(self):
        """Bounding the licence to what the response PROVED is not safe: "proved"
        is still the wrong word. A pass whose oldest returned row sits well
        before a row that later goes missing appears to prove that whole span
        -- but a clean paginated response proves the EXISTENCE of the rows it
        returned, never the COMPLETENESS of the interval between them.
        Computing a licence from the response under reconciliation is the
        structural error, regardless of how wide or well-evidenced that
        licence looks. Nothing is tombstoned until a
        per-ASPSP capability is actually measured, and none is
        (`TOMBSTONE_LICENSED_ASPSPS` is empty)."""
        first = FakeAIS([([raw_tx("2023-01-01", ref="OLD"),
                           raw_tx("2024-08-05", ref="MID", remittance="huur"),
                           raw_tx("2026-07-01", ref="NEW", remittance="loon")],
                          None)])
        flows.backfill(first, self.conn, ACCOUNT, "s1")

        # a WIDE span "proven" again; MID is missing from the response.
        second = FakeAIS([([raw_tx("2023-01-01", ref="OLD"),
                            raw_tx("2026-07-01", ref="NEW", remittance="loon")],
                           None)])
        out = flows.backfill(second, self.conn, ACCOUNT, "s1")

        rows = {r["booking_date"]: r for r in self._rows()}
        self.assertEqual(rows["2024-08-05"]["state"], "active")
        self.assertIsNone(rows["2024-08-05"]["state_reason"])
        self.assertEqual(rows["2023-01-01"]["state"], "active")
        self.assertEqual(rows["2026-07-01"]["state"], "active")
        self.assertEqual(out["completeness"], "complete")
        self.assertFalse(out["capped"])

    def test_the_outlier_that_forced_the_reversal_leaves_all_five_rows_active(self):
        """The reproduction that makes a bounded licence untenable rather than
        merely narrow: bounding it to `(proved_from, proved_to)`, computed
        from the RESPONSE
        under reconciliation, which still destroys history whenever a
        truncated-but-clean response happens to carry ONE old, unrelated row
        -- an account-opening entry, a backdated correction, a pending row
        with an old booking date. The licence widens straight back out to
        that row's date, and everything genuinely missing between it and the
        recent row is tombstoned on no more evidence than the ORIGINAL bug
        had. Five rows seeded across two years; the second pass is
        truncated but clean, carrying only the newest row PLUS one old one
        -- and now leaves all five untouched."""
        seed = FakeAIS([([raw_tx("2020-01-01", ref="R1"),
                          raw_tx("2021-03-01", ref="R2", remittance="huur"),
                          raw_tx("2022-06-01", ref="R3", remittance="energie"),
                          raw_tx("2023-09-01", ref="R4", remittance="internet"),
                          raw_tx("2026-07-20", ref="R5", remittance="loon")],
                         None)])
        flows.backfill(seed, self.conn, ACCOUNT, "s1")
        self.assertEqual(len(self._rows()), 5)

        # thirty minutes later: the SAME session, clean, but truncated -- and
        # it happens to carry one old row (an account-opening entry, a
        # backdated correction, a pending row with an old booking date)
        # alongside the newest one.
        truncated = FakeAIS([([raw_tx("2020-01-01", ref="R1"),
                               raw_tx("2026-07-20", ref="R5",
                                      remittance="loon")],
                              None)])
        out = flows.backfill(truncated, self.conn, ACCOUNT, "s1")

        rows = self._rows()
        self.assertEqual(len(rows), 5)
        self.assertEqual({r["state"] for r in rows}, {"active"})
        self.assertTrue(all(r["state_reason"] is None for r in rows))
        self.assertEqual(out["completeness"], "complete")
        self.assertFalse(out["capped"])

    def test_no_aspsp_is_licensed_to_tombstone_yet(self):
        """The constant itself, asserted directly: no ASPSP has a measured
        re-list-completeness capability is measured, so the licensed
        branch in `backfill` is unreachable by construction, not merely by
        the accident of no test having tried one."""
        self.assertEqual(flows.TOMBSTONE_LICENSED_ASPSPS, frozenset())
        self.assertNotIn("Revolut", flows.TOMBSTONE_LICENSED_ASPSPS)

    # ---- Fix 3: "proved less than 180 days" and "proved nothing because ----
    # ---- there is nothing" are different findings, and only the first ------
    # ---- carries the re-link remedy. -----------------------------------

    def test_an_empty_fetch_is_not_told_to_re_link_a_bank_with_nothing_to_re_link(self):
        """An empty, CLEAN response has not missed a window -- there is no
        window to miss, and it is indistinguishable here from a bank that
        silently truncated an active account to zero. Writing
        SHALLOW_NOTE durably here is the pinned-forever shape
        `eb_ais.revocation_is_final` exists to prevent on the OTHER path,
        reintroduced two functions away: re-linking a genuinely dormant
        account reproduces the same nothing, and nothing would ever clear the
        note again."""
        out = flows.backfill(FakeAIS([([], None)]), self.conn, ACCOUNT, "s1")
        self.assertFalse(out["shallow"])
        self.assertEqual(out["completeness"], "complete")
        self.assertIsNone(out["proved_from"])
        self.assertEqual(self._coverage(), [])
        row = self.conn.execute(
            "SELECT last_error FROM sync_state WHERE account_id='acc1'"
            " AND resource='transactions'").fetchone()
        self.assertIsNone(row["last_error"])

    def test_a_nonzero_but_short_span_is_still_reported_shallow(self):
        """The other half of Fix 3's distinction: some real history that
        merely does not reach 180 days is exactly what `shallow` and
        SHALLOW_NOTE exist to name, and the fix must not blunt that."""
        out = flows.backfill(
            FakeAIS([([raw_tx("2026-07-01", ref="R1")], None)]),
            self.conn, ACCOUNT, "s1")
        self.assertTrue(out["shallow"])
        self.assertIsNotNone(out["proved_from"])
        row = self.conn.execute(
            "SELECT last_error FROM sync_state WHERE account_id='acc1'"
            " AND resource='transactions'").fetchone()
        self.assertEqual(row["last_error"], flows.SHALLOW_NOTE)

    # ---- The parser handles the tight `"IBAN <code>"` title only. --------
    # ---- A grouping-tolerant second pattern was built, bounded, then ------
    # ---- deleted: every IBAN defect lived in that tolerance. --------------

    def test_a_conventionally_spaced_title_is_a_stated_limitation(self):
        """The limitation is pinned directly rather than left implicit: a
        conventionally-spaced title does NOT parse, and a lowercase TIGHT one
        does. The spacing tolerance was the source of every regression here;
        the lowercase handling never was, because the whole title is
        uppercased before the pattern ever runs."""
        self.assertEqual(
            flows._iban_of({"title": "IBAN NL00 REVO 0000 0000 01"}), "")
        self.assertEqual(
            flows._iban_of({"title": "iban nl00revo0000000001"}), IBAN_R)

    def test_the_whitelist_entry_format_parses(self):
        """Pins the provider's entry shape, from
        `tests/fixtures/whitelisted_accounts.json`: five keys (`aspsp`,
        `created`, `identification_hash`, `linker`, `title`), `aspsp` as
        `{"name", "country"}`, and `title` as `"IBAN <tight-iban>"` --
        uppercase, no internal spaces. If the provider's title format ever
        changes, this is the test that notices: `_iban_of` would start
        returning "" for entries it used to parse."""
        entries = json.loads((FIX / "whitelisted_accounts.json").read_text())
        self.assertEqual(len(entries), 3)
        expected = {"Revolut": IBAN_R, "ABN AMRO": IBAN_A,
                   "Rabobank": "NL73RABO0123456789"}
        for entry in entries:
            self.assertEqual(set(entry.keys()),
                             {"aspsp", "created", "identification_hash",
                              "linker", "title"})
            bank = entry["aspsp"]["name"]
            self.assertEqual(entry["aspsp"]["country"], "NL")
            self.assertEqual(flows._iban_of(entry), expected[bank],
                             f"bank={bank}")

        # and the whole pipeline, not just the parser: verify_accounts
        # against the real shape, scoped to one bank.
        session = json.loads((FIX / "session_revolut.json").read_text())
        v = flows.verify_accounts(
            session_accounts=session["accounts"], whitelisted=entries,
            intended=[], aspsp="Revolut", country="NL")
        self.assertTrue(v.ok, v.message)

    def test_extraction_before_canonicalisation_protects_three_title_shapes(self):
        """Handling a lowercase title by compacting the WHOLE title (removing
        all whitespace) before running the extraction regex destroys the word
        boundaries the extractor depends on, and breaks three shapes that
        parse correctly against the raw title:

        * a trailing label separated from the code by a single space used to
          stop correctly at the code, because the space was a real word
          boundary; compacting glued the label onto the code instead.
        * the SAME regression whether the label came from a title with no
          "IBAN" prefix at all.
        * a PRECEDING label+number ("Rekening 12") used to leave the code
          alone entirely; compacting glued it into one token and let the
          regex -- which has to drop its leading `\\b` to cope with the
          compacting -- anchor MID-TOKEN, swallowing "NG12" out of
          "REKENI|NG|12" as a false IBAN prefix.

        There is no grouping-tolerant fallback, but the ordering stays
        load-bearing: `_iban_of` extracts from the RAW
        (uppercased-only) title with `_IBAN_RE`'s leading `\\b` intact, and
        canonicalises only afterwards -- never compacts before matching --
        which is what keeps these three cases correct with the single tight
        pattern alone."""
        cases = [
            ("nl00revo0000000001", IBAN_R),
            ("IBAN NL00REVO0000000001 huishouden", IBAN_R),
            ("NL00REVO0000000001 Huishouden", IBAN_R),
            ("Rekening 12 NL00REVO0000000001", IBAN_R),
        ]
        for title, expected in cases:
            self.assertEqual(flows._iban_of({"title": title}), expected,
                             f"title={title!r}")

    def test_a_short_false_start_beside_an_iban_or_alone_never_absorbs_a_neighbour(self):
        """Four boundary shapes for the tight pattern: a Belgian- or
        Spanish-length IBAN followed by a trailing label,
        a two-letter-two-digit reference code preceding a real IBAN, and a
        two-letter-two-digit false start with NO real IBAN anywhere in the
        title. `_IBAN_RE`'s character class cannot cross a space at any
        IBAN length or in any position, so none of these ever needed a
        second pattern to resolve correctly."""
        cases = [
            ("BE00539000000034 huishouden", "BE00539000000034"),
            ("ES0021000418450200051332 spaar", "ES0021000418450200051332"),
            ("Ref AB12 NL00REVO0000000001", IBAN_R),
            ("REFERENTIE AB12CDEF ORDER", ""),
        ]
        for title, expected in cases:
            self.assertEqual(flows._iban_of({"title": title}), expected,
                             f"title={title!r}")

    # ---- Fix 4: the extra-account check must compare on the pair the ------
    # ---- ledger actually keys on, not on IBAN alone. -----------------------

    def test_the_same_iban_returned_under_two_currencies_is_reported_not_silently_linked(self):
        """`store.account_id` hashes (iban, currency): a consent returning the
        SAME whitelisted IBAN as both a EUR and a USD sub-account (the
        measured multi-currency shape) creates a SECOND ledger account
        nothing approved. A plain IBAN-set comparison cannot see this -- both
        pairs collapse onto the one IBAN already in `want` -- so it must be
        checked directly against the pair."""
        eur = acct(IBAN_R, uid="u-eur")
        usd = dict(acct(IBAN_R, uid="u-usd"), currency="USD")
        v = flows.verify_accounts(
            session_accounts=[eur, usd], whitelisted=[wl(IBAN_R)],
            intended=[IBAN_R], aspsp="Revolut", country="NL")
        self.assertFalse(v.ok)
        self.assertIn(IBAN_R, v.message)
        self.assertIn("currency", v.message.lower())

    def test_the_same_iban_in_one_currency_still_passes(self):
        """The negative control: nothing about Fix 4 may punish the ordinary,
        single-currency case."""
        v = flows.verify_accounts(
            session_accounts=[acct(IBAN_R)], whitelisted=[wl(IBAN_R)],
            intended=[IBAN_R], aspsp="Revolut", country="NL")
        self.assertTrue(v.ok, v.message)


if __name__ == "__main__":
    unittest.main()


class TestBackfillRuleKeys(TestBackfill):
    """new_row_ids + auto_tagged on every return."""

    def _mint_remittance_rule(self, word="energie", tags=("home", "energy")):
        import rules
        fields, refusal = rules.validate_rule(
            {"remittance_word": word, "tags": list(tags)})
        assert refusal is None, refusal
        self.conn.execute(
            "INSERT INTO tag_rules(signature, remittance_token, tags,"
            " created_at) VALUES (?,?,?,'t')",
            (rules.signature(fields), fields["remittance_token"],
             " ".join(tags)))

    def test_backfill_returns_new_row_ids_and_auto_tagged(self):
        ais = FakeAIS([([raw_tx("2026-08-01", ref="R1")], None)])
        out = flows.backfill(ais, self.conn, ACCOUNT, "s1")
        self.assertEqual(len(out["new_row_ids"]), out["inserted"])
        self.assertEqual(out["auto_tagged"], 0)

    def test_backfill_applies_rules_through_the_real_ingest_path(self):
        # This is the shared seam below sync, first-link and the inline
        # refresher: a rule minted here tags the fetched row via
        # apply_plan, whoever the caller was.
        self._mint_remittance_rule()
        ais = FakeAIS([([raw_tx("2026-08-01", ref="R9",
                                remittance="energie")], None)])
        out = flows.backfill(ais, self.conn, ACCOUNT, "s1")
        self.assertEqual(out["auto_tagged"], 1)
        rid = out["new_row_ids"][0]
        tags = sorted(r[0] for r in self.conn.execute(
            "SELECT tag FROM transaction_tags WHERE row_id=?", (rid,)))
        self.assertEqual(tags, ["energy", "home"])

    def test_zero_row_fetch_and_capped_run_both_carry_the_keys(self):
        empty = flows.backfill(FakeAIS([([], None)]), self.conn,
                               ACCOUNT, "s1")
        self.assertEqual(empty["new_row_ids"], [])
        self.assertEqual(empty["auto_tagged"], 0)
        capped = flows.backfill(EndlessAIS(), self.conn, ACCOUNT, "s1")
        self.assertTrue(capped["capped"])
        self.assertEqual(capped["new_row_ids"], [])
        self.assertEqual(capped["auto_tagged"], 0)
