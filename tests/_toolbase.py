# tests/_toolbase.py
"""Shared fixtures for the tool-module test files.

Every literal here is shaped the way the thing that produces it really
produces it. Enable Banking session ids are UUIDs; casa's state hashes and
state secrets are hex digests; a provenance fingerprint is a 64-char sha256; a
PEM has a body, not only armor lines. A double the producer could never emit
tests nothing — and in a plan the implementer copies it verbatim and trusts it.
"""
import datetime
import hashlib
import json
import os
import pathlib
import re
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"))

import apply  # noqa: E402
import callbacks  # noqa: E402
import bank_feed_server  # noqa: E402
import flows  # noqa: E402
import httpx  # noqa: E402
import store  # noqa: E402
import tools_auth  # noqa: E402
import tools_read  # noqa: E402

# Each test file imports the tool module it is about; this one imports only
# what every file needs, so no test module depends on another tool module
# existing.

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed"

# PEM-SHAPED, not a placeholder. provenance._key_fingerprint strips every
# `-----` armor line, so a value like "-----PEM-----" reduces to an empty body
# and raises. A fake whose shape differs from production proves nothing.
FAKE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
-----END PRIVATE KEY-----
"""

# Armor lines only: set, non-empty, and unusable — the production failure this
# guards against.
ARMOR_ONLY_PEM = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"

# The REAL fixture key. Setup PARSES the key (it derives the SPKI
# certificate from it), so Base exports this one; FAKE_KEY_PEM stays for
# the tests that deliberately want present-but-unreadable material.
TEST_KEY_PEM = (pathlib.Path(__file__).resolve().parent
                / "fixtures/test_rsa_2048.pem").read_text()

# A second, DIFFERENT valid key — the persistence gate's mismatch leg
# (an env key the vault will not reproduce) needs a real key that is
# not TEST_KEY_PEM.
OTHER_KEY_PEM = (pathlib.Path(__file__).resolve().parent
                 / "fixtures/test_rsa_2048_b.pem").read_text()

SESSION_ID = "9f2a4c1e-7b30-4d5a-8e21-0c6f5b8a3d17"
STATE_HASH = hashlib.sha256(b"attempt-1").hexdigest()
STATE_SECRET = hashlib.sha256(b"state-secret-1").hexdigest()
# The fencing token `take_lease` returns and `collect_one` injects into the
# attempt as `lease_fence`. An exchange that never sees one cannot heartbeat.
FENCE = hashlib.sha256(b"lease-fence-1").hexdigest()

# The IBAN FakeAIS's session returns, and therefore the one the whitelist has
# to carry for `flows.verify_accounts` to pass.
LINKED_IBAN = "NL01RABO0123456789"

# A SECOND bank, already whitelisted, and a second session id. Both exist
# because the whitelist is per APPLICATION, not per bank: once bank A is
# linked its entry stays, so bank B's verification has to filter or it reports
# every one of bank A's IBANs as missing and can never succeed.
# A one-bank fixture cannot see that defect at all.
OTHER_IBAN = "NL02ABNA0987654321"
OTHER_ASPSP = "ABN AMRO"
OTHER_SESSION_ID = "1b7c0f42-5e18-42a9-9d3c-2a6e4f8b1c05"

# The redirect URI casa's `.index` entry publishes for this plugin. It is the
# ONLY source of that string: `link_bank` mints against it, `start_auth` sends
# it, and `setup_bank_feed` registers it on the application. Nothing reconstructs
# it from PUBLIC_URL and no tool accepts it as an argument — a
# caller-supplied redirect URI would register an attacker-controlled redirect
# and harvest authorization codes.
DISCOVERED_REDIRECT = "https://casa.example/callback/plg-bank-feed--authorize"

# Frozen clock. Every clock read inside the tools returns this exact value, so
# deadline and cooldown arithmetic is assertable to the second instead of
# racing the machine it runs on. It is taken from the real clock rather than
# written as a literal because the session fixtures below use
# `datetime.date.today()`, and two clocks that disagree by months would make
# every cooldown assertion vacuous.
FROZEN_NOW = float(int(time.time()))

# The provider's expiry for the session FakeAIS returns, and the date the
# renewal handoff therefore asks for (expiry − RENEWAL_LEAD_DAYS).
SESSION_VALID_UNTIL = "2026-12-01T00:00:00Z"


def call(name, **args):
    return bank_feed_server.TOOLS[name]["fn"](args)


def iso_at(epoch):
    """The exact string the tools write for that instant."""
    return datetime.datetime.fromtimestamp(
        epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rate_limited(retry_after_s=None):
    """Exactly what `httpx.Client.request` raises on a 429.

    `httpx` parses the `Retry-After` header and attaches it as `retry_after_s`
    (seconds, or None when the provider sent none) — discarding it is what made
    a 429 unactionable. Constructing it here the same way production does keeps
    the double honest.
    """
    return httpx.RateLimited("provider returned 429", retry_after_s)


def declared_protected():
    """Names in casa.protectedTools, tolerating BOTH manifest forms.

    The manifest ships the {"name", "summary"} object form because casa interpolates
    `summary` with the call's canonical arguments into the operator's approval
    challenge. A bare set() over those dicts is a TypeError.
    """
    manifest = json.loads(
        (PLUGIN_ROOT / ".claude-plugin/plugin.json").read_text("utf-8"))
    entries = (manifest.get("casa") or {}).get("protectedTools") or []
    return {e["name"] if isinstance(e, dict) else e for e in entries}


def mcp_declared_env(with_references=False):
    """The environment variables deployment actually passes to the server.

    This is the real contract: `.mcp.json` is what casa reads when it launches
    the stdio server, so a variable absent from here is a variable that will
    never be set in production no matter what the code reads.

    Returns the set of PROCESS KEYS — what the server reads from `os.environ`.
    With `with_references=True`, returns `{KEY: REFERENCE}` instead: the
    reference is the `${VAR}` name casa resolves out of `plugin-env.conf`, and
    since issue #4 the two differ for the `casa.setupProvides` credentials. A
    value that is not a single reference maps to itself, so a caller comparing
    the two never silently treats malformed wiring as "not renamed".
    """
    mcp = json.loads((PLUGIN_ROOT / ".mcp.json").read_text("utf-8"))
    env = mcp["mcpServers"]["bank-feed"].get("env") or {}
    if not with_references:
        return set(env)
    out = {}
    for key, value in env.items():
        match = re.fullmatch(r"\$\{([A-Z_][A-Z0-9_]*)(?::-[^{}]*)?\}", str(value))
        out[key] = match.group(1) if match else key
    return out


class Recorder:
    """Connection proxy that records SQL, so VACUUM can be asserted."""

    def __init__(self, conn):
        self._conn = conn
        self.sql = []

    def execute(self, sql, *a, **k):
        self.sql.append(sql)
        return self._conn.execute(sql, *a, **k)

    def executescript(self, sql):
        self.sql.append(sql)
        return self._conn.executescript(sql)

    def __getattr__(self, name):
        return getattr(self._conn, name)


class FakeAIS:
    """One bank at a time, but WHICH bank is a parameter.

    A double hard-wired to a single ASPSP cannot express the sequential
    two-bank link the whitelist scoping turns on, so the bank, its IBAN and its session id
    are all constructor arguments and the session is built from them.
    """

    def __init__(self, bank="Rabobank", iban=LINKED_IBAN, country="NL",
                 session_id=SESSION_ID, accounts=None, app=None):
        self.bank = bank
        self.iban = iban
        self.country = country
        self.session_id = session_id
        # The GET /application record: a parameter, because the world guard's
        # whole subject is what this answer claims — a double pinned to one
        # world could not express a mis-wired install. None keeps the
        # historical production shape.
        self.app = None if app is None else dict(app)
        self.app_calls = 0
        self.raise_on_application = None   # world-check transient double
        # THE ACCOUNT SET IS A PARAMETER, and a fixture that hardcodes it is
        # the root cause of a whole class of blind spot. Returning exactly one
        # account, always, means no test in the suite can build a renewal whose
        # returned set is a SUPERSET of the bound set — which is the only shape
        # that passes `flows.verify_accounts` and therefore the only shape that
        # reaches `_renewal_precondition`'s exact-set comparison at all. The
        # test named for that comparison stopped at the whitelist check
        # instead, and the comparison itself was killed by nothing. A fixture
        # that pins a field cannot find a bug in it.
        self.accounts = None if accounts is None else [dict(a) for a in accounts]
        self.deleted = []
        self.auths = []
        # The redirect URI `start_auth` was actually sent, recorded separately
        # so a test can prove the ONE discovered string reaches all three
        # consumers (mint, start_auth, add_redirect_url).
        self.auth_redirects = []
        self.tx_calls = []
        self.balance_calls = 0
        self.raise_on_balances = None
        # A DELETE that fails deletes nothing — `deleted` stays empty, exactly
        # as the provider leaves the consent live. A double that
        # recorded the id and then raised would let a caller "prove" the
        # revocation happened.
        self.raise_on_delete = None

    @property
    def uid(self):
        return "uid-" + self.iban[-4:]

    def application(self):
        """`GET /application` under the APPLICATION's own JWT.

        Deliberately WITHOUT `redirect_urls`. Whether the AIS view carries
        that field is UNVERIFIED — the one live read of this endpoint recorded
        `name`, `environment` and `services` and nothing else — and a double
        that invents it would let a caller "check the redirect URI" against a
        field that may never be there, reporting "healthy, redirect present"
        from an absent key. The redirect question belongs to
        `eb_admin.Admin.add_redirect_url`, which does its own read-modify-write
        against the control panel, where the field is known to live.
        """
        self.app_calls += 1
        if self.raise_on_application is not None:
            raise self.raise_on_application
        if self.app is not None:
            return dict(self.app)
        return {"app_id": "app-1", "name": "casa-finance",
                "environment": "PRODUCTION", "active": True,
                "services": ["AIS"]}

    def aspsps(self, country):
        return [{"name": "Rabobank", "country": country,
                 "psu_types": ["personal", "business"],
                 "maximum_consent_validity": 15552000}]

    def start_auth(self, aspsp, country, psu_type, state, redirect_uri,
                   valid_days=179):
        self.auths.append((aspsp, country, psu_type, state, valid_days))
        self.auth_redirects.append(redirect_uri)
        return {"url": "https://tpp.enablebanking.com/auth?x=1",
                "authorization_id": "az"}

    def create_session(self, code):
        accounts = self.accounts
        if accounts is None:
            accounts = [acct(self.iban, uid=self.uid)]
        return {"session_id": self.session_id,
                "aspsp": {"name": self.bank, "country": self.country},
                "access": {"valid_until": SESSION_VALID_UNTIL},
                "accounts": [dict(a) for a in accounts]}

    def delete_session(self, sid):
        if self.raise_on_delete is not None:
            raise self.raise_on_delete
        self.deleted.append(sid)
        return {"deleted": True}

    def balances(self, uid):
        self.balance_calls += 1
        if self.raise_on_balances is not None:
            raise self.raise_on_balances
        return [{"balance_type": "CLBD", "reference_date": "2026-08-03",
                 "balance_amount": {"currency": "EUR", "amount": "12.34"}}]

    def transactions(self, uid, date_from, continuation_key=None):
        self.tx_calls.append((uid, date_from, continuation_key))
        return [], None


def acct(iban, uid=None, name="Betaalrekening", currency="EUR"):
    """One account inside a provider session payload.

    The IBAN is NESTED under `account_id`, exactly as the provider nests it and
    as `_exchange` has to unwrap it; a flat `iban` key is the LEDGER's shape and
    reading it here found nothing in production.
    """
    return {"uid": uid or ("uid-" + iban[-4:]), "currency": currency,
            "name": name, "account_id": {"iban": iban}}


def wl(iban, aspsp="Rabobank", country="NL"):
    """One control-panel whitelist entry, shaped the way the control panel
    really shapes it.

    Shape matters twice. The bank/country filters inside `flows` read
    `w["aspsp"]["name"]` and `["country"]`, not a flat "name" — a flat dict
    would make every account look un-whitelisted, send `link_bank` down the
    tap-1 branch, and narrow `verify_accounts` to nothing at all. And
    `flows.verify_accounts` reads the IBAN out of the human `title`, which is
    where the control panel really puts it; an entry without one verifies
    nothing.
    """
    return {"aspsp": {"name": aspsp, "country": country},
            "title": "IBAN " + iban,
            "identification_hash": "H-" + iban[-4:]}


class FakeAdmin:
    def __init__(self, whitelisted=True, ibans=(LINKED_IBAN,), entries=None,
                 redirect_urls=(DISCOVERED_REDIRECT,)):
        self._whitelisted = whitelisted
        # `entries` is the honest production shape: the whitelist belongs to
        # the APPLICATION and accumulates entries for every bank ever linked.
        self._entries = (list(entries) if entries is not None
                         else [wl(iban) for iban in ibans])
        self.token = "cp-token-from-the-control-panel"
        # `add_redirect_url`'s read-modify-write state, plus the call log.
        # Defaults to ALREADY REGISTERED, which is the steady state after the
        # first setup run and therefore the one `changed: False` describes.
        self.redirect_urls = list(redirect_urls)
        self.redirect_calls = []
        self.raise_on_add_redirect = None

        # The application rung. `apps` is what GET /api/applications returns;
        # `create_calls` records registrations, and `applications_calls` counts
        # list reads so a test can assert a rung did NOT consult the control
        # panel.
        self.apps = [{"app_id": "app-1", "name": "casa-finance",
                      "environment": "PRODUCTION"}]
        self.create_calls = []
        self.applications_calls = 0
        self.application_calls = []
        self.whitelisted_calls = []
        self.link_calls = []

    def applications(self):
        self.applications_calls += 1
        return [dict(a) for a in self.apps]

    def application(self, app_id):
        """`GET /api/application/{id}` — path-bound: answers for that id
        or 404s, exactly the property the sandbox world guard's admin
        rung leans on."""
        import eb_admin
        self.application_calls.append(app_id)
        for a in self.apps:
            if str(a.get("app_id") or a.get("kid") or "") == str(app_id):
                return dict(a)
        raise eb_admin.AdminError(404, "application")

    def create_application(self, name, certificate, redirect_urls,
                           environment="PRODUCTION"):
        self.create_calls.append((name, certificate, list(redirect_urls),
                                  environment))
        # The provider lists a created app immediately; the honest double does
        # too, because rung 4 VERIFIES the response id against a fresh listing
        # before trusting it.
        self.apps.append({"app_id": "app-created", "name": name,
                          "environment": environment})
        return "app-created"

    def whitelisted(self, app_id):
        # Logged: "the guard fires BEFORE any whitelist operation" is only
        # testable if the operation leaves a trace.
        self.whitelisted_calls.append(app_id)
        return [] if not self._whitelisted else list(self._entries)

    def link_accounts(self, app_id, aspsp, country, psu_type):
        self.link_calls.append((app_id, aspsp, country, psu_type))
        return {"url": "https://enablebanking.com/whitelist?x=1"}

    def add_redirect_url(self, app_id, redirect_uri):
        """`eb_admin.Admin.add_redirect_url`'s live-verified contract.

        Idempotent by EXACT byte equality — casa matches the URI byte for byte,
        so a "near duplicate" is a different URI — and it makes NO request at
        all when the value is already registered, which is what lets
        `setup_bank_feed` call it unconditionally instead of branching on a read
        it would have to perform anyway. Existing entries are preserved,
        because a PATCH replaces `redirect_urls` wholesale.
        """
        self.redirect_calls.append((app_id, redirect_uri))
        if self.raise_on_add_redirect is not None:
            raise self.raise_on_add_redirect
        if redirect_uri in self.redirect_urls:
            return {"changed": False, "redirect_urls": list(self.redirect_urls)}
        self.redirect_urls.append(redirect_uri)
        return {"changed": True, "redirect_urls": list(self.redirect_urls)}


class FakeVault:
    """opvault as tools_auth sees it: a dict of op:// refs plus the
    recording surfaces the setup tests assert on. `create_ssh_key`
    deposits the REAL fixture key, because the forge path re-reads and
    PARSES what it created — a double that deposits garbage would make
    the verified-read-back rung untestable."""

    VAULT = "ExampleVault"
    KEY_ITEM = "EnableBanking Key"
    CRED_ITEM = "EnableBanking"
    REF_PRIVATE_KEY = "op://ExampleVault/EnableBanking Key/private key"
    REF_REFRESH_TOKEN = "op://ExampleVault/EnableBanking/refresh token"
    REF_EMAIL = "op://ExampleVault/EnableBanking/username"

    def __init__(self, values=None, usable=True):
        import opvault
        self.OpError = opvault.OpError
        self.values = dict(values or {})
        self.usable = usable
        self.set_calls = []
        self.upsert_calls = []
        self.created = []
        self.reads = []           # every ref read() was asked for, in order
        self.fail_reads = {}      # ref -> OpError to raise (transient fault)
        self.exists_error = None  # OpError item_exists should raise
        self.items = None         # None -> derived from values; else a set

    def status(self):
        return None if self.usable else "the `op` CLI is not installed on this host"

    def read(self, ref):
        # Logged BEFORE any outcome: the read-back assertions count
        # occurrences, and a read that raised still happened. An unlogged
        # read makes the read-back test vacuous.
        self.reads.append(ref)
        if not self.usable:
            raise self.OpError("op is not usable")
        if ref in self.fail_reads:
            raise self.fail_reads[ref]
        if ref not in self.values:
            # op's REAL distinction, which the forge rung branches on: a
            # missing ref is not_found=True; everything else is a fault.
            raise self.OpError("isn't an item in the \"ExampleVault\" vault",
                               not_found=True)
        return self.values[ref]

    def item_exists(self, item, vault):
        if self.exists_error is not None:
            raise self.exists_error
        if self.items is not None:
            return item in self.items
        prefix = "op://%s/%s/" % (vault, item)
        return any(k.startswith(prefix) for k in self.values)

    def set_field(self, item, vault, field, value, concealed=True):
        self.set_calls.append((item, vault, field, value, concealed))
        self.values["op://%s/%s/%s" % (vault, item, field)] = value

    def upsert_field(self, item, vault, field, value, concealed=True):
        """opvault.upsert_field as the sandbox credential rung sees it
        Recorded SEPARATELY from set_calls so a test can
        prove which writer the mode selected — that routing IS the
        behaviour under test, not an implementation detail."""
        self.upsert_calls.append((item, vault, field, value, concealed))
        self.values["op://%s/%s/%s" % (vault, item, field)] = value

    def create_ssh_key(self, title, vault):
        self.created.append((title, vault))
        self.values["op://%s/%s/private key" % (vault, title)] = TEST_KEY_PEM


class FakeFB:
    """fbauth as tools_auth sees it. Behavior is parameterised per test;
    the default is a working stored-credential world: mint succeeds."""

    def __init__(self, mint=("id-token-1", 3600.0), exchange="rt-new",
                 mint_error=None, exchange_error=None, send_error=None):
        import fbauth
        self.AuthError = fbauth.AuthError
        self.DefangedLink = fbauth.DefangedLink
        self.parse_signin_link = fbauth.parse_signin_link   # pure; real one
        self._mint, self._mint_error = mint, mint_error
        self._exchange, self._exchange_error = exchange, exchange_error
        self._send_error = send_error
        self.sent = []
        self.minted = []
        self.exchanged = []

    def send_signin_email(self, email):
        self.sent.append(email)
        if self._send_error is not None:
            raise self._send_error

    def mint_id_token(self, refresh_token):
        self.minted.append(refresh_token)
        if self._mint_error is not None:
            raise self._mint_error
        return self._mint

    def exchange_link(self, email, oob_code):
        self.exchanged.append((email, oob_code))
        if self._exchange_error is not None:
            raise self._exchange_error
        return self._exchange


def capped_backfill(ais, conn, account, session_id, **kwargs):
    """`flows.backfill`'s CAPPED return, and its durable half.

    A capped run is bound to two things: change nothing canonical,
    and persist `completeness = 'partial'`. Both halves are reproduced here,
    because the consumers under test read both — the returned dict for the
    immediate wording and `sync_state` for the durable claim. A double that
    only returned the dict would let a consumer that reads neither pass.
    """
    conn.execute(
        "INSERT INTO sync_state(account_id, resource, completeness, last_error)"
        " VALUES (?, 'transactions', 'partial', 'capped')"
        " ON CONFLICT(account_id, resource) DO UPDATE SET"
        " completeness='partial', last_error='capped'",
        (account["account_id"],))
    return {"inserted": 0, "proved_from": None, "proved_to": None,
            "shallow": True, "pages": 20, "capped": True,
            "completeness": "partial"}


#: The session that stamped the STALE `sync_state` row `silent_backfill`
#: leaves behind — an earlier consent for the same account, which is exactly
#: what a renewal whose new fetch never ran has sitting on it.
PRIOR_SESSION_ID = "3d5e9a08-24b6-4f71-b0cc-7e1a9d4f2b63"


def silent_backfill(ais, conn, account, session_id, **kwargs):
    """`flows.backfill` as a producer that reports NEITHER signal.

    This is not a hypothetical: `flows.backfill`'s success path carried no
    `capped` and no `completeness` at all until this round, so the plugin's own
    producer emitted exactly this dict — and the guard's defaults read it as a
    finished deep fetch.

    The durable half is the other half of the trap. The row it writes says
    `complete`, truthfully, about an EARLIER session; a lookup that does not
    bind to the session under test credits that evidence to this one. Nothing
    here is stamped for `session_id`, because nothing was fetched for it.
    """
    conn.execute(
        "INSERT INTO sync_state(account_id, resource, completeness,"
        " last_success_session) VALUES (?, 'transactions', 'complete', ?)"
        " ON CONFLICT(account_id, resource) DO UPDATE SET"
        " completeness='complete', last_success_session=excluded.last_success_session",
        (account["account_id"], PRIOR_SESSION_ID))
    return {"inserted": 0, "proved_from": None, "proved_to": None,
            "shallow": True, "pages": 3}


def capped_renewal(conn, ais, *, old_session_id, new_session_id, accounts,
                   secret, incarnations=None):
    """`flows.complete_renewal` when the NEW session's fetch hits the page cap.

    The ordering is the whole point of the split: the switch does not
    begin until the fetch is durably complete, so nothing moves, the old
    session stays live and bound, and `retired` comes back False — which is
    what the caller branches on.

    It calls NO `delete_session`, and returns `revoked: False` with no error:
    nothing was switched, so nothing was owed a revocation. That is exactly the
    real short-path return, and a double that reported `revoked: True`
    here would let a caller print "the old consent has been withdrawn" about a
    renewal that never happened.
    """
    summary = {}
    for account in accounts:
        summary = capped_backfill(ais, conn, account, new_session_id)
    return dict(summary, accounts=0, generation=None, retired=False,
                revoked=False, revoke_error=None)


class FakeSpool:
    """casa's spool module object. It is only ever passed through by this
    plugin — callbacks owns every read of it — so an opaque stand-in is the
    honest shape here."""


class FakeCB:
    """Stands in for the callbacks module. Records that nothing polls."""

    def __init__(self, root, outcomes=None, run=None):
        self.root = root
        self.minted = []
        self.mint_redirects = []
        self.collections = 0
        self.outcomes = outcomes or []
        self._run = run
        self.heartbeats = []
        self.noted = []
        self.declared = []

    def spool(self):
        return FakeSpool()

    def heartbeat(self, conn, state_hash, fence):
        # The real one re-stamps the lease and raises Indeterminate when
        # it has been stolen. Recording the calls is what lets a test prove the
        # exchange fences EVERY ledger write rather than only the last one.
        self.heartbeats.append((state_hash, fence))

    def discover(self, plugin_root):
        return {"plugin": "bank-feed", "plugin_dir": self.root,
                "effective": "plg-bank-feed--authorize",
                "redirect_uri": DISCOVERED_REDIRECT}

    def mint(self, conn, sp, plugin_dir, meta, redirect_uri):
        """Persist the attempt row THROUGH `callbacks.META_COLUMNS`.

        The real `callbacks.mint` writes each meta key into the attempt column
        that map names, and `fence_verdict` reads `account_id` /
        `expected_generation` back out of those columns. Writing the columns
        here by hand from a fixed list is what let the generation fence look
        wired while `_start_auth` minted neither key: the test supplied
        what the producer omitted. Driving the same map the consumer reads
        means a producer that omits a key produces a NULL column, exactly as
        it would in production.
        """
        self.minted.append(meta)
        self.mint_redirects.append(redirect_uri)
        columns = [column for _, column in callbacks.META_COLUMNS]
        values = [meta.get(key) for key, _ in callbacks.META_COLUMNS]
        conn.execute(
            "INSERT INTO attempts(state_hash, state_secret, plugin_dir,"
            " redirect_uri, created_at, phase, %s)"
            " VALUES (?,?,?,?,?, 'minted', %s)"
            % (", ".join(columns), ", ".join("?" * len(columns))),
            [hashlib.sha256(b"mint-%d" % len(self.minted)).hexdigest(),
             hashlib.sha256(b"secret-%d" % len(self.minted)).hexdigest(),
             plugin_dir, redirect_uri, FROZEN_NOW] + values)
        # The real mint returns an opaque high-entropy state, not a counter.
        return hashlib.sha256(b"state-%d" % len(self.minted)).hexdigest()

    # The three declaration entry points are DELEGATED to the real module, not
    # reimplemented. They are the whole protocol now: `collect_one` ignores the
    # exchange's return value and reads back only the fenced declarations in
    # `attempts.outcome`, so a double that merely recorded the calls would let
    # an exchange that declares nothing — or declares in the wrong order — pass
    # here and fail in production. That is the exact shape of defect this round
    # exists to stop.
    def note_session(self, conn, attempt, session_id):
        self.noted.append(session_id)
        callbacks.note_session(conn, attempt, session_id)

    def declare_verified(self, conn, attempt):
        self.declared.append("verified")
        callbacks.declare_verified(conn, attempt)

    def declare_partial(self, conn, attempt):
        self.declared.append("partial")
        callbacks.declare_partial(conn, attempt)

    # There is deliberately no `quarantine` here any more. `Base.collect` now
    # calls `callbacks._finish_exchange`, which owns the whole tail —
    # promotion, quarantine, demotion and the release of every binding. A
    # second entry point into one half of that is how the harness came to model
    # `collect_one` instead of running it.

    def run_collection(self, conn, sp, plugin_dir, exchange):
        self.collections += 1
        if self._run is not None:
            return self._run(exchange)
        return list(self.outcomes)


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = pathlib.Path(self.dir.name)
        self.raw = store.open_db(self.root / "f.sqlite")
        self.conn = Recorder(self.raw)
        tools_read.CONN = self.conn
        self.addCleanup(setattr, tools_read, "CONN", None)
        self.ais = FakeAIS()
        self.admin = FakeAdmin()
        self.cb = FakeCB(str(self.root))
        self.state_hash = STATE_HASH

        # Setup seams. The default world: op usable, refresh token
        # stored and minting, and the PRIVATE KEY present in the vault and
        # identical to the env copy — the provisioned steady state, in
        # which registration's persistence gate passes. Key-rung tests that
        # need an empty vault pop the ref.
        self.vault = FakeVault({FakeVault.REF_REFRESH_TOKEN: "rt-stored",
                                FakeVault.REF_EMAIL: "op@example.com",
                                FakeVault.REF_PRIVATE_KEY: TEST_KEY_PEM})
        self.fb = FakeFB()
        # The in-memory continuation primes eb_admin's singleton; a
        # primed minter leaking between tests would silently change which
        # credential rung every later test exercises.
        import eb_admin
        self.addCleanup(setattr, eb_admin, "_MINTER", None)
        eb_admin._MINTER = None

        for module, attr, value in (
                (tools_auth, "CB", self.cb),
                (tools_auth, "AIS_FACTORY", lambda: self.ais),
                (tools_auth, "ADMIN_FACTORY", lambda: self.admin),
                (tools_auth, "_now_s", lambda: FROZEN_NOW),
                (tools_auth, "_PROTECTED_CACHE", tools_auth._PROTECTED_CACHE),
                (tools_auth, "OPVAULT", self.vault),
                (tools_auth, "FB", self.fb)):
            self.addCleanup(setattr, module, attr, getattr(module, attr))
            setattr(module, attr, value)

        # Module-level scratch lists survive between tests inside one process,
        # and a handoff queued by an earlier test would make a later one print
        # an instruction nobody asked for.
        for attr in ("_HANDOFFS", "_INCOMPLETE", "_MISMATCHES", "_WORLD_OK"):
            self.addCleanup(getattr(tools_auth, attr).clear)
            getattr(tools_auth, attr).clear()

        saved_env = dict(os.environ)

        def restore_env():
            os.environ.clear()
            os.environ.update(saved_env)
        self.addCleanup(restore_env)

        os.environ["CLAUDE_PLUGIN_ROOT"] = str(self.root)
        os.environ["CLAUDE_PLUGIN_DATA"] = str(self.root)
        os.environ["CASA_BANKFEED_EB_APP_ID"] = "app-1"
        os.environ["CASA_BANKFEED_EB_PRIVATE_KEY"] = TEST_KEY_PEM
        # ONLY the variable .mcp.json declares. Setting the undeclared name is
        # what hides an undeclared-name defect.
        os.environ[tools_auth.ADMIN_TOKEN_VAR] = "cp-token-from-the-control-panel"
        # Unit tests must NEVER reach the real `op` binary or the
        # network: with the service token absent, opvault.status()
        # reports unusable, eb_admin's vault rung is inert, and
        # _admin() falls through to the declared env token exactly as
        # the older tests assume.
        os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", None)

    # --- helpers --------------------------------------------------------
    def admin_not_whitelisted(self):
        return FakeAdmin(whitelisted=False)

    def expected_account_id(self, iban=LINKED_IBAN):
        """The account_id apply.upsert_account will mint for FakeAIS's account.

        Derived exactly as production derives it, so a test that needs the id
        before the exchange runs cannot drift from the real keying.
        """
        return store.account_id(iban, "EUR", store.local_secret(self.raw))

    def use_capped_backfill(self):
        """Make the next fetch hit MAX_PAGES.

        Both entry points, because a renewal does not call `flows.backfill`
        directly — `flows.complete_renewal` owns the fetch-then-switch ordering
        and is the only thing `tools_auth` calls for one.
        """
        self.addCleanup(setattr, flows, "backfill", flows.backfill)
        self.addCleanup(setattr, flows, "complete_renewal",
                        flows.complete_renewal)
        flows.backfill = capped_backfill
        flows.complete_renewal = capped_renewal

    def use_silent_backfill(self):
        """Make the next fetch report NOTHING about its own completeness.

        Only `flows.backfill` — this is the first-link path, and the point is a
        producer that returns normally while claiming neither success nor a cap.
        """
        self.addCleanup(setattr, flows, "backfill", flows.backfill)
        flows.backfill = silent_backfill

    def marker(self, state_hash=None):
        """The fenced declaration in `attempts.outcome` — the ONLY thing
        `collect_one` reads back from an exchange. Defaults to the attempt the
        last `collect()` actually collected."""
        row = self.raw.execute(
            "SELECT outcome FROM attempts WHERE state_hash=?",
            (state_hash or self.state_hash,)).fetchone()
        return None if row is None else row[0]

    def collect(self, code="4/0AeanS0b7YkQ2mVx8p1LrKqf3TzN6JhWc",
                state_hash=None, crash=False):
        """Drive collect_authorization through the REAL declaration protocol.

        `exchange`'s return value is IGNORED. `collect_one` shuts
        `sessions`, `accounts`, `balances`, `transactions`, `transaction_refs`
        and `coverage` with TEMP `BEFORE` triggers that `RAISE(ABORT, …)`, runs
        the exchange, and reads back only the fenced markers the exchange left
        in `attempts.outcome`. A boolean read after the call could never prove
        the writes came after the verification; a closed database can.

        So this double closes the ledger with callbacks' own `_close_ledger`
        and delegates `note_session` / `declare_verified` / `declare_partial`
        to the real functions. An exchange that writes before it declares fails
        HERE exactly as it fails in production, rather than being waved through
        by a permissive fake — which is how the last two rounds' defects
        survived.

        **And it delegates the TAIL too**. `declare_verified`
        reopens the ledger STAGED, so the exchange can write but cannot make a
        consent live; `callbacks._finish_exchange` is what promotes a staged
        first link or contains what is not live, and `callbacks._unstage_ledger`
        is what lets those writes happen at all. This harness used to stop at
        the marker and call `_quarantine` itself — reimplementing the tail of
        the function under test, so the tests measured the harness. Everything
        past the exchange is now callbacks' own code.

        The attempt row is real too, because `declare_verified` is fenced: it
        requires `phase='exchange_started'` and this lease token, and refuses
        outright if `note_session` did not run first.

        **It collects the attempt `link_bank` actually minted**, when there is
        one. An earlier version always wrote its own row with a hard-coded
        `purpose='link'`, which overwrote the producer's — so three renewal
        tests drove `link_bank`, threw away the `purpose='renew'`, `account_id`
        and `expected_generation` it had just minted, and silently exercised
        the first-link branch instead. Discarding the producer's output and
        substituting the test's own is the exact defect class this round exists
        to eliminate, and it reappeared inside the fixture written to prevent
        it. A row is synthesised only when nothing was minted.

        `crash=True` raises after the exchange returns and before
        `collect_authorization` can emit anything — the delivery failure is
        about, driven through the public tool rather than simulated.
        """
        if state_hash is None:
            pending = self.raw.execute(
                "SELECT state_hash FROM attempts WHERE phase='minted'"
                " ORDER BY rowid DESC LIMIT 1").fetchone()
            # THE FALLBACK MUST NOT SUBSTITUTE SOMEBODY ELSE'S ATTEMPT (R4).
            # `STATE_HASH` is the "no producer ran" case and means exactly
            # that: a synthesised first-link attempt, or the re-run of one.
            # Once `link_bank` HAS minted, a bare `collect()` means "collect
            # what the producer just made" — and if nothing is pending any
            # more, quietly falling back would hand `_exchange` an older
            # attempt carrying a DIFFERENT purpose. That is the same defect as
            # the `INSERT OR REPLACE` fixture that made three renewal tests run
            # the first-link branch, with a narrower trigger, and it must fail
            # loudly rather than change what is under test.
            if pending is None and self.cb.minted:
                raise AssertionError(
                    "collect() has no minted attempt to collect, but %d were "
                    "produced in this test and all have been collected. "
                    "Falling back to the default hash would run the exchange "
                    "against an attempt with a different purpose. Pass an "
                    "explicit state_hash if you meant to re-collect one."
                    % len(self.cb.minted))
            state_hash = pending[0] if pending else STATE_HASH
        self.state_hash = state_hash
        # Promote, never replace: `purpose`, `account_id` and
        # `expected_generation` stay exactly as the producer minted them.
        promoted = self.raw.execute(
            "UPDATE attempts SET phase='exchange_started', lease_owner='t',"
            " lease_token=?, lease_expiry=? WHERE state_hash=?",
            (FENCE, time.time() + 600, state_hash)).rowcount
        if not promoted:
            self.raw.execute(
                "INSERT INTO attempts(state_hash, state_secret, aspsp_name,"
                " country, psu_type, purpose, plugin_dir, created_at, phase,"
                " lease_owner, lease_token, lease_expiry)"
                " VALUES (?,?,?,?,?,'link',?,?,'exchange_started','t',?,?)",
                (state_hash, STATE_SECRET, self.ais.bank, self.ais.country,
                 "personal", str(self.root), FROZEN_NOW, FENCE,
                 time.time() + 600))
        attempt = dict(self.raw.execute(
            "SELECT * FROM attempts WHERE state_hash=?",
            (state_hash,)).fetchone())
        attempt["lease_fence"] = FENCE

        def run(exchange):
            callbacks._close_ledger(self.raw)
            try:
                exchange(code, attempt)          # return value ignored
            finally:
                # BOTH gates come down here, exactly as `_run_exchange` drops
                # them: the tail's own promotion, quarantine and demotion are
                # writes that `_close_ledger` AND `_stage_ledger` block.
                # Dropping only the first left the staging trigger armed and
                # every promotion aborting inside SQLite.
                callbacks._open_ledger(self.raw)
                callbacks._unstage_ledger(self.raw)
            if crash:
                raise RuntimeError("casa died before the turn was delivered")
            marker = self.marker(state_hash)
            noted = self.raw.execute(
                "SELECT session_id FROM attempts WHERE state_hash=?",
                (state_hash,)).fetchone()[0]
            # THE REAL TAIL, not this harness's idea of it. `_finish_exchange`
            # promotes a staged first link, or contains what is not live —
            # quarantine, demote to REVIEW_REQUIRED at generation 0, and
            # release every account's `session_id` AND `uid`.
            #
            # This block used to reimplement that: it called `_quarantine`
            # itself and stopped at the marker. So the tests exercised the
            # harness's model of `collect_one` rather than `collect_one`, and a
            # first link that production leaves STAGED was left staged here too
            # — which reads as "no live session for this bank" and turns the
            # next renewal into a first link. Reimplementing the tail of the
            # function under test is the same defect as the `INSERT OR REPLACE`
            # fixture that made three renewal tests run the first-link branch,
            # one level up. Delegate, do not model.
            #
            # It deliberately does NOT call `_settle`: the harness leaves
            # `attempts.outcome` exactly as the exchange declared it, because
            # that marker is what these tests assert on.
            live, _phase, _outcome = callbacks._finish_exchange(
                self.raw, attempt, noted, marker)
            partial = marker == "verified_partial"
            if marker not in ("verified", "verified_partial"):
                return [callbacks.Outcome(state_hash, "review_required",
                                          "the accounts returned were not the "
                                          "ones approved")]
            if not live and not partial:
                # A declared exchange that left nothing bound to its consent.
                # Settled and acked, but not a link — and not in
                # SUCCESS_STATUSES, which is what callers branch on.
                return [callbacks.Outcome(state_hash, "review_required",
                                          "nothing was left linked to that "
                                          "consent")]
            if partial:
                return [callbacks.Outcome(
                    state_hash, "partial",
                    "the consent is good but the history is incomplete")]
            return [callbacks.Outcome(state_hash, "succeeded",
                                      "%s: 1 account" % self.ais.bank)]
        self.cb._run = run
        return call("collect_authorization")

    # --- fixtures -------------------------------------------------------
    def session(self, sid=SESSION_ID, aspsp="Rabobank",
                days=100, psu_type="personal", status=None):
        # valid_until is stored exactly as the provider sends it and as
        # _exchange writes it: an ISO *datetime*, not a bare date.
        #
        # `status` is a PARAMETER. Hardcoded to AUTHORIZED, no fixture can
        # express a session in a status the plugin does not map — which is the
        # case `consent_status`'s per-session branches used to fall through to
        # the renewal wording for.
        valid = (datetime.date.today()
                 + datetime.timedelta(days=days)).isoformat() + "T00:00:00Z"
        self.raw.execute(
            "INSERT INTO sessions(session_id, aspsp_name, country, psu_type,"
            " status, authorized_at, valid_until) VALUES (?,?,?,?,?,?,?)",
            (sid, aspsp, "NL", psu_type,
             callbacks.LIVE_SESSION_STATUS if status is None else status,
             "2026-08-01T09:14:22Z", valid))
        return valid

    def covered(self, aid="acc1", start="2020-01-01", end="2026-08-01",
                session_id=SESSION_ID):
        """Proven coverage, written by the REAL producer.

        `apply.record_coverage` is what `flows.backfill` calls, and it merges
        touching intervals on the way in — so a fixture that INSERTed rows
        directly could express a shape the producer can never emit. Two
        disjoint calls are how a genuine interior gap actually arises.

        This exists because `FakeAIS.transactions` always returns `([], None)`,
        so no test in this file ever produced a non-empty `coverage` table and
        `consent_status`'s gap loop was invisible to the whole suite.
        """
        apply.record_coverage(self.raw, aid, start, end, session_id, incarnation="")

    def account(self, aid="acc1", session_id=SESSION_ID,
                currency="EUR", included=1):
        self.raw.execute(
            "INSERT INTO accounts(account_id, uid, session_id, iban_masked, name,"
            " currency, category, included, first_seen, last_seen)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (aid, "uid-" + aid, session_id, "NL••1234", "Betaalrekening",
             currency, "personal", included, "2026-01-01", "2026-08-01"))

    def synced(self, aid="acc1", resource="balances", last_attempt_at=None,
               last_success_at=None, next_retry_after=None,
               completeness="complete", last_success_session=None):
        # `last_success_session` is WHICH session ran the fetch to exhaustion,
        # and it is half of the completeness evidence. It defaults to None
        # because that is what a row written by anything other than a completed
        # `flows.backfill` really carries.
        self.raw.execute(
            "INSERT INTO sync_state(account_id, resource, last_attempt_at,"
            " last_success_at, completeness, next_retry_after,"
            " last_success_session) VALUES (?,?,?,?,?,?,?)",
            (aid, resource, last_attempt_at, last_success_at, completeness,
             next_retry_after, last_success_session))

    def tx(self, aid="acc1", ik="ik1", booking_date="2026-02-01",
           amount_minor=1000):
        assert amount_minor >= 0            # sign lives in `direction`
        self.raw.execute(
            "INSERT INTO transactions(account_id, identity_key, occurrence,"
            " booking_date, amount_minor, currency, direction, status, state)"
            " VALUES (?,?,0,?,?, 'EUR','DBIT','BOOK','active')",
            (aid, ik, booking_date, amount_minor))

    def count(self, table):
        return self.raw.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
