# plugins/bank-feed/server/store.py
"""SQLite ledger: schema, forward-only migrations, and data at rest.

Identity, money and data at rest. The database is the most sensitive artifact
in the system, so the modes and the symlink checks are
part of opening it, not an afterthought applied later.

The O_NOFOLLOW checks detect a PRE-EXISTING symlink at the database or sidecar
paths. They are not symlink-race safe -- see _create_nofollow.
"""
from __future__ import annotations

import errno
import hashlib
import hmac
import os
import secrets
import sqlite3
import stat
import time
from pathlib import Path

import ebmode

SCHEMA_VERSION = 5

_PROD_DB_FILENAME = "bank_feed.sqlite"
_SANDBOX_DB_FILENAME = "bank_feed.sandbox.sqlite"
_MARKER_FILENAME = "eb-environment"
_SIDECARS = ("-wal", "-shm")


def db_filename() -> str:
    """The mode's ledger filename.

    The mode-scoped FILENAME — not the install marker — is the ledger isolation
    boundary: a sandbox process cannot compose the production path, and
    the meta table (bindings, markers, provenance) isolates with the file
    for free. Exported: `tools_read.conn()` composes its path from this, so
    the filename is spelled in exactly one place."""
    return (_SANDBOX_DB_FILENAME if ebmode.is_sandbox()
            else _PROD_DB_FILENAME)


def _other_db_filename() -> str:
    return (_PROD_DB_FILENAME if ebmode.is_sandbox()
            else _SANDBOX_DB_FILENAME)


class StoreError(Exception):
    """Anything that makes the ledger unsafe to open, trust, or migrate."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);

-- `status` vocabulary, written by the collector and by `apply`:
--   AUTHORIZED      the live consent for its bank
--   REVIEW_REQUIRED quarantined; the consent exists at the bank but nothing is
--                   bound to it
--   REVOKE_PENDING  renewed away from: no longer live here, not yet confirmed
--                   gone at the bank
--   REVOKE_FAILED   the provider refused or could not be reached
--   CLOSED          the provider confirmed the consent is gone
-- `closed_at` is the OPERATOR-VISIBLE half and is not a synonym for "we are
-- done with it": `consent_status` lists exactly `closed_at IS NULL`, so it is
-- set only once the provider has confirmed the revocation. A consent that
-- still exists at the bank stays visible and revocable by its `consent_ref`,
-- whatever we intended to do with it.
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY NOT NULL, aspsp_name TEXT, country TEXT, psu_type TEXT,
  status TEXT, authorized_at TEXT, valid_until TEXT, closed_at TEXT,
  generation INTEGER NOT NULL DEFAULT 1);

-- `aspsp` is the bank's own name as the session reported it, and it is what
-- makes the per-ASPSP capability table live in production.
-- Without it flows.backfill has no name to look up, provenance.capability()
-- always returns DEFAULT_CAPABILITY, and every ingest silently falls back to
-- heuristic windowed matching even for the rows the provider identifies
-- exactly. Empty string, not NULL: an account
-- whose ASPSP was never recorded reads as "" and resolves to the untrusted
-- default, which is the correct fail-closed direction.
CREATE TABLE IF NOT EXISTS accounts (
  account_id TEXT PRIMARY KEY NOT NULL, uid TEXT, session_id TEXT, iban_masked TEXT,
  name TEXT, product TEXT, currency TEXT, usage TEXT, label TEXT,
  category TEXT, included INTEGER NOT NULL DEFAULT 1,
  aspsp TEXT NOT NULL DEFAULT '',
  first_seen TEXT, last_seen TEXT);

CREATE TABLE IF NOT EXISTS balances (
  account_id TEXT NOT NULL, balance_type TEXT NOT NULL, amount_minor INTEGER,
  currency TEXT, reference_date TEXT, fetched_at TEXT,
  PRIMARY KEY (account_id, balance_type));

-- state is 'active' | 'superseded' | 'vanished'; superseded_by points a pending
-- row at the booked row that replaced it. match_method is
-- 'reference' | 'reference_corroborated' | 'windowed' | 'inserted'; the read
-- tools disclose the counts of heuristic and needs_review rows behind a total.
CREATE TABLE IF NOT EXISTS transactions (
  row_id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id TEXT NOT NULL, provider_ref TEXT, provider_ref_kind TEXT,
  match_method TEXT, match_confidence REAL,
  needs_review INTEGER NOT NULL DEFAULT 0,
  -- Two reasons, not one: a row can be flagged AND later vanish, and a single
  -- column would let the second cause overwrite the first. ingest emits the
  -- reason on every flag and tombstone; without somewhere to put it the read
  -- tools can say "3 need review" and never answer "why?".
  review_reason TEXT,   -- why needs_review=1 ('provider_ref_reuse',
                        -- 'unresolved_cluster', windowed-match ambiguity)
  state_reason TEXT,    -- why state is what it is (e.g. why a row went
                        -- 'vanished', or which booked row superseded it)
  identity_key TEXT NOT NULL, occurrence INTEGER NOT NULL,
  booking_date TEXT, value_date TEXT, amount_minor INTEGER NOT NULL,
  currency TEXT NOT NULL, direction TEXT NOT NULL, status TEXT,
  counterparty TEXT, remittance TEXT, raw_json TEXT,
  first_seen TEXT, last_seen TEXT,
  state TEXT NOT NULL DEFAULT 'active', superseded_by INTEGER,
  UNIQUE (account_id, identity_key, occurrence));
CREATE INDEX IF NOT EXISTS ix_tx_account_date
  ON transactions(account_id, booking_date);
CREATE INDEX IF NOT EXISTS ix_tx_ref ON transactions(account_id, provider_ref);
CREATE INDEX IF NOT EXISTS ix_tx_state ON transactions(account_id, state);
-- apply and flows look a whole identity cluster up on every pass, to floor
-- the occurrence allocation on the rows that are actually there.
CREATE INDEX IF NOT EXISTS ix_tx_identity
  ON transactions(account_id, identity_key);

-- Occurrence allocation is DURABLE, not derived from whatever rows a pass
-- happens to load. `ingest._next_occurrence` sees only the `stored`
-- list its caller supplies, and a routine refresh narrows that to roughly the
-- last booked date minus seven days -- so a monthly standing order whose
-- earlier occurrences fall outside the window re-allocates occurrence 0 and
-- collides with UNIQUE (account_id, identity_key, occurrence). This table is
-- the high-water mark: next_occurrence is one above the highest occurrence
-- EVER issued in that cluster and only ever rises.
--
-- It is also the ONLY record of a slot a re-keyed row VACATED. After a re-key
-- the transactions table no longer holds a row at the old tuple, so a floor
-- derived from the surviving rows would hand that slot straight back out.
CREATE TABLE IF NOT EXISTS occurrence_alloc (
  account_id TEXT NOT NULL,
  identity_key TEXT NOT NULL,
  next_occurrence INTEGER NOT NULL,
  updated_at TEXT,
  PRIMARY KEY (account_id, identity_key));

CREATE TABLE IF NOT EXISTS transaction_refs (
  row_id INTEGER NOT NULL, provider_ref TEXT NOT NULL, provider_ref_kind TEXT,
  first_seen TEXT, last_seen TEXT,
  PRIMARY KEY (row_id, provider_ref));

CREATE TABLE IF NOT EXISTS coverage (
  account_id TEXT NOT NULL, interval_start TEXT NOT NULL,
  interval_end TEXT NOT NULL, fetched_at TEXT, session_id TEXT,
  complete INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (account_id, interval_start, interval_end));

-- `last_success_session` is which SESSION last completed a fetch of this
-- resource, and it is the evidence a renewal switch stands on: a renewal must
-- not close the old session until the new session's deep fetch is durably
-- complete. It is deliberately NOT coverage: coverage records the
-- interval we PROVED, which for an account that returned no rows is nothing at
-- all, while this records that the retrieval itself ran to exhaustion. A
-- dormant account therefore renews normally, and we still never claim to have
-- proven an interval the bank may simply have truncated.
CREATE TABLE IF NOT EXISTS sync_state (
  account_id TEXT NOT NULL, resource TEXT NOT NULL,
  last_attempt_at TEXT, last_success_at TEXT, completeness TEXT,
  last_error TEXT, next_retry_after TEXT, oldest_fetched TEXT,
  last_success_session TEXT,
  PRIMARY KEY (account_id, resource));

-- Per-ASPSP reference behaviour. Read through provenance.capability(); an
-- absent row is untrusted, not stable. `provenance` records where the claim
-- came from, so a trust claim can be audited and retired when it turns out to
-- be wrong. No row ships: trust is per-installation and is earned by local
-- observation (issue #7), never inherited.
CREATE TABLE IF NOT EXISTS aspsp_capability (
  aspsp TEXT PRIMARY KEY NOT NULL,
  ref_stable INTEGER NOT NULL DEFAULT 0,
  ref_scope TEXT NOT NULL DEFAULT 'unknown',
  observed_n INTEGER NOT NULL DEFAULT 0,
  provenance TEXT NOT NULL DEFAULT '',
  updated_at TEXT);

-- Rows the v5 migration took out of `aspsp_capability`, kept verbatim.
--
-- v5 retires capability rows written by a seeder that shipped one
-- installation's measurements as every installation's defaults. Identifying
-- them can only be done from their provenance text, and no text predicate is
-- exact: a local note deliberately shaped like the seed's would match. So the
-- migration does not DESTROY anything. It moves matched rows here, where a
-- wrongly-matched local observation is recoverable and an operator can see
-- what stopped being honoured and why.
--
-- Nothing reads this table: `provenance.capability()` looks only at the live
-- one, so a retired row cannot influence identity no matter how it got here.
-- That is what makes over-matching the safe direction to err in.
CREATE TABLE IF NOT EXISTS aspsp_capability_retired (
  aspsp TEXT NOT NULL,
  ref_stable INTEGER NOT NULL DEFAULT 0,
  ref_scope TEXT NOT NULL DEFAULT 'unknown',
  observed_n INTEGER NOT NULL DEFAULT 0,
  provenance TEXT NOT NULL DEFAULT '',
  updated_at TEXT,
  retired_at TEXT,
  retired_by TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (aspsp, retired_by));

-- our half of the callback contract; casa owns the spool ledger.
-- `expected_generation` is the repair/renewal fence: _start_auth
-- mints the target account's CURRENT sessions.generation into the attempt, and a
-- callback whose account has since been rebound by a higher-generation session is
-- discarded BEFORE the provider is contacted. Without it a slow repair callback
-- can overwrite an account's uid/session_id after a newer renewal already bound
-- it, silently reverting the account to a stale session. Nullable: an attempt
-- that is not repairing a specific account fences nothing.
CREATE TABLE IF NOT EXISTS attempts (
  state_hash TEXT PRIMARY KEY NOT NULL, state_secret TEXT, aspsp_name TEXT, country TEXT,
  psu_type TEXT, purpose TEXT, account_id TEXT, plugin_dir TEXT,
  redirect_uri TEXT, created_at REAL, phase TEXT NOT NULL DEFAULT 'minted',
  session_id TEXT, outcome TEXT, expected_generation INTEGER,
  lease_owner TEXT, lease_token TEXT, lease_expiry REAL);

-- Operator/specialist annotations (annotation spec, 2026-08-05). Anchored to
-- row_id: an in-place re-key keeps row_id, and apply_plan re-points both
-- tables when a supersede lands, so an annotation follows the booked
-- replacement. SCHEMA_VERSION 2 exists FOR these two tables: open_db runs
-- _SCHEMA only for a fresh file or when stored < SCHEMA_VERSION, so without
-- the bump a deployed v1 ledger would never receive them.
--
-- No attribution column on tags: the note journal carries
-- the audit trail, and its `author` is a VALIDATED enum ('user'|'agent') —
-- attribution, not authentication. Notes are append-only by tool design;
-- nothing edits or deletes a note row outside the deletion sites that erase
-- its transaction.
CREATE TABLE IF NOT EXISTS transaction_tags (
  row_id INTEGER NOT NULL,
  tag TEXT NOT NULL,
  added_at TEXT,
  PRIMARY KEY (row_id, tag));
CREATE INDEX IF NOT EXISTS ix_tags_tag ON transaction_tags(tag);

CREATE TABLE IF NOT EXISTS transaction_notes (
  note_id INTEGER PRIMARY KEY AUTOINCREMENT,
  row_id INTEGER NOT NULL,
  author TEXT NOT NULL,
  note TEXT NOT NULL,
  created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_notes_row ON transaction_notes(row_id);

-- Note full-text index. External
-- content: bodies live only in transaction_notes; the index joins back by
-- note_id. Maintained by the two triggers below, which fire at every
-- deletion site because all of them use row-level DELETE statements.
-- NO UPDATE trigger, deliberately: the ONE updater of transaction_notes is
-- apply_plan's supersede migration, which rewrites row_id only — a column
-- this index does not carry (content_rowid is note_id; the sole indexed
-- column is note). Do not add one "for safety": it would churn the index
-- for text that never changes. If note text ever becomes mutable, revisit
-- this contract in the same commit.
CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(
  note,
  content='transaction_notes', content_rowid='note_id',
  tokenize='porter unicode61');

CREATE TRIGGER IF NOT EXISTS trg_notes_fts_ai
AFTER INSERT ON transaction_notes BEGIN
  INSERT INTO notes_fts(rowid, note) VALUES (new.note_id, new.note);
END;

CREATE TRIGGER IF NOT EXISTS trg_notes_fts_ad
AFTER DELETE ON transaction_notes BEGIN
  INSERT INTO notes_fts(notes_fts, rowid, note)
  VALUES ('delete', old.note_id, old.note);
END;

-- Deterministic auto-tagging rules.
-- SCHEMA_VERSION 4 exists FOR this table. Row-independent: rules survive
-- purge/forget (counterparty knowledge, not row data) but ARE deleted by
-- delete_all_data, which is operator data under a total-erasure contract.
-- `signature` is the canonical serialization of the full predicate set —
-- the duplicate-detection primitive; NULL predicates serialize explicitly
-- so SQLite NULL-distinctness cannot defeat UNIQUE.
-- All matching happens in Python (rules.py); no SQL string functions.
CREATE TABLE IF NOT EXISTS tag_rules (
  rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
  signature TEXT NOT NULL UNIQUE,
  counterparty_canon TEXT,
  remittance_token TEXT,
  direction TEXT,
  currency TEXT,
  amount_min_minor INTEGER,
  amount_max_minor INTEGER,
  dom_min INTEGER,
  dom_max INTEGER,
  weekdays TEXT,
  tags TEXT NOT NULL,
  rationale TEXT,
  created_at TEXT);
"""

# Forward-only migrations: {target_version: (sql, ...)}. Anything _SCHEMA
# cannot express idempotently (an ALTER TABLE ADD COLUMN on a table that
# already exists) belongs here, keyed by the version it produces. The v3
# backfill is NOT idempotent (rerunning it would double-insert), which is
# exactly why it lives here: _migrate runs it once, inside the same
# transaction as the DDL and the version stamp. Fresh files take the
# _SCHEMA-only path and never run it — harmless, their note table is empty.
#: SHA-256 of each provenance string the removed seeder ever wrote, over the
#: whole of this repository's history (three, stable across every version of
#: the constant). Digests rather than the strings themselves BECAUSE the
#: strings carry the per-bank measurements the seed removal exists to withhold
#: -- publishing them in the migration would undo the removal. A digest
#: identifies a row exactly and reveals nothing.
#:
#: Regenerate, if the seeder is ever recovered from history again, with:
#:     python3 -c "import hashlib,sys;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())"
SEED_PROVENANCE_DIGESTS = (
    "5171d3432d65e9ab3681f53564a026a760792d3b22d9778fa7eeb03a7c5f67d3",
    "41d34896dd9ea746d3c22345f50c33e0e423fafd40839212bb5d84fd9a03095b",
    "4e37fbe78149e2443fa2f4a918b4f34c6e099518db1f267dadc36032b757469d",
)

#: The seeder's SHAPE -- marker, ISO date, colon. A second, deliberately
#: generous arm for a row a build wrote that these digests do not know about.
#: Safe to be generous only because retiring MOVES a row rather than deleting
#: it: see the `aspsp_capability_retired` comment.
SEED_PROVENANCE_GLOB = (
    "slice 0, production [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]: *")

_SEED_DIGEST_LIST = ", ".join("'%s'" % d for d in SEED_PROVENANCE_DIGESTS)

_SEED_MATCH = ("(bankfeed_sha256(provenance) IN (%s) OR provenance GLOB '%s')"
               % (_SEED_DIGEST_LIST, SEED_PROVENANCE_GLOB))


def _register_functions(conn: sqlite3.Connection) -> None:
    """SQLite has no SHA-256, and the v5 migration needs one to recognise the
    seeded rows by digest rather than by their text."""
    conn.create_function(
        "bankfeed_sha256", 1,
        lambda s: hashlib.sha256((s or "").encode("utf-8")).hexdigest())


_MIGRATIONS = {
    3: ("INSERT INTO notes_fts(rowid, note)"
        " SELECT note_id, note FROM transaction_notes;",),
    # v5 retires capability rows written by the removed seeder. They carry one
    # installation's measurements, and an upgrade that left them in place would
    # keep presenting those as this installation's own.
    #
    # TWO arms, and neither destroys anything.
    #
    #   * by DIGEST -- exact membership in the set of strings the seeder ever
    #     wrote, without republishing those strings (they carry the
    #     measurements this removal exists to withhold).
    #   * by SHAPE -- the marker, an ISO date, a colon. A heuristic, for a row
    #     some build wrote that the digest set does not know about. It can
    #     match a local note deliberately written that way.
    #
    # On the three strings that actually exist the arms OVERLAP COMPLETELY:
    # each matches both, so removing either changes nothing about which rows
    # are retired today, and no behavioural test can tell them apart. Say
    # plainly what the digest arm buys, then, because it is not extra reach:
    # it is what stamps `retired_by` as a certainty rather than a guess, and
    # it is what keeps the exact set retired if the shape arm is ever narrowed
    # or a build writes a string outside the shape.
    #
    # A heuristic arm is only defensible because retiring MOVES a row into
    # `aspsp_capability_retired`, which nothing reads: the trust claim stops
    # being honoured either way, and a wrongly-matched local observation is
    # recoverable rather than gone. `retired_by` records which arm matched, so
    # an operator can tell a certainty from a guess.
    #
    # GLOB, not LIKE, in the shape arm: SQLite's LIKE is ASCII case-insensitive
    # and would sweep in notes differing only in case -- needless breadth even
    # when it is recoverable.
    5: ("INSERT OR REPLACE INTO aspsp_capability_retired"
        "(aspsp, ref_stable, ref_scope, observed_n, provenance, updated_at,"
        " retired_at, retired_by)"
        " SELECT aspsp, ref_stable, ref_scope, observed_n, provenance,"
        " updated_at, datetime('now'),"
        " CASE WHEN bankfeed_sha256(provenance) IN (%s)"
        " THEN 'schema v5 (seed digest)' ELSE 'schema v5 (seed shape)' END"
        " FROM aspsp_capability WHERE %s;"
        % (_SEED_DIGEST_LIST, _SEED_MATCH),
        "DELETE FROM aspsp_capability WHERE %s;" % _SEED_MATCH),
}


def _oserr(exc) -> str:
    return errno.errorcode.get(exc.errno, str(exc.errno))


def _resolve(path) -> Path:
    if path is not None:
        return Path(path)
    data = os.environ.get("CLAUDE_PLUGIN_DATA") or ""
    if not data.strip():
        raise StoreError(
            "CLAUDE_PLUGIN_DATA is not set. The finance ledger is a durable "
            "record of the operator's financial life and is never "
            "written to a shared or world-readable location, so there is no "
            "fallback path. Refusing to open the database.")
    return Path(data.strip()) / db_filename()


# --------------------------------------------------------------------------
# The install marker: one file recording which world initialised this data
# directory, so a mode flip on an existing install REFUSES instead of silently
# running a parallel world. It is an early, legible refusal — NOT the isolation
# boundary; `db_filename()` and the mode-derived vault/application names are.
# `check_mode_marker` runs at tool dispatch (bank_feed_server.handle), before
# any tool body; `commit_mode_marker` runs at `tools_read.conn()`, immediately
# AFTER the ledger opened successfully (commit rule: DB first, marker second —
# a failed open commits nothing). Both read the SAME raw CLAUDE_PLUGIN_DATA
# value conn() uses — conn()'s exact truthiness, no stripping — so a
# whitespace-only value is guarded like any other dir string, not skipped.

# Refusal texts name STATIC filenames only, never the data-directory path —
# CLAUDE_PLUGIN_DATA is externally supplied text, and a directory name carrying
# a newline would put a forged line into a line-oriented report. The operator
# knows the directory — it is their CLAUDE_PLUGIN_DATA — so the filename plus
# the remedy is the whole map.
_MODE_FLIP_REFUSAL = (
    "This install's data directory was initialised in %s mode; %s=%s does "
    "not migrate it. Flipping the environment under a bound application "
    "and a populated ledger is a different operation. To run %s, install "
    "the specialist fresh (its own data directory), or — after tearing "
    "down this install's world — the operator may remove the '%s' file "
    "from the plugin data directory deliberately.")


def _marker_path(data: str) -> Path:
    return Path(data) / _MARKER_FILENAME


def check_mode_marker(data: str | None) -> None:
    """Raise StoreError when this data directory belongs to the other
    world; no-op when CLAUDE_PLUGIN_DATA is unset/empty (tools that need
    the ledger then fail at conn() as they would anyway). Order
    matters: the other-mode ledger file refuses
    UNCONDITIONALLY — before and regardless of the marker — because a
    matching marker must not suppress the detection of a restored,
    half-initialised or race-leftover opposite-mode file."""
    if not data:
        return
    mode = ebmode.mode()
    if (Path(data) / _other_db_filename()).exists():
        raise StoreError(
            "the data directory contains the other mode's ledger file "
            "('%s'), so it belongs to the %s world. Refusing to run %s "
            "here. Remove that file deliberately (operator action) or "
            "install the specialist fresh with its own data directory."
            % (_other_db_filename(),
               "PRODUCTION" if mode == ebmode.SANDBOX else "SANDBOX",
               mode))
    marker = _marker_path(data)
    try:
        raw = marker.read_bytes()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise StoreError(
            "the install marker '%s' could not be read (%s). Refusing to "
            "guess which world this directory belongs to."
            % (_MARKER_FILENAME, _oserr(exc) if getattr(exc, "errno", None)
               else type(exc).__name__)) from None
    try:
        recorded = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        # Undecodable bytes are just one more shape of foreign content — the
        # SAME content-free refusal below, never a raw UnicodeDecodeError
        # through the error renderer.
        recorded = None
    if recorded not in (ebmode.PRODUCTION, ebmode.SANDBOX):
        # Stored content is never echoed: our refusal, our words.
        raise StoreError(
            "the install marker '%s' carries an unrecognised value. "
            "Refusing to guess which world this directory belongs to; the "
            "operator may remove the file deliberately after checking the "
            "directory." % _MARKER_FILENAME)
    if recorded != mode:
        raise StoreError(_MODE_FLIP_REFUSAL % (
            recorded, ebmode.ENV_MODE_VAR, mode, mode, _MARKER_FILENAME))


def commit_mode_marker(data: str) -> None:
    """Record this world's claim on the data directory, once, after the
    ledger opened successfully. O_EXCL: the loser of a first-open race
    re-reads and compares instead of overwriting. Any write
    failure other than EEXIST raises — fail closed; the caller (conn())
    closes the connection it just opened."""
    mode = ebmode.mode()
    marker = _marker_path(data)
    try:
        fd = os.open(str(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o600)
    except FileExistsError:
        check_mode_marker(data)          # loser: the winner's claim decides
        return
    except OSError as exc:
        raise StoreError("cannot record the install marker '%s': %s"
                         % (_MARKER_FILENAME, _oserr(exc))) from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(mode + "\n")
    except OSError as exc:
        raise StoreError("cannot record the install marker '%s': %s"
                         % (_MARKER_FILENAME, _oserr(exc))) from None


def _prepare_dir(d: Path) -> None:
    """0700 directory. The leaf is the plugin's own data dir."""
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StoreError("cannot create the ledger directory: %s" % _oserr(exc)) from None
    try:
        os.chmod(str(d), 0o700)
    except OSError as exc:
        raise StoreError("cannot tighten the ledger directory to 0700: %s"
                         % _oserr(exc)) from None


def _create_nofollow(p: Path) -> None:
    """Create/open the database at 0600, refusing a PRE-EXISTING symlink.

    Scope of the guarantee, stated narrowly on purpose: this
    detects a symlink that is already sitting at `p` and refuses. It is NOT
    symlink-RACE safe -- this fd is closed and SQLite then reopens the same
    pathname itself, so a swap in between is not caught. Race safety needs
    fd/pinned-directory semantics (openat on a held directory fd, or a VFS
    that never re-resolves), which is not built. Under casa's
    same-UID threat model this is defence in depth; do not describe it as
    more than it is.
    """
    try:
        fd = os.open(str(p), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise StoreError("refusing to open %s: it is a symlink" % p.name) from None
        raise StoreError("cannot create %s: %s" % (p.name, _oserr(exc))) from None
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _guard_nofollow(p: Path) -> None:
    """Refuse a pre-planted symlink at a sidecar path; do not create it.

    Same narrow scope as _create_nofollow: pre-existing-symlink detection
    only. A sidecar SQLite has not created yet can still be swapped after
    this check and before SQLite creates it.
    """
    try:
        fd = os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise StoreError("refusing to open %s: it is a symlink" % p.name) from None
        raise StoreError("cannot inspect %s: %s" % (p.name, _oserr(exc))) from None
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _harden(p: Path) -> None:
    try:
        os.chmod(str(p), 0o600)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise StoreError("cannot set 0600 on %s: %s" % (p.name, _oserr(exc))) from None


def _stored_version(conn: sqlite3.Connection):
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
    except sqlite3.OperationalError:
        return None                       # no meta table: a fresh file
    if row is None:
        n = conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        return 0 if n else None           # tables but no version: pre-versioning
    try:
        return int(row[0])
    except (TypeError, ValueError):
        raise StoreError("meta.schema_version is not a number; refusing to guess"
                         ) from None


def _migrate(conn: sqlite3.Connection, current: int) -> None:
    """Apply the schema, any pending migrations, and the version stamp as
    ONE transaction.

    conn runs with isolation_level=None (autocommit), and executescript()
    always issues an implicit COMMIT of any PENDING transaction before it
    runs its own script. That means a `conn.execute("BEGIN")` issued before a
    *separate* executescript(_SCHEMA) call would be committed away first (a
    no-op, since nothing had happened yet), and the schema, each migration
    statement, and the version stamp would still each commit independently.
    A failure partway would then leave a half-migrated database still
    stamped at the OLD version, and a retry would re-run migration
    statements that already applied -- not all of which (an ALTER TABLE ADD
    COLUMN, say) are idempotent.

    SQLite DDL is transactional, so instead the schema, the migrations, and
    the version stamp are assembled into ONE script carrying its own
    embedded BEGIN/COMMIT and run through a single executescript() call. A
    failure partway leaves that transaction open -- SQLite does not roll
    back for us -- so it is rolled back explicitly before the error
    propagates, and nothing this call did is left half-applied. The
    pre-migration snapshot is unchanged by this: belt and
    braces, not replaced.
    """
    statements = [_SCHEMA.strip()]        # idempotent: new tables and indexes
    for target in range(current + 1, SCHEMA_VERSION + 1):
        for sql in _MIGRATIONS.get(target, ()):
            statements.append(sql.strip().rstrip(";") + ";")
    statements.append(
        "INSERT OR REPLACE INTO meta(key, value) VALUES"
        " ('schema_version', '%d');" % SCHEMA_VERSION)
    script = "BEGIN;\n" + "\n".join(statements) + "\nCOMMIT;\n"
    try:
        conn.executescript(script)
    except sqlite3.Error:
        conn.rollback()
        raise


def _snapshot_name(db: Path) -> Path:
    base = "%s.pre-migration-%s" % (db.name, time.strftime("%Y%m%dT%H%M%SZ",
                                                           time.gmtime()))
    cand = db.parent / base
    n = 2
    while cand.exists():
        cand = db.parent / ("%s-%d" % (base, n))
        n += 1
    return cand


def snapshot_before_migration(path):
    """VACUUM INTO a snapshot beside the ledger. Returns its path, or None.

    A schema migration is the one operation that can corrupt the
    ledger in a way re-linking will not fix, so it gets a snapshot; everything
    else is reconstructible from a fresh SCA and HA's backup is the
    backup. Returns None when there is nothing yet to protect.
    """
    db = Path(path)
    try:
        st = os.lstat(str(db))
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode):
        raise StoreError("refusing to snapshot %s: it is a symlink" % db.name)
    if st.st_size == 0:
        return None
    if sqlite3.sqlite_version_info < (3, 27, 0):
        raise StoreError("VACUUM INTO needs SQLite 3.27+; this build is %s"
                         % sqlite3.sqlite_version)
    dest = _snapshot_name(db)
    prev_umask = os.umask(0o077)          # the snapshot is as sensitive as the db
    try:
        src = sqlite3.connect(str(db), isolation_level=None)
        try:
            src.execute("VACUUM INTO ?", (str(dest),))
        finally:
            src.close()
    except sqlite3.DatabaseError as exc:
        raise StoreError("pre-migration snapshot failed: %s"
                         % type(exc).__name__) from None
    finally:
        os.umask(prev_umask)
    _harden(dest)
    return str(dest)


def open_db(path=None) -> sqlite3.Connection:
    """Open the ledger with the at-rest modes, integrity check, and migrations.

    `path` omitted means $CLAUDE_PLUGIN_DATA/<db_filename()> — the
    mode's ledger. There is no fallback directory: an unset variable raises.
    This function never touches the install marker — the commit lives at
    `tools_read.conn()`, the one
    runtime chokepoint, so explicit-path test opens stay marker-free.
    """
    db = _resolve(path)
    _prepare_dir(db.parent)
    _create_nofollow(db)
    for suffix in _SIDECARS:
        _guard_nofollow(db.parent / (db.name + suffix))

    conn = sqlite3.connect(str(db), isolation_level=None)
    conn.row_factory = sqlite3.Row
    _register_functions(conn)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        checked = [r[0] for r in conn.execute("PRAGMA integrity_check")]
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise StoreError("integrity check failed: %s. The ledger is unreadable; "
                         "restore a pre-migration snapshot or re-link the banks "
                         "first." % type(exc).__name__) from None
    if checked != ["ok"]:
        conn.close()
        raise StoreError("integrity check failed: the ledger is corrupt. Restore "
                         "a pre-migration snapshot or re-link the banks; a fresh "
                         "SCA reopens each bank's history.")

    current = _stored_version(conn)
    if current is None:
        conn.executescript(_SCHEMA)
        conn.execute("INSERT OR REPLACE INTO meta(key, value)"
                     " VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
    elif current > SCHEMA_VERSION:
        conn.close()
        raise StoreError(
            "database schema v%d is newer than this plugin (v%d); migrations are "
            "forward-only and cannot go back" % (current, SCHEMA_VERSION))
    elif current < SCHEMA_VERSION:
        snapshot_before_migration(db)     # before any schema change
        _migrate(conn, current)

    _harden(db)
    for suffix in _SIDECARS:
        _harden(db.parent / (db.name + suffix))
    return conn


def local_secret(conn: sqlite3.Connection) -> bytes:
    """Per-database HMAC key, generated at first run."""
    row = conn.execute(
        "SELECT value FROM meta WHERE key='account_secret'").fetchone()
    if row is not None:
        return bytes.fromhex(row[0])
    raw = secrets.token_bytes(32)
    conn.execute("INSERT INTO meta(key, value) VALUES ('account_secret', ?)",
                 (raw.hex(),))
    return raw


def account_id(iban: str, currency: str, secret: bytes) -> str:
    """Durable, session-independent account key.

    Keyed HMAC, not a bare hash: an unsalted digest of an IBAN is trivially
    reversible by brute force over a small space. Enable Banking's
    `uid` is session-scoped and is stored only as the current session handle.
    """
    material = "%s|%s" % ((iban or "").strip().upper(),
                          (currency or "").strip().upper())
    return hmac.new(secret, material.encode("utf-8"), hashlib.sha256).hexdigest()
