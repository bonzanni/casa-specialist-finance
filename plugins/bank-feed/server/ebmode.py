# plugins/bank-feed/server/ebmode.py
"""Which Enable Banking world this process lives in (sandbox-mode design,
2026-08-06).

One authority, one spelling. Every mode-derived surface — the application
name (`tools_auth`), the vault item names (`opvault`), the ledger filename
and install marker (`store`), the dispatcher banner (`bank_feed_server`) —
branches on `mode()` and never re-reads the environment variable itself:
a second reader is how `BANKFEED_EB_ENVIRONMENT` and a stray sibling
spelling would drift apart, which is the drift this aliasing prevents.

The mode is resolved ONCE per process and memoized. A server process's env
block is fixed at
spawn by `.mcp.json`, so the memo turns that deployment fact into an
in-process guarantee: the cached DB connection (`tools_read.CONN`), the
cached minter (`eb_admin._MINTER`) and the world-guard cache
(`tools_auth._WORLD_OK`) can never straddle two modes within one process,
by construction rather than by cache keying. Tests that need both modes
call `_reset()` between cases — the same discipline as resetting
`eb_admin._MINTER`.

An unrecognised value REFUSES rather than falling back to production
: a typo silently landing in the real-money world is the exact
failure this mode exists to prevent. The refusal names the variable and
the two valid values and never echoes the invalid value itself — refusal
text carries our words, not input.
"""
from __future__ import annotations

import os

ENV_MODE_VAR = "BANKFEED_EB_ENVIRONMENT"   # must equal .mcp.json's declared name
PRODUCTION = "PRODUCTION"
SANDBOX = "SANDBOX"

_MEMO = None               # resolved once per process; tests call _reset()


class ModeError(RuntimeError):
    """BANKFEED_EB_ENVIRONMENT carries an unrecognised value. Deliberately
    does not carry that value."""


def mode() -> str:
    """PRODUCTION or SANDBOX. Unset, empty or whitespace-only means
    PRODUCTION (sandbox is opt-in; the configurator leaves the variable
    unset for a production install). Matching is case-insensitive and
    stripped, so shell-quoting accidents are not refusals — only a value
    that names neither world is."""
    global _MEMO
    if _MEMO is None:
        raw = (os.environ.get(ENV_MODE_VAR) or "").strip().upper()
        if raw in ("", PRODUCTION):
            _MEMO = PRODUCTION
        elif raw == SANDBOX:
            _MEMO = SANDBOX
        else:
            raise ModeError(
                "%s carries an unrecognised value. Valid values are "
                "SANDBOX and PRODUCTION (unset means PRODUCTION). Refusing "
                "every tool until it is fixed — an unrecognised mode must "
                "never fall back to the real-money world." % ENV_MODE_VAR)
    return _MEMO


def is_sandbox() -> bool:
    return mode() == SANDBOX


def _reset() -> None:
    """Test seam ONLY: forget the memo so a test can exercise both worlds
    in one process. Production never calls this — the memo's whole point
    is that one process is one world."""
    global _MEMO
    _MEMO = None
