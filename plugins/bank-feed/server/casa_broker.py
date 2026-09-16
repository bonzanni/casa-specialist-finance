# plugins/bank-feed/server/casa_broker.py
"""Hand a link the operator must open to casa, which posts it in their chat.

casa >= v0.318.0's result contract lets a `capability` tool declare that one of
its slots is `delivers`-ed as an `operator_link` (ha-casa-app#1015). The tool
does not return the URL. During the call it DEPOSITS the URL with casa's broker,
over the internal Unix socket named by `$CASA_BROKER_SOCKET`, as the client named
by `$CASA_BROKER_CLIENT` (casa puts both in this server's environment). casa
answers with a reference, and the tool returns that reference in the slot's
field. After the result passes casa's structural check, casa posts ONE message
to the operator's chat: a link whose text is the label plus the host casa prints
from the URL, with the caption beneath it. So the URL never enters the model's
context, and never the chat or topic the model happens to be in.

Protocol (casa `result_broker.py`, v0.318.0):

    POST /internal/broker/deposit
         {"client", "slot", "value", "caption"?, "label"?}
      -> {"reference": "casa-cap-<32 hex>"} | {"error": "<code>"}

casa refuses a label longer than `MAX_LABEL_CHARS`, a caption longer than
`MAX_CAPTION_CHARS`, and either one if it is not a single printable line or
contains `://` or `www.`. It also refuses a label containing anything that
reads as a domain (`DOMAINISH_RE`), because the host is casa's to print.
`fit_label` and `fit_caption` turn any input into text casa accepts, so a
bank name the provider wrote can never make a link undeliverable.

Nothing casa sends back is echoed: a reference must have casa's shape, and an
error must look like one of casa's codes, or it is reported by a fixed label.
Standard library only, like everything under `plugins/`.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import socket

#: casa contract: result_broker — the environment variable naming this server's broker client
ENV_CLIENT = "CASA_BROKER_CLIENT"
#: casa contract: result_broker — the environment variable naming the broker's Unix socket
ENV_SOCKET = "CASA_BROKER_SOCKET"
#: casa contract: result_broker — the shape of a reference casa mints
REFERENCE_RE = re.compile(r"^casa-cap-[0-9a-f]{32}$")
#: casa contract: result_broker — the longest label a delivered link may carry
MAX_LABEL_CHARS = 40
#: casa contract: result_broker — the longest caption a delivered link may carry
MAX_CAPTION_CHARS = 200
#: casa contract: result_broker — what a label may not contain: text that reads as a domain
DOMAINISH_RE = re.compile(r"\.[A-Za-z]")

DEPOSIT_ROUTE = "/internal/broker/deposit"
TIMEOUT_S = 10.0
MAX_RESPONSE_BYTES = 64 * 1024
_CODE_RE = re.compile(r"^[a-z][a-z_]{0,39}$")
_WWW_DOT_RE = re.compile(r"(?i)(www)\.")
_ELLIPSIS = "…"


class DepositFailed(Exception):
    """The link was not accepted for delivery. `code` is a casa error code, or
    one of this module's own fixed labels. It is never text casa or the
    transport wrote."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost", timeout=TIMEOUT_S)
        self._path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_S)
        try:
            sock.connect(self._path)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


def deposit_link(slot: str, url: str, *, label: str, caption: str) -> str:
    """Deposit `url` in `slot` and return casa's reference.

    Raises `DepositFailed`: `broker_env_missing` when casa gave this server no
    broker (a casa older than the result contract, or no casa at all);
    `broker_unreachable:<ExceptionClass>` on a transport failure;
    `broker_bad_response` when the answer is not a JSON object; and otherwise
    casa's own error code (`bad_link`, `no_call_in_flight`, ...), or
    `unrecognized_error` when the answer carries neither a well-formed reference
    nor anything shaped like a code.
    """
    path = os.environ.get(ENV_SOCKET, "")
    client = os.environ.get(ENV_CLIENT, "")
    if not path or not client:
        raise DepositFailed("broker_env_missing")
    body = {"client": client, "slot": slot, "value": url,
            "label": label, "caption": caption}
    conn = _UnixHTTP(path)
    try:
        conn.request("POST", DEPOSIT_ROUTE,
                     body=json.dumps(body).encode("utf-8"),
                     headers={"Content-Type": "application/json"})
        raw = conn.getresponse().read(MAX_RESPONSE_BYTES + 1)
    except Exception as exc:                     # noqa: BLE001 — the class only
        raise DepositFailed("broker_unreachable:%s" % type(exc).__name__) from None
    finally:
        conn.close()
    try:
        answer = json.loads(raw.decode("utf-8")) \
            if len(raw) <= MAX_RESPONSE_BYTES else None
    except (ValueError, RecursionError):      # malformed, or nested past the parser's depth
        answer = None
    if not isinstance(answer, dict):
        raise DepositFailed("broker_bad_response")
    reference = answer.get("reference")
    if isinstance(reference, str) and REFERENCE_RE.fullmatch(reference):
        return reference
    error = answer.get("error")
    if isinstance(error, str) and _CODE_RE.fullmatch(error):
        raise DepositFailed(error)
    raise DepositFailed("unrecognized_error")


def _one_line(text) -> str:
    """Printable, single line, whitespace collapsed, with no `://` and no `www.`.

    Replacements run until nothing changes, so a replacement cannot create a
    new occurrence (for example `wwww..` -> `wwww.`). Each pass removes at
    least one occurrence and adds none of the other kind, so the loop ends.
    """
    s = "".join(ch if ch.isprintable() else " "
                for ch in ("" if text is None else str(text)))
    s = " ".join(s.split())
    while True:
        new = _WWW_DOT_RE.sub(r"\1", s.replace("://", ": //"))
        if new == s:
            return s
        s = new


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:max(limit - 1, 0)].rstrip() + _ELLIPSIS


def fit_caption(text, limit: int = MAX_CAPTION_CHARS) -> str:
    """`text` as a caption casa accepts, at most `limit` characters (never more
    than `MAX_CAPTION_CHARS`). A shorter `limit` lets a caller clip one part it
    did not write, before joining it to text of its own."""
    return _clip(_one_line(text), min(limit, MAX_CAPTION_CHARS))


def fit_label(prefix: str, name) -> str:
    """`prefix` followed by `name`, as a label casa accepts.

    Dots are removed from `name` (`ING Bank N.V.` -> `ING Bank NV`), because a
    dot followed by a letter reads as a domain, and `name` is clipped so that
    `prefix` always survives. `prefix` is this module's caller's own literal.

    The dots go BEFORE `_one_line`, never after: removing a character joins its
    neighbours, so `Bank:.//` would become `Bank://` after the scheme separator
    had already been broken. `_one_line` adds no dot, so its output still has
    none.
    """
    room = MAX_LABEL_CHARS - len(prefix)
    raw = "" if name is None else str(name)
    return prefix + _clip(_one_line(raw.replace(".", "")), room)
