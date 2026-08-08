"""RS256 (RSASSA-PKCS1-v1_5 with SHA-256) using only the standard library.

The construction is mandated by the provider and followed literally. No CRT
path: plain pow(m, d, n) at a handful of signatures per day.
"""
from __future__ import annotations
import base64, hashlib, json, time
from typing import NamedTuple


class KeyError_(ValueError):
    """Malformed, encrypted, or unsupported private key."""


class RSAKey(NamedTuple):
    n: int
    e: int
    d: int
    size_bytes: int


# DigestInfo prefix for SHA-256, from RFC 8017
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")
_RSA_OID = bytes.fromhex("2a864886f70d010101")           # 1.2.840.113549.1.1.1


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------- DER walking
def _read_len(buf: bytes, i: int) -> tuple[int, int]:
    if i >= len(buf):
        raise KeyError_("truncated DER length")
    first = buf[i]; i += 1
    if first < 0x80:
        return first, i
    count = first & 0x7F
    if count == 0 or count > 4:
        raise KeyError_("indefinite or oversized DER length")
    if i + count > len(buf):
        raise KeyError_("truncated DER length bytes")
    length = int.from_bytes(buf[i:i + count], "big")
    if length < 0x80:
        raise KeyError_("non-canonical DER length")      # must use short form
    return length, i + count


def _read_tlv(buf: bytes, i: int, expect: int) -> tuple[bytes, int]:
    if i >= len(buf):
        raise KeyError_("truncated DER")
    tag = buf[i]
    if tag != expect:
        raise KeyError_(f"expected DER tag 0x{expect:02x}, got 0x{tag:02x}")
    length, i = _read_len(buf, i + 1)
    end = i + length
    if end > len(buf):
        raise KeyError_("DER value overruns buffer")
    return buf[i:end], end


def _read_int(buf: bytes, i: int) -> tuple[int, int]:
    raw, i = _read_tlv(buf, i, 0x02)
    if not raw:
        raise KeyError_("empty INTEGER")
    if raw[0] & 0x80:
        raise KeyError_("negative INTEGER in RSA key")
    if len(raw) > 1 and raw[0] == 0x00 and not (raw[1] & 0x80):
        raise KeyError_("non-canonical INTEGER padding")
    return int.from_bytes(raw, "big"), i


def load_pkcs8(pem: str) -> RSAKey:
    if not isinstance(pem, str) or "-----BEGIN" not in pem:
        raise KeyError_("not a PEM document")
    if "ENCRYPTED PRIVATE KEY" in pem:
        raise KeyError_("encrypted private keys are not supported")
    blocks = [b for b in pem.split("-----BEGIN ") if "PRIVATE KEY-----" in b]
    if len(blocks) != 1:
        raise KeyError_(f"expected exactly one private key, found {len(blocks)}")
    body = blocks[0].split("-----", 1)[1]
    body = body.split("-----END", 1)[0]
    try:
        der = base64.b64decode("".join(body.split()), validate=True)
    except Exception:
        raise KeyError_("PEM body is not valid base64") from None

    outer, end = _read_tlv(der, 0, 0x30)
    if end != len(der):
        raise KeyError_("trailing bytes after PrivateKeyInfo")
    version, i = _read_int(outer, 0)
    if version != 0:
        raise KeyError_(f"unsupported PKCS#8 version {version}")
    alg, i = _read_tlv(outer, i, 0x30)
    oid, j = _read_tlv(alg, 0, 0x06)
    if oid != _RSA_OID:
        raise KeyError_("key algorithm is not rsaEncryption")
    params, j = _read_tlv(alg, j, 0x05)                  # NULL parameters
    if params != b"" or j != len(alg):
        raise KeyError_("malformed rsaEncryption parameters")
    inner, i = _read_tlv(outer, i, 0x04)                 # PrivateKey OCTET STRING
    if i != len(outer):
        raise KeyError_("trailing bytes in PrivateKeyInfo")

    seq, k = _read_tlv(inner, 0, 0x30)
    if k != len(inner):
        raise KeyError_("trailing bytes after RSAPrivateKey")
    ver, m = _read_int(seq, 0)
    if ver != 0:
        raise KeyError_("multi-prime RSA keys are not supported")
    n, m = _read_int(seq, m)
    e, m = _read_int(seq, m)
    d, m = _read_int(seq, m)
    if n.bit_length() < 2048:
        raise KeyError_(f"key too small: {n.bit_length()} bits (minimum 2048)")
    if e < 3 or e % 2 == 0:
        raise KeyError_("invalid public exponent")
    if not (1 < d < n):
        raise KeyError_("invalid private exponent")
    return RSAKey(n=n, e=e, d=d, size_bytes=(n.bit_length() + 7) // 8)


# ---------------------------------------------------------------- signing
def _emsa_pkcs1_v15(digest: bytes, size_bytes: int) -> bytes:
    t = _SHA256_DIGESTINFO + digest
    if size_bytes < len(t) + 11:
        raise KeyError_("modulus too small for PKCS#1 v1.5 SHA-256")
    padding = b"\xff" * (size_bytes - len(t) - 3)
    return b"\x00\x01" + padding + b"\x00" + t


def sign(message: bytes, key: RSAKey) -> bytes:
    em = _emsa_pkcs1_v15(hashlib.sha256(message).digest(), key.size_bytes)
    m = int.from_bytes(em, "big")
    if m >= key.n:
        raise KeyError_("encoded message not smaller than modulus")
    s = pow(m, key.d, key.n)
    return s.to_bytes(key.size_bytes, "big")           # fixed width, left-padded


def sign_jwt(claims: dict, key: RSAKey, kid: str, ttl_s: int = 3600) -> str:
    now = int(time.time())
    payload = dict(claims)
    payload.setdefault("iat", now - 30)                # small backdated skew
    payload.setdefault("exp", now + min(ttl_s, 3600))  # well under the 86400 ceiling
    header = {"typ": "JWT", "alg": "RS256", "kid": kid}
    enc = lambda obj: _b64u(json.dumps(obj, separators=(",", ":"),
                                       sort_keys=False).encode("utf-8"))
    signing_input = f"{enc(header)}.{enc(payload)}"
    return f"{signing_input}.{_b64u(sign(signing_input.encode('ascii'), key))}"


# ---------------------------------------------------------------- DER writing
def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _enc_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(content)) + content


def _enc_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:                       # keep the INTEGER positive
        raw = b"\x00" + raw
    return _enc_tlv(0x02, raw)


def public_spki_pem(key: RSAKey) -> str:
    """The bare SubjectPublicKeyInfo PEM for this key's public half —
    byte-identical to `openssl pkey -pubout`.

    This exists because application registration takes an SPKI PEM
    (verified live: no X.509 needed) while the 1Password
    SSH-key item's `public key` field is OpenSSH-format. Deriving from the
    private key we already parse means no second format and no openssl.
    """
    rsa_pub = _enc_tlv(0x30, _enc_int(key.n) + _enc_int(key.e))
    alg = _enc_tlv(0x30, _enc_tlv(0x06, _RSA_OID) + _enc_tlv(0x05, b""))
    spki = _enc_tlv(0x30, alg + _enc_tlv(0x03, b"\x00" + rsa_pub))
    body = base64.b64encode(spki).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines)
            + "\n-----END PUBLIC KEY-----\n")
