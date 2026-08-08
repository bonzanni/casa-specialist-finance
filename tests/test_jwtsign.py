# tests/test_jwtsign.py
import base64, hashlib, json, pathlib, subprocess, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "plugins/bank-feed/server"))
import jwtsign

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
PEM = (FIX / "test_rsa_2048.pem").read_text()

FIXTURE_KEY = pathlib.Path(__file__).resolve().parent / "fixtures/test_rsa_2048.pem"

# `openssl pkey -in tests/fixtures/test_rsa_2048.pem -pubout` — an
# independent implementation. If public_spki_pem and openssl ever disagree,
# openssl is right. The fixture key is throwaway and regenerable
# (tests/fixtures/README-fixtures.md); recapture this block from that command
# whenever it is regenerated.
OPENSSL_SPKI = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzCvUqhurSvqjy4r1Vd6
kdMRnn1gmi1rRUexsx6ePJ3kx3eI21CE1ji1VdjChNyaRx0BMMLyly/CXlnFzLJI
B7kQUuXafvQ58TGB3P42FTueDMEU8OxemXvwmAblcOccOwOyA61bVZXVO2mpccgX
pphyeEF0Ky+iDnxf448Tf7IV5UpFich1R1oXTwlZd+H974r0FFaOr2TsDlPqDM/i
0O3gBial9pAv06IG8bFd5Tglx5qz7OpgaqmZ4ilgOAsXGVODI0+9j2qweegNgku+
BWV7VPSevzQIkQUkspD6gryKZHdXNYN5wOQ0alzfMDLZcN6afpxL9fV/i8lh3qVC
XQIDAQAB
-----END PUBLIC KEY-----
"""


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class TestLoad(unittest.TestCase):
    def test_loads_pkcs8(self):
        k = jwtsign.load_pkcs8(PEM)
        self.assertEqual(k.e, 65537)
        self.assertGreater(k.n, 2 ** 2040)
        self.assertEqual(k.size_bytes, 256)

    def test_rejects_encrypted_key(self):
        with self.assertRaises(jwtsign.KeyError_):
            jwtsign.load_pkcs8("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n"
                               "-----END ENCRYPTED PRIVATE KEY-----\n")

    def test_rejects_garbage(self):
        for bad in ("", "not a pem",
                    "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n"):
            with self.assertRaises(jwtsign.KeyError_):
                jwtsign.load_pkcs8(bad)

    def test_rejects_truncated_der(self):
        body = "".join(PEM.strip().splitlines()[1:-1])
        raw = base64.b64decode(body)
        truncated = base64.b64encode(raw[: len(raw) // 2]).decode()
        with self.assertRaises(jwtsign.KeyError_):
            jwtsign.load_pkcs8(
                f"-----BEGIN PRIVATE KEY-----\n{truncated}\n-----END PRIVATE KEY-----\n")

    def test_fuzz_truncations_never_crash_unexpectedly(self):
        body = "".join(PEM.strip().splitlines()[1:-1])
        raw = base64.b64decode(body)
        for cut in range(1, len(raw), 97):          # sampled, keeps the suite quick
            pem = ("-----BEGIN PRIVATE KEY-----\n"
                   + base64.b64encode(raw[:cut]).decode()
                   + "\n-----END PRIVATE KEY-----\n")
            with self.assertRaises(jwtsign.KeyError_):
                jwtsign.load_pkcs8(pem)


class TestSign(unittest.TestCase):
    def test_structure_and_openssl_verification(self):
        """The authoritative check: an INDEPENDENT implementation must verify it."""
        key = jwtsign.load_pkcs8(PEM)
        token = jwtsign.sign_jwt({"iss": "enablebanking.com",
                                  "aud": "api.enablebanking.com"}, key, kid="app-123")
        header_b64, payload_b64, sig_b64 = token.split(".")

        header = json.loads(_b64u_decode(header_b64))
        self.assertEqual(header, {"typ": "JWT", "alg": "RS256", "kid": "app-123"})
        payload = json.loads(_b64u_decode(payload_b64))
        self.assertEqual(payload["iss"], "enablebanking.com")
        self.assertLess(payload["exp"] - payload["iat"], 86400)
        self.assertNotIn("=", token)                 # base64url, unpadded

        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig = _b64u_decode(sig_b64)
        self.assertEqual(len(sig), key.size_bytes)   # left-padded to modulus width

        # verify with openssl — an implementation we did not write
        try:
            FIX.joinpath("_pub.pem").write_bytes(subprocess.run(
                ["openssl", "pkey", "-in", str(FIX / "test_rsa_2048.pem"), "-pubout"],
                capture_output=True, check=True).stdout)
            FIX.joinpath("_msg.bin").write_bytes(signing_input)
            FIX.joinpath("_sig.bin").write_bytes(sig)
            proc = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(FIX / "_pub.pem"),
                 "-signature", str(FIX / "_sig.bin"), str(FIX / "_msg.bin")],
                capture_output=True, text=True)
            self.assertIn("Verified OK", proc.stdout)
        finally:
            for f in ("_pub.pem", "_msg.bin", "_sig.bin"):
                FIX.joinpath(f).unlink(missing_ok=True)

    def test_deterministic(self):
        key = jwtsign.load_pkcs8(PEM)
        a = jwtsign.sign_jwt({"x": 1, "iat": 1000, "exp": 2000}, key, kid="k")
        b = jwtsign.sign_jwt({"x": 1, "iat": 1000, "exp": 2000}, key, kid="k")
        self.assertEqual(a, b)                       # PKCS#1 v1.5 is deterministic


class TestPublicSpkiPem(unittest.TestCase):
    def test_matches_openssl_for_the_fixture_key(self):
        key = jwtsign.load_pkcs8(FIXTURE_KEY.read_text())
        self.assertEqual(jwtsign.public_spki_pem(key), OPENSSL_SPKI)

    def test_the_pem_round_trips_through_a_der_walk(self):
        # Structural self-check that does not depend on the fixture: the
        # BIT STRING payload must re-parse to the same (n, e).
        key = jwtsign.load_pkcs8(FIXTURE_KEY.read_text())
        pem = jwtsign.public_spki_pem(key)
        body = "".join(pem.splitlines()[1:-1])
        der = base64.b64decode(body, validate=True)
        outer, end = jwtsign._read_tlv(der, 0, 0x30)
        self.assertEqual(end, len(der))
        alg, i = jwtsign._read_tlv(outer, 0, 0x30)
        oid, _ = jwtsign._read_tlv(alg, 0, 0x06)
        self.assertEqual(oid, jwtsign._RSA_OID)
        bits, i = jwtsign._read_tlv(outer, i, 0x03)
        self.assertEqual(bits[0], 0x00)          # zero unused bits
        seq, _ = jwtsign._read_tlv(bits[1:], 0, 0x30)
        n, j = jwtsign._read_int(seq, 0)
        e, _ = jwtsign._read_int(seq, j)
        self.assertEqual((n, e), (key.n, key.e))


if __name__ == "__main__":
    unittest.main()
