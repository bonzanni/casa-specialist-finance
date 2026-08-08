# Test fixtures

These files exist to drive the test suite and protect nothing.

- `test_rsa_2048.pem`, `test_rsa_2048_b.pem` — throwaway RSA private keys used
  as signing inputs. They are generated, never used against any provider, and
  can be regenerated at any time:

      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out <file>

  `tests/test_jwtsign.py` pins the SPKI public key openssl derives from
  `test_rsa_2048.pem`. After regenerating, recapture that constant with
  `openssl pkey -in tests/fixtures/test_rsa_2048.pem -pubout` — from openssl,
  never from the module under test, or the cross-check becomes circular.

- IBAN-shaped values in these fixtures are **checksum-invalid by
  construction** (`NL00` check digits, which are never valid). A fixture must
  never contain a checksum-valid account number; `scripts/scan_identifiers.py`
  enforces this.
