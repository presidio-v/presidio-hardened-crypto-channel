# Presidio-Hardened Crypto Channel — Requirements

## Overview

`presidio-hardened-crypto-channel` is a teaching and demonstration library that
implements a complete cryptographic channel: ECDH key exchange, AES-256-GCM
authenticated encryption, and HMAC integrity verification. It is used in
Experiment 1 of PRES-EDU-SEC-101 (Computer Security) to illustrate the
difference between encryption and authentication.

## Mandatory Presidio Security Extensions

- X25519 ECDH key exchange with HKDF-SHA256 session key derivation
- AES-256-GCM authenticated encryption (confidentiality + integrity in one primitive)
- HMAC-SHA256 over nonce + ciphertext as an explicit integrity layer
- `--no-hmac --tamper` mode demonstrating silent plaintext corruption without authentication
- On-import dependency audit via `pip-audit` (non-blocking if unavailable)
- Security event logging for key exchange, encryption, and channel operations
- Full GitHub security files: SECURITY.md, .github/dependabot.yml, .github/workflows/codeql.yml

## Technical Requirements

- Python 3.10+
- `cryptography>=42.0` only (no other crypto dependencies)
- `src/presidio_crypto_channel/` layout
- Thin `main.py` + `report.py` scripts at root for experiment use
- pytest ≥80% coverage
- ruff lint + format enforced
- MIT License, version 0.1.0

## Version Deliberation Log

### v0.1.0 — Initial release

**Scope decision:** X25519 (Curve25519) chosen over ECDH on P-256 because
it is simpler to use correctly (no low-order point attacks with Montgomery
ladder), has a fixed key size, and is the modern default in TLS 1.3.
For the course, the mathematical intuition (two parties compute the same
point by different paths) transfers directly from the ECDH pentagon diagram
in the lecture slides.

**Scope decision:** HMAC layer is kept *in addition* to AES-GCM's built-in
authentication tag to demonstrate the concept explicitly. In production code
you would rely on GCM's tag alone; having both is pedagogically useful for
showing that authentication can exist at different layers of the stack.

**Scope decision:** `--no-hmac --tamper` mode: since GCM always authenticates,
the tampered ciphertext will raise `InvalidTag` regardless. The demo mode
makes this explicit in the output, reinforcing the takeaway that the GCM tag
*is* the integrity mechanism even when HMAC is off.

<!-- Deliver the complete working project ready for GitHub publish. -->
