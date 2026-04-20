# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory
(via the "Security" tab → "Report a vulnerability") rather than a public issue.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 5 business days. We aim to release a patch
within 30 days of a confirmed vulnerability.

## Security Features

| Feature | Description |
|---------|-------------|
| **X25519 ECDH** | Elliptic-curve Diffie-Hellman with HKDF-SHA256 key derivation |
| **AES-256-GCM** | Authenticated encryption — confidentiality and integrity in one primitive |
| **HMAC-SHA256** | Explicit integrity layer over nonce + ciphertext |
| **No weak primitives** | No MD5, SHA-1, DES, RSA, or CBC mode anywhere in the stack |
| **Dependency audit** | `pip-audit` runs on import to detect known-vulnerable dependencies |
| **Security logging** | Structured events for all key exchange and channel operations |

## Dependency Management

- Dependabot monitors dependencies weekly.
- CodeQL runs on every push and on a weekly schedule.
- The only non-dev dependency is `cryptography>=42.0` (PyCA).

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
