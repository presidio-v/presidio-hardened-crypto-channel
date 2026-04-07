# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Email **security@presidio-group.eu** with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

You will receive an acknowledgement within 48 hours and a resolution within 7 days.

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
