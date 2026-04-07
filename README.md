# presidio-hardened-crypto-channel

Secure cryptographic channel demonstrating ECDH key exchange, AES-256-GCM
authenticated encryption, and HMAC integrity. Used in Experiment 1 of
PRES-EDU-SEC-101 — Computer Security.

## Setup

```bash
git clone https://github.com/presidio-v/presidio-hardened-crypto-channel.git
cd presidio-hardened-crypto-channel
pip install -r requirements.txt
```

## Experiments

### Run 1 — ECDH Key Exchange

```bash
python main.py --demo keyexchange --parties Alice Bob
```

Both parties derive identical session keys without transmitting the secret.

### Run 2 — AES-256-GCM Encryption

```bash
python main.py --demo symmetric --message "Hello from Alice" --key-size 256
```

### Run 3 — Full Secure Channel

```bash
python main.py --demo channel --client Alice --server Bob --messages 10
```

### Run 4 — Break It: Remove HMAC

```bash
python main.py --demo channel --no-hmac --tamper
```

Without authentication, a tampered message is detected by the GCM tag —
demonstrating that AES-GCM provides *both* confidentiality and integrity.

### Run 5 — Measure

```bash
python main.py --demo channel --messages 100 --duration 60
python report.py --experiment 1
```

## What to Observe

- `--no-hmac --tamper`: AES-GCM's auth tag catches the flip — `InvalidTag` raised
- `--tamper` (HMAC on): HMAC check fires first, before decryption attempt
- Key takeaway: encryption provides confidentiality; GCM tag / HMAC provides integrity

## Package Structure

```
src/presidio_crypto_channel/
├── keyexchange.py   X25519 ECDH + HKDF
├── symmetric.py     AES-256-GCM
├── channel.py       Full channel with optional HMAC
└── security.py      Logging + pip-audit
```

## License

MIT
