"""ECDH key exchange using X25519 with HKDF session-key derivation."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .security import log_security_event


@dataclass
class Party:
    name: str
    _private_key: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate, repr=False)

    @property
    def public_key(self) -> X25519PublicKey:
        return self._private_key.public_key()

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def derive_shared_secret(self, peer_public_bytes: bytes) -> bytes:
        peer_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
        return self._private_key.exchange(peer_key)

    def derive_session_key(self, peer_public_bytes: bytes, key_length: int = 32) -> bytes:
        shared = self.derive_shared_secret(peer_public_bytes)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,
            info=b"presidio-session-key",
        ).derive(shared)


@dataclass
class KeyExchangeResult:
    party_a: str
    party_b: str
    shared_secret_hex: str
    session_key_hex: str
    key_length_bits: int
    duration_ms: float
    keys_match: bool


def run_key_exchange(party_names: list[str]) -> list[KeyExchangeResult]:
    if len(party_names) < 2:
        raise ValueError("Need at least two parties for key exchange")

    results: list[KeyExchangeResult] = []

    for i in range(0, len(party_names) - 1):
        a_name = party_names[i]
        b_name = party_names[i + 1]

        t0 = time.perf_counter()
        a = Party(a_name)
        b = Party(b_name)

        a_pub = a.public_bytes()
        b_pub = b.public_bytes()

        key_a = a.derive_session_key(b_pub)
        key_b = b.derive_session_key(a_pub)
        duration_ms = (time.perf_counter() - t0) * 1000

        keys_match = key_a == key_b
        result = KeyExchangeResult(
            party_a=a_name,
            party_b=b_name,
            shared_secret_hex=key_a.hex()[:16] + "...",
            session_key_hex=key_a.hex(),
            key_length_bits=len(key_a) * 8,
            duration_ms=round(duration_ms, 3),
            keys_match=keys_match,
        )
        results.append(result)

        log_security_event(
            "key_exchange_complete",
            party_a=a_name,
            party_b=b_name,
            key_bits=result.key_length_bits,
            match=keys_match,
        )

    return results
