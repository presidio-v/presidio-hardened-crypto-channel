"""AES-256-GCM authenticated encryption and SHA-256/Argon2 utilities."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .security import log_security_event

_KEY_SIZES = {128: 16, 192: 24, 256: 32}
_NONCE_SIZE = 12  # 96-bit GCM nonce


@dataclass
class EncryptResult:
    ciphertext_hex: str
    nonce_hex: str
    tag_included: bool
    plaintext_length: int
    ciphertext_length: int
    key_bits: int
    duration_ms: float


@dataclass
class DecryptResult:
    plaintext: str
    verified: bool
    duration_ms: float


def generate_key(key_size_bits: int = 256) -> bytes:
    size = _KEY_SIZES.get(key_size_bits)
    if size is None:
        raise ValueError(f"key_size_bits must be one of {list(_KEY_SIZES)}")
    return os.urandom(size)


def encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


def run_symmetric_demo(
    message: str, key_size_bits: int = 256
) -> tuple[EncryptResult, DecryptResult]:
    key = generate_key(key_size_bits)

    t0 = time.perf_counter()
    nonce, ciphertext = encrypt(message, key)
    enc_ms = (time.perf_counter() - t0) * 1000

    enc_result = EncryptResult(
        ciphertext_hex=ciphertext.hex(),
        nonce_hex=nonce.hex(),
        tag_included=True,
        plaintext_length=len(message),
        ciphertext_length=len(ciphertext),
        key_bits=key_size_bits,
        duration_ms=round(enc_ms, 3),
    )

    t1 = time.perf_counter()
    try:
        recovered = decrypt(nonce, ciphertext, key)
        verified = recovered == message
    except InvalidTag:
        recovered = ""
        verified = False
    dec_ms = (time.perf_counter() - t1) * 1000

    dec_result = DecryptResult(
        plaintext=recovered,
        verified=verified,
        duration_ms=round(dec_ms, 3),
    )

    log_security_event(
        "symmetric_demo",
        key_bits=key_size_bits,
        plaintext_len=len(message),
        verified=verified,
    )
    return enc_result, dec_result
