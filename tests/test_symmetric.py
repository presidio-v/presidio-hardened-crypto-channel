"""Tests for AES-256-GCM symmetric encryption."""

import pytest

from presidio_crypto_channel.symmetric import (
    decrypt,
    encrypt,
    generate_key,
    run_symmetric_demo,
)


def test_generate_key_256():
    key = generate_key(256)
    assert len(key) == 32


def test_generate_key_128():
    key = generate_key(128)
    assert len(key) == 16


def test_generate_key_invalid():
    with pytest.raises(ValueError):
        generate_key(512)


def test_encrypt_decrypt_roundtrip():
    key = generate_key(256)
    msg = "Hello, World!"
    nonce, ct = encrypt(msg, key)
    recovered = decrypt(nonce, ct, key)
    assert recovered == msg


def test_ciphertext_is_different_each_time():
    key = generate_key(256)
    msg = "same message"
    _, ct1 = encrypt(msg, key)
    _, ct2 = encrypt(msg, key)
    assert ct1 != ct2


def test_wrong_key_raises():
    from cryptography.exceptions import InvalidTag

    key = generate_key(256)
    wrong_key = generate_key(256)
    nonce, ct = encrypt("secret", key)
    with pytest.raises(InvalidTag):
        decrypt(nonce, ct, wrong_key)


def test_tampered_ciphertext_raises():
    from cryptography.exceptions import InvalidTag

    key = generate_key(256)
    nonce, ct = encrypt("secret", key)
    tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
    with pytest.raises(InvalidTag):
        decrypt(nonce, tampered, key)


def test_run_symmetric_demo():
    enc, dec = run_symmetric_demo("Test message", 256)
    assert dec.verified
    assert dec.plaintext == "Test message"
    assert enc.key_bits == 256
    assert enc.plaintext_length == len("Test message")
