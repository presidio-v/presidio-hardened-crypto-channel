"""Tests for ECDH key exchange."""

from presidio_crypto_channel.keyexchange import Party, run_key_exchange


def test_party_generates_key():
    p = Party("Alice")
    assert len(p.public_bytes()) == 32


def test_shared_secret_is_symmetric():
    a = Party("Alice")
    b = Party("Bob")
    key_a = a.derive_session_key(b.public_bytes())
    key_b = b.derive_session_key(a.public_bytes())
    assert key_a == key_b


def test_session_key_is_32_bytes():
    a = Party("Alice")
    b = Party("Bob")
    key = a.derive_session_key(b.public_bytes())
    assert len(key) == 32


def test_different_parties_different_keys():
    a = Party("Alice")
    b = Party("Bob")
    c = Party("Carol")
    key_ab = a.derive_session_key(b.public_bytes())
    key_ac = a.derive_session_key(c.public_bytes())
    assert key_ab != key_ac


def test_run_key_exchange_two_parties(alice_bob_names):
    results = run_key_exchange(alice_bob_names)
    assert len(results) == 1
    r = results[0]
    assert r.keys_match
    assert r.key_length_bits == 256
    assert r.duration_ms > 0


def test_run_key_exchange_requires_two():
    import pytest

    with pytest.raises(ValueError):
        run_key_exchange(["Alice"])
