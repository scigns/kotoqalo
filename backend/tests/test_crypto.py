"""Unit tests for the AES-GCM field encryption primitives, independent
of any database or KeyProvider wiring.
"""

import os

import pytest
from cryptography.exceptions import InvalidTag

from app.crypto import EphemeralKeyProvider, decrypt_field, encrypt_field


def test_round_trip_recovers_original_plaintext():
    key = os.urandom(32)
    ciphertext = encrypt_field(key, "client@example.com")
    assert decrypt_field(key, ciphertext) == "client@example.com"


def test_two_encryptions_of_the_same_plaintext_differ():
    """A fresh random nonce per call means identical plaintexts don't
    produce identical ciphertexts -- otherwise an attacker could tell
    two rows share a value just by comparing bytes, without decrypting
    anything."""
    key = os.urandom(32)
    first = encrypt_field(key, "+679 123 4567")
    second = encrypt_field(key, "+679 123 4567")
    assert first != second
    assert decrypt_field(key, first) == decrypt_field(key, second) == "+679 123 4567"


def test_tampered_ciphertext_is_rejected_not_silently_wrong():
    """GCM is authenticated encryption -- flipping a byte must raise,
    not decrypt to silently-corrupted plaintext."""
    key = os.urandom(32)
    ciphertext = bytearray(encrypt_field(key, "42 Ledger Street, Suva"))
    ciphertext[-1] ^= 0xFF  # flip the last byte (part of the GCM auth tag)

    with pytest.raises(InvalidTag):
        decrypt_field(key, bytes(ciphertext))


def test_wrong_key_cannot_decrypt():
    key_a = os.urandom(32)
    key_b = os.urandom(32)
    ciphertext = encrypt_field(key_a, "sensitive value")

    with pytest.raises(InvalidTag):
        decrypt_field(key_b, ciphertext)


def test_ephemeral_key_provider_is_stable_within_the_process():
    """The same provider instance must return the same key every call --
    a fresh key per call would make anything encrypted a moment ago
    undecryptable a moment later."""
    provider = EphemeralKeyProvider()
    assert provider.get_data_encryption_key() == provider.get_data_encryption_key()


def test_ephemeral_key_provider_differs_across_instances():
    """Two separate providers (e.g. two test runs, two process starts)
    must not coincidentally share a key."""
    assert EphemeralKeyProvider().get_data_encryption_key() != EphemeralKeyProvider().get_data_encryption_key()
