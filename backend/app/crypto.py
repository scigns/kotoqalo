"""Field-level encryption for PII and banking-identifier columns.

Design: application-layer AES-256-GCM (not pgcrypto with a DB-resident
key -- a static key living in the same database it protects defeats the
point; anyone with DB access would also have the key). The data
encryption key itself is sourced from a KeyProvider, never hardcoded and
never derived from a static value, per the non-negotiable requirement
this phase exists to satisfy.

KeyProvider has exactly one production-track implementation planned
(InfisicalKeyProvider, stubbed -- see below) and one dev/test
implementation (EphemeralKeyProvider). Which one is active is selected
by Settings.key_provider, the same placeholder-until-provisioned pattern
already used for AUTH0_DOMAIN/AUTH0_AUDIENCE.
"""

import os
from abc import ABC, abstractmethod
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends

from app.config import Settings, get_settings

_NONCE_LENGTH = 12  # bytes; standard for AES-GCM


class KeyProvider(ABC):
    """Supplies the 256-bit data-encryption key used for AES-GCM field
    encryption. Implementations decide *where* the key lives; callers
    never know or care."""

    @abstractmethod
    def get_data_encryption_key(self) -> bytes:
        ...


class EphemeralKeyProvider(KeyProvider):
    """Dev/test only. Generates a fresh random 256-bit key once, held in
    memory for the process's lifetime -- never written to disk, .env, or
    anywhere persistent, and never a fixed/hardcoded value. Encrypted
    data does not survive a process restart under this provider; that's
    an accepted limitation for local development, not something this
    class works around.
    """

    def __init__(self):
        self._key = os.urandom(32)

    def get_data_encryption_key(self) -> bytes:
        return self._key


class InfisicalKeyProvider(KeyProvider):
    """Production target: fetches the data-encryption key from an
    Infisical project via a machine identity (Universal Auth).

    NOT YET IMPLEMENTED. This class defines the configuration shape
    (host, project, environment, secret path/name, machine identity
    client ID/secret) that will be needed, but deliberately does not
    implement the actual login/secret-retrieval HTTP calls -- the exact
    Infisical REST API/SDK surface is not something to guess at from
    memory. Verify the current Infisical API or Python SDK
    (https://infisical.com/docs) against a real provisioned project
    before implementing get_data_encryption_key(), and test against that
    real project before this is trusted with production data.
    """

    def __init__(
        self,
        host: str,
        project_id: str,
        environment: str,
        secret_path: str,
        secret_name: str,
        client_id: str,
        client_secret: str,
    ):
        self._host = host
        self._project_id = project_id
        self._environment = environment
        self._secret_path = secret_path
        self._secret_name = secret_name
        self._client_id = client_id
        self._client_secret = client_secret

    def get_data_encryption_key(self) -> bytes:
        raise NotImplementedError(
            "InfisicalKeyProvider is not implemented yet -- verify the current "
            "Infisical Universal Auth login flow and secret-retrieval endpoint "
            "against https://infisical.com/docs (or the official SDK) against a "
            "real provisioned Infisical project, then implement this method and "
            "test it before using in production."
        )


_key_provider: KeyProvider | None = None


def get_key_provider(settings: Settings = Depends(get_settings)) -> KeyProvider:
    global _key_provider
    if _key_provider is not None:
        return _key_provider

    if settings.key_provider == "ephemeral":
        _key_provider = EphemeralKeyProvider()
    elif settings.key_provider == "infisical":
        _key_provider = InfisicalKeyProvider(
            host=settings.infisical_host,
            project_id=settings.infisical_project_id,
            environment=settings.infisical_environment,
            secret_path=settings.infisical_secret_path,
            secret_name=settings.infisical_secret_name,
            client_id=settings.infisical_client_id,
            client_secret=settings.infisical_client_secret,
        )
    else:
        raise ValueError(f"unknown key_provider: {settings.key_provider!r}")

    return _key_provider


def encrypt_field(key: bytes, plaintext: str) -> bytes:
    """Returns nonce || ciphertext (GCM's authentication tag is included
    in the ciphertext AESGCM produces). A fresh random nonce is used for
    every call, per AES-GCM's requirement that a (key, nonce) pair is
    never reused."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(_NONCE_LENGTH)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ciphertext


def decrypt_field(key: bytes, blob: bytes) -> str:
    """Raises cryptography.exceptions.InvalidTag if the ciphertext was
    tampered with or the key is wrong -- GCM authenticates as well as
    encrypts, it does not silently return garbage."""
    nonce, ciphertext = blob[:_NONCE_LENGTH], blob[_NONCE_LENGTH:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
