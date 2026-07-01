import logging
import time
from dataclasses import dataclass
from typing import FrozenSet

import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.algorithms import RSAAlgorithm

from app.config import Settings, get_settings
from app.db import get_db

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=True)


class JWKSUnavailableError(Exception):
    """The JWKS source (Auth0, or a test double) could not be reached or
    parsed. Distinct from an unrecognized kid (KeyError): this means we
    don't yet know whether the token is valid, not that it's invalid."""


class JWKSClient:
    """Fetches and caches an Auth0 tenant's RS256 signing keys by `kid`."""

    def __init__(self, jwks_url: str, cache_ttl_seconds: float = 3600):
        self._jwks_url = jwks_url
        self._cache_ttl = cache_ttl_seconds
        self._cached_at = 0.0
        self._keys_by_kid: dict = {}

    def _refresh(self) -> None:
        try:
            response = httpx.get(self._jwks_url, timeout=5.0)
            response.raise_for_status()
            jwks = response.json()
            self._keys_by_kid = {key["kid"]: RSAAlgorithm.from_jwk(key) for key in jwks["keys"]}
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise JWKSUnavailableError(f"could not refresh JWKS from {self._jwks_url}") from exc
        self._cached_at = time.monotonic()

    def get_signing_key(self, kid: str):
        # No lock around _refresh(): concurrent requests racing a cache
        # miss/expiry can each independently re-fetch the JWKS (a
        # thundering-herd of a handful of redundant HTTPS calls to
        # Auth0), considered and deliberately deferred as low-priority at
        # this scale rather than adding locking complexity now.
        if not self._keys_by_kid or time.monotonic() - self._cached_at > self._cache_ttl:
            self._refresh()
        if kid not in self._keys_by_kid:
            # Key rotated since our last fetch -- refresh once before giving up.
            self._refresh()
        return self._keys_by_kid[kid]


class StaticJWKSClient(JWKSClient):
    """Test/local double: signing keys supplied directly, no network calls."""

    def __init__(self, keys_by_kid: dict):
        self._keys_by_kid = keys_by_kid
        self._cache_ttl = float("inf")
        self._cached_at = time.monotonic()

    def _refresh(self) -> None:
        raise JWKSUnavailableError("StaticJWKSClient has no remote source to refresh from")


_jwks_client: JWKSClient | None = None


def get_jwks_client(settings: Settings = Depends(get_settings)) -> JWKSClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = JWKSClient(f"https://{settings.auth0_domain}/.well-known/jwks.json")
    return _jwks_client


def decode_token(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
    jwks_client: JWKSClient = Depends(get_jwks_client),
) -> dict:
    token = credentials.credentials
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token header") from exc

    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token missing kid")

    try:
        signing_key = jwks_client.get_signing_key(kid)
    except KeyError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown signing key") from exc
    except JWKSUnavailableError as exc:
        # Distinct from "unknown signing key": we couldn't reach/parse the
        # JWKS source at all, so we don't know if the token is valid --
        # a 503 tells the client to retry, rather than a 401 implying the
        # token itself was rejected.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "auth provider unreachable") from exc

    try:
        claims = jwt.decode(
            token,
            key=signing_key,
            algorithms=["RS256"],
            audience=settings.auth0_audience,
            issuer=f"https://{settings.auth0_domain}/",
            # Small allowance for clock skew between this server and the
            # client/token issuer -- without it, a token that's still
            # genuinely valid can 401 right at the expiry boundary purely
            # because the two clocks disagree by a few seconds.
            leeway=30,
        )
    except jwt.InvalidTokenError as exc:
        # PyJWT's exception text can include claim values/internals; log
        # it server-side for debugging but never return it to the
        # client, which only needs to know the token was rejected.
        logger.info("rejected bearer token: %s", exc)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from exc

    return claims


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: str
    external_auth_subject: str
    roles: FrozenSet[str]


def get_current_user(claims: dict = Depends(decode_token), db=Depends(get_db)) -> AuthenticatedUser:
    subject = claims["sub"]
    with db.cursor() as cur:
        cur.execute(
            "SELECT id FROM users WHERE external_auth_subject = %s AND is_active",
            (subject,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "token is valid but no active local account is provisioned for this identity",
            )
        user_id = row[0]

        cur.execute(
            "SELECT role FROM user_roles WHERE user_id = %s AND revoked_at IS NULL",
            (user_id,),
        )
        roles = frozenset(r[0] for r in cur.fetchall())

    return AuthenticatedUser(user_id=str(user_id), external_auth_subject=subject, roles=roles)
