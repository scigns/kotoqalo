"""Proves RBAC is enforced at the API layer: a read-only-auditor cannot
write, and a bookkeeper cannot alter access-control settings (role
grants/revocations), even though bookkeeper can write elsewhere.

Tokens are signed locally with a throwaway RSA keypair standing in for
Auth0's JWKS -- app/auth.py's real verification path (kid lookup,
signature check, audience/issuer check) runs unmodified via
StaticJWKSClient, only the *source* of signing keys is swapped.
"""

import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.auth import StaticJWKSClient, get_jwks_client
from app.config import Settings, get_settings
from app.db import get_db
from app.main import app

TEST_KID = "test-key-1"
TEST_AUDIENCE = "https://dreamers-media-pacific-api.test"
TEST_DOMAIN = "dreamers-media-pacific.test.auth0.com"


@pytest.fixture(scope="module")
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture
def client(db, rsa_keypair):
    _, public_key = rsa_keypair
    db.cursor().execute("SET ROLE app_rw")  # matches how the real app always connects

    def _get_db_override():
        yield db

    app.dependency_overrides[get_db] = _get_db_override
    app.dependency_overrides[get_settings] = lambda: Settings(
        app_database_url="unused-in-tests", auth0_domain=TEST_DOMAIN, auth0_audience=TEST_AUDIENCE
    )
    app.dependency_overrides[get_jwks_client] = lambda: StaticJWKSClient({TEST_KID: public_key})

    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def _make_token(private_key, subject: str) -> str:
    return jwt.encode(
        {"sub": subject, "aud": TEST_AUDIENCE, "iss": f"https://{TEST_DOMAIN}/"},
        private_key,
        algorithm="RS256",
        headers={"kid": TEST_KID},
    )


def _create_user_with_roles(db, *roles: str):
    subject = f"test|{uuid.uuid4()}"
    cur = db.cursor()
    cur.execute(
        "INSERT INTO users (external_auth_subject, email, full_name) VALUES (%s, %s, 'RBAC Test User') RETURNING id",
        (subject, f"{uuid.uuid4()}@example.test"),
    )
    user_id = cur.fetchone()[0]
    for role in roles:
        cur.execute(
            "INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, %s, %s)",
            (user_id, role, user_id),
        )
    return str(user_id), subject


def test_healthz_is_public(client):
    assert client.get("/healthz").status_code == 200


def test_unauthenticated_request_is_rejected(client):
    response = client.post("/clients", json={"display_name": "X", "country_code": "AU"})
    assert response.status_code in (401, 403)


def test_bookkeeper_can_create_client(client, db, rsa_keypair):
    private_key, _ = rsa_keypair
    _, subject = _create_user_with_roles(db, "bookkeeper")
    token = _make_token(private_key, subject)

    response = client.post(
        "/clients",
        json={"display_name": "Acme Pacific Ltd", "country_code": "AU"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201


def test_read_only_auditor_cannot_create_client(client, db, rsa_keypair):
    private_key, _ = rsa_keypair
    _, subject = _create_user_with_roles(db, "read_only_auditor")
    token = _make_token(private_key, subject)

    response = client.post(
        "/clients",
        json={"display_name": "Should Not Be Created", "country_code": "AU"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_read_only_auditor_can_read_own_identity(client, db, rsa_keypair):
    private_key, _ = rsa_keypair
    _, subject = _create_user_with_roles(db, "read_only_auditor")
    token = _make_token(private_key, subject)

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["roles"] == ["read_only_auditor"]


def test_bookkeeper_cannot_grant_roles(client, db, rsa_keypair):
    private_key, _ = rsa_keypair
    _, bookkeeper_subject = _create_user_with_roles(db, "bookkeeper")
    target_id, _ = _create_user_with_roles(db)
    token = _make_token(private_key, bookkeeper_subject)

    response = client.post(
        f"/admin/users/{target_id}/roles",
        json={"role": "bookkeeper"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_bookkeeper_cannot_revoke_roles(client, db, rsa_keypair):
    private_key, _ = rsa_keypair
    _, bookkeeper_subject = _create_user_with_roles(db, "bookkeeper")
    target_id, _ = _create_user_with_roles(db, "read_only_auditor")
    token = _make_token(private_key, bookkeeper_subject)

    response = client.delete(
        f"/admin/users/{target_id}/roles/read_only_auditor",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_read_only_auditor_cannot_grant_roles(client, db, rsa_keypair):
    private_key, _ = rsa_keypair
    _, auditor_subject = _create_user_with_roles(db, "read_only_auditor")
    target_id, _ = _create_user_with_roles(db)
    token = _make_token(private_key, auditor_subject)

    response = client.post(
        f"/admin/users/{target_id}/roles",
        json={"role": "bookkeeper"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_read_only_auditor_cannot_revoke_roles(client, db, rsa_keypair):
    private_key, _ = rsa_keypair
    _, auditor_subject = _create_user_with_roles(db, "read_only_auditor")
    target_id, _ = _create_user_with_roles(db, "bookkeeper")
    token = _make_token(private_key, auditor_subject)

    response = client.delete(
        f"/admin/users/{target_id}/roles/bookkeeper",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_owner_admin_can_grant_and_revoke_roles(client, db, rsa_keypair):
    private_key, _ = rsa_keypair
    _, owner_subject = _create_user_with_roles(db, "owner_admin")
    target_id, _ = _create_user_with_roles(db)
    token = _make_token(private_key, owner_subject)

    grant_response = client.post(
        f"/admin/users/{target_id}/roles",
        json={"role": "read_only_auditor"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert grant_response.status_code == 201

    revoke_response = client.delete(
        f"/admin/users/{target_id}/roles/read_only_auditor",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert revoke_response.status_code == 200

    cur = db.cursor()
    cur.execute(
        "SELECT revoked_at FROM user_roles WHERE user_id = %s AND role = 'read_only_auditor'",
        (target_id,),
    )
    assert cur.fetchone()[0] is not None


def test_token_for_unknown_local_account_is_rejected(client, rsa_keypair):
    private_key, _ = rsa_keypair
    token = _make_token(private_key, "test|no-such-user")

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_token_signed_by_wrong_key_is_rejected(client, db):
    """kid alone must not be enough to pass verification -- the token has
    to actually be signed by the private key matching that kid's public
    key in the JWKS."""
    other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _, subject = _create_user_with_roles(db, "owner_admin")
    forged_token = jwt.encode(
        {"sub": subject, "aud": TEST_AUDIENCE, "iss": f"https://{TEST_DOMAIN}/"},
        other_private_key,
        algorithm="RS256",
        headers={"kid": TEST_KID},
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {forged_token}"})
    assert response.status_code == 401
