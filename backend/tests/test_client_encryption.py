"""Proves field-level encryption end-to-end through the real API: a
client's contact details are unreadable in a raw database dump/psql
session without the key, and correct when read back through the app
layer, per the non-negotiable requirement this satisfies.
"""

import uuid

from conftest import make_token


def _owner_token(db, rsa_keypair):
    private_key, _ = rsa_keypair
    cur = db.cursor()
    cur.execute(
        "INSERT INTO users (external_auth_subject, email, full_name) VALUES ('test|encryption-owner', 'owner@example.test', 'Owner') RETURNING id"
    )
    user_id = cur.fetchone()[0]
    cur.execute("INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, 'owner_admin', %s)", (user_id, user_id))
    return make_token(private_key, "test|encryption-owner")


def test_client_contact_details_round_trip_through_the_app_layer(client, db, rsa_keypair):
    token = _owner_token(db, rsa_keypair)

    create_response = client.post(
        "/clients",
        json={
            "display_name": "Pacific Development Partners",
            "country_code": "FJ",
            "contact_email": "finance@pacificdev.example",
            "contact_phone": "+679 555 0134",
            "billing_address": "17 Victoria Parade, Suva, Fiji",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert create_response.status_code == 201
    client_id = create_response.json()["id"]

    read_response = client.get(f"/clients/{client_id}", headers={"Authorization": f"Bearer {token}"})
    assert read_response.status_code == 200
    body = read_response.json()
    assert body["contact_email"] == "finance@pacificdev.example"
    assert body["contact_phone"] == "+679 555 0134"
    assert body["billing_address"] == "17 Victoria Parade, Suva, Fiji"


def test_client_contact_details_are_unreadable_via_raw_sql(client, db, rsa_keypair):
    """The core proof this phase requires: reading the raw bytea column
    directly (as any psql session or database dump would see it, with no
    knowledge of the app's KeyProvider) must not expose the plaintext
    anywhere in the stored bytes.
    """
    token = _owner_token(db, rsa_keypair)
    secret_email = "do-not-leak-this@pacificdev.example"
    secret_phone = "+679 999 8888"
    secret_address = "Confidential Compound, Nadi, Fiji"

    create_response = client.post(
        "/clients",
        json={
            "display_name": "Confidential Client Pty Ltd",
            "country_code": "FJ",
            "contact_email": secret_email,
            "contact_phone": secret_phone,
            "billing_address": secret_address,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert create_response.status_code == 201
    client_id = create_response.json()["id"]

    # Raw read, bypassing the app layer entirely -- this is exactly what
    # `psql` or a database dump would see.
    raw_cur = db.cursor()
    raw_cur.execute(
        "SELECT contact_email_encrypted, contact_phone_encrypted, billing_address_encrypted "
        "FROM clients WHERE id = %s",
        (client_id,),
    )
    email_blob, phone_blob, address_blob = raw_cur.fetchone()

    for secret, blob in [(secret_email, email_blob), (secret_phone, phone_blob), (secret_address, address_blob)]:
        raw_bytes = bytes(blob)
        assert secret.encode("utf-8") not in raw_bytes, f"plaintext {secret!r} found in raw ciphertext bytes"
        # Also check case-insensitively / substring fragments wouldn't
        # leak partial info (e.g. the domain name of the email).
        assert b"pacificdev" not in raw_bytes
        assert b"Fiji" not in raw_bytes

    # Same client, read back correctly through the app layer with the
    # right key.
    read_response = client.get(f"/clients/{client_id}", headers={"Authorization": f"Bearer {token}"})
    assert read_response.json()["contact_email"] == secret_email
    assert read_response.json()["contact_phone"] == secret_phone
    assert read_response.json()["billing_address"] == secret_address


def test_client_with_no_contact_details_has_null_encrypted_columns(client, db, rsa_keypair):
    """Optional fields stay optional -- omitting them must not encrypt an
    empty string or otherwise fabricate ciphertext for absent data."""
    token = _owner_token(db, rsa_keypair)

    create_response = client.post(
        "/clients",
        json={"display_name": "No Contact Details Ltd", "country_code": "AU"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert create_response.status_code == 201
    client_id = create_response.json()["id"]

    raw_cur = db.cursor()
    raw_cur.execute(
        "SELECT contact_email_encrypted, contact_phone_encrypted, billing_address_encrypted "
        "FROM clients WHERE id = %s",
        (client_id,),
    )
    assert raw_cur.fetchone() == (None, None, None)

    read_response = client.get(f"/clients/{client_id}", headers={"Authorization": f"Bearer {token}"})
    body = read_response.json()
    assert body["contact_email"] is None
    assert body["contact_phone"] is None
    assert body["billing_address"] is None


def test_get_nonexistent_client_is_404(client, db, rsa_keypair):
    token = _owner_token(db, rsa_keypair)
    response = client.get(f"/clients/{uuid.uuid4()}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404
