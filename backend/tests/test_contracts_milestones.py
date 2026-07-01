"""Contract/milestone CRUD (standard mutability) and the audit trail now
wired into every mutating endpoint, including the Phase 2 ones
(clients, role grants/revocations).
"""

import json

from conftest import make_token


def _owner_token(db, rsa_keypair, subject="test|contracts-owner"):
    private_key, _ = rsa_keypair
    cur = db.cursor()
    cur.execute(
        "INSERT INTO users (external_auth_subject, email, full_name) VALUES (%s, %s, 'Owner') RETURNING id",
        (subject, f"{subject.replace('|', '-')}@example.test"),
    )
    user_id = cur.fetchone()[0]
    cur.execute("INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, 'owner_admin', %s)", (user_id, user_id))
    return str(user_id), make_token(private_key, subject)


def _auditor_token(db, rsa_keypair, subject="test|contracts-auditor"):
    private_key, _ = rsa_keypair
    cur = db.cursor()
    cur.execute(
        "INSERT INTO users (external_auth_subject, email, full_name) VALUES (%s, %s, 'Auditor') RETURNING id",
        (subject, f"{subject.replace('|', '-')}@example.test"),
    )
    user_id = cur.fetchone()[0]
    cur.execute("INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, 'read_only_auditor', %s)", (user_id, user_id))
    return str(user_id), make_token(private_key, subject)


def _create_client_via_api(client, token):
    response = client.post(
        "/clients",
        json={"display_name": "Contract Test Client", "country_code": "AU"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_create_and_read_contract(client, db, rsa_keypair):
    _, token = _owner_token(db, rsa_keypair)
    client_id = _create_client_via_api(client, token)

    create_response = client.post(
        "/contracts",
        json={
            "client_id": client_id,
            "title": "Digital transformation ToR",
            "currency_code": "AUD",
            "total_value": "15000.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert create_response.status_code == 201
    body = create_response.json()
    assert body["status"] == "draft"
    assert body["total_value"] == "15000.00"
    contract_id = body["id"]

    get_response = client.get(f"/contracts/{contract_id}", headers={"Authorization": f"Bearer {token}"})
    assert get_response.status_code == 200
    assert get_response.json()["title"] == "Digital transformation ToR"


def test_create_contract_for_nonexistent_client_is_404(client, db, rsa_keypair):
    _, token = _owner_token(db, rsa_keypair)
    response = client.post(
        "/contracts",
        json={
            "client_id": "00000000-0000-0000-0000-000000000000",
            "title": "Should fail",
            "currency_code": "AUD",
            "total_value": "100.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_read_only_auditor_can_read_but_not_create_contract(client, db, rsa_keypair):
    _, owner_token = _owner_token(db, rsa_keypair)
    client_id = _create_client_via_api(client, owner_token)
    create_response = client.post(
        "/contracts",
        json={"client_id": client_id, "title": "Owner-created contract", "currency_code": "AUD", "total_value": "500.00"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    contract_id = create_response.json()["id"]

    _, auditor_token = _auditor_token(db, rsa_keypair)
    read_response = client.get(f"/contracts/{contract_id}", headers={"Authorization": f"Bearer {auditor_token}"})
    assert read_response.status_code == 200

    write_response = client.post(
        "/contracts",
        json={"client_id": client_id, "title": "Auditor should not create this", "currency_code": "AUD", "total_value": "1.00"},
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert write_response.status_code == 403


def test_list_contracts_filtered_by_client(client, db, rsa_keypair):
    _, token = _owner_token(db, rsa_keypair)
    client_a = _create_client_via_api(client, token)
    client_b = _create_client_via_api(client, token)

    for title, cid in [("A1", client_a), ("A2", client_a), ("B1", client_b)]:
        client.post(
            "/contracts",
            json={"client_id": cid, "title": title, "currency_code": "AUD", "total_value": "1.00"},
            headers={"Authorization": f"Bearer {token}"},
        )

    response = client.get(f"/contracts?client_id={client_a}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    titles = {c["title"] for c in response.json()}
    assert titles == {"A1", "A2"}


def test_update_contract_partial_fields_only(client, db, rsa_keypair):
    _, token = _owner_token(db, rsa_keypair)
    client_id = _create_client_via_api(client, token)
    create_response = client.post(
        "/contracts",
        json={"client_id": client_id, "title": "Original title", "currency_code": "AUD", "total_value": "100.00"},
        headers={"Authorization": f"Bearer {token}"},
    )
    contract_id = create_response.json()["id"]

    update_response = client.patch(
        f"/contracts/{contract_id}",
        json={"status": "active"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert update_response.status_code == 200
    body = update_response.json()
    assert body["status"] == "active"
    assert body["title"] == "Original title"  # untouched by the partial update


def test_contract_create_is_audit_logged(client, db, rsa_keypair):
    user_id, token = _owner_token(db, rsa_keypair)
    client_id = _create_client_via_api(client, token)
    create_response = client.post(
        "/contracts",
        json={"client_id": client_id, "title": "Audited contract", "currency_code": "AUD", "total_value": "42.00"},
        headers={"Authorization": f"Bearer {token}"},
    )
    contract_id = create_response.json()["id"]

    cur = db.cursor()
    cur.execute(
        "SELECT actor_user_id, action, entity_type, before_state, after_state "
        "FROM audit_log WHERE entity_type = 'contract' AND entity_id = %s",
        (contract_id,),
    )
    row = cur.fetchone()
    assert row is not None
    assert str(row[0]) == user_id
    assert row[1] == "CREATE"
    assert row[2] == "contract"
    assert row[3] is None
    # psycopg3 auto-deserializes jsonb columns into Python dicts.
    after_state = row[4]
    assert after_state["title"] == "Audited contract"


def test_client_create_audit_log_excludes_contact_details(client, db, rsa_keypair):
    """Contact fields must never appear in audit_log, plaintext or
    ciphertext -- audit_log itself is not field-encrypted."""
    _, token = _owner_token(db, rsa_keypair)
    create_response = client.post(
        "/clients",
        json={
            "display_name": "Sensitive Co",
            "country_code": "AU",
            "contact_email": "should-not-appear@example.test",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    client_id = create_response.json()["id"]

    cur = db.cursor()
    cur.execute(
        "SELECT after_state FROM audit_log WHERE entity_type = 'client' AND entity_id = %s",
        (client_id,),
    )
    after_state = cur.fetchone()[0]  # psycopg3 auto-deserializes jsonb to a dict
    assert "should-not-appear" not in json.dumps(after_state)


def test_role_grant_and_revoke_are_audit_logged(client, db, rsa_keypair):
    owner_id, owner_token = _owner_token(db, rsa_keypair)
    _, target_subject_token = _auditor_token(db, rsa_keypair, subject="test|grant-target")
    del target_subject_token
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE external_auth_subject = 'test|grant-target'")
    target_id = str(cur.fetchone()[0])

    client.post(
        f"/admin/users/{target_id}/roles",
        json={"role": "bookkeeper"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    client.delete(
        f"/admin/users/{target_id}/roles/bookkeeper",
        headers={"Authorization": f"Bearer {owner_token}"},
    )

    cur.execute(
        "SELECT action FROM audit_log WHERE entity_type = 'user_role' AND entity_id = %s ORDER BY id",
        (target_id,),
    )
    actions = [row[0] for row in cur.fetchall()]
    assert actions == ["GRANT_ROLE", "REVOKE_ROLE"]


def test_create_milestone_and_list_under_contract(client, db, rsa_keypair):
    _, token = _owner_token(db, rsa_keypair)
    client_id = _create_client_via_api(client, token)
    contract_id = client.post(
        "/contracts",
        json={"client_id": client_id, "title": "Contract with milestones", "currency_code": "AUD", "total_value": "3000.00"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]

    milestone_response = client.post(
        "/milestones",
        json={"contract_id": contract_id, "title": "Discovery phase", "amount": "1000.00", "currency_code": "AUD"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert milestone_response.status_code == 201
    assert milestone_response.json()["status"] == "pending"

    list_response = client.get(f"/contracts/{contract_id}/milestones", headers={"Authorization": f"Bearer {token}"})
    assert list_response.status_code == 200
    assert len(list_response.json()) == 1
    assert list_response.json()[0]["title"] == "Discovery phase"


def test_create_milestone_for_nonexistent_contract_is_404(client, db, rsa_keypair):
    _, token = _owner_token(db, rsa_keypair)
    response = client.post(
        "/milestones",
        json={
            "contract_id": "00000000-0000-0000-0000-000000000000",
            "title": "Should fail",
            "amount": "1.00",
            "currency_code": "AUD",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_update_milestone_status(client, db, rsa_keypair):
    _, token = _owner_token(db, rsa_keypair)
    client_id = _create_client_via_api(client, token)
    contract_id = client.post(
        "/contracts",
        json={"client_id": client_id, "title": "Contract", "currency_code": "AUD", "total_value": "500.00"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    milestone_id = client.post(
        "/milestones",
        json={"contract_id": contract_id, "title": "M1", "amount": "500.00", "currency_code": "AUD"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]

    update_response = client.patch(
        f"/milestones/{milestone_id}",
        json={"status": "invoiced"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert update_response.status_code == 200
    assert update_response.json()["status"] == "invoiced"


def test_bookkeeper_can_manage_contracts_and_milestones(client, db, rsa_keypair):
    """bookkeeper should have the same write access as owner_admin for
    ordinary contract/milestone CRUD -- only access-control settings
    (role grants) are owner_admin-only."""
    private_key, _ = rsa_keypair
    cur = db.cursor()
    cur.execute(
        "INSERT INTO users (external_auth_subject, email, full_name) VALUES ('test|bk', 'bk@example.test', 'BK') RETURNING id"
    )
    bk_id = cur.fetchone()[0]
    cur.execute("INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, 'bookkeeper', %s)", (bk_id, bk_id))
    bk_token = make_token(private_key, "test|bk")

    client_id = _create_client_via_api(client, bk_token)
    contract_response = client.post(
        "/contracts",
        json={"client_id": client_id, "title": "BK contract", "currency_code": "AUD", "total_value": "10.00"},
        headers={"Authorization": f"Bearer {bk_token}"},
    )
    assert contract_response.status_code == 201
