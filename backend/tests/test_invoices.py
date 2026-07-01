"""Invoice generation: multi-currency, sequential numbering, PDF output,
and the ledger posting triggered by issuance -- through the chain-tip
table, not a "last row" lookup (see 0011_ledger_hash_chain.py).
"""

from conftest import make_token


def _owner(db, rsa_keypair, subject="test|invoice-owner"):
    private_key, _ = rsa_keypair
    cur = db.cursor()
    cur.execute(
        "INSERT INTO users (external_auth_subject, email, full_name) VALUES (%s, %s, 'Owner') RETURNING id",
        (subject, f"{subject.replace('|', '-')}@example.test"),
    )
    user_id = cur.fetchone()[0]
    cur.execute("INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, 'owner_admin', %s)", (user_id, user_id))
    return str(user_id), make_token(private_key, subject)


def _set_up_contract(client, token, total_value="5000.00"):
    client_id = client.post(
        "/clients", json={"display_name": "Invoice Test Client", "country_code": "AU"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    contract_id = client.post(
        "/contracts",
        json={"client_id": client_id, "title": "Test Contract", "currency_code": "AUD", "total_value": total_value},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    return client_id, contract_id


def test_create_invoice_gets_sequential_number(client, db, rsa_keypair):
    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)

    first = client.post(
        "/invoices",
        json={
            "contract_id": contract_id, "client_id": client_id, "currency_code": "AUD",
            "subtotal_amount": "1000.00", "tax_amount": "100.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    second = client.post(
        "/invoices",
        json={
            "contract_id": contract_id, "client_id": client_id, "currency_code": "AUD",
            "subtotal_amount": "500.00", "tax_amount": "50.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    ).json()

    assert first["status"] == "draft"
    assert first["total_amount"] == "1100.00"  # server-computed, never client-supplied
    assert second["invoice_seq"] == first["invoice_seq"] + 1
    assert second["invoice_number"] != first["invoice_number"]


def test_issuing_invoice_generates_pdf_and_posts_ledger(client, db, rsa_keypair):
    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)
    invoice = client.post(
        "/invoices",
        json={
            "contract_id": contract_id, "client_id": client_id, "currency_code": "AUD",
            "subtotal_amount": "1000.00", "tax_amount": "100.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    invoice_id = invoice["id"]

    issue_response = client.post(f"/invoices/{invoice_id}/issue", headers={"Authorization": f"Bearer {token}"})
    assert issue_response.status_code == 200
    issued = issue_response.json()
    assert issued["status"] == "issued"
    assert issued["issued_at"] is not None

    pdf_response = client.get(f"/invoices/{invoice_id}/pdf", headers={"Authorization": f"Bearer {token}"})
    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"] == "application/pdf"
    assert pdf_response.content[:4] == b"%PDF"

    cur = db.cursor()
    cur.execute(
        """
        SELECT a.code, e.direction, e.amount
        FROM ledger_entries e
        JOIN ledger_transactions t ON t.id = e.ledger_transaction_id
        JOIN chart_of_accounts a ON a.id = e.account_id
        WHERE t.reference_type = 'invoice_issued' AND t.reference_id = %s
        ORDER BY a.code
        """,
        (invoice_id,),
    )
    postings = {(row[0], row[1]): str(row[2]) for row in cur.fetchall()}
    assert postings[("1000", "debit")] == "1100.0000"  # Accounts Receivable, total
    assert postings[("2000", "credit")] == "100.0000"  # GST/Tax Payable
    assert postings[("4000", "credit")] == "1000.0000"  # Consulting Revenue, subtotal


def test_issue_invoice_twice_is_rejected(client, db, rsa_keypair):
    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)
    invoice_id = client.post(
        "/invoices",
        json={"contract_id": contract_id, "client_id": client_id, "currency_code": "AUD", "subtotal_amount": "100.00"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]

    client.post(f"/invoices/{invoice_id}/issue", headers={"Authorization": f"Bearer {token}"})
    second_attempt = client.post(f"/invoices/{invoice_id}/issue", headers={"Authorization": f"Bearer {token}"})
    assert second_attempt.status_code == 409


def test_issued_invoice_amount_is_frozen_and_reversion_blocked(client, db, rsa_keypair):
    """The Phase 1 fail-closed freeze and forward-only status guard must
    still hold when invoices are created/issued through the real API,
    not just via direct SQL as in test_invoice_immutability.py."""
    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)
    invoice_id = client.post(
        "/invoices",
        json={"contract_id": contract_id, "client_id": client_id, "currency_code": "AUD", "subtotal_amount": "200.00"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    client.post(f"/invoices/{invoice_id}/issue", headers={"Authorization": f"Bearer {token}"})

    cur = db.cursor()
    cur.execute("SELECT 1 FROM invoices WHERE id = %s AND status = 'issued'", (invoice_id,))
    assert cur.fetchone() is not None

    # Direct SQL to exercise the DB-level guard itself (the API doesn't
    # expose a raw PATCH for invoices, deliberately).
    cur.execute("SAVEPOINT sp")
    try:
        cur.execute("UPDATE invoices SET subtotal_amount = 999999.00 WHERE id = %s", (invoice_id,))
        raised = False
    except Exception:
        raised = True
        db.cursor().execute("ROLLBACK TO SAVEPOINT sp")
    assert raised

    cur.execute("SAVEPOINT sp2")
    try:
        cur.execute("UPDATE invoices SET status = 'draft' WHERE id = %s", (invoice_id,))
        raised = False
    except Exception:
        raised = True
        db.cursor().execute("ROLLBACK TO SAVEPOINT sp2")
    assert raised


def test_void_invoice_from_draft_and_from_issued(client, db, rsa_keypair):
    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)

    draft_invoice_id = client.post(
        "/invoices",
        json={"contract_id": contract_id, "client_id": client_id, "currency_code": "AUD", "subtotal_amount": "10.00"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    void_draft_response = client.post(f"/invoices/{draft_invoice_id}/void", headers={"Authorization": f"Bearer {token}"})
    assert void_draft_response.status_code == 200
    assert void_draft_response.json()["status"] == "void"

    issued_invoice_id = client.post(
        "/invoices",
        json={"contract_id": contract_id, "client_id": client_id, "currency_code": "AUD", "subtotal_amount": "20.00"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    client.post(f"/invoices/{issued_invoice_id}/issue", headers={"Authorization": f"Bearer {token}"})
    void_issued_response = client.post(f"/invoices/{issued_invoice_id}/void", headers={"Authorization": f"Bearer {token}"})
    assert void_issued_response.status_code == 200
    assert void_issued_response.json()["status"] == "void"

    # Voiding an already-void invoice is rejected.
    second_void = client.post(f"/invoices/{issued_invoice_id}/void", headers={"Authorization": f"Bearer {token}"})
    assert second_void.status_code == 409


def test_create_invoice_with_matching_milestone_succeeds(client, db, rsa_keypair):
    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)
    milestone_id = client.post(
        "/milestones",
        json={"contract_id": contract_id, "title": "M1", "amount": "100.00", "currency_code": "AUD"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]

    response = client.post(
        "/invoices",
        json={
            "contract_id": contract_id, "milestone_id": milestone_id, "client_id": client_id,
            "currency_code": "AUD", "subtotal_amount": "100.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201
    assert response.json()["milestone_id"] == milestone_id


def test_create_invoice_with_milestone_from_a_different_contract_is_rejected(client, db, rsa_keypair):
    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)
    _, other_contract_id = _set_up_contract(client, token)
    milestone_on_other_contract = client.post(
        "/milestones",
        json={"contract_id": other_contract_id, "title": "M1", "amount": "100.00", "currency_code": "AUD"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]

    response = client.post(
        "/invoices",
        json={
            "contract_id": contract_id, "milestone_id": milestone_on_other_contract, "client_id": client_id,
            "currency_code": "AUD", "subtotal_amount": "100.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
