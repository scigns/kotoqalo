"""Manually recorded receipts/expenses -- ledger posting outside of
invoice issuance, and receipts marking a linked invoice paid.
"""

from conftest import make_token


def _owner(db, rsa_keypair, subject="test|receipts-owner"):
    private_key, _ = rsa_keypair
    cur = db.cursor()
    cur.execute(
        "INSERT INTO users (external_auth_subject, email, full_name) VALUES (%s, %s, 'Owner') RETURNING id",
        (subject, f"{subject.replace('|', '-')}@example.test"),
    )
    user_id = cur.fetchone()[0]
    cur.execute("INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, 'owner_admin', %s)", (user_id, user_id))
    return str(user_id), make_token(private_key, subject)


def _issued_invoice(client, token, amount="1000.00"):
    client_id = client.post(
        "/clients", json={"display_name": "Receipt Test Client", "country_code": "AU"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    contract_id = client.post(
        "/contracts",
        json={"client_id": client_id, "title": "Receipt Test Contract", "currency_code": "AUD", "total_value": amount},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    invoice_id = client.post(
        "/invoices",
        json={"contract_id": contract_id, "client_id": client_id, "currency_code": "AUD", "subtotal_amount": amount},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    client.post(f"/invoices/{invoice_id}/issue", headers={"Authorization": f"Bearer {token}"})
    return client_id, invoice_id


def test_receipt_against_issued_invoice_marks_it_paid_and_posts_ledger(client, db, rsa_keypair):
    _, token = _owner(db, rsa_keypair)
    client_id, invoice_id = _issued_invoice(client, token, amount="1000.00")

    response = client.post(
        "/receipts",
        json={
            "invoice_id": invoice_id, "client_id": client_id, "amount": "1000.00",
            "currency_code": "AUD", "description": "Payment received", "received_date": "2026-07-01",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201
    transaction_id = response.json()["ledger_transaction_id"]

    invoice_response = client.get(f"/invoices/{invoice_id}", headers={"Authorization": f"Bearer {token}"})
    assert invoice_response.json()["status"] == "paid"

    cur = db.cursor()
    cur.execute(
        """
        SELECT a.code, e.direction, e.amount
        FROM ledger_entries e
        JOIN chart_of_accounts a ON a.id = e.account_id
        WHERE e.ledger_transaction_id = %s
        ORDER BY a.code
        """,
        (transaction_id,),
    )
    postings = {(row[0], row[1]): str(row[2]) for row in cur.fetchall()}
    assert postings[("1000", "credit")] == "1000.0000"  # AR credited (paid down)
    assert postings[("1010", "debit")] == "1000.0000"  # Cash/Wise debited


def test_receipt_against_draft_invoice_is_rejected(client, db, rsa_keypair):
    _, token = _owner(db, rsa_keypair)
    client_id = client.post(
        "/clients", json={"display_name": "X", "country_code": "AU"}, headers={"Authorization": f"Bearer {token}"}
    ).json()["id"]
    contract_id = client.post(
        "/contracts",
        json={"client_id": client_id, "title": "C", "currency_code": "AUD", "total_value": "10.00"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    draft_invoice_id = client.post(
        "/invoices",
        json={"contract_id": contract_id, "client_id": client_id, "currency_code": "AUD", "subtotal_amount": "10.00"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]

    response = client.post(
        "/receipts",
        json={
            "invoice_id": draft_invoice_id, "client_id": client_id, "amount": "10.00",
            "currency_code": "AUD", "description": "Should be rejected", "received_date": "2026-07-01",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 409


def test_receipt_without_invoice_link_still_posts_ledger(client, db, rsa_keypair):
    """A receipt need not be tied to an invoice (e.g. a deposit or
    unrelated payment)."""
    _, token = _owner(db, rsa_keypair)
    client_id = client.post(
        "/clients", json={"display_name": "Deposit Client", "country_code": "AU"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]

    response = client.post(
        "/receipts",
        json={
            "client_id": client_id, "amount": "250.00", "currency_code": "AUD",
            "description": "Unlinked deposit", "received_date": "2026-07-01",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201


def test_expense_posts_ledger_debit_expense_credit_cash(client, db, rsa_keypair):
    _, token = _owner(db, rsa_keypair)
    response = client.post(
        "/expenses",
        json={
            "account_code": "5000", "amount": "45.50", "currency_code": "AUD",
            "description": "Wise transfer fee", "expense_date": "2026-07-01",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201
    transaction_id = response.json()["ledger_transaction_id"]

    cur = db.cursor()
    cur.execute(
        """
        SELECT a.code, e.direction, e.amount
        FROM ledger_entries e
        JOIN chart_of_accounts a ON a.id = e.account_id
        WHERE e.ledger_transaction_id = %s
        ORDER BY a.code
        """,
        (transaction_id,),
    )
    postings = {(row[0], row[1]): str(row[2]) for row in cur.fetchall()}
    assert postings[("5000", "debit")] == "45.5000"
    assert postings[("1010", "credit")] == "45.5000"


def test_expense_with_unknown_account_code_is_400_and_leaves_no_orphaned_transaction(client, db, rsa_keypair):
    """Empirically confirms get_db()'s commit-on-success/rollback-on-
    exception design: a failure partway through posting (bad account
    code on the second entry, after the ledger_transactions header and
    first entry were already inserted in this same request-scoped,
    not-yet-committed transaction) must leave nothing behind at all."""
    _, token = _owner(db, rsa_keypair)
    response = client.post(
        "/expenses",
        json={
            "account_code": "9999-does-not-exist", "amount": "10.00", "currency_code": "AUD",
            "description": "Should fail and roll back completely", "expense_date": "2026-07-01",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400

    cur = db.cursor()
    cur.execute("SELECT count(*) FROM ledger_transactions WHERE description = 'Should fail and roll back completely'")
    assert cur.fetchone()[0] == 0
