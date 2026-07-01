"""Invoice generation: multi-currency, sequential numbering, PDF output,
and the ledger posting triggered by issuance -- through the chain-tip
table, not a "last row" lookup (see 0011_ledger_hash_chain.py).
"""

import base64
import re
import zlib

from conftest import create_user_with_role


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """generate_invoice_pdf's reportlab canvas defaults to
    ASCII85Decode+FlateDecode content streams, so the drawn text isn't a
    readable substring of the raw PDF bytes -- decode the content
    stream(s) and pull out the literal strings passed to the Tj text-show
    operator, so tests can assert on what the PDF actually renders
    without a full PDF-parsing dependency."""
    content = b"".join(
        zlib.decompress(base64.a85decode(match.group(1)))
        for match in re.finditer(rb"stream\r?\n(.*?)~>endstream", pdf_bytes, re.DOTALL)
    )
    return " ".join(m.decode("latin-1") for m in re.findall(rb"\(((?:[^()\\]|\\.)*)\)\s*Tj", content))


def _owner(db, rsa_keypair, subject="test|invoice-owner"):
    return create_user_with_role(db, rsa_keypair, "owner_admin", subject)


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

    # The PDF must reflect the invoice's real, post-issuance state -- it
    # used to be built from the pre-update snapshot, so every issued
    # invoice's stored PDF permanently read "DRAFT -- not yet issued".
    pdf_text = _extract_pdf_text(pdf_response.content)
    assert "DRAFT -- not yet issued" not in pdf_text
    assert f"Issued: {issued['issued_at']}" in pdf_text

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


def test_create_invoice_with_client_id_not_matching_the_contracts_client_is_rejected(client, db, rsa_keypair):
    """contract_id determines which client an invoice is actually for
    (contracts.client_id) -- client_id used to only be checked for
    existence, so any other real client's id would silently produce an
    invoice billing the wrong client for this contract."""
    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)
    other_client_id, _ = _set_up_contract(client, token)

    response = client.post(
        "/invoices",
        json={
            "contract_id": contract_id, "client_id": other_client_id,
            "currency_code": "AUD", "subtotal_amount": "100.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400


def test_create_invoice_with_malformed_contract_id_is_422_not_500(client, db, rsa_keypair):
    """InvoiceCreate used to type contract_id/client_id/milestone_id as
    plain str, so a malformed id reached Postgres as a raw string and
    surfaced as an unhandled 500 instead of a clean validation error --
    the same class of bug already fixed for grant_role/revoke_role in
    Phase 2."""
    _, token = _owner(db, rsa_keypair)
    response = client.post(
        "/invoices",
        json={
            "contract_id": "not-a-uuid", "client_id": "not-a-uuid",
            "currency_code": "AUD", "subtotal_amount": "100.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


def test_create_invoice_with_negative_subtotal_is_422_not_500(client, db, rsa_keypair):
    """subtotal_amount/tax_amount had no Pydantic-level non-negativity
    check, so a negative value reached Postgres's CHECK(subtotal_amount
    >= 0) constraint and surfaced as an unhandled 500."""
    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)
    response = client.post(
        "/invoices",
        json={
            "contract_id": contract_id, "client_id": client_id,
            "currency_code": "AUD", "subtotal_amount": "-100.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


def test_issuing_an_invoice_sets_updated_by(client, db, rsa_keypair):
    """issue_invoice used to hand-roll its UPDATE instead of going
    through apply_partial_update, silently leaving updated_by unset --
    unlike every contract/milestone mutation."""
    user_id, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)
    invoice_id = client.post(
        "/invoices",
        json={"contract_id": contract_id, "client_id": client_id, "currency_code": "AUD", "subtotal_amount": "50.00"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    client.post(f"/invoices/{invoice_id}/issue", headers={"Authorization": f"Bearer {token}"})

    cur = db.cursor()
    cur.execute("SELECT updated_by FROM invoices WHERE id = %s", (invoice_id,))
    assert str(cur.fetchone()[0]) == user_id


def test_two_connections_serialize_on_issuing_the_same_invoice(rsa_keypair):
    """issue_invoice used to read an invoice's status with a plain
    SELECT (no locking) before mutating it, so two concurrent issue
    requests for the same draft invoice could both read status='draft'
    before either commits and both post a ledger entry. FOR UPDATE on
    the invoice row should serialize this, the same way
    0011_ledger_hash_chain.py's chain-tip lock serializes concurrent
    first-inserts (see test_ledger_hash_chain.py's analogous test).

    If this test's HTTP request completes, it really issues the fixture
    invoice and posts a real ledger transaction through it -- like
    test_ledger_atomicity.py's fixture user, that can never be cleaned up
    afterward (ledger rows are append-only, and the invoice/contract/
    client/user rows referencing/referenced-by it can't be deleted
    either). So this uses fixed, idempotent fixture rows (upserted, never
    deleted) instead of fresh ones per run.
    """
    import os
    import threading

    import psycopg
    from fastapi.testclient import TestClient

    from app.auth import StaticJWKSClient, get_jwks_client
    from app.config import Settings, get_settings
    from app.main import app
    from conftest import TEST_AUDIENCE, TEST_DOMAIN, TEST_KID, make_token

    private_key, public_key = rsa_keypair
    url = os.environ["MIGRATOR_DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://")

    setup_conn = psycopg.connect(url, autocommit=True)
    cur = setup_conn.cursor()
    subject = "test|concurrent-issue-owner-fixture"
    cur.execute(
        """
        INSERT INTO users (external_auth_subject, email, full_name)
        VALUES (%s, %s, 'Concurrent Issue Owner (permanent test fixture)')
        ON CONFLICT (external_auth_subject) DO NOTHING
        """,
        (subject, "concurrent-issue-owner-fixture@example.test"),
    )
    cur.execute("SELECT id FROM users WHERE external_auth_subject = %s", (subject,))
    user_id = cur.fetchone()[0]
    cur.execute(
        "INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, 'owner_admin', %s) ON CONFLICT DO NOTHING",
        (user_id, user_id),
    )

    cur.execute("SELECT id FROM clients WHERE display_name = 'Concurrent Issue Fixture Client'")
    row = cur.fetchone()
    if row is None:
        cur.execute(
            "INSERT INTO clients (display_name, country_code, created_by) "
            "VALUES ('Concurrent Issue Fixture Client', 'AU', %s) RETURNING id",
            (user_id,),
        )
        client_id = cur.fetchone()[0]
    else:
        client_id = row[0]

    cur.execute("SELECT id FROM contracts WHERE title = 'Concurrent Issue Fixture Contract'")
    row = cur.fetchone()
    if row is None:
        cur.execute(
            "INSERT INTO contracts (client_id, title, currency_code, total_value, created_by) "
            "VALUES (%s, 'Concurrent Issue Fixture Contract', 'AUD', 100.00, %s) RETURNING id",
            (client_id, user_id),
        )
        contract_id = cur.fetchone()[0]
    else:
        contract_id = row[0]

    cur.execute("SELECT id FROM invoices WHERE invoice_number = 'INV-LOCKTEST-000001'")
    row = cur.fetchone()
    if row is None:
        cur.execute(
            "INSERT INTO invoices (invoice_number, invoice_year, invoice_seq, contract_id, client_id, "
            "currency_code, subtotal_amount, tax_amount, total_amount, created_by) "
            "VALUES ('INV-LOCKTEST-000001', 2026, 999001, %s, %s, 'AUD', 100.00, 0, 100.00, %s) RETURNING id",
            (contract_id, client_id, user_id),
        )
        invoice_id = cur.fetchone()[0]
    else:
        invoice_id = row[0]
    setup_conn.close()

    app.dependency_overrides[get_settings] = lambda: Settings(
        app_database_url=os.environ["APP_DATABASE_URL"], auth0_domain=TEST_DOMAIN, auth0_audience=TEST_AUDIENCE
    )
    app.dependency_overrides[get_jwks_client] = lambda: StaticJWKSClient({TEST_KID: public_key})
    token = make_token(private_key, subject)
    real_client = TestClient(app)

    # Hold the invoice-row lock open on a raw connection -- controlling
    # request-internal timing to hold the lock open mid-HTTP-request
    # isn't something TestClient exposes, so this locks the row directly
    # first, mirroring test_ledger_hash_chain.py's approach of proving
    # the lock exists via a raw connection.
    locking_conn = psycopg.connect(url, autocommit=False)
    try:
        locking_conn.cursor().execute("SET ROLE app_rw")
        locking_conn.cursor().execute("SELECT 1 FROM invoices WHERE id = %s FOR UPDATE", (invoice_id,))

        issue_done = threading.Event()

        def _issue_via_http():
            real_client.post(f"/invoices/{invoice_id}/issue", headers={"Authorization": f"Bearer {token}"})
            issue_done.set()

        thread = threading.Thread(target=_issue_via_http)
        thread.start()
        thread.join(timeout=1.0)
        assert not issue_done.is_set(), (
            "issuing the invoice completed without blocking on the row lock held by another connection -- "
            "issue_invoice is not taking FOR UPDATE on the invoice row"
        )

        locking_conn.rollback()
        thread.join(timeout=5.0)
        assert issue_done.is_set(), "issue request never completed after the row lock was released"
    finally:
        app.dependency_overrides.clear()
        locking_conn.close()
