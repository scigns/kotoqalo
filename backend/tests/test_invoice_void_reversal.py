"""Voiding an issued invoice must leave the ledger balanced: the
append-only design forbids editing/deleting the original issuance
entries, so void_invoice posts a reversal through the same chain-tip
path (app/ledger.py's reverse_ledger_transaction) instead.
"""

import uuid

from conftest import create_user_with_role


def _owner(db, rsa_keypair, subject="test|void-reversal-owner"):
    return create_user_with_role(db, rsa_keypair, "owner_admin", subject)


def _set_up_contract(client, token, total_value="5000.00"):
    client_id = client.post(
        "/clients", json={"display_name": "Void Reversal Test Client", "country_code": "AU"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    contract_id = client.post(
        "/contracts",
        json={"client_id": client_id, "title": "Void Reversal Test Contract", "currency_code": "AUD", "total_value": total_value},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    return client_id, contract_id


def _postings_for_invoice(db, invoice_id):
    """Every ledger entry ever posted against this invoice, across both
    its issuance transaction and any reversal -- summed by (account_code,
    direction) so a fully-reversed invoice should net to zero on every
    account it touched."""
    cur = db.cursor()
    cur.execute(
        """
        SELECT a.code, e.direction, e.amount
        FROM ledger_entries e
        JOIN ledger_transactions t ON t.id = e.ledger_transaction_id
        JOIN chart_of_accounts a ON a.id = e.account_id
        WHERE t.reference_type IN ('invoice_issued', 'invoice_voided') AND t.reference_id = %s
        """,
        (str(invoice_id),),
    )
    return cur.fetchall()


def test_voiding_an_issued_invoice_reverses_the_ledger_posting_and_nets_to_zero(client, db, rsa_keypair):
    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)
    invoice_id = client.post(
        "/invoices",
        json={
            "contract_id": contract_id, "client_id": client_id, "currency_code": "AUD",
            "subtotal_amount": "1000.00", "tax_amount": "100.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    client.post(f"/invoices/{invoice_id}/issue", headers={"Authorization": f"Bearer {token}"})

    void_response = client.post(f"/invoices/{invoice_id}/void", headers={"Authorization": f"Bearer {token}"})
    assert void_response.status_code == 200
    assert void_response.json()["status"] == "void"

    rows = _postings_for_invoice(db, invoice_id)
    # Two transactions' worth of entries: 3 from issuance (AR debit,
    # revenue credit, tax credit) and 3 from the reversal.
    assert len(rows) == 6

    from decimal import Decimal
    net = {}
    for code, direction, amount in rows:
        signed = amount if direction == "debit" else -amount
        net[code] = net.get(code, Decimal("0")) + signed
    assert net == {"1000": Decimal("0"), "4000": Decimal("0"), "2000": Decimal("0")}

    # The reversal is recorded as a reversal of the original transaction,
    # not a freestanding, unrelated posting.
    cur = db.cursor()
    cur.execute(
        """
        SELECT t_reversal.reversal_of_transaction_id, t_original.id
        FROM ledger_transactions t_reversal
        JOIN ledger_transactions t_original
          ON t_original.reference_type = 'invoice_issued' AND t_original.reference_id = %s
        WHERE t_reversal.reference_type = 'invoice_voided' AND t_reversal.reference_id = %s
        """,
        (str(invoice_id), str(invoice_id)),
    )
    reversal_of_id, original_id = cur.fetchone()
    assert reversal_of_id == original_id

    # The chain must remain unbroken: the reversal's entries continue
    # directly from the chain tip as it stood after issuance -- i.e. the
    # first reversal row (by chain_seq) links to the last issuance row
    # (by chain_seq), not a fork or a gap.
    cur.execute(
        """
        SELECT e.chain_seq, e.previous_hash, e.row_hash
        FROM ledger_entries e
        JOIN ledger_transactions t ON t.id = e.ledger_transaction_id
        WHERE t.reference_type IN ('invoice_issued', 'invoice_voided') AND t.reference_id = %s
        ORDER BY e.chain_seq
        """,
        (str(invoice_id),),
    )
    chain_rows = cur.fetchall()
    seqs = [r[0] for r in chain_rows]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs), "chain_seq must be strictly increasing with no duplicates"
    for (_, _, prev_row_hash), (_, next_previous_hash, _) in zip(chain_rows, chain_rows[1:]):
        assert bytes(next_previous_hash) == bytes(prev_row_hash), "chain has a gap or fork between issuance and reversal"


def test_voiding_a_paid_invoice_is_disallowed_and_ledger_is_unchanged(client, db, rsa_keypair):
    """Marking an invoice paid via a receipt, then attempting to void it,
    must be rejected outright rather than silently reversed -- a refund
    (which would need to account for the receipt too, not just the
    issuance) is a distinct operation this phase doesn't implement."""
    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)
    invoice_id = client.post(
        "/invoices",
        json={"contract_id": contract_id, "client_id": client_id, "currency_code": "AUD", "subtotal_amount": "1000.00"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    client.post(f"/invoices/{invoice_id}/issue", headers={"Authorization": f"Bearer {token}"})
    client.post(
        "/receipts",
        json={
            "invoice_id": invoice_id, "client_id": client_id, "amount": "1000.00",
            "currency_code": "AUD", "description": "Payment received", "received_date": "2026-07-01",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    invoice_response = client.get(f"/invoices/{invoice_id}", headers={"Authorization": f"Bearer {token}"})
    assert invoice_response.json()["status"] == "paid"

    void_response = client.post(f"/invoices/{invoice_id}/void", headers={"Authorization": f"Bearer {token}"})
    assert void_response.status_code == 409

    # Status is unchanged, and no reversal (or any other extra posting)
    # was made -- only the original issuance + receipt entries exist.
    invoice_response = client.get(f"/invoices/{invoice_id}", headers={"Authorization": f"Bearer {token}"})
    assert invoice_response.json()["status"] == "paid"

    cur = db.cursor()
    cur.execute(
        "SELECT count(*) FROM ledger_transactions WHERE reference_type = 'invoice_voided' AND reference_id = %s",
        (str(invoice_id),),
    )
    assert cur.fetchone()[0] == 0


def test_find_ledger_transaction_id_matches_regardless_of_str_or_uuid_reference_id(client, db, rsa_keypair):
    """issue_invoice posts with reference_id=str(invoice_id) (a plain
    str), while create_receipt posts with reference_id=payload.invoice_id
    (a uuid.UUID, per ReceiptCreate's typing) -- find_ledger_transaction_id
    must find the right transaction either way, since it's how void looks
    up the posting it needs to reverse."""
    from app.ledger import find_ledger_transaction_id

    _, token = _owner(db, rsa_keypair)
    client_id, contract_id = _set_up_contract(client, token)
    invoice_id = client.post(
        "/invoices",
        json={"contract_id": contract_id, "client_id": client_id, "currency_code": "AUD", "subtotal_amount": "1000.00"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    client.post(f"/invoices/{invoice_id}/issue", headers={"Authorization": f"Bearer {token}"})
    receipt_response = client.post(
        "/receipts",
        json={
            "invoice_id": invoice_id, "client_id": client_id, "amount": "1000.00",
            "currency_code": "AUD", "description": "Payment received", "received_date": "2026-07-01",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    receipt_transaction_id = receipt_response.json()["ledger_transaction_id"]

    # issue_invoice's posting: reference_id was stored as a plain str.
    found_via_str = find_ledger_transaction_id(db, "invoice_issued", invoice_id)
    found_via_uuid = find_ledger_transaction_id(db, "invoice_issued", uuid.UUID(invoice_id))
    assert found_via_str is not None
    assert found_via_str == found_via_uuid

    # create_receipt's posting: reference_id was stored as a uuid.UUID
    # object (ReceiptCreate.invoice_id), not a str -- confirm looking it
    # up with a plain str still matches the same row.
    found_receipt_via_str = find_ledger_transaction_id(db, "receipt", invoice_id)
    assert found_receipt_via_str == receipt_transaction_id
