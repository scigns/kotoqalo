"""Invoices are normally mutable (unlike the ledger), but once issued
their financial substance must freeze -- only status/admin fields may
still change.
"""


def _insert_draft_invoice(db, seed):
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO invoices (
            invoice_number, invoice_year, invoice_seq, contract_id, client_id,
            currency_code, subtotal_amount, tax_amount, total_amount, created_by
        )
        VALUES ('INV-2026-000001', 2026, 1, %s, %s, 'AUD', 100.00, 10.00, 110.00, %s)
        RETURNING id
        """,
        (seed["contract_id"], seed["client_id"], seed["user_id"]),
    )
    return cur.fetchone()[0]


def test_draft_invoice_amounts_are_editable(db, seed):
    db.cursor().execute("SET ROLE app_rw")
    invoice_id = _insert_draft_invoice(db, seed)

    db.cursor().execute(
        "UPDATE invoices SET subtotal_amount = 200.00, total_amount = 220.00 WHERE id = %s",
        (invoice_id,),
    )

    cur = db.cursor()
    cur.execute("SELECT subtotal_amount FROM invoices WHERE id = %s", (invoice_id,))
    assert str(cur.fetchone()[0]) == "200.00"


def test_issued_invoice_amount_is_frozen(db, seed, expect_denied):
    db.cursor().execute("SET ROLE app_rw")
    invoice_id = _insert_draft_invoice(db, seed)
    db.cursor().execute(
        "UPDATE invoices SET status = 'issued', issued_at = now() WHERE id = %s",
        (invoice_id,),
    )

    err = expect_denied(
        db,
        "UPDATE invoices SET subtotal_amount = 999.00 WHERE id = %s",
        (invoice_id,),
    )
    assert "immutable once issued" in str(err)


def test_issued_invoice_status_and_admin_fields_still_editable(db, seed):
    db.cursor().execute("SET ROLE app_rw")
    invoice_id = _insert_draft_invoice(db, seed)
    db.cursor().execute(
        "UPDATE invoices SET status = 'issued', issued_at = now() WHERE id = %s",
        (invoice_id,),
    )

    db.cursor().execute(
        "UPDATE invoices SET status = 'paid', pdf_object_key = 'invoices/2026/INV-2026-000001.pdf' WHERE id = %s",
        (invoice_id,),
    )

    cur = db.cursor()
    cur.execute("SELECT status FROM invoices WHERE id = %s", (invoice_id,))
    assert cur.fetchone()[0] == "paid"
