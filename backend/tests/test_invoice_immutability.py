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


def test_issued_to_void_transition_still_works(db, seed):
    """A legitimate forward transition (not a reversion to draft) must
    remain unaffected by the reversion guard."""
    db.cursor().execute("SET ROLE app_rw")
    invoice_id = _insert_draft_invoice(db, seed)
    db.cursor().execute(
        "UPDATE invoices SET status = 'issued', issued_at = now() WHERE id = %s",
        (invoice_id,),
    )

    db.cursor().execute("UPDATE invoices SET status = 'void' WHERE id = %s", (invoice_id,))

    cur = db.cursor()
    cur.execute("SELECT status FROM invoices WHERE id = %s", (invoice_id,))
    assert cur.fetchone()[0] == "void"


def test_issued_to_draft_reversion_is_rejected(db, seed, expect_denied):
    """invoice_status has exactly four values (draft, issued, paid,
    void); reverting any non-draft invoice back to draft would silently
    reopen guard_invoice_financial_fields()'s freeze on the very next
    update (since that trigger only freezes fields while
    OLD.status <> 'draft')."""
    db.cursor().execute("SET ROLE app_rw")
    invoice_id = _insert_draft_invoice(db, seed)
    db.cursor().execute(
        "UPDATE invoices SET status = 'issued', issued_at = now() WHERE id = %s",
        (invoice_id,),
    )

    err = expect_denied(db, "UPDATE invoices SET status = 'draft' WHERE id = %s", (invoice_id,))
    assert "cannot revert" in str(err)


def test_paid_to_draft_reversion_is_rejected(db, seed, expect_denied):
    db.cursor().execute("SET ROLE app_rw")
    invoice_id = _insert_draft_invoice(db, seed)
    db.cursor().execute(
        "UPDATE invoices SET status = 'issued', issued_at = now() WHERE id = %s",
        (invoice_id,),
    )
    db.cursor().execute("UPDATE invoices SET status = 'paid' WHERE id = %s", (invoice_id,))

    err = expect_denied(db, "UPDATE invoices SET status = 'draft' WHERE id = %s", (invoice_id,))
    assert "cannot revert" in str(err)


def test_void_to_draft_reversion_is_rejected(db, seed, expect_denied):
    db.cursor().execute("SET ROLE app_rw")
    invoice_id = _insert_draft_invoice(db, seed)
    db.cursor().execute(
        "UPDATE invoices SET status = 'issued', issued_at = now() WHERE id = %s",
        (invoice_id,),
    )
    db.cursor().execute("UPDATE invoices SET status = 'void' WHERE id = %s", (invoice_id,))

    err = expect_denied(db, "UPDATE invoices SET status = 'draft' WHERE id = %s", (invoice_id,))
    assert "cannot revert" in str(err)


def test_reversion_exploit_is_fully_closed_end_to_end(db, seed, expect_denied):
    """The original exploit this fix closes: issue an invoice, try to
    revert it to draft to reopen its financial fields, confirm the
    reversion itself is rejected, then confirm the invoice's status is
    genuinely untouched (the whole UPDATE statement aborted, not just
    the status column) and the financial-field freeze still holds --
    the reversion attempt did not leave the row in some unguarded
    in-between state.
    """
    db.cursor().execute("SET ROLE app_rw")
    invoice_id = _insert_draft_invoice(db, seed)
    db.cursor().execute(
        "UPDATE invoices SET status = 'issued', issued_at = now() WHERE id = %s",
        (invoice_id,),
    )

    expect_denied(db, "UPDATE invoices SET status = 'draft' WHERE id = %s", (invoice_id,))

    cur = db.cursor()
    cur.execute("SELECT status, subtotal_amount FROM invoices WHERE id = %s", (invoice_id,))
    status, subtotal = cur.fetchone()
    assert status == "issued", "status must be unchanged after the rejected reversion"
    assert str(subtotal) == "100.00"

    # The financial freeze must still be enforced -- the rejected
    # reversion attempt must not have left the row in a state where the
    # freeze trigger no longer applies.
    err = expect_denied(
        db,
        "UPDATE invoices SET subtotal_amount = 999.00 WHERE id = %s",
        (invoice_id,),
    )
    assert "immutable once issued" in str(err)
