"""Proves the ledger is append-only at the database level, not just in
application code, and that double-entry postings must balance.
"""


def _insert_ledger_transaction(db, user_id, description, reference_type="manual_adjustment", reversal_of=None):
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO ledger_transactions (transaction_date, description, reference_type, reversal_of_transaction_id, created_by)
        VALUES (CURRENT_DATE, %s, %s, %s, %s)
        RETURNING id
        """,
        (description, reference_type, reversal_of, user_id),
    )
    return cur.fetchone()[0]


def _insert_entry(db, user_id, transaction_id, account_id, direction, amount, currency="AUD"):
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO ledger_entries (ledger_transaction_id, account_id, currency_code, direction, amount, created_by)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (transaction_id, account_id, currency, direction, amount, user_id),
    )
    return cur.fetchone()[0]


def _set_role(db, role):
    db.cursor().execute(f"SET ROLE {role}")


def test_balanced_double_entry_posting_succeeds(db, seed):
    _set_role(db, "app_rw")
    uid = seed["user_id"]
    txn_id = _insert_ledger_transaction(db, uid, "Invoice #1 issued")
    _insert_entry(db, uid, txn_id, seed["ar_account_id"], "debit", "100.00")
    _insert_entry(db, uid, txn_id, seed["revenue_account_id"], "credit", "100.00")

    db.cursor().execute("SET CONSTRAINTS ledger_entries_balance_check IMMEDIATE")

    cur = db.cursor()
    cur.execute("SELECT count(*) FROM ledger_entries WHERE ledger_transaction_id = %s", (txn_id,))
    assert cur.fetchone()[0] == 2


def test_unbalanced_posting_is_rejected_at_commit(db, seed, expect_denied):
    _set_role(db, "app_rw")
    uid = seed["user_id"]
    txn_id = _insert_ledger_transaction(db, uid, "Broken posting: debit only")
    _insert_entry(db, uid, txn_id, seed["ar_account_id"], "debit", "100.00")
    # No offsetting credit -- the deferred constraint trigger must catch
    # this, whether checked explicitly or at COMMIT time.

    err = expect_denied(db, "SET CONSTRAINTS ledger_entries_balance_check IMMEDIATE")
    assert "does not balance" in str(err)


def test_app_rw_cannot_update_ledger_entries(db, seed, expect_denied):
    _set_role(db, "app_rw")
    uid = seed["user_id"]
    txn_id = _insert_ledger_transaction(db, uid, "Invoice #2 issued")
    entry_id = _insert_entry(db, uid, txn_id, seed["ar_account_id"], "debit", "50.00")
    _insert_entry(db, uid, txn_id, seed["revenue_account_id"], "credit", "50.00")
    db.cursor().execute("SET CONSTRAINTS ledger_entries_balance_check IMMEDIATE")

    err = expect_denied(
        db,
        "UPDATE ledger_entries SET amount = 999 WHERE id = %s",
        (entry_id,),
    )
    assert "permission denied" in str(err).lower()


def test_app_rw_cannot_delete_ledger_entries(db, seed, expect_denied):
    _set_role(db, "app_rw")
    uid = seed["user_id"]
    txn_id = _insert_ledger_transaction(db, uid, "Invoice #3 issued")
    entry_id = _insert_entry(db, uid, txn_id, seed["ar_account_id"], "debit", "25.00")
    _insert_entry(db, uid, txn_id, seed["revenue_account_id"], "credit", "25.00")
    db.cursor().execute("SET CONSTRAINTS ledger_entries_balance_check IMMEDIATE")

    err = expect_denied(db, "DELETE FROM ledger_entries WHERE id = %s", (entry_id,))
    assert "permission denied" in str(err).lower()


def test_app_rw_cannot_update_ledger_transactions(db, seed, expect_denied):
    _set_role(db, "app_rw")
    uid = seed["user_id"]
    txn_id = _insert_ledger_transaction(db, uid, "Invoice #4 issued")

    err = expect_denied(
        db,
        "UPDATE ledger_transactions SET description = 'tampered' WHERE id = %s",
        (txn_id,),
    )
    assert "permission denied" in str(err).lower()


def test_owner_role_update_is_still_blocked_by_trigger(db, seed, expect_denied):
    """Even the schema-owning role (which DOES hold UPDATE/DELETE
    privilege on these tables) is stopped by the BEFORE UPDATE/DELETE
    trigger -- the REVOKE protects against the app, the trigger protects
    against everyone else short of disabling the trigger outright."""
    uid = seed["user_id"]
    txn_id = _insert_ledger_transaction(db, uid, "Invoice #5 issued")
    _insert_entry(db, uid, txn_id, seed["ar_account_id"], "debit", "10.00")
    _insert_entry(db, uid, txn_id, seed["revenue_account_id"], "credit", "10.00")
    db.cursor().execute("SET CONSTRAINTS ledger_entries_balance_check IMMEDIATE")

    err = expect_denied(
        db,
        "UPDATE ledger_transactions SET description = 'tampered' WHERE id = %s",
        (txn_id,),
    )
    assert "append-only" in str(err)


def test_owner_role_truncate_is_blocked(db, seed, expect_denied):
    err = expect_denied(db, "TRUNCATE ledger_entries")
    assert "append-only" in str(err)


def test_app_ro_cannot_insert_ledger_entries(db, seed, expect_denied):
    uid = seed["user_id"]
    txn_id = _insert_ledger_transaction(db, uid, "Should not be allowed")

    _set_role(db, "app_ro")
    err = expect_denied(
        db,
        "INSERT INTO ledger_entries (ledger_transaction_id, account_id, currency_code, direction, amount, created_by) "
        "VALUES (%s, %s, 'AUD', 'debit', 5.00, %s)",
        (txn_id, seed["ar_account_id"], uid),
    )
    assert "permission denied" in str(err).lower()


def test_corrections_use_reversal_entries_not_mutation(db, seed):
    """The documented correction pattern: post a new transaction that
    reverses the original, rather than editing it."""
    _set_role(db, "app_rw")
    uid = seed["user_id"]
    original_id = _insert_ledger_transaction(db, uid, "Invoice #6 issued (wrong amount)")
    _insert_entry(db, uid, original_id, seed["ar_account_id"], "debit", "100.00")
    _insert_entry(db, uid, original_id, seed["revenue_account_id"], "credit", "100.00")
    db.cursor().execute("SET CONSTRAINTS ledger_entries_balance_check IMMEDIATE")
    # IMMEDIATE applies for the rest of the transaction, not just this one
    # check -- re-arm DEFERRED so the reversal's two entries can both be
    # inserted before it's evaluated as a unit.
    db.cursor().execute("SET CONSTRAINTS ledger_entries_balance_check DEFERRED")

    reversal_id = _insert_ledger_transaction(
        db, uid, "Reversal of Invoice #6 (posted in error)", reference_type="reversal", reversal_of=original_id
    )
    _insert_entry(db, uid, reversal_id, seed["revenue_account_id"], "debit", "100.00")
    _insert_entry(db, uid, reversal_id, seed["ar_account_id"], "credit", "100.00")
    db.cursor().execute("SET CONSTRAINTS ledger_entries_balance_check IMMEDIATE")

    cur = db.cursor()
    cur.execute("SELECT reversal_of_transaction_id FROM ledger_transactions WHERE id = %s", (reversal_id,))
    assert cur.fetchone()[0] == original_id

    # The original is untouched -- still exactly its two original entries.
    cur.execute("SELECT count(*) FROM ledger_entries WHERE ledger_transaction_id = %s", (original_id,))
    assert cur.fetchone()[0] == 2
