"""Unit-level tests for app/ledger.py's posting helper, independent of
any HTTP endpoint.
"""

from decimal import Decimal

import pytest

from app.ledger import post_ledger_transaction


def test_unbalanced_entries_raise_before_any_db_write(db, seed):
    db.cursor().execute("SET ROLE app_rw")
    with pytest.raises(ValueError, match="do not balance"):
        post_ledger_transaction(
            db,
            actor_user_id=seed["user_id"],
            transaction_date="2026-07-01",
            description="Deliberately unbalanced",
            reference_type="manual_adjustment",
            reference_id=None,
            entries=[
                {"account_code": "1000", "direction": "debit", "amount": Decimal("100.00"), "currency_code": "AUD"},
                {"account_code": "4000", "direction": "credit", "amount": Decimal("50.00"), "currency_code": "AUD"},
            ],
        )

    cur = db.cursor()
    cur.execute("SELECT count(*) FROM ledger_transactions WHERE description = 'Deliberately unbalanced'")
    assert cur.fetchone()[0] == 0, "the balance check must fail before any row is inserted, not after"


def test_balanced_entries_post_successfully(db, seed):
    db.cursor().execute("SET ROLE app_rw")
    transaction_id = post_ledger_transaction(
        db,
        actor_user_id=seed["user_id"],
        transaction_date="2026-07-01",
        description="Balanced test posting",
        reference_type="manual_adjustment",
        reference_id=None,
        entries=[
            {"account_code": "1000", "direction": "debit", "amount": Decimal("75.00"), "currency_code": "AUD"},
            {"account_code": "4000", "direction": "credit", "amount": Decimal("75.00"), "currency_code": "AUD"},
        ],
    )

    cur = db.cursor()
    cur.execute("SELECT count(*) FROM ledger_entries WHERE ledger_transaction_id = %s", (transaction_id,))
    assert cur.fetchone()[0] == 2


def test_unknown_account_code_raises(db, seed):
    db.cursor().execute("SET ROLE app_rw")
    with pytest.raises(ValueError, match="unknown chart_of_accounts code"):
        post_ledger_transaction(
            db,
            actor_user_id=seed["user_id"],
            transaction_date="2026-07-01",
            description="Bad account code",
            reference_type="manual_adjustment",
            reference_id=None,
            entries=[
                {"account_code": "9999", "direction": "debit", "amount": Decimal("10.00"), "currency_code": "AUD"},
                {"account_code": "4000", "direction": "credit", "amount": Decimal("10.00"), "currency_code": "AUD"},
            ],
        )
