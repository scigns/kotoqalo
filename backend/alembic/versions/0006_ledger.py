"""append-only double-entry ledger

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- The transaction "header". Corrections are made by inserting a
        -- new ledger_transaction that reverses an earlier one
        -- (reversal_of_transaction_id), never by editing or deleting the
        -- original -- posted history is permanent.
        CREATE TABLE ledger_transactions (
            id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            transaction_date           date NOT NULL,
            description                text NOT NULL,
            reference_type             text NOT NULL,
            reference_id                uuid,
            reversal_of_transaction_id  uuid REFERENCES ledger_transactions(id),
            created_by                  uuid NOT NULL REFERENCES users(id),
            created_at                  timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX ledger_transactions_date_idx ON ledger_transactions (transaction_date);
        CREATE INDEX ledger_transactions_reference_idx ON ledger_transactions (reference_type, reference_id);
        """
    )

    op.execute(
        """
        -- Double-entry lines. "amount" is always positive; "direction"
        -- says debit or credit. currency_code lives here (not on the
        -- account) so a single chart of accounts serves AUD/FJD/USD/...
        -- without schema changes.
        CREATE TABLE ledger_entries (
            id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            ledger_transaction_id   uuid NOT NULL REFERENCES ledger_transactions(id),
            account_id              uuid NOT NULL REFERENCES chart_of_accounts(id),
            currency_code           char(3) NOT NULL REFERENCES currencies(code),
            direction                ledger_direction NOT NULL,
            amount                  numeric(18, 4) NOT NULL CHECK (amount > 0),
            created_by              uuid NOT NULL REFERENCES users(id),
            created_at              timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX ledger_entries_transaction_id_idx ON ledger_entries (ledger_transaction_id);
        CREATE INDEX ledger_entries_account_id_idx ON ledger_entries (account_id);
        """
    )

    op.execute(
        """
        -- Financial-integrity guard: every ledger_transaction must balance
        -- (sum of debits = sum of credits) independently per currency.
        -- Deferred to commit time so the application can insert all lines
        -- of a transaction across several statements before the check
        -- runs.
        CREATE FUNCTION check_ledger_transaction_balance() RETURNS trigger AS $$
        DECLARE
            imbalance numeric;
        BEGIN
            SELECT COALESCE(SUM(CASE WHEN direction = 'debit' THEN amount ELSE -amount END), 0)
            INTO imbalance
            FROM ledger_entries
            WHERE ledger_transaction_id = NEW.ledger_transaction_id
              AND currency_code = NEW.currency_code;

            IF imbalance <> 0 THEN
                RAISE EXCEPTION
                    'ledger_transaction % does not balance for currency %: debits minus credits = %',
                    NEW.ledger_transaction_id, NEW.currency_code, imbalance
                    USING ERRCODE = 'raise_exception';
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;

        CREATE CONSTRAINT TRIGGER ledger_entries_balance_check
            AFTER INSERT ON ledger_entries
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION check_ledger_transaction_balance();
        """
    )

    op.execute(
        """
        -- Append-only: no UPDATE or DELETE, ever, on posted entries.
        -- Paired with a REVOKE of those privileges from the application
        -- role in a later migration.
        CREATE TRIGGER ledger_transactions_prevent_mutation
            BEFORE UPDATE OR DELETE ON ledger_transactions
            FOR EACH ROW EXECUTE FUNCTION prevent_mutation();

        CREATE TRIGGER ledger_entries_prevent_mutation
            BEFORE UPDATE OR DELETE ON ledger_entries
            FOR EACH ROW EXECUTE FUNCTION prevent_mutation();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS ledger_entries_prevent_mutation ON ledger_entries;")
    op.execute("DROP TRIGGER IF EXISTS ledger_transactions_prevent_mutation ON ledger_transactions;")
    op.execute("DROP TRIGGER IF EXISTS ledger_entries_balance_check ON ledger_entries;")
    op.execute("DROP FUNCTION IF EXISTS check_ledger_transaction_balance();")
    op.execute("DROP TABLE IF EXISTS ledger_entries;")
    op.execute("DROP TABLE IF EXISTS ledger_transactions;")
