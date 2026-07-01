"""enums and helper trigger functions

Revision ID: 0001
Revises:
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TYPE user_role AS ENUM ('owner_admin', 'bookkeeper', 'read_only_auditor');
        CREATE TYPE contract_status AS ENUM ('draft', 'active', 'completed', 'cancelled');
        CREATE TYPE milestone_status AS ENUM ('pending', 'invoiced', 'paid', 'cancelled');
        CREATE TYPE invoice_status AS ENUM ('draft', 'issued', 'paid', 'void');
        CREATE TYPE account_type AS ENUM ('asset', 'liability', 'equity', 'revenue', 'expense');
        CREATE TYPE ledger_direction AS ENUM ('debit', 'credit');
        """
    )

    op.execute(
        """
        -- Generic "touch updated_at" trigger, reused by every mutable table.
        CREATE FUNCTION set_updated_at() RETURNS trigger AS $$
        BEGIN
            NEW.updated_at := now();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    op.execute(
        """
        -- Generic append-only guard. Attached as a BEFORE UPDATE OR DELETE
        -- trigger on any table that must never be mutated once a row exists
        -- (ledger_transactions, ledger_entries, audit_log). This is
        -- defense-in-depth on top of REVOKE UPDATE/DELETE granted to the
        -- application role: the REVOKE stops the app, this trigger stops
        -- any other client (including the migration/owner role, unless the
        -- trigger is explicitly disabled, which is itself a loud, auditable
        -- DDL statement).
        CREATE FUNCTION prevent_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION
                'table % is append-only: % is not permitted (row id: %)',
                TG_TABLE_NAME, TG_OP, COALESCE(OLD.id::text, 'unknown')
                USING ERRCODE = 'raise_exception';
        END;
        $$ LANGUAGE plpgsql;
        """
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS prevent_mutation();")
    op.execute("DROP FUNCTION IF EXISTS set_updated_at();")
    op.execute(
        """
        DROP TYPE IF EXISTS ledger_direction;
        DROP TYPE IF EXISTS account_type;
        DROP TYPE IF EXISTS invoice_status;
        DROP TYPE IF EXISTS milestone_status;
        DROP TYPE IF EXISTS contract_status;
        DROP TYPE IF EXISTS user_role;
        """
    )
