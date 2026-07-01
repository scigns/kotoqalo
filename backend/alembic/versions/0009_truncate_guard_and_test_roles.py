"""truncate guard on append-only tables; role impersonation for testing

Revision ID: 0009
Revises: 0008
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- BEFORE UPDATE/DELETE triggers do not fire for TRUNCATE, and
        -- app_rw was never granted TRUNCATE -- but the owning/migrator
        -- role still has it implicitly. This statement-level trigger
        -- closes that gap so append-only really means append-only,
        -- regardless of which role issues the command.
        CREATE FUNCTION prevent_truncate() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION
                'table % is append-only: TRUNCATE is not permitted', TG_TABLE_NAME
                USING ERRCODE = 'raise_exception';
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER ledger_transactions_prevent_truncate
            BEFORE TRUNCATE ON ledger_transactions
            FOR EACH STATEMENT EXECUTE FUNCTION prevent_truncate();

        CREATE TRIGGER ledger_entries_prevent_truncate
            BEFORE TRUNCATE ON ledger_entries
            FOR EACH STATEMENT EXECUTE FUNCTION prevent_truncate();

        CREATE TRIGGER audit_log_prevent_truncate
            BEFORE TRUNCATE ON audit_log
            FOR EACH STATEMENT EXECUTE FUNCTION prevent_truncate();
        """
    )

    op.execute(
        """
        -- Let the schema-owning role assume the lower-privileged runtime
        -- roles. This is a de-escalation path only (dreamers_migrator
        -- already has superset privileges as table owner) and exists so
        -- test suites and admin scripts can exercise the exact privilege
        -- boundary the application runs under, via SET ROLE, instead of
        -- managing a separate password/connection per role.
        GRANT app_rw TO dreamers_migrator;
        GRANT app_ro TO dreamers_migrator;
        """
    )


def downgrade() -> None:
    op.execute("REVOKE app_ro FROM dreamers_migrator;")
    op.execute("REVOKE app_rw FROM dreamers_migrator;")
    op.execute("DROP TRIGGER IF EXISTS audit_log_prevent_truncate ON audit_log;")
    op.execute("DROP TRIGGER IF EXISTS ledger_entries_prevent_truncate ON ledger_entries;")
    op.execute("DROP TRIGGER IF EXISTS ledger_transactions_prevent_truncate ON ledger_transactions;")
    op.execute("DROP FUNCTION IF EXISTS prevent_truncate();")
