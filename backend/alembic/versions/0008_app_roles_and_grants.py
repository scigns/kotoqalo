"""least-privilege application roles and grants

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- app_rw: the runtime role used by the FastAPI service.
        -- app_ro: read-only role for reporting/BI tooling and, later, a
        -- DB-level backstop for the read-only-auditor API role.
        -- No password is set here -- passwords are provisioned
        -- out-of-band from the secrets manager (ALTER ROLE ... PASSWORD,
        -- run by an operator, never committed to source).
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'app_rw') THEN
                CREATE ROLE app_rw LOGIN;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'app_ro') THEN
                CREATE ROLE app_ro LOGIN;
            END IF;
        END
        $$;

        DO $$
        BEGIN
            EXECUTE format('GRANT CONNECT ON DATABASE %I TO app_rw, app_ro', current_database());
        END
        $$;

        GRANT USAGE ON SCHEMA public TO app_rw, app_ro;
        """
    )

    op.execute(
        """
        -- Reference data: read-only for both roles, maintained by
        -- migrations/an admin process, never by the running application.
        GRANT SELECT ON currencies TO app_rw, app_ro;
        GRANT SELECT ON chart_of_accounts TO app_rw, app_ro;

        -- Standard mutable entities: no DELETE grant anywhere -- records
        -- are deactivated via is_active/status, never hard-deleted, so
        -- financial history is never destroyed even for "ordinary" data.
        GRANT SELECT, INSERT, UPDATE ON users TO app_rw;
        GRANT SELECT ON users TO app_ro;

        GRANT SELECT, INSERT, UPDATE ON user_roles TO app_rw;
        GRANT SELECT ON user_roles TO app_ro;

        GRANT SELECT, INSERT, UPDATE ON clients TO app_rw;
        GRANT SELECT ON clients TO app_ro;

        GRANT SELECT, INSERT, UPDATE ON contracts TO app_rw;
        GRANT SELECT ON contracts TO app_ro;

        GRANT SELECT, INSERT, UPDATE ON milestones TO app_rw;
        GRANT SELECT ON milestones TO app_ro;

        GRANT SELECT, INSERT, UPDATE ON invoice_number_counters TO app_rw;
        GRANT SELECT ON invoice_number_counters TO app_ro;

        GRANT SELECT, INSERT, UPDATE ON invoices TO app_rw;
        GRANT SELECT ON invoices TO app_ro;
        """
    )

    op.execute(
        """
        -- Append-only tables: INSERT and SELECT only. No UPDATE, no
        -- DELETE grant at all -- this is the database-level enforcement
        -- of "no UPDATE/DELETE on posted transactions" required
        -- independent of the BEFORE UPDATE/DELETE triggers already
        -- attached to these tables.
        GRANT SELECT, INSERT ON ledger_transactions TO app_rw;
        GRANT SELECT ON ledger_transactions TO app_ro;

        GRANT SELECT, INSERT ON ledger_entries TO app_rw;
        GRANT SELECT ON ledger_entries TO app_ro;

        GRANT SELECT, INSERT ON audit_log TO app_rw;
        GRANT SELECT ON audit_log TO app_ro;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM app_rw, app_ro;
        REVOKE USAGE ON SCHEMA public FROM app_rw, app_ro;
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM app_rw, app_ro', current_database());
        END
        $$;
        """
    )
    op.execute("DROP ROLE IF EXISTS app_ro;")
    op.execute("DROP ROLE IF EXISTS app_rw;")
