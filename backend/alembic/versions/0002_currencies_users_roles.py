"""currencies, users, user_roles

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- Reference table for supported currencies. New currencies (e.g.
        -- NZD, EUR) are added by inserting a row here, not by migrating the
        -- schema, so amount columns elsewhere are just numeric + a
        -- currency_code FK -- no per-currency columns anywhere.
        CREATE TABLE currencies (
            code        char(3) PRIMARY KEY,
            name        text NOT NULL,
            minor_unit  smallint NOT NULL DEFAULT 2 CHECK (minor_unit BETWEEN 0 AND 6),
            is_active   boolean NOT NULL DEFAULT true
        );

        INSERT INTO currencies (code, name, minor_unit) VALUES
            ('AUD', 'Australian Dollar', 2),
            ('FJD', 'Fijian Dollar', 2),
            ('USD', 'United States Dollar', 2);
        """
    )

    op.execute(
        """
        -- external_auth_subject is the "sub" claim from the managed auth
        -- provider (Auth0/Clerk/Supabase Auth etc, wired up in Phase 2).
        -- No password hash is stored here -- authentication is fully
        -- delegated to the provider.
        CREATE TABLE users (
            id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            external_auth_subject   text NOT NULL,
            email                   text NOT NULL,
            full_name               text NOT NULL,
            is_active               boolean NOT NULL DEFAULT true,
            created_at              timestamptz NOT NULL DEFAULT now(),
            updated_at              timestamptz NOT NULL DEFAULT now()
        );

        CREATE UNIQUE INDEX users_external_auth_subject_key ON users (external_auth_subject);
        CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

        CREATE TRIGGER users_set_updated_at
            BEFORE UPDATE ON users
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
        """
    )

    op.execute(
        """
        -- A user may hold more than one role simultaneously (e.g. the
        -- solo founder today holds owner_admin; later a bookkeeper is
        -- added as a separate user). Rows are never deleted so the
        -- grant/revoke history survives -- revoking access sets
        -- revoked_at rather than removing the row. audit_log additionally
        -- records the before/after state of every change here.
        CREATE TABLE user_roles (
            user_id     uuid NOT NULL REFERENCES users(id),
            role        user_role NOT NULL,
            granted_by  uuid REFERENCES users(id),
            granted_at  timestamptz NOT NULL DEFAULT now(),
            revoked_at  timestamptz,
            PRIMARY KEY (user_id, role)
        );
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS user_roles;")
    op.execute("DROP TABLE IF EXISTS users;")
    op.execute("DROP TABLE IF EXISTS currencies;")
