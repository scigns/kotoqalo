"""document app-layer encrypted columns

Revision ID: 0012
Revises: 0011
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- No schema change -- these bytea columns were created in
        -- 0004_clients_contracts_milestones.py as opaque placeholders
        -- for the app-layer envelope encryption built in Phase 3
        -- (see backend/app/crypto.py). COMMENT ON COLUMN records that
        -- fact directly in the schema catalog (visible via \\d+ clients
        -- in psql) so a future DBA/auditor inspecting the schema knows
        -- these are AES-256-GCM ciphertext, not raw data, and that the
        -- decryption key is never stored in this database.
        COMMENT ON COLUMN clients.contact_email_encrypted IS
            'AES-256-GCM ciphertext (nonce || ciphertext+tag), app-layer encrypted via backend/app/crypto.py. Key is sourced from a KeyProvider (Infisical in production), never stored in this database.';
        COMMENT ON COLUMN clients.contact_phone_encrypted IS
            'AES-256-GCM ciphertext (nonce || ciphertext+tag), app-layer encrypted via backend/app/crypto.py. Key is sourced from a KeyProvider (Infisical in production), never stored in this database.';
        COMMENT ON COLUMN clients.billing_address_encrypted IS
            'AES-256-GCM ciphertext (nonce || ciphertext+tag), app-layer encrypted via backend/app/crypto.py. Key is sourced from a KeyProvider (Infisical in production), never stored in this database.';
        """
    )


def downgrade() -> None:
    op.execute(
        """
        COMMENT ON COLUMN clients.contact_email_encrypted IS NULL;
        COMMENT ON COLUMN clients.contact_phone_encrypted IS NULL;
        COMMENT ON COLUMN clients.billing_address_encrypted IS NULL;
        """
    )
