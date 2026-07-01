"""clients, contracts, milestones

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- Contact PII (email/phone/address) is stored as ciphertext
        -- produced by the application's envelope-encryption layer
        -- (Phase 3: a KMS-managed data key, not a static DB-level key), so
        -- these columns are opaque bytea here. tax_id (ABN/TIN) is stored
        -- in the clear -- Australian ABNs are public register data, not
        -- confidential PII, but flag before Phase 1 sign-off if any client
        -- has a jurisdiction where that assumption doesn't hold.
        CREATE TABLE clients (
            id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            display_name                text NOT NULL,
            legal_name                  text,
            country_code                char(2) NOT NULL,
            tax_id                      text,
            contact_email_encrypted     bytea,
            contact_phone_encrypted     bytea,
            billing_address_encrypted   bytea,
            notes                       text,
            is_active                   boolean NOT NULL DEFAULT true,
            created_by                  uuid NOT NULL REFERENCES users(id),
            created_at                  timestamptz NOT NULL DEFAULT now(),
            updated_by                  uuid REFERENCES users(id),
            updated_at                  timestamptz NOT NULL DEFAULT now()
        );

        CREATE TRIGGER clients_set_updated_at
            BEFORE UPDATE ON clients
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
        """
    )

    op.execute(
        """
        CREATE TABLE contracts (
            id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            client_id     uuid NOT NULL REFERENCES clients(id),
            title         text NOT NULL,
            description   text,
            currency_code char(3) NOT NULL REFERENCES currencies(code),
            total_value   numeric(18, 2) NOT NULL CHECK (total_value >= 0),
            status        contract_status NOT NULL DEFAULT 'draft',
            start_date    date,
            end_date      date,
            created_by    uuid NOT NULL REFERENCES users(id),
            created_at    timestamptz NOT NULL DEFAULT now(),
            updated_by    uuid REFERENCES users(id),
            updated_at    timestamptz NOT NULL DEFAULT now(),
            CHECK (end_date IS NULL OR start_date IS NULL OR end_date >= start_date)
        );

        CREATE INDEX contracts_client_id_idx ON contracts (client_id);

        CREATE TRIGGER contracts_set_updated_at
            BEFORE UPDATE ON contracts
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
        """
    )

    op.execute(
        """
        CREATE TABLE milestones (
            id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            contract_id   uuid NOT NULL REFERENCES contracts(id),
            title         text NOT NULL,
            description   text,
            amount        numeric(18, 2) NOT NULL CHECK (amount >= 0),
            currency_code char(3) NOT NULL REFERENCES currencies(code),
            due_date      date,
            status        milestone_status NOT NULL DEFAULT 'pending',
            created_by    uuid NOT NULL REFERENCES users(id),
            created_at    timestamptz NOT NULL DEFAULT now(),
            updated_by    uuid REFERENCES users(id),
            updated_at    timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX milestones_contract_id_idx ON milestones (contract_id);

        CREATE TRIGGER milestones_set_updated_at
            BEFORE UPDATE ON milestones
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS milestones;")
    op.execute("DROP TABLE IF EXISTS contracts;")
    op.execute("DROP TABLE IF EXISTS clients;")
