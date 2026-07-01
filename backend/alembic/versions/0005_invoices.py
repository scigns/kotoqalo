"""invoice numbering and invoices

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- One counter row per calendar year, incremented with
        -- SELECT ... FOR UPDATE by the application inside the same
        -- transaction that inserts the invoice, giving a gapless,
        -- monotonically increasing sequence per year (INV-2026-000123)
        -- -- unlike a bare SEQUENCE, which can skip numbers on rollback.
        -- Trade-off: this row is a serialization point for invoice
        -- creation; acceptable at this business's transaction volume.
        CREATE TABLE invoice_number_counters (
            invoice_year  smallint PRIMARY KEY,
            last_number   integer NOT NULL DEFAULT 0 CHECK (last_number >= 0)
        );
        """
    )

    op.execute(
        """
        CREATE TABLE invoices (
            id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            invoice_number    text NOT NULL,
            invoice_year      smallint NOT NULL,
            invoice_seq       integer NOT NULL,
            contract_id       uuid NOT NULL REFERENCES contracts(id),
            milestone_id      uuid REFERENCES milestones(id),
            client_id         uuid NOT NULL REFERENCES clients(id),
            currency_code     char(3) NOT NULL REFERENCES currencies(code),
            subtotal_amount   numeric(18, 2) NOT NULL CHECK (subtotal_amount >= 0),
            tax_amount        numeric(18, 2) NOT NULL DEFAULT 0 CHECK (tax_amount >= 0),
            total_amount      numeric(18, 2) NOT NULL CHECK (total_amount >= 0),
            status            invoice_status NOT NULL DEFAULT 'draft',
            issued_at         timestamptz,
            due_date          date,
            pdf_object_key    text,
            created_by        uuid NOT NULL REFERENCES users(id),
            created_at        timestamptz NOT NULL DEFAULT now(),
            updated_by        uuid REFERENCES users(id),
            updated_at        timestamptz NOT NULL DEFAULT now()
        );

        CREATE UNIQUE INDEX invoices_invoice_number_key ON invoices (invoice_number);
        CREATE UNIQUE INDEX invoices_year_seq_key ON invoices (invoice_year, invoice_seq);
        CREATE INDEX invoices_contract_id_idx ON invoices (contract_id);
        CREATE INDEX invoices_client_id_idx ON invoices (client_id);
        CREATE INDEX invoices_status_idx ON invoices (status);

        CREATE TRIGGER invoices_set_updated_at
            BEFORE UPDATE ON invoices
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
        """
    )

    op.execute(
        """
        -- Once an invoice has left 'draft', its financial substance
        -- (amounts, currency, who it's billed to/for) cannot change --
        -- only status may progress (issued -> paid, issued -> void) and
        -- administrative fields like pdf_object_key/due_date. This keeps
        -- an issued tax invoice trustworthy without making the whole row
        -- append-only, since drafts genuinely need editing.
        CREATE FUNCTION guard_invoice_financial_fields() RETURNS trigger AS $$
        BEGIN
            IF OLD.status <> 'draft' THEN
                IF NEW.contract_id     IS DISTINCT FROM OLD.contract_id
                   OR NEW.milestone_id IS DISTINCT FROM OLD.milestone_id
                   OR NEW.client_id    IS DISTINCT FROM OLD.client_id
                   OR NEW.currency_code IS DISTINCT FROM OLD.currency_code
                   OR NEW.subtotal_amount IS DISTINCT FROM OLD.subtotal_amount
                   OR NEW.tax_amount      IS DISTINCT FROM OLD.tax_amount
                   OR NEW.total_amount    IS DISTINCT FROM OLD.total_amount
                   OR NEW.invoice_number  IS DISTINCT FROM OLD.invoice_number
                   OR NEW.invoice_year    IS DISTINCT FROM OLD.invoice_year
                   OR NEW.invoice_seq     IS DISTINCT FROM OLD.invoice_seq
                THEN
                    RAISE EXCEPTION
                        'invoice % has status %: financial fields are immutable once issued; post a correction instead',
                        OLD.id, OLD.status
                        USING ERRCODE = 'raise_exception';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER invoices_guard_financial_fields
            BEFORE UPDATE ON invoices
            FOR EACH ROW EXECUTE FUNCTION guard_invoice_financial_fields();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS invoices_guard_financial_fields ON invoices;")
    op.execute("DROP FUNCTION IF EXISTS guard_invoice_financial_fields();")
    op.execute("DROP TABLE IF EXISTS invoices;")
    op.execute("DROP TABLE IF EXISTS invoice_number_counters;")
