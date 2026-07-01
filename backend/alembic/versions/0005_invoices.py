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
        --
        -- Deliberately fail-closed: MUTABLE_FIELDS names the columns that
        -- stay editable post-issuance, and everything else is frozen by
        -- comparing the whole row (via to_jsonb) minus those fields. A
        -- future migration that adds a new financial column to invoices
        -- is automatically frozen by this trigger with no code change
        -- needed here -- the opposite of enumerating "frozen" columns by
        -- name, which would leave a forgotten new column silently
        -- mutable.
        CREATE FUNCTION guard_invoice_financial_fields() RETURNS trigger AS $$
        DECLARE
            mutable_fields CONSTANT text[] := ARRAY['status', 'issued_at', 'due_date', 'pdf_object_key', 'updated_by', 'updated_at'];
        BEGIN
            IF OLD.status <> 'draft' THEN
                IF (to_jsonb(OLD) - mutable_fields) IS DISTINCT FROM (to_jsonb(NEW) - mutable_fields) THEN
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

    op.execute(
        """
        -- status is in guard_invoice_financial_fields()'s own
        -- mutable_fields list (status must be changeable to progress
        -- issued -> paid / issued -> void), but that trigger only
        -- freezes fields *while* OLD.status <> 'draft' -- it has no
        -- opinion on which status transitions are themselves valid. That
        -- leaves a gap: setting status back to 'draft' on an
        -- issued/paid/void invoice would silently make every other
        -- financial field editable again on the *next* update (since
        -- guard_invoice_financial_fields would then see OLD.status =
        -- 'draft' and skip the freeze entirely), reopening exactly what
        -- the freeze exists to close. invoice_status only has four
        -- values (draft, issued, paid, void -- see
        -- 0001_enums_and_helpers.py), so "any non-draft status ->
        -- draft" is the complete set of reversions to forbid; this does
        -- not otherwise constrain which forward transitions are valid
        -- (e.g. issued -> void, issued -> paid), only that draft is a
        -- one-way door once left.
        CREATE FUNCTION guard_invoice_status_transitions() RETURNS trigger AS $$
        BEGIN
            IF OLD.status IN ('issued', 'paid', 'void') AND NEW.status = 'draft' THEN
                RAISE EXCEPTION
                    'invoice % cannot revert from status % back to draft -- this would silently unfreeze its financial fields on the next update; post a correction instead',
                    OLD.id, OLD.status
                    USING ERRCODE = 'raise_exception';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER invoices_guard_status_transitions
            BEFORE UPDATE ON invoices
            FOR EACH ROW EXECUTE FUNCTION guard_invoice_status_transitions();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS invoices_guard_status_transitions ON invoices;")
    op.execute("DROP FUNCTION IF EXISTS guard_invoice_status_transitions();")
    op.execute("DROP TRIGGER IF EXISTS invoices_guard_financial_fields ON invoices;")
    op.execute("DROP FUNCTION IF EXISTS guard_invoice_financial_fields();")
    op.execute("DROP TABLE IF EXISTS invoices;")
    op.execute("DROP TABLE IF EXISTS invoice_number_counters;")
