"""append-only audit log

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- One row per mutating action across contracts/invoices/ledger/
        -- users/roles, recording who did what, when, and the full
        -- before/after state. actor_user_id is nullable to allow
        -- system/service-initiated actions (e.g. a scheduled job), but
        -- per the human-in-the-loop requirement, no external money
        -- movement may originate from a system actor alone -- that's
        -- enforced at the application layer in Phase 4.
        -- Append-only for the same reason as the ledger: an audit trail
        -- that can be edited or deleted is not a trail.
        CREATE TABLE audit_log (
            id             bigserial PRIMARY KEY,
            actor_user_id  uuid REFERENCES users(id),
            actor_role     user_role,
            action         text NOT NULL,
            entity_type    text NOT NULL,
            entity_id      uuid,
            before_state   jsonb,
            after_state    jsonb,
            occurred_at    timestamptz NOT NULL DEFAULT now(),
            ip_address     inet,
            request_id     uuid
        );

        CREATE INDEX audit_log_entity_idx ON audit_log (entity_type, entity_id);
        CREATE INDEX audit_log_actor_idx ON audit_log (actor_user_id);
        CREATE INDEX audit_log_occurred_at_idx ON audit_log (occurred_at);

        CREATE TRIGGER audit_log_prevent_mutation
            BEFORE UPDATE OR DELETE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION prevent_mutation();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_prevent_mutation ON audit_log;")
    op.execute("DROP TABLE IF EXISTS audit_log;")
