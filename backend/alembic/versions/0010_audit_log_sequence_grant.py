"""grant sequence privilege backing audit_log's bigserial id

Revision ID: 0010
Revises: 0009
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- bigserial's implicit sequence needs its own USAGE grant --
        -- table-level INSERT privilege alone does not cover nextval() on
        -- the backing sequence. Without this, app_rw's inserts into
        -- audit_log (the append-only audit trail itself) fail outright.
        GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO app_rw;
        """
    )


def downgrade() -> None:
    op.execute("REVOKE USAGE, SELECT ON SEQUENCE audit_log_id_seq FROM app_rw;")
