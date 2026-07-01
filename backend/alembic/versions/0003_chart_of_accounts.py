"""chart of accounts

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- Minimal double-entry chart of accounts. ledger_entries always
        -- posts against an account here; accounts are currency-agnostic
        -- (an "Accounts Receivable" account can hold AUD, FJD, and USD
        -- entries -- the currency lives on the entry, not the account) so
        -- adding a currency never requires new accounts or a migration.
        CREATE TABLE chart_of_accounts (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            code         text NOT NULL,
            name         text NOT NULL,
            account_type account_type NOT NULL,
            is_active    boolean NOT NULL DEFAULT true,
            created_at   timestamptz NOT NULL DEFAULT now()
        );

        CREATE UNIQUE INDEX chart_of_accounts_code_key ON chart_of_accounts (code);

        INSERT INTO chart_of_accounts (code, name, account_type) VALUES
            ('1000', 'Accounts Receivable', 'asset'),
            ('1010', 'Cash / Wise Balance', 'asset'),
            ('2000', 'GST / Tax Payable', 'liability'),
            ('2010', 'Client Deposits Held', 'liability'),
            ('4000', 'Consulting Revenue', 'revenue'),
            ('5000', 'Bank & Transfer Fees', 'expense'),
            ('5010', 'Foreign Exchange Gain/Loss', 'expense');
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS chart_of_accounts;")
