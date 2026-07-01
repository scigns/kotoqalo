"""hash-chain the ledger for tamper-evidence

Revision ID: 0011
Revises: 0010
Create Date: 2026-07-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- pgcrypto is used here only for digest() (SHA-256 hashing), not
        -- for its symmetric-encryption functions -- PII/bank identifiers
        -- are still handled by app-layer envelope encryption (Phase 3),
        -- not a DB-level static key.
        CREATE EXTENSION IF NOT EXISTS pgcrypto;
        """
    )

    op.execute(
        """
        -- Tamper-evidence layered on top of the append-only guarantees
        -- already enforced by REVOKE + triggers: each row's hash commits
        -- to the previous row's hash, so altering or splicing historical
        -- rows (e.g. via a restored/edited backup, or direct disk-level
        -- tampering that bypasses the running Postgres instance's
        -- triggers entirely) is detectable by recomputing the chain,
        -- independent of trusting the live database's own enforcement.
        -- chain_seq gives a strict insertion order independent of the
        -- UUID primary key (UUIDs aren't sortable by insertion time), for
        -- readers reconstructing/verifying the chain later.
        ALTER TABLE ledger_entries
            ADD COLUMN chain_seq bigint GENERATED ALWAYS AS IDENTITY,
            ADD COLUMN previous_hash bytea,
            ADD COLUMN row_hash bytea;

        CREATE UNIQUE INDEX ledger_entries_chain_seq_key ON ledger_entries (chain_seq);
        """
    )

    op.execute(
        """
        -- The chain "tip" lives in its own always-exactly-one-row table
        -- rather than being looked up as "the last row of ledger_entries
        -- ORDER BY chain_seq DESC LIMIT 1". That lookup approach has a
        -- race: SELECT ... FOR UPDATE takes no lock at all when it
        -- matches zero rows, so on an empty ledger (or more precisely,
        -- whenever no row currently exists to lock), two concurrent
        -- first-inserts would both see "no previous row", both compute
        -- previous_hash = genesis, and both commit -- forking the chain
        -- at the very point tamper-evidence matters most. A single
        -- always-present row (id is constrained to the literal value 1)
        -- is never absent, so FOR UPDATE always has something to lock,
        -- and it also makes each insert's lock O(1) rather than an index
        -- descent to the tail of a growing table.
        CREATE TABLE ledger_chain_tip (
            id        smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            last_hash bytea NOT NULL
        );

        INSERT INTO ledger_chain_tip (id, last_hash)
        VALUES (1, digest('dreamers-media-pacific-ledger-genesis', 'sha256'));
        """
    )

    op.execute(
        """
        -- Every insert takes a FOR UPDATE lock on the single chain-tip
        -- row, serializing ledger writes -- an intentional trade-off
        -- (same shape as the invoice-number-counter serialization
        -- point), acceptable at this business's transaction volume.
        -- SECURITY DEFINER: FOR UPDATE/UPDATE require privileges app_rw
        -- deliberately does not have on these tables (no grants at all
        -- on ledger_chain_tip, and no UPDATE on ledger_entries -- that's
        -- the whole point of the append-only grant). Running as the
        -- function's owner (dreamers_migrator, a schema-owning role)
        -- resolves that without widening app_rw's own privileges.
        -- search_path is pinned to guard against the classic SECURITY
        -- DEFINER search_path-hijack risk, even though app_rw has no
        -- CREATE privilege on this schema to exploit it anyway.
        CREATE FUNCTION chain_ledger_entry_hash() RETURNS trigger
        SECURITY DEFINER
        SET search_path = public
        AS $$
        DECLARE
            prev_hash bytea;
        BEGIN
            SELECT last_hash INTO prev_hash FROM ledger_chain_tip WHERE id = 1 FOR UPDATE;

            NEW.previous_hash := prev_hash;
            NEW.row_hash := digest(
                convert_to(
                    encode(prev_hash, 'hex') || ':' ||
                    NEW.ledger_transaction_id::text || ':' ||
                    NEW.account_id::text || ':' ||
                    NEW.currency_code || ':' ||
                    NEW.direction::text || ':' ||
                    NEW.amount::text || ':' ||
                    NEW.created_by::text,
                    'UTF8'
                ),
                'sha256'
            );

            UPDATE ledger_chain_tip SET last_hash = NEW.row_hash WHERE id = 1;

            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER ledger_entries_chain_hash
            BEFORE INSERT ON ledger_entries
            FOR EACH ROW EXECUTE FUNCTION chain_ledger_entry_hash();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS ledger_entries_chain_hash ON ledger_entries;")
    op.execute("DROP FUNCTION IF EXISTS chain_ledger_entry_hash();")
    op.execute("DROP TABLE IF EXISTS ledger_chain_tip;")
    op.execute("DROP INDEX IF EXISTS ledger_entries_chain_seq_key;")
    op.execute(
        """
        ALTER TABLE ledger_entries
            DROP COLUMN IF EXISTS row_hash,
            DROP COLUMN IF EXISTS previous_hash,
            DROP COLUMN IF EXISTS chain_seq;
        """
    )
