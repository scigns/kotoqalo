"""Double-entry ledger posting, writing through the append-only,
hash-chained tables from Phase 1 (ledger_transactions / ledger_entries,
via the ledger_chain_tip lock -- see
alembic/versions/0011_ledger_hash_chain.py).

Multi-statement postings (one transaction header + several entries) are
only atomic because app/db.py's get_db() commits once at the end of a
successful request (not per-statement) -- the deferred balance-check
constraint trigger fires at that commit, checking the whole posting as
a unit.
"""

from collections import defaultdict
from decimal import Decimal
from typing import Optional, TypedDict


class LedgerEntryInput(TypedDict):
    account_code: str
    direction: str  # "debit" | "credit"
    amount: Decimal
    currency_code: str


def _validate_entries(entries: list[LedgerEntryInput]) -> None:
    """Fails fast with a clean, catchable error before any DB write,
    rather than relying solely on the database's own guards (the
    deferred balance-check trigger and ledger_entries' CHECK(amount > 0)
    remain the authoritative last-resort checks, already proven in
    Phase 1's tests) -- this is so a caller gets an immediate, well-formed
    400 instead of a confusing failure partway through posting."""
    sums: dict[str, Decimal] = defaultdict(Decimal)
    for entry in entries:
        if entry["amount"] <= 0:
            raise ValueError(f"entry amount must be positive, got {entry['amount']}")
        signed = entry["amount"] if entry["direction"] == "debit" else -entry["amount"]
        sums[entry["currency_code"]] += signed
    for currency_code, total in sums.items():
        if total != 0:
            raise ValueError(f"ledger entries do not balance for {currency_code}: debits minus credits = {total}")


def post_ledger_transaction(
    db,
    actor_user_id: str,
    transaction_date,
    description: str,
    reference_type: str,
    reference_id: Optional[str],
    entries: list[LedgerEntryInput],
    reversal_of_transaction_id: Optional[str] = None,
) -> str:
    """Posts a balanced double-entry ledger transaction. Raises
    ValueError (caught by callers and turned into a 400) if entries
    don't balance, have a non-positive amount, or reference an unknown
    chart_of_accounts code -- all checked in Python *before* any INSERT,
    so a caller-side mistake never leaves a partially-written posting
    behind (an unknown account code discovered only after the
    transaction header and some entries were already inserted would
    otherwise depend entirely on the request-level rollback in
    app/db.py's get_db() to clean up, which is real but not something
    this function should assume is the only thing standing between it
    and an orphaned row).
    """
    _validate_entries(entries)

    cur = db.cursor()
    account_ids: list = []
    for entry in entries:
        cur.execute("SELECT id FROM chart_of_accounts WHERE code = %s", (entry["account_code"],))
        row = cur.fetchone()
        if row is None:
            raise ValueError(f"unknown chart_of_accounts code: {entry['account_code']!r}")
        account_ids.append(row[0])

        cur.execute("SELECT 1 FROM currencies WHERE code = %s", (entry["currency_code"],))
        if cur.fetchone() is None:
            raise ValueError(f"unknown currency code: {entry['currency_code']!r}")

    cur.execute(
        """
        INSERT INTO ledger_transactions (transaction_date, description, reference_type, reference_id, reversal_of_transaction_id, created_by)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (transaction_date, description, reference_type, reference_id, reversal_of_transaction_id, actor_user_id),
    )
    transaction_id = cur.fetchone()[0]

    for entry, account_id in zip(entries, account_ids):
        cur.execute(
            """
            INSERT INTO ledger_entries (ledger_transaction_id, account_id, currency_code, direction, amount, created_by)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (transaction_id, account_id, entry["currency_code"], entry["direction"], entry["amount"], actor_user_id),
        )

    return str(transaction_id)
