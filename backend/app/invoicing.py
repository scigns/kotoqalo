"""Sequential, gapless invoice numbering (see
alembic/versions/0005_invoices.py's invoice_number_counters table for
why this is a dedicated per-year counter row rather than a bare
SEQUENCE)."""


def allocate_invoice_number(db, year: int) -> tuple[str, int]:
    """Returns (invoice_number, invoice_seq). Must be called within the
    same request-scoped transaction that inserts the invoice row (see
    app/db.py's get_db) -- the SELECT ... FOR UPDATE lock is held until
    that transaction commits or rolls back, serializing concurrent
    invoice creation within a year exactly like the ledger chain-tip
    lock serializes ledger postings.
    """
    cur = db.cursor()
    cur.execute(
        "INSERT INTO invoice_number_counters (invoice_year, last_number) VALUES (%s, 0) "
        "ON CONFLICT (invoice_year) DO NOTHING",
        (year,),
    )
    cur.execute(
        "SELECT last_number FROM invoice_number_counters WHERE invoice_year = %s FOR UPDATE",
        (year,),
    )
    last_number = cur.fetchone()[0]
    next_number = last_number + 1
    cur.execute(
        "UPDATE invoice_number_counters SET last_number = %s WHERE invoice_year = %s",
        (next_number, year),
    )
    invoice_number = f"INV-{year}-{next_number:06d}"
    return invoice_number, next_number
