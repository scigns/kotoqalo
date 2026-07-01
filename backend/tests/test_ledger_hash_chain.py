"""Proves the ledger's hash chain is computed correctly and is verifiable
independently of the database (i.e. by recomputing in Python), which is
the whole point of tamper-evidence: you don't have to trust the live
database's own bookkeeping to detect a spliced or edited row.
"""

import hashlib
import os
import threading
import uuid

import psycopg

GENESIS_HASH = hashlib.sha256(b"dreamers-media-pacific-ledger-genesis").digest()


def _expected_row_hash(previous_hash, ledger_transaction_id, account_id, currency_code, direction, amount, created_by):
    material = ":".join(
        [
            previous_hash.hex(),
            str(ledger_transaction_id),
            str(account_id),
            currency_code,
            direction,
            str(amount),
            str(created_by),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).digest()


def _insert_ledger_transaction(db, user_id, description):
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO ledger_transactions (transaction_date, description, reference_type, created_by)
        VALUES (CURRENT_DATE, %s, 'manual_adjustment', %s)
        RETURNING id
        """,
        (description, user_id),
    )
    return cur.fetchone()[0]


def _insert_entry(db, user_id, transaction_id, account_id, direction, amount, currency="AUD"):
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO ledger_entries (ledger_transaction_id, account_id, currency_code, direction, amount, created_by)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id, chain_seq, previous_hash, row_hash, currency_code, direction, amount, created_by
        """,
        (transaction_id, account_id, currency, direction, amount, user_id),
    )
    row = cur.fetchone()
    return {
        "id": row[0],
        "chain_seq": row[1],
        "previous_hash": bytes(row[2]),
        "row_hash": bytes(row[3]),
        "currency_code": row[4],
        "direction": row[5],
        "amount": row[6],
        "created_by": row[7],
    }


def test_first_entry_in_an_empty_ledger_chains_from_genesis(db, seed):
    db.cursor().execute("SET ROLE app_rw")
    uid = seed["user_id"]
    txn_id = _insert_ledger_transaction(db, uid, "Invoice #1 issued")
    entry = _insert_entry(db, uid, txn_id, seed["ar_account_id"], "debit", "100.00")

    assert entry["previous_hash"] == GENESIS_HASH
    assert entry["row_hash"] == _expected_row_hash(
        GENESIS_HASH,
        txn_id,
        seed["ar_account_id"],
        entry["currency_code"],
        entry["direction"],
        entry["amount"],
        entry["created_by"],
    )


def test_chain_links_consecutive_entries_and_is_independently_verifiable(db, seed):
    db.cursor().execute("SET ROLE app_rw")
    uid = seed["user_id"]
    txn_id = _insert_ledger_transaction(db, uid, "Invoice #2 issued")

    first = _insert_entry(db, uid, txn_id, seed["ar_account_id"], "debit", "50.00")
    second = _insert_entry(db, uid, txn_id, seed["revenue_account_id"], "credit", "50.00")
    db.cursor().execute("SET CONSTRAINTS ledger_entries_balance_check IMMEDIATE")

    assert second["chain_seq"] > first["chain_seq"]
    # The chain link: each row's previous_hash is the prior row's row_hash.
    assert second["previous_hash"] == first["row_hash"]

    # Recomputing both hashes in Python from the stored plaintext fields
    # (not trusting anything the database claims about itself) reproduces
    # exactly what's stored -- this is what a tamper check would do
    # against an export of the table.
    expected_first = _expected_row_hash(
        GENESIS_HASH, txn_id, seed["ar_account_id"], first["currency_code"], first["direction"], first["amount"], first["created_by"]
    )
    expected_second = _expected_row_hash(
        first["row_hash"],
        txn_id,
        seed["revenue_account_id"],
        second["currency_code"],
        second["direction"],
        second["amount"],
        second["created_by"],
    )
    assert first["row_hash"] == expected_first
    assert second["row_hash"] == expected_second


def test_concurrent_inserts_do_not_fork_the_chain(db, seed):
    """The FOR UPDATE lock on the chain tip means even multiple entries
    inserted in the same transaction end up in one unbroken sequence,
    not a fork -- this test just pins that behavior for a single writer;
    genuine concurrency safety comes from the row lock itself."""
    db.cursor().execute("SET ROLE app_rw")
    uid = seed["user_id"]
    txn_id = _insert_ledger_transaction(db, uid, "Invoice #3 issued")

    entries = [
        _insert_entry(db, uid, txn_id, seed["ar_account_id"], "debit", "10.00"),
        _insert_entry(db, uid, txn_id, seed["revenue_account_id"], "credit", "5.00"),
        _insert_entry(db, uid, txn_id, seed["revenue_account_id"], "credit", "5.00"),
    ]
    db.cursor().execute("SET CONSTRAINTS ledger_entries_balance_check IMMEDIATE")

    seqs = [e["chain_seq"] for e in entries]
    assert seqs == sorted(seqs)
    for prev, curr in zip(entries, entries[1:]):
        assert curr["previous_hash"] == prev["row_hash"]


def _raw_app_rw_connection():
    """A genuinely separate session (not the shared, single-transaction
    `db` fixture), needed to exercise real cross-connection locking --
    two statements on one connection can never race with each other."""
    url = os.environ["MIGRATOR_DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://")
    conn = psycopg.connect(url, autocommit=False)
    conn.cursor().execute("SET ROLE app_rw")
    return conn


def _create_user(conn) -> str:
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (external_auth_subject, email, full_name) VALUES (%s, %s, 'Concurrency Test User') RETURNING id",
        (f"test|{uuid.uuid4()}", f"{uuid.uuid4()}@example.test"),
    )
    return cur.fetchone()[0]


def test_two_connections_serialize_on_the_chain_tip_lock(db):
    """The bug this migration's design fixes: SELECT ... FOR UPDATE
    against zero rows takes no lock at all, so if the chain tip were
    looked up as "the last row of ledger_entries" (absent on an empty
    ledger), two concurrent first-inserts could both read "no previous
    row" and both chain from genesis, forking the chain. Moving the tip
    into its own always-exactly-one-row table means FOR UPDATE always
    has something to lock, so a second, truly concurrent connection must
    block until the first one finishes -- proven here directly by timing,
    not inferred from sequential inserts in one transaction (see
    test_concurrent_inserts_do_not_fork_the_chain above, which only
    proves that weaker, single-writer case).

    account_id references chart_of_accounts, which migrations seed as
    committed reference data, so both connections can see it without
    needing to share any uncommitted fixture state across connections.
    """
    del db  # only used to ensure Postgres is reachable/set up; not used directly

    conn_a = _raw_app_rw_connection()
    conn_b = _raw_app_rw_connection()
    try:
        cur = conn_a.cursor()
        cur.execute("SELECT id FROM chart_of_accounts WHERE code = '1000'")
        ar_account_id = cur.fetchone()[0]

        user_a = _create_user(conn_a)
        txn_a = _insert_ledger_transaction(conn_a, user_a, "A: concurrent first insert")
        _insert_entry(conn_a, user_a, txn_a, ar_account_id, "debit", "1.00")
        # conn_a now holds the FOR UPDATE lock on ledger_chain_tip,
        # uncommitted.

        b_done = threading.Event()

        def _insert_on_b():
            user_b = _create_user(conn_b)
            txn_b = _insert_ledger_transaction(conn_b, user_b, "B: concurrent first insert")
            _insert_entry(conn_b, user_b, txn_b, ar_account_id, "debit", "1.00")
            b_done.set()

        thread = threading.Thread(target=_insert_on_b)
        thread.start()
        thread.join(timeout=1.0)

        assert not b_done.is_set(), (
            "connection B completed its insert without blocking -- the chain-tip "
            "lock is not serializing concurrent first-inserts"
        )

        # Releasing A's lock (via rollback, so nothing is actually kept)
        # must unblock B.
        conn_a.rollback()
        thread.join(timeout=5.0)
        assert b_done.is_set(), "connection B never completed after the lock was released"
    finally:
        conn_a.rollback()
        conn_b.rollback()
        conn_a.close()
        conn_b.close()
