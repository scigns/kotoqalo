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


def _expected_row_hash(previous_hash, entry_id, ledger_transaction_id, account_id, currency_code, direction, amount, created_by, created_at):
    """Mirrors chain_ledger_entry_hash()'s current formula: every real
    column of ledger_entries except the hash-chain bookkeeping columns
    themselves (chain_seq, previous_hash, row_hash)."""
    material = ":".join(
        [
            previous_hash.hex(),
            str(entry_id),
            str(ledger_transaction_id),
            str(account_id),
            currency_code,
            direction,
            str(amount),
            str(created_by),
            str(created_at),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).digest()


def _old_row_hash_formula(previous_hash, ledger_transaction_id, account_id, currency_code, direction, amount, created_by):
    """Reproduces the PRE-FIX formula exactly (6 named columns; no id, no
    created_at). Used only by the negative control below to prove that
    gap was real, not to validate current behavior."""
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
        RETURNING id, chain_seq, previous_hash, row_hash, currency_code, direction, amount, created_by, created_at::text
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
        "created_at": row[8],
    }


def test_entry_chains_from_the_current_tip(db, seed):
    """Doesn't assume the ledger is empty -- test_ledger_atomicity.py
    deliberately leaves a real, permanently-committed entry behind (see
    its own docstring), so GENESIS_HASH is only ever the tip's value on
    a genuinely fresh database. Capturing the tip immediately before
    inserting and asserting the new entry chains from *that* value tests
    the same invariant (chains from whatever the tip currently is)
    without depending on run order or a pristine database."""
    uid = seed["user_id"]
    # Peeked before SET ROLE app_rw: app_rw has no grants at all on
    # ledger_chain_tip (deliberately, per 0011's own comments), so this
    # read has to happen as the owning role.
    peek_cur = db.cursor()
    peek_cur.execute("SELECT last_hash FROM ledger_chain_tip WHERE id = 1")
    tip_before = bytes(peek_cur.fetchone()[0])

    db.cursor().execute("SET ROLE app_rw")
    txn_id = _insert_ledger_transaction(db, uid, "Invoice #1 issued")
    entry = _insert_entry(db, uid, txn_id, seed["ar_account_id"], "debit", "100.00")

    assert entry["previous_hash"] == tip_before
    assert entry["row_hash"] == _expected_row_hash(
        tip_before,
        entry["id"],
        txn_id,
        seed["ar_account_id"],
        entry["currency_code"],
        entry["direction"],
        entry["amount"],
        entry["created_by"],
        entry["created_at"],
    )


def test_chain_links_consecutive_entries_and_is_independently_verifiable(db, seed):
    uid = seed["user_id"]
    peek_cur = db.cursor()
    peek_cur.execute("SELECT last_hash FROM ledger_chain_tip WHERE id = 1")
    tip_before = bytes(peek_cur.fetchone()[0])

    db.cursor().execute("SET ROLE app_rw")
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
        tip_before,
        first["id"],
        txn_id,
        seed["ar_account_id"],
        first["currency_code"],
        first["direction"],
        first["amount"],
        first["created_by"],
        first["created_at"],
    )
    expected_second = _expected_row_hash(
        first["row_hash"],
        second["id"],
        txn_id,
        seed["revenue_account_id"],
        second["currency_code"],
        second["direction"],
        second["amount"],
        second["created_by"],
        second["created_at"],
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


def test_old_hash_formula_missed_column_tampering_new_formula_catches_it(db, seed):
    """Negative control for the row_hash coverage fix: the pre-fix
    formula committed to only 6 named columns and never touched id or
    created_at. This proves that gap was real: tampering with
    created_at via a connection that bypasses the append-only trigger
    entirely (simulating an out-of-band tamperer -- e.g. someone editing
    a restored backup or writing to the data files directly, not a
    normal application write, which the trigger already blocks) would
    have gone completely undetected by the old formula, and is caught by
    the current one.
    """
    db.cursor().execute("SET ROLE app_rw")
    uid = seed["user_id"]
    account_id = seed["ar_account_id"]
    txn_id = _insert_ledger_transaction(db, uid, "Tamper-detection negative control")
    entry = _insert_entry(db, uid, txn_id, account_id, "debit", "42.00")
    # Balance the transaction and force the deferred balance-check to
    # fire now -- ALTER TABLE below is disallowed while a deferred
    # trigger event is still pending on this table.
    _insert_entry(db, uid, txn_id, seed["revenue_account_id"], "credit", "42.00")
    db.cursor().execute("SET CONSTRAINTS ledger_entries_balance_check IMMEDIATE")

    # entry["row_hash"] is what the CURRENT (fixed) trigger actually
    # stored, computed from these original, untampered values.
    assert entry["row_hash"] == _expected_row_hash(
        entry["previous_hash"], entry["id"], txn_id, account_id,
        entry["currency_code"], entry["direction"], entry["amount"],
        entry["created_by"], entry["created_at"],
    )

    # What the OLD (pre-fix) formula would have produced for this same
    # original row, had it been the deployed formula at insert time --
    # computed from the same untampered values captured above, before
    # any tampering happens.
    old_formula_before_tamper = _old_row_hash_formula(
        entry["previous_hash"], txn_id, account_id, entry["currency_code"],
        entry["direction"], entry["amount"], entry["created_by"],
    )

    # Simulate an out-of-band tamperer: disabling the trigger is itself a
    # loud, auditable DDL statement (see prevent_mutation()'s own
    # docstring) -- this is exactly the threat model the hash chain
    # exists to catch, distinct from the REVOKE/trigger defenses that
    # stop a normal client outright.
    owner_cur = db.cursor()
    owner_cur.execute("RESET ROLE")
    owner_cur.execute("ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_prevent_mutation")
    tampered_created_at = "2020-01-01T00:00:00+00:00"
    owner_cur.execute(
        "UPDATE ledger_entries SET created_at = %s WHERE id = %s",
        (tampered_created_at, entry["id"]),
    )
    owner_cur.execute("ALTER TABLE ledger_entries ENABLE TRIGGER ledger_entries_prevent_mutation")

    owner_cur.execute("SELECT created_at::text FROM ledger_entries WHERE id = %s", (entry["id"],))
    tampered_created_at_value = owner_cur.fetchone()[0]
    assert str(tampered_created_at_value) != str(entry["created_at"]), (
        "tampering didn't actually change created_at -- test setup is broken"
    )

    # Recomputing with the OLD formula against the tampered row must
    # reproduce the SAME hash as before tampering, since the old formula
    # never looked at created_at in the first place -- the tampering is
    # completely invisible to it.
    old_formula_after_tamper = _old_row_hash_formula(
        entry["previous_hash"], txn_id, account_id, entry["currency_code"],
        entry["direction"], entry["amount"], entry["created_by"],
    )
    assert old_formula_after_tamper == old_formula_before_tamper, (
        "the old formula should be blind to created_at tampering by construction -- "
        "if this fails, the negative control setup itself is wrong, not proof of anything"
    )

    # Recomputing with the CURRENT (fixed) formula against the tampered
    # row must now disagree with what's actually stored -- exposing the
    # tampering that the old formula would have missed entirely.
    new_formula_after_tamper = _expected_row_hash(
        entry["previous_hash"], entry["id"], txn_id, account_id,
        entry["currency_code"], entry["direction"], entry["amount"],
        entry["created_by"], tampered_created_at_value,
    )
    assert new_formula_after_tamper != entry["row_hash"], (
        "the current formula includes created_at, so it must detect this tampering "
        "by producing a hash different from what's stored"
    )


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
