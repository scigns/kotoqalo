"""A single source of truth for "which tables must be append-only",
checked against the database's actual privilege/trigger state.

prevent_mutation() and prevent_truncate() are shared, generic trigger
functions (backend/alembic/versions/0001, 0009), but *attaching* them to
a table is still a hand-written CREATE TRIGGER statement per table, per
migration (currently 6 statements across 0006/0007/0009 for 3 tables) --
nothing previously cross-checked that every table lacking UPDATE/DELETE
grants actually has both guards. Add a new append-only table here and
this test verifies the full invariant automatically; forgetting to add
it here means this test simply won't cover that table, which is a much
smaller, more visible gap than "nobody wrote a test for it at all".
"""

APPEND_ONLY_TABLES = ["ledger_transactions", "ledger_entries", "audit_log"]


def test_append_only_tables_have_no_update_or_delete_grant(db):
    cur = db.cursor()
    for table in APPEND_ONLY_TABLES:
        cur.execute("SELECT has_table_privilege('app_rw', %s, 'UPDATE')", (table,))
        assert cur.fetchone()[0] is False, f"{table}: app_rw must not hold UPDATE"

        cur.execute("SELECT has_table_privilege('app_rw', %s, 'DELETE')", (table,))
        assert cur.fetchone()[0] is False, f"{table}: app_rw must not hold DELETE"


def test_append_only_tables_have_mutation_and_truncate_guard_triggers(db):
    cur = db.cursor()
    for table in APPEND_ONLY_TABLES:
        cur.execute(
            """
            SELECT p.proname
            FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_proc p ON p.oid = t.tgfoid
            WHERE c.relname = %s AND NOT t.tgisinternal
            """,
            (table,),
        )
        trigger_functions = {row[0] for row in cur.fetchall()}
        assert "prevent_mutation" in trigger_functions, f"{table}: missing BEFORE UPDATE/DELETE guard trigger"
        assert "prevent_truncate" in trigger_functions, f"{table}: missing BEFORE TRUNCATE guard trigger"
