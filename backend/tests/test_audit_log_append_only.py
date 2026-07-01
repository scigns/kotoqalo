"""The audit trail must be as tamper-proof as the ledger it watches."""

import json


def _insert_audit_row(db, user_id):
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO audit_log (actor_user_id, actor_role, action, entity_type, entity_id, before_state, after_state)
        VALUES (%s, 'bookkeeper', 'UPDATE', 'contract', %s, %s, %s)
        RETURNING id
        """,
        (user_id, user_id, json.dumps({"status": "draft"}), json.dumps({"status": "active"})),
    )
    return cur.fetchone()[0]


def test_app_rw_can_insert_audit_rows(db, seed):
    db.cursor().execute("SET ROLE app_rw")
    row_id = _insert_audit_row(db, seed["user_id"])
    assert row_id is not None


def test_app_rw_cannot_update_audit_log(db, seed, expect_denied):
    db.cursor().execute("SET ROLE app_rw")
    row_id = _insert_audit_row(db, seed["user_id"])

    err = expect_denied(
        db,
        "UPDATE audit_log SET action = 'DELETE' WHERE id = %s",
        (row_id,),
    )
    assert "permission denied" in str(err).lower()


def test_app_rw_cannot_delete_audit_log(db, seed, expect_denied):
    db.cursor().execute("SET ROLE app_rw")
    row_id = _insert_audit_row(db, seed["user_id"])

    err = expect_denied(db, "DELETE FROM audit_log WHERE id = %s", (row_id,))
    assert "permission denied" in str(err).lower()


def test_owner_role_update_still_blocked_by_trigger(db, seed, expect_denied):
    row_id = _insert_audit_row(db, seed["user_id"])

    err = expect_denied(
        db,
        "UPDATE audit_log SET action = 'DELETE' WHERE id = %s",
        (row_id,),
    )
    assert "append-only" in str(err)


def test_owner_role_truncate_blocked(db, seed, expect_denied):
    err = expect_denied(db, "TRUNCATE audit_log")
    assert "append-only" in str(err)
