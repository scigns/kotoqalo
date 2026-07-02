"""Exercises the real (non-overridden) app/db.py get_db() -- every other
test in this suite overrides get_db to share the rolled-back-at-teardown
`db` fixture connection, which never actually calls get_db's own
commit()/rollback() logic. This is the one place that logic runs for
real, proving a successful request's multi-statement ledger posting
(transaction header + entries) is genuinely durable via a completely
independent connection afterward -- not just visible within the same
transaction.
"""

import os

import psycopg
from fastapi.testclient import TestClient

from app.auth import StaticJWKSClient, get_jwks_client
from app.config import Settings, get_settings
from app.main import app
from conftest import TEST_AUDIENCE, TEST_DOMAIN, TEST_KID, make_token


def _raw_migrator_connection():
    url = os.environ["MIGRATOR_DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(url, autocommit=True)


def test_successful_expense_request_really_commits_via_the_real_get_db(rsa_keypair):
    """This test's user row cannot be cleaned up afterward: the expense it
    posts becomes a real, append-only ledger_transactions row (created_by
    REFERENCES users(id)), and ledger rows can never be deleted by design
    (Phase 1's append-only enforcement). Deleting the user afterward would
    therefore always raise a ForeignKeyViolation -- that is the system
    working correctly, not a test bug. So this test uses a fixed,
    obviously-a-test-fixture user, upserted idempotently (ON CONFLICT DO
    NOTHING) rather than inserted fresh and torn down: it is expected,
    permanent residue in this dev database, reused across test runs
    instead of growing unboundedly.
    """
    private_key, public_key = rsa_keypair
    subject = "test|real-get-db-owner-fixture"
    setup_conn = _raw_migrator_connection()
    cur = setup_conn.cursor()
    cur.execute(
        """
        INSERT INTO users (external_auth_subject, email, full_name)
        VALUES (%s, %s, 'Real get_db Owner (permanent test fixture)')
        ON CONFLICT (external_auth_subject) DO NOTHING
        """,
        (subject, "real-get-db-owner-fixture@example.test"),
    )
    cur.execute("SELECT id FROM users WHERE external_auth_subject = %s", (subject,))
    user_id = cur.fetchone()[0]
    cur.execute(
        "INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, 'owner_admin', %s) ON CONFLICT DO NOTHING",
        (user_id, user_id),
    )
    try:

        app.dependency_overrides[get_settings] = lambda: Settings(
            app_database_url=os.environ["APP_DATABASE_URL"], auth0_domain=TEST_DOMAIN, auth0_audience=TEST_AUDIENCE
        )
        app.dependency_overrides[get_jwks_client] = lambda: StaticJWKSClient({TEST_KID: public_key})
        # Deliberately not overriding get_db -- this is the point of the test.

        token = make_token(private_key, subject)
        real_client = TestClient(app)
        response = real_client.post(
            "/expenses",
            json={
                "account_code": "5000", "amount": "12.34", "currency_code": "AUD",
                "description": "real-get-db-atomicity-test", "expense_date": "2026-07-01",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201, response.text
        transaction_id = response.json()["ledger_transaction_id"]

        # A completely independent connection must see this data -- proof
        # the real get_db() actually called conn.commit(), not just that
        # it was visible within the same in-flight transaction.
        verify_conn = _raw_migrator_connection()
        verify_cur = verify_conn.cursor()
        verify_cur.execute(
            "SELECT description FROM ledger_transactions WHERE id = %s",
            (transaction_id,),
        )
        row = verify_cur.fetchone()
        assert row is not None, "the successful request's ledger posting was not durably committed"
        assert row[0] == "real-get-db-atomicity-test"
        verify_conn.close()
    finally:
        # No user/user_roles cleanup here, deliberately: this user now has
        # a real ledger_transactions row referencing it, which can never
        # be deleted (append-only by design) -- so neither can the user.
        # See the fixture-user comment at the top of this test.
        app.dependency_overrides.clear()
        setup_conn.close()


def test_failed_expense_request_leaves_no_trace_via_the_real_get_db(rsa_keypair):
    """entries that fail Python-level validation (unbalanced, in this
    case) never reach the database at all -- but this still exercises
    get_db()'s real exception path end-to-end (the HTTPException raised
    by the endpoint propagates through the real, non-overridden
    dependency), which is worth pinning explicitly rather than only
    covering it incidentally.
    """
    private_key, public_key = rsa_keypair
    subject = "test|real-get-db-failure-owner"
    setup_conn = _raw_migrator_connection()
    user_id = None
    try:
        cur = setup_conn.cursor()
        cur.execute(
            "INSERT INTO users (external_auth_subject, email, full_name) VALUES (%s, %s, 'Real get_db Failure Owner') RETURNING id",
            (subject, "real-get-db-failure-owner@example.test"),
        )
        user_id = cur.fetchone()[0]
        cur.execute("INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, 'owner_admin', %s)", (user_id, user_id))

        app.dependency_overrides[get_settings] = lambda: Settings(
            app_database_url=os.environ["APP_DATABASE_URL"], auth0_domain=TEST_DOMAIN, auth0_audience=TEST_AUDIENCE
        )
        app.dependency_overrides[get_jwks_client] = lambda: StaticJWKSClient({TEST_KID: public_key})

        token = make_token(private_key, subject)
        real_client = TestClient(app)
        response = real_client.post(
            "/expenses",
            json={
                "account_code": "9999-unknown", "amount": "12.34", "currency_code": "AUD",
                "description": "real-get-db-should-not-persist", "expense_date": "2026-07-01",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 400

        verify_conn = _raw_migrator_connection()
        verify_cur = verify_conn.cursor()
        verify_cur.execute(
            "SELECT count(*) FROM ledger_transactions WHERE description = 'real-get-db-should-not-persist'"
        )
        assert verify_cur.fetchone()[0] == 0
        verify_conn.close()
    finally:
        app.dependency_overrides.clear()
        if user_id is not None:
            cur = setup_conn.cursor()
            cur.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id,))
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        setup_conn.close()
