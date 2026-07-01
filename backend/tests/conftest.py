import os
from pathlib import Path

import psycopg
import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


_load_dotenv(BACKEND_DIR / ".env")


@pytest.fixture
def db(): # noqa: ANN201
    """A single connection/transaction per test, as the schema-owning role.

    Tests use SET ROLE to switch privilege context (app_rw / app_ro)
    within this one transaction so seeded fixture rows (users, clients,
    contracts) inserted as the owner stay visible to statements run as
    the lower-privileged role, and the whole test is rolled back at the
    end -- nothing is ever committed, including any successfully-inserted
    ledger rows, so the append-only tables need no manual cleanup.
    """
    url = os.environ["MIGRATOR_DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://")
    conn = psycopg.connect(url, autocommit=False)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def seed(db):  # noqa: ANN201
    """Minimal reference rows needed to satisfy FKs in ledger/invoice tests."""
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO users (external_auth_subject, email, full_name)
        VALUES ('test|owner', 'owner@example.test', 'Test Owner')
        RETURNING id
        """
    )
    user_id = cur.fetchone()[0]

    cur.execute(
        """
        INSERT INTO clients (display_name, country_code, created_by)
        VALUES ('Test Client', 'AU', %s)
        RETURNING id
        """,
        (user_id,),
    )
    client_id = cur.fetchone()[0]

    cur.execute(
        """
        INSERT INTO contracts (client_id, title, currency_code, total_value, created_by)
        VALUES (%s, 'Test Contract', 'AUD', 1000.00, %s)
        RETURNING id
        """,
        (client_id, user_id),
    )
    contract_id = cur.fetchone()[0]

    cur.execute("SELECT id FROM chart_of_accounts WHERE code = '1000'")  # Accounts Receivable
    ar_account_id = cur.fetchone()[0]
    cur.execute("SELECT id FROM chart_of_accounts WHERE code = '4000'")  # Consulting Revenue
    revenue_account_id = cur.fetchone()[0]

    # Deliberately NOT committed: SET ROLE only changes the current_user
    # used for privilege checks, it does not start a new transaction, so
    # these uncommitted rows stay visible for the rest of this same
    # session regardless of which role later statements run as.

    return {
        "user_id": user_id,
        "client_id": client_id,
        "contract_id": contract_id,
        "ar_account_id": ar_account_id,
        "revenue_account_id": revenue_account_id,
    }


@pytest.fixture
def expect_denied():
    """Run a statement expected to fail, then recover the transaction.

    Uses a SAVEPOINT so a caught, expected failure (permission denied,
    a RAISE EXCEPTION from a guard trigger, etc.) doesn't abort the rest
    of the test's transaction -- only the one statement is undone.
    """

    def _run(conn, sql, params=None):
        cur = conn.cursor()
        cur.execute("SAVEPOINT expect_denied_sp")
        try:
            cur.execute(sql, params)
        except Exception as exc:  # noqa: BLE001
            conn.cursor().execute("ROLLBACK TO SAVEPOINT expect_denied_sp")
            return exc
        else:
            conn.cursor().execute("ROLLBACK TO SAVEPOINT expect_denied_sp")
            raise AssertionError(f"expected statement to be denied, but it succeeded: {sql}")

    return _run
