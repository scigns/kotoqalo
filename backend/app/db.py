import psycopg

from app.config import get_settings


def get_db():
    """One connection per request, as the app_rw runtime role.

    The three human-facing RBAC roles (owner_admin/bookkeeper/
    read_only_auditor) are an application-level concept enforced by
    app/rbac.py against the user_roles table -- the process itself always
    connects to Postgres as app_rw, per Phase 2's requirement to enforce
    RBAC "at the API layer". The DB-level app_rw/app_ro privilege split
    from Phase 1 is a separate defense layer protecting the ledger/audit
    log against the application itself misbehaving, not a per-end-user
    connection selector.
    """
    settings = get_settings()
    # APP_DATABASE_URL uses the SQLAlchemy-style postgresql+psycopg://
    # scheme (for Alembic/env.py consistency); native psycopg.connect()
    # only understands plain postgresql://.
    url = settings.app_database_url.replace("postgresql+psycopg://", "postgresql://")
    # autocommit=False, with an explicit commit only on a fully successful
    # request: ledger postings need several INSERTs (a ledger_transaction
    # header plus multiple balanced ledger_entries) to land in one atomic
    # unit, and the deferred balance-check constraint trigger only fires
    # at COMMIT -- under autocommit=True, each statement is its own
    # implicit transaction, so a single (individually unbalanced) entry
    # would be checked and rejected before the next entry in the same
    # posting was even inserted. This also makes every other handler's
    # writes atomic against a mid-request exception, which autocommit=True
    # never was.
    conn = psycopg.connect(url, autocommit=False)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
