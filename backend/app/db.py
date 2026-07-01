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
    conn = psycopg.connect(url, autocommit=True)
    try:
        yield conn
    finally:
        conn.close()
