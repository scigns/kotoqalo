"""Phase 2: auth + RBAC enforcement at the API layer.

Endpoints here are deliberately minimal -- just enough surface to prove
the three-role boundary (owner_admin / bookkeeper / read_only_auditor).
Full contract/invoice/milestone CRUD and audit-logging middleware are
Phase 3 scope, not built here.
"""

from fastapi import Depends, FastAPI

from app.auth import AuthenticatedUser, get_current_user
from app.db import get_db
from app.rbac import require_role
from app.schemas import ClientCreate, RoleGrant

app = FastAPI(title="Dreamers-Media Pacific Financial Backend")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/me")
def me(user: AuthenticatedUser = Depends(get_current_user)):
    return {"user_id": user.user_id, "roles": sorted(user.roles)}


@app.post("/clients", status_code=201)
def create_client(
    payload: ClientCreate,
    user: AuthenticatedUser = Depends(require_role("owner_admin", "bookkeeper")),
    db=Depends(get_db),
):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO clients (display_name, country_code, created_by) VALUES (%s, %s, %s) RETURNING id",
            (payload.display_name, payload.country_code, user.user_id),
        )
        client_id = cur.fetchone()[0]
    return {"id": str(client_id)}


@app.post("/admin/users/{user_id}/roles", status_code=201)
def grant_role(
    user_id: str,
    payload: RoleGrant,
    actor: AuthenticatedUser = Depends(require_role("owner_admin")),
    db=Depends(get_db),
):
    """Access-control settings: owner_admin only, deliberately excluding
    bookkeeper even though bookkeeper can write elsewhere in the app."""
    with db.cursor() as cur:
        cur.execute(
            """
            INSERT INTO user_roles (user_id, role, granted_by)
            VALUES (%s, %s, %s)
            ON CONFLICT (user_id, role)
            DO UPDATE SET revoked_at = NULL, granted_by = EXCLUDED.granted_by, granted_at = now()
            """,
            (user_id, payload.role, actor.user_id),
        )
    return {"status": "granted"}


@app.delete("/admin/users/{user_id}/roles/{role}")
def revoke_role(
    user_id: str,
    role: str,
    actor: AuthenticatedUser = Depends(require_role("owner_admin")),
    db=Depends(get_db),
):
    with db.cursor() as cur:
        cur.execute(
            "UPDATE user_roles SET revoked_at = now() WHERE user_id = %s AND role = %s AND revoked_at IS NULL",
            (user_id, role),
        )
    return {"status": "revoked"}
