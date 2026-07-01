"""Phase 2: auth + RBAC enforcement at the API layer.

Endpoints here are deliberately minimal -- just enough surface to prove
the three-role boundary (owner_admin / bookkeeper / read_only_auditor).
Full contract/invoice/milestone CRUD and audit-logging middleware are
Phase 3 scope, not built here.
"""

import uuid
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, status

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


RoleName = Literal["owner_admin", "bookkeeper", "read_only_auditor"]


def _require_existing_user(db, user_id: uuid.UUID) -> None:
    cur = db.cursor()
    cur.execute("SELECT 1 FROM users WHERE id = %s", (str(user_id),))
    if cur.fetchone() is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")


@app.post("/admin/users/{user_id}/roles", status_code=201)
def grant_role(
    user_id: uuid.UUID,
    payload: RoleGrant,
    actor: AuthenticatedUser = Depends(require_role("owner_admin")),
    db=Depends(get_db),
):
    """Access-control settings: owner_admin only, deliberately excluding
    bookkeeper even though bookkeeper can write elsewhere in the app.

    user_id/role are typed (uuid.UUID / Literal[...]) rather than plain
    str so FastAPI rejects malformed input with a 422 before it ever
    reaches a query -- a malformed UUID or invalid role name previously
    reached Postgres as a raw string and surfaced as an unhandled 500
    (invalid input syntax for uuid / invalid input value for enum),
    potentially leaking DB error detail in the response.
    """
    _require_existing_user(db, user_id)
    with db.cursor() as cur:
        cur.execute(
            """
            INSERT INTO user_roles (user_id, role, granted_by)
            VALUES (%s, %s, %s)
            ON CONFLICT (user_id, role)
            DO UPDATE SET revoked_at = NULL, granted_by = EXCLUDED.granted_by, granted_at = now()
            """,
            (str(user_id), payload.role, actor.user_id),
        )
    return {"status": "granted"}


@app.delete("/admin/users/{user_id}/roles/{role}")
def revoke_role(
    user_id: uuid.UUID,
    role: RoleName,
    actor: AuthenticatedUser = Depends(require_role("owner_admin")),
    db=Depends(get_db),
):
    _require_existing_user(db, user_id)
    with db.cursor() as cur:
        cur.execute(
            "UPDATE user_roles SET revoked_at = now() WHERE user_id = %s AND role = %s AND revoked_at IS NULL",
            (str(user_id), role),
        )
    return {"status": "revoked"}
