"""Small generic helpers shared across the standard-mutability CRUD
endpoints (contracts, milestones). Not used for invoices/ledger, which
have their own state-machine-shaped mutation endpoints instead of
freeform PATCH, per the fail-closed freeze / append-only designs from
Phase 1.
"""

from typing import Any, Optional

from fastapi import HTTPException, status


def require_exists(db, table: str, entity_id, not_found_message: str) -> None:
    """`table` is always a fixed string literal from call sites in this
    codebase, never derived from request input."""
    cur = db.cursor()
    cur.execute(f"SELECT 1 FROM {table} WHERE id = %s", (str(entity_id),))
    if cur.fetchone() is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, not_found_message)


def fetch_row_as_dict(db, table: str, columns: list[str], entity_id) -> Optional[dict[str, Any]]:
    cur = db.cursor()
    column_list = ", ".join(columns)
    cur.execute(f"SELECT {column_list} FROM {table} WHERE id = %s", (str(entity_id),))
    row = cur.fetchone()
    if row is None:
        return None
    return dict(zip(columns, row))


def apply_partial_update(db, table: str, entity_id, updates: dict[str, Any], actor_user_id: str) -> None:
    """`updates` keys must already come from a validated Pydantic model's
    declared field names (e.g. `payload.model_dump(exclude_unset=True)`
    against a fixed schema) -- never built from arbitrary/unvalidated
    request data, since column names are interpolated here (values are
    always parameterized)."""
    if not updates:
        return
    set_clauses = [f"{column} = %s" for column in updates]
    set_clauses.append("updated_by = %s")
    params = [*updates.values(), actor_user_id, str(entity_id)]
    cur = db.cursor()
    cur.execute(
        f"UPDATE {table} SET {', '.join(set_clauses)} WHERE id = %s",
        params,
    )
