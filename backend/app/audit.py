"""Audit logging for every mutating endpoint, consistent with Phase 2's
API-layer RBAC boundary.

This is not ASGI-level middleware (Starlette middleware only sees
request/response bytes, not what changed in the database) -- it's a
helper each mutating endpoint calls explicitly with the before/after
state it already has. That's a deliberate trade-off: less "automatic"
than framework middleware, but honest about what it captures and easy
to audit for completeness by grepping call sites, rather than trusting
implicit behavior to cover every route.
"""

import json
from typing import Any, Optional


def _role_for_audit(roles: frozenset) -> Optional[str]:
    """A user may hold more than one role; audit_log.actor_role is a
    single value. Picks a stable (sorted), not necessarily "the" role
    that authorized the action -- informational context alongside
    actor_user_id and the before/after state, not the primary audit
    signal."""
    return sorted(roles)[0] if roles else None


def record_audit_event(
    db,
    actor_user_id: str,
    actor_roles: frozenset,
    action: str,
    entity_type: str,
    entity_id: Optional[str],
    before_state: Optional[dict[str, Any]],
    after_state: Optional[dict[str, Any]],
) -> None:
    """Never pass decrypted PII/banking plaintext or raw ciphertext bytes
    in before_state/after_state -- callers must exclude those fields
    themselves (see app/main.py's client endpoints for the pattern),
    mirroring the "don't log full email bodies with banking details"
    principle from the Phase 4b Gmail integration plan, applied here
    proactively since audit_log already holds comparably sensitive
    before/after snapshots.
    """
    with db.cursor() as cur:
        cur.execute(
            """
            INSERT INTO audit_log (actor_user_id, actor_role, action, entity_type, entity_id, before_state, after_state)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                actor_user_id,
                _role_for_audit(actor_roles),
                action,
                entity_type,
                entity_id,
                # default=str: before/after state routinely contains
                # UUID/Decimal/date/datetime values that json.dumps
                # can't serialize natively; str() gives a readable,
                # good-enough representation for an audit trail (nothing
                # reconstructs typed values from this history).
                json.dumps(before_state, default=str) if before_state is not None else None,
                json.dumps(after_state, default=str) if after_state is not None else None,
            ),
        )
