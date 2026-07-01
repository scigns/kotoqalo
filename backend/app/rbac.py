from fastapi import Depends, HTTPException, status

from app.auth import AuthenticatedUser, get_current_user

ALL_ROLES = ("owner_admin", "bookkeeper", "read_only_auditor")


def require_role(*allowed_roles: str):
    """FastAPI dependency factory: 403s unless the caller holds at least
    one of the given roles. Roles come from user_roles (non-revoked only,
    see app/auth.py), never from a client-supplied claim."""

    def _check(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if not (user.roles & set(allowed_roles)):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role for this action")
        return user

    return _check
