"""
Admin-only dependency for FastAPI route protection.

Wraps the existing ``get_current_user`` dependency and additionally
verifies that the authenticated user holds the ADMIN role.
"""

from fastapi import Depends, HTTPException, status

from app.core.dependencies import get_current_user
from app.core.enums import UserRole
from app.models.user import User


def get_current_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Return the current user only if they have the ADMIN role.

    Raises:
        HTTPException 403 if the user is not an admin.
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return current_user
