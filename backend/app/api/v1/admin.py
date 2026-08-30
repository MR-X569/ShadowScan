"""
Admin API router — platform management endpoints.

All routes are protected by the ``get_current_admin`` dependency,
which ensures only users with the ADMIN role can access them.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.admin_dependency import get_current_admin
from app.core.database import get_db
from app.models.user import User
from app.schemas.admin import (
    AdminFindingResponse,
    AdminScanResponse,
    AdminStatsResponse,
    AdminUserResponse,
)
from app.services.admin_service import AdminService

router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
)


# ---------------------------------------------------------------------------
# GET /admin/stats — Platform statistics
# ---------------------------------------------------------------------------


@router.get(
    "/stats",
    response_model=AdminStatsResponse,
    summary="Platform statistics",
    description="Returns aggregate platform-wide statistics for the admin dashboard.",
)
def get_admin_stats(
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> AdminStatsResponse:
    service = AdminService(db)
    return service.get_stats()


# ---------------------------------------------------------------------------
# GET /admin/users — List all users
# ---------------------------------------------------------------------------


@router.get(
    "/users",
    response_model=list[AdminUserResponse],
    summary="List all users",
    description="Returns all registered users, ordered newest-first.",
)
def list_all_users(
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> list[AdminUserResponse]:
    service = AdminService(db)
    return service.get_all_users()


# ---------------------------------------------------------------------------
# GET /admin/scans — List all scans
# ---------------------------------------------------------------------------


@router.get(
    "/scans",
    response_model=list[AdminScanResponse],
    summary="List all scans",
    description="Returns all scans across all users, ordered newest-first.",
)
def list_all_scans(
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> list[AdminScanResponse]:
    service = AdminService(db)
    return service.get_all_scans()


# ---------------------------------------------------------------------------
# GET /admin/findings — List all findings
# ---------------------------------------------------------------------------


@router.get(
    "/findings",
    response_model=list[AdminFindingResponse],
    summary="List all findings",
    description="Returns all findings across all scans, ordered newest-first.",
)
def list_all_findings(
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> list[AdminFindingResponse]:
    service = AdminService(db)
    return service.get_all_findings()


# ---------------------------------------------------------------------------
# PUT /admin/users/{user_id}/disable — Disable a user
# ---------------------------------------------------------------------------


@router.put(
    "/users/{user_id}/disable",
    summary="Disable a user",
    description="Sets the user's is_active flag to False, preventing login.",
)
def disable_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> dict[str, str]:
    service = AdminService(db)
    return service.disable_user(user_id, current_admin)


# ---------------------------------------------------------------------------
# PUT /admin/users/{user_id}/enable — Enable a user
# ---------------------------------------------------------------------------


@router.put(
    "/users/{user_id}/enable",
    summary="Enable a user",
    description="Sets the user's is_active flag to True, allowing login.",
)
def enable_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> dict[str, str]:
    service = AdminService(db)
    return service.enable_user(user_id, current_admin)


# ---------------------------------------------------------------------------
# DELETE /admin/users/{user_id} — Delete a user
# ---------------------------------------------------------------------------


@router.delete(
    "/users/{user_id}",
    summary="Delete a user",
    description=(
        "Permanently deletes a user and all their associated data. "
        "Cannot delete self or another admin."
    ),
)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> dict[str, str]:
    service = AdminService(db)
    return service.delete_user(user_id, current_admin)
