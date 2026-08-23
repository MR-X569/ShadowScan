"""
Scan Management API — /scans

Endpoints:
  POST   /scans              — Create a new scan
  GET    /scans              — List current user's scans (paginated)
  GET    /scans/{scan_id}    — Get full details of a single scan
  DELETE /scans/{scan_id}    — Delete a scan

All endpoints require a valid JWT (enforced by get_current_user dependency).
Ownership is enforced at the service layer; the router stays thin.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanListResponse, ScanResponse
from app.services.scan_service import ScanService

router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
)


# ---------------------------------------------------------------------------
# POST /scans — Create a new scan
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=ScanResponse,
    status_code=201,
    summary="Create a new scan",
    description=(
        "Submits a target URL for vulnerability scanning. "
        "The scan is created with status **PENDING** and belongs to the "
        "authenticated user."
    ),
)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanResponse:
    service = ScanService(db)
    return service.create_scan(current_user, payload)


# ---------------------------------------------------------------------------
# GET /scans — List current user's scans
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=list[ScanListResponse],
    summary="List scans",
    description=(
        "Returns a paginated list of scans belonging to the authenticated "
        "user, ordered newest-first. Maximum `limit` is capped at 100."
    ),
)
def list_scans(
    skip: int = Query(0, ge=0, description="Number of records to skip."),
    limit: int = Query(20, ge=1, le=100, description="Page size (max 100)."),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ScanListResponse]:
    service = ScanService(db)
    return service.list_scans(current_user, skip=skip, limit=limit)


# ---------------------------------------------------------------------------
# GET /scans/{scan_id} — Get scan details
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan details",
    description=(
        "Returns full details of a single scan. "
        "Returns 404 if the scan does not exist, 403 if it belongs to "
        "another user."
    ),
)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanResponse:
    service = ScanService(db)
    return service.get_scan(current_user, scan_id)


# ---------------------------------------------------------------------------
# DELETE /scans/{scan_id} — Delete a scan
# ---------------------------------------------------------------------------


@router.delete(
    "/{scan_id}",
    summary="Delete a scan",
    description=(
        "Permanently deletes a scan and its associated data. "
        "Returns 404 if the scan does not exist, 403 if it belongs to "
        "another user."
    ),
)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    service = ScanService(db)
    return service.delete_scan(current_user, scan_id)
