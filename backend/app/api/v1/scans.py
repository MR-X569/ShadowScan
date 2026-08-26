from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.user import User
from app.schemas.scan import FindingResponse, ScanCreate, ScanListResponse, ScanResponse
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
        "The scan is created and automatically queued for execution."
    ),
)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanResponse:
    service = ScanService(db)
    return service.create_scan(current_user, payload, background_tasks=background_tasks)


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
# GET /scans/findings/all — List all findings for current user across scans
# ---------------------------------------------------------------------------


@router.get(
    "/findings/all",
    response_model=list[FindingResponse],
    summary="List all user findings",
    description="Returns all findings across all scans owned by the authenticated user.",
)
def list_all_findings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[FindingResponse]:
    service = ScanService(db)
    return service.get_user_all_findings(current_user)


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
# GET /scans/{scan_id}/findings — Get scan findings
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}/findings",
    response_model=list[FindingResponse],
    summary="Get scan findings",
    description="Returns all vulnerability findings identified for this scan.",
)
def get_scan_findings(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[FindingResponse]:
    service = ScanService(db)
    return service.get_scan_findings(current_user, scan_id)


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

