"""
ScanService — business logic layer for the Scan Management module.

Responsibilities:
  - URL normalisation (AnyHttpUrl → str for storage)
  - Ownership enforcement (user can only access their own scans)
  - Orchestration of CRUD calls
  - Raising domain-appropriate exceptions consumed by the API layer

This service intentionally does NOT start the actual scanner engine.
That concern will be handled by a separate ScannerEngine component.
"""

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.enums import ScanStatus
from app.crud.scan import (
    create_scan,
    delete_scan,
    get_scan_by_id,
    get_scans_by_user,
)
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanListResponse, ScanResponse


class ScanService:

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def create_scan(
        self,
        current_user: User,
        payload: ScanCreate,
    ) -> ScanResponse:
        """Create a new scan owned by `current_user`.

        The scan is initialised with status PENDING; the scanner engine
        will transition it through RUNNING → COMPLETED / FAILED.

        Args:
            current_user: The authenticated user making the request.
            payload:      Validated request body containing the target URL.

        Returns:
            ScanResponse of the newly-created scan.
        """
        # Normalise AnyHttpUrl → plain string for DB storage
        target_url = str(payload.target_url)

        new_scan = Scan(
            user_id=current_user.id,
            target_url=target_url,
            status=ScanStatus.PENDING,
        )

        persisted = create_scan(self.db, new_scan)
        return ScanResponse.model_validate(persisted)

    def list_scans(
        self,
        current_user: User,
        skip: int = 0,
        limit: int = 20,
    ) -> list[ScanListResponse]:
        """Return a paginated list of scans owned by `current_user`.

        Args:
            current_user: The authenticated user making the request.
            skip:         Offset for pagination.
            limit:        Maximum number of records (capped at 100).

        Returns:
            List of ScanListResponse objects ordered newest-first.
        """
        # Cap limit to prevent abuse
        limit = min(limit, 100)

        scans = get_scans_by_user(
            self.db,
            user_id=current_user.id,
            skip=skip,
            limit=limit,
        )
        return [ScanListResponse.model_validate(s) for s in scans]

    def get_scan(
        self,
        current_user: User,
        scan_id: int,
    ) -> ScanResponse:
        """Fetch full detail of a single scan.

        Args:
            current_user: The authenticated user making the request.
            scan_id:      Primary key of the requested scan.

        Returns:
            ScanResponse if the scan exists and is owned by current_user.

        Raises:
            HTTPException 404 — scan does not exist.
            HTTPException 403 — scan belongs to a different user.
        """
        scan = self._get_scan_or_404(scan_id)
        self._assert_owner(scan, current_user)
        return ScanResponse.model_validate(scan)

    def delete_scan(
        self,
        current_user: User,
        scan_id: int,
    ) -> dict[str, str]:
        """Hard-delete a scan after verifying ownership.

        Args:
            current_user: The authenticated user making the request.
            scan_id:      Primary key of the scan to delete.

        Returns:
            Confirmation message dict.

        Raises:
            HTTPException 404 — scan does not exist.
            HTTPException 403 — scan belongs to a different user.
        """
        scan = self._get_scan_or_404(scan_id)
        self._assert_owner(scan, current_user)
        delete_scan(self.db, scan)
        return {"detail": f"Scan {scan_id} deleted successfully."}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_scan_or_404(self, scan_id: int) -> Scan:
        """Retrieve a scan by id or raise HTTP 404."""
        scan = get_scan_by_id(self.db, scan_id)
        if scan is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with id {scan_id} not found.",
            )
        return scan

    def _assert_owner(self, scan: Scan, current_user: User) -> None:
        """Raise HTTP 403 if `current_user` does not own `scan`."""
        if scan.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this scan.",
            )
