"""
ScanService — business logic layer for the Scan Management module.

Responsibilities:
  - URL normalisation (AnyHttpUrl → str for storage)
  - Ownership enforcement (user can only access their own scans)
  - Orchestration of CRUD calls
  - Invoking ScannerEngine asynchronously via FastAPI BackgroundTasks
  - Persisting findings and calculating risk score
  - Raising domain-appropriate exceptions consumed by the API layer
"""

import logging
from datetime import datetime, UTC
from fastapi import BackgroundTasks, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.enums import ScanStatus, Severity
from app.crud.finding import bulk_create_findings, get_findings_by_scan, get_all_findings_by_user
from app.crud.scan import (
    create_scan,
    delete_scan,
    get_scan_by_id,
    get_scans_by_user,
    update_scan_status,
)
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import FindingResponse, ScanCreate, ScanListResponse, ScanResponse
from app.scanner.engine import create_engine

logger = logging.getLogger(__name__)


async def execute_scan_task(scan_id: int, target_url: str, user_id: int) -> None:
    """Background task to run scanner engine, persist findings, and calculate risk score."""
    logger.info("Executing background scan %d on %s", scan_id, target_url)
    db = SessionLocal()
    try:
        update_scan_status(db, scan_id, ScanStatus.RUNNING)

        engine = create_engine()
        findings_data = await engine.run(
            scan_id=scan_id,
            target_url=target_url,
            user_id=user_id,
        )

        db_findings = []
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        }

        for f in findings_data:
            db_finding = Finding(
                scan_id=scan_id,
                vulnerability_name=f.title,
                plugin=f.plugin,
                severity=f.severity,
                description=f.description,
                recommendation=f.recommendation,
                evidence=f.evidence,
            )
            db_findings.append(db_finding)
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1

        bulk_create_findings(db, db_findings)

        # Risk score calculation: 0.0 to 10.0 scale
        raw_score = (
            severity_counts[Severity.CRITICAL] * 3.5
            + severity_counts[Severity.HIGH] * 2.0
            + severity_counts[Severity.MEDIUM] * 1.0
            + severity_counts[Severity.LOW] * 0.25
        )
        risk_score = round(min(10.0, raw_score), 1)

        update_scan_status(
            db,
            scan_id=scan_id,
            status=ScanStatus.COMPLETED,
            risk_score=risk_score,
            completed_at=datetime.now(UTC),
        )
        logger.info(
            "Scan %d completed successfully with %d findings, risk score=%.1f",
            scan_id,
            len(db_findings),
            risk_score,
        )
    except Exception as exc:
        logger.error("Scan %d failed with error: %s", scan_id, exc, exc_info=True)
        update_scan_status(
            db,
            scan_id=scan_id,
            status=ScanStatus.FAILED,
            completed_at=datetime.now(UTC),
        )
    finally:
        db.close()


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
        background_tasks: BackgroundTasks | None = None,
    ) -> ScanResponse:
        """Create a new scan and schedule scanner engine execution."""
        target_url = str(payload.target_url)

        new_scan = Scan(
            user_id=current_user.id,
            target_url=target_url,
            status=ScanStatus.PENDING,
        )

        persisted = create_scan(self.db, new_scan)

        if background_tasks is not None:
            background_tasks.add_task(
                execute_scan_task,
                persisted.id,
                persisted.target_url,
                current_user.id,
            )

        return ScanResponse.model_validate(persisted)

    def list_scans(
        self,
        current_user: User,
        skip: int = 0,
        limit: int = 20,
    ) -> list[ScanListResponse]:
        """Return a paginated list of scans owned by `current_user`."""
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
        """Fetch full detail of a single scan."""
        scan = self._get_scan_or_404(scan_id)
        self._assert_owner(scan, current_user)
        return ScanResponse.model_validate(scan)

    def get_scan_findings(
        self,
        current_user: User,
        scan_id: int,
    ) -> list[FindingResponse]:
        """Fetch all vulnerability findings for a single scan."""
        scan = self._get_scan_or_404(scan_id)
        self._assert_owner(scan, current_user)

        findings = get_findings_by_scan(self.db, scan_id)
        return [
            FindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                vulnerability_name=f.vulnerability_name,
                plugin=f.plugin,
                severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                description=f.description,
                recommendation=f.recommendation,
                evidence=f.evidence,
                status=f.status.value if hasattr(f.status, "value") else str(f.status),
                created_at=f.created_at,
            )
            for f in findings
        ]

    def get_user_all_findings(
        self,
        current_user: User,
    ) -> list[FindingResponse]:
        """Fetch all vulnerability findings across all scans owned by current user."""
        findings = get_all_findings_by_user(self.db, current_user.id)
        return [
            FindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                vulnerability_name=f.vulnerability_name,
                plugin=f.plugin,
                severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                description=f.description,
                recommendation=f.recommendation,
                evidence=f.evidence,
                status=f.status.value if hasattr(f.status, "value") else str(f.status),
                created_at=f.created_at,
            )
            for f in findings
        ]

    def delete_scan(
        self,
        current_user: User,
        scan_id: int,
    ) -> dict[str, str]:
        """Hard-delete a scan after verifying ownership."""
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

