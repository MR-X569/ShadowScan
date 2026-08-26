from datetime import datetime, UTC
from sqlalchemy.orm import Session

from app.core.enums import ScanStatus
from app.models.scan import Scan


def create_scan(db: Session, scan: Scan) -> Scan:
    """Persist a new Scan record and return it with its generated id."""
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan_by_id(db: Session, scan_id: int) -> Scan | None:
    """Return a single Scan by primary key, or None if not found."""
    return (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )


def get_scans_by_user(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 20,
) -> list[Scan]:
    """Return a paginated list of scans belonging to a specific user.

    Args:
        db:      Active database session.
        user_id: Owner filter — only scans owned by this user are returned.
        skip:    Number of records to skip (offset).
        limit:   Maximum number of records to return.
    """
    return (
        db.query(Scan)
        .filter(Scan.user_id == user_id)
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def update_scan_status(
    db: Session,
    scan_id: int,
    status: ScanStatus,
    risk_score: float | None = None,
    completed_at: datetime | None = None,
) -> Scan | None:
    """Update a scan's status, risk score, and completion timestamp."""
    scan = get_scan_by_id(db, scan_id)
    if not scan:
        return None
    scan.status = status
    if risk_score is not None:
        scan.risk_score = risk_score
    if completed_at is not None:
        scan.completed_at = completed_at
    db.commit()
    db.refresh(scan)
    return scan


def delete_scan(db: Session, scan: Scan) -> None:
    """Hard-delete a Scan record from the database."""
    db.delete(scan)
    db.commit()

