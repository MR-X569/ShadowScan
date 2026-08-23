"""
CRUD operations for the Scan model.

All functions are stateless pure-database accessors.
Business logic and ownership enforcement belong in ScanService.
"""

from sqlalchemy.orm import Session

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


def delete_scan(db: Session, scan: Scan) -> None:
    """Hard-delete a Scan record from the database."""
    db.delete(scan)
    db.commit()
