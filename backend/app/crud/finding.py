"""
CRUD operations for the Finding model.
"""

from sqlalchemy.orm import Session

from app.models.finding import Finding


def create_finding(db: Session, finding: Finding) -> Finding:
    """Persist a new finding."""
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def bulk_create_findings(db: Session, findings: list[Finding]) -> list[Finding]:
    """Persist multiple findings in a single transaction."""
    if not findings:
        return []
    db.add_all(findings)
    db.commit()
    for f in findings:
        db.refresh(f)
    return findings


def get_findings_by_scan(db: Session, scan_id: int) -> list[Finding]:
    """Return all findings for a given scan, ordered by severity/id."""
    return (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.id.asc())
        .all()
    )


def get_all_findings_by_user(db: Session, user_id: int) -> list[Finding]:
    """Return all findings across all scans owned by a user."""
    from app.models.scan import Scan

    return (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.user_id == user_id)
        .order_by(Finding.created_at.desc())
        .all()
    )
