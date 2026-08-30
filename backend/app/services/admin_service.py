"""
AdminService — business logic layer for the Admin module.

Responsibilities:
  - Platform-wide statistics aggregation
  - Listing all users / scans / findings (not scoped to a single user)
  - User management (enable, disable, delete)
  - Safety guards (cannot delete self or other admins)
"""

from fastapi import HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.enums import ScanStatus, Severity, UserRole
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.admin import (
    AdminFindingResponse,
    AdminScanResponse,
    AdminStatsResponse,
    AdminUserResponse,
    LatestScanItem,
    LatestUserItem,
)


class AdminService:

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> AdminStatsResponse:
        """Aggregate platform-wide statistics."""
        db = self.db

        total_users = db.query(func.count(User.id)).scalar() or 0
        verified_users = db.query(func.count(User.id)).filter(User.is_verified.is_(True)).scalar() or 0

        total_scans = db.query(func.count(Scan.id)).scalar() or 0
        scans_running = db.query(func.count(Scan.id)).filter(Scan.status == ScanStatus.RUNNING).scalar() or 0
        scans_completed = db.query(func.count(Scan.id)).filter(Scan.status == ScanStatus.COMPLETED).scalar() or 0
        scans_failed = db.query(func.count(Scan.id)).filter(Scan.status == ScanStatus.FAILED).scalar() or 0

        critical_findings = db.query(func.count(Finding.id)).filter(Finding.severity == Severity.CRITICAL).scalar() or 0
        high_findings = db.query(func.count(Finding.id)).filter(Finding.severity == Severity.HIGH).scalar() or 0
        medium_findings = db.query(func.count(Finding.id)).filter(Finding.severity == Severity.MEDIUM).scalar() or 0
        low_findings = db.query(func.count(Finding.id)).filter(Finding.severity == Severity.LOW).scalar() or 0

        # Latest 5 scans with username
        latest_scans_rows = (
            db.query(Scan, User.username)
            .join(User, Scan.user_id == User.id)
            .order_by(Scan.created_at.desc())
            .limit(5)
            .all()
        )
        latest_scans = [
            LatestScanItem(
                id=scan.id,
                target_url=scan.target_url,
                status=scan.status.value if hasattr(scan.status, "value") else str(scan.status),
                risk_score=scan.risk_score,
                created_at=scan.created_at,
                username=username,
            )
            for scan, username in latest_scans_rows
        ]

        # Latest 5 users
        latest_users_rows = (
            db.query(User)
            .order_by(User.created_at.desc())
            .limit(5)
            .all()
        )
        latest_users = [
            LatestUserItem(
                id=u.id,
                username=u.username,
                email=u.email,
                is_verified=u.is_verified,
                created_at=u.created_at,
            )
            for u in latest_users_rows
        ]

        return AdminStatsResponse(
            total_users=total_users,
            verified_users=verified_users,
            total_scans=total_scans,
            scans_running=scans_running,
            scans_completed=scans_completed,
            scans_failed=scans_failed,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            latest_scans=latest_scans,
            latest_users=latest_users,
        )

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def get_all_users(self) -> list[AdminUserResponse]:
        """Return all users ordered by creation date (newest first)."""
        users = self.db.query(User).order_by(User.created_at.desc()).all()
        return [
            AdminUserResponse(
                id=u.id,
                username=u.username,
                email=u.email,
                full_name=u.full_name,
                role=u.role.value if hasattr(u.role, "value") else str(u.role),
                is_active=u.is_active,
                is_verified=u.is_verified,
                created_at=u.created_at,
            )
            for u in users
        ]

    def disable_user(self, user_id: int, current_admin: User) -> dict[str, str]:
        """Disable a user account (set is_active = False)."""
        target = self._get_user_or_404(user_id)
        self._guard_self_and_admin(target, current_admin, action="disable")
        target.is_active = False
        self.db.commit()
        return {"detail": f"User '{target.username}' disabled."}

    def enable_user(self, user_id: int, current_admin: User) -> dict[str, str]:
        """Enable a user account (set is_active = True)."""
        target = self._get_user_or_404(user_id)
        target.is_active = True
        self.db.commit()
        return {"detail": f"User '{target.username}' enabled."}

    def delete_user(self, user_id: int, current_admin: User) -> dict[str, str]:
        """Permanently delete a user and all associated data."""
        target = self._get_user_or_404(user_id)
        self._guard_self_and_admin(target, current_admin, action="delete")
        username = target.username
        self.db.delete(target)
        self.db.commit()
        return {"detail": f"User '{username}' deleted."}

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def get_all_scans(self) -> list[AdminScanResponse]:
        """Return all scans with owner username, newest first."""
        rows = (
            self.db.query(Scan, User.username)
            .join(User, Scan.user_id == User.id)
            .order_by(Scan.created_at.desc())
            .all()
        )
        return [
            AdminScanResponse(
                id=scan.id,
                target_url=scan.target_url,
                status=scan.status.value if hasattr(scan.status, "value") else str(scan.status),
                risk_score=scan.risk_score,
                created_at=scan.created_at,
                completed_at=scan.completed_at,
                username=username,
            )
            for scan, username in rows
        ]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def get_all_findings(self) -> list[AdminFindingResponse]:
        """Return all findings with scan target_url, newest first."""
        rows = (
            self.db.query(Finding, Scan.target_url)
            .join(Scan, Finding.scan_id == Scan.id)
            .order_by(Finding.created_at.desc())
            .all()
        )
        return [
            AdminFindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                vulnerability_name=f.vulnerability_name,
                plugin=f.plugin,
                severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                description=f.description,
                target_url=target_url,
                created_at=f.created_at,
            )
            for f, target_url in rows
        ]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_user_or_404(self, user_id: int) -> User:
        user = self.db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with id {user_id} not found.",
            )
        return user

    def _guard_self_and_admin(self, target: User, admin: User, action: str) -> None:
        """Prevent an admin from modifying themselves or other admins."""
        if target.id == admin.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot {action} your own account.",
            )
        target_role = target.role.value if hasattr(target.role, "value") else str(target.role)
        if target_role == UserRole.ADMIN.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cannot {action} another admin account.",
            )
