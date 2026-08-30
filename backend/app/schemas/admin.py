"""
Pydantic schemas for the Admin module.

These are response-only schemas used by the admin API endpoints.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# User listing
# ---------------------------------------------------------------------------


class AdminUserResponse(BaseModel):
    """User record as seen by an admin."""

    id: int
    username: str
    email: str
    full_name: str | None = None
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Scan listing (includes owner username)
# ---------------------------------------------------------------------------


class AdminScanResponse(BaseModel):
    """Scan record with owner username for admin listing."""

    id: int
    target_url: str
    status: str
    risk_score: float | None = None
    created_at: datetime | None = None
    completed_at: datetime | None = None
    username: str  # joined from users table

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Finding listing (includes scan target_url)
# ---------------------------------------------------------------------------


class AdminFindingResponse(BaseModel):
    """Finding record with scan target_url for admin listing."""

    id: int
    scan_id: int
    vulnerability_name: str
    plugin: str | None = None
    severity: str
    description: str | None = None
    target_url: str  # joined from scans table
    created_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Latest items (embedded in stats)
# ---------------------------------------------------------------------------


class LatestScanItem(BaseModel):
    id: int
    target_url: str
    status: str
    risk_score: float | None = None
    created_at: datetime | None = None
    username: str

    model_config = ConfigDict(from_attributes=True)


class LatestUserItem(BaseModel):
    id: int
    username: str
    email: str
    is_verified: bool
    created_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Dashboard statistics
# ---------------------------------------------------------------------------


class AdminStatsResponse(BaseModel):
    """Aggregate platform statistics for the admin dashboard."""

    total_users: int
    verified_users: int
    total_scans: int
    scans_running: int
    scans_completed: int
    scans_failed: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    latest_scans: list[LatestScanItem]
    latest_users: list[LatestUserItem]
