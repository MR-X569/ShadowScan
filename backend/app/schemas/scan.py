"""
Pydantic schemas for the Scan Management module.

ScanCreate       — request body for POST /scans
ScanUpdate       — internal update payload (status / risk_score)
ScanListResponse — lightweight item returned by GET /scans
ScanResponse     — full detail returned by GET /scans/{id}
"""

from datetime import datetime

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field

from app.core.enums import ScanStatus


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class ScanCreate(BaseModel):
    """Payload accepted when creating a new scan."""

    target_url: AnyHttpUrl = Field(
        ...,
        description="The fully-qualified HTTP/HTTPS URL to scan.",
        examples=["https://example.com"],
    )


# ---------------------------------------------------------------------------
# Internal / system schemas (not exposed directly to clients)
# ---------------------------------------------------------------------------


class ScanUpdate(BaseModel):
    """Used internally by the scanner engine to update scan progress."""

    status: ScanStatus | None = None
    risk_score: float | None = Field(None, ge=0.0, le=10.0)
    completed_at: datetime | None = None


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class ScanListResponse(BaseModel):
    """Lightweight representation used in paginated list responses."""

    id: int
    target_url: str
    status: ScanStatus
    risk_score: float | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanResponse(BaseModel):
    """Full scan detail returned by GET /scans/{scan_id}."""

    id: int
    user_id: int
    target_url: str
    status: ScanStatus
    risk_score: float | None
    created_at: datetime
    completed_at: datetime | None

    model_config = ConfigDict(from_attributes=True)