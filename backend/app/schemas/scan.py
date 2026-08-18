from datetime import datetime
from pydantic import BaseModel, ConfigDict


class ScanBase(BaseModel):
    target_url: str


class ScanCreate(ScanBase):
    pass


class ScanResponse(ScanBase):
    id: int
    user_id: int
    status: str
    risk_score: float | None
    created_at: datetime
    completed_at: datetime | None

    model_config = ConfigDict(from_attributes=True)