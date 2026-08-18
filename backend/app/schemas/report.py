from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ReportBase(BaseModel):
    report_type: str


class ReportCreate(ReportBase):
    pass


class ReportResponse(ReportBase):
    id: int
    scan_id: int
    report_path: str
    generated_at: datetime

    model_config = ConfigDict(from_attributes=True)