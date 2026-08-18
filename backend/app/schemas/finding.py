from pydantic import BaseModel, ConfigDict


class FindingBase(BaseModel):
    vulnerability_name: str
    severity: str
    description: str | None = None
    recommendation: str | None = None
    status: str = "OPEN"


class FindingCreate(FindingBase):
    pass


class FindingResponse(FindingBase):
    id: int
    scan_id: int

    model_config = ConfigDict(from_attributes=True)