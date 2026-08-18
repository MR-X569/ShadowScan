from sqlalchemy import Column, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from app.core.enums import Severity, FindingStatus
from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    vulnerability_name = Column(String(100), nullable=False)

    severity = Column(
    Enum(Severity),
    nullable=False,
    )

    description = Column(Text, nullable=True)

    recommendation = Column(Text, nullable=True)

    status = Column(
    Enum(FindingStatus),
    default=FindingStatus.OPEN,
    nullable=False,
    )

    scan = relationship("Scan", back_populates="findings")