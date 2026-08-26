from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.enums import Severity, FindingStatus
from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    vulnerability_name = Column(String(100), nullable=False)

    plugin = Column(String(100), nullable=True)

    severity = Column(
        Enum(Severity),
        nullable=False,
    )

    description = Column(Text, nullable=True)

    recommendation = Column(Text, nullable=True)

    evidence = Column(Text, nullable=True)

    status = Column(
        Enum(FindingStatus),
        default=FindingStatus.OPEN,
        nullable=False,
    )

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="findings")