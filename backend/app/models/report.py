from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    report_type = Column(String(20), nullable=False)

    report_path = Column(String(255), nullable=False)

    generated_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="reports")