from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    target_url = Column(String(255), nullable=False)

    status = Column(String(20), default="pending")

    risk_score = Column(Float, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationship
    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
    reports = relationship("Report", back_populates="scan")

    