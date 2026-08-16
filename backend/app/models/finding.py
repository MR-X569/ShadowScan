from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    vulnerability_name = Column(String(100), nullable=False)

    severity = Column(String(20), nullable=False)

    description = Column(Text, nullable=True)

    recommendation = Column(Text, nullable=True)

    status = Column(String(20), default="Open")

    scan = relationship("Scan", back_populates="findings")