from datetime import datetime, UTC
from app.core.enums import VerificationPurpose
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Enum,
    text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class EmailVerification(Base):
    __tablename__ = "email_verifications"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    otp = Column(
        String(6),
        nullable=False,
    )

    purpose = Column(
        Enum(VerificationPurpose),
        nullable=False,
    )

    attempts = Column(
        Integer,
        default=0,
        server_default=text("0"),
        nullable=False,
    )

    used = Column(
        Boolean,
        default=False,
        server_default=text("false"),
        nullable=False,
    )

    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=func.now(),
        nullable=False,
    )

    user = relationship(
        "User",
        back_populates="email_verifications",
    )