from datetime import datetime
from app.core.enums import VerificationPurpose
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Enum,
)

from sqlalchemy.orm import relationship

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
        ForeignKey("users.id"),
        nullable=False,
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
        nullable=False,
    )

    used = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    expires_at = Column(
        DateTime,
        nullable=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    user = relationship(
        "User",
        back_populates="email_verifications",
    )