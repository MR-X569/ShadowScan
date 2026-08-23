from sqlalchemy import Boolean, Column, DateTime, Enum, Integer, String
from app.core.enums import UserRole
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy import Boolean
from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)

    full_name = Column(String(100), nullable=True)

    role = Column(
    Enum(UserRole),
    default=UserRole.USER,
    nullable=False,
    )
    
    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    is_verified = Column(
    Boolean,
    default=False,
    nullable=False,
    )

    email_verifications = relationship(
    "EmailVerification",
    back_populates="user",
    cascade="all, delete-orphan",
    )
    
    scans = relationship("Scan", back_populates="user")