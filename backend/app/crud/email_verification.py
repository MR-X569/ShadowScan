"""
CRUD operations for EmailVerification.

Contains only database operations.
Business logic belongs in the service layer.
"""

from datetime import datetime

from sqlalchemy.orm import Session

from app.core.enums import VerificationPurpose
from app.models.email_verification import EmailVerification


def create_verification(
    db: Session,
    verification: EmailVerification,
) -> EmailVerification:
    """
    Create a new verification record.
    """
    db.add(verification)
    db.commit()
    db.refresh(verification)
    return verification


def get_active_verification(
    db: Session,
    user_id: int,
    purpose: VerificationPurpose,
) -> EmailVerification | None:
    """
    Return the latest unused and unexpired OTP.
    """
    return (
        db.query(EmailVerification)
        .filter(
            EmailVerification.user_id == user_id,
            EmailVerification.purpose == purpose,
            EmailVerification.used.is_(False),
            EmailVerification.expires_at > datetime.utcnow(),
        )
        .order_by(EmailVerification.created_at.desc())
        .first()
    )


def get_verification_by_otp(
    db: Session,
    user_id: int,
    otp: str,
    purpose: VerificationPurpose,
) -> EmailVerification | None:
    """
    Find a verification record by OTP.
    """
    return (
        db.query(EmailVerification)
        .filter(
            EmailVerification.user_id == user_id,
            EmailVerification.otp == otp,
            EmailVerification.purpose == purpose,
            EmailVerification.used.is_(False),
            EmailVerification.expires_at > datetime.utcnow(),
        )
        .first()
    )


def mark_verification_used(
    db: Session,
    verification: EmailVerification,
) -> None:
    """
    Mark OTP as used.
    """
    verification.used = True
    db.commit()


def increment_attempts(
    db: Session,
    verification: EmailVerification,
) -> None:
    """
    Increase failed OTP attempts.
    """
    verification.attempts += 1
    db.commit()


def delete_user_verifications(
    db: Session,
    user_id: int,
    purpose: VerificationPurpose,
) -> None:
    """
    Delete all OTPs for a user and purpose.
    Used before generating a fresh OTP.
    """
    (
        db.query(EmailVerification)
        .filter(
            EmailVerification.user_id == user_id,
            EmailVerification.purpose == purpose,
        )
        .delete()
    )

    db.commit()


def delete_expired_verifications(
    db: Session,
) -> None:
    """
    Delete expired OTP records.
    """
    (
        db.query(EmailVerification)
        .filter(
            EmailVerification.expires_at <= datetime.utcnow()
        )
        .delete()
    )

    db.commit()