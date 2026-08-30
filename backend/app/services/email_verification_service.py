from datetime import datetime, UTC
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.enums import VerificationPurpose
from app.core.otp import generate_otp, get_expiry_time

from app.crud.email_verification import (
    create_verification,
    delete_user_verifications,
    get_active_verification,
    increment_attempts,
    mark_verification_used,
)

from app.crud.user import get_user_by_email, verify_user

from app.models.email_verification import EmailVerification
from app.models.user import User

from app.services.email_service import EmailService

MAX_OTP_ATTEMPTS = 5
RESEND_COOLDOWN_SECONDS = 60


class EmailVerificationService:

    def __init__(self, db: Session):
        self.db = db
        self.email_service = EmailService()

    def send_verification_otp(
        self,
        user: User,
    ) -> None:

        delete_user_verifications(
            self.db,
            user.id,
            VerificationPurpose.EMAIL_VERIFICATION,
        )

        otp = generate_otp()

        verification = EmailVerification(
            user_id=user.id,
            otp=otp,
            purpose=VerificationPurpose.EMAIL_VERIFICATION,
            expires_at=get_expiry_time(),
            created_at=datetime.now(UTC),
            attempts=0,
            used=False,
        )

        create_verification(
            self.db,
            verification,
        )

        success = self.email_service.send_verification_email(
            user.email,
            otp,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification email.",
            )

    def verify_email(
        self,
        email: str,
        otp: str,
    ) -> None:

        user = get_user_by_email(
            self.db,
            email,
        )

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )

        if user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already verified.",
            )

        verification = get_active_verification(
            self.db,
            user.id,
            VerificationPurpose.EMAIL_VERIFICATION,
        )

        if verification is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP.",
            )

        # Check lockout BEFORE accepting/rejecting OTP — fixes off-by-one bug.
        if verification.attempts >= MAX_OTP_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Maximum OTP attempts exceeded. Please request a new OTP.",
            )

        if verification.otp != otp:
            increment_attempts(self.db, verification)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP.",
            )

        mark_verification_used(
            self.db,
            verification,
        )

        verify_user(
            self.db,
            user,
        )

    def resend_verification_otp(
        self,
        email: str,
    ) -> None:

        user = get_user_by_email(self.db, email)

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )

        if user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already verified.",
            )

        # Rate limit cooldown on active OTP
        active_verification = get_active_verification(
            self.db,
            user.id,
            VerificationPurpose.EMAIL_VERIFICATION,
        )
        if active_verification and active_verification.created_at:
            created_at = active_verification.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            elapsed = (datetime.now(UTC) - created_at).total_seconds()
            if elapsed < RESEND_COOLDOWN_SECONDS and active_verification.attempts < MAX_OTP_ATTEMPTS:
                remaining = int(RESEND_COOLDOWN_SECONDS - elapsed)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Please wait {remaining} seconds before requesting a new OTP.",
                )

        self.send_verification_otp(user)

    # ------------------------------------------------------------------
    # Password reset OTP methods
    # ------------------------------------------------------------------

    def send_password_reset_otp(self, email: str) -> None:
        """
        Send a password-reset OTP to the given email address.
        Always returns without error even if the email is not found,
        to prevent user enumeration.
        """
        user = get_user_by_email(self.db, email)
        if user is None:
            # Silently return — don't reveal whether the email exists.
            return

        delete_user_verifications(
            self.db,
            user.id,
            VerificationPurpose.PASSWORD_RESET,
        )

        otp = generate_otp()

        verification = EmailVerification(
            user_id=user.id,
            otp=otp,
            purpose=VerificationPurpose.PASSWORD_RESET,
            expires_at=get_expiry_time(),
            created_at=datetime.now(UTC),
            attempts=0,
            used=False,
        )

        create_verification(self.db, verification)

        # Best-effort — if email fails, don't surface the error
        self.email_service.send_password_reset_email(user.email, otp)

    def verify_reset_otp(self, email: str, otp: str) -> None:
        """
        Verify a password-reset OTP without consuming it.
        Raises HTTPException if invalid, expired, or locked out.
        """
        user = get_user_by_email(self.db, email)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP.",
            )

        verification = get_active_verification(
            self.db,
            user.id,
            VerificationPurpose.PASSWORD_RESET,
        )

        if verification is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP.",
            )

        if verification.attempts >= MAX_OTP_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Maximum OTP attempts exceeded. Please request a new OTP.",
            )

        if verification.otp != otp:
            increment_attempts(self.db, verification)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP.",
            )
        # OTP is valid — do NOT mark as used yet (that happens in reset_password)

    def consume_reset_otp(self, email: str, otp: str) -> None:
        """
        Consume (mark used) a valid password-reset OTP.
        Call this only after verifying the OTP is correct.
        """
        user = get_user_by_email(self.db, email)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP.",
            )

        verification = get_active_verification(
            self.db,
            user.id,
            VerificationPurpose.PASSWORD_RESET,
        )

        if verification is None or verification.otp != otp:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP.",
            )

        mark_verification_used(self.db, verification)
