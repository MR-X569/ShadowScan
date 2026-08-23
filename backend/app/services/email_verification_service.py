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

        if verification is None or verification.otp != otp:
            if verification is not None:
                increment_attempts(self.db, verification)

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP.",
            )

        if verification.attempts >= 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum OTP attempts exceeded.",
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

        self.send_verification_otp(user)
