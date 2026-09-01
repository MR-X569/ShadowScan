"""Comprehensive tests for user registration, email verification, OTP lifecycle, and authentication flows."""

from datetime import datetime, timedelta, UTC
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.enums import VerificationPurpose
from app.crud.email_verification import get_active_verification
from app.crud.user import get_user_by_email, get_user_by_username
from app.models.email_verification import EmailVerification
from app.models.user import User
from app.schemas.email_verification import (
    ForgotPasswordRequest,
    ResendOTPRequest,
    ResetPasswordRequest,
    VerifyEmailRequest,
    VerifyResetOtpRequest,
)
from app.schemas.user import UserCreate
from app.services.auth_service import AuthService
from app.services.email_verification_service import (
    EmailVerificationService,
    MAX_OTP_ATTEMPTS,
)


@pytest.fixture
def db_session():
    """Create a fresh in-memory SQLite database session for each test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# 1. New Valid Registration & OTP Delivery
# ---------------------------------------------------------------------------


def test_new_valid_registration_creates_unverified_user_and_sends_otp(db_session):
    """Test standard registration: user record is created unverified and OTP is dispatched."""
    auth_service = AuthService(db_session)

    with patch.object(
        auth_service.email_verification.email_service,
        "send_verification_email",
        return_value=True,
    ) as mock_send:
        user_in = UserCreate(
            username="testuser",
            email="testuser@example.com",
            password="Password123!",
            full_name="Test User",
        )
        created_user = auth_service.register(user_in)

        assert created_user.id is not None
        assert created_user.username == "testuser"
        assert created_user.email == "testuser@example.com"
        assert created_user.is_verified is False

        # Verify OTP record in database
        active_otp = get_active_verification(
            db_session, created_user.id, VerificationPurpose.EMAIL_VERIFICATION
        )
        assert active_otp is not None
        assert len(active_otp.otp) == 6
        assert active_otp.used is False

        # Verify email delivery was invoked
        mock_send.assert_called_once_with("testuser@example.com", active_otp.otp)


# ---------------------------------------------------------------------------
# 2. OTP Delivery Failure Leaves User Unverified & Reproduces State
# ---------------------------------------------------------------------------


def test_otp_delivery_failure_leaves_user_unverified(db_session):
    """
    Reproduce case: OTP/email delivery fails (e.g. SMTP down), raising 500.
    The user record remains in DB as is_verified=False.
    """
    auth_service = AuthService(db_session)

    with patch.object(
        auth_service.email_verification.email_service,
        "send_verification_email",
        return_value=False,
    ):
        user_in = UserCreate(
            username="delivery_fail_user",
            email="fail_delivery@example.com",
            password="Password123!",
            full_name="Delivery Fail",
        )

        with pytest.raises(HTTPException) as exc_info:
            auth_service.register(user_in)

        assert exc_info.value.status_code == 500
        assert "Failed to send verification email" in exc_info.value.detail

        # User is saved in the database as unverified
        user_in_db = get_user_by_email(db_session, "fail_delivery@example.com")
        assert user_in_db is not None
        assert user_in_db.is_verified is False


# ---------------------------------------------------------------------------
# 3. Retry Registration with Existing Unverified Email Recovers Account
# ---------------------------------------------------------------------------


def test_retry_registration_with_existing_unverified_email_succeeds(db_session):
    """
    Attempting registration again with the same unverified email recovers the
    account: no duplicate record is created, details are updated, and a fresh OTP is sent.
    """
    auth_service = AuthService(db_session)

    # Initial attempt with email failure
    with patch.object(
        auth_service.email_verification.email_service,
        "send_verification_email",
        return_value=False,
    ):
        user_in_1 = UserCreate(
            username="retry_user",
            email="retry@example.com",
            password="OldPassword123!",
            full_name="Old Name",
        )
        with pytest.raises(HTTPException):
            auth_service.register(user_in_1)

    initial_user = get_user_by_email(db_session, "retry@example.com")
    assert initial_user is not None
    initial_user_id = initial_user.id

    # Second registration attempt (retry) with updated password/name
    with patch.object(
        auth_service.email_verification.email_service,
        "send_verification_email",
        return_value=True,
    ) as mock_send_success:
        user_in_2 = UserCreate(
            username="retry_user",
            email="retry@example.com",
            password="NewPassword123!",
            full_name="Updated Name",
        )
        recovered_user = auth_service.register(user_in_2)

        # Same user record reused (no duplicate)
        assert recovered_user.id == initial_user_id
        assert recovered_user.full_name == "Updated Name"
        assert recovered_user.is_verified is False

        # Fresh OTP generated and sent
        active_otp = get_active_verification(
            db_session, recovered_user.id, VerificationPurpose.EMAIL_VERIFICATION
        )
        assert active_otp is not None
        mock_send_success.assert_called_once_with("retry@example.com", active_otp.otp)


# ---------------------------------------------------------------------------
# 4. Duplicate Already-Verified Account is Rejected
# ---------------------------------------------------------------------------


def test_duplicate_already_verified_account_rejected(db_session):
    """Attempting to register with an email of an already-verified user must fail."""
    auth_service = AuthService(db_session)

    with patch.object(
        auth_service.email_verification.email_service,
        "send_verification_email",
        return_value=True,
    ):
        user_in = UserCreate(
            username="verified_user",
            email="verified@example.com",
            password="Password123!",
            full_name="Verified User",
        )
        user = auth_service.register(user_in)
        # Mark verified
        user.is_verified = True
        db_session.commit()

        # Try to register again with the same verified email
        with pytest.raises(ValueError) as exc_info:
            auth_service.register(user_in)

        assert "Email already exists" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 5. Login Before Verification is Rejected
# ---------------------------------------------------------------------------


def test_login_before_verification_rejected(db_session):
    """Unverified users must receive HTTP 403 when attempting to login."""
    auth_service = AuthService(db_session)

    with patch.object(
        auth_service.email_verification.email_service,
        "send_verification_email",
        return_value=True,
    ):
        user_in = UserCreate(
            username="unverified_login",
            email="unverified_login@example.com",
            password="Password123!",
            full_name="Unverified",
        )
        auth_service.register(user_in)

        with pytest.raises(HTTPException) as exc_info:
            auth_service.login("unverified_login@example.com", "Password123!")

        assert exc_info.value.status_code == 403
        assert "verify your email" in exc_info.value.detail.lower()


# ---------------------------------------------------------------------------
# 6. Resend OTP for Unverified User & Superseding Old OTPs
# ---------------------------------------------------------------------------


def test_resend_otp_invalidates_old_and_sends_fresh_otp(db_session):
    """Resending OTP generates a fresh code and supersedes/deletes previous OTPs."""
    auth_service = AuthService(db_session)
    email_service = EmailVerificationService(db_session)

    with patch.object(email_service.email_service, "send_verification_email", return_value=True):
        user_in = UserCreate(
            username="resend_user",
            email="resend@example.com",
            password="Password123!",
            full_name="Resend User",
        )
        auth_service.register(user_in)
        user = get_user_by_email(db_session, "resend@example.com")

        old_otp = get_active_verification(
            db_session, user.id, VerificationPurpose.EMAIL_VERIFICATION
        )
        assert old_otp is not None

        old_otp_value = old_otp.otp
        # Age the created_at timestamp to bypass 60s cooldown for testing
        old_otp.created_at = datetime.now(UTC) - timedelta(seconds=65)
        db_session.commit()

        email_service.resend_verification_otp("resend@example.com")

        new_otp = get_active_verification(
            db_session, user.id, VerificationPurpose.EMAIL_VERIFICATION
        )
        assert new_otp is not None
        assert new_otp.used is False
        # Verify new active OTP exists and old OTP was deleted
        assert db_session.query(EmailVerification).filter_by(user_id=user.id).count() == 1


def test_resend_otp_rate_limiting_cooldown(db_session):
    """Requesting resend immediately within 60s cooldown raises HTTP 429."""
    auth_service = AuthService(db_session)
    email_service = EmailVerificationService(db_session)

    with patch.object(email_service.email_service, "send_verification_email", return_value=True):
        user_in = UserCreate(
            username="cooldown_user",
            email="cooldown@example.com",
            password="Password123!",
            full_name="Cooldown User",
        )
        auth_service.register(user_in)

        # Immediate resend attempt should trigger rate limit (429)
        with pytest.raises(HTTPException) as exc_info:
            email_service.resend_verification_otp("cooldown@example.com")

        assert exc_info.value.status_code == 429
        assert "Please wait" in exc_info.value.detail


def test_resend_otp_for_already_verified_user_fails(db_session):
    """Resending OTP for an already-verified user raises HTTP 400."""
    auth_service = AuthService(db_session)
    email_service = EmailVerificationService(db_session)

    with patch.object(email_service.email_service, "send_verification_email", return_value=True):
        user_in = UserCreate(
            username="already_v_user",
            email="already_v@example.com",
            password="Password123!",
            full_name="Already Verified",
        )
        user = auth_service.register(user_in)
        user.is_verified = True
        db_session.commit()

        with pytest.raises(HTTPException) as exc_info:
            email_service.resend_verification_otp("already_v@example.com")

        assert exc_info.value.status_code == 400
        assert "already verified" in exc_info.value.detail


def test_resend_otp_for_nonexistent_user_raises_404(db_session):
    """Resending OTP for an unknown email raises HTTP 404."""
    email_service = EmailVerificationService(db_session)

    with pytest.raises(HTTPException) as exc_info:
        email_service.resend_verification_otp("ghost@example.com")

    assert exc_info.value.status_code == 404
    assert "User not found" in exc_info.value.detail


# ---------------------------------------------------------------------------
# 7. Successful OTP Verification Marks Account Verified
# ---------------------------------------------------------------------------


def test_successful_otp_verification_marks_account_verified(db_session):
    """Submitting the valid OTP marks the user is_verified=True and consumes the OTP."""
    auth_service = AuthService(db_session)
    email_service = EmailVerificationService(db_session)

    with patch.object(email_service.email_service, "send_verification_email", return_value=True):
        user_in = UserCreate(
            username="verify_me",
            email="verify_me@example.com",
            password="Password123!",
            full_name="Verify Me",
        )
        user = auth_service.register(user_in)

        active_otp = get_active_verification(
            db_session, user.id, VerificationPurpose.EMAIL_VERIFICATION
        )
        assert active_otp is not None

        # Verify email with correct OTP
        email_service.verify_email("verify_me@example.com", active_otp.otp)

        db_session.refresh(user)
        assert user.is_verified is True
        assert active_otp.used is True

        # Now login succeeds
        token = auth_service.login("verify_me@example.com", "Password123!")
        assert token.access_token is not None


# ---------------------------------------------------------------------------
# 8. Invalid & Expired OTPs and Lockout
# ---------------------------------------------------------------------------


def test_invalid_otp_rejected_and_increments_attempts(db_session):
    """Submitting wrong OTP raises HTTP 400 and increments attempt count."""
    auth_service = AuthService(db_session)
    email_service = EmailVerificationService(db_session)

    with patch.object(email_service.email_service, "send_verification_email", return_value=True):
        user_in = UserCreate(
            username="wrong_otp_user",
            email="wrong_otp@example.com",
            password="Password123!",
            full_name="Wrong OTP",
        )
        user = auth_service.register(user_in)
        active_otp = get_active_verification(
            db_session, user.id, VerificationPurpose.EMAIL_VERIFICATION
        )

        with pytest.raises(HTTPException) as exc_info:
            email_service.verify_email("wrong_otp@example.com", "000000")

        assert exc_info.value.status_code == 400
        assert "Invalid or expired OTP" in exc_info.value.detail

        db_session.refresh(active_otp)
        assert active_otp.attempts == 1
        db_session.refresh(user)
        assert user.is_verified is False


def test_expired_otp_is_rejected(db_session):
    """Expired OTP raises HTTP 400."""
    auth_service = AuthService(db_session)
    email_service = EmailVerificationService(db_session)

    with patch.object(email_service.email_service, "send_verification_email", return_value=True):
        user_in = UserCreate(
            username="expired_otp_user",
            email="expired_otp@example.com",
            password="Password123!",
            full_name="Expired OTP",
        )
        user = auth_service.register(user_in)
        active_otp = get_active_verification(
            db_session, user.id, VerificationPurpose.EMAIL_VERIFICATION
        )

        # Set expires_at in past
        active_otp.expires_at = datetime.now(UTC) - timedelta(minutes=10)
        db_session.commit()

        with pytest.raises(HTTPException) as exc_info:
            email_service.verify_email("expired_otp@example.com", active_otp.otp)

        assert exc_info.value.status_code == 400
        assert "Invalid or expired OTP" in exc_info.value.detail


def test_max_otp_attempts_lockout(db_session):
    """Exceeding MAX_OTP_ATTEMPTS locks out verification and returns HTTP 429."""
    auth_service = AuthService(db_session)
    email_service = EmailVerificationService(db_session)

    with patch.object(email_service.email_service, "send_verification_email", return_value=True):
        user_in = UserCreate(
            username="lockout_user",
            email="lockout@example.com",
            password="Password123!",
            full_name="Lockout User",
        )
        user = auth_service.register(user_in)
        active_otp = get_active_verification(
            db_session, user.id, VerificationPurpose.EMAIL_VERIFICATION
        )

        # Simulate 5 failed attempts
        active_otp.attempts = MAX_OTP_ATTEMPTS
        db_session.commit()

        # Even with the correct OTP, verification is locked out
        with pytest.raises(HTTPException) as exc_info:
            email_service.verify_email("lockout@example.com", active_otp.otp)

        assert exc_info.value.status_code == 429
        assert "Maximum OTP attempts exceeded" in exc_info.value.detail


# ---------------------------------------------------------------------------
# 9. Syntactic Email Validation & 123@gmail.com RFC Compliance
# ---------------------------------------------------------------------------


def test_syntactic_email_validation_and_rfc_compliance():
    """
    Validate that standard RFC-compliant formats are accepted,
    while 123@gmail.com (purely numeric local-part) and malformed addresses are rejected.
    """
    valid_emails = [
        "user123@gmail.com",
        "user.name+tag@example.co.uk",
        "admin_1@sub.company.org",
        "test-user@domain.io",
    ]

    for em in valid_emails:
        u = UserCreate(
            username="user_" + em.split("@")[0].replace(".", "_").replace("+", "_")[:20],
            email=em,
            password="Password123!",
            full_name="Valid Email Test",
        )
        assert u.email == em

        # Also verify request schemas accept valid emails
        v_req = VerifyEmailRequest(email=em, otp="123456")
        assert v_req.email == em
        r_req = ResendOTPRequest(email=em)
        assert r_req.email == em

    # Malformed emails (including pure-numeric local parts) must be rejected
    invalid_emails = [
        "123@gmail.com",
        "notanemail",
        "missingatsign.com",
        "user@",
        "@nodomain.com",
        "user@domain..com",
    ]

    for bad_em in invalid_emails:
        with pytest.raises(ValidationError):
            UserCreate(
                username="bad_user",
                email=bad_em,
                password="Password123!",
                full_name="Bad Email Test",
            )

