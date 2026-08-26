from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.config import settings
from app.schemas.user import UserCreate, UserResponse
from app.schemas.token import Token
from app.schemas.email_verification import (
    VerifyEmailRequest,
    ResendOTPRequest,
    ForgotPasswordRequest,
    VerifyResetOtpRequest,
    ResetPasswordRequest,
)
from app.services.auth_service import AuthService
from app.services.email_verification_service import (
    EmailVerificationService,
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
)
def register(
    user: UserCreate,
    db: Session = Depends(get_db),
):
    service = AuthService(db)

    try:
        return service.register(user)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e),
        )


@router.post(
    "/login",
    response_model=Token,
)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    service = AuthService(db)

    try:
        return service.login(
            form_data.username,
            form_data.password,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=401,
            detail=str(e),
        )


@router.post("/verify-email")
def verify_email(
    payload: VerifyEmailRequest,
    db: Session = Depends(get_db),
):
    service = EmailVerificationService(db)

    service.verify_email(
        payload.email,
        payload.otp,
    )

    return {
        "message": "Email verified successfully."
    }


@router.post("/resend-otp")
def resend_otp(
    payload: ResendOTPRequest,
    db: Session = Depends(get_db),
):
    service = EmailVerificationService(db)

    service.resend_verification_otp(
        payload.email,
    )

    return {
        "message": "Verification OTP sent."
    }


@router.post("/forgot-password")
def forgot_password(
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    service = AuthService(db)
    service.forgot_password(payload.email)
    return {
        "message": "If an account with this email exists, a password reset code has been sent."
    }


@router.post("/verify-reset-otp")
def verify_reset_otp(
    payload: VerifyResetOtpRequest,
    db: Session = Depends(get_db),
):
    service = AuthService(db)
    service.verify_reset_otp(payload.email, payload.otp)
    return {
        "message": "OTP verified successfully."
    }


@router.post("/reset-password")
def reset_password(
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    service = AuthService(db)
    service.reset_password(payload.email, payload.otp, payload.password)
    return {
        "message": "Password has been reset successfully. You can now log in."
    }


@router.get("/google/login")
def google_login(
    db: Session = Depends(get_db),
):
    service = AuthService(db)
    authorization_url, state = service.get_google_authorization_url()

    response = RedirectResponse(
        url=authorization_url,
        status_code=302,
    )
    response.set_cookie(
        key="google_oauth_state",
        value=state,
        max_age=600,
        httponly=True,
        samesite="lax",
    )

    return response


@router.get(
    "/google/callback",
)
def google_callback(
    response: Response,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    google_oauth_state: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
):
    service = AuthService(db)

    token = service.login_with_google(
        code=code,
        state_value=state,
        expected_state=google_oauth_state,
        error=error,
    )

    # Set secure short-lived httpOnly cookie instead of exposing token in URL query parameter
    redirect_response = RedirectResponse(
        url=f"{settings.frontend_url}/auth/google/callback",
        status_code=302,
    )
    redirect_response.delete_cookie("google_oauth_state")
    redirect_response.set_cookie(
        key="oauth_exchange_token",
        value=token.access_token,
        max_age=300,
        httponly=True,
        samesite="lax",
    )

    return redirect_response


@router.post(
    "/google/token-exchange",
    response_model=Token,
)
def google_token_exchange(
    response: Response,
    oauth_exchange_token: str | None = Cookie(default=None),
):
    """Exchanges the temporary httpOnly OAuth cookie for the API bearer token."""
    if not oauth_exchange_token:
        raise HTTPException(
            status_code=400,
            detail="No OAuth exchange token found. Please login again.",
        )

    # Delete the exchange cookie once consumed
    response.delete_cookie("oauth_exchange_token")

    return Token(
        access_token=oauth_exchange_token,
        token_type="bearer",
    )
