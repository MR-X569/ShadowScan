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

    redirect_response = RedirectResponse(
        url=f"{settings.frontend_url}/auth/google/callback?token={token.access_token}",
        status_code=302,
    )
    redirect_response.delete_cookie("google_oauth_state")

    return redirect_response
