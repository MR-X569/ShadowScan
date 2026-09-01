import hashlib
import hmac
import logging
import secrets
import time

from fastapi import HTTPException, status
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from sqlalchemy.orm import Session

from app.core.config import settings

logger = logging.getLogger(__name__)
from app.schemas.user import UserCreate
from app.schemas.token import Token

from app.models.user import User

from app.crud.user import (
    create_user,
    get_user_by_email,
    get_user_by_username,
)

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
)

from app.services.email_verification_service import (
    EmailVerificationService,
)


class AuthService:

    def __init__(self, db: Session):
        self.db = db
        self.email_verification = EmailVerificationService(db)

    def register(
        self,
        user: UserCreate,
    ) -> User:

        existing_user_by_email = get_user_by_email(
            self.db,
            user.email,
        )
        existing_user_by_username = get_user_by_username(
            self.db,
            user.username,
        )

        if existing_user_by_email:
            if existing_user_by_email.is_verified:
                raise ValueError(
                    "Email already exists."
                )

            # Recovering or re-registering an unverified account
            if existing_user_by_username and existing_user_by_username.id != existing_user_by_email.id:
                raise ValueError(
                    "Username already exists."
                )

            existing_user_by_email.username = user.username
            existing_user_by_email.full_name = user.full_name
            existing_user_by_email.hashed_password = hash_password(
                user.password,
            )
            self.db.commit()
            self.db.refresh(existing_user_by_email)

            self.email_verification.send_verification_otp(
                existing_user_by_email,
            )
            return existing_user_by_email

        if existing_user_by_username:
            raise ValueError(
                "Username already exists."
            )

        new_user = User(
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            hashed_password=hash_password(
                user.password,
            ),
        )

        created_user = create_user(
            self.db,
            new_user,
        )

        self.email_verification.send_verification_otp(
            created_user,
        )

        return created_user

    def login(
        self,
        username: str,
        password: str,
    ) -> Token:

        identifier = username.strip() if username else ""
        if not identifier:
            raise ValueError(
                "Username or email is required."
            )

        # Check by email or username based on format
        if "@" in identifier:
            user = get_user_by_email(
                self.db,
                identifier,
            ) or get_user_by_username(
                self.db,
                identifier,
            )
        else:
            user = get_user_by_username(
                self.db,
                identifier,
            ) or get_user_by_email(
                self.db,
                identifier,
            )

        if not user:
            raise ValueError(
                "Invalid username or password."
            )


        if not verify_password(
            password,
            user.hashed_password,
        ):
            raise ValueError(
                "Invalid username or password."
            )

        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please verify your email before logging in.",
            )

        access_token = create_access_token(
            {
                "sub": user.username,
            }
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
        )

    def get_google_authorization_url(self) -> tuple[str, str]:
        """Create a Google consent-screen URL for the configured web client."""
        state = self._create_google_oauth_state()
        flow = self._create_google_oauth_flow(state=state)

        authorization_url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="select_account",
        )

        return authorization_url, state

    def login_with_google(
        self,
        code: str | None,
        state_value: str | None,
        expected_state: str | None,
        error: str | None = None,
    ) -> Token:
        """Exchange and validate a Google callback before issuing our JWT."""
        if error is not None:
            logger.error(f"Google OAuth returned an error: {error}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Google authentication error: {error}",
            )

        if not code or not state_value:
            logger.error("Missing authorization code or state parameter in Google callback.")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing authorization code or state in Google OAuth callback.",
            )

        if not expected_state or not hmac.compare_digest(
            state_value,
            expected_state,
        ):
            logger.error("State parameter does not match or expected state cookie is missing.")
            self._raise_invalid_google_callback("OAuth state mismatch.")

        self._validate_google_oauth_state(state_value)
        flow = self._create_google_oauth_flow(state=state_value)

        try:
            flow.fetch_token(code=code)
        except Exception as exc:
            logger.error(f"Error fetching Google OAuth token: {exc}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to exchange Google OAuth code: {exc}",
            ) from exc

        token_value = flow.credentials.id_token

        if not token_value:
            logger.error("Google credentials did not return an ID token.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Google token: ID token missing.",
            )

        try:
            google_user = id_token.verify_oauth2_token(
                token_value,
                GoogleRequest(),
                settings.google_client_id,
            )
        except (GoogleAuthError, ValueError) as exc:
            logger.error(f"Google ID token verification failed: {exc}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid Google ID token: {exc}",
            ) from exc

        if google_user.get("iss") not in {
            "accounts.google.com",
            "https://accounts.google.com",
        }:
            logger.error(f"Invalid Google token issuer: {google_user.get('iss')}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Google token issuer.",
            )

        email = google_user.get("email")

        if not email:
            logger.error("Google user profile has no email.")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google account did not provide an email address.",
            )

        if google_user.get("email_verified") is not True:
            logger.error(f"Google email is not verified: {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google account email is not verified.",
            )

        return self._login_or_create_google_user(
            email=email,
            full_name=google_user.get("name"),
            picture=google_user.get("picture"),
            google_id=google_user.get("sub"),
        )

    def _login_or_create_google_user(
        self,
        email: str,
        full_name: str | None,
        picture: str | None,
        google_id: str | None,
    ) -> Token:
        """Find or create a user from a validated Google identity."""
        del picture, google_id

        normalized_email = email.strip().lower()
        user = get_user_by_email(self.db, normalized_email)

        if user is None:
            user = User(
                username=self._generate_google_username(),
                email=normalized_email,
                full_name=full_name,
                hashed_password=hash_password(secrets.token_urlsafe(32)),
                is_verified=True,
            )
            user = create_user(self.db, user)
        else:
            # If account already exists with this email, ensure it is verified
            if not user.is_verified:
                user.is_verified = True
                self.db.commit()
                self.db.refresh(user)

        access_token = create_access_token(
            {
                "sub": user.username,
            }
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
        )

    def _create_google_oauth_flow(self, state: str | None = None) -> Flow:
        if not all(
            (
                settings.google_client_id,
                settings.google_client_secret,
                settings.google_redirect_uri,
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Google OAuth is not configured.",
            )

        # Allow HTTP redirect in local development
        if settings.google_redirect_uri and settings.google_redirect_uri.startswith("http://"):
            import os
            os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [settings.google_redirect_uri],
                }
            },
            scopes=[
                "openid",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
            ],
            state=state,
            autogenerate_code_verifier=False,
        )
        flow.redirect_uri = settings.google_redirect_uri

        return flow


    def _create_google_oauth_state(self) -> str:
        payload = f"{int(time.time())}:{secrets.token_urlsafe(32)}"
        signature = hmac.new(
            settings.secret_key.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"{payload}.{signature}"

    def _validate_google_oauth_state(self, state_value: str) -> None:
        try:
            payload, signature = state_value.rsplit(".", 1)
            timestamp_value, _ = payload.split(":", 1)
            timestamp = int(timestamp_value)
        except (TypeError, ValueError):
            logger.error(f"Malformed state parameter: {state_value}")
            self._raise_invalid_google_callback("Malformed OAuth state parameter.")

        expected_signature = hmac.new(
            settings.secret_key.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            logger.error("State HMAC signature verification failed.")
            self._raise_invalid_google_callback("Invalid OAuth state signature.")

        if time.time() - timestamp > 600 or timestamp > time.time():
            logger.error(f"OAuth state expired or invalid timestamp: {timestamp}")
            self._raise_invalid_google_callback("Expired OAuth state parameter.")

    def _generate_google_username(self) -> str:
        while True:
            username = f"google_{secrets.token_urlsafe(12)}"
            if get_user_by_username(self.db, username) is None:
                return username

    @staticmethod
    def _raise_invalid_google_callback(detail: str = "Invalid Google OAuth callback.") -> None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )

    def forgot_password(
        self,
        email: str,
    ) -> None:
        """Trigger password reset OTP for the given email (anti-enumeration)."""
        self.email_verification.send_password_reset_otp(email)

    def verify_reset_otp(
        self,
        email: str,
        otp: str,
    ) -> None:
        """Validate password reset OTP."""
        self.email_verification.verify_reset_otp(email, otp)

    def reset_password(
        self,
        email: str,
        otp: str,
        new_password: str,
    ) -> None:
        """Verify OTP, consume it, and update user password."""
        user = get_user_by_email(self.db, email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP.",
            )

        self.email_verification.consume_reset_otp(email, otp)

        user.hashed_password = hash_password(new_password)
        self.db.commit()
        self.db.refresh(user)

    def change_password(
        self,
        user: User,
        old_password: str,
        new_password: str,
    ) -> None:
        """Change password for an authenticated user."""
        if not verify_password(old_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect.",
            )

        if old_password == new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password cannot be the same as the current password.",
            )

        user.hashed_password = hash_password(new_password)
        self.db.commit()
        self.db.refresh(user)

