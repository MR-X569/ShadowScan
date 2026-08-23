import hashlib
import hmac
import secrets
import time

from fastapi import HTTPException, status
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from sqlalchemy.orm import Session

from app.core.config import settings
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

        if get_user_by_username(
            self.db,
            user.username,
        ):
            raise ValueError(
                "Username already exists."
            )

        if get_user_by_email(
            self.db,
            user.email,
        ):
            raise ValueError(
                "Email already exists."
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

        user = get_user_by_username(
            self.db,
            username,
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
        if error is not None or not code or not state_value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Google OAuth callback.",
            )

        if not expected_state or not hmac.compare_digest(
            state_value,
            expected_state,
        ):
            self._raise_invalid_google_callback()

        self._validate_google_oauth_state(state_value)
        flow = self._create_google_oauth_flow(state=state_value)

        try:
            flow.fetch_token(code=code)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Google OAuth callback.",
            ) from exc

        token_value = flow.credentials.id_token

        if not token_value:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Google token.",
            )

        try:
            google_user = id_token.verify_oauth2_token(
                token_value,
                GoogleRequest(),
                settings.google_client_id,
            )
        except (GoogleAuthError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Google token.",
            ) from exc

        if google_user.get("iss") not in {
            "accounts.google.com",
            "https://accounts.google.com",
        }:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Google token.",
            )

        email = google_user.get("email")

        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google account did not provide an email address.",
            )

        if google_user.get("email_verified") is not True:
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
        # The current User model has no fields for Google ID or profile image.
        # Keep the integration migration-free until those fields are introduced.
        del picture, google_id

        user = get_user_by_email(self.db, email)

        if user is None:
            user = User(
                username=self._generate_google_username(),
                email=email,
                full_name=full_name,
                hashed_password=hash_password(secrets.token_urlsafe(32)),
                is_verified=True,
            )
            user = create_user(self.db, user)

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
            scopes=["openid", "email", "profile"],
            state=state,
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
            self._raise_invalid_google_callback()

        expected_signature = hmac.new(
            settings.secret_key.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

        if (
            not hmac.compare_digest(signature, expected_signature)
            or time.time() - timestamp > 600
            or timestamp > time.time()
        ):
            self._raise_invalid_google_callback()

    def _generate_google_username(self) -> str:
        while True:
            username = f"google_{secrets.token_urlsafe(12)}"
            if get_user_by_username(self.db, username) is None:
                return username

    @staticmethod
    def _raise_invalid_google_callback() -> None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Google OAuth callback.",
        )

    def forgot_password(
        self,
        email: str,
    ):
        pass

    def reset_password(
        self,
        token: str,
        new_password: str,
    ):
        pass

    def change_password(
        self,
        user: User,
        old_password: str,
        new_password: str,
    ):
        pass
