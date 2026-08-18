from sqlalchemy.orm import Session

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


class AuthService:

    def __init__(self, db: Session):
        self.db = db

    def register(
        self,
        user: UserCreate,
    ) -> User:

        if get_user_by_username(self.db, user.username):
            raise ValueError("Username already exists.")

        if get_user_by_email(self.db, user.email):
            raise ValueError("Email already exists.")

        new_user = User(
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            hashed_password=hash_password(user.password),
        )

        return create_user(
            self.db,
            new_user,
        )

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

        access_token = create_access_token(
            {
                "sub": user.username,
            }
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
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