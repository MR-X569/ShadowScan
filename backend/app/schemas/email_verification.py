import re
from pydantic import BaseModel, Field, field_validator

from app.utils.email_validation import validate_and_normalize_email


class VerifyEmailRequest(BaseModel):
    email: str
    otp: str = Field(
        min_length=6,
        max_length=6,
    )

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        return validate_and_normalize_email(v)


class ResendOTPRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        return validate_and_normalize_email(v)


class ForgotPasswordRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        return validate_and_normalize_email(v)


class VerifyResetOtpRequest(BaseModel):
    email: str
    otp: str = Field(
        min_length=6,
        max_length=6,
    )

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        return validate_and_normalize_email(v)


class ResetPasswordRequest(BaseModel):
    email: str
    otp: str = Field(
        min_length=6,
        max_length=6,
    )
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        return validate_and_normalize_email(v)

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        errors = []
        if len(v) < 8:
            errors.append("at least 8 characters")
        if not re.search(r"[A-Z]", v):
            errors.append("one uppercase letter")
        if not re.search(r"[a-z]", v):
            errors.append("one lowercase letter")
        if not re.search(r"[0-9]", v):
            errors.append("one number")
        if not re.search(r"[^A-Za-z0-9]", v):
            errors.append("one special character")
        if errors:
            raise ValueError(
                f"Password must contain: {', '.join(errors)}."
            )
        return v