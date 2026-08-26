"""
OTP utility functions.

Responsible for:
- Generating secure OTPs
- Calculating expiry time
"""

import secrets
from datetime import datetime, timedelta, UTC


OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 5


def generate_otp() -> str:
    """
    Generate a cryptographically secure 6-digit OTP.
    """
    return f"{secrets.randbelow(900000) + 100000}"


def get_expiry_time() -> datetime:
    """
    Return the OTP expiry timestamp (timezone-aware UTC).
    """
    return datetime.now(UTC) + timedelta(
        minutes=OTP_EXPIRY_MINUTES
    )


def is_otp_expired(expires_at: datetime) -> bool:
    """
    Check whether an OTP has expired.
    """
    return datetime.now(UTC) > expires_at