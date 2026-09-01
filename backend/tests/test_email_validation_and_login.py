import pytest
from app.utils.email_validation import validate_and_normalize_email
from app.schemas.user import UserCreate


def test_email_validation_invalid_cases():
    invalid_emails = [
        "123@gmail.com",       # Pure numeric local-part
        "abc@",                # Missing domain
        "@gamil.com",          # Missing local-part
        "abc@gmail",           # Missing TLD
        "abc..def@gmail.com",  # Consecutive dots in local-part
        "abc@.com",            # Empty domain label
        "abc@gmail.",          # Trailing dot
        "abc@@gmail.com",      # Multiple @ symbols
        "99999@domain.com",    # Pure numeric local-part
        ".user@domain.com",    # Leading dot in local-part
        "user.@domain.com",    # Trailing dot in local-part
        "user@domain..com",    # Consecutive dots in domain
        "",                    # Empty
        "   ",                 # Whitespace
    ]

    for email in invalid_emails:
        with pytest.raises(ValueError):
            validate_and_normalize_email(email)


def test_email_validation_valid_cases():
    valid_cases = {
        "test@gmail.com": "test@gmail.com",
        "john.doe@gmail.com": "john.doe@gmail.com",
        "user123@gmail.com": "user123@gmail.com",
        "hello.world+test@gmail.com": "hello.world+test@gmail.com",
        "TEST@GMAIL.COM": "test@gmail.com",
        "  User.Name@Company.Org  ": "user.name@company.org",
        "admin@shadowscan.site": "admin@shadowscan.site",
    }

    for raw, expected in valid_cases.items():
        normalized = validate_and_normalize_email(raw)
        assert normalized == expected


def test_user_create_schema_rejects_numeric_email():
    with pytest.raises(ValueError):
        UserCreate(
            username="testuser",
            email="123@gmail.com",
            password="Password123!",
        )


def test_user_create_schema_accepts_valid_email():
    user = UserCreate(
        username="testuser",
        email="  Valid.User123@Gmail.Com  ",
        password="Password123!",
    )
    assert user.email == "valid.user123@gmail.com"
