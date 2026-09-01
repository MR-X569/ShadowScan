"""
Email validation and normalization utilities for ShadowScan.
Enforces RFC 5322 compliance and production security policy rules.
"""

import re

# Regex patterns for strict components
# Local part: allows alphanumeric, dot, hyphen, underscore, plus, but:
# - Cannot start or end with a dot
# - Cannot contain consecutive dots (..)
# - Must contain at least one alphabetic character (rejects purely numeric local parts like 123@gmail.com)
LOCAL_PART_PATTERN = re.compile(
    r"^[a-zA-Z0-9_+-]+(?:\.[a-zA-Z0-9_+-]+)*$"
)

# Domain label: 1-63 alphanumeric characters, hyphens allowed in middle
DOMAIN_LABEL_PATTERN = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)

# TLD: At least 2 alphabetic characters
TLD_PATTERN = re.compile(
    r"^[a-zA-Z]{2,63}$"
)


def validate_and_normalize_email(email_str: str) -> str:
    """
    Validates and normalizes an email address.
    
    Raises:
        ValueError: If email is empty, malformed, violates policy, or invalid.
    Returns:
        Normalized email string (stripped and lowercase).
    """
    if not isinstance(email_str, str):
        raise ValueError("Email must be a string.")

    email = email_str.strip().lower()

    if not email:
        raise ValueError("Email address cannot be empty.")

    if len(email) > 254:
        raise ValueError("Email address exceeds maximum length of 254 characters.")

    # Must contain exactly one '@' symbol
    if email.count("@") != 1:
        raise ValueError("Email must contain exactly one '@' symbol.")

    local_part, domain_part = email.split("@")

    # Local-part length check
    if not local_part or len(local_part) > 64:
        raise ValueError("Email username part must be between 1 and 64 characters.")

    # Local-part syntax and no consecutive dots
    if ".." in local_part:
        raise ValueError("Email username cannot contain consecutive dots.")

    if not LOCAL_PART_PATTERN.match(local_part):
        raise ValueError("Email username contains invalid characters or formatting.")

    # Policy rule: Local part must contain at least one letter (rejects pure digits like 123@gmail.com)
    if not re.search(r"[a-zA-Z]", local_part):
        raise ValueError(
            "Email username must contain at least one letter (purely numeric addresses are not permitted)."
        )

    # Domain part validation
    if not domain_part:
        raise ValueError("Email domain cannot be empty.")

    if ".." in domain_part:
        raise ValueError("Email domain cannot contain consecutive dots.")

    labels = domain_part.split(".")
    if len(labels) < 2:
        raise ValueError("Email domain must include a valid top-level domain (e.g. .com, .org).")

    # Validate each domain label
    for label in labels:
        if not label:
            raise ValueError("Email domain contains empty labels or invalid dots.")
        if not DOMAIN_LABEL_PATTERN.match(label):
            raise ValueError(f"Email domain label '{label}' is invalid.")

    # Validate TLD (last label)
    tld = labels[-1]
    if not TLD_PATTERN.match(tld):
        raise ValueError(f"Email top-level domain '.{tld}' is invalid.")

    return f"{local_part}@{domain_part}"
