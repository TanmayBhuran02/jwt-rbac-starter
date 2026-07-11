"""JWT token creation, verification, and password hashing utilities.

Uses python-jose for JWT encoding/decoding and bcrypt for password hashing.
Hash comparison via bcrypt.checkpw is constant-time by design.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt

from jwt_rbac.config import get_settings
from jwt_rbac.core.exceptions import CredentialsException

logger = logging.getLogger(__name__)


def get_password_hash(password: str) -> str:
    """Hash a plaintext password using bcrypt.

    Args:
        password: The plaintext password to hash.

    Returns:
        The bcrypt-hashed password string.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash (constant-time).

    Args:
        plain_password: The plaintext password to check.
        hashed_password: The stored bcrypt hash.

    Returns:
        True if the password matches, False otherwise.
    """
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_access_token(
    subject: str,
    roles: list[str],
    permissions: list[str] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT access token.

    Args:
        subject: The user ID to embed as the ``sub`` claim.
        roles: List of role names to embed in the token.
        permissions: Optional list of permission strings.
        expires_delta: Custom expiry duration; defaults to config value.

    Returns:
        The encoded JWT string.
    """
    settings = get_settings()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode: dict = {
        "exp": expire,
        "sub": str(subject),
        "roles": roles,
        "permissions": permissions or [],
        "jti": str(uuid.uuid4()),
        "type": "access",
    }
    if settings.jwt_issuer:
        to_encode["iss"] = settings.jwt_issuer
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token(
    subject: str,
    roles: list[str],
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT refresh token with a separate secret.

    Args:
        subject: The user ID to embed as the ``sub`` claim.
        roles: List of role names to embed in the token.
        expires_delta: Custom expiry duration; defaults to 7 days.

    Returns:
        The encoded refresh JWT string.
    """
    settings = get_settings()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(days=settings.refresh_token_expire_days)
    )
    to_encode: dict = {
        "exp": expire,
        "sub": str(subject),
        "roles": roles,
        "jti": str(uuid.uuid4()),
        "type": "refresh",
    }
    if settings.jwt_issuer:
        to_encode["iss"] = settings.jwt_issuer
    return jwt.encode(to_encode, settings.refresh_secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT access token.

    Args:
        token: The raw JWT string.

    Returns:
        The decoded payload dictionary.

    Raises:
        CredentialsException: If the token is invalid, expired, or has wrong issuer.
    """
    settings = get_settings()
    try:
        options: dict = {}
        if settings.jwt_issuer:
            options["issuer"] = settings.jwt_issuer
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm],
            options={"verify_iss": bool(settings.jwt_issuer)},
            issuer=settings.jwt_issuer if settings.jwt_issuer else None,
        )
        return payload
    except JWTError as exc:
        logger.debug("Access token decode failed: %s", exc)
        raise CredentialsException()


def decode_refresh_token(token: str) -> dict:
    """Decode and validate a JWT refresh token.

    Args:
        token: The raw refresh JWT string.

    Returns:
        The decoded payload dictionary.

    Raises:
        CredentialsException: If the token is invalid, expired, or not a refresh token.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.refresh_secret_key,
            algorithms=[settings.algorithm],
            issuer=settings.jwt_issuer if settings.jwt_issuer else None,
            options={"verify_iss": bool(settings.jwt_issuer)},
        )
        if payload.get("type") != "refresh":
            raise CredentialsException("Invalid token type")
        return payload
    except JWTError as exc:
        logger.debug("Refresh token decode failed: %s", exc)
        raise CredentialsException("Invalid or expired refresh token")
