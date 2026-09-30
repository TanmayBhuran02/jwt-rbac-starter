"""Unit tests for password hashing and JWT creation/decoding."""

from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt

from jwt_rbac.config import get_settings
from jwt_rbac.core.exceptions import CredentialsException
from jwt_rbac.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    decode_token,
    get_password_hash,
    verify_password,
)

# --------------------------------------------------------------------------
# Password hashing
# --------------------------------------------------------------------------


def test_hash_and_verify_roundtrip():
    """A freshly hashed password verifies against itself."""
    hashed = get_password_hash("password123")
    assert verify_password("password123", hashed) is True


def test_verify_rejects_wrong_password():
    """A non-matching password does not verify."""
    hashed = get_password_hash("password123")
    assert verify_password("wrongpassword", hashed) is False


def test_hash_is_salted_and_unique():
    """Two hashes of the same password differ (per-hash random salt)."""
    assert get_password_hash("same") != get_password_hash("same")


def test_hash_never_contains_plaintext():
    """The stored hash does not leak the plaintext password."""
    assert "supersecret" not in get_password_hash("supersecret")


def test_hash_and_verify_unicode_password():
    """Non-ASCII passwords round-trip through bcrypt correctly."""
    password = "pässwörd-🔐-密码"
    assert verify_password(password, get_password_hash(password)) is True


def test_verify_unicode_against_ascii_hash_fails():
    """A unicode password does not verify against an ASCII hash."""
    hashed = get_password_hash("password123")
    assert verify_password("pässwörd", hashed) is False


# --------------------------------------------------------------------------
# Access tokens
# --------------------------------------------------------------------------


def test_access_token_contains_expected_claims():
    """create_access_token embeds sub, roles, permissions, jti, type and exp."""
    token = create_access_token(
        subject="user-123", roles=["ADMIN", "USER"], permissions=["users:read"]
    )
    payload = decode_token(token)

    assert payload["sub"] == "user-123"
    assert payload["roles"] == ["ADMIN", "USER"]
    assert payload["permissions"] == ["users:read"]
    assert payload["type"] == "access"
    assert payload["jti"]
    assert isinstance(payload["exp"], int)


def test_access_token_jti_is_unique_per_token():
    """Each minted token gets a distinct jti so it can be revoked individually."""
    first = decode_token(create_access_token(subject="u1", roles=[]))
    second = decode_token(create_access_token(subject="u1", roles=[]))
    assert first["jti"] != second["jti"]


def test_access_token_permissions_default_to_empty_list():
    """Omitting permissions yields an empty list, not None."""
    payload = decode_token(create_access_token(subject="u1", roles=["USER"]))
    assert payload["permissions"] == []


def test_access_token_subject_is_stringified():
    """A UUID subject is encoded as a string claim."""
    from uuid import uuid4

    subject = str(uuid4())
    assert decode_token(create_access_token(subject=subject, roles=[]))["sub"] == subject


def test_access_token_honours_custom_expiry():
    """expires_delta overrides the configured access-token lifetime."""
    now = int(datetime.now(timezone.utc).timestamp())
    token = create_access_token(subject="u1", roles=[], expires_delta=timedelta(seconds=5))
    payload = decode_token(token)

    # Allow a couple of seconds of slack for execution time.
    assert now + 3 <= payload["exp"] <= now + 7


def test_access_token_default_expiry_uses_configured_minutes():
    """Without expires_delta the configured access-token TTL is applied."""
    settings = get_settings()
    now = int(datetime.now(timezone.utc).timestamp())
    payload = decode_token(create_access_token(subject="u1", roles=[]))

    expected = now + settings.access_token_expire_minutes * 60
    assert expected - 5 <= payload["exp"] <= expected + 5


def test_expired_access_token_is_rejected():
    """A token whose exp is in the past fails to decode."""
    token = create_access_token(subject="u1", roles=[], expires_delta=timedelta(seconds=-60))
    with pytest.raises(CredentialsException):
        decode_token(token)


def test_access_token_signed_with_wrong_secret_is_rejected():
    """A token signed with a foreign secret fails signature verification."""
    settings = get_settings()
    forged = jwt.encode(
        {"exp": 9999999999, "sub": "attacker", "roles": ["ADMIN"], "type": "access"},
        "a-completely-different-secret-key-value-32",
        algorithm=settings.algorithm,
    )
    with pytest.raises(CredentialsException):
        decode_token(forged)


def test_garbage_token_is_rejected():
    """A non-JWT string raises CredentialsException."""
    with pytest.raises(CredentialsException):
        decode_token("not-a-jwt")


def test_tampered_token_signature_is_rejected():
    """Flipping the signature invalidates the token."""
    token = create_access_token(subject="u1", roles=[])
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload}.{signature[:-4]}AAAA"
    with pytest.raises(CredentialsException):
        decode_token(tampered)


# --------------------------------------------------------------------------
# Refresh tokens
# --------------------------------------------------------------------------


def test_refresh_token_contains_expected_claims():
    """create_refresh_token embeds sub, roles, jti and type=refresh."""
    token = create_refresh_token(subject="user-9", roles=["USER"])
    payload = decode_refresh_token(token)

    assert payload["sub"] == "user-9"
    assert payload["roles"] == ["USER"]
    assert payload["type"] == "refresh"
    assert payload["jti"]


def test_refresh_token_uses_a_different_secret():
    """A refresh token cannot be decoded with the access-token secret."""
    token = create_refresh_token(subject="u1", roles=[])
    with pytest.raises(CredentialsException):
        decode_token(token)


def test_decode_refresh_token_rejects_access_token():
    """An access token must not be accepted where a refresh token is required."""
    access_token = create_access_token(subject="u1", roles=["USER"])
    with pytest.raises(CredentialsException):
        decode_refresh_token(access_token)


def test_expired_refresh_token_is_rejected():
    """An already-expired refresh token fails to decode."""
    token = create_refresh_token(subject="u1", roles=[], expires_delta=timedelta(days=-1))
    with pytest.raises(CredentialsException):
        decode_refresh_token(token)


def test_garbage_refresh_token_is_rejected():
    """A non-JWT string raises CredentialsException for refresh decoding."""
    with pytest.raises(CredentialsException):
        decode_refresh_token("garbage")


def test_refresh_token_without_type_claim_is_rejected():
    """A token with no ``type`` claim is not treated as a refresh token."""
    settings = get_settings()
    token = jwt.encode(
        {"exp": 9999999999, "sub": "u1", "roles": []},
        settings.refresh_secret_key,
        algorithm=settings.algorithm,
    )
    with pytest.raises(CredentialsException):
        decode_refresh_token(token)


def test_access_and_refresh_tokens_have_distinct_jtis():
    """Minting a pair produces two independently revocable tokens."""
    access = decode_token(create_access_token(subject="u1", roles=[]))
    refresh = decode_refresh_token(create_refresh_token(subject="u1", roles=[]))
    assert access["jti"] != refresh["jti"]
