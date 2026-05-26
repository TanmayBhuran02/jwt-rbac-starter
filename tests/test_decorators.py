"""Test file covering decorator usage and edge cases for auth, rbac, user, and security components."""

import datetime

import pytest
from fastapi import APIRouter, Depends, HTTPException, Request
from jose import jwt

from app.config import settings
from app.core.dependencies import require_permission, require_role
from app.core.exceptions import CredentialsException
from app.core.security import create_access_token, decode_refresh_token, decode_token
from app.main import app
from tests.conftest import get_auth_header, login_user, make_admin, make_moderator, register_user

# Define transient test router for testing standalone decorators and dependencies
router = APIRouter(prefix="/test-decor")


@router.get("/role-admin")
@require_role("ADMIN")
def role_admin_route(request: Request):
    """Admin-only route via decorator."""
    return {"message": "success"}


@router.get("/permission-write")
@require_permission("users:write")
def permission_write_route(request: Request):
    """Write permission route via decorator."""
    return {"message": "success"}


@router.get("/dep-permission")
def dep_permission_route(user=Depends(require_permission("reports:read"))):
    """Reports permission route via Depends."""
    return {"message": "success"}


app.include_router(router)


def test_require_role_decorator_missing_token(client):
    """Accessing decorator-guarded route without token returns 401."""
    res = client.get("/test-decor/role-admin")
    assert res.status_code == 401
    assert res.json()["error"] == "UNAUTHORIZED"


def test_require_role_decorator_non_admin(client):
    """Accessing decorator-guarded admin route as normal user returns 403."""
    register_user(client, "decor_user@example.com")
    tokens = login_user(client, "decor_user@example.com")

    res = client.get("/test-decor/role-admin", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 403
    assert res.json()["error"] == "FORBIDDEN"


def test_require_role_decorator_success(client, db_session):
    """Accessing decorator-guarded admin route as admin succeeds."""
    reg = register_user(client, "decor_admin@example.com")
    make_admin(db_session, reg["id"])
    tokens = login_user(client, "decor_admin@example.com")

    res = client.get("/test-decor/role-admin", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 200
    assert res.json() == {"message": "success"}


def test_require_permission_decorator_success(client, db_session):
    """Accessing decorator-guarded permission route with right permission succeeds."""
    reg = register_user(client, "decor_mod@example.com")
    make_moderator(db_session, reg["id"])
    tokens = login_user(client, "decor_mod@example.com")

    res = client.get(
        "/test-decor/permission-write", headers=get_auth_header(tokens["access_token"])
    )
    assert res.status_code == 200
    assert res.json() == {"message": "success"}


def test_jwt_issuer_validation(db_session):
    """Verify JWT issuer validation when JWT_ISSUER is set."""
    from app.config import settings

    # Temporarily set issuer
    settings.jwt_issuer = "test-issuer"
    try:
        token = create_access_token(subject="user123", roles=["USER"])
        payload = decode_token(token)
        assert payload["iss"] == "test-issuer"

        # Test decoding with missing/wrong issuer throws CredentialsException
        settings.jwt_issuer = "different-issuer"
        with pytest.raises(CredentialsException):
            decode_token(token)
    finally:
        settings.jwt_issuer = None


def test_invalid_tokens():
    """Verify that invalid tokens raise CredentialsException."""
    with pytest.raises(CredentialsException):
        decode_token("invalid-token-string")
    with pytest.raises(CredentialsException):
        decode_refresh_token("invalid-refresh-token")


def test_blacklist_reuse(client):
    """Verify reuse of blacklisted refresh token returns 401."""
    register_user(client, "reuse_refresh@example.com")
    tokens = login_user(client, "reuse_refresh@example.com")
    refresh_token = tokens["refresh_token"]

    # First refresh succeeds
    res = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert res.status_code == 200

    # Second refresh using the same blacklisted refresh token fails
    res = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert res.status_code == 401


def test_duplicate_registration_raises_conflict(client):
    """Verify registering an already existing email raises conflict."""
    register_user(client, "duplicate@example.com")
    res = client.post(
        "/users/register", json={"email": "duplicate@example.com", "password": "password123"}
    )
    assert res.status_code == 400
    assert "already registered" in res.json()["message"]


def test_rbac_service_edge_cases(db_session):
    """Test RBACService error paths."""
    from app.repositories.sql_role_repo import SqlRoleRepository
    from app.services.rbac_service import RBACService

    repo = SqlRoleRepository(db_session)
    service = RBACService(repo)

    # Assigning non-existent role raises HTTPException 404
    with pytest.raises(HTTPException) as excinfo:
        service.assign_role(str(uuid4_fake()), "NON_EXISTENT_ROLE")
    assert excinfo.value.status_code == 404

    # Revoking non-existent role raises HTTPException 404
    with pytest.raises(HTTPException) as excinfo:
        service.revoke_role(str(uuid4_fake()), "NON_EXISTENT_ROLE")
    assert excinfo.value.status_code == 404


def test_deactivated_user_protected_route(client, db_session):
    """Accessing protected routes with deactivated user token returns 401."""
    reg = register_user(client, "deact_route@example.com")
    tokens = login_user(client, "deact_route@example.com")

    # Deactivate user
    from app.repositories.sql_user_repo import SqlUserRepository

    repo = SqlUserRepository(db_session)
    repo.set_active(reg["id"], False)

    res = client.get("/users/me", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 401


def test_nonexistent_user_token(client):
    """Accessing protected routes with valid JWT but non-existent user returns 401."""
    import uuid

    token = create_access_token(subject=str(uuid.uuid4()), roles=["USER"])
    res = client.get("/users/me", headers=get_auth_header(token))
    assert res.status_code == 401


def test_token_missing_sub(client):
    """Accessing protected routes with token missing 'sub' claim returns 401."""
    to_encode = {
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30),
        "roles": ["USER"],
        "type": "access",
    }
    token = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    res = client.get("/users/me", headers=get_auth_header(token))
    assert res.status_code == 401


def test_decorator_revoked_token(client, db_session):
    """Decorator route fails for a revoked token."""
    reg = register_user(client, "revoked_decor@example.com")
    make_admin(db_session, reg["id"])
    tokens = login_user(client, "revoked_decor@example.com")

    # Logout to blacklist token
    client.post("/auth/logout", headers=get_auth_header(tokens["access_token"]))

    # Request decorator route
    res = client.get("/test-decor/role-admin", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 401


def test_decorator_missing_sub(client):
    """Decorator route fails for a token missing 'sub'."""
    to_encode = {
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30),
        "roles": ["ADMIN"],
        "type": "access",
    }
    token = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    res = client.get("/test-decor/role-admin", headers=get_auth_header(token))
    assert res.status_code == 401


def test_decorator_deactivated_user(client, db_session):
    """Decorator route fails for deactivated user."""
    reg = register_user(client, "decor_deact@example.com")
    make_admin(db_session, reg["id"])
    tokens = login_user(client, "decor_deact@example.com")

    # Deactivate
    from app.repositories.sql_user_repo import SqlUserRepository

    repo = SqlUserRepository(db_session)
    repo.set_active(reg["id"], False)

    res = client.get("/test-decor/role-admin", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 401


def test_decorator_wrong_token_type(client, db_session):
    """Decorator route fails when using a refresh token instead of access token."""
    reg = register_user(client, "decor_wrong_type@example.com")
    make_admin(db_session, reg["id"])
    tokens = login_user(client, "decor_wrong_type@example.com")

    res = client.get("/test-decor/role-admin", headers=get_auth_header(tokens["refresh_token"]))
    assert res.status_code == 401


def test_decorator_invalid_auth_header(client):
    """Decorator route fails with non-bearer auth header."""
    res = client.get("/test-decor/role-admin", headers={"Authorization": "Basic blah"})
    assert res.status_code == 401


def test_require_permission_dependency_failed(client):
    """require_permission Depends fails when missing permission."""
    register_user(client, "dep_perm_fail@example.com")
    tokens = login_user(client, "dep_perm_fail@example.com")
    res = client.get("/test-decor/dep-permission", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 403


def test_require_permission_dependency_success(client, db_session):
    """require_permission Depends succeeds with correct permission."""
    reg = register_user(client, "dep_perm_ok@example.com")
    make_moderator(db_session, reg["id"])
    tokens = login_user(client, "dep_perm_ok@example.com")
    res = client.get("/test-decor/dep-permission", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 200


def uuid4_fake():
    import uuid

    return uuid.uuid4()
