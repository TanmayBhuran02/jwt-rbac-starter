"""Unit tests for the service layer (auth, user, RBAC).

Services are constructed directly on the per-test session so their behaviour —
including error paths — can be asserted without going through HTTP.
"""

import pytest
from fastapi import HTTPException

from jwt_rbac.core.exceptions import CredentialsException
from jwt_rbac.core.security import decode_refresh_token, decode_token, verify_password
from jwt_rbac.repositories.memory_blacklist import MemoryTokenBlacklist
from jwt_rbac.repositories.sql_role_repo import SqlRoleRepository
from jwt_rbac.repositories.sql_user_repo import SqlUserRepository
from jwt_rbac.schemas.auth import LoginRequest, RefreshRequest
from jwt_rbac.schemas.user import UserCreate
from jwt_rbac.services.auth_service import AuthService
from jwt_rbac.services.rbac_service import RBACService
from jwt_rbac.services.user_service import UserService


@pytest.fixture
def blacklist():
    """A fresh in-memory blacklist for each test."""
    return MemoryTokenBlacklist()


@pytest.fixture
def user_repo(db_session):
    return SqlUserRepository(db_session)


@pytest.fixture
def role_repo(db_session):
    return SqlRoleRepository(db_session)


@pytest.fixture
def auth_service(user_repo, blacklist):
    return AuthService(user_repo=user_repo, blacklist=blacklist)


@pytest.fixture
def user_service(user_repo, role_repo):
    return UserService(user_repo=user_repo, role_repo=role_repo)


@pytest.fixture
def rbac_service(role_repo):
    return RBACService(role_repo=role_repo)


def _register(user_service, email="svc@example.com", password="password123", **kwargs):
    """Register a user through the service and return the created user."""
    return user_service.register(UserCreate(email=email, password=password, **kwargs))


# --------------------------------------------------------------------------
# AuthService.login
# --------------------------------------------------------------------------


def test_login_returns_token_pair(auth_service, user_service):
    """Valid credentials yield an access and a refresh token."""
    _register(user_service, "login@example.com")

    tokens = auth_service.login(LoginRequest(email="login@example.com", password="password123"))
    assert tokens.access_token
    assert tokens.refresh_token
    assert tokens.token_type == "bearer"


def test_login_embeds_roles_and_permissions(auth_service, user_service):
    """The access token carries the user's roles and permissions."""
    _register(user_service, "claims@example.com")

    payload = decode_token(
        auth_service.login(
            LoginRequest(email="claims@example.com", password="password123")
        ).access_token
    )
    assert payload["roles"] == ["USER"]
    assert "users:read" in payload["permissions"]


def test_login_deduplicates_permissions(auth_service, user_service, role_repo):
    """Permissions shared by several roles appear only once in the token."""
    created = _register(user_service, "dedupe@example.com")
    role_repo.assign_to_user(str(created.id), "MODERATOR")

    payload = decode_token(
        auth_service.login(
            LoginRequest(email="dedupe@example.com", password="password123")
        ).access_token
    )
    assert sorted(payload["permissions"]) == sorted(set(payload["permissions"]))
    assert payload["permissions"].count("users:read") == 1


def test_login_unknown_user_is_rejected(auth_service):
    """An unknown email raises a generic 401."""
    with pytest.raises(CredentialsException) as excinfo:
        auth_service.login(LoginRequest(email="ghost@example.com", password="password123"))
    assert excinfo.value.status_code == 401
    # The message must not reveal whether the account exists.
    assert "Invalid email or password" in excinfo.value.detail


def test_login_wrong_password_is_rejected(auth_service, user_service):
    """A wrong password raises the same generic 401."""
    _register(user_service, "wrongpw@example.com")
    with pytest.raises(CredentialsException):
        auth_service.login(LoginRequest(email="wrongpw@example.com", password="nope"))


def test_login_inactive_user_is_rejected(auth_service, user_service, user_repo):
    """A deactivated account cannot log in."""
    created = _register(user_service, "inactive@example.com")
    user_repo.set_active(str(created.id), False)

    with pytest.raises(CredentialsException):
        auth_service.login(LoginRequest(email="inactive@example.com", password="password123"))


# --------------------------------------------------------------------------
# AuthService.refresh
# --------------------------------------------------------------------------


def test_refresh_returns_a_new_pair(auth_service, user_service):
    """Exchanging a refresh token produces a fresh access/refresh pair."""
    _register(user_service, "refresh@example.com")
    first = auth_service.login(LoginRequest(email="refresh@example.com", password="password123"))

    second = auth_service.refresh(RefreshRequest(refresh_token=first.refresh_token))
    assert second.access_token != first.access_token
    assert second.refresh_token != first.refresh_token


def test_refresh_blacklists_the_old_token(auth_service, user_service, blacklist):
    """The consumed refresh token can no longer be replayed."""
    _register(user_service, "rotate@example.com")
    first = auth_service.login(LoginRequest(email="rotate@example.com", password="password123"))
    old_jti = decode_refresh_token(first.refresh_token)["jti"]

    auth_service.refresh(RefreshRequest(refresh_token=first.refresh_token))
    assert blacklist.is_blacklisted(old_jti) is True


def test_refresh_rejects_blacklisted_token(auth_service, user_service, blacklist):
    """Reusing a rotated refresh token raises a 401."""
    _register(user_service, "reuse@example.com")
    tokens = auth_service.login(LoginRequest(email="reuse@example.com", password="password123"))
    jti = decode_refresh_token(tokens.refresh_token)["jti"]
    blacklist.add(jti)

    with pytest.raises(CredentialsException) as excinfo:
        auth_service.refresh(RefreshRequest(refresh_token=tokens.refresh_token))
    assert "revoked" in excinfo.value.detail.lower()


def test_refresh_rejects_access_token(auth_service):
    """An access token is not accepted on the refresh endpoint."""
    from jwt_rbac.core.security import create_access_token

    token = create_access_token(subject="u1", roles=["USER"])
    with pytest.raises(CredentialsException):
        auth_service.refresh(RefreshRequest(refresh_token=token))


def test_refresh_rejects_deactivated_user(auth_service, user_service, user_repo):
    """A user deactivated after login cannot refresh."""
    created = _register(user_service, "deact@example.com")
    tokens = auth_service.login(LoginRequest(email="deact@example.com", password="password123"))
    user_repo.set_active(str(created.id), False)

    with pytest.raises(CredentialsException):
        auth_service.refresh(RefreshRequest(refresh_token=tokens.refresh_token))


def test_refresh_rejects_deleted_user(auth_service, user_service, db_session):
    """A token for a user that no longer exists is rejected."""
    from jwt_rbac.core.security import create_refresh_token
    from jwt_rbac.models.user import User

    _register(user_service, "gone@example.com")
    db_user = db_session.query(User).filter(User.email == "gone@example.com").first()
    db_session.delete(db_user)
    db_session.commit()

    token = create_refresh_token(subject=str(db_user.id), roles=["USER"])
    with pytest.raises(CredentialsException):
        auth_service.refresh(RefreshRequest(refresh_token=token))


def test_refresh_picks_up_role_changes(auth_service, user_service, role_repo):
    """Roles are re-read from the database, so new grants take effect.

    The association table imposes no ordering, so compare as a set.
    """
    created = _register(user_service, "promote@example.com")
    tokens = auth_service.login(LoginRequest(email="promote@example.com", password="password123"))
    role_repo.assign_to_user(str(created.id), "ADMIN")

    payload = decode_token(
        auth_service.refresh(RefreshRequest(refresh_token=tokens.refresh_token)).access_token
    )
    assert set(payload["roles"]) == {"USER", "ADMIN"}


# --------------------------------------------------------------------------
# AuthService.logout
# --------------------------------------------------------------------------


def test_logout_blacklists_access_jti(auth_service, user_service, blacklist):
    """The supplied access JTI is revoked."""
    _register(user_service, "logout@example.com")
    auth_service.logout(access_jti="jti-abc", refresh_token=None)
    assert blacklist.is_blacklisted("jti-abc") is True


def test_logout_blacklists_both_tokens(auth_service, user_service, blacklist):
    """Both the access and refresh JTIs are revoked on logout."""
    _register(user_service, "both@example.com")
    tokens = auth_service.login(LoginRequest(email="both@example.com", password="password123"))
    access_jti = decode_token(tokens.access_token)["jti"]
    refresh_jti = decode_refresh_token(tokens.refresh_token)["jti"]

    auth_service.logout(access_jti=access_jti, refresh_token=tokens.refresh_token)
    assert blacklist.is_blacklisted(access_jti) is True
    assert blacklist.is_blacklisted(refresh_jti) is True


def test_logout_tolerates_invalid_refresh_token(auth_service, blacklist):
    """An undecodable refresh token is ignored rather than raising."""
    auth_service.logout(access_jti="jti-xyz", refresh_token="not-a-token")
    assert blacklist.is_blacklisted("jti-xyz") is True


def test_logout_without_any_token_is_a_noop(auth_service, blacklist):
    """Calling logout with nothing to revoke does nothing."""
    auth_service.logout(access_jti=None, refresh_token=None)
    assert blacklist._blacklisted == set()


# --------------------------------------------------------------------------
# UserService.register
# --------------------------------------------------------------------------


def test_register_creates_active_user(user_service):
    """Registration returns an active user."""
    created = _register(user_service, "reg@example.com")
    assert created.is_active is True
    assert created.email == "reg@example.com"


def test_register_assigns_default_user_role(user_service):
    """The default USER role is attached automatically."""
    created = _register(user_service, "default_role@example.com")
    assert [r.name for r in created.roles] == ["USER"]


def test_register_honours_explicit_role_name(user_service):
    """A caller may request a different role at registration time."""
    created = _register(user_service, "mod@example.com", role_name="MODERATOR")
    assert [r.name for r in created.roles] == ["MODERATOR"]


def test_register_duplicate_email_raises_400(user_service):
    """Registering the same email twice is a 400."""
    _register(user_service, "dupe@example.com")
    with pytest.raises(HTTPException) as excinfo:
        _register(user_service, "dupe@example.com")
    assert excinfo.value.status_code == 400
    assert "already registered" in excinfo.value.detail


def test_register_never_returns_the_hash(user_service):
    """The public representation does not leak the password hash."""
    created = _register(user_service, "nohash@example.com")
    assert not hasattr(created, "hashed_password")


# --------------------------------------------------------------------------
# UserService.get_profile / change_password
# --------------------------------------------------------------------------


def test_get_profile_returns_user(user_service):
    """get_profile returns the stored user."""
    created = _register(user_service, "profile@example.com")
    assert user_service.get_profile(str(created.id)).email == "profile@example.com"


def test_get_profile_unknown_user_raises_404(user_service):
    """An unknown id produces a 404."""
    with pytest.raises(HTTPException) as excinfo:
        user_service.get_profile("00000000-0000-0000-0000-000000000000")
    assert excinfo.value.status_code == 404


def test_change_password_updates_hash(user_service, user_repo):
    """A correct current password re-hashes the stored credential."""
    created = _register(user_service, "changepw@example.com")

    user_service.change_password(
        user_id=str(created.id),
        current_password="password123",
        new_password="brandnewpass456",
    )
    assert verify_password(
        "brandnewpass456", user_repo.find_by_email("changepw@example.com").hashed_password
    )


def test_change_password_wrong_current_raises_400(user_service, user_repo):
    """A wrong current password is rejected and nothing is changed."""
    created = _register(user_service, "wrongcur@example.com")
    original_hash = user_repo.find_by_email("wrongcur@example.com").hashed_password

    with pytest.raises(HTTPException) as excinfo:
        user_service.change_password(
            user_id=str(created.id),
            current_password="not-my-password",
            new_password="brandnewpass456",
        )
    assert excinfo.value.status_code == 400
    assert user_repo.find_by_email("wrongcur@example.com").hashed_password == original_hash


def test_change_password_unknown_user_raises_404(user_service):
    """Changing the password of a missing user produces a 404."""
    with pytest.raises(HTTPException) as excinfo:
        user_service.change_password(
            user_id="00000000-0000-0000-0000-000000000000",
            current_password="password123",
            new_password="brandnewpass456",
        )
    assert excinfo.value.status_code == 404


def test_get_user_with_hash_returns_internal_representation(user_service):
    """_get_user_with_hash exposes the bcrypt hash for verification."""
    created = _register(user_service, "withhash@example.com")
    record = user_service._get_user_with_hash(str(created.id))
    assert verify_password("password123", record.hashed_password)


def test_get_user_with_hash_unknown_user_returns_none(user_service):
    """A missing user yields None rather than raising."""
    assert user_service._get_user_with_hash("00000000-0000-0000-0000-000000000000") is None


# --------------------------------------------------------------------------
# RBACService
# --------------------------------------------------------------------------


def test_assign_role_adds_role_to_user(rbac_service, user_service):
    """assign_role attaches an existing role."""
    created = _register(user_service, "assign@example.com")
    rbac_service.assign_role(str(created.id), "ADMIN")

    roles = user_service.role_repo.get_user_roles(str(created.id))
    assert "ADMIN" in [r.name for r in roles]


def test_assign_role_unknown_raises_404(rbac_service):
    """Assigning a non-existent role produces a 404."""
    with pytest.raises(HTTPException) as excinfo:
        rbac_service.assign_role("any-user", "NOT_A_ROLE")
    assert excinfo.value.status_code == 404
    assert "NOT_A_ROLE" in excinfo.value.detail


def test_revoke_role_removes_role(rbac_service, user_service):
    """revoke_role detaches a previously assigned role."""
    created = _register(user_service, "revoke@example.com")
    rbac_service.assign_role(str(created.id), "MODERATOR")
    rbac_service.revoke_role(str(created.id), "MODERATOR")

    roles = [r.name for r in user_service.role_repo.get_user_roles(str(created.id))]
    assert "MODERATOR" not in roles


def test_revoke_role_unknown_raises_404(rbac_service):
    """Revoking a non-existent role produces a 404."""
    with pytest.raises(HTTPException) as excinfo:
        rbac_service.revoke_role("any-user", "NOT_A_ROLE")
    assert excinfo.value.status_code == 404


def test_list_roles_and_permissions(rbac_service):
    """list_roles / list_permissions return the seeded reference data."""
    assert "ADMIN" in {r.name for r in rbac_service.list_roles()}
    assert "users:read" in {p.name for p in rbac_service.list_permissions()}


def test_set_role_permissions_replaces_set(rbac_service, db_session):
    """set_role_permissions swaps the full permission set on a role."""
    from jwt_rbac.models.role import Role

    role = db_session.query(Role).filter(Role.name == "USER").first()
    updated = rbac_service.set_role_permissions(role.id, ["admin:access"])
    assert [p.name for p in updated.permissions] == ["admin:access"]


def test_set_role_permissions_unknown_permission_raises_400(rbac_service, db_session):
    """An unknown permission name surfaces as a 400 from the repository."""
    from jwt_rbac.models.role import Role

    role = db_session.query(Role).filter(Role.name == "USER").first()
    with pytest.raises(HTTPException) as excinfo:
        rbac_service.set_role_permissions(role.id, ["nope:not:exist"])
    assert excinfo.value.status_code == 400
