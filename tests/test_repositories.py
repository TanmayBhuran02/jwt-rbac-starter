"""Unit tests for the SQLAlchemy repository implementations.

These exercise the repositories directly against the per-test transaction
provided by the ``db_session`` fixture, so every write is rolled back.
"""

import pytest

from jwt_rbac.core.exceptions import ServiceError
from jwt_rbac.core.security import verify_password
from jwt_rbac.models.role import Permission, Role
from jwt_rbac.models.user import User
from jwt_rbac.repositories.sql_role_repo import SqlRoleRepository
from jwt_rbac.repositories.sql_user_repo import SqlUserRepository
from jwt_rbac.schemas.user import UserCreate


@pytest.fixture
def user_repo(db_session):
    """A SqlUserRepository bound to the per-test session."""
    return SqlUserRepository(db_session)


@pytest.fixture
def role_repo(db_session):
    """A SqlRoleRepository bound to the per-test session."""
    return SqlRoleRepository(db_session)


# --------------------------------------------------------------------------
# SqlUserRepository
# --------------------------------------------------------------------------


def test_create_persists_user(user_repo, db_session):
    """create() inserts a row and returns the public representation."""
    created = user_repo.create(UserCreate(email="create@example.com", password="password123"))

    assert created.email == "create@example.com"
    assert user_repo.find_by_email("create@example.com") is not None


def test_create_hashes_the_password(user_repo, db_session):
    """The stored password is a bcrypt hash, never the plaintext."""
    created = user_repo.create(UserCreate(email="hash@example.com", password="password123"))

    db_user = db_session.query(User).filter(User.id == str(created.id)).first()
    assert db_user.hashed_password != "password123"
    assert verify_password("password123", db_user.hashed_password)


def test_create_assigns_uuid_and_active_flag(user_repo):
    """New users get a UUID primary key and are active by default."""
    created = user_repo.create(UserCreate(email="new@example.com", password="password123"))
    assert created.id is not None
    assert created.is_active is True


def test_find_by_email_returns_user_with_hash(user_repo):
    """find_by_email returns a UserInDB including the password hash."""
    user_repo.create(UserCreate(email="withhash@example.com", password="password123"))
    found = user_repo.find_by_email("withhash@example.com")

    assert found is not None
    assert found.hashed_password
    assert verify_password("password123", found.hashed_password)


def test_find_by_email_missing_returns_none(user_repo):
    """An unknown email yields None rather than raising."""
    assert user_repo.find_by_email("nobody@example.com") is None


def test_find_by_id_returns_public_shape(user_repo):
    """find_by_id returns a UserOut (no password hash exposed)."""
    created = user_repo.create(UserCreate(email="byid@example.com", password="password123"))
    found = user_repo.find_by_id(str(created.id))

    assert found is not None
    assert found.email == "byid@example.com"
    assert not hasattr(found, "hashed_password")


def test_find_by_id_missing_returns_none(user_repo):
    """An unknown id yields None."""
    assert user_repo.find_by_id("00000000-0000-0000-0000-000000000000") is None


def test_list_all_returns_created_users(user_repo):
    """list_all returns every user in the system."""
    user_repo.create(UserCreate(email="list1@example.com", password="password123"))
    user_repo.create(UserCreate(email="list2@example.com", password="password123"))

    emails = [u.email for u in user_repo.list_all()]
    assert "list1@example.com" in emails
    assert "list2@example.com" in emails


def test_list_all_includes_roles(user_repo, role_repo):
    """list_all serializes nested roles and permissions."""
    created = user_repo.create(UserCreate(email="withrole@example.com", password="password123"))
    role_repo.assign_to_user(str(created.id), "USER")

    listed = {u.email: u for u in user_repo.list_all()}["withrole@example.com"]
    assert [r.name for r in listed.roles] == ["USER"]


def test_update_password_changes_hash(user_repo):
    """update_password replaces the stored bcrypt hash."""
    from jwt_rbac.core.security import get_password_hash

    created = user_repo.create(UserCreate(email="pw@example.com", password="password123"))
    new_hash = get_password_hash("brandnewpass999")

    user_repo.update_password(str(created.id), new_hash)
    found = user_repo.find_by_email("pw@example.com")
    assert found.hashed_password == new_hash
    assert verify_password("brandnewpass999", found.hashed_password)


def test_update_password_unknown_user_is_a_noop(user_repo):
    """Updating a non-existent user does not raise."""
    user_repo.update_password("00000000-0000-0000-0000-000000000000", "irrelevant")


def test_set_active_toggles_flag(user_repo):
    """set_active flips is_active and persists it."""
    created = user_repo.create(UserCreate(email="toggle@example.com", password="password123"))

    user_repo.set_active(str(created.id), False)
    assert user_repo.find_by_id(str(created.id)).is_active is False

    user_repo.set_active(str(created.id), True)
    assert user_repo.find_by_id(str(created.id)).is_active is True


def test_set_active_unknown_user_is_a_noop(user_repo):
    """Setting active on a non-existent user does not raise."""
    user_repo.set_active("00000000-0000-0000-0000-000000000000", False)


# --------------------------------------------------------------------------
# SqlRoleRepository
# --------------------------------------------------------------------------


def test_find_by_name_returns_seeded_role(role_repo):
    """Seeded roles are retrievable by name."""
    found = role_repo.find_by_name("ADMIN")
    assert found is not None
    assert found.name == "ADMIN"


def test_find_by_name_unknown_returns_none(role_repo):
    """An unknown role name yields None."""
    assert role_repo.find_by_name("NOT_A_ROLE") is None


def test_assign_to_user_adds_role(user_repo, role_repo):
    """assign_to_user attaches a role to a user."""
    created = user_repo.create(UserCreate(email="assign@example.com", password="password123"))

    role_repo.assign_to_user(str(created.id), "MODERATOR")
    assert [r.name for r in user_repo.find_by_id(str(created.id)).roles] == ["MODERATOR"]


def test_assign_to_user_is_idempotent(user_repo, role_repo):
    """Assigning the same role twice does not duplicate the association."""
    created = user_repo.create(UserCreate(email="dup@example.com", password="password123"))

    role_repo.assign_to_user(str(created.id), "USER")
    role_repo.assign_to_user(str(created.id), "USER")

    assert [r.name for r in user_repo.find_by_id(str(created.id)).roles] == ["USER"]


def test_assign_to_user_unknown_role_is_a_noop(user_repo, role_repo):
    """An unknown role name is silently ignored by the repository."""
    created = user_repo.create(UserCreate(email="norole@example.com", password="password123"))

    role_repo.assign_to_user(str(created.id), "NOT_A_ROLE")
    assert user_repo.find_by_id(str(created.id)).roles == []


def test_assign_to_user_unknown_user_is_a_noop(role_repo):
    """Assigning to a non-existent user does not raise."""
    role_repo.assign_to_user("00000000-0000-0000-0000-000000000000", "USER")


def test_revoke_from_user_removes_role(user_repo, role_repo):
    """revoke_from_user detaches a previously assigned role."""
    created = user_repo.create(UserCreate(email="revoke@example.com", password="password123"))
    role_repo.assign_to_user(str(created.id), "USER")

    role_repo.revoke_from_user(str(created.id), "USER")
    assert user_repo.find_by_id(str(created.id)).roles == []


def test_revoke_from_user_unknown_role_is_a_noop(user_repo, role_repo):
    """Revoking a role the user does not have is safely ignored."""
    created = user_repo.create(UserCreate(email="norevoke@example.com", password="password123"))
    role_repo.assign_to_user(str(created.id), "USER")

    role_repo.revoke_from_user(str(created.id), "ADMIN")
    assert [r.name for r in user_repo.find_by_id(str(created.id)).roles] == ["USER"]


def test_get_user_roles_returns_role_list(user_repo, role_repo):
    """get_user_roles returns RoleOut entries for the user."""
    created = user_repo.create(UserCreate(email="roles@example.com", password="password123"))
    role_repo.assign_to_user(str(created.id), "ADMIN")

    roles = role_repo.get_user_roles(str(created.id))
    assert [r.name for r in roles] == ["ADMIN"]
    assert roles[0].permissions


def test_get_user_roles_unknown_user_returns_empty_list(role_repo):
    """An unknown user id yields an empty list."""
    assert role_repo.get_user_roles("00000000-0000-0000-0000-000000000000") == []


def test_list_all_returns_seeded_roles(role_repo):
    """list_all returns the three seeded roles."""
    names = {r.name for r in role_repo.list_all()}
    assert {"ADMIN", "USER", "MODERATOR"} <= names


def test_list_permissions_returns_seeded_permissions(role_repo):
    """list_permissions returns the four seeded permissions."""
    names = {p.name for p in role_repo.list_permissions()}
    assert {"users:read", "users:write", "admin:access", "reports:read"} <= names


def test_set_permissions_replaces_role_permissions(db_session, role_repo):
    """set_permissions swaps the full permission set on a role."""
    role = db_session.query(Role).filter(Role.name == "USER").first()

    updated = role_repo.set_permissions(role.id, ["reports:read", "admin:access"])
    assert {p.name for p in updated.permissions} == {"reports:read", "admin:access"}


def test_set_permissions_with_unknown_name_raises_400(db_session, role_repo):
    """An unknown permission name produces a 400 ServiceError."""
    role = db_session.query(Role).filter(Role.name == "USER").first()

    with pytest.raises(ServiceError) as excinfo:
        role_repo.set_permissions(role.id, ["users:read", "does:not:exist"])
    assert excinfo.value.status_code == 400
    assert "does:not:exist" in excinfo.value.detail


def test_set_permissions_on_missing_role_raises_404(role_repo):
    """An unknown role id produces a 404 ServiceError."""
    with pytest.raises(ServiceError) as excinfo:
        role_repo.set_permissions(999_999, ["users:read"])
    assert excinfo.value.status_code == 404


# --------------------------------------------------------------------------
# Database failure handling
# --------------------------------------------------------------------------


class _BrokenSession:
    """A session stand-in whose queries always fail."""

    def query(self, *args, **kwargs):
        raise RuntimeError("database is on fire")

    def add(self, *args, **kwargs):
        raise RuntimeError("database is on fire")

    def commit(self):
        raise RuntimeError("database is on fire")

    def rollback(self):
        pass

    def refresh(self, *args, **kwargs):
        raise RuntimeError("database is on fire")


def test_user_repository_wraps_query_errors_in_service_error():
    """A failing query surfaces as a ServiceError, not a raw exception."""
    repo = SqlUserRepository(_BrokenSession())
    with pytest.raises(ServiceError) as excinfo:
        repo.find_by_email("anyone@example.com")
    assert excinfo.value.status_code == 500


def test_user_repository_wraps_create_errors_in_service_error():
    """A failing insert surfaces as a ServiceError and rolls back."""
    repo = SqlUserRepository(_BrokenSession())
    with pytest.raises(ServiceError):
        repo.create(UserCreate(email="boom@example.com", password="password123"))


def test_user_repository_wraps_list_all_errors_in_service_error():
    """A failing list_all surfaces as a ServiceError."""
    repo = SqlUserRepository(_BrokenSession())
    with pytest.raises(ServiceError):
        repo.list_all()


def test_user_repository_wraps_find_by_id_errors_in_service_error():
    """A failing find_by_id surfaces as a ServiceError."""
    repo = SqlUserRepository(_BrokenSession())
    with pytest.raises(ServiceError):
        repo.find_by_id("any-id")


def test_role_repository_wraps_errors_in_service_error():
    """Role repository failures are also wrapped in ServiceError."""
    repo = SqlRoleRepository(_BrokenSession())
    with pytest.raises(ServiceError):
        repo.find_by_name("ADMIN")


def test_role_repository_list_permissions_wraps_errors():
    """list_permissions failures are wrapped in ServiceError."""
    repo = SqlRoleRepository(_BrokenSession())
    with pytest.raises(ServiceError):
        repo.list_permissions()


def test_repository_db_attribute_is_the_session(db_session):
    """UserService._get_user_with_hash relies on the repo exposing .db."""
    assert SqlUserRepository(db_session).db is db_session
    assert SqlRoleRepository(db_session).db is db_session


def test_permissions_and_roles_are_seeded_once(db_session):
    """The session fixture seeds the documented reference data."""
    assert db_session.query(Permission).count() == 4
    assert db_session.query(Role).count() == 3
