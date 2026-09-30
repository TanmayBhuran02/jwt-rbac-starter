"""Tests for the idempotent seed script and the public package surface."""

import pytest
from sqlalchemy import inspect

from jwt_rbac.models.role import Permission, Role
from jwt_rbac.models.user import User

# --------------------------------------------------------------------------
# Seed script
# --------------------------------------------------------------------------


def test_seed_creates_reference_data(db_session):
    """Running the seed populates permissions, roles and the admin user."""
    from jwt_rbac.seed import seed

    seed()

    assert {p.name for p in db_session.query(Permission).all()} >= {
        "users:read",
        "users:write",
        "admin:access",
        "reports:read",
    }
    assert {r.name for r in db_session.query(Role).all()} >= {
        "ADMIN",
        "USER",
        "MODERATOR",
    }


def test_seed_is_idempotent(db_session):
    """Running the seed twice does not duplicate any rows."""
    from jwt_rbac.seed import seed

    seed()
    counts = (
        db_session.query(Permission).count(),
        db_session.query(Role).count(),
        db_session.query(User).filter(User.email == "admin@example.com").count(),
    )

    seed()
    assert (
        db_session.query(Permission).count(),
        db_session.query(Role).count(),
        db_session.query(User).filter(User.email == "admin@example.com").count(),
    ) == counts


def test_seed_assigns_admin_role_to_admin_user(db_session):
    """The seeded admin user is a member of the ADMIN role."""
    from jwt_rbac.config import get_settings
    from jwt_rbac.seed import seed

    seed()
    admin = db_session.query(User).filter(User.email == get_settings().admin_email).first()
    assert admin is not None
    assert "ADMIN" in [r.name for r in admin.roles]


def test_seed_hashes_the_admin_password(db_session):
    """The seeded admin password is stored as a bcrypt hash."""
    from jwt_rbac.config import get_settings
    from jwt_rbac.core.security import verify_password
    from jwt_rbac.seed import seed

    seed()
    admin = db_session.query(User).filter(User.email == get_settings().admin_email).first()
    assert admin.hashed_password != get_settings().admin_password
    assert verify_password(get_settings().admin_password, admin.hashed_password)


def test_seed_defines_expected_permission_sets():
    """The seed module declares the documented role/permission mapping."""
    from jwt_rbac import seed as seed_module

    assert set(seed_module.PERMISSIONS) == {
        "users:read",
        "users:write",
        "admin:access",
        "reports:read",
    }
    assert set(seed_module.ROLES) == {"ADMIN", "USER", "MODERATOR"}
    assert seed_module.ROLES["USER"] == ["users:read"]


def test_seed_creates_all_tables():
    """The schema is fully materialized after seeding."""
    from jwt_rbac.models.db import get_engine
    from jwt_rbac.seed import seed

    seed()

    # `engine` is a lazy proxy that `inspect()` cannot introspect directly,
    # so resolve the real engine first.
    tables = set(inspect(get_engine()).get_table_names())
    assert {"users", "roles", "permissions", "user_role", "role_permission"} <= tables


# --------------------------------------------------------------------------
# Public package surface
# --------------------------------------------------------------------------


EXPECTED_EXPORTS = {
    # Core setup
    "setup",
    # Interfaces
    "IUserRepository",
    "IRoleRepository",
    "ITokenBlacklist",
    # Auth dependencies
    "require_role",
    "require_permission",
    "get_current_user",
    # Exceptions
    "CredentialsException",
    "ForbiddenException",
    "ServiceError",
    # Schemas
    "UserCreate",
    "UserOut",
    "UserInDB",
    "RoleOut",
    "PermissionOut",
    "LoginRequest",
    "TokenResponse",
    # Security utilities
    "get_password_hash",
    "verify_password",
    "create_access_token",
    "create_refresh_token",
}


def test_all_declared_exports_exist():
    """Every name in __all__ is actually importable from the package."""
    import jwt_rbac

    for name in jwt_rbac.__all__:
        assert hasattr(jwt_rbac, name), name


def test_expected_public_api_is_exported():
    """The documented public API is present in __all__."""
    import jwt_rbac

    assert EXPECTED_EXPORTS <= set(jwt_rbac.__all__)


def test_package_exposes_setup_entrypoint():
    """`from jwt_rbac import setup` works as advertised in the README."""
    from jwt_rbac import setup

    assert callable(setup)


def test_package_interfaces_are_abstract():
    """The repository interfaces cannot be instantiated directly.

    Instantiating an ABC with unimplemented abstract methods is exactly the
    behaviour under test, so the type checker is silenced here on purpose.
    """
    from jwt_rbac import IRoleRepository, ITokenBlacklist, IUserRepository

    for interface in (IUserRepository, IRoleRepository, ITokenBlacklist):
        with pytest.raises(TypeError):
            interface()  # type: ignore[abstract]


def test_require_helpers_return_dependencies():
    """require_role / require_permission return usable dependency objects."""
    from jwt_rbac import require_permission, require_role

    assert require_role("ADMIN").role_names == ("ADMIN",)
    assert require_permission("users:read").permission_names == ("users:read",)


def test_require_helpers_accept_multiple_values():
    """Several names can be passed; the user needs only one of them."""
    from jwt_rbac import require_role

    assert set(require_role("ADMIN", "MODERATOR").role_names) == {"ADMIN", "MODERATOR"}


def test_main_module_exposes_app():
    """`uvicorn jwt_rbac.main:app` has a target to import."""
    from jwt_rbac.main import app as main_app

    assert main_app.title


def test_seed_module_is_executable_via_dunder_main():
    """`python -m jwt_rbac.seed` is wired up."""
    from jwt_rbac import seed as seed_module

    assert callable(seed_module.seed)
