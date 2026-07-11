"""
JWT + RBAC Starter Kit
======================

A production-ready, pip-installable authentication and role-based access
control package built with FastAPI, SQLAlchemy, and dependency-injector.

Quick start::

    from jwt_rbac import setup

    app = setup(
        secret_key="my-32-char-minimum-secret-key-here!!",
        refresh_secret_key="another-32-char-minimum-secret-key!!",
        database_url="sqlite:///./app.db",
    )

Public API re-exports:
    - ``setup`` — Configure and create a FastAPI application
    - ``IUserRepository`` — Abstract user repository interface
    - ``IRoleRepository`` — Abstract role repository interface
    - ``ITokenBlacklist`` — Abstract token blacklist interface
    - ``require_role`` — Role-checking dependency / decorator
    - ``require_permission`` — Permission-checking dependency / decorator
    - ``get_current_user`` — FastAPI dependency for extracting the current user
    - Schemas, exceptions, and security utilities
"""

from jwt_rbac.core.dependencies import get_current_user, require_permission, require_role
from jwt_rbac.core.exceptions import CredentialsException, ForbiddenException, ServiceError
from jwt_rbac.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
)
from jwt_rbac.interfaces.role_repository import IRoleRepository
from jwt_rbac.interfaces.token_blacklist import ITokenBlacklist
from jwt_rbac.interfaces.user_repository import IUserRepository
from jwt_rbac.schemas.auth import LoginRequest, TokenResponse
from jwt_rbac.schemas.role import PermissionOut, RoleOut
from jwt_rbac.schemas.user import UserCreate, UserInDB, UserOut
from jwt_rbac.setup import setup

__all__ = [
    # Core setup
    "setup",
    # Interfaces (for custom implementations)
    "IUserRepository",
    "IRoleRepository",
    "ITokenBlacklist",
    # Auth dependencies (for protecting routes)
    "require_role",
    "require_permission",
    "get_current_user",
    # Exceptions (for custom error handling)
    "CredentialsException",
    "ForbiddenException",
    "ServiceError",
    # Schemas (for type hints in custom code)
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
]
