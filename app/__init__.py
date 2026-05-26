"""
JWT + RBAC Starter Kit
======================

A production-ready authentication and role-based access control starter kit
built with FastAPI, SQLAlchemy, and dependency-injector.

Quick start for external developers::

    from app.setup import setup

    app = setup(
        secret_key="my-32-char-minimum-secret-key-here",
        token_expire_minutes=60,
    )

Public API re-exports:
    - ``IUserRepository`` — Abstract user repository interface
    - ``IRoleRepository`` — Abstract role repository interface
    - ``ITokenBlacklist`` — Abstract token blacklist interface
    - ``require_role`` — Role-checking dependency / decorator
    - ``require_permission`` — Permission-checking dependency / decorator
"""

from app.core.dependencies import require_permission, require_role
from app.interfaces.role_repository import IRoleRepository
from app.interfaces.token_blacklist import ITokenBlacklist
from app.interfaces.user_repository import IUserRepository
from app.setup import setup

__all__ = [
    "IUserRepository",
    "IRoleRepository",
    "ITokenBlacklist",
    "require_role",
    "require_permission",
    "setup",
]
