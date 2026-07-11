"""Dependency injection container using dependency-injector."""

from dependency_injector import containers, providers

from jwt_rbac.config import get_settings
from jwt_rbac.models.db import get_db
from jwt_rbac.repositories.memory_blacklist import MemoryTokenBlacklist
from jwt_rbac.repositories.sql_role_repo import SqlRoleRepository
from jwt_rbac.repositories.sql_user_repo import SqlUserRepository
from jwt_rbac.services.auth_service import AuthService
from jwt_rbac.services.rbac_service import RBACService
from jwt_rbac.services.user_service import UserService


def _create_blacklist():
    """Factory that returns a Redis or in-memory blacklist based on config."""
    settings = get_settings()
    if settings.redis_url:
        from jwt_rbac.repositories.redis_blacklist import RedisTokenBlacklist

        return RedisTokenBlacklist(redis_url=settings.redis_url)
    return MemoryTokenBlacklist()


class Container(containers.DeclarativeContainer):
    """Application-wide DI container."""

    config = providers.Configuration()

    # DB session — yields a new session per request
    db_session = providers.Resource(get_db)

    # Token blacklist — singleton for the lifetime of the app
    token_blacklist = providers.Singleton(_create_blacklist)

    user_repository = providers.Factory(
        SqlUserRepository,
        db=db_session,
    )

    role_repository = providers.Factory(
        SqlRoleRepository,
        db=db_session,
    )

    auth_service = providers.Factory(
        AuthService,
        user_repo=user_repository,
        blacklist=token_blacklist,
    )

    user_service = providers.Factory(
        UserService,
        user_repo=user_repository,
        role_repo=role_repository,
    )

    rbac_service = providers.Factory(
        RBACService,
        role_repo=role_repository,
    )
