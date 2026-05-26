"""Dependency injection container using dependency-injector."""

from dependency_injector import containers, providers

from app.config import settings
from app.models.db import get_db
from app.repositories.memory_blacklist import MemoryTokenBlacklist
from app.repositories.sql_role_repo import SqlRoleRepository
from app.repositories.sql_user_repo import SqlUserRepository
from app.services.auth_service import AuthService
from app.services.rbac_service import RBACService
from app.services.user_service import UserService


def _create_blacklist():
    """Factory that returns a Redis or in-memory blacklist based on config."""
    if settings.redis_url:
        from app.repositories.redis_blacklist import RedisTokenBlacklist

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
