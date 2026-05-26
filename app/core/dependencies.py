"""FastAPI dependency injection for authentication and authorization."""

import functools
import inspect
import logging

from dependency_injector.wiring import Provide, inject
from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer

from app.containers import Container
from app.core.exceptions import CredentialsException, ForbiddenException
from app.core.security import decode_token
from app.interfaces.token_blacklist import ITokenBlacklist
from app.interfaces.user_repository import IUserRepository
from app.schemas.user import UserOut

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


@inject
def get_current_user(
    token: str = Depends(oauth2_scheme),
    user_repo: IUserRepository = Depends(Provide[Container.user_repository]),
    blacklist: ITokenBlacklist = Depends(Provide[Container.token_blacklist]),
) -> UserOut:
    """Extract and validate the current user from the JWT access token.

    Checks token validity, blacklist status, and user existence.

    Args:
        token: The Bearer token extracted from the Authorization header.
        user_repo: Injected user repository.
        blacklist: Injected token blacklist.

    Returns:
        The authenticated user.

    Raises:
        CredentialsException: If the token is invalid, blacklisted, or user not found.
    """
    payload = decode_token(token)

    # Check blacklist
    jti = payload.get("jti")
    if jti and blacklist.is_blacklisted(jti):
        raise CredentialsException("Token has been revoked")

    user_id: str = payload.get("sub")
    if user_id is None:
        raise CredentialsException()

    user = user_repo.find_by_id(user_id)
    if user is None:
        raise CredentialsException()
    if not user.is_active:
        raise CredentialsException("User account is deactivated")
    return user


class RoleRequired:
    """FastAPI dependency and standalone decorator for role-based access control."""

    def __init__(self, *role_names: str):
        self.role_names = role_names

    def __call__(self, func_or_user=None, current_user: UserOut = Depends(get_current_user)):
        if func_or_user is not None and callable(func_or_user):
            func = func_or_user

            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                request = kwargs.get("request")
                if not request:
                    for arg in args:
                        if isinstance(arg, Request):
                            request = arg
                            break
                if not request:
                    raise CredentialsException("Request context is missing")
                auth_header = request.headers.get("Authorization", "")
                if not auth_header.startswith("Bearer "):
                    raise CredentialsException("Missing authentication token")
                token = auth_header.split(" ")[1]
                from app.main import app as global_app

                try:
                    payload = decode_token(token)
                    jti = payload.get("jti")
                    blacklist = global_app.container.token_blacklist()
                    if jti and blacklist.is_blacklisted(jti):
                        raise CredentialsException("Token has been revoked")
                    user_id = payload.get("sub")
                    if not user_id:
                        raise CredentialsException()
                    user_repo = global_app.container.user_repository()
                    user = user_repo.find_by_id(user_id)
                    if not user:
                        raise CredentialsException()
                    if not user.is_active:
                        raise CredentialsException("User account is deactivated")
                except Exception as e:
                    if isinstance(e, HTTPException):
                        raise e
                    raise CredentialsException("Invalid token")
                user_roles = {r.name for r in user.roles}
                required = set(self.role_names)
                if not user_roles & required and "ADMIN" not in user_roles:
                    raise ForbiddenException(
                        detail=f"One of these roles required: {', '.join(self.role_names)}"
                    )
                return (
                    await func(*args, **kwargs)
                    if inspect.iscoroutinefunction(func)
                    else func(*args, **kwargs)
                )

            return wrapper

        user = current_user
        user_roles = {r.name for r in user.roles}
        required = set(self.role_names)
        if not user_roles & required and "ADMIN" not in user_roles:
            raise ForbiddenException(
                detail=f"One of these roles required: {', '.join(self.role_names)}"
            )
        return user


class PermissionRequired:
    """FastAPI dependency and standalone decorator for permission-based access control."""

    def __init__(self, *permission_names: str):
        self.permission_names = permission_names

    def __call__(self, func_or_user=None, current_user: UserOut = Depends(get_current_user)):
        if func_or_user is not None and callable(func_or_user):
            func = func_or_user

            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                request = kwargs.get("request")
                if not request:
                    for arg in args:
                        if isinstance(arg, Request):
                            request = arg
                            break
                if not request:
                    raise CredentialsException("Request context is missing")
                auth_header = request.headers.get("Authorization", "")
                if not auth_header.startswith("Bearer "):
                    raise CredentialsException("Missing authentication token")
                token = auth_header.split(" ")[1]
                from app.main import app as global_app

                try:
                    payload = decode_token(token)
                    jti = payload.get("jti")
                    blacklist = global_app.container.token_blacklist()
                    if jti and blacklist.is_blacklisted(jti):
                        raise CredentialsException("Token has been revoked")
                    user_id = payload.get("sub")
                    if not user_id:
                        raise CredentialsException()
                    user_repo = global_app.container.user_repository()
                    user = user_repo.find_by_id(user_id)
                    if not user:
                        raise CredentialsException()
                    if not user.is_active:
                        raise CredentialsException("User account is deactivated")
                except Exception as e:
                    if isinstance(e, HTTPException):
                        raise e
                    raise CredentialsException("Invalid token")
                user_permissions: set[str] = set()
                for role in user.roles:
                    for perm in role.permissions:
                        user_permissions.add(perm.name)
                required = set(self.permission_names)
                if not user_permissions & required and "admin:access" not in user_permissions:
                    raise ForbiddenException(
                        detail=f"One of these permissions required: {', '.join(self.permission_names)}"
                    )
                return (
                    await func(*args, **kwargs)
                    if inspect.iscoroutinefunction(func)
                    else func(*args, **kwargs)
                )

            return wrapper

        user = current_user
        user_permissions: set[str] = set()
        for role in user.roles:
            for perm in role.permissions:
                user_permissions.add(perm.name)
        required = set(self.permission_names)
        if not user_permissions & required and "admin:access" not in user_permissions:
            raise ForbiddenException(
                detail=f"One of these permissions required: {', '.join(self.permission_names)}"
            )
        return user


def require_role(*role_names: str) -> RoleRequired:
    """Dependency/decorator that requires the user to have ANY of the specified roles."""
    return RoleRequired(*role_names)


def require_permission(*permission_names: str) -> PermissionRequired:
    """Dependency/decorator that requires the user to have ANY of the specified permissions."""
    return PermissionRequired(*permission_names)
