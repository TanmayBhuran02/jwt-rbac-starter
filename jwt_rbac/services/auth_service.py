"""Authentication service handling login, refresh, and logout."""

import logging

from jwt_rbac.core.exceptions import CredentialsException, handle_db_exceptions
from jwt_rbac.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    verify_password,
)
from jwt_rbac.interfaces.token_blacklist import ITokenBlacklist
from jwt_rbac.interfaces.user_repository import IUserRepository
from jwt_rbac.schemas.auth import LoginRequest, RefreshRequest, TokenResponse

logger = logging.getLogger(__name__)


class AuthService:
    """Handles authentication flows: login, token refresh, and logout."""

    def __init__(self, user_repo: IUserRepository, blacklist: ITokenBlacklist) -> None:
        self.user_repo = user_repo
        self.blacklist = blacklist

    @handle_db_exceptions
    def login(self, data: LoginRequest) -> TokenResponse:
        """Authenticate a user and return a token pair.

        Args:
            data: Login credentials (email + password).

        Returns:
            Access and refresh tokens.

        Raises:
            CredentialsException: If credentials are invalid or user is inactive.
        """
        user = self.user_repo.find_by_email(data.email)
        if not user or not user.is_active:
            raise CredentialsException("Invalid email or password")

        if not verify_password(data.password, user.hashed_password):
            raise CredentialsException("Invalid email or password")

        roles = [role.name for role in user.roles]
        permissions = []
        for role in user.roles:
            for perm in role.permissions:
                if perm.name not in permissions:
                    permissions.append(perm.name)

        access_token = create_access_token(
            subject=str(user.id), roles=roles, permissions=permissions
        )
        refresh_token = create_refresh_token(subject=str(user.id), roles=roles)

        logger.info("User %s logged in successfully", user.email)
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)

    @handle_db_exceptions
    def refresh(self, data: RefreshRequest) -> TokenResponse:
        """Exchange a refresh token for a new token pair.

        Args:
            data: The refresh token to exchange.

        Returns:
            A new access + refresh token pair.

        Raises:
            CredentialsException: If the refresh token is blacklisted, expired, or invalid.
        """
        payload = decode_refresh_token(data.refresh_token)

        jti = payload.get("jti")
        if jti and self.blacklist.is_blacklisted(jti):
            raise CredentialsException("Token has been revoked")

        user_id = payload.get("sub")
        if not user_id:
            raise CredentialsException("Invalid token")

        # Re-fetch user to get current roles
        user = self.user_repo.find_by_id(user_id)
        if not user or not user.is_active:
            raise CredentialsException("User not found or inactive")

        roles = [role.name for role in user.roles]
        permissions = []
        for role in user.roles:
            for perm in role.permissions:
                if perm.name not in permissions:
                    permissions.append(perm.name)

        # Blacklist the old refresh token
        if jti:
            self.blacklist.add(jti)

        access_token = create_access_token(subject=user_id, roles=roles, permissions=permissions)
        new_refresh_token = create_refresh_token(subject=user_id, roles=roles)

        return TokenResponse(access_token=access_token, refresh_token=new_refresh_token)

    @handle_db_exceptions
    def logout(self, access_jti: str | None, refresh_token: str | None) -> None:
        """Blacklist the current access and refresh tokens.

        Args:
            access_jti: The JTI from the current access token.
            refresh_token: The raw refresh token string to decode and blacklist.
        """
        if access_jti:
            self.blacklist.add(access_jti)

        if refresh_token:
            try:
                payload = decode_refresh_token(refresh_token)
                refresh_jti = payload.get("jti")
                if refresh_jti:
                    self.blacklist.add(refresh_jti)
            except CredentialsException:
                pass  # If refresh token is already expired, just blacklist access

        logger.info("Tokens blacklisted successfully")
