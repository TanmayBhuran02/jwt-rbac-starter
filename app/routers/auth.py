"""Authentication router: login, refresh, logout, me alias, token introspection."""

from dependency_injector.wiring import Provide, inject
from fastapi import APIRouter, Depends, Request, Response, status

from app.containers import Container
from app.core.dependencies import get_current_user, oauth2_scheme
from app.core.limiter import limiter
from app.core.security import decode_token
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    TokenInfo,
    TokenResponse,
)
from app.schemas.user import UserOut
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user",
    description="Validate credentials and return an access + refresh token pair. Rate-limited to 5 attempts/minute per IP.",
)
@limiter.limit("5/minute")
@inject
def login(
    request: Request,
    data: LoginRequest,
    auth_service: AuthService = Depends(Provide[Container.auth_service]),
) -> TokenResponse:
    """Authenticate with email and password."""
    return auth_service.login(data)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh tokens",
    description="Exchange a valid refresh token for a new access + refresh token pair.",
)
@inject
def refresh_token(
    data: RefreshRequest,
    auth_service: AuthService = Depends(Provide[Container.auth_service]),
) -> TokenResponse:
    """Exchange a refresh token for a new token pair."""
    return auth_service.refresh(data)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout",
    description="Blacklist the current access and refresh tokens.",
)
@inject
def logout(
    token: str = Depends(oauth2_scheme),
    auth_service: AuthService = Depends(Provide[Container.auth_service]),
    refresh_token: str | None = None,
) -> Response:
    """Logout and blacklist tokens."""
    payload = decode_token(token)
    access_jti = payload.get("jti")
    auth_service.logout(access_jti=access_jti, refresh_token=refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/me",
    response_model=UserOut,
    summary="Get current user (alias)",
    description="Alias for GET /users/me — returns the authenticated user's profile.",
)
def auth_me(current_user: UserOut = Depends(get_current_user)) -> UserOut:
    """Alias for /users/me."""
    return current_user


@router.get(
    "/token/info",
    response_model=TokenInfo,
    summary="Token introspection",
    description="Decode and return the payload of the current access token.",
)
def token_info(token: str = Depends(oauth2_scheme)) -> dict:
    """Return the decoded JWT payload (no secret needed client-side)."""
    payload = decode_token(token)
    return payload
