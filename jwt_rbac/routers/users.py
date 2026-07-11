"""User router: registration, profile, password change."""

from dependency_injector.wiring import Provide, inject
from fastapi import APIRouter, Depends

from jwt_rbac.containers import Container
from jwt_rbac.core.dependencies import get_current_user
from jwt_rbac.schemas.auth import PasswordChangeRequest
from jwt_rbac.schemas.user import UserCreate, UserOut
from jwt_rbac.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["users"])


@router.post(
    "/register",
    response_model=UserOut,
    summary="Register new user",
    description="Create a new user account. The default USER role is assigned automatically.",
)
@inject
def register(
    data: UserCreate,
    user_service: UserService = Depends(Provide[Container.user_service]),
) -> UserOut:
    """Register a new user."""
    return user_service.register(data)


@router.get(
    "/me",
    response_model=UserOut,
    summary="Get current user profile",
    description="Returns the authenticated user's profile including roles and permissions.",
)
def get_me(current_user: UserOut = Depends(get_current_user)) -> UserOut:
    """Get the current user's profile."""
    return current_user


@router.patch(
    "/me/password",
    status_code=200,
    summary="Change password",
    description="Change the current user's password. Requires current password verification.",
)
@inject
def change_password(
    data: PasswordChangeRequest,
    current_user: UserOut = Depends(get_current_user),
    user_service: UserService = Depends(Provide[Container.user_service]),
) -> dict:
    """Change the current user's password."""
    user_service.change_password(
        user_id=str(current_user.id),
        current_password=data.current_password,
        new_password=data.new_password,
    )
    return {"message": "Password updated successfully"}
