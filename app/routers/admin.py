"""Admin router: user management, role assignment, active toggle."""

from dependency_injector.wiring import Provide, inject
from fastapi import APIRouter, Depends, HTTPException, status

from app.containers import Container
from app.core.dependencies import require_role
from app.interfaces.user_repository import IUserRepository
from app.schemas.role import PermissionAssignment, PermissionOut, RoleOut
from app.schemas.user import RoleAssignment, UserOut
from app.services.rbac_service import RBACService

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get(
    "/users",
    response_model=list[UserOut],
    summary="List all users",
    description="Admin-only: returns all registered users with their roles.",
)
@inject
def list_users(
    user_repo: IUserRepository = Depends(Provide[Container.user_repository]),
    _: UserOut = Depends(require_role("ADMIN")),
) -> list[UserOut]:
    """List all users (admin only)."""
    return user_repo.list_all()


@router.post(
    "/users/{user_id}/roles",
    status_code=200,
    summary="Assign or revoke a role",
    description="Admin-only: assign or revoke a role from a user.",
)
@inject
def manage_user_role(
    user_id: str,
    data: RoleAssignment,
    rbac_service: RBACService = Depends(Provide[Container.rbac_service]),
    user_repo: IUserRepository = Depends(Provide[Container.user_repository]),
    _: UserOut = Depends(require_role("ADMIN")),
) -> dict:
    """Assign or revoke a role from a user."""
    # Verify user exists
    user = user_repo.find_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if data.action == "assign":
        rbac_service.assign_role(user_id, data.role_name)
        return {"message": f"Role '{data.role_name}' assigned to user"}
    else:
        rbac_service.revoke_role(user_id, data.role_name)
        return {"message": f"Role '{data.role_name}' revoked from user"}


@router.patch(
    "/users/{user_id}/toggle-active",
    status_code=200,
    summary="Toggle user active status",
    description="Admin-only: activate or deactivate a user account.",
)
@inject
def toggle_user_active(
    user_id: str,
    user_repo: IUserRepository = Depends(Provide[Container.user_repository]),
    _: UserOut = Depends(require_role("ADMIN")),
) -> dict:
    """Toggle a user's active status."""
    user = user_repo.find_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    new_status = not user.is_active
    user_repo.set_active(user_id, new_status)
    return {
        "message": f"User {'activated' if new_status else 'deactivated'}",
        "is_active": new_status,
    }


@router.get(
    "/roles",
    response_model=list[RoleOut],
    summary="List all roles",
    description="Admin-only: returns all available roles.",
)
@inject
def list_roles(
    rbac_service: RBACService = Depends(Provide[Container.rbac_service]),
    _: UserOut = Depends(require_role("ADMIN")),
) -> list[RoleOut]:
    """List all available roles (admin only)."""
    return rbac_service.list_roles()


@router.get(
    "/permissions",
    response_model=list[PermissionOut],
    summary="List all permissions",
    description="Admin-only: returns all available permissions.",
)
@inject
def list_permissions(
    rbac_service: RBACService = Depends(Provide[Container.rbac_service]),
    _: UserOut = Depends(require_role("ADMIN")),
) -> list[PermissionOut]:
    """List all available permissions (admin only)."""
    return rbac_service.list_permissions()


@router.put(
    "/roles/{role_id}/permissions",
    response_model=RoleOut,
    summary="Assign or update permissions for a role",
    description="Admin-only: replaces all permissions on a role with the provided set.",
)
@inject
def set_role_permissions(
    role_id: int,
    data: PermissionAssignment,
    rbac_service: RBACService = Depends(Provide[Container.rbac_service]),
    _: UserOut = Depends(require_role("ADMIN")),
) -> RoleOut:
    """Replace all permissions on a role (admin only)."""
    return rbac_service.set_role_permissions(role_id, data.permissions)
