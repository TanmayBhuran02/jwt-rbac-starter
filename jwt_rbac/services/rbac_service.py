"""RBAC service for role assignment and revocation."""

import logging

from fastapi import HTTPException, status

from jwt_rbac.core.exceptions import handle_db_exceptions
from jwt_rbac.interfaces.role_repository import IRoleRepository

logger = logging.getLogger(__name__)


class RBACService:
    """Handles role-based access control operations."""

    def __init__(self, role_repo: IRoleRepository) -> None:
        self.role_repo = role_repo

    @handle_db_exceptions
    def assign_role(self, user_id: str, role_name: str) -> None:
        """Assign a role to a user.

        Args:
            user_id: The UUID string of the user.
            role_name: The name of the role to assign.

        Raises:
            HTTPException: If the role does not exist.
        """
        role = self.role_repo.find_by_name(role_name)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role '{role_name}' not found",
            )
        self.role_repo.assign_to_user(user_id, role_name)
        logger.info("Assigned role %s to user %s", role_name, user_id)

    @handle_db_exceptions
    def revoke_role(self, user_id: str, role_name: str) -> None:
        """Revoke a role from a user.

        Args:
            user_id: The UUID string of the user.
            role_name: The name of the role to revoke.

        Raises:
            HTTPException: If the role does not exist.
        """
        role = self.role_repo.find_by_name(role_name)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role '{role_name}' not found",
            )
        self.role_repo.revoke_from_user(user_id, role_name)
        logger.info("Revoked role %s from user %s", role_name, user_id)

    @handle_db_exceptions
    def list_roles(self):
        """List all available roles."""
        return self.role_repo.list_all()

    @handle_db_exceptions
    def list_permissions(self):
        """List all available permissions."""
        return self.role_repo.list_permissions()

    @handle_db_exceptions
    def set_role_permissions(self, role_id: int, permission_names: list[str]):
        """Replace all permissions on a role with the given set.

        Args:
            role_id: The primary key of the role.
            permission_names: A list of permission name strings to assign.

        Returns:
            The updated role with its new permissions.

        Raises:
            HTTPException: If the role or any permission is not found.
        """
        updated_role = self.role_repo.set_permissions(role_id, permission_names)
        logger.info("Updated permissions for role %d to %s", role_id, permission_names)
        return updated_role
