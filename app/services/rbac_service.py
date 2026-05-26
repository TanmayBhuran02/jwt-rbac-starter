"""RBAC service for role assignment and revocation."""

import logging

from fastapi import HTTPException, status

from app.core.exceptions import handle_db_exceptions
from app.interfaces.role_repository import IRoleRepository

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
