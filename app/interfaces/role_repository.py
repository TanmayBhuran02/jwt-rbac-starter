"""Abstract interface for role persistence."""

from abc import ABC, abstractmethod

from app.schemas.role import PermissionOut, RoleOut


class IRoleRepository(ABC):
    """Repository interface for role management operations.

    All implementations must be thread-safe for use with FastAPI's
    dependency injection system.
    """

    @abstractmethod
    def find_by_name(self, name: str) -> RoleOut | None:
        """Find a role by its name.

        Args:
            name: The role name (e.g. 'ADMIN', 'USER').

        Returns:
            The role with permissions, or None if not found.
        """
        ...

    @abstractmethod
    def assign_to_user(self, user_id: str, role_name: str) -> None:
        """Assign a role to a user.

        Args:
            user_id: The UUID string of the user.
            role_name: The name of the role to assign.
        """
        ...

    @abstractmethod
    def revoke_from_user(self, user_id: str, role_name: str) -> None:
        """Revoke a role from a user.

        Args:
            user_id: The UUID string of the user.
            role_name: The name of the role to revoke.
        """
        ...

    @abstractmethod
    def get_user_roles(self, user_id: str) -> list[RoleOut]:
        """Get all roles assigned to a user.

        Args:
            user_id: The UUID string of the user.

        Returns:
            A list of roles assigned to the user.
        """
        ...

    @abstractmethod
    def list_all(self) -> list[RoleOut]:
        """List all available roles.

        Returns:
            A list of all roles in the system.
        """
        ...

    @abstractmethod
    def list_permissions(self) -> list[PermissionOut]:
        """List all available permissions.

        Returns:
            A list of all permissions in the system.
        """
        ...

    @abstractmethod
    def set_permissions(self, role_id: int, permission_names: list[str]) -> RoleOut:
        """Replace all permissions on a role with the given set.

        Args:
            role_id: The primary key of the role.
            permission_names: A list of permission name strings to assign.

        Returns:
            The updated role with its new permissions.

        Raises:
            ServiceError: If the role is not found or a permission name is invalid.
        """
        ...
