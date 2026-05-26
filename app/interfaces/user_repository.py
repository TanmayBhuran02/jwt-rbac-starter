"""Abstract interface for user persistence."""

from abc import ABC, abstractmethod

from app.schemas.user import UserCreate, UserInDB, UserOut


class IUserRepository(ABC):
    """Repository interface for user CRUD operations.

    All implementations must be thread-safe for use with FastAPI's
    dependency injection system.
    """

    @abstractmethod
    def find_by_email(self, email: str) -> UserInDB | None:
        """Find a user by email address.

        Args:
            email: The email to search for.

        Returns:
            The user with hashed password, or None if not found.
        """
        ...

    @abstractmethod
    def find_by_id(self, user_id: str) -> UserOut | None:
        """Find a user by their unique ID.

        Args:
            user_id: The UUID string of the user.

        Returns:
            The public user representation, or None if not found.
        """
        ...

    @abstractmethod
    def create(self, data: UserCreate) -> UserOut:
        """Create a new user account.

        Args:
            data: The registration data including email and password.

        Returns:
            The newly created user.
        """
        ...

    @abstractmethod
    def list_all(self) -> list[UserOut]:
        """List all users in the system.

        Returns:
            A list of all users.
        """
        ...

    @abstractmethod
    def update_password(self, user_id: str, hashed_password: str) -> None:
        """Update a user's hashed password.

        Args:
            user_id: The UUID string of the user.
            hashed_password: The new bcrypt-hashed password.
        """
        ...

    @abstractmethod
    def set_active(self, user_id: str, is_active: bool) -> None:
        """Toggle a user's active status.

        Args:
            user_id: The UUID string of the user.
            is_active: The new active status.
        """
        ...
