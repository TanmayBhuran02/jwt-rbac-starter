"""User service handling registration, profile, and password changes."""

import logging

from fastapi import HTTPException, status

from app.core.exceptions import handle_db_exceptions
from app.core.security import get_password_hash, verify_password
from app.interfaces.role_repository import IRoleRepository
from app.interfaces.user_repository import IUserRepository
from app.schemas.user import UserCreate, UserOut

logger = logging.getLogger(__name__)


class UserService:
    """Handles user-related business logic."""

    def __init__(self, user_repo: IUserRepository, role_repo: IRoleRepository) -> None:
        self.user_repo = user_repo
        self.role_repo = role_repo

    @handle_db_exceptions
    def register(self, data: UserCreate) -> UserOut:
        """Register a new user account with the default USER role.

        Args:
            data: Registration data (email + password).

        Returns:
            The newly created user.

        Raises:
            HTTPException: If the email is already registered.
        """
        logger.info("Registering user: %s", data.email)
        existing = self.user_repo.find_by_email(data.email)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        user = self.user_repo.create(data)
        assigned_role = data.role_name if getattr(data, "role_name", None) else "USER"
        self.role_repo.assign_to_user(str(user.id), assigned_role)

        return self.user_repo.find_by_id(str(user.id))

    @handle_db_exceptions
    def get_profile(self, user_id: str) -> UserOut:
        """Retrieve a user's profile by ID.

        Args:
            user_id: The UUID string of the user.

        Returns:
            The user profile.

        Raises:
            HTTPException: If the user is not found.
        """
        user = self.user_repo.find_by_id(user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        return user

    @handle_db_exceptions
    def change_password(self, user_id: str, current_password: str, new_password: str) -> None:
        """Change the current user's password.

        Verifies the current password before updating. Uses bcrypt re-hash.

        Args:
            user_id: The UUID string of the user.
            current_password: The current password for verification.
            new_password: The new password to set.

        Raises:
            HTTPException: If the current password is incorrect or user not found.
        """
        # find_by_email returns UserInDB with hashed_password, but we need to
        # look up by ID. We'll use find_by_id to confirm existence, then
        # use the repo's internal DB to verify the password.
        user_with_hash = self._get_user_with_hash(user_id)
        if not user_with_hash:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        if not verify_password(current_password, user_with_hash.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect",
            )

        new_hash = get_password_hash(new_password)
        self.user_repo.update_password(user_id, new_hash)
        logger.info("Password changed for user %s", user_id)

    def _get_user_with_hash(self, user_id: str):
        """Retrieve user with hashed password by scanning by email.

        This is a workaround since IUserRepository.find_by_id returns UserOut
        (without the hash). We iterate to find by ID. For production,
        consider adding find_by_id_internal to the interface.
        """
        # Use the underlying repo to get the user with hash
        # SqlUserRepository has direct DB access
        if hasattr(self.user_repo, "db"):
            from app.models.user import User

            db_user = self.user_repo.db.query(User).filter(User.id == user_id).first()
            if db_user:
                from app.schemas.user import UserInDB

                return UserInDB.model_validate(db_user)
        return None
