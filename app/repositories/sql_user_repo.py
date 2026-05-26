"""SQLAlchemy implementation of the user repository interface."""

import logging

from sqlalchemy.orm import Session

from app.core.exceptions import ServiceError
from app.core.security import get_password_hash
from app.interfaces.user_repository import IUserRepository
from app.models.user import User
from app.schemas.user import UserCreate, UserInDB, UserOut

logger = logging.getLogger(__name__)


class SqlUserRepository(IUserRepository):
    """SQLAlchemy-backed user repository."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def find_by_email(self, email: str) -> UserInDB | None:
        """Find a user by email address."""
        try:
            user = self.db.query(User).filter(User.email == email).first()
            if user:
                return UserInDB.model_validate(user)
            return None
        except Exception as exc:
            logger.exception("Database error in find_by_email")
            raise ServiceError(detail="Database error") from exc

    def find_by_id(self, user_id: str) -> UserOut | None:
        """Find a user by their unique ID."""
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            if user:
                return UserOut.model_validate(user)
            return None
        except Exception as exc:
            logger.exception("Database error in find_by_id")
            raise ServiceError(detail="Database error") from exc

    def create(self, data: UserCreate) -> UserOut:
        """Create a new user account."""
        try:
            hashed_password = get_password_hash(data.password)
            db_user = User(email=data.email, hashed_password=hashed_password)
            self.db.add(db_user)
            self.db.commit()
            self.db.refresh(db_user)
            return UserOut.model_validate(db_user)
        except Exception as exc:
            self.db.rollback()
            logger.exception("Database error in create")
            raise ServiceError(detail="Database error") from exc

    def list_all(self) -> list[UserOut]:
        """List all users in the system."""
        try:
            users = self.db.query(User).all()
            return [UserOut.model_validate(u) for u in users]
        except Exception as exc:
            logger.exception("Database error in list_all")
            raise ServiceError(detail="Database error") from exc

    def update_password(self, user_id: str, hashed_password: str) -> None:
        """Update a user's hashed password."""
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            if user:
                user.hashed_password = hashed_password
                self.db.commit()
        except Exception as exc:
            self.db.rollback()
            logger.exception("Database error in update_password")
            raise ServiceError(detail="Database error") from exc

    def set_active(self, user_id: str, is_active: bool) -> None:
        """Toggle a user's active status."""
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            if user:
                user.is_active = is_active
                self.db.commit()
        except Exception as exc:
            self.db.rollback()
            logger.exception("Database error in set_active")
            raise ServiceError(detail="Database error") from exc
