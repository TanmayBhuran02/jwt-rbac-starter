"""SQLAlchemy implementation of the role repository interface."""

import logging

from sqlalchemy.orm import Session

from app.core.exceptions import ServiceError
from app.interfaces.role_repository import IRoleRepository
from app.models.role import Permission, Role
from app.models.user import User
from app.schemas.role import PermissionOut, RoleOut

logger = logging.getLogger(__name__)


class SqlRoleRepository(IRoleRepository):
    """SQLAlchemy-backed role repository."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def find_by_name(self, name: str) -> RoleOut | None:
        """Find a role by its name."""
        try:
            role = self.db.query(Role).filter(Role.name == name).first()
            if role:
                return RoleOut.model_validate(role)
            return None
        except Exception as exc:
            logger.exception("Database error in find_by_name")
            raise ServiceError(detail="Database error") from exc

    def assign_to_user(self, user_id: str, role_name: str) -> None:
        """Assign a role to a user."""
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            role = self.db.query(Role).filter(Role.name == role_name).first()
            if user and role and role not in user.roles:
                user.roles.append(role)
                self.db.commit()
        except Exception as exc:
            self.db.rollback()
            logger.exception("Database error in assign_to_user")
            raise ServiceError(detail="Database error") from exc

    def revoke_from_user(self, user_id: str, role_name: str) -> None:
        """Revoke a role from a user."""
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            role = self.db.query(Role).filter(Role.name == role_name).first()
            if user and role and role in user.roles:
                user.roles.remove(role)
                self.db.commit()
        except Exception as exc:
            self.db.rollback()
            logger.exception("Database error in revoke_from_user")
            raise ServiceError(detail="Database error") from exc

    def get_user_roles(self, user_id: str) -> list[RoleOut]:
        """Get all roles assigned to a user."""
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            if user:
                return [RoleOut.model_validate(r) for r in user.roles]
            return []
        except Exception as exc:
            logger.exception("Database error in get_user_roles")
            raise ServiceError(detail="Database error") from exc

    def list_all(self) -> list[RoleOut]:
        """List all available roles."""
        try:
            roles = self.db.query(Role).all()
            return [RoleOut.model_validate(r) for r in roles]
        except Exception as exc:
            logger.exception("Database error in list_all")
            raise ServiceError(detail="Database error") from exc

    def list_permissions(self) -> list[PermissionOut]:
        """List all available permissions."""
        try:
            permissions = self.db.query(Permission).all()
            return [PermissionOut.model_validate(p) for p in permissions]
        except Exception as exc:
            logger.exception("Database error in list_permissions")
            raise ServiceError(detail="Database error") from exc

    def set_permissions(self, role_id: int, permission_names: list[str]) -> RoleOut:
        """Replace all permissions on a role with the given set."""
        try:
            role = self.db.query(Role).filter(Role.id == role_id).first()
            if not role:
                raise ServiceError(detail="Role not found", status_code=404)

            # Resolve permission names to ORM objects
            permissions = (
                self.db.query(Permission)
                .filter(Permission.name.in_(permission_names))
                .all()
            )
            found_names = {p.name for p in permissions}
            unknown = set(permission_names) - found_names
            if unknown:
                raise ServiceError(
                    detail=f"Unknown permissions: {', '.join(sorted(unknown))}",
                    status_code=400,
                )

            role.permissions = permissions
            self.db.commit()
            self.db.refresh(role)
            return RoleOut.model_validate(role)
        except ServiceError:
            raise
        except Exception as exc:
            self.db.rollback()
            logger.exception("Database error in set_permissions")
            raise ServiceError(detail="Database error") from exc
