"""Idempotent seed script for default roles, permissions, and ADMIN user.

Usage:
    python -m app.seed

Creates:
    - Default permissions: users:read, users:write, admin:access, reports:read
    - Default roles: ADMIN, USER, MODERATOR
    - One ADMIN user from ADMIN_EMAIL / ADMIN_PASSWORD env vars
"""

import logging
import sys

from app.config import settings
from app.core.security import get_password_hash
from app.models.db import Base, SessionLocal, engine
from app.models.role import Permission, Role
from app.models.user import User

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

PERMISSIONS = ["users:read", "users:write", "admin:access", "reports:read"]

ROLES = {
    "ADMIN": ["users:read", "users:write", "admin:access", "reports:read"],
    "USER": ["users:read"],
    "MODERATOR": ["users:read", "users:write", "reports:read"],
}


def seed() -> None:
    """Run the idempotent seed process."""
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        # --- Permissions ---
        for perm_name in PERMISSIONS:
            existing = db.query(Permission).filter(Permission.name == perm_name).first()
            if not existing:
                db.add(Permission(name=perm_name))
                logger.info("  Created permission: %s", perm_name)
            else:
                logger.info("  Permission exists: %s", perm_name)
        db.commit()

        # --- Roles ---
        for role_name, perm_names in ROLES.items():
            existing = db.query(Role).filter(Role.name == role_name).first()
            if not existing:
                perms = db.query(Permission).filter(Permission.name.in_(perm_names)).all()
                role = Role(name=role_name, permissions=perms)
                db.add(role)
                logger.info("  Created role: %s with permissions %s", role_name, perm_names)
            else:
                logger.info("  Role exists: %s", role_name)
        db.commit()

        # --- Admin User ---
        admin_email = settings.admin_email
        admin_password = settings.admin_password

        existing_admin = db.query(User).filter(User.email == admin_email).first()
        if not existing_admin:
            admin_role = db.query(Role).filter(Role.name == "ADMIN").first()
            admin_user = User(
                email=admin_email,
                hashed_password=get_password_hash(admin_password),
                is_active=True,
            )
            if admin_role:
                admin_user.roles.append(admin_role)
            db.add(admin_user)
            db.commit()
            logger.info("  Created ADMIN user: %s", admin_email)
        else:
            logger.info("  Admin user exists: %s", admin_email)

        logger.info("Seed complete!")

    except Exception:
        db.rollback()
        logger.exception("Seed failed")
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    seed()
