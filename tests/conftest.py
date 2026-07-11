"""Shared test fixtures for the JWT + RBAC starter kit."""

import pytest
from dependency_injector import providers
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from jwt_rbac.main import app
from jwt_rbac.models.db import Base
from jwt_rbac.models.role import Permission, Role
from jwt_rbac.models.user import User
from jwt_rbac.repositories.memory_blacklist import MemoryTokenBlacklist

# Use a file-based SQLite for testing
engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Create test database with default roles and permissions."""
    # Override DI container
    app.container.db_session.override(providers.Resource(override_get_db))
    app.container.token_blacklist.override(providers.Singleton(MemoryTokenBlacklist))

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()

    p1 = Permission(name="users:read")
    p2 = Permission(name="users:write")
    p3 = Permission(name="admin:access")
    p4 = Permission(name="reports:read")
    db.add_all([p1, p2, p3, p4])
    db.commit()

    r_admin = Role(name="ADMIN", permissions=[p1, p2, p3, p4])
    r_user = Role(name="USER", permissions=[p1])
    r_mod = Role(name="MODERATOR", permissions=[p1, p2, p4])
    db.add_all([r_admin, r_user, r_mod])
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    """Provide a test client for the FastAPI app."""
    # Disable rate limiting for testing to avoid 429 Too Many Requests
    from jwt_rbac.core.limiter import limiter

    limiter.enabled = False

    with TestClient(app) as c:
        yield c


@pytest.fixture
def db_session():
    """Provide a direct database session for test setup."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def register_user(client: TestClient, email: str, password: str = "password123") -> dict:
    """Helper: register a user and return the response JSON."""
    res = client.post(
        "/users/register",
        json={"email": email, "password": password},
    )
    return res.json()


def login_user(client: TestClient, email: str, password: str = "password123") -> dict:
    """Helper: login and return the response JSON with tokens."""
    res = client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    return res.json()


def get_auth_header(token: str) -> dict:
    """Helper: build Authorization header dict."""
    return {"Authorization": f"Bearer {token}"}


def make_admin(db_session, user_id: str) -> None:
    """Helper: assign ADMIN role to a user directly in the DB."""
    user = db_session.query(User).filter(User.id == user_id).first()
    admin_role = db_session.query(Role).filter(Role.name == "ADMIN").first()
    if user and admin_role and admin_role not in user.roles:
        user.roles.append(admin_role)
        db_session.commit()


def make_moderator(db_session, user_id: str) -> None:
    """Helper: assign MODERATOR role to a user directly in the DB."""
    user = db_session.query(User).filter(User.id == user_id).first()
    mod_role = db_session.query(Role).filter(Role.name == "MODERATOR").first()
    if user and mod_role and mod_role not in user.roles:
        user.roles.append(mod_role)
        db_session.commit()
