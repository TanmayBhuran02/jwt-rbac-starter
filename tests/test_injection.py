"""Injection tests: verify custom repositories can be injected via DI container."""

from datetime import datetime, timezone
from uuid import uuid4

from dependency_injector import providers
from fastapi.testclient import TestClient

from app.interfaces.user_repository import IUserRepository
from app.main import app
from app.schemas.role import PermissionOut, RoleOut
from app.schemas.user import UserInDB, UserOut


class FakeUserRepository(IUserRepository):
    """A fake user repository that returns hardcoded data for injection testing."""

    def __init__(self):
        self._user_id = str(uuid4())
        self._users = {}

    def find_by_email(self, email: str) -> UserInDB | None:
        return self._users.get(email)

    def find_by_id(self, user_id: str) -> UserOut | None:
        for u in self._users.values():
            if str(u.id) == user_id:
                return UserOut(
                    id=u.id,
                    email=u.email,
                    is_active=u.is_active,
                    created_at=u.created_at,
                    roles=u.roles,
                )
        return None

    def create(self, data) -> UserOut:
        from app.core.security import get_password_hash

        uid = uuid4()
        user = UserInDB(
            id=uid,
            email=data.email,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            roles=[
                RoleOut(
                    id=1,
                    name="USER",
                    permissions=[PermissionOut(id=1, name="users:read")],
                )
            ],
            hashed_password=get_password_hash(data.password),
        )
        self._users[data.email] = user
        return UserOut(
            id=uid,
            email=data.email,
            is_active=True,
            created_at=user.created_at,
            roles=user.roles,
        )

    def list_all(self) -> list[UserOut]:
        return [
            UserOut(
                id=u.id,
                email=u.email,
                is_active=u.is_active,
                created_at=u.created_at,
                roles=u.roles,
            )
            for u in self._users.values()
        ]

    def update_password(self, user_id: str, hashed_password: str) -> None:
        for u in self._users.values():
            if str(u.id) == user_id:
                self._users[u.email] = UserInDB(
                    id=u.id,
                    email=u.email,
                    is_active=u.is_active,
                    created_at=u.created_at,
                    roles=u.roles,
                    hashed_password=hashed_password,
                )

    def set_active(self, user_id: str, is_active: bool) -> None:
        for u in self._users.values():
            if str(u.id) == user_id:
                self._users[u.email] = UserInDB(
                    id=u.id,
                    email=u.email,
                    is_active=is_active,
                    created_at=u.created_at,
                    roles=u.roles,
                    hashed_password=u.hashed_password,
                )


def test_custom_repo_injected_via_setup():
    """Custom repo injected via DI container is used for registration and login."""
    fake_repo = FakeUserRepository()

    # Override the container
    app.container.user_repository.override(providers.Object(fake_repo))

    try:
        with TestClient(app) as client:
            # Register via the fake repo
            res = client.post(
                "/users/register",
                json={"email": "injected@test.com", "password": "testpass123"},
            )
            assert res.status_code == 200
            assert res.json()["email"] == "injected@test.com"

            # The fake repo should have the user
            assert fake_repo.find_by_email("injected@test.com") is not None

            # Login should work
            res = client.post(
                "/auth/login",
                json={"email": "injected@test.com", "password": "testpass123"},
            )
            assert res.status_code == 200
            assert "access_token" in res.json()
    finally:
        app.container.user_repository.reset_override()


def test_setup_api_injection():
    """Verify that calling setup() with a custom repo injects it correctly."""
    from app.setup import setup

    fake_repo = FakeUserRepository()

    # Instantiate app via setup()
    custom_app = setup(
        user_repository=fake_repo,
        secret_key="my-super-secret-key-change-me-in-production",
        refresh_secret_key="my-refresh-secret-key-change-in-prod",
    )

    try:
        with TestClient(custom_app) as client:
            # Register via custom app
            res = client.post(
                "/users/register",
                json={"email": "setup_injected@test.com", "password": "testpass123"},
            )
            assert res.status_code == 200
            assert res.json()["email"] == "setup_injected@test.com"

            # Verify it went to the fake repository
            assert fake_repo.find_by_email("setup_injected@test.com") is not None
    finally:
        custom_app.container.unwire()
        from app.main import app as global_app

        global_app.container.wire(
            modules=[
                "app.core.dependencies",
                "app.routers.auth",
                "app.routers.users",
                "app.routers.admin",
            ]
        )


def test_setup_api_invalid_secrets():
    """Verify that setup() enforces a minimum 32 character limit for secrets."""
    import pytest

    from app.setup import setup

    with pytest.raises(ValueError, match="secret_key must be at least 32 characters long"):
        setup(secret_key="too-short")

    with pytest.raises(ValueError, match="refresh_secret_key must be at least 32 characters long"):
        setup(
            secret_key="my-super-secret-key-change-me-in-production", refresh_secret_key="too-short"
        )


def test_setup_api_partial_repo_error():
    """Verify that setup() raises a TypeError if an object missing abstract methods is passed."""
    import pytest

    from app.setup import setup

    class DummyObj:
        pass

    with pytest.raises(TypeError, match="missing the following required abstract methods"):
        setup(user_repository=DummyObj())
