"""Unit tests for the ``setup()`` configuration API."""

from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient

from jwt_rbac.interfaces.user_repository import IUserRepository
from jwt_rbac.setup import _validate_repo_interface, setup

VALID_SECRET = "my-super-secret-key-change-me-in-production"
VALID_REFRESH_SECRET = "my-refresh-secret-key-change-in-prod"

# The modules whose ``Provide[...]`` markers ``setup()`` rewires globally.
WIRED_MODULES = [
    "jwt_rbac.core.dependencies",
    "jwt_rbac.routers.auth",
    "jwt_rbac.routers.users",
    "jwt_rbac.routers.admin",
]


@pytest.fixture(autouse=True)
def restore_global_wiring():
    """Re-attach the global app's container after every test in this module.

    ``setup()`` calls ``Container().wire(modules=[...])``, which rebinds the
    ``Provide[...]`` markers in those *shared* modules process-wide.  Left
    unrestored, every later test that uses the global app would resolve its
    repositories from whichever container happened to be created last — leaking
    connections and silently breaking dependency injection.
    """
    yield
    from jwt_rbac.main import app as global_app

    global_app.container.wire(modules=WIRED_MODULES)


def _paths(app: FastAPI) -> set[str]:
    """Collect the route paths registered on an app."""
    return {route.path for route in app.routes if hasattr(route, "path")}


# --------------------------------------------------------------------------
# Secret validation
# --------------------------------------------------------------------------


def test_short_secret_key_is_rejected():
    """A secret under 32 characters raises a clear ValueError."""
    with pytest.raises(ValueError, match="secret_key must be at least 32 characters long"):
        setup(secret_key="too-short")


def test_short_refresh_secret_is_rejected():
    """The refresh secret is validated the same way."""
    with pytest.raises(ValueError, match="refresh_secret_key must be at least 32 characters long"):
        setup(secret_key=VALID_SECRET, refresh_secret_key="too-short")


# --------------------------------------------------------------------------
# Repository interface validation
# --------------------------------------------------------------------------


def test_empty_object_fails_validation():
    """An object missing every abstract method is rejected."""

    class Dummy:
        pass

    with pytest.raises(TypeError, match="missing the following required abstract methods"):
        _validate_repo_interface(Dummy(), IUserRepository)


def test_non_callable_attribute_fails_validation():
    """A shadowing attribute that is not callable is rejected."""

    class Partial(IUserRepository):
        find_by_email = "not-a-function"
        find_by_id = "not-a-function"
        create = "not-a-function"
        list_all = "not-a-function"
        update_password = "not-a-function"
        set_active = "not-a-function"

    with pytest.raises(TypeError, match="missing the following required abstract methods"):
        _validate_repo_interface(Partial(), IUserRepository)


def test_fully_implemented_passes_validation():
    """A complete implementation is accepted."""
    from tests.test_injection import FakeUserRepository

    # Should not raise.
    _validate_repo_interface(FakeUserRepository(), IUserRepository)


def test_custom_blacklist_is_validated():
    """A token blacklist missing the required methods is rejected.

    A plain object is used rather than an ``ITokenBlacklist`` subclass because
    an ABC cannot be instantiated without implementing every abstract method —
    which is precisely the situation under test.
    """

    class Incomplete:
        """Implements nothing of the blacklist contract."""

    with pytest.raises(TypeError, match="ITokenBlacklist"):
        setup(
            secret_key=VALID_SECRET,
            refresh_secret_key=VALID_REFRESH_SECRET,
            token_blacklist=Incomplete(),
        )


def test_complete_blacklist_is_accepted():
    """A fully implemented blacklist passes validation."""
    from jwt_rbac.repositories.memory_blacklist import MemoryTokenBlacklist

    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        include_ui=False,
        token_blacklist=MemoryTokenBlacklist(),
    )
    assert app.container.token_blacklist() is not None


# --------------------------------------------------------------------------
# Routing options
# --------------------------------------------------------------------------


def test_router_prefix_is_applied_to_all_routes():
    """Every API route is mounted under the configured prefix."""
    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        router_prefix="/api/v1",
        include_ui=False,
    )
    paths = _paths(app)
    assert "/api/v1/auth/login" in paths
    assert "/api/v1/users/register" in paths
    assert "/api/v1/admin/users" in paths
    # Unprefixed paths must not exist.
    assert "/auth/login" not in paths


def test_additional_routers_are_included():
    """Extra routers supplied by the caller are mounted."""

    extra = APIRouter(prefix="/extra")

    @extra.get("/ping")
    def ping():
        return {"pong": True}

    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        include_ui=False,
        additional_routers=[extra],
    )
    assert "/extra/ping" in _paths(app)


def test_additional_routers_respect_prefix():
    """Additional routers honour router_prefix too."""

    extra = APIRouter(prefix="/extra")

    @extra.get("/ping")
    def ping():
        return {"pong": True}

    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        include_ui=False,
        router_prefix="/v2",
        additional_routers=[extra],
    )
    assert "/v2/extra/ping" in _paths(app)


def test_include_ui_false_omits_template_routes():
    """Disabling the UI removes the HTML template routes."""
    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        include_ui=False,
    )
    assert "/dashboard" not in _paths(app)
    assert "/admin-panel" not in _paths(app)


def test_include_ui_true_serves_template_routes():
    """The bundled UI routes are registered by default."""
    app = setup(secret_key=VALID_SECRET, refresh_secret_key=VALID_REFRESH_SECRET)
    paths = _paths(app)
    assert "/dashboard" in paths
    assert "/admin-panel" in paths


def test_custom_frontend_dir_is_used(tmp_path):
    """A caller-supplied templates directory is used for the UI router."""
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "login.html").write_text("<html>custom login</html>")
    (templates / "dashboard.html").write_text("<html>custom dashboard</html>")
    (templates / "admin.html").write_text("<html>custom admin</html>")

    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        include_ui=True,
        frontend_dir=str(tmp_path),
    )
    with TestClient(app) as client:
        res = client.get("/")
        assert res.status_code == 200
        assert "custom login" in res.text


# --------------------------------------------------------------------------
# Middleware and metadata
# --------------------------------------------------------------------------


def test_security_headers_enabled_by_default():
    """Security headers are attached to responses by default."""
    app = setup(secret_key=VALID_SECRET, refresh_secret_key=VALID_REFRESH_SECRET)
    with TestClient(app) as client:
        res = client.get("/auth/token/info", headers={"Authorization": "Bearer x"})
        assert res.headers["X-Content-Type-Options"] == "nosniff"
        assert res.headers["X-Frame-Options"] == "DENY"
        assert res.headers["Referrer-Policy"] == "no-referrer"


def test_security_headers_can_be_disabled():
    """security_headers=False removes the security header middleware."""
    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        security_headers=False,
    )
    with TestClient(app) as client:
        res = client.get("/auth/token/info", headers={"Authorization": "Bearer x"})
        assert "X-Frame-Options" not in res.headers


def test_custom_title_and_version():
    """App metadata is configurable."""
    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        app_title="My Auth API",
        app_version="9.9.9",
    )
    assert app.title == "My Auth API"
    assert app.version == "9.9.9"


def test_openapi_schema_is_generated():
    """The bundled routes produce a valid OpenAPI document."""
    app = setup(secret_key=VALID_SECRET, refresh_secret_key=VALID_REFRESH_SECRET)
    with TestClient(app) as client:
        schema = client.get("/openapi.json")
        assert schema.status_code == 200
        assert "/auth/login" in schema.json()["paths"]


def test_allowed_origins_are_applied():
    """Configured CORS origins appear on the middleware."""
    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        allowed_origins=["https://trusted.example.com"],
    )
    with TestClient(app) as client:
        res = client.get(
            "/auth/token/info",
            headers={"Authorization": "Bearer x", "Origin": "https://trusted.example.com"},
        )
        assert res.headers.get("access-control-allow-origin") == "https://trusted.example.com"


def test_custom_exception_handler_is_registered():
    """A caller-supplied handler replaces the built-in one for its status code."""

    from fastapi.responses import JSONResponse

    async def conflict_handler(request, exc):
        return JSONResponse(status_code=409, content={"error": "CUSTOM_CONFLICT"})

    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        include_ui=False,
        custom_exception_handlers={409: conflict_handler},
    )

    # The handler is registered on the app...
    assert app.exception_handlers[409] is conflict_handler

    # ...and is actually used when the app raises that status.
    @app.get("/boom")
    def boom():
        raise HTTPException(status_code=409, detail="conflict")

    with TestClient(app) as client:
        res = client.get("/boom")
        assert res.status_code == 409
        assert res.json()["error"] == "CUSTOM_CONFLICT"


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------


def test_startup_and_shutdown_hooks_run():
    """on_startup / on_shutdown are invoked around the app lifetime."""
    events: list[str] = []

    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        include_ui=False,
        on_startup=lambda: events.append("startup"),
        on_shutdown=lambda: events.append("shutdown"),
    )
    with TestClient(app):
        assert events == ["startup"]
    assert events == ["startup", "shutdown"]


def test_async_lifecycle_hooks_are_awaited():
    """Coroutine hooks are supported, not just plain callables."""
    events: list[str] = []

    async def async_startup():
        events.append("startup")

    async def async_shutdown():
        events.append("shutdown")

    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        include_ui=False,
        on_startup=async_startup,
        on_shutdown=async_shutdown,
    )
    with TestClient(app):
        assert events == ["startup"]
    assert events == ["startup", "shutdown"]


def test_custom_lifespan_replaces_the_default():
    """A caller-supplied lifespan takes over from the seeding lifespan."""
    events: list[str] = []

    @asynccontextmanager
    async def custom_lifespan(app):
        events.append("custom-start")
        yield
        events.append("custom-end")

    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        include_ui=False,
        lifespan=custom_lifespan,
    )
    with TestClient(app):
        assert events == ["custom-start"]
    assert events == ["custom-start", "custom-end"]


def test_container_is_attached_to_the_app():
    """setup() exposes the DI container as app.container."""
    app = setup(secret_key=VALID_SECRET, refresh_secret_key=VALID_REFRESH_SECRET)
    assert hasattr(app, "container")
    assert app.state.limiter is not None


def test_router_prefix_is_recorded_in_state():
    """The prefix is stored so templates can build correct links."""
    app = setup(
        secret_key=VALID_SECRET,
        refresh_secret_key=VALID_REFRESH_SECRET,
        router_prefix="/api",
    )
    assert app.state.router_prefix == "/api"


def test_package_data_paths_exist():
    """The bundled templates and static assets ship with the package."""
    package_dir = Path(__file__).resolve().parent.parent / "jwt_rbac"
    assert (package_dir / "templates" / "login.html").exists()
    assert (package_dir / "templates" / "dashboard.html").exists()
    assert (package_dir / "templates" / "admin.html").exists()
    assert (package_dir / "static" / "styles.css").exists()
