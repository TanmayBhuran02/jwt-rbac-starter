"""Setup entry point for configuring and initializing the FastAPI application.

This is the primary integration API.  Call ``setup()`` with your desired
configuration to get a fully wired FastAPI application instance.
"""

import inspect
import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from dependency_injector import providers
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from jwt_rbac.config import get_settings, init_settings
from jwt_rbac.containers import Container
from jwt_rbac.core.limiter import limiter
from jwt_rbac.interfaces.role_repository import IRoleRepository
from jwt_rbac.interfaces.token_blacklist import ITokenBlacklist
from jwt_rbac.interfaces.user_repository import IUserRepository
from jwt_rbac.routers import admin, auth, users

logger = logging.getLogger(__name__)

_PACKAGE_DIR = Path(__file__).resolve().parent


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


@asynccontextmanager
async def _default_lifespan(app: FastAPI):
    """Application startup/shutdown lifecycle.

    Seeds default roles and permissions when the default SQL repository is
    in use.  Skipped entirely for custom repository implementations.
    """
    from jwt_rbac.repositories.sql_user_repo import SqlUserRepository

    user_repo = app.container.user_repository()
    if isinstance(user_repo, SqlUserRepository):
        from jwt_rbac.models.db import Base, get_engine, get_session_local
        from jwt_rbac.models.role import Permission, Role

        Base.metadata.create_all(bind=get_engine())

        db = get_session_local()()
        try:
            if not db.query(Role).first():
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
                logger.info("Seeded default roles and permissions in SQL database")
        finally:
            db.close()

    # Execute user-provided startup hook if present
    startup_hook = getattr(app.state, "_on_startup", None)
    if startup_hook:
        await startup_hook() if inspect.iscoroutinefunction(startup_hook) else startup_hook()

    yield

    # Execute user-provided shutdown hook if present
    shutdown_hook = getattr(app.state, "_on_shutdown", None)
    if shutdown_hook:
        await shutdown_hook() if inspect.iscoroutinefunction(shutdown_hook) else shutdown_hook()


def _validate_repo_interface(repo_instance, expected_interface: type):
    """Check if a repository instance implements all expected abstract methods."""
    missing_methods = []

    # Get all abstract methods of the expected interface
    abstract_methods = getattr(expected_interface, "__abstractmethods__", set())
    if not abstract_methods:
        abstract_methods = {
            name
            for name, val in inspect.getmembers(expected_interface)
            if getattr(val, "__isabstractmethod__", False)
        }

    for method_name in abstract_methods:
        if not hasattr(repo_instance, method_name):
            missing_methods.append(method_name)
            continue

        attr = getattr(repo_instance, method_name)
        if not callable(attr):
            missing_methods.append(method_name)
            continue

        # If it's a class or instance, verify the method isn't still abstract
        cls = repo_instance if inspect.isclass(repo_instance) else repo_instance.__class__
        class_attr = getattr(cls, method_name, None)
        if getattr(class_attr, "__isabstractmethod__", False):
            missing_methods.append(method_name)

    if missing_methods:
        raise TypeError(
            f"Injected repository {repo_instance.__class__.__name__} is missing the following "
            f"required abstract methods of {expected_interface.__name__}: {', '.join(missing_methods)}"
        )


def _create_ui_router(templates_dir: Path) -> APIRouter:
    """Create the UI router with templates from the given directory.

    Args:
        templates_dir: Path to the Jinja2 templates directory.

    Returns:
        A configured APIRouter serving HTML template routes.
    """
    from fastapi.templating import Jinja2Templates

    router = APIRouter(tags=["ui"])
    templates = Jinja2Templates(directory=str(templates_dir))

    @router.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index(request: Request):
        """Login page."""
        return templates.TemplateResponse("login.html", {"request": request})

    @router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    def dashboard(request: Request):
        """Dashboard page."""
        return templates.TemplateResponse("dashboard.html", {"request": request})

    @router.get("/admin-panel", response_class=HTMLResponse, include_in_schema=False)
    def admin_panel(request: Request):
        """Admin panel page."""
        return templates.TemplateResponse("admin.html", {"request": request})

    return router


def setup(
    # --- Repository injection ---
    user_repository: IUserRepository | None = None,
    role_repository: IRoleRepository | None = None,
    token_blacklist: ITokenBlacklist | None = None,
    # --- UI / frontend ---
    include_ui: bool = True,
    frontend_dir: str | None = None,
    # --- Routing ---
    router_prefix: str = "",
    additional_routers: list[APIRouter] | None = None,
    # --- JWT / auth ---
    secret_key: str | None = None,
    refresh_secret_key: str | None = None,
    algorithm: str = "HS256",
    token_expire_minutes: int = 30,
    refresh_token_expire_days: int = 7,
    jwt_issuer: str | None = None,
    # --- Database ---
    database_url: str | None = None,
    # --- Security ---
    allowed_origins: list[str] | None = None,
    rate_limit: str | None = "5/minute",
    security_headers: bool = True,
    # --- FastAPI metadata ---
    app_title: str = "JWT + RBAC Starter Kit",
    app_version: str = "1.0.0",
    # --- Lifecycle hooks ---
    lifespan: Any | None = None,
    on_startup: Callable | None = None,
    on_shutdown: Callable | None = None,
    # --- Advanced ---
    custom_exception_handlers: dict | None = None,
) -> FastAPI:
    """Configure, initialize, and return a FastAPI application.

    This is the main entry point for integrating jwt-rbac-starter into your
    project.  All parameters are optional — sensible defaults are provided
    and environment variables / ``.env`` files are used as fallbacks.

    Args:
        user_repository: Optional custom user repository implementing ``IUserRepository``.
        role_repository: Optional custom role repository implementing ``IRoleRepository``.
        token_blacklist: Optional custom token blacklist implementing ``ITokenBlacklist``.
            When not provided, auto-selects Redis (if ``REDIS_URL`` is set) or in-memory.
        include_ui: If True, include Jinja2 HTML template routes and mount static files.
        frontend_dir: Path to a custom frontend directory containing ``templates/``
            and optionally ``static/`` subdirectories.  When None, uses the bundled
            default templates.
        router_prefix: Prefix all endpoints (API and UI) with this path (e.g. "/api/v1").
        additional_routers: Extra ``APIRouter`` instances to include in the app.
        secret_key: JWT secret key (minimum 32 characters).
        refresh_secret_key: JWT refresh token secret key (minimum 32 characters).
        algorithm: JWT signing algorithm (default: "HS256").
        token_expire_minutes: Access token expiration time in minutes.
        refresh_token_expire_days: Refresh token expiration time in days.
        jwt_issuer: JWT issuer claim (validated when set).
        database_url: SQLAlchemy database connection string.
        allowed_origins: List of CORS allowed origins.
        rate_limit: Login rate limit string (e.g. "5/minute") or None to disable.
        security_headers: If True, add X-Content-Type-Options, X-Frame-Options, etc.
        app_title: FastAPI application title.
        app_version: FastAPI application version string.
        lifespan: Custom async context manager for app lifecycle.
            When provided, replaces the default lifespan (which auto-seeds roles).
        on_startup: Async or sync callable to run at startup (used with the default lifespan).
        on_shutdown: Async or sync callable to run at shutdown (used with the default lifespan).
        custom_exception_handlers: Dict of ``{status_code_or_exception: handler}`` to
            override or extend the default error handlers.

    Returns:
        A fully configured FastAPI application instance.
    """
    # 1. Initialize settings — programmatic values override env / .env
    init_settings(
        secret_key=secret_key,
        refresh_secret_key=refresh_secret_key,
        algorithm=algorithm,
        access_token_expire_minutes=token_expire_minutes,
        refresh_token_expire_days=refresh_token_expire_days,
        database_url=database_url,
        jwt_issuer=jwt_issuer,
        allowed_origins=",".join(allowed_origins) if allowed_origins else None,
    )
    settings = get_settings()

    # 2. Validate secrets
    if len(settings.secret_key) < 32:
        raise ValueError("secret_key must be at least 32 characters long")
    if len(settings.refresh_secret_key) < 32:
        raise ValueError("refresh_secret_key must be at least 32 characters long")

    # 3. Validate repository interfaces if injected
    if user_repository is not None:
        _validate_repo_interface(user_repository, IUserRepository)
    if role_repository is not None:
        _validate_repo_interface(role_repository, IRoleRepository)
    if token_blacklist is not None:
        _validate_repo_interface(token_blacklist, ITokenBlacklist)

    # 4. Configure DI container
    container = Container()
    if user_repository is not None:
        container.user_repository.override(providers.Object(user_repository))
    if role_repository is not None:
        container.role_repository.override(providers.Object(role_repository))
    if token_blacklist is not None:
        container.token_blacklist.override(providers.Object(token_blacklist))

    container.wire(
        modules=[
            "jwt_rbac.core.dependencies",
            "jwt_rbac.routers.auth",
            "jwt_rbac.routers.users",
            "jwt_rbac.routers.admin",
        ]
    )

    # 5. Configure rate limiter
    if rate_limit is None:
        limiter.enabled = False

    # 6. Initialize FastAPI
    chosen_lifespan = lifespan if lifespan is not None else _default_lifespan
    app = FastAPI(
        title=app_title,
        description="A production-ready authentication and role-based access control starter kit.",
        version=app_version,
        lifespan=chosen_lifespan,
    )
    app.container = container

    # Store hooks for the default lifespan to use
    app.state._on_startup = on_startup
    app.state._on_shutdown = on_shutdown

    # Store router_prefix in app.state so templates can access it
    app.state.router_prefix = router_prefix

    # State for rate limiter
    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={
                "error": "RATE_LIMITED",
                "message": f"Rate limit exceeded: {exc.detail}",
                "status": 429,
            },
        )

    # Middleware
    if security_headers:
        app.add_middleware(SecurityHeadersMiddleware)

    cors_origins = (
        allowed_origins
        if allowed_origins
        else (settings.allowed_origins.split(",") if settings.allowed_origins else ["*"])
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Consistent JSON error envelope handlers
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        error_map = {
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            400: "BAD_REQUEST",
            422: "VALIDATION_ERROR",
            429: "RATE_LIMITED",
            500: "INTERNAL_ERROR",
        }
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": error_map.get(exc.status_code, "ERROR"),
                "message": exc.detail,
                "status": exc.status_code,
            },
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = []
        for err in exc.errors():
            errors.append(
                {
                    "field": " → ".join(str(loc) for loc in err.get("loc", [])),
                    "message": err.get("msg", ""),
                    "type": err.get("type", ""),
                }
            )
        return JSONResponse(
            status_code=422,
            content={
                "error": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "status": 422,
                "details": errors,
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception: %s", exc)
        return JSONResponse(
            status_code=500,
            content={
                "error": "INTERNAL_ERROR",
                "message": "An internal error occurred",
                "status": 500,
            },
        )

    # Apply custom exception handlers (override or extend)
    if custom_exception_handlers:
        for exc_class_or_code, handler in custom_exception_handlers.items():
            app.add_exception_handler(exc_class_or_code, handler)

    # 7. Include routes
    app.include_router(auth.router, prefix=router_prefix)
    app.include_router(users.router, prefix=router_prefix)
    app.include_router(admin.router, prefix=router_prefix)

    # Include additional user-provided routers
    if additional_routers:
        for extra_router in additional_routers:
            app.include_router(extra_router, prefix=router_prefix)

    # 8. Mount frontend
    if include_ui:
        if frontend_dir is not None:
            # User-provided frontend directory
            frontend_path = Path(frontend_dir)
            templates_dir = frontend_path / "templates"
            static_dir = frontend_path / "static"
        else:
            # Bundled default frontend
            templates_dir = _PACKAGE_DIR / "templates"
            static_dir = _PACKAGE_DIR / "static"

        if static_dir.exists():
            app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        ui_router = _create_ui_router(templates_dir)
        app.include_router(ui_router, prefix=router_prefix)

    return app
