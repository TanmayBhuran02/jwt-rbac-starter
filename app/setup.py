"""Setup entry point for configuring and initializing the FastAPI application."""

import inspect
import logging
from contextlib import asynccontextmanager

from dependency_injector import providers
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.containers import Container
from app.core.limiter import limiter
from app.interfaces.role_repository import IRoleRepository
from app.interfaces.user_repository import IUserRepository
from app.routers import admin, auth, ui, users

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown lifecycle."""
    # Seed default roles and permissions only if default SQL repository is used
    from app.repositories.sql_user_repo import SqlUserRepository

    user_repo = app.container.user_repository()
    if isinstance(user_repo, SqlUserRepository):
        from app.models.db import Base, SessionLocal, engine
        from app.models.role import Permission, Role

        Base.metadata.create_all(bind=engine)

        db = SessionLocal()
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

    yield


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


def setup(
    user_repository: IUserRepository = None,
    role_repository: IRoleRepository = None,
    include_ui: bool = True,
    router_prefix: str = "",
    secret_key: str = None,
    refresh_secret_key: str = None,
    token_expire_minutes: int = 30,
) -> FastAPI:
    """Configure, initialize, and return a FastAPI application.

    Args:
        user_repository: Optional custom user repository.
        role_repository: Optional custom role repository.
        include_ui: If True, include Jinja2 HTML template routes and mount static files.
        router_prefix: Prefix all endpoints (API and UI) with this path (e.g. "/api/v1").
        secret_key: JWT secret key (minimum 32 characters).
        refresh_secret_key: JWT refresh token secret key (minimum 32 characters).
        token_expire_minutes: Token expiration time in minutes.

    Returns:
        FastAPI application instance.
    """
    # 1. Validate secrets
    if secret_key is not None:
        if len(secret_key) < 32:
            raise ValueError("secret_key must be at least 32 characters long")
        settings.secret_key = secret_key
    else:
        if len(settings.secret_key) < 32:
            raise ValueError("secret_key must be at least 32 characters long")

    if refresh_secret_key is not None:
        if len(refresh_secret_key) < 32:
            raise ValueError("refresh_secret_key must be at least 32 characters long")
        settings.refresh_secret_key = refresh_secret_key
    else:
        if len(settings.refresh_secret_key) < 32:
            raise ValueError("refresh_secret_key must be at least 32 characters long")

    settings.access_token_expire_minutes = token_expire_minutes

    # 2. Validate repository interfaces if injected
    if user_repository is not None:
        _validate_repo_interface(user_repository, IUserRepository)
    if role_repository is not None:
        _validate_repo_interface(role_repository, IRoleRepository)

    # 3. Configure DI container
    container = Container()
    if user_repository is not None:
        container.user_repository.override(providers.Object(user_repository))
    if role_repository is not None:
        container.role_repository.override(providers.Object(role_repository))

    container.wire(
        modules=[
            "app.core.dependencies",
            "app.routers.auth",
            "app.routers.users",
            "app.routers.admin",
        ]
    )

    # 4. Initialize FastAPI
    app = FastAPI(
        title="JWT + RBAC Starter Kit",
        description="A production-ready authentication and role-based access control starter kit.",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.container = container

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
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins.split(",") if settings.allowed_origins else ["*"],
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

    # 5. Include routes
    app.include_router(auth.router, prefix=router_prefix)
    app.include_router(users.router, prefix=router_prefix)
    app.include_router(admin.router, prefix=router_prefix)

    if include_ui:
        app.mount("/static", StaticFiles(directory="app/static"), name="static")
        app.include_router(ui.router, prefix=router_prefix)

    return app
