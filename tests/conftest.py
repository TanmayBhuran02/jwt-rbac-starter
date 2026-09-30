"""Shared test fixtures for the JWT + RBAC starter kit.

The suite runs against a **real PostgreSQL instance** — there is no SQLite
fallback.  Point ``TEST_DATABASE_URL`` at a dedicated throwaway database::

    createdb -h localhost -U postgres jwt_rbac_test

If PostgreSQL is unreachable the session aborts with a hard
``pytest.UsageError`` explaining how to fix it, rather than silently skipping
tests.

Isolation strategy
------------------
The schema is created once per session on a *committed* connection.  Each test
then runs inside its own outer transaction that is rolled back during teardown.
Sessions are bound to that connection with
``join_transaction_mode="create_savepoint"``, so the ``db.commit()`` calls made
by the application under test become savepoints rather than real commits.  The
result is full per-test isolation at negligible cost, and the schema survives
every rollback.
"""

import os

import pytest
from dependency_injector import providers
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from jwt_rbac.main import app
from jwt_rbac.models.db import Base
from jwt_rbac.models.role import Permission, Role
from jwt_rbac.models.user import User
from jwt_rbac.repositories.memory_blacklist import MemoryTokenBlacklist

# --------------------------------------------------------------------------
# Database configuration
# --------------------------------------------------------------------------

DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:root@localhost:5432/jwt_rbac_test"

# Reference data seeded once for the whole session.
SEED_PERMISSIONS = ["users:read", "users:write", "admin:access", "reports:read"]
SEED_ROLES: dict[str, list[str]] = {
    "ADMIN": ["users:read", "users:write", "admin:access", "reports:read"],
    "USER": ["users:read"],
    "MODERATOR": ["users:read", "users:write", "reports:read"],
}

# Cross-fixture state, populated by the session fixture.
_STATE: dict = {}


def get_test_database_url() -> str:
    """Resolve the test database URL from the environment.

    Returns:
        The ``TEST_DATABASE_URL`` value, or the documented default when unset.
    """
    return os.getenv("TEST_DATABASE_URL", "").strip() or DEFAULT_TEST_DATABASE_URL


def _require_driver() -> None:
    """Abort with an actionable message if the PostgreSQL driver is missing."""
    try:
        import psycopg2  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise pytest.UsageError(
            "The PostgreSQL driver is required to run the test suite.\n"
            'Install it with:  pip install -e ".[dev]"\n'
            "(psycopg2-binary is part of the `dev` extra in pyproject.toml)."
        ) from exc


def _probe(url: str) -> None:
    """Verify the test database is reachable, aborting the session if not.

    Raises:
        pytest.UsageError: If the database cannot be connected to.
    """
    _require_driver()

    probe_engine = create_engine(url, poolclass=None)
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        raise pytest.UsageError(
            "Cannot connect to the test PostgreSQL database:\n"
            f"    {url}\n\n"
            "PostgreSQL is REQUIRED — this suite has no SQLite fallback.\n"
            "Fix it with either:\n"
            "    1. Start a server and create the database:\n"
            "         docker compose up -d db\n"
            "         createdb -h localhost -U postgres jwt_rbac_test\n"
            "    2. Or point TEST_DATABASE_URL at an existing database:\n"
            "         set TEST_DATABASE_URL=postgresql://user:pass@host:5432/db\n\n"
            f"Underlying error: {exc.orig or exc}"
        ) from exc
    finally:
        probe_engine.dispose()


def _terminate_stray_backends(url: str) -> None:
    """Force-close any connection still attached to the test database.

    A container built through ``setup()`` owns its own ``db_session``
    ``Resource``.  If such a container is discarded without being shut down,
    its session — and therefore its checked-out connection — is never
    released.  That connection stays ``idle in transaction`` holding locks,
    which would make the final ``DROP TABLE`` block forever.  Terminating
    stragglers from a maintenance connection guarantees teardown terminates.

    Errors are swallowed: cleanup is best-effort and must never mask the real
    test results.
    """
    try:
        url_obj = make_url(url)
        db_name = url_obj.database
        if not db_name:
            return

        # Connect to the default maintenance database on the same server.
        maintenance_url = url_obj.set(database="postgres")
        admin_engine = create_engine(maintenance_url, poolclass=None, isolation_level="AUTOCOMMIT")
        try:
            with admin_engine.connect() as conn:
                conn.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname = :dbname AND pid <> pg_backend_pid()"
                    ),
                    {"dbname": db_name},
                )
        finally:
            admin_engine.dispose()
    except Exception:  # pragma: no cover - best-effort cleanup
        pass


# Fail fast at import time — before any test module is imported — so a missing
# database produces one clear error instead of dozens of confusing failures.
_probe(get_test_database_url())


# --------------------------------------------------------------------------
# Session-scoped schema
# --------------------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Create the schema once, seed reference data, and patch the app container.

    The schema is created on a plain committed connection so that it is not
    affected by the per-test rollbacks.  The application's lazy engine/session
    singletons are then pointed at this engine so that code paths bypassing the
    DI container (notably the startup lifespan) also hit the test database.
    """
    from jwt_rbac.config import init_settings
    from jwt_rbac.models import db as db_module

    url = get_test_database_url()

    # Release anything left over from a previous, interrupted run before we
    # try to drop the schema.
    _terminate_stray_backends(url)

    # A generous pool keeps the suite fast; `pool_pre_ping` guards against
    # connections dropped by the server between tests.
    engine = create_engine(url, future=True, pool_size=10, max_overflow=20, pool_pre_ping=True)

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    # Seed permissions and roles using a separate, committed session.
    seed_session = sessionmaker(bind=engine, future=True)()
    try:
        perms: dict[str, Permission] = {}
        for name in SEED_PERMISSIONS:
            perm = Permission(name=name)
            seed_session.add(perm)
            perms[name] = perm
        seed_session.commit()

        for role_name, perm_names in SEED_ROLES.items():
            role = Role(name=role_name, permissions=[perms[n] for n in perm_names])
            seed_session.add(role)
        seed_session.commit()
    finally:
        seed_session.close()

    # Point the app's lazy engine/session singletons at the test database so
    # _default_lifespan() and seed() never touch the real DATABASE_URL.
    original_engine = db_module._engine
    original_session_local = db_module._SessionLocal
    db_module._engine = engine
    db_module._SessionLocal = sessionmaker(bind=engine, future=True)

    # Also point the application settings at the test database.
    init_settings(database_url=url)

    # Override the token blacklist once for the whole session.  The db_session
    # override is *not* installed here — it must be re-bound for every test by
    # the `db_session` fixture, because a cached provider would hand out a
    # stale session belonging to a previous (already rolled back) test.
    blacklist = MemoryTokenBlacklist()
    app.container.token_blacklist.override(providers.Object(blacklist))

    _STATE.update(engine=engine, blacklist=blacklist, url=url)

    yield

    # --- Teardown -------------------------------------------------------
    app.container.token_blacklist.reset_override()

    db_module._engine = original_engine
    db_module._SessionLocal = original_session_local

    # Drop the pool, evict any connection still checked out by a container
    # that was never shut down, then remove the schema.
    engine.dispose()
    _terminate_stray_backends(url)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    _STATE.clear()


# --------------------------------------------------------------------------
# Per-test transaction isolation
# --------------------------------------------------------------------------


@pytest.fixture
def db_session():
    """Provide a session bound to the per-test transaction.

    Any writes performed by the test (or by application code running during
    the test) are visible through this session and are rolled back afterwards.
    """
    engine = _STATE["engine"]

    connection = engine.connect()
    outer_transaction = connection.begin()
    session = sessionmaker(
        bind=connection,
        autocommit=False,
        autoflush=False,
        future=True,
        join_transaction_mode="create_savepoint",
    )()

    # Point the DI container at *this* test's session so that application code
    # shares the transaction and every write is undone during teardown.  The
    # override is re-installed per test (never cached) so no test can inherit
    # a session whose transaction has already been rolled back.
    app.container.db_session.override(providers.Object(session))

    try:
        yield session
    finally:
        app.container.db_session.reset_override()
        session.close()
        if outer_transaction.is_active:
            outer_transaction.rollback()
        connection.close()


def _reset_limiter(enabled: bool = False) -> None:
    """Put the shared slowapi limiter back to a known state.

    The limiter is a module-level singleton whose counters live in process
    memory, so its state survives between tests.  Left alone, a test that
    deliberately exhausts the 5/minute login budget would make every later
    login return 429.  Resetting both the counters and the enabled flag keeps
    each test independent.
    """
    from jwt_rbac.core.limiter import limiter

    limiter.reset()
    limiter.enabled = enabled


@pytest.fixture(autouse=True)
def clean_state(db_session):
    """Reset per-test mutable state shared across tests.

    The database transaction is rolled back by ``db_session``.  This fixture
    additionally clears the in-memory token blacklist and the rate limiter so
    no state can leak from one test into the next.
    """
    _reset_limiter(enabled=False)
    yield
    blacklist = _STATE.get("blacklist")
    if blacklist is not None:
        blacklist._blacklisted.clear()
    _reset_limiter(enabled=False)


@pytest.fixture
def client():
    """Provide a test client for the FastAPI app.

    Rate limiting is disabled for the duration of the test so requests never
    collide with the 5/minute login budget.  Tests that specifically exercise
    the limiter re-enable it themselves; ``clean_state`` restores it either way.
    """
    _reset_limiter(enabled=False)
    with TestClient(app) as c:
        yield c


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


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
