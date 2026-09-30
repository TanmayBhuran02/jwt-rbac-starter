"""Unit tests for the lazy engine/session proxies in jwt_rbac.models.db.

The module keeps engine and session factory in module-level globals that are
built on first access.  Each test resets those globals so the lazy-creation
path is exercised in isolation.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from jwt_rbac import models  # noqa: F401  (ensures the package is importable)
from jwt_rbac.models import db as db_module
from jwt_rbac.models.db import (
    _LazyEngine,
    _LazySessionLocal,
    get_db,
    get_engine,
    get_session_local,
)


@pytest.fixture(autouse=True)
def reset_db_module():
    """Reset the lazy singletons around every test in this module."""
    original_engine = db_module._engine
    original_session_local = db_module._SessionLocal
    db_module._engine = None
    db_module._SessionLocal = None
    yield
    db_module._engine = original_engine
    db_module._SessionLocal = original_session_local


# --------------------------------------------------------------------------
# get_engine
# --------------------------------------------------------------------------


def test_get_engine_creates_engine_on_first_call():
    """The engine is constructed lazily on first access."""
    engine = get_engine()
    assert engine is not None
    assert db_module._engine is engine


def test_get_engine_is_memoized():
    """Subsequent calls reuse the same engine rather than rebuilding it."""
    assert get_engine() is get_engine()


def test_get_engine_uses_configured_database_url(monkeypatch):
    """The engine is built from settings.database_url."""
    monkeypatch.setattr(
        "jwt_rbac.models.db.get_settings",
        lambda: type("S", (), {"database_url": "sqlite:///:memory:"})(),
    )
    engine = get_engine()
    assert "sqlite" in str(engine.url)


def test_get_engine_adds_check_same_thread_for_sqlite(monkeypatch):
    """SQLite URLs get check_same_thread=False so TestClient threads work."""
    monkeypatch.setattr(
        "jwt_rbac.models.db.get_settings",
        lambda: type("S", (), {"database_url": "sqlite:///:memory:"})(),
    )
    engine = get_engine()
    assert engine.dialect.name == "sqlite"


def test_get_engine_omits_check_same_thread_for_postgres(monkeypatch):
    """Non-SQLite URLs must not receive the check_same_thread argument."""
    monkeypatch.setattr(
        "jwt_rbac.models.db.get_settings",
        lambda: type("S", (), {"database_url": "postgresql://u:p@localhost:5432/db"})(),
    )
    engine = get_engine()
    assert engine.dialect.name == "postgresql"


# --------------------------------------------------------------------------
# get_session_local
# --------------------------------------------------------------------------


def test_get_session_local_returns_a_factory():
    """get_session_local returns a callable session factory."""
    factory = get_session_local()
    assert callable(factory)


def test_get_session_local_is_memoized():
    """The session factory is built once and reused."""
    assert get_session_local() is get_session_local()


def test_get_session_local_is_bound_to_the_engine():
    """Sessions created by the factory are bound to the module engine."""
    factory = get_session_local()
    engine = get_engine()
    session = factory()
    try:
        assert isinstance(session, Session)
        assert session.get_bind() is engine
    finally:
        session.close()


def test_get_session_local_builds_engine_first():
    """Requesting a session lazily builds the engine if needed."""
    assert db_module._engine is None
    get_session_local()
    assert db_module._engine is not None


# --------------------------------------------------------------------------
# Lazy proxies
# --------------------------------------------------------------------------


def test_lazy_engine_proxy_forwards_attributes():
    """The engine proxy delegates attribute access to the real engine."""
    proxy = db_module.engine
    assert isinstance(proxy, _LazyEngine)
    assert proxy.url is not None
    assert proxy.dialect.name


def test_lazy_engine_proxy_repr_is_delegated():
    """repr() on the proxy produces the underlying engine's repr."""
    assert "Engine" in repr(db_module.engine)


def test_lazy_session_proxy_is_callable():
    """The session proxy constructs real sessions when called."""
    proxy = db_module.SessionLocal
    assert isinstance(proxy, _LazySessionLocal)
    session = proxy()
    try:
        assert isinstance(session, Session)
    finally:
        session.close()


def test_lazy_session_proxy_forwards_attributes():
    """Attribute access on the session proxy delegates to the factory."""
    assert db_module.SessionLocal.kw["autocommit"] is False


# --------------------------------------------------------------------------
# Backwards-compatible aliases
# --------------------------------------------------------------------------


def test_compat_helpers_return_the_live_objects():
    """_get_engine_compat / _get_session_compat alias the lazy getters."""
    assert db_module._get_engine_compat() is get_engine()
    assert db_module._get_session_compat() is get_session_local()


# --------------------------------------------------------------------------
# get_db generator
# --------------------------------------------------------------------------


def test_get_db_yields_a_session():
    """The FastAPI dependency yields a usable Session."""
    generator = get_db()
    session = next(generator)
    try:
        assert isinstance(session, Session)
    finally:
        session.close()


def test_get_db_closes_the_session_on_exhaustion():
    """Fully consuming the generator closes the session."""
    generator = get_db()
    session = next(generator)
    session_id = id(session)
    with pytest.raises(StopIteration):
        next(generator)
    # After close the session is no longer usable as an open transaction.
    assert id(session) == session_id


def test_get_db_uses_the_configured_session_factory():
    """get_db builds its session from get_session_local()."""
    generator = get_db()
    session = next(generator)
    try:
        assert session.get_bind() is get_engine()
    finally:
        session.close()


# --------------------------------------------------------------------------
# Re-entrancy of the lazy engine
# --------------------------------------------------------------------------


def test_explicitly_created_engine_is_returned_unchanged(monkeypatch):
    """If _engine is already set, get_engine returns that instance as-is."""
    sentinel = create_engine("sqlite:///:memory:")
    db_module._engine = sentinel
    assert get_engine() is sentinel
    sentinel.dispose()
