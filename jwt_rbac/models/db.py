"""Database engine and session factory.

Engine and session are lazily created on first access via ``get_engine()`` /
``get_session_local()``, so importing this module has no side effects.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from jwt_rbac.config import get_settings

Base = declarative_base()

# Module-level lazy singletons
_engine = None
_SessionLocal = None


def get_engine():
    """Return the SQLAlchemy engine, creating it on first call."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(
            settings.database_url,
            connect_args=(
                {"check_same_thread": False}
                if "sqlite" in settings.database_url
                else {}
            ),
        )
    return _engine


def get_session_local():
    """Return the session factory, creating it on first call."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=get_engine()
        )
    return _SessionLocal


# Keep backward-compatible aliases for existing code
def _get_engine_compat():
    return get_engine()


def _get_session_compat():
    return get_session_local()


# These properties exist so that code like `from jwt_rbac.models.db import engine`
# still works, but they are lazily resolved.
class _LazyEngine:
    """Proxy that defers engine creation until first attribute access."""

    def __getattr__(self, name):
        return getattr(get_engine(), name)

    def __repr__(self):
        return repr(get_engine())


class _LazySessionLocal:
    """Proxy that defers session factory creation until first call."""

    def __call__(self, *args, **kwargs):
        return get_session_local()(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(get_session_local(), name)


engine = _LazyEngine()
SessionLocal = _LazySessionLocal()


def get_db():
    """Yield a database session for FastAPI dependency injection."""
    db = get_session_local()()
    try:
        yield db
    finally:
        db.close()
