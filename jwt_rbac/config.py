"""Application configuration loaded from environment variables.

Settings are lazily initialized — they are not created until ``get_settings()``
is called or ``init_settings()`` is used by ``setup()``. This avoids
import-time failures when the package is used as a library.
"""

import logging
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

# Module-level settings reference — lazily populated
_settings: "Settings | None" = None


class Settings(BaseSettings):
    """Global application settings, populated from .env or environment."""

    secret_key: str = "your-super-secret-key-change-me-in-production"
    refresh_secret_key: str = "your-refresh-secret-key-change-in-prod"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    database_url: str = "sqlite:///./sql_app.db"
    redis_url: str | None = None
    allowed_origins: str = "http://localhost:3000,http://localhost:8000"
    jwt_issuer: str | None = None
    admin_email: str = "admin@example.com"
    admin_password: str = "changeme123"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


def get_settings() -> Settings:
    """Return the current settings instance, lazily creating one if needed.

    On first call (if ``init_settings`` was not called beforehand), a default
    ``Settings()`` is created from environment variables / ``.env`` file.

    Returns:
        The active Settings instance.
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def init_settings(**overrides: Any) -> Settings:
    """Initialize settings with programmatic overrides.

    Called by ``setup()`` to configure settings before any other module
    accesses them.  Values not provided fall through to environment
    variables / ``.env`` defaults.

    Args:
        **overrides: Any ``Settings`` field name with its desired value.
            Only non-``None`` values are applied.

    Returns:
        The newly created Settings instance.
    """
    global _settings
    # Filter out None values so env / defaults are used for unspecified fields
    filtered = {k: v for k, v in overrides.items() if v is not None}
    _settings = Settings(**filtered)
    return _settings
