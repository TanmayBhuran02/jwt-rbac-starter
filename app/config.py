"""Application configuration loaded from environment variables."""

import logging

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Global application settings, populated from .env or environment."""

    secret_key: str = "your-super-secret-key-change-me-in-production"
    refresh_secret_key: str = "your-refresh-secret-key-change-in-prod"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    database_url: str = "postgresql://postgres:root@localhost:5432/auth_db"
    redis_url: str | None = None
    allowed_origins: str = "http://localhost:3000,http://localhost:8000"
    jwt_issuer: str | None = None
    admin_email: str = "admin@example.com"
    admin_password: str = "changeme123"

    @model_validator(mode="after")
    def validate_secrets(self) -> "Settings":
        if len(self.secret_key) < 32:
            raise ValueError("secret_key must be at least 32 characters long")
        if len(self.refresh_secret_key) < 32:
            raise ValueError("refresh_secret_key must be at least 32 characters long")
        return self

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
