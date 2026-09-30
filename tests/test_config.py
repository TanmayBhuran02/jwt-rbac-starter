"""Unit tests for the lazily-initialized settings singleton.

These tests manipulate the module-level ``_settings`` global, so every test
restores the original value in teardown to keep the rest of the suite stable.
"""

import pytest

from jwt_rbac import config as config_module
from jwt_rbac.config import Settings, get_settings, init_settings


@pytest.fixture(autouse=True)
def restore_settings():
    """Snapshot and restore the module-level settings singleton."""
    original = config_module._settings
    yield
    config_module._settings = original


# --------------------------------------------------------------------------
# get_settings
# --------------------------------------------------------------------------


def test_get_settings_returns_settings_instance():
    """get_settings yields a Settings object."""
    assert isinstance(get_settings(), Settings)


def test_get_settings_is_a_singleton():
    """Repeated calls return the very same object (not a fresh copy)."""
    assert get_settings() is get_settings()


def test_get_settings_creates_instance_when_unset():
    """Calling get_settings with no prior init lazily builds the singleton."""
    config_module._settings = None
    created = get_settings()
    assert created is not None
    assert config_module._settings is created


def test_get_settings_does_not_overwrite_existing_instance():
    """An already-initialized singleton is returned unchanged."""
    existing = Settings(secret_key="a" * 40)
    config_module._settings = existing
    assert get_settings() is existing


# --------------------------------------------------------------------------
# init_settings
# --------------------------------------------------------------------------


def test_init_settings_applies_overrides():
    """Explicit overrides replace the corresponding defaults."""
    settings = init_settings(
        secret_key="x" * 40,
        access_token_expire_minutes=99,
    )
    assert settings.secret_key == "x" * 40
    assert settings.access_token_expire_minutes == 99


def test_init_settings_registers_the_singleton():
    """The new instance becomes the module-level settings object."""
    created = init_settings(secret_key="y" * 40)
    assert config_module._settings is created
    assert get_settings() is created


def test_init_settings_ignores_none_overrides():
    """A None override is dropped, so the field falls back to env/default.

    ``init_settings`` builds a brand-new ``Settings`` on every call, so
    "None is filtered out" means the keyword is never handed to the
    constructor — the field keeps its default (or env value) instead of
    becoming ``None``.
    """
    settings = init_settings(access_token_expire_minutes=None)
    assert settings.access_token_expire_minutes == 30  # model default
    assert settings.access_token_expire_minutes is not None


def test_init_settings_none_override_still_honours_environment(monkeypatch):
    """Passing None does not stop an environment variable from winning."""
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "77")
    settings = init_settings(access_token_expire_minutes=None)
    assert settings.access_token_expire_minutes == 77


def test_init_settings_with_no_arguments_returns_defaults():
    """Calling init_settings() with no kwargs yields a fresh default Settings.

    Each call constructs a new object, so values from a previous call are not
    carried over — that is the documented contract of ``init_settings``.
    """
    init_settings(secret_key="z" * 40)
    settings = init_settings()
    assert settings.secret_key == Settings.model_fields["secret_key"].default


def test_init_settings_can_replace_a_previous_value():
    """A later call overrides an earlier one."""
    init_settings(access_token_expire_minutes=10)
    assert init_settings(access_token_expire_minutes=20).access_token_expire_minutes == 20


# --------------------------------------------------------------------------
# Environment variable handling
# --------------------------------------------------------------------------


def test_environment_variables_are_read(monkeypatch):
    """Settings pick values up from the process environment."""
    monkeypatch.setenv("SECRET_KEY", "env-provided-secret-key-value-32ch")
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "45")

    settings = init_settings(secret_key=None, access_token_expire_minutes=None)
    assert settings.secret_key == "env-provided-secret-key-value-32ch"
    assert settings.access_token_expire_minutes == 45


def test_explicit_override_beats_environment(monkeypatch):
    """A programmatic override takes precedence over the environment."""
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "45")
    settings = init_settings(access_token_expire_minutes=7)
    assert settings.access_token_expire_minutes == 7


def test_optional_fields_default_to_none(monkeypatch):
    """Optional settings default to None so features stay opt-in."""
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("JWT_ISSUER", raising=False)
    settings = init_settings(redis_url=None, jwt_issuer=None)
    assert settings.redis_url is None
    assert settings.jwt_issuer is None


def test_allowed_origins_parsed_from_string(monkeypatch):
    """ALLOWED_ORIGINS is a comma-separated string on the Settings model."""
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://a.test,http://b.test")
    settings = init_settings(allowed_origins=None)
    assert settings.allowed_origins == "http://a.test,http://b.test"


def test_database_url_can_be_overridden():
    """database_url is a normal overridable field."""
    settings = init_settings(database_url="postgresql://u:p@localhost:5432/other_db")
    assert settings.database_url == "postgresql://u:p@localhost:5432/other_db"
