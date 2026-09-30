"""Unit tests for the token blacklist implementations.

The Redis implementation is exercised against a fake ``redis`` module so no
Redis server is required.
"""

import sys
import types

import pytest

from jwt_rbac.interfaces.token_blacklist import ITokenBlacklist
from jwt_rbac.repositories.memory_blacklist import MemoryTokenBlacklist
from jwt_rbac.repositories.redis_blacklist import RedisTokenBlacklist

# --------------------------------------------------------------------------
# MemoryTokenBlacklist
# --------------------------------------------------------------------------


def test_memory_blacklist_starts_empty():
    """A new in-memory blacklist contains no entries."""
    blacklist = MemoryTokenBlacklist()
    assert blacklist.is_blacklisted("anything") is False


def test_memory_blacklist_add_then_check():
    """A JTI added to the blacklist is subsequently reported as revoked."""
    blacklist = MemoryTokenBlacklist()
    blacklist.add("jti-123")
    assert blacklist.is_blacklisted("jti-123") is True


def test_memory_blacklist_keeps_entries_separate():
    """Adding one JTI does not revoke an unrelated one."""
    blacklist = MemoryTokenBlacklist()
    blacklist.add("jti-1")
    assert blacklist.is_blacklisted("jti-2") is False


def test_memory_blacklist_add_is_idempotent():
    """Adding the same JTI twice is harmless (set semantics)."""
    blacklist = MemoryTokenBlacklist()
    blacklist.add("jti-1")
    blacklist.add("jti-1")
    assert blacklist._blacklisted == {"jti-1"}


def test_memory_blacklist_implements_interface():
    """MemoryTokenBlacklist satisfies the ITokenBlacklist contract."""
    assert isinstance(MemoryTokenBlacklist(), ITokenBlacklist)


# --------------------------------------------------------------------------
# RedisTokenBlacklist
# --------------------------------------------------------------------------


class _FakeRedis:
    """Minimal stand-in for ``redis.Redis`` recording the calls it receives."""

    def __init__(self):
        self.store: dict[str, str] = {}
        self.ttls: dict[str, int] = {}
        self.calls: list[tuple] = []

    def setex(self, key, ttl, value):
        self.calls.append(("setex", key, ttl, value))
        self.store[key] = value
        self.ttls[key] = ttl

    def exists(self, key):
        self.calls.append(("exists", key))
        return 1 if key in self.store else 0


@pytest.fixture
def fake_redis(monkeypatch):
    """Install a fake ``redis`` module for the duration of a test."""
    fake = _FakeRedis()
    module = types.ModuleType("redis")
    module.Redis = _FakeRedis  # noqa: N815 - mirrors the real module attribute
    module.from_url = lambda url, **kwargs: fake
    monkeypatch.setitem(sys.modules, "redis", module)
    return fake


def test_redis_blacklist_uses_namespaced_key(fake_redis):
    """Entries are stored under a `blacklist:` prefixed key."""
    blacklist = RedisTokenBlacklist(redis_url="redis://localhost:6379/0")
    blacklist.add("jti-1")
    assert "blacklist:jti-1" in fake_redis.store


def test_redis_blacklist_sets_default_ttl(fake_redis):
    """Entries expire automatically using the documented 8-day default."""
    blacklist = RedisTokenBlacklist(redis_url="redis://localhost:6379/0")
    blacklist.add("jti-1")
    assert fake_redis.ttls["blacklist:jti-1"] == 691200


def test_redis_blacklist_honours_custom_ttl(fake_redis):
    """A custom ttl_seconds is used instead of the default."""
    blacklist = RedisTokenBlacklist(redis_url="redis://localhost:6379/0", ttl_seconds=60)
    blacklist.add("jti-1")
    assert fake_redis.ttls["blacklist:jti-1"] == 60


def test_redis_blacklist_is_blacklisted_after_add(fake_redis):
    """A JTI added to Redis is reported as revoked."""
    blacklist = RedisTokenBlacklist(redis_url="redis://localhost:6379/0")
    assert blacklist.is_blacklisted("jti-1") is False
    blacklist.add("jti-1")
    assert blacklist.is_blacklisted("jti-1") is True


def test_redis_blacklist_unknown_jti_is_false(fake_redis):
    """An unknown JTI is not reported as revoked."""
    blacklist = RedisTokenBlacklist(redis_url="redis://localhost:6379/0")
    assert blacklist.is_blacklisted("never-added") is False


def test_redis_blacklist_uses_exists_with_namespaced_key(fake_redis):
    """Lookups query Redis with the same namespaced key used for writes."""
    blacklist = RedisTokenBlacklist(redis_url="redis://localhost:6379/0")
    blacklist.is_blacklisted("jti-1")
    assert ("exists", "blacklist:jti-1") in fake_redis.calls


def test_redis_blacklist_implements_interface(fake_redis):
    """RedisTokenBlacklist satisfies the ITokenBlacklist contract."""
    blacklist = RedisTokenBlacklist(redis_url="redis://localhost:6379/0")
    assert isinstance(blacklist, ITokenBlacklist)


def test_redis_blacklist_state_is_shared_per_client(fake_redis):
    """Two blacklist objects on one client observe the same entries."""
    first = RedisTokenBlacklist(redis_url="redis://localhost:6379/0")
    second = RedisTokenBlacklist(redis_url="redis://localhost:6379/0")
    first.add("shared")
    assert second.is_blacklisted("shared") is True


# --------------------------------------------------------------------------
# Container selection
# --------------------------------------------------------------------------


def test_create_blacklist_returns_memory_when_no_redis_url(monkeypatch):
    """Without REDIS_URL the container wires up the in-memory blacklist."""
    from jwt_rbac import containers

    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setattr(
        "jwt_rbac.containers.get_settings",
        lambda: type("S", (), {"redis_url": None})(),
    )
    assert isinstance(containers._create_blacklist(), MemoryTokenBlacklist)


def test_create_blacklist_returns_redis_when_configured(monkeypatch, fake_redis):
    """With REDIS_URL set the container wires up the Redis blacklist."""
    from jwt_rbac import containers

    monkeypatch.setattr(
        "jwt_rbac.containers.get_settings",
        lambda: type("S", (), {"redis_url": "redis://localhost:6379/0"})(),
    )
    assert isinstance(containers._create_blacklist(), RedisTokenBlacklist)
