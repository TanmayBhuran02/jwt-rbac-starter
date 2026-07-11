"""Redis-backed token blacklist for multi-process / production deployments.

Only imported when ``REDIS_URL`` is set in the environment.
"""

import logging

from jwt_rbac.interfaces.token_blacklist import ITokenBlacklist

logger = logging.getLogger(__name__)


class RedisTokenBlacklist(ITokenBlacklist):
    """Redis-backed token blacklist with automatic TTL expiry.

    Args:
        redis_url: The Redis connection URL (e.g. ``redis://localhost:6379/0``).
        ttl_seconds: Time-to-live for blacklisted entries; defaults to 8 days.
    """

    def __init__(self, redis_url: str, ttl_seconds: int = 691200) -> None:
        import redis

        self._client = redis.from_url(redis_url)
        self._ttl = ttl_seconds
        logger.info("Redis token blacklist connected to %s", redis_url)

    def add(self, jti: str) -> None:
        """Add a token JTI to Redis with automatic TTL expiry."""
        self._client.setex(f"blacklist:{jti}", self._ttl, "1")

    def is_blacklisted(self, jti: str) -> bool:
        """Check whether a JTI exists in Redis."""
        return self._client.exists(f"blacklist:{jti}") > 0
