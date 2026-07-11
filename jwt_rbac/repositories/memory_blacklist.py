"""In-memory token blacklist for single-process deployments."""

from jwt_rbac.interfaces.token_blacklist import ITokenBlacklist


class MemoryTokenBlacklist(ITokenBlacklist):
    """Set-backed in-memory token blacklist.

    Suitable for single-process / development use. Tokens are lost on restart.
    For production, use ``RedisTokenBlacklist`` instead.
    """

    def __init__(self) -> None:
        self._blacklisted: set[str] = set()

    def add(self, jti: str) -> None:
        """Add a token JTI to the in-memory set."""
        self._blacklisted.add(jti)

    def is_blacklisted(self, jti: str) -> bool:
        """Check whether a JTI exists in the in-memory set."""
        return jti in self._blacklisted
