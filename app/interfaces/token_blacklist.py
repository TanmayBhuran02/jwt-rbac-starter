"""Abstract interface for token blacklisting."""

from abc import ABC, abstractmethod


class ITokenBlacklist(ABC):
    """Interface for JWT token blacklist storage.

    Implementations must provide thread-safe ``add`` and ``is_blacklisted`` methods.
    """

    @abstractmethod
    def add(self, jti: str) -> None:
        """Add a token JTI to the blacklist.

        Args:
            jti: The JWT ID to blacklist.
        """
        ...

    @abstractmethod
    def is_blacklisted(self, jti: str) -> bool:
        """Check whether a token JTI has been blacklisted.

        Args:
            jti: The JWT ID to check.

        Returns:
            True if the token is blacklisted, False otherwise.
        """
        ...
