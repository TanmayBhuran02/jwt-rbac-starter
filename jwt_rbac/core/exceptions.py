import functools
import logging

from fastapi import HTTPException, status
from sqlalchemy.exc import SQLAlchemyError


class CredentialsException(HTTPException):
    """Raised when authentication credentials are missing or invalid."""

    def __init__(self, detail: str = "Could not validate credentials") -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class ForbiddenException(HTTPException):
    """Raised when user lacks required role or permission."""

    def __init__(self, detail: str = "Not enough permissions") -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


class ServiceError(HTTPException):
    """Generic service-layer error wrapping unexpected exceptions."""

    def __init__(self, detail: str = "An internal error occurred", status_code: int = 500) -> None:
        super().__init__(status_code=status_code, detail=detail)


def handle_db_exceptions(func):
    """Decorator to wrap service methods, catch SQLAlchemyErrors, and raise ServiceError."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SQLAlchemyError as e:
            logging.getLogger(func.__module__).exception(
                "Database exception in %s: %s", func.__name__, e
            )
            raise ServiceError("Database error occurred")

    return wrapper
