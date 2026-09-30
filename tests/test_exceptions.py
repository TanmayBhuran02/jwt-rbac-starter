"""Unit tests for the custom HTTP exceptions and the DB error decorator."""

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from jwt_rbac.core.exceptions import (
    CredentialsException,
    ForbiddenException,
    ServiceError,
    handle_db_exceptions,
)

# --------------------------------------------------------------------------
# Exception types
# --------------------------------------------------------------------------


def test_credentials_exception_defaults():
    """CredentialsException is a 401 with a Bearer challenge by default."""
    exc = CredentialsException()
    assert exc.status_code == 401
    assert exc.detail == "Could not validate credentials"
    assert exc.headers == {"WWW-Authenticate": "Bearer"}


def test_credentials_exception_custom_detail():
    """A custom detail is preserved."""
    exc = CredentialsException("Token has been revoked")
    assert exc.status_code == 401
    assert exc.detail == "Token has been revoked"
    assert exc.headers == {"WWW-Authenticate": "Bearer"}


def test_forbidden_exception_defaults():
    """ForbiddenException is a 403 with a default detail."""
    exc = ForbiddenException()
    assert exc.status_code == 403
    assert exc.detail == "Not enough permissions"


def test_forbidden_exception_custom_detail():
    """A custom detail is preserved on ForbiddenException."""
    exc = ForbiddenException("One of these roles required: ADMIN")
    assert exc.status_code == 403
    assert "ADMIN" in exc.detail


def test_service_error_defaults_to_500():
    """ServiceError defaults to a 500 with a generic message."""
    exc = ServiceError()
    assert exc.status_code == 500
    assert exc.detail == "An internal error occurred"


def test_service_error_accepts_custom_status_code():
    """ServiceError can carry an arbitrary status code (e.g. 404)."""
    exc = ServiceError(detail="Role not found", status_code=404)
    assert exc.status_code == 404
    assert exc.detail == "Role not found"


@pytest.mark.parametrize("exc_class", [CredentialsException, ForbiddenException, ServiceError])
def test_all_exceptions_are_http_exceptions(exc_class):
    """Every custom exception is usable with FastAPI's exception machinery."""
    assert issubclass(exc_class, HTTPException)


# --------------------------------------------------------------------------
# handle_db_exceptions
# --------------------------------------------------------------------------


def test_handle_db_exceptions_converts_sqlalchemy_error():
    """A SQLAlchemyError is converted into a 500 ServiceError."""

    @handle_db_exceptions
    def boom():
        raise SQLAlchemyError("query failed")

    with pytest.raises(ServiceError) as excinfo:
        boom()
    assert excinfo.value.status_code == 500
    assert excinfo.value.detail == "Database error occurred"


def test_handle_db_exceptions_converts_operational_error():
    """A specific SQLAlchemy subclass such as OperationalError is also caught."""

    @handle_db_exceptions
    def boom():
        raise OperationalError("SELECT 1", {}, Exception("connection lost"))

    with pytest.raises(ServiceError):
        boom()


def test_handle_db_exceptions_propagates_other_errors():
    """Non-database exceptions are not swallowed or rewritten."""
    sentinel = ValueError("business rule violated")

    @handle_db_exceptions
    def boom():
        raise sentinel

    with pytest.raises(ValueError) as excinfo:
        boom()
    # The original exception instance must survive untouched.
    assert excinfo.value is sentinel


def test_handle_db_exceptions_returns_value_on_success():
    """The wrapped function's return value passes through untouched."""

    @handle_db_exceptions
    def double(value):
        return value * 2

    assert double(21) == 42


def test_handle_db_exceptions_forwards_arguments():
    """Positional and keyword arguments are forwarded to the wrapped function."""

    @handle_db_exceptions
    def add(a, b, c=0):
        return a + b + c

    assert add(1, 2, c=3) == 6


def test_handle_db_exceptions_preserves_function_metadata():
    """functools.wraps keeps __name__ and __doc__ intact for introspection."""
    assert add_two.__name__ == "add_two"
    assert add_two.__doc__ == "Add two numbers."


@handle_db_exceptions
def add_two(a, b):
    """Add two numbers."""
    return a + b


def test_handle_db_exceptions_does_not_hide_http_exceptions():
    """An HTTPException raised inside a service passes through unwrapped."""

    @handle_db_exceptions
    def boom():
        raise ForbiddenException("nope")

    with pytest.raises(ForbiddenException):
        boom()
