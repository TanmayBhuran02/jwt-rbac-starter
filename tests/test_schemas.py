"""Unit tests for the Pydantic request/response schemas."""

import pytest
from pydantic import ValidationError

from jwt_rbac.schemas.auth import (
    LoginRequest,
    PasswordChangeRequest,
    RefreshRequest,
    TokenInfo,
    TokenResponse,
)
from jwt_rbac.schemas.role import PermissionAssignment, PermissionOut, RoleOut
from jwt_rbac.schemas.user import RoleAssignment, UserCreate

# --------------------------------------------------------------------------
# UserCreate
# --------------------------------------------------------------------------


def test_user_create_accepts_valid_payload():
    """A valid email and 8+ character password is accepted."""
    user = UserCreate(email="new@example.com", password="password123")
    assert user.email == "new@example.com"
    assert user.role_name is None


def test_user_create_rejects_short_password():
    """Passwords shorter than 8 characters are rejected."""
    with pytest.raises(ValidationError):
        UserCreate(email="new@example.com", password="short")


def test_user_create_rejects_invalid_email():
    """A malformed email address is rejected."""
    with pytest.raises(ValidationError):
        UserCreate(email="not-an-email", password="password123")


def test_user_create_accepts_optional_role_name():
    """role_name may be supplied to pick the initial role."""
    user = UserCreate(email="mod@example.com", password="password123", role_name="MODERATOR")
    assert user.role_name == "MODERATOR"


def test_user_create_exposes_schema_descriptions():
    """Documented fields carry descriptions for the OpenAPI docs."""
    assert UserCreate.model_fields["email"].description


# --------------------------------------------------------------------------
# RoleAssignment
# --------------------------------------------------------------------------


def test_role_assignment_defaults_to_assign():
    """The action defaults to "assign"."""
    assert RoleAssignment(role_name="ADMIN").action == "assign"


def test_role_assignment_accepts_revoke():
    """The "revoke" action is a valid choice."""
    assert RoleAssignment(role_name="ADMIN", action="revoke").action == "revoke"


@pytest.mark.parametrize("action", ["delete", "ADMIN", "", "assign "])
def test_role_assignment_rejects_unknown_action(action):
    """Anything outside ^(assign|revoke)$ is rejected."""
    with pytest.raises(ValidationError):
        RoleAssignment(role_name="ADMIN", action=action)


def test_role_assignment_requires_role_name():
    """role_name is mandatory."""
    with pytest.raises(ValidationError):
        RoleAssignment()


# --------------------------------------------------------------------------
# PermissionAssignment
# --------------------------------------------------------------------------


def test_permission_assignment_accepts_names():
    """A non-empty list of permission names is accepted."""
    assignment = PermissionAssignment(permissions=["users:read", "users:write"])
    assert len(assignment.permissions) == 2


def test_permission_assignment_rejects_empty_list():
    """min_length=1 forbids an empty permission list."""
    with pytest.raises(ValidationError):
        PermissionAssignment(permissions=[])


# --------------------------------------------------------------------------
# Auth schemas
# --------------------------------------------------------------------------


def test_login_request_requires_both_fields():
    """Email and password are both mandatory."""
    with pytest.raises(ValidationError):
        LoginRequest(email="a@example.com")
    with pytest.raises(ValidationError):
        LoginRequest(password="password123")


def test_login_request_does_not_validate_email_format():
    """LoginRequest.email is a plain str — invalid addresses reach the service.

    Login failures must be reported generically, so the schema deliberately
    does not validate the address format here.
    """
    assert LoginRequest(email="not-an-email", password="password123").email == "not-an-email"


def test_token_response_defaults_to_bearer():
    """token_type defaults to "bearer"."""
    response = TokenResponse(access_token="a", refresh_token="r")
    assert response.token_type == "bearer"


def test_token_response_requires_both_tokens():
    """Both tokens are required."""
    with pytest.raises(ValidationError):
        TokenResponse(access_token="only-access")


def test_refresh_request_requires_token():
    """refresh_token is mandatory."""
    with pytest.raises(ValidationError):
        RefreshRequest()


def test_password_change_enforces_minimum_length():
    """The new password must be at least 8 characters."""
    with pytest.raises(ValidationError):
        PasswordChangeRequest(current_password="password123", new_password="short")


def test_password_change_accepts_valid_payload():
    """A compliant password change payload is accepted."""
    request = PasswordChangeRequest(current_password="password123", new_password="newpassword456")
    assert request.new_password == "newpassword456"


# --------------------------------------------------------------------------
# TokenInfo
# --------------------------------------------------------------------------


def test_token_info_maps_type_alias_to_token_type():
    """The JWT "type" claim is exposed as the token_type field."""
    info = TokenInfo(
        **{
            "sub": "user-1",
            "roles": ["USER"],
            "permissions": ["users:read"],
            "exp": 9999999999,
            "jti": "jti-1",
            "type": "access",
        }
    )
    assert info.token_type == "access"


def test_token_info_defaults_roles_and_permissions():
    """roles and permissions default to empty lists."""
    info = TokenInfo(**{"sub": "u", "exp": 1, "jti": "j", "type": "access"})
    assert info.roles == []
    assert info.permissions == []


def test_token_info_requires_core_claims():
    """sub, exp, jti and type are all required."""
    with pytest.raises(ValidationError):
        TokenInfo(**{"sub": "u"})


def test_token_info_issuer_is_optional():
    """The iss claim is optional."""
    info = TokenInfo(**{"sub": "u", "exp": 1, "jti": "j", "type": "refresh"})
    assert info.iss is None


# --------------------------------------------------------------------------
# Output schemas
# --------------------------------------------------------------------------


def test_role_out_from_attributes():
    """RoleOut can be built from an ORM-like object."""

    class FakeRole:
        id = 1
        name = "ADMIN"
        permissions = [type("P", (), {"id": 10, "name": "admin:access"})()]

    role = RoleOut.model_validate(FakeRole())
    assert role.name == "ADMIN"
    assert role.permissions[0].name == "admin:access"


def test_permission_out_from_attributes():
    """PermissionOut can be built from an ORM-like object."""

    class FakePermission:
        id = 5
        name = "users:read"

    assert PermissionOut.model_validate(FakePermission()).name == "users:read"


def test_role_out_permissions_default_to_empty():
    """permissions defaults to an empty list."""

    class FakeRole:
        id = 2
        name = "USER"
        permissions = []

    assert RoleOut.model_validate(FakeRole()).permissions == []
