"""API tests for the admin router."""

import uuid

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient

from jwt_rbac.core.dependencies import require_permission
from jwt_rbac.main import app
from jwt_rbac.models.role import Role
from tests.conftest import (
    get_auth_header,
    login_user,
    make_admin,
    make_moderator,
    register_user,
)


@pytest.fixture
def admin_token(client, db_session):
    """Register a user, promote it to ADMIN, and return its access token."""
    data = register_user(client, "admin_api@example.com")
    make_admin(db_session, data["id"])
    return login_user(client, "admin_api@example.com")["access_token"]


@pytest.fixture
def user_token(client):
    """Register and log in an ordinary USER."""
    register_user(client, "plain_api@example.com")
    return login_user(client, "plain_api@example.com")["access_token"]


# --------------------------------------------------------------------------
# Authorization
# --------------------------------------------------------------------------


def test_admin_endpoints_require_authentication(client):
    """Every admin endpoint rejects anonymous callers with 401."""
    for method, path in [
        ("get", "/admin/users"),
        ("get", "/admin/roles"),
        ("get", "/admin/permissions"),
    ]:
        res = getattr(client, method)(path)
        assert res.status_code == 401, path
        assert res.json()["error"] == "UNAUTHORIZED"


def test_admin_endpoints_reject_normal_users(client, user_token):
    """A USER without the ADMIN role gets 403."""
    headers = get_auth_header(user_token)
    for path in ["/admin/users", "/admin/roles", "/admin/permissions"]:
        res = client.get(path, headers=headers)
        assert res.status_code == 403, path
        assert res.json()["error"] == "FORBIDDEN"


# --------------------------------------------------------------------------
# GET /admin/users
# --------------------------------------------------------------------------


def test_list_users_returns_every_user(client, admin_token, db_session):
    """GET /admin/users lists all registered users."""
    register_user(client, "listed_a@example.com")
    register_user(client, "listed_b@example.com")

    res = client.get("/admin/users", headers=get_auth_header(admin_token))
    assert res.status_code == 200

    emails = {u["email"] for u in res.json()}
    assert {"listed_a@example.com", "listed_b@example.com"} <= emails


def test_list_users_never_exposes_password_hashes(client, admin_token):
    """The user listing contains no credential material."""
    res = client.get("/admin/users", headers=get_auth_header(admin_token))
    assert all("hashed_password" not in user for user in res.json())


# --------------------------------------------------------------------------
# GET /admin/roles and /admin/permissions
# --------------------------------------------------------------------------


def test_list_roles_returns_seeded_roles(client, admin_token):
    """GET /admin/roles returns the seeded roles with their permissions."""
    res = client.get("/admin/roles", headers=get_auth_header(admin_token))
    assert res.status_code == 200

    roles = {r["name"]: r for r in res.json()}
    assert {"ADMIN", "USER", "MODERATOR"} <= set(roles)
    assert {p["name"] for p in roles["ADMIN"]["permissions"]} >= {"users:read", "admin:access"}


def test_list_permissions_returns_seeded_permissions(client, admin_token):
    """GET /admin/permissions returns the four seeded permissions."""
    res = client.get("/admin/permissions", headers=get_auth_header(admin_token))
    assert res.status_code == 200
    assert {p["name"] for p in res.json()} >= {
        "users:read",
        "users:write",
        "admin:access",
        "reports:read",
    }


# --------------------------------------------------------------------------
# POST /admin/users/{id}/roles
# --------------------------------------------------------------------------


def test_assign_role_via_api(client, admin_token, db_session):
    """An admin can assign a role to another user."""
    target = register_user(client, "assign_api@example.com")

    res = client.post(
        f"/admin/users/{target['id']}/roles",
        json={"role_name": "MODERATOR", "action": "assign"},
        headers=get_auth_header(admin_token),
    )
    assert res.status_code == 200
    assert "MODERATOR" in res.json()["message"]


def test_revoke_role_via_api(client, admin_token):
    """An admin can revoke a previously assigned role."""
    target = register_user(client, "revoke_api@example.com")
    client.post(
        f"/admin/users/{target['id']}/roles",
        json={"role_name": "MODERATOR", "action": "assign"},
        headers=get_auth_header(admin_token),
    )

    res = client.post(
        f"/admin/users/{target['id']}/roles",
        json={"role_name": "MODERATOR", "action": "revoke"},
        headers=get_auth_header(admin_token),
    )
    assert res.status_code == 200
    assert "revoked" in res.json()["message"]


def test_assign_role_to_unknown_user_returns_404(client, admin_token):
    """Assigning a role to a missing user produces a 404."""
    res = client.post(
        f"/admin/users/{uuid.uuid4()}/roles",
        json={"role_name": "USER", "action": "assign"},
        headers=get_auth_header(admin_token),
    )
    assert res.status_code == 404
    assert res.json()["error"] == "NOT_FOUND"


def test_assign_unknown_role_returns_404(client, admin_token):
    """Assigning a role that does not exist produces a 404."""
    target = register_user(client, "badrole_api@example.com")

    res = client.post(
        f"/admin/users/{target['id']}/roles",
        json={"role_name": "NOT_A_ROLE", "action": "assign"},
        headers=get_auth_header(admin_token),
    )
    assert res.status_code == 404
    assert "NOT_A_ROLE" in res.json()["message"]


def test_invalid_action_is_rejected(client, admin_token):
    """An action outside assign|revoke fails schema validation with 422."""
    target = register_user(client, "badaction_api@example.com")

    res = client.post(
        f"/admin/users/{target['id']}/roles",
        json={"role_name": "USER", "action": "obliterate"},
        headers=get_auth_header(admin_token),
    )
    assert res.status_code == 422
    assert res.json()["error"] == "VALIDATION_ERROR"


# --------------------------------------------------------------------------
# PATCH /admin/users/{id}/toggle-active
# --------------------------------------------------------------------------


def test_toggle_active_deactivates_then_activates(client, admin_token):
    """Toggling flips is_active both ways."""
    target = register_user(client, "toggle_api@example.com")

    res = client.patch(
        f"/admin/users/{target['id']}/toggle-active", headers=get_auth_header(admin_token)
    )
    assert res.status_code == 200
    assert res.json()["is_active"] is False

    res = client.patch(
        f"/admin/users/{target['id']}/toggle-active", headers=get_auth_header(admin_token)
    )
    assert res.json()["is_active"] is True


def test_toggle_active_unknown_user_returns_404(client, admin_token):
    """Toggling a missing user produces a 404."""
    res = client.patch(
        f"/admin/users/{uuid.uuid4()}/toggle-active", headers=get_auth_header(admin_token)
    )
    assert res.status_code == 404


def test_deactivated_user_loses_admin_access(client, admin_token, db_session):
    """Deactivating an admin immediately revokes their access."""
    victim_data = register_user(client, "exadmin_api@example.com")
    make_admin(db_session, victim_data["id"])
    victim_token = login_user(client, "exadmin_api@example.com")["access_token"]

    assert client.get("/admin/users", headers=get_auth_header(victim_token)).status_code == 200

    client.patch(
        f"/admin/users/{victim_data['id']}/toggle-active",
        headers=get_auth_header(admin_token),
    )
    assert client.get("/admin/users", headers=get_auth_header(victim_token)).status_code == 401


# --------------------------------------------------------------------------
# PUT /admin/roles/{id}/permissions
# --------------------------------------------------------------------------


def test_set_role_permissions_replaces_set(client, admin_token, db_session):
    """PUT replaces every permission on the target role."""
    user_role = db_session.query(Role).filter(Role.name == "USER").first()

    res = client.put(
        f"/admin/roles/{user_role.id}/permissions",
        json={"permissions": ["admin:access", "reports:read"]},
        headers=get_auth_header(admin_token),
    )
    assert res.status_code == 200
    assert {p["name"] for p in res.json()["permissions"]} == {"admin:access", "reports:read"}


def test_set_role_permissions_unknown_role_returns_404(client, admin_token):
    """Updating a non-existent role produces a 404."""
    res = client.put(
        "/admin/roles/999999/permissions",
        json={"permissions": ["users:read"]},
        headers=get_auth_header(admin_token),
    )
    assert res.status_code == 404


def test_set_role_permissions_unknown_permission_returns_400(client, admin_token, db_session):
    """An unknown permission name produces a 400."""
    user_role = db_session.query(Role).filter(Role.name == "USER").first()

    res = client.put(
        f"/admin/roles/{user_role.id}/permissions",
        json={"permissions": ["does:not:exist"]},
        headers=get_auth_header(admin_token),
    )
    assert res.status_code == 400
    assert "does:not:exist" in res.json()["message"]


def test_set_role_permissions_empty_list_rejected(client, admin_token, db_session):
    """An empty permission list fails schema validation."""
    user_role = db_session.query(Role).filter(Role.name == "USER").first()

    res = client.put(
        f"/admin/roles/{user_role.id}/permissions",
        json={"permissions": []},
        headers=get_auth_header(admin_token),
    )
    assert res.status_code == 422


def test_permission_change_is_enforced_on_next_request(client, admin_token, db_session):
    """Removing a permission immediately blocks the affected route.

    A throwaway permission-guarded route is registered for this test only and
    removed again in the finally block so the shared app is left untouched.
    """
    user_role = db_session.query(Role).filter(Role.name == "MODERATOR").first()
    res = client.put(
        f"/admin/roles/{user_role.id}/permissions",
        json={"permissions": ["users:read"]},  # reports:read is removed
        headers=get_auth_header(admin_token),
    )
    assert res.status_code == 200

    @app.get("/test-perm/reports-only")
    def reports_only(user=Depends(require_permission("reports:read"))):
        return {"ok": True}

    try:
        data = register_user(client, "permchange_api@example.com")
        make_moderator(db_session, data["id"])
        token = login_user(client, "permchange_api@example.com")["access_token"]

        with TestClient(app) as scoped:
            res = scoped.get("/test-perm/reports-only", headers=get_auth_header(token))
        assert res.status_code == 403
    finally:
        app.router.routes = [
            r for r in app.router.routes if getattr(r, "path", "") != "/test-perm/reports-only"
        ]
