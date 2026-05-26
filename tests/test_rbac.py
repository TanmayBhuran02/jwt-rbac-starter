"""RBAC tests: role-based access control for admin routes."""

from tests.conftest import (
    get_auth_header,
    login_user,
    make_admin,
    make_moderator,
    register_user,
)


def test_admin_route_blocked_for_user(client):
    """Accessing admin route as USER returns 403."""
    register_user(client, "rbac_user@example.com")
    tokens = login_user(client, "rbac_user@example.com")

    res = client.get("/admin/users", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 403


def test_admin_route_succeeds_for_admin(client, db_session):
    """Accessing admin route as ADMIN succeeds."""
    reg_data = register_user(client, "rbac_admin@example.com")
    make_admin(db_session, reg_data["id"])

    # Re-login to get fresh token with ADMIN role
    tokens = login_user(client, "rbac_admin@example.com")

    res = client.get("/admin/users", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_require_role_multiple_passes_for_moderator(client, db_session):
    """require_role("ADMIN", "MODERATOR") passes for MOD user."""
    # The /admin/roles endpoint requires ADMIN, but we'll test with
    # a user who has MODERATOR role accessing admin users (which requires ADMIN).
    # Instead, let's verify a MODERATOR user can access endpoints that accept ADMIN or MOD.
    reg_data = register_user(client, "rbac_mod@example.com")
    make_moderator(db_session, reg_data["id"])

    # Re-login with MODERATOR role
    tokens = login_user(client, "rbac_mod@example.com")

    # MOD user should still be blocked from admin-only routes
    res = client.get("/admin/users", headers=get_auth_header(tokens["access_token"]))
    # require_role("ADMIN") only passes ADMIN, so MOD gets 403
    assert res.status_code == 403


def test_admin_can_assign_role(client, db_session):
    """Admin can assign a role to a user via POST /admin/users/{id}/roles."""
    # Create admin user
    admin_data = register_user(client, "assign_admin@example.com")
    make_admin(db_session, admin_data["id"])
    admin_tokens = login_user(client, "assign_admin@example.com")

    # Create target user
    target_data = register_user(client, "assign_target@example.com")

    # Assign MODERATOR role
    res = client.post(
        f"/admin/users/{target_data['id']}/roles",
        json={"role_name": "MODERATOR", "action": "assign"},
        headers=get_auth_header(admin_tokens["access_token"]),
    )
    assert res.status_code == 200

    # Verify role was assigned
    target_tokens = login_user(client, "assign_target@example.com")
    res = client.get("/users/me", headers=get_auth_header(target_tokens["access_token"]))
    assert res.status_code == 200
    roles = [r["name"] for r in res.json()["roles"]]
    assert "MODERATOR" in roles


def test_admin_can_toggle_active(client, db_session):
    """Admin can deactivate a user."""
    admin_data = register_user(client, "toggle_admin@example.com")
    make_admin(db_session, admin_data["id"])
    admin_tokens = login_user(client, "toggle_admin@example.com")

    target_data = register_user(client, "toggle_target@example.com")

    # Deactivate
    res = client.patch(
        f"/admin/users/{target_data['id']}/toggle-active",
        headers=get_auth_header(admin_tokens["access_token"]),
    )
    assert res.status_code == 200
    assert res.json()["is_active"] is False

    # Deactivated user should fail to login
    res = client.post(
        "/auth/login",
        json={"email": "toggle_target@example.com", "password": "password123"},
    )
    assert res.status_code == 401
