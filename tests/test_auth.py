"""Authentication tests: login, refresh, logout, blacklisting, rate limiting."""

from tests.conftest import get_auth_header, login_user, register_user


def test_register_and_login(client):
    """Login with valid credentials returns JWT."""
    register_user(client, "auth_test@example.com")

    res = client.post(
        "/auth/login",
        json={"email": "auth_test@example.com", "password": "password123"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_login_wrong_password(client):
    """Login with wrong password returns 401."""
    register_user(client, "wrong_pw@example.com")

    res = client.post(
        "/auth/login",
        json={"email": "wrong_pw@example.com", "password": "wrong"},
    )
    assert res.status_code == 401
    data = res.json()
    assert data["error"] == "UNAUTHORIZED"


def test_protected_route_no_token(client):
    """Accessing protected route without token returns 401."""
    res = client.get("/users/me")
    assert res.status_code == 401


def test_refresh_returns_new_token(client):
    """Refresh token returns new access token."""
    register_user(client, "refresh_test@example.com")
    tokens = login_user(client, "refresh_test@example.com")

    res = client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    # New tokens should be different
    assert data["access_token"] != tokens["access_token"]


def test_logout_blacklists_token(client):
    """Blacklisted token rejected after logout."""
    register_user(client, "logout_test@example.com")
    tokens = login_user(client, "logout_test@example.com")

    # Verify token works before logout
    res = client.get("/users/me", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 200

    # Logout
    res = client.post(
        "/auth/logout",
        headers=get_auth_header(tokens["access_token"]),
    )
    assert res.status_code == 204

    # Token should be blacklisted now
    res = client.get("/users/me", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 401


def test_get_profile_with_roles(client):
    """Profile includes user roles."""
    register_user(client, "profile_test@example.com")
    tokens = login_user(client, "profile_test@example.com")

    res = client.get("/users/me", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == "profile_test@example.com"
    assert any(role["name"] == "USER" for role in data["roles"])


def test_auth_me_alias(client):
    """GET /auth/me works as alias for /users/me."""
    register_user(client, "alias_test@example.com")
    tokens = login_user(client, "alias_test@example.com")

    res = client.get("/auth/me", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 200
    assert res.json()["email"] == "alias_test@example.com"


def test_token_introspection(client):
    """GET /auth/token/info returns decoded payload."""
    register_user(client, "introspect@example.com")
    tokens = login_user(client, "introspect@example.com")

    res = client.get("/auth/token/info", headers=get_auth_header(tokens["access_token"]))
    assert res.status_code == 200
    data = res.json()
    assert "sub" in data
    assert "roles" in data
    assert "jti" in data
    assert data["type"] == "access"


def test_change_password(client):
    """PATCH /users/me/password changes the password."""
    register_user(client, "changepw@example.com")
    tokens = login_user(client, "changepw@example.com")

    res = client.patch(
        "/users/me/password",
        json={"current_password": "password123", "new_password": "newpassword456"},
        headers=get_auth_header(tokens["access_token"]),
    )
    assert res.status_code == 200

    # Login with new password should work
    res = client.post(
        "/auth/login",
        json={"email": "changepw@example.com", "password": "newpassword456"},
    )
    assert res.status_code == 200


def test_change_password_wrong_current(client):
    """PATCH /users/me/password rejects wrong current password."""
    register_user(client, "badcurrent@example.com")
    tokens = login_user(client, "badcurrent@example.com")

    res = client.patch(
        "/users/me/password",
        json={"current_password": "wrongpassword", "new_password": "newpassword456"},
        headers=get_auth_header(tokens["access_token"]),
    )
    assert res.status_code == 400


def test_rate_limiting(client):
    """Rate limit triggers after 5 failed logins."""
    from jwt_rbac.core.limiter import limiter

    limiter.enabled = True

    try:
        for _ in range(5):
            res = client.post(
                "/auth/login",
                json={"email": "nonexistent@example.com", "password": "wrong"},
            )
            assert res.status_code == 401

        # The 6th request triggers 429
        res = client.post(
            "/auth/login",
            json={"email": "nonexistent@example.com", "password": "wrong"},
        )
        assert res.status_code == 429
        assert res.json()["error"] == "RATE_LIMITED"
    finally:
        limiter.enabled = False
