"""Tests for the bundled HTML UI, static assets, and JSON error envelopes."""

import uuid

import pytest

# --------------------------------------------------------------------------
# Template routes
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/dashboard", "/admin-panel"])
def test_ui_routes_return_html(client, path):
    """Each template route renders successfully."""
    res = client.get(path)
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    assert "<html" in res.text.lower()


def test_index_is_the_login_page(client):
    """The root route serves the login/register form."""
    res = client.get("/")
    assert "password" in res.text.lower()


def test_dashboard_page_renders(client):
    """The dashboard template is served."""
    res = client.get("/dashboard")
    assert res.status_code == 200


def test_admin_panel_renders(client):
    """The admin panel template is served."""
    res = client.get("/admin-panel")
    assert res.status_code == 200


def test_ui_routes_are_hidden_from_the_schema(client):
    """Template routes are excluded from the OpenAPI document."""
    paths = client.get("/openapi.json").json()["paths"]
    assert "/dashboard" not in paths
    assert "/admin-panel" not in paths


def test_static_stylesheet_is_served(client):
    """The bundled stylesheet is mounted under /static."""
    res = client.get("/static/styles.css")
    assert res.status_code == 200
    assert "text/css" in res.headers["content-type"]


def test_static_unknown_file_returns_404(client):
    """A missing static asset produces a 404."""
    assert client.get("/static/nope.css").status_code == 404


# --------------------------------------------------------------------------
# Security headers
# --------------------------------------------------------------------------


def test_security_headers_on_api_responses(client):
    """API responses carry the hardening headers."""
    res = client.get("/users/me")
    assert res.status_code == 401
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert res.headers["Referrer-Policy"] == "no-referrer"


def test_security_headers_on_html_responses(client):
    """HTML responses carry the hardening headers too."""
    res = client.get("/dashboard")
    assert res.headers["X-Frame-Options"] == "DENY"


def test_unauthorized_response_includes_challenge_header(client):
    """A 401 advertises the Bearer scheme."""
    res = client.get("/users/me")
    assert res.headers.get("www-authenticate") == "Bearer"


# --------------------------------------------------------------------------
# Error envelopes
# --------------------------------------------------------------------------


def test_error_envelope_shape_for_401(client):
    """401 responses use the documented error envelope."""
    body = client.get("/users/me").json()
    assert set(body) == {"error", "message", "status"}
    assert body["error"] == "UNAUTHORIZED"
    assert body["status"] == 401


def test_error_envelope_shape_for_app_raised_404(client, db_session):
    """A 404 raised by the application uses the documented error envelope."""
    from tests.conftest import get_auth_header, login_user, make_admin, register_user

    data = register_user(client, "envelope404@example.com")
    make_admin(db_session, data["id"])
    token = login_user(client, "envelope404@example.com")["access_token"]

    res = client.patch(f"/admin/users/{uuid.uuid4()}/toggle-active", headers=get_auth_header(token))
    assert res.status_code == 404

    body = res.json()
    assert body["error"] == "NOT_FOUND"
    assert body["status"] == 404


def test_unrouted_path_returns_starlette_default_404(client):
    """A request to an unregistered path returns Starlette's default 404 body.

    Routing 404s are produced by the router itself, before the application's
    ``HTTPException`` handler is consulted, so they use Starlette's
    ``detail`` shape rather than the custom error envelope.
    """
    res = client.get("/no-such-endpoint")
    assert res.status_code == 404
    assert res.json() == {"detail": "Not Found"}


def test_error_envelope_for_bad_token(client):
    """A malformed bearer token yields a 401 envelope."""
    res = client.get("/users/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert res.status_code == 401
    assert res.json()["error"] == "UNAUTHORIZED"


def test_validation_error_envelope_includes_details(client):
    """422 responses list the offending fields."""
    res = client.post("/users/register", json={"email": "not-an-email"})
    assert res.status_code == 422

    body = res.json()
    assert body["error"] == "VALIDATION_ERROR"
    assert body["status"] == 422
    assert body["details"]
    assert {"field", "message", "type"} <= set(body["details"][0])


def test_validation_error_missing_field(client):
    """A missing required field is reported with its name."""
    res = client.post("/auth/login", json={"email": "someone@example.com"})
    assert res.status_code == 422
    assert any("password" in d["field"] for d in res.json()["details"])


def test_bad_request_envelope(client):
    """400 responses use the documented error envelope."""
    from tests.conftest import register_user

    register_user(client, "envelope_dupe@example.com")
    res = client.post(
        "/users/register", json={"email": "envelope_dupe@example.com", "password": "password123"}
    )
    assert res.status_code == 400
    body = res.json()
    assert body["error"] == "BAD_REQUEST"
    assert body["status"] == 400


# --------------------------------------------------------------------------
# CORS
# --------------------------------------------------------------------------


def test_cors_preflight_for_allowed_origin(client):
    """A preflight from an allowed origin is approved."""
    res = client.options(
        "/auth/login",
        headers={
            "Origin": "http://localhost:8000",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "http://localhost:8000"


def test_cors_headers_present_on_actual_request(client):
    """The allow-origin header is echoed on a normal request."""
    res = client.get("/users/me", headers={"Origin": "http://localhost:8000"})
    assert res.headers.get("access-control-allow-origin") == "http://localhost:8000"


# --------------------------------------------------------------------------
# OpenAPI
# --------------------------------------------------------------------------


def test_openapi_lists_all_api_routes(client):
    """Every documented endpoint appears in the OpenAPI schema."""
    paths = client.get("/openapi.json").json()["paths"]
    for path in [
        "/auth/login",
        "/auth/refresh",
        "/auth/logout",
        "/auth/me",
        "/auth/token/info",
        "/users/register",
        "/users/me",
        "/users/me/password",
        "/admin/users",
        "/admin/roles",
        "/admin/permissions",
    ]:
        assert path in paths, path
