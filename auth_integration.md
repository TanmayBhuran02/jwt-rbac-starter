# 🔐 Auth Integration Guide

> **jwt-rbac-starter** — Drop-in JWT authentication & role-based access control for FastAPI projects.

This guide walks you through injecting the starter kit into **your own project** as a dependency and integrating every feature it offers.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Setup (5 Minutes)](#quick-setup-5-minutes)
- [Project Structure Overview](#project-structure-overview)
- [Feature Integration Guide](#feature-integration-guide)
  - [1. JWT Authentication (Login / Refresh / Logout)](#1-jwt-authentication-login--refresh--logout)
  - [2. User Registration & Profile Management](#2-user-registration--profile-management)
  - [3. Role-Based Access Control (RBAC)](#3-role-based-access-control-rbac)
  - [4. Permission-Based Access Control](#4-permission-based-access-control)
  - [5. Token Blacklisting (Revocation)](#5-token-blacklisting-revocation)
  - [6. Rate Limiting](#6-rate-limiting)
  - [7. Admin Panel & User Management](#7-admin-panel--user-management)
  - [8. Frontend UI Templates](#8-frontend-ui-templates)
  - [9. Custom Repository Injection](#9-custom-repository-injection)
  - [10. Error Handling & JSON Envelope](#10-error-handling--json-envelope)
  - [11. Security Headers & CORS](#11-security-headers--cors)
  - [12. Docker Deployment](#12-docker-deployment)
- [Environment Variables Reference](#environment-variables-reference)
- [API Endpoints Reference](#api-endpoints-reference)
- [Schemas Reference](#schemas-reference)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | ≥ 3.10 |
| PostgreSQL | ≥ 14 (or any SQLAlchemy-compatible DB) |
| Redis | ≥ 7 *(optional — for token blacklisting in production)* |

---

## Quick Setup (5 Minutes)

### Step 1 — Clone the starter kit into your project

```bash
# From your project root
git clone https://github.com/your-org/jwt-rbac-starter.git auth
```

Or add it as a **Git submodule** for versioned dependency tracking:

```bash
git submodule add https://github.com/your-org/jwt-rbac-starter.git auth
```

### Step 2 — Install dependencies

Add these to your project's `requirements.txt` (or merge from `auth/requirements.txt`):

```txt
fastapi==0.111.0
uvicorn[standard]
python-jose[cryptography]
passlib[bcrypt]
bcrypt
pydantic-settings
pydantic[email]
dependency-injector
sqlalchemy
psycopg2-binary
jinja2
python-multipart
python-dotenv
slowapi
redis
```

Then install:

```bash
pip install -r requirements.txt
```

### Step 3 — Configure environment variables

Create a `.env` file in your project root:

```env
# Security — REQUIRED (minimum 32 characters each)
SECRET_KEY=change-me-to-at-least-32-characters-long
REFRESH_SECRET_KEY=another-secret-at-least-32-chars

# Database — REQUIRED
DATABASE_URL=postgresql://postgres:root@localhost:5432/your_db

# Optional
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
REDIS_URL=
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000
JWT_ISSUER=
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=changeme123
```

### Step 4 — Initialize in your FastAPI app

```python
# your_project/main.py
from jwt_rbac import setup

app = setup(
    secret_key="your-32-char-minimum-secret-key-here!!!",
    refresh_secret_key="your-refresh-secret-key-at-least-32-chars",
    token_expire_minutes=60,
    include_ui=True,       # Set False for API-only mode
    router_prefix="/api/v1",  # Optional — prefix all auth routes
)
```

### Step 5 — Seed default data

```bash
python -m jwt_rbac.seed
```

This creates (idempotently):
- **Permissions**: `users:read`, `users:write`, `admin:access`, `reports:read`
- **Roles**: `ADMIN`, `USER`, `MODERATOR`
- **Admin user**: from `ADMIN_EMAIL` / `ADMIN_PASSWORD` env vars

### Step 6 — Run

```bash
uvicorn your_project.main:app --reload
```

✅ You now have a fully working auth system. Open `http://localhost:8000/login` to see the UI.

---

## Project Structure Overview

```
jwt-rbac-starter/
├── jwt_rbac/
│   ├── __init__.py          # Public API re-exports
│   ├── setup.py             # setup() — the main entry point
│   ├── config.py            # Settings from .env via pydantic-settings
│   ├── containers.py        # DI container (dependency-injector)
│   ├── main.py              # Default app entry point
│   ├── seed.py              # Idempotent database seeder
│   ├── core/
│   │   ├── dependencies.py  # get_current_user, require_role, require_permission
│   │   ├── security.py      # JWT creation/decoding, password hashing
│   │   ├── exceptions.py    # CredentialsException, ForbiddenException, ServiceError
│   │   └── limiter.py       # SlowAPI rate limiter instance
│   ├── interfaces/          # Abstract base classes (the public contract)
│   │   ├── user_repository.py
│   │   ├── role_repository.py
│   │   └── token_blacklist.py
│   ├── models/              # SQLAlchemy ORM models
│   │   ├── db.py            # Engine, SessionLocal, Base
│   │   ├── user.py          # User model
│   │   └── role.py          # Role + Permission models
│   ├── repositories/        # Default SQL + memory/Redis implementations
│   │   ├── sql_user_repo.py
│   │   ├── sql_role_repo.py
│   │   ├── memory_blacklist.py
│   │   └── redis_blacklist.py
│   ├── routers/             # FastAPI APIRouter modules
│   │   ├── auth.py          # /auth/* endpoints
│   │   ├── users.py         # /users/* endpoints
│   │   ├── admin.py         # /admin/* endpoints
│   │   └── ui.py            # HTML template routes
│   ├── schemas/             # Pydantic request/response models
│   │   ├── auth.py
│   │   ├── user.py
│   │   └── role.py
│   ├── services/            # Business logic layer
│   │   ├── auth_service.py
│   │   ├── user_service.py
│   │   └── rbac_service.py
│   ├── static/              # CSS, JS assets
│   └── templates/           # Jinja2 HTML templates
├── tests/
├── .env.example
├── requirements.txt
├── pyproject.toml
├── Dockerfile
└── docker-compose.yml
```

---

## Feature Integration Guide

### 1. JWT Authentication (Login / Refresh / Logout)

The starter kit provides a complete token lifecycle out of the box.

#### How it works

- **Login** (`POST /auth/login`) — Validates credentials, returns an access + refresh token pair.
- **Refresh** (`POST /auth/refresh`) — Exchanges a valid refresh token for a new pair. The old refresh token is blacklisted.
- **Logout** (`POST /auth/logout`) — Blacklists both the access and refresh tokens.

#### Token structure

Tokens are signed JWTs containing:

```json
{
  "sub": "user-uuid",
  "roles": ["USER"],
  "permissions": ["users:read"],
  "jti": "unique-token-id",
  "type": "access",
  "exp": 1720000000,
  "iss": "your-issuer"
}
```

#### Using in your frontend

```javascript
// Login
const response = await fetch("/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "user@example.com", password: "password123" }),
});
const { access_token, refresh_token } = await response.json();

// Authenticated request
const me = await fetch("/users/me", {
  headers: { Authorization: `Bearer ${access_token}` },
});

// Refresh tokens
const refreshed = await fetch("/auth/refresh", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ refresh_token }),
});

// Logout
await fetch("/auth/logout", {
  method: "POST",
  headers: { Authorization: `Bearer ${access_token}` },
});
```

#### Token introspection

Decode a token without exposing secrets client-side:

```javascript
const info = await fetch("/auth/token/info", {
  headers: { Authorization: `Bearer ${access_token}` },
});
// Returns: { sub, roles, permissions, exp, jti, token_type, iss }
```

---

### 2. User Registration & Profile Management

#### Register a new user

```python
# POST /users/register
{
    "email": "newuser@example.com",
    "password": "securepassword",
    "role_name": "USER"           # Optional — defaults to "USER"
}
```

The `role_name` field lets you assign a role at registration (e.g., `"MODERATOR"`).

#### Get current user profile

```python
# GET /users/me — requires Bearer token
# Returns: { id, email, is_active, created_at, roles: [{ id, name, permissions }] }
```

#### Change password

```python
# PATCH /users/me/password — requires Bearer token
{
    "current_password": "oldpassword",
    "new_password": "newpassword123"  # Minimum 8 characters
}
```

---

### 3. Role-Based Access Control (RBAC)

Protect your own routes using `require_role` — works as both a FastAPI dependency and a decorator.

#### Import

```python
from jwt_rbac import require_role
```

#### As a FastAPI dependency (recommended)

```python
from fastapi import APIRouter, Depends

router = APIRouter()

# Single role
@router.get("/admin/dashboard")
async def admin_dashboard(user=Depends(require_role("ADMIN"))):
    return {"message": f"Welcome, {user.email}"}

# Multiple roles (user must have ANY one of them)
@router.get("/reports")
async def view_reports(user=Depends(require_role("ADMIN", "MODERATOR"))):
    return {"message": "Reports data here"}
```

#### Default roles

| Role | Permissions |
|---|---|
| `ADMIN` | `users:read`, `users:write`, `admin:access`, `reports:read` |
| `MODERATOR` | `users:read`, `users:write`, `reports:read` |
| `USER` | `users:read` |

> **Note**: `ADMIN` role acts as a **superuser** — it automatically passes all role and permission checks, even if the required role/permission isn't explicitly listed.

#### Response codes

| Code | Meaning |
|---|---|
| `401 Unauthorized` | Token is missing, expired, blacklisted, or invalid |
| `403 Forbidden` | User is authenticated but lacks the required role |

---

### 4. Permission-Based Access Control

For finer-grained control, use `require_permission` instead of (or alongside) `require_role`.

#### Import

```python
from jwt_rbac import require_permission
```

#### Usage

```python
from fastapi import Depends

# Single permission
@router.get("/data")
async def read_data(user=Depends(require_permission("users:read"))):
    return {"data": "..."}

# Multiple permissions (user must have ANY one of them)
@router.delete("/data/{id}")
async def delete_data(id: str, user=Depends(require_permission("users:write", "admin:access"))):
    return {"deleted": id}
```

#### Default permissions

| Permission | Description |
|---|---|
| `users:read` | Read user data |
| `users:write` | Create/modify user data |
| `admin:access` | Access admin-level resources |
| `reports:read` | Access reporting features |

> **Tip**: You can define your own permissions by adding them to the database or through the admin API (`PUT /admin/roles/{role_id}/permissions`).

---

### 5. Token Blacklisting (Revocation)

Supports two backends — selected automatically based on config:

| Backend | Config | Use Case |
|---|---|---|
| **In-Memory** | `REDIS_URL` not set | Development, single-instance |
| **Redis** | `REDIS_URL=redis://...` | Production, multi-instance |

#### How it works

1. On **logout**, the access and refresh token JTIs are added to the blacklist.
2. On **refresh**, the old refresh token JTI is blacklisted.
3. Every authenticated request checks the access token JTI against the blacklist.

#### Custom blacklist implementation

Implement the `ITokenBlacklist` interface:

```python
from jwt_rbac import ITokenBlacklist

class DynamoDBBlacklist(ITokenBlacklist):
    def __init__(self, table_name: str):
        import boto3
        self.table = boto3.resource("dynamodb").Table(table_name)

    def add(self, jti: str) -> None:
        self.table.put_item(Item={"jti": jti, "ttl": int(time.time()) + 86400})

    def is_blacklisted(self, jti: str) -> bool:
        response = self.table.get_item(Key={"jti": jti})
        return "Item" in response
```

---

### 6. Rate Limiting

The login endpoint is rate-limited to **5 requests per minute per IP** using [SlowAPI](https://github.com/laurentS/slowapi).

#### Applying rate limits to your own routes

```python
from jwt_rbac.core.limiter import limiter
from fastapi import Request

@router.post("/my-endpoint")
@limiter.limit("10/minute")
async def my_endpoint(request: Request):
    return {"status": "ok"}
```

> **Important**: The `request: Request` parameter **must** be present in the function signature for the rate limiter to extract the client IP.

---

### 7. Admin Panel & User Management

All admin endpoints require the `ADMIN` role.

#### List all users

```bash
GET /admin/users
Authorization: Bearer <admin_token>
```

#### Assign / revoke a role

```bash
POST /admin/users/{user_id}/roles
Authorization: Bearer <admin_token>
Content-Type: application/json

# Assign
{ "role_name": "MODERATOR", "action": "assign" }

# Revoke
{ "role_name": "MODERATOR", "action": "revoke" }
```

#### Toggle user active status

```bash
PATCH /admin/users/{user_id}/toggle-active
Authorization: Bearer <admin_token>
```

Deactivated users cannot log in or use existing tokens.

#### List all roles

```bash
GET /admin/roles
Authorization: Bearer <admin_token>
```

#### List all permissions

```bash
GET /admin/permissions
Authorization: Bearer <admin_token>
```

#### Update permissions on a role

```bash
PUT /admin/roles/{role_id}/permissions
Authorization: Bearer <admin_token>
Content-Type: application/json

{ "permissions": ["users:read", "users:write", "reports:read"] }
```

> **Warning**: This **replaces** all existing permissions on the role.

---

### 8. Frontend UI Templates

The starter kit includes ready-to-use HTML/CSS/JS views:

| View | Route | Description |
|---|---|---|
| Login / Register | `/login` | Email + password form with role selection dropdown |
| Dashboard | `/dashboard` | Protected — shows profile, roles, permissions |
| Admin Panel | `/admin/ui` | Protected (ADMIN only) — user management, role assignment |

#### Including the UI

```python
app = setup(
    include_ui=True,  # Mounts /static and includes Jinja2 template routes
    # ...
)
```

#### Excluding the UI (API-only mode)

```python
app = setup(
    include_ui=False,  # No static files, no template routes
    # ...
)
```

#### Using `router_prefix` with UI

When you set a `router_prefix`, all routes (API and UI) are prefixed:

```python
app = setup(
    router_prefix="/api/v1",
    include_ui=True,
)
# Login page is now at /api/v1/login
# API endpoints are at /api/v1/auth/login, etc.
```

---

### 9. Custom Repository Injection

The core power of this starter kit: **swap out the data layer** without touching any auth logic.

#### Abstract interfaces

You need to implement these interfaces (any method you skip raises `TypeError` at startup — not a runtime `AttributeError`):

##### `IUserRepository`

```python
from jwt_rbac import IUserRepository
from jwt_rbac.schemas.user import UserCreate, UserInDB, UserOut

class MyUserRepo(IUserRepository):
    def find_by_email(self, email: str) -> UserInDB | None: ...
    def find_by_id(self, user_id: str) -> UserOut | None: ...
    def create(self, data: UserCreate) -> UserOut: ...
    def list_all(self) -> list[UserOut]: ...
    def update_password(self, user_id: str, hashed_password: str) -> None: ...
    def set_active(self, user_id: str, is_active: bool) -> None: ...
```

##### `IRoleRepository`

```python
from jwt_rbac import IRoleRepository
from jwt_rbac.schemas.role import PermissionOut, RoleOut

class MyRoleRepo(IRoleRepository):
    def find_by_name(self, name: str) -> RoleOut | None: ...
    def assign_to_user(self, user_id: str, role_name: str) -> None: ...
    def revoke_from_user(self, user_id: str, role_name: str) -> None: ...
    def get_user_roles(self, user_id: str) -> list[RoleOut]: ...
    def list_all(self) -> list[RoleOut]: ...
    def list_permissions(self) -> list[PermissionOut]: ...
    def set_permissions(self, role_id: int, permission_names: list[str]) -> RoleOut: ...
```

#### Injecting custom repos into `setup()`

```python
from jwt_rbac import setup

mongo_user_repo = MongoUserRepository(collection=db["users"])
mongo_role_repo = MongoRoleRepository(collection=db["roles"])

app = setup(
    user_repository=mongo_user_repo,
    role_repository=mongo_role_repo,
    secret_key="your-32-char-minimum-secret-key-here!!!",
    refresh_secret_key="your-refresh-secret-key-at-least-32-chars",
    include_ui=False,
)
```

#### Example: MongoDB user repository

```python
from uuid import uuid4
from datetime import datetime, timezone

from jwt_rbac import IUserRepository
from jwt_rbac.schemas.user import UserCreate, UserInDB, UserOut
from jwt_rbac.schemas.role import RoleOut, PermissionOut
from jwt_rbac.core.security import get_password_hash


class MongoUserRepository(IUserRepository):
    def __init__(self, collection):
        self.collection = collection

    def find_by_email(self, email: str) -> UserInDB | None:
        doc = self.collection.find_one({"email": email})
        if not doc:
            return None
        return UserInDB(
            id=doc["_id"],
            email=doc["email"],
            is_active=doc["is_active"],
            created_at=doc["created_at"],
            hashed_password=doc["hashed_password"],
            roles=[
                RoleOut(
                    id=r["id"],
                    name=r["name"],
                    permissions=[PermissionOut(**p) for p in r.get("permissions", [])],
                )
                for r in doc.get("roles", [])
            ],
        )

    def find_by_id(self, user_id: str) -> UserOut | None:
        doc = self.collection.find_one({"_id": user_id})
        if not doc:
            return None
        return UserOut(
            id=doc["_id"],
            email=doc["email"],
            is_active=doc["is_active"],
            created_at=doc["created_at"],
            roles=[
                RoleOut(
                    id=r["id"],
                    name=r["name"],
                    permissions=[PermissionOut(**p) for p in r.get("permissions", [])],
                )
                for r in doc.get("roles", [])
            ],
        )

    def create(self, data: UserCreate) -> UserOut:
        user_id = str(uuid4())
        now = datetime.now(timezone.utc)
        doc = {
            "_id": user_id,
            "email": data.email,
            "hashed_password": get_password_hash(data.password),
            "is_active": True,
            "created_at": now,
            "roles": [],
        }
        self.collection.insert_one(doc)
        return UserOut(id=user_id, email=data.email, is_active=True, created_at=now, roles=[])

    def list_all(self) -> list[UserOut]:
        return [self.find_by_id(str(doc["_id"])) for doc in self.collection.find()]

    def update_password(self, user_id: str, hashed_password: str) -> None:
        self.collection.update_one(
            {"_id": user_id}, {"$set": {"hashed_password": hashed_password}}
        )

    def set_active(self, user_id: str, is_active: bool) -> None:
        self.collection.update_one({"_id": user_id}, {"$set": {"is_active": is_active}})
```

> **Tip**: When using custom repositories, automatic role/permission seeding via the `lifespan` hook is skipped. You must seed your own database.

---

### 10. Error Handling & JSON Envelope

All API errors follow a consistent JSON envelope:

```json
{
    "error": "UNAUTHORIZED",
    "message": "Could not validate credentials",
    "status": 401
}
```

#### Error types

| HTTP Status | Error Code | When |
|---|---|---|
| 400 | `BAD_REQUEST` | Malformed request |
| 401 | `UNAUTHORIZED` | Missing/invalid/expired token |
| 403 | `FORBIDDEN` | Insufficient role or permission |
| 404 | `NOT_FOUND` | Resource not found |
| 422 | `VALIDATION_ERROR` | Request body validation failed |
| 429 | `RATE_LIMITED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Unhandled server error |

#### Validation errors include field details

```json
{
    "error": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "status": 422,
    "details": [
        {
            "field": "body → password",
            "message": "String should have at least 8 characters",
            "type": "string_too_short"
        }
    ]
}
```

#### Custom exception classes you can reuse

```python
from jwt_rbac.core.exceptions import (
    CredentialsException,   # 401 with WWW-Authenticate: Bearer
    ForbiddenException,     # 403
    ServiceError,           # Generic 500 (or custom status_code)
)

# Usage in your own services
raise CredentialsException("Your custom auth error message")
raise ForbiddenException("You cannot access this resource")
raise ServiceError("Something went wrong", status_code=503)
```

#### Database exception decorator

Wrap your service methods to auto-catch SQLAlchemy errors:

```python
from jwt_rbac.core.exceptions import handle_db_exceptions

class MyService:
    @handle_db_exceptions
    def do_something(self):
        # Any SQLAlchemyError → ServiceError("Database error occurred")
        ...
```

---

### 11. Security Headers & CORS

#### Security headers (auto-applied)

Every response includes:

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |

#### CORS configuration

Set via the `ALLOWED_ORIGINS` environment variable (comma-separated):

```env
ALLOWED_ORIGINS=http://localhost:3000,https://your-frontend.com
```

If not set, defaults to allowing all origins (`*`).

---

### 12. Docker Deployment

#### App + PostgreSQL

```bash
docker compose up
```

#### App + PostgreSQL + Redis (production)

```bash
docker compose --profile redis up
```

#### Custom Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "jwt_rbac.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Environment Variables Reference

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `SECRET_KEY` | `str` | — | ✅ | JWT signing key (min 32 chars) |
| `REFRESH_SECRET_KEY` | `str` | — | ✅ | Refresh token signing key (min 32 chars) |
| `ALGORITHM` | `str` | `HS256` | ❌ | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `int` | `30` | ❌ | Access token TTL in minutes |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `int` | `7` | ❌ | Refresh token TTL in days |
| `DATABASE_URL` | `str` | `postgresql://...` | ✅ | SQLAlchemy connection string |
| `REDIS_URL` | `str` | `None` | ❌ | Redis URL for token blacklist |
| `ALLOWED_ORIGINS` | `str` | `localhost` | ❌ | Comma-separated CORS origins |
| `JWT_ISSUER` | `str` | `None` | ❌ | JWT `iss` claim (validated when set) |
| `ADMIN_EMAIL` | `str` | `admin@example.com` | ❌ | Seed script admin email |
| `ADMIN_PASSWORD` | `str` | `changeme123` | ❌ | Seed script admin password |

---

## API Endpoints Reference

### Auth (`/auth`)

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/login` | ❌ | Login, returns access + refresh token pair |
| `POST` | `/auth/refresh` | ❌ | Exchange refresh token for new pair |
| `POST` | `/auth/logout` | ✅ | Blacklist current tokens (204 No Content) |
| `GET` | `/auth/me` | ✅ | Alias for `/users/me` |
| `GET` | `/auth/token/info` | ✅ | Decode and return JWT payload |

### Users (`/users`)

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/users/register` | ❌ | Register new user (optional `role_name`) |
| `GET` | `/users/me` | ✅ | Get current user profile with roles |
| `PATCH` | `/users/me/password` | ✅ | Change password (requires current password) |

### Admin (`/admin`)

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/admin/users` | 🔒 ADMIN | List all users |
| `POST` | `/admin/users/{id}/roles` | 🔒 ADMIN | Assign or revoke a role |
| `PATCH` | `/admin/users/{id}/toggle-active` | 🔒 ADMIN | Toggle user active/inactive |
| `GET` | `/admin/roles` | 🔒 ADMIN | List all roles |
| `GET` | `/admin/permissions` | 🔒 ADMIN | List all permissions |
| `PUT` | `/admin/roles/{id}/permissions` | 🔒 ADMIN | Replace all permissions on a role |

### UI (when `include_ui=True`)

| Route | Description |
|---|---|
| `/login` | Login / register page |
| `/dashboard` | Authenticated user dashboard |
| `/admin/ui` | Admin management panel |

---

## Schemas Reference

### Request Schemas

```python
# Login
LoginRequest { email: str, password: str }

# Token refresh
RefreshRequest { refresh_token: str }

# Registration
UserCreate { email: EmailStr, password: str (min 8), role_name: str | None }

# Password change
PasswordChangeRequest { current_password: str, new_password: str (min 8) }

# Role management
RoleAssignment { role_name: str, action: "assign" | "revoke" }

# Permission management
PermissionAssignment { permissions: list[str] (min 1 item) }
```

### Response Schemas

```python
# Token pair
TokenResponse { access_token: str, refresh_token: str, token_type: "bearer" }

# Token introspection
TokenInfo { sub: str, roles: list[str], permissions: list[str], exp: int, jti: str, token_type: str, iss: str | None }

# User profile
UserOut { id: UUID, email: EmailStr, is_active: bool, created_at: datetime, roles: list[RoleOut] }

# Role
RoleOut { id: int, name: str, permissions: list[PermissionOut] }

# Permission
PermissionOut { id: int, name: str }
```

---

## Troubleshooting

### `ValueError: secret_key must be at least 32 characters long`

Your `SECRET_KEY` or `REFRESH_SECRET_KEY` is too short. Both must be ≥ 32 characters.

### `TypeError: Injected repository MyRepo is missing the following required abstract methods...`

Your custom repository doesn't implement all methods from the interface. The error message lists exactly which methods are missing.

### Token works on first request but fails on subsequent ones

Check if you're accidentally blacklisting the access token. Only `/auth/logout` should blacklist tokens. Also verify `REDIS_URL` is consistent across instances if running multiple workers.

### `422 VALIDATION_ERROR` on login

The login endpoint expects a JSON body `{ "email": "...", "password": "..." }`, not form data. Make sure you're sending `Content-Type: application/json`.

### Rate limit errors (`429 RATE_LIMITED`)

The login endpoint allows only **5 attempts per minute per IP**. Wait 60 seconds or adjust the limit in `jwt_rbac/routers/auth.py`.

### CORS errors in browser

Add your frontend origin to `ALLOWED_ORIGINS` in `.env`:
```env
ALLOWED_ORIGINS=http://localhost:3000,https://your-app.com
```

### Seeds not running / roles missing

Run the seed script manually:
```bash
python -m jwt_rbac.seed
```
If using custom repositories, the automatic lifespan seeding is skipped — you must seed your own database.

---

> **Need help?** Check the interactive API docs at `http://localhost:8000/docs` (Swagger UI) or `http://localhost:8000/redoc` (ReDoc).
