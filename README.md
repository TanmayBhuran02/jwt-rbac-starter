# JWT + RBAC Python Starter Kit

A **production-ready** authentication and role-based access control starter kit built with FastAPI, SQLAlchemy, and dependency-injector. Designed to be injected into your own projects with minimal effort.

## ✨ Features

- **JWT Authentication** — Access + refresh token pairs with JTI-based blacklisting
- **Role-Based Access Control** — ADMIN / USER / MODERATOR roles with granular permissions
- **Dependency Injection** — Clean architecture via `dependency-injector`; swap repositories at will
- **Token Blacklisting** — In-memory (default) or Redis-backed (production)
- **Rate Limiting** — Login endpoint rate-limited to 5 attempts/minute per IP
- **Security Headers** — `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
- **CORS** — Configurable allowed origins
- **Consistent Errors** — Every error is a JSON envelope: `{error, message, status}`
- **Frontend UI Templates** — Built-in HTML/CSS for Login, Dashboard, and Admin management
- **Seed Script** — Idempotent `python -m jwt_rbac.seed` for default data
- **Docker** — One-command deployment with `docker compose up`
- **Test Suite** — 307 tests against a real PostgreSQL instance, 92% coverage

---

## 🚀 Quickstart

```bash
git clone https://github.com/your-org/jwt-rbac-starter.git
cd jwt-rbac-starter
cp .env.example .env                       # edit secrets!
pip install -r requirements.txt            # installs [dev,redis,postgres]
python -m jwt_rbac.seed                    # seed roles + admin user
uvicorn jwt_rbac.main:app --reload         # open http://localhost:8000
```

---

## 🏗️ Project Structure

```
jwt_rbac/
├── main.py              # uvicorn entrypoint  (jwt_rbac.main:app)
├── setup.py             # setup() — the public configuration API
├── seed.py              # Idempotent seed script
├── config.py            # Pydantic-settings, lazily initialized
├── containers.py        # dependency-injector DI container
├── core/
│   ├── security.py      # bcrypt hashing + JWT create/decode
│   ├── dependencies.py  # get_current_user, require_role, require_permission
│   ├── exceptions.py    # CredentialsException, ForbiddenException, ServiceError
│   └── limiter.py       # Shared slowapi limiter
├── interfaces/          # ABCs: IUserRepository, IRoleRepository, ITokenBlacklist
├── models/              # SQLAlchemy models + lazy engine/session
├── repositories/        # Sql*, MemoryTokenBlacklist, RedisTokenBlacklist
├── routers/             # auth, users, admin, ui
├── schemas/             # Pydantic request/response models
├── services/            # AuthService, UserService, RBACService
├── static/              # styles.css
└── templates/           # login.html, dashboard.html, admin.html

tests/
├── conftest.py                    # Postgres fixtures + rollback isolation
├── test_auth.py                   # Login, refresh, logout, rate limiting
├── test_rbac.py                   # Role-gated admin routes
├── test_decorators.py             # require_role / require_permission as decorators
├── test_injection.py              # Custom repository injection via setup()
├── test_security.py               # Password hashing + JWT internals
├── test_exceptions.py             # Exception types + handle_db_exceptions
├── test_config.py                 # Settings singleton & env precedence
├── test_db_module.py              # Lazy engine/session proxies
├── test_repositories.py           # SQLAlchemy repository CRUD
├── test_blacklist.py              # Memory + Redis blacklists
├── test_services.py               # Service-layer unit tests
├── test_setup.py                  # setup() configuration API
├── test_schemas.py                # Pydantic validation rules
├── test_admin_api.py              # /admin endpoints end-to-end
├── test_ui_and_errors.py          # Templates, static assets, error envelopes
└── test_seed_and_package.py       # Seed idempotency + public API surface
```

---

## 🔌 Injecting Your Own Repository

Implement the abstract interfaces and pass them to `setup()`:

```python
from jwt_rbac import IUserRepository

class MyMongoUserRepository(IUserRepository):
    def find_by_email(self, email: str):
        return self.collection.find_one({"email": email})

    def find_by_id(self, user_id: str):
        return self.collection.find_one({"_id": user_id})

    def create(self, data):
        return self.collection.insert_one({"email": data.email, ...})

    def list_all(self):
        return list(self.collection.find())

    def update_password(self, user_id: str, hashed_password: str):
        self.collection.update_one(
            {"_id": user_id}, {"$set": {"hashed_password": hashed_password}}
        )

    def set_active(self, user_id: str, is_active: bool):
        self.collection.update_one({"_id": user_id}, {"$set": {"is_active": is_active}})

app = setup(user_repository=MyMongoUserRepository(), ...)
```

Any missing abstract method raises a clear `TypeError` at startup — not a cryptic runtime `AttributeError`.

---

## 🛡️ Using `require_role` / `require_permission`

Both work as a FastAPI `Depends()` **and** as a standalone decorator:

```python
from fastapi import Depends, Request
from jwt_rbac import require_role, require_permission

# As a dependency
@router.get("/admin")
async def admin_only(user=Depends(require_role("ADMIN"))):
    ...

# Multiple roles — the user needs only one
@router.get("/reports")
async def reports(user=Depends(require_role("ADMIN", "MODERATOR"))):
    ...

# Permission-based
@router.get("/data")
async def read_data(user=Depends(require_permission("users:read"))):
    ...

# As a decorator — the route must accept `request`
@router.get("/admin-panel")
@require_role("ADMIN")
async def panel(request: Request):
    ...
```

- **403 Forbidden** when authenticated but missing the required role/permission
- **401 Unauthorized** with `WWW-Authenticate: Bearer` when the token is missing/invalid/revoked

---

## ⚙️ Environment Variables

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `SECRET_KEY` | `str` | — | ✅ | JWT access-token signing key (min 32 chars) |
| `REFRESH_SECRET_KEY` | `str` | — | ✅ | Refresh-token signing key (min 32 chars) |
| `ALGORITHM` | `str` | `HS256` | ❌ | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `int` | `30` | ❌ | Access token TTL |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `int` | `7` | ❌ | Refresh token TTL |
| `DATABASE_URL` | `str` | `sqlite:///./sql_app.db` | ❌ | SQLAlchemy connection string for the app |
| `TEST_DATABASE_URL` | `str` | `postgresql://postgres:root@localhost:5432/jwt_rbac_test` | ❌ | **Test suite only** — see [Running Tests](#-running-tests) |
| `REDIS_URL` | `str` | `None` | ❌ | Redis URL for the token blacklist |
| `ALLOWED_ORIGINS` | `str` | `http://localhost:3000,http://localhost:8000` | ❌ | Comma-separated CORS origins |
| `JWT_ISSUER` | `str` | `None` | ❌ | JWT issuer claim (validated when set) |
| `ADMIN_EMAIL` | `str` | `admin@example.com` | ❌ | Seed script admin email |
| `ADMIN_PASSWORD` | `str` | `changeme123` | ❌ | Seed script admin password |

---

## 🧪 Running Tests

The suite runs against a **real PostgreSQL instance** — there is no SQLite fallback. If the
database is unreachable, pytest aborts immediately with setup instructions rather than skipping
tests, so a misconfigured environment can never be mistaken for a green run.

### One-time setup

```bash
# 1. Start PostgreSQL (or use an existing server)
docker compose up -d db

# 2. Create the dedicated test database
createdb -h localhost -U postgres jwt_rbac_test

# 3. Install the driver and tooling
pip install -e ".[dev]"
```

### Running

```bash
pytest                                    # whole suite
pytest tests/test_rbac.py                 # a single file
pytest -k "blacklist or refresh"          # by keyword
pytest --cov=jwt_rbac --cov-report=html   # with an HTML coverage report
```

### Pointing at a different database

Override `TEST_DATABASE_URL` — it defaults to
`postgresql://postgres:root@localhost:5432/jwt_rbac_test`:

```bash
# macOS / Linux
export TEST_DATABASE_URL=postgresql://user:pass@host:5432/my_test_db

# Windows (cmd)
set TEST_DATABASE_URL=postgresql://user:pass@host:5432/my_test_db

# PowerShell
$env:TEST_DATABASE_URL = "postgresql://user:pass@host:5432/my_test_db"
```

### How isolation works

Running against a real database means test data must not leak between tests. The suite uses
**transaction rollback** rather than truncation, which is both faster and stricter:

1. The schema is created **once per session** on a committed connection and seeded with the
   four permissions and the ADMIN / USER / MODERATOR roles.
2. Each test runs inside its **own outer transaction**, which is rolled back during teardown.
3. Sessions are bound to that connection with `join_transaction_mode="create_savepoint"`, so the
   `db.commit()` calls made by the application under test become **savepoints** rather than real
   commits. The outer rollback therefore undoes everything.
4. In-memory state that lives outside the database — the token blacklist and the rate limiter — is
   reset by an autouse fixture.

The result: every test starts from a known, empty state, and the suite is **order-independent**
(it passes identically in alphabetical and reverse file order).

### Test coverage

| Module | Coverage |
|---|---|
| `core/security.py` | 98% |
| `services/auth_service.py` | 98% |
| `setup.py` | 89% |
| `repositories/sql_user_repo.py` | 88% |
| `core/dependencies.py` | 85% |
| `repositories/sql_role_repo.py` | 79% |
| `seed.py` | 79% |
| **Total (`jwt_rbac`)** | **92%** |

---

## 🐳 Docker

```bash
# App + PostgreSQL
docker compose up

# App + PostgreSQL + Redis (for the token blacklist)
docker compose --profile redis up
```

To run the test suite against the compose-managed database:

```bash
docker compose up -d db
docker compose exec db createdb -U postgres jwt_rbac_test
pytest
```

---

## 📡 API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/login` | ❌ | Login, returns token pair (rate-limited) |
| `POST` | `/auth/refresh` | ❌ | Exchange a refresh token for a new pair |
| `POST` | `/auth/logout` | ✅ | Blacklist the current token, returns 204 |
| `GET` | `/auth/me` | ✅ | Alias for `/users/me` |
| `GET` | `/auth/token/info` | ✅ | Decode and return the current token's payload |
| `POST` | `/users/register` | ❌ | Register a new user (accepts optional `role_name`) |
| `GET` | `/users/me` | ✅ | Current user profile |
| `PATCH` | `/users/me/password` | ✅ | Change the current user's password |
| `GET` | `/admin/users` | 🔒 ADMIN | List all users |
| `POST` | `/admin/users/{id}/roles` | 🔒 ADMIN | Assign or revoke a role |
| `PATCH` | `/admin/users/{id}/toggle-active` | 🔒 ADMIN | Toggle a user's active status |
| `GET` | `/admin/roles` | 🔒 ADMIN | List all roles |
| `GET` | `/admin/permissions` | 🔒 ADMIN | List all permissions |
| `PUT` | `/admin/roles/{id}/permissions` | 🔒 ADMIN | Replace all permissions on a role |

### Error envelope

Every error response uses the same shape:

```json
{ "error": "FORBIDDEN", "message": "One of these roles required: ADMIN", "status": 403 }
```

| Code | `error` |
|---|---|
| 400 | `BAD_REQUEST` |
| 401 | `UNAUTHORIZED` |
| 403 | `FORBIDDEN` |
| 404 | `NOT_FOUND` |
| 422 | `VALIDATION_ERROR` (includes a `details` array) |
| 429 | `RATE_LIMITED` |
| 500 | `INTERNAL_ERROR` |

> **Note:** 404s for *unrouted* paths are produced by the router itself, before the app's
> `HTTPException` handler runs, so they return Starlette's default `{"detail": "Not Found"}`.
> 404s raised by application code use the envelope above.

---

## 🎨 Frontend UI Views

The starter kit ships with out-of-the-box templates built from plain HTML/CSS and vanilla JavaScript.

| View | Path | Description |
|---|---|---|
| **Login/Register** | `/` | Authentication and account creation (includes role selection) |
| **Dashboard** | `/dashboard` | Profile info and granted permissions for the signed-in user |
| **Admin Panel** | `/admin-panel` | `ADMIN` only — manage users, assign roles, toggle account state |
| **Stylesheet** | `/static/styles.css` | Bundled CSS |

These routes are hidden from the OpenAPI schema. Pass `include_ui=False` to `setup()` to disable them.

---

## 🤝 Contributing

1. **Don't break the ABCs** — `IUserRepository`, `IRoleRepository`, and `ITokenBlacklist` are the public contract. Adding methods is fine; removing or changing signatures is a breaking change.
2. **All public functions must have type annotations and docstrings.**
3. **New code needs tests.** The suite runs against real PostgreSQL — add fixtures rather than mocks where practical.
4. **Run linting before committing:**
   ```bash
   pre-commit install
   pre-commit run --all-files
   ```
   Or directly:
   ```bash
   ruff check . && ruff format .
   ```

---

## 📝 Security Notes

- Password hashing uses **bcrypt** via the `bcrypt` package directly. `bcrypt.checkpw` is **constant-time** by design, preventing timing attacks.
- Tokens include a `jti` (JWT ID) claim for per-token revocation via the blacklist.
- The refresh token is signed with a **separate secret** from the access token, so a leaked refresh secret cannot be used to mint access tokens.
- Refresh tokens are single-use: rotating one blacklists the old JTI, preventing replay.
- Login is rate-limited to **5 attempts per minute per IP** via `slowapi`.
- Login failures return a generic `Invalid email or password` for both unknown users and wrong passwords, so the endpoint cannot be used to enumerate accounts.
- Errors are logged server-side while the client receives a redacted message.

---

## 📄 License

MIT
