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
- **Frontend UI Templates** — Built-in HTML/CSS templates for Login, Dashboard, and Admin management
- **Admin UI** — User management, role assignment, active/inactive toggling
- **Seed Script** — Idempotent `python -m app.seed` for default data
- **Docker** — One-command deployment with `docker compose up`

---

## 🚀 Quickstart

```bash
git clone https://github.com/your-org/jwt-rbac-starter.git
cd jwt-rbac-starter
cp .env.example .env          # edit secrets!
pip install -r requirements.txt
python -m app.seed             # seed roles + admin user
uvicorn app.main:app --reload  # open http://localhost:8000/login
```

---

## 🔌 Injecting Your Own Repository

Implement the abstract interfaces and pass them to `setup()`:

```python
from app import IUserRepository, IRoleRepository

class MyMongoUserRepository(IUserRepository):
    def find_by_email(self, email: str):
        return self.collection.find_one({"email": email})

    def find_by_id(self, user_id: str):
        return self.collection.find_one({"_id": user_id})

    def create(self, data):
        result = self.collection.insert_one({"email": data.email, ...})
        return result

    def list_all(self):
        return list(self.collection.find())

    def update_password(self, user_id: str, hashed_password: str):
        self.collection.update_one({"_id": user_id}, {"$set": {"hashed_password": hashed_password}})

    def set_active(self, user_id: str, is_active: bool):
        self.collection.update_one({"_id": user_id}, {"$set": {"is_active": is_active}})
```

Any missing abstract method raises a clear `TypeError` at import time — not a cryptic runtime `AttributeError`.

---

## 🛡️ Using `require_role` / `require_permission`

Both work as FastAPI `Depends()`:

```python
from app import require_role, require_permission

# Single role
@router.get("/admin")
async def admin_only(user=Depends(require_role("ADMIN"))):
    ...

# Multiple roles (pass if user has ANY)
@router.get("/reports")
async def reports(user=Depends(require_role("ADMIN", "MODERATOR"))):
    ...

# Permission-based
@router.get("/data")
async def read_data(user=Depends(require_permission("users:read"))):
    ...
```

- **403 Forbidden** when authenticated but missing required role
- **401 Unauthorized** with `WWW-Authenticate: Bearer` when token is missing/expired

---

## ⚙️ Environment Variables

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `SECRET_KEY` | `str` | — | ✅ | JWT signing key (min 32 chars recommended) |
| `REFRESH_SECRET_KEY` | `str` | — | ✅ | Refresh token signing key |
| `ALGORITHM` | `str` | `HS256` | ❌ | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `int` | `30` | ❌ | Access token TTL |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `int` | `7` | ❌ | Refresh token TTL |
| `DATABASE_URL` | `str` | `postgresql://...` | ✅ | SQLAlchemy connection string |
| `REDIS_URL` | `str` | `None` | ❌ | Redis URL for token blacklist |
| `ALLOWED_ORIGINS` | `str` | `localhost` | ❌ | Comma-separated CORS origins |
| `JWT_ISSUER` | `str` | `None` | ❌ | JWT issuer claim (validated when set) |
| `ADMIN_EMAIL` | `str` | `admin@example.com` | ❌ | Seed script admin email |
| `ADMIN_PASSWORD` | `str` | `changeme123` | ❌ | Seed script admin password |

---

## 🧪 Running Tests

```bash
pytest -v
```

With coverage:

```bash
pytest --cov=app --cov-report=html
```

---

## 🐳 Docker

```bash
# App + PostgreSQL
docker compose up

# App + PostgreSQL + Redis (for token blacklist)
docker compose --profile redis up
```

---

## 📡 API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/login` | ❌ | Login, returns token pair |
| `POST` | `/auth/refresh` | ❌ | Refresh tokens |
| `POST` | `/auth/logout` | ✅ | Blacklist tokens, returns 204 |
| `GET` | `/auth/me` | ✅ | Alias for `/users/me` |
| `GET` | `/auth/token/info` | ✅ | Token introspection |
| `POST` | `/users/register` | ❌ | Register new user (accepts optional `role_name`) |
| `GET` | `/users/me` | ✅ | Current user profile |
| `PATCH` | `/users/me/password` | ✅ | Change password |
| `GET` | `/admin/users` | 🔒 ADMIN | List all users |
| `POST` | `/admin/users/{id}/roles` | 🔒 ADMIN | Assign/revoke role |
| `PATCH` | `/admin/users/{id}/toggle-active` | 🔒 ADMIN | Toggle user active |
| `GET` | `/admin/roles` | 🔒 ADMIN | List all roles |
| `PUT` | `/admin/roles/{id}/permissions` | 🔒 ADMIN | Assign / update permissions for a role |

---

## 🎨 Frontend UI Views

The starter kit comes with out-of-the-box frontend templates built using pure HTML/CSS and vanilla JavaScript. 

| View | Path | Description |
|---|---|---|
| **Login/Register** | `/login` | Handles user authentication and account creation (includes role selection). |
| **Dashboard** | `/dashboard` | Protected route for authenticated users to view profile info and permissions. |
| **Admin Panel** | `/admin/ui` | Protected route for `ADMIN` role. Manage users, assign roles, and toggle account states. |

---

## 🤝 Contributing

1. **Don't break the ABCs** — `IUserRepository`, `IRoleRepository`, and `ITokenBlacklist` are the public contract. Adding methods is fine; removing or changing signatures is a breaking change.
2. **All public functions must have type annotations and docstrings.**
3. **Run linting before committing:**
   ```bash
   pre-commit install
   pre-commit run --all-files
   ```

---

## 📝 Security Notes

- Password hashing uses **bcrypt** via `passlib`. The `bcrypt.checkpw` function is **constant-time** by design, preventing timing attacks.
- Tokens include a `jti` (JWT ID) claim for per-token revocation via the blacklist.
- The refresh token uses a **separate secret** from the access token.
- Login is rate-limited to **5 attempts per minute per IP** via `slowapi`.

---

## License

MIT
