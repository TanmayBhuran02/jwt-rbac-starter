"""Idempotent seed script entry point.

Usage:
    python -m app.seed
"""

from jwt_rbac.seed import seed

seed()
