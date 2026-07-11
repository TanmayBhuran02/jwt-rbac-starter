"""FastAPI application entry point.

Initializes and configures the application using the package's ``setup()`` API.
"""

import logging

from jwt_rbac.config import get_settings
from jwt_rbac.setup import setup

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Build application instance using setup API
settings = get_settings()
app = setup(
    secret_key=settings.secret_key,
    refresh_secret_key=settings.refresh_secret_key,
    token_expire_minutes=settings.access_token_expire_minutes,
    include_ui=True,
    router_prefix="",
)
