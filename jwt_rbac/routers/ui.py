"""UI router: template routes for login, dashboard, and admin-panel."""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

_PACKAGE_DIR = Path(__file__).resolve().parent.parent

router = APIRouter(tags=["ui"])
templates = Jinja2Templates(directory=str(_PACKAGE_DIR / "templates"))


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def index(request: Request) -> HTMLResponse:
    """Login page."""
    return templates.TemplateResponse("login.html", {"request": request})


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard(request: Request) -> HTMLResponse:
    """Dashboard page."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@router.get("/admin-panel", response_class=HTMLResponse, include_in_schema=False)
def admin_panel(request: Request) -> HTMLResponse:
    """Admin panel page."""
    return templates.TemplateResponse("admin.html", {"request": request})
