"""UI router: template routes for login, dashboard, and admin-panel."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["ui"])
templates = Jinja2Templates(directory="app/templates")


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
