"""
Frontend router — serves the PhishGuard Nexus SPA at /.
"""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os

router = APIRouter()

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)


@router.get("/", response_class=HTMLResponse)
async def serve_spa(request: Request):
    """Serve the PhishGuard Nexus single-page application."""
    return templates.TemplateResponse("index.html", {"request": request})
