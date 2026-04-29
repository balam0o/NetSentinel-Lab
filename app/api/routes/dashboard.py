from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(tags=["dashboard"])

BASE_DIR = Path(__file__).resolve().parents[2]
DASHBOARD_FILE = BASE_DIR / "static" / "dashboard" / "index.html"


@router.get("/dashboard", include_in_schema=False)
def get_dashboard():
    return FileResponse(DASHBOARD_FILE)