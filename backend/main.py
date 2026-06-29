"""VulnForge — Main Application"""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from core.config import CORS_ORIGINS
from core.database import init_db
from api.routes import router as api_router

DASHBOARD_PATH = Path(__file__).parent.parent / "frontend" / "dashboard.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print("[VulnForge] Database initialized")
    yield
    print("[VulnForge] Shutting down")


app = FastAPI(
    title="VulnForge API",
    description="AI-Powered Cybersecurity Audit Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Dev mode: allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the VulnForge dashboard."""
    if DASHBOARD_PATH.exists():
        return DASHBOARD_PATH.read_text()
    return "<h1>Dashboard not found</h1>"
