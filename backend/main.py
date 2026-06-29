"""VulnForge — Main Application"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import CORS_ORIGINS
from core.database import init_db
from api.routes import router as api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    print("[VulnForge] Database initialized")
    yield
    # Shutdown
    print("[VulnForge] Shutting down")


app = FastAPI(
    title="VulnForge API",
    description="AI-Powered Cybersecurity Audit Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/")
async def root():
    return {
        "service": "VulnForge",
        "version": "0.1.0",
        "status": "operational",
        "docs": "/docs",
    }
