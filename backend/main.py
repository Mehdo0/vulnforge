"""VulnForge — Main Application"""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from core.config import CORS_ORIGINS
from core.database import init_db
from api.routes import router as api_router

DASHBOARD_PATH = Path(__file__).parent.parent / "frontend" / "dashboard.html"
PRIVACY_PATH = Path(__file__).parent.parent / "frontend" / "privacy.html"
TERMS_PATH = Path(__file__).parent.parent / "frontend" / "terms.html"
COOKIES_PATH = Path(__file__).parent.parent / "frontend" / "cookies.html"
ABOUT_PATH = Path(__file__).parent.parent / "frontend" / "about.html"
CONTACT_PATH = Path(__file__).parent.parent / "frontend" / "contact.html"


def _serve_html(path: Path) -> str:
    """Serve an HTML file if it exists, otherwise return a 404 message."""
    if path.exists():
        return path.read_text()
    return "<h1>Page not found</h1>"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Relaxed CSP for dashboard (needs Google Fonts and inline styles for the dashboard)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'"
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter (per IP). Production should use Redis."""
    def __init__(self, app, max_requests: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next):
        import time
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        
        # Clean old entries
        if client_ip in self.requests:
            self.requests[client_ip] = [
                t for t in self.requests[client_ip] 
                if now - t < self.window_seconds
            ]
        else:
            self.requests[client_ip] = []
        
        # Check rate limit
        if len(self.requests[client_ip]) >= self.max_requests:
            return Response(
                content='{"detail":"Too many requests. Please slow down."}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": str(self.window_seconds)}
            )
        
        self.requests[client_ip].append(now)
        return await call_next(request)


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

# Security headers first
app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting
app.add_middleware(RateLimitMiddleware, max_requests=100, window_seconds=60)

# CORS - use configured origins, never wildcard with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(api_router)


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the VulnForge dashboard."""
    return _serve_html(DASHBOARD_PATH)


@app.get("/privacy", response_class=HTMLResponse)
async def privacy():
    """Serve the privacy policy page."""
    return _serve_html(PRIVACY_PATH)


@app.get("/terms", response_class=HTMLResponse)
async def terms():
    """Serve the terms of service page."""
    return _serve_html(TERMS_PATH)


@app.get("/cookies", response_class=HTMLResponse)
async def cookies():
    """Serve the cookie policy page."""
    return _serve_html(COOKIES_PATH)


@app.get("/about", response_class=HTMLResponse)
async def about():
    """Serve the about page."""
    return _serve_html(ABOUT_PATH)


@app.get("/contact", response_class=HTMLResponse)
async def contact():
    """Serve the contact page."""
    return _serve_html(CONTACT_PATH)
