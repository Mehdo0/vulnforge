"""VulnForge — Core Configuration"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Security
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Database (SQLite for local dev, PostgreSQL via env for Docker)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./data/vulnforge.db",
)
DATABASE_URL_SYNC = DATABASE_URL.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg2")

# Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Scanner settings
MAX_SCAN_DURATION_SECONDS = 600
MAX_CONCURRENT_SCANS_PER_USER = 3
SCAN_RATE_LIMIT = "5/hour"

# Agent settings
AGENT_TIMEOUT_SECONDS = 120
MAX_AGENTS_PER_SCAN = 5

# Token pricing
TOKEN_COST_PER_1K = 0.002
PRICING_MARGIN = 2.0

# Pricing tiers
PRICING = {
    "bronze": {
        "name": "Bronze",
        "description": "Basic security scan",
        "base_price_chf": 19,
        "max_tokens": 5000,
        "features": ["Web vulnerability scan", "Security headers check", "Basic PDF report"],
    },
    "silver": {
        "name": "Silver",
        "description": "Full security audit",
        "base_price_chf": 99,
        "max_tokens": 20000,
        "features": ["All Bronze features", "API security testing", "Configuration audit", "AI-powered analysis", "Detailed PDF report"],
    },
    "gold": {
        "name": "Gold",
        "description": "Enterprise-grade audit + remediation",
        "base_price_chf": 299,
        "max_tokens": 50000,
        "features": ["All Silver features", "Code repository scan", "Fix recommendations with code", "Executive summary", "Priority support"],
    },
}

# CORS
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")

# Report storage
REPORT_DIR = BASE_DIR / "data" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)
