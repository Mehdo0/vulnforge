"""VulnForge — Database Session"""
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from core.config import DATABASE_URL, DATABASE_URL_SYNC
from models.models import Base

# Async engine for FastAPI
async_engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)
AsyncSessionLocal = async_sessionmaker(async_engine, expire_on_commit=False)

# Sync engine for Alembic/scripts
sync_engine = create_engine(
    DATABASE_URL_SYNC,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL_SYNC else {},
)
SyncSessionLocal = sessionmaker(sync_engine)


async def get_db() -> AsyncSession:
    """FastAPI dependency for async DB sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


def init_db():
    """Create all tables."""
    import os
    os.makedirs("data", exist_ok=True)
    Base.metadata.create_all(bind=sync_engine)
