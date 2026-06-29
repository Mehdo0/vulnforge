"""VulnForge — Database Models"""
from datetime import datetime, timezone
from enum import Enum
import uuid

from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text, Boolean, Enum as SAEnum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID


class Base(DeclarativeBase):
    pass


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanStatus(str, Enum):
    PENDING = "pending"
    CONSENT_VERIFICATION = "consent_verification"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PlanTier(str, Enum):
    BRONZE = "bronze"
    SILVER = "silver"
    GOLD = "gold"


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    company: Mapped[str | None] = mapped_column(String(255), nullable=True)
    plan_tier: Mapped[PlanTier] = mapped_column(SAEnum(PlanTier), default=PlanTier.BRONZE)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scans = relationship("ScanModel", back_populates="user")


class ScanModel(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    estimated_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actual_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_estimate: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    report_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    user = relationship("UserModel", back_populates="scans")
    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    agent_type: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scan = relationship("ScanModel", back_populates="findings")


class ConsentModel(Base):
    __tablename__ = "consents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, unique=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_method: Mapped[str | None] = mapped_column(String(20), nullable=True)
    document_s3_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
