"""VulnForge — API Schemas (Pydantic)"""
from datetime import datetime
from uuid import UUID
from typing import Optional
from pydantic import BaseModel, EmailStr, Field

from models.models import Severity, ScanStatus, PlanTier


# ── Auth ──────────────────────────────────────────────
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    company: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserResponse(BaseModel):
    id: UUID
    email: str
    company: Optional[str]
    plan_tier: PlanTier
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ── Scans ─────────────────────────────────────────────
class ScanCreate(BaseModel):
    target_url: str = Field(max_length=2048)
    scope: Optional[str] = None
    plan_tier: PlanTier = PlanTier.BRONZE

class ScanEstimate(BaseModel):
    estimated_tokens: int
    estimated_cost_chf: float
    plan_tier: str

class ScanResponse(BaseModel):
    id: UUID
    target_url: str
    status: ScanStatus
    estimated_tokens: Optional[int]
    actual_tokens: Optional[int]
    cost_estimate: Optional[float]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    finding_count: int = 0

    class Config:
        from_attributes = True


# ── Findings ──────────────────────────────────────────
class FindingResponse(BaseModel):
    id: UUID
    agent_type: str
    title: str
    description: str
    severity: Severity
    cvss_score: Optional[float]
    category: str
    evidence: Optional[str]
    remediation: Optional[str]
    cwe_id: Optional[str]
    endpoint: Optional[str]

    class Config:
        from_attributes = True

class ScanDetailResponse(ScanResponse):
    findings: list[FindingResponse] = []


# ── Consent ───────────────────────────────────────────
class ConsentResponse(BaseModel):
    id: UUID
    scan_id: UUID
    verified: bool
    verification_method: Optional[str]
    verified_at: Optional[datetime]

    class Config:
        from_attributes = True
