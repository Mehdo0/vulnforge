"""VulnForge — API Routes"""
from datetime import datetime, timezone
from uuid import UUID
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from core.database import get_db
from core.auth import hash_password, verify_password, create_access_token, get_current_user
from core.config import PRICING, TOKEN_COST_PER_1K, PRICING_MARGIN
from models.models import UserModel, ScanModel, FindingModel, ConsentModel, ScanStatus, PlanTier
from schemas.schemas import (
    UserRegister, UserLogin, TokenResponse, UserResponse,
    ScanCreate, ScanResponse, ScanDetailResponse, ScanEstimate,
    FindingResponse, ConsentResponse,
)
from orchestrator.orchestrator import run_audit


router = APIRouter(prefix="/api")


# ══════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════

@router.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegister, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(UserModel).where(UserModel.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = UserModel(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        company=payload.company,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/auth/login", response_model=TokenResponse)
async def login(payload: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")

    token = create_access_token(data={"sub": str(user.id)})
    return TokenResponse(access_token=token)


@router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: UserModel = Depends(get_current_user)):
    return current_user


# ══════════════════════════════════════════════════════
# SCANS
# ══════════════════════════════════════════════════════

@router.post("/scans/estimate", response_model=ScanEstimate)
async def estimate_scan(
    payload: ScanCreate,
    current_user: UserModel = Depends(get_current_user),
):
    """Estimate token usage and cost before starting a scan."""
    tier = PRICING[payload.plan_tier.value]
    base_tokens = 2000  # minimum for any scan
    
    # Rough estimation based on scope
    if payload.scope:
        base_tokens += len(payload.scope) // 10
    
    estimated_tokens = min(base_tokens, tier["max_tokens"])
    token_cost = (estimated_tokens / 1000) * TOKEN_COST_PER_1K
    total_cost = round(token_cost * PRICING_MARGIN + tier["base_price_chf"], 2)
    
    return ScanEstimate(
        estimated_tokens=estimated_tokens,
        estimated_cost_chf=total_cost,
        plan_tier=payload.plan_tier.value,
    )


@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Submit a new security audit."""
    # Enforce plan tier: user cannot request above their plan
    tier_order = {"bronze": 1, "silver": 2, "gold": 3}
    user_tier_level = tier_order.get(current_user.plan_tier.value, 1)
    requested_tier_level = tier_order.get(payload.plan_tier.value, 1)
    if requested_tier_level > user_tier_level:
        raise HTTPException(
            status_code=403,
            detail=f"Your {current_user.plan_tier.value} plan cannot request {payload.plan_tier.value} scans. Please upgrade your plan."
        )
    
    # Check concurrent scan limit
    active_count = await db.execute(
        select(func.count(ScanModel.id)).where(
            ScanModel.user_id == current_user.id,
            ScanModel.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        )
    )
    if active_count.scalar() >= 3:
        raise HTTPException(status_code=429, detail="Max 3 concurrent scans. Wait for active scans to complete.")

    # Estimate cost
    tier = PRICING[payload.plan_tier.value]
    estimated_tokens = min(5000, tier["max_tokens"])
    token_cost = (estimated_tokens / 1000) * TOKEN_COST_PER_1K
    cost_estimate = round(token_cost * PRICING_MARGIN + tier["base_price_chf"], 2)

    scan = ScanModel(
        user_id=current_user.id,
        target_url=payload.target_url,
        scope=payload.scope,
        status=ScanStatus.PENDING,
        estimated_tokens=estimated_tokens,
        cost_estimate=cost_estimate,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Create consent record
    consent = ConsentModel(scan_id=scan.id)
    db.add(consent)
    await db.commit()

    # Launch audit in background
    background_tasks.add_task(run_audit, str(scan.id))

    return ScanResponse(
        id=scan.id,
        target_url=scan.target_url,
        status=scan.status,
        estimated_tokens=scan.estimated_tokens,
        cost_estimate=scan.cost_estimate,
        created_at=scan.created_at,
        started_at=None,
        completed_at=None,
        actual_tokens=None,
        finding_count=0,
    )


@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanModel)
        .where(ScanModel.user_id == current_user.id)
        .order_by(ScanModel.created_at.desc())
        .limit(50)
    )
    scans = result.scalars().all()

    # Count findings for each scan
    scan_ids = [s.id for s in scans]
    finding_counts = {}
    if scan_ids:
        count_result = await db.execute(
            select(FindingModel.scan_id, func.count(FindingModel.id))
            .where(FindingModel.scan_id.in_(scan_ids))
            .group_by(FindingModel.scan_id)
        )
        finding_counts = {row[0]: row[1] for row in count_result}

    return [
        ScanResponse(
            id=s.id, target_url=s.target_url, status=s.status,
            estimated_tokens=s.estimated_tokens, actual_tokens=s.actual_tokens,
            cost_estimate=s.cost_estimate, created_at=s.created_at,
            started_at=s.started_at, completed_at=s.completed_at,
            finding_count=finding_counts.get(s.id, 0),
        ) for s in scans
    ]


@router.get("/scans/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: UUID,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanModel).where(ScanModel.id == scan_id, ScanModel.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(
        select(FindingModel).where(FindingModel.scan_id == scan_id).order_by(FindingModel.severity)
    )
    findings = findings_result.scalars().all()

    return ScanDetailResponse(
        id=scan.id, target_url=scan.target_url, status=scan.status,
        estimated_tokens=scan.estimated_tokens, actual_tokens=scan.actual_tokens,
        cost_estimate=scan.cost_estimate, created_at=scan.created_at,
        started_at=scan.started_at, completed_at=scan.completed_at,
        finding_count=len(findings),
        findings=[FindingResponse(
            id=f.id, agent_type=f.agent_type, title=f.title,
            description=f.description, severity=f.severity,
            cvss_score=f.cvss_score, category=f.category,
            evidence=f.evidence, remediation=f.remediation,
            cwe_id=f.cwe_id, endpoint=f.endpoint,
        ) for f in findings],
    )


# ══════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════

@router.get("/health")
async def health():
    return {"status": "ok", "service": "vulnforge-api", "version": "0.1.0"}
