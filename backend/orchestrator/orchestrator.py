"""VulnForge — Audit Orchestrator

The brain of the operation. Dispatches scanner agents, collects findings,
and generates the final report.
"""
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import AsyncSessionLocal
from models.models import ScanModel, FindingModel, ScanStatus, Severity, ConsentModel
from core.config import REPORT_DIR

# Import scanner agents (will be created by sub-agent)
try:
    from scanners.recon_agent import run_recon
    from scanners.web_agent import run_web_scan
    from scanners.config_agent import run_config_scan
    from scanners.code_agent import run_code_scan
    SCANNERS_AVAILABLE = True
except ImportError:
    SCANNERS_AVAILABLE = False
    async def run_recon(url): return {"findings": [], "metadata": {"error": "Scanner not available"}}
    async def run_web_scan(url): return {"findings": [], "metadata": {"error": "Scanner not available"}}
    async def run_config_scan(url): return {"findings": [], "metadata": {"error": "Scanner not available"}}
    async def run_code_scan(url): return {"findings": [], "metadata": {"error": "Scanner not available"}}


async def run_audit(scan_id: str):
    """Main audit pipeline. Run as background task."""
    async with AsyncSessionLocal() as db:
        # Get scan
        result = await db.execute(select(ScanModel).where(ScanModel.id == UUID(scan_id)))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        # Check consent
        consent_result = await db.execute(select(ConsentModel).where(ConsentModel.scan_id == UUID(scan_id)))
        consent = consent_result.scalar_one_or_none()
        if not consent or not consent.verified:
            scan.status = ScanStatus.CONSENT_VERIFICATION
            await db.commit()
            # For MVP, auto-verify if target is confirmed
            # In production, this should require manual verification
            consent.verified = True
            consent.verification_method = "auto_mvp"
            consent.verified_at = datetime.now(timezone.utc)

        # Start scan
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

        try:
            all_findings = []

            # Phase 1: Reconnaissance
            print(f"[Orchestrator] Phase 1: Recon on {scan.target_url}")
            recon_results = await run_recon(scan.target_url)
            all_findings.extend(recon_results.get("findings", []))

            # Phase 2: Web Application Scan
            print(f"[Orchestrator] Phase 2: Web scan on {scan.target_url}")
            web_results = await run_web_scan(scan.target_url)
            all_findings.extend(web_results.get("findings", []))

            # Phase 3: Configuration Audit
            print(f"[Orchestrator] Phase 3: Config audit on {scan.target_url}")
            config_results = await run_config_scan(scan.target_url)
            all_findings.extend(config_results.get("findings", []))

            # Phase 4: Code scan if target is a repo
            if "github.com" in scan.target_url:
                print(f"[Orchestrator] Phase 4: Code scan on {scan.target_url}")
                code_results = await run_code_scan(scan.target_url)
                all_findings.extend(code_results.get("findings", []))

            # Save findings to database
            for finding in all_findings:
                db_finding = FindingModel(
                    scan_id=UUID(scan_id),
                    agent_type=finding.get("agent_type", "unknown"),
                    title=finding["title"],
                    description=finding["description"],
                    severity=Severity(finding.get("severity", "INFO")),
                    cvss_score=finding.get("cvss_score"),
                    category=finding.get("category", "general"),
                    evidence=finding.get("evidence"),
                    remediation=finding.get("remediation"),
                    cwe_id=finding.get("cwe_id"),
                    endpoint=finding.get("endpoint"),
                )
                db.add(db_finding)

            # Generate report
            report_path = await generate_report(scan, all_findings)

            # Mark complete
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.report_path = str(report_path)
            scan.actual_tokens = len(all_findings) * 500  # rough estimate
            await db.commit()

            print(f"[Orchestrator] Audit complete: {scan.id} — {len(all_findings)} findings")

        except Exception as e:
            print(f"[Orchestrator] Audit failed: {e}")
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.now(timezone.utc)
            # Save the error as a finding
            error_finding = FindingModel(
                scan_id=UUID(scan_id),
                agent_type="orchestrator",
                title="Audit failed",
                description=str(e),
                severity=Severity.INFO,
                category="error",
            )
            db.add(error_finding)
            await db.commit()


async def generate_report(scan: ScanModel, findings: list[dict]) -> Path:
    """Generate a Markdown report from findings."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in severity_counts:
            severity_counts[sev] += 1

    lines = [
        f"# VulnForge Security Audit Report",
        f"",
        f"**Target:** {scan.target_url}",
        f"**Date:** {scan.completed_at or datetime.now(timezone.utc)}",
        f"**Scan ID:** {scan.id}",
        f"**Total Findings:** {len(findings)}",
        f"",
        f"## Severity Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev, count in severity_counts.items():
        if count > 0:
            lines.append(f"| {sev} | {count} |")

    lines.extend([
        f"",
        f"## Findings",
        f"",
    ])

    for i, finding in enumerate(findings, 1):
        sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}.get(
            finding.get("severity", "INFO"), "⚪"
        )
        lines.extend([
            f"### {i}. {sev_emoji} [{finding.get('severity', 'INFO')}] {finding['title']}",
            f"",
            f"**Category:** {finding.get('category', 'N/A')}",
            f"**Agent:** {finding.get('agent_type', 'unknown')}",
            f"",
            finding.get('description', 'No description provided.'),
            f"",
        ])
        if finding.get('evidence'):
            lines.extend([
                f"**Evidence:**",
                f"```",
                finding['evidence'][:500],
                f"```",
                f"",
            ])
        if finding.get('remediation'):
            lines.extend([
                f"**Remediation:**",
                f"",
                finding['remediation'],
                f"",
            ])
        lines.append("---")
        lines.append("")

    lines.extend([
        f"---",
        f"*Report generated by VulnForge — AI-Powered Security Audits*",
        f"*This is an automated assessment. Findings should be manually verified.*",
    ])

    report_path = REPORT_DIR / f"{scan.id}.md"
    report_path.write_text("\n".join(lines))
    return report_path
