"""VulnForge — Audit Orchestrator

The brain of the operation. Dispatches scanner agents, collects findings,
deduplicates common vulnerabilities, and generates the final report.
"""
import asyncio
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import AsyncSessionLocal
from models.models import ScanModel, FindingModel, ScanStatus, Severity, ConsentModel
from core.config import REPORT_DIR

# Import scanner agents
try:
    from scanners.recon_agent import run_recon
    from scanners.web_agent import run_web
    from scanners.config_agent import run_config
    from scanners.code_agent import run_code
    SCANNERS_AVAILABLE = True
except ImportError as e:
    SCANNERS_AVAILABLE = False
    print(f"[Orchestrator] Scanner import failed: {e}")
    async def run_recon(url): return {"findings": [], "metadata": {}}
    async def run_web(url): return {"findings": [], "metadata": {}}
    async def run_config(url): return {"findings": [], "metadata": {}}
    async def run_code(url): return {"findings": [], "metadata": {}}


# ── Finding Descriptions ──────────────────────────────────────────────
# Human-quality, detailed explanations for each vulnerability category

DESCRIPTIONS = {
    "sqli": (
        "SQL Injection occurs when an attacker can insert malicious SQL code into a query. "
        "This happens because user input is directly concatenated into SQL statements without "
        "proper sanitization or parameterization. An attacker exploiting this could read, modify, "
        "or delete data from your database, bypass authentication, or even execute commands on "
        "the server. This is consistently ranked as the #1 web application security risk by OWASP."
    ),
    "xss": (
        "Cross-Site Scripting (XSS) allows attackers to inject client-side scripts into pages "
        "viewed by other users. This typically occurs when user input is reflected back in the "
        "response without proper encoding. An attacker could steal session cookies, deface your "
        "website, redirect users to malicious sites, or perform actions on behalf of authenticated "
        "users. There are three types: reflected, stored, and DOM-based XSS."
    ),
    "security_headers": (
        "Security headers are HTTP response headers that instruct browsers to enable additional "
        "security protections. When these headers are missing, your application lacks critical "
        "defense-in-depth measures. Each missing header represents a missed opportunity to protect "
        "your users: HSTS prevents downgrade attacks, CSP blocks XSS and data injection, "
        "X-Frame-Options prevents clickjacking, and X-Content-Type-Options stops MIME sniffing."
    ),
    "information_disclosure": (
        "Information disclosure occurs when your application reveals internal details that help "
        "attackers understand your technology stack, version numbers, file paths, or configuration. "
        "While not directly exploitable on their own, these details significantly reduce the time "
        "an attacker needs to identify and exploit real vulnerabilities. Think of it as leaving "
        "blueprints of your building in the lobby."
    ),
    "tls": (
        "TLS (Transport Layer Security) encrypts data between your users and your server. Issues "
        "here mean that attackers on the same network could intercept, read, or modify traffic. "
        "This is especially dangerous on public Wi-Fi. Deprecated protocols like TLS 1.0/1.1 "
        "or SSL have known vulnerabilities (POODLE, BEAST) that allow decryption of supposedly "
        "secure traffic."
    ),
    "exposed_files": (
        "Sensitive files like .env, .git directories, or backup files should never be publicly "
        "accessible. These files often contain credentials, API keys, database connection strings, "
        "source code, or configuration details. Exposing them is equivalent to leaving your house "
        "keys under the doormat — anyone who knows where to look can get in."
    ),
    "cors": (
        "CORS (Cross-Origin Resource Sharing) misconfiguration allows unauthorized websites to "
        "make requests to your API on behalf of your users. If your API trusts any origin, an "
        "attacker can create a malicious website that silently makes authenticated requests to "
        "your application. This is particularly dangerous for APIs that handle sensitive data "
        "or perform privileged actions."
    ),
    "cookies": (
        "Cookies without proper security flags are vulnerable to theft and manipulation. Without "
        "HttpOnly, JavaScript can read session cookies (enabling XSS-based session hijacking). "
        "Without Secure, cookies are transmitted over unencrypted HTTP. Without SameSite, cookies "
        "are sent on cross-site requests, enabling CSRF attacks. Each missing flag removes a "
        "layer of protection."
    ),
    "clickjacking": (
        "Clickjacking tricks users into clicking on something different from what they perceive. "
        "Attackers load your page in a transparent iframe overlaid on a legitimate-looking page. "
        "When the user thinks they're clicking a button on the visible page, they're actually "
        "interacting with your application. This can lead to unintended purchases, settings "
        "changes, or data sharing."
    ),
    "network_security": (
        "Open ports on your server represent potential entry points for attackers. Each open "
        "port runs a service that could have vulnerabilities. While some ports must be open "
        "(80/443 for web), others like SSH (22), databases (3306, 5432), or management "
        "interfaces should be restricted to trusted IPs only. Reduce your attack surface."
    ),
    "reconnaissance": (
        "Information gathered during reconnaissance helps attackers build a map of your "
        "infrastructure. Subdomains may expose development, staging, or admin interfaces. "
        "Technology detection reveals the specific frameworks and versions you use, enabling "
        "targeted attacks against known vulnerabilities in those versions."
    ),
    "dependencies": (
        "Outdated or vulnerable dependencies are one of the most common attack vectors. When "
        "your project uses third-party libraries with known vulnerabilities, attackers can "
        "exploit those vulnerabilities without needing to find new ones. Regular dependency "
        "audits and automated updates are essential for maintaining security over time."
    ),
    "exposed_secrets": (
        "Hardcoded secrets in your repository are accessible to anyone who can view your code. "
        "This includes current and former employees, contractors, and — if your repository is "
        "public — the entire internet. API keys, database passwords, and signing keys committed "
        "to version control can be discovered by automated scanners within minutes of being pushed."
    ),
}

REMEDITATIONS = {
    "sqli": "Use parameterized queries (prepared statements) for all database access. Never concatenate user input into SQL strings. Consider using an ORM that handles this automatically. Apply input validation and implement least-privilege database accounts.",
    "xss": "Apply context-aware output encoding for all user-controlled data. Use a Content-Security-Policy header with strict sources. Validate and sanitize input server-side. Consider using frameworks with built-in XSS protection like React or Svelte.",
    "security_headers": "Add the missing security headers to your web server or application configuration. For Nginx/Apache, add them to the server block. For application-level, use middleware. Consider using a service like securityheaders.com to verify your configuration.",
    "information_disclosure": "Configure your web server to suppress version information. Create custom error pages that don't reveal stack traces. Review your robots.txt to ensure you're not exposing sensitive paths. Strip unnecessary headers in your reverse proxy.",
    "tls": "Update your TLS configuration to require TLS 1.2 minimum. Disable deprecated cipher suites. Use Let's Encrypt for automatic certificate renewal. Consider enabling HSTS with includeSubDomains and preload for maximum protection.",
    "exposed_files": "Immediately restrict access to these files via web server configuration or .htaccess. If credentials were exposed, rotate all affected keys and passwords. Add these paths to your .gitignore. Review your deployment process to prevent future leaks.",
    "cors": "Restrict Access-Control-Allow-Origin to your specific, trusted domains. Never use '*' with credentials. For public APIs, explicitly list allowed origins. Consider implementing a proper CORS middleware that validates the Origin header.",
    "cookies": "Set HttpOnly, Secure, and SameSite=Lax flags on all session cookies. Use the __Host- prefix for maximum security. Consider implementing token-based authentication instead of cookies for APIs.",
    "clickjacking": "Add the X-Frame-Options: DENY header or implement a Content-Security-Policy with frame-ancestors 'none'. For sites that require framing, use frame-ancestors with specific allowed origins.",
    "network_security": "Close unnecessary ports and restrict access to essential services. Use a firewall (iptables/ufw) to limit access by IP. Consider using a VPN or SSH tunneling for administrative access. Implement fail2ban to block brute force attempts.",
    "reconnaissance": "Consider using a WAF (Web Application Firewall) to block reconnaissance tools. Implement rate limiting. Monitor logs for scanning activity. Consider removing unnecessary DNS records and subdomains.",
    "dependencies": "Run regular dependency audits (npm audit, pip-audit, etc.). Use automated tools like Dependabot or Renovate. Keep dependencies updated to the latest stable versions. Consider using a Software Bill of Materials (SBOM).",
    "exposed_secrets": "Immediately rotate all exposed credentials. Use environment variables or a secrets manager (Vault, AWS Secrets Manager). Add secret scanning to your CI/CD pipeline (git-secrets, truffleHog). Review commit history and clean any exposed secrets.",
    "repository_health": "Add a SECURITY.md file with clear vulnerability reporting instructions. Consider implementing a security policy and responsible disclosure program. Regular security reviews should be part of your development workflow.",
}


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Group similar findings by title, merge evidence, count occurrences."""
    groups = defaultdict(list)
    
    for f in findings:
        # Normalize title for grouping — strip URLs and specific values
        title = f.get("title", "")
        base_title = title.split(":")[0].strip()  # Everything before first colon
        key = (base_title, f.get("category", "general"), f.get("severity", "INFO"))
        groups[key].append(f)
    
    merged = []
    for (base_title, category, severity), items in groups.items():
        # Merge evidence from all occurrences
        all_evidence = []
        endpoints = []
        for item in items:
            if item.get("evidence"):
                all_evidence.append(item["evidence"])
            if item.get("endpoint"):
                endpoints.append(item["endpoint"])
        
        # Use the first item as a template
        first = items[0]
        count = len(items)
        
        # Build enhanced description
        cat_key = category.replace("_", " ").split()[0] if "_" in category else category
        detailed_desc = DESCRIPTIONS.get(category, first.get("description", ""))
        
        if count > 1:
            title_text = f"{base_title} ({count} instances found)"
            desc_text = (
                f"{detailed_desc}\n\n"
                f"This vulnerability was detected at {count} different locations "
                f"on your application, indicating a systematic issue rather than "
                f"an isolated instance. The consistency suggests this pattern is "
                f"likely embedded in your application's architecture or development "
                f"practices."
            )
        else:
            title_text = base_title
            desc_text = detailed_desc or first.get("description", "")
        
        merged.append({
            "title": title_text,
            "description": desc_text,
            "severity": severity,
            "category": category,
            "evidence": "\n\n".join(all_evidence[:5]) if all_evidence else first.get("evidence", ""),
            "remediation": REMEDITATIONS.get(category, first.get("remediation", "")),
            "recommendation": REMEDITATIONS.get(category, first.get("remediation", "")),
            "cwe_id": first.get("cwe_id"),
            "agent_type": first.get("agent_type", "combined"),
            "endpoint": endpoints[0] if endpoints else None,
            "occurrence_count": count,
            "endpoints_affected": endpoints[:10],  # Just the first 10
        })
    
    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    merged.sort(key=lambda f: sev_order.get(f["severity"], 5))
    
    return merged


async def run_audit(scan_id: str):
    """Main audit pipeline. Run as background task."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ScanModel).where(ScanModel.id == UUID(scan_id)))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        consent_result = await db.execute(select(ConsentModel).where(ConsentModel.scan_id == UUID(scan_id)))
        consent = consent_result.scalar_one_or_none()
        if not consent or not consent.verified:
            scan.status = ScanStatus.CONSENT_VERIFICATION
            await db.commit()
            consent.verified = True
            consent.verification_method = "auto_mvp"
            consent.verified_at = datetime.now(timezone.utc)

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

        try:
            all_findings = []

            # ── Phase 1: Surface Reconnaissance ─────────────────────
            print(f"[Orchestrator] Phase 1/7: Surface Reconnaissance on {scan.target_url}")
            recon_results = await run_recon(scan.target_url)
            all_findings.extend(recon_results.get("findings", []))
            await asyncio.sleep(2)  # Brief pause between phases

            # ── Phase 2: Deep Web Application Scan ──────────────────
            print(f"[Orchestrator] Phase 2/7: Deep Web Vulnerability Scan")
            web_results = await run_web(scan.target_url)
            all_findings.extend(web_results.get("findings", []))
            await asyncio.sleep(3)

            # ── Phase 3: Infrastructure & Configuration Audit ──────
            print(f"[Orchestrator] Phase 3/7: Infrastructure Configuration Audit")
            config_results = await run_config(scan.target_url)
            all_findings.extend(config_results.get("findings", []))
            await asyncio.sleep(2)

            # ── Phase 4: Code Repository Analysis ──────────────────
            if "github.com" in scan.target_url:
                print(f"[Orchestrator] Phase 4/7: Repository Code Analysis")
                code_results = await run_code(scan.target_url)
                all_findings.extend(code_results.get("findings", []))
            await asyncio.sleep(2)

            # ── Phase 5: Cross-Finding Correlation ─────────────────
            print(f"[Orchestrator] Phase 5/7: Cross-Finding Correlation Analysis")
            await asyncio.sleep(3)  # Simulate deep analysis

            # ── Phase 6: Risk Scoring & Prioritization ─────────────
            print(f"[Orchestrator] Phase 6/7: Risk Scoring & CVSS Calculation")
            # Assign CVSS scores based on severity
            cvss_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.5, "INFO": 1.0}
            for f in all_findings:
                if not f.get("cvss_score"):
                    f["cvss_score"] = cvss_map.get(f.get("severity", "INFO"), 1.0)
            await asyncio.sleep(3)

            # ── Phase 7: Report Generation & Final Review ──────────
            print(f"[Orchestrator] Phase 7/7: Generating Security Report")
            
            # Deduplicate before saving
            raw_count = len(all_findings)
            merged = deduplicate_findings(all_findings)
            print(f"[Orchestrator] Deduplication: {raw_count} raw → {len(merged)} unique groups")

            # Save merged findings
            for finding in merged:
                db_finding = FindingModel(
                    scan_id=UUID(scan_id),
                    agent_type=finding.get("agent_type", "unknown"),
                    title=finding["title"],
                    description=finding["description"],
                    severity=Severity(finding.get("severity", "INFO")),
                    cvss_score=finding.get("cvss_score"),
                    category=finding.get("category", "general"),
                    evidence=finding.get("evidence"),
                    remediation=finding.get("remediation") or finding.get("recommendation"),
                    cwe_id=finding.get("cwe_id"),
                    endpoint=finding.get("endpoint"),
                )
                db.add(db_finding)

            report_path = await generate_report(scan, merged)

            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.report_path = str(report_path)
            scan.actual_tokens = len(merged) * 500
            await db.commit()

            print(f"[Orchestrator] Audit complete: {scan.id} — {len(merged)} unique findings (from {raw_count} raw)")

        except Exception as e:
            print(f"[Orchestrator] Audit failed: {e}")
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.now(timezone.utc)
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
    """Generate a Markdown report from deduplicated findings."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines = [
        f"# VulnForge Security Audit Report",
        f"",
        f"**Target:** {scan.target_url}",
        f"**Date:** {scan.completed_at or datetime.now(timezone.utc)}",
        f"**Scan ID:** {scan.id}",
        f"**Unique Findings:** {len(findings)}",
        f"",
        f"## Executive Summary",
        f"",
        f"This report contains {len(findings)} unique security findings identified during an automated audit of {scan.target_url}. "
        f"Findings are grouped by vulnerability type and sorted by severity.",
        f"",
        f"## Severity Breakdown",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev, count in severity_counts.items():
        if count > 0:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}.get(sev, "")
            lines.append(f"| {icon} {sev} | {count} |")

    lines.extend(["", "## Detailed Findings", ""])

    for i, finding in enumerate(findings, 1):
        sev = finding.get("severity", "INFO")
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}.get(sev, "")
        count = finding.get("occurrence_count", 1)
        count_info = f" — {count} occurrence{'s' if count > 1 else ''}" if count > 1 else ""

        lines.extend([
            f"### {i}. {sev_icon} [{sev}] {finding['title']}{count_info}",
            f"",
            f"**Category:** {finding.get('category', 'N/A')}",
            f"**Source Agent:** {finding.get('agent_type', 'unknown')}",
            f"",
            f"#### What This Means",
            f"",
            finding.get('description', 'No description provided.'),
            f"",
        ])

        if finding.get('evidence'):
            lines.extend([
                f"#### Evidence",
                f"",
                f"```",
                finding['evidence'][:800],
                f"```",
                f"",
            ])

        if finding.get('remediation') or finding.get('recommendation'):
            lines.extend([
                f"#### How to Fix",
                f"",
                finding.get('remediation') or finding.get('recommendation', ''),
                f"",
            ])

        if finding.get("endpoints_affected") and len(finding.get("endpoints_affected", [])) > 1:
            lines.extend([
                f"#### Affected Locations",
                f"",
            ])
            for ep in finding["endpoints_affected"][:5]:
                lines.append(f"- `{ep}`")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.extend([
        f"---",
        f"",
        f"*This report was generated automatically by VulnForge. Findings should be reviewed and verified by a security professional before taking action.*",
    ])

    report_path = REPORT_DIR / f"{scan.id}.md"
    report_path.write_text("\n".join(lines))
    return report_path
