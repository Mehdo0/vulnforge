"""
VulnForge — Web Application Security Agent

Tests for OWASP Top 10 vulnerabilities:
  - Reflected XSS
  - SQL Injection (error-based)
  - Security header analysis (CSP, HSTS, X-Frame-Options, etc.)
  - Information disclosure (server headers, verbose errors, debug endpoints)
  - CORS misconfiguration
"""

from __future__ import annotations

import asyncio
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from .base import BaseAgent, Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# XSS test payloads
# ---------------------------------------------------------------------------

XSS_PAYLOADS: List[Dict[str, str]] = [
    {
        "name": "Basic script tag",
        "payload": '<script>alert("VulnForge-XSS")</script>',
        "pattern": r'<script>alert\("VulnForge-XSS"\)</script>',
    },
    {
        "name": "Img onerror",
        "payload": '<img src=x onerror=alert("VulnForge-XSS")>',
        "pattern": r'<img src=x onerror=alert\("VulnForge-XSS"\)>',
    },
    {
        "name": "SVG onload",
        "payload": '<svg onload=alert("VulnForge-XSS")>',
        "pattern": r'<svg onload=alert\("VulnForge-XSS"\)>',
    },
    {
        "name": "Body onload",
        'payload': '<body onload=alert("VulnForge-XSS")>',
        "pattern": r'<body onload=alert\("VulnForge-XSS"\)>',
    },
    {
        "name": "javascript: URL",
        "payload": 'javascript:alert("VulnForge-XSS")',
        "pattern": r'javascript:alert\("VulnForge-XSS"\)',
    },
]

# ---------------------------------------------------------------------------
# SQL Injection test payloads
# ---------------------------------------------------------------------------

SQLI_PAYLOADS: List[Dict[str, str]] = [
    {
        "name": "Single quote",
        "payload": "'",
        "pattern": r"(?i)(?:sql|syntax|error|warning|unclosed|mysql|postgresql|sqlite|ora-|microsoft sql|odbc|driver|db2|\" at line)",
    },
    {
        "name": "Double quote",
        'payload': '"',
        "pattern": r"(?i)(?:sql|syntax|error|warning|unclosed|mysql|postgresql|sqlite|ora-|microsoft sql|odbc|driver|db2|\" at line)",
    },
    {
        "name": "Boolean OR 1=1",
        "payload": "' OR '1'='1",
        "pattern": r"(?i)(?:sql|syntax|error|warning|unclosed|mysql|postgresql|sqlite|ora-|microsoft sql|odbc)",
    },
    {
        "name": "Boolean OR 1=1--",
        "payload": "' OR 1=1--",
        "pattern": r"(?i)(?:sql|syntax|error|warning|unclosed|mysql|postgresql|sqlite|ora-|microsoft sql|odbc)",
    },
    {
        "name": "UNION SELECT",
        "payload": "' UNION SELECT NULL--",
        "pattern": r"(?i)(?:sql|syntax|error|column|the used select statements have a different number of columns|ora-|mysql|postgresql)",
    },
    {
        "name": "Sleep/time-based",
        "payload": "'; WAITFOR DELAY '00:00:05'--",
        "pattern": r"(?i)(?:sql|syntax|error|timeout|mysql|postgresql|sqlite|ora-)",
    },
]

# ---------------------------------------------------------------------------
# Debug / information disclosure paths
# ---------------------------------------------------------------------------

DEBUG_PATHS: List[str] = [
    "/debug",
    "/debug/",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/.env",
    "/error",
    "/errors",
    "/trace",
    "/stacktrace",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/info",
    "/metrics",
    "/health",
    "/status",
    "/server-status",
    "/server-info",
    "/phpmyadmin",
    "/adminer",
]

# ---------------------------------------------------------------------------
# CORS test origins
# ---------------------------------------------------------------------------

CORS_TEST_ORIGINS: List[str] = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://vulnforge-evil.com",
]


class WebAgent(BaseAgent):
    """Web application security agent — OWASP Top 10 vulnerability scanner."""

    agent_name = "web"

    async def run(self) -> ScanResult:
        """Execute all web security checks."""
        result = ScanResult(
            metadata={
                "target": self.target,
                "hostname": self.hostname,
                "scheme": self.scheme,
            }
        )

        t0 = asyncio.get_event_loop().time()
        self.log(f"Starting web security scan on {self.target}")

        base_url = f"{self.scheme}://{self.hostname}"
        if self.port not in (80, 443, None):
            base_url = f"{self.scheme}://{self.hostname}:{self.port}"

        # Fetch baseline page
        status_code, body, headers = await self.http_get(base_url)
        result.metadata["status_code"] = status_code
        result.metadata["headers"] = headers

        # --- Security header analysis ---
        header_checks = self.check_security_headers(headers)
        result.metadata["header_checks"] = header_checks
        for check in header_checks:
            present = check["present"]
            header = check["header"]
            value = check["value"]
            rec = check["recommendation"]
            cwe = check["cwe"]

            if check["required"] and not present:
                result.add(Finding(
                    title=f"Missing required security header: {header}",
                    description=f"The {header} header is missing. This is a critical security header that should always be present.",
                    severity=Severity.HIGH,
                    category="security_headers",
                    evidence=f"Header '{header}' not in response",
                    recommendation=rec,
                    cwe_id=cwe,
                    agent=self.agent_name,
                ))
            elif not present:
                result.add(Finding(
                    title=f"Missing security header: {header}",
                    description=f"The {header} header is not set.",
                    severity=Severity.MEDIUM if header == "Content-Security-Policy" else Severity.LOW,
                    category="security_headers",
                    evidence=f"Header '{header}' not found in response",
                    recommendation=rec,
                    cwe_id=cwe,
                    agent=self.agent_name,
                ))

        # --- CORS testing ---
        await self._test_cors(base_url, result)

        # --- XSS testing ---
        await self._test_xss(base_url, body, headers, result)

        # --- SQL Injection testing ---
        await self._test_sqli(base_url, result)

        # --- Information disclosure ---
        await self._test_info_disclosure(base_url, result)

        # --- Debug endpoints ---
        await self._test_debug_endpoints(base_url, result)

        result.duration = asyncio.get_event_loop().time() - t0
        self.log(f"Web scan completed in {result.duration:.1f}s — {len(result.findings)} findings")
        return result

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------

    async def _test_cors(self, base_url: str, result: ScanResult) -> None:
        """Test for CORS misconfiguration."""
        for origin in CORS_TEST_ORIGINS:
            headers = {"Origin": origin}
            _, _, resp_headers = await self.http_get(base_url, extra_headers=headers)

            acao = resp_headers.get("Access-Control-Allow-Origin", "")
            acac = resp_headers.get("Access-Control-Allow-Credentials", "")

            # Dangerous: origin reflected + credentials allowed
            if acao == origin or acao == "*":
                if acao == "*" and acac.lower() == "true":
                    result.add(Finding(
                        title="Wildcard CORS with credentials",
                        description="Access-Control-Allow-Origin is '*' and Access-Control-Allow-Credentials is 'true'. This is blocked by browsers but indicates misconfiguration.",
                        severity=Severity.HIGH,
                        category="cors",
                        evidence=f"ACAO: {acao}, ACAC: {acac}, Test Origin: {origin}",
                        recommendation="Use an explicit allowlist of origins. Never combine '*' with credentials.",
                        cwe_id="CWE-942",
                        agent=self.agent_name,
                    ))
                elif acao == "*":
                    result.add(Finding(
                        title="Wildcard CORS — all origins allowed",
                        description="Access-Control-Allow-Origin is set to '*', allowing any website to read responses.",
                        severity=Severity.MEDIUM,
                        category="cors",
                        evidence=f"ACAO: {acao}",
                        recommendation="Restrict CORS to specific trusted origins.",
                        cwe_id="CWE-942",
                        agent=self.agent_name,
                    ))
                elif acao == origin:
                    result.add(Finding(
                        title="CORS origin reflection",
                        description=f"The server reflects the Origin header ({origin}) in Access-Control-Allow-Origin.",
                        severity=Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM,
                        category="cors",
                        evidence=f"ACAO: {acao} (reflected from Origin: {origin}), ACAC: {acac}",
                        recommendation="Use a static allowlist instead of reflecting the Origin header.",
                        cwe_id="CWE-942",
                        agent=self.agent_name,
                    ))

    # ------------------------------------------------------------------
    # XSS
    # ------------------------------------------------------------------

    async def _test_xss(
        self, base_url: str, body: str, headers: Dict[str, str], result: ScanResult
    ) -> None:
        """Test for reflected XSS in query parameters."""
        # Extract query parameter candidates from forms or links
        param_candidates: List[str] = []

        # Find <input> names
        input_names = re.findall(r'<input[^>]+name=["\'](\w+)["\']', body, re.I)
        param_candidates.extend(input_names)

        # Find query params in links
        query_params = re.findall(r'\?(\w+)=', body)
        param_candidates.extend(query_params)

        # Default candidates
        if not param_candidates:
            param_candidates = ["q", "search", "query", "id", "page", "name", "email", "user", "s"]

        # Remove duplicates, keep first 10
        param_candidates = list(dict.fromkeys(param_candidates))[:10]

        tested_urls: set = set()

        for param in param_candidates:
            for xss_test in XSS_PAYLOADS[:3]:  # Limit to top 3 payloads per param
                test_url = f"{base_url}?{param}={xss_test['payload']}"
                if test_url in tested_urls:
                    continue
                tested_urls.add(test_url)

                try:
                    _, resp_body, _ = await self.http_get(test_url)
                    if re.search(xss_test["pattern"], resp_body, re.I):
                        result.add(Finding(
                            title=f"Reflected XSS via parameter '{param}' ({xss_test['name']})",
                            description=f"The parameter '{param}' reflects the XSS payload without sanitization.",
                            severity=Severity.HIGH,
                            category="xss",
                            evidence=f"URL: {test_url}\nPayload reflected in response.",
                            recommendation="HTML-encode all user input before rendering. Use Content-Security-Policy headers.",
                            cwe_id="CWE-79",
                            agent=self.agent_name,
                        ))
                        break  # One finding per param is enough
                except Exception:
                    continue

    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------

    async def _test_sqli(self, base_url: str, result: ScanResult) -> None:
        """Test for error-based SQL injection."""
        injection_points: List[str] = [
            f"{base_url}?id=",
            f"{base_url}?page=",
            f"{base_url}?product=",
            f"{base_url}?user=",
            f"{base_url}?cat=",
            f"{base_url}?category=",
            f"{base_url}?news=",
        ]

        for base_point in injection_points:
            for sqli_test in SQLI_PAYLOADS[:4]:  # Limit payloads
                test_url = base_point + sqli_test["payload"]
                try:
                    _, resp_body, resp_headers = await self.http_get(test_url)
                    if re.search(sqli_test["pattern"], resp_body, re.I):
                        result.add(Finding(
                            title=f"Potential SQL Injection — {sqli_test['name']}",
                            description=f"Error-based SQL injection detected with payload: {sqli_test['payload']}",
                            severity=Severity.CRITICAL,
                            category="sqli",
                            evidence=f"URL: {test_url}\nResponse contains database error.",
                            recommendation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                            cwe_id="CWE-89",
                            agent=self.agent_name,
                        ))
                        break
                except Exception:
                    continue

    # ------------------------------------------------------------------
    # Information Disclosure
    # ------------------------------------------------------------------

    async def _test_info_disclosure(self, base_url: str, result: ScanResult) -> None:
        """Check for common information disclosure issues."""
        # Check various common paths for sensitive files
        for sensitive_path in [
            "/.env",
            "/.git/HEAD",
            "/.git/config",
            "/.svn/entries",
            "/backup.zip",
            "/backup.tar.gz",
            "/dump.sql",
            "/wp-config.php.bak",
        ]:
            url = urljoin(base_url, sensitive_path)
            try:
                status, body, _ = await self.http_get(url)
                if status == 200 and len(body) > 10:
                    result.add(Finding(
                        title=f"Exposed sensitive file: {sensitive_path}",
                        description=f"The file {sensitive_path} is publicly accessible. This could leak credentials or source code.",
                        severity=Severity.CRITICAL,
                        category="information_disclosure",
                        evidence=f"URL: {url} returned HTTP {status}, {len(body)} bytes",
                        recommendation=f"Restrict access to {sensitive_path}. Add deny rules in your web server or .htaccess.",
                        cwe_id="CWE-538",
                        agent=self.agent_name,
                    ))
            except Exception:
                continue

        # Check for directory listing
        try:
            status, body, headers = await self.http_get(f"{base_url}/images/")
            if status == 200 and ("Index of" in body or "Parent Directory" in body):
                result.add(Finding(
                    title="Directory listing enabled",
                    description="A directory listing was found, which exposes file structure to attackers.",
                    severity=Severity.MEDIUM,
                    category="information_disclosure",
                    evidence=f"Directory listing found at {base_url}/images/",
                    recommendation="Disable directory listing (Options -Indexes in Apache, 'autoindex off' in nginx).",
                    cwe_id="CWE-548",
                    agent=self.agent_name,
                ))
        except Exception:
            pass

        # Check Server header for version
        server = (headers.get("Server") or headers.get("server", ""))
        version_match = re.search(r"[\d]+\.[\d]+", server)
        if version_match:
            result.add(Finding(
                title="Server header leaks version information",
                description=f"The Server header reveals version: {server}",
                severity=Severity.LOW,
                category="information_disclosure",
                evidence=f"Server: {server}",
                recommendation="Configure server_tokens off (nginx) or ServerTokens Prod (Apache).",
                cwe_id="CWE-200",
                agent=self.agent_name,
            ))

    # ------------------------------------------------------------------
    # Debug endpoints
    # ------------------------------------------------------------------

    async def _test_debug_endpoints(self, base_url: str, result: ScanResult) -> None:
        """Check for exposed debug/diagnostic endpoints."""
        for debug_path in DEBUG_PATHS:
            url = urljoin(base_url, debug_path)
            try:
                status, body, _ = await self.http_get(url)
                if status in (200, 401, 403):
                    severity = Severity.MEDIUM if status == 200 else Severity.LOW
                    result.add(Finding(
                        title=f"Debug endpoint accessible: {debug_path}",
                        description=f"The path {debug_path} returned HTTP {status}, indicating a debug/diagnostic endpoint may be exposed.",
                        severity=severity,
                        category="information_disclosure",
                        evidence=f"URL: {url} returned HTTP {status}",
                        recommendation="Restrict debug endpoints to internal networks or disable in production.",
                        cwe_id="CWE-489",
                        agent=self.agent_name,
                    ))
            except Exception:
                continue


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

async def run_web(target_url: str) -> dict:
    """Run the web application security agent.

    Returns:
        dict with findings list, metadata, errors, and duration.
    """
    agent = WebAgent(target_url)
    result = await agent.run()
    return result.to_dict()
