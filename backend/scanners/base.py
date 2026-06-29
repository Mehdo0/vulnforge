"""
VulnForge — Base Scanner Utilities

Provides the Finding dataclass, Severity enum, and common utility functions
shared across all specialized scanning agents.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Vulnerability severity levels aligned with CVSS terminology."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single vulnerability or security concern discovered during a scan."""

    title: str
    description: str
    severity: Severity
    category: str
    evidence: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    agent: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "agent": self.agent,
            "timestamp": self.timestamp,
        }

    @property
    def fingerprint(self) -> str:
        """Deterministic hash for deduplication."""
        raw = f"{self.title}|{self.category}|{self.evidence[:200]}"
        return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Aggregated output from a single agent run."""

    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
            "errors": self.errors,
            "duration": self.duration,
        }


# ---------------------------------------------------------------------------
# Base Agent
# ---------------------------------------------------------------------------

class BaseAgent:
    """Shared functionality for all scanning agents."""

    agent_name: str = "base"
    default_timeout: int = 15
    user_agent: str = (
        "Mozilla/5.0 (compatible; VulnForge-Scanner/1.0; "
        "+https://vulnforge.io/bot)"
    )

    def __init__(self, target: str, timeout: int = 15) -> None:
        self.target = target
        self.timeout = timeout
        self.parsed = urlparse(target if "://" in target else f"https://{target}")
        self.hostname = self.parsed.hostname or target
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.scheme = self.parsed.scheme or "https"

    # -- subprocess helpers -------------------------------------------------

    async def _run(
        self, *args: str, timeout: Optional[int] = None, input_data: Optional[str] = None
    ) -> Tuple[int, str, str]:
        """Run a subprocess asynchronously.  Returns (returncode, stdout, stderr)."""
        t = timeout if timeout is not None else self.timeout
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else None,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input_data.encode() if input_data else None),
                timeout=t,
            )
            return (proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace"))
        except asyncio.TimeoutError:
            return (-1, "", f"Command timed out after {t}s: {' '.join(args)}")
        except FileNotFoundError:
            return (-2, "", f"Tool not found: {args[0]}")
        except Exception as exc:
            return (-3, "", str(exc))

    async def _tool_exists(self, name: str) -> bool:
        """Check whether a CLI tool is on PATH."""
        rc, _, _ = await self._run("which", name, timeout=5)
        return rc == 0

    # -- HTTP helpers -------------------------------------------------------

    async def _curl(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        follow_redirects: bool = True,
        insecure: bool = False,
        include_headers: bool = False,
    ) -> Tuple[int, str, str]:
        """Execute a curl request and return (returncode, stdout, stderr)."""
        args = ["curl", "-s", "-m", str(self.timeout)]
        if include_headers:
            args.append("-i")
        if follow_redirects:
            args.append("-L")
        if insecure:
            args.append("-k")
        args.extend(["-X", method])
        if headers:
            for k, v in headers.items():
                args.extend(["-H", f"{k}: {v}"])
        if data:
            args.extend(["-d", data])
        args.append(url)
        return await self._run(*args)

    async def http_get(
        self, url: str, extra_headers: Optional[Dict[str, str]] = None
    ) -> Tuple[int, str, Dict[str, str]]:
        """GET a URL; returns (status_code, body, response_headers)."""
        hdrs = {"User-Agent": self.user_agent}
        if extra_headers:
            hdrs.update(extra_headers)

        rc, out, err = await self._curl(url, method="GET", headers=hdrs, follow_redirects=True, include_headers=True)

        status_code = 0
        resp_headers: Dict[str, str] = {}
        body = out

        if out:
            # Split headers from body
            parts = out.split("\r\n\r\n", 1)
            if len(parts) == 2:
                header_block, body = parts
                # Parse status line
                header_lines = header_block.split("\r\n")
                if header_lines:
                    status_match = re.match(r"HTTP/\S+\s+(\d+)", header_lines[0])
                    if status_match:
                        status_code = int(status_match.group(1))
                for line in header_lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        resp_headers[k.strip()] = v.strip()

        return status_code, body, resp_headers

    # -- TLS helpers --------------------------------------------------------

    async def get_tls_info(self, hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """Retrieve TLS certificate information."""
        try:
            rc, out, err = await self._run(
                "openssl", "s_client",
                "-connect", f"{hostname}:{port}",
                "-servername", hostname,
                "-showcerts",
                timeout=10,
                input_data="Q\n",  # quit
            )
            if rc != 0 and "CONNECTED" not in out:
                return None

            info: Dict[str, Any] = {"raw": out[:2000]}

            # Extract version
            ver = re.search(r"Protocol\s*:\s*(\S+)", out)
            if ver:
                info["protocol"] = ver.group(1)

            # Extract cipher
            cip = re.search(r"Cipher\s*:\s*(\S+)", out)
            if cip:
                info["cipher"] = cip.group(1)

            # Extract certificate expiry via openssl x509 pipeline
            rc2, cert_out, _ = await self._run(
                "openssl", "s_client",
                "-connect", f"{hostname}:{port}",
                "-servername", hostname,
                timeout=10,
                input_data="Q\n",
            )
            if cert_out:
                rc3, date_out, _ = await self._run(
                    "bash", "-c",
                    "openssl x509 -noout -enddate 2>/dev/null",
                    timeout=5,
                    input_data=cert_out,
                )
                match = re.search(r"notAfter=(.+)", date_out)
                if match:
                    info["not_after"] = match.group(1).strip()

            return info
        except Exception:
            return None

    # -- Header checking ----------------------------------------------------

    @staticmethod
    def check_security_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for the presence and quality of key security headers."""
        checks: List[Dict[str, Any]] = []

        header_checks = {
            "Strict-Transport-Security": {
                "required": True,
                "rec": "Enable HSTS with 'max-age=31536000; includeSubDomains'.",
                "cwe": "CWE-319",
            },
            "Content-Security-Policy": {
                "required": True,
                "rec": "Define a strict CSP to prevent XSS and data injection.",
                "cwe": "CWE-1021",
            },
            "X-Frame-Options": {
                "required": False,
                "rec": "Set 'DENY' or 'SAMEORIGIN' to prevent clickjacking.",
                "cwe": "CWE-1021",
            },
            "X-Content-Type-Options": {
                "required": False,
                "rec": "Set 'nosniff' to prevent MIME-sniffing attacks.",
                "cwe": "CWE-116",
            },
            "Referrer-Policy": {
                "required": False,
                "rec": "Set 'strict-origin-when-cross-origin' or stricter.",
                "cwe": "CWE-200",
            },
            "Permissions-Policy": {
                "required": False,
                "rec": "Restrict browser features with a Permissions-Policy header.",
                "cwe": "CWE-693",
            },
        }

        for hdr_name, config in header_checks.items():
            value = headers.get(hdr_name) or headers.get(hdr_name.lower())
            present = value is not None
            checks.append({
                "header": hdr_name,
                "present": present,
                "value": value if present else "",
                "required": config["required"],
                "recommendation": config["rec"],
                "cwe": config["cwe"],
            })

        return checks

    # -- Logging helper -----------------------------------------------------

    def log(self, message: str) -> None:
        """Simple structured log line."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        print(f"[{ts}] [{self.agent_name}] {message}", flush=True)


# ---------------------------------------------------------------------------
# Common regular expressions
# ---------------------------------------------------------------------------

# Patterns for hardcoded secrets
SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r"(?i)(?:api[_-]?key|apikey|api)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{20,})['\"]?", "API Key"),
    (r"(?i)(?:secret|secret[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{16,})['\"]?", "Secret Key"),
    (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{3,})['\"]", "Hardcoded Password"),
    (r"(?i)(?:token|auth[_-]?token|access[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{16,})['\"]?", "Access Token"),
    (r"(?i)(?:private[_-]?key|privkey|rsa[_-]?private)\s*[=:]\s*['\"]?(-{3,}BEGIN)", "Private Key"),
    (r"(?i)mongodb(?:\+srv)?://[^'\"\s]+", "MongoDB Connection String"),
    (r"(?i)postgres(?:ql)?://[^'\"\s]+", "PostgreSQL Connection String"),
    (r"(?i)mysql://[^'\"\s]+", "MySQL Connection String"),
    (r"(?i)redis://[^'\"\s]+", "Redis Connection String"),
    (r"(?i)ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"(?i)gho_[A-Za-z0-9]{36}", "GitHub OAuth Token"),
    (r"(?i)ghu_[A-Za-z0-9]{36}", "GitHub User Token"),
    (r"(?i)ghs_[A-Za-z0-9]{36}", "GitHub Server Token"),
    (r"(?i)ghr_[A-Za-z0-9]{36}", "GitHub Refresh Token"),
    (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r'(?i)sk-(?:live|test)-[0-9a-zA-Z]{24,}', "Stripe Secret Key"),
    (r"(?i)-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key Block"),
    (r"(?i)xox[baprs]-[0-9a-zA-Z\-]{10,}", "Slack Token"),
    (r"(?i)conn(?:ection)?[_-]?string\s*[=:]\s*['\"]?([^'\"]{10,})['\"]?", "Connection String"),
    (r"(?im)Authorization[=:]\s*Bearer\s+[A-Za-z0-9_\-\.]{20,}", "Bearer Token"),
    (r"(?i)(?:DATABASE_URL|DB_URL|DB_URI)\s*=\s*['\"]?([^'\"]{10,})['\"]?", "Database URL"),
    (r"(?i)(?:JWT_SECRET|ENCRYPTION_KEY|SIGNING_KEY)\s*=\s*['\"]?([^'\"]{10,})['\"]?", "Crypto Secret"),
    (r"(?i)slack[._]webhook[._]url\s*[=:]\s*['\"]?(https://hooks\.slack\.com[^'\"]+)['\"]?", "Slack Webhook"),
]

# Sensitive file paths to check for
SENSITIVE_PATHS: List[str] = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.backup",
    "/.env.bak",
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.svn/entries",
    "/.DS_Store",
    "/backup",
    "/backup.zip",
    "/backup.tar.gz",
    "/dump.sql",
    "/database.sql",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-config.php.save",
    "/config.php.bak",
    "/config.yml.bak",
    "/config.yaml.bak",
    "/.htaccess.bak",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/debug",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.vscode/settings.json",
    "/.idea/workspace.xml",
    "/package-lock.json",
]
