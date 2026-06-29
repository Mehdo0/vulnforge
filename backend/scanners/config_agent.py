"""
VulnForge — Configuration & Infrastructure Agent

Passive analysis of server/application configuration:
  - TLS/SSL analysis (protocol version, cipher suites, certificate expiry)
  - Cookie security flags (HttpOnly, Secure, SameSite)
  - Exposed sensitive files (.env, .git, backup files)
  - Rate limiting detection (basic heuristics)
  - Open redirect detection
"""

from __future__ import annotations

import asyncio
import datetime
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from .base import BaseAgent, Finding, ScanResult, Severity, SENSITIVE_PATHS

# ---------------------------------------------------------------------------
# Weak TLS versions & ciphers
# ---------------------------------------------------------------------------

WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

WEAK_CIPHERS: Dict[str, str] = {
    "NULL": "Null cipher (no encryption)",
    "EXPORT": "Export-grade cipher",
    "DES": "DES encryption",
    "3DES": "3DES encryption",
    "RC4": "RC4 stream cipher",
    "MD5": "MD5 hash",
    "anon": "Anonymous key exchange",
    "ADH": "Anonymous Diffie-Hellman",
    "AECDH": "Anonymous ECDH",
    "PSK": "Pre-Shared Key (may bypass PKI)",
    "SRP": "Secure Remote Password",
    "aNULL": "No authentication",
}


class ConfigAgent(BaseAgent):
    """Configuration and infrastructure security agent."""

    agent_name = "config"

    async def run(self) -> ScanResult:
        """Execute configuration security checks."""
        result = ScanResult(
            metadata={
                "target": self.target,
                "hostname": self.hostname,
                "scheme": self.scheme,
            }
        )

        t0 = asyncio.get_event_loop().time()
        self.log(f"Starting config scan on {self.target}")

        base_url = f"{self.scheme}://{self.hostname}"
        if self.port not in (80, 443, None):
            base_url = f"{self.scheme}://{self.hostname}:{self.port}"

        # -- TLS Analysis --
        tls_result = await self._analyze_tls()
        if tls_result:
            result.metadata["tls"] = tls_result
            await self._evaluate_tls(tls_result, result)

        # -- Cookie Analysis --
        _, body, headers = await self.http_get(base_url)
        result.metadata["headers"] = headers
        await self._analyze_cookies(headers, result)

        # -- Exposed Sensitive Files --
        await self._check_sensitive_files(base_url, result)

        # -- Rate Limiting Detection --
        await self._detect_rate_limiting(base_url, result)

        # -- Open Redirect --
        await self._check_open_redirect(base_url, result)

        result.duration = asyncio.get_event_loop().time() - t0
        self.log(f"Config scan completed in {result.duration:.1f}s — {len(result.findings)} findings")
        return result

    # ------------------------------------------------------------------
    # TLS Analysis
    # ------------------------------------------------------------------

    async def _analyze_tls(self) -> Optional[Dict[str, Any]]:
        """Gather TLS configuration details."""
        port_to_check = self.port or (443 if self.scheme == "https" else 443)

        tls_info = await self.get_tls_info(self.hostname, port_to_check)
        if not tls_info:
            return None

        result: Dict[str, Any] = dict(tls_info)

        # Check supported versions
        versions = await self._check_tls_versions()
        result["supported_versions"] = versions

        # Check cipher suites
        ciphers = await self._check_cipher_suites()
        result["ciphers"] = ciphers

        # Parse certificate expiry
        not_after = tls_info.get("not_after")
        if not_after:
            result["cert_expiry"] = not_after
            try:
                exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                remaining = exp - datetime.datetime.utcnow()
                result["cert_days_remaining"] = remaining.days
                result["cert_expired"] = remaining.total_seconds() < 0
            except ValueError:
                result["cert_days_remaining"] = None
                result["cert_expired"] = False

        return result

    async def _check_tls_versions(self) -> List[str]:
        """Check which TLS versions the server supports."""
        versions: List[str] = []
        port = self.port or 443

        checks = {
            "SSLv3":   "-ssl3",
            "TLSv1":   "-tls1",
            "TLSv1.1": "-tls1_1",
            "TLSv1.2": "-tls1_2",
            "TLSv1.3": "-tls1_3",
        }

        for label, flag in checks.items():
            rc, out, _ = await self._run(
                "openssl", "s_client",
                "-connect", f"{self.hostname}:{port}",
                "-servername", self.hostname,
                flag,
                timeout=10,
                input_data="Q\n",
            )
            if rc == 0 or "CONNECTED" in out:
                if "BEGIN CERTIFICATE" in out or "Server certificate" in out:
                    versions.append(label)

        return versions

    async def _check_cipher_suites(self) -> List[str]:
        """List cipher suites offered by the server."""
        port = self.port or 443
        rc, out, _ = await self._run(
            "openssl", "s_client",
            "-connect", f"{self.hostname}:{port}",
            "-servername", self.hostname,
            "-cipher", "ALL:COMPLEMENTOFALL",
            timeout=10,
            input_data="Q\n",
        )
        if "Cipher" in out:
            match = re.search(r"Cipher\s*:\s*(\S+)", out)
            if match:
                return [match.group(1)]
        return []

    async def _evaluate_tls(self, tls_info: Dict[str, Any], result: ScanResult) -> None:
        """Evaluate TLS findings."""
        # Check weak protocol versions
        supported = tls_info.get("supported_versions", [])
        weak_versions = [v for v in supported if v in WEAK_TLS_VERSIONS]
        if weak_versions:
            result.add(Finding(
                title=f"Weak TLS versions supported: {', '.join(weak_versions)}",
                description=f"The server supports outdated TLS protocols: {', '.join(weak_versions)}. Vulnerable to POODLE, BEAST, CRIME.",
                severity=Severity.HIGH,
                category="tls",
                evidence=f"Supported weak versions: {', '.join(weak_versions)}",
                recommendation="Disable TLS 1.0, 1.1, and SSLv3. Enforce TLS 1.2 minimum, TLS 1.3 preferred.",
                cwe_id="CWE-326",
                agent=self.agent_name,
            ))

        # Check weak ciphers
        ciphers = tls_info.get("ciphers", [])
        weak_found: List[str] = []
        for cipher_str in ciphers:
            for weak_word, desc in WEAK_CIPHERS.items():
                if weak_word in cipher_str:
                    weak_found.append(f"{cipher_str} ({desc})")
                    break

        if weak_found:
            result.add(Finding(
                title="Weak cipher suites in use",
                description=f"The server negotiates weak cipher suites: {', '.join(weak_found)}",
                severity=Severity.MEDIUM,
                category="tls",
                evidence=", ".join(weak_found),
                recommendation="Remove weak cipher suites. Use only modern ciphers (AES-GCM, ChaCha20-Poly1305).",
                cwe_id="CWE-327",
                agent=self.agent_name,
            ))

        # Certificate expiry
        days = tls_info.get("cert_days_remaining")
        expired = tls_info.get("cert_expired", False)

        if expired:
            result.add(Finding(
                title="TLS certificate has EXPIRED",
                description="The TLS/SSL certificate has expired. Connections are insecure.",
                severity=Severity.CRITICAL,
                category="tls",
                evidence=f"Certificate expired. Expiry: {tls_info.get('cert_expiry')}",
                recommendation="Renew the TLS certificate immediately.",
                cwe_id="CWE-295",
                agent=self.agent_name,
            ))
        elif days is not None:
            if days <= 7:
                severity = Severity.HIGH
            elif days <= 30:
                severity = Severity.MEDIUM
            else:
                severity = None

            if severity:
                result.add(Finding(
                    title=f"TLS certificate expires in {days} days",
                    description=f"The certificate will expire in {days} days ({tls_info.get('cert_expiry')}).",
                    severity=severity,
                    category="tls",
                    evidence=f"Expiry: {tls_info.get('cert_expiry')}",
                    recommendation="Renew the certificate before expiry." if days <= 7 else "Plan certificate renewal.",
                    cwe_id="CWE-295",
                    agent=self.agent_name,
                ))

        # No TLS on HTTPS
        if not tls_info.get("protocol") and self.scheme == "https":
            result.add(Finding(
                title="Unable to establish TLS connection",
                description="Could not retrieve TLS information on HTTPS target. May indicate invalid certificate.",
                severity=Severity.MEDIUM,
                category="tls",
                evidence="TLS handshake failed",
                recommendation="Verify the TLS certificate is valid and properly configured.",
                cwe_id="CWE-295",
                agent=self.agent_name,
            ))

    # ------------------------------------------------------------------
    # Cookie Analysis
    # ------------------------------------------------------------------

    async def _analyze_cookies(self, headers: Dict[str, str], result: ScanResult) -> None:
        """Check Set-Cookie headers for security flags."""
        set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie", "")
        if not set_cookie:
            return

        cookie_strings: List[str] = [set_cookie] if isinstance(set_cookie, str) else list(set_cookie)

        for cookie_str in cookie_strings:
            parts = cookie_str.split(";")
            name_value = parts[0].strip()
            flags = {p.strip().lower() for p in parts[1:]}
            cookie_name = name_value.split("=")[0] if "=" in name_value else name_value

            issues: List[str] = []
            if "httponly" not in flags:
                issues.append("HttpOnly")
            if "secure" not in flags:
                issues.append("Secure")
            if not any("samesite" in f for f in flags):
                issues.append("SameSite")

            if issues:
                result.add(Finding(
                    title=f"Cookie '{cookie_name}' missing security flags: {', '.join(issues)}",
                    description=f"The cookie '{cookie_name}' is missing: {', '.join(issues)}.",
                    severity=Severity.MEDIUM,
                    category="cookies",
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    recommendation=f"Add {' and '.join(issues)} flag{'s' if len(issues) > 1 else ''}. "
                                   "HttpOnly prevents XSS access, Secure enforces HTTPS-only, SameSite prevents CSRF.",
                    cwe_id="CWE-1004" if "httponly" in [i.lower() for i in issues] else "CWE-614",
                    agent=self.agent_name,
                ))

        # Global SameSite check
        all_cookie_str = " ".join(cookie_strings)
        if "SameSite" not in all_cookie_str and all_cookie_str:
            result.add(Finding(
                title="Cookies missing SameSite attribute",
                description="No cookies have the SameSite attribute set, increasing CSRF risk.",
                severity=Severity.LOW,
                category="cookies",
                evidence="No SameSite attribute found in Set-Cookie headers",
                recommendation="Set SameSite=Lax or SameSite=Strict on all cookies.",
                cwe_id="CWE-1275",
                agent=self.agent_name,
            ))

    # ------------------------------------------------------------------
    # Sensitive File Exposure
    # ------------------------------------------------------------------

    async def _check_sensitive_files(self, base_url: str, result: ScanResult) -> None:
        """Check for exposed sensitive configuration files."""
        sem = asyncio.Semaphore(5)

        async def _check_one(path: str) -> None:
            async with sem:
                url = urljoin(base_url, path)
                try:
                    status, body, _ = await self.http_get(url)

                    if status == 200 and len(body) > 5:
                        severity = Severity.CRITICAL if ".env" in path or ".git" in path else Severity.HIGH
                        result.add(Finding(
                            title=f"Exposed sensitive file: {path}",
                            description=f"The file {path} is publicly accessible. May leak credentials or source code.",
                            severity=severity,
                            category="configuration",
                            evidence=f"HTTP {status}, {len(body)} bytes returned",
                            recommendation=f"Restrict access to {path} at the web server level.",
                            cwe_id="CWE-538",
                            agent=self.agent_name,
                        ))
                    elif status == 403 and ".git" in path:
                        result.add(Finding(
                            title=f"Git directory found but access-restricted: {path}",
                            description="The .git directory should not be web-accessible at all.",
                            severity=Severity.LOW,
                            category="configuration",
                            evidence=f"HTTP {status} for {url}",
                            recommendation="Move .git directory completely outside the web root.",
                            cwe_id="CWE-527",
                            agent=self.agent_name,
                        ))
                except Exception:
                    pass

        tasks = [_check_one(p) for p in SENSITIVE_PATHS]
        await asyncio.gather(*tasks)

    # ------------------------------------------------------------------
    # Rate Limiting Detection
    # ------------------------------------------------------------------

    async def _detect_rate_limiting(self, base_url: str, result: ScanResult) -> None:
        """Basic rate limiting detection via rapid requests."""
        num_requests = 10

        for i in range(num_requests):
            status, body, headers = await self.http_get(base_url)

            if status == 429:
                result.add(Finding(
                    title="Rate limiting detected",
                    description=f"Target returned HTTP 429 after {i + 1} requests. Rate limiting is active.",
                    severity=Severity.INFO,
                    category="rate_limiting",
                    evidence=f"HTTP 429 after {i + 1} requests",
                    recommendation="Rate limiting is configured. Review thresholds for appropriateness.",
                    agent=self.agent_name,
                ))
                result.metadata["rate_limiting"] = True
                return

            await asyncio.sleep(0.1)

        result.add(Finding(
            title="No rate limiting detected",
            description=f"Sent {num_requests} rapid requests without triggering rate limiting (no HTTP 429).",
            severity=Severity.MEDIUM,
            category="rate_limiting",
            evidence=f"{num_requests} requests completed without rate limiting response",
            recommendation="Implement rate limiting to prevent brute force and DoS attacks.",
            agent=self.agent_name,
        ))
        result.metadata["rate_limiting"] = False

    # ------------------------------------------------------------------
    # Open Redirect
    # ------------------------------------------------------------------

    async def _check_open_redirect(self, base_url: str, result: ScanResult) -> None:
        """Check for basic open redirect vulnerabilities."""
        redirect_params = [
            "redirect", "url", "next", "return", "returnUrl", "goto",
            "redirect_to", "redirect_uri", "callback", "target",
        ]

        evil_url = "https://evil.com/malware"

        for param in redirect_params:
            test_url = f"{base_url}?{param}={evil_url}"
            try:
                status, _, resp_headers = await self.http_get(test_url)
                location = resp_headers.get("Location") or resp_headers.get("location", "")
                if location and "evil.com" in location:
                    result.add(Finding(
                        title=f"Open redirect via '{param}' parameter",
                        description=f"The application redirects to an attacker-controlled URL via '{param}'.",
                        severity=Severity.MEDIUM,
                        category="open_redirect",
                        evidence=f"Location: {location} (from ?{param}={evil_url})",
                        recommendation="Use a whitelist of allowed redirect URLs or relative paths only.",
                        cwe_id="CWE-601",
                        agent=self.agent_name,
                    ))
            except Exception:
                continue


async def run_config(target_url: str) -> dict:
    """Run the configuration security agent and return structured findings."""
    agent = ConfigAgent(target_url)
    result = await agent.run()
    return result.to_dict()
