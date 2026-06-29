"""
VulnForge — Reconnaissance Agent

Discovers the attack surface of a target:
  - Subdomain enumeration (DNS + wordlist)
  - Port scanning (top 100, via nmap or /dev/tcp fallback)
  - Technology stack detection (whatweb or header analysis)
  - HTTP response header collection
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseAgent, Finding, ScanResult, Severity

# ---------------------------------------------------------------------------
# Wordlist (trimmed top subdomains for basic enumeration)
# ---------------------------------------------------------------------------

SUBDOMAIN_WORDLIST: List[str] = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
    "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
    "m", "imap", "test", "ns", "blog", "shop", "api", "dev", "staging",
    "admin", "portal", "cdn", "status", "vpn", "git", "ci", "jenkins",
    "monitor", "grafana", "kibana", "docs", "support", "help", "wiki",
    "assets", "static", "media", "images", "img", "app", "mobile",
    "remote", "beta", "alpha", "demo", "sandbox", "uat", "qa", "prod",
    "intranet", "extranet", "secure", "login", "sso", "auth", "db",
    "sql", "mysql", "pgsql", "redis", "mongo", "elastic", "kibana",
    "nagios", "zabbix", "prometheus", "alertmanager", "traefik",
    "docker", "swarm", "k8s", "kubernetes", "rancher", "portainer",
    "phpmyadmin", "adminer", "pgadmin", "backup", "files", "storage",
    "s3", "minio", "ldap", "kerberos",
]

# Well-known technology signatures from response headers
TECH_SIGNATURES: Dict[str, List[str]] = {
    "Server": [],
    "X-Powered-By": [],
    "X-Generator": [],
    "X-Drupal-Cache": [],
    "X-Drupal-Dynamic-Cache": [],
}

TECH_FINGERPRINTS: Dict[str, List[str]] = {
    "nginx":        [r"(?i)nginx"],
    "Apache":       [r"(?i)apache"],
    "IIS":          [r"(?i)microsoft-iis"],
    "Cloudflare":   [r"(?i)cloudflare"],
    "Varnish":      [r"(?i)varnish"],
    "LiteSpeed":    [r"(?i)litespeed"],
    "WordPress":    [r"(?i)wordpress", r"wp-content", r"wp-json"],
    "Drupal":       [r"(?i)drupal"],
    "Joomla":       [r"(?i)joomla"],
    "Django":       [r"(?i)django", r"csrftoken"],
    "Ruby on Rails": [r"(?i)rails", r"_rails_"],
    "Laravel":      [r"(?i)laravel", r"laravel_session"],
    "Express":      [r"(?i)express"],
    "Next.js":      [r"(?i)next\.js", r"__next"],
    "React":        [r"(?i)react"],
    "Vue.js":       [r"(?i)vue\.?js"],
    "Angular":      [r"(?i)angular"],
    "jQuery":       [r"(?i)jquery"],
    "PHP":          [r"(?i)php"],
    "ASP.NET":      [r"(?i)asp\.net"],
    "Node.js":      [r"(?i)node\.?js"],
    "GraphQL":      [r"(?i)graphql"],
    "Vercel":       [r"(?i)vercel"],
    "Netlify":      [r"(?i)netlify"],
    "AWS":          [r"(?i)awselb|awsalb|cloudfront|s3\.amazonaws"],
    "GCP":          [r"(?i)google(?:frontend|cloud)"],
    "Azure":        [r"(?i)microsoft-azure|azurewebsites"],
}

# Top 100 TCP ports
TOP_100_PORTS: List[int] = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30,
    32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88,
    89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139,
    143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256,
    259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417,
    425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513,
    514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593,
    616, 617,
]


class ReconAgent(BaseAgent):
    """Reconnaissance agent — discovers attack surface of a target."""

    agent_name = "recon"

    # -- public API ----------------------------------------------------------

    async def run(self) -> ScanResult:
        """Execute the full recon pipeline and return aggregated results."""
        result = ScanResult(
            metadata={
                "target": self.target,
                "hostname": self.hostname,
                "scheme": self.scheme,
                "port": self.port,
            }
        )

        t0 = asyncio.get_event_loop().time()
        self.log(f"Starting recon on {self.target}")

        # Run all independent checks in parallel
        tls_task = asyncio.create_task(self._check_tls())
        http_task = asyncio.create_task(self._probe_http())

        # Port scan (serial — already parallel internally)
        ports = await self._port_scan()
        # Subdomain enumeration
        subs = await self._enumerate_subdomains()

        tls_info = await tls_task
        status_code, body, headers = await http_task

        # Technology detection
        techs = await self._detect_technologies(headers, body)

        # -- Record findings --------------------------------------------------

        result.metadata["open_ports"] = ports
        result.metadata["subdomains"] = subs
        result.metadata["technologies"] = techs
        result.metadata["headers"] = headers or {}

        # Interesting open ports
        for port_info in ports:
            if port_info["port"] not in (80, 443):
                result.add(Finding(
                    title=f"Open port: {port_info['port']}/{port_info.get('protocol', 'tcp')}",
                    description=f"Port {port_info['port']} is open. Service: {port_info.get('service', 'unknown')}",
                    severity=Severity.INFO,
                    category="recon",
                    evidence=f"Port {port_info['port']}/{port_info.get('protocol', 'tcp')} open",
                    recommendation="Review whether this port needs to be publicly accessible.",
                    agent=self.agent_name,
                ))

        # Subdomain finding
        if subs:
            result.add(Finding(
                title=f"Subdomains discovered: {len(subs)}",
                description=f"Found {len(subs)} subdomains via DNS enumeration.",
                severity=Severity.INFO,
                category="recon",
                evidence="\n".join(subs[:20]),
                recommendation="Review exposed subdomains for sensitive services.",
                agent=self.agent_name,
            ))

        # Technology disclosure
        if techs:
            tech_list = ", ".join(techs)
            result.add(Finding(
                title=f"Technology stack detected",
                description=f"Detected technologies: {tech_list}",
                severity=Severity.INFO,
                category="recon",
                evidence=tech_list,
                recommendation="Ensure all detected technologies are up to date and no sensitive versions are exposed.",
                agent=self.agent_name,
            ))

        # TLS info
        if tls_info:
            protocol = tls_info.get("protocol", "unknown")
            if protocol and "TLSv1" in protocol and protocol not in ("TLSv1.2", "TLSv1.3"):
                result.add(Finding(
                    title=f"Outdated TLS protocol: {protocol}",
                    description=f"The server supports {protocol}, which is considered weak.",
                    severity=Severity.HIGH,
                    category="tls",
                    evidence=f"Protocol: {protocol}, Cipher: {tls_info.get('cipher', 'unknown')}",
                    recommendation="Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
                    cwe_id="CWE-326",
                    agent=self.agent_name,
                ))

        # Check for server header disclosure
        server_header = headers.get("Server", headers.get("server", ""))
        if server_header and server_header not in ("", "none"):
            result.add(Finding(
                title="Server header discloses technology version",
                description=f"Server header reveals: {server_header}",
                severity=Severity.LOW,
                category="information_disclosure",
                evidence=f"Server: {server_header}",
                recommendation="Suppress or obfuscate the Server header to avoid version disclosure.",
                cwe_id="CWE-200",
                agent=self.agent_name,
            ))

        # X-Powered-By header
        powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        if powered_by:
            result.add(Finding(
                title="X-Powered-By header discloses technology",
                description=f"X-Powered-By header reveals: {powered_by}",
                severity=Severity.LOW,
                category="information_disclosure",
                evidence=f"X-Powered-By: {powered_by}",
                recommendation="Remove the X-Powered-By header.",
                cwe_id="CWE-200",
                agent=self.agent_name,
            ))

        result.duration = asyncio.get_event_loop().time() - t0
        self.log(f"Recon completed in {result.duration:.1f}s — {len(result.findings)} findings")
        return result

    # -- port scanning -------------------------------------------------------

    async def _port_scan(self) -> List[Dict[str, Any]]:
        """Scan top ports. Uses nmap if available, falls back to socket connect."""
        if await self._tool_exists("nmap"):
            return await self._nmap_scan()
        else:
            return await self._socket_scan()

    async def _nmap_scan(self) -> List[Dict[str, Any]]:
        ports_str = ",".join(str(p) for p in TOP_100_PORTS)
        rc, out, err = await self._run(
            "nmap", "-sT", "-sV", "-p", ports_str,
            "--open", "-T4", "-Pn", self.hostname,
            timeout=120,
        )
        results: List[Dict[str, Any]] = []
        for line in out.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port_proto = parts[0]
                port = int(port_proto.split("/")[0])
                service = parts[1] if len(parts) > 1 else "unknown"
                version = " ".join(parts[2:]) if len(parts) > 2 else ""
                results.append({
                    "port": port, "protocol": "tcp", "state": "open",
                    "service": service, "version": version,
                })
        return results

    async def _socket_scan(self) -> List[Dict[str, Any]]:
        """Fallback: limited parallel socket connect scan."""
        results: List[Dict[str, Any]] = []

        async def _check_port(port: int) -> Optional[Dict[str, Any]]:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.hostname, port),
                    timeout=2.0,
                )
                writer.close()
                await writer.wait_closed()
                svc = socket.getservbyport(port, "tcp") if port <= 1024 else "unknown"
                return {"port": port, "protocol": "tcp", "state": "open", "service": svc, "version": ""}
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return None

        # Limit to top 30 for socket scan to avoid excessive time
        limited_ports = [p for p in TOP_100_PORTS if p <= 10000][:30]
        tasks = [_check_port(p) for p in limited_ports]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        for item in gathered:
            if item and not isinstance(item, BaseException):
                results.append(item)

        return results

    # -- subdomain enumeration -----------------------------------------------

    async def _enumerate_subdomains(self) -> List[str]:
        """Enumerate subdomains via DNS and basic wordlist."""
        found: List[str] = set()  # type: ignore[assignment]

        base = self.hostname
        # Strip leading www. to get the base domain
        if base.startswith("www."):
            base = base[4:]

        async def _resolve(sub: str) -> Optional[str]:
            full = f"{sub}.{base}"
            try:
                rc, out, _ = await self._run("host", full, timeout=5)
                if rc == 0 and "has address" in out:
                    return full
                rc2, out2, _ = await self._run("dig", "+short", full, timeout=5)
                if rc2 == 0 and out2.strip():
                    return full
            except Exception:
                pass
            return None

        tasks = [_resolve(sub) for sub in SUBDOMAIN_WORDLIST]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = {r for r in results if r and not isinstance(r, BaseException)}

        return sorted(found)

    # -- HTTP probing --------------------------------------------------------

    async def _probe_http(self) -> Tuple[int, str, Dict[str, str]]:
        """Basic HTTP probe to grab status code, body, and headers."""
        url = f"{self.scheme}://{self.hostname}"
        if (self.scheme == "https" and self.port != 443) or (self.scheme == "http" and self.port != 80):
            url = f"{self.scheme}://{self.hostname}:{self.port}"
        return await self.http_get(url)

    # -- technology detection -------------------------------------------------

    async def _detect_technologies(self, headers: Dict[str, str], body: str) -> List[str]:
        """Detect technology stack from headers and HTML body."""
        techs: List[str] = []

        # Check headers
        for tech, patterns in TECH_FINGERPRINTS.items():
            for hdr_key, hdr_val in headers.items():
                for pat in patterns:
                    if re.search(pat, hdr_val):
                        techs.append(tech)
                        break

        # Check body (first 100KB)
        body_sample = body[:100000] if body else ""
        for tech, patterns in TECH_FINGERPRINTS.items():
            if tech not in techs:
                for pat in patterns:
                    if re.search(pat, body_sample):
                        techs.append(tech)
                        break

        # Try whatweb if available
        if await self._tool_exists("whatweb"):
            url = f"{self.scheme}://{self.hostname}"
            rc, out, _ = await self._run("whatweb", "--no-errors", url, timeout=30)
            if rc == 0 and out:
                # whatweb output format: URL [detected-tech] [...]
                # Parse out technologies in brackets
                bracket_items = re.findall(r"\[([^\]]+)\]", out)
                for item in bracket_items:
                    name = item.split(",")[0].strip()
                    if name and name not in techs:
                        techs.append(name)

        return sorted(set(techs))

    # -- TLS check -----------------------------------------------------------

    async def _check_tls(self) -> Optional[Dict[str, Any]]:
        """Run TLS analysis on the target."""
        if self.scheme != "https" and self.port != 443:
            port_to_check = 443
        else:
            port_to_check = self.port or 443
        return await self.get_tls_info(self.hostname, port_to_check)


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

async def run_recon(target_url: str) -> dict:
    """Run the recon agent and return structured JSON findings.

    Returns:
        dict with keys: subdomains, open_ports, technologies, headers, findings
    """
    agent = ReconAgent(target_url)
    result = await agent.run()
    data = result.to_dict()
    # Flatten metadata into top-level keys for convenience
    data["subdomains"] = result.metadata.get("subdomains", [])
    data["open_ports"] = result.metadata.get("open_ports", [])
    data["technologies"] = result.metadata.get("technologies", [])
    data["headers"] = result.metadata.get("headers", {})
    return data
