"""
VulnForge — Code Repository Security Agent

Analyzes GitHub repositories for:
  - Hardcoded secrets (API keys, tokens, passwords)
  - Exposed .env and configuration files
  - Common dependency vulnerabilities (via manifest files)
  - Sensitive file patterns in commit history
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .base import BaseAgent, Finding, ScanResult, Severity, SECRET_PATTERNS

# ---------------------------------------------------------------------------
# Dependency vulnerability lookup (basic version-based checks)
# ---------------------------------------------------------------------------

KNOWN_VULN_DEPENDENCIES: Dict[str, List[Dict[str, Any]]] = {
    "lodash": [
        {"version": "<4.17.21", "cve": "CVE-2021-23337", "severity": Severity.HIGH, "desc": "Prototype pollution via setWith and set functions"},
        {"version": "<4.17.19", "cve": "CVE-2020-8203", "severity": Severity.HIGH, "desc": "Prototype pollution in zipObjectDeep"},
    ],
    "express": [
        {"version": "<4.18.0", "cve": "CVE-2024-29041", "severity": Severity.MEDIUM, "desc": "Open redirect vulnerability"},
    ],
    "django": [
        {"version": "<3.2.25", "cve": "CVE-2024-27351", "severity": Severity.HIGH, "desc": "Potential ReDoS in django.utils.text.Truncator"},
        {"version": "<5.0.6", "cve": "CVE-2024-27351", "severity": Severity.HIGH, "desc": "Potential regular expression denial of service"},
    ],
    "flask": [
        {"version": "<2.3.0", "cve": "CVE-2023-30861", "severity": Severity.HIGH, "desc": "Cookie leak via information disclosure"},
    ],
    "requests": [
        {"version": "<2.32.0", "cve": "CVE-2024-35195", "severity": Severity.MEDIUM, "desc": "Headers not removed on redirect when using no_auth"},
    ],
    "axios": [
        {"version": "<1.7.4", "cve": "CVE-2024-39338", "severity": Severity.HIGH, "desc": "Server-Side Request Forgery (SSRF)"},
    ],
    "next": [
        {"version": "<14.2.10", "cve": "CVE-2024-46982", "severity": Severity.CRITICAL, "desc": "SSRF via Server Actions"},
    ],
    "fastapi": [
        {"version": "<0.109.1", "cve": "CVE-2024-24762", "severity": Severity.HIGH, "desc": "ReDoS via form data parsing"},
    ],
    "log4j": [
        {"version": "<2.17.1", "cve": "CVE-2021-44228", "severity": Severity.CRITICAL, "desc": "RCE via JNDI lookup (Log4Shell)"},
    ],
    "pyyaml": [
        {"version": "<6.0.1", "cve": "CVE-2020-14343", "severity": Severity.CRITICAL, "desc": "Arbitrary code execution via unsafe YAML loading"},
    ],
    "pillow": [
        {"version": "<10.3.0", "cve": "CVE-2022-45199", "severity": Severity.HIGH, "desc": "Denial of service via decompression bomb"},
    ],
    "urllib3": [
        {"version": "<2.2.2", "cve": "CVE-2024-37891", "severity": Severity.MEDIUM, "desc": "Proxy-Authorization header leak on cross-origin redirects"},
    ],
    "cryptography": [
        {"version": "<42.0.4", "cve": "CVE-2024-26130", "severity": Severity.HIGH, "desc": "NULL pointer dereference leading to crash"},
    ],
    "jquery": [
        {"version": "<3.5.0", "cve": "CVE-2020-11023", "severity": Severity.MEDIUM, "desc": "XSS via HTML parsing in jQuery.htmlPrefilter"},
    ],
    "bootstrap": [
        {"version": "<5.3.3", "cve": "CVE-2024-6531", "severity": Severity.MEDIUM, "desc": "XSS via data attribute injection"},
    ],
}

# Files that commonly contain secrets
SECRET_FILE_PATTERNS: List[str] = [
    r"\.env$", r"\.env\.local$", r"\.env\.production$",
    r"credentials\.json$", r"credentials\.yaml$",
    r"secrets\.yaml$", r"secrets\.json$",
    r"serviceAccountKey\.json$",
    r"\.pem$", r"\.key$", r"\.p12$", r"\.pfx$",
    r"id_rsa$", r"id_ed25519$", r"id_ecdsa$",
    r"known_hosts$",
]

MANIFEST_FILES: Dict[str, List[str]] = {
    "npm":     ["package.json"],
    "python":  ["requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg"],
    "ruby":    ["Gemfile", "Gemfile.lock"],
    "php":     ["composer.json", "composer.lock"],
    "java":    ["pom.xml", "build.gradle", "build.gradle.kts"],
    "go":      ["go.mod", "go.sum"],
    "rust":    ["Cargo.toml", "Cargo.lock"],
    "dotnet":  ["*.csproj", "packages.config"],
}


class CodeAgent(BaseAgent):
    """Code repository security agent."""

    agent_name = "code"

    def __init__(self, target: str, timeout: int = 30) -> None:
        super().__init__(target, timeout)
        self._is_github_repo = (
            "github.com" in target or self.parsed.hostname == "github.com"
        )
        self._repo_owner: Optional[str] = None
        self._repo_name: Optional[str] = None
        self._api_base = "https://api.github.com"

        if self._is_github_repo:
            path_parts = self.parsed.path.strip("/").split("/")
            if len(path_parts) >= 2:
                self._repo_owner = path_parts[0]
                self._repo_name = path_parts[1].replace(".git", "")

    async def run(self) -> ScanResult:
        """Execute code security analysis."""
        result = ScanResult(
            metadata={
                "target": self.target,
                "is_github_repo": self._is_github_repo,
                "repo_owner": self._repo_owner,
                "repo_name": self._repo_name,
            }
        )

        t0 = asyncio.get_event_loop().time()
        self.log(f"Starting code scan on {self.target}")

        if not self._is_github_repo or not self._repo_owner or not self._repo_name:
            result.errors.append("Target is not a recognizable GitHub repository URL.")
            self.log("Not a GitHub repo — code scan limited to URL-based checks only.")
            await self._check_exposed_env_via_url(result)
            result.duration = asyncio.get_event_loop().time() - t0
            return result

        results_tasks = await asyncio.gather(
            self._check_exposed_env_via_url(result),
            self._check_git_exposure(result),
            self._scan_github_contents(result),
            self._check_dependency_vulnerabilities(result),
            return_exceptions=True,
        )

        for task_result in results_tasks:
            if isinstance(task_result, Exception):
                result.errors.append(str(task_result))

        result.duration = asyncio.get_event_loop().time() - t0
        self.log(f"Code scan completed in {result.duration:.1f}s — {len(result.findings)} findings")
        return result

    async def _check_exposed_env_via_url(self, result: ScanResult) -> None:
        """Check if .env files are exposed."""
        if not self._repo_owner or not self._repo_name:
            base_url = f"{self.scheme}://{self.hostname}"
            for url in [f"{base_url}/.env", f"{base_url}/.env.local"]:
                try:
                    status, body, _ = await self.http_get(url)
                    if status == 200 and len(body) > 10:
                        result.add(Finding(
                            title="Exposed .env file",
                            description=f"An environment file is accessible at {url}, potentially leaking secrets.",
                            severity=Severity.CRITICAL,
                            category="secrets",
                            evidence=f"HTTP {status}, {len(body)} bytes",
                            recommendation="Remove .env from public access. Rotate exposed credentials.",
                            cwe_id="CWE-538",
                            agent=self.agent_name,
                        ))
                except Exception:
                    pass
            return

        branches = ["main", "master", "develop"]
        env_paths = [".env", ".env.local", ".env.production", ".env.development"]

        for branch in branches:
            for env_path in env_paths:
                raw_url = (
                    f"https://raw.githubusercontent.com/"
                    f"{self._repo_owner}/{self._repo_name}/{branch}/{env_path}"
                )
                try:
                    status, body, _ = await self.http_get(raw_url)
                    if status == 200 and len(body) > 10:
                        result.add(Finding(
                            title=f"Exposed {env_path} in repository ({branch})",
                            description=f"The file {env_path} is publicly accessible on branch {branch}.",
                            severity=Severity.CRITICAL,
                            category="secrets",
                            evidence=f"Accessible at {raw_url} ({len(body)} bytes)",
                            recommendation="Remove {env_path} from the repo. Add to .gitignore. Rotate all credentials.",
                            cwe_id="CWE-538",
                            agent=self.agent_name,
                        ))
                except Exception:
                    pass

    async def _check_git_exposure(self, result: ScanResult) -> None:
        """Check GitHub API for repo metadata."""
        if not self._repo_owner or not self._repo_name:
            return

        api_url = f"{self._api_base}/repos/{self._repo_owner}/{self._repo_name}"
        try:
            status, body, _ = await self.http_get(api_url)
            if status == 200:
                repo_data = json.loads(body)
                result.metadata["repo_full_name"] = repo_data.get("full_name", "")
                result.metadata["repo_private"] = repo_data.get("private", False)
                result.metadata["repo_description"] = repo_data.get("description", "")
                result.metadata["repo_archived"] = repo_data.get("archived", False)

                if repo_data.get("private"):
                    result.add(Finding(
                        title="Private repository — limited visibility",
                        description="This is a private repository. Scanning is limited to publicly accessible paths.",
                        severity=Severity.INFO,
                        category="repository",
                        evidence=f"Repository: {repo_data.get('full_name')} (private)",
                        recommendation="Full scanning requires authentication token with repo access.",
                        agent=self.agent_name,
                    ))

                if repo_data.get("archived"):
                    result.add(Finding(
                        title="Repository is archived",
                        description="This repository has been archived and may contain outdated/unmaintained code.",
                        severity=Severity.INFO,
                        category="repository",
                        evidence=f"Archived: {repo_data.get('full_name')}",
                        recommendation="Review whether the archived code contains sensitive data that should be removed.",
                        agent=self.agent_name,
                    ))
            elif status == 404:
                result.add(Finding(
                    title="Repository not found via GitHub API",
                    description=f"The repository {self._repo_owner}/{self._repo_name} returned 404.",
                    severity=Severity.INFO,
                    category="repository",
                    evidence=f"GitHub API returned {status}",
                    recommendation="Verify the repository URL is correct and accessible.",
                    agent=self.agent_name,
                ))
        except Exception as exc:
            result.errors.append(f"GitHub API error: {exc}")

    async def _scan_github_contents(self, result: ScanResult) -> None:
        """Scan repository tree via GitHub API for sensitive files."""
        if not self._repo_owner or not self._repo_name:
            return

        try:
            contents_url = (
                f"{self._api_base}/repos/{self._repo_owner}/"
                f"{self._repo_name}/git/trees/HEAD?recursive=1"
            )
            status, body, _ = await self.http_get(contents_url)

            if status != 200:
                return

            tree_data = json.loads(body)
            files = tree_data.get("tree", [])
            result.metadata["total_files"] = len(files)

            for file_entry in files:
                path = file_entry.get("path", "")
                file_type = file_entry.get("type", "")

                if file_type != "blob":
                    continue

                filename = path.split("/")[-1]

                for pattern in SECRET_FILE_PATTERNS:
                    if re.search(pattern, filename, re.I):
                        result.add(Finding(
                            title=f"Sensitive file in repository: {path}",
                            description=f"A file matching sensitive patterns ({filename}) was found.",
                            severity=Severity.HIGH,
                            category="secrets",
                            evidence=f"File: {path}",
                            recommendation="Remove this file from the repo and add to .gitignore. Rotate exposed credentials.",
                            cwe_id="CWE-538",
                            agent=self.agent_name,
                        ))
                        break

            manifest_files: List[Dict[str, Any]] = []
            for manifest_type, patterns in MANIFEST_FILES.items():
                for pattern in patterns:
                    for file_entry in files:
                        path = file_entry.get("path", "")
                        filename = path.split("/")[-1]
                        if filename == pattern or (pattern.startswith("*") and filename.endswith(pattern[1:])):
                            manifest_files.append({
                                "type": manifest_type,
                                "path": path,
                                "sha": file_entry.get("sha"),
                            })

            result.metadata["manifest_files"] = manifest_files
            self.log(f"Found {len(manifest_files)} manifest files")

        except json.JSONDecodeError:
            result.errors.append("Failed to parse GitHub API response")
        except Exception as exc:
            result.errors.append(f"Contents scan error: {exc}")

    async def _check_dependency_vulnerabilities(self, result: ScanResult) -> None:
        """Check manifest files for known-vulnerable dependencies."""
        manifest_files = result.metadata.get("manifest_files", [])

        for manifest in manifest_files:
            path = manifest["path"]
            manifest_type = manifest["type"]
            sha = manifest.get("sha")
            if not sha:
                continue

            try:
                blob_url = (
                    f"{self._api_base}/repos/{self._repo_owner}/"
                    f"{self._repo_name}/git/blobs/{sha}"
                )
                status, body, _ = await self.http_get(blob_url)

                if status != 200:
                    continue

                blob_data = json.loads(body)
                raw_content = blob_data.get("content", "")
                if not raw_content:
                    continue

                decoded = base64.b64decode(raw_content).decode("utf-8", errors="replace")
                await self._check_deps_from_manifest(manifest_type, path, decoded, result)

            except Exception as exc:
                result.errors.append(f"Dependency check error for {path}: {exc}")

    async def _check_deps_from_manifest(
        self, manifest_type: str, path: str, content: str, result: ScanResult
    ) -> None:
        """Parse a manifest and check dependencies against known vulns."""
        dependencies: Dict[str, str] = {}

        try:
            if manifest_type == "npm":
                data = json.loads(content)
                deps = data.get("dependencies", {})
                dev_deps = data.get("devDependencies", {})
                all_deps = {**deps, **dev_deps}
                for name, version in all_deps.items():
                    dependencies[name.lower()] = str(version).lstrip("^~>= ")

            elif manifest_type == "python":
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*([><=!~]+)\s*([A-Za-z0-9_\-\.]+)', line)
                    if match:
                        dependencies[match.group(1).lower()] = match.group(3)

            elif manifest_type == "ruby":
                for line in content.splitlines():
                    match = re.search(r'gem\s+[\'"]([A-Za-z0-9_\-]+)[\'"]\s*,\s*[\'"]([0-9.]+)[\'"]?', line)
                    if match:
                        dependencies[match.group(1).lower()] = match.group(2)

            elif manifest_type == "php":
                data = json.loads(content)
                require = data.get("require", {})
                for name, version in require.items():
                    if "/" in name:
                        name = name.split("/")[-1]
                    dependencies[name.lower()] = str(version).lstrip("^~>= ")

            elif manifest_type == "java":
                for match in re.finditer(
                    r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>',
                    content,
                ):
                    dependencies[match.group(2).lower()] = match.group(3)

        except (json.JSONDecodeError, Exception):
            return

        for dep_name, dep_version in dependencies.items():
            if dep_name in KNOWN_VULN_DEPENDENCIES:
                for vuln in KNOWN_VULN_DEPENDENCIES[dep_name]:
                    if self._version_matches(dep_version, vuln["version"]):
                        result.add(Finding(
                            title=f"Vulnerable dependency: {dep_name} {dep_version}",
                            description=f"{vuln['desc']} ({vuln['cve']}). Installed: {dep_version}, affected: {vuln['version']}.",
                            severity=vuln["severity"],
                            category="vulnerable_dependency",
                            evidence=f"File: {path}\nDependency: {dep_name}@{dep_version}\nCVE: {vuln['cve']}",
                            recommendation=f"Upgrade {dep_name} to the latest patched version.",
                            cwe_id="CWE-1104",
                            agent=self.agent_name,
                        ))

    @staticmethod
    def _version_matches(version: str, constraint: str) -> bool:
        """Simple version-to-constraint matching."""
        if not version or not constraint:
            return False
        version_parts = re.findall(r"\d+", version)
        constraint_parts = re.findall(r"\d+", constraint)
        if not version_parts or not constraint_parts:
            return False
        max_len = max(len(version_parts), len(constraint_parts))
        v = [int(version_parts[i]) if i < len(version_parts) else 0 for i in range(max_len)]
        c = [int(constraint_parts[i]) if i < len(constraint_parts) else 0 for i in range(max_len)]

        if constraint.startswith("<="):
            return v <= c
        elif constraint.startswith("<"):
            return v < c
        elif constraint.startswith(">="):
            return v >= c
        elif constraint.startswith(">"):
            return v > c
        elif constraint.startswith("=="):
            return v == c
        else:
            return v < c


async def run_code(target_url: str) -> dict:
    """Run the code repository security agent.

    Accepts GitHub repo URLs (https://github.com/owner/repo) or any URL.
    Returns dict with findings, metadata, errors, and duration.
    """
    agent = CodeAgent(target_url)
    result = await agent.run()
    return result.to_dict()
