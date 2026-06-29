# VulnForge — Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT                                │
│  Browser ──► vulnforge.io ──► Dashboard + Reports            │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS
┌──────────────────────────▼──────────────────────────────────┐
│                    NGINX REVERSE PROXY                        │
│  TLS termination, rate limiting, WAF                          │
└──────────────┬───────────────────────────────┬──────────────┘
               │                               │
┌──────────────▼──────────┐     ┌──────────────▼──────────────┐
│     SVELTEKIT SSR        │     │      FASTAPI BACKEND         │
│  Frontend rendering      │     │  REST API + WebSocket        │
│  Static assets           │     │  Auth, Scans, Reports        │
└──────────────────────────┘     └──────────────┬──────────────┘
                                                │
                            ┌───────────────────┼───────────────┐
                            │                   │               │
                    ┌───────▼──────┐   ┌───────▼──────┐  ┌─────▼──────┐
                    │  PostgreSQL   │   │    Redis      │  │   Celery   │
                    │  Users, Scans │   │  Cache, Queue │  │  Workers   │
                    │  Findings     │   │  Sessions     │  │  Tasks     │
                    └──────────────┘   └──────────────┘  └─────┬──────┘
                                                               │
                    ┌──────────────────────────────────────────▼──────┐
                    │           ORCHESTRATOR (Celery Task)              │
                    │                                                  │
                    │  1. Receive scan request                          │
                    │  2. Verify consent document                       │
                    │  3. Estimate scope & token cost                   │
                    │  4. Spawn agent swarm                             │
                    │  5. Monitor progress                              │
                    │  6. Collect & aggregate findings                  │
                    │  7. Generate report                               │
                    │  8. Notify user                                   │
                    └──────────────┬───────────────────────────────────┘
                                   │
        ┌──────────────┬───────────┼───────────┬──────────────┐
        │              │           │           │              │
┌───────▼──────┐ ┌─────▼─────┐ ┌──▼────┐ ┌────▼─────┐ ┌─────▼──────┐
│ RECON AGENT  │ │  WEB APP  │ │  API  │ │  CONFIG  │ │   CODE     │
│              │ │  AGENT    │ │ AGENT │ │  AGENT   │ │   AGENT    │
│ • subdomains │ │ • XSS     │ │• auth │ │• headers │ │• secrets   │
│ • ports      │ │ • SQLi    │ │• rate │ │• TLS     │ │• dep vulns │
│ • tech stack │ │ • CSRF    │ │• CORS │ │• cookies │ │• hardcoded │
│ • DNS        │ │ • fuzzing │ │• JWT  │ │• CSP     │ │• CI/CD     │
└──────────────┘ └───────────┘ └───────┘ └──────────┘ └────────────┘
                                   │
                          ┌────────▼────────┐
                          │   SYNTHESIZER    │
                          │ • Deduplicate    │
                          │ • Severity score │
                          │ • Exploit chain  │
                          │ • Fix suggestion │
                          │ • Report gen     │
                          └─────────────────┘
```

## Agent Specifications

### Orchestrator (Master)
- **Role:** Command & control
- **Input:** Target URL + scope + consent doc
- **Output:** Final report
- **Responsibilities:**
  - Parse scope, identify attack surface
  - Dispatch specialized agents in parallel
  - Monitor agent health & timeout handling
  - Aggregate findings, remove duplicates
  - Assign CVSS scores
  - Generate human-readable report

### Recon Agent
- **Tools:** nmap, whatweb, subfinder, amass, dig
- **Finds:** Open ports, technologies, subdomains, DNS misconfig
- **Tactics:** Passive + active recon

### Web Application Agent
- **Tools:** nuclei templates, custom scripts, browser (playwright)
- **Finds:** XSS, SQLi, CSRF, IDOR, SSTI, file inclusion
- **Tactics:** Fuzzing, payload injection, authentication bypass

### API Security Agent
- **Tools:** Custom REST/GraphQL fuzzer, JWT analyzer
- **Finds:** Rate limiting, auth bypass, CORS misconfig, mass assignment
- **Tactics:** Schema analysis, token manipulation, parameter pollution

### Configuration Agent
- **Tools:** testssl.sh, securityheaders.com analysis, CSP evaluator
- **Finds:** Missing headers, weak TLS, cookie flags, information disclosure
- **Tactics:** Passive analysis, non-intrusive

### Code Security Agent (GitHub repos)
- **Tools:** truffleHog, gitleaks, dependency-check, semgrep
- **Finds:** Hardcoded secrets, vulnerable dependencies, SAST findings
- **Tactics:** Static analysis, commit history scanning

### Synthesizer
- **Role:** Intelligence fusion
- **Input:** Raw findings from all agents
- **Output:** Structured vulnerability report
- **Responsibilities:**
  - Deduplicate similar findings
  - Chain related vulnerabilities (e.g., XSS + weak CSP)
  - Assign CVSS 3.1 scores
  - Generate executive summary
  - Produce fix recommendations
  - Create timeline of attack simulation

## Data Model (Core)

```python
# Users
User: id, email, hashed_password, company, plan_tier, stripe_id

# Scans
Scan: id, user_id, target_url, scope, status, created_at, completed_at

# Findings
Finding: id, scan_id, agent_type, title, description, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO),
         cvss_score, cvss_vector, evidence, remediation, cwe_id

# Consent
Consent: id, scan_id, document_url, verified_at, ip_address, user_agent

# Subscriptions
Subscription: id, user_id, plan, scans_remaining, tokens_remaining, current_period_end
```

## API Endpoints (Planned)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | User registration |
| POST | `/api/auth/login` | Login, returns JWT |
| POST | `/api/scans` | Submit new scan |
| GET | `/api/scans` | List user's scans |
| GET | `/api/scans/{id}` | Scan details + progress |
| GET | `/api/scans/{id}/report` | Download report (PDF/MD) |
| POST | `/api/scans/{id}/consent` | Upload consent document |
| WS | `/ws/scan/{id}` | Real-time scan progress |
| GET | `/api/account` | User profile & usage |
| POST | `/api/checkout` | Stripe checkout session |

## Deployment Architecture

```
Production Server (Hetzner / DigitalOcean)
├── Docker Compose
│   ├── nginx (reverse proxy + SSL)
│   ├── backend (FastAPI, 2+ replicas)
│   ├── frontend (SvelteKit, SSR)
│   ├── celery-worker (2+ replicas)
│   ├── celery-beat (scheduler)
│   ├── postgres (primary + replica)
│   └── redis (cache + broker)
├── Volumes
│   ├── postgres_data
│   ├── redis_data
│   └── scan_artifacts
└── Monitoring
    ├── Prometheus + Grafana
    ├── Sentry (error tracking)
    └── Uptime monitoring
```

## Security of the Platform Itself

- All agent scans run in isolated Docker containers
- No persistent access to client targets after scan
- Scan artifacts auto-deleted after 30 days (GDPR)
- All inter-service communication over TLS
- Secrets managed via environment variables, never in code
- Regular security audits of VulnForge itself
