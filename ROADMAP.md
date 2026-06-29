# VulnForge — Project Roadmap

> **Current phase:** PHASE 0 — Foundation (June 29, 2026)

---

## PHASE 0 — Foundation (Week 1-2)

**Goal:** Project scaffold, legal framework, core architecture

| # | Task | Status | Owner |
|---|------|--------|-------|
| 0.1 | Git repo with full project structure | ✅ Done | Hernest |
| 0.2 | Legal framework (ToS, consent form, privacy, disclaimer) | ✅ Done | Hernest |
| 0.3 | Architecture document (ARCHITECTURE.md) | ✅ Done | Hernest |
| 0.4 | Set up development environment (Docker Compose) | ⬜ | Hernest |
| 0.5 | CI/CD pipeline (GitHub Actions) | ⬜ | Hernest |
| 0.6 | Domain & branding (name, logo, colors) | ⬜ | Mehdi |

**Milestone:** `git clone && docker compose up` works. Docs are complete.

---

## PHASE 1 — Core Scanner (Week 3-5)

**Goal:** Single-agent scanning pipeline working end-to-end

| # | Task | Status | Owner |
|---|------|--------|-------|
| 1.1 | Backend API scaffold (FastAPI, routes, auth) | ⬜ | Hernest |
| 1.2 | Database schema (users, scans, findings, subscriptions) | ⬜ | Hernest |
| 1.3 | Recon agent — subdomain enum, tech detection, port scanning | ⬜ | Hernest |
| 1.4 | Web scanner agent — XSS, SQLi, CSRF, headers, CORS | ⬜ | Hernest |
| 1.5 | Config scanner agent — .env leaks, TLS, secrets in repos | ⬜ | Hernest |
| 1.6 | Synthesizer — aggregate findings into structured report | ⬜ | Hernest |
| 1.7 | Scan a test target (DVWA, Juice Shop) end-to-end | ⬜ | Hernest |

**Milestone:** One target scanned, report generated. Pipeline works.

---

## PHASE 2 — Multi-Agent Orchestration (Week 6-8)

**Goal:** Swarm intelligence — agents communicate and collaborate

| # | Task | Status | Owner |
|---|------|--------|-------|
| 2.1 | Master Orchestrator — dispatch, coordinate, aggregate | ⬜ | Hernest |
| 2.2 | Agent-to-agent communication protocol (REST/WS) | ⬜ | Hernest |
| 2.3 | Parallel scan execution (Redis + Celery) | ⬜ | Hernest |
| 2.4 | Scan queue with priority & rate limiting | ⬜ | Hernest |
| 2.5 | Real-time scan progress WebSocket | ⬜ | Hernest |
| 2.6 | Target consent verification before any scan | ⬜ | Hernest |

**Milestone:** Multiple agents attack a target simultaneously, orchestrator compiles results.

---

## PHASE 3 — Dashboard & User Experience (Week 9-11)

**Goal:** Client-facing web application

| # | Task | Status | Owner |
|---|------|--------|-------|
| 3.1 | User auth (register, login, JWT, password reset) | ⬜ | Hernest |
| 3.2 | Dashboard — scan history, active scans, findings overview | ⬜ | Hernest |
| 3.3 | Scan submission form (URL, scope, consent upload) | ⬜ | Hernest |
| 3.4 | Report viewer — interactive findings with severity filters | ⬜ | Hernest |
| 3.5 | PDF/Markdown report export | ⬜ | Hernest |
| 3.6 | Multi-language support (EN/FR) | ⬜ | Hernest |

**Milestone:** User can sign up, submit a target, get a beautiful report.

---

## PHASE 4 — Monetization (Week 12-13)

**Goal:** Get paid

| # | Task | Status | Owner |
|---|------|--------|-------|
| 4.1 | Stripe integration (checkout, webhooks, invoices) | ⬜ | Hernest |
| 4.2 | Pricing tiers (Bronze/Silver/Gold) with feature gating | ⬜ | Hernest |
| 4.3 | Token-based pricing calculator (pre-scan estimate) | ⬜ | Hernest |
| 4.4 | Subscription billing (monthly continuous monitoring) | ⬜ | Hernest |
| 4.5 | Usage dashboard for clients (scans remaining, billing) | ⬜ | Hernest |
| 4.6 | Admin panel for Mehdi (revenue, users, scan stats) | ⬜ | Hernest |

**Milestone:** First paying customer.

---

## PHASE 5 — Launch & Scale (Week 14-16)

**Goal:** Production-ready, deployed, marketed

| # | Task | Status | Owner |
|---|------|--------|-------|
| 5.1 | Production deployment (VPS/Dedicated server) | ⬜ | Hernest |
| 5.2 | SSL, domain, DNS, monitoring, backups | ⬜ | Hernest |
| 5.3 | Rate limiting & abuse prevention | ⬜ | Hernest |
| 5.4 | Landing page & marketing site (claude-design skill) | ⬜ | Hernest |
| 5.5 | Documentation for clients (how to use, what to expect) | ⬜ | Hernest |
| 5.6 | GitHub integration (scan repos directly) | ⬜ | Hernest |

**Milestone:** vulnforge.io is live, accepting customers.

---

## PHASE 6 — Advanced Features (Week 17+)

**Goal:** Competitive moat

| # | Task | Status | Owner |
|---|------|--------|-------|
| 6.1 | Scheduled/recurring scans (continuous monitoring) | ⬜ | Hernest |
| 6.2 | API for programmatic scan triggering | ⬜ | Hernest |
| 6.3 | Custom scan policies (OWASP Top 10, PCI-DSS, custom) | ⬜ | Hernest |
| 6.4 | White-label reports (client branding) | ⬜ | Hernest |
| 6.5 | Integrations (Slack, Jira, GitHub Issues) | ⬜ | Hernest |
| 6.6 | AI fix generator — auto-generate patches for found vulns | ⬜ | Hernest |
| 6.7 | Competitive benchmarking (how does client compare to peers?) | ⬜ | Hernest |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Legal liability (unauthorized scan) | Low | Critical | Mandatory consent verification before all scans |
| Token costs exceed pricing | Medium | High | Token estimation pre-scan, dynamic pricing |
| Scan targets blocking agents | High | Medium | Proxy rotation, throttling, User-Agent rotation |
| False positives erode trust | Medium | High | Two-pass validation, human review for Gold tier |
| Competitor launches similar product | Medium | Medium | Speed to market, AI quality moat |

---

## Key Decisions Needed from Mehdi

- [ ] **Company name** — VulnForge or something else?
- [ ] **Domain** — vulnforge.io? .ch? .com?
- [ ] **Pricing** — confirm token-based + margin model
- [ ] **Legal entity** — Swiss GmbH? Sole proprietorship?
- [ ] **Hosting** — Which VPS provider? Budget?
- [ ] **Launch target** — When do we want first customer?
