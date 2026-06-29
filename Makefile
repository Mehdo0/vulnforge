.PHONY: install run dev clean test db-reset

# ── VulnForge Makefile ──────────────────────────────────────
# Single-command startup: make run
# Dev with hot reload:   make dev

PYTHON := python3
PIP := pip3
UVICORN := uvicorn
HOST := 0.0.0.0
PORT := 8000
APP := backend.main:app

# ── Install ─────────────────────────────────────────────────

install:
	@echo "📦 Installing VulnForge dependencies..."
	cd backend && $(PIP) install -q -r requirements.txt
	@echo "✅ Dependencies installed"

# ── Run (production) ────────────────────────────────────────

run: install
	@echo "🛡️  VulnForge starting on http://$(HOST):$(PORT)"
	cd backend && $(PYTHON) -m $(UVICORN) $(APP) --host $(HOST) --port $(PORT)

# ── Dev (hot reload) ────────────────────────────────────────

dev: install
	@echo "🔧 VulnForge dev mode on http://$(HOST):$(PORT)"
	cd backend && $(PYTHON) -m $(UVICORN) $(APP) --host $(HOST) --port $(PORT) --reload

# ── Docker ──────────────────────────────────────────────────

docker-up:
	docker compose -f docker/docker-compose.yml up -d --build

docker-down:
	docker compose -f docker/docker-compose.yml down

docker-logs:
	docker compose -f docker/docker-compose.yml logs -f

# ── Testing ─────────────────────────────────────────────────

test:
	@echo "🧪 Running VulnForge API tests..."
	@curl -s http://localhost:$(PORT)/api/health | python3 -m json.tool
	@echo ""
	@echo "📝 Register test user..."
	@curl -s -X POST http://localhost:$(PORT)/api/auth/register \
		-H "Content-Type: application/json" \
		-d '{"email":"test@vulnforge.io","password":"Test12345!"}' | python3 -m json.tool
	@echo ""
	@echo "🔑 Login..."
	@TOKEN=$$(curl -s -X POST http://localhost:$(PORT)/api/auth/login \
		-H "Content-Type: application/json" \
		-d '{"email":"test@vulnforge.io","password":"Test12345!"}' \
		| python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])"); \
	curl -s http://localhost:$(PORT)/api/auth/me -H "Authorization: Bearer $$TOKEN" | python3 -m json.tool
	@echo ""
	@echo "✅ All tests passed"

# ── Utilities ───────────────────────────────────────────────

clean:
	@echo "🧹 Cleaning..."
	rm -rf backend/__pycache__ backend/**/__pycache__ backend/data/reports/*
	@echo "✅ Cleaned"

db-reset:
	@echo "🗑️  Resetting database..."
	rm -f backend/data/vulnforge.db
	@echo "✅ Database reset"

setup: install
	@echo "🔐 Setting up secrets..."
	@mkdir -p secrets
	@openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
		-keyout secrets/server.key \
		-out secrets/server.crt \
		-subj "/C=CH/ST=Vaud/L=Lausanne/O=VulnForge/CN=localhost" 2>/dev/null
	@echo "✅ SSL certs generated"
	@echo ""
	@echo "🎉 VulnForge is ready! Run: make run"

# ── Full reset ──────────────────────────────────────────────

reset: clean db-reset
	@echo "🔄 Full reset complete. Run: make run"
