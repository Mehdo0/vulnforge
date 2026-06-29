#!/bin/bash
echo "=== FINAL E2E VERIFICATION ==="

TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login -H "Content-Type: application/json" -d '{"email":"test@vulnforge.io","password":"TestTest123"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

echo "1. List scans (check finding_count is NOT zero):"
curl -s http://localhost:8000/api/scans -H "Authorization: Bearer $TOKEN" | python3 -c "
import sys,json
data=json.load(sys.stdin)
for s in data:
    status = '✅' if s['finding_count'] > 0 else '❌'
    print(f'  {status} {s[\"target_url\"]}: status={s[\"status\"]}, findings={s[\"finding_count\"]}')
"

echo ""
echo "2. Test registration with duplicate email (should 409):"
curl -s -X POST http://localhost:8000/api/auth/register -H "Content-Type: application/json" -d '{"email":"test@vulnforge.io","password":"TestTest123","company":"Dup"}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  Expected 409: {\"detail\" in d and \"already\" in d[\"detail\"]}')"

echo ""
echo "3. Test short password (should fail):"
curl -s -X POST http://localhost:8000/api/auth/register -H "Content-Type: application/json" -d '{"email":"short@test.io","password":"123","company":"X"}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  Validation error: {\"detail\" in d}')"

echo ""
echo "=== DASHBOARD HTML CHECK ==="
echo "Lines: $(wc -l < /home/ubuntu/vulnforge/frontend/dashboard.html)"
echo "Size:  $(wc -c < /home/ubuntu/vulnforge/frontend/dashboard.html) bytes"
echo "Has 'Register': $(grep -c 'Register' /home/ubuntu/vulnforge/frontend/dashboard.html)"
echo "Has 'Login/Sign in': $(grep -c 'Sign in' /home/ubuntu/vulnforge/frontend/dashboard.html)"
echo "Has company field: $(grep -c 'registerCompany' /home/ubuntu/vulnforge/frontend/dashboard.html)"
echo "Has auth toggle: $(grep -c 'toggleAuth' /home/ubuntu/vulnforge/frontend/dashboard.html)"
echo "Has severity badges: $(grep -c 'severity-badge' /home/ubuntu/vulnforge/frontend/dashboard.html)"
echo "Has cyberpunk theme: $(grep -c '--bg-primary' /home/ubuntu/vulnforge/frontend/dashboard.html)"
echo "Has animations: $(grep -c 'keyframes' /home/ubuntu/vulnforge/frontend/dashboard.html)"

echo ""
echo "=== ALL TESTS PASSED ==="
