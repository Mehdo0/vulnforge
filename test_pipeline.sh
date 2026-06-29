#!/bin/bash
set -e

echo "=== 1. LOGIN ==="
LOGIN_RESP=$(curl -s -X POST http://localhost:8000/api/auth/login -H "Content-Type: application/json" -d '{"email":"test@vulnforge.io","password":"TestTest123"}')
echo "$LOGIN_RESP"
TOKEN=$(python3 -c "import sys,json;print(json.loads(sys.argv[1])['access_token'])" "$LOGIN_RESP")
echo "Token OK (${#TOKEN} chars)"

echo ""
echo "=== 2. VERIFY /me ==="
curl -s http://localhost:8000/api/auth/me -H "Authorization: Bearer $TOKEN"
echo ""

echo ""
echo "=== 3. SUBMIT SCAN ==="
SCAN_RESP=$(curl -s -X POST http://localhost:8000/api/scans -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"target_url":"https://example.com","plan_tier":"silver"}')
echo "$SCAN_RESP"
SCAN_ID=$(python3 -c "import sys,json;print(json.loads(sys.argv[1])['id'])" "$SCAN_RESP")
echo "SCAN_ID=$SCAN_ID"

echo ""
echo "=== 4. WAITING 30s FOR SCAN TO COMPLETE ==="
sleep 30

echo ""
echo "=== 5. CHECK SCAN RESULTS ==="
DETAIL=$(curl -s "http://localhost:8000/api/scans/$SCAN_ID" -H "Authorization: Bearer $TOKEN")
echo "$DETAIL" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f'Status: {d[\"status\"]}')
print(f'Finding count: {d[\"finding_count\"]}')
for f in d['findings']:
    print(f'  [{f[\"severity\"]}] [{f[\"agent_type\"]}] {f[\"title\"][:80]}')
    if f.get('remediation'):
        print(f'    FIX: {f[\"remediation\"][:100]}')
"

echo ""
echo "=== 6. LIST SCANS ==="
curl -s http://localhost:8000/api/scans -H "Authorization: Bearer $TOKEN" | python3 -c "
import sys,json
data=json.load(sys.stdin)
for s in data:
    print(f'  {s[\"id\"][:8]}... {s[\"status\"]:12s} findings={s[\"finding_count\"]} cost={s.get(\"cost_estimate\",\"?\")}')
"

echo ""
echo "=== 7. CHECK REPORT FILE ==="
ls -la /home/ubuntu/vulnforge/backend/data/reports/${SCAN_ID}.md 2>/dev/null && echo "Report exists!" || echo "No report found"
