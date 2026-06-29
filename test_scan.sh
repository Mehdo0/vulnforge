#!/bin/bash
set -e
echo "=== LOGIN ==="
LOGIN_RESP=$(curl -s -X POST http://localhost:8000/api/auth/login -H "Content-Type: application/json" -d '{"email":"test@vulnforge.io","password":"TestTest123"}')
echo "$LOGIN_RESP"

TOKEN=$(python3 -c "import sys,json;print(json.loads(sys.argv[1])['access_token'])" "$LOGIN_RESP")
echo "TOKEN length: ${#TOKEN}"

echo "=== SUBMITTING SCAN ==="
SCAN_RESP=$(curl -s -X POST http://localhost:8000/api/scans -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"target_url":"https://example.com","plan_tier":"silver"}')
echo "$SCAN_RESP"
echo "$SCAN_RESP" > /tmp/scan_response.json

SCAN_ID=$(python3 -c "import sys,json;print(json.loads(sys.argv[1])['id'])" "$SCAN_RESP")
echo "SCAN_ID=$SCAN_ID"

echo "=== WAITING 30s ==="
sleep 30

echo "=== CHECKING SCAN RESULTS ==="
curl -s "http://localhost:8000/api/scans/$SCAN_ID" -H "Authorization: Bearer $TOKEN"

echo ""
echo "=== LISTING ALL SCANS ==="
curl -s http://localhost:8000/api/scans -H "Authorization: Bearer $TOKEN"
