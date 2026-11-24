#!/usr/bin/env bash
set -euo pipefail

echo "1) Authorized request via EdgeGate (zero upstream API keys in sandbox):"
docker compose -f docker-compose.demo.yml exec -T sandbox \
  curl -fsS -H "X-EdgeGate-Token: eg-demo-token-alpha" http://edgegate:8080/v1/github/repos/edgegate

echo "2) Cross-tenant org-beta request (expected HTTP 403):"
STATUS=$(docker compose -f docker-compose.demo.yml exec -T sandbox \
  curl -s -o /dev/null -w "%{http_code}" -H "X-EdgeGate-Token: eg-demo-token-beta" http://edgegate:8080/v1/github/repos/edgegate)
echo "HTTP $STATUS"
[ "$STATUS" = "403" ]

echo "3) Unapproved destination route (expected HTTP 403):"
STATUS=$(docker compose -f docker-compose.demo.yml exec -T sandbox \
  curl -s -o /dev/null -w "%{http_code}" -H "X-EdgeGate-Token: eg-demo-token-alpha" http://edgegate:8080/v1/openai/chat)
echo "HTTP $STATUS"
[ "$STATUS" = "403" ]

echo "4) SSRF cloud metadata block (expected HTTP 403):"
STATUS=$(docker compose -f docker-compose.demo.yml exec -T sandbox \
  curl -s -o /dev/null -w "%{http_code}" -H "X-EdgeGate-Token: eg-demo-token-alpha" http://edgegate:8080/v1/metadata/latest)
echo "HTTP $STATUS"
[ "$STATUS" = "403" ]

echo "5) Direct egress bypass from isolated sandbox to upstream-a (expected network failure):"
if docker compose -f docker-compose.demo.yml exec -T sandbox curl -fsS --max-time 2 http://upstream-a:9001/ >/dev/null 2>&1; then
  echo "FAIL: sandbox bypassed EdgeGate!" >&2
  exit 1
else
  echo "PASS: direct egress from sandbox blocked at network layer."
fi
