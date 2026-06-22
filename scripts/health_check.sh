#!/bin/bash
# scripts/health_check.sh — Vérifie tous les endpoints /health
set -e
BASE_URL="${API_URL:-http://localhost:8000}"
echo "=== SmartSIEM Health Check ==="
check() {
  local name=$1 url=$2
  status=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
  [ "$status" = "200" ] && echo "  ? $name ($url)" || echo "  ? $name ($url) ? HTTP $status"
}
check "Backend API"    "$BASE_URL/health"
check "Elasticsearch" "http://${ES_HOST:-localhost}:9200/_cluster/health"
check "Redis"         "http://${REDIS_HOST:-localhost}:6379" || true
echo "=== Fin du Health Check ==="
