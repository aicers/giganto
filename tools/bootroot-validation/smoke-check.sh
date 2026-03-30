#!/usr/bin/env bash
# smoke-check.sh — Verify mTLS connectivity to Giganto's GraphQL endpoint.
#
# Usage:
#   ./smoke-check.sh [--host HOST] [--port PORT] [--wait SECONDS]
#
# Options:
#   --host HOST     Target hostname (default: localhost)
#   --port PORT     Target port (default: 8443)
#   --wait SECONDS  Max seconds to wait for server readiness (default: 10)
#
# Environment variable overrides (same as start-validation.sh):
#   REAL_BOOTROOT_LEAF_PEM    — Client certificate for mTLS
#   REAL_BOOTROOT_KEY_PEM     — Client private key
#   REAL_BOOTROOT_CA_BUNDLE   — CA bundle for server verification
#
# Exit codes:
#   0 — Smoke check passed (TLS handshake + GraphQL response OK)
#   1 — Smoke check failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURES_DIR="${SCRIPT_DIR}/checked-fixtures"

HOST="localhost"
PORT="8443"
WAIT_SECONDS=10

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)  HOST="$2";         shift 2 ;;
    --port)  PORT="$2";         shift 2 ;;
    --wait)  WAIT_SECONDS="$2"; shift 2 ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# --- Resolve certificate paths ---
CERT_PATH="${REAL_BOOTROOT_LEAF_PEM:-${FIXTURES_DIR}/leaf.pem}"
KEY_PATH="${REAL_BOOTROOT_KEY_PEM:-${FIXTURES_DIR}/leaf.key}"
CA_BUNDLE="${REAL_BOOTROOT_CA_BUNDLE:-${FIXTURES_DIR}/ca-bundle.pem}"

for f in "$CERT_PATH" "$KEY_PATH" "$CA_BUNDLE"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: Required file not found: $f" >&2
    echo "Run generate-fixtures.sh first." >&2
    exit 1
  fi
done

URL="https://${HOST}:${PORT}/graphql"

echo "=== Bootroot mTLS Smoke Check ==="
echo "Target:     ${URL}"
echo "Cert:       ${CERT_PATH}"
echo "Key:        ${KEY_PATH}"
echo "CA bundle:  ${CA_BUNDLE}"
echo ""

# --- Wait for server readiness ---
echo "Waiting for server (up to ${WAIT_SECONDS}s)..."
READY=false
for i in $(seq 1 "$WAIT_SECONDS"); do
  if curl -sf --max-time 2 \
    --cert "$CERT_PATH" --key "$KEY_PATH" --cacert "$CA_BUNDLE" \
    -o /dev/null "$URL" 2>/dev/null; then
    READY=true
    break
  fi
  sleep 1
done

if [ "$READY" = false ]; then
  echo "ERROR: Server not reachable at ${URL}" >&2
  echo "" >&2
  echo "Common failure causes:" >&2
  echo "  - Server not started (run start-validation.sh first)" >&2
  echo "  - TLS handshake failure (wrong CA bundle or cert)" >&2
  echo "  - Certificate expired" >&2
  echo "  - Wrong CA bundle ordering (must be intermediate + root)" >&2
  echo "  - Missing SAN entries (leaf cert needs DNS:localhost)" >&2
  exit 1
fi
echo "Server is reachable."
echo ""

# --- GraphQL introspection query (minimal) ---
QUERY='{"query":"{ __typename }"}'

echo "Running GraphQL smoke query..."
HTTP_CODE=$(curl -s -o /tmp/giganto-smoke-response.json -w "%{http_code}" \
  --cert "$CERT_PATH" --key "$KEY_PATH" --cacert "$CA_BUNDLE" \
  -H "Content-Type: application/json" \
  -d "$QUERY" \
  "$URL")

echo "HTTP status: ${HTTP_CODE}"

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  echo ""
  echo "Response body:"
  cat /tmp/giganto-smoke-response.json
  echo ""
  echo ""
  echo "=== SMOKE CHECK PASSED ==="
  echo "mTLS handshake succeeded and GraphQL endpoint responded."
  rm -f /tmp/giganto-smoke-response.json
  exit 0
else
  echo ""
  echo "=== SMOKE CHECK FAILED ==="
  echo "HTTP ${HTTP_CODE} — expected 2xx." >&2
  echo "" >&2
  echo "Response:" >&2
  cat /tmp/giganto-smoke-response.json >&2
  echo "" >&2
  echo "" >&2
  echo "Troubleshooting:" >&2
  echo "  - HTTP 400: Query format issue" >&2
  echo "  - HTTP 403: Client certificate rejected" >&2
  echo "  - HTTP 495/496: TLS certificate error" >&2
  echo "  - curl error 35: TLS handshake failure" >&2
  echo "  - curl error 58: Problem with client cert/key" >&2
  rm -f /tmp/giganto-smoke-response.json
  exit 1
fi
