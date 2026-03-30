#!/usr/bin/env bash
# start-validation.sh — Start Giganto with Bootroot-compatible mTLS inputs.
#
# Usage:
#   ./start-validation.sh [--generate] [--background]
#
# Options:
#   --generate    Run generate-fixtures.sh first if fixtures are missing
#   --background  Run Giganto in the background (writes PID to .giganto.pid)
#
# Environment variable overrides (for real Bootroot-issued certs):
#   REAL_BOOTROOT_LEAF_PEM    — Path to real leaf certificate
#   REAL_BOOTROOT_KEY_PEM     — Path to real private key
#   REAL_BOOTROOT_CA_BUNDLE   — Path to real CA bundle
#
# When REAL_BOOTROOT_* variables are set, they take precedence over
# the locally generated fixtures.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURES_DIR="${SCRIPT_DIR}/checked-fixtures"
GENERATE=false
BACKGROUND=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --generate)
      GENERATE=true
      shift
      ;;
    --background)
      BACKGROUND=true
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# --- Resolve certificate paths ---
CERT_PATH="${REAL_BOOTROOT_LEAF_PEM:-${FIXTURES_DIR}/leaf.pem}"
KEY_PATH="${REAL_BOOTROOT_KEY_PEM:-${FIXTURES_DIR}/leaf.key}"
CA_BUNDLE_PATH="${REAL_BOOTROOT_CA_BUNDLE:-${FIXTURES_DIR}/ca-bundle.pem}"

# Check if fixtures exist; generate if requested
if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ] || [ ! -f "$CA_BUNDLE_PATH" ]; then
  if [ "$GENERATE" = true ]; then
    echo "Fixtures not found. Generating..."
    bash "${SCRIPT_DIR}/generate-fixtures.sh"
  else
    echo "ERROR: Certificate fixtures not found." >&2
    echo "Run with --generate or execute generate-fixtures.sh first." >&2
    echo "" >&2
    echo "Expected files:" >&2
    echo "  ${CERT_PATH}" >&2
    echo "  ${KEY_PATH}" >&2
    echo "  ${CA_BUNDLE_PATH}" >&2
    exit 1
  fi
fi

# --- Determine data-store binary ---
GIGANTO_BIN="${GIGANTO_BIN:-}"
if [ -z "$GIGANTO_BIN" ]; then
  # Try cargo build output, then PATH
  CARGO_BIN="${SCRIPT_DIR}/../../target/release/giganto"
  CARGO_BIN_DEBUG="${SCRIPT_DIR}/../../target/debug/giganto"
  if [ -x "$CARGO_BIN" ]; then
    GIGANTO_BIN="$CARGO_BIN"
  elif [ -x "$CARGO_BIN_DEBUG" ]; then
    GIGANTO_BIN="$CARGO_BIN_DEBUG"
  elif command -v giganto &>/dev/null; then
    GIGANTO_BIN="$(command -v giganto)"
  else
    echo "ERROR: giganto binary not found." >&2
    echo "Build with 'cargo build --release' or set GIGANTO_BIN." >&2
    exit 1
  fi
fi

# --- Prepare data directory ---
DATA_DIR="${GIGANTO_DATA_DIR:-/tmp/giganto-validation-data}"
EXPORT_DIR="${GIGANTO_EXPORT_DIR:-/tmp/giganto-validation-export}"
mkdir -p "$DATA_DIR" "$EXPORT_DIR"

# --- Create minimal validation config ---
CONFIG_FILE="${SCRIPT_DIR}/validation-config.toml"
GRAPHQL_ADDR="${GRAPHQL_SRV_ADDR:-[::]:8443}"

cat > "$CONFIG_FILE" <<EOF
graphql_srv_addr = "${GRAPHQL_ADDR}"
data_dir = "${DATA_DIR}"
export_dir = "${EXPORT_DIR}"
EOF

echo "=== Bootroot mTLS Validation Server ==="
echo "Binary:     ${GIGANTO_BIN}"
echo "Config:     ${CONFIG_FILE}"
echo "Cert:       ${CERT_PATH}"
echo "Key:        ${KEY_PATH}"
echo "CA bundle:  ${CA_BUNDLE_PATH}"
echo "Data dir:   ${DATA_DIR}"
echo "GraphQL:    https://localhost:8443"
echo ""

# --- Determine how to pass CA certs ---
# Giganto accepts --ca-certs which can take comma-separated paths or
# a single file containing multiple PEM certificates (the CA bundle).
CA_CERTS_ARG="${CA_BUNDLE_PATH}"

CMD=(
  "$GIGANTO_BIN"
  -c "$CONFIG_FILE"
  --cert "$CERT_PATH"
  --key "$KEY_PATH"
  --ca-certs "$CA_CERTS_ARG"
)

if [ "$BACKGROUND" = true ]; then
  echo "Starting in background..."
  "${CMD[@]}" &
  PID=$!
  echo "$PID" > "${SCRIPT_DIR}/.giganto.pid"
  echo "PID: ${PID} (saved to .giganto.pid)"
  echo "Stop with: kill \$(cat ${SCRIPT_DIR}/.giganto.pid)"
else
  echo "Starting Giganto (Ctrl+C to stop)..."
  exec "${CMD[@]}"
fi
