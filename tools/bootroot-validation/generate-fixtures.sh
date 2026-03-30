#!/usr/bin/env bash
# generate-fixtures.sh — Generate a canonical Bootroot-shaped certificate
# chain for mTLS validation: root CA -> intermediate CA -> leaf cert.
#
# Usage:
#   ./generate-fixtures.sh [--clean] [--output-dir DIR]
#
# Options:
#   --clean       Remove previously generated fixtures before generating
#   --output-dir  Directory for generated files (default: checked-fixtures/)
#
# The script is idempotent: re-running overwrites existing fixtures.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/checked-fixtures"
CLEAN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean)
      CLEAN=true
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

GENERATED_FILES=(
  root.key root.pem
  intermediate.key intermediate.pem
  leaf.key leaf.pem
  ca-bundle.pem
)

if [ "$CLEAN" = true ]; then
  echo "Cleaning generated fixtures in ${OUTPUT_DIR}..."
  for f in "${GENERATED_FILES[@]}"; do
    rm -f "${OUTPUT_DIR}/${f}"
  done
  echo "Clean complete."
  exit 0
fi

mkdir -p "$OUTPUT_DIR"

DAYS_VALID=30
KEY_BITS=2048

echo "=== Generating Bootroot-shaped certificate chain ==="
echo "Output directory: ${OUTPUT_DIR}"
echo "Validity: ${DAYS_VALID} days"
echo ""

# --- Root CA ---
echo "[1/3] Generating Root CA..."
openssl req -x509 -newkey "rsa:${KEY_BITS}" \
  -keyout "${OUTPUT_DIR}/root.key" \
  -out "${OUTPUT_DIR}/root.pem" \
  -days "$DAYS_VALID" \
  -nodes \
  -subj "/CN=Bootroot Test Root CA/O=aicers/OU=giganto-test" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  2>/dev/null

echo "  Root CA:  ${OUTPUT_DIR}/root.pem"

# --- Intermediate CA ---
echo "[2/3] Generating Intermediate CA..."
openssl req -newkey "rsa:${KEY_BITS}" \
  -keyout "${OUTPUT_DIR}/intermediate.key" \
  -out "${OUTPUT_DIR}/intermediate.csr" \
  -nodes \
  -subj "/CN=Bootroot Test Intermediate CA/O=aicers/OU=giganto-test" \
  2>/dev/null

openssl x509 -req \
  -in "${OUTPUT_DIR}/intermediate.csr" \
  -CA "${OUTPUT_DIR}/root.pem" \
  -CAkey "${OUTPUT_DIR}/root.key" \
  -CAcreateserial \
  -out "${OUTPUT_DIR}/intermediate.pem" \
  -days "$DAYS_VALID" \
  -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign") \
  2>/dev/null

rm -f "${OUTPUT_DIR}/intermediate.csr" "${OUTPUT_DIR}/root.srl"
echo "  Intermediate CA:  ${OUTPUT_DIR}/intermediate.pem"

# --- Leaf Certificate ---
echo "[3/3] Generating Leaf certificate..."
openssl req -newkey "rsa:${KEY_BITS}" \
  -keyout "${OUTPUT_DIR}/leaf.key" \
  -out "${OUTPUT_DIR}/leaf.csr" \
  -nodes \
  -subj "/CN=localhost/O=aicers/OU=giganto-test" \
  2>/dev/null

openssl x509 -req \
  -in "${OUTPUT_DIR}/leaf.csr" \
  -CA "${OUTPUT_DIR}/intermediate.pem" \
  -CAkey "${OUTPUT_DIR}/intermediate.key" \
  -CAcreateserial \
  -out "${OUTPUT_DIR}/leaf.pem" \
  -days "$DAYS_VALID" \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1") \
  2>/dev/null

rm -f "${OUTPUT_DIR}/leaf.csr" "${OUTPUT_DIR}/intermediate.srl"
echo "  Leaf cert:  ${OUTPUT_DIR}/leaf.pem"

# --- CA Bundle (intermediate + root, order matters) ---
echo ""
echo "Assembling CA bundle (intermediate + root)..."
cat "${OUTPUT_DIR}/intermediate.pem" "${OUTPUT_DIR}/root.pem" \
  > "${OUTPUT_DIR}/ca-bundle.pem"
echo "  CA bundle:  ${OUTPUT_DIR}/ca-bundle.pem"

# --- Verification ---
echo ""
echo "=== Verifying chain ==="
if openssl verify \
  -CAfile "${OUTPUT_DIR}/root.pem" \
  -untrusted "${OUTPUT_DIR}/intermediate.pem" \
  "${OUTPUT_DIR}/leaf.pem" 2>/dev/null; then
  echo "Chain verification: OK"
else
  echo "ERROR: Chain verification failed!" >&2
  exit 1
fi

echo ""
echo "=== Summary ==="
echo "  root.pem          — Root CA certificate"
echo "  root.key          — Root CA private key"
echo "  intermediate.pem  — Intermediate CA certificate"
echo "  intermediate.key  — Intermediate CA private key"
echo "  leaf.pem          — Leaf/server certificate (CN=localhost)"
echo "  leaf.key          — Leaf/server private key"
echo "  ca-bundle.pem     — CA bundle (intermediate + root)"
echo ""
echo "These are SHORT-LIVED TEST-ONLY certificates."
echo "Do NOT use them in production."
