#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATION_DIR="${BOOTROOT_VALIDATION_DIR:-/tmp/giganto-bootroot-mtls}"
CONFIG_TEMPLATE_PATH="${ROOT_DIR}/scripts/bootroot-mtls-validation.config.toml.in"
CONFIG_PATH="${VALIDATION_DIR}/config.toml"
DATA_DIR="${VALIDATION_DIR}/data"
EXPORT_DIR="${VALIDATION_DIR}/export"
LOG_DIR="${VALIDATION_DIR}/logs"
CERT_DIR="${VALIDATION_DIR}/certs"
LOG_PATH="${LOG_DIR}/giganto.log"
SMOKE_TIMEOUT_SECS="${BOOTROOT_SMOKE_TIMEOUT_SECS:-60}"

GRAPHQL_ADDR="${BOOTROOT_GIGANTO_GRAPHQL_ADDR:-127.0.0.1:18443}"
INGEST_ADDR="${BOOTROOT_GIGANTO_INGEST_ADDR:-127.0.0.1:18370}"
PUBLISH_ADDR="${BOOTROOT_GIGANTO_PUBLISH_ADDR:-127.0.0.1:18371}"

CA_KEY="${BOOTROOT_GIGANTO_CA_KEY:-${CERT_DIR}/ca.key.pem}"
ROOT_CA_CERT="${BOOTROOT_GIGANTO_ROOT_CA_CERT:-${CERT_DIR}/ca.root.pem}"
EXTRA_CA_KEY="${BOOTROOT_GIGANTO_EXTRA_CA_KEY:-${CERT_DIR}/ca.extra.key.pem}"
EXTRA_CA_CERT="${BOOTROOT_GIGANTO_EXTRA_CA_CERT:-${CERT_DIR}/ca.extra.pem}"
SERVER_CERT="${BOOTROOT_GIGANTO_SERVER_CERT:-${CERT_DIR}/server.cert.pem}"
SERVER_KEY="${BOOTROOT_GIGANTO_SERVER_KEY:-${CERT_DIR}/server.key.pem}"
CLIENT_CERT="${BOOTROOT_GIGANTO_CLIENT_CERT:-${CERT_DIR}/client.cert.pem}"
CLIENT_KEY="${BOOTROOT_GIGANTO_CLIENT_KEY:-${CERT_DIR}/client.key.pem}"
CA_CERTS="${BOOTROOT_GIGANTO_CA_CERTS:-${CERT_DIR}/ca.cert.pem}"

usage() {
    cat <<'EOF'
Usage:
  ./scripts/bootroot-mtls-validation.sh prepare
  ./scripts/bootroot-mtls-validation.sh run-server
  ./scripts/bootroot-mtls-validation.sh query-config
  ./scripts/bootroot-mtls-validation.sh prepare-real
  ./scripts/bootroot-mtls-validation.sh run-server-real
  ./scripts/bootroot-mtls-validation.sh query-config-real
  ./scripts/bootroot-mtls-validation.sh smoke-real
  ./scripts/bootroot-mtls-validation.sh print-env
EOF
}

require_file() {
    local path="$1"
    if [[ ! -f "${path}" ]]; then
        echo "required file not found: ${path}" >&2
        exit 1
    fi
}

require_command() {
    local command="$1"
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "required command not found: ${command}" >&2
        exit 1
    fi
}

generate_local_certs() {
    local server_csr="${CERT_DIR}/server.csr.pem"
    local client_csr="${CERT_DIR}/client.csr.pem"
    local server_ext="${CERT_DIR}/server.ext"
    local client_ext="${CERT_DIR}/client.ext"

    mkdir -p "${CERT_DIR}"

    if [[ -f "${ROOT_CA_CERT}" && -f "${EXTRA_CA_CERT}" && -f "${CA_KEY}" && -f "${EXTRA_CA_KEY}" && -f "${SERVER_CERT}" && -f "${SERVER_KEY}" && -f "${CLIENT_CERT}" && -f "${CLIENT_KEY}" && -f "${CA_CERTS}" ]]; then
        return
    fi

    require_command openssl

    cat > "${server_ext}" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:validation.data-store.localhost.bootroot.test
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

    cat > "${client_ext}" <<'EOF'
subjectAltName=DNS:validation.sensor.localhost.bootroot.test
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

    openssl genrsa -out "${CA_KEY}" 2048 >/dev/null 2>&1
    openssl req \
        -x509 \
        -new \
        -nodes \
        -key "${CA_KEY}" \
        -sha256 \
        -days 3650 \
        -subj "/CN=giganto-bootroot-validation-ca" \
        -out "${ROOT_CA_CERT}" >/dev/null 2>&1

    openssl genrsa -out "${EXTRA_CA_KEY}" 2048 >/dev/null 2>&1
    openssl req \
        -x509 \
        -new \
        -nodes \
        -key "${EXTRA_CA_KEY}" \
        -sha256 \
        -days 3650 \
        -subj "/CN=giganto-bootroot-validation-extra-ca" \
        -out "${EXTRA_CA_CERT}" >/dev/null 2>&1

    openssl genrsa -out "${SERVER_KEY}" 2048 >/dev/null 2>&1
    openssl req \
        -new \
        -key "${SERVER_KEY}" \
        -subj "/CN=validation.data-store.localhost.bootroot.test" \
        -out "${server_csr}" >/dev/null 2>&1
    openssl x509 \
        -req \
        -in "${server_csr}" \
        -CA "${EXTRA_CA_CERT}" \
        -CAkey "${EXTRA_CA_KEY}" \
        -CAcreateserial \
        -out "${SERVER_CERT}" \
        -days 3650 \
        -sha256 \
        -extfile "${server_ext}" >/dev/null 2>&1

    openssl genrsa -out "${CLIENT_KEY}" 2048 >/dev/null 2>&1
    openssl req \
        -new \
        -key "${CLIENT_KEY}" \
        -subj "/CN=validation.sensor.localhost.bootroot.test" \
        -out "${client_csr}" >/dev/null 2>&1
    openssl x509 \
        -req \
        -in "${client_csr}" \
        -CA "${EXTRA_CA_CERT}" \
        -CAkey "${EXTRA_CA_KEY}" \
        -CAcreateserial \
        -out "${CLIENT_CERT}" \
        -days 3650 \
        -sha256 \
        -extfile "${client_ext}" >/dev/null 2>&1

    cat "${ROOT_CA_CERT}" "${EXTRA_CA_CERT}" > "${CA_CERTS}"

    rm -f \
        "${server_csr}" \
        "${client_csr}" \
        "${server_ext}" \
        "${client_ext}" \
        "${CERT_DIR}/ca.root.srl"
}

prepare_common() {
    require_file "${SERVER_CERT}"
    require_file "${SERVER_KEY}"
    require_file "${CLIENT_CERT}"
    require_file "${CLIENT_KEY}"
    require_file "${CA_CERTS}"
    require_file "${CONFIG_TEMPLATE_PATH}"

    mkdir -p "${DATA_DIR}" "${EXPORT_DIR}" "${LOG_DIR}"

    sed \
        -e "s|__INGEST_ADDR__|${INGEST_ADDR}|g" \
        -e "s|__PUBLISH_ADDR__|${PUBLISH_ADDR}|g" \
        -e "s|__GRAPHQL_ADDR__|${GRAPHQL_ADDR}|g" \
        -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__LOG_PATH__|${LOG_PATH}|g" \
        -e "s|__EXPORT_DIR__|${EXPORT_DIR}|g" \
        "${CONFIG_TEMPLATE_PATH}" > "${CONFIG_PATH}"

    echo "prepared Bootroot mTLS validation environment"
    echo "config: ${CONFIG_PATH}"
    echo "graphql: https://${GRAPHQL_ADDR}/graphql"
    echo "server cert: ${SERVER_CERT}"
    echo "client cert: ${CLIENT_CERT}"
    echo "ca bundle: ${CA_CERTS}"
}

prepare() {
    generate_local_certs
    prepare_common
}

prepare_real() {
    prepare_common
}

run_server_common() {
    exec cargo run -- \
        -c "${CONFIG_PATH}" \
        --cert "${SERVER_CERT}" \
        --key "${SERVER_KEY}" \
        --ca-certs "${CA_CERTS}"
}

run_server() {
    prepare
    run_server_common
}

run_server_real() {
    prepare_real
    run_server_common
}

query_config_common() {
    curl \
        --silent \
        --show-error \
        --fail \
        --cert "${CLIENT_CERT}" \
        --key "${CLIENT_KEY}" \
        --cacert "${CA_CERTS}" \
        --header 'content-type: application/json' \
        --data '{"query":"{ ping config { graphqlSrvAddr ingestSrvAddr publishSrvAddr } }"}' \
        "https://${GRAPHQL_ADDR}/graphql"
    echo
}

query_config() {
    prepare >/dev/null
    query_config_common
}

query_config_real() {
    prepare_real >/dev/null
    query_config_common
}

stop_server() {
    local pid="$1"

    if kill -0 "${pid}" >/dev/null 2>&1; then
        kill "${pid}" >/dev/null 2>&1 || true
        wait "${pid}" >/dev/null 2>&1 || true
    fi
}

smoke_real() {
    local attempt
    local max_attempts=$((SMOKE_TIMEOUT_SECS * 2))
    local server_pid
    local response

    prepare_real

    cargo run -- \
        -c "${CONFIG_PATH}" \
        --cert "${SERVER_CERT}" \
        --key "${SERVER_KEY}" \
        --ca-certs "${CA_CERTS}" \
        >"${LOG_PATH}" 2>&1 &
    server_pid=$!

    trap 'stop_server "${server_pid}"' EXIT

    for ((attempt = 1; attempt <= max_attempts; attempt += 1)); do
        if response="$(query_config_common 2>&1)"; then
            echo "real Bootroot input smoke check succeeded"
            echo "log: ${LOG_PATH}"
            echo "${response}"
            trap - EXIT
            stop_server "${server_pid}"
            return 0
        fi
        sleep 0.5
    done

    echo "real Bootroot input smoke check failed after ${SMOKE_TIMEOUT_SECS}s" >&2
    echo "log: ${LOG_PATH}" >&2
    if [[ -f "${LOG_PATH}" ]]; then
        tail -n 40 "${LOG_PATH}" >&2 || true
    fi
    trap - EXIT
    stop_server "${server_pid}"
    return 1
}

print_env() {
    cat <<EOF
ROOT_DIR=${ROOT_DIR}
VALIDATION_DIR=${VALIDATION_DIR}
CONFIG_PATH=${CONFIG_PATH}
GRAPHQL_ADDR=${GRAPHQL_ADDR}
INGEST_ADDR=${INGEST_ADDR}
PUBLISH_ADDR=${PUBLISH_ADDR}
CA_KEY=${CA_KEY}
ROOT_CA_CERT=${ROOT_CA_CERT}
EXTRA_CA_KEY=${EXTRA_CA_KEY}
EXTRA_CA_CERT=${EXTRA_CA_CERT}
SERVER_CERT=${SERVER_CERT}
SERVER_KEY=${SERVER_KEY}
CLIENT_CERT=${CLIENT_CERT}
CLIENT_KEY=${CLIENT_KEY}
CA_CERTS=${CA_CERTS}
SMOKE_TIMEOUT_SECS=${SMOKE_TIMEOUT_SECS}
EOF
}

main() {
    local command="${1:-}"
    case "${command}" in
        prepare)
            prepare
            ;;
        run-server)
            run_server
            ;;
        query-config)
            query_config
            ;;
        prepare-real)
            prepare_real
            ;;
        run-server-real)
            run_server_real
            ;;
        query-config-real)
            query_config_real
            ;;
        smoke-real)
            smoke_real
            ;;
        print-env)
            print_env
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
