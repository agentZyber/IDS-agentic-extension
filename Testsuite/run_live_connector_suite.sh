#!/bin/bash
#
# Deploy the IDS testbed, ensure both connectors are broker-registered, and run
# the live connector testsuite with a connector A port fallback when needed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

CONNECTORA_HOST_PORT="${CONNECTORA_HOST_PORT:-8080}"
CONNECTORA_FALLBACK_PORT="${CONNECTORA_FALLBACK_PORT:-28080}"
CONNECTORA_CONTAINER_NAME="${CONNECTORA_CONTAINER_NAME:-connectora-live}"
BROKER_RECIPIENT="${BROKER_RECIPIENT:-https://broker-reverseproxy/infrastructure}"
BROKER_CATALOG_ID="${BROKER_CATALOG_ID:-https://broker-reverseproxy/connectors/}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-testbed}"
COMPOSE_NETWORK="${COMPOSE_NETWORK:-${COMPOSE_PROJECT_NAME}_local}"
RESULT_DIR="${RESULT_DIR:-/tmp/ids-test-results}"
RESULT_FILE="${RESULT_FILE:-${RESULT_DIR}/connector-suite-$(date +'%Y-%m-%d_%H-%M-%S').json}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-password}"
CONNECTORA_URL=""

DAPS_USERS_BACKUP="$(mktemp)"
cp "DAPS/config/users.yml" "$DAPS_USERS_BACKUP"

cleanup() {
    cp "$DAPS_USERS_BACKUP" "DAPS/config/users.yml"
    rm -f "$DAPS_USERS_BACKUP"
}

trap cleanup EXIT

log() {
    printf '[live-suite] %s\n' "$*"
}

fail() {
    printf '[live-suite] %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

port_in_use() {
    local port="$1"
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
}

wait_for_public_status() {
    local url="$1"
    local expected_status="$2"
    local attempts="${3:-60}"
    local sleep_seconds="${4:-2}"
    local code

    for ((i = 1; i <= attempts; i++)); do
        code="$(curl -ksS -o /dev/null -w '%{http_code}' "$url" || true)"
        if [ "$code" = "$expected_status" ]; then
            return 0
        fi
        sleep "$sleep_seconds"
    done

    fail "Timed out waiting for $url to return HTTP $expected_status"
}

current_manual_connectora_port() {
    docker port "$CONNECTORA_CONTAINER_NAME" 8080/tcp | head -n 1 | awk -F: '{print $NF}'
}

start_compose_services() {
    log "Starting core IDS services with docker compose"
    docker compose up -d omejdn omejdn-server omejdn-ui postgresa postgresb connectorb broker-reverseproxy broker-core broker-fuseki
    wait_for_public_status "https://localhost/auth/jwks.json" "200"
    wait_for_public_status "https://localhost:444/infrastructure" "405"
    wait_for_public_status "https://localhost:8081/actuator/health" "401"
}

start_connectora_compose() {
    log "Starting connector A via docker compose on host port 8080"
    docker compose up -d connectora
    CONNECTORA_URL="https://localhost:8080"
}

start_connectora_manual() {
    local host_port="$1"

    log "Starting connector A manually on host port ${host_port}"
    docker rm -f connectora >/dev/null 2>&1 || true
    docker rm -f "$CONNECTORA_CONTAINER_NAME" >/dev/null 2>&1 || true

    docker run -d \
        --name "$CONNECTORA_CONTAINER_NAME" \
        --network "$COMPOSE_NETWORK" \
        --network-alias connectora \
        -p "${host_port}:8080" \
        -e CONFIGURATION_PATH=/config/config.json \
        -e DAPS_URL=https://omejdn \
        -e DAPS_TOKEN_URL=https://omejdn/auth/token \
        -e DAPS_KEY_URL=https://omejdn/auth/jwks.json \
        -e DAPS_INCOMING_DAT_DEFAULT_WELLKNOWN=/jwks.json \
        -e SERVER_SSL_KEY-STORE=file:///conf/connectorA.p12 \
        -e SPRING_DATASOURCE_URL=jdbc:postgresql://postgresa:5432/connectoradb \
        -e SPRING_DATASOURCE_PLATFORM=postgres \
        -e SPRING_DATASOURCE_DRIVERCLASSNAME=org.postgresql.Driver \
        -e SPRING_DATASOURCE_USERNAME=postgresusera \
        -e SPRING_DATASOURCE_PASSWORD=password \
        -e SPRING_JPA_DATABASE_PLATFORM=org.hibernate.dialect.PostgreSQLDialect \
        -e HTTP_TIMEOUT_CONNECT=20000 \
        -e HTTP_TIMEOUT_READ=20000 \
        -e HTTP_TIMEOUT_WRITE=20000 \
        -e HTTP_TIMEOUT_CALL=20000 \
        -v "$REPO_ROOT/DataspaceConnectorA/conf/config.json:/config/config.json" \
        -v "$REPO_ROOT/DataspaceConnectorA/conf/connectorA.p12:/conf/connectorA.p12" \
        -v "$REPO_ROOT/DataspaceConnectorA/conf/truststore.p12:/config/truststore.p12" \
        idstestbed/dataspace-connector:8.0.2 >/dev/null

    CONNECTORA_URL="https://localhost:${host_port}"
}

ensure_connectora() {
    local desired_port="$CONNECTORA_HOST_PORT"

    if docker ps --format '{{.Names}}' | grep -qx 'connectora'; then
        CONNECTORA_URL="https://localhost:8080"
        log "Reusing existing compose-managed connector A on host port 8080"
        return
    fi

    if docker ps --format '{{.Names}}' | grep -qx "$CONNECTORA_CONTAINER_NAME"; then
        desired_port="$(current_manual_connectora_port)"
        CONNECTORA_URL="https://localhost:${desired_port}"
        log "Reusing existing manual connector A on host port ${desired_port}"
        return
    fi

    if [ "$desired_port" = "8080" ] && ! port_in_use 8080; then
        start_connectora_compose
    else
        if [ "$desired_port" = "8080" ]; then
            desired_port="$CONNECTORA_FALLBACK_PORT"
        fi
        port_in_use "$desired_port" && fail "Host port ${desired_port} is already in use"
        start_connectora_manual "$desired_port"
    fi
}

register_connector() {
    local connector_url="$1"
    local config_path="$2"

    curl -ksS -u "${ADMIN_USERNAME}:${ADMIN_PASSWORD}" \
        -X POST \
        "${connector_url}/api/ids/connector/update?recipient=${BROKER_RECIPIENT}" \
        -H 'Content-Type: application/json' \
        --data @"$config_path" >/dev/null
}

wait_for_broker_catalog() {
    local payload_file
    payload_file="$(mktemp)"

    for ((i = 1; i <= 30; i++)); do
        curl -ksS -u "${ADMIN_USERNAME}:${ADMIN_PASSWORD}" \
            -X POST \
            "https://localhost:8081/api/ids/description?recipient=${BROKER_RECIPIENT}&elementId=${BROKER_CATALOG_ID}" \
            -o "$payload_file"

        if python3 - "$payload_file" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
connectors = [
    item.get("sameAs")
    for item in payload.get("@graph", [])
    if isinstance(item, dict) and item.get("@type") == "ids:BaseConnector"
]
required = {"https://connector_A", "https://connector_B"}
if required.issubset(set(connectors)):
    print("Broker catalog connectors:", ", ".join(sorted(connectors)))
    raise SystemExit(0)
raise SystemExit(1)
PY
        then
            rm -f "$payload_file"
            return 0
        fi

        sleep 2
    done

    rm -f "$payload_file"
    fail "Broker catalog did not expose both connector_A and connector_B in time"
}

run_newman_suite() {
    local newman_args=(
        run "Testsuite/Testsuite.postman_collection.json"
        --folder Connector
        -e "Testsuite/env/Applicant_IDS_Connector_Test_Configuration.postman_environment.json"
        --insecure
        --reporters cli,json
        --reporter-json-export "$RESULT_FILE"
    )

    mkdir -p "$RESULT_DIR"

    if [ "$CONNECTORA_URL" != "https://localhost:8080" ]; then
        newman_args+=(--env-var "CONNECTORA_URL=${CONNECTORA_URL}")
    fi

    log "Running Newman connector suite against connector A at ${CONNECTORA_URL}"
    newman "${newman_args[@]}"
    log "JSON report written to ${RESULT_FILE}"
}

main() {
    require_command curl
    require_command docker
    require_command lsof
    require_command newman
    require_command python3

    start_compose_services
    ensure_connectora
    wait_for_public_status "${CONNECTORA_URL}/actuator/health" "401"

    log "Registering connector A and connector B with the broker"
    register_connector "$CONNECTORA_URL" "DataspaceConnectorA/conf/config.json"
    register_connector "https://localhost:8081" "DataspaceConnectorB/conf/config.json"
    wait_for_broker_catalog

    run_newman_suite
}

main "$@"
