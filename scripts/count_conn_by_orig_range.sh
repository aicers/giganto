#!/usr/bin/env bash

# Count connRawEvents whose source IP falls in a given range by paging through the GraphQL API.
# Requirements: bash, curl, jq.
# Usage:
#   scripts/count_conn_by_orig_range.sh <GRAPHQL_URL> <SENSOR> <ORIG_START_IP> <ORIG_END_IP> [PAGE_SIZE]
# Example:
#   scripts/count_conn_by_orig_range.sh https://127.0.0.1:8443/graphql ingest_sensor_1 192.168.4.0 192.168.4.255 500 \
#     --cert /path/cert.pem --key /path/key.pem --cacert /path/ca.pem
#
# Extra curl options can be passed after the positional arguments (e.g., TLS certs).

set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "usage: $0 <GRAPHQL_URL> <SENSOR> <ORIG_START_IP> <ORIG_END_IP> [PAGE_SIZE] [-- curl opts]" >&2
  exit 1
fi

GRAPHQL_URL=$1
SENSOR=$2
ORIG_START=$3
ORIG_END=$4

shift 4
PAGE_SIZE=500
if [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; then
  PAGE_SIZE=$1
  shift
fi

EXTRA_CURL_ARGS=("$@")

# GraphQL query body reused on every page.
read -r -d '' GQL_QUERY <<'EOF' || true
query ConnRawEvents($filter: NetworkFilter!, $first: Int, $after: String) {
  connRawEvents(filter: $filter, first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges { node { origAddr } }
  }
}
EOF

total=0
after_json=null

while :; do
  # Compose request payload with the current cursor.
  payload=$(jq -n \
    --argjson first "$PAGE_SIZE" \
    --argjson after "$after_json" \
    --arg sensor "$SENSOR" \
    --arg orig_start "$ORIG_START" \
    --arg orig_end "$ORIG_END" \
    --arg query "$GQL_QUERY" \
    '{
      query: $query,
      variables: {
        filter: {
          sensor: $sensor,
          origAddr: { start: $orig_start, end: $orig_end }
        },
        first: $first,
        after: $after
      }
    }')

  response=$(curl -sS -X POST "$GRAPHQL_URL" \
    -H 'Content-Type: application/json' \
    -d "$payload" \
    "${EXTRA_CURL_ARGS[@]}")

  # Fail fast on GraphQL errors.
  if [[ $(echo "$response" | jq '.errors // empty | length') -gt 0 ]]; then
    echo "GraphQL errors:" >&2
    echo "$response" | jq '.errors' >&2
    exit 1
  fi

  page_count=$(echo "$response" | jq '.data.connRawEvents.edges | length')
  total=$(( total + page_count ))

  has_next=$(echo "$response" | jq '.data.connRawEvents.pageInfo.hasNextPage')
  if [[ "$has_next" != "true" ]]; then
    break
  fi

  next_cursor=$(echo "$response" | jq -r '.data.connRawEvents.pageInfo.endCursor')
  if [[ "$next_cursor" == "null" || -z "$next_cursor" ]]; then
    break
  fi

  after_json=$(jq -Rn --arg c "$next_cursor" '$c')
done

echo "$total"
