#!/usr/bin/env python3
"""
Count connRawEvents whose source IP falls in a given range by paging through the GraphQL API.

Requirements: Python 3 (stdlib only: urllib, ssl, json).

Usage:
  python3 scripts/count_conn_by_orig_range.py --sensor SENSOR --orig-start START_IP --orig-end END_IP [TLS options]

TLS options (optional):
  --cacert /path/ca.pem         CA bundle for server verification
  --cert /path/client_cert.pem  Client certificate (optionally with key)
  --key /path/client_key.pem    Client private key (if not in cert)
  --insecure                    Disable TLS verification (not recommended)
"""

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

GRAPHQL_URL = "https://127.0.0.1:8443/graphql"
PAGE_SIZE = 100  # Server-side maximum enforced by get_connection (src/graphql.rs).

GQL_QUERY = """
query ConnRawEvents($filter: NetworkFilter!, $first: Int, $after: String) {
  connRawEvents(filter: $filter, first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges { node { origAddr } }
  }
}
"""


def build_ssl_context(args: argparse.Namespace) -> ssl.SSLContext:
    if args.insecure:
        ctx = ssl._create_unverified_context()
    else:
        ctx = ssl.create_default_context(cafile=args.cacert)
    if args.cert or args.key:
        ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    return ctx


def fetch_page(ctx: ssl.SSLContext, sensor: str, orig_start: str, orig_end: str, after: str | None) -> tuple[int, str | None, bool]:
    payload = {
        "query": GQL_QUERY,
        "variables": {
            "filter": {
                "sensor": sensor,
                "origAddr": {"start": orig_start, "end": orig_end},
            },
            "first": PAGE_SIZE,
            "after": after,
        },
    }
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    req = urllib.request.Request(
        GRAPHQL_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            body = resp.read()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"HTTP request failed: {exc}") from exc

    try:
        decoded = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse JSON response: {exc}") from exc

    if decoded.get("errors"):
        raise RuntimeError(f"GraphQL errors: {decoded['errors']}")

    conn = (decoded.get("data") or {}).get("connRawEvents") or {}
    edges = conn.get("edges") or []
    page_info = conn.get("pageInfo") or {}
    has_next = bool(page_info.get("hasNextPage"))
    end_cursor = page_info.get("endCursor")

    return len(edges), end_cursor, has_next


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Count connRawEvents by source IP range.")
    parser.add_argument("--sensor", required=True, help="Sensor name (NetworkFilter.sensor)")
    parser.add_argument(
        "--orig-start",
        required=True,
        help="출발지 IP - start (inclusive)",
    )
    parser.add_argument(
        "--orig-end",
        required=True,
        help="출발지 IP - end (exclusive)",
    )
    parser.add_argument("--cacert", help="CA bundle for TLS verification")
    parser.add_argument("--cert", help="Client certificate (optionally with key)")
    parser.add_argument("--key", help="Client private key (if not bundled with cert)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ctx = build_ssl_context(args)

    total = 0
    after: str | None = None

    while True:
        count, after, has_next = fetch_page(ctx, args.sensor, args.orig_start, args.orig_end, after)
        total += count
        if not has_next or not after:
            break

    print(total)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
