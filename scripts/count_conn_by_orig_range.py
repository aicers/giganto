#!/usr/bin/env python3
"""
Count connRawEvents whose source IP falls in a given range by paging through the GraphQL API.

Requirements: Python 3 (stdlib only: urllib, ssl, json).

Usage:
  python3 scripts/count_conn_by_orig_range.py --sensor SENSOR --orig-start START_IP --orig-end END_IP \
    --checkpoint /path/file [--time-start RFC3339] [--time-end RFC3339] [--max-requests N] [TLS options]

Required arguments:
  --sensor SENSOR              Sensor 이름 (NetworkFilter.sensor)
  --orig-start START_IP        출발지 IP - start (inclusive)
  --orig-end END_IP            출발지 IP - end (exclusive)
  --checkpoint /path/file      Cursor checkpoint 파일

Optional arguments:
  --time-start RFC3339         Start time (inclusive)
  --time-end RFC3339           End time (exclusive)
  --max-requests N             Stop after N requests/pages (for testing or chunked runs)

TLS options:
  --cacert /path/ca.pem         CA bundle for server verification
  --cert /path/client_cert.pem  Client certificate (optionally with key)
  --key /path/client_key.pem    Client private key (if not in cert)
  --insecure                    Disable TLS verification (not recommended)
"""

import argparse
import json
import os
import pathlib
import ssl
import sys
import tempfile
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


def build_opener(ctx: ssl.SSLContext) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def fetch_page(
    opener: urllib.request.OpenerDirector,
    sensor: str,
    orig_start: str,
    orig_end: str,
    after: str | None,
    time_start: str | None,
    time_end: str | None,
) -> tuple[int, str | None, bool]:
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
    if time_start or time_end:
        payload["variables"]["filter"]["time"] = {
            "start": time_start,
            "end": time_end,
        }
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    req = urllib.request.Request(
        GRAPHQL_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with opener.open(req, timeout=30) as resp:
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
    parser = argparse.ArgumentParser(
        description="Count connRawEvents by source IP range.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 scripts/count_conn_by_orig_range.py \\\n"
            "    --sensor sensor \\\n"
            "    --orig-start 192.168.4.0 \\\n"
            "    --orig-end 192.168.4.255 \\\n"
            "    --time-start 2025-10-14T15:00:00Z \\\n"
            "    --time-end 2025-11-15T15:00:00Z \\\n"
            "    --checkpoint /tmp/conn_cursor.chk\n"
            "\n"
            "  # Limit to 10 requests/pages for a quick test\n"
            "  python3 scripts/count_conn_by_orig_range.py \\\n"
            "    --sensor sensor \\\n"
            "    --orig-start 192.168.4.0 \\\n"
            "    --orig-end 192.168.4.255 \\\n"
            "    --time-start 2025-10-14T15:00:00Z \\\n"
            "    --time-end 2025-11-15T15:00:00Z \\\n"
            "    --checkpoint /tmp/conn_cursor.chk \\\n"
            "    --max-requests 10\n"
        ),
    )
    parser.add_argument("--sensor", required=True, help="sensor 호스트네임")
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
    parser.add_argument("--time-start", help="시작 시각 (inclusive, RFC3339 예: 2025-10-14T15:00:00Z)")
    parser.add_argument("--time-end", help="종료 시각 (exclusive, RFC3339 예: 2025-11-15T15:00:00Z)")
    parser.add_argument(
        "--checkpoint",
        required=True,
        type=pathlib.Path,
        help="페이지 커서를 저장/재개할 파일 경로",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        help="N번 요청(페이지) 처리 후 종료 (테스트/분할 실행용)",
    )
    parser.add_argument("--cacert", help="CA bundle for TLS verification")
    parser.add_argument("--cert", help="Client certificate (optionally with key)")
    parser.add_argument("--key", help="Client private key (if not bundled with cert)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    return parser.parse_args()


def load_checkpoint(path: pathlib.Path) -> tuple[str | None, int]:
    try:
        data = json.loads(path.read_text())
        cursor = data.get("cursor")
        total = int(data.get("total", 0))
        return cursor, total
    except FileNotFoundError:
        return None, 0
    except Exception:
        return None, 0


def save_checkpoint(path: pathlib.Path, cursor: str | None, total: int) -> None:
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".tmp.")
    tmp = pathlib.Path(tmp_path)
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
        json.dump({"cursor": cursor, "total": total}, f)
    tmp.replace(path)


def main() -> int:
    args = parse_args()
    ctx = build_ssl_context(args)
    opener = build_opener(ctx)

    total = 0
    after: str | None = None
    after, total = load_checkpoint(args.checkpoint)

    requests = 0

    while True:
        count, after, has_next = fetch_page(
            opener,
            args.sensor,
            args.orig_start,
            args.orig_end,
            after,
            args.time_start,
            args.time_end,
        )
        total += count
        requests += 1

        args.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        save_checkpoint(args.checkpoint, after, total)

        if args.max_requests and requests >= args.max_requests:
            break

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
