#!/usr/bin/env python3
"""
Count connRawEvents with optional IP/port filters by paging through the GraphQL API.

Requirements: Python 3 (stdlib only: urllib, ssl, json).

Usage:
  python3 scripts/count_conn_events.py --graphql-url https://HOST:PORT/graphql --sensor SENSOR --checkpoint /path/file \
    [--orig-ip-start START_IP] [--orig-ip-end END_IP] \
    [--orig-port-start N] [--orig-port-end N] \
    [--resp-ip-start START_IP] [--resp-ip-end END_IP] \
    [--resp-port-start N] [--resp-port-end N] \
    [--time-start RFC3339(UTC)] [--time-end RFC3339(UTC)] [--max-requests N] [--no-filter]

Required arguments:
  --graphql-url URL            Giganto GraphQL 엔드포인트 (예: https://127.0.0.1:8443/graphql)
  --sensor SENSOR              Sensor 이름 (NetworkFilter.sensor)
  --checkpoint /path/file      Cursor checkpoint 파일

Optional arguments (IP/Port 필터는 하나 이상 지정 필요; `--no-filter`로 무시 가능):
  --orig-ip-start START_IP     출발지 IP - start (inclusive)
  --orig-ip-end END_IP         출발지 IP - end (exclusive)
  --orig-port-start N          출발지 포트 - start (inclusive)
  --orig-port-end N            출발지 포트 - end (exclusive)
  --resp-ip-start START_IP     도착지 IP - start (inclusive)
  --resp-ip-end END_IP         도착지 IP - end (exclusive)
  --resp-port-start N          도착지 포트 - start (inclusive)
  --resp-port-end N            도착지 포트 - end (exclusive)
  --time-start RFC3339(UTC)    Start time (inclusive, UTC)
  --time-end RFC3339(UTC)      End time (exclusive, UTC)
  --max-requests N             Stop after N requests/pages (for testing or chunked runs)
  --no-filter                  IP/Port 필터 없이 시간만 필터링하여 전체 카운트 (긴 러닝타임 및 리소스 소모 주의)
"""

import argparse
import json
import os
import pathlib
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

PAGE_SIZE = 100  # Server-side maximum enforced by get_connection (src/graphql.rs).
LOG_INTERVAL = 100  # Emit progress logs every N requests.
REQUEST_TIMEOUT = 30 * 60  # Seconds to wait for each HTTP response.
MAX_SLICE = timedelta(days=1)  # Split long time ranges into <=1 day slices.

GQL_QUERY = """
query ConnRawEvents($filter: NetworkFilter!, $first: Int, $after: String) {
  connRawEvents(filter: $filter, first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges { cursor }
  }
}
"""


def build_ssl_context() -> ssl.SSLContext:
    # Always run in insecure mode as per current requirements.
    return ssl._create_unverified_context()


def build_opener(ctx: ssl.SSLContext) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def fetch_page(
    opener: urllib.request.OpenerDirector,
    base_filter: dict,
    after: str | None,
    time_start: str | None,
    time_end: str | None,
    graphql_url: str,
) -> tuple[int, str | None, bool]:
    filt = dict(base_filter)
    if time_start or time_end:
        filt["time"] = {"start": time_start, "end": time_end}
    payload = {
        "query": GQL_QUERY,
        "variables": {
            "filter": filt,
            "first": PAGE_SIZE,
            "after": after,
        },
    }
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    req = urllib.request.Request(graphql_url, data=data, headers={"Content-Type": "application/json"}, method="POST")

    try:
        with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
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
        description="Count connRawEvents with optional IP/port filters.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Source IP+Port range over a time range\n"
            "  python3 scripts/count_conn_events.py \\\n"
            "    --graphql-url https://127.0.0.1:8443/graphql \\\n"
            "    --sensor sensor \\\n"
            "    --orig-ip-start 192.168.0.0 --orig-ip-end 192.169.0.0 \\\n"
            "    --orig-port-start 443 --orig-port-end 444 \\\n"
            "    --time-start 2025-10-14T15:00:00Z \\\n"
            "    --time-end 2025-11-15T15:00:00Z \\\n"
            "    --checkpoint ./origin-ip-port.chk\n"
            "\n"
            "  # Total count (no filters) for a sensor over a time range\n"
            "  python3 scripts/count_conn_events.py \\\n"
            "    --graphql-url https://127.0.0.1:8443/graphql \\\n"
            "    --sensor sensor \\\n"
            "    --time-start 2025-10-14T00:00:00Z \\\n"
            "    --time-end 2025-11-15T15:00:00Z \\\n"
            "    --no-filter \\\n"
            "    --checkpoint ./no-filter.chk\n"
            "\n"
            "  # Destination IP+Port, limit to 10 requests/pages for a quick test\n"
            "  python3 scripts/count_conn_events.py \\\n"
            "    --graphql-url https://127.0.0.1:8443/graphql \\\n"
            "    --sensor sensor \\\n"
            "    --resp-ip-start 10.0.0.0 --resp-ip-end 10.1.0.0 \\\n"
            "    --resp-port-start 443 --resp-port-end 444 \\\n"
            "    --time-start 2025-10-14T15:00:00Z \\\n"
            "    --time-end 2025-11-15T15:00:00Z \\\n"
            "    --checkpoint ./resp-ip-port-test.chk \\\n"
            "    --max-requests 10\n"
        ),
    )
    parser.add_argument("--graphql-url", required=True, help="Giganto GraphQL 엔드포인트 (예: https://127.0.0.1:8443/graphql)")
    parser.add_argument("--sensor", required=True, help="sensor 호스트네임")
    parser.add_argument("--orig-ip-start", help="출발지 IP - start (inclusive)")
    parser.add_argument("--orig-ip-end", help="출발지 IP - end (exclusive)")
    parser.add_argument("--resp-ip-start", help="도착지 IP - start (inclusive)")
    parser.add_argument("--resp-ip-end", help="도착지 IP - end (exclusive)")
    parser.add_argument("--orig-port-start", type=int, help="출발지 포트 - start (inclusive)")
    parser.add_argument("--orig-port-end", type=int, help="출발지 포트 - end (exclusive)")
    parser.add_argument("--resp-port-start", type=int, help="도착지 포트 - start (inclusive)")
    parser.add_argument("--resp-port-end", type=int, help="도착지 포트 - end (exclusive)")
    parser.add_argument("--time-start", help="시작 시각 (inclusive, RFC3339(UTC) 예: 2025-10-14T15:00:00Z)")
    parser.add_argument("--time-end", help="종료 시각 (exclusive, RFC3339(UTC) 예: 2025-11-15T15:00:00Z)")
    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="IP/Port 필터 없이 시간만 필터링하여 전체 카운트 (긴 러닝타임 및 리소스 소모 주의)",
    )
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
    return parser.parse_args()


def parse_rfc3339(ts: str | None) -> datetime | None:
    if ts is None:
        return None
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts[:-1]).replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(ts)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Invalid RFC3339 time: {ts}") from exc


def isoformat(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def load_checkpoint(path: pathlib.Path) -> tuple[str | None, int, int, datetime | None, dict]:
    try:
        data = json.loads(path.read_text())
        cursor = data.get("cursor")
        total = int(data.get("total", 0))
        requests = int(data.get("requests", 0))
        next_start_raw = data.get("next_start")
        next_start = parse_rfc3339(next_start_raw) if next_start_raw else None
        params = data.get("params") or {}
        return cursor, total, requests, next_start, params
    except FileNotFoundError:
        return None, 0, 0, None, {}
    except Exception:
        return None, 0, 0, None, {}


def save_checkpoint(
    path: pathlib.Path,
    cursor: str | None,
    total: int,
    requests: int,
    next_start: datetime | None,
    params: dict,
) -> None:
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".tmp.")
    tmp = pathlib.Path(tmp_path)
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
        json.dump(
            {
                "cursor": cursor,
                "total": total,
                "requests": requests,
                "next_start": isoformat(next_start),
                "params": params,
            },
            f,
        )
    tmp.replace(path)


def log(msg: str) -> None:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"[{now}] {msg}")


def build_base_filter(args: argparse.Namespace) -> dict:
    base = {"sensor": args.sensor}
    has_filter = False

    def add_range(key: str, start, end):
        nonlocal has_filter
        if start is not None or end is not None:
            base[key] = {"start": start, "end": end}
            has_filter = True

    add_range("origAddr", args.orig_ip_start, args.orig_ip_end)
    add_range("respAddr", args.resp_ip_start, args.resp_ip_end)
    add_range("origPort", args.orig_port_start, args.orig_port_end)
    add_range("respPort", args.resp_port_start, args.resp_port_end)

    if not has_filter and not args.no_filter:
        raise SystemExit("At least one IP or port range must be provided (or use --no-filter).")

    return base


def main() -> int:
    args = parse_args()
    ctx = build_ssl_context()
    opener = build_opener(ctx)

    time_start_dt = parse_rfc3339(args.time_start)
    time_end_dt = parse_rfc3339(args.time_end)
    if time_start_dt and time_end_dt and time_start_dt >= time_end_dt:
        raise SystemExit("time-start must be earlier than time-end")

    base_filter = build_base_filter(args)

    run_params = {
        "sensor": args.sensor,
        "orig_ip_start": args.orig_ip_start,
        "orig_ip_end": args.orig_ip_end,
        "orig_port_start": args.orig_port_start,
        "orig_port_end": args.orig_port_end,
        "resp_ip_start": args.resp_ip_start,
        "resp_ip_end": args.resp_ip_end,
        "resp_port_start": args.resp_port_start,
        "resp_port_end": args.resp_port_end,
        "time_start": isoformat(time_start_dt),
        "time_end": isoformat(time_end_dt),
        "no_filter": args.no_filter,
    }

    after: str | None
    total: int
    requests: int
    next_start: datetime | None
    saved_params: dict
    after, total, requests, next_start, saved_params = load_checkpoint(args.checkpoint)

    if saved_params and saved_params != run_params:
        raise SystemExit(
            f"checkpoint params mismatch: saved={saved_params}, current={run_params}. "
            "Delete or use a different checkpoint file."
        )

    if next_start is None:
        next_start = time_start_dt

    log(
        f"[start] sensor={args.sensor}, "
        f"orig-ip-start={args.orig_ip_start}, orig-ip-end={args.orig_ip_end}, "
        f"orig-port-start={args.orig_port_start}, orig-port-end={args.orig_port_end}, "
        f"resp-ip-start={args.resp_ip_start}, resp-ip-end={args.resp_ip_end}, "
        f"resp-port-start={args.resp_port_start}, resp-port-end={args.resp_port_end}, "
        f"time-start={isoformat(time_start_dt)}, time-end={isoformat(time_end_dt)}, "
        f"checkpoint={args.checkpoint}, next-start={isoformat(next_start)}"
    )
    if after:
        log(f"[resume] loaded cursor={after}, loaded total={total}, requests={requests}")
    else:
        log("[resume] no cursor found, starting from beginning")

    should_stop = False

    while True:
        # Determine slice boundaries
        if time_start_dt and time_end_dt:
            if next_start is None:
                next_start = time_start_dt
            if next_start >= time_end_dt:
                break
            slice_start = next_start
            slice_end = min(next_start + MAX_SLICE, time_end_dt)
        else:
            # No time slicing if time range not provided
            slice_start = next_start or time_start_dt
            slice_end = time_end_dt

        log(
            f"[slice] start={isoformat(slice_start)}, end={isoformat(slice_end)}, "
            f"cursor={after}, total={total}, requests={requests}"
        )

        while True:
            count, after, has_next = fetch_page(
                opener,
                base_filter,
                after,
                isoformat(slice_start),
                isoformat(slice_end),
                args.graphql_url,
            )
            total += count
            requests += 1

            args.checkpoint.parent.mkdir(parents=True, exist_ok=True)
            save_checkpoint(args.checkpoint, after, total, requests, slice_start, run_params)

            if (
                requests == 1
                or requests % LOG_INTERVAL == 0
                or (args.max_requests and requests >= args.max_requests)
                or (not has_next or not after)
            ):
                log(
                    f"[request {requests}] page_count={count}, total={total}, "
                    f"has_next={has_next}, cursor={after}"
                )

            if args.max_requests and requests >= args.max_requests:
                should_stop = True
                break

            if not has_next or not after:
                break

        # move to next slice
        after = None
        next_start = slice_end if slice_end else None
        save_checkpoint(args.checkpoint, after, total, requests, next_start, run_params)

        if should_stop:
            break

        if time_start_dt and time_end_dt:
            if next_start and next_start >= time_end_dt:
                break
        else:
            # no slicing; processed one iteration
            break

    log(f"[done] total={total}, requests={requests}, checkpoint={args.checkpoint}")
    print(total)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
