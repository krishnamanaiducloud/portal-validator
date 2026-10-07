"""Generic production-path timing benchmark; no enterprise endpoints or state."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pytest import MonkeyPatch
from test_scan_post_lifecycle import production_spa
from app.main import ScanRequest, execute_scan


async def measure(origin: str, routes: int, settle_ms: int) -> dict:
    request = ScanRequest(
        target=origin, allow_private_networks=True, max_pages=routes + 1,
        max_depth=2, timeout_ms=5000, total_timeout_ms=240000,
        render_settle_ms=settle_ms, max_navigation_actions=0,
        max_discovery_scrolls=0, check_security_headers=False,
        large_resource_threshold_bytes=1024, large_image_threshold_bytes=1024,
        approved_read_post_operations=[{
            "method": "POST", "host": "127.0.0.1", "path": "/api/query",
            "description": "Generic fixture owner approved read query",
        }],
    )
    report = await execute_scan(request)
    summary = report["summary"]
    post = next(item for item in report["api_inventory"] if item["method"] == "POST")
    assert summary["routes_validated"] == routes + 1
    assert post["calls"] == 7 * routes and post["status_2xx"] == 7 * routes
    timings = [item.get("timings", item) for item in report["results"]]
    return {
        **{key: summary.get(key) for key in (
            "total_scan_duration_ms", "average_route_duration_ms", "p95_route_duration_ms",
            "authentication_duration_ms", "discovery_duration_ms", "validation_duration_ms",
            "finalization_duration_ms", "routes_validated", "slow_pages",
        )},
        "application_settle_ms": sum(int(item.get("application_settle_ms") or 0) for item in timings),
        "validator_observation_ms": sum(int(item.get("validator_observation_ms") or 0) for item in timings),
        "validator_overhead_ms": sum(int(item.get("validator_overhead_ms") or 0) for item in timings),
        "approved_post_calls": post["calls"],
        "browser_contexts": report.get("scan_timing", {}).get("browser_contexts"),
        "pages": report.get("scan_timing", {}).get("pages"),
        "full_navigations": sum(item["navigation_type"] == "DOCUMENT_NAVIGATION" for item in report["results"]),
        "spa_transitions": sum(item["navigation_type"] != "DOCUMENT_NAVIGATION" for item in report["results"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--routes", type=int, default=43)
    parser.add_argument("--settle-ms", type=int, default=500)
    parser.add_argument(
        "--baseline", action="store_true",
        help="Load committed main/health implementations in memory for a same-fixture comparison.",
    )
    parser.add_argument(
        "--baseline-ref", default="3617364f35b7b285604e8568425475844b60af0e",
        help="Read-only historical baseline (defaults to the published 1.9.0 source).",
    )
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    if args.baseline:
        # Read-only historical comparison: no checkout, worktree or user files
        # are modified. Both runs keep the exact same browser/fixture/deps.
        from app import health, main as main_module
        for module, path in ((health, "app/health.py"), (main_module, "app/main.py")):
            source = subprocess.check_output(
                ["git", "show", f"{args.baseline_ref}:{path}"],
                cwd=Path(__file__).resolve().parents[1], text=True,
            )
            exec(compile(source, f"{args.baseline_ref}:{path}", "exec"), module.__dict__)
        global ScanRequest, execute_scan
        ScanRequest = main_module.ScanRequest
        execute_scan = main_module.execute_scan
    with MonkeyPatch.context() as patch:
        fixture = production_spa.__wrapped__(patch)
        origin, handler = next(fixture)
        handler.routes = args.routes
        try:
            result = asyncio.run(measure(origin, args.routes, args.settle_ms))
            result["implementation"] = "committed_main_health" if args.baseline else "working_main_health"
            if args.baseline:
                result["baseline_ref"] = args.baseline_ref
            print(json.dumps(result, sort_keys=True))
        finally:
            try:
                next(fixture)
            except StopIteration:
                pass


if __name__ == "__main__":
    main()
