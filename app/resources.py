"""Passive, sanitized resource-size evidence from the browser's own timings.

No resource is fetched, replayed or read by this module. Cross-origin entries
without Timing-Allow-Origin can expose zero sizes: those are reported as
unavailable rather than falsely claiming zero-byte network transfer.
"""
from __future__ import annotations

import math
import hashlib
import hmac
import secrets
import re
from collections import defaultdict, deque
from typing import Any
from urllib.parse import urlparse

from app.network import normalize_api_endpoint, safe_api_identity
from app.reporting import finding


RESOURCE_TIMING_SCRIPT = r"""
() => performance.getEntriesByType('resource').slice(-10000).map((entry) => ({
  name: entry.name,
  initiator_type: entry.initiatorType,
  start_time: entry.startTime,
  duration_ms: entry.duration,
  transfer_size_bytes: entry.transferSize,
  encoded_body_size_bytes: entry.encodedBodySize,
  decoded_body_size_bytes: entry.decodedBodySize,
  response_end: entry.responseEnd,
  same_origin: (() => {
    try { return new URL(entry.name, location.href).origin === location.origin; }
    catch (_) { return false; }
  })(),
}))
"""

_TIMING_SALT = secrets.token_bytes(32)


def resource_timing_key(url: str) -> str:
    """Opaque process-local correlation without retaining URL query secrets.

    Salted hashes avoid exposing a deterministic token/session fingerprint. The
    internal key is never needed in resource details or the final report.
    """
    return hmac.new(_TIMING_SALT, str(url).encode("utf-8"), hashlib.sha256).hexdigest()


def _nonnegative_number(value: Any, *, integer: bool = False) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return int(value) if integer else round(value, 2)


def _timing_sizes(timing: dict[str, Any]) -> dict[str, int | float | str | None]:
    sizes = {
        key: _nonnegative_number(timing.get(key), integer=True)
        for key in ("transfer_size_bytes", "encoded_body_size_bytes", "decoded_body_size_bytes")
    }
    exposed = any((value or 0) > 0 for value in sizes.values())
    reliable = bool(timing.get("same_origin")) or exposed
    completed = (_nonnegative_number(timing.get("response_end")) or 0) > 0
    if not reliable or not completed:
        sizes = {key: None for key in sizes}
    return {
        **sizes,
        "resource_duration_ms": _nonnegative_number(timing.get("duration_ms")) if completed else None,
        "size_source": "BROWSER_RESOURCE_TIMING" if reliable and completed else "UNAVAILABLE",
    }


async def enrich_resource_timings(page, events: list[dict[str, Any]]) -> int:
    """Attach natural browser timings to current-route listener events.

    ResourceTiming entries for identical sanitized identities are consumed from
    the newest document entries, matching the current route event counts. This
    avoids counting old same-document SPA entries as new transfers. Detached or
    otherwise inaccessible frames simply have no size evidence; their listener
    events and failures remain visible.
    """
    eligible = [
        event for event in events
        if not event.get("blocked_by_validator") and not event.get("error")
        and isinstance(event.get("status"), int)
        and event.get("response_completed", True)
    ]
    if not eligible:
        return 0
    timings: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for frame in page.frames:
        try:
            entries = await frame.evaluate(RESOURCE_TIMING_SCRIPT)
        except Exception as exc:
            # Playwright frame detachment/context destruction is expected during
            # navigation. Preserve unmeasurable resource events; never retry via
            # an active resource request or attach an unsafe exception message.
            if type(exc).__module__.startswith("playwright"):
                continue
            raise
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not str(entry.get("name", "")).startswith(("http://", "https://")):
                continue
            safe_url, _, _ = safe_api_identity(str(entry["name"]))
            # Real request events carry a secret-free opaque key, preventing
            # normalized IDs/query variants from borrowing another call's size.
            exact_key = resource_timing_key(str(entry["name"]))
            safe_timing = {key: value for key, value in entry.items() if key != "name"}
            timings[exact_key].append(safe_timing)
            timings[safe_url].append(safe_timing)
    counts: dict[str, int] = defaultdict(int)
    for event in eligible:
        safe_url, _, _ = safe_api_identity(str(event.get("url") or ""))
        identity = str(event.get("_resource_timing_key") or safe_url)
        counts[identity] += 1
    pools = {
        identity: deque(sorted(entries, key=lambda item: float(item.get("start_time") or 0))[-counts[identity]:])
        for identity, entries in timings.items() if counts[identity]
    }
    enriched = 0
    for event in eligible:
        safe_url, _, _ = safe_api_identity(str(event.get("url") or ""))
        pool = pools.get(str(event.get("_resource_timing_key") or safe_url))
        if pool:
            event.update(_timing_sizes(pool.popleft()))
            enriched += 1
    return enriched


def _resource_type(event: dict[str, Any], path: str) -> str:
    resource_type = str(event.get("resource_type") or event.get("type") or "other").upper()
    if resource_type in {"IMG", "IMAGE"}:
        return "IMAGE"
    if resource_type in {"SCRIPT", "JS"}:
        return "SCRIPT"
    if resource_type in {"STYLESHEET", "CSS"}:
        return "STYLESHEET"
    if resource_type in {"FETCH", "XHR"}:
        return resource_type
    if resource_type == "FONT" or path.lower().endswith((".woff", ".woff2", ".ttf", ".otf")):
        return "FONT"
    return "OTHER"


def safe_content_type(value: Any) -> str | None:
    """Keep only a MIME type, never arbitrary response-header parameters."""
    candidate = str(value or "").split(";", 1)[0].strip().lower()
    return candidate if re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", candidate) else None


def build_resource_report(
    events: list[dict[str, Any]],
    *,
    large_resource_threshold_bytes: int = 1024 * 1024,
    large_image_threshold_bytes: int = 512 * 1024,
    large_js_threshold_bytes: int = 1024 * 1024,
    large_css_font_threshold_bytes: int = 512 * 1024,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Serialize safe per-call resource details and measurable-transfer totals."""
    details: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for event in events:
        if id(event) in seen_ids:
            continue
        seen_ids.add(id(event))
        safe_url, host, path = safe_api_identity(str(event.get("url") or ""))
        resource_type = _resource_type(event, path)
        if str(event.get("resource_type") or "").lower() in {"document", "eventsource", "websocket"}:
            continue
        sizes = {
            key: _nonnegative_number(event.get(key), integer=True)
            for key in ("transfer_size_bytes", "encoded_body_size_bytes", "decoded_body_size_bytes")
        }
        blocked = bool(event.get("blocked_by_validator"))
        if blocked:
            sizes = {key: None for key in sizes}
        # Compressed payload size can remain measurable for a cached resource;
        # it is explicitly distinguished from actual network-transfer bytes.
        measured_size = sizes["transfer_size_bytes"]
        measurement = "TRANSFER_SIZE"
        if measured_size is None or measured_size == 0:
            measured_size = sizes["encoded_body_size_bytes"]
            measurement = "ENCODED_BODY_SIZE"
        categories: list[str] = []
        thresholds: dict[str, int] = {}
        if measured_size is not None:
            if resource_type == "IMAGE" and measured_size > large_image_threshold_bytes:
                categories.append("LARGE_IMAGE")
                thresholds["LARGE_IMAGE"] = large_image_threshold_bytes
            if resource_type == "SCRIPT":
                if measured_size > large_js_threshold_bytes:
                    categories.append("LARGE_JS_BUNDLE")
                    thresholds["LARGE_JS_BUNDLE"] = large_js_threshold_bytes
            elif resource_type in {"STYLESHEET", "FONT"}:
                if measured_size > large_css_font_threshold_bytes:
                    categories.append("LARGE_CSS_FONT")
                    thresholds["LARGE_CSS_FONT"] = large_css_font_threshold_bytes
            elif measured_size > large_resource_threshold_bytes:
                categories.append("LARGE_RESOURCE")
                thresholds["LARGE_RESOURCE"] = large_resource_threshold_bytes
        route = str(event.get("initiating_route") or "")
        # Preserve logical SPA route fragments, but never serialize query values
        # or opaque identifiers from resource correlation metadata.
        if route:
            parsed_route = urlparse(route)
            route, _, _ = safe_api_identity(route)
            if parsed_route.fragment.startswith(("/", "!/")):
                fragment_path = parsed_route.fragment.split("?", 1)[0].lstrip("!")
                route += "#" + normalize_api_endpoint(fragment_path)
        status = event.get("status")
        failed = not blocked and (bool(event.get("error")) or isinstance(status, int) and status >= 400)
        details.append({
            "url": safe_url,
            "host": host,
            "path": path,
            "type": resource_type,
            "content_type": safe_content_type(event.get("content_type")),
            "route": route or None,
            "status": status if isinstance(status, int) else None,
            "duration_ms": _nonnegative_number(event.get("resource_duration_ms", event.get("duration_ms"))),
            **sizes,
            "size_source": event.get("size_source", "UNAVAILABLE"),
            "size_categories": categories,
            "size_thresholds_bytes": thresholds,
            "warning_size_basis": measurement if categories else None,
            "failed": failed,
            "blocked_by_validator": blocked,
        })
    transfers = [item["transfer_size_bytes"] for item in details if item["transfer_size_bytes"] is not None]
    summary = {
        "resources_observed": len(details),
        "total_transfer_size_bytes": sum(transfers) if transfers else None,
        "resources_with_transfer_size": len(transfers),
        "large_resources": sum(bool(item["size_categories"]) for item in details),
        "large_images": sum("LARGE_IMAGE" in item["size_categories"] for item in details),
        "large_js_bundles": sum("LARGE_JS_BUNDLE" in item["size_categories"] for item in details),
        "large_css_fonts": sum("LARGE_CSS_FONT" in item["size_categories"] for item in details),
        "resource_failures": sum(item["failed"] for item in details),
        "largest_resources": sorted(
            (item for item in details if item["transfer_size_bytes"] is not None),
            key=lambda item: item["transfer_size_bytes"], reverse=True,
        )[:5],
        "large_resource_threshold_bytes": large_resource_threshold_bytes,
        "large_image_threshold_bytes": large_image_threshold_bytes,
        "large_js_threshold_bytes": large_js_threshold_bytes,
        "large_css_font_threshold_bytes": large_css_font_threshold_bytes,
    }
    return details, summary


def large_resource_findings(details: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in details:
        for category in item["size_categories"]:
            threshold = item.get("size_thresholds_bytes", {}).get(category)
            observed = (
                item["encoded_body_size_bytes"]
                if item["warning_size_basis"] == "ENCODED_BODY_SIZE"
                else item["transfer_size_bytes"]
            )
            findings.append(finding(
                category,
                "WARNING",
                f"A naturally loaded resource measured {observed} bytes > configured {threshold} byte threshold.",
                resource=f"{item['host']} {item['path']}",
                component="RESOURCE",
                observed_bytes=observed,
                threshold_bytes=threshold,
                size_basis=item["warning_size_basis"],
                transfer_size_bytes=item["transfer_size_bytes"],
                encoded_body_size_bytes=item["encoded_body_size_bytes"],
                blocking=False,
            ))
    return findings
