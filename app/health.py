from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

from app.network import safe_api_identity
from app.reporting import finding


RENDER_HEALTH_SCRIPT = r"""
() => {
  const body = document.body;
  const visible = body ? Array.from(body.querySelectorAll('*')).filter((element) => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
  }) : [];
  const text = (body?.innerText || '').replace(/\s+/g, ' ').trim();
  const alertText = Array.from(document.querySelectorAll('[role="alert"], main h1, main h2'))
    .filter((element) => {
      const style = getComputedStyle(element);
      return style.visibility !== 'hidden' && style.display !== 'none';
    })
    .map((element) => (element.textContent || '').replace(/\s+/g, ' ').trim())
    .join(' ').slice(0, 500);
  const busy = Array.from(document.querySelectorAll('[aria-busy="true"], [role="progressbar"]'))
    .filter((element) => {
      const style = getComputedStyle(element);
      return style.visibility !== 'hidden' && style.display !== 'none';
    }).length;
  const challenge = Array.from(document.querySelectorAll([
    '[data-sitekey]',
    'iframe[src*="captcha" i]',
    'iframe[title*="captcha" i]',
    'iframe[title*="challenge" i]',
    '[aria-label*="captcha" i]'
  ].join(','))).filter((element) => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
  }).length;
  return {
    ready_state: document.readyState,
    title: document.title.slice(0, 256),
    text_length: text.length,
    visible_elements: visible.length,
    busy_indicators: busy,
    challenge_indicators: challenge,
    alert_text: alertText,
  };
}
"""


ERROR_SURFACE_MARKERS = (
    "application error",
    "internal server error",
    "service unavailable",
    "something went wrong",
    "unexpected error",
)


async def capture_render_health(page) -> dict[str, Any]:
    result = await page.evaluate(RENDER_HEALTH_SCRIPT)
    return {
        "ready_state": str(result.get("ready_state") or "unknown"),
        "title": str(result.get("title") or "")[:256],
        "text_length": max(0, int(result.get("text_length", 0))),
        "visible_elements": max(0, int(result.get("visible_elements", 0))),
        "busy_indicators": max(0, int(result.get("busy_indicators", 0))),
        "challenge_indicators": max(0, int(result.get("challenge_indicators", 0))),
        "alert_text": str(result.get("alert_text") or "")[:500],
    }


async def wait_for_render_settle(
    page,
    *,
    settle_ms: int,
    maximum_ms: int,
    network_activity: Callable[[], dict[str, int | float]] | None = None,
    minimum_observation_ms: int = 500,
    network_quiet_ms: int = 500,
) -> dict[str, Any]:
    """Wait for bounded DOM stability and route-scoped network quiet.

    Long-lived sockets/event streams are excluded by the activity tracker. The
    maximum remains authoritative so polling portals cannot hold a scan open.
    """
    if settle_ms <= 0:
        return await capture_render_health(page)
    maximum_ms = max(settle_ms, maximum_ms)
    started = time.perf_counter()
    deadline = started + (maximum_ms / 1000)
    stable_since: float | None = None
    previous: tuple[object, ...] | None = None
    latest: dict[str, Any] = {}
    initial_activity = network_activity() if network_activity is not None else {}
    last_generation = int(initial_activity.get("generation", 0))
    network_quiet_since = started
    while True:
        latest = await capture_render_health(page)
        signature = (
            latest["ready_state"],
            latest["text_length"],
            latest["visible_elements"],
            latest["busy_indicators"],
            latest["challenge_indicators"],
            latest["title"],
        )
        now = time.perf_counter()
        activity = network_activity() if network_activity is not None else {}
        generation = int(activity.get("generation", 0))
        pending = int(activity.get("pending", 0))
        if generation != last_generation:
            last_generation = generation
            network_quiet_since = now
        if signature == previous:
            stable_since = stable_since or now
            dom_stable = (now - stable_since) * 1000 >= settle_ms
            observed_minimum = (now - started) * 1000 >= minimum_observation_ms
            network_quiet = (
                pending == 0
                and (now - network_quiet_since) * 1000 >= network_quiet_ms
            )
            if dom_stable and observed_minimum and network_quiet:
                latest.update({
                    "settle_reason": "DOM_AND_NETWORK_QUIET",
                    "network_pending": pending,
                    "network_activity_generation": generation,
                    "settle_elapsed_ms": round((now - started) * 1000),
                })
                return latest
        else:
            previous = signature
            stable_since = None
        if now >= deadline:
            latest.update({
                "settle_reason": "BOUNDED_TIMEOUT",
                "network_pending": pending,
                "network_activity_generation": generation,
                "settle_elapsed_ms": round((now - started) * 1000),
            })
            return latest
        await asyncio.sleep(min(0.1, max(0.01, deadline - now)))


def assess_page_health(
    snapshot: dict[str, Any],
    *,
    load_ms: int,
    slow_page_threshold_ms: int,
) -> tuple[str | None, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    classification: str | None = None
    if snapshot.get("challenge_indicators", 0):
        classification = "CHALLENGE_REQUIRED"
        findings.append(finding(
            "AUTOMATION_CHALLENGE_OBSERVED",
            "INFO",
            "A browser challenge requires user interaction and was not bypassed.",
        ))
    elif snapshot.get("text_length", 0) < 20 and snapshot.get("visible_elements", 0) < 3:
        classification = "PAGE_RENDER_ERROR"
        findings.append(finding(
            "BLANK_PAGE",
            "ERROR",
            "The main document loaded but did not render meaningful visible content.",
            blocking=True,
        ))
    else:
        visible_signal = f"{snapshot.get('title', '')} {snapshot.get('alert_text', '')}".lower()
        if any(marker in visible_signal for marker in ERROR_SURFACE_MARKERS):
            classification = "PAGE_RENDER_ERROR"
            findings.append(finding(
                "APPLICATION_ERROR_SURFACE",
                "ERROR",
                "The rendered page contains a generic application error signal.",
                blocking=True,
            ))
    if snapshot.get("busy_indicators", 0):
        findings.append(finding(
            "RENDER_STILL_BUSY",
            "WARNING",
            "Visible loading indicators remained after the configured render-settle period.",
        ))
    if load_ms > slow_page_threshold_ms:
        findings.append(finding(
            "SLOW_PAGE",
            "WARNING",
            f"Page load exceeded the configured {slow_page_threshold_ms} ms threshold.",
        ))
    return classification, findings


def api_health_findings(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for event in events:
        status = event.get("status")
        _, fallback_host, fallback_endpoint = safe_api_identity(str(event.get("url") or ""))
        method = str(event.get("method") or "GET").upper()
        host = str(event.get("host") or fallback_host)
        endpoint = str(event.get("endpoint") or fallback_endpoint)
        required = event.get("importance", "REQUIRED") == "REQUIRED"
        resource = f"{method} {host} {endpoint}"
        detail = {
            "resource": resource,
            "method": method,
            "host": host,
            "endpoint": endpoint,
            "http_status": status,
            "importance": "REQUIRED" if required else "OPTIONAL",
            "target_failure": True,
            "validator_block": False,
        }
        if event.get("error"):
            upper_error = str(event["error"]).upper()
            failure_type = (
                "API_TLS_FAILURE" if "CERT" in upper_error or "TLS" in upper_error else
                "API_DNS_FAILURE" if "NAME_NOT_RESOLVED" in upper_error else
                "API_TIMEOUT" if "TIMEOUT" in upper_error else
                "API_NETWORK_FAILURE"
            )
            findings.append(finding(
                failure_type,
                "WARNING",
                "An observed application API request failed.",
                **detail,
            ))
        elif isinstance(status, int) and status >= 500:
            findings.append(finding(
                "API_SERVER_ERROR" if required else "API_SERVER_ERROR_OPTIONAL",
                "ERROR" if required else "WARNING",
                (
                    f"A required route API returned HTTP {status}."
                    if required else
                    f"A background or optional API returned HTTP {status}."
                ),
                **detail,
                blocking=required,
            ))
        elif isinstance(status, int) and status >= 400:
            failure_type = {
                400: "API_BAD_REQUEST",
                401: "API_AUTHENTICATION_FAILURE",
                403: "API_AUTHORIZATION_FAILURE",
                404: "API_NOT_FOUND",
                408: "API_TIMEOUT",
                409: "API_CONFLICT",
                429: "API_RATE_LIMITED",
            }.get(status, "API_CLIENT_ERROR")
            findings.append(finding(
                failure_type,
                "WARNING",
                f"An observed application API returned HTTP {status}.",
                **detail,
            ))
    return findings


def realtime_health_findings(
    websocket_events: list[dict[str, Any]],
    event_streams: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for event in websocket_events:
        if event.get("status") == "ERROR":
            findings.append(finding(
                "WEBSOCKET_CONNECTION_FAILED",
                "WARNING",
                "A naturally initiated WebSocket connection reported an error.",
                resource=event.get("url"),
            ))
    for event in event_streams:
        status = event.get("status")
        if event.get("error") or (isinstance(status, int) and status >= 400):
            findings.append(finding(
                "EVENT_STREAM_FAILED",
                "WARNING",
                "A naturally initiated server-sent event stream failed.",
                resource=event.get("url"),
            ))
    return findings
