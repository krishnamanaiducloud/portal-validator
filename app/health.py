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

# Sampling is a bounded internal observation cadence, not an application wait
# or a user-facing route timeout. A remaining deadline always takes precedence.
RENDER_SAMPLE_INTERVAL_SECONDS = 0.1


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


async def document_navigation_timing(page) -> tuple[int, float, float] | None:
    """Map the local browser's document timing onto the validator's clock.

    Chromium and Python run in the same container and share the Unix epoch.
    Using performance.timeOrigin avoids treating evaluate()/IPC return latency
    as part of the document's clock offset and clipping away policy pauses.
    """
    timing = await page.evaluate("""() => {
      const entry = performance.getEntriesByType('navigation')[0];
      return entry && entry.domContentLoadedEventEnd > 0
        ? {duration: entry.domContentLoadedEventEnd - entry.startTime,
           epochStart: performance.timeOrigin + entry.startTime}
        : null;
    }""")
    if not timing:
        return None
    duration_ms = max(0, round(timing["duration"]))
    epoch_to_monotonic = time.perf_counter() - time.time()
    started = timing["epochStart"] / 1000 + epoch_to_monotonic
    return duration_ms, started, started + duration_ms / 1000


async def wait_for_render_settle(
    page,
    *,
    settle_ms: int,
    maximum_ms: int,
    network_activity: Callable[[], dict[str, int | float]] | None = None,
    minimum_observation_ms: int = 500,
    network_quiet_ms: int = 300,
    readiness_selector: str | None = None,
) -> dict[str, Any]:
    """Wait for bounded DOM stability and route-scoped network quiet.

    Long-lived sockets/event streams are excluded by the activity tracker. The
    maximum remains authoritative so polling portals cannot hold a scan open.
    """
    maximum_ms = max(0, int(maximum_ms))
    settle_ms = max(0, int(settle_ms))
    minimum_observation_ms = max(0, int(minimum_observation_ms))
    network_quiet_ms = max(0, int(network_quiet_ms))
    started = time.perf_counter()
    deadline = started + (maximum_ms / 1000)
    stable_since: float | None = None
    previous: tuple[object, ...] | None = None
    latest: dict[str, Any] = {
        "ready_state": "unknown", "title": "", "text_length": 0,
        "visible_elements": 0, "busy_indicators": 0,
        "challenge_indicators": 0, "alert_text": "",
        "configured_readiness_met": not bool(readiness_selector),
    }
    initial_activity = network_activity() if network_activity is not None else {}
    last_generation = int(initial_activity.get("generation", 0))
    network_quiet_since = started
    application_active_until = started
    first_render_ready: float | None = None
    capture_intervals: list[tuple[float, float]] = []
    dom_active_until = started
    api_active_until = started

    def finish(reason: str, now: float, pending: int, generation: int) -> dict[str, Any]:
        elapsed_ms = max(0, round((now - started) * 1000))
        # The trailing stability/quiet confirmation is a validator observation,
        # not application work. Only observed render changes, visible loading,
        # and request activity contribute to application readiness.
        # Evaluating our DOM diagnostic is validator work. Subtract only the
        # portion before the last observed readiness activity; never subtract a
        # trailing capture twice or include a late polling confirmation.
        active_capture_seconds = sum(
            max(0.0, min(end, application_active_until) - begin)
            for begin, end in capture_intervals if begin < application_active_until
        )
        application_ms = min(elapsed_ms, max(0, round(
            (application_active_until - started - active_capture_seconds) * 1000
        )))
        latest.update({
            "settle_reason": reason,
            "network_pending": pending,
            "network_activity_generation": generation,
            "settle_elapsed_ms": elapsed_ms,
            "settle_render_ready_ms": (
                max(0, round((first_render_ready - started) * 1000))
                if first_render_ready is not None else None
            ),
            "settle_application_ms": application_ms,
            "settle_validator_observation_ms": elapsed_ms - application_ms,
            "settle_capture_ms": max(0, round(sum(
                end - begin for begin, end in capture_intervals
            ) * 1000)),
            "settle_dom_activity_ms": max(0, round((dom_active_until - started) * 1000)),
            "settle_api_activity_ms": max(0, round((api_active_until - started) * 1000)),
        })
        return latest

    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            activity = network_activity() if network_activity is not None else {}
            return finish(
                "BOUNDED_TIMEOUT", time.perf_counter(),
                int(activity.get("pending", 0)), int(activity.get("generation", 0)),
            )
        capture_started = time.perf_counter()
        try:
            latest = await asyncio.wait_for(capture_render_health(page), timeout=remaining)
            # A fresh DOM snapshot does not carry the configured condition. If
            # its visibility check exhausts the budget, readiness is unproven,
            # not implicitly successful or inherited from an earlier sample.
            latest["configured_readiness_met"] = not bool(readiness_selector)
            if readiness_selector:
                latest["configured_readiness_met"] = await asyncio.wait_for(
                    page.locator(readiness_selector).first.is_visible(),
                    timeout=max(0.001, deadline - time.perf_counter()),
                )
        except TimeoutError:
            capture_intervals.append((capture_started, time.perf_counter()))
            activity = network_activity() if network_activity is not None else {}
            return finish(
                "BOUNDED_TIMEOUT", time.perf_counter(),
                int(activity.get("pending", 0)), int(activity.get("generation", 0)),
            )
        now = time.perf_counter()
        capture_intervals.append((capture_started, now))
        signature = (
            latest["ready_state"],
            latest["text_length"],
            latest["visible_elements"],
            latest["busy_indicators"],
            latest["challenge_indicators"],
            latest["title"],
            latest.get("configured_readiness_met", True),
        )
        activity = network_activity() if network_activity is not None else {}
        generation = int(activity.get("generation", 0))
        pending = int(activity.get("pending", 0))
        if first_render_ready is None and (
            latest["ready_state"] in {"interactive", "complete"}
            and latest.get("configured_readiness_met", True)
            and not latest["busy_indicators"]
            and (latest["text_length"] >= 20 or latest["visible_elements"] >= 3)
        ):
            first_render_ready = capture_started
        if pending:
            api_active_until = capture_started
            application_active_until = max(application_active_until, capture_started)
        if latest["busy_indicators"] or latest["ready_state"] == "loading" or not latest.get("configured_readiness_met", True):
            dom_active_until = capture_started
            application_active_until = max(application_active_until, capture_started)
        if generation != last_generation:
            last_generation = generation
            network_quiet_since = now
            last_activity = float(activity.get("last_activity", now))
            api_active_until = max(api_active_until, min(now, max(started, last_activity)))
            application_active_until = max(
                application_active_until, min(now, max(started, last_activity))
            )
        # Disabling DOM stability confirmation does not disable the separately
        # configured network/minimum observation windows. In particular, an
        # already requested popup document must not disappear before discovery.
        if (
            settle_ms == 0 and latest.get("configured_readiness_met", True)
            and pending == 0
            and (now - started) * 1000 >= minimum_observation_ms
            and (now - network_quiet_since) * 1000 >= network_quiet_ms
        ):
            return finish("SETTLE_DISABLED", now, pending, generation)
        if signature == previous:
            if stable_since is None:
                stable_since = capture_started
            dom_stable = (now - stable_since) * 1000 >= settle_ms
            observed_minimum = (now - started) * 1000 >= minimum_observation_ms
            network_quiet = (
                pending == 0
                and (now - network_quiet_since) * 1000 >= network_quiet_ms
            )
            content_ready = (
                latest["ready_state"] in {"interactive", "complete"}
                and latest.get("configured_readiness_met", True)
                and not latest["busy_indicators"]
                and (latest["text_length"] >= 20 or latest["visible_elements"] >= 3)
            )
            if dom_stable and observed_minimum and network_quiet and content_ready:
                return finish("DOM_AND_NETWORK_QUIET", now, pending, generation)
        else:
            if previous is not None:
                dom_active_until = capture_started
                application_active_until = max(application_active_until, capture_started)
            previous = signature
            stable_since = capture_started
        if now >= deadline:
            return finish("BOUNDED_TIMEOUT", now, pending, generation)
        await asyncio.sleep(min(RENDER_SAMPLE_INTERVAL_SECONDS, max(0.0, deadline - now)))


def route_performance_timing(
    *,
    navigation_ms: int,
    render_health: dict[str, Any] | None,
    total_validation_ms: int,
    render_start_ms: int | None = None,
    navigation_policy_ms: int = 0,
) -> dict[str, int | None | str]:
    """Split application-readiness evidence from deliberate observation waits.

    For same-document routes navigation_ms measures semantic activation/URL
    transition, not a new document handshake. application_load_ms includes that
    activation plus observed render/network work, but excludes the final
    stability confirmation and discovery/reporting overhead. Explicitly measured
    navigation-policy pauses are validator work, not target navigation time.
    This is a passive readiness estimate, not Core Web Vitals or a
    user-interaction benchmark.
    """
    raw_navigation_ms = max(0, int(navigation_ms))
    validator_navigation_ms = min(raw_navigation_ms, max(0, int(navigation_policy_ms)))
    navigation_ms = raw_navigation_ms - validator_navigation_ms
    total_validation_ms = max(raw_navigation_ms, int(total_validation_ms))
    snapshot = render_health or {}
    # Readiness timestamps remain relative to the real route-start clock. A
    # policy pause must not shift them or become available render-settle time.
    render_offset = max(raw_navigation_ms, int(render_start_ms or raw_navigation_ms))
    application_settle_ms = min(
        max(0, total_validation_ms - raw_navigation_ms),
        max(0, int(snapshot.get("settle_application_ms") or 0)),
    )
    observation_ms = max(0, int(snapshot.get("settle_validator_observation_ms") or 0))
    ready_ms = snapshot.get("settle_render_ready_ms")
    application_load_ms = navigation_ms + application_settle_ms
    return {
        "application_navigation_ms": navigation_ms,
        "navigation_ms": navigation_ms,
        "raw_navigation_ms": raw_navigation_ms,
        "validator_navigation_ms": validator_navigation_ms,
        "render_ready_ms": render_offset + max(0, int(ready_ms)) if ready_ms is not None else None,
        "dom_ready_ms": render_offset + max(0, int(ready_ms)) if ready_ms is not None else None,
        "application_settle_ms": application_settle_ms,
        "dom_settle_ms": max(0, int(snapshot.get("settle_dom_activity_ms") or 0)),
        "api_settle_ms": max(0, int(snapshot.get("settle_api_activity_ms") or 0)),
        "render_validation_ms": max(0, int(snapshot.get("settle_capture_ms") or 0)),
        "validator_observation_ms": observation_ms,
        "validator_overhead_ms": total_validation_ms - application_load_ms,
        "total_validation_ms": total_validation_ms,
        "application_load_ms": application_load_ms,
        "performance_basis": "OBSERVED_APPLICATION_READINESS",
    }


def assess_page_health(
    snapshot: dict[str, Any],
    *,
    load_ms: int,
    slow_page_threshold_ms: int,
    performance_enabled: bool = True,
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
    if performance_enabled and load_ms > slow_page_threshold_ms:
        findings.append(finding(
            "SLOW_ROUTE",
            "WARNING",
            f"Slow route: {load_ms / 1000:.2f}s > configured {slow_page_threshold_ms / 1000}s threshold",
            code="SLOW_ROUTE",
            component="ROUTE_PERFORMANCE",
            observed_ms=load_ms,
            threshold_ms=slow_page_threshold_ms,
            evidence={"application_load_ms": load_ms, "slow_route_threshold_ms": slow_page_threshold_ms},
        ))
    return classification, findings


def api_health_findings(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for event in events:
        # A denied request never reached the target. It is separately reported
        # as validator-policy evidence, never a target API failure.
        if event.get("blocked_by_validator"):
            continue
        status = event.get("status")
        _, fallback_host, fallback_endpoint = safe_api_identity(str(event.get("url") or ""))
        method = str(event.get("method") or "GET").upper()
        host = str(event.get("host") or fallback_host)
        endpoint = str(event.get("endpoint") or fallback_endpoint)
        importance = str(event.get("importance") or "REQUIRED").upper()
        importance = importance if importance in {"REQUIRED", "OPTIONAL", "BACKGROUND"} else "REQUIRED"
        required = importance == "REQUIRED"
        resource = f"{method} {host} {endpoint}"
        detail = {
            "resource": resource,
            "method": method,
            "host": host,
            "endpoint": endpoint,
            "http_status": status,
            "importance": importance,
            "target_failure": True,
            "validator_block": False,
        }
        if event.get("request_canceled"):
            findings.append(finding(
                "API_REQUEST_CANCELED", "WARNING",
                "The browser canceled an API request; no server or network failure is inferred.",
                **{**detail, "target_failure": False},
            ))
        elif event.get("lifecycle_status") == "INCOMPLETE":
            findings.append(finding(
                "API_OBSERVATION_INCOMPLETE", "WARNING",
                "API observation ended before a complete response was available.",
                **{**detail, "target_failure": False},
            ))
        # A known HTTP error remains target evidence even when observation of
        # its response body is incomplete or the browser later cancels it.
        if isinstance(status, int) and status >= 500:
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
        elif event.get("error") and not event.get("request_canceled") and event.get("lifecycle_status") != "INCOMPLETE":
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
