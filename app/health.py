from __future__ import annotations

from typing import Any

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
  return {
    ready_state: document.readyState,
    title: document.title.slice(0, 256),
    text_length: text.length,
    visible_elements: visible.length,
    busy_indicators: busy,
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
        "alert_text": str(result.get("alert_text") or "")[:500],
    }


def assess_page_health(
    snapshot: dict[str, Any],
    *,
    load_ms: int,
    slow_page_threshold_ms: int,
) -> tuple[str | None, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    classification: str | None = None
    if snapshot.get("text_length", 0) < 20 and snapshot.get("visible_elements", 0) < 3:
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
        resource = event.get("url")
        if event.get("error"):
            findings.append(finding(
                "API_REQUEST_FAILED",
                "WARNING",
                "An observed application API request failed.",
                resource=resource,
            ))
        elif isinstance(status, int) and status >= 500:
            findings.append(finding(
                "API_SERVER_ERROR",
                "ERROR",
                f"An observed application API returned HTTP {status}.",
                resource=resource,
                blocking=True,
            ))
        elif isinstance(status, int) and status >= 400:
            findings.append(finding(
                "API_CLIENT_ERROR",
                "WARNING",
                f"An observed application API returned HTTP {status}.",
                resource=resource,
            ))
    return findings
