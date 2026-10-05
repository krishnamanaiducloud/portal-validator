from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from app.security import JWT_RE, SENSITIVE_KEYS, normalized_host, sanitize_text, sanitize_url


SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
VALID_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9-]{0,31}$")
UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
HEX_IDENTIFIER_RE = re.compile(r"^[0-9a-f]{24,64}$", re.IGNORECASE)
INTEGER_IDENTIFIER_RE = re.compile(r"^[0-9]{2,}$")
OPAQUE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_-]{32,}$")
SENSITIVE_PATH_LABELS = frozenset(
    key.replace("-", "_").lower() for key in SENSITIVE_KEYS
)
POLICY_CLASSIFICATIONS = frozenset({
    "APPROVED_READ_POST",
    "APPROVED_READ_REQUEST",
    "SESSION_REFRESH",
    "ACCESS_GATE",
})


def classify_traffic(
    *,
    method: str,
    endpoint: str,
    resource_type: str,
    phase: str,
    blocked_by_validator: bool = False,
) -> str:
    """Classify safe network metadata without inspecting headers or bodies."""
    if blocked_by_validator:
        return "VALIDATOR_BLOCKED"
    normalized_type = resource_type.lower()
    normalized_path = endpoint.lower()
    normalized_phase = phase.upper()
    if normalized_type == "document":
        return "DOCUMENT"
    if normalized_phase == "AUTHENTICATION":
        return "AUTH_API"
    if normalized_phase == "SESSION_REFRESH":
        return "SESSION_REFRESH"
    if normalized_type not in {"xhr", "fetch"}:
        return "STATIC_RESOURCE"
    if normalized_path.endswith("/config.json") or normalized_path == "/config.json":
        return "MICROFRONTEND_CONFIG"
    if any(marker in normalized_path for marker in (
        "/analytics", "/beacon", "/collect", "/metrics", "/telemetry",
    )):
        return "TELEMETRY"
    return "APPLICATION_API"


class RouteNetworkActivity:
    """Track bounded route activity without retaining request secrets."""

    def __init__(self) -> None:
        self._pending: dict[int, str | None] = {}
        self._last_activity: dict[str | None, float] = {}
        self._generation: dict[str | None, int] = {}

    def request_started(self, request: Any, route_id: str | None) -> None:
        if str(request.resource_type).lower() in {"websocket", "eventsource"}:
            return
        key = id(request)
        if key in self._pending:
            return
        self._pending[key] = route_id
        self._touch(route_id)

    def request_finished(self, request: Any) -> None:
        key = id(request)
        if key not in self._pending:
            return
        route_id = self._pending.pop(key)
        self._touch(route_id)

    def snapshot(self, route_id: str | None) -> dict[str, int | float]:
        return {
            "generation": self._generation.get(route_id, 0),
            "pending": sum(value == route_id for value in self._pending.values()),
            "last_activity": self._last_activity.get(route_id, 0.0),
        }

    def _touch(self, route_id: str | None) -> None:
        self._last_activity[route_id] = time.perf_counter()
        self._generation[route_id] = self._generation.get(route_id, 0) + 1


def summarize_route_api_coverage(events: list[dict[str, Any]]) -> dict[str, int | str]:
    """Report business-API coverage separately from config and authentication."""
    application_events = [
        event for event in events
        if (
            event.get("traffic_category") == "APPLICATION_API"
            or (
                event.get("traffic_category") == "VALIDATOR_BLOCKED"
                and event.get("resource_type") in {"xhr", "fetch"}
                and not str(event.get("endpoint") or "").lower().endswith("/config.json")
                and event.get("phase") not in {"AUTHENTICATION", "SESSION_REFRESH"}
            )
        )
    ]
    blocked = sum(bool(event.get("blocked_by_validator")) for event in application_events)
    executed = len(application_events) - blocked
    return {
        "api_coverage": (
            "APPLICATION_API_OBSERVED" if executed else
            "APPLICATION_API_BLOCKED" if blocked else
            "NO_APPLICATION_API_OBSERVED"
        ),
        "apis_observed": len(events),
        "application_apis_observed": len(application_events),
        "application_apis_executed": executed,
        "blocked_api_attempts": blocked,
    }


def normalize_api_endpoint(path: str) -> str:
    """Return a query-free, conservatively normalized and redacted API path."""
    if not path:
        return "/"
    parsed_path = urlparse(path).path if "://" in path else path.split("?", 1)[0].split("#", 1)[0]
    segments = parsed_path.split("/")
    output: list[str] = []
    previous = ""
    for raw_segment in segments:
        if not raw_segment:
            continue
        decoded = unquote(raw_segment)
        normalized_label = decoded.strip().lower().replace("-", "_")
        if previous in SENSITIVE_PATH_LABELS:
            output.append("{redacted}")
        elif JWT_RE.search(decoded):
            output.append("{redacted}")
        elif (
            UUID_SEGMENT_RE.fullmatch(decoded)
            or HEX_IDENTIFIER_RE.fullmatch(decoded)
            or INTEGER_IDENTIFIER_RE.fullmatch(decoded)
            or OPAQUE_IDENTIFIER_RE.fullmatch(decoded)
        ):
            output.append("{id}")
        else:
            output.append(raw_segment[:256])
        previous = normalized_label
    normalized = "/" + "/".join(output)
    return normalized[:2048] or "/"


def safe_api_identity(url: str) -> tuple[str, str, str]:
    parsed = urlparse(url)
    host = normalized_host(parsed.hostname or "")
    endpoint = normalize_api_endpoint(parsed.path or "/")
    origin = sanitize_url(url, include_path=False).split("?", 1)[0]
    safe_url = f"{origin}{endpoint}" if origin != "[REDACTED_URL]" else origin
    return safe_url, host, endpoint


@dataclass(frozen=True)
class ApprovedRequestRule:
    method: str
    host: str
    path: str
    classification: str
    path_pattern: bool = False

    def matches(self, method: str, url: str) -> bool:
        parsed = urlparse(url)
        if (
            method.upper() != self.method
            or normalized_host(parsed.hostname or "") != self.host
        ):
            return False
        candidate = parsed.path or "/"
        if not self.path_pattern:
            # Inventory normalization must never broaden an administrator-approved
            # execution path into a wildcard.
            return candidate == self.path
        expected_segments = self.path.strip("/").split("/")
        candidate_segments = candidate.strip("/").split("/")
        return len(expected_segments) == len(candidate_segments) and all(
            expected == "{segment}" or expected == actual
            for expected, actual in zip(expected_segments, candidate_segments)
        )


@dataclass(frozen=True)
class AccessGateRule:
    host: str
    selector: str


@dataclass(frozen=True)
class ReadOnlyPolicy:
    safe_application_requests: tuple[ApprovedRequestRule, ...] = ()
    access_gates: tuple[AccessGateRule, ...] = ()

    def match(self, method: str, url: str) -> ApprovedRequestRule | None:
        return next(
            (rule for rule in self.safe_application_requests if rule.matches(method, url)),
            None,
        )

    def access_gate_for(self, url: str) -> AccessGateRule | None:
        host = normalized_host(urlparse(url).hostname or "")
        return next((rule for rule in self.access_gates if rule.host == host), None)


def load_read_only_policy(
    *,
    raw: str | None = None,
    path: str | Path | None = None,
) -> ReadOnlyPolicy:
    """Load administrator-owned read-only exceptions from JSON, never scan input."""
    configured_raw = raw if raw is not None else os.getenv("PORTAL_VALIDATOR_READ_ONLY_POLICY")
    configured_path = path if path is not None else os.getenv("PORTAL_VALIDATOR_READ_ONLY_POLICY_FILE")
    if configured_raw and configured_path:
        raise ValueError("Configure one read-only policy source, not both")
    if configured_path:
        policy_path = Path(configured_path)
        if not policy_path.is_file() or policy_path.stat().st_size > 64 * 1024:
            raise ValueError("Read-only policy file is missing or too large")
        configured_raw = policy_path.read_text(encoding="utf-8")
    if not configured_raw:
        return ReadOnlyPolicy()
    try:
        data = json.loads(configured_raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Read-only policy is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("Read-only policy must be a JSON object")
    request_items = data.get("safe_application_requests", [])
    gate_items = data.get("access_gates", [])
    if not isinstance(request_items, list) or len(request_items) > 100:
        raise ValueError("safe_application_requests must contain at most 100 rules")
    if not isinstance(gate_items, list) or len(gate_items) > 25:
        raise ValueError("access_gates must contain at most 25 rules")

    rules: list[ApprovedRequestRule] = []
    for item in request_items:
        if not isinstance(item, dict):
            raise ValueError("Each safe application request rule must be an object")
        method = str(item.get("method") or "").strip().upper()
        host = normalized_host(str(item.get("host") or ""))
        has_exact_path = "path" in item
        has_path_pattern = "path_pattern" in item
        if has_exact_path == has_path_pattern:
            raise ValueError("Policy rule must configure exactly one path or path_pattern")
        raw_path = str(
            item.get("path") if has_exact_path else item.get("path_pattern")
        ).strip()
        classification = str(
            item.get("classification")
            or ("APPROVED_READ_POST" if method == "POST" else "APPROVED_READ_REQUEST")
        ).strip().upper()
        if not VALID_METHOD_RE.fullmatch(method) or method in SAFE_HTTP_METHODS:
            raise ValueError("Policy methods must be explicit mutation-capable HTTP methods")
        if not host or "/" in host or "://" in host:
            raise ValueError("Policy rule host must be an exact hostname")
        if not raw_path.startswith("/") or "?" in raw_path or "#" in raw_path:
            raise ValueError("Policy rule path must be a query-free absolute path")
        if has_exact_path and any(marker in raw_path for marker in ("*", "{", "}")):
            raise ValueError("Exact policy paths cannot contain wildcard syntax")
        if has_path_pattern:
            segments = [segment for segment in raw_path.split("/") if segment]
            literals = [segment for segment in segments if segment != "{segment}"]
            if (
                len(segments) < 3
                or len(literals) < 2
                or segments[0] == "{segment}"
                or any(
                    segment != "{segment}" and not re.fullmatch(r"[A-Za-z0-9._~-]+", segment)
                    for segment in segments
                )
            ):
                raise ValueError(
                    "Policy path_pattern must be segment-bounded with at least two literal segments"
                )
        if classification not in POLICY_CLASSIFICATIONS:
            raise ValueError("Policy rule classification is not supported")
        rules.append(ApprovedRequestRule(
            method=method,
            host=host,
            path=raw_path,
            classification=classification,
            path_pattern=has_path_pattern,
        ))

    gates: list[AccessGateRule] = []
    for item in gate_items:
        if not isinstance(item, dict):
            raise ValueError("Each access gate rule must be an object")
        host = normalized_host(str(item.get("host") or ""))
        selector = str(item.get("selector") or "").strip()
        if not host or "/" in host or "://" in host:
            raise ValueError("Access gate host must be an exact hostname")
        if not selector or len(selector) > 512:
            raise ValueError("Access gate selector is missing or too long")
        gates.append(AccessGateRule(host=host, selector=selector))
    return ReadOnlyPolicy(tuple(rules), tuple(gates))


class PassiveNetworkObserver:
    """Correlate request lifecycles while retaining metadata-only attempt records."""

    def __init__(self, events: list[dict[str, Any]]):
        self.events = events
        self._events_by_request: dict[int, dict[str, Any]] = {}

    def observe_request(
        self,
        request: Any,
        *,
        phase: str,
        importance: str,
        initiating_route: str | None,
        main_document: bool,
    ) -> dict[str, Any]:
        key = id(request)
        existing = self._events_by_request.get(key)
        if existing is not None:
            return existing
        method = str(request.method).upper()
        safe_url, host, endpoint = safe_api_identity(str(request.url))
        try:
            frame_identity = (
                "MAIN_FRAME" if request.frame.parent_frame is None else "CHILD_FRAME"
            )
        except Exception:
            frame_identity = "UNKNOWN_FRAME"
        event: dict[str, Any] = {
            "url": safe_url,
            "host": host,
            "endpoint": endpoint,
            "method": method,
            "status": None,
            "error": None,
            "blocked_by_validator": False,
            "block_reason": None,
            "protocol": "GRAPHQL" if endpoint.lower().endswith("/graphql") else "REST",
            "resource_type": str(request.resource_type),
            "phase": phase,
            "importance": importance,
            "observed_at": _observed_at(),
            "duration_ms": None,
            "initiating_route": initiating_route,
            "main_document": main_document,
            "frame_identity": frame_identity,
            "request_classification": "SAFE_METHOD" if method in SAFE_HTTP_METHODS else "UNKNOWN",
            "allowed_by_policy": method in SAFE_HTTP_METHODS,
            "target_reached": None,
            "lifecycle": "REQUESTED",
            "traffic_category": classify_traffic(
                method=method,
                endpoint=endpoint,
                resource_type=str(request.resource_type),
                phase=phase,
            ),
            "_started_at": time.perf_counter(),
        }
        self._events_by_request[key] = event
        self.events.append(event)
        return event

    def mark_allowed(
        self,
        request: Any,
        classification: str,
        *,
        phase: str | None = None,
        importance: str | None = None,
    ) -> dict[str, Any] | None:
        event = self._events_by_request.get(id(request))
        if event is None:
            return None
        event["request_classification"] = classification
        event["allowed_by_policy"] = True
        event["lifecycle"] = "ALLOWED"
        if phase is not None:
            event["phase"] = phase
        if importance is not None:
            event["importance"] = importance
        event["traffic_category"] = classify_traffic(
            method=str(event.get("method") or "GET"),
            endpoint=str(event.get("endpoint") or "/"),
            resource_type=str(event.get("resource_type") or "other"),
            phase=str(event.get("phase") or "VALIDATION"),
        )
        return event

    def mark_blocked(
        self,
        request: Any,
        reason: str,
        *,
        classification: str = "BLOCKED_MUTATION",
    ) -> dict[str, Any] | None:
        event = self._events_by_request.get(id(request))
        if event is None:
            return None
        event.update({
            "blocked_by_validator": True,
            "block_reason": reason,
            "request_classification": classification,
            "allowed_by_policy": False,
            "target_reached": False,
            "lifecycle": "BLOCKED",
            "duration_ms": self._duration(event),
        })
        event["traffic_category"] = "VALIDATOR_BLOCKED"
        return event

    def record_response(self, request: Any, status: int) -> dict[str, Any] | None:
        event = self._events_by_request.get(id(request))
        if event is None or event.get("lifecycle") == "BLOCKED":
            return event
        if event.get("lifecycle") == "RESPONSE":
            return event
        if event.get("request_classification") == "UNKNOWN":
            event["request_classification"] = "APPLICATION_REQUEST"
        event.update({
            "status": int(status),
            "target_reached": True,
            "lifecycle": "RESPONSE",
            "duration_ms": self._duration(event),
        })
        return event

    def record_failure(self, request: Any, error: str) -> dict[str, Any] | None:
        event = self._events_by_request.get(id(request))
        if event is None or event.get("lifecycle") in {"BLOCKED", "RESPONSE", "FAILED"}:
            return event
        if event.get("request_classification") == "UNKNOWN":
            event["request_classification"] = "APPLICATION_REQUEST"
        event.update({
            "error": sanitize_text(str(error).splitlines()[0], limit=1000),
            "target_reached": True,
            "lifecycle": "FAILED",
            "duration_ms": self._duration(event),
        })
        return event

    def finalize_pending(self) -> None:
        for event in self.events:
            if event.get("lifecycle") in {"REQUESTED", "ALLOWED"}:
                if event.get("request_classification") == "UNKNOWN":
                    event["request_classification"] = "APPLICATION_REQUEST"
                event["lifecycle"] = "PENDING_AT_SCAN_END"
                event["duration_ms"] = self._duration(event)
            event.pop("_started_at", None)

    @staticmethod
    def _duration(event: dict[str, Any]) -> int | None:
        started = event.get("_started_at")
        return round((time.perf_counter() - started) * 1000) if isinstance(started, float) else None


def _observed_at() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
