from __future__ import annotations

import json
import ipaddress
import os
import re
import time
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from app.security import JWT_RE, SENSITIVE_KEYS, normalized_host, sanitize_text, sanitize_url


SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
PUBLIC_POLICY_NAMES = {
    "APPROVED_READ_POST": "APPROVED_READ_ONLY",
    "APPROVED_READ_REQUEST": "APPROVED_READ_ONLY",
    "BLOCKED_MUTATION": "READ_ONLY_BLOCKED",
    "READ_ONLY_BLOCK": "READ_ONLY_BLOCKED",
}
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


def _policy_hostname(value: Any) -> str:
    host = normalized_host(str(value or ""))
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Policy rule host must be an exact hostname") from exc
    if len(host) > 253 or not all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in host.split(".")
    ):
        raise ValueError("Policy rule host must be an exact hostname without URL, credentials, port or wildcards")
    return host


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


def request_identity(request: Any) -> Any:
    """Stable weak-referenceable identity across Playwright API wrappers.

    This identity is used only as a weak mapping key, never serialized or logged.
    Keeping the underlying implementation weak avoids retaining its raw headers
    or body after Playwright finishes/disposes the request.
    """
    return getattr(request, "_impl_obj", request)


def public_policy_classification(classification: str) -> str:
    """Stable display vocabulary, retaining legacy execution classifications."""
    return PUBLIC_POLICY_NAMES.get(classification, classification)


class RouteNetworkActivity:
    """Track bounded route activity without retaining request secrets."""

    def __init__(self) -> None:
        self._pending: weakref.WeakKeyDictionary[Any, str | None] = weakref.WeakKeyDictionary()
        self._last_activity: dict[str | None, float] = {}
        self._generation: dict[str | None, int] = {}

    def request_started(self, request: Any, route_id: str | None, *, relevant: bool = True) -> None:
        if not relevant or str(request.resource_type).lower() in {"websocket", "eventsource"}:
            return
        key = request_identity(request)
        if key in self._pending:
            return
        self._pending[key] = route_id
        self._touch(route_id)

    def request_finished(self, request: Any) -> None:
        key = request_identity(request)
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
        if "//" in candidate:
            return False
        expected_segments = self.path.strip("/").split("/")
        candidate_segments = candidate.strip("/").split("/")
        # A raw encoded slash can look like one segment here but become a
        # different operation after a proxy/router decodes it. Likewise reject
        # another escape layer rather than guessing how many times an upstream
        # component decodes paths. Ordinary bounded IDs remain supported.
        for segment in candidate_segments:
            try:
                decoded = unquote(segment, errors="strict")
            except UnicodeDecodeError:
                return False
            if (
                decoded in {".", ".."}
                or any(marker in decoded for marker in ("/", "\\", "%", "?", "#"))
                or any(ord(character) <= 32 or ord(character) == 127 for character in decoded)
            ):
                return False
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
    """Load explicit read-only POST exceptions from administrator configuration."""
    explicit_source = raw is not None or path is not None
    configured_raw = raw if explicit_source else os.getenv("PORTAL_VALIDATOR_READ_ONLY_POLICY")
    configured_path = path if explicit_source else os.getenv("PORTAL_VALIDATOR_READ_ONLY_POLICY_FILE")
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
        host = _policy_hostname(item.get("host"))
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
        if method != "POST":
            raise ValueError("Read-only policy exceptions must use POST; other mutation methods remain blocked")
        if not host or "/" in host or "://" in host:
            raise ValueError("Policy rule host must be an exact hostname")
        if not raw_path.startswith("/") or "?" in raw_path or "#" in raw_path:
            raise ValueError("Policy rule path must be a query-free absolute path")
        if (
            len(raw_path) > 2048 or raw_path.startswith("//")
            or "\\" in raw_path or any(ord(character) <= 32 for character in raw_path)
            or any(segment in {".", ".."} for segment in unquote(raw_path).split("/"))
            or re.search(r"%(?:2f|5c|00)", raw_path, re.IGNORECASE)
        ):
            raise ValueError("Policy rule path must be normalized and must not contain ambiguous separators")
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
        # CPython object ids can be reused after Playwright disposes a completed
        # request. Retaining id(request) forever aliases later POSTs to old GETs.
        # Weak object keys preserve identity without keeping raw Request objects
        # (which contain headers/bodies) alive for the duration of a scan.
        self._events_by_request: weakref.WeakKeyDictionary[Any, dict[str, Any]] = weakref.WeakKeyDictionary()
        self._sequence = 0

    def observe_request(
        self,
        request: Any,
        *,
        phase: str,
        importance: str,
        initiating_route: str | None,
        main_document: bool,
        route_activation_id: str | None = None,
    ) -> dict[str, Any]:
        key = self._request_key(request)
        existing = self._events_by_request.get(key)
        if existing is not None:
            return existing
        method = str(request.method).upper()
        self._sequence += 1
        safe_url, host, endpoint = safe_api_identity(str(request.url))
        try:
            frame_identity = (
                "MAIN_FRAME" if request.frame.parent_frame is None else "CHILD_FRAME"
            )
        except Exception:
            frame_identity = "UNKNOWN_FRAME"
        event: dict[str, Any] = {
            "request_id": f"request-{self._sequence}",
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
            "route_activation_id": route_activation_id,
            "observer_seen": True,
            "policy_evaluated": False,
            "policy_decision": "PENDING",
            "policy_reason": None,
            "route_handler_seen": False,
            "request_reached_network": None,
            "request_dispatched": False,
            "response_seen": False,
            "response_status": None,
            "response_completed": False,
            "request_failed": False,
            "failure_category": None,
            "aggregation_seen": False,
            "serialized_to_report": False,
            "main_document": main_document,
            "frame_identity": frame_identity,
            "request_classification": "SAFE_METHOD" if method in SAFE_HTTP_METHODS else "UNKNOWN",
            "policy_classification": "SAFE_METHOD" if method in SAFE_HTTP_METHODS else "UNKNOWN",
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
        event = self._events_by_request.get(self._request_key(request))
        if event is None:
            return None
        event["request_classification"] = classification
        event["policy_classification"] = public_policy_classification(classification)
        event["allowed_by_policy"] = True
        event["lifecycle"] = "ALLOWED"
        event.update(policy_evaluated=True, policy_decision="ALLOW", policy_reason=classification)
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
        event = self._events_by_request.get(self._request_key(request))
        if event is None:
            return None
        event.update({
            "blocked_by_validator": True,
            "block_reason": reason,
            "request_classification": classification,
            "policy_classification": public_policy_classification(classification),
            "allowed_by_policy": False,
            "target_reached": False,
            "lifecycle": "BLOCKED",
            "duration_ms": self._duration(event),
            "policy_evaluated": True,
            "policy_decision": "BLOCK",
            "policy_reason": reason,
            "request_reached_network": False,
            "failure_category": reason,
        })
        event["traffic_category"] = "VALIDATOR_BLOCKED"
        return event

    def record_response(self, request: Any, status: int) -> dict[str, Any] | None:
        event = self._events_by_request.get(self._request_key(request))
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
            "request_reached_network": True,
            "response_seen": True,
            "response_status": int(status),
        })
        return event

    def record_failure(self, request: Any, error: str) -> dict[str, Any] | None:
        event = self._events_by_request.get(self._request_key(request))
        if event is not None and event.get("lifecycle") == "BLOCKED":
            event["request_failed"] = True
            return event
        if event is None or event.get("lifecycle") == "FAILED":
            return event
        if event.get("request_classification") == "UNKNOWN":
            event["request_classification"] = "APPLICATION_REQUEST"
        event.update({
            "error": sanitize_text(str(error).splitlines()[0], limit=1000),
            "target_reached": True if event.get("response_seen") else None,
            "lifecycle": "FAILED",
            "duration_ms": self._duration(event),
            "request_reached_network": True if event.get("response_seen") else None,
            "request_failed": True,
            "failure_category": "RESPONSE_BODY_FAILURE" if event.get("response_seen") else "NETWORK_FAILURE",
            "response_completed": False,
        })
        return event

    def mark_route_handler(self, request: Any) -> None:
        event = self._events_by_request.get(self._request_key(request))
        if event is not None:
            event["route_handler_seen"] = True

    def mark_dispatched(self, request: Any) -> None:
        event = self._events_by_request.get(self._request_key(request))
        if event is not None:
            event["request_dispatched"] = True

    def record_finished(self, request: Any) -> None:
        event = self._events_by_request.get(self._request_key(request))
        if event is None or not event.get("response_seen") or event.get("blocked_by_validator"):
            return
        try:
            response_end = request.timing.get("responseEnd")
        except Exception:
            response_end = None
        event["duration_ms"] = (
            round(response_end) if isinstance(response_end, (int, float)) and response_end >= 0
            else self._duration(event)
        )
        event["response_completed"] = True

    def finalize_pending(self) -> None:
        for event in self.events:
            if event.get("lifecycle") in {"REQUESTED", "ALLOWED"}:
                if event.get("request_classification") == "UNKNOWN":
                    event["request_classification"] = "APPLICATION_REQUEST"
                event["lifecycle"] = "PENDING_AT_SCAN_END"
                event["duration_ms"] = self._duration(event)
            event.pop("_started_at", None)

    @staticmethod
    def _request_key(request: Any) -> Any:
        # Async API wrappers can themselves be recreated for one underlying
        # request. The implementation's identity is stable throughout its
        # lifecycle; the weak key does not retain its sensitive raw contents.
        return request_identity(request)

    @staticmethod
    def _duration(event: dict[str, Any]) -> int | None:
        started = event.get("_started_at")
        return round((time.perf_counter() - started) * 1000) if isinstance(started, float) else None


def _observed_at() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
