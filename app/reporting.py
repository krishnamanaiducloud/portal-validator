from __future__ import annotations

from collections import Counter
from copy import deepcopy
import math
from typing import Any
from urllib.parse import urlparse

from app.navigation import classify_navigation_error
from app.network import (
    classify_post_observation,
    public_policy_classification,
    safe_api_identity,
    summarize_post_diagnostics,
    summarize_post_observation,
    summarize_route_api_coverage,
)
from app.security import sanitize_text, sanitize_url


PASS_OUTCOMES = frozenset({"PASS", "PASS_WITH_WARNINGS"})
AUTH_OUTCOMES = frozenset({
    "AUTH_FAILED", "AUTH_REQUIRED", "AUTH_TIMEOUT",
    "MFA_REQUIRED", "SESSION_EXPIRED", "AUTHENTICATION_BLOCKED", "AUTHENTICATION_REQUIRED",
})
ACCESS_OUTCOMES = frozenset({"ACCESS_RESTRICTED", "CHALLENGE_REQUIRED"})
LIMITED_OUTCOMES = frozenset({
    "DISCOVERED_BUT_NOT_SAFELY_ACTIVATABLE",
    "DISCOVERY_LIMITATION", "DOWNLOAD_OBSERVED",
}) | ACCESS_OUTCOMES
FAILURE_OUTCOMES = frozenset({
    "TLS_ERROR",
    "DNS_ERROR",
    "NETWORK_ERROR",
    "HTTP_ERROR",
    "TIMEOUT",
    "NAVIGATION_ERROR",
    "VALIDATION_FAILED",
    "PAGE_RENDER_ERROR",
    "AUTHORIZATION_DENIED",
    "FAIL",
})
API_WARNING_TYPES = frozenset({
    "API_REQUEST_CANCELED", "API_OBSERVATION_INCOMPLETE",
    "API_AUTHENTICATION_FAILURE", "API_AUTHORIZATION_FAILURE", "API_BAD_REQUEST",
    "API_CLIENT_ERROR", "API_CONFLICT", "API_CORS_FAILURE", "API_DNS_FAILURE",
    "API_NETWORK_FAILURE", "API_NOT_FOUND", "API_RATE_LIMITED", "API_REQUEST_FAILED",
    "API_RESPONSE_BODY_FAILURE", "API_SERVER_ERROR_OPTIONAL", "API_TIMEOUT", "API_TLS_FAILURE",
})


_AUTHENTICATION_FAILURE_ALIASES = {
    "AUTH_FAILED": "AUTHENTICATION_FAILED",
    "AUTH_REQUIRED": "AUTHENTICATION_REQUIRED",
    "MFA_REQUIRED": "AUTHENTICATION_REQUIRED",
    "AUTH_TIMEOUT": "AUTHENTICATION_TIMEOUT",
    "AUTH_CONFIGURATION_ERROR": "AUTHENTICATION_CONFIGURATION_ERROR",
}
_AUTHENTICATION_FAILURE_GUIDANCE = {
    "AUTHENTICATION_BLOCKED": (
        "Review the blocked authentication transition and explicitly approved authentication hosts/endpoints. "
        "Preserve TLS, SSRF and read-only restrictions; do not broadly allow external destinations."
    ),
    "AUTHENTICATION_FAILED": "Complete the authorized login workflow and verify that the application accepts the resulting session.",
    "AUTHENTICATION_REQUIRED": (
        "Provide a current authorized session profile or complete the approved authentication workflow. "
        "A desktop browser session is separate from the validator browser."
    ),
    "AUTHENTICATION_TIMEOUT": "Check identity-provider reachability and the authorized login workflow before adjusting the authentication timeout.",
    "SESSION_EXPIRED": "Refresh the authorized session using the configured refresh workflow, then start a new scan.",
    "IDENTITY_PROVIDER_UNAVAILABLE": "Check the approved identity provider's availability and network reachability; retry after service is restored.",
    "AUTHENTICATION_CONFIGURATION_ERROR": "Ask the operator to verify the configured authentication policy and selected session profile without sharing their contents.",
    "APPLICATION_NOT_READY": "Verify that the authenticated application shell renders and that configured readiness conditions are correct.",
    "ACCESS_RESTRICTED": "The target denied access. Verify permission and any approved access requirements; HTTP 403 alone does not prove a missing login.",
    "CHALLENGE_REQUIRED": "Complete any permitted access challenge through an authorized workflow; do not bypass the target's browser security.",
    "TLS_ERROR": "Verify the mounted corporate CA chain and browser trust initialization. Keep certificate verification enabled.",
    "DNS_ERROR": "Check target DNS and the configured destination/network policy before starting a new scan.",
    "NETWORK_ERROR": "Check target connectivity and network policy before starting a new scan.",
    "HTTP_ERROR": "Review the captured main-document HTTP status and restore target availability before starting a new scan.",
    "NAVIGATION_ERROR": "Review the approved navigation flow and target availability before starting a new scan.",
    "TIMEOUT": "Review target navigation and application readiness within the configured scan timeouts.",
}
_AUTHENTICATION_FAILURE_STAGES = frozenset({
    "INITIALIZING", "INITIAL_NAVIGATION", "AUTHENTICATING", "AUTHENTICATED",
    "SESSION_ESTABLISHED", "SESSION_REFRESH", "APPLICATION_BOOTSTRAP", "APPLICATION_READY",
    "REQUEST_POLICY", "NAVIGATING", "AUTHENTICATION", "READINESS",
})


def _diagnostic_code(value: object, *, maximum: int = 96) -> str | None:
    """Accept machine classifications, never arbitrary exception text or secrets."""
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        return None
    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for character in value):
        return None
    return value


def create_authentication_error(
    category: str,
    *,
    stage: str = "AUTHENTICATING",
    http_status: int | None = None,
    method: str | None = None,
    endpoint: str | None = None,
    policy_decision: str | None = None,
    duration_ms: int | float | None = None,
) -> dict[str, Any]:
    """Produce strictly whitelisted, body/header-free bootstrap diagnostics.

    This records evidence; it cannot approve a destination or infer that an
    arbitrary HTTP error is an identity-provider/authentication failure. The
    orchestration gate must decide whether a failure is global.
    """
    category = _AUTHENTICATION_FAILURE_ALIASES.get(category, category)
    if category not in _AUTHENTICATION_FAILURE_GUIDANCE:
        category = "AUTHENTICATION_FAILED"
    safe_endpoint = None
    if isinstance(endpoint, str):
        try:
            safe_endpoint = safe_api_identity(endpoint)[0]
        except (TypeError, ValueError):
            safe_endpoint = None
        if safe_endpoint == "[REDACTED_URL]":
            safe_endpoint = None
    safe_duration = (
        round(duration_ms) if isinstance(duration_ms, (int, float))
        and not isinstance(duration_ms, bool) and math.isfinite(duration_ms) and duration_ms >= 0 else None
    )
    return {
        "category": category,
        "stage": stage if stage in _AUTHENTICATION_FAILURE_STAGES else "AUTHENTICATING",
        "http_status": (
            http_status if isinstance(http_status, int) and not isinstance(http_status, bool)
            and 100 <= http_status <= 599 else None
        ),
        "method": method.upper() if isinstance(method, str) and method.upper() in {
            "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE",
        } else None,
        "endpoint": safe_endpoint,
        "policy_decision": _diagnostic_code(policy_decision),
        "duration_ms": safe_duration,
        "remediation": _AUTHENTICATION_FAILURE_GUIDANCE[category],
    }


def _safe_authentication_diagnostics(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Authentication traffic is diagnostic evidence, never application API health."""
    output = []
    for item in items:
        if not isinstance(item, dict):
            continue
        diagnostic = create_authentication_error(
            str(item.get("category") or item.get("reason") or "AUTHENTICATION_FAILED"),
            stage=str(item.get("stage") or "AUTHENTICATING"),
            http_status=item.get("http_status", item.get("status")),
            method=item.get("method"),
            endpoint=item.get("endpoint", item.get("url")),
            policy_decision=item.get("policy_decision", item.get("policy_reason")),
            duration_ms=item.get("duration_ms"),
        )
        for key in ("reason", "policy_reason", "phase", "protocol"):
            value = _diagnostic_code(item.get(key))
            if value:
                diagnostic[key] = value
        for key in ("affects_authentication", "source_approved", "destination_approved", "flow_active"):
            if isinstance(item.get(key), bool):
                diagnostic[key] = item[key]
        for key in ("source_host", "destination_host"):
            value = item.get(key)
            if isinstance(value, str):
                # Host-only evidence must not admit URL credentials or queries.
                try:
                    parsed = urlparse("https://" + value)
                    if parsed.hostname and parsed.netloc == value and not parsed.username and not parsed.password:
                        diagnostic[key] = parsed.hostname.lower().rstrip(".")
                except ValueError:
                    pass
        if diagnostic not in output:
            output.append(diagnostic)
    return output


def apply_global_authentication_failure(
    report: dict[str, Any],
    error: dict[str, Any],
    *,
    diagnostics: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a failed, zero-coverage report without mutating prior scan data.

    Invoke only after the scan's global authentication/application-readiness
    gate failed, never for an individual denied route after readiness succeeds.
    Allowlisting retained metadata prevents stale/new route or API collections
    from surviving an authentication failure through an unexpected report key.
    """
    safe_error = create_authentication_error(
        str(error.get("category") or "AUTHENTICATION_FAILED"),
        stage=str(error.get("stage") or "AUTHENTICATING"),
        http_status=error.get("http_status"), method=error.get("method"),
        endpoint=error.get("endpoint"), policy_decision=error.get("policy_decision"),
        duration_ms=error.get("duration_ms"),
    )
    category = safe_error["category"]
    output = {
        key: deepcopy(report[key]) for key in (
            "report_schema_version", "validator_version", "build_identity", "scan_id", "run_id",
            "target", "scan_configuration", "scan_timing", "timings", "safety", "scan_lifecycle",
        ) if key in report
    }
    summary = aggregate_report(
        [], routes_discovered=0, routes_eligible=0, routes_queued=0,
        termination_reason=category, api_events=[],
    )
    summary.update({
        "status": "FAILED", "scan_status": "FAILED", "authentication_status": "FAILED",
        "execution_status": "FAILED", "execution_complete": False,
        "scan_completeness": "FAILED", "coverage_status": "NOT_STARTED",
        "coverage_grade": "NOT_STARTED", "coverage_complete": False,
        "discovery_status": "NOT_STARTED", "validation_status": "NOT_STARTED",
        "route_coverage": "NOT_STARTED", "routes_tested": 0, "tested_routes": 0,
        "coverage_detail": "Global authentication/application readiness failed; no application route or API results are accepted for this scan.",
        "coverage_reasons": [{"code": category, "count": 1}],
        "unique_apis": 0, "business_apis": 0, "api_calls": 0,
        "unique_resources": 0, "resource_calls": 0, "security_recommendations": 0,
        "menu_controls_discovered": 0, "menu_controls_activated": 0, "menu_controls_unresolved": 0,
        "view_controls_discovered": 0, "view_controls_activated": 0, "view_controls_unresolved": 0,
    })
    for key in (
        "authentication_duration_ms", "finalization_duration_ms", "total_scan_duration_ms",
    ):
        value = report.get("summary", {}).get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0:
            summary[key] = round(value)
    summary.update({
        "discovery_duration_ms": 0, "validation_duration_ms": 0,
        "average_route_duration_ms": 0, "p50_route_duration_ms": 0, "p95_route_duration_ms": 0,
    })
    coverage = {
        "discovery_status": "NOT_STARTED", "validation_status": "NOT_STARTED",
        "scan_completeness": "FAILED", "execution_status": "FAILED",
        "coverage_status": "NOT_STARTED", "coverage_grade": "NOT_STARTED",
        "coverage_scope": "OBSERVED_REACHABLE_SCOPE", "total_application_coverage": "UNKNOWN",
        "coverage_reasons": summary["coverage_reasons"], "termination_reason": category,
        **{key: summary[key] for key in (
            "routes_discovered", "routes_eligible", "routes_queued", "routes_validated", "routes_skipped",
            "routes_remaining", "routes_not_tested", "routes_tested", "tested_routes",
            "navigation_controls_discovered", "navigation_controls_activated", "navigation_controls_unresolved",
            "business_apis", "api_requests_observed", "api_responses_completed", "api_requests_blocked",
            "api_requests_failed", "api_requests_incomplete", "api_requests_canceled", "api_requests_not_actively_tested",
            "not_tested_reason_counts",
        )},
    }
    safe_diagnostics = _safe_authentication_diagnostics(
        diagnostics if diagnostics is not None else report.get("authentication_diagnostics", []),
    )
    output.update({
        "scan_status": "FAILED", "outcome": "FAILED", "authentication_status": "FAILED",
        "authentication_error": safe_error, "pages": 0, "summary": summary, "coverage": coverage,
        "navigation_coverage": {
            **navigation_coverage([], summary, []), "status": "NOT_STARTED",
        },
        "coverage_dimensions": {
            "execution": {"status": "FAILED", "reason": "Global authentication/application readiness failed."},
            "navigation": {"status": "NOT_STARTED", "reason": "No route results are accepted after global authentication/application-readiness failure."},
            "authentication": {"status": "FAILED", "reason": safe_error["remediation"]},
            "api": {"status": "NOT_STARTED", "reason": "Authentication diagnostics are not application API checks."},
        },
        "authentication_diagnostics": safe_diagnostics,
        "network_observation": {
            **{key: 0 for key in (
                "total_http_requests_observed", "api_requests_observed", "observed_requests", "policy_evaluated",
                "blocked_requests", "responses_seen", "responses_completed", "requests_failed",
                "browser_request_failed_events", "route_handler_seen", "request_dispatched", "read_only_blocks",
                "aggregated_requests", "requests_canceled", "requests_incomplete",
            )},
            "http_methods_observed": {}, "observed_methods": [], "scope": "APPLICATION_RESULTS_WITHHELD",
        },
        "resource_summary": {"scope": "APPLICATION_RESULTS_WITHHELD", "total_resources": 0},
        "session": {"status": "FAILED"},
        **{key: [] for key in (
            "results", "route_inventory", "not_tested_routes", "skipped_routes", "api_inventory",
            "api_request_occurrences", "business_api_inventory", "resource_inventory", "resource_details",
            "security_recommendations",
        )},
    })
    return output


def _api_validation_status(items: list[dict[str, Any]], *, loaded: bool) -> str:
    types = {str(item.get("type")) for item in items}
    return (
        "FAIL" if "API_SERVER_ERROR" in types else
        "WARNING" if types & API_WARNING_TYPES else
        "PASS" if loaded else "NOT_TESTED"
    )


def finding(
    finding_type: str,
    severity: str,
    message: str,
    *,
    blocking: bool = False,
    resource: str | None = None,
    blocked_by_validator: bool = False,
    block_reason: str | None = None,
    **metadata: Any,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "type": finding_type,
        "severity": severity,
        "impact": "BLOCKING" if blocking else (
            "INFORMATIONAL" if severity == "INFO" else "NON_BLOCKING"
        ),
        "blocking": blocking,
        "message": message,
        "count": 1,
    }
    if resource:
        item["resource"] = resource
    if blocked_by_validator:
        item["blocked_by_validator"] = True
        item["block_reason"] = block_reason or "validator_policy"
    item.update(metadata)
    return item


def deduplicate_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduplicated: dict[tuple[Any, ...], dict[str, Any]] = {}
    for item in items:
        key = (
            item.get("type"),
            item.get("severity"),
            bool(item.get("blocking")),
            item.get("resource"),
            item.get("message"),
            bool(item.get("blocked_by_validator")),
            item.get("block_reason"),
        )
        if key in deduplicated:
            deduplicated[key]["count"] += int(item.get("count", 1))
        else:
            deduplicated[key] = dict(item)
            deduplicated[key]["count"] = int(item.get("count", 1))
    return list(deduplicated.values())


def build_findings(
    *,
    classification: str,
    status: int | None,
    error: str | None,
    missing_security_headers: list[str],
    console_errors: list[str],
    page_errors: list[str] | None,
    failed_resources: list[dict[str, Any]],
    additional_findings: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = list(additional_findings or [])
    if classification == "AUTHENTICATION_BLOCKED":
        items.append(finding(
            "AUTHENTICATION_BLOCKED", "INFO",
            "The approved authentication flow was blocked before the application shell became ready. "
            "Review the narrowly scoped authentication policy or provide a current authorized session profile; "
            "authenticated application routes were not validated.",
            user_action_required=True,
        ))
    elif classification in {"AUTH_REQUIRED", "AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"}:
        items.append(finding(
            "AUTHENTICATION_REQUIRED", "INFO",
            "An authorized application session is required before protected route coverage can be evaluated.",
            user_action_required=True,
        ))
    for header in missing_security_headers:
        items.append(finding(
            "MISSING_SECURITY_HEADER",
            "WARNING",
            f"Recommended security header is missing: {header}",
            resource=header,
        ))
    for message in console_errors:
        items.append(finding("CONSOLE_ERROR", "WARNING", message))
    for message in page_errors or []:
        items.append(finding("PAGE_SCRIPT_ERROR", "WARNING", message))
    for resource_failure in failed_resources:
        resource = resource_failure.get("url")
        if resource_failure.get("blocked_by_validator"):
            reason = resource_failure.get("block_reason")
            if reason == "read_only_mutation_policy":
                items.append(finding(
                    "READ_ONLY_MUTATION_BLOCKED",
                    "WARNING",
                    "A mutating request was blocked to preserve read-only validation.",
                    resource=resource,
                    blocked_by_validator=True,
                    block_reason=reason,
                ))
            else:
                items.append(finding(
                    "RESOURCE_SKIPPED",
                    "INFO",
                    "Resource was intentionally skipped by validator policy.",
                    resource=resource,
                    blocked_by_validator=True,
                    block_reason=reason,
                ))
        elif resource_failure.get("main_document"):
            items.append(finding(
                "MAIN_DOCUMENT_FAILED",
                "ERROR",
                resource_failure.get("error") or "Main-document navigation failed.",
                resource=resource,
                blocking=True,
            ))
        else:
            items.append(finding(
                "RESOURCE_FAILED",
                "WARNING",
                resource_failure.get("error") or "A page resource failed to load.",
                resource=resource,
            ))
    if classification == "AUTHORIZATION_DENIED":
        items.append(finding(
            "AUTHORIZATION_DENIED", "ERROR",
            "The established application session is not authorized for this route (HTTP 403).",
            blocking=True,
        ))
    elif status in {403, 429}:
        items.append(finding(
            "HTTP_ACCESS_RESTRICTED" if status == 403 else "HTTP_RATE_LIMITED",
            "INFO",
            (
                "Main document returned HTTP 403 and denied access. The reason for the restriction "
                "was not established; application coverage is limited."
                if status == 403 else
                "Main document returned HTTP 429 and rate-limited access. Application coverage "
                "is limited; this response does not establish an authentication requirement."
            ),
        ))
    elif status is not None and status >= 400:
        if classification in AUTH_OUTCOMES:
            items.append(finding(
                "AUTHENTICATION_REQUIRED",
                "INFO",
                "The destination requires authentication.",
            ))
        else:
            items.append(finding(
                "HTTP_ERROR",
                "ERROR",
                f"Main document returned HTTP {status}.",
                blocking=True,
            ))
    if classification == "CHALLENGE_REQUIRED":
        items.append(finding(
            "ACCESS_CHALLENGE",
            "INFO",
            "An access challenge was observed instead of validated application content. "
            "Application coverage is limited; the challenge's cause was not established.",
        ))
    elif classification == "ACCESS_RESTRICTED" and status not in {403, 429}:
        items.append(finding(
            "ACCESS_RESTRICTED",
            "INFO",
            "The target restricted browser access. Application coverage is limited; "
            "the reason for the restriction was not established.",
        ))
    if error and not any(item["type"] == "MAIN_DOCUMENT_FAILED" for item in items):
        items.append(finding(
            "NAVIGATION_FAILURE",
            "ERROR",
            error,
            blocking=True,
        ))
    return deduplicate_findings(items)


def determine_page_outcome(
    base_classification: str,
    findings: list[dict[str, Any]],
) -> str:
    """Return the single authoritative page outcome."""
    if base_classification != "PASS":
        return base_classification
    if any(item.get("blocking") for item in findings):
        return "VALIDATION_FAILED"
    if any(item.get("severity") in {"WARNING", "ERROR"} for item in findings):
        return "PASS_WITH_WARNINGS"
    return "PASS"


FAILURE_DIMENSIONS = {
    "API_SERVER_ERROR": "API",
    "API_SERVER_ERROR_OPTIONAL": "API",
    "HTTP_ERROR": "DOCUMENT_HTTP",
    "MAIN_DOCUMENT_FAILED": "NAVIGATION",
    "NAVIGATION_FAILURE": "NAVIGATION",
    "BLANK_PAGE": "RENDER",
    "APPLICATION_ERROR_SURFACE": "RENDER",
    "PAGE_SCRIPT_ERROR": "CONSOLE",
    "RESOURCE_FAILED": "RESOURCES",
    "READ_ONLY_MUTATION_BLOCKED": "READ_ONLY_SAFETY",
}


def structured_warning_reasons(
    classification: str, findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Explain non-blocking warnings without copying arbitrary finding payloads."""
    if classification == "PASS":
        return []
    reasons: list[dict[str, Any]] = []
    for item in findings:
        if item.get("blocking") or item.get("severity") not in {"WARNING", "ERROR"}:
            continue
        original_code = str(item.get("type") or "UNKNOWN")
        component = "VALIDATION"
        if original_code in {"SLOW_PAGE", "SLOW_ROUTE"}:
            code, component = "SLOW_ROUTE", "PERFORMANCE"
        elif original_code in {"CONSOLE_ERROR", "CONSOLE_WARNING", "PAGE_SCRIPT_ERROR"}:
            code, component = "CONSOLE_WARNING", "CONSOLE"
        elif original_code == "MISSING_SECURITY_HEADER":
            code, component = "SECURITY_RECOMMENDATION", "SECURITY"
        elif original_code == "READ_ONLY_MUTATION_BLOCKED":
            code, component = "READ_ONLY_BLOCK", "READ_ONLY_SAFETY"
        elif original_code == "RESOURCE_FAILED":
            code, component = "NON_CRITICAL_RESOURCE_FAILURE", "RESOURCES"
        elif original_code.startswith("LARGE_"):
            code, component = original_code, "RESOURCES"
        elif original_code.startswith("API_"):
            code = (
                "BACKGROUND_API_WARNING" if item.get("importance") == "BACKGROUND" else
                "OPTIONAL_API_FAILURE" if item.get("importance") == "OPTIONAL" or original_code.endswith("_OPTIONAL") else
                "API_WARNING"
            )
            component = "API"
        elif original_code == "RENDER_STILL_BUSY":
            code, component = "APPLICATION_STILL_BUSY", "RENDER"
        else:
            code = "OTHER_NON_BLOCKING_WARNING"
        evidence: dict[str, Any] = {"original_code": sanitize_text(original_code, limit=100)}
        resource = item.get("resource")
        if isinstance(resource, str):
            evidence["resource"] = (
                sanitize_url(resource) if resource.startswith(("http://", "https://"))
                else sanitize_text(resource, limit=1000)
            )
        for key in (
            "http_status", "count", "observed_ms", "duration_ms", "threshold_ms",
            "threshold_bytes", "transfer_size_bytes", "encoded_body_size_bytes", "decoded_body_size_bytes",
        ):
            value = item.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0:
                evidence[key] = value
        reason: dict[str, Any] = {
            "code": code,
            "description": sanitize_text(item.get("message") or code.replace("_", " ").title(), limit=1000),
            "severity": "WARNING",
            "evidence": evidence,
            "affected_component": component,
        }
        for key, unit in (("threshold_ms", "ms"), ("threshold_bytes", "bytes")):
            if key in evidence:
                reason["threshold"] = {"value": evidence[key], "unit": unit}
                break
        reasons.append(reason)
    if classification == "PASS_WITH_WARNINGS" and not reasons:
        reasons.append({
            "code": "OTHER_NON_BLOCKING_WARNING",
            "description": "The route validated with a non-blocking warning; detailed warning evidence was unavailable.",
            "severity": "WARNING",
            "evidence": {"basis": "LEGACY_NON_BLOCKING_OUTCOME"},
            "affected_component": "VALIDATION",
        })
    return reasons


def failure_metadata(
    classification: str,
    findings: list[dict[str, Any]],
    error: str | None,
) -> tuple[str | None, str | None, list[dict[str, Any]]]:
    """Explain a failure independently of document HTTP status."""
    blocking = [item for item in findings if item.get("blocking")]
    evidence = blocking or (
        [item for item in findings if item.get("severity") == "ERROR"]
        if classification in FAILURE_OUTCOMES else []
    )
    if evidence:
        primary = evidence[0]
        dimension = FAILURE_DIMENSIONS.get(str(primary.get("type")), classification)
        return str(primary.get("message") or classification), dimension, evidence
    if classification in FAILURE_OUTCOMES:
        return error or classification.replace("_", " ").title(), classification, []
    return None, None, []


def classify_page_result(
    *,
    url: str,
    status: int | None,
    error: str | None,
    missing_security_headers: list[str],
    console_errors: list[str],
    failed_resources: list[dict[str, Any]],
    security_headers_tested: bool,
    authentication_classification: str | None = None,
    render_classification: str | None = None,
    additional_findings: list[dict[str, Any]] | None = None,
    page_errors: list[str] | None = None,
    route_transition_succeeded: bool = False,
    navigation_mode: str = "DOCUMENT_NAVIGATION",
    inherited_strict_tls: bool = False,
    security_headers_inherited: bool = False,
    include_security_header_findings: bool = True,
) -> dict[str, Any]:
    loaded = error is None and (status is not None or route_transition_succeeded)
    base_classification = authentication_classification
    if base_classification is None:
        if error:
            base_classification = classify_navigation_error(error)
        elif status == 401:
            base_classification = "AUTH_REQUIRED"
        elif status in {403, 429}:
            base_classification = "ACCESS_RESTRICTED"
        elif status is not None and status >= 400:
            base_classification = "HTTP_ERROR"
        else:
            base_classification = "PASS"

    if base_classification == "PASS" and render_classification:
        base_classification = render_classification
    structured_findings = build_findings(
        classification=base_classification,
        status=status,
        error=error,
        missing_security_headers=(
            missing_security_headers if include_security_header_findings else []
        ),
        console_errors=console_errors,
        page_errors=page_errors,
        failed_resources=failed_resources,
        additional_findings=additional_findings,
    )
    classification = determine_page_outcome(base_classification, structured_findings)
    warning_reasons = structured_warning_reasons(classification, structured_findings)
    page_load_status = (
        "LOADED" if loaded else
        "NOT_TESTED" if classification in LIMITED_OUTCOMES else
        "FAILED_TO_LOAD"
    )

    if classification == "TLS_ERROR":
        tls_status = "UNTRUSTED"
        tls_validation = "BROWSER"
        tls_detail = "Chromium rejected the HTTPS certificate chain with strict verification enabled."
    elif loaded and urlparse(url).scheme == "https" and inherited_strict_tls:
        tls_status = "TRUSTED"
        tls_validation = "INHERITED_BROWSER"
        tls_detail = (
            "Same-document route inherited the strict TLS browser context from its "
            "successfully validated HTTPS document; no new handshake is claimed."
        )
    elif loaded and urlparse(url).scheme == "https":
        tls_status = "TRUSTED"
        tls_validation = "BROWSER"
        tls_detail = "HTTPS connection successfully validated by Chromium using strict certificate verification."
    elif loaded:
        tls_status = "NOT_APPLICABLE"
        tls_validation = "NOT_APPLICABLE"
        tls_detail = "The final page used HTTP rather than HTTPS."
    else:
        tls_status = "NOT_TESTED"
        tls_validation = "NOT_TESTED"
        tls_detail = "Browser TLS trust could not be evaluated because main-document navigation did not complete."

    severity_counts = Counter(item["severity"] for item in structured_findings)
    occurrence_count = sum(int(item.get("count", 1)) for item in structured_findings)
    if not loaded or not security_headers_tested:
        security_headers_status = "NOT_TESTED"
    elif missing_security_headers:
        security_headers_status = "WARNING"
    else:
        security_headers_status = "PASS"

    if not loaded or classification in AUTH_OUTCOMES or classification in LIMITED_OUTCOMES:
        validation_status = "NOT_TESTED"
    elif classification in FAILURE_OUTCOMES:
        validation_status = "FAIL"
    elif classification == "PASS_WITH_WARNINGS" or severity_counts["WARNING"]:
        validation_status = "WARNING"
    else:
        validation_status = "PASS"

    category = "TLS_CERTIFICATE_ERROR" if classification == "TLS_ERROR" else (
        "VALIDATION_FINDINGS" if classification == "PASS_WITH_WARNINGS" else (
            None if classification == "PASS" else classification
        )
    )
    finding_types = {item["type"] for item in structured_findings}
    api_status = (
        "NOT_TESTED" if classification in ACCESS_OUTCOMES else
        _api_validation_status(structured_findings, loaded=loaded)
    )
    resource_status = (
        "WARNING" if finding_types & {"RESOURCE_FAILED", "RESOURCE_SKIPPED"} else
        "PASS" if loaded else "NOT_TESTED"
    )
    console_status = (
        "WARNING" if finding_types & {"CONSOLE_ERROR", "PAGE_SCRIPT_ERROR"} else
        "PASS" if loaded else "NOT_TESTED"
    )
    render_status = (
        "FAIL" if classification == "PAGE_RENDER_ERROR" else
        "NOT_TESTED" if not loaded or classification in LIMITED_OUTCOMES | AUTH_OUTCOMES else
        "WARNING" if "RENDER_STILL_BUSY" in finding_types else "PASS"
    )
    authentication_status = (
        classification if classification in AUTH_OUTCOMES else
        "NOT_TESTED" if classification in ACCESS_OUTCOMES else
        "PASS" if loaded else "NOT_TESTED"
    )
    failure_reason, failure_dimension, failure_details = failure_metadata(
        classification,
        structured_findings,
        error,
    )
    return {
        "classification": classification,
        "page_load_status": page_load_status,
        "validation_status": validation_status,
        "category": category,
        "tls_status": tls_status,
        "tls_basis": (
            "CHROMIUM_STRICT" if tls_validation == "BROWSER" else
            "INHERITED_STRICT_BROWSER_CONTEXT" if tls_validation == "INHERITED_BROWSER" else
            tls_validation
        ),
        "tls_detail": tls_detail,
        "tls": {
            "status": tls_status,
            "validation": tls_validation,
            "certificate_verification": tls_validation in {"BROWSER", "INHERITED_BROWSER"},
            "bypass_used": False,
            "independent_certificate_inspection": False,
            "inherited": tls_validation == "INHERITED_BROWSER",
            "new_handshake": tls_validation == "BROWSER",
        },
        "security_headers_status": security_headers_status,
        "security_headers_basis": (
            "INHERITED_DOCUMENT_RESPONSE" if security_headers_inherited else
            "DOCUMENT_RESPONSE" if security_headers_tested else
            "NOT_TESTED"
        ),
        "navigation_type": navigation_mode,
        "navigation_status": (
            "SUCCESS" if loaded else
            "NOT_TESTED" if classification in LIMITED_OUTCOMES else
            "FAILED"
        ),
        "render_status": render_status,
        "authentication_status": authentication_status,
        "access_status": (
            classification if classification in ACCESS_OUTCOMES else
            "NO_RESTRICTION_OBSERVED" if loaded and classification in PASS_OUTCOMES else
            "NOT_TESTED"
        ),
        "coverage_detail": (
            "An access challenge was observed instead of validated application content. "
            "Application coverage is limited; the challenge's cause was not established."
            if classification == "CHALLENGE_REQUIRED" else
            "The target restricted browser access. Application coverage is limited; "
            "an authentication requirement was not established."
            if classification == "ACCESS_RESTRICTED" else None
        ),
        "api_status": api_status,
        "resource_status": resource_status,
        "console_status": console_status,
        "performance_status": "WARNING" if finding_types & {"SLOW_PAGE", "SLOW_ROUTE"} else (
            "PASS" if loaded else "NOT_TESTED"
        ),
        "read_only_status": (
            "PROTECTED" if "READ_ONLY_MUTATION_BLOCKED" in finding_types else "ENFORCED"
        ),
        "failure_reason": failure_reason,
        "failure_dimension": failure_dimension,
        "failure_details": failure_details,
        "finding_details": structured_findings,
        "warning_reasons": warning_reasons,
        "warning_count": len(warning_reasons),
        "warning_codes": sorted({reason["code"] for reason in warning_reasons}),
        "findings": len(structured_findings),
        "finding_occurrences": occurrence_count,
        "info_findings": severity_counts["INFO"],
        "warning_findings": severity_counts["WARNING"],
        "error_findings": severity_counts["ERROR"],
        "passed": loaded and classification in PASS_OUTCOMES,
    }


def refresh_route_api_health(
    result: dict[str, Any], events: list[dict[str, Any]],
    *, resource_failures: list[dict[str, Any]] | None = None,
    console_errors: list[str] | None = None, page_errors: list[str] | None = None,
) -> dict[str, Any]:
    """Reconcile late responses onto their original route without re-navigation.

    Context-wide observation continues after one route's snapshot. Rebuild only
    its API findings from the final event stream; preserve document, auth, TLS,
    render and performance evidence exactly as originally evaluated. Optional
    final resource/console inputs replace only their corresponding findings.
    The caller supplies events attributed to this route activation, not a slice
    of requests that happened to finish while another route was being scanned.
    """
    # health uses finding() above; a local import avoids a module import cycle.
    from app.health import api_health_findings

    target_events = [event for event in events if not event.get("blocked_by_validator")]
    replaced_types = {"RESOURCE_FAILED", "RESOURCE_SKIPPED", "READ_ONLY_MUTATION_BLOCKED"}
    retained_findings = [
        item for item in result.get("finding_details", [])
        if not str(item.get("type") or "").startswith("API_")
        and (resource_failures is None or item.get("type") not in replaced_types)
        and (console_errors is None or item.get("type") != "CONSOLE_ERROR")
        and (page_errors is None or item.get("type") != "PAGE_SCRIPT_ERROR")
    ]
    final_resource_findings = build_findings(
        classification="PASS", status=None, error=None, missing_security_headers=[],
        console_errors=console_errors or [], page_errors=page_errors or [], failed_resources=resource_failures or [],
    ) if any(value is not None for value in (resource_failures, console_errors, page_errors)) else []
    items = deduplicate_findings([
        *retained_findings,
        *final_resource_findings,
        *api_health_findings(target_events),
    ])
    loaded = result.get("page_load_status") == "LOADED"
    previous_classification = str(result.get("classification") or "PASS")
    # VALIDATION_FAILED can be caused by an API snapshot alone. Re-evaluate its
    # retained non-API blocking findings, without changing genuine nav/auth/
    # render failures or asserting that an unloaded document became healthy.
    base_classification = (
        "PASS" if loaded and previous_classification in (PASS_OUTCOMES | {"VALIDATION_FAILED"})
        else previous_classification
    )
    classification = determine_page_outcome(base_classification, items)
    reasons = structured_warning_reasons(classification, items)
    severities = Counter(item.get("severity") for item in items)
    failure_reason, failure_dimension, failure_details = failure_metadata(
        classification, items, result.get("error"),
    )
    failed_events = [
        event for event in target_events
        if (
            event.get("error") and not event.get("request_canceled")
            and event.get("lifecycle_status") != "INCOMPLETE"
        ) or (
            isinstance(event.get("status"), int) and event["status"] >= 400
        )
    ]
    required_failures = sum(event.get("importance") == "REQUIRED" for event in failed_events)
    updated = dict(result)
    updated.update({
        "classification": classification,
        "category": (
            "TLS_CERTIFICATE_ERROR" if classification == "TLS_ERROR" else
            "VALIDATION_FINDINGS" if classification == "PASS_WITH_WARNINGS" else
            None if classification == "PASS" else classification
        ),
        "validation_status": (
            "NOT_TESTED" if not loaded or classification in AUTH_OUTCOMES or classification in LIMITED_OUTCOMES else
            "FAIL" if classification in FAILURE_OUTCOMES else
            "WARNING" if classification == "PASS_WITH_WARNINGS" else "PASS"
        ),
        "passed": loaded and classification in PASS_OUTCOMES,
        "finding_details": items,
        "findings": len(items),
        "finding_occurrences": sum(int(item.get("count", 1)) for item in items),
        "info_findings": severities["INFO"],
        "warning_findings": severities["WARNING"],
        "error_findings": severities["ERROR"],
        "warning_reasons": reasons,
        "warning_count": len(reasons),
        "warning_codes": sorted({reason["code"] for reason in reasons}),
        "failure_reason": failure_reason,
        "failure_dimension": failure_dimension,
        "failure_details": failure_details,
        "api_requests": list(events),
        "api_status": (
            "NOT_TESTED" if classification in ACCESS_OUTCOMES else
            _api_validation_status(items, loaded=loaded)
        ),
        "api_failures": len(failed_events),
        "failed_api_count": len(failed_events),
        "failed_required_api_count": required_failures,
        "failed_optional_api_count": len(failed_events) - required_failures,
        "api_network_failure_count": sum(
            bool(event.get("error")) and not isinstance(event.get("status"), int)
            for event in failed_events
        ),
        "read_only_blocks": sum(
            bool(event.get("blocked_by_validator")) and event.get("block_reason") in {
                "READ_ONLY_MUTATION_BLOCKED", "read_only_mutation_policy",
            }
            for event in events
        ),
        **summarize_route_api_coverage(events),
    })
    if resource_failures is not None:
        updated.update({
            "failed_resources": list(resource_failures),
            "resource_failure_count": sum(
                not failure.get("blocked_by_validator")
                and not failure.get("main_document")
                and ("CANCELED" not in request_failure_types(failure)
                     or isinstance(failure.get("status"), int) and failure["status"] >= 400)
                for failure in resource_failures
            ),
            "resource_status": (
                "WARNING" if any(item.get("type") in {"RESOURCE_FAILED", "RESOURCE_SKIPPED"} for item in items)
                else "PASS" if loaded else "NOT_TESTED"
            ),
        })
    if console_errors is not None:
        updated["console_errors"] = list(console_errors)
    if page_errors is not None:
        updated["page_errors"] = list(page_errors)
    if console_errors is not None or page_errors is not None:
        updated["console_status"] = (
            "WARNING" if any(item.get("type") in {"CONSOLE_ERROR", "PAGE_SCRIPT_ERROR"} for item in items)
            else "PASS" if loaded else "NOT_TESTED"
        )
    return updated


def _api_execution_evidence(event: dict[str, Any]) -> dict[str, bool]:
    """Read completion evidence without turning response headers into success.

    Older report snapshots only stored a final status. Continue supporting
    those snapshots, but require explicit completion for observer lifecycles.
    """
    status = event.get("status")
    has_status = isinstance(status, int) and not isinstance(status, bool) and 100 <= status < 600
    lifecycle = str(event.get("lifecycle_status") or "")
    has_lifecycle = any(key in event for key in (
        "lifecycle", "lifecycle_status", "response_seen", "response_completed", "request_dispatched",
    ))
    blocked = bool(event.get("blocked_by_validator"))
    canceled = bool(event.get("request_canceled")) or lifecycle == "CANCELED" or any(
        marker in str(event.get("error") or "").upper()
        for marker in ("ERR_ABORTED", "ABORTERROR", "NS_BINDING_ABORTED", "CANCELLED", "CANCELED")
    )
    failed = not blocked and not canceled and bool(
        event.get("request_failed") or event.get("error") or lifecycle == "FAILED"
    )
    completed = not blocked and not canceled and not failed and bool(event.get(
        "response_completed",
        lifecycle == "COMPLETED" if has_lifecycle else has_status,
    ))
    return {
        "blocked": blocked,
        "canceled": canceled,
        "failed": failed,
        "responded": not blocked and bool(event.get("response_seen", has_status)),
        "completed": completed,
        "incomplete": not (blocked or canceled or failed or completed) and (
            has_lifecycle or event.get("observation_outcome") == "INCOMPLETE"
        ),
    }


def unvisited_route_reason(termination_reason: str) -> str:
    """Use the same explicit stop reason in inventory rows and counters."""
    return {
        "MAX_ROUTES_REACHED": "NOT_TESTED_MAX_ROUTES",
        "SCAN_TIMEOUT": "NOT_TESTED_TIMEOUT",
        "USER_CANCELLED": "NOT_TESTED_CANCELLED",
        "SESSION_EXPIRED": "NOT_TESTED_SESSION_EXPIRED",
        "APPLICATION_NOT_READY": "NOT_TESTED_APPLICATION_NOT_READY",
        "AUTHENTICATION_BLOCKED": "NOT_TESTED_AUTHENTICATION_BLOCKED",
        "AUTH_REQUIRED": "NOT_TESTED_AUTHENTICATION_REQUIRED",
        "AUTHENTICATION_REQUIRED": "NOT_TESTED_AUTHENTICATION_REQUIRED",
        "MFA_REQUIRED": "NOT_TESTED_AUTHENTICATION_REQUIRED",
        "AUTH_FAILED": "NOT_TESTED_AUTHENTICATION_FAILED",
        "AUTH_TIMEOUT": "NOT_TESTED_AUTHENTICATION_TIMEOUT",
        "ACCESS_RESTRICTED": "NOT_TESTED_ACCESS_RESTRICTED",
        "CHALLENGE_REQUIRED": "NOT_TESTED_CHALLENGE_REQUIRED",
    }.get(termination_reason, "NOT_TESTED")


def aggregate_report(
    results: list[dict[str, Any]],
    *,
    routes_discovered: int | None = None,
    routes_eligible: int | None = None,
    routes_queued: int | None = None,
    routes_remaining: int = 0,
    routes_skipped: int = 0,
    termination_reason: str = "DISCOVERY_EXHAUSTED",
    api_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    load_counts = Counter(result["page_load_status"] for result in results)
    classification_counts = Counter(result["classification"] for result in results)
    validation_counts = Counter(result["validation_status"] for result in results)
    passed_pages = sum(bool(result.get("passed")) for result in results)
    failed_pages = sum(
        result["page_load_status"] == "FAILED_TO_LOAD"
        or result["classification"] in FAILURE_OUTCOMES
        for result in results
    )
    discovered_count = routes_discovered if routes_discovered is not None else len(results)
    eligible_count = routes_eligible if routes_eligible is not None else discovered_count
    validated_count = len(results)
    skipped_count = min(max(0, routes_skipped), max(0, eligible_count - validated_count))
    not_tested_count = max(0, eligible_count - validated_count - skipped_count)
    not_tested_reason = unvisited_route_reason(termination_reason)
    not_tested_reason_counts = (
        {not_tested_reason: not_tested_count} if not_tested_count else {}
    )
    # Finishing the queue is an execution fact, not proof that protected portal
    # content was reached or that route discovery had comprehensive visibility.
    coverage_reasons: Counter[str] = Counter()
    observed_api_requests: dict[object, dict[str, Any]] = {}
    for result in results:
        classification = result["classification"]
        if classification in AUTH_OUTCOMES:
            coverage_reasons["AUTHENTICATION_INCOMPLETE"] += 1
        elif classification in ACCESS_OUTCOMES:
            coverage_reasons[classification] += 1
        elif classification in LIMITED_OUTCOMES:
            coverage_reasons["DISCOVERY_LIMITATION"] += 1
        elif result["page_load_status"] != "LOADED" or classification in {
            "TLS_ERROR", "DNS_ERROR", "NETWORK_ERROR", "HTTP_ERROR", "TIMEOUT", "NAVIGATION_ERROR",
        }:
            coverage_reasons["NAVIGATION_FAILED"] += 1
        elif classification == "PAGE_RENDER_ERROR":
            coverage_reasons["APPLICATION_NOT_READY"] += 1
        if result.get("application_ready") is False and classification != "PAGE_RENDER_ERROR":
            coverage_reasons["APPLICATION_NOT_READY"] += 1
        if classification not in AUTH_OUTCOMES and result.get("authentication_status") in {
            "AUTHENTICATION_BLOCKED", "AUTHENTICATION_REQUIRED",
        }:
            coverage_reasons["AUTHENTICATION_INCOMPLETE"] += 1
        limitations = int(result.get("discovery_limitations", 0))
        if limitations:
            coverage_reasons["DISCOVERY_LIMITATION"] += limitations
        unresolved_controls = int(result.get("navigation_controls_unresolved", 0))
        if unresolved_controls:
            coverage_reasons["NAVIGATION_CONTROLS_UNRESOLVED"] += unresolved_controls
        for event in result.get("api_requests", []):
            request_key = event.get("request_id") or id(event)
            previous = observed_api_requests.get(request_key)
            if previous is None or previous.get("lifecycle_status") not in {
                "COMPLETED", "FAILED", "BLOCKED", "CANCELED",
            }:
                observed_api_requests[request_key] = event
    # The continuous observer is authoritative for late and discovery traffic
    # that may not belong to a completed route snapshot.
    for event in api_events or []:
        observed_api_requests[event.get("request_id") or id(event)] = event
    api_evidence = [_api_execution_evidence(event) for event in observed_api_requests.values()]
    lifecycle_counts = {
        "COMPLETED": sum(item["completed"] for item in api_evidence),
        "FAILED": sum(item["failed"] for item in api_evidence),
        "BLOCKED": sum(item["blocked"] for item in api_evidence),
        "CANCELED": sum(item["canceled"] and not item["blocked"] for item in api_evidence),
        "INCOMPLETE": sum(item["incomplete"] for item in api_evidence),
    }
    lifecycle_counts["OBSERVED_ONLY"] = len(api_evidence) - sum(lifecycle_counts.values())
    incomplete_api_requests = sum(item["incomplete"] for item in api_evidence)
    if incomplete_api_requests:
        coverage_reasons["API_OBSERVATION_INCOMPLETE"] = incomplete_api_requests
    application_routes_validated = sum(
        result["page_load_status"] == "LOADED"
        and result.get("application_ready") is not False
        and result.get("authentication_status") not in {"AUTHENTICATION_BLOCKED", "AUTHENTICATION_REQUIRED"}
        and result["classification"] not in AUTH_OUTCOMES | LIMITED_OUTCOMES
        and result["classification"] not in {
            "TLS_ERROR", "DNS_ERROR", "NETWORK_ERROR", "HTTP_ERROR", "TIMEOUT",
            "NAVIGATION_ERROR", "PAGE_RENDER_ERROR",
        }
        for result in results
    )
    if not_tested_count:
        coverage_reasons["ROUTES_NOT_TESTED"] = not_tested_count
    if skipped_count:
        coverage_reasons["ROUTES_SKIPPED"] = skipped_count
    if termination_reason != "DISCOVERY_EXHAUSTED":
        coverage_reasons[termination_reason] += 1
    if not application_routes_validated:
        coverage_reasons["NO_APPLICATION_ROUTES"] = 1
    coverage_complete = not coverage_reasons
    # Preserve the legacy coverage_status values for API compatibility while
    # exposing a clear four-state grade for consumers that need to distinguish
    # a complete scan from a scan limited by access or discovery boundaries.
    coverage_grade = (
        "UNKNOWN" if not results else
        "COMPLETE" if coverage_complete else
        "LIMITED" if not application_routes_validated else
        "PARTIAL"
    )
    execution_status = (
        "CANCELLED" if termination_reason == "USER_CANCELLED"
        else "TIMED_OUT" if termination_reason == "SCAN_TIMEOUT"
        else "FAILED" if termination_reason in {"ERROR", "SCAN_FAILED", "INTERNAL_ERROR"}
        else "COMPLETE"
    )
    summary = {
        "total_pages": len(results),
        "loaded_pages": load_counts["LOADED"],
        "loaded": load_counts["LOADED"],
        "failed_to_load": load_counts["FAILED_TO_LOAD"],
        "not_tested_pages": load_counts["NOT_TESTED"],
        "skipped_pages": load_counts["NOT_TESTED"],
        "passed_pages": passed_pages,
        "passed": passed_pages,
        "pass": passed_pages,
        "clean_pass_pages": classification_counts["PASS"],
        "pass_with_warnings": classification_counts["PASS_WITH_WARNINGS"],
        "auth_required_pages": classification_counts["AUTH_REQUIRED"] + classification_counts["AUTHENTICATION_REQUIRED"],
        "authentication_blocked_pages": classification_counts["AUTHENTICATION_BLOCKED"],
        "session_expired_pages": classification_counts["SESSION_EXPIRED"],
        "warning_pages": validation_counts["WARNING"],
        "failed_pages": failed_pages,
        "failed": failed_pages,
        "total_findings": sum(int(result.get("findings", 0)) for result in results),
        "findings": sum(int(result.get("findings", 0)) for result in results),
        "finding_occurrences": sum(int(result.get("finding_occurrences", 0)) for result in results),
        "info_findings": sum(int(result.get("info_findings", 0)) for result in results),
        "warning_findings": sum(int(result.get("warning_findings", 0)) for result in results),
        "warnings": sum(int(result.get("warning_findings", 0)) for result in results),
        "warning": sum(int(result.get("warning_findings", 0)) for result in results),
        "error_findings": sum(int(result.get("error_findings", 0)) for result in results),
        "errors": sum(int(result.get("error_findings", 0)) for result in results),
        "validation_failures": validation_counts["FAIL"],
        "fail": validation_counts["FAIL"],
        "not_tested": not_tested_count,
        "validation_not_tested": validation_counts["NOT_TESTED"],
        "total_load_time": sum(result.get("load_ms") or 0 for result in results),
        "duration_ms": sum(result.get("load_ms") or 0 for result in results),
        "routes_discovered": discovered_count,
        "routes_eligible": eligible_count,
        "routes_queued": routes_queued if routes_queued is not None else len(results),
        "routes_validated": validated_count,
        "routes_remaining": not_tested_count,
        "routes_not_tested": not_tested_count,
        "routes_skipped": skipped_count,
        "not_tested_reason_counts": not_tested_reason_counts,
        "healthy_routes": passed_pages,
        "routes_with_warnings": classification_counts["PASS_WITH_WARNINGS"],
        "auth_issues": sum(classification_counts[item] for item in AUTH_OUTCOMES),
        "access_issues": sum(classification_counts[item] for item in ACCESS_OUTCOMES),
        "access_restricted_pages": classification_counts["ACCESS_RESTRICTED"],
        "challenge_required_pages": classification_counts["CHALLENGE_REQUIRED"],
        "api_failures": sum(int(result.get("api_failures", 0)) for result in results),
        "api_requests_observed": len(api_evidence),
        "api_request_lifecycle_counts": lifecycle_counts,
        "api_requests_allowed": sum(
            not evidence["blocked"] and (
                event.get("policy_decision") == "ALLOW"
                or event.get("policy_decision") is None and event.get("allowed_by_policy") is True
            )
            for event, evidence in zip(observed_api_requests.values(), api_evidence)
        ),
        "api_requests_sent": sum(bool(event.get("request_dispatched")) for event in observed_api_requests.values()),
        "api_requests_responded": sum(item["responded"] for item in api_evidence),
        "api_responses_completed": sum(item["completed"] for item in api_evidence),
        "api_requests_blocked": sum(item["blocked"] for item in api_evidence),
        "api_requests_canceled": sum(item["canceled"] for item in api_evidence),
        "api_requests_incomplete": incomplete_api_requests,
        "api_http_failures": sum(
            not evidence["blocked"]
            and isinstance(event.get("status"), int) and not isinstance(event.get("status"), bool)
            and 400 <= event["status"] < 600
            for event, evidence in zip(observed_api_requests.values(), api_evidence)
        ),
        "api_requests_failed": sum(
            evidence["failed"] or (
                not evidence["blocked"]
                and isinstance(event.get("status"), int)
                and 400 <= event["status"] < 600
            )
            for event, evidence in zip(observed_api_requests.values(), api_evidence)
        ),
        "api_requests_not_actively_tested": len(api_evidence),
        "post_summary": summarize_post_observation(list(observed_api_requests.values())),
        "post_diagnostics": summarize_post_diagnostics(list(observed_api_requests.values())),
        "resource_failures": sum(int(result.get("resource_failure_count", 0)) for result in results),
        "console_failures": sum(
            len(result.get("console_errors", [])) + len(result.get("page_errors", []))
            for result in results
        ),
        "slow_pages": sum(bool(result.get("slow")) for result in results),
        "unsafe_actions_skipped": sum(int(result.get("unsafe_actions_skipped", 0)) for result in results),
        "navigation_controls_discovered": sum(
            int(result.get("navigation_controls_discovered", 0)) for result in results
        ),
        "navigation_controls_activated": sum(
            int(result.get("navigation_controls_activated", 0)) for result in results
        ),
        "navigation_controls_unresolved": sum(
            int(result.get("navigation_controls_unresolved", 0)) for result in results
        ),
        "read_only_blocks": sum(int(result.get("read_only_blocks", 0)) for result in results),
        "external_routes_skipped": sum(int(result.get("external_links_found", 0)) for result in results),
        "discovery_limitations": sum(int(result.get("discovery_limitations", 0)) for result in results),
        "classifications": dict(classification_counts),
        "termination_reason": termination_reason,
        "execution_status": execution_status,
        "execution_complete": execution_status == "COMPLETE",
        "coverage_status": (
            "COMPLETE" if coverage_complete
            else "NONE" if not application_routes_validated else "PARTIAL"
        ),
        "coverage_grade": coverage_grade,
        "coverage_complete": coverage_complete,
        "coverage_scope": "OBSERVED_REACHABLE_SCOPE",
        "total_application_coverage": "UNKNOWN",
        "coverage_detail": (
            "Coverage describes observed routes reachable within the configured scope and limits; "
            "the total number of application routes and APIs is unknown."
        ),
        "coverage_reasons": [
            {"code": code, "count": count} for code, count in sorted(coverage_reasons.items())
        ],
        "application_routes_validated": application_routes_validated,
        "scan_completeness": (
            "CANCELLED" if termination_reason == "USER_CANCELLED"
            else "PARTIAL" if termination_reason == "SCAN_TIMEOUT"
            else "COMPLETE" if coverage_complete
            else "FAILED" if not results
            else "PARTIAL"
        ),
        "discovery_status": (
            "UNKNOWN" if not results else
            "LIMITED" if any(code in coverage_reasons for code in (
                "DISCOVERY_LIMITATION", "NAVIGATION_CONTROLS_UNRESOLVED", "AUTHENTICATION_INCOMPLETE",
                "ACCESS_RESTRICTED", "CHALLENGE_REQUIRED", "NAVIGATION_FAILED", "APPLICATION_NOT_READY",
            )) else
            "COMPLETE" if termination_reason == "DISCOVERY_EXHAUSTED" and not not_tested_count else
            "PARTIAL"
        ),
        "validation_status": (
            "COMPLETE" if coverage_complete else "PARTIAL"
        ),
    }
    invariants = {
        "api_lifecycles_reconciled": sum(lifecycle_counts.values()) == len(api_evidence),
        "validated_not_above_eligible": validated_count <= eligible_count,
        "eligible_reconciled": (
            validated_count + not_tested_count + skipped_count == eligible_count
        ),
        "warnings_are_subset_of_passed": (
            classification_counts["PASS_WITH_WARNINGS"] <= passed_pages
        ),
    }
    if not all(invariants.values()):
        raise ValueError("Report counters are internally inconsistent")
    summary["counter_invariants"] = invariants
    return summary


def classify_api_status(status: int | None, error: str | None) -> str:
    if error:
        upper = error.upper()
        if "CERT" in upper or "TLS" in upper or "ERR_SSL_" in upper:
            return "API_TLS_FAILURE"
        if "NAME_NOT_RESOLVED" in upper:
            return "API_DNS_FAILURE"
        if any(marker in upper for marker in ("TIMEOUT", "TIMED_OUT", "TIMED OUT")):
            return "API_TIMEOUT"
        return "API_NETWORK_FAILURE"
    if status is None:
        return "UNKNOWN"
    if 200 <= status < 300:
        return "SUCCESS"
    if 300 <= status < 400:
        return "REDIRECT"
    return {
        400: "API_BAD_REQUEST",
        401: "API_AUTHENTICATION_FAILURE",
        403: "API_AUTHORIZATION_FAILURE",
        404: "API_NOT_FOUND",
        408: "API_TIMEOUT",
        409: "API_CONFLICT",
        429: "API_RATE_LIMITED",
    }.get(status, "API_SERVER_FAILURE" if status >= 500 else "API_CLIENT_ERROR")


def request_failure_types(event: dict[str, Any]) -> list[str]:
    """Keep HTTP, transfer completion and validator policy evidence separate."""
    evidence = _api_execution_evidence(event)
    if evidence["blocked"]:
        return ["POLICY_BLOCKED"]
    types = []
    status = event.get("status")
    if isinstance(status, int) and not isinstance(status, bool) and 400 <= status < 600:
        types.append(f"HTTP_{status // 100}XX")
    if evidence["canceled"]:
        types.append("CANCELED")
    elif evidence["failed"]:
        types.append("RESPONSE_BODY_FAILURE" if evidence["responded"] else "NETWORK_FAILURE")
    elif evidence["incomplete"]:
        types.append("INCOMPLETE")
    return types


def navigation_coverage(
    results: list[dict[str, Any]], summary: dict[str, Any],
    route_inventory: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Describe observed navigation without inventing a total application size."""
    inventory = results if route_inventory is None else route_inventory
    auth_blocked = sum(
        result.get("classification") in AUTH_OUTCOMES
        or result.get("authentication_status") in {
            "AUTHENTICATION_BLOCKED", "AUTHENTICATION_REQUIRED", "AUTH_REQUIRED", "SESSION_EXPIRED",
        }
        for result in inventory
    )
    menu_counts = [
        result.get("navigation_actions", {}).get("menus_expanded")
        for result in results
        if isinstance(result.get("navigation_actions"), dict)
    ]
    recorded_menu_counts = [count for count in menu_counts if isinstance(count, int) and not isinstance(count, bool)]
    return {
        "scope": "OBSERVED_REACHABLE_SCOPE",
        "total_application_coverage": "UNKNOWN",
        "controls_discovered": summary.get("navigation_controls_discovered"),
        # Control observations and route candidates are different populations.
        "safe_candidates": summary.get("routes_eligible", len(inventory)),
        "visited_views": len(results),
        "validated_views": summary.get("application_routes_validated", 0),
        "successful_views": sum(
            bool(result.get("passed")) and result.get("classification") in PASS_OUTCOMES
            and result.get("application_ready") is not False
            for result in results
        ),
        "menus_expanded": sum(recorded_menu_counts) if recorded_menu_counts else None,
        "failed_views": summary.get("failed_pages", 0),
        "skipped_unsafe_controls": summary.get("unsafe_actions_skipped", 0),
        "unreachable_views": sum(result.get("page_load_status") == "FAILED_TO_LOAD" for result in results),
        "authentication_blocked_views": auth_blocked,
        "application_not_ready_views": sum(result.get("application_ready") is False for result in results),
        "not_tested_views": summary.get("routes_not_tested", 0),
        "unresolved_controls": summary.get("navigation_controls_unresolved", 0),
        "limitations": summary.get("coverage_reasons", []),
        "control_count_basis": "OBSERVATIONS_ACROSS_VISITED_VIEWS",
        "candidate_count_basis": "UNIQUE_ELIGIBLE_ROUTE_IDENTITIES",
    }


def build_coverage_dimensions(
    results: list[dict[str, Any]], summary: dict[str, Any],
) -> dict[str, dict[str, str]]:
    """Keep execution, navigation, session readiness and passive APIs independent.

    Reasons are generated from counters/enums rather than raw authentication
    errors. Completing observed requests never proves that every API exists in
    the inventory, and processing a queue never proves login succeeded.
    """
    execution_status = str(summary.get("execution_status") or "UNKNOWN")
    if execution_status not in {"COMPLETE", "CANCELLED", "TIMED_OUT", "FAILED"}:
        execution_status = "UNKNOWN"
    execution_reason = {
        "COMPLETE": "The configured scan execution finished; this does not establish complete portal coverage.",
        "CANCELLED": "The scan was canceled before normal completion.",
        "TIMED_OUT": "The overall scan deadline was reached.",
        "FAILED": "The scan terminated with an execution failure.",
        "UNKNOWN": "Execution completion evidence was not recorded.",
    }[execution_status]

    navigation_status = str(summary.get("discovery_status") or "UNKNOWN")
    if navigation_status not in {"COMPLETE", "PARTIAL", "LIMITED"}:
        navigation_status = "UNKNOWN"
    navigation_codes = {
        str(item.get("code")) for item in summary.get("coverage_reasons", [])
        if isinstance(item, dict) and item.get("code") in {
            "AUTHENTICATION_INCOMPLETE", "APPLICATION_NOT_READY", "ACCESS_RESTRICTED", "CHALLENGE_REQUIRED",
            "NAVIGATION_FAILED", "NAVIGATION_CONTROLS_UNRESOLVED", "DISCOVERY_LIMITATION", "NO_APPLICATION_ROUTES",
            "ROUTES_NOT_TESTED", "ROUTES_SKIPPED", "MAX_ROUTES_REACHED", "SCAN_TIMEOUT", "USER_CANCELLED",
        }
    }
    navigation_reason = (
        "Observed reachable navigation was processed; total application coverage remains unknown."
        if navigation_status == "COMPLETE" else
        "Navigation coverage is limited by: " + ", ".join(sorted(navigation_codes)) + "."
        if navigation_codes else "No complete navigation-discovery evidence was recorded."
    )

    auth_states = {
        str(result.get(field) or "")
        for result in results for field in ("authentication_status", "classification")
    }
    if "AUTHENTICATION_BLOCKED" in auth_states:
        authentication_status, authentication_reason = (
            "BLOCKED", "The configured authentication policy blocked a required authentication transition.",
        )
    elif "SESSION_EXPIRED" in auth_states:
        authentication_status, authentication_reason = (
            "SESSION_EXPIRED", "The supplied browser session no longer grants access to the application.",
        )
    elif auth_states & {"AUTH_REQUIRED", "AUTHENTICATION_REQUIRED", "MFA_REQUIRED"}:
        authentication_status, authentication_reason = (
            "REQUIRED", "Authorized authentication or user action is required before protected-route discovery.",
        )
    elif auth_states & {"AUTH_FAILED", "AUTH_TIMEOUT"}:
        authentication_status, authentication_reason = (
            "FAILED", "Authentication did not complete within the configured workflow and limits.",
        )
    else:
        session_evidence = [
            any(event.get("state") == "SESSION_ESTABLISHED" for event in lifecycle.get("events", [])
                if isinstance(event, dict))
            for result in results
            if isinstance(lifecycle := result.get("browser_lifecycle"), dict)
        ]
        authentication_status, authentication_reason = (
            ("READY", "Browser session/navigation checks completed; application-shell readiness is evaluated separately.")
            if session_evidence and all(session_evidence) and len(session_evidence) == len(results) else
            ("UNKNOWN", "No explicit session-establishment lifecycle evidence was recorded; HTTP 200 alone is insufficient.")
        )

    observed = int(summary.get("api_requests_observed", 0))
    incomplete = int(summary.get("api_requests_incomplete", 0))
    canceled = int(summary.get("api_requests_canceled", 0))
    blocked = int(summary.get("api_requests_blocked", 0))
    api_status = (
        "NOT_OBSERVED" if not observed else
        "PARTIAL" if incomplete or canceled else "POLICY_LIMITED" if blocked else "OBSERVED"
    )
    api_reason = (
        "No API requests were observed; this is not evidence that the portal has no APIs."
        if not observed else
        f"Passive observation recorded {observed} requests, {incomplete} unfinished, {canceled} canceled and {blocked} policy-blocked. "
        "API health is reported separately; unobserved endpoints and total API coverage remain unknown."
    )
    return {
        "execution": {"status": execution_status, "reason": execution_reason},
        "navigation": {"status": navigation_status, "reason": navigation_reason},
        "authentication": {"status": authentication_status, "reason": authentication_reason},
        "api": {"status": api_status, "reason": api_reason},
    }


def aggregate_api_inventory(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate naturally observed API traffic without request headers or bodies."""
    inventory: dict[tuple[str, str, str], dict[str, Any]] = {}
    for result in results:
        result_route_id = result.get("normalized_route_identity") or result.get("url")
        for event in result.get("api_requests", []):
            event["aggregation_seen"] = True
            event_url = str(event.get("url") or "")
            _, safe_host, safe_endpoint = safe_api_identity(event_url)
            host = str(event.get("host") or safe_host).lower()
            endpoint = str(event.get("endpoint") or safe_endpoint)
            if not host or not endpoint.startswith("/"):
                continue
            method = str(event.get("method") or "GET").upper()
            protocol = str(event.get("protocol") or "REST")
            key = (method, host, endpoint)
            item = inventory.setdefault(key, {
                "method": method,
                "host": host,
                "endpoint": endpoint,
                "raw_sanitized_endpoint": endpoint,
                "normalized_endpoint": endpoint,
                "normalization_confidence": "EXACT",
                "category": protocol,
                "calls": 0,
                "allowed_calls": 0,
                "blocked_calls": 0,
                "observed_calls": 0,
                "sent_calls": 0,
                "responded_calls": 0,
                "completed_calls": 0,
                "approved_read_only_calls": 0,
                "executed_approved_calls": 0,
                "failed_calls": 0,
                "failure_count": 0,
                "canceled_calls": 0,
                "incomplete_calls": 0,
                "business_success_calls": 0,
                "status_2xx": 0,
                "status_3xx": 0,
                "status_4xx": 0,
                "status_5xx": 0,
                "network_failures": 0,
                "response_body_failures": 0,
                "validator_blocks": 0,
                "blocked_count": 0,
                "discovery_phase_count": 0,
                "validation_phase_count": 0,
                "authentication_phase_count": 0,
                "application_bootstrap_phase_count": 0,
                "route_validation_phase_count": 0,
                "session_refresh_phase_count": 0,
                "first_seen": None,
                "last_seen": None,
                "durations_ms": [],
                "routes": set(),
                "failure_classifications": Counter(),
                "request_classifications": Counter(),
                "block_reasons": Counter(),
                "importance": Counter(),
                "traffic_categories": Counter(),
                "traffic_roles": Counter(),
                "post_classifications": Counter(),
                "response_statuses": Counter(),
                "authentication_classifications": Counter(),
                "validation_reasons": Counter(),
                "failure_types": Counter(),
                "lifecycle_status_counts": Counter(),
            })
            item["calls"] += 1
            item["observed_calls"] += 1
            item["failure_types"].update(request_failure_types(event))
            item["lifecycle_status_counts"][str(event.get("lifecycle_status") or "NOT_RECORDED")] += 1
            post_summary = summarize_post_observation([event])
            item["approved_read_only_calls"] += post_summary["approved_read_only_calls"]
            item["executed_approved_calls"] += post_summary["executed_approved_calls"]
            item["post_classifications"].update(classify_post_observation(event))
            request_classification = str(event.get("request_classification") or "")
            authentication_classification = (
                "AUTH_BOOTSTRAP" if request_classification == "AUTH_FLOW" else
                "SESSION_REFRESH" if request_classification == "SESSION_REFRESH" else
                "AUTHENTICATION_ATTEMPT"
                if str(event.get("phase") or "").upper() == "AUTHENTICATION" else
                "NOT_AUTHENTICATION"
            )
            item["authentication_classifications"][authentication_classification] += 1
            role = str(event.get("traffic_role") or event.get("traffic_category") or "UNCLASSIFIED_API")
            item["traffic_roles"][role] += 1
            evidence = _api_execution_evidence(event)
            canceled = evidence["canceled"]
            item["sent_calls"] += bool(event.get("request_dispatched"))
            item["responded_calls"] += evidence["responded"]
            item["completed_calls"] += evidence["completed"]
            item["canceled_calls"] += canceled
            item["failed_calls"] += evidence["failed"]
            item["incomplete_calls"] += evidence["incomplete"]
            if evidence["blocked"]:
                item["validation_reasons"]["BLOCKED_BY_POLICY"] += 1
            elif canceled:
                item["validation_reasons"]["REQUEST_CANCELED"] += 1
            elif evidence["failed"]:
                item["validation_reasons"][
                    "RESPONSE_BODY_FAILURE" if evidence["responded"] else "TRANSPORT_FAILURE"
                ] += 1
            elif evidence["incomplete"]:
                item["validation_reasons"][
                    "RESPONSE_BODY_NOT_COMPLETED" if evidence["responded"] else
                    "NOT_DISPATCHED_BEFORE_SCAN_END" if event.get("request_dispatched") is False else
                    "NO_RESPONSE_BEFORE_SCAN_END"
                ] += 1
            elif not evidence["completed"]:
                item["validation_reasons"]["REQUEST_OBSERVED_ONLY"] += 1
            phase = str(event.get("phase") or "VALIDATION").upper()
            phase_field = {
                "DISCOVERY": "discovery_phase_count",
                "AUTHENTICATION": "authentication_phase_count",
                "APPLICATION_BOOTSTRAP": "application_bootstrap_phase_count",
                "ROUTE_VALIDATION": "route_validation_phase_count",
                "SESSION_REFRESH": "session_refresh_phase_count",
            }.get(phase, "validation_phase_count")
            item[phase_field] += 1
            observed_at = event.get("observed_at")
            if observed_at is not None:
                item["first_seen"] = item["first_seen"] or observed_at
                item["last_seen"] = observed_at
            item["importance"][str(event.get("importance") or "UNKNOWN")] += 1
            item["traffic_categories"][str(
                event.get("traffic_category") or "APPLICATION_API"
            )] += 1
            route_id = event.get("initiating_route") or result_route_id
            if route_id:
                item["routes"].add(route_id)
            item["request_classifications"][str(
                event.get("request_classification") or "UNKNOWN"
            )] += 1
            if event.get("blocked_by_validator"):
                item["validator_blocks"] += 1
                item["blocked_count"] += 1
                item["blocked_calls"] += 1
                item["block_reasons"][str(
                    event.get("block_reason") or "VALIDATOR_POLICY_BLOCK"
                )] += 1
                continue
            item["allowed_calls"] += (
                event.get("policy_decision") == "ALLOW" if "policy_decision" in event
                else event.get("allowed_by_policy", True)
            )
            status = event.get("status")
            item["failure_count"] += bool(
                (isinstance(status, int) and 400 <= status < 600)
                or evidence["failed"]
            )
            if isinstance(status, int) and 200 <= status < 600:
                item[f"status_{status // 100}xx"] += 1
                item["response_statuses"][str(status)] += 1
                if status >= 400:
                    item["validation_reasons"][f"HTTP_{status}"] += 1
            if canceled:
                item["failure_classifications"]["REQUEST_CANCELED"] += 1
            elif evidence["failed"] and not evidence["responded"]:
                item["network_failures"] += 1
            elif evidence["failed"]:
                item["response_body_failures"] += 1
            classification = "UNKNOWN" if canceled else (
                "API_RESPONSE_BODY_FAILURE" if event.get("error") and isinstance(status, int)
                else classify_api_status(status, event.get("error"))
            )
            if classification not in {"SUCCESS", "REDIRECT", "UNKNOWN"}:
                item["failure_classifications"][classification] += 1
            if role == "APPLICATION_API" and isinstance(status, int) and 200 <= status < 400 and evidence["completed"]:
                item["business_success_calls"] += 1
            duration = event.get("duration_ms")
            if (
                isinstance(status, int) and 200 <= status < 600
                and evidence["completed"]
                and isinstance(duration, (int, float)) and duration >= 0
            ):
                item["durations_ms"].append(round(duration))

    output: list[dict[str, Any]] = []
    for item in inventory.values():
        durations = item.pop("durations_ms")
        routes = sorted(item.pop("routes"))
        failures = dict(item.pop("failure_classifications"))
        classifications = dict(item.pop("request_classifications"))
        block_reasons = dict(item.pop("block_reasons"))
        importance = dict(item.pop("importance"))
        traffic_categories = dict(item.pop("traffic_categories"))
        traffic_roles = dict(item.pop("traffic_roles"))
        post_classifications = dict(item.pop("post_classifications"))
        response_statuses = dict(item.pop("response_statuses"))
        authentication_classifications = dict(item.pop("authentication_classifications"))
        reason_counts = item.pop("validation_reasons")
        failure_types = dict(item.pop("failure_types"))
        lifecycle_status_counts = dict(item.pop("lifecycle_status_counts"))
        target_failures = item["failure_count"]
        status_counts = {
            "2xx": item["status_2xx"],
            "3xx": item["status_3xx"],
            "4xx": item["status_4xx"],
            "5xx": item["status_5xx"],
            "network": item["network_failures"],
        }
        observation_outcome = (
            "FAILED" if item["status_5xx"] or item["network_failures"] else
            "WARNING" if item["status_4xx"] or item["response_body_failures"] else
            "BLOCKED_BY_VALIDATOR"
            if item["blocked_calls"] and not item["allowed_calls"] else
            "WARNING" if item["blocked_calls"] else
            "INCOMPLETE" if item["incomplete_calls"] or item["canceled_calls"] else
            "NOT_EXECUTED" if not item["completed_calls"] else
            "HEALTHY"
        )
        validation_status = (
            "BLOCKED" if item["blocked_calls"] and not item["allowed_calls"] else
            "FAILED" if item["status_4xx"] or item["status_5xx"] or item["network_failures"] or item["response_body_failures"] else
            "INCOMPLETE" if item["incomplete_calls"] or item["canceled_calls"] else
            "PARTIALLY_VALIDATED" if item["blocked_calls"] and item["completed_calls"] else
            "VALIDATED" if item["completed_calls"] else
            "OBSERVED" if item["observed_calls"] else
            "NOT_TESTED"
        )
        reason_messages = {
            "BLOCKED_BY_POLICY": "The validator blocked this request under the configured safety policy.",
            "REQUEST_CANCELED": "The browser canceled this request before response completion.",
            "TRANSPORT_FAILURE": "The request failed before an HTTP response was observed.",
            "RESPONSE_BODY_FAILURE": "HTTP response headers arrived, but the response failed before completion.",
            "RESPONSE_BODY_NOT_COMPLETED": "HTTP response headers arrived; response completion was not observed.",
            "RESPONSE_NOT_OBSERVED": "No HTTP response was observed before the observation cutoff.",
            "NO_RESPONSE_BEFORE_SCAN_END": "The request was observed, but no HTTP response arrived before the observation cutoff.",
            "NOT_DISPATCHED_BEFORE_SCAN_END": "The request was observed, but transmission was not confirmed before the observation cutoff.",
            "REQUEST_OBSERVED_ONLY": "Only the request was observed; completed response evidence is unavailable.",
        }
        reasons = [
            {
                "code": code,
                "count": count,
                "message": (
                    f"The endpoint returned HTTP {code.removeprefix('HTTP_')}."
                    if code.startswith("HTTP_") else reason_messages[code]
                ),
            }
            for code, count in sorted(reason_counts.items())
        ]
        item.update({
            "routes_using_endpoint": routes,
            "route_count": len(routes),
            "routes_observed": len(routes),
            "average_duration_ms": (
                round(sum(durations) / len(durations)) if durations else None
            ),
            "worst_duration_ms": max(durations) if durations else None,
            "failure_classifications": failures,
            "failure_types": sorted(failure_types),
            "failure_type_counts": failure_types,
            "lifecycle_status_counts": lifecycle_status_counts,
            "classifications": sorted(classifications),
            "policies": sorted({
                "READ_ONLY_BLOCK" if name == "BLOCKED_MUTATION" else name
                for name in classifications
            }),
            "policy_classifications": sorted({
                public_policy_classification(name) for name in classifications
            }),
            "classification_counts": classifications,
            "post_classifications": sorted(post_classifications),
            "post_classification_counts": post_classifications,
            "response_status_counts": response_statuses,
            "authentication_classifications": sorted(authentication_classifications),
            "authentication_classification_counts": authentication_classifications,
            "block_reasons": block_reasons,
            "importance_counts": importance,
            "traffic_categories": traffic_categories,
            "traffic_roles": traffic_roles,
            "traffic_role": max(traffic_roles, key=traffic_roles.get, default="UNCLASSIFIED_API"),
            "traffic_category": max(
                traffic_categories,
                key=traffic_categories.get,
                default="APPLICATION_API",
            ),
            "status_counts": status_counts,
            "target_failure_count": target_failures,
            "observation_outcome": observation_outcome,
            "validation_status": validation_status,
            "validation_outcome": (
                "PASSED" if validation_status == "VALIDATED" else
                "PARTIAL" if validation_status == "PARTIALLY_VALIDATED" else
                "NOT_TESTED" if validation_status == "OBSERVED" else validation_status
            ),
            "validation_basis": "PASSIVE_BROWSER_OBSERVATION",
            "actively_tested": False,
            "active_validation_status": "NOT_ACTIVELY_TESTED",
            "validation_reasons": reasons,
            "validation_reason": " ".join(reason["message"] for reason in reasons) or (
                "A completed browser response was observed; no independent API probe was executed."
            ),
            "observation_status": (
                "BLOCKED_BY_POLICY" if observation_outcome == "BLOCKED_BY_VALIDATOR"
                else observation_outcome
            ),
            "health": (
                "FAILED" if item["status_5xx"] or item["network_failures"] else
                "DEGRADED" if item["status_4xx"] or item["response_body_failures"] else
                "INCOMPLETE" if item["incomplete_calls"] or item["canceled_calls"] else
                "NOT_EXECUTED" if not item["completed_calls"] else
                "HEALTHY"
            ),
        })
        output.append(item)
    return sorted(output, key=lambda item: (item["host"], item["endpoint"], item["method"]))


def aggregate_api_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate the scan-wide listener stream, including authentication and late events."""
    return aggregate_api_inventory([{"api_requests": events}])


def aggregate_security_recommendations(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate document-level recommendations across inherited SPA routes."""
    recommendations: dict[str, set[str]] = {}
    for result in results:
        if result.get("security_headers_basis") != "DOCUMENT_RESPONSE":
            continue
        route = result.get("normalized_route_identity") or result.get("url")
        for header in result.get("missing_security_headers", []):
            recommendations.setdefault(str(header), set()).add(str(route))
    return [
        {
            "type": "MISSING_SECURITY_HEADER",
            "header": header,
            "severity": "RECOMMENDATION",
            "impact": "NON_BLOCKING",
            "affected_documents": sorted(routes),
            "affected_document_count": len(routes),
        }
        for header, routes in sorted(recommendations.items())
    ]


def aggregate_resource_inventory(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate browser-loaded resources without request headers, bodies, or cookies."""
    inventory: dict[tuple[str, str, str], dict[str, Any]] = {}
    for result in results:
        result_route_id = result.get("normalized_route_identity") or result.get("url")
        for event in result.get("resources", []):
            parsed = urlparse(str(event.get("url") or ""))
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            resource_type = str(event.get("resource_type") or "other").upper()
            key = (parsed.hostname.lower(), parsed.path or "/", resource_type)
            item = inventory.setdefault(key, {
                "host": parsed.hostname.lower(),
                "path": parsed.path or "/",
                "type": resource_type,
                "calls": 0,
                "failures": 0,
                "validator_blocks": 0,
                "methods": Counter(),
                "first_seen": None,
                "last_seen": None,
                "response_status_counts": Counter(),
                "failure_type_counts": Counter(),
                "lifecycle_status_counts": Counter(),
                "routes": set(),
            })
            item["calls"] += 1
            method = event.get("method")
            if isinstance(method, str) and method:
                item["methods"][method.upper()] += 1
            observed_at = event.get("observed_at")
            if observed_at:
                item["first_seen"] = item["first_seen"] or observed_at
                item["last_seen"] = observed_at
            status = event.get("status")
            if isinstance(status, int) and not isinstance(status, bool) and 100 <= status < 600:
                item["response_status_counts"][str(status)] += 1
            item["failure_type_counts"].update(request_failure_types(event))
            item["lifecycle_status_counts"][str(event.get("lifecycle_status") or "NOT_RECORDED")] += 1
            if event.get("blocked_by_validator"):
                item["validator_blocks"] += 1
            elif _api_execution_evidence(event)["failed"] or (
                isinstance(status, int) and not isinstance(status, bool) and 400 <= status < 600
            ):
                item["failures"] += 1
            route_id = event.get("initiating_route") or result_route_id
            if route_id:
                item["routes"].add(route_id)
    output: list[dict[str, Any]] = []
    for item in inventory.values():
        routes = sorted(item.pop("routes"))
        methods = dict(item.pop("methods"))
        failure_types = dict(item["failure_type_counts"])
        item.update({
            "method": next(iter(methods)) if len(methods) == 1 else "MULTIPLE" if methods else None,
            "method_counts": methods,
            "routes_using_resource": routes,
            "route_count": len(routes),
            "health": (
                "DEGRADED" if item["failures"] else
                "BLOCKED_BY_POLICY" if item["validator_blocks"] == item["calls"] else
                "PARTIAL" if item["validator_blocks"] else
                "INCOMPLETE" if failure_types.get("INCOMPLETE") or failure_types.get("CANCELED") else
                "HEALTHY"
            ),
            "failure_types": sorted(failure_types),
            "failure_type_counts": failure_types,
            "response_status_counts": dict(item["response_status_counts"]),
            "lifecycle_status_counts": dict(item["lifecycle_status_counts"]),
        })
        if not item["validator_blocks"]:
            item.pop("validator_blocks")
        output.append(item)
    return sorted(output, key=lambda item: (item["host"], item["path"], item["type"]))


def aggregate_resource_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate resources from the listener that remains installed for the whole scan."""
    return aggregate_resource_inventory([{"resources": events}])
