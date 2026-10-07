from __future__ import annotations

from collections import Counter
import math
from typing import Any
from urllib.parse import urlparse

from app.navigation import classify_navigation_error
from app.network import public_policy_classification, safe_api_identity, summarize_route_api_coverage
from app.security import sanitize_text, sanitize_url


PASS_OUTCOMES = frozenset({"PASS", "PASS_WITH_WARNINGS"})
AUTH_OUTCOMES = frozenset({
    "ACCESS_RESTRICTED", "AUTH_FAILED", "AUTH_REQUIRED", "AUTH_TIMEOUT",
    "MFA_REQUIRED", "SESSION_EXPIRED",
})
LIMITED_OUTCOMES = frozenset({
    "CHALLENGE_REQUIRED", "DISCOVERED_BUT_NOT_SAFELY_ACTIVATABLE",
    "DISCOVERY_LIMITATION", "DOWNLOAD_OBSERVED",
})
FAILURE_OUTCOMES = frozenset({
    "TLS_ERROR",
    "DNS_ERROR",
    "NETWORK_ERROR",
    "HTTP_ERROR",
    "TIMEOUT",
    "NAVIGATION_ERROR",
    "VALIDATION_FAILED",
    "PAGE_RENDER_ERROR",
    "FAIL",
})
API_WARNING_TYPES = frozenset({
    "API_AUTHENTICATION_FAILURE", "API_AUTHORIZATION_FAILURE", "API_BAD_REQUEST",
    "API_CLIENT_ERROR", "API_CONFLICT", "API_CORS_FAILURE", "API_DNS_FAILURE",
    "API_NETWORK_FAILURE", "API_NOT_FOUND", "API_RATE_LIMITED", "API_REQUEST_FAILED",
    "API_RESPONSE_BODY_FAILURE", "API_SERVER_ERROR_OPTIONAL", "API_TIMEOUT", "API_TLS_FAILURE",
})


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
    if status is not None and status >= 400:
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
        elif status == 403:
            base_classification = "ACCESS_RESTRICTED"
        elif status is not None and status >= 400:
            base_classification = "HTTP_ERROR"
        else:
            base_classification = "PASS"

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
    if base_classification == "PASS" and render_classification:
        base_classification = render_classification
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
    api_status = _api_validation_status(structured_findings, loaded=loaded)
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
        "NOT_TESTED" if not loaded or classification in LIMITED_OUTCOMES else
        "WARNING" if "RENDER_STILL_BUSY" in finding_types else "PASS"
    )
    authentication_status = (
        classification if classification in AUTH_OUTCOMES else
        "CHALLENGE_REQUIRED" if classification == "CHALLENGE_REQUIRED" else
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
) -> dict[str, Any]:
    """Reconcile late responses onto their original route without re-navigation.

    Context-wide observation continues after one route's snapshot. Rebuild only
    its API findings from the final event stream; preserve document, auth, TLS,
    render, resource and performance evidence exactly as originally evaluated.
    The caller supplies events attributed to this route activation, not a slice
    of requests that happened to finish while another route was being scanned.
    """
    # health uses finding() above; a local import avoids a module import cycle.
    from app.health import api_health_findings

    target_events = [event for event in events if not event.get("blocked_by_validator")]
    items = deduplicate_findings([
        *[
            item for item in result.get("finding_details", [])
            if not str(item.get("type") or "").startswith("API_")
        ],
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
        if event.get("error") or (
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
        "api_status": _api_validation_status(items, loaded=loaded),
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
    return updated


def aggregate_report(
    results: list[dict[str, Any]],
    *,
    routes_discovered: int | None = None,
    routes_eligible: int | None = None,
    routes_queued: int | None = None,
    routes_remaining: int = 0,
    routes_skipped: int = 0,
    termination_reason: str = "DISCOVERY_EXHAUSTED",
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
    not_tested_reason = {
        "MAX_ROUTES_REACHED": "NOT_TESTED_MAX_ROUTES",
        "SCAN_TIMEOUT": "NOT_TESTED_TIMEOUT",
        "USER_CANCELLED": "NOT_TESTED_CANCELLED",
        "SESSION_EXPIRED": "NOT_TESTED_SESSION_EXPIRED",
    }.get(termination_reason, "NOT_TESTED")
    not_tested_reason_counts = (
        {not_tested_reason: not_tested_count} if not_tested_count else {}
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
        "auth_required_pages": classification_counts["AUTH_REQUIRED"],
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
        "api_failures": sum(int(result.get("api_failures", 0)) for result in results),
        "resource_failures": sum(int(result.get("resource_failure_count", 0)) for result in results),
        "console_failures": sum(
            len(result.get("console_errors", [])) + len(result.get("page_errors", []))
            for result in results
        ),
        "slow_pages": sum(bool(result.get("slow")) for result in results),
        "unsafe_actions_skipped": sum(int(result.get("unsafe_actions_skipped", 0)) for result in results),
        "read_only_blocks": sum(int(result.get("read_only_blocks", 0)) for result in results),
        "external_routes_skipped": sum(int(result.get("external_links_found", 0)) for result in results),
        "discovery_limitations": sum(int(result.get("discovery_limitations", 0)) for result in results),
        "classifications": dict(classification_counts),
        "termination_reason": termination_reason,
        "scan_completeness": (
            "CANCELLED" if termination_reason == "USER_CANCELLED"
            else "PARTIAL" if termination_reason == "SCAN_TIMEOUT"
            else "COMPLETE" if termination_reason == "DISCOVERY_EXHAUSTED" and not_tested_count == 0
            else "FAILED" if not results
            else "PARTIAL"
        ),
        "discovery_status": (
            "COMPLETE" if termination_reason == "DISCOVERY_EXHAUSTED" else "PARTIAL"
        ),
        "validation_status": (
            "COMPLETE" if not_tested_count == 0 else "PARTIAL"
        ),
    }
    invariants = {
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
        if "CERT" in upper or "TLS" in upper:
            return "API_TLS_FAILURE"
        if "NAME_NOT_RESOLVED" in upper:
            return "API_DNS_FAILURE"
        if "TIMEOUT" in upper:
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
            })
            item["calls"] += 1
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
            item["allowed_calls"] += 1
            status = event.get("status")
            if isinstance(status, int) and 200 <= status < 600:
                item[f"status_{status // 100}xx"] += 1
            if event.get("error") and not isinstance(status, int):
                item["network_failures"] += 1
            elif event.get("error"):
                item["response_body_failures"] += 1
            classification = (
                "API_RESPONSE_BODY_FAILURE" if event.get("error") and isinstance(status, int)
                else classify_api_status(status, event.get("error"))
            )
            if classification not in {"SUCCESS", "REDIRECT", "UNKNOWN"}:
                item["failure_classifications"][classification] += 1
            duration = event.get("duration_ms")
            if (
                isinstance(status, int) and 200 <= status < 600
                and not event.get("error")
                and event.get("response_completed", True)
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
        target_failures = item["status_4xx"] + item["status_5xx"] + item["network_failures"] + item["response_body_failures"]
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
            "HEALTHY"
        )
        item.update({
            "routes_using_endpoint": routes,
            "route_count": len(routes),
            "routes_observed": len(routes),
            "average_duration_ms": (
                round(sum(durations) / len(durations)) if durations else None
            ),
            "worst_duration_ms": max(durations) if durations else None,
            "failure_classifications": failures,
            "classifications": sorted(classifications),
            "policies": sorted({
                "READ_ONLY_BLOCK" if name == "BLOCKED_MUTATION" else name
                for name in classifications
            }),
            "policy_classifications": sorted({
                public_policy_classification(name) for name in classifications
            }),
            "classification_counts": classifications,
            "block_reasons": block_reasons,
            "importance_counts": importance,
            "traffic_categories": traffic_categories,
            "traffic_category": max(
                traffic_categories,
                key=traffic_categories.get,
                default="APPLICATION_API",
            ),
            "status_counts": status_counts,
            "target_failure_count": target_failures,
            "observation_outcome": observation_outcome,
            "health": (
                "FAILED" if item["status_5xx"] or item["network_failures"] else
                "DEGRADED" if item["status_4xx"] or item["response_body_failures"] else
                "NOT_EXECUTED" if not item["status_2xx"] and not item["status_3xx"] else
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
                "routes": set(),
            })
            item["calls"] += 1
            if event.get("blocked_by_validator"):
                item["validator_blocks"] += 1
            elif event.get("error") or (
                isinstance(event.get("status"), int) and event["status"] >= 400
            ):
                item["failures"] += 1
            route_id = event.get("initiating_route") or result_route_id
            if route_id:
                item["routes"].add(route_id)
    output: list[dict[str, Any]] = []
    for item in inventory.values():
        routes = sorted(item.pop("routes"))
        item.update({
            "routes_using_resource": routes,
            "route_count": len(routes),
            "health": "DEGRADED" if item["failures"] else "HEALTHY",
        })
        if not item["validator_blocks"]:
            item.pop("validator_blocks")
        output.append(item)
    return sorted(output, key=lambda item: (item["host"], item["path"], item["type"]))


def aggregate_resource_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate resources from the listener that remains installed for the whole scan."""
    return aggregate_resource_inventory([{"resources": events}])
