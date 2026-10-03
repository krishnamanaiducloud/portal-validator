from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlparse

from app.navigation import classify_navigation_error


PASS_OUTCOMES = frozenset({"PASS", "PASS_WITH_WARNINGS"})
AUTH_OUTCOMES = frozenset({"AUTH_REQUIRED", "AUTH_TIMEOUT", "MFA_REQUIRED", "SESSION_EXPIRED"})
FAILURE_OUTCOMES = frozenset({
    "AUTH_FAILED",
    "ACCESS_RESTRICTED",
    "TLS_ERROR",
    "DNS_ERROR",
    "NETWORK_ERROR",
    "HTTP_ERROR",
    "TIMEOUT",
    "NAVIGATION_ERROR",
    "VALIDATION_FAILED",
})


def finding(
    finding_type: str,
    severity: str,
    message: str,
    *,
    blocking: bool = False,
    resource: str | None = None,
    blocked_by_validator: bool = False,
    block_reason: str | None = None,
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
    failed_resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for header in missing_security_headers:
        items.append(finding(
            "MISSING_SECURITY_HEADER",
            "WARNING",
            f"Recommended security header is missing: {header}",
            resource=header,
        ))
    for message in console_errors:
        items.append(finding("CONSOLE_ERROR", "WARNING", message))
    for resource_failure in failed_resources:
        resource = resource_failure.get("url")
        if resource_failure.get("blocked_by_validator"):
            items.append(finding(
                "RESOURCE_SKIPPED",
                "INFO",
                "Resource was intentionally skipped by validator policy.",
                resource=resource,
                blocked_by_validator=True,
                block_reason=resource_failure.get("block_reason"),
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
    if any(item.get("severity") == "WARNING" for item in findings):
        return "PASS_WITH_WARNINGS"
    return "PASS"


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
) -> dict[str, Any]:
    loaded = error is None and status is not None
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
        missing_security_headers=missing_security_headers,
        console_errors=console_errors,
        failed_resources=failed_resources,
    )
    classification = determine_page_outcome(base_classification, structured_findings)
    page_load_status = "LOADED" if loaded else "FAILED_TO_LOAD"

    if classification == "TLS_ERROR":
        tls_status = "UNTRUSTED"
        tls_validation = "BROWSER"
        tls_detail = "Chromium rejected the HTTPS certificate chain with strict verification enabled."
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

    if not loaded or classification in AUTH_OUTCOMES:
        validation_status = "NOT_TESTED"
    elif classification in FAILURE_OUTCOMES:
        validation_status = "FAIL"
    elif severity_counts["WARNING"]:
        validation_status = "WARNING"
    else:
        validation_status = "PASS"

    category = "TLS_CERTIFICATE_ERROR" if classification == "TLS_ERROR" else (
        "VALIDATION_FINDINGS" if classification == "PASS_WITH_WARNINGS" else (
            None if classification == "PASS" else classification
        )
    )
    return {
        "classification": classification,
        "page_load_status": page_load_status,
        "validation_status": validation_status,
        "category": category,
        "tls_status": tls_status,
        "tls_basis": "CHROMIUM_STRICT" if tls_validation == "BROWSER" else tls_validation,
        "tls_detail": tls_detail,
        "tls": {
            "status": tls_status,
            "validation": tls_validation,
            "certificate_verification": tls_validation == "BROWSER",
            "bypass_used": False,
            "independent_certificate_inspection": False,
        },
        "security_headers_status": security_headers_status,
        "finding_details": structured_findings,
        "findings": len(structured_findings),
        "finding_occurrences": occurrence_count,
        "info_findings": severity_counts["INFO"],
        "warning_findings": severity_counts["WARNING"],
        "error_findings": severity_counts["ERROR"],
        "passed": loaded and classification in PASS_OUTCOMES,
    }


def aggregate_report(results: list[dict[str, Any]]) -> dict[str, Any]:
    load_counts = Counter(result["page_load_status"] for result in results)
    classification_counts = Counter(result["classification"] for result in results)
    validation_counts = Counter(result["validation_status"] for result in results)
    passed_pages = sum(bool(result.get("passed")) for result in results)
    failed_pages = sum(
        result["page_load_status"] == "FAILED_TO_LOAD"
        or result["classification"] in FAILURE_OUTCOMES
        for result in results
    )
    summary = {
        "total_pages": len(results),
        "loaded_pages": load_counts["LOADED"],
        "loaded": load_counts["LOADED"],
        "failed_to_load": load_counts["FAILED_TO_LOAD"],
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
        "not_tested": validation_counts["NOT_TESTED"],
        "total_load_time": sum(result.get("load_ms") or 0 for result in results),
        "duration_ms": sum(result.get("load_ms") or 0 for result in results),
        "classifications": dict(classification_counts),
    }
    return summary
