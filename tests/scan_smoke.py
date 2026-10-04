"""Live, opt-in HTTP smoke test for a running Portal Validator container."""

import json
import os
import urllib.request


base_url = os.environ.get("PORTAL_VALIDATOR_URL", "http://portal-validator:8080")
target = os.environ.get("PORTAL_VALIDATOR_SMOKE_TARGET", "https://google.com")
payload = json.dumps({
    "target": target,
    "max_pages": 1,
    "max_depth": 0,
    "timeout_ms": 30000,
    "total_timeout_ms": 60000,
    "render_settle_ms": 250,
    "authentication": {"mode": "none"},
}).encode("utf-8")
request = urllib.request.Request(
    f"{base_url}/api/scan",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=90) as response:
    report = json.load(response)

assert report["pages"] == 1, report
assert report["safety"]["read_only_enforced"] is True, report
assert report["results"][0]["tls"]["bypass_used"] is False, report
assert report["summary"]["routes_validated"] == 1, report
print(json.dumps({
    "classification": report["results"][0]["classification"],
    "http_status": report["results"][0]["status"],
    "page_load_status": report["results"][0]["page_load_status"],
    "tls_status": report["results"][0]["tls_status"],
}, sort_keys=True))
