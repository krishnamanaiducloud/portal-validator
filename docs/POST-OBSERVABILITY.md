# POST observation and reporting correction

## Root cause and boundaries

The inspected baseline already registered BrowserContext listeners before
navigation/SSO, observed non-safe methods before policy interception, correlated
live browser requests, and reconciled the continuous stream with inventory.
There was no reproduced additional raw POST loss from listener timing or endpoint
deduplication. Reporting lacked the required POST evidence vocabulary and eight
diagnostics; its legacy observed-request total counted API traffic, not documents
and assets. The method dropdown did not guarantee all supported methods.

An owned navigation-cancellation regression also exposed a redirect-guard race:
Chromium can cancel an interception before the guard's continuation command is
processed. Treating the resulting stale interception ID as a security validation
failure could close the dedicated browser, leaving later observations incomplete.
Only the exact stale-ID error at the direct CDP command boundary is handled as an
already-gone request. Destination validation still precedes redirect release;
policy denials remain recorded and unexpected enforcement errors fail closed.
Chromium's [interception implementation](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/content/browser/devtools/devtools_url_loader_interceptor.cc)
and the executable browser regression inform this narrow distinction.

No request approval, replay, TLS/CA configuration, SSRF rule, credential scope,
SSO boundary, crawl boundary, or production container security setting changes.
Endpoint names and successful HTTP responses never establish read-only safety.

## Additive report contract

Every POST event has `POST_OBSERVED` plus evidence labels as applicable:
`POST_READ_ONLY_APPROVED`, `POST_READ_ONLY_UNVERIFIED`,
`POST_BLOCKED_BY_POLICY`, `POST_AUTH_BOOTSTRAP`, `POST_MUTATION_RESTRICTED`,
and `POST_NETWORK_FAILED`. These are independent evidence, not permissions.
Policy aborts and navigation cancellations are not target network failures.

`summary.post_diagnostics` exposes:

- `total_http_requests_observed`
- `post_requests_observed`
- `post_requests_allowed`
- `post_requests_blocked`
- `approved_read_only_post_endpoints`
- `unverified_post_endpoints`
- `post_requests_without_completed_responses`
- `unique_post_endpoints_reported`

Calls and unique endpoints are different units. Endpoint categories can overlap
when calls to the same endpoint have different policy decisions. Calls without
completed responses include blocked, canceled, failed, and unfinished requests;
this does not mean every such call reached the server. A missing total in an
older report remains unknown, not zero. Legacy fields remain compatible.

The UI shows these counters, explicit `BLOCKED_BY_POLICY`, actual HTTP status
counts, failed-call totals, associated routes, authentication classification, and
POST classification. Existing pagination, filtering, and evidence remain usable.
Canceled/incomplete requests are retained without fabricated HTTP outcomes.

## Validation

Focused commands (the full release also runs `python -m pytest -q tests`):

```sh
python -m pytest -q tests/test_post_diagnostics.py tests/test_post_inventory_contract.py
python -m pytest -q tests/test_post_context_coverage.py tests/test_navigation_guard.py
python -m pytest -q tests/test_scan_post_lifecycle.py tests/test_scan_final_drain.py
python -m pytest -q tests/test_spa_api_activation.py tests/test_sso_navigation_browser.py
PORTAL_VALIDATOR_URL=http://127.0.0.1:8080 python tests/ui_check.py
```

Controlled fixtures verify natural Fetch/XHR, same-origin and approved
cross-origin iframe POSTs, exact-once backend receipts, zero unapproved mutation
receipts, session preservation, approved SSO, cancellation, failed/incomplete
responses, stable request identities, reconciliation, redaction, and UI filtering
and pagination. Fixtures use generic loopback servers, never an enterprise portal.

Service workers remain blocked so they cannot bypass read-only interception.
Worker-only/offline behavior and requests never initiated by the application
cannot be observed or claimed healthy. Actual authenticated portal coverage
requires an authorized deployed-session test; local fixtures do not establish
the complete endpoint inventory of a remote application.
