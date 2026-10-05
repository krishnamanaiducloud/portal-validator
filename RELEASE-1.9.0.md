# Portal Validator 1.9.0 production correction

## Root causes and limits of the evidence

- The old passive observer retained `id(request)` indefinitely. Python can reuse
  that address after a completed Playwright request is disposed. A regression
  against the original implementation reproduced later POST objects aliasing
  earlier GET records. Correlation now uses weak underlying-request identity and
  assigns a unique metadata-only request ID. A short legacy browser run did not
  reproduce the alias, so it would be incorrect to claim this proves the exact
  failure stage in an unavailable private production deployment.
- Read-only summary counts previously depended on per-route resource snapshots.
  Disabling resource checks demonstrably produced a zero summary despite blocked
  requests in the scan-wide observer. Discovery/late traffic could likewise fall
  outside route snapshots. Summary counts now reconcile with the entire passive
  stream, independently of resource-check settings.
- Slow-page assessment used elapsed route time, including deliberate settle and
  discovery waits. It now uses observed application-readiness time, with separate
  observation timing. This corrects the metric; it does not assume that every
  production slow warning had the same cause.
- Production previously inherited build-tool layers even after deleting their
  files. Debug also replaced a complete virtualenv, retaining the previous copy
  in its parent layers. A minimal Wolfi final stage and incremental debug tooling
  remove that layer waste without removing Chromium or certificate tools.

## Observation and approval

Natural browser request → observer → explicit read-only/network policy → route
handler → actual response/failure → scan-wide aggregator → report → API table.

Observation is idempotent and occurs before blocking, including when interception
is scheduled ahead of the context event callback. Safe lifecycle fields expose
the request/activation ID, method, sanitized host/path, phase/route, observer,
policy, handler, dispatch/response/failure, aggregation, and serialization stages.
No body, headers, cookies, credentials, token values, or browser state is captured.

GET/HEAD/OPTIONS retain their existing policy. POST is blocked unless a narrow
authentication-navigation exception or explicit read-only operation approval
matches. PUT/PATCH/DELETE remain blocked and cannot be approved. SSRF, permitted
ports, private-network approval, credentials, resources, and crawling remain
separate boundaries. A matched external operation passes URL/DNS checks; approval
does not allow unrelated operations at that host.

Configure owner-approved POSTs under **Discovery & health → Advanced → Approved
read-only API operations**, or use the existing administrator policy environment
variables documented in README. Per-scan API input:

```json
{"approved_read_post_operations": [
  {"method": "POST", "host": "api.example.net", "path": "/v1/read-query",
   "description": "Application-owner-approved read operation"}
]}
```

Paths are exact and query-free. Bounded patterns use complete `{segment}` labels
with strict literal-path constraints; broad glob/prefix patterns are rejected.
Actual bounded-path candidates also reject encoded separators, traversal,
double encoding, controls, and malformed UTF-8. Explicit per-scan policy parsing
does not inherit the administrator's policy-file environment; validated scan
rules merge with that separate administrator policy without source conflicts.
Approval never synthesizes or replays a POST: the portal must generate it.
Protect access to this service so only authorized operators approve operations.

Blocked calls appear with their method, call/block counts, `NOT_EXECUTED`, and
N/A response/timing. Approved calls use the real target response. The method
filter includes every observed method, including blocked attempts.

## UI, timing, and resource evidence

- Twenty API columns and thirteen route columns have independent show/hide,
  Select all, Clear all, and Reset controls. Identifying columns remain visible.
  Only column names/preferences persist in the two `portal-validator.*-columns`
  localStorage keys; unknown/new columns default to visible. Nothing is sent to
  the backend. Compact is the default; Comfortable is optional.
- Header tooltips define calls, actual HTTP status buckets, failures without an
  HTTP response, distinct route count, policy allowed/blocked counts, and
  bootstrap/authentication/route/refresh phase counts. Response-body failures
  retain their actual status but are separately classified and excluded from
  completed-response timings. Avg Time and Worst Time use completed calls only.
- Warning drill-down exposes count, categories, and sanitized descriptions.
  PASS_WITH_WARNINGS remains healthy, not a failure. Both synchronized horizontal
  scrollbars remain functional when selected columns overflow.
- Navigation/SPA activation, render readiness, observed application settling,
  validator observation, and total validation have separate millisecond fields.
  Route Time/slow classification use `application_load_ms`, not artificial
  trailing quiet/minimum observation waits. This is a passive readiness estimate,
  not Core Web Vitals.
- ResourceTiming is read passively for already-loaded resources. Transfer,
  encoded-body, and decoded-body bytes are distinct. Unavailable/opaque timing
  evidence is null, not invented. A process-salted internal correlation key
  prevents sanitized URL collisions and is stripped before reporting. No extra
  downloads occur. Large-resource warnings never directly fail a loaded page.
- Advanced thresholds default to 1 MiB per resource and 512 KiB per image.
  Summary cards and collapsible details support resource-type, failure, and
  large-only filters. Measurable transfer totals do not claim complete coverage.

## Files changed

- `app/network.py`: lifetime-safe correlation, strict POST rules, safe lifecycle.
- `app/main.py`: scan approval contract, listener/policy/report integration,
  scan-wide counters, readiness/resource integration; version 1.9.0/schema 2.3.
- `app/reporting.py`: blocked-only outcomes and completed-response statistics.
- `app/health.py`: application versus validator timing and performance toggle.
- **New** `app/resources.py`: passive, sanitized size evidence and warnings.
- `app/static/index.html`, `app/static/app.js`, `app/static/dashboard.css`:
  approval editor, columns/density, warnings, resource views, labels/tooltips.
- `Dockerfile`: digest-pinned builder/runtime separation; signed exact APK
  transaction; matching virtualenv/browser copies; final executable and both
  Chromium-mode launch checks; non-root user preserved.
- `Dockerfile-debug`: production inheritance plus same-layer incremental tools.
- `openshift/deployment.yaml`: versioned image reference only; existing mounts,
  trust environment, writable tmp, and restricted security context unchanged.
- `README.md`: generic operation configuration and report/image documentation.
- `tests/test_app.py`, `tests/test_health.py`, `tests/ui_check.py`: version,
  completed-response timing, and UI regressions.
- **New** `tests/test_scan_post_lifecycle.py`, `tests/test_resource_timing.py`,
  `tests/test_containerfiles.py`: full scan browser/lifecycle, passive sizes,
  and layer/build guards.
- **New** this release record. No trust/entrypoint/SSO/TLS code was changed.

## Validation commands

```bash
python -m pytest -q --tb=short --show-capture=no
PORTAL_VALIDATOR_URL=http://127.0.0.1:18080 \
  UI_SCREENSHOT=reports/portal-validator-1.9.0-ui.png python tests/ui_check.py
docker build -t mohankrishna999/portal-validator:1.9.0 .
docker build -f Dockerfile-debug \
  --build-arg PRODUCTION_IMAGE=mohankrishna999/portal-validator:1.9.0 \
  -t mohankrishna999/portal-validator:1.9.0-debug .
```

The production `execute_scan` browser regression covers 44 routes, 301 naturally
generated approved POSTs with actual HTTP 201 responses, 129 blocked
PUT/PATCH/DELETE attempts, preserved session cookies, blocked POST inventory,
resource-check-disabled counters, redaction, and passive image/JS bytes. It
permits loopback/ephemeral ports only within the isolated fixture; production
network policy is unchanged. UI smoke includes persistent independent columns,
new-column defaults, both scrollbars, 44-route/33-warning data, and
1920/1366/768/390-pixel layouts. The measured final UI run rendered 100/500/1000
API rows in 15.3/106.5/189.3 ms respectively (not a production performance SLA).

### Executed results and published artifacts

- Final Windows suite: **177 passed, 1 skipped**, 122.34 seconds. The skip is the
  Windows permission requirement for creating the ConfigMap symlink fixture.
- Linux debug-runtime suite with read-only test/candidate-source mounts and an
  arbitrary UID: **178 passed**, 235.28 seconds, including that symlink fixture.
- Final published debug image, with only tests mounted (application from image):
  **45 passed, 1 deselected**, 27.47 seconds across POST lifecycle and trust
  regressions. The 44-route case was already covered by both full-suite runs.
- Both final image builds succeeded. Production build gates launched both
  matching Chromium modes. Production runtime smoke passed with UID 1000820000,
  a read-only root filesystem, writable tmpfs HOME, mounted generic test CA,
  NSS SSL CA trust, and strict Google HTTPS **HTTP 200 / title Google**.
  The final debug image passed the same arbitrary-UID/NSS/strict HTTPS smoke.
- Final production and debug Trivy scans: **0 fixable HIGH/CRITICAL findings**.
  This is not a claim that every severity or every scanner reports zero findings.
  Scan reports and UI screenshots are local ignored artifacts under `reports/`.
- Public application dependencies and Playwright **1.63.0 / Chromium revision
  1243** are preserved. Production does not ship compiler/download stages or
  application-venv pip/setuptools; debug adds only development dependencies.

Docker Hub registry manifests were verified after pushing only versioned tags:

| Image tag | Compressed layer bytes | Previous 1.8.0 equivalent | Reduction |
| --- | ---: | ---: | ---: |
| `mohankrishna999/portal-validator:1.9.0` | 502,490,734 | 824,523,264 | 39.1% |
| `mohankrishna999/portal-validator:1.9.0-debug` | 508,143,656 | 890,429,762 | 42.9% |

Production digest: `sha256:5ca0d8a37c52e22b59b6918f7da5cc18f90e30a455b2f4c39bb3bd9106c734a3`.

Debug digest: `sha256:fcb0348cf4f4c24fcdef23e4b7b56f1ca5253e1384bf52a18d742676ec18d150`.

Both manifests use OCI gzip layer media types. No `latest` or `prod-*` tags were
built/pushed. The debug build used the exact production digest as its base.

Additional validation commands (Linux/WSL):

```bash
docker run --rm --user 1000820000:0 --read-only \
  --tmpfs /tmp:rw,nosuid,size=512m \
  -v /path/to/managed-ca.crt:/etc/portal-validator/certs/ca-bundle.crt:ro \
  -v /path/to/approved-ca-directory:/etc/portal-validator/zscaler:ro \
  -v "$PWD/tests/container_smoke.sh":/tmp/container-smoke.sh:ro \
  mohankrishna999/portal-validator:1.9.0 sh /tmp/container-smoke.sh
trivy image --image-src remote --scanners vuln --severity HIGH,CRITICAL \
  --ignore-unfixed --exit-code 1 mohankrishna999/portal-validator:1.9.0
trivy image --image-src remote --scanners vuln --severity HIGH,CRITICAL \
  --ignore-unfixed --exit-code 1 mohankrishna999/portal-validator:1.9.0-debug
```

## Post-deployment verification and remaining production work

Startup is unchanged: mounted ConfigMaps → entrypoint → runtime PEM/NSS
initialization → `exec` original Uvicorn command. Corporate roots remain mounted,
not baked in, and certificate verification remains strict.

```bash
oc rollout status deployment/portal-validator
oc exec deployment/portal-validator -- python -c \
  'import os; print("UID:",os.getuid()); print("HOME:",os.environ["HOME"])'
oc exec deployment/portal-validator -- python -m app.trust status
oc exec deployment/portal-validator -- sh -c \
  'certutil -L -d "sql:$CHROMIUM_NSS_DB"'
oc exec -i deployment/portal-validator -- python - <<'PY'
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    response = page.goto("https://google.com", wait_until="domcontentloaded", timeout=60000)
    print("STATUS:", response.status if response else None)
    print("TITLE:", page.title())
    browser.close()
PY
```

On the authorized portal, first run without approvals and inspect POST attempts,
the API method filter, block counts, and `network_observation` reconciliation.
Then approve only owner-confirmed read POSTs and verify actual statuses and route
attribution. Use safe request/activation lifecycle IDs to identify any remaining
private production loss stage; no private production profile or cluster access
was used locally. Do not increase privileges, disable TLS, or broadly allow
private networks to pass this check.
