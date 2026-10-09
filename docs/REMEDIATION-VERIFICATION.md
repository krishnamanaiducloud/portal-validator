# Portal Validator implementation and verification report

Date: 2026-10-08. Scope: the current, uncommitted remediation against source
baseline `2deea84` (`1.10.0`), published in versioned images `1.11.0`. Git approval
is pending; examples and fixtures are generic.

## Release status and evidence boundary

**The final application/backend gate passed 360 tests with no skips.**
The accepted source was rebuilt into both version1.11.0 images and its application
file hashes were verified against each final image. Strict Python and Chromium
HTTPS succeeded against an isolated CA-signed fixture in both final images after
the real entrypoint imported its root into NSS. Final UI/security/publication
results are recorded below; real OpenShift deployment is not claimed.

The subsequent user request explicitly authorizes building and publishing
versioned images after verification. Git publication approval is requested
separately; no deployment is authorized. An existing deployment/image is not
evidence that the uncommitted implementation has been deployed.

Both versioned images were pushed and their Docker Hub manifest digests verified:

| Image | Registry digest | Compressed layer bytes |
| --- | --- | --- |
| `mohankrishna999/portal-validator:1.11.0` | `sha256:85c11c44a25d67f27f3c2296e61d81109152249310c77c003bd723c10ca79a94` | 500,148,216 |
| `mohankrishna999/portal-validator:1.11.0-debug` | `sha256:12378ca62ab6c301787cca53e28c4a6a522dd0916c67249bd7437df06c73df98` | 505,801,098 |

Architecture: Linux/amd64; OCI manifests with gzip layers. No latest or prod-date
tag was published. No Git commit/push or OpenShift deployment was performed for
this new Portal Validator remediation without the separate required approval.

No authorized production portal, external access-restricted site, or OpenShift
pod was exercised for this remediation. No production route count or session
validity is claimed. The isolated Linux current-source test recorded strict
public HTTPS HTTP200 and a real Chromium launch as UID `1000820000:0`.

## Confirmed causes and focused corrections

| Confirmed code defect | Correction | Files and regression evidence |
| --- | --- | --- |
| `DOMContentLoaded` could be mistaken for completed authentication while an automatic protocol form or callback was still transitioning. Same-portal authentication paths could be classified as application success. | Observe the natural authentication lifecycle until an application surface, login/MFA, HTTP denial, unrelated destination, or bounded authentication timeout. An authentication callback alone is not application coverage. | `app/navigation.py`, `app/main.py`; `test_auth_navigation_coverage.py`, `test_sso_navigation_browser.py`. |
| Generic `state`/`error` fields were overly broad authentication signals; authentication navigation and crawl scope needed distinct approval. | Require meaningful protocol evidence and exact approved identity-provider hosts for authentication POSTs; preserve separate portal, resource, credential, and network boundaries. Never submit a form on the validator's initiative. | `app/navigation.py`, `app/main.py`; protocol-signal, destination-approval, anonymous/expired/valid-session tests. |
| Playwright routing does not intercept every native HTTP redirect hop, and configured header overrides can survive redirects. A popup's first request can precede its Frame. | Install browser-wide response-stage Chromium interception before the first HTTP navigation; validate native hops without replay/body access. Treat documented pre-Frame popup documents as navigation, preserving exact IdP approval and network checks. | New `app/navigation_guard.py`, integration in `app/main.py`; real-browser primary/popup/OOPIF zero-destination-hit and credential-boundary regressions. |
| A finished queue on an identity, challenge, denied, or incomplete page could be presented as comprehensive portal coverage. | Separate `execution_status` from `coverage_status`; include structured coverage reasons, application-route counts, untested/skipped routes and outstanding API observations. | `app/reporting.py`, `app/main.py`, UI coverage banner; coverage regression tests. |
| HTTP headers alone, an allowed request, or a policy block could be confused with a completed API observation. Cancellation could resemble a target network failure. | Track observed/allowed/blocked/sent/responded/completed/failed/canceled/incomplete independently. Preserve known HTTP errors even if response-body observation is incomplete. Separate browser failure events from genuine nonblocked/noncanceled failures. | `app/network.py`, `app/health.py`, `app/reporting.py`, `app/main.py`; `test_execution_evidence.py`. |
| Challenge/configuration/authentication traffic could inflate apparent business API coverage. | Keep semantic `traffic_role` independent from execution policy. Count business success only for completed, actual application API responses. Unknown traffic remains visible. | `app/network.py`, `app/reporting.py`; challenge/config/auth/business classification tests. |
| Some important timeout/admission settings were not independently exposed or bounded. | Optional phase deadlines and explicit readiness conditions; server-side bounds; fair per-process concurrent-scan admission constrained by deployment capacity. Routes stay serial within one authenticated browser context. | `app/main.py`, `app/health.py`, `app/scans.py`, UI controls; deadline, concurrency and UI contract tests. |
| Inspect content was constrained by table layout and legacy aggregate `NOT_EXECUTED` could hide an incomplete/canceled API outcome. | Shared full-width expandable/resizable inspector, optional full-screen dialog, independent scrolling and focus restoration; preserve authoritative API observation labels and readable lifecycle counts. | `app/static/app.js`, `index.html`, `styles.css`; `tests/ui_check.py`. |
| Timeout during a readiness-selector check could discard its result and default to healthy; whole-message redaction could consume JSON delimiters. | Default each fresh readiness sample to unmet before awaiting visibility; redact structured JSON values before serialization while preserving text/access-log redaction. | `app/health.py`, `app/logging_config.py`; deterministic readiness deadline and structured OAuth/SAML log tests. |
| Primary-page readiness cleared shared-context authentication evidence before a popup's approved native POST callback. | Preserve observed authentication evidence for the shared context. Every authentication POST still requires protocol evidence, an approved destination and normal network validation. | `app/main.py`; delayed approved/unapproved popup SAML307-to-callback regression. |
| Estimating the document clock using the time an evaluate response reached Python could clip measured policy waits by browser messaging latency. | Align the local container's browser Navigation Timing epoch with Python's monotonic clock; do not move the document window when the measurement response is delayed. | `app/health.py`, `app/main.py`; deterministic zero/2.4-second IPC-return-delay tests and real-browser slow-document/policy-wait tests. |

The reported reduction from many authorized routes to one authentication-related
document is consistent with the confirmed authentication/completion defects.
Its complete production cause cannot be proven without the affected authorized
session, sanitized redirect evidence, application readiness, and deployed image
digest. Controlled fixtures replace guesses; they do not establish production
coverage or guarantee a particular number of routes.

## Requirement-by-requirement implementation and acceptance map

| Request section | Implementation / preserved behavior | Tests / remaining acceptance boundary |
| --- | --- | --- |
| 1. Observed authenticated-portal and public-site failures | Report authentication stage, document status, challenge/access denial and limited coverage separately; do not treat configuration GETs or challenge POSTs as business validation. | Generic SSO, denied/challenge and API-role fixtures. Actual authorized portal and external access-denial comparison are **not run**. |
| 2. Repository/history investigation | Inspected current scan/context setup, route guards, request listeners, discovery/normalization, storage-state handling, deadlines, report/UI flow, manifests, and relevant history including the previous route/POST fixes. Reused existing helpers instead of a new crawler. | Baseline `2deea84`; previous route identities and request ownership are retained. Historical production counts cannot be independently reconstructed locally. |
| 3. Route discovery | Preserve pre-navigation History/hash instrumentation, semantic links/menu/tab activation, lazy navigation, frames/popups, bounded queue, exact route identities and configurable query policy. Titles do not determine route identity. Auth/IdP destinations are not crawl targets. | Existing `test_discovery.py`, `test_discovery_regressions.py`, `test_spa_api_activation.py`; full-scan fixture defines 51 SPA routes plus landing page. Passed in the final Linux suite. Generic hooks cover framework patterns; separate React/Angular/Vue bundles are not individually certified. |
| 3. Coverage accounting | Keep discovered-route inventory and validated, remaining, skipped/not-tested counters. Exact termination reasons and structured coverage restrictions survive a finished execution. | `test_auth_navigation_coverage.py`, deadlines and route-limit invariants. An unvisited route remains reported rather than silently disappearing. |
| 4. SSO | Keep secure mounted storage-state profiles and one shared context across OAuth/OIDC/SAML transitions, cookies and application navigation. Observe natural automatic protocol forms; stop honestly for login/MFA/expired state. Existing atomic runtime session persistence/refresh remains in place. | Valid/expired/anonymous browser fixture; explicit IdP approval and callback tests; existing session-refresh tests. Production MFA, profile freshness and provider refresh permissions require operator verification. |
| 5. Passive POST visibility | Context listeners observe requests before policy, including naturally emitted Fetch/XHR, frames and approved authentication documents. Preserve request identity, route ownership, response completion and scan-wide aggregation. | `test_scan_post_lifecycle.py`, execution evidence and GraphQL tests. GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE are observed; observation never grants permission. |
| 5. Read-only POST execution | Exact administrator-approved method/host/path or bounded-path rules only. Query-only GraphQL uses parsed operations. Mutation/unknown operations remain blocked and visible; no payload rewriting, endpoint probing or POST replay. | Approved/blocked/repeated/iframe/Fetch/XHR/failed/late POST fixtures and GraphQL query/mutation regressions passed; target receipt counts establish natural execution without retries. |
| 5. Service workers | Preserve context service-worker blocking so interception and read-only enforcement cannot silently be bypassed. Report browser-observable requests only. | Do not claim visibility into unexecuted service-worker-only/offline traffic. Sites requiring a service worker can have limited functionality; do not weaken policy to hide that limitation. |
| 6. Public website behavior | Preserve HTTP status and redirect diagnostics, DNS/TLS/proxy/network error classification, authentication/access restriction and challenge evidence. No CAPTCHA/WAF/bot-protection bypass. | Existing navigation/health tests and generic browser fixtures cover success, denial, errors and redirects. External site behavior depends on session, IP, proxy and access policy and is not reproduced by a loopback fixture. |
| 7. Inspect UI | Expand/collapse, full-width view, optional full-screen dialog, vertical resize, one independent details scroller, responsive sections, keyboard/Escape/focus restoration and sanitized copy/download. Preserve table controls. | Full UI smoke **passed**, including four viewport sizes, focus, scrolling and diagnostic allowlisting/export. No overall UI replacement. |
| 8. Completion and timing | Preserve bounded adaptive DOM/network readiness rather than exclusive `networkidle`. Track preflight, browser startup, navigation, authentication, readiness, discovery, route validation, network observation, aggregation, report generation/finalization and total duration. Pending observations constrain coverage. | Deadline/readiness/coverage tests passed. Short duration alone is not treated as a defect. Listener-lifetime network observation overlaps other phases and must not be summed as disjoint accounting. Report generation measures construction of the report dictionary, not subsequent HTTP serialization. |
| 9. API inventory and health | Independent lifecycle counts, semantic traffic role, policy classification, route ownership, status distribution and completed-response-only timing. Missing timing is `null`/N/A, not zero. API row/Inspect preserve incomplete and canceled evidence. | Execution-evidence tests and UI regressions. No status-code-only network-failure claim; challenge success is not business success. |
| 9. Inventory usability | Preserve method/status/policy/route/role filters, pagination and dynamic columns. Sanitized endpoints, all observed methods and blocked attempts remain reportable. | UI smoke passes 100/500/1000 API inventories and pagination; 44 route rows remain visible. A separate 52-route fixture verifies 50+2 pagination, complete/disjoint page membership, previous-page restoration and restoration of the existing route view. |
| 10. Dynamic configuration | UI/server contracts for maximum routes/depth/redirects, per-route/total/phase/API deadlines, readiness selector, observation/stability/network-quiet windows, slow threshold and scan concurrency. Blank phase limits inherit existing budgets. | Pydantic validation, API timeout Fetch/XHR cancellation, concurrency admission/cancel/deadline tests, actual form-payload UI assertions. No automatic POST retry. |
| 11. OpenShift security | No changes to the working CA/NSS bootstrap, pinned Playwright/browser architecture, non-root user, arbitrary-UID writable HOME, restricted security context, read-only root filesystem or mounted credentials. No TLS bypass or sandbox-disabling flag added. | Security/containerfile/trust tests passed. Both final images passed strict fixture HTTPS as UID1000820000:0 with read-only filesystem, dropped capabilities and no-new-privileges. Actual OpenShift verification remains **not run**. |
| 12. Regression fixtures | Reuse controlled discovery/POST/session/GraphQL/timeout tests; add authentication coverage, lifecycle evidence, redirect guard and admission tests plus UI regressions. Fixtures are generic and use isolated loopback servers. | Final Linux suite: 360 passed, no skips. Exact-image UI/runtime/NSS/strict fixture HTTPS also passed; actual cluster verification remains separate. |
| 13. Implementation process | Investigation and focused implementation, then regression integration and security review. Publication follows tests and user authorization. | Accepted application source hashes match both final runtime images; final security and runtime gates passed. |
| 14. Acceptance | All 16 requested acceptance points map to the rows above. Local implementation alone does not certify real session recovery, exact authorized route counts or OpenShift deployment behavior. | Controlled local acceptance passed; production verification and Git approval boundaries are explicit below. |

### Configuration and performance semantics

- `navigation_timeout_ms`, `authentication_timeout_ms`, `readiness_timeout_ms`
  and `api_timeout_ms`: optional 1,000-120,000 ms bounds; blank preserves the
  existing budget/behavior. API deadlines cancel a naturally issued request;
  they do not retry it or change its body.
- `readiness_selector`: optional CSS selector, maximum 512 characters.
- `concurrency_limit`: 1 through deployment `MAX_CONCURRENT_SCANS`; the UI
  discovers the cap from `/api/auth-profiles`. A request for 1 receives exclusive
  browser admission. This is a per-process limit, not a cluster-wide semaphore.
- Crawler scope, exact authentication-host approval, credential scope, resource
  scope and SSRF/private-network authorization remain distinct. A host approval
  never disables destination/network validation.
- `application_navigation_ms`, `application_settle_ms`, `validator_overhead_ms`
  and `total_validation_ms` remain separate. Slow warnings compare measured
  application time with the user-configured threshold, not minimum observation,
  polling, stability confirmation, discovery or report overhead.
- `PASS_WITH_WARNINGS` remains healthy and contains structured warning reasons.
  The UI exposes the warning count/reasons without requiring raw JSON inspection.
- Document navigation uses the final application's Navigation Timing after SSO,
  with measured validator policy pauses subtracted. Browser sampling has finite
  resolution; values close to a configured threshold are not a precision benchmark.
  Clock alignment assumes Chromium and Python share the same container/OS clock,
  as in this application's local browser launch architecture; it is not a remote
  browser timing protocol.

### Package refresh

Authoritative PyPI metadata was checked on 2026-10-08. Upgrade FastAPI from
`0.142.2` to stable `0.143.0` and Pydantic from `2.13.5` to stable `2.14.0`.
Other direct production/development pins were already the latest non-yanked
stable releases, including Playwright `1.63.0`. Its Chromium revision `1243`
is unchanged. The refreshed Windows dependency/model/logging gate passed 63 tests.

Compatibility note: FastAPI 0.143 makes automatic OpenTelemetry exporter setup
opt-in. This repository has no OTEL auto-export configuration; operators relying
on injected `OTEL_*` settings must review the official release notes and explicitly
configure their provider/exporter. Pydantic's Python3.9 support removal does not
affect the Python3.14 runtime. No telemetry or TLS security bypass was added.

The final image inventory recorded glibc `2.44-r8`, Python3.14
`3.14.8_git20261008-r0`, pcre2 `10.49-r1`, NSS/tools `3.128-r2` and OS pip-wheel
`26.2.1-r2`. The minimal production/development images deliberately uninstall
the pip/setuptools command-line installation after the build; the OS-provided
ensurepip wheel is a separate dependency. No pip command is claimed available
in the final production image. Fresh final-image Trivy scans reported zero
findings for both variants; this is not a guarantee against undiscovered CVEs.

## Files in this remediation

Application changes:

- `app/main.py`: authentication settling, configuration/admission, redirect-guard
  integration, lifecycle/timing/coverage reporting and safe network counters.
- `app/navigation.py`: stronger protocol evidence, exact authentication approval,
  bounded natural authentication transitions and terminal classification.
- `app/navigation_guard.py` (new): native HTTP redirect response guard.
- `app/network.py`: purpose classification and explicit request lifecycle.
- `app/health.py`: readiness condition, incomplete/canceled evidence and preservation
  of observed HTTP target errors.
- `app/logging_config.py`: preserve valid structured JSON through repeated central
  redaction filters, including OAuth/SAML URL values.
- `app/reporting.py`: API aggregation, coverage/completion and reconciled evidence.
- `app/scans.py`: fair cancellable per-process browser admission.
- `app/static/app.js`: configuration payloads, coverage banner, role/lifecycle
  diagnostics, expanded inspector and safe diagnostic copy/download.
- `app/static/index.html`: phase/readiness/authentication/admission controls and
  inspector structure.
- `app/static/styles.css`: inspector sizing, responsive layout and table controls.

Test changes/new files:

- `tests/test_app.py`
- `tests/test_resource_timing.py`
- `tests/test_logging_config.py` (new)
- `tests/test_scan_deadlines.py` (existing work preserved)
- `tests/test_scan_post_lifecycle.py`
- `tests/ui_check.py`
- `tests/test_auth_navigation_coverage.py` (new)
- `tests/test_execution_evidence.py` (new)
- `tests/test_navigation_guard.py` (new)
- `tests/test_scan_concurrency.py` (new)
- `tests/test_sso_navigation_browser.py` (new)
- `docs/REMEDIATION-VERIFICATION.md` (this new report)

`app/trust.py`, `container-entrypoint.sh` and the production Dockerfile are
preserved. Authorized release metadata updates touch `requirements.txt`,
`Dockerfile-debug`, `README.md`, `openshift/deployment.yaml`, the application version
and its health endpoint test. No cluster manifest was applied.

## Tests executed and remaining gates

### Completed local verification

The isolated local Python environment ran:

```powershell
$env:PORTAL_VALIDATOR_URL = 'http://127.0.0.1:18080'
$env:UI_SCREENSHOT = '<local-artifact-directory>\portal-ui-pagination.png'
python tests/ui_check.py
git diff --check -- app/static/app.js tests/ui_check.py
```

Result: `UI_SMOKE_PASSED`. This exercised current static files against the local
application server; intercepted local scan endpoints were deliberate fixtures,
not external portal scans. It does not prove that a stale server process loaded
the new Python backend. Measured API-table render times for the last complete
run were 12.1/20.5/19.7 ms for 100/500/1000 records. Privacy and prohibited-TLS-change
checks on the UI diff passed. Concurrency blank omission, cap rejection and the
actual submitted payload were verified. The 52-route pagination regression
passed as part of that complete smoke.

### Final backend verification: integration correction and rerun

Run after all integration edits, in an isolated environment with the pinned
Playwright browser available:

```sh
python -m pytest -q
python -m pytest -q tests/test_navigation_guard.py tests/test_sso_navigation_browser.py
python -m pytest -q tests/test_auth_navigation_coverage.py tests/test_execution_evidence.py tests/test_scan_concurrency.py
python -m pytest -q tests/test_scan_post_lifecycle.py tests/test_scan_deadlines.py tests/test_discovery_regressions.py tests/test_graphql_policy.py
```

The latest focused backend run passed **98 tests in 28.04 seconds**:

```sh
python -m pytest -q tests/test_sso_navigation_browser.py::test_api_redirect_header_guard_does_not_fail_successful_main_document tests/test_execution_evidence.py tests/test_auth_navigation_coverage.py tests/test_reporting_warnings.py tests/test_health.py
```

An initial Linux current-source run recorded **355 passed, one failed**. Its
adaptive-readiness assertion incorrectly included total diagnostic/host overhead;
the test now checks adaptive readiness directly while retaining the application
load, slow-warning, deadline, browser-context and target-request assertions.

The next Linux run recorded **356 passed, two failed** during concurrent image
export. It exposed the popup authentication-state race and document clock
alignment issue described above. A standalone repeat of the timing test passed,
but that did not waive the full-run failures. After the corrections, the focused
readiness/resource/policy/popup/final-SSO performance gate passed **31 tests in
37.75 seconds**. The final Linux rerun passed **360 tests, no skips, in
369.24 seconds**. The previous
run's separate browser smoke could not start because the dependency image's old
local digest was replaced during a concurrent rebuild; the next test/browser
run completes before rebuilding that tag.

The accepted source snapshot manifest SHA-256 was
`93dccce00c9dab19f356e47dd83e26550886d96042e08c7a65d65655cea00c2b`.
The subsequently changed UI harness only stops a pending outer smooth-scroll
animation before asserting independent inspector scrolling; no assertion or
application behavior was removed. Both image application hashes still match the
accepted application source exactly.

External smoke limitation: Chromium launched but public Google navigation later
timed out (`net::ERR_TIMED_OUT`, not `ERR_CERT_AUTHORITY_INVALID`), including a
bounded www-target check. WSL curl separately returned HTTP200. These external
failures are retained, not converted into TLS passes or fixed by bypass flags.
Both exact final images instead passed an isolated strict HTTPS test with a
generated CA/leaf, real startup NSS import, Python verified HTTPS, and normal
Playwright verified HTTPS HTTP200. The fixture had no external network access,
ran as the arbitrary UID, and kept all temporary CA/key material out of Git and
the images. This proves the runtime trust mechanism; it does not prove external
Google reachability or production SSO from OpenShift.

Do not substitute earlier passing subset counts for a final pass.
Required security gates include: validation before
native redirect follow, no credential-header escape, safe popup attachment,
same-process and out-of-process frames, preserved approved authentication POSTs,
and fail-closed cleanup without POST replay.

The first exact-image runtime gate passed for both candidate images as
UID `1000820000:0`, read-only root filesystem, dropped capabilities and
no-new-privileges. The existing entrypoint created a runtime PEM and imported a
generic fixture CA into NSS with `C,,`; real Chromium launched; health returned
version1.11.0; both processes exited gracefully with code0. The production image
also passed the full UI smoke (100/500/1000 API records and 52-route pagination).
Both fresh Trivy scans reported zero findings. That earlier candidate was not
published. After the final corrections, both final images again passed runtime,
arbitrary-UID, read-only-filesystem, health, Chromium, NSS and graceful-exit checks
and fresh zero-finding Trivy scans. The final exact-production-image UI gate
passed all checks; API rendering took 16.7/19.1/18.9 ms for 100/500/1000 records.
The inspector scroll test now cancels its own still-running outer smooth-scroll
animation before measuring independent inner scrolling; assertions are retained.

Full-suite command (read-only accepted-source snapshot in the matching dependency
image, followed by final-image application-hash comparison):

```sh
python -m pytest -q -ra -p no:cacheprovider --junitxml=/results/pytest.xml tests
```

Final result: **360 passed, zero skipped, 369.24 seconds**. Build-time verification
found the pinned browser in the final image and launched default headless Chromium
and the full Chromium channel. Exact final-image runtime/UI/strict fixture HTTPS
checks exercised the packaged application without a replacement application mount.

Remaining operational boundaries:

1. Git publication approval remains separate; no cluster deployment is authorized.
2. Fresh OpenShift pod verification below and an owner-approved authenticated scan
   must establish expected routes and real natural read-only POST receipts there.
3. The local external-browser timeout remains unverified outside the isolated
   fixture. Do not describe it as successful external Google/enterprise navigation.

## Preserved OpenShift startup sequence

1. OpenShift mounts approved CA files and read-only session profiles; `/tmp`
   provides writable per-pod storage under the restricted security context.
2. The existing entrypoint sets writable HOME and runtime CA variables.
3. `python -m app.trust initialize` builds the deduplicated runtime bundle and
   initializes/imports the approved enterprise roots into Chromium NSS.
4. The wrapper executes the original application command using `exec "$@"`.
5. Uvicorn serves asynchronous scan jobs. Each admitted scan creates its browser
   context, restores the selected profile and registers observation/security
   instrumentation before target application navigation.
6. Natural authentication transitions are observed separately from crawl scope;
   application readiness precedes bounded discovery/validation.
7. Finalization accounts for every observed request and remaining route; process
   termination continues to reach Uvicorn directly.

This sequence is derived from source inspection. It was not executed inside a
fresh OpenShift pod for the uncommitted changes.

## Exact post-deployment checks (only after approval)

Use an approved namespace and already-deployed pod. These commands do not perform
a deployment or reveal full environment/profile/certificate contents.

```sh
NAMESPACE='your-namespace'
POD="$(oc -n "$NAMESPACE" get pod -l app=portal-validator -o jsonpath='{.items[0].metadata.name}')"
oc -n "$NAMESPACE" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].imageID}{"\n"}'
oc -n "$NAMESPACE" logs "$POD" -c portal-validator --tail=100
oc -n "$NAMESPACE" exec "$POD" -c portal-validator -- id
oc -n "$NAMESPACE" exec "$POD" -c portal-validator -- sh -ec '
  tr "\000" "\n" < /proc/1/environ |
    grep -E "^(HOME|PLAYWRIGHT_BROWSERS_PATH|SSL_CERT_FILE|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|PORTAL_VALIDATOR_MANAGED_CA_BUNDLE|RUNTIME_CA_BUNDLE|CHROMIUM_NSS_DB)="
  test -w "$HOME"
  test -w /tmp
  test ! -w /ms-playwright
  test ! -w /etc/ssl
'
oc -n "$NAMESPACE" exec "$POD" -c portal-validator -- sh -ec '
  python -c "import os; from pathlib import Path; p=Path(os.environ[\"RUNTIME_CA_BUNDLE\"]); print(\"Runtime certificate count:\",p.read_text().count(\"-----BEGIN CERTIFICATE-----\"))"
  python -c "import json,os; from pathlib import Path; print(json.dumps(json.loads(Path(os.environ[\"PORTAL_VALIDATOR_TRUST_STATUS\"]).read_text()),indent=2))"
  certutil -L -d "sql:$CHROMIUM_NSS_DB"
'
oc -n "$NAMESPACE" exec "$POD" -c portal-validator -- python -c 'import importlib.metadata as m; from pathlib import Path; from playwright.sync_api import sync_playwright; print("Playwright",m.version("playwright")); p=sync_playwright().start(); executable=Path(p.chromium.executable_path); print("Chromium executable",executable); assert executable.is_file(); p.stop()'
```

Expected properties, not assumed results: nonzero non-root UID; writable HOME;
runtime PEM/NSS metadata reflecting mounted approved roots; Playwright 1.63.0;
matching Chromium under `/ms-playwright/chromium-1243/`. Do not hard-code an
expected certificate count, print PEM bodies or dump all of PID 1's environment.

Test a company-approved HTTPS URL. Use the same commands separately for an
approved public target and an approved internal target; do not add those actual
target names or results to version control.

```sh
TARGET_URL='https://portal.example.org/'
oc -n "$NAMESPACE" exec "$POD" -c portal-validator -- curl --fail-with-body --silent --show-error --output /dev/null --write-out 'HTTP %{http_code}\n' "$TARGET_URL"
oc -n "$NAMESPACE" exec -i "$POD" -c portal-validator -- python - "$TARGET_URL" <<'PY'
import sys
from urllib.error import HTTPError
from urllib.request import urlopen

try:
    with urlopen(sys.argv[1], timeout=30) as response:
        print("STRICT_PYTHON_HTTPS_COMPLETED", "HTTP", response.status)
except HTTPError as response:
    # A verified HTTPS response can still deny anonymous application access.
    print("STRICT_PYTHON_HTTPS_COMPLETED", "HTTP", response.code)
    response.close()
PY
oc -n "$NAMESPACE" exec -i "$POD" -c portal-validator -- python - "$TARGET_URL" <<'PY'
import sys
from playwright.sync_api import sync_playwright

with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    try:
        context = browser.new_context()
        page = context.new_page()
        response = page.goto(sys.argv[1], wait_until="domcontentloaded", timeout=30000)
        print("STRICT_BROWSER_NAVIGATION_COMPLETED")
        print("HTTP", response.status if response else None)
        context.close()
    finally:
        browser.close()
PY
oc -n "$NAMESPACE" exec "$POD" -c portal-validator -- python -c 'import urllib.request; response=urllib.request.urlopen("http://127.0.0.1:8080/healthz",timeout=5); print("Application health HTTP",response.status)'
```

A strict browser HTTP401/403 or a login redirect is not proof of broken TLS and
is not proof of authenticated application coverage. Diagnose authentication only
after certificate validation succeeds. A debug image may contain curl while the
minimal production image does not; do not install tools into a running pod.
Use the approved debug image or existing Python HTTPS client when curl is absent.

Finally, use the application UI with an owner-approved mounted SSO profile and
exact approved authentication/resource/credential hosts. Confirm the final
application landing page, discovered-route inventory, application API role,
read-only policy decision, target response and response completion independently.
Check observed/aggregated counts reconcile and that blocked mutations never reach
the controlled target. Validate expired/anonymous sessions as negative cases.
Never print profile JSON, cookies, tokens, protocol assertions, request bodies or
authentication headers to gather that evidence.

## Remaining risks and assumptions

- Approved identity-provider hosts must be configured explicitly; restoring an
  old broad authentication exception is not an acceptable compatibility fix.
- Expired profiles, MFA and provider access policy may require approved human
  reauthentication. Silent refresh cannot override identity-provider policy.
- Private-network access remains opt-in and subject to existing address/port
  policy. Test fixtures explicitly authorize their isolated loopback targets;
  that is not a production private-network default.
- Browser-visible readiness and safe DOM navigation are bounded observations,
  not proof that every application feature or hidden route was exercised.
- Chrome/CDP redirect interception is security-sensitive and Chromium-specific;
  unverified popup/cross-process-frame behavior is a release blocker, not a reason
  to disable TLS, remove the guard or silently relax destination validation.
- Raw diagnostics are server-sanitized metadata. The UI selects known route
  fields for export and never reads browser/profile credential storage.
- Working trust behavior is deliberately preserved. Any later certificate error
  must be diagnosed separately from authentication, access denial and crawl scope.
