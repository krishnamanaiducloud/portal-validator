# Portal Validator 1.12.10 - explicit authentication and view evidence

## Root causes and focused corrections

The valid authentication-host contract already worked in 1.12.9:
`phaseConfiguration` -> submitted JSON -> `ScanRequest.authentication_hosts`
-> scoped storage/context -> `AuthenticationNavigationPolicy` -> report count.
A zero count means the accepted request contained no approved hosts. A mounted
profile supplies session state; it never implicitly approves its identity hosts.
The correction does not invent hosts or derive approvals from cookies.

Confirmed defects and corrections:

| Existing behavior | Corrected behavior |
| --- | --- |
| Unknown request fields were silently discarded, including misspelled authentication configuration. | Scan/authentication schemas reject unknown fields with useful non-sensitive validation metadata. |
| Default HTTP 422 errors could echo rejected credential values. | The validation handler returns field/code metadata and fixed guidance, never rejected values or exception text. |
| Missing profile/credential errors surfaced only after a scan was queued. | Profile and credential configuration is checked before the asynchronous scan is accepted. |
| An OAuth token POST with zero approved identity hosts was safely blocked, but a rendered shell could still report authentication PASS and complete coverage. | Genuine denied protocol attempts retain precise authentication reasons and invalidate protected application readiness, including delayed/final-drain evidence. |
| A configured readiness selector could race document replacement. | Read-only condition checks use the existing bounded navigation-aware retry. |
| A blank selected tab inherited the surrounding shell's healthy content. | Readiness measures the observed tab panel, including open shadow content; empty/missing panels cannot inherit the parent shell's readiness. |
| Lazy iframe menu discovery observed the parent page instead of the frame. | The existing readiness callback observes the frame that owns the expanded menu. |
| A child view failed after one false parent-readiness sample even when the condition appeared within the remaining budget. | The child-parent check polls the actual condition within the existing bounded readiness deadline. |
| Policy-only API warnings appeared in the Failed only drilldown. | Failure filtering requires actual target HTTP/network/response-body failure evidence. Policy restrictions remain in the inventory. |
| Endpoint inspectors showed aggregate state without individual request lifecycle reasons. | Inspectors include an allowlisted projection of correlated request occurrences, route identities and explicit incomplete/block/transport evidence. |
| Chromium ERR_TIMED_OUT and ERR_SSL_ errors could become generic network failures. | Explicit timeout/TLS error markers retain their classification; ordinary aborts remain cancellations. |

Authorization methods are unchanged: authentication POSTs still require narrow
protocol/transaction/source/destination evidence. Authentication diagnoses do
not authorize requests. Business POST approvals remain separate and explicit;
no POST is synthesized or replayed. HTTP statuses, TLS enforcement, SSRF,
credential isolation, existing CA/NSS initialization and safe activation rules
are preserved.

## Configuration and dashboard

The existing Approved authentication hosts input is now visible in the
Authentication panel, with a configured-host count and missing-approval guidance.
Comma/whitespace-separated hosts are normalized and deduplicated before request
serialization, then validated by the backend. No configuration is silently
inferred or saved to local storage. Public websites still default to no auth.

An optional `readiness_event` accepts a bounded event name. An init script
observes the owner-provided window/document event before application scripts
run, retaining only a document-scoped boolean, never an event payload. If both
`readiness_selector` and `readiness_event` are configured, both must succeed.
The state resets on full-document navigation. Existing timing bounds and generic
readiness remain the default; no fixed application-specific sleep is introduced.

New Authentication diagnostics show precise generic reason codes such as
`AUTHENTICATION_HOSTS_REQUIRED`, `AUTHENTICATION_HOST_NOT_APPROVED`, and
`AUTHENTICATION_FLOW_NOT_ACTIVE`. The dashboard shows at most 50 diagnostic
rows with an explicit total; every record remains in exported JSON. New
per-request inspectors omit bodies, headers, query values, cookies, storage,
and free-form transport errors. Actual browser error codes are safe metadata.
Existing columns, density, route/API pagination and hierarchy remain available.

## Changed files

```text
app/main.py
app/navigation.py
app/health.py
app/discovery.py
app/reporting.py
app/static/app.js
app/static/index.html
app/version.py
tests/test_scan_configuration_contract.py (new)
tests/test_authentication_denial_diagnostics.py (new)
tests/test_application_readiness_conditions.py (new)
tests/test_api_failure_taxonomy.py (new)
tests/test_sso_navigation_browser.py
tests/test_app.py
tests/ui_check.py
tests/release_image_smoke.py
Dockerfile
Dockerfile-debug
openshift/deployment.yaml
README.md
docs/RELEASE-1.12.10.md (new)
```

Dockerfiles retain the existing pinned bases, Python environment, matching
Playwright/Chromium installation, entrypoint and non-root runtime. The
Deployment changes only the versioned image reference; Secret/CA mounts and
restricted security settings are unchanged. No cluster rollout is performed
by building or publishing an image.

## Verification

Controlled regressions cover public multipage/hash/history sites, safe Material
menus, nested tabs, delayed remote views, open shadows, same-origin frames,
authorized SSO and expired sessions, approved/read-only and blocked POSTs,
HTTP errors, explicit transport timeouts, navigation interruptions, partial
coverage, and inventory pagination. Missing-host OAuth is now authentication
blocked, not a successful protected scan. The existing seven-view Material
fixture remains intact; this release does not claim private-portal coverage.

The full source run collected 825 cases: 824 passed and the Windows ConfigMap
symlink fixture skipped. The final late-parent readiness correction added one
case; its final-source readiness/resource/Material suite passed all 46 cases.
Final collection contains 826 cases. The integrated dashboard smoke passed,
including actual form-to-API host/event submission, authentication guidance,
safe correlated occurrence diagnostics, failure filtering, 1,000-record API
pagination, mobile layout and strict CSP.

The final debug image passed 48 focused Linux cases with zero failures/skips,
including the ConfigMap symlink test, seven-view Material scan, and all new
authentication/readiness/configuration/API taxonomy cases. Source identity was
VERIFIED before and after, and all application imports came from `/app`, not
a host-source mount. Two synthetic test-only budgets were adjusted after
container timing exposed an unsupported 200 ms positive-readiness assumption
and a short activation budget. All assertions and production limits remained
unchanged; the adjusted host cases also passed. Prior failed-run logs were
preserved rather than counted as successful runs.

Both images passed release smoke under arbitrary UID `1000820000`, read-only
root, dropped capabilities and no-new-privileges. Strict Python and Chromium
local/NSS TLS, Google HTTP 200, application/debug startup, source identity,
redacted access logging, graceful SIGTERM, and repeated trust initialization
passed. The first debug public-navigation check hit a transport timeout; its
unchanged full retry passed without altering TLS checks or timeouts.

Completed Trivy 0.72.0 scans found zero vulnerabilities at every severity in
both final images, using the database updated `2026-10-13T13:06:33Z`. The
initial production analysis timed out; serial analysis (`--parallel 1`,
10-minute limit) completed successfully for both. Scan scheduling changed,
not vulnerability policies or TLS settings. No Java artifacts were detected.
These are time-specific scanner results, not guarantees about future findings.

### Published artifacts

Both `linux/amd64` images were built from application commit
`1b1b301046cf30f76074c637c78bfd401c3df6f1` at `2026-10-14T04:19:30Z`
and pushed to Docker Hub on October 14, 2026 UTC. Runtime Playwright 1.63.0,
Chromium revision 1243 and glibc 2.44-r8 remain aligned with the working build.

| Tag | Manifest digest |
| --- | --- |
| `mohankrishna999/portal-validator:1.12.10` | `sha256:90d457e19c38705af5b255cbb0146e63b940560744904d193255cb77d318ec0e` |
| `mohankrishna999/portal-validator:1.12.10-debug` | `sha256:a9e5f8d7a4c69cbfc0fde27b905b60d0060bd82b05f1651bece1a6e633cfa286` |

Independent Docker Hub registry HTTPS checks verified both manifest digests
against their downloaded bytes and verified the referenced config digests.
Both remote images use Docker schema 2 with gzip layers (18 production,
20 debug), report `linux/amd64`, user `10001:10001`, version `1.12.10`, and
the application revision above. No TLS verification was disabled for these
registry checks.

No `latest` or `prod-*` tags were created. Subsequent publication records and
test-only fixture-budget adjustments do not change application source inside
these images; their embedded revision intentionally identifies the application
commit above. No cluster rollout or live private-portal validation was performed.

```sh
python -m pytest -q --tb=short --show-capture=no tests
PORTAL_VALIDATOR_URL=http://127.0.0.1:8080 UI_SCREENSHOT=/tmp/portal-ui.png python tests/ui_check.py
docker buildx build --builder default --platform linux/amd64 --provenance=false --sbom=false --output type=docker,oci-mediatypes=false,compression=gzip --build-arg VCS_REF="$(git rev-parse HEAD)" --build-arg BUILD_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)" -t mohankrishna999/portal-validator:1.12.10 .
docker buildx build --builder default --platform linux/amd64 --provenance=false --sbom=false --output type=docker,oci-mediatypes=false,compression=gzip --build-arg PRODUCTION_IMAGE=mohankrishna999/portal-validator:1.12.10 -f Dockerfile-debug -t mohankrishna999/portal-validator:1.12.10-debug .
trivy image --image-src docker --scanners vuln mohankrishna999/portal-validator:1.12.10
trivy image --image-src docker --scanners vuln mohankrishna999/portal-validator:1.12.10-debug
```

For each final image, run `tests/release_image_smoke.py` as UID `1000820000:0`
with a read-only root filesystem, dropped capabilities, no-new-privileges,
writable `/tmp`, and no application-source bind mount. Enable
`RELEASE_SMOKE_PUBLIC_HTTPS=true`; enable `RELEASE_SMOKE_DEBUG=true` for debug.
Check the exact application commit as well as VERIFIED source integrity.

After an independently authorized deployment, select the intended context and
namespace; inspect the immutable imageID and runtime build identity:

```sh
oc -n "$NAMESPACE" get pods -l app=portal-validator -o custom-columns=NAME:.metadata.name,IMAGE:.spec.containers[0].image,IMAGE_ID:.status.containerStatuses[0].imageID
oc -n "$NAMESPACE" exec deployment/portal-validator -- python -c 'import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/diagnostics/build")),indent=2))'
oc -n "$NAMESPACE" exec deployment/portal-validator -- sh -c 'id; certutil -L -d "sql:$HOME/.local/share/pki/nssdb"'
```

Use an authorized generic target, select the intended mounted profile, and
explicitly configure each required identity-provider host. Verify:

1. Effective authentication-host count matches the request.
2. Authentication diagnostics explain each rejected protocol request.
3. Application readiness succeeds before active protected route discovery.
4. Distinct hash/history routes and nested views retain their hierarchy.
5. Natural POST attempts and actual HTTP failures appear with route attribution.
6. Incomplete/canceled/policy-blocked observations are not invented HTTP failures.
7. Partial coverage explains missing permissions, unsafe controls and limits.

## Remaining limitations

No image can manufacture authorization, repair interactive MFA, bypass a bot
challenge, or safely discover arbitrary state-changing controls. A profile can
expire and approved SSO transactions can still require user action. Generic
readiness is heuristic; applications with ambiguous loading surfaces should
provide a visible readiness selector or document event. Events emitted before
the validator context exists are not proof for a newly loaded document. Polling,
permissions and configured limits can prevent exhaustive coverage; even a scan
that processes every discovered candidate cannot prove every possible view.

No organization-specific destination, credential, session profile or certificate
is included in this release. Live private application behavior is not verified
by synthetic fixtures or by public HTTPS smoke tests.
