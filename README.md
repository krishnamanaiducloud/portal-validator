# Portal Validator

Portal Validator 1.9.0 is an authenticated, read-only browser health validator for public,
private, and authenticated portals. It follows real browser redirects,
classifies authentication outcomes, crawls a controlled portal scope, and
reports load, TLS, HTTP, console, resource, performance, and security-header
results without disabling certificate verification.

Targets may be hostnames (`google.com`, `www.google.com`) or complete HTTP(S)
URLs. Bare hostnames default to HTTPS.

## Navigation, crawl, and network safety

Browser navigation and crawling intentionally have different boundaries:

- Main-frame HTTP/HTTPS redirects may cross origins for generic SSO flows.
- Every main-frame destination is parsed, DNS-resolved, and checked before it
  is allowed. Loopback, link-local, multicast, reserved, unspecified, and
  cloud-metadata addresses are blocked. Private addresses require explicit
  per-scan approval.
- Redirect chains are bounded, loop-checked, sanitized, and returned in the
  report.
- Semantic links, navigation roles, safe menus/tabs, and SPA history/hash routes
  are discovered in one browser context. Routes are crawled only on the original
  hostname, its equivalent `www` form, or explicitly approved portal hosts.
  `Include subdomains` expands the primary boundary using DNS-label matching;
  external links are reported but not crawled.
- Route identities use a configurable query policy and always remove tracking
  and authentication parameters to prevent ID/pagination loops and report leaks.
- Optional resource hosts allow only subresources, not recursive crawling.
- Scan-supplied Basic, bearer, and custom-header credentials default to the
  exact target host and are sent to another portal/API host only when that host
  is explicitly credential-approved. Credential, crawl, and resource scopes
  are independent. Browser cookie domain rules remain in effect.
- Normal validation permits only GET, HEAD, and OPTIONS. Unexpected mutating
  requests are observed first, then blocked and reported as
  `READ_ONLY_MUTATION_BLOCKED`. Main-frame
  SSO form POSTs are handled separately: they are allowed only inside a detected
  authentication chain and every new destination still passes the network/SSRF
  policy.
- Only ports 80, 443, 8080, and 8443 are accepted.

### Passive API observation and read-only policy

Observed API Inventory is passive: it records safe metadata for every natural
browser request method, but it never probes, replays, retries, or transforms an
API call. Observation never implies permission. Unknown POST, PUT, PATCH,
DELETE, and other mutation-capable methods remain blocked before reaching the
target while their attempted method, sanitized host/path, route, and policy
outcome remain visible. Request/response bodies, headers, cookies, tokens, and
storage are never captured. Route totals and unique API totals are independent.

Authorized application owners may approve an exact POST + hostname + query-free
path for a logically read-only application request, session refresh, or
access-gate action. PUT, PATCH, and DELETE cannot be approved.
When an identifier varies, `path_pattern` may replace one or more complete path
segments with `{segment}`. Patterns must contain at least three segments and two
literal segments; globbing, `**`, prefix rules, and broad method rules are rejected.
Set `PORTAL_VALIDATOR_READ_ONLY_POLICY` to JSON, or mount the same JSON and set
`PORTAL_VALIDATOR_READ_ONLY_POLICY_FILE` (maximum 64 KiB). Configure only one:

```json
{
  "safe_application_requests": [
    {
      "method": "POST",
      "host": "portal.example.com",
      "path": "/api/read-query",
      "classification": "APPROVED_READ_POST"
    },
    {
      "method": "POST",
      "host": "portal.example.com",
      "path_pattern": "/api/items/{segment}/query",
      "classification": "APPROVED_READ_POST"
    }
  ],
  "access_gates": [
    {"host": "portal.example.com", "selector": "#approved-access-gate"}
  ]
}
```

Rules use exact hosts and exact or segment-bounded paths; URL wording, response
status, and request body never establish safety. An access-gate selector must resolve to one visible,
explicitly approved control, and any non-safe request caused by it still needs
its own safe-request rule. Authentication POSTs retain their separate narrow
main-frame authentication-chain exception. Browser-native session refresh runs
inside the same context; lost authenticated sessions terminate remaining route
validation as `SESSION_EXPIRED` instead of creating misleading failures.

For one scan, open **Discovery & health → Advanced → Approved read-only API
operations** and add a POST hostname plus exact path (or a bounded `{segment}`
pattern). Only add operations confirmed read-only by their application owner.
These approvals are not stored in browser preferences and do not authorize
unrelated requests, private-network access, or new crawl origins. The API field
is `approved_read_post_operations`, for example:

```json
{
  "target": "https://portal.example.net",
  "approved_read_post_operations": [
    {"method": "POST", "host": "api.example.net", "path": "/v1/read-query"}
  ]
}
```

The portal must naturally generate the call; the validator never creates or
replays its body. Blocked calls remain in the inventory with `NOT_EXECUTED`, no
HTTP response, and a read-only block count. `network_observation` reconciles the
scan-wide observed methods and request count with the serialized API inventory,
including calls made during discovery or outside a route snapshot. Request
correlation follows the live underlying Playwright request rather than a reused
Python object address.

Authentication modes are anonymous, HTTP Basic, bearer/token, custom headers,
cookies, and mounted Playwright `storage_state`. Reports use generic behavioral
classifications such as `PASS`, `AUTH_REQUIRED`, `AUTH_FAILED`, `AUTH_TIMEOUT`,
`MFA_REQUIRED`, `SESSION_EXPIRED`, `ACCESS_RESTRICTED`, `TLS_ERROR`,
`DNS_ERROR`, `NETWORK_ERROR`, `TIMEOUT`, `HTTP_ERROR`, and `NAVIGATION_ERROR`.
Bearer input accepts either a raw token or one leading `Bearer` scheme and is
normalized to exactly one `Authorization: Bearer ...` header. The transient
secret field is cleared after submission and secret values are never returned.
In SSO mode, the validator owns no Authorization header and does not replace an
application-generated bearer credential.

Treat `storage_state` files as secrets: generate them through an approved
authentication workflow, store them in an OpenShift Secret, mount them
read-only at `/auth`, restrict access, rotate them, and never commit them.
The UI discovers valid `*.json` profiles from this mount; users cannot enter an
arbitrary container path. Desktop browser sessions are separate from the
Playwright Chromium session running in OpenShift.

### Automatic session refresh

For a profile named `/auth/approved.json`, an optional read-only companion file
`/auth/approved.refresh.json` enables silent browser refresh:

```json
{
  "refresh_url": "https://identity.example.net/session/refresh",
  "timeout_ms": 60000,
  "settle_ms": 1500
}
```

The mounted state seeds a private `0600` runtime copy. Before crawling, the same
Playwright context visits the configured refresh URL, allowing the identity
provider's normal refresh cookie/token flow to run. After a successful portal
validation, the updated browser state is atomically saved under
`$HOME/.portal-validator/sessions` and reused by later scans in that pod. The
refresh URL, cookies, tokens, and storage contents are never returned in a
report. An interactive login or MFA challenge is not guessed or bypassed; it is
reported as `SESSION_EXPIRED`, `AUTH_REQUIRED`, or `MFA_REQUIRED`. Pod-local
state is intentionally ephemeral, so the mounted Secret remains the bootstrap
source after a rollout.

Run this service only for systems you are authorized to validate, and protect
the service itself with organizational access controls.

## Enterprise CA trust

The container entrypoint is the only trust writer. Before Uvicorn starts it:

1. Reads the required managed bundle from
   `PORTAL_VALIDATOR_MANAGED_CA_BUNDLE`.
2. Recursively discovers `*.crt`, `*.pem`, and `*.cer` under the existing
   `/etc/portal-validator/zscaler` mount by default. Colon-separated directory
   overrides and legacy file inputs remain supported for compatibility.
3. Parses every discovered X.509 certificate, rejects malformed/private-key
   inputs, skips non-CA certificates, and fails if no usable self-signed root
   is present.
4. De-duplicates certificates and atomically writes `RUNTIME_CA_BUNDLE` under
   the writable non-root home.
5. Initializes `CHROMIUM_NSS_DB` with an empty password when needed and imports
   only semantically validated self-signed enterprise roots with `C,,` trust.
   Intermediates remain available in the PEM bundle but never receive NSS root
   trust. The general managed bundle is never copied into NSS. Stable logical-
   path nicknames and fingerprint checks make restarts idempotent and safely
   handle ConfigMap certificate rotation without touching unrelated entries.
6. Exports `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `CURL_CA_BUNDLE`, then
   uses `exec` to start the original command.

The OpenShift-managed ConfigMap remains read-only and is never overwritten.
Certificates are mounted at deployment time, not baked into the image. TLS
verification remains enabled (`ignore_https_errors=False`); no insecure bypass
flags are used.

Relevant environment variables:

| Variable | Default / purpose |
|---|---|
| `HOME` | `/tmp/portal-validator-home` |
| `PORTAL_VALIDATOR_MANAGED_CA_BUNDLE` | `/etc/portal-validator/certs/ca-bundle.crt` (required) |
| `PORTAL_VALIDATOR_ADDITIONAL_CA_DIRS` | Colon-separated required directories; defaults to `/etc/portal-validator/zscaler` |
| `PORTAL_VALIDATOR_BROWSER_CA_DIRS` | Optional browser-root override; defaults to the additional CA directories |
| `PORTAL_VALIDATOR_ADDITIONAL_CA_FILES` | Legacy OS-path-separated required PEM files |
| `PORTAL_VALIDATOR_OPTIONAL_CA_DIRS` | OS-path-separated optional certificate directories |
| `RUNTIME_CA_BUNDLE` | `$HOME/.portal-validator/ca-bundle.crt` |
| `CHROMIUM_NSS_DB` | `$HOME/.local/share/pki/nssdb` |
| `PORTAL_VALIDATOR_TRUST_STATUS` | `$HOME/.portal-validator/trust-status.json` |
| `LOG_LEVEL` | `INFO`; use `DEBUG` only for diagnostics |

## Images

The multi-stage production image uses a digest-pinned Chainguard Python builder
and a digest-pinned Wolfi runtime. Only the application virtualenv, matching
Playwright 1.63.0 Chromium under `/ms-playwright`, and required runtime libraries
are shipped. Compiler/download tools, a second system browser, and package caches
stay outside the final image. Browser permissions are set before copying to avoid
duplicating the browser layer. A build-time check verifies the expected executable
and launches Chromium in the final runtime. The runtime retains `certutil` and
runs as UID/GID 10001 while supporting an arbitrary OpenShift UID.

Build versioned tags only:

```bash
docker build -t mohankrishna999/portal-validator:1.9.0 .
docker build -f Dockerfile-debug \
  --build-arg PRODUCTION_IMAGE=mohankrishna999/portal-validator:1.9.0 \
  -t mohankrishna999/portal-validator:1.9.0-debug .
```

The debug image incrementally adds `debugpy`, test tools, hot reload, and port
5678 to the production virtualenv, rather than copying a second virtualenv.
It inherits the same browser and trust initialization as production.

For a local run, mount a complete managed bundle and approved corporate CA
directory:

```bash
docker run --rm -p 8080:8080 \
  --read-only --tmpfs /tmp:rw,nosuid,size=512m \
  -v ./ca-bundle.crt:/etc/portal-validator/certs/ca-bundle.crt:ro \
  -v ./corporate-cas:/etc/portal-validator/zscaler:ro \
  mohankrishna999/portal-validator:1.9.0
```

## OpenShift

`openshift/deployment.yaml` creates an injection-labeled
`portal-validator-trusted-ca` ConfigMap for the managed bundle. It mounts that
bundle read-only and mounts every key from the existing combined
`portal-validator-zscaler-ca` ConfigMap at `/etc/portal-validator/zscaler`.
The cluster-managed ConfigMap is not modified and no additional CA ConfigMap is
created:

```bash
oc apply -f openshift/deployment.yaml
```

The deployment disables service-account token mounting, runs non-root, drops
all Linux capabilities, disallows privilege escalation, and uses the runtime
default seccomp profile. `$HOME` under `/tmp` is ephemeral by design, so every
new pod reconstructs trust from mounted ConfigMaps.

Verify a fresh pod:

```bash
oc logs deploy/portal-validator
oc exec deploy/portal-validator -- sh -c \
  'tr "\000" "\n" </proc/1/environ | grep -E "^(HOME|SSL_CERT_FILE|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|PORTAL_VALIDATOR_MANAGED_CA_BUNDLE|PORTAL_VALIDATOR_ADDITIONAL_CA_DIRS|PORTAL_VALIDATOR_BROWSER_CA_DIRS|RUNTIME_CA_BUNDLE|CHROMIUM_NSS_DB)="'
oc exec deploy/portal-validator -- sh -c \
  'grep -c "BEGIN CERTIFICATE" "$RUNTIME_CA_BUNDLE"'
oc exec deploy/portal-validator -- sh -c \
  'cat "$PORTAL_VALIDATOR_TRUST_STATUS"'
oc exec deploy/portal-validator -- sh -c 'certutil -L -d "sql:$CHROMIUM_NSS_DB"'
oc exec deploy/portal-validator -- curl --fail --show-error --location https://google.com
oc exec -i deploy/portal-validator -- python - <<'PY'
from pathlib import Path
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    path = Path(p.chromium.executable_path)
    print("Playwright Chromium:", path, "exists:", path.is_file())
    browser = p.chromium.launch(headless=True)
    for url in ("https://google.com", "https://your-authorized-internal-portal.example"):
        page = browser.new_page()
        response = page.goto(url, wait_until="domcontentloaded", timeout=60000)
        print(url, "STATUS:", response.status if response else None, "TITLE:", page.title())
        page.close()
    browser.close()
PY
```

## Development and reports

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
```

### Asynchronous scan API

The UI does not keep a long-running request open through the OpenShift router.
It creates a scan with `POST /api/scans`, polls `GET /api/scans/{scan_id}`, and
retrieves the completed report from `GET /api/scans/{scan_id}/report`. Creation
returns `202 Accepted` immediately. `POST /api/scans/{scan_id}/cancel` requests
graceful cancellation; the current route finishes and the shared browser
context is closed before a partial report is finalized. The legacy synchronous
`POST /api/scan` remains available for compatible clients, but new integrations
should use the asynchronous endpoints.

States are `QUEUED`, `STARTING`, `AUTHENTICATING`, `DISCOVERING`, `VALIDATING`,
`FINALIZING`, `COMPLETED`, `PARTIAL`, `FAILED`, and `CANCELLED`. Progress and
errors contain only sanitized metadata. The configured total timeout is the
application scan budget and produces `PARTIAL / SCAN_TIMEOUT`; it is not an
HTTP request timeout.

The job registry is bounded and process-local. The supplied deployment uses a
single application replica. Multi-replica or restart-surviving job retrieval
requires a shared job store such as an approved database or Redis deployment.

Each result separates `page_load_status` (`LOADED`/`FAILED_TO_LOAD`) from
`validation_status` (`PASS`/`WARNING`/`FAIL`/`NOT_TESTED`) and the authoritative
page outcome (`PASS`, `PASS_WITH_WARNINGS`, authentication outcomes, or an
actual failure). `PASS_WITH_WARNINGS` remains a passed page. Expected resources
skipped by validator policy are informational and deduplicated; unexpected
failed subresources remain warnings and do not turn a successfully loaded main
document into a load failure. `tls_status=TRUSTED` means Chromium completed certificate-chain
validation; it does not claim independent inspection of the origin certificate
when an enterprise TLS proxy is present.

Report schema `2.3` keeps route identity independent from the rendered title and
adds route-level application API coverage plus network-settle evidence.
It preserves canonical hash/hashbang/history paths and exposes `route_name`,
`route_name_source`, `route_name_confidence`, `display_path`, `spa_route`, and
deduplicated discovery provenance. Navigation labels and accessible names rank
ahead of headings and document titles, so a shared SPA title cannot collapse
distinct routes. A failed validation also includes `failure_dimension`,
`failure_reason`, and sanitized supporting findings while retaining document
HTTP status as independent evidence. Client-only transitions display
`N/A (SPA)` rather than fabricating an HTTP response.

The portal-health summary also reports discovered, eligible, queued, validated,
skipped, and not-tested routes with `COMPLETE`, `PARTIAL`, `FAILED`, or
`CANCELLED` coverage
and an explicit termination reason. The default maximum is 50 routes and the
request-scoped `max_pages` value limits routes actually validated rather than
routes discovered. Terminal counters follow `discovered = validated +
not_tested + skipped`; unexecuted routes carry an explicit reason. Summary cards
drill into route, API, resource, security, and coverage evidence.

Observed API calls are aggregated by sanitized method/host/normalized path with
status distribution, timing, failure classification, affected routes, allowed
and blocked counts, request classifications, and bootstrap/authentication/route
validation/session-refresh phase counts. Every natural method is observed
before read-only enforcement. Naturally observed authentication POSTs are
visible, but bodies, credentials, and sensitive headers are never captured.
Required route APIs and optional/background APIs
are attributed separately so an explained critical dependency failure can fail
a route without treating telemetry as equivalent. Resources,
APIs, and routes remain separate inventories. Browser APIs are observed only
from natural application activity; the validator never probes or replays a
discovered endpoint. Observed API Inventory is therefore not an active API
scanner. Document-level security recommendations are evaluated on
actual document responses and are not repeated for each inherited SPA route.

Same-document routes preferentially reactivate the originally discovered safe
semantic link/menu/tab control. Direct history/hash transitions are a fallback.
After activation, a bounded adaptive settle window combines DOM stability with
route-scoped network quiet so delayed component and microfrontend requests are
attributed before the route closes. Config traffic is reported separately from
application API coverage; blocked business requests remain visible without being
treated as target network failures.

Route **Time** and slow warnings now use `application_load_ms`, a passive
application-readiness estimate: navigation/SPA activation plus observed render
and network work, excluding trailing stability confirmation, minimum observation
waits, and discovery/reporting overhead. The report separately exposes
`application_navigation_ms`, `application_settle_ms`, `validator_overhead_ms`,
and `total_validation_ms`, with detailed DOM/API/observation timings retained.
`application_load_ms = application_navigation_ms + application_settle_ms`;
validator overhead is the remaining route validation time. This is not a Core
Web Vitals measurement. Slow warnings compare this estimate against the exact
UI-configured `slow_page_threshold_ms`, for example
`Slow route: 5.82s > configured 5.0s threshold`.
API **Average Time (ms)**/**Worst Time (ms)** use completed responses only;
blocked, pending, and failed requests cannot inflate response-time averages.
**Refresh Calls** counts recognized authentication/session-refresh traffic,
not ordinary repeated application calls. Bootstrap, authentication, and route
calls retain separate phase counts.

**Maximum time / route** (`timeout_ms`) bounds navigation, readiness, and route
discovery rather than forcing each route to wait that long. The total scan
budget starts at scan entry and includes browser queue/startup time; expiry
preserves completed routes and reports remaining coverage as partial/not tested.
Advanced settings independently configure DOM stability (`render_settle_ms`),
minimum observation (`min_observation_ms`), and network quiet (`network_quiet_ms`).
Observation listeners remain active throughout the browser context lifetime;
shortening readiness waits does not uninstall API listeners. Requests that
finish after a route closes are reconciled with their initiating route.
The report includes a secret-free `scan_configuration` snapshot and
`scan_timing` diagnostics for authentication, discovery, validation, finalization,
browser/page counts, and full versus SPA navigations.

Approved, naturally issued read-only POSTs are observed and evaluated even when
asset/resource checking is disabled. Approval still requires an explicit
method/host/path rule and does not bypass SSRF policy. A completed required API
500 is a target failure; a denied POST is a validator-policy block, not a target
failure. Popup-origin requests retain their initiating route and shared session.
No endpoint is probed, replayed, or given blanket POST permission.

API and route **Columns** controls independently persist only column visibility
in `portal-validator.api-columns` and `portal-validator.route-columns`. All new
columns default to visible, identifying columns remain available, and density
defaults to Compact. Header tooltips describe each metric. Every
`PASS_WITH_WARNINGS` route exposes `warning_count` and structured
`warning_reasons` with a code, description, affected component, safe evidence,
and threshold where applicable. The table shows warning counts and summaries;
route details show readable reasons without requiring raw JSON. Healthy still
includes both PASS and PASS_WITH_WARNINGS; warnings never count as failed routes.

The collapsible **Resource Details** view reads the browser's natural
ResourceTiming entries without additional downloads. Transfer size, encoded body
size, and decoded body size are separate byte measurements; inaccessible timing
data is unavailable, not a fabricated zero. Total transfer covers measurable
resources only. Large resources remain non-blocking warnings. Independent
Advanced thresholds default to 512 KiB for images and CSS/fonts, and 1 MiB for
JavaScript and other resources (`large_image_threshold_bytes`,
`large_css_font_threshold_bytes`, `large_js_threshold_bytes`, and
`large_resource_threshold_bytes`). Resource Details supports search, route,
status, type, failed/large filters, numeric sorting, and independent column
visibility; API method filtering explicitly distinguishes no observed POSTs
from POSTs hidden by filters.

Logs are structured JSON with a per-scan ID. URLs, query secrets, credentials,
tokens, cookies, storage state, and certificate/private-key material are
redacted or excluded at the centralized logging boundary.

## Troubleshooting classifications

- `TLS_ERROR`: Chromium rejected the certificate chain. Verify the managed and
  additional CA mounts, entrypoint logs, runtime bundle, and NSS database; do
  not add a TLS bypass.
- `AUTH_REQUIRED`: the page exposed a login/authentication flow and no usable
  authenticated session was supplied. Use an approved `storage_state` or other
  supported mode.
- `AUTH_FAILED` / `SESSION_EXPIRED`: supplied authentication was rejected or a
  saved browser session returned to login. Rotate or recreate the secret.
- `ACCESS_RESTRICTED`: the server returned 403 or an equivalent restricted
  result. Confirm authorization and network policy.
- `DNS_ERROR`: a destination did not resolve. Check cluster DNS and the exact
  hostname.
- `NETWORK_ERROR`: connection or SSRF policy blocked the destination. Private
  networks require explicit approval; metadata, loopback, and link-local
  destinations always remain blocked.
- `TIMEOUT` / `AUTH_TIMEOUT`: increase per-page or total timeout only after
  checking DNS, proxy, browser, and IdP latency.
- `HTTP_ERROR`: navigation completed but the server returned an HTTP error.
- `NAVIGATION_ERROR`: inspect the sanitized redirect chain and browser error;
  common causes are malformed redirects, redirect loops, or redirect limits.
