# Portal Validator

Portal Validator 1.7.0 is an authenticated, read-only browser health validator for public,
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

Administrators may approve an exact method + hostname + query-free path for a
logically read-only application request, session refresh, or access-gate action.
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
    }
  ],
  "access_gates": [
    {"host": "portal.example.com", "selector": "#approved-access-gate"}
  ]
}
```

Rules use exact hosts and paths; URL wording, response status, and request body
never establish safety. An access-gate selector must resolve to one visible,
explicitly approved control, and any non-safe request caused by it still needs
its own safe-request rule. Authentication POSTs retain their separate narrow
main-frame authentication-chain exception. Browser-native session refresh runs
inside the same context; lost authenticated sessions terminate remaining route
validation as `SESSION_EXPIRED` instead of creating misleading failures.

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

The production image uses the pinned Chainguard Python base and Playwright
1.63.0 with its matching Chromium revision under `/ms-playwright`. A build-time
assertion fails the build if the expected browser is missing. The runtime keeps
`certutil`, removes build tooling, and runs as UID/GID 10001 while remaining
compatible with an arbitrary OpenShift UID.

Build versioned tags only:

```bash
docker build -t mohankrishna999/portal-validator:1.7.0 .
docker build -f Dockerfile-debug \
  --build-arg PRODUCTION_IMAGE=mohankrishna999/portal-validator:1.7.0 \
  -t mohankrishna999/portal-validator:1.7.0-debug .
```

The debug image adds `debugpy`, hot reload, and port 5678. It inherits the same
browser and trust initialization as production.

For a local run, mount a complete managed bundle and approved corporate CA
directory:

```bash
docker run --rm -p 8080:8080 \
  --read-only --tmpfs /tmp:rw,nosuid,size=512m \
  -v ./ca-bundle.crt:/etc/portal-validator/certs/ca-bundle.crt:ro \
  -v ./corporate-cas:/etc/portal-validator/zscaler:ro \
  mohankrishna999/portal-validator:1.7.0
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

Report schema `2.1` keeps route identity independent from the rendered title.
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
