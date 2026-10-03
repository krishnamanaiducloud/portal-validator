# Portal Validator

Portal Validator 1.2.0 is a browser-based HTTP/HTTPS validator for public,
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
- Discovered links are crawled only on the original hostname and its equivalent
  `www` form. `Include subdomains` expands that crawl boundary using DNS-label
  matching; external links are reported but not crawled.
- Optional resource hosts allow only subresources, not recursive crawling.
- Scan-supplied Basic, bearer, and custom-header credentials are sent only to
  approved credential hosts. Browser cookie domain rules remain in effect.
- Mutating methods are blocked unless the caller explicitly acknowledges them
  and supplies safe portal-scoped path prefixes.
- Only ports 80, 443, 8080, and 8443 are accepted.

Authentication modes are anonymous, HTTP Basic, bearer/token, custom headers,
cookies, and mounted Playwright `storage_state`. Reports use generic behavioral
classifications such as `PASS`, `AUTH_REQUIRED`, `AUTH_FAILED`, `AUTH_TIMEOUT`,
`MFA_REQUIRED`, `SESSION_EXPIRED`, `ACCESS_RESTRICTED`, `TLS_ERROR`,
`DNS_ERROR`, `NETWORK_ERROR`, `TIMEOUT`, `HTTP_ERROR`, and `NAVIGATION_ERROR`.

Treat `storage_state` files as secrets: generate them through an approved
authentication workflow, store them in an OpenShift Secret, mount them
read-only at `/auth`, restrict access, rotate them, and never commit them.

Run this service only for systems you are authorized to validate, and protect
the service itself with organizational access controls.

## Enterprise CA trust

The container entrypoint is the only trust writer. Before Uvicorn starts it:

1. Reads the required managed bundle from
   `PORTAL_VALIDATOR_MANAGED_CA_BUNDLE`.
2. Reads each required path in `PORTAL_VALIDATOR_ADDITIONAL_CA_FILES` and each
   `*.crt`/`*.pem` in optional `PORTAL_VALIDATOR_OPTIONAL_CA_DIRS`.
3. Rejects missing required files, private keys, malformed PEM, oversized
   inputs, and additional chains without a self-signed root.
4. De-duplicates certificates and atomically writes `RUNTIME_CA_BUNDLE` under
   the writable non-root home.
5. Initializes `CHROMIUM_NSS_DB` with an empty password when needed and imports
   only the additional enterprise roots/intermediates. Stable managed
   nicknames allow certificate rotation without touching unrelated NSS entries.
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
| `PORTAL_VALIDATOR_ADDITIONAL_CA_FILES` | OS-path-separated required PEM files |
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
docker build -t mohankrishna999/portal-validator:1.2.0 .
docker build -f Dockerfile-debug \
  --build-arg PRODUCTION_IMAGE=mohankrishna999/portal-validator:1.2.0 \
  -t mohankrishna999/portal-validator:1.2.0-debug .
```

The debug image adds `debugpy`, hot reload, and port 5678. It inherits the same
browser and trust initialization as production.

For a local run, mount a complete managed bundle. Additional enterprise roots
are optional unless configured:

```bash
docker run --rm -p 8080:8080 \
  --read-only --tmpfs /tmp:rw,nosuid,size=512m \
  -v ./ca-bundle.crt:/etc/portal-validator/certs/ca-bundle.crt:ro \
  -v ./enterprise-root.crt:/etc/portal-validator/additional/root.crt:ro \
  -e PORTAL_VALIDATOR_ADDITIONAL_CA_FILES=/etc/portal-validator/additional/root.crt \
  mohankrishna999/portal-validator:1.2.0
```

## OpenShift

`openshift/deployment.yaml` creates an injection-labeled
`portal-validator-trusted-ca` ConfigMap for the managed bundle. It mounts that
bundle read-only and separately mounts `portal-validator-additional-ca`. Create
the additional ConfigMap without changing the cluster-managed ConfigMap:

```bash
oc create configmap portal-validator-additional-ca \
  --from-file=enterprise-root-ca.crt=./CNC-ROOT-CA.crt \
  --dry-run=client -o yaml | oc apply -f -
oc apply -f openshift/deployment.yaml
```

The deployment disables service-account token mounting, runs non-root, drops
all Linux capabilities, disallows privilege escalation, and uses the runtime
default seccomp profile. `$HOME` under `/tmp` is ephemeral by design, so every
new pod reconstructs trust from mounted ConfigMaps.

Verify a fresh pod:

```bash
oc logs deploy/portal-validator
oc exec deploy/portal-validator -- sh -c 'echo "$HOME"; python -m app.trust status'
oc exec deploy/portal-validator -- sh -c 'certutil -L -d "sql:$CHROMIUM_NSS_DB"'
oc exec deploy/portal-validator -- python - <<'PY'
from pathlib import Path
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    path = Path(p.chromium.executable_path)
    print("Playwright Chromium:", path, "exists:", path.is_file())
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    response = page.goto("https://google.com", wait_until="domcontentloaded", timeout=30000)
    print("STATUS:", response.status if response else None)
    print("TITLE:", page.title())
    browser.close()
PY
```

## Development and reports

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
```

Each result separates `page_load_status` (`LOADED`/`FAILED_TO_LOAD`) from
`validation_status` (`PASS`/`WARNING`/`FAIL`/`NOT_TESTED`). Failed subresources
remain findings and do not turn a successfully loaded main document into a load
failure. `tls_status=TRUSTED` means Chromium completed certificate-chain
validation; it does not claim independent inspection of the origin certificate
when an enterprise TLS proxy is present.

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
