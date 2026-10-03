# Portal Validator

A browser-based validator for public, private, and authenticated web portals. It crawls an explicitly bounded host with Chromium and reports broken pages, JavaScript errors, failed resources, performance, and missing security headers.

Targets may be entered as a hostname such as `google.com` or as an HTTP(S) URL;
bare hostnames default to HTTPS.

## Authentication modes

- Anonymous/public portal
- HTTP Basic credentials
- Bearer or API token
- Custom request headers
- Session cookies
- Playwright storage-state profiles for SSO, SAML, OIDC, MFA, and other interactive login flows

Sensitive headers are attached only to the approved portal hostname or its explicitly enabled subdomains. Secrets are held for one request and are not returned in reports. For SSO, complete authentication through an approved Playwright workflow, save its storage state as `<profile>.json`, and mount it read-only at `/auth`.

## Safety boundaries

- Navigation stays on the target hostname and its equivalent `www`/non-`www`
  form unless subdomains are explicitly enabled.
- CDN/API hosts are separate, explicit resource-only allowances.
- Loopback, link-local, multicast, reserved, and unspecified addresses are blocked.
- Private-network scanning requires explicit per-scan approval.
- `POST`, `PUT`, `PATCH`, and `DELETE` are blocked by default.
- Mutation traffic requires acknowledgement and path-prefix allowlisting.
- Only ports 80, 443, 8080, and 8443 are permitted.

Run this service only for portals you are authorized to test. Protect the validator itself behind your organization’s access control because it can reach approved private targets and receive temporary credentials.

## Production container

Both images use the pinned Chainguard Python development image. The exact
Playwright version pinned in `requirements.txt` installs and uses its matching
Chromium revision under `/ms-playwright`; the application does not override it
with a system Chrome executable. The application runs as UID/GID `10001`.

```bash
docker build -t mohankrishna999/portal-validator:1.1.3 .
docker run --rm -p 8080:8080 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  -v ./auth:/auth:ro \
  -v ./corporate-ca.pem:/etc/portal-validator/certs/ca-bundle.crt:ro \
  -v ./zscaler-root-ca.crt:/etc/portal-validator/zscaler/zscaler-root-ca.crt:ro \
  -e CORPORATE_CA_BUNDLE=/etc/portal-validator/certs/ca-bundle.crt \
  mohankrishna999/portal-validator:1.1.3
```

Open <http://localhost:8080>.

## Debug container

The debug image includes hot reload and a `debugpy` listener on port 5678.

```bash
docker build -f Dockerfile-debug -t mohankrishna999/portal-validator:1.1.3-debug .
docker run --rm -p 8080:8080 -p 5678:5678 \
  -v "$PWD/app:/app/app" -v "$PWD/auth:/auth:ro" \
  -v ./zscaler-root-ca.crt:/etc/portal-validator/zscaler/zscaler-root-ca.crt:ro \
  mohankrishna999/portal-validator:1.1.3-debug
```

## Tests

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

Verify the Playwright-managed browser inside the production image:

```bash
docker run --rm -i --entrypoint python \
  mohankrishna999/portal-validator:1.1.3 - <<'PY'
from pathlib import Path
from playwright.sync_api import sync_playwright

with sync_playwright() as playwright:
    path = Path(playwright.chromium.executable_path)
    print("Playwright Chromium:", path)
    print("Exists:", path.is_file())
    browser = playwright.chromium.launch(
        headless=True,
        args=["--disable-dev-shm-usage"],
    )
    print("BROWSER LAUNCHED SUCCESSFULLY")
    browser.close()
PY
```

## OpenShift

The supplied manifest creates `portal-validator-trusted-ca` with the OpenShift
`config.openshift.io/inject-trusted-cabundle=true` label. The Cluster Network
Operator injects the cluster's merged public and organization CA bundle into
`ca-bundle.crt`; the deployment mounts it read-only at
`/etc/portal-validator/certs/ca-bundle.crt`.

Ensure the internal corporate root CA is present in the cluster-wide additional
trust bundle before deployment. If CA trust is managed only in this namespace,
remove the injection label and create the ConfigMap explicitly instead:

```bash
oc create configmap portal-validator-trusted-ca \
  --from-file=ca-bundle.crt=./corporate-ca-chain.pem \
  --dry-run=client -o yaml | oc apply -f -
```

Create the dedicated Zscaler root CA ConfigMap separately:

```bash
oc create configmap portal-validator-zscaler-ca \
  --from-file=zscaler-root-ca.crt=./zscaler-root-ca.crt \
  --dry-run=client -o yaml | oc apply -f -
```

The container entrypoint requires this certificate and imports it as
`Zscaler Root CA` with `C,,` trust into
`sql:$HOME/.local/share/pki/nssdb` before Uvicorn starts. The import is
idempotent, and startup fails if the mounted certificate is absent or cannot be
imported. The certificate remains external to the image.

The PEM file must contain the self-signed corporate root and any required
intermediate certificates. At startup, Portal Validator combines it with the
container's public CA bundle and imports it into Chromium's NSS database. An
invalid configured bundle fails startup. TLS verification remains enabled;
`ignore_https_errors` is never enabled.

Create an optional `portal-validator-auth` secret containing SSO storage-state
JSON files, then run `oc apply -f openshift/deployment.yaml`.

The deployment uses a non-root user, drops Linux capabilities, disables service-account token mounting, uses runtime-default seccomp, and mounts both the SSO secret and CA bundle read-only.

## Report status model

Each result reports page loading separately from validation:

- `page_load_status`: `LOADED` or `FAILED_TO_LOAD`
- `validation_status`: `PASS`, `WARNING`, `FAIL`, or `NOT_TESTED`
- `tls_status`: `TRUSTED`, `UNTRUSTED`, `NOT_APPLICABLE`, or `NOT_TESTED`
- `security_headers_status`: `PASS`, `WARNING`, or `NOT_TESTED`

Missing optional security headers, console errors, or failed subresources make a
successfully loaded page a `WARNING`; they do not turn it into a load failure.
Certificate failures are reported as `FAILED_TO_LOAD` with category
`TLS_CERTIFICATE_ERROR`, TLS `UNTRUSTED`, and security headers `NOT_TESTED`.
TLS `TRUSTED` means Chromium completed HTTPS certificate-chain validation. It
does not claim that the origin certificate was independently inspected, which
is important when a corporate proxy such as Zscaler terminates TLS.
