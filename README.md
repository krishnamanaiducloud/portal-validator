# Portal Validator

A browser-based validator for public, private, and authenticated web portals. It crawls an explicitly bounded host with Chromium and reports broken pages, JavaScript errors, failed resources, performance, and missing security headers.

## Authentication modes

- Anonymous/public portal
- HTTP Basic credentials
- Bearer or API token
- Custom request headers
- Session cookies
- Playwright storage-state profiles for SSO, SAML, OIDC, MFA, and other interactive login flows

Sensitive headers are attached only to the approved portal hostname or its explicitly enabled subdomains. Secrets are held for one request and are not returned in reports. For SSO, complete authentication through an approved Playwright workflow, save its storage state as `<profile>.json`, and mount it read-only at `/auth`.

## Safety boundaries

- Navigation stays on the target hostname unless subdomains are explicitly enabled.
- CDN/API hosts are separate, explicit resource-only allowances.
- Loopback, link-local, multicast, reserved, and unspecified addresses are blocked.
- Private-network scanning requires explicit per-scan approval.
- `POST`, `PUT`, `PATCH`, and `DELETE` are blocked by default.
- Mutation traffic requires acknowledgement and path-prefix allowlisting.
- Only ports 80, 443, 8080, and 8443 are permitted.

Run this service only for portals you are authorized to test. Protect the validator itself behind your organization’s access control because it can reach approved private targets and receive temporary credentials.

## Production container

Both images use the pinned Chainguard Python development image and install Wolfi's current Chromium package. The application runs as UID/GID `10001`.

```bash
docker build -t mohankrishna999/portal-validator:1.0.1 .
docker run --rm -p 8080:8080 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  -v ./auth:/auth:ro \
  mohankrishna999/portal-validator:1.0.1
```

Open <http://localhost:8080>.

## Debug container

The debug image includes hot reload and a `debugpy` listener on port 5678.

```bash
docker build -f Dockerfile-debug -t mohankrishna999/portal-validator:1.0.1-debug .
docker run --rm -p 8080:8080 -p 5678:5678 \
  -v "$PWD/app:/app/app" -v "$PWD/auth:/auth:ro" \
  mohankrishna999/portal-validator:1.0.1-debug
```

## Tests

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

## OpenShift

Update the registry in `openshift/deployment.yaml`, create an optional `portal-validator-auth` secret containing SSO storage-state JSON files, and run `oc apply -f openshift/deployment.yaml`.

The deployment uses a non-root user, drops Linux capabilities, disables service-account token mounting, uses runtime-default seccomp, and mounts the SSO secret read-only.
