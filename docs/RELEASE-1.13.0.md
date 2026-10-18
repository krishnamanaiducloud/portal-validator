# Portal Validator 1.13.0 — authentication-first enforcement

## Contract

The scan-wide access/readiness gate precedes route discovery, control
activation and application health assessment. Anonymous public sites remain
supported: the gate verifies usable public application access, not a mandatory
login. A static HTTP 200 shell alone does not prove a session is accepted.

Successful lifecycle:

`INITIALIZING → AUTHENTICATING → AUTHENTICATED → APPLICATION_READY → DISCOVERING_ROUTES → VALIDATING_ROUTES → COMPLETED`

Global authentication/readiness failure produces `scan_status=FAILED`,
`authentication_status=FAILED`, zero discovered/validated/tested routes and
empty application route/API inventories. Coverage is `NOT_STARTED`, not
partial success. Mid-scan session expiry invalidates previously collected
application results for that scan. Authentication request evidence is retained
separately, without request bodies, headers, credentials or query values.

Report schema 2.6 adds `authentication_error`, top-level authentication/scan
status, tested-route counts and a monotonic `scan_lifecycle`. The error contains
category, stage, available HTTP status/method, sanitized endpoint, policy
decision, duration and remediation. Application API tables do not contain
authentication diagnostics. A route-specific 403 after the global gate passes
is `AUTHORIZATION_DENIED`; other authorized routes continue to be validated.

The UI clears prior results at submission and rejects stale create, status,
report and cancellation responses using a local generation plus scan ID.
Failed jobs retain a readable report and expose no terminal state until the
report is attached. Authentication failures have a dedicated diagnostic panel.

## Security and compatibility

No corporate CA/NSS initialization, TLS verification, browser version, SSRF
policy, read-only POST approval or authentication-host approval is weakened.
Playwright remains 1.63.0 with its matching managed Chromium. Production and
debug images retain non-root/arbitrary-UID support. Only versioned image tags
are published. The Deployment image reference is updated; a cluster rollout is
an operator action, not part of publishing this release.

Consumers that previously interpreted failed bootstrap rows as application
routes must instead inspect `authentication_error`. Legacy internal job phase
names remain accepted for compatibility; new scans publish the lifecycle above.

## Verification

```powershell
python -m pytest -q --tb=short --show-capture=no
$env:PORTAL_VALIDATOR_URL='http://127.0.0.1:18139'
$env:UI_SCREENSHOT="$env:TEMP/portal-validator-1.13.0.png"
python tests/ui_check.py
```

The regression suite uses isolated generic synthetic sites: authenticated SSO,
hash routes, URL-less tabs, per-route API errors, denied routes, expired
sessions, missing readiness, invalid configuration and stale UI responses.
No real session profiles or organization-specific endpoints are required.

After an operator deploys the versioned image, inspect `/api/build-info` and
`/healthz`, run a public scan and an authorized-profile scan, then intentionally
use an expired test profile. The failed scan must have zero rows/counts,
`NOT_STARTED` coverage and actionable sanitized authentication diagnostics.
Live cluster/identity-provider verification requires operator access and is
not implied by local fixture or image tests.
