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

## Root causes and changed files

`app/main.py:execute_scan` previously admitted the bootstrap target before
access/readiness, published discovery/validation prematurely, and retained
passively discovered links after failed bootstrap. The gate now admits the
target only after readiness. `reject_global_authentication` stops browser work;
`require_current_session` also checks delayed denials during panel discovery.
Final-drain authentication failures discard application results atomically.

`app/reporting.py` adds a strictly whitelisted failure contract and separate
authentication evidence. It classifies a denied route after successful global
access as authorization failure. `app/scans.py` accepts the required lifecycle;
`app/main.py:_run_scan_job` attaches reports before publishing terminal state.

`app/static/app.js` adds scan generation/ID guards, immediate result clearing,
failed-job report retrieval, safe diagnostic rendering and authorization-failure
filtering. `app/static/index.html` adds the failure panel without redesigning the
dashboard. `app/version.py`, both Dockerfiles, `openshift/deployment.yaml` and
`README.md` align release references; Dockerfile stages/startup/security are
otherwise unchanged. The Deployment changes only its versioned image reference.

New files: `tests/test_authentication_first.py`,
`tests/test_authentication_first_reporting.py`, and this release note.

Updated regressions: `tests/test_app.py`,
`tests/test_application_readiness_conditions.py`,
`tests/test_auth_policy_integration.py`, `tests/test_authenticated_spa.py`,
`tests/test_bootstrap_route_retention.py`, `tests/test_execution_evidence.py`,
`tests/test_public_access_scan.py`, `tests/test_scan_configuration_contract.py`,
`tests/test_scan_deadlines.py`, `tests/test_sso_navigation_browser.py`,
`tests/ui_check.py`, and `tests/release_image_smoke.py`.

## Integrated remediation branches

- PR #1 (`fix/generic-auth-ops-request-visibility`): generic native
  disclosure, Bootstrap-style dropdown and header-menu discovery, observed
  menu-ancestry restoration, blocked/incomplete request visibility, the
  operator authentication-policy helper and its CI workflow.
- PR #2 (`fix/auth-fail-closed-scan-report`): superseded by the scan-wide gate
  above. Its job-level regression (a failed scan never exposes a previous
  scan's routes) is retained in `tests/test_auth_fail_closed_scan.py` against
  the `authentication_error` contract; its parallel report helper and duplicate
  workflow were not merged.

## Additional fixes

- `MFA_REQUIRED` is a distinct authentication failure category with its own
  remediation instead of being folded into `AUTHENTICATION_REQUIRED`.
- A policy-blocked authentication request is reported once in
  `authentication_diagnostics`, carrying the scan's failure category.
- At bootstrap, render settling keeps headroom inside the route budget, so a
  never-completing resource (tracking pixel, long poll) no longer turns a
  visibly ready public application into a gate timeout with zero routes.
- Authentication observation tolerates multi-hop client redirects that replace
  the document more often than the bounded DOM retry count.
- A navigation trigger whose `aria-expanded="true"` is stale after its panel
  was hidden or replaced is reopened after a short bounded mount window,
  instead of consuming the whole discovery budget. This restores nested menu
  and Material overlay discovery.
- `tests/test_broad_authenticated_discovery.py` scans a synthetic
  cookie-authenticated portal with more than 44 views (native disclosures, Bootstrap
  dropdown, sidebar, history and hash routes, URL-less tabs), asserts at least
  44 activated and validated views, per-view API initialisation and HTTP 500
  attribution to the initiating view, and zero routes without the session.
- Production base images are re-pinned to current Chainguard digests.

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

After an operator deploys the versioned image, inspect `/api/diagnostics/build` and
`/healthz`, run a public scan and an authorized-profile scan, then intentionally
use an expired test profile. The failed scan must have zero rows/counts,
`NOT_STARTED` coverage and actionable sanitized authentication diagnostics.
Live cluster/identity-provider verification requires operator access and is
not implied by local fixture or image tests.

```sh
oc -n "$NAMESPACE" get pods -l app=portal-validator -o custom-columns=NAME:.metadata.name,IMAGE:.spec.containers[0].image,IMAGE_ID:.status.containerStatuses[0].imageID
oc -n "$NAMESPACE" exec deployment/portal-validator -- python -c 'import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/diagnostics/build")),indent=2))'
oc -n "$NAMESPACE" logs deployment/portal-validator --since=15m | rg 'AUTHENTICATION_APPROVALS_APPLIED|AUTHENTICATION_OBSERVATION_COMPLETED|APPLICATION_SHELL|SCAN_AUTHENTICATION_FAILED|ROUTE_VALIDATED|SCAN_COMPLETED'
```
