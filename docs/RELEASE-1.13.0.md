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

The runtime moves from Python 3.14 to Python 3.15 (`python-3.15`
`3.15.0_git20261017-r0`): Python 3.14.8 still accepts control characters in
`poplib` commands (CVE-2025-15367), which CPython 3.15 rejects. All pinned
dependencies install on 3.15; PyYAML, a `uvicorn[standard]` extra, builds from
source and uses its pure-Python implementation.

The debug image adds `curl`, `bind-tools` (`dig`, `nslookup`), `iproute2`
(`ip`, `ss`) and `jq` from an exact signed APK transaction, plus `debugpy` and
`pytest`. `openssl`, `certutil`, `ps`, `top` and `less` already ship in the
production image. The debug image runs with the same entrypoint, CA trust
initialization, TLS verification and network policy as production.

## Security scan results

Scanned on 2026-10-19 (UTC) with Trivy 0.72.0 (DB updated 2026-10-18 18:32
UTC; OS, Python and Node.js packages plus secrets) and Grype 0.104.0 (DB built
2026-10-18 06:27 UTC; image and Syft 1.46.0 SPDX SBOM). Source checks: pip-audit
2.10.1, Bandit 1.9.4, Hadolint 2.14.0 and Gitleaks 8.28.0.

| Check | Production `1.13.0` | Debug `1.13.0-debug` |
|---|---|---|
| Trivy Critical/High/Medium/Low | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| Trivy secrets | 0 | 0 |
| Grype Critical/High/Medium/Low | 0 / 0 / 3 / 0 | 0 / 0 / 3 / 0 |
| SBOM packages (SPDX) | 121 | 172 |

- pip-audit: no known vulnerabilities in `requirements.txt` or
  `requirements-dev.txt`.
- Gitleaks: no leaks in the 64-commit history or the working tree.
- Bandit: no High findings. Three Medium and six Low findings were reviewed as
  false positives: string constants such as `refresh_token` (B105), commented
  intentional `try/except/pass` (B110), the `$HOME` fallback path (B108) and
  fixed-argument `openssl`/`certutil` subprocess calls (B404/B603).
- Hadolint: warnings are root in builder stages that are not shipped (DL3002)
  and intentional word splitting of an exact-version APK constraints file
  (DL3018/SC2046/DL4006); the final stages run as UID 10001.

### Approved exception: alsa-lib

Grype matches three Medium CVEs against `alsa-lib 1.2.16.1-r3` through NVD CPE
ranges ("through 1.2.16.1"); the Wolfi security data used by Trivy lists none.
No fixed release exists upstream or in Wolfi, and both bundled Chromium builds
(full and headless shell) dynamically link `libasound.so.2`, so the library
cannot be removed without breaking browser scans.

| CVE | Issue | Precondition |
|---|---|---|
| CVE-2026-90781 | One-byte stack overflow parsing a control element identifier | Attacker-supplied ALSA state file or control identifier |
| CVE-2026-96674 | Integer overflow in topology element size | Attacker-supplied topology file |
| CVE-2026-96675 | Out-of-bounds read in the multi PCM plugin | Attacker-supplied ALSA configuration |

Compensating controls: the container has no sound devices, runs as a non-root
arbitrary UID with a read-only root filesystem, dropped capabilities and no
privilege escalation; ALSA configuration is root-owned image content, and the
validator never loads ALSA state, topology or configuration supplied by a scan
target. The release owner approved this exception for 1.13.0. Re-evaluate on
the next build and remove the exception once Wolfi publishes a fixed
`alsa-lib`.

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

## Executed verification

- Host suite (WSL2 Ubuntu, Python 3.14, Playwright 1.63.0 Chromium): 1168 of
  1169 passed in one full run; the remaining authentication-observation test
  passed after its fix, together with the 98 surrounding authentication tests.
- Image suite (debug image, Python 3.15.0, arbitrary UID, read-only root, all
  capabilities dropped): 1163 of 1169 passed. The six failures are
  `tests/test_operator_policy_script.py`, which executes the operator
  workstation helper `scripts/apply_auth_policy.sh`; the images intentionally
  ship no `bash`. Those tests pass on the host.
- Frontend: `tests/ui_check.py` passed against a live server, including
  failed-authentication zero-route rendering, stale-result isolation and
  44-route pagination.
- Release image smoke (`tests/release_image_smoke.py`) passed for both images
  with `--user 1000820000:0 --read-only --cap-drop ALL --security-opt
  no-new-privileges`: source integrity `VERIFIED`, Playwright 1.63.0 with
  Chromium 153.0.8010.12, strict Python and Chromium TLS through a disposable
  corporate CA, `/healthz`, redacted access logs, graceful SIGTERM and an
  idempotent entrypoint.
- Some sub-second browser fixtures are timing-sensitive on a heavily loaded
  host and were confirmed by isolated reruns.

## Published images

Built from commit `37ce675f537039610c43d6193e6607af9cec3bf9` for
`linux/amd64` only (the tested platform). Later commits on the release branch
change documentation and the Deployment reference only.

| Image | Digest | Compressed size |
|---|---|---|
| `docker.io/mohankrishna999/portal-validator:1.13.0` | `sha256:002f93b341a4e89fe67da9da451417f872d8f08a5896ffe8081b1c684ce85fdb` | 503.6 MB |
| `docker.io/mohankrishna999/portal-validator:1.13.0-debug` | `sha256:f1a5ac8e27281c51a380d676074254747d24536f1a8816f959a87defa5d8cca7` | 527.3 MB |

Both digests were confirmed from the registry and by pulling each image by
digest, which reported version 1.13.0, the commit above and `VERIFIED` source
integrity. `openshift/deployment.yaml` pins the production image by tag and
digest. No cluster rollout was performed.
