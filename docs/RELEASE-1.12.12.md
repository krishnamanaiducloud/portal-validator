# Portal Validator 1.12.12 - explicit authentication policy and bootstrap readiness

The security review used source baseline
`9e77779874a0ceb0a81da56507738c5823f679ca` (1.12.11). The seven reported Claude
changes were absent: no cookie-domain approval inference, profile-host endpoint,
`suggestAuthenticationHostsFromProfile`, or `document_moved_during_quiet_window`
was present. The review therefore corrected observed behavior and added explicit
operator configuration; it did not remove an implementation found only in the
reported description.

| Reported file | Baseline finding and local correction |
| --- | --- |
| `app/main.py` | No automatic cookie-host approval or new profile-host API. Resolve explicit operator/manual approvals, report counts, and use bounded bootstrap readiness. |
| `app/navigation.py` | No reported quiet-window helper. Require endpoint evidence for authentication POSTs; observe natural redirects and a read-only readiness predicate within deadlines. |
| `app/static/app.js` | No automatic suggestion/autofill function. Preserve manual approvals on profile switches and display effective/manual/operator counts. |
| `app/static/index.html` | No profile-derived approval control. Explain separate session state, manual approvals and optional operator policy. |
| `tests/test_app.py` | Reported metadata endpoint tests absent. Existing API contract retained; release-version expectation updated. |
| `tests/test_scoped_authentication.py` | Reported automatic-trust tests absent. Existing scoped authentication protections retained. |
| `tests/ui_check.py` | Reported autofill tests absent. Add real profile-switch preservation, no metadata requests, safe counts and older-report checks. |

## Implemented corrections

`PORTAL_VALIDATOR_AUTH_POLICIES_FILE` optionally points to a read-only mounted
JSON policy, separate from browser session state. Exact target hosts select
administrator-approved authentication hosts; manual and operator approvals are
deduplicated. Cookie domains, local storage and redirect history never grant
approval. Invalid configured policies fail closed. No profile-host metadata
endpoint is added, and reports expose policy counts rather than configuration
contents or policy identifiers. See the [README policy example](../README.md)
for the versioned JSON contract.

Authentication POSTs require an active authorized flow, approved source and
destination, protocol/body evidence and a recognized or explicitly approved
endpoint. Optional `authentication_endpoints` support exact nonstandard callback
paths without wildcard approval. Redirect-hop, DNS/SSRF and strict TLS checks
remain active. Authentication exceptions are separate from read-only business
POST approvals; requests are neither synthesized nor replayed.

The baseline additionally omitted source approval on top-level form POSTs and
accepted protocol-shaped bodies without sufficient endpoint validation. The
guard now uses the previous HTTP hop (not a stale approved frame) for preserved
POST redirects, and the initiating document otherwise. Missing source evidence
fails closed. Default endpoint recognition requires a protocol terminal segment;
an arbitrary business operation under `/oauth/...` or a misleading `.oauth2`
suffix is not an authentication endpoint. Nonstandard paths require exact
operator approval. This is narrower than trusting every request on an IdP host.

The reproduced navigation gap was treating a portal document as complete before
its application shell was ready. Authentication observation now accepts an
optional read-only readiness predicate, follows document-replacement events and
honors cancellation and overall/readiness deadlines. It does not depend on a
fixed quiet window. Existing callers retain their prior behavior when the
predicate is absent. Generic route/view discovery and failed, incomplete,
interrupted and policy-blocked API evidence remain available.

New policy parsing and matching live in `app/auth_policy.py`. Added regression
coverage is in `tests/test_auth_policy.py`,
`tests/test_authentication_endpoint_policy.py` and
`tests/test_auth_bootstrap_readiness.py`, alongside updated navigation/UI checks.

## Verification and limits

- Focused authentication/readiness integration run: **76 passed**.
- Complete host-suite checkpoint: **1,072 passed, 3 skipped** in 1,264.40
  seconds. The skips require Windows symlink privileges. This run collected
  1,075 tests before the 17 operator-policy integration cases and 23 final
  terminal-endpoint cases were added; it is not represented as a single clean
  run of the final 1,115-case collection. The later endpoint correction passed
  the separate 214-case run below, and final-image Linux tests cover the new
  integration/security cases and projected-volume symlinks.
- Post-version full frontend smoke passed on a fresh 1.12.12 server, including
  actual profile switches, unchanged manual approvals, no profile-host requests,
  safe source counts, older reports, CSP, mobile layouts and inventory controls.
- Final endpoint/source/readiness security and browser SSO run: **214 passed**
  in 237.71 seconds, including authenticated SPA and SSO browser integrations.
- Final production and debug core smoke tests both passed under UID
  `1000820000:0`, read-only root, dropped capabilities and no-new-privileges:
  strict Python and Chromium NSS local TLS, matching Playwright 1.63.0/revision
  1243, health endpoint, redacted access logs, graceful SIGTERM and idempotent
  trust initialization. All 26 application/entrypoint hashes matched the exact
  reviewed snapshot; no host application source was mounted.
- An earlier candidate's optional strict Google smoke timed out after 30 seconds
  after local TLS checks succeeded. It did not report a certificate-trust error;
  public HTTPS success is not claimed for this release. No TLS bypass was added.
- Final-image Linux run: **525 passed, 1 harness failure, 0 skipped** in 572.26
  seconds. The sole failure was a structural test trying to read an unmounted
  `/tmp/container-entrypoint.sh`, not application execution. All new security,
  operator-policy SSO, cancellation, browser discovery, per-view API, redaction
  and projected-volume symlink cases passed. All 18 loaded application modules
  resolved under `/app/app`; the exact final-image source hashes matched both
  before and after. The unchanged structural/trust tests are rerun below with
  their required entrypoint, Dockerfiles and deployment mounted read-only.
- Corrected configuration harness: **17 passed, 0 skipped** in 0.98 seconds,
  covering every trust test and all three Dockerfile structure tests. The first
  expanded rerun also needed access to image-owned static assets; `/tmp/app`
  now links to `/app/app`, rather than mounting host application source. No test
  assertion, runtime policy or application file was weakened to obtain a pass.
- Both completed Trivy 0.72.0 scans returned exit 0 with **zero reported
  vulnerabilities across all severities**, including 92 Wolfi packages and
  Node/Python dependencies. Database timestamp:
  `2026-10-14T13:10:32.349175575Z` (next update `2026-10-15T13:10:32Z`). This is
  a point-in-time scanner result, not a guarantee about future advisories or an
  assertion that an external Wiz scan was run.
- Both versioned images were pushed successfully and independently verified
  over HTTPS: raw manifest/config byte hashes, registry/Hub digests, Docker
  schema2/config media, all gzip layers (18 production / 20 debug), Linux amd64,
  user `10001:10001`, version `1.12.12` and creation timestamp
  `2026-10-15T05:24:20Z`. The revision label is intentionally empty because the
  source is uncommitted. No `latest` or `prod-*` tags were published.

| Published image | Verified registry manifest digest |
| --- | --- |
| `mohankrishna999/portal-validator:1.12.12` | `sha256:1dbf8d0598b6d4dc201e0faad23767805e13e58ae888676543b24f0644720465` |
| `mohankrishna999/portal-validator:1.12.12-debug` | `sha256:cdab546fe111719d59556a33bce801fc429f6400c5358f10ebfa0ddc46cbd932` |

Fixtures use synthetic applications and identity providers. They do not establish
universal portal/SSO support or validate a private production deployment.
Unknown-source popup POSTs remain fail-closed; provider-specific ACS/callback
paths outside default protocol endpoints need explicit operator approval.

The application has no built-in multi-tenant authentication or per-profile
ownership enforcement. Platform controls must protect the entire UI/API and
restrict profile/policy mounts; separate deployments when users require separate
trust boundaries. A new image is required for these code changes. Operator
policy configuration is optional and separate from session Secrets; existing
CA/NSS trust setup and session-state mounts are unchanged. No cluster rollout
or live private-portal validation is performed by these local edits.

Source changes remain uncommitted under the user's explicit restriction. Build
and publication authorization are separate from source commit/push or deployment
authorization.

## Changed files and functions

| Files | Change |
| --- | --- |
| `app/auth_policy.py` (new) | Strict bounded operator-policy parser, exact target matching and endpoint canonicalization; no session-state input. |
| `app/main.py` | `lifespan`, `authentication_approvals_for_scan`, `authentication_request_source`, scan preflight/effective configuration, route guard and bootstrap integration. Preserve the original immutable request and independent profile scope. |
| `app/navigation.py` | `settle_authentication_navigation` gains optional bounded readiness and cancellation; authentication POST, iframe, token and preserved-redirect guards require endpoint/source evidence. |
| `app/static/app.js`, `app/static/index.html` | Preserve manual approvals on profile switches, clarify operator policy and display approval-source counts without profile metadata requests. |
| `app/version.py`, `Dockerfile`, `Dockerfile-debug`, `openshift/deployment.yaml` | Version references only; base images, browser installation, startup command, security context and CA mounts unchanged. |
| `tests/test_auth_policy.py` (new) | Exact approvals, strict schema/URLs, bounds, cookie-state rejection and projected-volume symlink handling. |
| `tests/test_auth_policy_integration.py` (new) | Real operator-approved SSO/SPA, fail-closed preflight/startup, absent metadata endpoint, profile isolation and bootstrap cancellation. |
| `tests/test_authentication_endpoint_policy.py` (new) | Forged protocol fields cannot authorize business mutations or unknown sources; exact nonstandard endpoints and all other authorization gates. |
| `tests/test_authentication_request_source.py` (new) | Previous HTTP hop takes precedence over stale frame origin; missing evidence fails closed. |
| `tests/test_auth_bootstrap_readiness.py` (new) | Delayed redirects/components, document replacement, readiness deadlines, listener cleanup and distinct user/process cancellation. |
| `tests/test_auth_navigation_coverage.py` | Nonstandard authentication callbacks require explicit endpoint approval. |
| `tests/test_app.py`, `tests/ui_check.py`, `tests/release_image_smoke.py` | Version, UI approval isolation, hardened final-image startup and exact source-snapshot checks. |
| `README.md`, `docs/RELEASE-1.12.12.md` (new) | Configuration, seven-file audit, limitations and verification evidence. |
| `docs/RELEASE-1.12.11.md` | Record previously executed 1.12.11 tests, image publication and point-in-time scans. |

## Verification commands

```sh
python -m pytest -q --tb=short --show-capture=no tests
python -m pytest -q tests/test_auth_policy_integration.py tests/test_authentication_endpoint_policy.py tests/test_auth_bootstrap_readiness.py
PORTAL_VALIDATOR_URL=http://127.0.0.1:18138 UI_SCREENSHOT=/tmp/portal-ui.png python tests/ui_check.py
trivy image --image-src docker --scanners vuln mohankrishna999/portal-validator:1.12.12
trivy image --image-src docker --scanners vuln mohankrishna999/portal-validator:1.12.12-debug
```

Actual versioned image builds/pushes used the existing WSL Docker engine, cached
digest-pinned bases and the reviewed uncommitted source snapshot:

```sh
docker buildx build --progress plain --builder default --pull=false --platform linux/amd64 --provenance=false --sbom=false --output type=docker,oci-mediatypes=false,compression=gzip --build-arg VCS_REF= --build-arg BUILD_TIMESTAMP=2026-10-15T05:24:20Z -t mohankrishna999/portal-validator:1.12.12 .
docker buildx build --progress plain --builder default --pull=false --platform linux/amd64 --provenance=false --sbom=false --output type=docker,oci-mediatypes=false,compression=gzip --build-arg PRODUCTION_IMAGE=mohankrishna999/portal-validator:1.12.12 -f Dockerfile-debug -t mohankrishna999/portal-validator:1.12.12-debug .
docker push mohankrishna999/portal-validator:1.12.12
docker push mohankrishna999/portal-validator:1.12.12-debug
```

Final-image smoke/regressions ran with `--user 1000820000:0 --read-only
--cap-drop ALL --security-opt no-new-privileges --tmpfs
/tmp:rw,nosuid,nodev,size=1g,mode=1777 --shm-size=256m`. Test scripts and the
expected 26-file SHA-256 map were mounted read-only; application imports came
from the final image, not a bind-mounted worktree. The smoke script was
`tests/release_image_smoke.py`, using `RELEASE_SMOKE_SOURCE_HASHES` for this
uncommitted snapshot and `RELEASE_SMOKE_DEBUG=true` for debug startup. The Linux
regression run selected all new authentication-policy/readiness/source tests,
existing authenticated SPA/SSO/scoped authentication, discovery/popup/Material,
trust/redaction and POST/API lifecycle/failure/finalization tests.

After a separately authorized rollout, verify image identity and approval counts
without printing policy hosts, profiles, cookies or tokens:

```sh
oc -n "$NAMESPACE" get pods -l app=portal-validator -o custom-columns=NAME:.metadata.name,IMAGE:.spec.containers[0].image,IMAGE_ID:.status.containerStatuses[0].imageID
oc -n "$NAMESPACE" exec deployment/portal-validator -- python -c 'import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/diagnostics/build")),indent=2))'
oc -n "$NAMESPACE" exec deployment/portal-validator -- python -c 'from app.auth_policy import load_authentication_policies; p=load_authentication_policies(); print({"policies":len(p),"authentication_hosts":sum(len(x.authentication_hosts) for x in p),"authentication_endpoints":sum(len(x.authentication_endpoints) for x in p)})'
oc -n "$NAMESPACE" logs deployment/portal-validator --since=15m | rg 'AUTHENTICATION_APPROVALS_APPLIED|AUTHENTICATION_REQUEST_BLOCKED|AUTHENTICATION_OBSERVATION_COMPLETED|APPLICATION_SHELL|ROUTE_VALIDATED|SCAN_COMPLETED'
```

Use an owner-approved profile and exact authentication policy for the intended
portal. Check application readiness before interpreting coverage; inspect each
route/view's API occurrences and all blocked/incomplete/stop reasons. Successful
synthetic tests do not prove exhaustive live coverage. An uncommitted snapshot
must not claim the baseline Git revision: its diagnostic remains `UNVERIFIED`
while still detecting source drift, and release validation separately compares
every application/entrypoint hash to the reviewed snapshot.
