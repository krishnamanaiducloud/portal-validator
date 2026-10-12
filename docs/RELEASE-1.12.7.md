# Portal Validator 1.12.7 — authenticated SPA and per-view health

## Changes

The implementation and synthetic baseline comparison are documented in
[AUTHENTICATED-SPA-REMEDIATION.md](AUTHENTICATED-SPA-REMEDIATION.md).

- Read-only DOM probes tolerate bounded authentication document replacement; dispatched interactions and requests are never retried.
- Explicitly approved protocol-specific authentication traffic is evaluated separately from resource filtering and read-only business POST approvals. Every destination still passes the existing network/SSRF policy.
- Authentication and observable shell readiness precede navigation discovery. Failed authentication/readiness limits coverage instead of producing an apparently complete landing-page scan.
- Hover/click menus, nested destinations, distinct hash routes, stable URL-less views and same-origin frame views retain their own route identities and readiness evidence.
- Individual API/resource occurrences retain route attribution, sanitized initiator origins, policy/lifecycle reasons and definitive HTTP failures. Cleanup does not manufacture target failures.
- Navigation Coverage and a hierarchical view/API explorer expose visited, failed, skipped and limited destinations. Existing configurable API columns remain available, with an additional failure-type filter and optional per-route timeout.
- Mounted session profiles remain read-only. Scoped session updates preserve unrelated profiles and browser state.
- Initiator metadata contains only a sanitized HTTP(S) origin, never a path, query, fragment or credentials.
- A release startup smoke caught an existing access-log formatter incompatibility: central redaction flattened Uvicorn's five structured arguments. Access logs now preserve the formatter contract while dropping all query/fragment values, including unrecognized query secrets. Generic application/error log redaction is unchanged.

The public synthetic fixture moves from one authentication page in the published
1.12.6 baseline to seven safely visited application views: entry, four hash routes
and two URL-less tabs. Shared APIs are attributed to every relevant view; approved
natural POSTs execute, unapproved mutations stay blocked, and HTTP 502 API/resource
failures remain visible. This does not establish exhaustive coverage of a private
production portal.

## Release boundaries

Only new versioned production/debug tags are used:

```text
mohankrishna999/portal-validator:1.12.7
mohankrishna999/portal-validator:1.12.7-debug
```

`Dockerfile-debug` extends the matching production version. The OpenShift
Deployment change is image-tag-only; its CA mounts, arbitrary-UID security
settings and writable temporary volume are preserved. The application version,
UI footer and README examples advance together. Report schema remains 2.5;
new evidence is additive.

CA/trust initialization, certificate verification, dependencies, read-only
business-operation approval and SSRF protections are not bypassed. No private
corporate names, destinations, certificates, credentials or storage profiles are
included in this release. No cluster rollout is performed by publication.

## Verification commands

```sh
python -m pytest -q --tb=short --show-capture=no tests
python -m pytest -q --tb=short --show-capture=no tests/test_authenticated_spa.py tests/test_navigation_lifecycle.py tests/test_scoped_authentication.py tests/test_resource_observation_finalization.py tests/test_navigation_coverage_reporting.py tests/test_network.py tests/test_logging_config.py
docker buildx build --builder default --platform linux/amd64 --provenance=false --sbom=false --output type=docker,oci-mediatypes=false,compression=gzip -t mohankrishna999/portal-validator:1.12.7 .
docker buildx build --builder default --platform linux/amd64 --provenance=false --sbom=false --output type=docker,oci-mediatypes=false,compression=gzip --build-arg PRODUCTION_IMAGE=mohankrishna999/portal-validator:1.12.7 -f Dockerfile-debug -t mohankrishna999/portal-validator:1.12.7-debug .
trivy image --scanners vuln mohankrishna999/portal-validator:1.12.7
trivy image --scanners vuln mohankrishna999/portal-validator:1.12.7-debug
```

After an approved deployment, inspect startup trust events, verify the versioned
health response, and run an authorized scan with the selected mounted session
profile and explicit authentication hosts. Inspect navigation coverage, route
hierarchy, per-view API occurrences, skipped controls and policy decisions.
Authentication, permissions and configured budgets can limit coverage; neither
HTTP 200 for the entry document nor the configured route ceiling proves complete
application coverage.

## Executed release verification — 2026-10-11

- Initial complete Linux source suite: **670 passed**, with no skips or failures. After release-only version, initiator-privacy and access-logging corrections, the focused host rerun passed **114 tests** and the final debug-image rerun passed **168 tests in 142.63s**. The latter imports application code from `/app`, not the mounted test source, and includes the authenticated SPA, navigation lifecycle, scoped session, resource reconciliation, network privacy, logging, coverage and version suites. Its single warning concerns pytest assertion rewriting of already imported `anyio`, not an application failure. The entire suite was not repeated after those final focused corrections.
- Both final images passed matching Playwright `1.63.0` / Chromium revision `1243` build checks. All **21 application files plus the entrypoint** matched the accepted working-source SHA-256 hashes in each image.
- Both final images ran as UID `1000820000:0` with a read-only root filesystem, writable temporary storage, dropped capabilities and `no-new-privileges`. Real entrypoint bootstrap imported a disposable fixture root into NSS with `C,,` trust. Strict Python and Chromium HTTPS against its signed test server passed; strict Chromium Google navigation returned HTTP 200 and title `Google`. One earlier public navigation attempt timed out at transport level; no TLS bypass was used.
- Installed glibc is **2.44-r8**. Python is `3.14.8_git20261008-r0`; NSS/tools are `3.128-r2`. Dependency versions and the production Dockerfile architecture are unchanged.
- Trivy **0.72.0**, using the database updated `2026-10-11T13:06:05Z`, scanned all severities and reported **zero known vulnerabilities** in each final image. This point-in-time result is not a guarantee against undisclosed vulnerabilities or a replacement for the deployment's Wiz scan.
- Production Uvicorn and the debug image's debugpy/reloader startup returned the versioned health response, emitted correctly formatted access logs without the synthetic query value, and completed graceful application shutdown on SIGTERM. A second entrypoint invocation in each image retained the existing NSS root rather than duplicating it. Initial parallel startup probes exceeded their 20s fixture budget; isolated startup verification uses a 60s test deadline without changing application/deployment timeouts. Production Uvicorn re-raises SIGTERM after graceful shutdown (subprocess return `-15`); the debug reloader exits 0. Debugpy reports its existing frozen-module breakpoint warning; debugging and the health check still start.
- Generic-content and secret checks, central redaction tests and `git diff --check` passed. No private production portal/session or cluster rollout was tested.

Published and Docker Hub registry-verified image manifests:

```text
1.12.7       sha256:8d4a9ecd8fbadf0f6135a7047f9fbfb99b94519953935d8925292ef1c02adac2
1.12.7-debug sha256:0eb717ef992d8a605fb84775b3eb7a51068ce19be34f3525f1d7447b14a0cf68
```

Both tags are active `linux/amd64` images. The registry confirms Docker schema-2
manifests with gzip-compressed Docker layers. Layer-transfer sizes are
500,237,742 bytes for production and 505,890,699 bytes for debug. Only these two
new versioned tags were published; no `latest`, date-based production tag or
existing release was changed. A transient Docker Hub OAuth TLS handshake
timeout interrupted the first debug push; the normal TLS-verified retry succeeded.
