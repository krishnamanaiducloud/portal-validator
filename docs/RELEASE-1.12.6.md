# Portal Validator 1.12.6 — discovery and evidence accuracy

## Confirmed causes

- Discovery and activation used different selectors. Some custom route attributes were collected but could not be activated naturally. Traversal indices also differed between JavaScript and Playwright across shadow roots.
- URL-less navigation was limited to conventional tabs. Custom navigation views could be omitted, while a menu opener could be queued again as a view and activated twice.
- Nested navigation labels were lost when panels closed. Action-budget exhaustion did not account for remaining controls, especially when the action budget was zero.
- The report's route table consumed only validated results. Real routes omitted by route/depth/action/time limits were hidden outside separate JSON diagnostics.
- A response with HTTP 200 headers but no completion could appear healthy. Endpoint reporting did not clearly separate passive response observation from independent API testing.
- Coverage omitted unresolved controls. Dashboard filters and resource counters did not expose all lifecycle and scope distinctions.

## Changes

Shared DOM helpers now collect and activate the same safe controls using exact element handles. Open shadow DOM, URL metadata, hash/history routes, nested menus and URL-less semantic views retain distinct identities. URL-less activation requires observed content, URL or selection change. Menu expanders are not also queued as UI views. Nested parent menus are restored only through observed, uniquely matched safe controls.

`route_inventory` includes validated entries plus evidenced `NOT_TESTED`/`SKIPPED` routes, their actual sanitized URLs, names, parents, hierarchy, discovery sources and explicit coverage reasons. `results` remains validation-only for existing consumers. Report schema is **2.5**.

Coverage grades describe **observed reachable scope**, not a guarantee of the total application's routes or APIs. Execution completion remains separate. Unresolved controls, discovery deadlines, unvisited routes and incomplete API responses prevent complete observed coverage. Menu-control counts are observations across routes; UI-view counts use unique route IDs.

Observed API records distinguish completed responses, headers-only responses, no-response observations, cancellations, transport/body errors, HTTP errors and validator blocks. Structured validation reasons explain incomplete or unsuccessful results. `validation_basis=PASSIVE_BROWSER_OBSERVATION` and `active_validation_status=NOT_ACTIVELY_TESTED` prevent passive observation from being represented as an independent API probe.

The existing raw API inventory is preserved. Business API drilldown selects application traffic, rather than configuration, authentication and static-resource records. Naturally generated POST requests remain observable before policy enforcement. Requests are not replayed; only existing narrowly approved read-only operations may execute.

The dashboard exposes route hierarchy/source, untested/skipped routes, API lifecycle and HTTP response filters, passive-validation explanations, business API filtering, explicit resource metric scope and coverage limitations. Existing column selection, resizing, pagination, responsive layout and CSP remain in use.

## Scope and security

TLS/CA trust initialization, authentication/SSO policy, network/SSRF validation, read-only POST approval and mutation blocking are unchanged. No private certificates, storage profiles or organization-specific destinations are published. Dependencies and production Dockerfile architecture are unchanged; the debug base and deployment image reference advance to the versioned release.

Closed shadow roots, undisclosed routes, controls without safe navigation semantics, inaccessible authenticated content and workflows beyond configured limits cannot be exhaustively inferred. The validator must report those limits rather than claim universal coverage. Private production-portal acceptance still requires an authorized scan using its mounted profile and actual read-only controls.

## Files changed

- Discovery/backend: `app/discovery.py`, `app/main.py`, `app/reporting.py`.
- Dashboard: `app/static/app.js`, `app/static/styles.css`, `app/static/index.html`.
- Release references/documentation: `Dockerfile-debug`, `openshift/deployment.yaml`, `README.md`, this note.
- New regression suites: `tests/test_api_lifecycle_reporting.py`, `tests/test_custom_navigation.py`, `tests/test_route_inventory.py`.
- Updated regression suites: `tests/test_app.py`, `tests/test_discovery.py`, `tests/test_discovery_regressions.py`, `tests/test_navigation_control_safety.py`, `tests/ui_check.py`.

## Verification commands

```sh
python -m pytest -q tests
PORTAL_VALIDATOR_URL=http://127.0.0.1:18085 UI_SCREENSHOT=/tmp/portal-ui.png python tests/ui_check.py
docker build -t mohankrishna999/portal-validator:1.12.6 .
docker build --build-arg PRODUCTION_IMAGE=mohankrishna999/portal-validator:1.12.6 -f Dockerfile-debug -t mohankrishna999/portal-validator:1.12.6-debug .
trivy image --scanners vuln mohankrishna999/portal-validator:1.12.6
trivy image --scanners vuln mohankrishna999/portal-validator:1.12.6-debug
```

Fresh-container verification uses the real entrypoint, mounted generic test CA, UID `1000820000:0`, read-only root filesystem, writable `/tmp`, dropped capabilities and `no-new-privileges`. The image source must match the accepted source; matching Playwright/Chromium must launch without TLS bypass.

After an approved deployment, verify health/version and startup trust logs, then run an authorized scan with the desired route/action/depth/timeout settings. Inspect `route_inventory`, `coverage`, lifecycle reasons and `summary.counter_invariants`; compare visited views with actual safe portal navigation. Unapproved mutations must remain blocked. No cluster rollout is performed by this release workflow.

## Executed verification

- The complete Linux suite ran as UID `1000820000:0` with a read-only filesystem and matching Playwright/Chromium dependencies: **582 passed, 2 failed**, no skips, in 892.30 seconds. One failure was an outdated assertion expecting limited discovery rather than unknown coverage when a scan finalized zero routes. The other was a 5-second semantic-click actionability timeout during concurrent host/scanner activity; the scanner correctly reported the timeout instead of claiming success or replaying a request.
- After correcting that assertion and retaining full nested-menu ancestry, the final discovery/reporting/inventory/safety rerun passed **109 tests**, no failures/skips, in 209.28 seconds. This includes both earlier failures and the two new sibling-panel/shadow hierarchy cases. The entire 586-test final suite was not repeated after those focused changes.
- Additional focused backend verification passed **113 tests**. Frontend browser verification passed `UI_SMOKE_PASSED`, including hierarchy, unvisited/skipped routes, lifecycle/HTTP filters, business API drilldown, column persistence, responsive layouts and CSP.
- Both final images passed real-entrypoint trust initialization and strict Python **and Chromium** HTTPS against an isolated generic CA/server fixture, without verification bypass. Both matched all 21 current application files, ran as UID `1000820000:0` with a read-only filesystem, and launched Playwright `1.63.0` with Chromium revision `1243`. Installed glibc is `2.44-r8`.
- Trivy 0.72.0 with the October 11 vulnerability database reported **zero known vulnerabilities** in each exact final image: production `sha256:e20c112ef30063cbbc10226216424ab45b2c92c65c8f7b2c1661f37ba327d48a` and debug `sha256:faa9ff915ccbf003403b8e97119715ad8cd4fabed3cfff0429635b7d49955f92`. This is a point-in-time result, not a guarantee against undisclosed vulnerabilities or a substitute for the deployment's Wiz scan.
- Production/debug startup commands and versioned health endpoints were checked; graceful shutdown exited 0. An earlier production candidate also returned Google HTTP 200 with strict Chromium verification. Debug public-Google attempts timed out at transport/navigation level, without a certificate-authority error; the final controlled HTTPS tests passed. Public-network reachability is not guaranteed by a container-local fixture.
- Source privacy checks and `git diff --check` passed. No private production portal or mounted production session was tested; no cluster rollout was performed.
