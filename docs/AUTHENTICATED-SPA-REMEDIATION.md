# Authenticated SPA discovery and per-view health correction

## Root causes

The repository's discovery implementation is `app/discovery.py`; there is no `pipelines/discovery.py`.

1. `app/main.py:detect_auth_signals` converted every DOM error into absent login/MFA signals. Discovery, naming and render probes could race an authentication document replacement. `app/navigation.py:settle_authentication_navigation` also read document state without a consistent navigation snapshot.
2. `app/main.py:route_guard_policy` exempted top-level navigation, but authentication iframe/token-fetch traffic encountered ordinary resource and mutation filters first. Authentication-host approval alone was not a resource exception and must not become one.
3. `app/main.py:execute_scan` started discovery even when configured readiness was not reached. Authentication-policy evidence was reset for each route despite retaining one browser context. Successfully observed entry-document redirects were not used to avoid revisiting equivalent entry points.
4. `app/discovery.py:expand_safe_navigation` did not hover to reveal hover-only destinations. View identities included framework-generated control/panel IDs. Frame views were activated against the wrong document, and readiness was measured against the parent rather than the child view.
5. Resource responses/failures could produce two records for one occurrence and lose a known status on body failure. Late resources were grouped by completion window rather than original activation. API failure dimensions could double-count one failed request. Cancellation and policy decisions were not fully preserved through sanitized resource reporting. Browser cleanup could also manufacture failed-resource findings after the observation cutoff.
6. `app/main.py:abort_by_validator` interpreted weak authentication words in unrelated blocked business/asset paths as proof that authentication failed. Denial classification now requires request-kind, protocol and identity-scope evidence.

## Backend implementation

- `app/discovery.py`: bounded read-only `retry_dom_operation`/`evaluate_dom`, hover-first safe expansion, exact control activation, semantic view identities, and `resolve_view_target` for uniquely matching same-origin frames. Dispatched clicks, submissions and requests are never retried.
- `app/navigation.py`: consistent authentication-document observation; explicit approved-source/destination protocol-specific iframe and OAuth token policies. Preserved authentication POST redirects require actual form/grant evidence, not a suggestive URL alone.
- `app/navigation_guard.py`: transient request parsing produces only protocol-evidence booleans; bodies/tokens are not included in metadata or reports. All destinations still pass URL/port/DNS policy.
- `app/session.py`: copy/scoping of selected storage state to explicitly approved destinations, host-only cookie materialization, and scoped persistence preserving unrelated sessions. Mounted profiles remain unchanged. A deleted scoped cookie cannot reappear from an older broad-domain cookie.
- `app/health.py`: navigation-aware render/timing snapshots and observable shell readiness, independent of the network becoming completely idle.
- `app/network.py`: sanitized browser-frame initiator origins on individual request occurrences; paths, queries, fragments and credentials are removed. No request bodies, cookies or authentication headers are retained.
- `app/main.py`: listeners precede navigation; the sequence is navigation, bounded authentication observation, shell/view readiness, then discovery. Failed authentication or initial shell readiness stops authenticated crawling. Each subsequent failed view remains visible while other already known safe destinations can still be evaluated. Route names are refreshed after bootstrap rather than retaining a loading placeholder. Parent and same-origin frame menus share one action budget. Only actually observed successful document redirects become entry aliases. Route, auth, TLS, resource and API evidence remain separate. Final occurrences include sanitized initiator origins and route associations; global `api_request_occurrences` preserves individual observations in addition to the unique inventory.
- `app/reporting.py` and `app/resources.py`: definitive HTTP failures retain precedence, with secondary body/lifecycle evidence. Policy blocks are not server failures; canceled requests are not fabricated target failures. Late resources are reconciled onto their original route. Failed occurrence totals do not sum overlapping failure dimensions. Readiness/authentication limits prevent complete coverage.

## Dashboard

`app/static/index.html`, `app/static/app.js` and `app/static/styles.css` add Navigation Coverage and a hierarchical menu/view/API explorer. Existing configurable API columns remain available. Failure type joins the method, route, HTTP status and lifecycle filters. Authentication/readiness limitations are visible. The optional `per_route_timeout_ms` separates the overall route ceiling from navigation, authentication and readiness phase budgets; it defaults to the existing `timeout_ms` ceiling for compatibility. Routes remain serial inside one authenticated context; `concurrency_limit` governs independent scan contexts under the deployment cap.

## Synthetic before/after evidence

The fixture is generic, local and isolated. Only its loopback servers are permitted by its test resolver; production SSRF policy is unchanged. Its selected storage profile contains only disposable test data.

| Metric | Published 1.12.6 baseline | Corrected implementation |
| --- | --- | --- |
| Authenticated application shell | Not reached; token POST blocked | Reached after scoped OAuth/SAML flow |
| Visited views | 1 authentication page | 7: entry, 4 distinct hashes, 2 URL-less tabs |
| Unique API observations | 1 blocked token endpoint | 7, including auth/bootstrap/business/error traffic |
| Shared API route associations | 0 application views | All 7 application views |
| Natural approved business POSTs | 0 | Observed per visited view; never replayed |
| Unapproved mutation dispatches | 0 | 0; attempted calls remain visible as policy blocks |
| HTTP 502 evidence | Application not reached | API and script-resource failures visible |
| Total application coverage | Unknown/limited | Still unknown; unsafe controls explicitly skipped |

Finding all safe fixture destinations does not prove exhaustive coverage of an arbitrary real portal. No private production portal, production session or cluster rollout was tested.

## Regression suites

New: `tests/test_authenticated_spa.py`, `tests/test_navigation_lifecycle.py`, `tests/test_scoped_authentication.py`, `tests/test_navigation_coverage_reporting.py`, `tests/test_resource_observation_finalization.py`.

Updated for discovery: `tests/test_sso_navigation_browser.py`, `tests/test_navigation_guard.py`, `tests/test_health.py`, `tests/test_execution_evidence.py`, `tests/test_post_context_coverage.py`, `tests/test_post_inventory_contract.py`, `tests/test_scan_post_lifecycle.py`, `tests/ui_check.py`. Release verification also updates `tests/test_network.py`, `tests/test_logging_config.py` and the version assertion in `tests/test_app.py`.

They cover authentication approval/denial, context replacement and persistent errors, hover/click/nested menus, hash/view/frame identity, child readiness, API attribution and shared endpoints, known HTTP failures, mutation blocking, session isolation/rotation/deletion, late resources, cleanup cancellation, truncated HTTP error responses, honest coverage and secret redaction.

## Exact changed files

Application: `app/discovery.py`, `app/health.py`, `app/main.py`, `app/navigation.py`, `app/navigation_guard.py`, `app/network.py`, `app/reporting.py`, `app/resources.py`, `app/session.py`.

Frontend: `app/static/app.js`, `app/static/index.html`, `app/static/styles.css`.

Tests: the five new and updated files listed above. Readiness assertions now require failed validation (while retaining `LOADED`) when the configured shell condition is not reached. The API count test asserts one failed occurrence plus its independent HTTP/body evidence, the context spy forwards the new optional scope, and the 51-route fixture has a 10s route ceiling for constrained debug CI. Dedicated deadline tests remain unchanged.

Documentation: this new file and `docs/RELEASE-1.12.7.md`. Release references: `README.md`, `Dockerfile-debug`, `openshift/deployment.yaml` and the application/UI version. `app/logging_config.py` receives the release smoke's narrowly scoped Uvicorn access-formatter compatibility fix; it preserves central redaction and removes all access-log query/fragment data.

## Initial source validation — 2026-10-11

- Final Linux source validation: **670 passed**, no skips or failures, across three disjoint partitions covering all 39 test modules. Each used UID `1000820000:0`, a read-only source/root filesystem, writable temporary storage, dropped capabilities and `no-new-privileges`.
  - A: **78 passed in 375.43s** — `test_scan_post_lifecycle.py`, `test_scan_final_drain.py`, `test_resource_timing.py`, `test_resource_observation_finalization.py`, `test_post_context_coverage.py`.
  - B: **57 passed in 387.99s** — `test_sso_navigation_browser.py`, `test_authenticated_spa.py`, `test_execution_evidence.py`, `test_public_access_scan.py`.
  - C: **535 passed in 555.17s** — all remaining test modules, using `--ignore=tests/<module>` for every A/B module. All partitions used `-q --tb=short --show-capture=no` and the container configuration below.
- The authenticated SPA regression in partition B asserts all seven safe destinations, the ready `Home` heading, two real authentication POSTs, per-view approved read-only POST responses, shared API attribution, blocked mutations, HTTP 502 API/resource evidence, occurrence reconciliation and sanitized reports.
- An earlier full Linux run returned 650 passes and four failures: two stale readiness/counting expectations, an outdated test spy, and one short fixture deadline. The isolated deadline case passed before its budget adjustment. The final partitions above reran every test after those test corrections and the resource/auth-denial fixes.
- Dashboard browser smoke: **passed**, including Navigation Coverage/explorer, failure filters, all configurable columns, 1,000 API records with pagination, mobile layouts and strict CSP. Measured rendering for 100/500/1,000 inventory records was 15.9/28.6/20.3ms respectively; these are local paginated UI measurements, not portal-performance promises.
- Python compilation and `git diff --check`: **passed**. Generic-content checks found no organization-specific names/domains from the supplied examples.
- At this initial source-validation stage, a new production-image build and publication had not been executed. These tests mounted edited source into the previously published dependency image; they did not modify that image. Subsequent authorized release verification is documented in `docs/RELEASE-1.12.7.md`. No production OpenShift rollout or private portal/session validation is implied.

## Exact verification commands

```sh
python -m pytest -q --tb=short --show-capture=no tests
python -m pytest -q --tb=short --show-capture=no tests/test_authenticated_spa.py
# Start in a separate terminal, then run the UI check:
python -m uvicorn app.main:app --host 127.0.0.1 --port 18087
PORTAL_VALIDATOR_URL=http://127.0.0.1:18087 UI_SCREENSHOT=/tmp/portal-ui.png python tests/ui_check.py
```

Container validation uses the existing dependency-matched debug image to test the current source, without producing a production release:

```sh
docker run --rm --entrypoint python --user 1000820000:0 --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=1g --cap-drop ALL \
  --security-opt no-new-privileges --shm-size 1g \
  -e PYTHONPATH=/workspace -e PYTEST_ADDOPTS=-pno:cacheprovider \
  -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
  -e REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
  -e CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
  --mount type=bind,source=/mnt/c/Mohan/my_repo/git-hub/portal-validator,target=/workspace,readonly \
  --workdir /workspace mohankrishna999/portal-validator:1.12.6-debug \
  -m pytest -q --tb=short --show-capture=no tests
```

This mounts source read-only; it does not claim that the already-published 1.12.6 image contains these new changes. Run the UI command against a locally started instance of the current source. No credentials, certificates or production storage state are needed for these fixtures.

## Remaining limits and security

- Interactive login, expired sessions, consent, MFA, browser challenges, SameSite/third-party-cookie rules and permissions can prevent authenticated coverage. They require an authorized workflow, not security bypasses.
- Explicit `authentication_hosts` are required for external identity POSTs. They are not crawler/resource host allowlists. Read-only business POSTs still require their separate exact-operation policy.
- A preserved authentication POST redirect fails closed when Chromium does not provide verifiable protocol-body evidence to the guard.
- Default readiness is an observable rendered-content heuristic, not proof of business authorization. Configure `readiness_selector` for a known authenticated application shell when stronger evidence is required.
- Closed shadow roots, unadvertised routes, ambiguous actions, cross-origin frame DOM and configured route/depth/action/time limits remain coverage limitations. Ambiguous unnamed same-origin frames are reported rather than guessed. These limits must not be represented as full application coverage.
- TLS/CA trust initialization, production Dockerfile architecture, dependencies and OpenShift security settings are unchanged. Source-level test results alone do not imply publication or deployment; see the separate release verification note.
