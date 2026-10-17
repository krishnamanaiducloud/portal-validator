# Portal Validator 1.12.11 — known-good discovery regressions

## Historical comparison and corrections

Compared the discovery behavior at `9407720a7cf9490e35eed162f2fe14455490a464`
(1.3.1) with the current implementation. Classic anchors, navigation metadata
and safe collapsed menus still produced equivalent candidates. Three concrete
regressions were reproduced instead of reverting the application or relaxing
authentication, SSRF, TLS or read-only execution.

| Reproduced behavior before | Focused correction |
| --- | --- |
| Default query ignoring collapsed `#/workspace?view=home`, `view=reports` and `view=activity` into one route. | Preserve sanitized SPA fragment parameters as route identity; continue ignoring ordinary HTTP queries by default. Explicit allowlists and secret/tracking exclusions remain enforced. |
| Breadth-first traversal visited a sibling document before a queued hash/history route. Synthetic history then changed that sibling's URL without restoring the SPA, losing its content and API activity. | Retain the actual observed source document GET separately from its logical history URL. Restore a displaced source through guarded document navigation, retain its real response, then activate the SPA route. The document observer baseline identifies the actual source, ignoring an initial hash; shared history URLs cannot establish document ownership. |
| An authenticated rendered shell containing a completed ARIA progress bar failed readiness and stopped validation after one page. | A finite completed determinate bar is status, not an active loader. Explicit busy state, incomplete/indeterminate/invalid progress, configured readiness and challenge gates remain blocking. |

## Synthetic before/after evidence

- Fragment-query fixture: one discovered/validated landing route before;
  three distinct validated views afterward, for both hash and hashbang routing.
- Displaced-source fixture: queued Reports inspected the unrelated document and
  missed its API before; afterward both hash/history variants render Reports,
  retain the context cookie, and capture the real API GET 200 once with matching
  route and activation attribution. Sibling SPA transitions still use one document.
  History URLs without a server document fallback restore their actual shell
  GET instead. A displaced source without an observed GET fails explicitly;
  authentication/business POST documents are never replayed.
  A sibling application independently visiting the same history URL still
  restores the correct source document instead of inheriting the wrong DOM.
  A popup whose observer started at `about:blank` uses its actual Navigation
  Timing document identity instead; this preserves the original window,
  avoids duplicate tabs and does not accept unrelated history observations.
- Completed-progress authenticated fixture: one loaded page, two retained but
  untested routes and `APPLICATION_NOT_READY` before; three rendered, ready,
  passing routes afterward.

These controlled fixtures demonstrate specific fixes, not complete coverage of
an untested private application. A genuine failed authentication/readiness gate
still stops protected activation and retains passive route evidence with a
partial-coverage reason. Safe navigation limits, permissions and ambiguous
controls can still prevent exhaustive discovery.

## Files and security

Runtime changes are limited to `app/discovery.py`, `app/main.py` and
`app/health.py`. The existing query-policy UI/help now distinguishes document
queries from SPA fragment identity; the rest of the UI is unchanged.
Release identity, versioned image references, smoke expectations and README are
aligned to 1.12.11. Regression tests are in `tests/test_discovery.py`,
`tests/test_fragment_route_identity.py` and
`tests/test_readiness_discovery_regression.py`.

CA/NSS bootstrap, entrypoint, Playwright 1.63.0 and its Chromium revision 1243,
pinned base images, dependencies, arbitrary UID support, strict TLS, SSO
approvals, network guards and POST execution policies are unchanged. No POST
is synthesized or replayed. No organization-specific data or session material
is included. The deployment image reference changes; no cluster rollout is
performed by publishing these artifacts.

The fragment-query collapse was introduced in `c6c11534`; FIFO traversal was
introduced in `f5f0e929`. The first-unready activation stop appeared in
`07a5760`, with passive destination retention added in `5694dc3`. The readiness
and authentication gates themselves are preserved; the completed-loader false
positive is corrected rather than bypassing readiness.

## Verification and publication

The pre-correction 883-case full host run exposed six failures: four passed unchanged in a
serial rerun; both popup duplicates reproduced independently and led to the
Navigation Timing correction above. Its original result (876 passed, 6 failed,
1 Windows ConfigMap-symlink skip) is retained, not represented as a clean run.
The final 31-case sequential run passed: all 21 discovery cases, all six popup
cases and the four other previously failing cases. This includes the new real
popup regression, bringing the final collection to 884 cases. No assertions or
production time limits were weakened to obtain those results.

The integrated dashboard smoke passed, including request configuration, API
failure filters, route inventory, 1,000-record pagination, mobile layout and CSP.
The final debug image passed 135 Linux cases in 147.82 seconds with zero
failures or skips, under arbitrary UID `1000820000:0` and a read-only root.
Its exact application source `9e77779874a0ceb0a81da56507738c5823f679ca` was VERIFIED
before and after; all 18 loaded application modules resolved under `/app/app`.
Only tests and the Dockerfile were mounted read-only, never host application
code. The run includes popup ownership, hash/history/query views, SPA API
activation, Material navigation and the real Linux ConfigMap symlink fixture.
Production core smoke and debug public-HTTPS smoke also passed with strict
local Python/Chromium NSS TLS, source identity, startup, log redaction, graceful
SIGTERM and idempotent trust initialization. Both completed Trivy 0.72.0 scans
reported zero vulnerabilities across all severities with database timestamp
`2026-10-14T13:10:32.349175575Z`; this is a point-in-time result, not a guarantee
against future advisories. Both versioned tags were pushed and independently
verified over HTTPS as Linux amd64, non-root, Docker schema2/gzip artifacts:

- Production `1.12.11`: `sha256:f9a51f2ad6ae9df9c706b1c69d5444a04a7c063f5b15bb9f9144a5b63c75e914`.
- Debug `1.12.11-debug`: `sha256:62f7fe07a563906402f105118fb6950bb27ad004a948549ad83a880e439f6fd4`.

Debug strict Google HTTPS smoke returned 200. Three production public smoke
attempts timed out; a separate strict Chromium production diagnostic then
returned 200 through the Google/www redirect, with no failed browser requests.
Production's local strict TLS/core smoke passed independently. Public-network
latency remains distinct from browser installation or TLS trust failures.

### Changed files

| Files | Change |
| --- | --- |
| `app/discovery.py` | Safe fragment identity; actual-document SPA restoration and popup fallback. |
| `app/main.py` | Keep each same-document route's observed GET source and pass it to navigation. |
| `app/health.py` | Exclude completed valid progress bars, preserving active-loader gates. |
| `app/static/index.html` | Clarify document-query policy; update footer version. |
| `app/static/app.js`, `app/version.py` | Align frontend/backend release identity. |
| `Dockerfile`, `Dockerfile-debug` | Version labels/default production base only; build architecture unchanged. |
| `openshift/deployment.yaml` | Versioned image reference only; no cluster mutation. |
| `tests/test_discovery.py` | Source-document, history collision, initial hash and popup regressions. |
| `tests/test_fragment_route_identity.py` (new) | Fragment policies, secret filtering and full scanner regressions. |
| `tests/test_readiness_discovery_regression.py` (new) | Completed/active progress and authenticated scanner regressions. |
| `tests/test_app.py`, `tests/ui_check.py`, `tests/release_image_smoke.py` | Release-version expectations only. |
| `README.md`, `docs/RELEASE-1.12.11.md` (new) | Behavior, validation evidence and publication/verification instructions. |

### Source verification commands

```sh
python -m pytest -q --tb=short --show-capture=no tests
python -m pytest -q tests/test_discovery.py tests/test_popup_discovery.py
PORTAL_VALIDATOR_URL=http://127.0.0.1:18124 UI_SCREENSHOT=/tmp/portal-ui.png python tests/ui_check.py
```

### Post-deployment verification

After an independently authorized rollout, select the intended namespace and
verify the running imageID and embedded application identity, not just the tag:

```sh
oc -n "$NAMESPACE" get pods -l app=portal-validator -o custom-columns=NAME:.metadata.name,IMAGE:.spec.containers[0].image,IMAGE_ID:.status.containerStatuses[0].imageID
oc -n "$NAMESPACE" exec deployment/portal-validator -- python -c 'import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/diagnostics/build")),indent=2))'
oc -n "$NAMESPACE" logs deployment/portal-validator --since=15m | rg 'APPLICATION_SHELL|PASSIVE_NAVIGATION|LINK_DISCOVERED|ROUTE_VALIDATED|SCAN_COMPLETED'
```

Use the intended mounted profile and explicit approved authentication hosts for
an authorized portal. Confirm authentication/readiness before interpreting
coverage. Check distinct hash/query views, nested tabs, route-associated API
occurrences, counter invariants and every not-tested/stop reason. Neither a
route ceiling nor successful synthetic fixtures prove exhaustive live coverage.

CA/NSS and TLS settings require no migration for this release. No live private
portal or OpenShift deployment was tested from this development environment.
