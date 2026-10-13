# Portal Validator 1.12.9 - lazy navigation and retained coverage evidence

## Root causes and historical comparison

There are no local version tags. The version declarations identify 1.4.0 at
`91b9d81`, 1.5.0 at `f5f0e92`, and the published 1.12.8 at `e2acec9`.
Discovery code is identical between the two historical versions. All three
preserve distinct `/#/tasks` and `/#/reports` identities and observe browser
history/hash changes. Hash-path normalization is not the demonstrated regression.

The additional `application_ready` discovery gate and first-route stop in
`execute_scan` arrived in `07a5760` (1.12.7). Unlike the earlier implementation,
this can hide even passive in-scope links when bootstrap readiness fails.
Authentication failure already prevented active discovery in 1.4.0/1.5.0.
Removing the readiness or authentication gates would not be a safe correction.

The directly reproduced navigation omissions in 1.12.8 are:

- A Material trigger can omit `aria-expanded` before opening its menu.
- CDK creates the overlay and its `aria-controls` relationship after activation;
  associating panels only before a click loses their opener and hierarchy.
- Body-appended child menus appear after other top-level triggers in DOM order.
  Opening the next top-level menu destroys the child before it is explored.
- A semantic tab may create its referenced panel only when selected.
- Returning to a hash route can insert remote controls asynchronously. Looking
  for them immediately loses a previously observed view.
- DOM text/element counts can remain unchanged while an MFE replaces navigation
  semantics. Those counts alone cannot prove the configured stability window.

The actual production profile, approval settings, and final browser evidence
were not available. These reproductions do not establish which combination
caused a particular private production scan to stop at one route.

## Focused changes

- `app/discovery.py`: recognize evidenced Material menu triggers, associate
  lazily created semantic overlays with their opener, explore visible children
  first, and safely dismiss an identified CDK menu backdrop using Escape before
  moving to another top-level menu. No force clicks or arbitrary buttons.
  Lazy semantic tab panels must become visible; parent tabs/menus are restored
  through the same central helpers. Previously observed remote controls are
  awaited within one configured activation deadline. Clicks are not replayed.
- `app/health.py`: observe navigation-semantic DOM mutations, open shadow roots,
  URL changes and document replacement when evaluating stability. Only a
  generation counter and document epoch enter the report. Detached roots are
  disconnected; style-animation attributes do not manufacture readiness work.
  Existing user-configured timing bounds and overhead accounting remain intact.
- `app/main.py`: retain passive in-scope route evidence when authentication or
  readiness prevents activation. Do not click, scroll, crawl the IdP or activate
  those routes. Preserve a specific stop reason and keep their rows NOT_TESTED.
  Resource observations now retain actual HTTP method and observation time.
- `app/reporting.py`: one mapping keeps unvisited row reasons and counters in
  agreement. Resource aggregation retains actual method/count/time metadata,
  without inventing values for legacy observations.
- `app/static/app.js`, `index.html`, `styles.css`: additive Failed Endpoints
  table with route associations, affected calls, first/last observations and
  whitelisted diagnostics. Known HTTP errors remain visible when completion is
  unresolved. Policy blocks and incomplete-only attempts are not target failures.
  Existing route explorer, resizing, fullscreen, pagination, columns and filters
  remain available; no CSP relaxation.
- `app/version.py`, Dockerfiles, Deployment, README and release smoke checks:
  matching versioned 1.12.9 production/debug references. Existing trust,
  Playwright/Chromium alignment, dependencies and securityContext are unchanged.

## Controlled measurements

The same synthetic authorized Material/hash/MFE fixture was run against
1.12.8 and the correction. These are fixture metrics, not production estimates.

| Metric | 1.12.8 | Correction |
| --- | ---: | ---: |
| Discovered views | 3 | 7 |
| Attempted views | 3 | 7 |
| Application-ready validated views | 3 | 7 |
| Failed health checks | 0 | 2 |
| Skipped views | 0 | 0 |

The correction exposes two real HTTP 502 failures that the earlier crawl never
reached. The seven views include lazy tabs and a nested subtab. A shared API is
associated with all seven. Approved natural POSTs execute; mutation attempts
are observed and blocked before the fixture server receives them. Restoring a
parent view can naturally produce additional requests; calls are not route counts.
Coverage remains PARTIAL because unsafe controls were excluded; health failures
are counted separately. Visiting all seven known views does not prove exhaustive
application coverage.

Separate failing-before tests reproduced a one-row report on visible hash
links behind an unready/login shell. The correction retains three observed
identities, attempts only the entry page, validates zero application views,
and marks the two unvisited routes with authentication/readiness reasons.

## Tests and files

New regression files:

```text
tests/test_material_menu_discovery.py
tests/test_material_spa_scan.py
tests/test_bootstrap_route_retention.py
tests/test_dom_readiness.py
tests/test_resource_failure_metadata.py
```

Existing `tests/test_app.py`, `tests/test_health.py`, `tests/ui_check.py`, and
`tests/release_image_smoke.py` are updated. The dashboard smoke includes
unfinished HTTP 502, script HTTP 503, transport errors, blocked/pending exclusion,
affected call counts, timestamps, escaping and diagnostic field isolation.

All application/test files changed are listed above; release-only files are
`Dockerfile`, `Dockerfile-debug`, `openshift/deployment.yaml`, `README.md`,
`app/version.py`, and this document. No certificate, profile, token or
organization-specific route is included.

## Build and verification

### Executed checks and published images

The Windows source-suite run collected 778 tests. All 777 runnable tests passed
after updating the legacy resource-inventory expectation for the new optional
method/timestamp fields. The ConfigMap symlink-layout test was skipped because
this Windows environment could not create its fixture symlinks. That test
subsequently passed in Linux. The full browser dashboard smoke also passed,
including the Failed Endpoints cases, diagnostic isolation, independent scrolling, table
performance and mobile layouts. Inspector scroll assertions allow pending
resize/render callbacks to settle before measuring scroll isolation.

After a user-approved WSL service recovery, both images were rebuilt from
application commit `5694dc3873457bbc5c5c5468a2e56cfa93c176b6` at
`2026-10-13T14:33:30Z`. Final-runtime source identity, matching Chromium
executable and browser launch checks passed. Both images retain
Playwright 1.63.0 / Chromium revision 1243 and glibc 2.44-r8.

Twenty-four focused Linux regressions passed in the final debug image with
zero failures or skips, including the ConfigMap symlink-layout test. All
application imports came from `/app`, not a mounted source tree. Both final
images passed the release smoke under UID `1000820000`, with a read-only root
filesystem, dropped capabilities and no-new-privileges. Strict local Python
TLS, Chromium NSS TLS, Google HTTPS (HTTP 200), application startup, redacted
access logging, graceful SIGTERM and repeated entrypoint initialization passed.

Trivy 0.72.0 found zero vulnerabilities at every severity in both final images
using the database updated `2026-10-13T13:06:33Z`. This is a time-specific
scanner result, not a guarantee about future findings or other scanners.

Only these versioned Docker Hub tags were published on October 13, 2026:

| Tag | Manifest digest |
| --- | --- |
| `mohankrishna999/portal-validator:1.12.9` | `sha256:f47f3d92ea2eb19133c527aeabcc96305c4c40534fe486ffd3514908b86d831a` |
| `mohankrishna999/portal-validator:1.12.9-debug` | `sha256:4cca3d8ee2783feb3ce971219ac17b79a89cf2bfd3caee483acbaa656496b672` |

Independent registry inspection verified both manifest/config digests,
`linux/amd64`, version/revision labels, user `10001:10001`, Docker schema 2
manifests and exclusively gzip-compressed Docker layers.

No OpenShift rollout or private-portal validation was performed. This
publication record is documentation-only; the images identify the application
commit above, rather than the later documentation commit.

Run the full suite against the final committed source and final image:

```sh
python -m pytest -q --tb=short --show-capture=no tests
PORTAL_VALIDATOR_URL=http://127.0.0.1:8080 UI_SCREENSHOT=/tmp/portal-ui.png python tests/ui_check.py
git diff --exit-code
git diff --cached --exit-code
docker buildx build --builder default --platform linux/amd64 --provenance=false --sbom=false --output type=docker,oci-mediatypes=false,compression=gzip --build-arg VCS_REF="$(git rev-parse HEAD)" --build-arg BUILD_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)" -t mohankrishna999/portal-validator:1.12.9 .
docker buildx build --builder default --platform linux/amd64 --provenance=false --sbom=false --output type=docker,oci-mediatypes=false,compression=gzip --build-arg PRODUCTION_IMAGE=mohankrishna999/portal-validator:1.12.9 -f Dockerfile-debug -t mohankrishna999/portal-validator:1.12.9-debug .
trivy image --scanners vuln mohankrishna999/portal-validator:1.12.9
trivy image --scanners vuln mohankrishna999/portal-validator:1.12.9-debug
docker run --rm --read-only --user 1000820000:0 --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,size=1g --shm-size=256m -e RELEASE_SMOKE_PUBLIC_HTTPS=true -v "$PWD/tests/release_image_smoke.py:/release_image_smoke.py:ro" --entrypoint python mohankrishna999/portal-validator:1.12.9 /release_image_smoke.py
docker run --rm --read-only --user 1000820000:0 --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,size=1g --shm-size=256m -e RELEASE_SMOKE_DEBUG=true -e RELEASE_SMOKE_PUBLIC_HTTPS=true -v "$PWD/tests/release_image_smoke.py:/release_image_smoke.py:ro" --entrypoint python mohankrishna999/portal-validator:1.12.9-debug /release_image_smoke.py
```

Publishing images does not deploy them. After an authorized operator rollout,
select the correct namespace/context, then verify the pod's immutable imageID
against the published registry digest and inspect source identity:

```sh
oc -n "$NAMESPACE" get pods -l app=portal-validator -o custom-columns=NAME:.metadata.name,IMAGE:.spec.containers[0].image,IMAGE_ID:.status.containerStatuses[0].imageID
oc -n "$NAMESPACE" exec deployment/portal-validator -- python -c 'import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/diagnostics/build")),indent=2))'
```

For an authorized portal, select its mounted profile and explicitly approve
only required authentication hosts/protocol exchanges. Supply a readiness
selector for a portal-specific authenticated MFE when generic visible readiness
is insufficient. A visible shell after a bounded settle timeout is not proof
that every remote component stabilized. Inspect readiness/lifecycle reasons,
NOT_TESTED rows, API policy outcomes and all coverage dimensions before treating
the scan as complete. An unavailable/expired session cannot be repaired by
globally allowing POSTs, importing desktop cookies or bypassing TLS.
