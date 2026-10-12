# Portal Validator 1.12.8 — source identity and context-owned views

## Source/deployment audit

Work began on clean `main` at `07a57603523981d349dd9838dfd206b8265b4869`,
matching GitHub. Docker Hub's 1.12.7 production manifest matched the published
release digest `sha256:8d4a9ecd8fbadf0f6135a7047f9fbfb99b94519953935d8925292ef1c02adac2`.
That source has no `post_audit_mode` and caps navigation actions at 50. Those
observations alone cannot demonstrate source/deployment drift. No undefined
audit mode or broader POST execution permission is introduced in this release.

No OpenShift credentials/context were available during this audit. The local
Kubernetes context belongs to an unrelated development cluster and was not used.
Production pod digests, mounted files, ReplicaSet revisions, private authenticated
sessions and external portal coverage therefore still require operator verification.

## Focused corrections

- `app/main.py` and `app/discovery.py`: retain original popup pages rather than
  reloading their URL in the primary tab. Observe all context pages, preserve
  page-owned navigation and diagnostics, and drain pending popup observations
  within the existing route deadline. Every destination still passes existing
  scoped navigation/authentication and SSRF policy.
  Popup bootstrap API/resource events and console/script diagnostics belong to
  the independently inspected popup, with opener metadata retained separately.
  Persistent URL-less controls retain a stable identity across hash changes;
  recreated controls can still identify distinct application views.
- `app/browser_lifecycle.py`: explicit lifecycle evidence and failure stage;
  authentication and shell readiness remain prerequisites for application discovery.
- `app/health.py`: include visible open-shadow component content in application
  readiness, loading and challenge checks. A valid shadow-only shell must not be
  stopped before its already-supported navigation can be discovered.
- `app/network.py`: late policy callbacks cannot regress a terminal request state;
  response/finished/failure ordering retains HTTP status independently from body
  completion. Page/frame identifiers are local ordinals, not sensitive URLs.
- `app/reporting.py`: separate execution, navigation, authentication and API
  coverage evidence, plus reconciled request and view counters. Finishing a scan
  never implies exhaustive site coverage.
- `app/build_info.py` and `app/version.py`: final-image source manifest with
  version, exact Git revision, UTC build time and SHA-256 file hashes. The
  diagnostic endpoint compares actual runtime files with this snapshot. Missing
  metadata is explicitly unverified; altered files are a mismatch.
- Dashboard: display build identity and four coverage dimensions; block scan
  submission on a confirmed frontend/backend/source mismatch. The script is
  content-addressed and pinned with browser-enforced SHA-256 SRI, with no inline
  script or CSP relaxation. Existing route explorer/inspector is preserved.
  Future releases must advance the backend version and frontend version literal
  together; an inconsistent release is intentionally reported as a mismatch.
- Navigation action ceiling is 1500 in schema, discovery and UI; default remains
  20. Time/depth/route budgets still bound execution. This ceiling is not a
  coverage claim or an authorization to activate unsafe controls.
- `Dockerfile`, `Dockerfile-debug`, Deployment and README: matching versioned
  release references. Debug inherits the production source manifest. CA mounts,
  trust code, Playwright 1.63.0, Chromium, strict TLS, non-root execution and
  read-only business POST approval are unchanged.

The manifest is an integrity comparison, not a cryptographically signed image
attestation. It does not establish deployment identity from readiness. A runtime
image cannot embed its own eventual registry digest without changing that digest;
the endpoint reports `image_digest: null` unless a validated
`PORTAL_VALIDATOR_IMAGE_DIGEST=sha256:...` is supplied by the workload. Operators
must independently compare the pod's `imageID` with the registry digest.

## Measured regression evidence

The strengthened delayed-popup test was run against unchanged 1.12.7 source:
the popup document was fetched twice. The corrected implementation inspects it
once, without a replay/reload. Two new controlled popup fixtures (semantic new-tab
link and automatic window) each validate exactly five independent views across
three original browser pages. The workspace and nested document are each fetched
once; approved natural POSTs are attributed to their views, mutation POSTs never
reach the fixture server, and popup-owned diagnostics are not assigned to the
primary page. These are synthetic measurements, not production portal metrics.

Additional browser regressions exercise a naturally generated approved popup
POST and POST-to-303-to-GET redirect. Correlation uses captured Request/Response
identity when the popup frame becomes available; no second POST is dispatched.
A popup completed during final network draining remains visible as discovered
but unvalidated, with explicit partial coverage rather than silent COMPLETE.
Frozen reports cannot be mutated by subsequent source-identity enrichment.
Semantic controls that produce no actual navigation keep the existing failure
contract regardless of whether the document observer or DOM timer expires first;
neither path retries the click or repeats its naturally generated POST.
Delayed native document navigation now waits for the new document's
DOMContentLoaded event before returning its final response/URL, rather than
mistaking response headers for a committed document. Same-URL reloads remain
supported; successive documents correlate readiness to their own committed
response rather than reusing an earlier document's event. The legacy access-log
test now checks the existing stronger query
omission policy; the production redactor and trust implementation are unchanged.

Eight new observer regressions failed against unchanged 1.12.7 and pass after
correction, covering late-approval/response/finished races and source identity.
The existing authenticated SPA fixture remains a separate seven-view check;
this release does not infer business API counts or total routes from screenshots.

## Verification commands

Changed files for this release:

```text
Dockerfile
Dockerfile-debug
README.md
app/browser_lifecycle.py (new)
app/build_info.py (new)
app/version.py (new)
app/discovery.py
app/health.py
app/main.py
app/network.py
app/reporting.py
app/static/app.js
app/static/index.html
app/static/styles.css
openshift/deployment.yaml
docs/RELEASE-1.12.8.md (new)
tests/release_image_smoke.py (new)
tests/test_browser_lifecycle.py (new)
tests/test_build_info.py (new)
tests/test_coverage_dimensions.py (new)
tests/test_network_lifecycle_races.py (new)
tests/test_app.py
tests/test_authenticated_spa.py
tests/test_containerfiles.py
tests/test_navigation_coverage_reporting.py
tests/test_navigation_control_safety.py
tests/test_popup_discovery.py
tests/test_trust.py
tests/ui_check.py
```

Run the full suite against the final source, not merely collection:

```sh
python -m pytest -q --tb=short --show-capture=no tests
PORTAL_VALIDATOR_URL=http://127.0.0.1:8080 UI_SCREENSHOT=/tmp/portal-ui.png python tests/ui_check.py
```

Build only from clean committed source. Match the debug base to production:

```sh
git diff --exit-code
git diff --cached --exit-code
docker buildx build --builder default --platform linux/amd64 --provenance=false --sbom=false --output type=docker,oci-mediatypes=false,compression=gzip --build-arg VCS_REF="$(git rev-parse HEAD)" --build-arg BUILD_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)" -t mohankrishna999/portal-validator:1.12.8 .
docker buildx build --builder default --platform linux/amd64 --provenance=false --sbom=false --output type=docker,oci-mediatypes=false,compression=gzip --build-arg PRODUCTION_IMAGE=mohankrishna999/portal-validator:1.12.8 -f Dockerfile-debug -t mohankrishna999/portal-validator:1.12.8-debug .
docker run --rm --entrypoint python mohankrishna999/portal-validator:1.12.8 -c 'from app.build_info import build_diagnostics; import json; d=build_diagnostics(); print(json.dumps(d,indent=2)); assert d["source_integrity"]["status"]=="VERIFIED"'
trivy image --scanners vuln mohankrishna999/portal-validator:1.12.8
trivy image --scanners vuln mohankrishna999/portal-validator:1.12.8-debug
docker run --rm --read-only --user 1000820000:0 --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,size=1g --shm-size=256m -e RELEASE_SMOKE_PUBLIC_HTTPS=true -v "$PWD/tests/release_image_smoke.py:/release_image_smoke.py:ro" --entrypoint python mohankrishna999/portal-validator:1.12.8 /release_image_smoke.py
docker run --rm --read-only --user 1000820000:0 --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,size=1g --shm-size=256m -e RELEASE_SMOKE_DEBUG=true -e RELEASE_SMOKE_PUBLIC_HTTPS=true -v "$PWD/tests/release_image_smoke.py:/release_image_smoke.py:ro" --entrypoint python mohankrishna999/portal-validator:1.12.8-debug /release_image_smoke.py
```

## Post-deployment operator checks

Publication does not perform a cluster rollout. After an authorized rollout,
choose the correct namespace/context before running:

```sh
oc -n "$NAMESPACE" get deployment portal-validator -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
oc -n "$NAMESPACE" get pods -l app=portal-validator -o custom-columns=NAME:.metadata.name,IMAGE:.spec.containers[0].image,IMAGE_ID:.status.containerStatuses[0].imageID
oc -n "$NAMESPACE" get rs -l app=portal-validator -o wide
oc -n "$NAMESPACE" exec deployment/portal-validator -- python -c 'import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/diagnostics/build")),indent=2))'
oc -n "$NAMESPACE" exec deployment/portal-validator -- python -c 'from playwright.sync_api import sync_playwright; import os,importlib.metadata as m; print("Playwright",m.version("playwright")); print("HOME",os.environ["HOME"]); p=sync_playwright().start(); print(p.chromium.executable_path); b=p.chromium.launch(headless=True); print("Chromium",b.version); b.close(); p.stop()'
oc -n "$NAMESPACE" exec deployment/portal-validator -- certutil -L -d sql:/tmp/portal-validator-home/.local/share/pki/nssdb
```

Open the dashboard through the intended Route, inspect Build details and confirm
the frontend matches the backend commit/version and runtime source snapshot.
Validate an authorized portal using its explicitly approved session and policy;
inspect lifecycle failure stages and all four coverage dimensions. A healthy
pod, a successful shell response or a configured route ceiling is not proof of
authenticated route or API coverage. No proprietary destinations, certificates,
profiles, tokens or credentials are included in these instructions or images.
