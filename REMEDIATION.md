# Focused remediation: route warnings, timing, and read-only POST observation

Status: source correction, not a published release. No version, Dockerfile,
image tag, deployment, trust, TLS, or SSO configuration was changed for this work.
Private production acceptance remains required before a new release image is
built or published. The previously published 1.9.0 images do not contain these
source changes.

## Reproduced causes and corrections

- The previous popup observer closed a popup after DOMContentLoaded, cancelling
  a naturally issued delayed POST. Popups now live with the shared browser
  context, retain their initiating route/activation/phase, and inherit this
  ownership across nested popups. The delayed-popup regression fails with the
  committed scanner and passes with the correction.
- API health snapshots were conditional on asset checking and used list offsets.
  API observation/health is now independent of asset checking. Final response
  reconciliation uses the initiating route activation, including late responses
  and network failures; failures do not contaminate the next route's resources.
- Some lifecycle maps keyed recreated Playwright wrappers by their Python object
  IDs. All related maps now use weak references to the stable implementation
  identity, avoiding stale pending entries without retaining request secrets.
- Slow-route timing included pre-render validator processing. Application time
  now consists of navigation/activation plus observed application settle, while
  capture, confirmation, and report processing remain validator overhead. A
  regression with a large artificial pre-render gap proves it cannot generate
  a slow warning. Independent DOM/API evidence remains available.
- Every warning outcome exposes structured reasons and a readable count/summary
  in the UI. `PASS_WITH_WARNINGS` remains healthy and never increases failed
  route counts. Slow warnings use the exact dynamic threshold, including
  non-preset values such as 7250 ms.
- Absolute route and scan deadlines cap browser work and preflight DNS/progress
  awaits. The settle helper cannot extend the remaining budget. Expiry retains
  completed routes and reports remaining routes as partial/not tested. Browser
  cleanup and final report assembly may add time beyond the work deadline.

No fixed multi-second route sleep was found or removed (count: zero). The
optimization removes a redundant first stability sample, caps the prior settle
budget extension, and exposes independent minimum-observation/network-quiet
controls while continuously observing traffic. The old 5-second warning
threshold was not itself a mandatory wait. No claimed production wait was
invented to explain the private scan baseline.

Approved POSTs remain explicit method/host/path operations, naturally issued by
the target application. They are never replayed or actively probed. Required
POST 500 responses are target API failures; optional failures are warnings;
denied operations are validator-policy blocks, not target failures. SSRF,
credential scope, authentication, and strict certificate validation are retained.

## Files

- `app/main.py`: lifecycle ownership, popup lifetime, continuous API attribution,
  final reconciliation, deadline enforcement, configuration/timing diagnostics.
- `app/network.py`: stable weak identities and additive display policy aliases.
- `app/health.py`: bounded readiness, overhead separation, precise slow warnings.
- `app/reporting.py`: structured safe warning evidence and late API reconciliation.
- `app/resources.py`: independent image, JS, CSS/font, and other size thresholds.
- `app/static/app.js`, `app/static/index.html`, `app/static/dashboard.css`:
  warning explanations, dynamic controls, API/resource filters and diagnostics.
- `tests/test_health.py`, `tests/test_resource_timing.py`,
  `tests/test_scan_post_lifecycle.py`, `tests/ui_check.py`: expanded regressions.
- New `tests/test_reporting_warnings.py`, `tests/test_scan_deadlines.py`,
  `tests/scan_timing_benchmark.py`: warning/deadline cases and reproducible timing.
- `README.md` and this new document: contracts, evidence, and release limitations.

## Measured generic fixture

Both runs use the same browser/dependencies and generic server fixture with 44
routes and 301 naturally issued approved POST responses. Baseline loads published
1.9.0 `main.py` and `health.py` from commit `3617364` in memory; it shares current supporting modules. This
isolates the scanner/readiness change, but is not an isolated historical-image
comparison, a private-portal measurement, or a performance SLA. Host scheduling
and browser startup differ between runs.

| Measurement | Before | After |
| --- | ---: | ---: |
| Total scan | 73.930 s | 50.977 s |
| Average route validation | 1.351 s | 1.063 s |
| P95 route validation | 1.824 s | 1.322 s |
| Authentication/configuration | 4.600 s | 1.828 s |
| Discovery | 2.201 s | 1.714 s |
| Route validation total | 59.428 s | 46.766 s |
| Finalization | 0.272 s | 0.319 s |
| Observed application settle total | 22.132 s | 12.040 s |
| Validator observation total | 26.718 s | 22.069 s |
| Approved POST calls | 301 | 301 |
| Full document navigations / SPA transitions | 1 / 43 | 1 / 43 |

The scanner keeps one shared browser context and primary page for ordinary SPA
routes. The fast-SPA runtime regression explicitly verifies counts of 1 and 1;
the nested-popup regression verifies three pages in the shared context. Baseline
did not report these counters, so historical measured context/page values are
not fabricated. The benchmark now emits the current counters when available.

Total time improved by 31.0% on this fixture. New route overhead totals 29.979 s;
the old scanner did not instrument this field, so no before/after overhead
comparison is claimed. The four principal route fields are
`application_navigation_ms`, `application_settle_ms`, `validator_overhead_ms`,
and `total_validation_ms`. The first two sum to `application_load_ms`; all
three components sum to route validation time. Discovery is reported separately.

Reproduce locally (no release images are built):

```bash
python -m pytest -q --tb=short --show-capture=no
python tests/scan_timing_benchmark.py --baseline
python tests/scan_timing_benchmark.py
PORTAL_VALIDATOR_URL=http://127.0.0.1:18082 \
  UI_SCREENSHOT=reports/portal-validator-remediation-ui.png python tests/ui_check.py
```

Benchmark JSON and UI screenshots are ignored local artifacts under `reports/`.
The UI smoke verified non-preset dynamic threshold submission, readable warning
evidence, healthy warning counters, POST filtering, resource controls, persistent
column visibility, strict CSP, and mobile layouts. Its final 100/500/1000-row API
renders measured 13.5/119.0/188.6 ms respectively. Approved-POST UI regressions
also exercise canonical and legacy backend policy fields together and alone.

## Executed validation

- Windows full suite: **223 passed, 1 skipped**, 254.76 s. The skip is the
  Windows permission requirement for the ConfigMap-symlink fixture. This run
  preceded the last optional-resource-deadline and HTTP-resource integration
  assertions; the final focused run of those cases passed (**2 passed**, 17.46 s).
- Final Linux full suite against the corrected source: **226 passed**, 259.77 s,
  including the ConfigMap-symlink fixture, real browser POST/SSO lifecycle,
  deadlines, redaction/security, and trust regressions. Execution used arbitrary
  UID 1000820000, a read-only root/source filesystem, and writable temporary HOME.
- Final fast-SPA context/page-count regression: **1 passed**, 8.01 s.
- Warning/health/resource unit regressions: **59 passed**, 1 browser case
  intentionally deselected, 1.05 s. The full suites execute that browser case.
- Full standalone UI smoke passed after the policy compatibility correction.
- `python -m compileall -q app tests` and `git diff --check` passed. A tracked
  content privacy search found no company-specific names. Trust, TLS, SSO,
  credential scope, Dockerfiles, dependency pins, and deployment are unchanged.

Linux validation runs the candidate source/tests read-only inside the previously
published debug runtime, not a newly built image. Its invocation is:

```bash
docker run --rm --name portal-validator-remediation-tests \
  --user 1000820000:0 --read-only --tmpfs /tmp:rw,nosuid,size=1g \
  --entrypoint python -e HOME=/tmp/portal-validator-home -e PYTHONPATH=/workspace \
  -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
  -e REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
  -e CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
  -v "$PWD":/workspace:ro -w /workspace \
  mohankrishna999/portal-validator:1.9.0-debug \
  -m pytest -q -p no:cacheprovider --tb=short --show-capture=no
```

The test-only system CA environment above avoids depending on absent cluster
ConfigMaps; it does not alter deployment configuration or disable verification.
Actual pod startup remains the existing ConfigMap mounts → trust entrypoint →
`exec` Uvicorn sequence.

## Production acceptance still required

Actual private OpenShift/SSO traffic could not be exercised from this workstation:
neither `oc` nor `kubectl` is available and no approved session or sanitized
failing production report was supplied. The generic tests prove the reproduced
lifecycle corrections, not the exact cause of every private endpoint failure.

After deploying an approved candidate through your normal process, verify:

```bash
oc rollout status deployment/portal-validator
oc exec deployment/portal-validator -- python -m app.trust status
oc exec deployment/portal-validator -- sh -c \
  'certutil -L -d "sql:$CHROMIUM_NSS_DB"'
oc logs deployment/portal-validator --since=10m
oc port-forward deployment/portal-validator 18080:8080
```

In the forwarded UI, use the approved mounted SSO profile and owner-approved
POST method/host/path rules. Do not paste credentials, cookies, storage-state
contents, private certificates, or query-bearing private URLs into source or
logs. Check each affected route's human warning reasons and API inventory:
approved POST 200 healthy; required POST 500 target failure; denied POST validator
block; late/popup requests attributed to their initiating route. Confirm dynamic
settings in `scan_configuration`, the four timing fields in route evidence,
coverage counter invariants, and actual total/P95 timings against the same
production baseline. Keep all production reports local/private.

Readiness is a bounded passive estimate, not Core Web Vitals. Its sampled DOM
signature can miss same-length/same-count content replacements without other
activity; long-running foreground polling may consume the configured deadline.
Console messages without a browser request identity remain attributed to the
currently active route; API/resource lifecycle evidence retains original
ownership. No useful console diagnostics are suppressed to conceal this limit.
No blanket polling ignore rule, TLS bypass, replay, or wider network allowance
was added to hide these cases.
