# Route discovery and observed POST correction

## Confirmed causes

- Hidden password templates incorrectly gated discovery as login pages; ordinary numeric filters incorrectly gated it as MFA.
- Requests initiated while expanding navigation were recorded as background APIs but excluded from readiness tracking. Their lazy links could arrive after discovery finished.
- Collecting only the final menu state lost links from earlier, mutually exclusive panels. Router-link attributes and safe semantic menu/tab controls were not fully covered.
- Discovery kept its observations locally until the entire expansion pass finished. A later panel timeout could discard earlier routes.
- Hidden submenu controls were marked visited before their opener revealed them. Disabling DOM settling also bypassed configured network observation, allowing a slow popup document to disappear before its route was collected.
- Closing the browser context immediately after the route loop could terminate outstanding optional/discovery POST responses. Closure-induced failures were not distinguished from observations incomplete at scan termination.
- The UI's scan duration used summed route load times rather than measured total scan time.

## Focused changes

Discovery now observes visible, enabled authentication inputs with explicit MFA evidence; retains links and actual history/hash/control transitions incrementally; observes each safe panel before opening the next; and uses the existing route-scoped network and timeout policy. Explicit static/configuration resource links are not queued as documents. No extensionless API or route is guessed from its name.

Hidden submenu controls remain eligible when they become visible. A zero DOM settle setting still honors the independently configured minimum/network quiet windows and outstanding navigation requests; pending popup observations also contribute to readiness.

An exhausted discovery budget is a structured `DISCOVERY_TIMEOUT` warning/coverage limitation, not a failure to load an already loaded main document. Earlier routes remain queued. Total timeout, cancellation, maximum routes/depth, crawler scope, SSRF validation and mutation blocking remain authoritative.

The final network drain waits for natural request completion across all observation phases. Its maximum is the configured API timeout, otherwise readiness timeout, otherwise route timeout, capped by the remaining total scan budget; its quiet window is the configured network quiet window. No POST is probed, retried or replayed. Outstanding records are frozen as `INCOMPLETE` before context closure. A real response proves dispatch, but does not manufacture read-only policy approval.

`summary.post_summary` reports `observed_calls`, `approved_read_only_calls` and `executed_approved_calls`. The UI displays these authoritative counters independently of inventory filters. Execution is dispatch evidence, not proof of successful HTTP/body completion; the lifecycle counters retain that distinction.

The route table and Inspect panel have independent, visible pointer/keyboard resize handles and session-persistent numeric height preferences. Expand/Collapse and modal Full Screen/Close/Escape controls preserve scrolling, sticky headers, focus and sanitized export. Scan duration prefers measured total scan time.

## Files changed for this correction

- `app/discovery.py`, `app/health.py`, `app/main.py`, `app/network.py`, `app/reporting.py`
- `app/static/index.html`, `app/static/app.js`, `app/static/styles.css`
- `tests/test_discovery_regressions.py`, `tests/test_popup_discovery.py` (new), `tests/test_post_observation_summary.py` (new), `tests/test_scan_final_drain.py` (new), `tests/ui_check.py`
- This verification note (new).

Release metadata is aligned to `1.12.0` in `README.md`, `Dockerfile-debug`, `openshift/deployment.yaml`, the UI footer, application version and health test. Existing unrelated/previous remediation edits in the working tree are preserved. Dependencies, container architecture, deployment security, trust/CA initialization and TLS verification are unchanged.

## Verification and deployment

Run the full backend suite with the matching Playwright Chromium installed:

```sh
python -m pytest -q tests
```

Run frontend tests against an owned local application instance, with a writable screenshot destination:

```sh
PORTAL_VALIDATOR_URL=http://127.0.0.1:18084 UI_SCREENSHOT=/tmp/portal-ui.png python tests/ui_check.py
```

Build normal/debug images with new versioned candidate tags (do not overwrite an existing release or create `latest`/date-based production tags). Build the debug Dockerfile with `--build-arg PRODUCTION_IMAGE=<the-normal-candidate-tag>` so both contain the same current application. Verify arbitrary UID, read-only filesystem, NSS bootstrap and matching Chromium in each final image before publishing through the established release process.

After deploying an approved new image:

```sh
oc set image deployment/portal-validator portal-validator=docker.io/mohankrishna999/portal-validator:1.12.0
oc rollout status deployment/portal-validator
oc logs deployment/portal-validator --tail=200
oc exec deployment/portal-validator -- python -c 'import os; from playwright.sync_api import sync_playwright; p=sync_playwright().start(); print("UID:",os.getuid()); print("Chromium exists:",os.path.isfile(p.chromium.executable_path)); p.stop()'
```

Run a scan with a valid mounted session profile and the application's actual navigation controls. Confirm more than the seed route appears when reachable in-scope links exist, check `termination_reason` and coverage limitations against configured limits, and compare `summary.post_summary` and API lifecycle totals with downloaded JSON. Confirm an unapproved mutation remains blocked and HTTP 401/403 is not healthy. Delayed requests must either complete naturally or remain explicitly incomplete when the observation budget expires.

Container-local tests cannot prove authenticated route/API coverage for a production portal. A portal must actually expose each route/request during a permitted observed workflow; inaccessible, unsafe, expired-session and out-of-scope destinations remain limited. A late timer beyond configured observation windows is not proof of a missing backend endpoint. No private portal was contacted for this correction.

## Executed release verification

- Before the discovery fixes, the controlled reproduction produced five failures: hidden password, business numeric/MFA, delayed menu fetch, mutually exclusive menu panels and router-link navigation.
- Final full Linux backend/integration suite: **403 passed, no skips**, in **517.58 seconds**. The current source (including new/untracked tests) was snapshotted and hash-verified before execution; application/build/test hashes were rechecked before image publication. The test dependency/runtime image was the existing matching `1.11.0-debug` image with the current `1.12.0` source mounted read-only. Both newly built final images were independently verified to contain that same accepted application source.
- Production-image frontend suite: **passed**, including drag/keyboard resizing, session persistence, Expand/Collapse/fullscreen/Escape/focus, Inspect/export, sticky headers, 44/52-route cases, 1,000 API rows, responsive layouts and strict CSP. The API table's measured 100/500/1,000-row render times were 22.2/22.5/8.1 ms on this host.
- Both actual final images: startup and health passed as UID `1000820000:0`, read-only root filesystem, dropped capabilities and `no-new-privileges`; matching Playwright `1.63.0`/Chromium revision `1243` launched; NSS and generated runtime PEM contained the mounted generic fixture CA; graceful shutdown exited with code 0.
- Both actual final images passed strict Python and Chromium HTTPS against an isolated local CA/server fixture through the real entrypoint, without certificate-verification bypasses. The separate test-runner public HTTPS smoke also returned Google HTTP 200. This does not establish production portal/SSO coverage.
- Fresh Trivy 0.72.0 vulnerability scans reported **0 findings** for both exact final images. This is scanner evidence, not a guarantee against future or scanner-specific findings.
- `git diff --check` and the private-organization-reference check passed. No new certificate material, private portal identifiers, profiles or secrets were included in the source/images.

Both images were pushed and their Docker Hub manifest digests verified:

| Image | Registry digest |
| --- | --- |
| `mohankrishna999/portal-validator:1.12.0` | `sha256:65cc57195e7cc9bdd6ced7753a7b0760f7d4cf53ae853331c40624999b2d0e51` |
| `mohankrishna999/portal-validator:1.12.0-debug` | `sha256:4006c4d3daa02bf02ece744b04003bb5064d69b466f542fba46fc30565340883` |

Only these new versioned tags were published; existing releases, `latest` and date-based production tags were not changed. No cluster deployment or Git commit/push was performed for this correction. All pre-existing working-tree changes remain preserved.
