# Portal Validator 1.13.9 — navigation outcomes, dialogs and scope reporting

## How the findings were established

`tests/test_navigation_matrix.py` builds a synthetic portal with one
self-contained page per navigation pattern (scenarios A–L), plus a second
origin for new-tab destinations. Each scenario was first run against the
unchanged 1.13.8 code:

- Eight scenarios already passed: C (approved scope), D, E, F, G, I, J and K.
- Five failed. Three were defects (A, B and C out of scope). The other two
  (H and L) were wrong assertions in the new tests: the validator was
  already correct.

The root-cause column below records only what those runs showed.

| Symptom | Code path | Root cause | Fix | Regression test |
|---|---|---|---|---|
| In-page tab timeout | `activate_ui_view` (kind `navigation`) → `NAVIGATION_VIEW_COMPLETED_SCRIPT` | Activating the control for the view already shown changes neither the URL, the selected state nor the content. The wait was bounded only by the route budget, so the route ended as `TIMEOUT` after the full per-route time. | A bounded, configurable observation (`ui_activation_timeout_ms`, default 5000). It reports `NO_OBSERVABLE_CHANGE`, which is not a failure and comes with diagnostics. | A |
| Dialog activation not validated | `describeView` → `isNavigationControl` | Buttons using `aria-haspopup="dialog"`, or `aria-controls` that points to a `<dialog>`/`role="dialog"`, are not navigation controls. These dialogs were never discovered. Only the Bootstrap `data-bs-target` modal worked. | Dialog openers become views (`presentation: dialog`, source `ui-dialog`). Validation is scoped to the dialog's content, and the dialog is closed afterwards with Escape or its own close control. Controls inside the dialog are never clicked. | B |
| External new-tab link invisible | `enqueue_discovered_routes` → `external_urls` | Out-of-scope destinations were only counted in a per-route `external_links` list. They never appeared in the route inventory, and the original page's URL never changed. | Out-of-scope destinations are listed in the route inventory as `SKIPPED_OUT_OF_SCOPE` / `EXTERNAL_DESTINATION_DISCOVERED`, with their label and parent route. They are never visited or counted as failures. Approved hosts are validated as `POPUP_NAVIGATION`. | C (both modes) |
| Duplicate route discovery | `discovered_route_key` + provenance | No defect: identical labels with different destinations stayed separate, and true duplicates merged. The merged counts were not visible. | `summary.discovery_metrics`, with definitions. | I |
| Incomplete API coverage | `aggregate_api_inventory` | No defect: 200/404/502 kept their exact codes (`response_status_counts`), a reset connection was `NETWORK_FAILURE`, a hanging request was `INCOMPLETE`, and no status was invented. The test had read a non-existent field. | None needed. | L |
| Required configuration 502 | route health → `api_health_findings` | No defect: the route was `VALIDATION_FAILED` with "A required route API returned HTTP 502", and the inventory kept the 502. | None needed. | H |
| Authentication configuration mismatch | request → `authentication_approvals_for_scan` | No defect: a configured identity host reached the scan configuration (`authentication_host_count`). Its value never appeared in results. | None needed. | K |

## Navigation outcomes

Every visited route now carries `navigation_outcome`, alongside the existing
`navigation_type`. The type says how the route was activated; the outcome
says what observably happened:

- `DOCUMENT_NAVIGATION`
- `HISTORY_NAVIGATION`
- `HASH_NAVIGATION`
- `IN_PAGE_ACTIVATION`
- `DIALOG_ACTIVATION`
- `OVERLAY_ACTIVATION`
- `POPUP_NAVIGATION`
- `IFRAME_NAVIGATION`
- `EXTERNAL_NAVIGATION`
- `NO_OBSERVABLE_CHANGE`
- `POLICY_BLOCKED`
- `ACTIVATION_TIMEOUT`

See the README's *Navigation outcomes* table for the evidence behind each
outcome and the readiness strategy it uses.

Routes that end as `TIMEOUT`, `ACTIVATION_TIMEOUT` or `NO_OBSERVABLE_CHANGE`
include a sanitized `timeout_diagnostics` object containing:

- the expected and observed outcome, including booleans for URL, selected
  state, content, panel and dialog changes;
- the failed phase;
- the original and final URL;
- whether a new page opened, and whether readiness was reached;
- elapsed and per-phase times;
- the configured budgets.

## Dashboard

- The routes table shows the observed outcome as a chip, with the activation
  type beneath it. The Navigation filter accepts both.
- The Outcome filter adds *No visible change* and *Out of scope*.
- Out-of-scope destinations get their own summary card.
- A *Session renewals* card appears when the application's own token
  renewal, the periodic profile refresh, or session recovery was observed.
- The coverage panel shows the discovery metrics.
- The route inspector includes the timeout diagnostics.
- New setting: *UI activation timeout (ms)* under *Route identity controls*.

## Session renewal

The automatic session renewal from 1.13.8 is unchanged and remains on by
default. The dashboard now shows how often the session was renewed.

## Verification

- Host suite (WSL2, Python and Playwright): 1234 of 1235 passed, including
  all 13 navigation-matrix scenarios.
  - The one failure was
    `test_disabled_resource_checks_do_not_hide_scan_wide_read_only_blocks`.
    Its 5 s route budget expired under full-suite load before the fixture
    issued its POSTs, so its POST lookup found nothing.
  - Rerun alone, it passed 3 of 3 times. Its whole file, together with the
    application, settings and matrix tests, then passed on the release
    version: 115 passed.
- UI smoke (`tests/ui_check.py`): passed. It covers outcome chips, the
  dialog filter, the *Out of scope* and *No visible change* filters, the
  *Session renewals* card, timeout diagnostics in the inspector, and the
  new setting.
- Debug image (Python 3.15, restricted runtime): 1229 of 1235 passed. The 6
  failures are `tests/test_operator_policy_script.py`, which needs `bash`;
  the image does not ship it.
- `tests/release_image_smoke.py` passed for both images. The debug run used
  `RELEASE_SMOKE_STARTUP_TIMEOUT=300`.

| Image | Digest | Compressed size |
|---|---|---|
| `docker.io/mohankrishna999/portal-validator:1.13.9` | `sha256:38a21071dd46d65a54e45d9b493978f6cb8cf6bf6997b95753889f7094da0445` | 503.7 MB |
| `docker.io/mohankrishna999/portal-validator:1.13.9-debug` | `sha256:22dbb21f3320ea07a8d715a5c350595ff9cafce09e8d28998cbe29a5d56b1c2c` | 527.3 MB |

Both images were built for `linux/amd64` from commit
`0191221f51df3fbc8e8bc049ca6c20fc79f5d038`. The digests were confirmed from
the registry. Each image pulled by digest reported version 1.13.9, that
commit and `VERIFIED` source integrity.

| Scanner | Result (both images) |
|---|---|
| Trivy 0.72.0 | 0 vulnerabilities, 0 secrets |
| Grype 0.104.0 | 3 Medium: the still-unfixed `alsa-lib 1.2.16.1-r3` CVEs (CVE-2026-90781, CVE-2026-96674, CVE-2026-96675). Chromium requires libasound. They are carried forward under the exception in `docs/RELEASE-1.13.0.md`, pending an upstream fix. |
| Syft | SPDX SBOM generated |

`openshift/deployment.yaml` pins the production image by tag and digest. No
cluster rollout was performed.

## Known limitations

- A popup or dialog is recognised only when its control references the panel
  (`aria-controls`, `data-bs-target`/`data-target`, `#id`) or uses
  `aria-haspopup`. Overlays mounted with no such reference are still
  discovered through their links, but are not validated as views of their
  own.
- Navigation scope stays host-based: the target, its `www` form, *Include
  subdomains* and approved *Portal hosts*. There is no separate
  per-origin crawl mode.
- Timing fields that were never measured are `null`. The diagnostics report
  the elapsed time of failed activations.
- Not verified against any private enterprise application; all evidence
  comes from the synthetic fixtures.
