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
