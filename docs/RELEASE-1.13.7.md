# Portal Validator 1.13.7 — linked pages, notifications and profile views

## Linked pages no longer time out

When a readiness selector or event is configured, it describes the
application shell. A hyperlink to a separately loaded page outside that shell
never shows it. Examples are help, documentation, release notes, legal pages
or another in-scope site. Such routes used to wait for the selector until the
route's time budget ran out, and then failed with "Configured maximum time
per route exceeded".

A page now counts as a linked document when all of the following hold:

- it is a newly loaded document, after the application shell was proven;
- it rendered meaningful, stable content with no busy indicators;
- it never showed the configured condition for the **Linked page grace**
  period (default 2000 ms).

Such a page is validated as a linked document. Its settle reason is
`LINKED_DOCUMENT_RENDERED`, and the report records `application_readiness:
LINKED_DOCUMENT` so it stays distinguishable from pages that showed the shell
marker. Load time excludes the grace wait.

The grace period is configurable under *Route identity controls*. Setting it
to `0` restores strict behaviour, where every page must show the configured
condition. Same-document views of the application and the first
(authentication-gate) route always require the configured condition.

## Notification, profile and other header popovers are validated

Popup controls outside the primary navigation are now validated as views.
Examples are a notification bell, a profile or avatar menu showing the
signed-in user, and help or app-switcher buttons. Each must use
`aria-haspopup` or `aria-expanded` and control a panel through
`aria-controls` (or a `data-bs-target`/`data-target`/`#id` reference).

Validation opens the panel, waits for its own content to render, and
attributes the panel's API calls, such as notifications or user identity, to
that view. These controls appear with discovery source `ui-popover`.

- Header popovers are shared, so each is validated once per scan. Enable
  *Re-explore on every route* to validate them on every route.
- Links inside the panels (for example *My profile*) are still discovered
  and validated as their own routes.
- A popover already left open, for example by menu exploration, is toggled
  closed first so its load is observed. If it will not close, it is
  validated as it is, instead of waiting for the route timeout.
- Popovers opened by the validator are closed again before the next route,
  so an open overlay cannot cover the next control.
- Dropdowns inside the primary navigation (`nav`, `role="navigation"`,
  menubars, menus, trees, `aside`) are still explored for links only.
- Labels such as *Sign out*, *Delete* or *Submit* are never activated, and
  all requests remain under the read-only network policy.

## Verification

- Host suite (WSL2, Python and Playwright): 1203 passed. This includes the
  new `tests/test_auxiliary_views.py`, which covers linked documents (same
  tab and new tab), the notification panel, the profile menu with identity
  data, and the strict `shell_marker_grace_ms=0` mode.
- UI smoke (`tests/ui_check.py`): passed. It includes the new *Linked page
  grace* setting.
- Debug image (Python 3.15, restricted runtime): 1195 of 1203 passed.
  - 6 failures are `tests/test_operator_policy_script.py`, which needs
    `bash`. The image deliberately does not ship it, and these tests pass on
    the host.
  - 2 failures were per-test time budgets exceeded under full-suite load:
    `test_cdk_backdrop_is_closed_with_escape_before_next_top_level_menu` and
    `test_nested_subtabs_are_validated_with_their_read_only_post`. Rerun in
    isolation, both passed 3 of 3 times in the 1.13.7 image and in the 1.13.6
    image, and they pass on the host.
- `tests/release_image_smoke.py` passed for both images. The debug run used
  `RELEASE_SMOKE_STARTUP_TIMEOUT=300`.

| Image | Digest | Compressed size |
|---|---|---|
| `docker.io/mohankrishna999/portal-validator:1.13.7` | `sha256:644534ce71ae66b638b471a8ef1e2a4f89dc738d5071493c8b8cd65cd22c9c21` | 503.7 MB |
| `docker.io/mohankrishna999/portal-validator:1.13.7-debug` | `sha256:e7f56b32c669e61a6fce6d11284a96621b061f96e722c2a5614ad35a8896b667` | 527.3 MB |

Both images were built for `linux/amd64` from commit
`bc447e4528330523a5204e7d11b24845930cf97d`. The digests were confirmed from
the registry. Each image pulled by digest reported version 1.13.7, that
commit and `VERIFIED` source integrity.

| Scanner | Result (both images) |
|---|---|
| Trivy 0.72.0 | 0 vulnerabilities, 0 secrets |
| Grype 0.104.0 | 3 Medium: the still-unfixed `alsa-lib 1.2.16.1-r3` CVEs (CVE-2026-90781, CVE-2026-96674, CVE-2026-96675), carried forward under the exception in `docs/RELEASE-1.13.0.md` |
| Syft | SPDX SBOM generated |

`openshift/deployment.yaml` pins the production image by tag and digest. No
cluster rollout was performed.
