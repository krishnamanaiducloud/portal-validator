# Portal Validator 1.13.6 — sub-tabs and read-only POST review

## Query-addressed sub-tabs are validated as separate views

Some applications address tabs and sub-tabs only through a query parameter,
for example `/reports?tab=daily` and `/reports?tab=monthly`. Under the
default `ignore` query parameter policy, these destinations normalized to the
same route. Only the first one was validated, and every other sub-tab was
dropped as a duplicate.

The scanner now learns which query parameters tell sibling tab, menu item or
option destinations apart. A parameter counts when it appears on two or more
siblings under the same path with different values. During that scan, those
parameters become part of route identity. Tracking and secret-bearing
parameters are still removed. Nothing is configured per site, so this works
the same way for any portal.

Nested `role="tab"` sub-tabs inside a tab panel were already discovered.
`tests/test_nested_subtabs.py` now covers both cases.

## Review panel for blocked read-only POST requests

POST requests are denied by default. A POST that was never approved as
read-only is blocked before it reaches the application. Its result therefore
cannot be validated, and the dashboard showed 0 approved read-only POST
endpoints.

When a scan observes POST endpoints that were blocked only because they were
unverified, the dashboard now lists them in a review panel:

- Nothing is pre-selected.
- Authentication traffic is never offered.
- **Approve selected as read-only** adds the selected endpoints under
  *Approved read-only API operations*. Inventory placeholders such as `{id}`
  become `{segment}` path patterns.
- **Approve and run again** also starts a new scan.

Approving an endpoint stays an explicit operator decision. Unapproved POSTs
remain blocked, and request bodies are never logged or replayed.

The previous 100-operation limit on approved read-only POST operations has
been removed from the UI.

## Notes for sign-in protected portals

Sub-tab discovery inside a route can only run once the route has rendered.
If routes report as sign-in blocked, approve the identity hosts suggested in
the authentication callout (added in 1.13.4) first. Their sub-tabs will be
discovered on the next run.

## Verification

- Host suite (WSL2, Python and Playwright): 1201 passed. This includes the
  new nested and query-addressed sub-tab tests.
- UI smoke (`tests/ui_check.py`): passed. It covers the POST approval review:
  only unverified, non-authentication POSTs are offered, nothing is
  pre-selected, and approved paths become exact or `{segment}` rules.
- Debug image (Python 3.15, restricted runtime): 1195 of 1201 passed. The 6
  failures are `tests/test_operator_policy_script.py`, which runs the
  host-side operator script with `bash`. The runtime image deliberately does
  not ship `bash`, and these tests pass on the host.
- `tests/release_image_smoke.py` passed for both images. The debug run used
  `RELEASE_SMOKE_STARTUP_TIMEOUT=300` because the debugpy and reload worker
  needs more than the default 60 s.

| Image | Digest | Compressed size |
|---|---|---|
| `docker.io/mohankrishna999/portal-validator:1.13.6` | `sha256:6d0de34ffa9d43a249552886a84afa57a061702e51b6b1327bf220f07aa53030` | 502.8 MB |
| `docker.io/mohankrishna999/portal-validator:1.13.6-debug` | `sha256:0682b3aca11055dd30d232066f52d5c9e34753ff2d7439fbd24d1e07e3d7c3bc` | 526.5 MB |

Both images were built for `linux/amd64` from commit
`0b6b798677ae215354689c82ffa180517ff9257e`. The digests were confirmed from
the registry. Each image pulled by digest reported version 1.13.6, that
commit and `VERIFIED` source integrity.

| Scanner | Result (both images) |
|---|---|
| Trivy 0.72.0 | 0 vulnerabilities, 0 secrets |
| Grype 0.104.0 | 3 Medium: the still-unfixed `alsa-lib 1.2.16.1-r3` CVEs (CVE-2026-90781, CVE-2026-96674, CVE-2026-96675), carried forward under the exception in `docs/RELEASE-1.13.0.md` |
| Syft | SPDX SBOM generated |

`openshift/deployment.yaml` pins the production image by tag and digest. No
cluster rollout was performed.
