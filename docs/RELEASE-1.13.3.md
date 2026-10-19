# Portal Validator 1.13.3 — renewal blocks no longer fail scans

## Authentication failed after about five minutes

With an SSO session profile, scans still ended as "Authentication failed"
after about 318 seconds, with no routes reported. This lines up with a
5-minute access token: the application renews it in the background with a
refresh-token POST or a silent-renew iframe to its identity provider.

When the identity provider host was not approved, that renewal request was
blocked. 1.13.2 already recovered expired sessions, but it treated a
blocked renewal as `AUTHENTICATION_BLOCKED`, a policy failure that still
failed the whole scan. A legacy rule also stopped discovery after any route
with a blocked authentication request.

Now:

- An authentication request blocked after the application passed the
  authentication gate affects only its own route. That route is reported
  as `AUTHENTICATION_BLOCKED` and the scan continues.
- If the session later expires, mid-scan recovery (1.13.2) applies. When
  recovery is impossible, the scan stops as `PARTIAL` and keeps the routes
  already validated.
- The blocks are reported in `mid_scan_authentication_blocks`, including
  the identity host and endpoint. The dashboard names the host to add to
  *Authentication hosts* so the application can renew its session.
- Blocks that the application's own start-up depended on still fail the
  scan closed with zero routes. So do initial authentication failures.
- An unapproved identity host is still never contacted.

## Sortable route and API columns

The routes table's Navigation hierarchy and Discovery source columns, and
the API table's Traffic role, Policy and later columns, were added by
JavaScript without sort controls. All of them now sort on the values they
display. Details sorts by each route's total validation time, which is the
timing breakdown the inspector shows. `tests/ui_check.py` now fails if any
rendered data column in the routes, API, resource, failed-endpoint or
request-issue tables lacks a sort control. The only unsortable columns are
the failure tables' Diagnostics action buttons.

## Tests

- `tests/test_session_renewal.py`: a renewal blocked on a later route
  neither fails the scan nor stops discovery. The unapproved host is never
  contacted, and the block is reported with its host. This test fails on
  1.13.2.
- `tests/ui_check.py`: sortable-header audit across all five tables, and
  ascending/descending sorting of Navigation hierarchy, Discovery source and
  Details.

## Published images

Built from commit `26e5a3c9a9b0ac58bc754f3b6ea8dcd394fb9f4a` for `linux/amd64`.
Later commits change documentation and the Deployment reference only.

| Image | Digest | Compressed size |
|---|---|---|
| `docker.io/mohankrishna999/portal-validator:1.13.3` | `sha256:38ce47a91cdfa32fe522c257c5a4ff82004a9547c13b6b05cb4d2127647e4c03` | 503.6 MB |
| `docker.io/mohankrishna999/portal-validator:1.13.3-debug` | `sha256:2c2e820580d82b6c50fda5f9ce3a351a278e190949143ac43b668b4e07354aec` | 527.3 MB |

Both digests were confirmed from the registry. Each image was pulled by digest
and reported version 1.13.3, the commit above and `VERIFIED` source integrity.
`openshift/deployment.yaml` pins the production image by tag and digest. No
cluster rollout was performed.

## Verification

- Host suite (WSL2, Python 3.14): 1187 passed. The single failure in that run
  came from a test snapshot taken while the version was being bumped. The
  version-dependent tests (83) passed after a consistent re-sync, as did the
  frontend `tests/ui_check.py`.
- Debug image (Python 3.15, arbitrary UID, read-only root, all capabilities
  dropped): 115 of 115 session recovery, session renewal (including the
  mid-scan blocked-renewal reproduction), authentication-first, SSO,
  scan-speed, broad discovery and API tests passed.
- `tests/release_image_smoke.py` passed for both images.

## Security scan results

Trivy 0.72.0 (DB 2026-10-19 19:08 UTC) and Grype 0.104.0 (DB 2026-10-19 06:39
UTC):

| Check | `1.13.3` | `1.13.3-debug` |
|---|---|---|
| Trivy Critical/High/Medium/Low | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| Trivy secrets | 0 | 0 |
| Grype Critical/High/Medium/Low | 0 / 0 / 3 / 0 | 0 / 0 / 3 / 0 |
| SBOM packages (SPDX) | 121 | 172 |

The three Grype findings are the unchanged, still-unfixed `alsa-lib
1.2.16.1-r3` CVEs, carried forward under the exception documented in
`docs/RELEASE-1.13.0.md`.
