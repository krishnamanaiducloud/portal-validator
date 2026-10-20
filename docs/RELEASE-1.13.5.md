# Portal Validator 1.13.5 — corporate CA directory restored

1.13.4 renamed the default corporate CA directory from
`/etc/portal-validator/zscaler` to `/etc/portal-validator/corporate-ca`. It
also renamed the example manifest's ConfigMap and volume to match.

Existing deployments still mount their CA certificates at the original path.
Because a configured CA directory that is missing fails closed, 1.13.4 failed
at startup with "Configured corporate CA directory does not exist".

1.13.5 reverts that change exactly. The following now match 1.13.3 byte for
byte:

- `app/trust.py`
- `container-entrypoint.sh`
- the CA settings in `openshift/deployment.yaml`
- `tests/test_trust.py`

The ConfigMap is `portal-validator-zscaler-ca`, mounted at
`/etc/portal-validator/zscaler`. The 1.13.4 migration note no longer applies.
All other 1.13.4 changes are unchanged.

## Verification

- Startup reproduction: CA certificates are mounted at the original
  directory and no override variables are set. The 1.13.4 image fails, and
  the 1.13.5 image starts and initializes trust.
- The trust and container tests, the release image smoke tests and the
  in-image regression suite passed. Results are recorded below.

## Results

- Startup reproduction:
  - `1.13.4` failed with `Configured corporate CA directory does not exist:
    /etc/portal-validator/corporate-ca`.
  - `1.13.5` found `/etc/portal-validator/zscaler` and started.
- Trust, container, application and build tests: 97 passed.
- Debug image (Python 3.15, restricted runtime): 174 of 174 tests passed.
- `tests/release_image_smoke.py` passed for both images.

| Image | Digest | Compressed size |
|---|---|---|
| `docker.io/mohankrishna999/portal-validator:1.13.5` | `sha256:105426186f9b35c6b21479a60fec6ecd134bd921c1e287321f429c37d7ec5c69` | 503.7 MB |
| `docker.io/mohankrishna999/portal-validator:1.13.5-debug` | `sha256:9f0ae77ee9762a6caa2f9b774c6ca243d4e3a014c03993f4e17415580d5f192e` | 527.3 MB |

Both images were built from commit `2f7cfacbc80710e723dbd38d375de82187ba8b48`
for `linux/amd64`. Both digests were confirmed from the registry; each image
pulled by digest reported version 1.13.5, that commit, `VERIFIED` source
integrity and the default directory `/etc/portal-validator/zscaler`.

| Scanner | Result (both images) |
|---|---|
| Trivy 0.72.0 (DB 2026-10-19 19:08 UTC) | 0 vulnerabilities, 0 secrets |
| Grype 0.104.0 (DB 2026-10-19 06:39 UTC) | 3 Medium: the still-unfixed `alsa-lib 1.2.16.1-r3` CVEs, carried forward under the exception documented in `docs/RELEASE-1.13.0.md` |

`openshift/deployment.yaml` pins the production image by tag and digest. No
cluster rollout was performed.
