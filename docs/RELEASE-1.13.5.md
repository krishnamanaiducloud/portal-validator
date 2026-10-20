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
