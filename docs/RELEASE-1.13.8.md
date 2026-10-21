# Portal Validator 1.13.8 — auto-loaded read-only POSTs and session renewal

## Auto-loaded read-only POST requests are allowed

Previously, every POST was blocked unless an operator approved its exact
endpoint. Applications that load their data through POST therefore showed
no results. Common examples are search, list and query APIs, GraphQL
queries and JSON-RPC readers.

A POST now reaches the application without per-endpoint approval when all of
the following hold:

- The application issued it by itself as a fetch/XHR while a view loaded.
  Form submissions and document navigations never qualify, and the
  validator never submits forms or replays requests.
- It comes from an in-scope page and goes to a portal host or an approved
  resource host.
- It carries concrete read-only evidence, one of:
  - a GraphQL body whose operations are all queries (`GRAPHQL_QUERY`);
  - a JSON-RPC body whose method names a read operation
    (`JSON_RPC_READ`);
  - a path that names a read operation (search, list, get, query, find,
    lookup, filter, summary and similar) and no write operation
    (`READ_OPERATION_PATH`).

The following always stay blocked unless explicitly approved:

- paths or methods containing any write word, such as save, update,
  delete, submit, create, approve, send, upload, export, track or
  token/refresh;
- GraphQL mutations, and GraphQL endpoints without a proven query;
- multipart uploads;
- endpoints with no read evidence.

Allowed requests are classified `AUTO_READ_ONLY` and labelled
`POST_READ_ONLY_AUTO_ALLOWED` in the API inventory. They count towards the
approved read-only POST totals. Anything still blocked keeps appearing in
the *POST approval review* panel, where it can be approved explicitly.

The setting is *Advanced → Auto-loaded read-only POSTs*
(`auto_allow_read_only_posts`, default on). Turning it off restores the
previous explicit-approval-only behaviour.

## Session tokens renew automatically

Token renewal used to be allowed only as a form-encoded
`grant_type=refresh_token` request to an identity host the operator had
approved. Renewal in any other form was blocked, so the session eventually
expired mid-scan:

- JSON refresh bodies;
- refresh, renew or keepalive endpoints on the portal itself (for example
  `/api/auth/refresh`, `/token/refresh`, `/session/keep-alive`);
- refreshes to the identity host the SSO profile signed in to.

The application's own renewal is now allowed as `SESSION_REFRESH` when it is
a fetch/XHR POST from an in-scope page and one of the following applies:

- **Portal host:** a refresh-token exchange (form or JSON), or an endpoint
  whose name says it refreshes, renews or keeps the session or token alive.
  Logout, revoke, password and registration endpoints are excluded.
- **Identity host:** a refresh-token exchange (form or JSON) to a host that
  is approved, was traversed during this scan's sign-in, or that the
  session profile already holds cookies for.

For the last case only the profile's cookie domains are read. The cookies of
unapproved hosts are still never loaded into the scan. Destination, DNS and
port validation still applies to every renewal request, and token values are
never logged or reported.

The report's `session` section now records `automatic_renewals` and
`renewal_hosts`. The setting is *Advanced → Session renewal*
(`auto_allow_session_renewal`, default on). A refresh-token exchange to a
host with no relation to the session stays blocked.

## Verification

- Host suite (WSL2, Python and Playwright): 1222 passed. New coverage:
  - `tests/test_auto_read_posts.py`:
    - inference rules: 14 allowed and blocked cases;
    - renewal signals;
    - an end-to-end portal whose search, list and GraphQL-query POSTs and
      its own `/api/auth/refresh` reach the server, while the GraphQL
      mutation and the preference save do not;
    - strict mode.
  - `tests/test_session_renewal.py`: renewal to the identity host that holds
    the session profile's cookies, with no host approval.
  - `tests/test_scan_post_lifecycle.py`: the production-style fixture's own
    `POST /api/query` is allowed by default and PUT/PATCH/DELETE stay
    blocked.
  - Tests of the explicit-approval semantics now pin
    `auto_allow_read_only_posts=False`.
- UI smoke (`tests/ui_check.py`): passed. It includes both new settings.
- Debug image (Python 3.15, restricted runtime): 1214 of 1222 passed.
  - 6 failures are `tests/test_operator_policy_script.py`, which needs
    `bash`; the image does not ship it.
  - 2 failures were per-test time budgets exceeded under full-suite load:
    `test_auto_loaded_read_only_posts_reach_the_application` and
    `test_noop_semantic_navigation_does_not_fabricate_route_transition_or_repeat_post`.
    Rerun in isolation in the image, both passed 3 of 3 times.
  - The new test's budgets were widened afterwards. That was a test-only
    change; the image's runtime code is unchanged.
- `tests/release_image_smoke.py` passed for both images. The debug run used
  `RELEASE_SMOKE_STARTUP_TIMEOUT=300`.

| Image | Digest | Compressed size |
|---|---|---|
| `docker.io/mohankrishna999/portal-validator:1.13.8` | `sha256:ff663daf247bca5e21946ad52ad217ca98126ba801fcbad34bff7422c8cafff2` | 503.7 MB |
| `docker.io/mohankrishna999/portal-validator:1.13.8-debug` | `sha256:134d81fc52a4fcf76d964712d1553cd89121e232f064ac4ef70b9cc31498858e` | 527.3 MB |

Both images were built for `linux/amd64` from commit
`5ba9086f766393349734877cad2041ab68e286a8`. The digests were confirmed from
the registry. Each image pulled by digest reported version 1.13.8, that
commit and `VERIFIED` source integrity.

| Scanner | Result (both images) |
|---|---|
| Trivy 0.72.0 | 0 vulnerabilities, 0 secrets |
| Grype 0.104.0 | 3 Medium: the still-unfixed `alsa-lib 1.2.16.1-r3` CVEs (CVE-2026-90781, CVE-2026-96674, CVE-2026-96675), carried forward under the exception in `docs/RELEASE-1.13.0.md` |
| Syft | SPDX SBOM generated |

`openshift/deployment.yaml` pins the production image by tag and digest. No
cluster rollout was performed.
