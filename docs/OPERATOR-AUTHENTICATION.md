# Generic OpenShift SSO approval and request issue reporting

Authentication destination authorization is **not** derivable from browser
cookies, localStorage, redirects, or the mere presence of a storage-state file.
A reused profile authenticates a session; it cannot approve new network hosts.
The validator must allow only explicitly approved OAuth/SAML authentication
operations inside an active, validated flow. Business POSTs remain read-only
blocked unless an independent, specifically approved read operation applies.

## OpenShift deployment (operator action)

1. Copy `openshift/authentication-policy.example.json` to a **private operator
   configuration file** outside the application source repository. Replace
   `portal.example` and `identity.example` with the portal and approved IdP
   destinations for **your environment**. Do not put tokens or passwords in this
   policy. Nonstandard callback endpoints must be explicitly approved by full
   HTTPS URL under `authentication_endpoints`; common paths work without them.
2. With `oc` access, preview what will change:

   ```bash
   scripts/apply_auth_policy.sh YOUR_NAMESPACE /path/to/approved-policies.json
   ```

3. Once the policy is security-reviewed and approved, run:

   ```bash
   scripts/apply_auth_policy.sh YOUR_NAMESPACE /path/to/approved-policies.json --apply
   ```

   This creates a ConfigMap containing the reviewed policy and mounts it
   read-only at `/etc/portal-validator/auth-policies`, then points the app's
   `PORTAL_VALIDATOR_AUTH_POLICIES_FILE` there. Existing session Secrets,
   corporate CA mounts, security context and read-only POST rules are unchanged.
   A malformed active policy fails closed. The sample file cannot be applied
   directly; the script refuses the `.example` placeholders.

**GitOps warning:** `oc set env` and `oc set volume` change the live Deployment.
If Argo CD/OpenShift GitOps controls it, implement the equivalent ConfigMap,
volume mount and environment variable in the authoritative GitOps source first,
then synchronize. Otherwise the controller may revert the operational changes.
This script never hardcodes identity hosts or obtains them from storage state.

## Verification gates

- Verify the actual pod version and build digest, not only the Deployment tag.
- Run a scan against a permitted test portal using an authorized, valid profile.
  Confirm `scan_configuration.authentication_host_count` is nonzero for portals
  whose SSO flow requires external identity hosts, and that bootstrap no longer
  ends `AUTHENTICATION_BLOCKED`.
- Confirm the scan reaches `DISCOVERING` and the application-shell readiness
  checks complete before expecting Angular/SPA menus, tab views, and generated
  API traffic. `HTTP 200` on the shell document is insufficient.
- Confirm per-view route/POST attribution for naturally generated requests.
  Never replay POSTs to improve inventory counts; only execute explicitly
  approved read operations under the dedicated policy.
- The **Failed Endpoints** panel reports actual target HTTP, transport and
  response-body failures. The new **Blocked / Incomplete Requests** panel
  separately reports policy-blocked, canceled and incomplete requests. These
  numbers must not be combined into a fictitious target failure count.

The authorized SSO app must be reachable from the OpenShift network and its
session may have expired. The changes do not override MFA, IdP access controls,
SSRF validation, TLS verification or tenant policy. They do not guarantee that
all interactive SPA tabs can be safely activated automatically. Unknown
coverage must remain explicitly labeled incomplete.
