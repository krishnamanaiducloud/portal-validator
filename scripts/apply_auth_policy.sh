#!/usr/bin/env bash
# Configure an explicitly approved, per-portal OAuth/SAML destination policy.
# Never infer trust from browser cookies, redirects or storage state.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: scripts/apply_auth_policy.sh NAMESPACE POLICY_JSON [DEPLOYMENT] --apply

Without --apply, validate inputs and show the planned changes only.
POLICY_JSON must be an operator-reviewed JSON policy using the existing
PORTAL_VALIDATOR_AUTH_POLICIES_FILE schema. No tokens belong in this file.
For GitOps-managed workloads, commit the equivalent ConfigMap, environment
variable, and read-only volume mount to the authoritative GitOps repository.
HELP
}

if [[ $# -lt 2 || $# -gt 4 || "$1" == --help ]]; then
  usage
  [[ "${1:-}" == --help ]] && exit 0
  exit 2
fi
NAMESPACE=$1
POLICY_FILE=$2
DEPLOYMENT=portal-validator
APPLY=false
for argument in "${@:3}"; do
  if [[ "$argument" == --apply ]]; then
    APPLY=true
  elif [[ "$DEPLOYMENT" == portal-validator ]]; then
    DEPLOYMENT=$argument
  else
    usage >&2
    exit 2
  fi
done
[[ "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || { echo 'Invalid namespace' >&2; exit 2; }
[[ "$DEPLOYMENT" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || { echo 'Invalid deployment name' >&2; exit 2; }
[[ -f "$POLICY_FILE" && -r "$POLICY_FILE" ]] || { echo 'Policy JSON must be a readable file' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'python3 is required' >&2; exit 2; }
command -v oc >/dev/null || { echo 'OpenShift oc CLI is required' >&2; exit 2; }

# The service also performs independent strict canonicalization at startup.
# This preflight checks basic shape and refuses example-only/no-op input.
python3 - "$POLICY_FILE" <<'PY'
import json
import re
import sys
from urllib.parse import urlsplit
path = sys.argv[1]
with open(path, 'rb') as handle:
    contents = handle.read(1024 * 1024 + 1)
if not contents or len(contents) > 1024 * 1024:
    raise SystemExit('Policy JSON size is invalid')
try:
    doc = json.loads(contents)
except (ValueError, UnicodeError):
    raise SystemExit('Policy JSON is invalid')
if not isinstance(doc, dict) or set(doc) != {'version', 'policies'} or type(doc['version']) is not int or doc['version'] != 1:
    raise SystemExit('Unexpected policy JSON schema')
policies = doc['policies']
if not isinstance(policies, list) or not policies or len(policies) > 100:
    raise SystemExit('Provide at least one explicitly reviewed portal policy')
for entry in policies:
    if not isinstance(entry, dict) or not {'id', 'portal_hosts', 'authentication_hosts'} <= set(entry):
        raise SystemExit('Policy entry is missing required fields')
    if not isinstance(entry.get('id'), str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', entry['id']):
        raise SystemExit('Policy identifier is invalid')
    for field in ('portal_hosts', 'authentication_hosts'):
        hosts = entry[field]
        if not isinstance(hosts, list) or not hosts or len(hosts) > 25:
            raise SystemExit('Expected 1-25 exact hosts in ' + field)
        for host in hosts:
            if not isinstance(host, str) or not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', host) or '..' in host or host.endswith('.') or host.startswith('-') or '*' in host or host.endswith('.example'):
                raise SystemExit('Policy contains an invalid or unedited example host')
    for endpoint in entry.get('authentication_endpoints', []):
        if not isinstance(endpoint, str):
            raise SystemExit('Authentication endpoint must be a URL')
        parsed = urlsplit(endpoint)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise SystemExit('Explicit authentication endpoint must be a clean HTTPS URL')
print(f'Validated policy structure: {len(policies)} operator-approved portal rule(s).')
PY

oc -n "$NAMESPACE" get deployment "$DEPLOYMENT" -o name >/dev/null
printf 'Namespace: %s\nDeployment: %s\nPolicy: reviewed JSON file (contents are not printed)\n' "$NAMESPACE" "$DEPLOYMENT"
if [[ "$APPLY" != true ]]; then
  echo 'Dry-run only. Use --apply to create/update the ConfigMap and roll the deployment.'
  exit 0
fi
CONFIGMAP=portal-validator-auth-policies
MOUNT=/etc/portal-validator/auth-policies
oc -n "$NAMESPACE" create configmap "$CONFIGMAP" \
  --from-file="policies.json=$POLICY_FILE" --dry-run=client -o yaml | oc -n "$NAMESPACE" apply -f - >/dev/null
oc -n "$NAMESPACE" set volume "deployment/$DEPLOYMENT" \
  --add --overwrite --type=configmap --configmap-name="$CONFIGMAP" \
  --name=auth-policies --mount-path="$MOUNT" --read-only >/dev/null
oc -n "$NAMESPACE" set env "deployment/$DEPLOYMENT" \
  "PORTAL_VALIDATOR_AUTH_POLICIES_FILE=$MOUNT/policies.json" >/dev/null
oc -n "$NAMESPACE" rollout status "deployment/$DEPLOYMENT" --timeout=180s
oc -n "$NAMESPACE" exec "deployment/$DEPLOYMENT" -- python -c \
  'from app.auth_policy import load_authentication_policies; p=load_authentication_policies(); print("Active operator policy count:", len(p))'
echo 'Operator policy mounted. Validate an authorized SSO scan before expecting route discovery.'
