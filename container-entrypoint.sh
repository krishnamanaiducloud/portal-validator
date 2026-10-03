#!/bin/sh
set -eu

: "${HOME:=/tmp/portal-validator-home}"
: "${PORTAL_VALIDATOR_MANAGED_CA_BUNDLE:=/etc/portal-validator/certs/ca-bundle.crt}"
: "${RUNTIME_CA_BUNDLE:=$HOME/.portal-validator/ca-bundle.crt}"
: "${CHROMIUM_NSS_DB:=$HOME/.local/share/pki/nssdb}"
: "${PORTAL_VALIDATOR_TRUST_STATUS:=$HOME/.portal-validator/trust-status.json}"

export HOME
export PORTAL_VALIDATOR_MANAGED_CA_BUNDLE
export RUNTIME_CA_BUNDLE
export CHROMIUM_NSS_DB
export PORTAL_VALIDATOR_TRUST_STATUS
export SSL_CERT_FILE="$RUNTIME_CA_BUNDLE"
export REQUESTS_CA_BUNDLE="$RUNTIME_CA_BUNDLE"
export CURL_CA_BUNDLE="$RUNTIME_CA_BUNDLE"

umask 077
mkdir -p "$HOME/.portal-validator" "$CHROMIUM_NSS_DB"

echo "Initializing runtime CA bundle and Chromium NSS trust"
python -m app.trust initialize
echo "Runtime CA bundle and Chromium NSS trust initialization completed"

exec "$@"
