#!/bin/sh
set -eu

: "${HOME:=/tmp/portal-validator-home}"
export HOME

NSS_DIR="$HOME/.local/share/pki/nssdb"
NSS_DB="sql:$NSS_DIR"
ZSCALER_CA="/etc/portal-validator/zscaler/zscaler-root-ca.crt"
ZSCALER_NICKNAME="Zscaler Root CA"

if ! command -v certutil >/dev/null 2>&1; then
    echo "ERROR: certutil is required for Chromium NSS trust initialization" >&2
    exit 1
fi

umask 077
mkdir -p "$NSS_DIR"

if [ ! -f "$NSS_DIR/cert9.db" ]; then
    certutil -N \
      -d "$NSS_DB" \
      --empty-password
fi

if [ ! -s "$ZSCALER_CA" ] || [ ! -r "$ZSCALER_CA" ]; then
    echo "ERROR: Zscaler CA certificate is missing, empty, or unreadable: $ZSCALER_CA" >&2
    exit 1
fi

CURRENT_CA="$NSS_DIR/.zscaler-current.$$.pem"
trap 'rm -f "$CURRENT_CA"' 0 HUP INT TERM

certificate_body() {
    awk '
      /-----BEGIN CERTIFICATE-----/ { inside = 1; next }
      /-----END CERTIFICATE-----/ { inside = 0 }
      inside { gsub(/[[:space:]]/, ""); printf "%s", $0 }
    ' "$1"
}

has_ssl_ca_trust() {
    certutil -L -d "$NSS_DB" | awk -v nickname="$ZSCALER_NICKNAME" '
      index($0, nickname) == 1 {
        trust = substr($0, length(nickname) + 1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", trust)
        if (trust == "C,,") found = 1
      }
      END { exit(found ? 0 : 1) }
    '
}

certificate_exists=false
certificate_matches=false
if certutil -L -d "$NSS_DB" -n "$ZSCALER_NICKNAME" -a >"$CURRENT_CA" 2>/dev/null; then
    certificate_exists=true
    mounted_body="$(certificate_body "$ZSCALER_CA")"
    current_body="$(certificate_body "$CURRENT_CA")"
    if [ -n "$mounted_body" ] && [ "$mounted_body" = "$current_body" ]; then
        certificate_matches=true
    fi
fi

if [ "$certificate_matches" = true ] && has_ssl_ca_trust; then
    echo "Zscaler Root CA already present in Chromium NSS DB"
else
    if [ "$certificate_exists" = true ]; then
        certutil -D -d "$NSS_DB" -n "$ZSCALER_NICKNAME"
    fi

    if ! certutil -A \
      -d "$NSS_DB" \
      -n "$ZSCALER_NICKNAME" \
      -t "C,," \
      -i "$ZSCALER_CA"; then
        echo "ERROR: Failed to import Zscaler Root CA into Chromium NSS DB" >&2
        exit 1
    fi

    if [ "$certificate_exists" = true ]; then
        echo "Zscaler Root CA updated successfully in Chromium NSS DB"
    else
        echo "Zscaler Root CA imported successfully into Chromium NSS DB"
    fi
fi

if ! certutil -L -d "$NSS_DB" -n "$ZSCALER_NICKNAME" >/dev/null 2>&1 \
  || ! has_ssl_ca_trust; then
    echo "ERROR: Zscaler Root CA verification failed in Chromium NSS DB" >&2
    exit 1
fi

rm -f "$CURRENT_CA"
trap - 0 HUP INT TERM

echo "Chromium NSS trust initialization completed"

exec "$@"
