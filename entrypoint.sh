#!/usr/bin/env bash
# entrypoint.sh — prepare FIDO_HOME and launch the headless USB/IP authenticator.
set -euo pipefail

FIDO_HOME="${FIDO_HOME:-/run/fido}"
export FIDO_HOME
export PYTHONPATH="/app${PYTHONPATH:+:${PYTHONPATH}}"

mkdir -p "$FIDO_HOME"

# On first boot the platform key does not exist yet. Generate it once so that
# makeCredential (registration) can derive per-RP keys and persist resident
# credentials. It is an EC P-256 key written to ${FIDO_HOME}/platform.key.
if [ ! -f "$FIDO_HOME/platform.key" ]; then
    echo "[entrypoint] Generating platform key in $FIDO_HOME ..." >&2
    python -c "from soft_fido2.key_pair import KeyUtils; KeyUtils.create_platform_key()"
fi

# Create the official PIN-protected wallet before starting the USB/IP service.
# The PIN is read only from a mounted secret and is never printed.
if [ ! -f "$FIDO_HOME/${SOFT_FIDO2_WALLET:-ibkr}.passkey" ]; then
    if [ ! -r "${SOFT_FIDO2_PIN_FILE:-/run/secrets/fido2_pin}" ]; then
        echo "[entrypoint] missing PIN secret; cannot create the passkey wallet" >&2
        exit 1
    fi
    python /usr/local/bin/provision_passkey.py
fi

# Headless mode has no fingerprint scanner or GUI to satisfy the "user
# presence" check, so skip it. Without this, getInfo returns OPERATION_DENIED
# and the authenticator is unusable. Override to anything else to disable.
export SOFT_FIDO2_SKIP_UP="${SOFT_FIDO2_SKIP_UP:-true}"

exec python -m soft_fido2 \
    --transport usbip \
    --port "${SOFT_FIDO2_PORT:-3240}" \
    --no-systray
