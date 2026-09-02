#!/usr/bin/env bash
# Keep the soft-fido2 virtual USB key attached to the host.
#
# Unlike usbip-attach.service (one-shot), this service continuously checks the
# vhci-hcd attachment and re-attaches after a container restart, USB/IP TCP
# disconnect, or host-side device reset.
set -u

SERVER_HOST="${USBIP_SERVER_HOST:-127.0.0.1}"
SERVER_PORT="${USBIP_PORT:-3240}"
BUSID="${USBIP_BUSID:-1-1.1}"
INTERVAL="${USBIP_CHECK_INTERVAL:-10}"

log() { echo "[usbip-watchdog] $(date '+%F %T') $*"; }

wait_server() {
    local timeout="${1:-60}"
    local i
    for i in $(seq 1 "$timeout"); do
        (echo > "/dev/tcp/${SERVER_HOST}/${SERVER_PORT}") 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

is_attached() {
    usbip port 2>/dev/null | grep -q '<Port in Use>' || return 1

    # A stale vhci port may still be printed as "Port in Use" after its TCP
    # data channel dies. Also require the soft-fido2 HID device to exist in
    # sysfs; if it disappeared, force a detach/attach cycle.
    local node
    for node in /sys/class/hidraw/hidraw*; do
        [ -r "$node/device/uevent" ] || continue
        grep -qi 'HID_NAME=soft-fido2' "$node/device/uevent" 2>/dev/null && return 0
    done
    return 1
}

fix_perms() {
    find /dev/bus/usb -maxdepth 2 -type c 2>/dev/null |
        while read -r dev; do chmod 666 "$dev" 2>/dev/null || true; done
    find /dev -maxdepth 1 -name 'hidraw*' -type c 2>/dev/null |
        while read -r dev; do chmod 666 "$dev" 2>/dev/null || true; done
}

log "started (server=${SERVER_HOST}:${SERVER_PORT}, busid=${BUSID}, interval=${INTERVAL}s)"

while :; do
    if is_attached; then
        fix_perms
        sleep "$INTERVAL"
        continue
    fi

    log "virtual key is not attached; re-attaching ..."
    usbip detach -p 00 2>/dev/null || true
    modprobe vhci-hcd 2>/dev/null || log "WARN: modprobe vhci-hcd failed"

    if wait_server 60; then
        if usbip attach -r "$SERVER_HOST" -b "$BUSID" 2>/dev/null; then
            log "attached ${BUSID}"
            fix_perms
        else
            log "attach failed; will retry"
        fi
    else
        log "soft-fido2 server not reachable on ${SERVER_HOST}:${SERVER_PORT}"
    fi

    sleep "$INTERVAL"
done
