#!/bin/bash
# Soft-cycles the USB gadget connection without physically unplugging the cable — useful on
# this Pi because the same port that carries the CDC-NCM data link also supplies power, so a
# physical unplug isn't an option while testing.
#
# Mechanism: unbinding a configfs gadget's UDC drops the D+/D- pull-up, which the host (the
# head unit) sees as a genuine disconnect; rebinding re-asserts it, which the host sees as a
# fresh device attach and re-enumerates from scratch (SET_ADDRESS, SET_CONFIGURATION, etc.).
# This is the same operation that was used earlier to recover from a stuck "not attached"
# UDC state, repurposed here as a deliberate, repeatable disconnect/reconnect trigger.
#
# Run as root on the Pi. See README.md "Cycling the USB connection without unplugging".

set -euo pipefail

GADGET_NAME="${1:-ncm0}"
GADGET_DIR="/sys/kernel/config/usb_gadget/${GADGET_NAME}"
SETTLE_S="${2:-2}"

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

if [[ ! -d "$GADGET_DIR" ]]; then
    echo "No gadget at $GADGET_DIR — run setup_ncm_gadget.sh first" >&2
    exit 1
fi

UDC_FILE="${GADGET_DIR}/UDC"
CURRENT_UDC="$(cat "$UDC_FILE" 2>/dev/null || true)"

if [[ -z "$CURRENT_UDC" ]]; then
    # Not currently bound — pick the (first) available UDC to bind to.
    CURRENT_UDC="$(ls /sys/class/udc | head -n1)"
    if [[ -z "$CURRENT_UDC" ]]; then
        echo "No UDC found under /sys/class/udc" >&2
        exit 1
    fi
    echo "Gadget was unbound; will bind to $CURRENT_UDC"
else
    echo "Currently bound to $CURRENT_UDC — cycling..."
    echo "" > "$UDC_FILE"
    echo "  unbound (host should now see a disconnect)"
fi

sleep "$SETTLE_S"

echo "$CURRENT_UDC" > "$UDC_FILE"
echo "  bound to $CURRENT_UDC (host should now see a fresh attach + re-enumeration)"

echo
echo "Check state with:"
echo "  cat /sys/class/udc/${CURRENT_UDC}/state"
echo "  ip -d link show usb0"
