#!/bin/bash
# Soft-cycles the iap1_0 USB gadget's UDC binding without physically unplugging the cable — same
# technique and rationale as pi/mirrorlink-ncm/cycle_usb.sh (that file has the full explanation).
# Unbinding drops the D+/D- pull-up, which the head unit sees as a genuine disconnect; rebinding
# re-asserts it, triggering a fresh enumeration. Useful here because iap1_daemon.py's identify
# state (received strings, negotiated lingo, etc.) is per-connection — a clean re-enumeration is
# the easiest way to force a fresh handshake attempt for repeated trials.
#
# Run as root on the Pi.

set -euo pipefail

GADGET_NAME="${1:-iap1_0}"
GADGET_DIR="/sys/kernel/config/usb_gadget/${GADGET_NAME}"
SETTLE_S="${2:-2}"

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

if [[ ! -d "$GADGET_DIR" ]]; then
    echo "No gadget at $GADGET_DIR — run setup_gadget.sh first" >&2
    exit 1
fi

UDC_FILE="${GADGET_DIR}/UDC"
CURRENT_UDC="$(cat "$UDC_FILE" 2>/dev/null || true)"

if [[ -z "$CURRENT_UDC" ]]; then
    CURRENT_UDC="$(ls /sys/class/udc | head -n1)"
    if [[ -z "$CURRENT_UDC" ]]; then
        echo "No UDC found under /sys/class/udc" >&2
        exit 1
    fi
    echo "Gadget was unbound; will bind to $CURRENT_UDC"
else
    echo "Currently bound to $CURRENT_UDC — cycling..."
    echo "" > "$UDC_FILE"
    echo "  unbound (head unit should now see a disconnect)"
fi

sleep "$SETTLE_S"

echo "$CURRENT_UDC" > "$UDC_FILE"
echo "  bound to $CURRENT_UDC (head unit should now see a fresh attach + re-enumeration)"

echo
echo "Check state with:"
echo "  cat /sys/class/udc/${CURRENT_UDC}/state"
