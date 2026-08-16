#!/bin/bash
# Soft-cycles the mass-storage USB gadget without physically unplugging the cable — the same port
# that carries the USB data also powers the Pi, so a physical unplug isn't an option while testing.
#
# Mechanism: unbinding a configfs gadget's UDC drops the D+/D- pull-up, which the head unit sees as
# a genuine disconnect; rebinding re-asserts it, which it sees as a fresh device attach and
# re-enumerates from scratch (SET_ADDRESS, SET_CONFIGURATION, INQUIRY, READ CAPACITY, etc.).
#
# Why this matters for MSD specifically: the head unit's diagnostic "Output Logs" button only
# un-greys when it currently sees a mounted USB disk. If the gadget bound AFTER you were already on
# the diag screen, or the head unit cached a "no disk" state, a cycle forces a fresh attach so it
# re-polls and re-reads the disk. It also makes the head unit re-read the FAT after you've swapped
# the backing image (e.g. after rebuilding it partitioned).
#
# NOTE on coherency: do NOT cycle while the head unit is mid-write (during a Log Copy). Cycle
# BEFORE starting the dump (to un-grey the button) or AFTER it reports "complete" (before
# read_logs.sh). Cycling mid-write drops the disk under the host and corrupts the FAT.
#
# Run as root on the Pi. Usage:  sudo ./cycle_usb.sh [gadget_name] [settle_seconds]

set -euo pipefail

GADGET_NAME="${1:-msd0}"
GADGET_DIR="/sys/kernel/config/usb_gadget/${GADGET_NAME}"
SETTLE_S="${2:-2}"
LUN="${GADGET_DIR}/functions/mass_storage.0/lun.0"

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

if [[ ! -d "$GADGET_DIR" ]]; then
    echo "No gadget at $GADGET_DIR — run setup_msd_gadget.sh first" >&2
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
    # sync first so any pending writes to the backing file are flushed before we drop the link.
    sync
    echo "" > "$UDC_FILE"
    echo "  unbound (head unit should now see a disconnect)"
fi

sleep "$SETTLE_S"

echo "$CURRENT_UDC" > "$UDC_FILE"
echo "  bound to $CURRENT_UDC (head unit should now see a fresh attach + re-enumeration)"

sleep 1
echo
echo "  UDC state : $(cat "/sys/class/udc/${CURRENT_UDC}/state" 2>/dev/null || echo '?')  (want: configured)"
echo "  lun file  : $(cat "${LUN}/file" 2>/dev/null || echo '(detached!)')"
echo
echo "Head unit's 'Output Logs' button should now be active. After it reports 'complete', run:"
echo "  sudo ./read_logs.sh"
