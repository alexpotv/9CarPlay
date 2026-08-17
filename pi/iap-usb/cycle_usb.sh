#!/bin/bash
# Soft-cycles the iPod-HID USB gadget without physically unplugging the cable — the same port that
# carries the USB data also powers the Pi, so a physical unplug isn't an option while testing.
#
# Analog of pi/msd-gadget/cycle_usb.sh, but g_ipod_gadget is a LEGACY-style gadget driver, not a
# configfs gadget: it auto-binds the first free UDC on insmod, and there is no configfs UDC file to
# echo into. So the "unbind / rebind" here is done by RELOADING the composite module — rmmod drops
# the D+/D- pull-up (head unit sees a disconnect), re-insmod re-asserts it (fresh attach +
# re-enumeration: GET_DESCRIPTOR, SET_ADDRESS, SET_CONFIGURATION, and — for us — the HU's
# OnDeviceChangeEvent + iAP transport probe). The two function modules (g_ipod_audio, g_ipod_hid)
# stay loaded; only the top composite is cycled.
#
# Why you need this: dwc2 sometimes doesn't complete the bind on the first insmod (you've seen the
# "run it twice" pattern — first shows 'not attached', second 'configured'). A cycle forces a clean
# re-bind. It also forces the head unit to re-probe if the gadget came up AFTER the HU had already
# cached a "no device" state.
#
# NOTE: 'not attached' off-car is NORMAL — the UDC only reaches 'configured' once a USB HOST (the
# head unit) actually enumerates the port. Don't chase 'configured' on the bench.
#
# PRODUCT_ID / SWAP_CONFIGS carry over from setup_ipod_gadget.sh via the same env vars, so a cycle
# keeps whatever identity you last set up.
#
# Run as root on the Pi. Usage:  sudo ./cycle_usb.sh [settle_seconds]

set -euo pipefail

SRC="${IPOD_GADGET_SRC:-/opt/9carplay/ipod-gadget}"
SETTLE_S="${1:-2}"
PRODUCT_ID="${IPOD_PRODUCT_ID:-0x1297}"
SWAP_CONFIGS="${IPOD_SWAP_CONFIGS:-0}"
KO="$SRC/gadget/g_ipod_gadget.ko"

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

if [[ ! -f "$KO" ]]; then
    echo "No $KO — run setup_ipod_gadget.sh first (build step)." >&2
    exit 1
fi

if lsmod | grep -q '^g_ipod_gadget'; then
    echo "Currently loaded — cycling (unbind)..."
    rmmod g_ipod_gadget
    echo "  rmmod'd (head unit should now see a disconnect)"
else
    echo "Not currently loaded; will bind fresh."
    # Make sure the function modules + libcomposite are present, else the insmod below fails with
    # "Unknown symbol".
    modprobe libcomposite 2>/dev/null || true
    lsmod | grep -q '^g_ipod_audio' || insmod "$SRC/gadget/g_ipod_audio.ko"
    lsmod | grep -q '^g_ipod_hid'   || insmod "$SRC/gadget/g_ipod_hid.ko"
fi

sleep "$SETTLE_S"

insmod "$KO" product_id="$PRODUCT_ID" swap_configs="$SWAP_CONFIGS"
echo "  insmod'd product_id=$PRODUCT_ID swap_configs=$SWAP_CONFIGS (fresh attach + re-enumeration)"

sleep 1
UDC="$(ls /sys/class/udc 2>/dev/null | head -n1 || true)"
echo
echo "  UDC        : ${UDC:-<none>}"
echo "  UDC state  : $(cat "/sys/class/udc/${UDC}/state" 2>/dev/null || echo '?')  ('not attached' is normal off-car; want 'configured' once the HU enumerates)"
echo "  /dev/iap0  : $([[ -e /dev/iap0 ]] && echo present || echo 'MISSING — check dmesg')"
echo
echo "Then run the bridge:  sudo python3 iap_usb_bridge.py"
