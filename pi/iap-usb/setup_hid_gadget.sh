#!/bin/bash
# Configfs f_hid gadget presenting the Apple iAP-USB-HID device — the SYNTHESIS of the two prior
# USB attempts in this repo:
#   - pi/iap1/setup_gadget.sh   (configfs FunctionFS)  reached 'configured' on this car, because a
#                               configfs gadget connects AT BIND (pull-up asserts when you write UDC),
#                               but presented a vendor-BULK interface — the wrong transport (that was
#                               the pre-RE usbmux guess).
#   - pi/iap-usb (ipod-gadget)  presents the correct Apple iAP HID interface, but is a LEGACY driver
#                               that binds DEACTIVATED and only asserts the pull-up when /dev/iap0 is
#                               opened — and that activate path doesn't drive the dwc2 pull-up here,
#                               so it never leaves 'not attached'.
#
# This script combines the working half of each: configfs (connects at bind -> reaches 'configured',
# proven on this car with MSD + iap1_0) carrying f_hid with the EXACT iPod HID report descriptor
# from oandrew/ipod-gadget (RE-verified, see references/cr-v/IAP_OVER_USB.md §5a). It exposes
# /dev/hidg0 with the same raw-HID-report semantics as ipod-gadget's /dev/iap0, so hid_framing.py +
# iap_usb_bridge.py run UNCHANGED on top (the bridge auto-prefers /dev/hidg0).
#
# KNOWN LIMITATION vs ipod-gadget: f_hid does NOT ACK the Apple vendor control request bRequest 0x40
# (ipod-gadget does). Enumeration to 'configured' does not involve 0x40, so this WILL clear the
# 'not attached' blocker. If the HU then stalls waiting on a 0x40 handshake AFTER config, that's the
# signal to fall back to patching ipod-gadget to connect-at-bind (remove its usb_function_deactivate)
# instead — see README "Two bearers".
#
# Host->device path: the descriptor's OUTPUT reports (IDs 5-9) have no interrupt-OUT endpoint; the HU
# delivers them via SET_REPORT on EP0, exactly like a real iPod. We set no_out_endpoint=1 so f_hid
# matches (kernel >= 5.19; the Pi's 6.18 has it). f_hid routes SET_REPORT OUT data to /dev/hidg0
# reads, so the bridge sees HU->iPod reports normally.
#
# Prereqs: dtoverlay=dwc2,dr_mode=peripheral (pi/step-1-commands.md step 0), libcomposite.
# Only one gadget binds the UDC at a time — tear down msd/ncm/ipod-gadget first (this script does).
#
# Run as root on the Pi.  Usage:  sudo ./setup_hid_gadget.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Must run as root" >&2; exit 1; fi

GADGET_NAME="iaphid0"
G="/sys/kernel/config/usb_gadget/${GADGET_NAME}"
PRODUCT_ID="${IPOD_PRODUCT_ID:-0x1297}"   # U1-sweep knob; VID is fixed Apple 0x05ac

# --- 0. clear the field: unbind/remove any other gadget, unload the ipod-gadget legacy driver ------
rmmod g_ipod_gadget g_ipod_hid g_ipod_audio 2>/dev/null || true
for u in /sys/kernel/config/usb_gadget/*/UDC; do [[ -e "$u" ]] && echo "" > "$u" 2>/dev/null || true; done

modprobe libcomposite

# --- 1. (re)create the gadget tree -----------------------------------------------------------------
if [[ -d "$G" ]]; then
    echo "" > "$G/UDC" 2>/dev/null || true
    # remove function links + functions so we start clean
    find "$G/configs" -maxdepth 2 -type l -exec rm -f {} + 2>/dev/null || true
    rmdir "$G"/configs/*/strings/* "$G"/configs/* "$G"/functions/* "$G"/strings/* 2>/dev/null || true
    rmdir "$G" 2>/dev/null || true
fi
mkdir -p "$G"
cd "$G"

echo 0x05ac > idVendor           # Apple
echo "$PRODUCT_ID" > idProduct   # 0x1297 (RE default)
echo 0x0310 > bcdDevice          # matches the RE'd iPod-HID device (IAP_OVER_USB.md §5a)
echo 0x0200 > bcdUSB

mkdir -p strings/0x409
echo "000000000000000000000000000000" > strings/0x409/serialnumber
echo "Apple Inc." > strings/0x409/manufacturer
echo "iPhone"     > strings/0x409/product

mkdir -p configs/c.1/strings/0x409
echo "iAP1 HID config" > configs/c.1/strings/0x409/configuration
echo 500 > configs/c.1/MaxPower

# --- 2. the f_hid function with the EXACT iPod report descriptor -----------------------------------
mkdir -p functions/hid.usb0
echo 0 > functions/hid.usb0/protocol
echo 0 > functions/hid.usb0/subclass
echo 64 > functions/hid.usb0/report_length      # max report = 63 data + 1 report-ID = 64 (interrupt IN wMaxPacketSize)

# Apple iPod iAP-USB-HID report descriptor (verbatim from oandrew/ipod-gadget gadget/ipod.h):
#   Usage Page 0xFF00; Report Size 8; INPUT report IDs 1..4 counts {12,14,20,63} (iPod->HU);
#   OUTPUT report IDs 5..9 counts {8,10,14,20,63} (HU->iPod, via SET_REPORT).
python3 - "$G/functions/hid.usb0/report_desc" <<'PY'
import sys
desc = bytes([
    0x06,0x00,0xff, 0x09,0x01, 0xa1,0x01, 0x75,0x08, 0x26,0x80,0x00,
    0x15,0x00, 0x09,0x01, 0x85,0x01, 0x95,0x0c, 0x82,0x02,0x01,
    0x09,0x01, 0x85,0x02, 0x95,0x0e, 0x82,0x02,0x01,
    0x09,0x01, 0x85,0x03, 0x95,0x14, 0x82,0x02,0x01,
    0x09,0x01, 0x85,0x04, 0x95,0x3f, 0x82,0x02,0x01,
    0x09,0x01, 0x85,0x05, 0x95,0x08, 0x92,0x02,0x01,
    0x09,0x01, 0x85,0x06, 0x95,0x0a, 0x92,0x02,0x01,
    0x09,0x01, 0x85,0x07, 0x95,0x0e, 0x92,0x02,0x01,
    0x09,0x01, 0x85,0x08, 0x95,0x14, 0x92,0x02,0x01,
    0x09,0x01, 0x85,0x09, 0x95,0x3f, 0x92,0x02,0x01,
    0xc0,
])
with open(sys.argv[1], "wb") as f:
    f.write(desc)
PY

# host->device via SET_REPORT only (no interrupt-OUT endpoint), matching the real iPod. Best-effort:
# the attribute exists on kernel >= 5.19; if absent, f_hid falls back to also creating an OUT ep
# (harmless — the HU uses SET_REPORT regardless).
if [[ -e functions/hid.usb0/no_out_endpoint ]]; then
    echo 1 > functions/hid.usb0/no_out_endpoint && echo "  no_out_endpoint=1 (SET_REPORT-only, like a real iPod)"
else
    echo "  NOTE: no_out_endpoint attribute absent on this kernel — an OUT ep will exist but the HU should still use SET_REPORT"
fi

ln -sf functions/hid.usb0 configs/c.1/

# --- 3. bind the UDC -> this is the CONNECT event (pull-up asserts now, at bind) --------------------
UDC="$(ls /sys/class/udc | head -n1)"
echo "$UDC" > UDC
echo "  bound to UDC: $UDC  (pull-up asserted AT BIND — the car should enumerate now)"

sleep 1
echo
echo "  UDC state : $(cat /sys/class/udc/$UDC/state 2>/dev/null || echo '?')   (want: 'configured' once the HU enumerates)"
echo "  /dev/hidg0: $([[ -e /dev/hidg0 ]] && echo present || echo 'MISSING — check dmesg')"
echo "  idProduct : $PRODUCT_ID"
echo
echo "Now run the bridge (it auto-targets /dev/hidg0):"
echo "  sudo python3 iap_usb_bridge.py"
echo
echo "Then dump the HU log (tear this gadget down first, bring msd up) and look for OnDeviceChangeEvent"
echo "+ GetConnectType 'iAP over USB' + SwitchConnect success. See references/cr-v/IAP_OVER_USB.md §6."
