#!/bin/bash
# Build + load the iPod USB-HID gadget so the head unit enumerates the Pi as an Apple iAP device,
# exposing /dev/iap0 for the bridge (iap_usb_bridge.py). See references/cr-v/IAP_OVER_USB.md.
#
# The USB-device HID layer is the oandrew/ipod-gadget KERNEL MODULE — it handles the Apple-specific
# quirks the generic configfs f_hid does not: the vendor GET_DESCRIPTOR for the iAP report descriptor,
# the Apple vendor control request (bRequest 0x40), and host->device data via SET_REPORT (no OUT
# endpoint). Descriptors it presents (confirmed by RE, IAP_OVER_USB.md):
#   idVendor 0x05AC (Apple), idProduct 0x1297, bcdDevice 0x0310, bcdUSB 0x0200
#   HID interface (class 3), one interrupt-IN endpoint (64B), vendor usage page 0xFF00
#   INPUT reports  ID 1..4 len {12,14,20,63}  (iPod->HU)
#   OUTPUT reports ID 5..9 len {8,10,14,20,63} (HU->iPod, via SET_REPORT)
#
# Prereqs: dwc2 peripheral mode (dtoverlay=dwc2,dr_mode=peripheral — pi/step-1-commands.md step 0),
# kernel headers for the running kernel, build-essential/git. Only one gadget binds the UDC at a
# time — tear down msd/ncm/aoa first.
#
# Run as root on the Pi.

set -euo pipefail

REPO="${IPOD_GADGET_REPO:-https://github.com/oandrew/ipod-gadget}"
SRC="${IPOD_GADGET_SRC:-/opt/9carplay/ipod-gadget}"

if [[ $EUID -ne 0 ]]; then echo "Must run as root" >&2; exit 1; fi

echo "== 1. fetch ipod-gadget =="
if [[ ! -d "$SRC/.git" ]]; then
    mkdir -p "$(dirname "$SRC")"
    git clone "$REPO" "$SRC"
else
    git -C "$SRC" pull --ff-only || true
fi

echo "== 2. build the kernel module against the running kernel =="
# Invoke kbuild DIRECTLY with M pointing at the source dir. Do NOT use ipod-gadget's own
# `make` wrapper: its `all:` target builds with `M=$(PWD)`, and $(PWD) is an inherited env var
# that a plain `make -C "$SRC/gadget"` does NOT update (-C changes make's cwd but not $PWD), so
# kbuild ends up with M pointing at wherever you launched the script from and fails with
# "Makefile: No such file or directory". Setting M ourselves sidesteps that entirely — kbuild
# reads $SRC/gadget/Makefile (its obj-m lines) as the module Makefile.
KDIR="/lib/modules/$(uname -r)/build"
make -C "$KDIR" M="$SRC/gadget" modules

echo "== 3. load it =="
# NOTE: confirm the exact module name / whether it auto-binds a UDC or needs configfs from the
# repo README. Common path: insmod the built .ko, then bind the UDC if not automatic.
MOD="$(ls "$SRC"/gadget/*.ko 2>/dev/null | head -n1 || true)"
if [[ -z "$MOD" ]]; then echo "no .ko built under $SRC/gadget — check the build" >&2; exit 1; fi
insmod "$MOD" || echo "insmod failed (already loaded? check dmesg)"

echo "== 4. bind the UDC (if the module didn't auto-bind) =="
UDC="$(ls /sys/class/udc 2>/dev/null | head -n1 || true)"
echo "  available UDC: ${UDC:-<none - check dwc2 peripheral mode>}"
# If the module creates a configfs gadget, bind with:
#   echo "$UDC" | sudo tee /sys/kernel/config/usb_gadget/<name>/UDC
# (mirror the | sudo tee pattern from pi/msd-gadget — a bare 'sudo echo >' fails on sysfs.)

echo
echo "Expect /dev/iap0 to appear. Then run the bridge:"
echo "  sudo python3 iap_usb_bridge.py"
echo
echo "Watch enumeration on the Pi (dmesg) and — with the head unit connected — its own log via"
echo "pi/msd-gadget log dump: look for GetConnectType 'iAP over USB' and 'SwitchConnect' success"
echo "(no 'SwitchConnect Failed' / 'iAPoverBTConnectError'). See references/cr-v/IAP_OVER_USB.md §6."
