#!/bin/bash
# Sets up a Linux USB gadget (configfs) presenting an Apple-identity device with a single
# vendor-class FunctionFS interface, ready for iap1_daemon.py to drive a legacy iAP1 "phone"
# identify handshake over it — the Gate 2 (app whitelist) implementation described in
# references/cr-v/iap.md. Companion to pi/aoa-gadget/ and pi/mirrorlink-ncm/, same configfs
# pattern, different target protocol (iAP1 over USB instead of AOA or CDC-NCM/SSDP).
#
# Run as root on the Raspberry Pi itself (NOT the dev machine). Requires:
#   - a Pi model whose USB port supports peripheral/OTG mode (Pi Zero/Zero 2 W, or a Pi 4/5 via
#     its USB-C port) — a plain USB-A host-only port cannot do this.
#   - dtoverlay=dwc2 in /boot/firmware/config.txt, then reboot.
#   - libcomposite loaded (modprobe libcomposite).
# Cannot coexist with the AOA or CDC-NCM gadgets — all three bind the same UDC. Tear down
# whichever one is active first (see that directory's README "clean restart"/teardown steps).

set -euo pipefail

GADGET_NAME="iap1_0"
GADGET_DIR="/sys/kernel/config/usb_gadget/${GADGET_NAME}"
FFS_MOUNT="/dev/ffs-iap1"

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

modprobe libcomposite

mkdir -p "$GADGET_DIR"
cd "$GADGET_DIR"

# Apple's USB vendor ID (0x05ac) is public (USB-IF's registry, linux-usb.org, and every Apple
# device that has ever enumerated on any host). The product ID below (0x1297) is likewise public
# — it appears in libimobiledevice/usbmuxd's own device tables as one of the PIDs a 2012-2014-era
# iPhone presents in normal (non-DFU/non-recovery) USB mode. Neither value is secret or something
# only an MFi licensee would know; they're just USB enumeration identity, same category of public
# information as the AOA VID/PID pi/aoa-gadget/ already uses. Per iap.md's "Open risks" #2, what
# actually determines whether the head unit trusts this identity is the (still unresolved) MFi
# device-attestation question, not the VID/PID itself — this is chosen to be a *plausible* iPhone
# of the right era, not a claim that this specific PID is confirmed required.
echo 0x05ac > idVendor
echo 0x1297 > idProduct
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB

mkdir -p strings/0x409
echo "000000000000000000000000000000" > strings/0x409/serialnumber
echo "Apple Inc." > strings/0x409/manufacturer
echo "iPhone" > strings/0x409/product

mkdir -p configs/c.1/strings/0x409
echo "iAP1 HondaLink test config" > configs/c.1/strings/0x409/configuration
echo 500 > configs/c.1/MaxPower

mkdir -p functions/ffs.iap1
ln -sf functions/ffs.iap1 configs/c.1/

mkdir -p "$FFS_MOUNT"
mount -t functionfs iap1 "$FFS_MOUNT" 2>/dev/null || true

echo "Gadget configfs tree created at $GADGET_DIR"
echo "FunctionFS mounted at $FFS_MOUNT"
echo
echo "Next: run iap1_daemon.py against $FFS_MOUNT — it must be running and have opened ep0"
echo "BEFORE the UDC is bound, since binding triggers enumeration and the head unit will start"
echo "probing immediately:"
echo "  sudo python3 iap1_daemon.py $FFS_MOUNT"
echo
echo "Then, in another shell, bind the UDC to start enumeration (or use cycle_usb.sh):"
echo "  ls /sys/class/udc"
echo "  echo <udc-name> > $GADGET_DIR/UDC"
