#!/bin/bash
# Sets up a Linux USB gadget (configfs) with a single FunctionFS function,
# ready for a userspace daemon (aoa_gadget) to drive the AOA device-side
# handshake over it.
#
# Run as root on the Raspberry Pi itself (NOT on the dev machine). Requires:
#   - a Pi model whose USB port supports peripheral/OTG mode (Pi Zero/Zero 2 W,
#     or a Pi 4/5 via its USB-C port) — a plain USB-A host-only port cannot do this.
#   - dwc2 overlay enabled in /boot/firmware/config.txt:
#       dtoverlay=dwc2
#     and (if using the USB-C port for both power+data on a Pi 4/5) libcomposite
#     loaded: `modprobe libcomposite`.
#
# This declares idVendor/idProduct as the Google AOA accessory identifiers
# (0x18d1 / 0x2d00) from the start, rather than implementing genuine two-stage
# re-enumeration (enumerate as something generic, then detach/re-enumerate as
# 0x18d1 after the Start request) the way a real Android phone does. This is a
# deliberate v1 simplification — see README.md "Known simplifications". If the
# head unit's vncbearer-USBAAP.dll insists on observing the actual transition,
# this script will need to grow a second gadget profile and a UDC
# unbind/rebind step triggered by aoa_gadget.c on receiving AOA_START.

set -euo pipefail

GADGET_NAME="aoa0"
GADGET_DIR="/sys/kernel/config/usb_gadget/${GADGET_NAME}"
FFS_MOUNT="/dev/ffs-aoa0"

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

modprobe libcomposite

mkdir -p "$GADGET_DIR"
cd "$GADGET_DIR"

# Google's AOA accessory VID/PID (no adb, no audio) — see README for the
# other PIDs (0x2d01 = +adb, 0x2d02 = +audio, 0x2d03 = +audio+adb) if the
# head unit turns out to expect one of those instead.
echo 0x18d1 > idVendor
echo 0x2d00 > idProduct
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB

mkdir -p strings/0x409
echo "0123456789abcdef" > strings/0x409/serialnumber
echo "9CarPlay Project" > strings/0x409/manufacturer
echo "AOA Bridge (dev)" > strings/0x409/product

mkdir -p configs/c.1/strings/0x409
echo "AOA bridge config" > configs/c.1/strings/0x409/configuration
echo 120 > configs/c.1/MaxPower

mkdir -p functions/ffs.aoa0
ln -sf functions/ffs.aoa0 configs/c.1/

mkdir -p "$FFS_MOUNT"
mount -t functionfs aoa0 "$FFS_MOUNT" 2>/dev/null || true

echo "Gadget configfs tree created at $GADGET_DIR"
echo "FunctionFS mounted at $FFS_MOUNT"
echo
echo "Next: run aoa_gadget against $FFS_MOUNT/ep0 to write descriptors — it"
echo "must be running and have opened ep0 BEFORE the UDC is bound, since"
echo "binding triggers enumeration and the host will start probing immediately."
echo
echo "Once aoa_gadget has written descriptors and opened all endpoints, bind"
echo "the UDC to start enumeration:"
echo "  ls /sys/class/udc                       # find the controller name"
echo "  echo <udc-name> > $GADGET_DIR/UDC"
