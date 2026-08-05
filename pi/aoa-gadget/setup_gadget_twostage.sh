#!/bin/bash
# Sets up the same USB gadget (configfs) as setup_gadget.sh, but starting at
# a GENERIC placeholder identity instead of Google's AOA accessory identity
# — for use with aoa_gadget_twostage (NOT plain aoa_gadget, which expects
# setup_gadget.sh's direct-to-accessory-identity setup instead).
#
# aoa_gadget_twostage performs the real two-stage switch a phone does: it
# starts here at the generic identity, and only rewrites idVendor/idProduct
# to Google's AOA accessory identity (0x18d1/0x2d00) itself, at runtime, once
# it receives AOA_START from the host. Do not pre-set the accessory identity
# in this script — that would defeat the point of testing the two-stage path.
#
# Run as root on the Raspberry Pi itself. Requires the same prerequisites as
# setup_gadget.sh — see that file's header and README.md.

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

# Generic placeholder identity (Linux Foundation "Multifunction Composite
# Gadget", a common generic Linux gadget ID) — arbitrary stand-in for
# whatever native (non-Google) identity a real phone would present before
# the AOA switch. aoa_gadget_twostage.c rewrites idVendor/idProduct itself
# on receiving AOA_START; nothing else needs to change this later.
echo 0x1d6b > idVendor
echo 0x0104 > idProduct
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB

mkdir -p strings/0x409
echo "0123456789abcdef" > strings/0x409/serialnumber
echo "9CarPlay Project" > strings/0x409/manufacturer
echo "AOA Bridge (pre-switch)" > strings/0x409/product

mkdir -p configs/c.1/strings/0x409
echo "AOA bridge config" > configs/c.1/strings/0x409/configuration
echo 120 > configs/c.1/MaxPower

mkdir -p functions/ffs.aoa0
ln -sf functions/ffs.aoa0 configs/c.1/

mkdir -p "$FFS_MOUNT"
mount -t functionfs aoa0 "$FFS_MOUNT" 2>/dev/null || true

echo "Gadget configfs tree created at $GADGET_DIR, starting at the GENERIC"
echo "identity (0x1d6b/0x0104) — this is the two-stage setup."
echo "FunctionFS mounted at $FFS_MOUNT"
echo
echo "Next: run aoa_gadget_twostage against $FFS_MOUNT/ep0 (NOT plain"
echo "aoa_gadget — that binary expects setup_gadget.sh's direct setup"
echo "instead) — it must be running and have opened ep0 BEFORE the UDC is"
echo "bound, since binding triggers enumeration and the host will start"
echo "probing immediately."
echo
echo "Once aoa_gadget_twostage has written descriptors and opened all"
echo "endpoints, bind the UDC to start enumeration:"
echo "  ls /sys/class/udc                       # find the controller name"
echo "  echo <udc-name> | sudo tee $GADGET_DIR/UDC"
echo
echo "aoa_gadget_twostage will perform the identity switch (unbind/rewrite"
echo "idVendor+idProduct/rebind) itself once it receives AOA_START — no"
echo "further manual UDC action needed after the initial bind above."
