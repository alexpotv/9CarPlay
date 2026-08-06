#!/bin/bash
# Clean teardown of any previous aoa0 gadget (either direct or two-stage mode),
# per the "Running the two-stage test" step 1 in README.md.
# Safe to run even if no gadget is present or teardown is only partially done.

set -u

GADGET=/sys/kernel/config/usb_gadget/aoa0

sudo pkill -f 'aoa_gadget|aoa_gadget_twostage' || true

if [ -d "$GADGET" ]; then
    [ -f "$GADGET/UDC" ] && echo "" | sudo tee "$GADGET/UDC" >/dev/null
    sudo umount /dev/ffs-aoa0 2>/dev/null || true
    sudo rm -f "$GADGET/configs/c.1/ffs.aoa0"
    sudo rmdir "$GADGET/functions/ffs.aoa0" 2>/dev/null
    sudo rmdir "$GADGET/configs/c.1/strings/0x409" 2>/dev/null
    sudo rmdir "$GADGET/configs/c.1" 2>/dev/null
    sudo rmdir "$GADGET/strings/0x409" 2>/dev/null
    sudo rmdir "$GADGET" 2>/dev/null
fi

echo "Clean teardown complete."
