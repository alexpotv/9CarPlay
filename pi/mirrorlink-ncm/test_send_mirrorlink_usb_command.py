#!/usr/bin/env python3
"""Standalone test: sends the exact "MirrorLink USB command" (ETSI TS 103 544-1, clause 4.2.2)
to the Pi's gadget, from a REGULAR COMPUTER acting as USB host — independent of the car.

Why this exists: mirrorlink_usb_cmd_listener.py only ever logged BIND/ENABLE events against the
real head unit, never a SETUP event for this command — the same "BIND/ENABLE only, nothing else"
pattern seen with the earlier AOA gadget. That's ambiguous: it could mean the head unit genuinely
never sends this command, OR it could mean our own ncm.usb0 + ffs.mlctrl composite gadget has a
plumbing bug that prevents the request from ever reaching userspace, regardless of what any host
sends. This script isolates that: if the listener logs "MirrorLink USB command received" when this
script runs, our gadget-side implementation is proven correct, and the real head unit's silence is
real (not our bug). If it does NOT arrive even from this controlled test, that's a genuine bug in
the gadget setup to fix before drawing any conclusion about the head unit's behavior.

Setup:
    1. Unplug the Pi's USB gadget port (the one normally connected to the head unit) from the car.
    2. Plug it into a regular computer instead (this script's host — your Mac/PC/Linux machine).
    3. On the Pi: make sure mirrorlink_usb_cmd_listener.py is running and the UDC is bound
       (same sequence as the real-car Quickstart — setup_ncm_gadget.sh, start the listener, then
       cycle_usb.sh).
    4. On the host computer: pip install pyusb, and on macOS also `brew install libusb`.
    5. Run this script on the host computer. Watch the Pi's listener console for the result.

Caveat: the gadget enumerates as CDC-NCM (Ethernet-over-USB), so the host OS may auto-attach its
own networking driver to it before this script can claim it for raw control transfers. This script
tries to detach any active kernel driver first, but if it still fails with a permissions/busy
error, a Linux host (real or VM) tends to be the most reliable — macOS's IONetworkingFamily can be
more persistent about holding onto a claimed CDC-Ethernet interface. Running with sudo may also be
required on Linux.

Usage:
    python3 test_send_mirrorlink_usb_command.py [--major 1] [--minor 1]
"""

import argparse
import sys

try:
    import usb.core
    import usb.util
except ImportError:
    print("pyusb not installed. Run: pip3 install pyusb", file=sys.stderr)
    print("On macOS you also need libusb: brew install libusb", file=sys.stderr)
    sys.exit(1)

# Must match idVendor/idProduct set in setup_ncm_gadget.sh
GADGET_VID = 0x1d6b
GADGET_PID = 0x0104

BMREQUESTTYPE_HOST_TO_DEVICE_VENDOR_DEVICE = 0x40
MIRRORLINK_USB_COMMAND_BREQUEST = 0xF0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--major", type=int, default=1, help="MirrorLink major version to send")
    ap.add_argument("--minor", type=int, default=1, help="MirrorLink minor version to send")
    ap.add_argument("--host-vendor-id", type=lambda x: int(x, 0), default=0x05AC,
                     help="wIndex value to send (spec: 'USB host vendor ID') — arbitrary for this test")
    args = ap.parse_args()

    dev = usb.core.find(idVendor=GADGET_VID, idProduct=GADGET_PID)
    if dev is None:
        print(f"No device found with VID={GADGET_VID:#06x} PID={GADGET_PID:#06x}.", file=sys.stderr)
        print("Is the Pi's gadget plugged into THIS computer and the UDC bound?", file=sys.stderr)
        sys.exit(1)

    print(f"Found device: {dev}")

    # The gadget enumerates as a CDC-NCM (Ethernet) device, so the host OS may auto-attach its
    # own networking driver to it — which can block raw control-transfer access. Try to detach
    # any kernel driver first; this is a no-op (and harmless) on platforms/backends where it's
    # not supported or not needed (e.g. often the case on macOS with libusb).
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
            print("Detached an active kernel driver from interface 0.")
    except (usb.core.USBError, NotImplementedError):
        pass  # not supported on this platform/backend, or nothing to detach — fine either way

    # wValue: low byte = major version, high byte = minor version (USB is little-endian)
    wvalue = (args.major & 0xFF) | ((args.minor & 0xFF) << 8)

    print(f"Sending MirrorLink USB command: bmRequestType=0x{BMREQUESTTYPE_HOST_TO_DEVICE_VENDOR_DEVICE:02x} "
          f"bRequest=0x{MIRRORLINK_USB_COMMAND_BREQUEST:02x} "
          f"wValue=0x{wvalue:04x} (v{args.major}.{args.minor}) "
          f"wIndex=0x{args.host_vendor_id:04x} wLength=0")

    try:
        dev.ctrl_transfer(
            bmRequestType=BMREQUESTTYPE_HOST_TO_DEVICE_VENDOR_DEVICE,
            bRequest=MIRRORLINK_USB_COMMAND_BREQUEST,
            wValue=wvalue,
            wIndex=args.host_vendor_id,
            data_or_wLength=0,
        )
        print("SUCCESS — control transfer completed without a STALL.")
        print("Check the Pi's mirrorlink_usb_cmd_listener.py console for the received-command line.")
    except usb.core.USBError as e:
        print(f"FAILED — control transfer was stalled or errored: {e}", file=sys.stderr)
        print("This means either our gadget doesn't claim this request (needs debugging), or a "
              "permissions/driver-claim issue on this host is blocking raw control transfers.",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
