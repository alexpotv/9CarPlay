#!/usr/bin/env python3
"""set_apple_did.py — make the Pi advertise an Apple Bluetooth Device ID (PnP / DID, SDP 0x1200).

WHY (CHANGE 1, 2026-08-11): in references/guided/btmon/appmode/1 the head unit, right after auth,
searched our av1/av2 SDP records AND our PnP/Device-ID record — for which BlueZ returns its default
`0x1d6b` (Linux Foundation) vendor — and then declined to open the AppMode data channel. A real iPhone
reports Apple's vendor `0x05AC`. This sets the adapter's Device ID to Apple so the head unit sees an
Apple-looking phone.

CAVEAT: this is a *best-effort* experiment. Firmware RE did NOT confirm that the AppMode connection is
gated on the Device ID (the vendor/product read we found feeds the Siri/SmartPhoneVR module, not the
AvSpp connect decision). Run it, but treat a change in behavior as the real evidence.

Mechanism: the BlueZ management (mgmt) API command MGMT_OP_SET_DEVICE_ID (0x0041) — the correct,
version-independent way to set the adapter DID from userspace. Run as root, with bluetoothd running,
BEFORE (or alongside) btsdp_iap_guided.py. It persists until the adapter/bluetoothd resets.

Usage:
    sudo ./set_apple_did.py                 # Apple vendor 0x05AC, iPhone product 0x12A8
    sudo ./set_apple_did.py --index 0 --product 0x12a8 --version 0x0100
    sudo ./set_apple_did.py --off           # clear the custom DID (source 0)

Verify afterwards (should show vendor 05ac):
    sdptool browse local | grep -iA3 'PnP'      # if sdptool present
    # or re-run capture.sh and check the PnP Information response in the .txt
"""

import argparse
import socket
import struct
import sys

# BlueZ mgmt constants
BTPROTO_HCI = 1
HCI_DEV_NONE = 0xFFFF
HCI_CHANNEL_CONTROL = 3
MGMT_OP_SET_DEVICE_ID = 0x0041
MGMT_EV_CMD_COMPLETE = 0x0001
MGMT_EV_CMD_STATUS = 0x0002

# Device ID source values (SDP DID VendorIDSource, attr 0x0205)
SRC_BT_SIG = 0x0001
SRC_USB_IF = 0x0002        # Apple/most phones report their USB-IF vendor ID here

APPLE_VENDOR = 0x05AC
DEFAULT_PRODUCT = 0x12A8   # a common iPhone USB product ID
DEFAULT_VERSION = 0x0100


def _hexint(s):
    return int(s, 0)


def set_device_id(index, source, vendor, product, version):
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
    try:
        sock.bind((HCI_DEV_NONE, HCI_CHANNEL_CONTROL))
    except OSError as e:
        sock.close()
        raise SystemExit(f"failed to bind mgmt control socket ({e}); run as root with bluetoothd up")

    params = struct.pack("<HHHH", source, vendor, product, version)
    pkt = struct.pack("<HHH", MGMT_OP_SET_DEVICE_ID, index, len(params)) + params
    sock.send(pkt)
    sock.settimeout(3.0)
    try:
        resp = sock.recv(1024)
    except socket.timeout:
        sock.close()
        raise SystemExit("no mgmt response (timeout) — is the adapter index correct?")
    sock.close()

    ev_op, ev_index, ev_len = struct.unpack_from("<HHH", resp, 0)
    body = resp[6:6 + ev_len]
    if ev_op == MGMT_EV_CMD_COMPLETE and len(body) >= 3:
        cmd_op, status = struct.unpack_from("<HB", body, 0)
        return status
    if ev_op == MGMT_EV_CMD_STATUS and len(body) >= 3:
        cmd_op, status = struct.unpack_from("<HB", body, 0)
        return status
    return -1


def main():
    p = argparse.ArgumentParser(description="Set the Pi's Bluetooth Device ID to Apple (best-effort)")
    p.add_argument("--index", type=int, default=0, help="HCI adapter index (default 0 = hci0)")
    p.add_argument("--source", type=_hexint, default=SRC_USB_IF, help="vendor ID source (default 0x0002 USB-IF)")
    p.add_argument("--vendor", type=_hexint, default=APPLE_VENDOR, help="vendor ID (default 0x05AC Apple)")
    p.add_argument("--product", type=_hexint, default=DEFAULT_PRODUCT, help="product ID (default 0x12A8)")
    p.add_argument("--version", type=_hexint, default=DEFAULT_VERSION, help="version (default 0x0100)")
    p.add_argument("--off", action="store_true", help="clear the DID (source=0)")
    args = p.parse_args()

    if not hasattr(socket, "AF_BLUETOOTH"):
        raise SystemExit("this Python build has no AF_BLUETOOTH support")

    if args.off:
        source, vendor, product, version = 0, 0, 0, 0
    else:
        source, vendor, product, version = args.source, args.vendor, args.product, args.version

    status = set_device_id(args.index, source, vendor, product, version)
    if status == 0:
        if args.off:
            print(f"[set_apple_did] cleared Device ID on hci{args.index}")
        else:
            print(f"[set_apple_did] hci{args.index} Device ID set: "
                  f"source=0x{source:04x} vendor=0x{vendor:04x} product=0x{product:04x} "
                  f"version=0x{version:04x}")
        print("  verify:  sdptool browse local | grep -iA3 PnP   (or re-capture and check PnP response)")
        return 0
    print(f"[set_apple_did] mgmt SET_DEVICE_ID failed, status=0x{status:02x} "
          f"(0x0c=not powered? 0x11=invalid index?)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
