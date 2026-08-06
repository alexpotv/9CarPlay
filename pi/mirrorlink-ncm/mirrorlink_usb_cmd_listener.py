#!/usr/bin/env python3
"""Watches a FunctionFS control-only interface (ffs.mlctrl, set up alongside the kernel ncm.usb0
function by setup_ncm_gadget.sh) for the "MirrorLink USB command" defined in ETSI TS 103 544-1,
clause 4.2.2 — a USB control transfer the head unit sends to the device:

    bmRequestType = 0x40   (host-to-device, vendor, device recipient)
    bRequest      = 0xF0
    wValue        = MirrorLink version (low byte = major, high byte = minor)
    wIndex        = USB host vendor ID
    wLength       = 0

Per spec: "USB devices, not supporting MirrorLink USB command, will return STALL PID... If the
MirrorLink Server is not able to switch to USB CDC/NCM functionality in response to the MirrorLink
USB command, the USB device shall respond with a STALL PID." A bare usb_f_ncm-only gadget has
nothing registered to claim this vendor request, so the kernel composite framework auto-STALLs it
— which, per the same spec, is exactly the condition the head unit's own client-side logic checks
to determine "is this an operating MirrorLink Server" (clause 4.2.3, condition 1: "The MirrorLink
USB command does not return with STALL PID"). This script exists purely to not-stall that one
request (and log it, plus anything else that arrives on this interface, for visibility) —
everything else (the actual CDC-NCM data path, SSDP, DHCP, HTTP/SOAP) is unaffected and keeps
running exactly as before via ncm.usb0 and ssdp_announce.py.

MUST be started BEFORE the gadget's UDC is bound (FunctionFS requires descriptors to be written
to ep0 first) — see setup_ncm_gadget.sh's printed instructions. Once running, bind the UDC (e.g.
via cycle_usb.sh) in a separate shell; this listener stays running throughout and across cycles.

Usage:
    sudo python3 mirrorlink_usb_cmd_listener.py /dev/ffs-mlctrl
"""

import os
import struct
import sys

FUNCTIONFS_DESCRIPTORS_MAGIC_V2 = 3
FUNCTIONFS_STRINGS_MAGIC = 2

FUNCTIONFS_HAS_FS_DESC = 1
FUNCTIONFS_HAS_HS_DESC = 2
FUNCTIONFS_ALL_CTRL_RECIP = 0x40  # forward ALL control requests (any recipient), not just ours

USB_DT_INTERFACE = 4

EVENT_NAMES = ["BIND", "UNBIND", "ENABLE", "DISABLE", "SETUP", "SUSPEND", "RESUME"]
FUNCTIONFS_SETUP = 4

MIRRORLINK_USB_COMMAND_BREQUEST = 0xF0
BMREQUESTTYPE_HOST_TO_DEVICE_VENDOR_DEVICE = 0x40


def build_interface_descriptor():
    # bLength, bDescriptorType, bInterfaceNumber, bAlternateSetting, bNumEndpoints,
    # bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol, iInterface
    return struct.pack("<BBBBBBBBB", 9, USB_DT_INTERFACE, 0, 0, 0, 0xFF, 0xFF, 0xFF, 1)


def build_descriptors():
    intf = build_interface_descriptor()
    flags = FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC | FUNCTIONFS_ALL_CTRL_RECIP
    body = struct.pack("<II", 1, 1) + intf + intf  # fs_count=1, hs_count=1, same descriptor both
    HEADER_LEN = 12  # magic(u32) + length(u32) + flags(u32)
    header = struct.pack("<III", FUNCTIONFS_DESCRIPTORS_MAGIC_V2, HEADER_LEN + len(body), flags)
    return header + body


def build_strings():
    name = b"MirrorLink Control\x00"
    body = struct.pack("<H", 0x0409) + name  # lang code + NUL-terminated string
    HEADER_LEN = 16  # magic(u32) + length(u32) + str_count(u32) + lang_count(u32)
    header = struct.pack("<IIII", FUNCTIONFS_STRINGS_MAGIC, HEADER_LEN + len(body), 1, 1)
    return header + body


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <functionfs-mountpoint>", file=sys.stderr)
        sys.exit(1)
    mount = sys.argv[1]
    ep0_path = os.path.join(mount, "ep0")

    if os.geteuid() != 0:
        print("Must run as root", file=sys.stderr)
        sys.exit(1)

    ep0 = os.open(ep0_path, os.O_RDWR)

    descs = build_descriptors()
    n = os.write(ep0, descs)
    print(f"[mlctrl] wrote {n} bytes of descriptors to ep0")

    strs = build_strings()
    n = os.write(ep0, strs)
    print(f"[mlctrl] wrote {n} bytes of strings to ep0")

    print("[mlctrl] watching ep0 for events (BIND/ENABLE/SETUP/...) — now bind the UDC "
          "(e.g. sudo ./cycle_usb.sh) in another shell.")

    while True:
        data = os.read(ep0, 12 * 8)
        if not data:
            print("[mlctrl] ep0 closed, exiting")
            break
        for i in range(0, len(data) - 11, 12):
            raw = data[i:i + 8]
            ev_type = data[i + 8]
            name = EVENT_NAMES[ev_type] if ev_type < len(EVENT_NAMES) else f"?{ev_type}"
            if ev_type == FUNCTIONFS_SETUP:
                breq_type, brequest, wvalue, windex, wlength = struct.unpack("<BBHHH", raw)
                print(f"[mlctrl] SETUP bRequestType=0x{breq_type:02x} bRequest=0x{brequest:02x} "
                      f"wValue=0x{wvalue:04x} wIndex=0x{windex:04x} wLength={wlength}")
                if (breq_type == BMREQUESTTYPE_HOST_TO_DEVICE_VENDOR_DEVICE
                        and brequest == MIRRORLINK_USB_COMMAND_BREQUEST):
                    major = wvalue & 0xFF
                    minor = (wvalue >> 8) & 0xFF
                    print(f"[mlctrl] *** MirrorLink USB command received *** "
                          f"requested version {major}.{minor}, host vendorID=0x{windex:04x} "
                          f"-> acknowledging (not stalling)")
                    # Host-to-device, wLength=0: nothing to read/write for the (empty) data
                    # stage — simply not stalling this request (returning without calling any
                    # halt/stall ioctl) completes the status stage successfully. Matches the
                    # AOA_START handling pattern in pi/aoa-gadget/aoa_gadget_twostage.c.
                elif wlength > 0 and not (breq_type & 0x80):
                    # Host-to-device with a data stage we don't recognize — drain it so the
                    # transfer completes cleanly instead of stalling on unread data.
                    try:
                        os.read(ep0, wlength)
                    except OSError:
                        pass
            else:
                print(f"[mlctrl] event: {name}")


if __name__ == "__main__":
    main()
