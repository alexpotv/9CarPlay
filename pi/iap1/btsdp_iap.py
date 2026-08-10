#!/usr/bin/env python3
"""btsdp_iap — hosts the SDP service record + RFCOMM listener for the "second," Bluetooth-carried
iAP1 session identified in references/cr-v/iap.md, "A real iAP-over-Bluetooth transport exists."

Why this exists: a live btmon capture (iap.md, "Confirmed by live btmon capture (2026-08-10)")
showed the head unit performing an unconditional SDP Service Search Attribute Request for Apple's
real, public iAP-over-Bluetooth UUID right after HFP connects — as part of its normal profile sweep,
not gated behind any UI navigation — and getting back an empty response because nothing on the Pi
registered that UUID yet. This script closes that gap: it registers a BlueZ D-Bus profile for the
UUID the head unit was observed searching for, so a repeat capture can show what happens once the
search actually resolves to something (does the head unit follow up with an RFCOMM connection? does
it then speak classic iAP1 framing over that channel?).

CONFIDENCE NOTE — the UUID's last byte: the live capture decoded the raw 16 bytes as
00000000-deca-fade-deca-deafdecacafe (ends 0xFE). An earlier raw-byte search directly against
Communication.exe's binary found 0xFF instead (...caff). The live capture is trusted here since it
reflects exactly what the head unit's Bluetooth stack put on the wire — see iap.md for the full
discussion of the discrepancy.

This registers ONLY the custom UUID as the primary service class (matching exactly what the capture
showed being searched for) — not also the standard SPP UUID (0x1101) as a secondary class, since
that wasn't confirmed necessary and BlueZ's simple RegisterProfile(UUID=...) call doesn't support
a multi-class ServiceClassIDList without hand-building a raw SDP XML record. If a repeat capture
shows the head unit's search or connection attempt failing/differing because of this, that's the
next thing to adjust.

On an incoming RFCOMM connection, bytes are fed into the exact same iAP1 packet parser already
built and tested for the USB path (iap1_daemon.py's try_parse_packet/build_packet/REQUEST_HANDLERS)
— the wire format is presumed identical regardless of transport (both ultimately go through
Communication.exe's iPod_Initialize(iAPType=1, ...) on the head unit side). Writes back to the
RFCOMM socket the same way iap1_daemon.py writes to the USB bulk IN endpoint (os.write on the raw
fd) — sockets support the write() syscall on Linux, so no separate send-path code is needed.

Run ALONGSIDE (not instead of) hfp_ag.py — both are separate BlueZ D-Bus profiles on the same
adapter; HFP remains the confirmed precondition (iap.md, "Bluetooth gating confirmed by
decompilation") for anything here to matter.

Prerequisites (same as hfp_ag.py):
    sudo apt install -y python3-dbus python3-gi bluez

Usage, on the Pi, as root, after setup_bt_phone.sh and alongside hfp_ag.py:
    sudo python3 btsdp_iap.py
"""

import os
import socket
import sys
import threading

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

import iap1_daemon
from iap1_daemon import State, process_rx
from markers import session_suffix

# NEventWatcher.exe's own outgoing iAP1-over-Bluetooth packet builder (decompiled 2026-08-10,
# FUN_0001f714 — see iap1_daemon.py's OUTGOING_SYNC_MODE docstring) writes only a bare 0x55 sync
# byte, never 0xFF 0x55. Every response_*() builder in iap1_daemon.py goes through build_packet(),
# which honors this module-level flag — set it here, once, so every reply this process sends over
# RFCOMM uses the firmware-confirmed framing without each response builder needing to know it's
# running under Bluetooth specifically. iap1_daemon.py's own USB-side main() leaves the default
# ("full") alone, since there's no equivalent firmware evidence for the USB transport yet.
iap1_daemon.OUTGOING_SYNC_MODE = "short"

BUS_NAME = "org.bluez"
PROFILE_MANAGER_PATH = "/org/bluez"
PROFILE_DBUS_PATH = "/9carplay/iap_bt"

# See module docstring — live-capture-confirmed value, last byte differs from the earlier
# static-analysis read (...caff).
IAP_BT_UUID = "00000000-deca-fade-deca-deafdecacafe"

# Deliberately different from hfp_ag.py's Channel=1 so both profiles can be registered
# simultaneously on the same adapter without any ambiguity about which RFCOMM channel is which.
RFCOMM_CHANNEL = 2


def rfcomm_session(fd, device):
    sock = socket.fromfd(fd, socket.AF_BLUETOOTH, socket.SOCK_STREAM)
    sock.setblocking(True)
    print(f"[btsdp-iap] RFCOMM session started from {device}")

    # Fresh State (and thus fresh, timestamped, per-session capture files) per connection — same
    # shape as iap1_daemon.py's, just pointed at BT-specific filenames so a live trial's USB and
    # Bluetooth captures never collide, and so repeated connections within one trial don't mix
    # (see iap1_daemon.py's main() for the static-filename bug this pattern avoids).
    suffix = session_suffix()
    capture_path = f"iap1_bt_capture_{suffix}.bin"
    unclassified_path = f"iap1_bt_unclassified_{suffix}.bin"
    print(f"[btsdp-iap] Session suffix: {suffix} "
          f"(run markers.py {suffix} alongside this for correlation)")
    state = State(capture_path, unclassified_path)
    ep_in_fd = sock.fileno()  # os.write() works on a real socket fd exactly like a bulk-IN fd.

    try:
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError as e:
                print(f"[btsdp-iap] recv error: {e}")
                break
            if not chunk:
                break
            state.rx_buf += chunk
            process_rx(state, ep_in_fd)
    finally:
        state.capture_fp.close()
        state.unclassified_fp.close()
        print(f"[btsdp-iap] RFCOMM session with {device} ended")
        sock.close()


class IapBtProfile(dbus.service.Object):
    @dbus.service.method("org.bluez.Profile1", in_signature="", out_signature="")
    def Release(self):
        print("[btsdp-iap] Release()")

    @dbus.service.method("org.bluez.Profile1", in_signature="oha{sv}", out_signature="")
    def NewConnection(self, device, fd, properties):
        print(f"[btsdp-iap] NewConnection from {device} (properties={properties})")
        real_fd = fd.take()
        threading.Thread(target=rfcomm_session, args=(real_fd, device), daemon=True).start()

    @dbus.service.method("org.bluez.Profile1", in_signature="o", out_signature="")
    def RequestDisconnection(self, device):
        print(f"[btsdp-iap] RequestDisconnection from {device}")


def main():
    if os.geteuid() != 0:
        print("Must run as root", file=sys.stderr)
        sys.exit(1)

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    profile = IapBtProfile(bus, PROFILE_DBUS_PATH)
    manager = dbus.Interface(
        bus.get_object(BUS_NAME, PROFILE_MANAGER_PATH), "org.bluez.ProfileManager1"
    )
    opts = {
        "Name": "9CarPlay iAP1 Bluetooth Link",
        "RequireAuthentication": dbus.Boolean(False),
        "RequireAuthorization": dbus.Boolean(False),
        "AutoConnect": dbus.Boolean(True),
        "Channel": dbus.UInt16(RFCOMM_CHANNEL),
    }
    manager.RegisterProfile(PROFILE_DBUS_PATH, IAP_BT_UUID, opts)
    print(f"[btsdp-iap] Registered iAP-over-Bluetooth profile (UUID={IAP_BT_UUID}, "
          f"RFCOMM channel={RFCOMM_CHANNEL})")
    print("[btsdp-iap] Capture/unclassified files are created per-RFCOMM-session as "
          "iap1_bt_{capture,unclassified}_<suffix>.bin (see rfcomm_session()).")
    print("[btsdp-iap] Waiting for the head unit's SDP search to resolve and an RFCOMM "
          "connection to follow. Run a fresh btmon capture alongside this (see "
          "BTMON_ANALYSIS.md) to confirm.")

    try:
        GLib.MainLoop().run()
    except KeyboardInterrupt:
        manager.UnregisterProfile(PROFILE_DBUS_PATH)
        sys.exit(0)


if __name__ == "__main__":
    if not hasattr(socket, "AF_BLUETOOTH"):
        print("This Python build has no socket.AF_BLUETOOTH support — "
              "install bluez/libbluetooth-dev and use the system python3.",
              file=sys.stderr)
        sys.exit(1)
    main()
