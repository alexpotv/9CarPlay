#!/usr/bin/env python3
"""Phase B — minimal Hands-Free Profile Audio Gateway (HFP AG), the role a
real phone plays when a car's head unit acts as the Hands-Free (HF) unit.

Why this exists: BlueZ's built-in bluetoothd only ships the HF (car/headset)
role internally (see the "handsfree" plugin) — there is no built-in AG
(phone) role, which is exactly why Phase A's plain pairing + A2DP got a
stable Bluetooth connection but never satisfied whatever the head unit's
MirrorLink UI service (UIMirrorLink_BTManager, per strings_out.txt) checks
before treating a paired device as an actual phone. This script registers a
custom BlueZ D-Bus profile for the Handsfree Audio Gateway service class
(UUID 0000111f-0000-1000-8000-00805f9b34fb) and implements just enough of
the AT command exchange to complete a Service Level Connection (SLC) — NOT a
full telephony stack. The goal is only to see whether the head unit then
treats the Pi as a real phone (stable HFP connection, phone icon) and
whether THAT, in turn, unlocks anything on the USB/AOA side.

Every AT command received is printed — this is valuable diagnostic data on
its own (it tells us exactly what the head unit's HF client asks for) even
if the MirrorLink correlation theory turns out to be wrong.

Prerequisites (install once):
    sudo apt install -y python3-dbus python3-gi bluez

Run as root (needs to register a system D-Bus profile object and bind an
RFCOMM channel), alongside — not instead of — bluetoothd already running
normally (do not stop bluetoothd; this just adds a profile to it):
    sudo python3 hfp_ag.py

Then pair/connect from the Pi exactly as in Phase A (bluetoothctl scan/pair/
trust/connect against the car's MAC) — this script's profile takes over the
HFP AG role automatically once BlueZ knows the car opened an RFCOMM
connection for that service class. Watch this script's console for the AT
command exchange, and the car's screen for a phone icon / stable connection.
"""

import socket
import sys
import threading

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

BUS_NAME = "org.bluez"
PROFILE_MANAGER_PATH = "/org/bluez"
PROFILE_DBUS_PATH = "/9carplay/hfp_ag"
HFP_AG_UUID = "0000111f-0000-1000-8000-00805f9b34fb"

# Static indicator states we report to AT+CIND? — enough for an HF client to
# consider the "phone" idle/ready, not a real telephony state machine.
# Order must match the (name, range) list we report to AT+CIND=?.
CIND_ORDER = ["service", "call", "callsetup", "callheld", "signal", "roam", "battchg"]
CIND_VALUES = {
    "service": 1,   # network available
    "call": 0,      # no active call
    "callsetup": 0, # no call setup in progress
    "callheld": 0,  # no held call
    "signal": 5,    # arbitrary signal strength
    "roam": 0,      # not roaming
    "battchg": 5,   # arbitrary battery level
}


def handle_at_command(line, sock):
    line = line.strip()
    if not line:
        return
    print(f"[hfp-ag] <- {line!r}")

    def reply(text):
        msg = f"\r\n{text}\r\n"
        sock.sendall(msg.encode("ascii", errors="replace"))
        print(f"[hfp-ag] -> {text!r}")

    upper = line.upper()

    if upper.startswith("AT+BRSF"):
        # Report minimal AG features (0 = none of the optional ones) — just
        # enough for the HF side to proceed past feature negotiation.
        reply("+BRSF: 0")
        reply("OK")
    elif upper.startswith("AT+CIND=?"):
        parts = ",".join(
            f'("{name}",(0-{1 if name in ("service", "call", "callsetup", "callheld", "roam") else (5 if name == "battchg" else 5)}))'
            for name in CIND_ORDER
        )
        reply(f"+CIND: {parts}")
        reply("OK")
    elif upper.startswith("AT+CIND?"):
        vals = ",".join(str(CIND_VALUES[name]) for name in CIND_ORDER)
        reply(f"+CIND: {vals}")
        reply("OK")
    elif upper.startswith("AT+CMER"):
        reply("OK")
    elif upper.startswith("AT+CHLD=?"):
        reply("+CHLD: (0,1,2,3)")
        reply("OK")
    elif upper.startswith("AT+CLIP") or upper.startswith("AT+CCWA") or upper.startswith("AT+CMEE"):
        reply("OK")
    elif upper.startswith("AT+VGS") or upper.startswith("AT+VGM"):
        reply("OK")
    else:
        # Best-effort: acknowledge anything we don't explicitly handle so
        # the HF side's SLC establishment isn't blocked on an unrecognized
        # command. Not spec-correct, but sufficient for probing this.
        reply("OK")


def rfcomm_session(fd):
    sock = socket.fromfd(fd, socket.AF_BLUETOOTH, socket.SOCK_STREAM)
    # The fd BlueZ hands us via NewConnection is non-blocking; fromfd()
    # doesn't clear that, so a blocking-style recv() below would otherwise
    # raise EAGAIN immediately instead of waiting for the head unit's first
    # AT command.
    sock.setblocking(True)
    print("[hfp-ag] RFCOMM session started")
    buf = b""
    try:
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
            while b"\r" in buf:
                line, buf = buf.split(b"\r", 1)
                try:
                    handle_at_command(line.decode("ascii", errors="replace"), sock)
                except (BrokenPipeError, OSError) as e:
                    print(f"[hfp-ag] write failed: {e}")
                    return
    except OSError as e:
        print(f"[hfp-ag] session read error: {e}")
    finally:
        print("[hfp-ag] RFCOMM session ended")
        sock.close()


class HfpAgProfile(dbus.service.Object):
    @dbus.service.method("org.bluez.Profile1", in_signature="", out_signature="")
    def Release(self):
        print("[hfp-ag] Release()")

    @dbus.service.method("org.bluez.Profile1", in_signature="oha{sv}", out_signature="")
    def NewConnection(self, device, fd, properties):
        print(f"[hfp-ag] NewConnection from {device}")
        real_fd = fd.take()
        threading.Thread(target=rfcomm_session, args=(real_fd,), daemon=True).start()

    @dbus.service.method("org.bluez.Profile1", in_signature="o", out_signature="")
    def RequestDisconnection(self, device):
        print(f"[hfp-ag] RequestDisconnection from {device}")


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    profile = HfpAgProfile(bus, PROFILE_DBUS_PATH)
    manager = dbus.Interface(
        bus.get_object(BUS_NAME, PROFILE_MANAGER_PATH), "org.bluez.ProfileManager1"
    )
    opts = {
        "Name": "Hands-Free Audio Gateway",
        "RequireAuthentication": dbus.Boolean(False),
        "RequireAuthorization": dbus.Boolean(False),
        "AutoConnect": dbus.Boolean(True),
        "Channel": dbus.UInt16(1),
    }
    manager.RegisterProfile(PROFILE_DBUS_PATH, HFP_AG_UUID, opts)
    print(f"[hfp-ag] Registered Handsfree Audio Gateway profile ({HFP_AG_UUID})")
    print("[hfp-ag] Waiting for the head unit to connect...")

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
