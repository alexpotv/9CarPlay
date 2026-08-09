#!/bin/bash
# Configures the Pi's onboard Bluetooth radio as a phone-class device and gets it ready to accept
# an HFP (Hands-Free Profile) connection from the head unit — a confirmed PRECONDITION for the
# legacy iAP1 HondaLink path, not just a guess. See references/cr-v/iap.md, "Bluetooth gating
# confirmed by decompilation" for the full decompiled evidence: Communication.exe's
# `[LPAApp][Help]::isIPhoneConnected` (FUN_000ca890) will not return true unless a Bluetooth HFP
# connection flag is set (fed from `NBTManagerHandler` in NEventWatcher.exe via a
# BluetoothStatusEvent carrying a non-zero, "connected" AccessoryMacAddress), ANDed with the USB
# iAP session being active — or, on the fallback path, unless the currently-connected BT device's
# address matches one already on file.
#
# This script only gets the adapter into the right class/discoverable state (same technique as
# pi/bluetooth-test/setup_bt.sh + setup_bt_a2dp.sh, consolidated here for the iap1 test flow).
# It does NOT implement HFP itself — BlueZ's bluetoothd only ships the HF (car-side) role, not the
# AG (phone-side) role we need. For that, run pi/bluetooth-test/hfp_ag.py (already built, directly
# reusable — see "Next steps" printed below).
#
# Run as root on the Raspberry Pi.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

command -v bluetoothctl >/dev/null || {
    echo "bluez not installed — run: sudo apt install -y bluez bluez-tools" >&2
    exit 1
}

systemctl enable --now bluetooth
rfkill unblock bluetooth

MAIN_CONF="/etc/bluetooth/main.conf"

# 0x5A020C: major=Phone, minor=Smartphone, with Audio/Networking/Object Transfer/Capturing
# service-class bits set — same value pi/bluetooth-test/setup_bt_a2dp.sh uses, closer to what a
# real phone advertises than a bare major/minor pair. Written to main.conf (not just `btmgmt
# class`) because bluetoothd resets the runtime class on its own restarts otherwise — confirmed
# directly during the earlier pi/bluetooth-test/ trials (see that README's "Phase A" step 4).
if grep -q '^Class *=' "$MAIN_CONF" 2>/dev/null; then
    sed -i 's/^Class *=.*/Class = 0x5A020C/' "$MAIN_CONF"
elif grep -q '^\[General\]' "$MAIN_CONF" 2>/dev/null; then
    sed -i '/^\[General\]/a Class = 0x5A020C' "$MAIN_CONF"
else
    printf '\n[General]\nClass = 0x5A020C\n' >> "$MAIN_CONF"
fi

btmgmt name "9CarPlay iAP1 Phone"
systemctl restart bluetooth
rfkill unblock bluetooth
btmgmt power on
btmgmt pairable on
# Modern btmgmt renamed the "discoverable" command to "discov" (it also takes a required
# yes/no/limited argument plus an optional timeout in seconds — 0 means "no timeout", i.e. stay
# discoverable indefinitely instead of BlueZ's usual ~180s window, which matters here since the
# head unit's own pairing menu needs time to be reached and used manually). The old
# `btmgmt discoverable on` form used in earlier scripts in this repo (pi/bluetooth-test/) errors
# with "Invalid command in menu mgmt: discoverable" on current BlueZ — confirmed on real hardware.
btmgmt discov yes 0

echo
echo "Bluetooth adapter is phone-class (0x5A020C), discoverable, and pairable as"
echo "'9CarPlay iAP1 Phone'."
echo
echo "IMPORTANT — ordering matters (see iap.md): the head unit's own"
echo "isIPhoneConnected() check requires a genuine, STABLE HFP connection to exist"
echo "before (or at least concurrently with) the USB iAP1 session, not just a bonded"
echo "pairing. Next steps, in order:"
echo
echo "  1. Start the HFP Audio Gateway daemon (reused from pi/bluetooth-test/ — BlueZ"
echo "     has no built-in AG/phone role, only HF/car role):"
echo "       sudo python3 ../bluetooth-test/hfp_ag.py"
echo
echo "  2. Pair from the HEAD UNIT's own Bluetooth 'add device' menu (not from the"
echo "     Pi) — this is also how the head unit learns/records this Pi's BD address"
echo "     as 'the accessory' (see iap.md: OnBluetoothStatusEvent logs"
echo "     'AccessoryMacAddress Non' if the head unit doesn't yet have one on file"
echo "     for the connecting device). Confirm/enter any passkey via 'bluetoothctl'"
echo "     here if prompted."
echo
echo "  3. Confirm a STABLE HFP connection (not just 'Paired: yes' — watch for the"
echo "     phone icon and a Service Level Connection in hfp_ag.py's console, not"
echo "     connect/disconnect flapping) before starting or continuing the USB iap1_daemon.py"
echo "     test. If it flaps, remove/re-pair from scratch — see"
echo "     pi/bluetooth-test/README.md 'Phase A' step 3 for the known failure mode."
echo
echo "  4. Only then bind/cycle the USB gadget (setup_gadget.sh / cycle_usb.sh) and watch"
echo "     for whatever changes on the head unit's own screen with BT connected that"
echo "     didn't happen when it wasn't."
