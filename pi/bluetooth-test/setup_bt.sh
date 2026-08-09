#!/bin/bash
# Configures the Pi's onboard Bluetooth radio to look like a phone during
# pairing, and makes it discoverable/pairable — for testing whether the head
# unit's MirrorLink USB/AOA discovery is gated on first seeing the connecting
# device over Bluetooth (see references/cr-v/strings_out.txt: the MirrorLink
# connection-start XML includes a <bdAddr> field, and there's a dedicated
# UIMirrorLink_BTManager.cpp in the firmware's MirrorLink UI service).
#
# This does NOT implement Hands-Free Profile (HFP) — it only sets the
# Bluetooth Class of Device to "Phone / Smartphone" and makes the adapter
# discoverable/pairable using BlueZ's stock SDP records. If the head unit
# requires actual HFP capability to accept a device as a "phone" before
# offering MirrorLink, this alone won't be enough — see bluetooth-test/README.md
# "Phase B" for that fallback.
#
# Run as root on the Raspberry Pi.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

command -v bluetoothctl >/dev/null || { echo "bluez not installed — run: sudo apt install -y bluez bluez-tools" >&2; exit 1; }

systemctl enable --now bluetooth
rfkill unblock bluetooth

# Major device class 0x02 = Phone, minor class 0x03 = Smartphone
# (Bluetooth SIG "Baseband assigned numbers" — Major/Minor Device Class).
# This is what shows up as the device "type" in the head unit's pairing UI
# and is a reasonable first guess for whatever UIMirrorLink_BTManager checks
# before considering a paired device phone-like.
btmgmt class 0x02 0x03

btmgmt name "9CarPlay AOA Bridge"
btmgmt power on
btmgmt pairable on
# Modern btmgmt renamed "discoverable" to "discov" (yes/no/limited + optional timeout in seconds,
# 0 = no timeout) — the old form here errored with "Invalid command in menu mgmt: discoverable" on
# current BlueZ, confirmed on real hardware. See pi/iap1/setup_bt_phone.sh for the same fix.
btmgmt discov yes 0

echo
echo "Bluetooth adapter is now discoverable and pairable as a Phone-class"
echo "device named '9CarPlay AOA Bridge'."
echo
echo "Next: initiate pairing from the HEAD UNIT's Bluetooth 'add device' menu"
echo "(not from the Pi) so it appears in the car's scan. When the car prompts"
echo "for a passkey/confirmation, run 'bluetoothctl' here in a second shell"
echo "to confirm/enter it interactively — see README.md for the exact flow."
