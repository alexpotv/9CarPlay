#!/bin/bash
# Phase B (partial) — adds a real Bluetooth profile (A2DP sink) on top of
# Phase A's plain pairing (setup_bt.sh), and makes the Class-of-Device
# setting persistent across bluetoothd restarts.
#
# Why: Phase A pairing bonds successfully but offers no profile the head
# unit can actually open a session with (no A2DP, no HFP) — this produces
# repeated connect/disconnect flapping (org.bluez.Error.Failed
# br-connection-profile-unavailable) and the Pi shows in the car's device
# list with no phone/music icon, because there's no capability to hang an
# icon off. A2DP sink is much cheaper to stand up than full Hands-Free
# Profile and should be enough to get a stable Connected: yes + an icon,
# which lets us test whether ANY real profile connection changes the
# USB/AOA discovery behavior before committing to the heavier HFP-AG stack
# (see README.md "Phase B" for that).
#
# Also fixes: `btmgmt class` (used in setup_bt.sh) is runtime-only —
# bluetoothd can silently reset the adapter's class on its own
# init/power-cycle, which is why the icon never appeared even after running
# setup_bt.sh. This script sets Class= in /etc/bluetooth/main.conf instead,
# which bluetoothd itself applies and keeps across restarts.
#
# Run as root on the Raspberry Pi. Run setup_bt.sh first if you haven't.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

apt-get install -y pulseaudio pulseaudio-module-bluetooth

MAIN_CONF="/etc/bluetooth/main.conf"

# 0x5A020C: a commonly-observed Android smartphone Class of Device value
# (major=Phone, minor=Smartphone, service class bits for Audio/Networking/
# Object Transfer/Capturing set) — closer to what a real phone advertises
# than the bare major/minor pair setup_bt.sh set at runtime.
if grep -q '^Class *=' "$MAIN_CONF" 2>/dev/null; then
    sed -i 's/^Class *=.*/Class = 0x5A020C/' "$MAIN_CONF"
else
    if grep -q '^\[General\]' "$MAIN_CONF" 2>/dev/null; then
        sed -i '/^\[General\]/a Class = 0x5A020C' "$MAIN_CONF"
    else
        printf '\n[General]\nClass = 0x5A020C\n' >> "$MAIN_CONF"
    fi
fi

systemctl restart bluetooth
rfkill unblock bluetooth
btmgmt power on
btmgmt pairable on
btmgmt discoverable on

echo
echo "Class of Device set persistently to 0x5A020C (Phone/Smartphone) in"
echo "$MAIN_CONF, and pulseaudio-module-bluetooth installed for A2DP sink"
echo "support."
echo
echo "Next: on the Pi, run 'pulseaudio --start' if it isn't already running"
echo "(as your normal user, not root — PulseAudio refuses to run as root by"
echo "default), THEN re-pair from scratch:"
echo
echo "  bluetoothctl"
echo "  remove <car-MAC>      # clear the old flapping bond first"
echo "  scan on"
echo "  pair <car-MAC>"
echo "  trust <car-MAC>"
echo "  connect <car-MAC>"
echo
echo "Check the car's device list for a music-note icon and a stable"
echo "Connected: yes this time before moving on to the USB/AOA test."
