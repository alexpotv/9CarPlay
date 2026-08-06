#!/bin/bash
# Sets up a USB CDC-NCM (Ethernet-over-USB) gadget via configfs — the bearer the real MirrorLink
# spec (ETSI TS 103 544) actually describes, superseding the AOA approach in pi/aoa-gadget/ which
# tested negative against real head units (see references/cr-v/PROTOCOL_ANALYSIS.md, "Update —
# live AOA testing was negative..."). Unlike the AOA gadget, this uses Linux's built-in usb_f_ncm
# kernel gadget function — no custom userspace daemon needed for the USB side itself.
#
# UNTESTED ON REAL HARDWARE — this is a first scaffold, not a validated implementation. In
# particular the assigned IP addresses below are a reasonable guess (matching the
# 192.168.42.0/24 / 169.254.x.x address strings found in vncdiscoverer-usb.dll's strings, which
# suggests this range is at least plausible) but not confirmed against the actual head unit.
#
# Run as root on the Raspberry Pi. Requires the same one-time dwc2 peripheral-mode setup as
# pi/aoa-gadget/ (see pi/step-1-commands.md step 0) — this cannot coexist with the AOA gadget at
# the same time, since both bind the same UDC. Tear down the AOA gadget first if it's running
# (pi/aoa-gadget/README.md "clean restart" section).

set -euo pipefail

GADGET_NAME="ncm0"
GADGET_DIR="/sys/kernel/config/usb_gadget/${GADGET_NAME}"
IFNAME="usb0"
PI_IP="192.168.42.1"
PI_NETMASK="24"

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

modprobe libcomposite

mkdir -p "$GADGET_DIR"
cd "$GADGET_DIR"

# Generic placeholder identity — real MirrorLink phones present their own vendor identity here;
# we don't yet know if the head unit cares about VID/PID for the NCM path the way it apparently
# does for AAP, so this is not tuned to anything specific yet.
echo 0x1d6b > idVendor
echo 0x0104 > idProduct
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB

mkdir -p strings/0x409
echo "0123456789abcdef" > strings/0x409/serialnumber
echo "9CarPlay Project" > strings/0x409/manufacturer
echo "MirrorLink NCM Bridge (dev)" > strings/0x409/product

mkdir -p configs/c.1/strings/0x409
echo "MirrorLink NCM config" > configs/c.1/strings/0x409/configuration
echo 120 > configs/c.1/MaxPower

mkdir -p "functions/ncm.usb0"
# Locally-administered MAC addresses (bit 1 of first byte set) for both ends of the virtual
# Ethernet link — dev_addr is the Pi's (gadget) side, host_addr is what the Pi tells the head unit
# its own (host-side) address is expected to be.
echo "02:00:00:00:00:01" > functions/ncm.usb0/dev_addr
echo "02:00:00:00:00:02" > functions/ncm.usb0/host_addr

ln -sf functions/ncm.usb0 configs/c.1/

echo "Gadget configfs tree created at $GADGET_DIR (CDC-NCM function)."
echo
echo "Next: find the UDC and bind it to start enumeration:"
echo "  ls /sys/class/udc"
echo "  echo <udc-name> | sudo tee $GADGET_DIR/UDC"
echo
echo "Once bound and the head unit enumerates the link, bring up the network interface:"
echo "  ip addr add ${PI_IP}/${PI_NETMASK} dev ${IFNAME}"
echo "  ip link set ${IFNAME} up"
echo
echo "Then confirm link state with 'ip addr show ${IFNAME}' and check whether the head unit side"
echo "picks up an address (watch 'ip neigh show dev ${IFNAME}' for ARP entries, or run a packet"
echo "capture with 'tcpdump -i ${IFNAME}') before starting ssdp_announce.py."
