#!/bin/bash
# Runs a DHCP server scoped only to the usb0 (CDC-NCM) link, so the head unit's own DHCP client
# can actually get an IP address instead of retrying DHCPDISCOVER forever.
#
# Confirmed live via tcpdump: repeated "BOOTP/DHCP, Request from 02:00:00:00:00:02" packets on
# usb0 — that MAC is exactly the NCM host_addr configured in setup_ncm_gadget.sh, i.e. this is
# the head unit itself acting as a DHCP client. Until this runs, nothing answers those requests,
# so the head unit never obtains an IP and can't originate any further traffic (HTTP, SSDP, etc.)
# back to us — a very plausible root cause for it reporting "disconnected".
#
# Requires dnsmasq: sudo apt install dnsmasq
# Run as root, in its own shell, alongside ssdp_announce.py (see README.md Quickstart).

set -euo pipefail

IFNAME="usb0"
RANGE_START="192.168.42.10"
RANGE_END="192.168.42.100"
NETMASK="255.255.255.0"
LEASE_TIME="12h"
GATEWAY="192.168.42.1"   # must match the IP assigned to usb0 by cycle_usb.sh/setup_ncm_gadget.sh

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

if ! command -v dnsmasq &>/dev/null; then
    echo "dnsmasq not found — install with: sudo apt install dnsmasq" >&2
    exit 1
fi

echo "Starting DHCP server on ${IFNAME}, range ${RANGE_START}-${RANGE_END}, gateway ${GATEWAY}"
echo "(Ctrl+C to stop. Leave this running for the whole trial.)"

# --port=0 disables dnsmasq's DNS service — we only want DHCP, and don't want to fight any
# other DNS resolver already running on the Pi.
# --bind-interfaces + explicit --interface scopes this strictly to usb0.
exec dnsmasq \
    --no-daemon \
    --interface="$IFNAME" \
    --bind-interfaces \
    --except-interface=lo \
    --port=0 \
    --dhcp-range="${RANGE_START},${RANGE_END},${NETMASK},${LEASE_TIME}" \
    --dhcp-option=option:router,"$GATEWAY" \
    --log-dhcp
