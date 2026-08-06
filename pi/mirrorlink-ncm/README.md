# MirrorLink over USB CDC-NCM + UPnP/SSDP — the new primary bearer approach

## Why this exists

`pi/aoa-gadget/` (AOA/Android Open Accessory) tested negative against two real head units: standard
USB enumeration completed but the head unit's discovery layer never issued a single AOA control
request (`GetProtocol`/`SendString`/`Start`), in every mode tried (direct-identity, true two-stage
switch) and with Bluetooth pairing in every state tried (unpaired, plain pairing, stable A2DP, full
custom HFP Audio Gateway — see `pi/bluetooth-test/`).

Decompiling `vncdiscoverer-usb.dll` in Ghidra confirmed the AOA logic in the firmware is real and
correctly matches our gadget's identity, but is never reached — and, separately, confirmed the same
DLL has a completely independent discovery path based on the WinCE `GetIpAddrTable` API, watching
for a *network interface* to appear rather than a raw USB device. Cross-referencing this against the
actual published spec (ETSI TS 103 544, the standardized Car Connectivity Consortium MirrorLink
spec) confirmed why: **"the MirrorLink Server, implementing the USB device, shall enable CDC/NCM and
start advertising itself via SSDP:alive messages, when receiving the MirrorLink USB command."**
MirrorLink's actual USB bearer is **CDC-NCM (Ethernet-over-USB) + UPnP/SSDP discovery**, not AOA.
`vncbearer-USBAAP.dll` is very likely a secondary/Android-app-specific bearer, not what this head
unit's MirrorLink UI service is watching for on a bare USB connection.

Full technical writeup: `references/cr-v/PROTOCOL_ANALYSIS.md`, "Update — live AOA testing was
negative; real bearer is USB CDC-NCM + UPnP/SSDP, not AOA".

**Status: scaffolded, UNTESTED ON REAL HARDWARE.** This is a first implementation attempt based on
the spec text and firmware evidence above, not a validated working path yet.

## What's here

- `setup_ncm_gadget.sh` — configfs setup for a USB CDC-NCM gadget (Linux's built-in `usb_f_ncm`
  kernel function — no custom userspace daemon needed for the USB side itself, unlike the AOA
  gadget's FunctionFS approach). Brings up a `usb0` network interface on the Pi.
- `ssdp_announce.py` — once the NCM link has an IP address, this sends periodic UPnP `NOTIFY
  ssdp:alive` multicast announcements (per the spec text above), serves a minimal UPnP device
  description XML over HTTP, and responds to `M-SEARCH` queries. Advertises two UPnP service types
  confirmed present as literal strings in the head unit's own firmware:
  `urn:schemas-upnp-org:service:TmApplicationServer:1` and
  `urn:schemas-upnp-org:service:TmClientProfile:1` ("Tm" = Terminal Mode, the CCC framework
  MirrorLink is built on).

## Known gaps / best-effort guesses that may need correcting

- **Root device type URN** (`DEVICE_TYPE` in `ssdp_announce.py`) was NOT found in the firmware
  strings dump — only the two service types were. `urn:schemas-upnp-org:device:TerminalModeDevice:1`
  is a plausible guess following standard UPnP naming convention, not a confirmed value. If the
  head unit's own `M-SEARCH` can be observed (e.g. via `tcpdump -i usb0` once the link is up), its
  `ST:` header would confirm the real value directly — do that before assuming this guess is wrong.
- **IP addressing** (`192.168.42.1` for the Pi side) is a plausible guess based on
  `192.168.42.0/24`/`169.254.x.x` address strings found in `vncdiscoverer-usb.dll`, not confirmed.
  The head unit may expect to self-assign via a specific mechanism (static, link-local, or DHCP) —
  not yet known which.
- **The "MirrorLink USB command" precondition**: the spec text says the phone enables CDC/NCM and
  starts advertising "when receiving the MirrorLink USB command" — it's not yet clear whether this
  refers to something the head unit sends first (in which case our gadget may need to already be
  listening for it before switching to NCM, similar to AOA's two-stage identity switch) or whether
  simply presenting as CDC-NCM from first enumeration is sufficient to test. Starting simple
  (advertise unconditionally) is the right first experiment; revisit if it's silently ignored.

## Running the test

1. Tear down the AOA gadget first if it's running — both bind the same UDC and can't coexist (see
   `pi/aoa-gadget/README.md` "clean restart" section for the teardown sequence).
2. On the Pi:
   ```
   cd pi/mirrorlink-ncm
   sudo ./setup_ncm_gadget.sh
   ```
   Follow its printed instructions: find the UDC name, bind it, then bring up the `usb0` interface
   with the IP/netmask it prints.
3. Connect the Pi's peripheral USB port to the head unit.
4. Watch for the interface to come up on both sides — `ip addr show usb0`, `ip neigh show dev usb0`
   (ARP entries appearing means the head unit's side of the link is alive), and/or
   `tcpdump -i usb0` to see any traffic at all from the head unit before starting the SSDP
   announcer, since that traffic (if any) is the best source of truth for the guesses above.
5. Start the announcer:
   ```
   sudo python3 ssdp_announce.py --ip 192.168.42.1
   ```
   Watch its console for `NOTIFY ssdp:alive` sends and any `M-SEARCH` requests received from the
   head unit — an incoming `M-SEARCH` at all would be strong confirmation this is the right bearer,
   independent of whether our response format is fully correct yet.
6. Check the head unit's MirrorLink/HondaLink diagnostics menu for any state change versus the AOA
   testing baseline (which showed nothing at all).

Report back what's observed at each step — particularly whether `usb0` comes up at the kernel level
on the Pi side at all (confirms the head unit accepts a CDC-NCM device the same way it accepted the
AOA gadget's enumeration), and whether any traffic (ARP, DHCP, SSDP) arrives from the head unit
before assuming the SSDP layer itself is wrong.
