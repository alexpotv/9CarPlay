# MirrorLink over USB CDC-NCM + UPnP/SSDP — the new primary bearer approach

## Quickstart: reproduce a "Detected Device" event

This is the confirmed, reproducible procedure for getting the head unit to log a MirrorLink
detection event. **Bluetooth pairing is NOT required for this** — this result was obtained with
no Bluetooth connection at all. There are two distinct cases below: **first-time setup after a
fresh Pi boot** (the gadget doesn't exist yet), and **a repeat trial within the same boot
session** (the gadget already exists — you're just re-triggering a fresh attach). Read the IP
configuration note at the end of this section before running either — it's a common failure point.

### A. First-time setup, after a fresh Pi boot

Needed exactly once per boot, because `setup_ncm_gadget.sh` creates configfs state that does not
survive a reboot (configfs is in-memory only).

1. **Connect the Pi to the head unit over USB first**, before doing anything else — this is the
   same port that also powers the Pi, so it should already be plugged in as part of normal
   power-up. Leave it connected for every step below.
2. **Tear down the AOA gadget if it's active** (only relevant if it was set up earlier in this
   boot session — a genuinely fresh boot won't have this):
   ```
   # see pi/aoa-gadget/README.md "clean restart" section
   ```
3. **Create the CDC-NCM gadget:**
   ```
   cd pi/mirrorlink-ncm
   sudo modprobe libcomposite   # only needed if setup_ncm_gadget.sh doesn't already do this
   sudo ./setup_ncm_gadget.sh
   ```
   This builds the configfs gadget tree — `functions/ncm.usb0`, the config, the strings — but
   does **not** bind it to a UDC and does **not** assign an IP address. Both of those now happen
   automatically in the next step.
4. **Bind the gadget and bring the link up** by running the cycle script once:
   ```
   sudo ./cycle_usb.sh
   ```
   Since the `UDC` file is still empty at this point, `cycle_usb.sh` detects that and does a
   fresh bind (not a cycle) — see "Does `cycle_usb.sh` bind the UDC itself?" below. It then
   unconditionally assigns `192.168.42.1/24` to `usb0` and brings the link up, so after this step
   both the USB binding and the IP configuration are done — you should never need to run a manual
   `ip addr add` / `ip link set up` yourself.
5. Continue with the shared steps in **"Running a trial"** below.

### B. Repeat trial, same boot session (gadget already exists)

Needed every time you want to force a new detection event without a full reboot — e.g. after a
"disconnected" result, to try again.

1. Just re-run the cycle script — it re-does the unbind/rebind **and** re-applies the IP/link-up
   step every time, so you don't need to check or restore IP state yourself even if a previous
   cycle happened to wipe it:
   ```
   sudo ./cycle_usb.sh
   ```
2. Continue with **"Running a trial"** below (or skip straight to it if the announcer from a
   previous trial is still running).

### Running a trial (shared by both cases above)

1. **Start the SSDP announcer FIRST, with a short interval, before triggering the attach**, if
   it isn't already running. The head unit only appears to watch for our announcement in a
   window right after it sees a fresh USB attach — the announcer needs to already be running so
   a `NOTIFY ssdp:alive` lands inside that window:
   ```
   sudo python3 ssdp_announce.py --ip 192.168.42.1 --interval 3
   ```
   Leave this running in its own shell. It only needs to be started once — it's fine to leave it
   running across multiple `cycle_usb.sh` trials.
2. **In a second shell, trigger the attach** (this is `cycle_usb.sh` from section A step 4 or
   section B step 1 above — already done if you just came from one of those).
3. **Check the head unit's MirrorLink/HondaLink diagnostics screen.** A new dated entry should
   appear with two events a few seconds apart: `Detected Device`, followed by `MirrorLink Status
   (disconnected)`. This is the current confirmed result — the head unit does react to the
   CDC-NCM attach, but the connection doesn't yet progress past this point (see "Known gaps"
   below for what's still unresolved).

If step 3 doesn't produce a new entry on the first try, just re-run `cycle_usb.sh` again without
restarting the announcer — each cycle is one clean trial, and a miss on one trial doesn't mean
the setup is wrong.

**Does `cycle_usb.sh` bind the UDC itself?** Yes, in both directions. It reads the gadget's
current `UDC` file: if something is already bound, it unbinds then rebinds to that same
controller (simulating an unplug/replug); if the file is empty — e.g. right after a fresh
`setup_ncm_gadget.sh`, before anything has been bound yet — it auto-detects the available
controller from `/sys/class/udc` and binds it. Either way, it then also (re-)applies
`192.168.42.1/24` on `usb0` and brings the link up, unconditionally, every time it runs.

**IP configuration — what's guaranteed and what isn't.** `setup_ncm_gadget.sh` does not assign
an IP itself; it only builds the gadget. The IP is applied entirely by `cycle_usb.sh`, every time
it runs, whether that's the very first bind or a later re-cycle. This was made unconditional
specifically because a UDC unbind/rebind is **not** guaranteed to preserve a previously-assigned
IP — this was observed directly during testing (`ssdp_announce.py` failed with
`OSError: [Errno 99] Cannot assign requested address` / `EADDRNOTAVAIL` after a cycle that had
silently dropped the address). Practical implication: **always go through `cycle_usb.sh` rather
than assuming the IP from a previous step is still there** — do not run `ssdp_announce.py`
without having run `cycle_usb.sh` at least once since the last gadget creation or reboot.

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

**Status: confirmed reproducible partial positive result on real hardware.** Following the
Quickstart above, the head unit's MirrorLink diagnostics screen logs a `Detected Device` event
followed a few seconds later by `MirrorLink Status (disconnected)` — a real reaction to the
CDC-NCM attach + SSDP announcement, and a materially better result than AOA ever produced (which
showed no reaction at all, on any test). The connection does not yet progress past this point;
see "Known gaps" below for what's still unresolved (the "disconnected" outcome suggests the head
unit accepted the device and detected our announcement, but something after that — description
XML fetch, TCP session, or a further pairing/handshake step — isn't happening or isn't correct
yet).

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

## Why cycling instead of physically unplugging

The head unit appears to only actively watch for a MirrorLink SSDP announcement in a window
right after it sees a fresh USB attach — reconnecting `ssdp_announce.py` alone, without a new
attach event, has not produced a new diagnostics-screen event even when packets are confirmed
reaching `usb0`. Normally you'd test this by unplugging and replugging the cable, but on this Pi
the same USB port also supplies power, so a physical unplug isn't practical mid-test.

`cycle_usb.sh` (see Quickstart above for full usage) instead forces a *soft* disconnect/reconnect
at the USB protocol level by unbinding and rebinding the gadget's UDC (USB Device Controller).
Unbinding drops the D+/D- pull-up resistor, which the head unit sees as a real disconnect;
rebinding re-asserts it, triggering a full re-enumeration (`SET_ADDRESS`, `SET_CONFIGURATION`,
etc.) exactly as a physical replug would — without touching the cable or losing power. This is
the same operation that was used earlier in testing to recover from a stuck `not attached` UDC
state, and it's also why the script re-applies the IP/link-up step every time (see "IP
configuration" in the Quickstart) — the state that survives a cycle isn't fully guaranteed.

For a deeper look while a trial is running, in a spare shell: `cat /sys/class/udc/*/state`
(should read `configured` once the head unit accepts the attach) and
`sudo tcpdump -i usb0 -n` (any ARP/DHCP/SSDP traffic from the head unit).
