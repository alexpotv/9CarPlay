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

1. **Start the DHCP server**, if it isn't already running — confirmed necessary: the head unit is
   a DHCP client (see "IP configuration" below), and won't get anywhere without something
   answering its `DHCPDISCOVER`:
   ```
   sudo apt install -y dnsmasq   # once, if not already installed
   sudo ./start_dhcp_server.sh
   ```
   Leave this running in its own shell.
2. **Start the SSDP announcer, with a short interval, before triggering the attach**, if it isn't
   already running. The head unit only appears to watch for our announcement in a window right
   after it sees a fresh USB attach — the announcer needs to already be running so a `NOTIFY
   ssdp:alive` lands inside that window:
   ```
   sudo python3 ssdp_announce.py --ip 192.168.42.1 --interval 3
   ```
   Leave this running in its own shell too. It only needs to be started once — it's fine to leave
   it running across multiple `cycle_usb.sh` trials.
3. **In a third shell, trigger the attach** (this is `cycle_usb.sh` from section A step 4 or
   section B step 1 above — already done if you just came from one of those).
4. **Check the head unit's MirrorLink/HondaLink diagnostics screen**, and watch the `[http]` log
   in the `ssdp_announce.py` shell and the DHCP log in the `start_dhcp_server.sh` shell. As of the
   last hardware trial (before the DHCP server existed), the diagnostics screen showed a new dated
   entry with two events a few seconds apart — `Detected Device`, then `MirrorLink Status
   (disconnected)` — and `tcpdump` showed the head unit repeatedly retrying `DHCPDISCOVER` with no
   response. With a DHCP server now answering, the expected next result is the DHCP log showing a
   lease handed out, followed by `[http]` showing a `GET /description.xml` (and hopefully further:
   an SCPD fetch, a `SUBSCRIBE`, or a control action — see "Next test" below).

If step 4 doesn't produce a new entry on the first try, just re-run `cycle_usb.sh` again without
restarting the announcer or DHCP server — each cycle is one clean trial, and a miss on one trial
doesn't mean the setup is wrong.

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

**Status: steadily progressing on real hardware, DHCP + device-type gaps resolved.** With
`start_dhcp_server.sh` running, the head unit obtains a DHCP lease (diagnostics screen logs
`Detected Device` then `Assigned IP address`) and then actively sends `M-SEARCH` for
`urn:schemas-upnp-org:device:TmServerDevice:1` — confirming the previously-guessed root device
type URN was wrong, now corrected in `ssdp_announce.py`. This is real, two-way protocol engagement
from the head unit, well past anything AOA ever produced. Not yet tested: whether a matching
`M-SEARCH` response now leads to an HTTP fetch of `/description.xml` and beyond — see "Next test"
below.

## What's here

- `setup_ncm_gadget.sh` — configfs setup for a USB CDC-NCM gadget (Linux's built-in `usb_f_ncm`
  kernel function — no custom userspace daemon needed for the USB side itself, unlike the AOA
  gadget's FunctionFS approach). Brings up a `usb0` network interface on the Pi.
- `cycle_usb.sh` — soft-cycles the gadget's UDC binding (see "Why cycling instead of physically
  unplugging" below) and (re-)applies the Pi's IP/link-up state every time it runs.
- `start_dhcp_server.sh` — a `dnsmasq`-based DHCP server scoped strictly to `usb0`, needed because
  the head unit is a DHCP client on this link (confirmed via `tcpdump` — see "IP configuration"
  below) and gets nowhere without something answering it.
- `ssdp_announce.py` — once the NCM link has an IP address, this sends periodic UPnP `NOTIFY
  ssdp:alive` multicast announcements, serves a UPnP device description XML plus per-service SCPD
  (action list) XML over HTTP, handles SOAP `POST` control requests, and handles GENA
  `SUBSCRIBE`/`UNSUBSCRIBE` on `/eventSub`. Advertises two UPnP service types confirmed present as
  literal strings in the head unit's own firmware — `urn:schemas-upnp-org:service:
  TmApplicationServer:1` and `urn:schemas-upnp-org:service:TmClientProfile:1` ("Tm" = Terminal
  Mode, the CCC framework MirrorLink is built on) — and implements enough of the standard UPnP
  control/eventing surface (confirmed via firmware strings to be a CyberGarage/CyberLink C++ UPnP
  stack: SOAP-over-HTTP with a `SOAPACTION` header, GENA eventing, and literal paths
  `/description.xml` / `/eventSub`) to respond meaningfully rather than 404 to whatever the head
  unit tries next. Action names on each service (`GetApplicationList`, `LaunchApplication`,
  `GetApplicationCertificateInfo`, etc. on `TmApplicationServer`; `GetMaxNumProfiles`,
  `GetClientProfile`, `SetClientProfile` on `TmClientProfile`) are inferred from internal C++
  method names adjacent to the service-type strings in the firmware, not confirmed against a real
  SCPD/WSDL — every control request is logged in full (path, SOAPACTION, body) regardless of
  whether we recognize the action, specifically so a real invocation can be captured and the
  actual argument list learned from what the head unit sends.

## Known gaps / best-effort guesses that may need correcting

- ~~Root device type URN unknown~~ **Resolved.** With the DHCP server running, the head unit
  obtains a lease and then actively sends `M-SEARCH` with
  `ST: urn:schemas-upnp-org:device:TmServerDevice:1` — not `TerminalModeDevice:1` as previously
  guessed. `DEVICE_TYPE` in `ssdp_announce.py` has been corrected to the confirmed value, and our
  `NOTIFY`/`M-SEARCH` responses should now actually match what the head unit is looking for.
- ~~IP addressing mechanism unknown~~ **Resolved.** Confirmed live via `tcpdump`: the head unit
  sends repeated `BOOTP/DHCP Request` packets from MAC `02:00:00:00:00:02` (exactly the NCM
  `host_addr` configured in `setup_ncm_gadget.sh`) — it's a DHCP client. `start_dhcp_server.sh`
  now answers this. The Pi's own static `192.168.42.1/24` (the guess based on address strings in
  `vncdiscoverer-usb.dll`) is kept as the DHCP server's gateway/subnet — still not independently
  confirmed as the exact range the head unit expects, but at least now self-consistent, and the
  head unit will get *some* working lease to test with either way.
- **SCPD action arguments are unknown.** Actions are declared with zero arguments, which keeps
  the SCPD schema-valid but means any action requiring input (e.g. `LaunchApplication` almost
  certainly needs an app identifier) can't yet be answered meaningfully — the control handler logs
  the raw SOAP body of every invocation so real argument names/values can be read off a live
  capture once the head unit actually calls one.
- **The "MirrorLink USB command" precondition**: the spec text says the phone enables CDC/NCM and
  starts advertising "when receiving the MirrorLink USB command" — it's not yet clear whether this
  refers to something the head unit sends first (in which case our gadget may need to already be
  listening for it before switching to NCM, similar to AOA's two-stage identity switch) or whether
  simply presenting as CDC-NCM from first enumeration is sufficient to test. Starting simple
  (advertise unconditionally) is the right first experiment; revisit if it's silently ignored.

## Next test: does the head unit fetch SCPD / invoke a control action now?

**Confirmed so far**: with the corrected `DEVICE_TYPE` and a working DHCP lease, the head unit
does `GET /description.xml` (200) once, then starts its own periodic `M-SEARCH` (which we now
answer correctly) — but in a ~20s trial it didn't go further, and the diagnostics screen stayed at
`Assigned IP address`. `ssdp_announce.py` now also serves `<URLBase>` in the description (a real,
confirmed-via-firmware-string element we were previously missing), which may or may not matter.

A follow-up trial with Bluetooth paired at the same time produced the identical two diagnostics
events and, notably, **no `GET /description.xml` at all this time** — because `DEVICE_UUID` was
previously fixed across runs, the head unit may have simply recognized us as an already-known
device from the earlier trial and skipped re-fetching, which would make that absence a caching
artifact rather than a new negative result for the Bluetooth-correlation theory. `DEVICE_UUID` is
now randomized by default on every run specifically to rule this out — each trial now presents as
a genuinely new device, so a fresh `GET /description.xml` should occur every time regardless of
what happened in a previous trial (pass `--fixed-uuid` to opt back into the old deterministic
behavior if that's ever useful).

For the next trial:

1. **Let it run longer — don't `Ctrl+C` early.** 20s may just not have been enough time; a real
   UPnP control point can have multiple internal timeouts/retries before either progressing or
   giving up. Leave a trial running for at least 60-90s and watch both the console and the
   diagnostics screen the whole time.
2. **Optionally, pair Bluetooth at the same time** (`pi/bluetooth-test/`, either plain pairing or
   the full HFP setup) before triggering the CDC-NCM/SSDP trial. New firmware evidence found a
   `<bdAddr>` (Bluetooth address) field in what looks like session/connection data — it's possible
   the head unit needs to correlate this UPnP session with an already Bluetooth-paired device to
   let it proceed past initial detection, even though Bluetooth wasn't required to get *that* far.
3. Read the `[http]` console log, which shows every HTTP request received, in order — this alone
   answers several open questions, no `tcpdump` required:
   - **Still nothing beyond `GET /description.xml`** — even with the `URLBase` fix and more time,
     this would suggest the head unit is evaluating the description content and rejecting/ignoring
     it (missing element, wrong value) rather than just not having gotten there yet. Next step
     would be a `tcpdump -A` capture of the exact bytes on both sides of that GET to check for
     anything we're not accounting for.
   - **`GET /scpd_TmApplicationServer.xml` and/or `GET /scpd_TmClientProfile.xml` appear**, logged
     with `"SCPD fetched for service ..."` — confirms it's progressing normally through
     description → SCPD. Watch what happens right after.
   - **`SUBSCRIBE /eventSub` appears** — confirms GENA eventing is part of the flow.
   - **`POST /control_<service>` appears with a `SOAPACTION`** — the actual goal: read the logged
     action name and full SOAP body. Given the firmware's `attestationRequest` template
     (`trustRoot`/`nonce`/`componentID`) and the `GetApplicationCertificateInfo` action name, a
     certificate/attestation exchange as the very first invoked action would not be surprising —
     if so, that ties this layer directly into the Phase 3 pairing/certificate risk already
     flagged in `PROJECT_PLAN.md`, and would mean genuine CCC-issued credentials are likely needed
     here too, not only at the RFB layer.

Whatever the result, it narrows the search meaningfully — report back the full `[http]` log
(from a longer trial, with or without Bluetooth paired) and we'll know which of the remaining
unknowns to chase next.

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
