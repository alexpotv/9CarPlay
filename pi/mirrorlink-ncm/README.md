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
   This builds the configfs gadget tree — `functions/ncm.usb0` **and** `functions/ffs.mlctrl`
   (see "The MirrorLink USB command" below — required, not optional), the config, the strings —
   but does **not** bind it to a UDC and does **not** assign an IP address.
4. **Start the MirrorLink USB command listener** (must happen before binding — FunctionFS
   requires its descriptors to be written to `ep0` first):
   ```
   sudo python3 mirrorlink_usb_cmd_listener.py /dev/ffs-mlctrl
   ```
   Leave this running in its own shell for the rest of the session — it stays open across UDC
   cycles.
5. **Bind the gadget and bring the link up** by running the cycle script once:
   ```
   sudo ./cycle_usb.sh
   ```
   Since the `UDC` file is still empty at this point, `cycle_usb.sh` detects that and does a
   fresh bind (not a cycle) — see "Does `cycle_usb.sh` bind the UDC itself?" below. It then
   unconditionally assigns `192.168.42.1/24` to `usb0` and brings the link up, so after this step
   both the USB binding and the IP configuration are done — you should never need to run a manual
   `ip addr add` / `ip link set up` yourself.
6. Continue with the shared steps in **"Running a trial"** below.

### B. Repeat trial, same boot session (gadget already exists)

Needed every time you want to force a new detection event without a full reboot — e.g. after a
"disconnected" result, to try again.

1. If `mirrorlink_usb_cmd_listener.py` isn't still running from before, start it first (same
   ordering requirement as a fresh setup — it must have written its descriptors before any bind):
   ```
   sudo python3 mirrorlink_usb_cmd_listener.py /dev/ffs-mlctrl
   ```
2. Re-run the cycle script — it re-does the unbind/rebind **and** re-applies the IP/link-up step
   every time, so you don't need to check or restore IP state yourself even if a previous cycle
   happened to wipe it:
   ```
   sudo ./cycle_usb.sh
   ```
3. Continue with **"Running a trial"** below (or skip straight to it if the announcer from a
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
  kernel function) **plus** a second function, `ffs.mlctrl` (FunctionFS), that exists purely to
  catch the "MirrorLink USB command" — see below. Brings up a `usb0` network interface on the Pi.
- `mirrorlink_usb_cmd_listener.py` — watches `ffs.mlctrl`'s `ep0` and acknowledges (rather than
  auto-stalling) the MirrorLink USB command. Must be started before the UDC is bound — see
  Quickstart. See "The MirrorLink USB command" below for why this exists.
- `cycle_usb.sh` — soft-cycles the gadget's UDC binding (see "Why cycling instead of physically
  unplugging" below) and (re-)applies the Pi's IP/link-up state every time it runs.
- `start_dhcp_server.sh` — a `dnsmasq`-based DHCP server scoped strictly to `usb0`, needed because
  the head unit is a DHCP client on this link (confirmed via `tcpdump` — see "IP configuration"
  below) and gets nowhere without something answering it.
- `ssdp_announce.py` — once the NCM link has an IP address, this sends periodic UPnP `NOTIFY
  ssdp:alive` multicast announcements, serves a UPnP device description XML (including the real,
  spec-confirmed `X_mirrorLinkVersion` element — see "Known gaps" below) plus per-service SCPD
  XML over HTTP, handles SOAP `POST` control requests, and handles GENA `SUBSCRIBE`/`UNSUBSCRIBE`
  on `/eventSub`. Action names and several argument lists (`LaunchApplication`, `SetClientProfile`,
  `GetCertifiedApplicationsList`) are confirmed both by decompiling `MIrrorLink.exe` and
  independently by the official ETSI TS 103 544 spec (parts 9/10/12, saved in
  `references/cr-v/etsi_spec/`) — every control request is logged in full (path, SOAPACTION, body)
  regardless of whether we recognize the action.

## The MirrorLink USB command

ETSI TS 103 544-1 clause 4.2.2 defines a specific USB control transfer, the "MirrorLink USB
command", that the head unit (as USB host) sends to the device *before* it will trust a MirrorLink
session over USB:
```
bmRequestType = 0x40   (host-to-device, vendor, device recipient)
bRequest      = 0xF0
wValue        = MirrorLink version (low byte major, high byte minor — e.g. 0x0101 for 1.1)
wIndex        = USB host vendor ID
wLength       = 0
```
Per spec: *"USB devices, not supporting MirrorLink USB command, will return STALL PID... If the
MirrorLink Server is not able to switch to USB CDC/NCM functionality in response, the USB device
shall respond with a STALL PID."* — and the head unit's own client-side logic for recognizing "an
operating MirrorLink Server" explicitly requires condition 1: *"the command does not return with
STALL PID"*. A bare `usb_f_ncm`-only gadget has nothing registered to claim this vendor request,
so the kernel composite framework auto-STALLs it by default — meaning, until
`mirrorlink_usb_cmd_listener.py` was added, **we were very likely failing this exact check on
every single trial**, independent of and prior to anything at the IP/SSDP/HTTP layer. This was
found by reading the actual spec after multiple XML-content fixes produced no change on hardware —
see `references/cr-v/PROTOCOL_ANALYSIS.md` for the full trace.

## Known gaps / best-effort guesses that may need correcting

- ~~Root device type URN unknown~~ **Resolved.** Confirmed via the head unit's own `M-SEARCH`:
  `ST: urn:schemas-upnp-org:device:TmServerDevice:1`.
- ~~IP addressing mechanism unknown~~ **Resolved.** The head unit is a DHCP client (confirmed via
  `tcpdump`); `start_dhcp_server.sh` answers it.
- ~~SCPD is required for the head unit to proceed~~ **Resolved — this was never actually a
  requirement.** ETSI TS 103 544-12: *"The MirrorLink Client MAY retrieve the MirrorLink Server's
  service description [SCPD]; but all necessary information... are available in the Service
  section of the device description."* SCPD-fetch is optional by spec — a compliant client is
  expected to already know the standardized actions. Never seeing an SCPD request was correct,
  expected behavior all along, not a bug.
- ~~MirrorLink protocol version element unknown/guessed~~ **Resolved via the official spec**
  (`references/cr-v/etsi_spec/ts_103544-12_UPnP_Server_Device.pdf`, Table 3 + literal example
  XML): the real element is `X_mirrorLinkVersion`, a direct child of `<device>`, containing
  `<majorVersion>`/`<minorVersion>` directly — no wrapper. Two earlier guesses (a fabricated
  `<attributeList>`/`<attribute>` wrapper) were wrong; that shape actually belongs to a different,
  Deprecated feature (`X_deviceKeys`/`key`) that happens to share the same parsing function in the
  decompiled binary, which is what caused the confusion.
- **The MirrorLink USB command (see above) — implemented, untested on hardware.**
  `mirrorlink_usb_cmd_listener.py` is new and has not yet been validated against a real head unit.
  Watch its console output during the next trial for a `*** MirrorLink USB command received ***`
  line — if it never appears, either the head unit doesn't send this request over this bearer in
  practice (possible — not every implementation follows every clause), or something about the
  hybrid `ncm.usb0` + `ffs.mlctrl` composite isn't routing the request to us correctly (e.g. the
  `FUNCTIONFS_ALL_CTRL_RECIP` flag not having the intended effect in practice) and needs debugging.
- **X_Signature** (an RSA-SHA1 XML signature over the device description, tied to attestation) is
  listed as Mandatory in the spec's attribute table, but annotated as introduced in later
  MirrorLink versions (1.2/1.3) alongside `X_presentations`/`X_localization`/`X_mlUiMode`. Since
  this firmware only knows about `ml-1-0`/`ml-1-1`, it's plausible not enforced here — not
  implemented, not yet confirmed either way.

## Next test: does the MirrorLink USB command get received now?

**State before this round**: with the corrected `DEVICE_TYPE`, working DHCP, and the real
`X_mirrorLinkVersion` element (validated well-formed against an independent UPnP library,
`upnpclient`, with zero errors), the head unit still only did `GET /description.xml` once and
never progressed further — no SCPD fetch (now known to be expected — see "Known gaps"), no
`SUBSCRIBE`, no control action. Diagnostics stayed at `Assigned IP address` (an improvement over
earlier trials, which showed an explicit `MirrorLink Status (disconnected)` rejection — no
rejection this time suggests progress, just a stall further in).

Reading ETSI TS 103 544-1 directly resolved why: the head unit is expected to send a specific USB
control transfer — the "MirrorLink USB command" — before it will trust the session, and our
gadget had nothing to receive it (see "The MirrorLink USB command" above). This is now
implemented in `mirrorlink_usb_cmd_listener.py`, untested on hardware as of this writing.

For the next trial, the ordering from the Quickstart matters — `mirrorlink_usb_cmd_listener.py`
must be running *before* `cycle_usb.sh` binds the UDC. Then:

1. Watch the **listener's own console** first, above everything else — this is the most direct
   signal now. Look for:
   ```
   [mlctrl] *** MirrorLink USB command received *** requested version X.Y, host vendorID=0x....
   ```
   - **If this line appears**: real confirmation the head unit does send this command over USB and
     we're now acknowledging it instead of stalling. Check immediately after whether the
     diagnostics screen progresses past `Assigned IP address`, and whether `ssdp_announce.py`'s
     `[http]` log shows any new activity (a repeat `GET /description.xml`, or — the real goal — a
     `SUBSCRIBE`/`POST` with a `SOAPACTION`, ideally `SetClientProfile` first per
     ETSI TS 103 544-13's session-setup sequence).
   - **If it never appears**: either this head unit doesn't send the command in practice over this
     bearer, or the hybrid `ncm.usb0` + `ffs.mlctrl` composite isn't routing the request to us the
     way intended (worth checking `[mlctrl] event: BIND`/`ENABLE` lines appear at all, confirming
     the FunctionFS side of the gadget is alive; if even those are missing, the composite may not
     be enumerating both functions correctly and needs its own debugging pass).
2. Regardless of the listener's result, still watch `ssdp_announce.py`'s `[http]` log and the
   diagnostics screen as before — report back all three (listener console, `[http]` log,
   diagnostics screen state) so we know precisely which layer to chase next.

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
