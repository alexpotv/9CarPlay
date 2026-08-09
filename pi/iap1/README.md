# iAP1 legacy HondaLink phone scaffold

Implements the Gate 2 (app whitelist) plan from `references/cr-v/iap.md` — a first live test of
whether the head unit's factory HondaLink source will recognize a Pi presenting as a legacy
(iAP1-era) iPhone, list apps, and pass basic AV/touch through the patent's USB+HDMI channels
(US9116563B2). Companion to `pi/aoa-gadget/` and `pi/mirrorlink-ncm/` — same project, same
build-a-plausible-scaffold-then-test-on-hardware methodology, different (older, separate) protocol
family. Read `references/cr-v/iap.md` before touching this code — it has the full decompiled
evidence this scaffold is based on.

## What this does and doesn't attempt

Per the user's request, this is deliberately light and generic — enough to exercise five things,
no more:

| Goal | Status |
|---|---|
| Pi is detected as a phone-like USB device | Implemented (best-effort) — Apple VID + plausible iPhone PID, vendor-class FunctionFS interface |
| Bluetooth HFP connection (confirmed precondition) | Implemented — `setup_bt_phone.sh` + reused `pi/bluetooth-test/hfp_ag.py` |
| Basic iAP1 identify handshake | Implemented (best-effort) — see "Confidence levels" below |
| Head unit lists available apps | Speculative placeholder only — see "Confidence levels"; the real wire mechanism for `SetServerVRAppData` is unresolved |
| AV via HDMI | Implemented, trivially — `hdmi_testpattern.sh`, no protocol needed per RE finding |
| Touch input registered via USB | Instrumented, not decoded — unclassified bulk-OUT bytes are logged with timestamps for post-hoc correlation; the wire format is unknown |

This does **not** implement Gate 1 (MFi device attestation) — see `iap.md`, "Open risks" #2. If the
head unit demands genuine MFi authentication before reaching the identify layer this scaffold
speaks, expect the connection to stall there. Finding out exactly where it stalls is the point of
this test, the same way `pi/aoa-gadget/` and `pi/mirrorlink-ncm/` each characterized exactly how
far their respective bearers got before hitting a wall.

**Bluetooth is a confirmed precondition, not optional, for this path.** Decompiling
`Communication.exe`'s `isIPhoneConnected()` found a hard gate: it requires either (a) a Bluetooth
HFP connection flag AND the USB iAP flag both set, or (b) the currently BT-connected device's
address matching one already on file. See `iap.md`, "Bluetooth gating confirmed by decompilation",
and run `setup_bt_phone.sh` (below) **before** — or at least concurrently with — testing the USB
side. This is a different, confirmed-positive finding from the earlier BT-gating *theory* in
`pi/bluetooth-test/`, which tested negative for the separate (and since-superseded) MirrorLink/AOA
path — don't conflate the two; this one has decompiled code backing it, specific to this path.

## Confidence levels (read this before interpreting test results)

- **USB gadget enumeration** (Apple VID `0x05ac`, a plausible 2013-era iPhone PID, vendor-class
  bulk interface) — same confidence as every other gadget in this repo: built against public USB
  mechanics, untested against this specific head unit.
- **iAP1 packet framing** (`0xFF 0x55 <LEN> <payload> <checksum>`) — CONFIDENT. This is the
  classic, public, pre-MFi-enforcement "iPod Accessory Protocol" framing, documented across
  hobbyist/aftermarket-accessory community sources for over a decade, not Apple's confidential
  iAP2/MFi spec.
- **The specific command IDs** (`RequestIdentify=0x00`, etc., in `iap1_daemon.py`) — the least
  confident part of this scaffold. Assigned from the commonly-described Request(even)/Return(odd)
  numbering convention seen across public references, not verified against Honda's actual
  implementation. Expect to revise these based on what a live trial or wire capture shows.
- **The app-list announcement** (`build_app_list_announce()` in `iap1_daemon.py`) — pure
  speculation. `SetServerVRAppData`'s real wire encoding was not found in `Communication.exe` (it's
  behind an unextracted module — see `iap.md`). This is sent on a deliberately out-of-range,
  greppable placeholder Lingo ID purely so a live capture has something to correlate against.
- **Touch** — not decoded at all. Every byte that doesn't parse as a valid iAP1 packet is logged
  with a timestamp to `iap1_unclassified.bin`, so a trial where you deliberately tap the head
  unit's screen while connected can be correlated against the log afterward.

## Prerequisites

Same as `pi/aoa-gadget/` and `pi/mirrorlink-ncm/`:

- A Raspberry Pi model with a USB port that supports **peripheral/OTG mode** (Pi Zero/Zero 2 W, or
  a Pi 4/5 via its USB-C port).
- `dtoverlay=dwc2` in `/boot/firmware/config.txt`, then reboot.
- `libcomposite` kernel module (`modprobe libcomposite`).
- Python 3 (no non-stdlib dependencies — `iap1_daemon.py` only uses `os`/`select`/`struct`/`sys`/
  `time`).
- Cannot coexist with the AOA or CDC-NCM gadgets — all three bind the same UDC. Tear down whichever
  is currently active first.

## What's here

- `setup_gadget.sh` — configfs gadget setup: Apple VID/PID, one FunctionFS function (`ffs.iap1`)
  with a vendor-class interface (bulk IN + bulk OUT).
- `iap1_daemon.py` — the identify-handshake/logging daemon. Must be running (and have opened
  `ep0`) **before** the UDC is bound. Writes recognized iAP1 packets to `iap1_capture.bin` and
  everything else (raw, timestamped) to `iap1_unclassified.bin`.
- `apps.py` — plain-data identity/app manifest (`PHONE_IDENTITY`, `GENERAL_LINGO_IDENTITY`,
  `APPS`). Edit this to change what the daemon presents without touching protocol code. See its
  module docstring for exactly which fields map to which decompiled check in `Communication.exe`.
- `cycle_usb.sh` — soft-cycles the gadget's UDC binding for repeat trials, same technique as
  `pi/mirrorlink-ncm/cycle_usb.sh`.
- `hdmi_testpattern.sh` — pushes a visible test pattern out the Pi's HDMI output, independent of
  the USB daemon (per RE, HDMI carries a plain mirrored framebuffer with no protocol coupling to
  the USB/iAP session — see `PROTOCOL_ANALYSIS.md`, "HDMI side: no protocol-specific negotiation
  found").
- `setup_bt_phone.sh` — configures the Pi's Bluetooth radio as a phone-class device
  (discoverable/pairable, Class of Device 0x5A020C), a confirmed precondition for this path (see
  above and `iap.md`). Does not implement HFP itself — pairs with `pi/bluetooth-test/hfp_ag.py`
  (reused directly, not duplicated) for the actual Hands-Free Profile Audio Gateway role.

## Quickstart

1. Tear down any other active gadget (AOA/CDC-NCM) first if this isn't a fresh boot.
2. **Bluetooth first** — get a stable HFP connection established before spending time on the USB
   side, since `isIPhoneConnected()` requires it (see "Bluetooth is a confirmed precondition"
   above):
   ```
   cd pi/iap1
   sudo ./setup_bt_phone.sh
   sudo python3 ../bluetooth-test/hfp_ag.py
   ```
   Then pair from the **head unit's own** Bluetooth "add device" menu (not from the Pi — this is
   also how the head unit learns/records this Pi's BD address as "the accessory," per
   `OnBluetoothStatusEvent`'s `AccessoryMacAddress Non` check in `iap.md`). Confirm a stable HFP
   Service Level Connection (watch `hfp_ag.py`'s console and the head unit's phone icon) — not
   just "paired" — before moving on. See `setup_bt_phone.sh`'s own printed instructions and
   `pi/bluetooth-test/README.md` "Phase A"/"Phase B" for troubleshooting connect/disconnect
   flapping.
3. On the Pi, before connecting to the head unit's USB port:
   ```
   sudo ./setup_gadget.sh
   sudo python3 iap1_daemon.py /dev/ffs-iap1
   ```
   Wait for "Descriptors written and all endpoints opened" before binding.
4. In a second shell, bind the UDC (or use the cycle script, which auto-detects an unbound gadget
   and does a fresh bind):
   ```
   sudo ./cycle_usb.sh
   ```
5. Connect (or leave connected) to the head unit's USB port, and select whatever source triggers
   its HondaLink/phone-app UI.
6. In a third shell (or on an HDMI-connected monitor), start the visible test pattern so you can
   independently confirm the AV leg:
   ```
   sudo ./hdmi_testpattern.sh
   ```
7. Watch `iap1_daemon.py`'s console. Useful outcomes, weakest to strongest signal (mirrors the
   pattern used in `pi/aoa-gadget/README.md`):
   - Nothing at all / no `[event] ENABLE` — the head unit isn't probing this port the way we
     expect, or the descriptors are wrong.
   - `ENABLE` but no bulk traffic afterward — standard USB enumeration completes but nothing
     iAP1-shaped ever arrives. Could mean Gate 1 (MFi) is being checked at a layer below what
     we're presenting (e.g. the head unit expects to talk to a real MFi coprocessor via a specific
     control/vendor request we haven't implemented) — worth also watching for `[setup]` lines
     logging any vendor control requests we don't otherwise handle.
   - `[rx] iAP1 packet ...` lines — real, structurally-valid framing is arriving; this alone
     confirms the framing guess in "Confidence levels" is at least plausible enough to be
     recognized as *something* by whatever's parsing it upstream (or is coincidental noise —
     cross-check against `iap1_capture.bin`).
   - A `RequestIdentify`-shaped exchange completes and the head unit's own UI/diagnostics screen
     shows something beyond generic "device attached" (a device name, a phone icon, an app list,
     anything HondaLink-specific) — this would be the real milestone: confirmation the identify
     layer is far enough along to matter, and a concrete signal for what to fix next.
8. Whatever happens, tap the head unit's own touchscreen a few times while connected, then check
   `iap1_unclassified.bin` (timestamps + hex) for anything that showed up in that window — this is
   the touch-discovery methodology described above.
9. Report back (or update `iap.md`/`PROJECT_PLAN.md`) with: did `ENABLE` fire, did any `[setup]`
   vendor requests show up, did any `[rx]` packets show up, what (if anything) changed on the head
   unit's own screen, and whether tapping the screen produced anything in
   `iap1_unclassified.bin`. That combination is what determines the next iteration — exactly the
   same iterative loop `pi/aoa-gadget/` and `pi/mirrorlink-ncm/` went through.

## Fixed since the first hardware trial

- **Bulk endpoints going permanently dead after a `cycle_usb.sh` UDC unbind/rebind.** First live
  trial showed `ENABLE` firing correctly on each re-enumeration, but a
  `[ep_out] read error: [Errno 108] Cannot send after transport endpoint shutdown` right after the
  first cycle — the previously-opened `ep1`/`ep2` file descriptors are invalidated by a UDC
  unbind and don't come back on their own once the gadget re-enumerates, and the daemon was only
  ever opening them once at startup. Fixed: `iap1_daemon.py` now reopens `ep1`/`ep2`
  (`open_bulk_eps()`) right after every `FUNCTIONFS_ENABLE` event, with an `ESHUTDOWN`/`ENODEV`
  read-error fallback in case that ordering is ever missed. If you were seeing `ENABLE` fire with
  no bulk traffic ever recognized afterward on a *second or later* cycle, this was why — traffic
  may have been arriving but landing on a dead fd, not actually absent.
- **Interface class/subclass/protocol bytes** — the vendor interface was originally fully generic
  (`0xFF`/`0xFF`/`0xFF`, the same starting point `pi/aoa-gadget/` used). Updated to `0xFF`/`0xFE`/
  `0x02` — not a new guess, but the publicly documented (non-NDA) identity real iPhones present for
  their USB "usbmux" interface, per libimobiledevice/usbmuxd's own published device-matching rules
  and the Linux `ipheth` driver source. Worth a fresh trial to see if this changes anything, given
  the first trial got `BIND`/`ENABLE` with no higher-layer engagement — the same "enumerates but
  nothing above that layer cares" pattern `pi/aoa-gadget/` hit before its own interface-identity
  fix.

## Known gaps (likely first things to revise after a live trial)

- Exact iAP1 command ID numbering is a best-effort guess (see "Confidence levels").
- `SetServerVRAppData`'s real wire carrier is unknown — `build_app_list_announce()` is placeholder
  instrumentation, not a working implementation.
- Touch relay wire format is completely unknown — this scaffold only logs candidate bytes, it
  doesn't interpret them.
- Gate 1 (MFi device attestation) isn't implemented at all — if it's required before this layer is
  reached, this scaffold will need a real (or convincingly faked) MFi coprocessor response first,
  which is a separate, harder problem (see `iap.md`).
- `wMaxPacketSize`/`bInterval` values are reasonable defaults, not verified against what the head
  unit actually expects for this interface.
- The BD-address "accessory" registration flow (does the head unit need to learn the Pi's MAC via
  its own pairing menu specifically, versus accepting any currently-connected HFP device — see
  `iap.md`) is inferred from decompiled logic, not yet confirmed against live pairing behavior.
- Whether the head unit's `isIPhoneConnected()` USB-iAP flag (`+0x78`, per `iap.md`) is satisfied
  merely by USB enumeration/`ENABLE`, or requires the identify handshake to actually complete, is
  unconfirmed — worth watching whether BT alone (HFP connected, USB not yet attempted) already
  changes anything on the head unit's screen.
