# AOA gadget scaffold (Phase 2 live test)

Minimal AOA (Android Open Accessory) device-side handshake, implemented as a
Linux USB FunctionFS gadget, for the first live test against the real CR-V
head unit described in `references/cr-v/PROJECT_PLAN.md` (Phase 2).

**Goal of this scaffold**: get to the point where we can plug a Pi into the
actual head unit's USB port and observe, empirically, how far the connection
gets — does the head unit recognize the Pi at all (AOA discovery), does it
open the RFB bulk pipe, and does the pairing/public-key gate (see
`PROTOCOL_ANALYSIS.md`) actually block anything. It does **not** implement
CarPlay ingestion, RFB server logic, or touch injection — those are separate,
later milestones (Phase 1 and Phase 4 of the project plan).

## Correction to CLAUDE.md's phrasing

The top-level `CLAUDE.md` says "the Pi must present itself as an AOA device
identifying as `manufacturer="RealVNC"`" — phrased as if the Pi reports that
identity. Having implemented this against the actual AOA spec, that's
backwards: in AOA, the **host** (accessory role — the head unit here) sends
identity strings *to* the device (phone role — our Pi) via the `SendString`
(51/52/53 series) control requests. The `manufacturer="RealVNC"` /
`"RealVNC AAP Bearer"` strings found in `vncbearer-USBAAP.dll` during static
analysis are what the **head unit will send us**, not something we need to
declare. Our side just needs to correctly implement the generic AOA
device-side protocol (`GetProtocol`, accept `SendString`, handle `Start`) —
there's no identity string we need to get right on our end at all. Worth
fixing the phrasing in `CLAUDE.md` once this is confirmed against real
hardware.

## What's here

- `setup_gadget.sh` — configfs script to create the USB gadget + FunctionFS
  function. Run as root, on the Pi.
- `aoa_gadget.c` — the userspace daemon that drives the handshake over
  FunctionFS: writes USB descriptors (one vendor-class interface, one bulk
  OUT + one bulk IN endpoint) and strings to `ep0`, handles the AOA control
  requests (`GetProtocol`/`SendString`/`Start`), then drops into a bulk-read
  loop that hex-dumps and raw-captures (`aoa_capture.bin`) everything the
  head unit sends afterward — expected to be the start of an RFB handshake
  per `PROTOCOL_ANALYSIS.md`.
- `Makefile` — `make` builds `aoa_gadget` with plain `gcc`.

**Status: untested on real hardware.** This was written and cross-checked
against the public FunctionFS (`linux/usb/functionfs.h`) and AOA2
(source.android.com/docs/core/interaction/accessories/aoa2) specs, but there
was no Linux/Pi box in the environment that produced this to actually compile
or run it against a real `dwc2` USB controller. Treat it as a first draft to
validate and iterate on with the hardware in hand, not verified-working code.
Build it on the Pi itself (or cross-compile) — it depends on kernel-matching
struct layouts that are safest to trust when compiled where they'll run.

## Prerequisites

- A Raspberry Pi model with a USB port that supports **peripheral/OTG mode**:
  Pi Zero / Zero 2 W, or a Pi 4/5 via its USB-C port. A plain USB-A host-only
  port (Pi 3 and most Pi 4/5 USB-A ports) cannot do this — this is a hardware
  constraint, not a software one.
- `dtoverlay=dwc2` in `/boot/firmware/config.txt`, then reboot.
- `libcomposite` kernel module (`modprobe libcomposite`).
- Build tools (`gcc`, `make`) — `sudo apt install build-essential`.

## Running the first test

1. On the Pi (not yet connected to the head unit):
   ```
   sudo ./setup_gadget.sh
   make
   sudo ./aoa_gadget /dev/ffs-aoa0
   ```
   `aoa_gadget` must have opened all endpoints (it prints "Descriptors
   written and all endpoints opened") **before** you bind the UDC — binding
   triggers enumeration and the host will start probing immediately.

2. In a second shell on the Pi, bind the UDC to start enumeration:
   ```
   ls /sys/class/udc
   echo <udc-name> | sudo tee /sys/kernel/config/usb_gadget/aoa0/UDC
   ```

3. *Then* plug the Pi's peripheral-mode USB port into the head unit's USB
   port (or do this with the cable already connected and the head unit
   powered — order shouldn't matter once the gadget is bound, but test both
   if the first doesn't trigger anything).

4. Watch `aoa_gadget`'s output. Useful outcomes, weakest to strongest signal:
   - Nothing at all / no `[event] ENABLE` — the head unit isn't probing this
     port the way we expect, or the descriptors are wrong. Check with
     `usbmon` (below) regardless of app-level output — that's ground truth.
   - `ENABLE` but no `GetProtocol` setup event — head unit doesn't recognize
     this as an AOA-capable device at this VID/PID/descriptor combination.
   - `GetProtocol` handled, `SendString` logs show
     `manufacturer = "RealVNC"` etc — confirms the discovery/AOA layer works
     exactly as expected from the firmware strings. This alone is a real
     milestone.
   - `AOA_START` received, then bytes show up in the bulk capture loop —
     we're now receiving the head unit's side of whatever comes next
     (expected: RFB `ProtocolVersion` handshake, `"RFB 003.008\n"` or
     similar). This is where we'd actually observe the public-key gate live.

5. Capture raw USB traffic in parallel, regardless of app-level output — this
   is the ground truth if anything above doesn't match expectations:
   ```
   sudo modprobe usbmon
   cat /sys/kernel/debug/usb/usbmon/<bus>u > capture.mon   # or use wireshark/usbmon-capture
   ```

## Known simplifications (likely to need revisiting)

- **No true re-enumeration after `Start`.** A real Android phone stays at a
  generic VID/PID until `AOA_START`, then detaches and re-enumerates
  presenting Google's `0x18d1` vendor ID. This scaffold takes a shortcut and
  declares `0x18d1`/`0x2d00` from the very first enumeration, keeping the
  same static gadget/descriptors throughout. If the head unit's
  `vncbearer-USBAAP.dll` specifically watches for that VID/PID *transition*
  (rather than just probing any device with `GetProtocol` and checking the
  response), this will need a second gadget profile and a UDC unbind/rebind
  triggered from `aoa_gadget.c` on receiving `AOA_START`.
- **HID and audio AOA extensions are stubbed, not implemented** (`AOA_
  REGISTER_HID` etc.) — not expected to matter for this test, but logged if
  seen so we'd notice.
- **wMaxPacketSize / bInterval values are reasonable defaults, not verified**
  against what `vncbearer-USBAAP.dll` actually expects — RFB doesn't have
  strict timing requirements, so this is a low-risk guess, but worth
  reviewing if throughput looks wrong once real data flows.
- No RFB server logic at all yet — the bulk IN endpoint is opened but never
  written to. Once we've confirmed we're receiving bytes worth responding
  to, the next milestone is a minimal RFB `ProtocolVersion` reply to see if
  the head unit continues past that.
