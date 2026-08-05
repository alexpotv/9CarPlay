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

## Two modes — which one to use

There are now **two** independent gadget setups in this directory. They are
not interchangeable — mixing a setup script with the wrong binary will leave
the gadget in a state neither program expects.

| | Direct (original) | Two-stage (current recommendation) |
|---|---|---|
| Setup script | `setup_gadget.sh` | `setup_gadget_twostage.sh` |
| Daemon | `aoa_gadget` | `aoa_gadget_twostage` |
| Starting identity | Google's AOA accessory ID (`0x18d1`/`0x2d00`) from the first enumeration | A generic placeholder ID (`0x1d6b`/`0x0104`), switched to the accessory ID automatically on `AOA_START` |
| Status against real head unit | **Confirmed insufficient** — completes standard enumeration (`BIND`/`ENABLE`) but the head unit never sends any AOA control request or bulk data afterward | Untested on real hardware yet — implements the two-stage identity switch believed to be required (see below) |
| Still useful for | Quick sanity checks that dwc2 peripheral mode itself works (e.g. against a generic Mac/PC host) | The actual head-unit test going forward |

**Why two-stage exists**: a live test using `aoa_gadget`/`setup_gadget.sh`
against the real CR-V head unit got as far as full standard USB enumeration
(`BIND`, `ENABLE` — meaning the head unit successfully read our descriptors
and activated our interface) but the head unit's MirrorLink-specific
discovery layer never engaged with us afterward at all — no
`GetProtocol`/`SendString`/`Start` control requests, and no bulk-endpoint
traffic either. The leading explanation is the "Known simplifications" item
below: real Android phones enumerate under a generic identity first, and
only switch to Google's accessory identity (`0x18d1`/`0x2d00`) *after* the
host has driven them through the `GetProtocol`/`SendString`/`Start`
handshake. A device that skips straight to the post-switch identity (what
`aoa_gadget` does) is likely invisible to a discovery layer that only
recognizes an accessory session it has itself witnessed being established —
explaining both the missing control requests (not a discovery candidate,
already at the "done" identity) and the missing bulk data (never recognized
as an established accessory either, since the switch handshake never
happened through this head unit).

`aoa_gadget_twostage` reproduces the real sequence: enumerate generic →
respond to `GetProtocol`/`SendString` → on `Start`, unbind the UDC, rewrite
`idVendor`/`idProduct` in configfs to the accessory identity, and rebind —
same FunctionFS interface/endpoint descriptors throughout, since the VID/PID
switch is a configfs-gadget-level attribute change, not a FunctionFS
descriptor change.

## What's here

- `setup_gadget.sh` — configfs script for the **direct** mode: creates the
  gadget already at the AOA accessory identity. Pair with `aoa_gadget` only.
- `setup_gadget_twostage.sh` — configfs script for the **two-stage** mode:
  creates the gadget at a generic placeholder identity. Pair with
  `aoa_gadget_twostage` only.
- `aoa_gadget.c` — the direct-mode userspace daemon: writes USB descriptors
  (one vendor-class interface, one bulk OUT + one bulk IN endpoint) and
  strings to `ep0`, handles the AOA control requests
  (`GetProtocol`/`SendString`/`Start`), then watches `ep0` and the bulk OUT
  endpoint concurrently, hex-dumping and raw-capturing (`aoa_capture.bin`)
  anything received on either.
- `aoa_gadget_twostage.c` — the two-stage-mode userspace daemon: same
  control-request handling as `aoa_gadget.c`, but on receiving `AOA_START`
  it performs the unbind/rewrite-identity/rebind switch itself
  (`perform_switch()`) instead of just logging and continuing at the same
  identity. **Untested on real hardware** — the switch sequence is a
  best-effort reproduction of what a real phone's kernel driver does
  internally, not yet validated against a live dwc2 controller or the head
  unit.
- `Makefile` — `make` (or `make all`) builds both `aoa_gadget` and
  `aoa_gadget_twostage` with plain `gcc`.

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

## Running the direct-mode test (`aoa_gadget` / `setup_gadget.sh`)

Kept as a fallback / quick sanity check that dwc2 peripheral mode itself
works — **confirmed insufficient on its own** against the real head unit
(see "Two modes" above). Use the two-stage test below for actual head-unit
testing going forward.

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

4. Watch `aoa_gadget`'s output — it now watches `ep0` and the bulk OUT
   endpoint concurrently, so any traffic on either shows up without needing
   to wait for `AOA_START` first. Useful outcomes, weakest to strongest
   signal:
   - Nothing at all / no `[event] ENABLE` — the head unit isn't probing this
     port the way we expect, or the descriptors are wrong.
   - `ENABLE` but no `[setup]` line and no bulk data — **this is what we
     actually observed against the real head unit.** Standard enumeration
     completes but the MirrorLink discovery layer never engages. See "Two
     modes" above for why, and use the two-stage test instead.
   - `GetProtocol` handled, `SendString` logs show
     `manufacturer = "RealVNC"` etc — confirms the discovery/AOA layer works
     exactly as expected from the firmware strings. This alone is a real
     milestone.
   - `AOA_START` received, then bytes show up on the bulk endpoint —
     we're now receiving the head unit's side of whatever comes next
     (expected: RFB `ProtocolVersion` handshake, `"RFB 003.008\n"` or
     similar). This is where we'd actually observe the public-key gate live.

Note: `usbmon` does **not** apply to this link — it only captures traffic on
buses where the Pi itself is acting as USB host. Here the head unit is the
host and the Pi is the peripheral, so there's no bus on the Pi side carrying
this traffic. `aoa_gadget`'s own `[setup]`/bulk-data logging is the ground
truth for this connection.

## Running the two-stage test (`aoa_gadget_twostage` / `setup_gadget_twostage.sh`)

This is the current recommended test against the head unit — see "Two
modes" above for why. **Untested on real hardware as of writing.**

1. Full clean teardown first if a gadget from a previous run (either mode)
   is still present — configfs won't let you set up a new gadget on top of
   a bound one:
   ```
   sudo pkill -f 'aoa_gadget|aoa_gadget_twostage' || true
   echo "" | sudo tee /sys/kernel/config/usb_gadget/aoa0/UDC
   sudo umount /dev/ffs-aoa0
   sudo rm -f /sys/kernel/config/usb_gadget/aoa0/configs/c.1/ffs.aoa0
   sudo rmdir /sys/kernel/config/usb_gadget/aoa0/functions/ffs.aoa0
   sudo rmdir /sys/kernel/config/usb_gadget/aoa0/configs/c.1/strings/0x409
   sudo rmdir /sys/kernel/config/usb_gadget/aoa0/configs/c.1
   sudo rmdir /sys/kernel/config/usb_gadget/aoa0/strings/0x409
   sudo rmdir /sys/kernel/config/usb_gadget/aoa0
   ```

2. On the Pi (not yet connected to the head unit):
   ```
   sudo ./setup_gadget_twostage.sh
   make
   sudo ./aoa_gadget_twostage /dev/ffs-aoa0
   ```
   Wait for "Descriptors written and all endpoints opened" before binding.

3. In a second shell, bind the UDC — same as direct mode:
   ```
   ls /sys/class/udc
   echo <udc-name> | sudo tee /sys/kernel/config/usb_gadget/aoa0/UDC
   ```
   This is the **only** manual bind needed — if the head unit sends
   `AOA_START`, `aoa_gadget_twostage` performs the unbind/identity-rewrite/
   rebind switch itself (`perform_switch()`), no further manual UDC action
   required.

4. Connect to the head unit, same as direct mode, and watch the console:
   - `[setup]` lines for `GetProtocol`/`SendString` — the discovery layer is
     engaging with us this time, a real milestone the direct-mode test never
     reached.
   - `[switch] ...` lines — the identity switch is happening. Watch for a
     fresh `BIND`/`ENABLE` cycle afterward (the head unit re-enumerating us
     at the new identity), then `[setup]` or bulk-data lines for whatever
     comes next.
   - If the switch fails partway (see `[switch] failed ...` messages), the
     gadget may be left in an inconsistent state — do the full teardown from
     step 1 before retrying, don't just restart the daemon.

## Known simplifications (likely to need revisiting)

- ~~**No true re-enumeration after `Start`.**~~ **Addressed** by
  `aoa_gadget_twostage`/`setup_gadget_twostage.sh` — see "Two modes" above.
  Still open: the *specific* generic placeholder identity used
  (`0x1d6b`/`0x0104`) is a guess, not confirmed to match what
  `vncbearer-USBAAP.dll` expects a pre-switch device to look like; revisit
  if two-stage mode still doesn't get a response.
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
