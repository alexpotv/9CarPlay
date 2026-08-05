# Step 1 — Validating USB peripheral (AOA gadget) mode on the Pi

This is the command sequence that got the Pi 5 successfully enumerating as a
USB gadget against a known-good host (a Mac), confirmed via `BIND`/`ENABLE`
events on the Pi side and `ioreg`/`system_profiler` showing the device on the
host side. This validates dwc2 peripheral mode works on this hardware, before
ever touching the actual head unit. See `pi/aoa-gadget/README.md` for full
background and `references/cr-v/PROJECT_PLAN.md` (Phase 2) for how this fits
into the overall project.

## 0. One-time setup (before first run only)

Edit `/boot/firmware/config.txt`:
- Ensure a `dtoverlay=dwc2,dr_mode=peripheral` line exists under a section
  that actually applies to this board (`[pi5]` or `[all]` — **not** `[cm5]`
  or another board-specific section that won't match a plain Pi 5).
- Remove/zero out any `otg_mode=1` line — that setting forces the USB-C port
  into host mode, which is the opposite of what we need for gadget/peripheral
  mode.

Reboot, then confirm the controller is visible:
```
ls /sys/class/udc
```
If this prints nothing, peripheral mode isn't bound and nothing below will
work — stop and fix this first.

Install build tools and load the gadget framework kernel module:
```
sudo apt install -y build-essential
sudo modprobe libcomposite
```

Build the userspace daemon (from `pi/aoa-gadget/`):
```
make
```

## 1. Create the USB gadget (configfs)

```
sudo ./setup_gadget.sh
```
Sets up the configfs gadget tree (`/sys/kernel/config/usb_gadget/aoa0`),
declares the AOA vendor/product IDs (`0x18d1`/`0x2d00`), and mounts the
FunctionFS endpoint at `/dev/ffs-aoa0`. This does **not** start enumeration
yet — the UDC isn't bound at this point, so the host doesn't see anything.

## 2. Start the AOA daemon (leave running in its own shell)

```
sudo ./aoa_gadget /dev/ffs-aoa0
```
Writes USB descriptors and strings to `ep0`, then opens the bulk IN/OUT
endpoints. Must reach "Descriptors written and all endpoints opened" **before**
step 4 — binding the UDC triggers enumeration and the host starts probing
immediately, so the daemon needs to already be ready to answer.

Once running, it prints live handshake events (`BIND`, `ENABLE`,
`GetProtocol`, `SendString`, `AOA_START`, etc.) and captures whatever bytes
the host sends afterward to `aoa_capture.bin`.

## 3. Find the UDC name

In a second shell:
```
ls /sys/class/udc
```
Prints the name of the peripheral-mode USB controller (needed for the next
step).

## 4. Bind the UDC to start enumeration

```
echo <udc-name> | sudo tee /sys/kernel/config/usb_gadget/aoa0/UDC
```
This is the moment enumeration actually starts — the host (Mac, or later the
head unit) will now see the device and begin probing it. Watch the
`aoa_gadget` shell from step 2 for `[event] BIND` / `[event] ENABLE`.

## 5. Verify from the host side

On a Mac:
```
ioreg -p IOUSB -w0
```
or
```
system_profiler SPUSBDataType | grep -A8 -i "0x18d1\|AOA Bridge"
```
Look for `AOA Bridge (dev)` as a `registered, matched, active` device — this
confirms the host's USB stack accepted our descriptors as valid, not just
that dwc2 completed low-level enumeration.

## Next step: testing against the head unit instead of a generic host

A generic Mac/PC host won't exercise the actual AOA protocol (`GetProtocol`/
`SendString`) — only an AOA-aware host does that. The real test is repeating
steps 1–4 with the Pi's peripheral port connected to the **head unit**
instead.

**Correction:** an earlier version of this doc suggested capturing with
`usbmon` here (`sudo cat /sys/kernel/debug/usb/usbmon/<bus>u > capture.mon`).
That doesn't apply to this link — `usbmon` only captures traffic on buses
where **the Pi itself is acting as USB host**. On this connection the head
unit is the host and the Pi is the peripheral, so there is no bus on the Pi
side carrying this traffic; no `<bus>u` file corresponds to it no matter
which number you pick.

The actual ground truth for this link is `aoa_gadget`'s own logging, which
already sees everything addressed to us:
- Every control request on `ep0` prints a `[setup] bRequestType=... bRequest=...`
  line (`handle_setup()`), recognized or not — if `GetProtocol`/`SendString`/
  `Start` never appear here, the head unit genuinely never sent them.
- Every read on the bulk OUT endpoint (`ep1`) is hex-dumped to the console and
  appended to `aoa_capture.bin`, independent of whether any AOA control
  request happened first (this used to be gated behind seeing `AOA_START`,
  which hid the case where the head unit skips discovery and just starts
  writing bulk data — since our gadget already presents at the AOA accessory
  VID/PID `0x18d1`/`0x2d00` from first enumeration instead of the two-stage
  switch a real phone does; see `pi/aoa-gadget/README.md` "Known
  simplifications"). Fixed by polling `ep0` and non-blockingly reading `ep1`
  concurrently in the main loop.

If you have access to the head unit's diagnostics menu, watch it alongside
`aoa_gadget`'s console — it shows the head unit's own interpretation of
connection state, which is the most direct signal for "how far did this get."

## Doing a clean restart between test attempts

`setup_gadget.sh` is **not** safe to re-run on top of an already-bound
gadget — it will fail (e.g. `ln: failed to create symbolic link
'configs/c.1/ffs.aoa0': File exists`) because configfs won't let you modify
a gadget's structure while it's bound to a UDC. Tear down fully before
retrying:
```
sudo pkill -f aoa_gadget || true
echo "" | sudo tee /sys/kernel/config/usb_gadget/aoa0/UDC
sudo umount /dev/ffs-aoa0
sudo rm -f /sys/kernel/config/usb_gadget/aoa0/configs/c.1/ffs.aoa0
sudo rmdir /sys/kernel/config/usb_gadget/aoa0/functions/ffs.aoa0
sudo rmdir /sys/kernel/config/usb_gadget/aoa0/configs/c.1/strings/0x409
sudo rmdir /sys/kernel/config/usb_gadget/aoa0/configs/c.1
sudo rmdir /sys/kernel/config/usb_gadget/aoa0/strings/0x409
sudo rmdir /sys/kernel/config/usb_gadget/aoa0
```
Confirm clean (`ls /sys/kernel/config/usb_gadget/` and `mount | grep ffs`
should both show nothing), then repeat steps 1–4 from scratch.
