# pi/msd-gadget — Pi as a USB thumb drive for head-unit log capture

Makes the Raspberry Pi present to the head unit as a **removable USB Mass Storage Device** (a
"thumb drive"), backed by a FAT32 image file, so the head unit's Dealer Diagnostic Mode
**"Log Copy to USB"** (`UIDiag_LogCopyHONDA_GLB`) writes its logs *into the Pi* — no physical thumb
drive, and no unplugging the Pi (it is already in this USB port for power).

This is the **connect-the-Pi-then-immediately-dump** capture that
[`../../references/cr-v/IMPLEMENTATION_PLAN.md`](../../references/cr-v/IMPLEMENTATION_PLAN.md)
Phase 1a needs to see *which* `NotifyStartSmartPhoneApps` guard fails for a live Pi connection.

## Why it's safe to run alongside the iAP1 bridge

The iAP1 app path is over **Bluetooth**; this gadget is over **USB**. They don't touch each other,
so the Pi can be the iAP1 bridge (BT) and the log-dump target (USB-MSD) *at the same time*. In one
car-on cycle you can: bring up the BT iAP1 connection, let the app gate fail, then Log Copy →
`read_logs.sh` and read the head unit's own `[LPAApp]` guard-failure line for that exact connection.

## Prerequisites

- One-time dwc2 peripheral mode: `dtoverlay=dwc2,dr_mode=peripheral` (see
  [`../step-1-commands.md`](../step-1-commands.md) step 0).
- Only one gadget can bind the UDC at a time — tear down any AOA (`../aoa-gadget/`) or NCM
  (`../mirrorlink-ncm/`) gadget first.
- `dosfstools` for `mkfs.vfat` (`sudo apt install dosfstools`).

## Usage

```bash
# 1. Build the gadget + backing image, then bind the UDC (setup prints the exact bind line).
sudo ./setup_msd_gadget.sh            # override size with e.g. IMG_SIZE_MB=2048 sudo -E ./setup_msd_gadget.sh
sudo sh -c 'echo $(ls /sys/class/udc | head -1) > /sys/kernel/config/usb_gadget/msd0/UDC'

# 2. On the head unit: Diagnostic Mode -> Log Copy. WAIT for its "complete" screen.

# 3. Pull the logs back out (ejects the LUN so the head unit flushes, then reads read-only).
sudo ./read_logs.sh                   # writes to ./dump-YYYYmmdd-HHMMSS/  (or pass a dir)
```

Decode the WinCE cyclic logs:

```bash
LC_ALL=C strings -n 4 dump-*/SER_MSG.LOG      # or:  tr '\r' '\n' < file
```

## The one non-obvious rule: block-level, not file-level

USB Mass Storage exposes **raw sectors**, not files. While the head unit has the disk mounted, *it*
owns the FAT filesystem and caches blocks in its own RAM; the Pi only sees the image.

**Do not loop-mount the image on the Pi while the head unit is still using it** — you'll read a
half-written FAT and can corrupt it. `read_logs.sh` handles this correctly: it first ejects the LUN
(forcing the head unit's FAT driver to flush and release), *then* loop-mounts read-only. There is no
gadget-side "host finished writing" event, so the head unit's **"complete"** screen is your signal
to run `read_logs.sh`.

## Files

- `setup_msd_gadget.sh` — creates the FAT32 image (`/opt/9carplay/logdisk.img`, default 1 GB) and
  the `mass_storage.0` configfs gadget (removable, writable, label `LOGDISK`).
- `read_logs.sh` — ejects the LUN, loop-mounts the image read-only, copies files out, re-attaches.

## Caveats

- Some WinCE head units auto-scan a freshly-inserted drive as a media source. Keeping the image
  empty (blank FAT) avoids it getting distracted; a "USB device" audio-source prompt, if it appears,
  is cosmetic.
- Delete `/opt/9carplay/logdisk.img` to start from a clean drive; `setup_msd_gadget.sh` reuses an
  existing image so prior dumps aren't clobbered.
