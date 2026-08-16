#!/bin/bash
# Presents the Raspberry Pi to the head unit as a USB Mass Storage Device (a "thumb drive"),
# backed by a FAT32 image file. The head unit's Dealer Diagnostic Mode "Log Copy to USB"
# (UIDiag_LogCopyHONDA_GLB) then writes its log files INTO that image — no physical thumb drive,
# and no unplugging the Pi (which is already in this same USB port for power).
#
# This uses Linux's built-in usb_f_mass_storage kernel gadget function via configfs — the same
# mechanism as pi/mirrorlink-ncm/setup_ncm_gadget.sh, just a different function. It is INDEPENDENT
# of the iAP1-over-Bluetooth bridge (that path is Bluetooth, not USB), so the Pi can be the iAP1
# bridge over BT and the log-dump target over USB at the same time.
#
# Prereqs: the same one-time dwc2 peripheral-mode setup as the other gadgets
# (dtoverlay=dwc2,dr_mode=peripheral — see pi/step-1-commands.md step 0). Only one gadget can bind
# the UDC at a time: tear down any AOA/NCM gadget first (their README "clean restart" sections).
#
# Run as root on the Pi.
#
# READING THE LOGS BACK — READ THIS, it is the one non-obvious part:
#   USB Mass Storage is BLOCK-level. While the head unit has the disk mounted, IT owns the FAT
#   filesystem and caches blocks in its own RAM; the Pi only sees the raw image. Do NOT loop-mount
#   the image on the Pi while the head unit is still using it — you will read stale/inconsistent
#   data and can corrupt the filesystem. Correct sequence:
#     1. Run this script, then bind the UDC (cycle_usb.sh / the bind line below).
#     2. On the head unit: Diagnostic Mode -> Log Copy. Wait for its "complete" screen.
#     3. On the Pi: run  ./read_logs.sh  (it ejects the LUN so the head unit flushes, then
#        loop-mounts the image read-only and copies the files out).
#   There is no gadget-side "host finished writing" event, so step 2's completion is your signal.

set -euo pipefail

GADGET_NAME="msd0"
GADGET_DIR="/sys/kernel/config/usb_gadget/${GADGET_NAME}"
IMG="/opt/9carplay/logdisk.img"
IMG_SIZE_MB="${IMG_SIZE_MB:-1024}"      # size of the fake drive; override: IMG_SIZE_MB=2048 ./setup_msd_gadget.sh
VOL_LABEL="LOGDISK"

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

# --- backing image (only (re)create if missing; keep existing dumps otherwise) ---
mkdir -p "$(dirname "$IMG")"
if [[ ! -f "$IMG" ]]; then
    echo "Creating ${IMG_SIZE_MB}MB FAT32 backing image at $IMG ..."
    dd if=/dev/zero of="$IMG" bs=1M count="$IMG_SIZE_MB" status=progress
    # A plain FAT filesystem on the whole image (no partition table) is what most head units and
    # card-reader-style USB sticks present; the WinCE FAT driver mounts it directly.
    mkfs.vfat -F 32 -n "$VOL_LABEL" "$IMG"
else
    echo "Reusing existing backing image $IMG (delete it to start clean)."
fi

modprobe libcomposite

mkdir -p "$GADGET_DIR"
cd "$GADGET_DIR"

# Generic mass-storage identity. Some head units index/scan a newly-inserted drive; a well-known
# vendor/product string keeps that boring. Tune later only if the unit rejects the device.
echo 0x0781 > idVendor      # SanDisk-ish generic VID (cosmetic; change freely)
echo 0x5567 > idProduct
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB

mkdir -p strings/0x409
echo "000000009CP1"          > strings/0x409/serialnumber
echo "9CarPlay"              > strings/0x409/manufacturer
echo "Log Dump Disk"         > strings/0x409/product

mkdir -p configs/c.1/strings/0x409
echo "MSD config"            > configs/c.1/strings/0x409/configuration
echo 250                     > configs/c.1/MaxPower

mkdir -p functions/mass_storage.0
# lun.0 tuning:
#   removable=1 : head unit treats it as an ejectable USB stick (and lets us eject on our side).
#   ro=0        : head unit can write (the whole point).
#   cdrom=0     : it's a disk, not an optical drive.
#   nofua=1     : tolerate the head unit not sending Force-Unit-Access; slightly faster, fine here.
echo 1 > functions/mass_storage.0/lun.0/removable
echo 0 > functions/mass_storage.0/lun.0/ro
echo 0 > functions/mass_storage.0/lun.0/cdrom
echo 1 > functions/mass_storage.0/lun.0/nofua
echo "$IMG" > functions/mass_storage.0/lun.0/file

ln -sf functions/mass_storage.0 configs/c.1/

echo "Gadget configfs tree created at $GADGET_DIR (mass_storage.0 -> $IMG)."
echo
echo "Now bind the UDC to go live:"
UDC="$(ls /sys/class/udc | head -n1 || true)"
if [[ -n "${UDC:-}" ]]; then
    echo "  echo $UDC > $GADGET_DIR/UDC        # (or use pi/mirrorlink-ncm/cycle_usb.sh style)"
else
    echo "  (no UDC found under /sys/class/udc — check dwc2 peripheral mode, pi/step-1-commands.md)"
fi
echo
echo "The head unit should now enumerate a removable USB drive labelled '$VOL_LABEL'."
echo "After running its Log Copy and seeing 'complete', run:  sudo ./read_logs.sh"
