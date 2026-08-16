#!/bin/bash
# Safely read back whatever the head unit wrote into the mass-storage image.
#
# Because USB Mass Storage is block-level, we must make sure the head unit has RELEASED the disk
# before the Pi touches the filesystem, or we read a half-written FAT. Steps:
#   1. Eject the LUN on the gadget side (detach the backing file). This makes the head unit see the
#      "stick" disappear, forcing its FAT driver to flush and drop its cache. Do this only AFTER the
#      head unit's Log Copy shows "complete".
#   2. Loop-mount the image READ-ONLY on the Pi and copy the files out.
#   3. Re-attach the file so the gadget is ready for the next dump.
#
# Run as root on the Pi, from pi/msd-gadget/.

set -euo pipefail

GADGET_DIR="/sys/kernel/config/usb_gadget/msd0"
LUN="$GADGET_DIR/functions/mass_storage.0/lun.0"
IMG="/opt/9carplay/logdisk.img"
MNT="/mnt/logdisk"
OUT="${1:-./dump-$(date +%Y%m%d-%H%M%S)}"

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

echo "[1/3] Ejecting LUN so the head unit flushes and releases the disk ..."
# forced_eject exists on newer kernels; fall back to clearing 'file'.
if [[ -e "$LUN/forced_eject" ]]; then
    echo 1 > "$LUN/forced_eject" || echo "" > "$LUN/file"
else
    echo "" > "$LUN/file"
fi
sync
sleep 1

echo "[2/3] Loop-mounting image read-only and copying out to $OUT ..."
mkdir -p "$MNT" "$OUT"
# Fresh loop mount reads current blocks straight from the file (no stale Pi page cache concern,
# since we never mounted it while the head unit was writing).
mount -o loop,ro "$IMG" "$MNT"
cp -a "$MNT"/. "$OUT"/ 2>/dev/null || true
ls -la "$OUT"
umount "$MNT"

echo "[3/3] Re-attaching backing file so the gadget is ready for the next dump ..."
echo "$IMG" > "$LUN/file"

echo "Done. Logs are in: $OUT"
echo "Decode WinCE cyclic logs with:  LC_ALL=C strings -n 4 <file>   (or  tr '\\r' '\\n')"
