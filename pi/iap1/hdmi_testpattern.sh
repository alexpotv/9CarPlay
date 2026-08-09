#!/bin/bash
# Pushes a static test pattern out the Pi's HDMI output — the "AV via HDMI" leg of Honda's patent
# (US9116563B2) architecture. Per references/cr-v/PROTOCOL_ANALYSIS.md ("HDMI side: no
# protocol-specific negotiation found"), the head unit's HDMI input handling
# (UIAVSystem_HDMIConnect/UIAVSystem_HDMIConnectInfoRequest/UIAVSystem_HDMIDisplaySize) is generic
# AUX/HDMI-source plumbing with no tie to the iAP/MFi authentication state at the protocol level —
# so unlike the USB side, there is nothing to reverse-engineer here: any standard HDMI output
# should work once the head unit's UI is switched to the HondaLink/phone-app video source. This
# script exists only to give iap1_daemon.py's USB-side testing something visible to confirm
# against on the actual screen — it is intentionally NOT wired to anything the USB daemon sends.
#
# Run directly on the Pi. Tries a few common approaches in order of preference and uses whichever
# is available — kept deliberately simple ("very light and generic") since there's no protocol
# requirement driving this, just "put a visible, obviously-alive image on the screen."

set -euo pipefail

echo "Looking for a way to drive HDMI output..."

if command -v ffmpeg >/dev/null 2>&1 && command -v ffplay >/dev/null 2>&1; then
    echo "Using ffmpeg testsrc via ffplay (fullscreen SMPTE-ish color bars + timestamp)."
    exec ffplay -f lavfi -i "testsrc=size=1280x720:rate=30" -fs -autoexit -loglevel warning
fi

if command -v fbi >/dev/null 2>&1; then
    echo "Using fbi to display a generated test image on the framebuffer."
    TMP_PNG="$(mktemp --suffix=.png)"
    if command -v convert >/dev/null 2>&1; then
        convert -size 1280x720 gradient:blue-red -gravity center \
            -pointsize 72 -fill white -annotate 0 "9CarPlay iAP1 test" "$TMP_PNG"
    else
        # No ImageMagick either — fall through to the raw framebuffer path below instead.
        rm -f "$TMP_PNG"
    fi
    if [[ -f "$TMP_PNG" ]]; then
        exec fbi -T 1 -noverbose -a "$TMP_PNG"
    fi
fi

if [[ -e /dev/fb0 ]]; then
    echo "Falling back to writing raw color bars directly to /dev/fb0 via Python."
    exec python3 - <<'EOF'
import struct
import sys

FB = "/dev/fb0"
# Best-effort: assume a common 32bpp framebuffer at a reported resolution from sysfs; fall back
# to a conservative 1280x720 guess if that's not readable. This is intentionally minimal — the
# goal is "something visibly changes on the HDMI output," not a general-purpose framebuffer tool.
try:
    with open("/sys/class/graphics/fb0/virtual_size") as f:
        w, h = (int(x) for x in f.read().strip().split(","))
except Exception:
    w, h = 1280, 720

bar_colors = [
    (255, 255, 255), (255, 255, 0), (0, 255, 255), (0, 255, 0),
    (255, 0, 255), (255, 0, 0), (0, 0, 255), (0, 0, 0),
]
bar_w = max(1, w // len(bar_colors))

row = bytearray()
for x in range(w):
    r, g, b = bar_colors[min(x // bar_w, len(bar_colors) - 1)]
    row += struct.pack("<BBBB", b, g, r, 0)  # BGRA, common for 32bpp Linux fbdev

with open(FB, "wb") as fb:
    for _ in range(h):
        fb.write(row)

print(f"Wrote {w}x{h} color bars to {FB}")
EOF
fi

echo "No supported HDMI output method found (checked ffmpeg+ffplay, fbi(+ImageMagick), /dev/fb0)." >&2
echo "Install one of: 'sudo apt install ffmpeg' or 'sudo apt install fbi imagemagick'." >&2
exit 1
