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

# Preferred method: have ffmpeg write frames straight into /dev/fb0 via its fbdev muxer. This
# talks directly to the kernel framebuffer device — no SDL, no window system, no GBM/EGL/GL
# context — so it sidesteps both failure modes ffplay hit on this headless Pi ("Couldn't find
# matching render driver" with the default driver, then "EGL not initialized" once forced onto
# kmsdrm, which needs a working GBM/Mesa GLES stack that isn't guaranteed to be set up).
if command -v ffmpeg >/dev/null 2>&1 && [[ -e /dev/fb0 ]]; then
    echo "Using ffmpeg's fbdev muxer to write straight to /dev/fb0 (no SDL/EGL involved)."
    FB_W=1280
    FB_H=720
    if [[ -r /sys/class/graphics/fb0/virtual_size ]]; then
        IFS=',' read -r FB_W FB_H < /sys/class/graphics/fb0/virtual_size
    fi
    BPP=32
    if [[ -r /sys/class/graphics/fb0/bits_per_pixel ]]; then
        BPP="$(cat /sys/class/graphics/fb0/bits_per_pixel)"
    fi
    case "$BPP" in
        16) PIXFMT=rgb565le ;;
        24) PIXFMT=bgr24 ;;
        32) PIXFMT=bgra ;;
        *) PIXFMT=bgra ;;
    esac
    echo "Framebuffer: ${FB_W}x${FB_H} @ ${BPP}bpp -> pix_fmt=$PIXFMT"
    # A single static frame, not a continuous stream: every other method in this script (fbi,
    # the raw Python writer below) just paints one image and stops, matching the actual goal
    # ("something visibly changes on the screen," not live video). Streaming testsrc at 30fps
    # meant re-running swscale's chroma-to-RGB565 conversion every frame, which was heavy enough
    # on the Pi's CPU to cause visible lag and, per a live trial, a crash. One frame is instant
    # and avoids that entirely.
    if ffmpeg -f lavfi -i "testsrc=size=${FB_W}x${FB_H}" -frames:v 1 -pix_fmt "$PIXFMT" \
        -f fbdev -y /dev/fb0 -loglevel warning; then
        echo "Wrote one static frame to /dev/fb0."
        exit 0
    fi
    echo "ffmpeg fbdev output failed — are you root, and is nothing else (a desktop session, " >&2
    echo "another ffmpeg/fbi) already holding /dev/fb0? Falling through to the next method." >&2
fi

# ffplay renders through SDL2, which defaults to looking for an X11/Wayland session. On a
# headless Pi (no desktop session running) there is none, so SDL falls through to a driver that
# can't actually put pixels on the HDMI output ("Couldn't find matching render driver") and warns
# about XDG_RUNTIME_DIR along the way. Fix: point SDL straight at the KMS/DRM output (the same
# framebuffer console output uses) and make sure XDG_RUNTIME_DIR exists, since SDL still checks
# for it even in this mode. Kept as a fallback below the fbdev method above, since kmsdrm still
# needs a working GBM/EGL/GLES stack that the fbdev method doesn't depend on at all.
if [[ -z "${XDG_RUNTIME_DIR:-}" || ! -d "${XDG_RUNTIME_DIR:-/nonexistent}" ]]; then
    export XDG_RUNTIME_DIR="/tmp/xdg-runtime-$(id -u)"
    mkdir -p "$XDG_RUNTIME_DIR"
    chmod 700 "$XDG_RUNTIME_DIR"
fi
export SDL_VIDEODRIVER=kmsdrm

if command -v ffmpeg >/dev/null 2>&1 && command -v ffplay >/dev/null 2>&1; then
    echo "Using ffmpeg testsrc via ffplay (fullscreen SMPTE-ish color bars + timestamp)."
    echo "SDL_VIDEODRIVER=$SDL_VIDEODRIVER XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"
    # Not exec'd here (unlike the other branches below): a plain call lets us detect ffplay/SDL
    # failing at runtime (wrong driver, DRM master already held, etc.) and fall through to the
    # next method instead of the whole script just exiting on a bad exit code.
    if ffplay -f lavfi -i "testsrc=size=1280x720:rate=30" -fs -autoexit -loglevel warning; then
        exit 0
    fi
    echo "ffplay/kmsdrm failed (are you in the 'video'/'render' group, and is nothing else " >&2
    echo "holding the DRM master, e.g. a desktop session or another ffplay)? Falling through " >&2
    echo "to the next method." >&2
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
