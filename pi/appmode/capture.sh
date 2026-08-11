#!/usr/bin/env bash
# capture.sh — guided btmon capture for an AppMode / HondaLink trial (run this ON THE PI).
#
# It walks you through a single capture: starts btmon, tells you exactly what to do on the head unit,
# waits for you to finish, stops btmon, converts to text, and runs the AppMode extractor so you
# immediately see any DataParts frames and the Bluetooth-layer events that matter.
#
# Usage:   sudo ./capture.sh [label]
#   label  optional short name for this run (default: timestamp)
#
# Output goes to ../../references/guided/btmon/<label>.{btsnoop,txt}
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$(cd "$HERE/../../references/guided/btmon" 2>/dev/null && pwd || echo "$HERE")"
LABEL="${1:-appmode_$(date +%Y%m%d_%H%M%S)}"
SNOOP="$OUTDIR/$LABEL.btsnoop"
TXT="$OUTDIR/$LABEL.txt"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
ask()  { printf '\n\033[1;33m??  %s\033[0m ' "$*"; }

# --- preflight -------------------------------------------------------------
if ! command -v btmon >/dev/null 2>&1; then
  echo "ERROR: btmon not found. Install bluez tools (apt-get install bluez)." >&2
  exit 1
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: run this on the Pi (Linux); btmon is Linux-only." >&2
  exit 1
fi
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: run with sudo (btmon needs CAP_NET_RAW). Try: sudo $0 $*" >&2
  exit 1
fi

step "Capture label: $LABEL"
info "btsnoop -> $SNOOP"
info "text    -> $TXT"

step "What this run captures"
info "A full HondaLink trial so we can see the AppMode DataParts handshake on the SPP channel."
info "You will: start the iAP harness, arm the hypothesis, launch HondaLink, and let it run until"
info "the on-screen error appears (~60-90s), then a bit longer so the post-auth traffic is captured."

ask "Ready to start btmon? [Enter]"; read -r _

# --- start btmon in the background ----------------------------------------
step "Starting btmon (capturing ALL controllers)"
btmon -w "$SNOOP" >/dev/null 2>&1 &
BTMON_PID=$!
sleep 1
if ! kill -0 "$BTMON_PID" 2>/dev/null; then
  echo "ERROR: btmon failed to start." >&2
  exit 1
fi
info "btmon running (pid $BTMON_PID)."

cat <<'EOF'

    Now, in OTHER terminals on the Pi, do the trial:
      1. Ensure HDMI is being driven from the Pi (pi/iap1/hdmi_testpattern.sh) so the head unit
         does not bail out with the "HDMI not connected" error.
      2. Start the HFP AG + iAP harness:
            python3 ../iap1/hfp_ag.py                 (if used in your setup)
            python3 ../iap1/btsdp_iap_guided.py
      3. ARM the hypothesis at the prompt, then on the head unit launch "HondaLink".
      4. Let it run until the "cannot connect via Bluetooth" error shows, THEN wait ~15 more
         seconds (so any retry / post-auth SPP traffic is captured).
EOF

ask "When the trial is done (error shown + ~15s), press [Enter] to STOP btmon."; read -r _

# --- stop btmon ------------------------------------------------------------
step "Stopping btmon"
kill "$BTMON_PID" 2>/dev/null || true
wait "$BTMON_PID" 2>/dev/null || true
sync
if [[ ! -s "$SNOOP" ]]; then
  echo "ERROR: capture file is empty ($SNOOP)." >&2
  exit 1
fi
info "Saved $(du -h "$SNOOP" | cut -f1) capture."

# --- convert + analyze -----------------------------------------------------
step "Converting to human-readable text"
btmon -r "$SNOOP" > "$TXT" 2>/dev/null || true
info "Wrote $TXT"

step "Scanning for AppMode DataParts frames + BT events"
python3 "$HERE/sniff_capture.py" "$SNOOP" || true

echo
step "Quick Bluetooth-layer grep (SDP for AppMode UUIDs / RFCOMM connect/disconnect)"
grep -niE "fa592c6e|453994d5|deca-fade|SABM|DISC|UA |Disconnect|Service Search" "$TXT" 2>/dev/null \
  | head -40 || info "(nothing matched — inspect $TXT manually)"

cat <<EOF

Done. Files:
  $SNOOP
  $TXT

Next:
  - If DataParts frames were found, note any 0xB1/0xB2/0xB3 auth frames and their bytes.
  - To try decrypting encrypted payloads once you know the nonce:
        python3 $HERE/sniff_capture.py "$SNOOP" --nonce 0x<nonce>
  - Re-decode a single frame by hand:
        python3 $HERE/appmode.py decode <hexbytes>
EOF
