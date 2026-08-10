#!/usr/bin/env python3
"""markers.py — operator-driven timestamp tags for correlating capture files against events
observed live on the head unit's screen (tap timing, UI-state changes, the "Could not launch
app" error, etc.) — see iap.md, "cmd=0x38 confirmed as a periodic post-launch retry/status poll"
and decode_capture.py for how these get merged against a trial's .bin files.

Usage, on the Pi, in a separate shell from iap1_daemon.py/btsdp_iap.py:
    python3 markers.py [suffix]

Type a short tag (e.g. "open-app", "error-shown") and press Enter at the moment it happens on
the head unit's screen. Each line is timestamped and appended to markers_<suffix>.log. If no
suffix is given, a fresh one is generated — but for a marker log to actually correlate against a
trial's capture files, pass the SAME suffix iap1_daemon.py/btsdp_iap.py printed at startup for
that trial. Ctrl-D or Ctrl-C to stop.
"""

import sys
import time


def session_suffix() -> str:
    """Fresh, timestamped suffix so each process launch gets its own marker/capture files instead
    of silently appending to (and misdating) a previous trial's leftovers — the exact bug that
    once made a marker land 11.4 hours from the nearest logged packet, per iap.md."""
    return time.strftime("%Y%m%d_%H%M%S")


def main():
    suffix = sys.argv[1] if len(sys.argv) > 1 else session_suffix()
    path = f"markers_{suffix}.log"
    print(f"[markers] suffix: {suffix}")
    print(f"[markers] writing to {path}")
    print("[markers] type a tag + Enter at the moment something happens on the head unit's "
          "screen (e.g. open-app, error-shown, phone-connected). Ctrl-D to stop.")
    with open(path, "a") as fp:
        try:
            while True:
                line = input("> ").strip()
                if not line:
                    continue
                ts = time.time()
                fp.write(f"{ts:.6f}\t{line}\n")
                fp.flush()
                print(f"[markers] {ts:.3f}  {line}")
        except (EOFError, KeyboardInterrupt):
            print("\n[markers] stopped")


if __name__ == "__main__":
    main()
