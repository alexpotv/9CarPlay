#!/usr/bin/env python3
"""decode_capture.py — merges a markers_<suffix>.log file against a trial's capture/unclassified
.bin files into one chronological, marker-relative timeline, so a live trial's packet stream can
be read against what was actually happening on the head unit's screen at the time (see
markers.py and iap.md, "cmd=0x38 confirmed as a periodic post-launch retry/status poll").

Usage:
    python3 decode_capture.py markers_<suffix>.log iap1_capture_<suffix>.bin \
        [iap1_unclassified_<suffix>.bin ...]

Pass the marker log from a trial alongside every .bin file from that SAME trial (matching
suffix) — mixing files from different trials will produce a meaningless timeline. Both the
capture and unclassified files use the same timestamped-record framing (see
iap1_daemon.py's write_record()), so either or both can be passed.
"""

import os
import struct
import sys

from iap1_daemon import SYNC, SYNC_SHORT, iap1_checksum


def read_records(path):
    """Yields (timestamp, raw_bytes) tuples from a write_record()-framed .bin file (double
    timestamp + uint32 length + raw bytes, repeated)."""
    with open(path, "rb") as fp:
        data = fp.read()
    offset = 0
    while offset + 12 <= len(data):
        ts, length = struct.unpack_from("<dI", data, offset)
        offset += 12
        chunk = data[offset:offset + length]
        offset += length
        yield ts, chunk


def read_markers(path):
    events = []
    with open(path) as fp:
        for line in fp:
            line = line.strip()
            if not line or "\t" not in line:
                continue
            ts_str, tag = line.split("\t", 1)
            events.append((float(ts_str), "MARKER", tag))
    return events


def describe_record(raw: bytes) -> str:
    """Best-effort human description of one raw record: decodes iAP1 framing if present, with
    either the full 0xFF 0x55 sync or the bare 0x55 SYNC_SHORT (see try_parse_packet's
    docstring), else falls back to a hex dump."""
    body = raw
    if body[:2] == SYNC:
        body = body[2:]
    elif body[:1] == SYNC_SHORT:
        body = body[1:]
    else:
        return f"raw {raw.hex()}"

    if len(body) < 1:
        return f"raw {raw.hex()}"
    length = body[0]
    if len(body) < 1 + length + 1 or length < 2:
        return f"raw {raw.hex()}"
    payload_body = body[1:1 + length]
    checksum = body[1 + length]
    if iap1_checksum(bytes([length]) + payload_body) != checksum:
        return f"raw {raw.hex()} (sync-like but bad checksum)"
    lingo, cmd = payload_body[0], payload_body[1]
    params = payload_body[2:]
    return f"iAP1 lingo=0x{lingo:02x} cmd=0x{cmd:02x} payload={params.hex()}"


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} markers.log capture1.bin [capture2.bin ...]",
              file=sys.stderr)
        sys.exit(1)

    marker_path = sys.argv[1]
    bin_paths = sys.argv[2:]

    events = read_markers(marker_path)
    for path in bin_paths:
        label = os.path.basename(path)
        for ts, chunk in read_records(path):
            events.append((ts, label, describe_record(chunk)))
    events.sort(key=lambda e: e[0])

    if not events:
        print("No events found.")
        return

    marker_timestamps = [ts for ts, kind, _ in events if kind == "MARKER"]
    zero_ts = marker_timestamps[0] if marker_timestamps else events[0][0]
    if not marker_timestamps:
        print("(no markers found — timeline is relative to the first record instead)\n")

    for ts, kind, detail in events:
        rel = ts - zero_ts
        print(f"{rel:+9.3f}s  [{kind:^12}]  {detail}")


if __name__ == "__main__":
    main()
