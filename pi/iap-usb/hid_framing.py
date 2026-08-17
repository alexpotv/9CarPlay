#!/usr/bin/env python3
"""hid_framing.py — Apple iAP-over-USB-HID link layer (report fragmentation).

iAP1 packets are carried inside HID reports. Each HID report on the wire is:

    [ReportID (1 byte)] [LinkControl (1 byte)] [payload ... padded to ReportDef.length-1]

The report SIZE is fixed per ReportID (from the HID report descriptor). A frame (one iAP1
packet) that doesn't fit in a single report is split across several, tied together by the
LinkControl byte.

NOTE — reports are zero-PADDED to their fixed size, and the HID link layer does NOT carry an
exact byte count. So a reassembled frame is `<iAP1 packet> + trailing zero padding`; the caller
trims it using the iAP1 packet's own length field (`0x55 <len> …`). The iap1_daemon packet
parser does this, so the bridge feeds the reassembled bytes straight to it.

Report defs below match the ACTIVE full-speed descriptor served by the ipod-gadget kernel
module (references/cr-v/IAP_OVER_USB.md; oandrew/ipod-gadget gadget/ipod.h):
  Vendor usage page 0xFF00, Report Size 8 bits.
  INPUT  reports (iPod -> head unit, we SEND):    ID 1..4  lengths {12, 14, 20, 63}
  OUTPUT reports (head unit -> iPod, we RECEIVE): ID 5..9  lengths {8, 10, 14, 20, 63}
  ("length" excludes the report-ID byte; MaxPayload = length - 1, the -1 for LinkControl.)

Ported from oandrew/ipod hid/hid.go + hid/report_def.go (MIT). Verified against the report
descriptor in IAP_OVER_USB.md.
"""

from dataclasses import dataclass

# LinkControl byte
LC_DONE = 0x00              # single report; frame complete
LC_CONTINUE = 0x01          # continuation, and this is the LAST report
LC_MORE_TO_FOLLOW = 0x02    # first report; more to follow
LC_CONTINUE_MORE = 0x03     # LC_CONTINUE | LC_MORE_TO_FOLLOW — a middle report

DIR_ACC_IN = 0   # device -> host (iPod -> accessory/head unit); we send these
DIR_ACC_OUT = 1  # host -> device (accessory -> iPod); we receive these


@dataclass(frozen=True)
class ReportDef:
    id: int
    length: int   # report length NOT including the report-ID byte
    dir: int

    @property
    def max_payload(self) -> int:
        return self.length - 1   # minus the LinkControl byte


# Matches the active full-speed descriptor in IAP_OVER_USB.md.
DEFAULT_REPORT_DEFS = [
    ReportDef(0x01, 12, DIR_ACC_IN),
    ReportDef(0x02, 14, DIR_ACC_IN),
    ReportDef(0x03, 20, DIR_ACC_IN),
    ReportDef(0x04, 63, DIR_ACC_IN),
    ReportDef(0x05, 8,  DIR_ACC_OUT),
    ReportDef(0x06, 10, DIR_ACC_OUT),
    ReportDef(0x07, 14, DIR_ACC_OUT),
    ReportDef(0x08, 20, DIR_ACC_OUT),
    ReportDef(0x09, 63, DIR_ACC_OUT),
]


def _pick(defs, payload_size, direction):
    """Smallest report of the given direction that fits payload_size; else the largest."""
    chosen = None
    for d in defs:
        if d.dir != direction:
            continue
        chosen = d
        if d.max_payload >= payload_size:
            break
    if chosen is None:
        raise ValueError(f"no report def for dir={direction}")
    return chosen


def encode_frame(data: bytes, defs=DEFAULT_REPORT_DEFS) -> list[bytes]:
    """Fragment one iAP1 packet into a list of on-wire HID reports (bytes we write to the
    interrupt-IN endpoint via /dev/iap0). Reports are zero-padded to their fixed length."""
    reports = []
    offset, left = 0, len(data)
    if left == 0:
        return reports
    while left > 0:
        d = _pick(defs, left, DIR_ACC_IN)
        if left > d.max_payload:
            take = d.max_payload
            lc = LC_MORE_TO_FOLLOW if offset == 0 else LC_CONTINUE_MORE
        else:
            take = left
            lc = LC_CONTINUE if offset > 0 else LC_DONE
        payload = data[offset:offset + take]
        body = bytes([lc]) + payload
        body += b"\x00" * (d.length - len(body))   # pad to fixed report length
        reports.append(bytes([d.id]) + body)
        offset += take
        left -= take
    return reports


class FrameReassembler:
    """Feed raw OUTPUT reports (bytes read from /dev/iap0, incl. the report-ID byte); yields
    complete iAP1 packets as they finish."""

    def __init__(self, defs=DEFAULT_REPORT_DEFS):
        self._defs = {d.id: d for d in defs}
        self._buf = bytearray()

    def push(self, report: bytes):
        if len(report) < 2:
            return None
        rid, lc, payload = report[0], report[1], report[2:]
        d = self._defs.get(rid)
        if d is not None:
            payload = payload[:d.max_payload]
        if lc == LC_DONE:
            self._buf = bytearray(payload)
            out = bytes(self._buf); self._buf = bytearray(); return out
        if lc == LC_MORE_TO_FOLLOW:
            self._buf = bytearray(payload); return None
        if lc == LC_CONTINUE_MORE:
            self._buf += payload; return None
        if lc == LC_CONTINUE:
            self._buf += payload
            out = bytes(self._buf); self._buf = bytearray(); return out
        return None


def _selftest():
    # round-trip via a matched OUT-direction reassembler (mirror the defs so IN encodes and
    # a mirrored decoder reassembles — validates the fragmentation logic itself).
    mirror = [ReportDef(d.id, d.length, DIR_ACC_OUT if d.dir == DIR_ACC_IN else DIR_ACC_IN)
              for d in DEFAULT_REPORT_DEFS]
    for n in (0, 1, 5, 11, 12, 61, 62, 63, 100, 500, 2000):
        data = bytes((i * 7 + 1) & 0xFF for i in range(n))
        reps = encode_frame(data)
        if n == 0:
            assert reps == [], n; continue
        # each report is [id][lc][payload...] padded to def.length+1
        for r in reps:
            d = {x.id: x for x in DEFAULT_REPORT_DEFS}[r[0]]
            assert len(r) == d.length + 1, (n, r.hex())
        ra = FrameReassembler(mirror)
        out = None
        for r in reps:
            out = ra.push(r) or out
        # HID layer pads to report size; frame = data + trailing zero padding (trimmed later by
        # the iAP1 length field). Validate: data is a prefix and the remainder is all zeros.
        assert out[:n] == data and all(b == 0 for b in out[n:]), (n, out.hex(), data.hex())
    # link-control sequence for a 3-report frame
    data = bytes(150)  # > 62 -> needs ID4(62)+ID4(62)+ID3/…; check first/mid/last LC
    reps = encode_frame(data)
    lcs = [r[1] for r in reps]
    assert lcs[0] == LC_MORE_TO_FOLLOW and lcs[-1] == LC_CONTINUE, lcs
    assert all(x == LC_CONTINUE_MORE for x in lcs[1:-1]), lcs
    print(f"[PASS] hid_framing self-test ({len(DEFAULT_REPORT_DEFS)} report defs)")


if __name__ == "__main__":
    _selftest()
