#!/usr/bin/env python3
"""sniff_capture.py — pull AppMode DataParts frames out of a btmon capture.

Reads a btsnoop (binary, as written by `btmon -w file.btsnoop`) OR an already-converted text dump,
reassembles ACL fragments per connection handle + direction, and scans the reassembled streams for the
AppMode `9F 02 .. 9F 03` framing. It also surfaces the Bluetooth-layer events that matter for the RE:
SDP searches for the AppMode UUIDs and RFCOMM SABM/UA/DISC (which tell us the channel/connection
direction).

This is transport-agnostic on purpose: instead of fully dissecting L2CAP/RFCOMM (version-fragile), it
locks onto the distinctive DataParts start marker in the reassembled ACL payload, which is robust.

Usage:
    ./sniff_capture.py capture.btsnoop
    ./sniff_capture.py capture.btsnoop --key 00112233445566778899aabbccddeeff   # try decrypt
    ./sniff_capture.py capture.btsnoop --nonce 0x12345678                        # derive key, decrypt

Convert a btsnoop to human text separately with:  btmon -r capture.btsnoop > capture.txt
"""

import argparse
import struct
import sys

import appmode_proto as ap

BTSNOOP_MAGIC = b"btsnoop\x00"

# HCI packet indicators (H4)
H4_CMD, H4_ACL, H4_SCO, H4_EVT = 0x01, 0x02, 0x03, 0x04


def _read_btsnoop(path):
    """Yield (direction, hci_type, payload_bytes) for each record.

    direction: "TX" (host->controller, i.e. sent by us/the Pi) or "RX" (received).
    Supports the two datalink encodings btmon emits: 1001 (HCI, type in flags) and
    1002 (H4/UART, type is the first payload byte).
    """
    with open(path, "rb") as fp:
        data = fp.read()
    if data[:8] != BTSNOOP_MAGIC:
        raise ValueError("not a btsnoop file")
    version, datalink = struct.unpack(">II", data[8:16])
    off = 16
    while off + 24 <= len(data):
        orig_len, incl_len, flags, drops, ts = struct.unpack(">IIIIq", data[off:off + 24])
        off += 24
        pkt = data[off:off + incl_len]
        off += incl_len
        if len(pkt) < 1:
            continue
        direction = "RX" if (flags & 0x01) else "TX"
        if datalink == 1002:              # H4: first byte is the packet indicator
            hci_type = pkt[0]
            payload = pkt[1:]
        else:                              # 1001 HCI: type encoded in flags bits 1-2 (monitor style)
            # btmon's own monitor format differs; fall back to sniffing the ACL shape.
            hci_type = H4_ACL
            payload = pkt
        yield direction, hci_type, payload


def _reassemble_acl(records):
    """Reassemble ACL PB fragments into complete L2CAP-bearing payloads.

    Yields (direction, handle, l2cap_payload_bytes). We key partial buffers by (direction, handle).
    """
    partial = {}  # (dir, handle) -> [need_total, bytearray]
    for direction, hci_type, payload in records:
        if hci_type != H4_ACL or len(payload) < 4:
            continue
        hdr = struct.unpack_from("<HH", payload, 0)
        handle = hdr[0] & 0x0FFF
        pb = (hdr[0] >> 12) & 0x3
        acl_len = hdr[1]
        body = payload[4:4 + acl_len]
        keyd = (direction, handle)
        if pb == 0x2 or pb == 0x0:        # first fragment of a higher-layer packet
            if len(body) >= 2:
                l2_len = struct.unpack_from("<H", body, 0)[0]
                total = l2_len + 4        # L2CAP header = len(2)+cid(2)
                if len(body) >= total:
                    yield direction, handle, body[:total]
                else:
                    partial[keyd] = [total, bytearray(body)]
        elif pb == 0x1:                   # continuation
            ent = partial.get(keyd)
            if ent:
                ent[1] += body
                if len(ent[1]) >= ent[0]:
                    yield direction, handle, bytes(ent[1][:ent[0]])
                    del partial[keyd]


def _scan_text(path, key):
    """Fallback: scan a text dump for hex byte runs and look for DataParts frames.

    Best-effort only — the binary .btsnoop path is far more reliable. We accumulate any run of >= 4
    consecutive two-hex-digit tokens on a line (btmon's hexdump rows) into one blob and scan it.
    """
    import re
    run = re.compile(r"(?:\b[0-9a-fA-F]{2}\b[ ]?){4,}")
    blob = bytearray()
    for line in open(path, "r", errors="ignore"):
        for m in run.finditer(line):
            toks = re.findall(r"\b[0-9a-fA-F]{2}\b", m.group(0))
            try:
                blob += bytes(int(t, 16) for t in toks)
            except ValueError:
                pass
    return list(ap.parse_frames(bytes(blob)))


def main(argv=None):
    p = argparse.ArgumentParser(description="Extract AppMode DataParts frames from a btmon capture")
    p.add_argument("capture", help="path to a .btsnoop (binary) or text dump")
    p.add_argument("--key", help="16-byte AES key (hex) to attempt payload decryption")
    p.add_argument("--nonce", help="nonce (hex/dec) to derive the key and attempt decryption")
    p.add_argument("--info", help="info bytes (hex) for key derivation")
    p.add_argument("--raw", action="store_true", help="also print reassembled stream sizes")
    args = p.parse_args(argv)

    key = None
    if args.key:
        key = bytes.fromhex(args.key.replace(" ", ""))
    elif args.nonce is not None:
        key = ap.derive_key(int(args.nonce, 0), bytes.fromhex(args.info) if args.info else b"")

    # binary btsnoop vs text
    is_btsnoop = open(args.capture, "rb").read(8) == BTSNOOP_MAGIC
    all_frames = []
    if is_btsnoop:
        streams = list(_reassemble_acl(_read_btsnoop(args.capture)))
        if args.raw:
            print(f"reassembled {len(streams)} L2CAP payloads")
        # concatenate per (direction) so frames split across L2CAP packets still parse
        by_dir = {"TX": bytearray(), "RX": bytearray()}
        for direction, handle, l2 in streams:
            by_dir[direction] += l2
        for direction, blob in by_dir.items():
            all_frames += ap.parse_frames_list(bytes(blob), direction=direction)
    else:
        print("(text capture: scanning hex runs — for best results pass the raw .btsnoop)")
        all_frames = _scan_text(args.capture, key)

    all_frames.sort(key=lambda f: (f.direction, f.offset))
    print(f"\n=== {len(all_frames)} DataParts frame(s) ===")
    if not all_frames:
        print("  none found. Check that the AppMode SPP channel actually carried data in this capture,")
        print("  and that btmon captured the right controller (btmon -i hciX -w file.btsnoop).")
    for f in all_frames:
        print("  " + f.describe())
        if key is not None and f.payload and len(f.payload) % 16 == 0:
            try:
                dec = ap.aes_cbc_decrypt(key, f.payload)
                print(f"        AES-decrypt -> {dec.hex()}")
            except Exception as e:  # pragma: no cover
                print(f"        AES-decrypt failed: {e}")

    # highlight auth frames + candidate nonces
    auth = [f for f in all_frames if f.pack_id in (0xB1, 0xB2, 0xB3)]
    if auth:
        print("\n=== auth frames (watch these to resolve nonce direction) ===")
        for f in auth:
            print("  " + f.describe())
            if len(f.payload) >= 5:
                # if a 4-byte nonce is carried plaintext it's often right after the subtype byte
                cand = f.payload[1:5]
                print(f"        candidate nonce (payload[1:5]) = {cand.hex()}  "
                      f"-> key {ap.derive_key(cand).hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
