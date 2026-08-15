#!/usr/bin/env python3
"""appmode_proto.py — zero-dependency codec for the Honda "AppMode" DataParts protocol.

This is the reference implementation of the protocol reverse-engineered from the head unit's
Communication.exe (see references/cr-v/AppMode.md for the full spec and firmware function addresses).
It has no third-party dependencies: MD5 comes from hashlib (stdlib), and AES-128 is implemented inline
below (with a FIPS-197 self-test) so the tools run unchanged on the Pi.

Wire frame:   9F 02 | id | checkByte | payload... | 9F 03      (0x9F doubled when literal in the body)
checkByte:    id XOR payload[0] XOR ... XOR payload[n-1]
crypto:       AES-128-CBC, zero IV, PKCS7; key = MD5( passphrase || nonce(4B big-endian) || info )
passphrase:   "HONDA_14M_X51A"   (embedded per-model key, see AppMode.md §6)
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Known constants (from firmware RE — references/cr-v/AppMode.md)
# ---------------------------------------------------------------------------

PASSPHRASE = b"HONDA_14M_X51A"          # .rdata 0x2239cc, memcpy'd into crypt ctx+0x40

MARK = 0x9F                             # escape / frame-marker byte
FRAME_START = bytes([MARK, 0x02])       # 9F 02
FRAME_END = bytes([MARK, 0x03])         # 9F 03

VALID_IDS = {0x00, 0xB1, 0xB2, 0xB3, 0xC1, 0xC2}

# AppMode SPP services the head unit hosts (phone connects to these)
AV_UUIDS = {
    "av1": "fa592c6e-5e85-410e-8a7e-5d6373117d39",   # observed RFCOMM channel 5
    "av2": "453994d5-d58b-96f9-6616-b37f586ba2ec",   # observed RFCOMM channel 6
}
IAP_UUID = "00000000-deca-fade-deca-deafdecacafe"    # iAP1 control channel (already implemented)

# (PackDataId, subtype byte(s)) -> human name  (CheckPackDataType FUN_0016f0b0)
#   subtype bytes are the first 1-2 bytes of the (plaintext) payload.
_TYPE_NAMES = {
    (0x00, (0x00,)): "PlainData/1",
    (0x00, (0x01,)): "PlainData/2",
    (0xB1, (0x00,)): "StartAuth",
    (0xB1, (0x01,)): "StartAuth/1",
    (0xB2, (0x00,)): "AuthResponse",
    (0xB3, (0x00,)): "AuthFin",
    (0xC1, (0x00, 0x01)): "DataA/CAN?",
    (0xC1, (0x00, 0x02)): "DataA",
    (0xC1, (0x01,)): "DataA",
    (0xC1, (0x02,)): "DataA",
    (0xC2, (0x00, 0x00)): "DataB",
    (0xC2, (0x00, 0x01)): "DataB",
    (0xC2, (0x00, 0x03)): "DataB/PartData?",
    (0xC2, (0x01,)): "DataB",
    (0xC2, (0x02,)): "DataB/CANSetting?",
}


def classify(pack_id: int, payload: bytes) -> str:
    """Best-effort human name for a (id, payload) pair per the firmware taxonomy."""
    for nbytes in (2, 1):
        sub = tuple(payload[:nbytes])
        name = _TYPE_NAMES.get((pack_id, sub))
        if name:
            return name
    if pack_id == 0xB1:
        return "StartAuth?"
    if pack_id == 0xB2:
        return "AuthResponse?"
    if pack_id == 0xB3:
        return "AuthFin?"
    return f"id=0x{pack_id:02x}"


# ---------------------------------------------------------------------------
# Framing: escape / unescape / build / parse
# ---------------------------------------------------------------------------

def check_byte(pack_id: int, payload: bytes) -> int:
    """8-bit XOR checksum over id followed by the payload (FUN_0016fc0c)."""
    x = pack_id & 0xFF
    for b in payload:
        x ^= b
    return x & 0xFF


def _escape(body: bytes) -> bytes:
    """Double every 0x9F in the frame body."""
    out = bytearray()
    for b in body:
        out.append(b)
        if b == MARK:
            out.append(MARK)
    return bytes(out)


def build_frame(pack_id: int, payload: bytes) -> bytes:
    """Serialize one DataParts frame: 9F 02 | id | length | payload | 9F 03 (with 9F escaping).

    ROUND 37 CORRECTION (hondalink/4, live): byte[1] is the payload LENGTH, not a checkByte. The head
    unit's own valid frame `9F 02 00 01 00 9F 03` = id 0x00, len 1, payload [0x00] — which cannot satisfy
    checkByte=XOR(id,payload)=0x00. The firmware serializer adds a length (PUP_AddDataLength); the real
    checkByte (FUN_0016fc0c, XOR(id,payload)) is carried INSIDE the plaintext of encrypted frames (§3),
    not as this wire field. Our earlier checkByte-in-byte[1] framing made the head unit read length=0 and
    reject every frame (it replied once then DISC'd). Length is 1 byte here (all observed/needed payloads
    are <256 B; revisit if a >255 B frame ever appears)."""
    payload = bytes(payload)
    body = bytes([pack_id & 0xFF, len(payload) & 0xFF]) + payload
    return FRAME_START + _escape(body) + FRAME_END


@dataclass
class Frame:
    pack_id: int
    check: int              # wire byte[1] — the payload LENGTH (ROUND 37); kept as `check` for callers
    payload: bytes          # unescaped payload (still ciphertext if the message is encrypted)
    raw: bytes              # the exact on-wire bytes of this frame (incl. markers)
    direction: str = ""     # "TX"/"RX"/"" if known (filled by capture tooling)
    offset: int = 0         # byte offset in the source stream

    @property
    def length(self) -> int:
        """The declared payload length (wire byte[1])."""
        return self.check

    @property
    def check_ok(self) -> bool:
        """Well-formed = the declared length matches the actual payload length (ROUND 37: byte[1] is a
        length, not a checkByte). Kept named check_ok so existing logging stays valid."""
        return self.check == len(self.payload)

    @property
    def name(self) -> str:
        return classify(self.pack_id, self.payload)

    def describe(self) -> str:
        d = f"[{self.direction}] " if self.direction else ""
        ck = "ok" if self.check_ok else f"BAD(len byte 0x{self.check:02x} vs {len(self.payload)})"
        return (f"{d}{self.name:<16} id=0x{self.pack_id:02x} len=0x{self.check:02x}({ck}) "
                f"payload={self.payload.hex()}")


def parse_frames(stream: bytes):
    """Scan a byte stream for 9F 02 ... 9F 03 frames and yield Frame objects.

    Robust to arbitrary surrounding bytes (RFCOMM/L2CAP framing etc.): it locks onto the distinctive
    9F 02 start marker and unescapes until the 9F 03 end marker, so it works on raw reassembled
    transport payloads without needing full RFCOMM dissection.
    """
    i, n = 0, len(stream)
    while i < n - 1:
        if stream[i] == MARK and stream[i + 1] == 0x02:
            start = i
            j = i + 2
            body = bytearray()
            ended = False
            while j < n:
                b = stream[j]
                if b == MARK:
                    if j + 1 >= n:
                        break
                    nxt = stream[j + 1]
                    if nxt == MARK:            # escaped literal 0x9F
                        body.append(MARK)
                        j += 2
                        continue
                    if nxt == 0x03:            # end of frame
                        j += 2
                        ended = True
                        break
                    if nxt == 0x02:            # unexpected nested start -> abort this frame
                        break
                    break                       # 9F followed by something else -> malformed
                body.append(b)
                j += 1
            if ended and len(body) >= 2:
                yield Frame(pack_id=body[0], check=body[1], payload=bytes(body[2:]),
                            raw=bytes(stream[start:j]), offset=start)
                i = j
                continue
        i += 1


def parse_frames_list(stream: bytes, direction: str = "") -> list:
    out = []
    for f in parse_frames(stream):
        f.direction = direction
        out.append(f)
    return out


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_key(nonce, info: bytes = b"", passphrase: bytes = PASSPHRASE) -> bytes:
    """AES-128 key = MD5( passphrase || nonce(4 bytes, big-endian) || info ).

    `nonce` may be an int (encoded as 4-byte big-endian) or a 4-byte bytes object.
    """
    if isinstance(nonce, int):
        nonce_bytes = struct.pack(">I", nonce & 0xFFFFFFFF)
    else:
        nonce_bytes = bytes(nonce)
    return hashlib.md5(passphrase + nonce_bytes + bytes(info)).digest()


# ---------------------------------------------------------------------------
# AES-128 (inline, dependency-free) + CBC/PKCS7 helpers
# ---------------------------------------------------------------------------

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_INV_SBOX = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_INV_SBOX = bytes(_INV_SBOX)
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p & 0xFF


def _key_expansion(key: bytes):
    assert len(key) == 16, "AES-128 requires a 16-byte key"
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[x] for x in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    # round keys as 16-byte blocks
    return [bytes(w[r * 4 + c][b] for c in range(4) for b in range(4)) for r in range(11)]


def _add_round_key(s, rk):
    return [s[i] ^ rk[i] for i in range(16)]


def _sub_bytes(s, box):
    return [box[b] for b in s]


def _shift_rows(s):
    # state is column-major: index = col*4 + row
    o = list(s)
    for r in range(1, 4):
        row = [s[c * 4 + r] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            o[c * 4 + r] = row[c]
    return o


def _inv_shift_rows(s):
    o = list(s)
    for r in range(1, 4):
        row = [s[c * 4 + r] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            o[c * 4 + r] = row[c]
    return o


def _mix_columns(s):
    o = [0] * 16
    for c in range(4):
        col = s[c * 4:c * 4 + 4]
        o[c * 4 + 0] = _xtime(col[0]) ^ (_xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3]
        o[c * 4 + 1] = col[0] ^ _xtime(col[1]) ^ (_xtime(col[2]) ^ col[2]) ^ col[3]
        o[c * 4 + 2] = col[0] ^ col[1] ^ _xtime(col[2]) ^ (_xtime(col[3]) ^ col[3])
        o[c * 4 + 3] = (_xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ _xtime(col[3])
    return o


def _inv_mix_columns(s):
    o = [0] * 16
    for c in range(4):
        col = s[c * 4:c * 4 + 4]
        o[c * 4 + 0] = _mul(col[0], 14) ^ _mul(col[1], 11) ^ _mul(col[2], 13) ^ _mul(col[3], 9)
        o[c * 4 + 1] = _mul(col[0], 9) ^ _mul(col[1], 14) ^ _mul(col[2], 11) ^ _mul(col[3], 13)
        o[c * 4 + 2] = _mul(col[0], 13) ^ _mul(col[1], 9) ^ _mul(col[2], 14) ^ _mul(col[3], 11)
        o[c * 4 + 3] = _mul(col[0], 11) ^ _mul(col[1], 13) ^ _mul(col[2], 9) ^ _mul(col[3], 14)
    return o


def _aes_encrypt_block(block: bytes, rks) -> bytes:
    s = _add_round_key(list(block), list(rks[0]))
    for r in range(1, 10):
        s = _sub_bytes(s, _SBOX)
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = _add_round_key(s, list(rks[r]))
    s = _sub_bytes(s, _SBOX)
    s = _shift_rows(s)
    s = _add_round_key(s, list(rks[10]))
    return bytes(s)


def _aes_decrypt_block(block: bytes, rks) -> bytes:
    s = _add_round_key(list(block), list(rks[10]))
    for r in range(9, 0, -1):
        s = _inv_shift_rows(s)
        s = _sub_bytes(s, _INV_SBOX)
        s = _add_round_key(s, list(rks[r]))
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = _sub_bytes(s, _INV_SBOX)
    s = _add_round_key(s, list(rks[0]))
    return bytes(s)


def _pkcs7_pad(data: bytes) -> bytes:
    p = 16 - (len(data) % 16)
    return data + bytes([p]) * p


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16 != 0:
        return data
    p = data[-1]
    if 1 <= p <= 16 and data[-p:] == bytes([p]) * p:
        return data[:-p]
    return data


def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes = b"\x00" * 16, pad: bool = True) -> bytes:
    rks = _key_expansion(key)
    data = _pkcs7_pad(plaintext) if pad else plaintext
    out = bytearray()
    prev = bytes(iv)
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _aes_encrypt_block(blk, rks)
        out += enc
        prev = enc
    return bytes(out)


def aes_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes = b"\x00" * 16, unpad: bool = True) -> bytes:
    rks = _key_expansion(key)
    out = bytearray()
    prev = bytes(iv)
    for i in range(0, len(ciphertext) - (len(ciphertext) % 16), 16):
        blk = ciphertext[i:i + 16]
        dec = _aes_decrypt_block(blk, rks)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return _pkcs7_unpad(bytes(out)) if unpad else bytes(out)


# ---------------------------------------------------------------------------
# Self-test (FIPS-197 vector + protocol round-trips)
# ---------------------------------------------------------------------------

def selftest() -> bool:
    ok = True

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        ok = ok and cond

    # FIPS-197 AES-128 known-answer
    k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    rks = _key_expansion(k)
    check("AES-128 encrypt KAT", _aes_encrypt_block(pt, rks) == ct)
    check("AES-128 decrypt KAT", _aes_decrypt_block(ct, rks) == pt)

    # CBC round trip
    key = derive_key(0x12345678, b"\x01\x02")
    msg = b"hello appmode payload!!"
    enc = aes_cbc_encrypt(key, msg)
    check("AES-CBC/PKCS7 round trip", aes_cbc_decrypt(key, enc) == msg)

    # frame round trip + escaping (payload containing 0x9F)
    payload = bytes([0x00, 0x9F, 0x9F, 0x02, 0x03, 0xAB])
    frame = build_frame(0xB2, payload)
    frames = list(parse_frames(b"\x00\x11" + frame + b"\x22"))
    check("frame build/parse round trip", len(frames) == 1 and frames[0].payload == payload
          and frames[0].pack_id == 0xB2 and frames[0].check_ok)

    # ROUND 37: length-prefixed framing matches the head unit's live frame exactly
    check("AuthRequest matches HU frame", build_frame(0x00, b"\x00") == bytes.fromhex("9f020001009f03"))
    check("frame byte[1] is payload length", frames[0].length == len(payload))

    # checkByte (internal plaintext integrity, §3 — no longer the wire byte[1])
    check("checkByte XOR", check_byte(0xB1, b"\x00") == (0xB1 ^ 0x00))

    # known key derivation is stable
    check("derive_key length", len(derive_key(0, b"")) == 16)
    return ok


if __name__ == "__main__":
    print("appmode_proto self-test:")
    raise SystemExit(0 if selftest() else 1)
