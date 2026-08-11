#!/usr/bin/env python3
"""appmode.py — command-line front-end for the AppMode DataParts codec (appmode_proto.py).

Everything here is dependency-free and safe to run on the Pi or any machine. See
references/cr-v/AppMode.md for the protocol spec.

Examples
--------
  # show all the recovered constants (key, UUIDs, opcodes, channels)
  ./appmode.py const

  # decode raw bytes captured off an AppMode SPP channel (any surrounding bytes are tolerated)
  ./appmode.py decode 9f02b1b1009f03
  ./appmode.py decode --file some_dump.bin

  # derive the AES-128 key for a given 4-byte nonce (hex or decimal), optional info bytes
  ./appmode.py key 12345678
  ./appmode.py key --nonce 0x12345678 --info 0001

  # decrypt an encrypted payload (give a nonce to derive the key, or the raw 16-byte key)
  ./appmode.py decrypt --nonce 0x12345678 aabbcc...      # ciphertext hex
  ./appmode.py decrypt --key 00112233445566778899aabbccddeeff aabbcc...

  # build a frame to send (id + payload hex) -> ready-to-write on-wire bytes
  ./appmode.py build 0xB2 0000

  # run the crypto/framing self-test
  ./appmode.py selftest
"""

import argparse
import sys

import appmode_proto as ap


def _hex(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace(":", "").replace("\n", "")
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return bytes.fromhex(s)


def _int(s: str) -> int:
    return int(s, 0)


def cmd_const(args):
    print("AppMode recovered constants (references/cr-v/AppMode.md)")
    print(f"  passphrase (AES key material) : {ap.PASSPHRASE!r}  ({ap.PASSPHRASE.hex()})")
    print(f"  cipher                        : AES-128-CBC, zero IV, PKCS7")
    print(f"  key derivation                : MD5( passphrase || nonce(4B big-endian) || info )")
    print(f"  frame                         : 9F 02 | id | checkByte | payload | 9F 03  (0x9F doubled)")
    print(f"  checkByte                     : id XOR payload[0..n-1]")
    print(f"  valid PackDataIds             : {{{', '.join(f'0x{i:02x}' for i in sorted(ap.VALID_IDS))}}}")
    print(f"  auth opcodes                  : 0xB1 StartAuth(HU->phone), 0xB2 AuthResponse(phone->HU), "
          f"0xB3 AuthFin(HU->phone)")
    print(f"  iAP control UUID              : {ap.IAP_UUID}")
    for name, uuid in ap.AV_UUIDS.items():
        ch = {"av1": 5, "av2": 6}[name]
        print(f"  AppMode SPP {name}                : {uuid}  (RFCOMM ch {ch}, head unit hosts)")


def _print_frames(frames, key=None, try_decrypt=False):
    if not frames:
        print("  (no DataParts frames found — no 9F 02 .. 9F 03 sequences)")
        return
    for f in frames:
        line = f.describe()
        print("  " + line)
        if try_decrypt and key is not None and f.payload and len(f.payload) % 16 == 0:
            try:
                dec = ap.aes_cbc_decrypt(key, f.payload)
                print(f"        AES-decrypt -> {dec.hex()}  ({dec!r})")
            except Exception as e:  # pragma: no cover
                print(f"        AES-decrypt failed: {e}")


def cmd_decode(args):
    data = open(args.file, "rb").read() if args.file else _hex(args.data)
    key = None
    if args.key:
        key = _hex(args.key)
    elif args.nonce is not None:
        key = ap.derive_key(_int(args.nonce), _hex(args.info) if args.info else b"")
    frames = list(ap.parse_frames(data))
    print(f"scanned {len(data)} bytes, found {len(frames)} DataParts frame(s):")
    _print_frames(frames, key=key, try_decrypt=key is not None)


def cmd_key(args):
    nonce = args.nonce if args.nonce is not None else args.pos_nonce
    if nonce is None:
        print("error: provide a nonce (positional or --nonce)", file=sys.stderr)
        return 2
    info = _hex(args.info) if args.info else b""
    k = ap.derive_key(_int(nonce), info)
    print(f"nonce  : 0x{_int(nonce) & 0xFFFFFFFF:08x}")
    print(f"info   : {info.hex() or '(none)'}")
    print(f"key    : {k.hex()}   (MD5('{ap.PASSPHRASE.decode()}' || nonce_BE || info))")


def cmd_decrypt(args):
    if args.key:
        key = _hex(args.key)
    elif args.nonce is not None:
        key = ap.derive_key(_int(args.nonce), _hex(args.info) if args.info else b"")
    else:
        print("error: provide --key or --nonce", file=sys.stderr)
        return 2
    ct = open(args.file, "rb").read() if args.file else _hex(args.data)
    dec = ap.aes_cbc_decrypt(key, ct, unpad=not args.no_unpad)
    print(f"key        : {key.hex()}")
    print(f"ciphertext : {ct.hex()}")
    print(f"plaintext  : {dec.hex()}")
    print(f"as ascii   : {dec!r}")


def cmd_build(args):
    pid = _int(args.id)
    payload = _hex(args.payload) if args.payload else b""
    frame = ap.build_frame(pid, payload)
    print(f"id       : 0x{pid:02x} ({ap.classify(pid, payload)})")
    print(f"payload  : {payload.hex() or '(empty)'}")
    print(f"checkByte: 0x{ap.check_byte(pid, payload):02x}")
    print(f"on-wire  : {frame.hex()}")


def cmd_selftest(args):
    return 0 if ap.selftest() else 1


def main(argv=None):
    p = argparse.ArgumentParser(description="AppMode DataParts protocol CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("const", help="print recovered constants")
    sp.set_defaults(func=cmd_const)

    sp = sub.add_parser("decode", help="parse DataParts frames from hex/bytes")
    sp.add_argument("data", nargs="?", help="hex string of captured bytes")
    sp.add_argument("--file", help="read raw bytes from a file instead")
    sp.add_argument("--key", help="16-byte AES key (hex) to attempt payload decryption")
    sp.add_argument("--nonce", help="nonce (hex/dec) to derive the key and attempt decryption")
    sp.add_argument("--info", help="info bytes (hex) for key derivation")
    sp.set_defaults(func=cmd_decode)

    sp = sub.add_parser("key", help="derive the AES key from a nonce")
    sp.add_argument("pos_nonce", nargs="?", help="nonce (hex/dec)")
    sp.add_argument("--nonce", help="nonce (hex/dec)")
    sp.add_argument("--info", help="info bytes (hex)")
    sp.set_defaults(func=cmd_key)

    sp = sub.add_parser("decrypt", help="AES-128-CBC decrypt a payload")
    sp.add_argument("data", nargs="?", help="ciphertext hex")
    sp.add_argument("--file", help="read ciphertext from a file")
    sp.add_argument("--key", help="16-byte AES key (hex)")
    sp.add_argument("--nonce", help="nonce (hex/dec) to derive the key")
    sp.add_argument("--info", help="info bytes (hex) for key derivation")
    sp.add_argument("--no-unpad", action="store_true", help="do not strip PKCS7 padding")
    sp.set_defaults(func=cmd_decrypt)

    sp = sub.add_parser("build", help="build an on-wire frame")
    sp.add_argument("id", help="PackDataId (hex/dec), e.g. 0xB2")
    sp.add_argument("payload", nargs="?", help="payload hex")
    sp.set_defaults(func=cmd_build)

    sp = sub.add_parser("selftest", help="run crypto/framing self-test")
    sp.set_defaults(func=cmd_selftest)

    args = p.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    raise SystemExit(main())
