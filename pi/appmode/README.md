# pi/appmode — AppMode (HondaLink) protocol tooling

Utilities for reverse-engineering and (eventually) implementing **AppMode**, the Honda HondaLink
smartphone app-link protocol that runs over the Bluetooth SPP channel after MFi auth. The full protocol
spec is in [`references/cr-v/AppMode.md`](../../references/cr-v/AppMode.md).

These are **zero-dependency** (stdlib only; AES is implemented inline) so they run as-is on the Pi.

## Files

| File | What it does |
|------|--------------|
| `appmode_proto.py` | The codec library: DataParts framing/escaping, checkByte (XOR), key derivation (MD5), inline AES-128-CBC, frame parse/build, message classification. Importable; `python3 appmode_proto.py` runs the self-test. |
| `appmode.py` | CLI over the library: `const`, `decode`, `key`, `decrypt`, `build`, `selftest`. |
| `sniff_capture.py` | Pulls DataParts frames out of a btmon `.btsnoop` (reassembles ACL, scans for `9F 02..9F 03`) and highlights auth frames + candidate nonces. |
| `capture.sh` | Interactive, guided btmon capture for a live trial (run on the Pi with `sudo`). |

## Quick start

```bash
# sanity-check the crypto/framing on any machine
python3 appmode.py selftest

# see everything we recovered from firmware
python3 appmode.py const

# decode bytes you captured off the SPP channel (surrounding bytes are tolerated)
python3 appmode.py decode 9f02b1b1009f03

# derive the AES key for a nonce, then decrypt an encrypted payload
python3 appmode.py key 0x12345678
python3 appmode.py decrypt --nonce 0x12345678 <ciphertext-hex>

# build a frame to send
python3 appmode.py build 0xB2 0000
```

## The wire-sniffing workflow (resolving the open questions)

Two things still need a live capture to confirm (see AppMode.md §7): the **nonce direction** and the
**`info`** bytes. The loop:

1. **On the Pi**, run a guided capture around a full HondaLink trial:
   ```bash
   sudo ./capture.sh my_run_1
   ```
   Follow the prompts (drive HDMI, start the iAP harness, arm the hypothesis, launch HondaLink, let it
   error, wait ~15s, stop). It saves `references/guided/btmon/my_run_1.{btsnoop,txt}` and immediately
   prints any DataParts frames it found plus the relevant SDP/RFCOMM events.

2. **Read the auth frames.** `sniff_capture.py` flags every `0xB1`/`0xB2`/`0xB3` frame and prints a
   candidate 4-byte nonce (`payload[1:5]`) with the key it would derive. Compare `0xB1` (head unit →
   phone) vs `0xB2` (phone → head unit) contents to see which carries the nonce.

3. **Confirm the key** by decrypting a known encrypted frame:
   ```bash
   python3 sniff_capture.py my_run_1.btsnoop --nonce 0x<nonce>
   ```
   If a `0xC1`/`0xC2` payload decrypts to sane bytes, the key derivation (and the `HONDA_14M_X51A`
   passphrase) is validated end-to-end on real data.

> Note: because the app is emulated on the Pi, "wire sniffing" here means capturing what the **head unit
> sends to our harness** on the SPP channel — there is no separate real iPhone to sniff. Bring the SPP
> channel up in the harness (after AppMode goes Active) so the head unit starts the `0xB1` exchange, and
> capture that.

## When implementing the phone side

Use `appmode_proto` directly:

```python
import appmode_proto as ap
# parse an incoming SPP read
for f in ap.parse_frames(rx_bytes):
    if f.pack_id == 0xB1:                      # StartAuth from head unit
        nonce = ...                            # (per the resolved nonce direction)
        key = ap.derive_key(nonce, info=b"")
        resp = ap.aes_cbc_encrypt(key, my_plaintext)
        tx = ap.build_frame(0xB2, b"\x00" + resp)   # AuthResponse
```
