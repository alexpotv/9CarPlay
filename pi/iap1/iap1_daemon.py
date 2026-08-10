#!/usr/bin/env python3
"""iap1_daemon — legacy iAP1 "HondaLink phone" scaffold over a Linux FunctionFS USB gadget.

Implements the real IDPS (Identify Device Preferences and Settings) + MFi device-authentication
handshake, verified 2026-08-10 against Apple's actual public "iPod Accessory Protocol Interface
Specification" (Release R38, archive.org) — see references/cr-v/iap.md for the fetch and the full
reasoning trail. This replaces this file's earlier best-effort guesses, several of which turned
out backwards or simply wrong once checked against the real spec:
  - cmd=0x38 is NOT a Honda-specific "status poll heartbeat" — it's the real, documented
    "Command 0x38: StartIDPS", sent Device-to-iPod, with a 16-bit *transaction ID* payload (not a
    counter). The accessory retries it because it never received a valid ACK — "the accessory may
    resend Start IDPS... must not retry more often than once per second" — matching exactly what
    every live trial observed.
  - cmd=0x00 (RequestIdentify) is iPod-to-Device, the opposite direction this file originally
    assumed — the accessory was never going to send it to us, which is why the old
    identify-gated app announcement code could never fire.
  - The leading 0xFF sync byte really is UART-only — every packet table in the spec marks byte 0
    "Sync byte (required only for UART serial)" — confirming OUTGOING_SYNC_MODE's Bluetooth
    "short" framing fix from earlier the same day was correct, straight from Apple's own spec.
  - `SetServerVRAppData` (this file's earlier main focus, per apps.py) turned out to be part of
    Honda's Siri/Voice-Recognition button integration ("VR" = Voice Recognition, confirmed via
    IPILib.dll's `IPI_*ServerVREvent` strings), not the general app-launch gate — the proactive
    app-announcement handshake built earlier the same day is removed; it was targeting the wrong
    mechanism entirely.

WHAT IS CONFIDENT vs BEST-EFFORT here:
  - USB gadget enumeration (Apple VID, plausible iPhone PID, vendor-class bulk interface) — same
    confidence level as every other gadget in this repo: built against public USB/FunctionFS
    mechanics, untested against this specific head unit.
  - iAP1 packet framing and every command ID/payload layout referenced by name below (StartIDPS,
    SetFIDTokenValues, EndIDPS, IDPSStatus, GetDevAuthenticationInfo, RetDevAuthenticationInfo,
    AckDevAuthenticationInfo, GetDevAuthenticationSignature, RetDevAuthenticationSignature,
    AckDevAuthenticationStatus) — all CONFIDENT, cited directly from Apple's own spec, not
    inferred from a capture or a public non-Apple community doc.
  - We do NOT cryptographically validate the accessory's X.509 certificate or its signature on our
    challenge — we have no Apple root CA key, and (importantly) nothing external enforces our own
    validation logic, since we ARE implementing the "iPod" role ourselves. We unconditionally
    accept whatever the accessory returns and tell it authentication succeeded. This is legitimate
    for a Pi emulating the phone side (iap.md's "Gate 1" analysis: classic iAP1's authentication
    threat model is the accessory proving itself to the phone, not the reverse) — not a shortcut
    around something that would otherwise block us.
  - Touch-event wire format is still UNKNOWN. This daemon does not attempt to parse touch data —
    it hex-dumps and timestamps everything it doesn't recognize into a separate capture file so a
    live trial (tap the head unit's screen while connected, then diff timing against the log) can
    find it empirically.

Usage (on the Pi, after setup_gadget.sh, BEFORE binding the UDC):
    sudo python3 iap1_daemon.py /dev/ffs-iap1
"""

import errno
import os
import select
import struct
import sys
import time

from apps import GENERAL_LINGO_IDENTITY, PHONE_IDENTITY
from markers import session_suffix

# ---- FunctionFS constants (uapi/linux/usb/functionfs.h) — same values used in
# pi/mirrorlink-ncm/mirrorlink_usb_cmd_listener.py and pi/aoa-gadget/aoa_gadget.c. ----

FUNCTIONFS_DESCRIPTORS_MAGIC_V2 = 3
FUNCTIONFS_STRINGS_MAGIC = 2
FUNCTIONFS_HAS_FS_DESC = 1
FUNCTIONFS_HAS_HS_DESC = 2

USB_DT_INTERFACE = 4
USB_DT_ENDPOINT = 5
USB_ENDPOINT_XFER_BULK = 2
USB_DIR_IN = 0x80
USB_DIR_OUT = 0x00

EVENT_NAMES = ["BIND", "UNBIND", "ENABLE", "DISABLE", "SETUP", "SUSPEND", "RESUME"]
FUNCTIONFS_SETUP = 4
FUNCTIONFS_ENABLE = 2

# ---- iAP1 (classic "iPod Accessory Protocol", public/non-NDA) packet framing ----

SYNC = b"\xff\x55"
LINGO_GENERAL = 0x00

# Which sync form build_packet() emits — "full" (0xFF 0x55) or "short" (bare 0x55, SYNC_SHORT).
# Defaults to "full" for USB (unconfirmed either way, though the spec below suggests "short" is
# probably right there too). btsdp_iap.py overrides this to "short" at import time for Bluetooth:
# confirmed twice over — first by decompiling NEventWatcher.exe's own outgoing iAP1-over-Bluetooth
# packet builder (FUN_0001f714, 2026-08-10), which writes only a single 0x55 byte as its ENTIRE
# sync sequence, and second by Apple's own public spec ("iPod Accessory Protocol Interface
# Specification" R38), which marks the leading 0xFF byte "Sync byte (required only for UART
# serial)" in every packet table — i.e. Bluetooth (and USB) genuinely don't use it.
OUTGOING_SYNC_MODE = "full"

# Verified 2026-08-10 against Apple's real "iPod Accessory Protocol Interface Specification"
# (Release R38) — see module docstring. Direction is Device-to-iPod unless noted otherwise.
CMD_REQUEST_IDENTIFY = 0x00     # iPod-to-Device only; the accessory never sends this to us (it
                                 # already proactively sends StartIDPS on its own — observed live).
CMD_ACK = 0x02                  # iPod-to-Device: generic ack. payload = [status, ackedCmdId].
CMD_REQUEST_IPOD_NAME = 0x07
CMD_RETURN_IPOD_NAME = 0x08
CMD_REQUEST_SOFTWARE_VERSION = 0x0B
CMD_RETURN_SOFTWARE_VERSION = 0x0C
CMD_REQUEST_SERIAL_NUM = 0x0F
CMD_RETURN_SERIAL_NUM = 0x10
CMD_REQUEST_MODEL_NUM = 0x1F
CMD_RETURN_MODEL_NUM = 0x20

# ---- Device (MFi) authentication — spec Commands 0x14-0x19. We initiate this ourselves right
# after IDPS completes (see CMD_END_IDPS's handling in process_rx) and unconditionally accept
# whatever the accessory returns — see module docstring for why that's legitimate here. ----
CMD_GET_DEV_AUTHENTICATION_INFO = 0x14        # iPod-to-Device, no payload.
CMD_RET_DEV_AUTHENTICATION_INFO = 0x15        # Device-to-iPod: [majorVer, minorVer] (Auth 1.0) or
                                               # [2, 0, curSection, maxSection, certData...] (2.0).
CMD_ACK_DEV_AUTHENTICATION_INFO = 0x16        # iPod-to-Device: [status] (0 = supported).
CMD_GET_DEV_AUTHENTICATION_SIGNATURE = 0x17   # iPod-to-Device: [challenge(16 or 20B), retryCounter].
CMD_RET_DEV_AUTHENTICATION_SIGNATURE = 0x18   # Device-to-iPod: [signature...].
CMD_ACK_DEV_AUTHENTICATION_STATUS = 0x19      # iPod-to-Device: [status] (0 = authenticated).

# ---- IDPS (Identify Device Preferences and Settings) — spec Commands 0x38-0x3C. This is the
# real identity of the "cmd=0x38" traffic every earlier trial captured — see module docstring. ----
CMD_START_IDPS = 0x38                # Device-to-iPod: [transIdHi, transIdLo].
CMD_SET_FID_TOKEN_VALUES = 0x39      # Device-to-iPod: [transIdHi, transIdLo, numTokens, tokens...].
CMD_RET_FID_TOKEN_VALUE_ACKS = 0x3A  # iPod-to-Device: [transIdHi, transIdLo, numAcks, acks...].
CMD_END_IDPS = 0x3B                  # Device-to-iPod: [transIdHi, transIdLo, accEndIDPSStatus].
CMD_IDPS_STATUS = 0x3C               # iPod-to-Device: [transIdHi, transIdLo, status].

# ---- Lingo capability discovery — spec Commands 0x4B/0x4C. Sent by the accessory once per Lingo
# it's interested in (General, Simple Remote, Display Remote, ...), each on its own request/reply
# — observed live 2026-08-10 immediately after IDPS+auth: the accessory retried this repeatedly
# with an incrementing LingoID (0x00, 0x02, 0x03, ...) since we never answered. ----
CMD_GET_IPOD_OPTIONS_FOR_LINGO = 0x4B  # Device-to-iPod: spec payload is just [LingoId] (1 byte),
                                        # though this head unit's actual on-wire request is 3
                                        # bytes ([transIdHi, transIdLo, LingoId]) — an
                                        # undocumented extension beyond the base spec, consistent
                                        # with the same transID-prefix convention used for
                                        # StartIDPS/SetFIDTokenValues/EndIDPS. We read LingoId as
                                        # the LAST payload byte so this is robust to either shape.
CMD_RET_IPOD_OPTIONS_FOR_LINGO = 0x4C  # iPod-to-Device: [LingoId, 8 option bits, big-endian]
                                        # (spec Table 2-112 — no transID slot exists here, so our
                                        # reply doesn't echo one, matching the base spec exactly).

# Spec Table 2-110's per-Lingo option bitmasks — bit N means "iPod supports feature N for this
# Lingo." Every Lingo defaults to 0 (no special capabilities — we don't implement audio/video/
# remote-control features) EXCEPT General Lingo (0x00), where bit 0x0D, "Communication with
# iPhone OS 3.x applications," is set — this is almost certainly the flag that gates whether the
# accessory will even attempt EA-style app-session communication (OpenDataSessionForProtocol,
# General Lingo cmd 0x3F) with us at all, which is the whole point of this exercise.
LINGO_GENERAL_OPTIONS_COMM_WITH_APPS = 1 << 0x0D
LINGO_OPTIONS = {
    LINGO_GENERAL: LINGO_GENERAL_OPTIONS_COMM_WITH_APPS,
}

SYNC_SHORT = SYNC[1:]  # bare 0x55 — the real framing for every non-UART transport, per spec.


def iap1_checksum(body: bytes) -> int:
    """body = LEN byte + payload (lingo+cmd+params). Checksum makes sum(body + [checksum]) % 256 == 0."""
    return (0x100 - (sum(body) & 0xFF)) & 0xFF


def _build_body_and_checksum(lingo: int, cmd: int, payload: bytes):
    body_payload = bytes([lingo, cmd]) + payload
    length = len(body_payload)
    body = bytes([length]) + body_payload
    checksum = iap1_checksum(body)
    return body, checksum


def build_packet(lingo: int, cmd: int, payload: bytes = b"") -> bytes:
    """Builds a framed packet using OUTGOING_SYNC_MODE's sync form ("full" 0xFF 0x55, or "short"
    bare 0x55 — see OUTGOING_SYNC_MODE's docstring). This is the framing every response_*()
    builder in this file uses; btsdp_iap.py sets OUTGOING_SYNC_MODE = "short" at import time so
    all of its replies use the firmware-confirmed Bluetooth framing without each call site having
    to know about it."""
    body, checksum = _build_body_and_checksum(lingo, cmd, payload)
    sync = SYNC if OUTGOING_SYNC_MODE == "full" else SYNC_SHORT
    return sync + body + bytes([checksum])


def _parse_at(buf: bytes, header_len: int):
    """Tries to parse a packet whose sync bytes (header_len of them, already matched at buf[0]) are
    followed by <LEN><payload...><checksum>. Returns None if more data is needed, "bad_checksum" if
    a full candidate was available but didn't check out, or (lingo, cmd, payload, total_len)."""
    if len(buf) < header_len + 1:
        return None
    length = buf[header_len]
    total_len = header_len + 1 + length + 1
    if len(buf) < total_len:
        return None
    body = buf[header_len:header_len + 1 + length]
    checksum = buf[header_len + 1 + length]
    if iap1_checksum(body) != checksum:
        return "bad_checksum"
    lingo = buf[header_len + 1]
    cmd = buf[header_len + 2]
    payload = bytes(buf[header_len + 3:header_len + 1 + length])
    return lingo, cmd, payload, total_len


def try_parse_packet(buf: bytes):
    """Attempts to parse one iAP1 packet from the front of buf.

    Returns (lingo, cmd, payload, consumed_bytes) on success, or (None, None, None,
    skip_bytes) if buf doesn't start with a valid packet — skip_bytes is how many bytes to
    drop before trying again (0 if more data is needed, otherwise how much garbage to discard
    before the next recoverable sync point).

    Recognizes two sync forms: the full SYNC (0xFF 0x55, UART-only per spec) and the bare
    SYNC_SHORT (0x55 alone, the real framing for Bluetooth/USB — see OUTGOING_SYNC_MODE's
    docstring). SYNC_SHORT matches are checksum-gated before being accepted, since a bare 0x55 is
    far more likely to turn up by coincidence in unrelated bytes than the 2-byte full sync is.
    """
    full_idx = buf.find(SYNC)
    short_idx = buf.find(SYNC_SHORT)
    if full_idx != -1 and (short_idx == -1 or full_idx <= short_idx):
        sync_idx, header_len = full_idx, len(SYNC)
    elif short_idx != -1:
        sync_idx, header_len = short_idx, len(SYNC_SHORT)
    else:
        # No sync candidate at all. Don't blindly discard a trailing 0xFF — it may be the first
        # half of a full sync split across two reads (see iap.md, "First live Bluetooth iAP1
        # packet decoded" — this exact scenario caused a real bug previously).
        if buf[-1:] == SYNC[:1]:
            return None, None, None, None, len(buf) - 1
        return None, None, None, None, len(buf)

    if sync_idx > 0:
        # Garbage before the next sync — let the caller log it as unclassified data, then
        # retry parsing from the sync point.
        return None, None, None, None, sync_idx

    result = _parse_at(buf, header_len)
    if result is None:
        return None, None, None, None, 0  # need more data
    if result == "bad_checksum":
        # Coincidental sync byte(s) — treat just the matched sync as garbage and resync.
        return None, None, None, None, header_len
    lingo, cmd, payload, total_len = result
    return lingo, cmd, payload, total_len, 0


# ---- Gadget descriptor/strings blobs (same shape as aoa_gadget.c / mirrorlink_usb_cmd_listener.py,
# just built with struct.pack here instead of a C struct literal). One vendor-class interface, one
# bulk OUT (head unit -> us) and one bulk IN (us -> head unit) endpoint. ----

IFACE_STRING = b"9CarPlay iAP1 bridge\x00"


def build_endpoint_descriptor(addr: int, max_packet: int) -> bytes:
    # bLength, bDescriptorType, bEndpointAddress, bmAttributes, wMaxPacketSize, bInterval
    return struct.pack("<BBBBHB", 7, USB_DT_ENDPOINT, addr, USB_ENDPOINT_XFER_BULK, max_packet, 0)


def build_interface_descriptor() -> bytes:
    # bLength, bDescriptorType, bInterfaceNumber, bAlternateSetting, bNumEndpoints,
    # bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol, iInterface
    #
    # bInterfaceClass 0xFF (vendor-specific) is unavoidably a guess. bInterfaceSubClass/Protocol
    # were originally 0xFF/0xFF (fully generic, matching the same starting point pi/aoa-gadget/
    # used) — updated to 0xFE/0x02 instead, which is NOT a guess: it's the publicly documented
    # (non-NDA) interface identity real iPhones present for their USB "usbmux" multiplexing
    # interface (the channel iAP/iTunes-sync/etc. are carried over), per libimobiledevice/usbmuxd's
    # own published USB device-matching rules and the Linux `ipheth` driver source, both of which
    # match on idVendor=0x05ac + interface class/subclass/protocol 0xFF/0xFE/0x02. If the head
    # unit's USB stack is filtering candidate "phone" interfaces by these bytes (plausible, given
    # BIND/ENABLE completes but nothing above that engages — see iap.md/README "Known gaps"), this
    # is a strictly better-informed guess than the fully generic one it replaces.
    return struct.pack("<BBBBBBBBB", 9, USB_DT_INTERFACE, 0, 0, 2, 0xFF, 0xFE, 0x02, 1)


def build_descriptors() -> bytes:
    intf = build_interface_descriptor()
    fs_out = build_endpoint_descriptor(1 | USB_DIR_OUT, 64)
    fs_in = build_endpoint_descriptor(2 | USB_DIR_IN, 64)
    hs_out = build_endpoint_descriptor(1 | USB_DIR_OUT, 512)
    hs_in = build_endpoint_descriptor(2 | USB_DIR_IN, 512)
    fs_descs = intf + fs_out + fs_in
    hs_descs = intf + hs_out + hs_in
    body = struct.pack("<II", 3, 3) + fs_descs + hs_descs  # fs_count=3, hs_count=3 (intf + 2 eps)
    flags = FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC
    header_len = 12
    header = struct.pack("<III", FUNCTIONFS_DESCRIPTORS_MAGIC_V2, header_len + len(body), flags)
    return header + body


def build_strings() -> bytes:
    body = struct.pack("<H", 0x0409) + IFACE_STRING
    header_len = 16
    header = struct.pack("<IIII", FUNCTIONFS_STRINGS_MAGIC, header_len + len(body), 1, 1)
    return header + body


# ---- Response builders, using apps.py data ----

def response_ipod_name() -> bytes:
    payload = GENERAL_LINGO_IDENTITY["ipod_name"].encode("ascii") + b"\x00"
    return build_packet(LINGO_GENERAL, CMD_RETURN_IPOD_NAME, payload)


def response_software_version() -> bytes:
    major, minor, rev = GENERAL_LINGO_IDENTITY["software_version"]
    return build_packet(LINGO_GENERAL, CMD_RETURN_SOFTWARE_VERSION, bytes([major, minor, rev]))


def response_serial_num() -> bytes:
    payload = GENERAL_LINGO_IDENTITY["serial_number"].encode("ascii") + b"\x00"
    return build_packet(LINGO_GENERAL, CMD_RETURN_SERIAL_NUM, payload)


def response_model_num() -> bytes:
    payload = GENERAL_LINGO_IDENTITY["model_number"].encode("ascii") + b"\x00"
    return build_packet(LINGO_GENERAL, CMD_RETURN_MODEL_NUM, payload)


REQUEST_HANDLERS = {
    CMD_REQUEST_IPOD_NAME: response_ipod_name,
    CMD_REQUEST_SOFTWARE_VERSION: response_software_version,
    CMD_REQUEST_SERIAL_NUM: response_serial_num,
    CMD_REQUEST_MODEL_NUM: response_model_num,
}


# ---- IDPS (spec Commands 0x38-0x3C) ----

def build_ack(status: int, acked_cmd: int) -> bytes:
    """Generic ACK (cmd=0x02): payload = [status, ackedCmdId]. Spec Table 2-12."""
    return build_packet(LINGO_GENERAL, CMD_ACK, bytes([status, acked_cmd]))


def parse_fid_token_values(payload: bytes):
    """Parses a SetFIDTokenValues payload ([transIdHi, transIdLo, numTokens, <fields>], spec Table
    2-68) into (trans_id, fields) — fields is a list of (info_byte_1, info_byte_2, data) per spec
    Table 2-69. Each field's own leading length byte does not include itself."""
    trans_id = (payload[0] << 8) | payload[1]
    num_tokens = payload[2]
    fields = []
    offset = 3
    for _ in range(num_tokens):
        length = payload[offset]
        info1 = payload[offset + 1]
        info2 = payload[offset + 2]
        data = bytes(payload[offset + 3:offset + 1 + length])
        fields.append((info1, info2, data))
        offset += 1 + length
    return trans_id, fields


def build_ret_fid_token_value_acks(trans_id: int, token_fields) -> bytes:
    """Acks every received FIDTokenValues field with a generic success ACK (spec Table 2-83's
    4-byte shape: [length=3, infoByte1, infoByte2, ACKStatus=0]). We always accept — as the "iPod"
    role, we're the one deciding what counts as valid identification, and nothing external is
    checking our judgment; see module docstring."""
    payload = bytes([(trans_id >> 8) & 0xFF, trans_id & 0xFF, len(token_fields)])
    for info1, info2, _data in token_fields:
        payload += bytes([0x03, info1, info2, 0x00])
    return build_packet(LINGO_GENERAL, CMD_RET_FID_TOKEN_VALUE_ACKS, payload)


def build_idps_status(trans_id: int, status: int = 0x00) -> bytes:
    """Spec Table 2-93. status=0x00: all required tokens received, authentication will proceed."""
    payload = bytes([(trans_id >> 8) & 0xFF, trans_id & 0xFF, status])
    return build_packet(LINGO_GENERAL, CMD_IDPS_STATUS, payload)


# ---- Lingo capability discovery (spec Commands 0x4B/0x4C) ----

def build_ret_ipod_options_for_lingo(lingo_id: int) -> bytes:
    """Spec Table 2-112: [LingoId, 8 option bits big-endian]. Options come from LINGO_OPTIONS,
    defaulting to 0 (no special capabilities) for any Lingo we don't have an entry for."""
    options = LINGO_OPTIONS.get(lingo_id, 0)
    payload = bytes([lingo_id]) + struct.pack(">Q", options)
    return build_packet(LINGO_GENERAL, CMD_RET_IPOD_OPTIONS_FOR_LINGO, payload)


# ---- Device (MFi) authentication (spec Commands 0x14-0x19) ----

def build_get_dev_authentication_info() -> bytes:
    return build_packet(LINGO_GENERAL, CMD_GET_DEV_AUTHENTICATION_INFO)


def build_ack_dev_authentication_info(status: int = 0x00) -> bytes:
    return build_packet(LINGO_GENERAL, CMD_ACK_DEV_AUTHENTICATION_INFO, bytes([status]))


def build_get_dev_authentication_signature(challenge: bytes, retry_counter: int) -> bytes:
    return build_packet(LINGO_GENERAL, CMD_GET_DEV_AUTHENTICATION_SIGNATURE,
                         challenge + bytes([retry_counter]))


def build_ack_dev_authentication_status(status: int = 0x00) -> bytes:
    return build_packet(LINGO_GENERAL, CMD_ACK_DEV_AUTHENTICATION_STATUS, bytes([status]))


def handle_ret_dev_authentication_info(state, payload: bytes, ep_in_fd):
    """RetDevAuthenticationInfo (cmd=0x15) — spec Table 2-36 (Authentication 1.0: [majorVer,
    minorVer]) or Table 2-37 (Authentication 2.0: [2, 0, curSection, maxSection, certData...],
    possibly split across multiple sections). Per spec: ack every non-final 2.0 section with a
    plain ACK(0x02), and only the final section with AckDevAuthenticationInfo(0x16) — then kick
    off the challenge/signature step (0x17) regardless of version, since we don't validate the
    certificate anyway (see module docstring)."""
    major, minor = payload[0], payload[1]
    if major == 0x02:
        cur_section, max_section = payload[2], payload[3]
        cert_chunk = bytes(payload[4:])
        state.cert_buf += cert_chunk
        print(f"  -> RetDevAuthenticationInfo (Authentication 2.0, section {cur_section}/"
              f"{max_section}, {len(cert_chunk)} cert byte(s), {len(state.cert_buf)} total)")
        if cur_section < max_section:
            os.write(ep_in_fd, build_ack(0x00, CMD_RET_DEV_AUTHENTICATION_INFO))
            return  # wait for the next section before proceeding
        print("  -> certificate complete; acking + requesting device signature")
        os.write(ep_in_fd, build_ack_dev_authentication_info(0x00))
    else:
        print(f"  -> RetDevAuthenticationInfo (Authentication {major}.{minor}); "
              "acking + requesting device signature")
        os.write(ep_in_fd, build_ack_dev_authentication_info(0x00))

    state.auth_retry_counter += 1
    challenge_len = 20 if major == 0x02 else 16
    challenge = os.urandom(challenge_len)
    os.write(ep_in_fd,
             build_get_dev_authentication_signature(challenge, state.auth_retry_counter))


# ---- runtime ----

def hexdump(buf: bytes) -> str:
    lines = []
    for i in range(0, len(buf), 16):
        chunk = buf[i:i + 16]
        lines.append(f"    {i:04x}: " + " ".join(f"{b:02x}" for b in chunk))
    return "\n".join(lines)


class State:
    def __init__(self, capture_path, unclassified_path):
        self.rx_buf = bytearray()
        self.capture_fp = open(capture_path, "ab")
        self.unclassified_fp = open(unclassified_path, "ab")
        # IDPS/device-authentication state machine — see CMD_START_IDPS's docstring.
        self.idps_done = False
        self.cert_buf = bytearray()   # X.509 certificate reassembly (Authentication 2.0 only)
        self.auth_retry_counter = 0


def handle_setup(ep0_fd, req_bytes: bytes):
    breq_type, brequest, wvalue, windex, wlength = struct.unpack("<BBHHH", req_bytes)
    print(f"[setup] bRequestType=0x{breq_type:02x} bRequest=0x{brequest:02x} "
          f"wValue=0x{wvalue:04x} wIndex=0x{windex:04x} wLength={wlength}")
    is_in = bool(breq_type & 0x80)
    if not is_in and wlength > 0:
        # Drain any host-to-device data stage for requests we don't specifically handle, so the
        # transfer completes cleanly instead of stalling on unread data (same pattern as
        # mirrorlink_usb_cmd_listener.py).
        try:
            os.read(ep0_fd, wlength)
        except OSError:
            pass


def ep0_event_loop(ep0_fd):
    """Returns (running, enabled) — enabled is True if a FUNCTIONFS_ENABLE event was seen in this
    batch, signaling the caller should (re)open the bulk endpoints (see open_bulk_eps/main).
    """
    data = os.read(ep0_fd, 12 * 8)
    if not data:
        print("[ep0] closed, exiting")
        return False, False
    enabled = False
    for i in range(0, len(data) - 11, 12):
        raw = data[i:i + 8]
        ev_type = data[i + 8]
        name = EVENT_NAMES[ev_type] if ev_type < len(EVENT_NAMES) else f"?{ev_type}"
        if ev_type == FUNCTIONFS_SETUP:
            handle_setup(ep0_fd, raw)
        else:
            print(f"[event] {name}")
            if ev_type == FUNCTIONFS_ENABLE:
                print("[event] gadget ENABLEd by head unit — enumeration complete, watching "
                      "bulk OUT for iAP1 traffic now.")
                enabled = True
    return True, enabled


def write_record(fp, ts: float, data: bytes):
    """Shared timestamped-record framing (double timestamp + uint32 length + raw bytes) used by
    both the capture and unclassified files, so decode_capture.py can read either with one
    reader — see read_records() there."""
    fp.write(struct.pack("<dI", ts, len(data)) + data)
    fp.flush()


def process_rx(state: State, ep_in_fd):
    """Tries to parse as many complete packets as possible out of state.rx_buf, dispatching
    handled ones and logging everything else (both recognized-but-unhandled packets and raw
    unparseable bytes — the latter is where touch data, if it's on this channel at all, would
    show up) to the capture files for offline analysis."""
    progressed = True
    while progressed and state.rx_buf:
        progressed = False
        lingo, cmd, payload, consumed, skip = try_parse_packet(bytes(state.rx_buf))
        if consumed:
            pkt_bytes = bytes(state.rx_buf[:consumed])
            del state.rx_buf[:consumed]
            write_record(state.capture_fp, time.time(), pkt_bytes)
            print(f"[rx] iAP1 packet lingo=0x{lingo:02x} cmd=0x{cmd:02x} "
                  f"payload={payload!r}")
            if lingo == LINGO_GENERAL and cmd == CMD_START_IDPS:
                trans_id = (payload[0] << 8) | payload[1]
                print(f"  -> StartIDPS (transID={trans_id}) — acking")
                os.write(ep_in_fd, build_ack(0x00, CMD_START_IDPS))
            elif lingo == LINGO_GENERAL and cmd == CMD_SET_FID_TOKEN_VALUES:
                trans_id, fields = parse_fid_token_values(payload)
                print(f"  -> SetFIDTokenValues (transID={trans_id}, {len(fields)} token(s)):")
                for info1, info2, data in fields:
                    print(f"       token id=(0x{info1:02x},0x{info2:02x}) data={data!r}")
                os.write(ep_in_fd, build_ret_fid_token_value_acks(trans_id, fields))
            elif lingo == LINGO_GENERAL and cmd == CMD_END_IDPS:
                trans_id = (payload[0] << 8) | payload[1]
                acc_status = payload[2]
                print(f"  -> EndIDPS (transID={trans_id}, accEndIDPSStatus={acc_status})")
                os.write(ep_in_fd, build_idps_status(trans_id, 0x00))
                if acc_status == 0x00 and not state.idps_done:
                    state.idps_done = True
                    print("  -> IDPS complete — initiating authentication "
                          "(GetDevAuthenticationInfo)")
                    os.write(ep_in_fd, build_get_dev_authentication_info())
            elif lingo == LINGO_GENERAL and cmd == CMD_RET_DEV_AUTHENTICATION_INFO:
                handle_ret_dev_authentication_info(state, payload, ep_in_fd)
            elif lingo == LINGO_GENERAL and cmd == CMD_RET_DEV_AUTHENTICATION_SIGNATURE:
                print(f"  -> RetDevAuthenticationSignature ({len(payload)}-byte signature) — "
                      "accepting unconditionally (see module docstring)")
                os.write(ep_in_fd, build_ack_dev_authentication_status(0x00))
            elif lingo == LINGO_GENERAL and cmd == CMD_GET_IPOD_OPTIONS_FOR_LINGO:
                lingo_id = payload[-1]
                options = LINGO_OPTIONS.get(lingo_id, 0)
                print(f"  -> GetiPodOptionsForLingo (lingo=0x{lingo_id:02x}) — replying with "
                      f"options=0x{options:016x}")
                os.write(ep_in_fd, build_ret_ipod_options_for_lingo(lingo_id))
            elif lingo == LINGO_GENERAL and cmd in REQUEST_HANDLERS:
                resp = REQUEST_HANDLERS[cmd]()
                print(f"  -> recognized request cmd=0x{cmd:02x}, replying")
                os.write(ep_in_fd, resp)
            else:
                print(f"  -> unrecognized lingo/cmd combination, no reply sent "
                      f"(logged to {state.capture_fp.name})")
            progressed = True
        elif skip:
            garbage = bytes(state.rx_buf[:skip])
            del state.rx_buf[:skip]
            ts = time.time()
            print(f"[rx] {len(garbage)} unclassified byte(s) (not a valid iAP1 packet) — "
                  f"logged with timestamp {ts:.3f} for touch-correlation analysis:")
            print(hexdump(garbage))
            write_record(state.unclassified_fp, ts, garbage)
            progressed = True
        # else: need more data, wait for next read


def open_bulk_eps(mount, old_out=None, old_in=None):
    """(Re)opens the bulk OUT/IN endpoint files. FunctionFS invalidates the previously-open ep1/
    ep2 file descriptors across a UDC unbind/rebind cycle (a soft disconnect/reconnect, e.g. via
    cycle_usb.sh) — attempting to read a stale fd afterward fails permanently with ESHUTDOWN
    ("Cannot send after transport endpoint shutdown"), even once the gadget re-enumerates and a
    fresh FUNCTIONFS_ENABLE event arrives on ep0. There is no way to "revive" the old fd; the fix
    is to close it and open the (same-path, but kernel-side-fresh) endpoint files again. Called
    both right after a FUNCTIONFS_ENABLE event (the normal case) and as a fallback if a read ever
    hits ESHUTDOWN/ENODEV directly (belt-and-suspenders against event/read ordering)."""
    for fd in (old_out, old_in):
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    new_out = os.open(os.path.join(mount, "ep1"), os.O_RDONLY | os.O_NONBLOCK)
    new_in = os.open(os.path.join(mount, "ep2"), os.O_WRONLY)
    return new_out, new_in


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <functionfs-mountpoint>   (e.g. /dev/ffs-iap1)",
              file=sys.stderr)
        sys.exit(1)
    mount = sys.argv[1]

    if os.geteuid() != 0:
        print("Must run as root", file=sys.stderr)
        sys.exit(1)

    ep0_fd = os.open(os.path.join(mount, "ep0"), os.O_RDWR)
    n = os.write(ep0_fd, build_descriptors())
    print(f"wrote {n} bytes of descriptors to ep0")
    n = os.write(ep0_fd, build_strings())
    print(f"wrote {n} bytes of strings to ep0")

    ep_out_fd, ep_in_fd = open_bulk_eps(mount)

    print("Descriptors written and all endpoints opened.")
    print("Now bind the UDC in another shell to start enumeration (or use cycle_usb.sh):")
    print("  echo <udc-name> > /sys/kernel/config/usb_gadget/iap1_0/UDC\n")

    # Fresh, timestamped filenames per launch — a static filename opened in append mode
    # previously let one trial's data silently mix with every earlier trial's leftovers, which
    # once produced a marker landing 11.4 hours from the nearest logged packet (see iap.md,
    # "cmd=0x38 confirmed as a periodic post-launch retry/status poll").
    suffix = session_suffix()
    state = State(f"iap1_capture_{suffix}.bin", f"iap1_unclassified_{suffix}.bin")
    print(f"Session suffix: {suffix} (run markers.py {suffix} alongside this for correlation)")
    print(f"Identified/recognized iAP1 packets -> {state.capture_fp.name}")
    print(f"Unclassified bytes (raw, timestamped) -> {state.unclassified_fp.name}")
    print(f"Phone identity in use: {PHONE_IDENTITY}")
    print("\nWatching ep0 and bulk OUT concurrently. Ctrl-C to stop.\n")

    poller = select.poll()
    poller.register(ep0_fd, select.POLLIN)

    running = True
    while running:
        # ep0 has a real .poll() implementation in FunctionFS; the bulk endpoint files do not
        # in most kernels (same caveat documented in aoa_gadget.c), so ep_out is opened
        # O_NONBLOCK above and just polled by attempting a read every loop iteration rather
        # than relying on select/poll readiness for it.
        events = poller.poll(500)
        for fd, ev in events:
            if fd == ep0_fd and (ev & select.POLLIN):
                running, enabled = ep0_event_loop(ep0_fd)
                if enabled:
                    # The previously-open bulk fds are about to be (or already are) invalid —
                    # see open_bulk_eps' docstring. Re-register nothing here since ep_out is
                    # polled by direct non-blocking read below, not via `poller`.
                    print("[bulk] reopening ep1/ep2 after ENABLE (old fds are invalid post-cycle)")
                    try:
                        ep_out_fd, ep_in_fd = open_bulk_eps(mount, ep_out_fd, ep_in_fd)
                    except OSError as reopen_err:
                        print(f"[bulk] reopen after ENABLE failed: {reopen_err} — will fall "
                              "back to reopening on the next read error", file=sys.stderr)
                    else:
                        # Nothing to send proactively — per spec the accessory initiates by
                        # sending StartIDPS on its own (CMD_START_IDPS's handling below reacts
                        # to it). See module docstring for why the old proactive app-announcement
                        # send was removed.
                        print("[bulk] ready — waiting for the head unit to send StartIDPS")

        try:
            chunk = os.read(ep_out_fd, 16384)
            if chunk:
                state.rx_buf += chunk
                process_rx(state, ep_in_fd)
        except BlockingIOError:
            pass
        except OSError as e:
            print(f"[ep_out] read error: {e}", file=sys.stderr)
            if e.errno in (errno.ESHUTDOWN, errno.ENODEV):
                print("[bulk] endpoint shut down — reopening ep1/ep2 as a fallback "
                      "(normally the ENABLE-triggered reopen above should have already done "
                      "this; seeing this message means that ordering didn't happen)")
                try:
                    ep_out_fd, ep_in_fd = open_bulk_eps(mount, ep_out_fd, ep_in_fd)
                except OSError as reopen_err:
                    print(f"[bulk] reopen failed: {reopen_err} — will keep retrying",
                          file=sys.stderr)

    state.capture_fp.close()
    state.unclassified_fp.close()
    os.close(ep0_fd)
    os.close(ep_out_fd)
    os.close(ep_in_fd)


if __name__ == "__main__":
    main()
