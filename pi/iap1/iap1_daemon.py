#!/usr/bin/env python3
"""iap1_daemon — legacy iAP1 "HondaLink phone" scaffold over a Linux FunctionFS USB gadget.

Implements the Gate 2 (app whitelist) plan from references/cr-v/iap.md: since full decompilation
of Communication.exe's `SetServerVRAppData`/`IsAuthInfoAllExist`/`CheckAuthInfo` found NO local
whitelist database and NO content comparison anywhere in that path — only a presence/completeness
check across six identity fields — satisfying it is a data-shape problem, not a cryptographic one.
This daemon supplies plausible, well-formed values for those fields (see apps.py) over a generic
iAP1-shaped USB link, so a live trial against the real head unit can observe how far the connection
gets. Gate 1 (device attestation, MFi) is a SEPARATE, still-unresolved question (iap.md, "Open
risks" #2) — if the head unit demands genuine MFi authentication before this layer is even reached,
this scaffold is expected to stall there. That's the boundary this test is designed to find.

WHAT IS CONFIDENT vs BEST-EFFORT here (be honest with yourself when reading logs):
  - USB gadget enumeration (Apple VID, plausible iPhone PID, vendor-class bulk interface) — same
    confidence level as every other gadget in this repo (pi/aoa-gadget, pi/mirrorlink-ncm): built
    against public USB/FunctionFS mechanics, untested against this specific head unit.
  - iAP1 packet framing (sync bytes, length, checksum) — this is CONFIDENT. This exact framing
    (0xFF 0x55 <LEN> <payload...> <checksum>, checksum making the post-sync bytes sum to 0 mod 256)
    is consistently documented across the public, pre-2010, non-NDA "iPod Accessory Protocol"
    community documentation that predates Apple's strict MFi authentication-chip enforcement — the
    same baseline countless hobbyist/aftermarket iPod accessories implemented without any secret
    Apple key material. This is NOT Apple's confidential iAP2/MFi wire spec; it's the older, public
    protocol family.
  - The SPECIFIC command IDs used below (RequestIdentify=0x00 etc.) are the single biggest
    unconfirmed guess in this file — assigned from the commonly-described Request(even)/
    Return(odd) numbering convention seen across public references, NOT verified against what
    Honda's Communication.exe/CLP_LPAAuth actually expects on this specific head unit. Expect to
    revise these once a live trial or wire capture shows real traffic — this file's job right now
    is to be a instrumented, plausible starting point to iterate from, exactly like
    aoa_gadget.c and ssdp_announce.py were for their respective bearers.
  - How SetServerVRAppData's (ProtocolName/BundleId/URL/AppID) app-list data is actually carried
    on the wire is UNKNOWN (iap.md, "Open risks" #2 — the real implementation lives behind an
    unextracted module). APP_LIST_ANNOUNCE below is a placeholder transmission on a clearly
    out-of-Apple's-reserved-range Lingo ID, sent speculatively after identify completes, purely so
    a live capture has something concrete to correlate against — not a claim this is the real
    mechanism.
  - Touch-event wire format is UNKNOWN (PROTOCOL_ANALYSIS.md found no protocol-specific
    negotiation for it). This daemon does not attempt to parse touch data — it hex-dumps and
    timestamps everything it doesn't recognize into a separate capture file so a live trial (tap
    the head unit's screen while connected, then diff timing against the log) can find it
    empirically, the same methodology already used successfully for AOA/CDC-NCM discovery.

Usage (on the Pi, after setup_gadget.sh, BEFORE binding the UDC):
    sudo python3 iap1_daemon.py /dev/ffs-iap1
"""

import errno
import os
import select
import struct
import sys
import time

from apps import APPS, GENERAL_LINGO_IDENTITY, PHONE_IDENTITY
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

# See module docstring — these specific numeric assignments are the least-confident part of this
# file. Named symbolically so the mapping is easy to revise in one place once real traffic is
# observed.
CMD_REQUEST_IDENTIFY = 0x00
CMD_ACK_IDENTIFY = 0x02
CMD_REQUEST_IPOD_NAME = 0x07
CMD_RETURN_IPOD_NAME = 0x08
CMD_REQUEST_SOFTWARE_VERSION = 0x0B
CMD_RETURN_SOFTWARE_VERSION = 0x0C
CMD_REQUEST_SERIAL_NUM = 0x0F
CMD_RETURN_SERIAL_NUM = 0x10
CMD_REQUEST_MODEL_NUM = 0x1F
CMD_RETURN_MODEL_NUM = 0x20

# Head-unit-originated status/heartbeat poll — see iap.md, "cmd=0x38 confirmed as a periodic
# post-launch retry/status poll." Consistently observed arriving as bare 0x55 (SYNC_SHORT below),
# never the full 0xFF 0x55 sync every other packet in this file uses.
CMD_STATUS_POLL = 0x38
CMD_STATUS_POLL_ACK = 0x39

# See response_status_poll_ack()'s docstring.
STATUS_POLL_REPLY_MODE = "mirror"

# Deliberately outside any Lingo range documented in the public General Lingo family — a
# placeholder channel for the app-list announcement described in the module docstring, chosen
# purely to be distinctive and greppable in a live capture, not a claim about Honda's real Lingo
# assignment for this data.
LINGO_APP_LIST_PLACEHOLDER = 0xF0
CMD_APP_LIST_ANNOUNCE = 0x01

SYNC_SHORT = SYNC[1:]  # bare 0x55 — CMD_STATUS_POLL's consistent (missing-0xFF) framing


def iap1_checksum(body: bytes) -> int:
    """body = LEN byte + payload (lingo+cmd+params). Checksum makes sum(body + [checksum]) % 256 == 0."""
    return (0x100 - (sum(body) & 0xFF)) & 0xFF


def build_packet(lingo: int, cmd: int, payload: bytes = b"") -> bytes:
    body_payload = bytes([lingo, cmd]) + payload
    length = len(body_payload)
    body = bytes([length]) + body_payload
    checksum = iap1_checksum(body)
    return SYNC + body + bytes([checksum])


def build_packet_no_sync(lingo: int, cmd: int, payload: bytes = b"") -> bytes:
    """Same framing as build_packet, but with only the bare SYNC_SHORT (0x55) byte in front,
    omitting the leading 0xFF — see response_status_poll_ack()'s docstring for why."""
    body_payload = bytes([lingo, cmd]) + payload
    length = len(body_payload)
    body = bytes([length]) + body_payload
    checksum = iap1_checksum(body)
    return SYNC_SHORT + body + bytes([checksum])


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

    Recognizes two sync forms: the full SYNC (0xFF 0x55, used by every command except
    CMD_STATUS_POLL) and the bare SYNC_SHORT (0x55 alone, CMD_STATUS_POLL's consistent framing —
    see iap.md, "First live Bluetooth iAP1 packet decoded"). SYNC_SHORT matches are
    checksum-gated before being accepted, since a bare 0x55 is far more likely to turn up by
    coincidence in unrelated bytes than the 2-byte full sync is.
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

def response_ack_identify() -> bytes:
    # Best-effort payload: a single lingo-support bitmask byte (bit 0 = General Lingo supported)
    # followed by the device name. Exact expected shape unconfirmed — see module docstring.
    payload = bytes([0x01]) + GENERAL_LINGO_IDENTITY["ipod_name"].encode("ascii") + b"\x00"
    return build_packet(LINGO_GENERAL, CMD_ACK_IDENTIFY, payload)


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


def response_status_poll_ack(payload: bytes) -> bytes:
    """Replies to a CMD_STATUS_POLL (cmd=0x38), echoing back the received counter payload as
    CMD_STATUS_POLL_ACK (cmd=0x39) — see iap.md, "cmd=0x38 confirmed as a periodic post-launch
    retry/status poll." Untested against real hardware (iap.md documented an earlier "tested
    live: no effect" result, but the code that was supposedly tested was never actually committed
    — see iap.md's 2026-08-10 comparative re-verification note. Treat this as the first real
    attempt, not a retest.).

    STATUS_POLL_REPLY_MODE controls framing:
      - "mirror" (default): omit the leading 0xFF, matching CMD_STATUS_POLL's own observed
        wire framing (every captured instance arrives as bare 0x55, never 0xFF 0x55) — on the
        theory that if the head unit's transmit side is consistently short-framed for this
        command, its receive side might expect the same and silently drop a fully-synced reply.
      - "full": send a normally-framed (0xFF 0x55 ...) reply like every other packet in this file.
    """
    if STATUS_POLL_REPLY_MODE == "mirror":
        return build_packet_no_sync(LINGO_GENERAL, CMD_STATUS_POLL_ACK, payload)
    return build_packet(LINGO_GENERAL, CMD_STATUS_POLL_ACK, payload)


REQUEST_HANDLERS = {
    CMD_REQUEST_IDENTIFY: response_ack_identify,
    CMD_REQUEST_IPOD_NAME: response_ipod_name,
    CMD_REQUEST_SOFTWARE_VERSION: response_software_version,
    CMD_REQUEST_SERIAL_NUM: response_serial_num,
    CMD_REQUEST_MODEL_NUM: response_model_num,
}


def build_app_list_announce() -> bytes:
    """Speculative placeholder — see module docstring. Encodes PHONE_IDENTITY plus each entry
    in APPS as NUL-separated ASCII fields, matching the field order
    SetServerVRAppData(ProtocolName, BundleId, URL, AppID) logs on the head unit side, so a raw
    hex/string dump of a live capture is at least easy to eyeball against this if it does turn
    out to resemble the real mechanism.
    """
    parts = [
        PHONE_IDENTITY["manufacturer"],
        PHONE_IDENTITY["model"],
    ]
    for app in APPS:
        parts += [app["protocol_name"], app["bundle_id"], app["url"]]
    payload = ("\x00".join(parts) + "\x00").encode("ascii", errors="replace")
    for app in APPS:
        payload += struct.pack("<I", app["app_id"])
    return build_packet(LINGO_APP_LIST_PLACEHOLDER, CMD_APP_LIST_ANNOUNCE, payload)


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
        self.identify_seen = False
        self.app_list_sent = False
        self.capture_fp = open(capture_path, "ab")
        self.unclassified_fp = open(unclassified_path, "ab")


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
            if lingo == LINGO_GENERAL and cmd == CMD_REQUEST_IDENTIFY:
                state.identify_seen = True
                print("  -> looks like RequestIdentify — replying with AckIdentify "
                      f"(name={GENERAL_LINGO_IDENTITY['ipod_name']!r})")
                os.write(ep_in_fd, response_ack_identify())
            elif lingo == LINGO_GENERAL and cmd == CMD_STATUS_POLL:
                print(f"  -> status-poll (cmd=0x38), replying with ack "
                      f"(mode={STATUS_POLL_REPLY_MODE})")
                os.write(ep_in_fd, response_status_poll_ack(payload))
            elif lingo == LINGO_GENERAL and cmd in REQUEST_HANDLERS:
                resp = REQUEST_HANDLERS[cmd]()
                print(f"  -> recognized request cmd=0x{cmd:02x}, replying")
                os.write(ep_in_fd, resp)
            else:
                print(f"  -> unrecognized lingo/cmd combination, no reply sent "
                      f"(logged to {state.capture_fp.name})")
            if state.identify_seen and not state.app_list_sent:
                print("  -> identify has been seen at least once; sending speculative "
                      "app-list announcement (see module docstring)")
                os.write(ep_in_fd, build_app_list_announce())
                state.app_list_sent = True
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
    print(f"Apps advertised (once wired up on the wire): {[a['display_name'] for a in APPS]}")
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
