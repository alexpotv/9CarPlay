#!/usr/bin/env python3
"""iap_usb_bridge.py — run iAP1 over the USB-HID bearer (the AppMode data channel).

Architecture (see references/cr-v/IAP_OVER_USB.md):

    head unit (USB host, iPod_Class driver)
        │  interrupt-IN reports  (iPod -> HU : our TX)   ID 1..4
        │  SET_REPORT / OUT      (HU -> iPod : our RX)   ID 5..9
    ipod-gadget kernel module  <->  /dev/iap0  (raw HID report bytes, incl. report-ID byte)
        │
    hid_framing.py         report fragment / reassemble
        │
    THIS bridge            iAP1 packet layer + response policy
        │
    ../iap1/iap1_daemon.py TRANSPORT-AGNOSTIC packet builders/parsers  (reused verbatim)
    ../appmode/appmode_proto.py  AppMode DataParts codec  (reused)

The response policy is the **locked BT baseline** (references/cr-v/IAP_OVER_USB.md §Appendix), ported
from pi/iap1/btsdp_iap_guided.respond_to_packet with the hypothesis-sweep machinery collapsed to the
known-good config and the BT-only av1/av2 SPP dial removed (there is no SPP over USB — AppMode data
rides the iACS/ATC USB channel via the same iPodDataTransfer packets).

STATUS: transport + framing + response state machine all implemented. Verified off-Pi that respond()
emits byte-identical replies to the BT baseline for the real captured IDPS/auth sequence (StartIDPS,
cmd 0x11 -> RetTransportMaxPayloadSize, SetFIDTokenValues -> RetFIDTokenACK + GetDevAuthInfo, EndIDPS
-> IDPSStatus, MFi auth accept, EI returns, announce, DataParts kick + 0xB1->0xB2). Needs on-Pi
enumeration + the empirical unknowns in README.md.
"""

import os
import struct
import sys
import time

_T0 = time.monotonic()


def _ts() -> str:
    """Milliseconds since bridge start — correlate with the head-unit log's ms timestamps."""
    return f"{(time.monotonic() - _T0) * 1000:8.0f}"

# Line-buffer stdout so logs appear immediately even when piped to tee (a pipe is block-buffered by
# default — that can make a still-running bridge look silent). Diagnostic runs depend on this.
try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

# Raw-wire logging: with RAW_LOG on, every read()/write() of /dev/iap0 is dumped as hex BEFORE any
# framing/parse, so a run reveals exactly what the head unit sends (and whether it sends anything) —
# independent of whether our reassembler/parser accepts it. Set IAP_RAW_LOG=0 to quiet it.
RAW_LOG = os.environ.get("IAP_RAW_LOG", "1") != "0"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "iap1"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "appmode"))
import hid_framing

try:
    import iap1_daemon as iap
except Exception as e:   # pragma: no cover  (dbus/gi only on the Pi)
    iap = None
    _IAP_IMPORT_ERR = e
try:
    import appmode_proto as appmode
except Exception:        # pragma: no cover
    appmode = None

# The HID char device carrying raw iAP reports. Two bearers expose the same raw-report semantics:
#   - ipod-gadget kernel module        -> /dev/iap0   (legacy driver; binds deactivated — enum issues)
#   - configfs f_hid (setup_hid_gadget.sh) -> /dev/hidg0  (connects at bind; reaches 'configured')
# Override with env IAP_USB_DEV. Default prefers /dev/hidg0 (the configfs bearer) when present.
IAP0 = os.environ.get(
    "IAP_USB_DEV",
    "/dev/hidg0" if os.path.exists("/dev/hidg0") else "/dev/iap0",
)

# ---- locked baseline config (was Hypothesis kwargs; see IAP_OVER_USB.md §Appendix) --------------
MAX_PAYLOAD_SIZE = 0x0200                 # command 0x11 -> RetTransportMaxPayloadSize (512)
GENERAL_APP_BIT = 1 << 0x0D               # 0x2000 — "comms with iPhone-OS apps" (GetiPodOptionsForLingo)
GENERAL_OPTIONS = GENERAL_APP_BIT
OTHER_LINGO_OPTIONS = 0
EA_OPEN_PROTOCOLS = ("hondalink",)        # OpenDataSessionForProtocol target
DP_OPCODE_SWEEP = (0x41, 0x42, 0x40, 0x43)  # iPodDataTransfer opcode candidates for the kick
DP_B2_OPCODE = 0x41                       # opcode for the 0xB2 AuthResponse
STRIP_FF = True                           # HID frames start at 0x55; strip iap1_daemon's 0xFF lead-in

# EI (lingo 0x04) NowPlaying/DB Gets -> typed empty/stopped Returns (keeps the EI sequencer advancing)
EI_GET_RETURNS = {
    0x001c: (0x001d, b"\x00" * 9),        # GetPlayStatus -> ReturnPlayStatus: stopped
    0x002c: (0x002d, b"\x00"),            # GetShuffle    -> off
    0x002f: (0x0030, b"\x00"),            # GetRepeat     -> off
    0x0018: (0x0019, struct.pack(">I", 0)),  # GetNumberCategorizedDBRecords -> count 0
}


def build_ei_packet(cmd16, payload):
    """Extended-Interface (lingo 0x04) packet; command id is 2 bytes wide."""
    body_payload = bytes([iap.LINGO_EXTENDED_INTERFACE, (cmd16 >> 8) & 0xFF, cmd16 & 0xFF]) + payload
    body = bytes([len(body_payload)]) + body_payload
    sync = iap.SYNC if iap.OUTGOING_SYNC_MODE == "full" else iap.SYNC_SHORT
    return sync + body + bytes([iap.iap1_checksum(body)])


def to_hid_tx(iap_packet: bytes) -> list[bytes]:
    if STRIP_FF and iap_packet[:1] == b"\xff":
        iap_packet = iap_packet[1:]
    return hid_framing.encode_frame(iap_packet)


class IapUsbBridge:
    def __init__(self, path=IAP0):
        self.path = path
        self.fd = None
        self.reasm = hid_framing.FrameReassembler()
        # iAP session state (was on the harness object)
        self.ea_protocols = []
        self.ea_opened = False
        self.ea_session_id = None
        self.dp_kicked = False
        self.dp_b2_sent = False
        self.phases = set()
        self.got_rx = False        # set on the first inbound frame; stops the opener resend

    # --- transport -------------------------------------------------------------------------------
    def open(self):
        # O_NONBLOCK is REQUIRED, not an optimization. ipod-gadget's ipod_hid_dev_read/_write share
        # one mutex (hid->lock), and the BLOCKING read path holds that mutex while waiting for a
        # SET_REPORT — starving every write, which then never reaches usb_ep_queue (proven by usb/14:
        # one [raw-tx], no completion, HU IntIn read er[-5] instantly because nothing was queued).
        # ipod_mutex_lock(&hid->lock, f_flags & O_NONBLOCK) uses TRY-LOCK when O_NONBLOCK is set, so
        # neither read nor write parks on the mutex; we drive readability with poll() instead.
        self.fd = os.open(self.path, os.O_RDWR | os.O_NONBLOCK)
        print(f"[{_ts()}] [iap-usb] opened {self.path} (O_NONBLOCK, poll-driven)")

    def _write_report(self, report: bytes, tries=60, gap_s=0.01) -> bool:
        """Write one HID report on the non-blocking fd. EAGAIN means the driver mutex was momentarily
        contended (a read in flight) or write_fifo is full (HU not draining IN); retry briefly, then
        give up rather than deadlock. Returns True if the report was accepted into write_fifo."""
        for _ in range(tries):
            try:
                os.write(self.fd, report)
                return True
            except BlockingIOError:
                time.sleep(gap_s)
        return False

    # --- proactive opener ------------------------------------------------------------------------
    # usb/11-12 proved the head unit's USB iAP FSM is RECEIVE-FIRST: it mounts the iPod, then waits
    # for us to transmit (IACS_iAP_FSM_USB_Recv_ch1 iACS_receive_command NG, then an 18s IDPS timeout),
    # and never sends a SET_REPORT (bridge got zero [raw-rx]). Over BT the accessory "proactively sends
    # StartIDPS on its own"; over USB it does not, so the iPod must prompt it. Classic iAP1: the iPod
    # sends RequestIdentify (0x00) -> the accessory replies IdentifyDeviceLingoes -> handshake proceeds.
    # Opener is configurable so we can iterate cheaply across candidates; resent until the first inbound.
    def _build_named_opener(self, which):
        if which == "requestidentify":
            return iap.build_packet(iap.LINGO_GENERAL, iap.CMD_REQUEST_IDENTIFY, b"")
        if which == "identify":       # IdentifyDeviceLingoes 0x13: lingoesSpoken|options|deviceId
            lingoes = 0
            for l in (0x00, 0x02, 0x03, 0x04):
                lingoes |= (1 << l)
            return iap.build_packet(iap.LINGO_GENERAL, iap.CMD_IDENTIFY_DEVICE_LINGOES,
                                    struct.pack(">III", lingoes, 0, 0))
        if which == "startidps":
            return iap.build_packet(iap.LINGO_GENERAL, iap.CMD_START_IDPS, b"\x00\x00")
        return None

    def opener_loop(self, period_s=1.5, rounds=8):
        """Prompt the receive-first head unit. IAP_USB_OPENER selects a single opener; the default
        'auto' CYCLES through all candidates each round, so one connection tests them all — stopping
        the instant the head unit replies (got_rx). 'none' disables.

        usb/14 lesson: ipod-gadget's write BLOCKS until the host collects the IN report, and the HU
        never collected it (its IntIn read errored er[-5] instantly). A blocking write therefore froze
        this loop after the FIRST opener — we never tried the others and got no completion signal. So
        each opener is now sent on its OWN throwaway thread (_threaded_send): a stuck write can't stall
        the cadence, every candidate is actually attempted, and the [tx-done] line tells us whether ANY
        write ever completes (= whether the HU ever issues IN tokens that drain our endpoint at all)."""
        if iap is None:
            print("[opener] disabled (iap1_daemon unavailable)"); return
        sel = os.environ.get("IAP_USB_OPENER", "auto").lower()
        if sel == "none":
            print("[opener] disabled by IAP_USB_OPENER=none"); return
        names = ["requestidentify", "identify", "startidps"] if sel == "auto" else [sel]
        print(f"[{_ts()}] [opener] receive-first HU kick; cycling {names} every {period_s}s until reply")
        for rnd in range(rounds):
            for which in names:
                if self.got_rx:
                    return
                pkt = self._build_named_opener(which)
                if pkt is None:
                    print(f"[opener] unknown opener {which!r}, skipping"); continue
                self._threaded_send(pkt, note=f"OPENER {which} (round {rnd+1})")
                time.sleep(period_s)
        print(f"[{_ts()}] [opener] finished all rounds; read loop still running")

    def _threaded_send(self, pkt: bytes, note=""):
        """Fire a packet on a daemon thread so a blocking write can't stall the caller. Logs when the
        write STARTS and when it actually COMPLETES (host collected the report), each timestamped."""
        import threading

        def _run():
            for report in to_hid_tx(pkt):
                if RAW_LOG:
                    print(f"[{_ts()}] [raw-tx] {report.hex()}  {note}")
                if self._write_report(report):
                    print(f"[{_ts()}] [tx-queued] {report.hex()}  (accepted into write_fifo)")
                else:
                    print(f"[{_ts()}] [tx-err] EAGAIN x60  {note}  (fifo full / lock contended)")
                    return
            print(f"[{_ts()}] [tx  ] {pkt.hex()}  {note}")

        threading.Thread(target=_run, daemon=True).start()

    def send_packet(self, pkt: bytes, note=""):
        for report in to_hid_tx(pkt):
            if RAW_LOG:
                print(f"[{_ts()}] [raw-tx] {report.hex()}")
            if not self._write_report(report):
                print(f"[{_ts()}] [tx-err] EAGAIN x60  {note}")
                return
        print(f"[{_ts()}] [tx  ] {pkt.hex()}  {note}")

    def read_loop(self):
        import select
        poller = select.poll()
        poller.register(self.fd, select.POLLIN)
        while True:
            # poll() waits for readability WITHOUT holding hid->lock, so writes stay unblocked. Only
            # touch the fd (and thus the driver mutex) when there's actually a report to collect.
            if not poller.poll(500):
                continue
            try:
                report = os.read(self.fd, 128)
            except BlockingIOError:
                continue      # spurious wake / lost the try-lock race; poll again
            if not report:
                continue
            if RAW_LOG:
                print(f"[{_ts()}] [raw-rx] {report.hex()}")
            # Primary path: Apple LinkControl reassembly ([ReportID][LinkControl][payload]).
            frame = self.reasm.push(report)
            if frame is not None and self._on_frame(frame, "reasm"):
                continue
            # Fallback: the head unit may deliver via SET_REPORT, where the report-ID is in wValue
            # (not the data), so the report is [LinkControl][payload] — off by one for the reassembler.
            # IDPS/handshake packets are single-report, so scan the RAW bytes for the iAP 0x55 sync
            # and parse directly. This makes the bridge robust to the exact report/link framing while
            # we confirm it from the raw logs. (Multi-report packets still need the reassembler.)
            self._on_frame(report, "raw55")

    def _mark(self, phase):
        if phase not in self.phases:
            self.phases.add(phase)
            print(f"  [PHASE] {phase}")

    # --- iAP1 packet layer -----------------------------------------------------------------------
    def _on_frame(self, frame: bytes, src="reasm") -> bool:
        pkt = self._trim_iap(frame)
        if pkt is None:
            return False
        lingo, cmd, payload = pkt
        self.got_rx = True          # first inbound: stop the opener resend
        print(f"[rx :{src}] lingo=0x{lingo:02x} cmd=0x{cmd:02x} payload={payload.hex()}")
        for reply in self.respond(lingo, cmd, payload):
            self.send_packet(reply)
        return True

    @staticmethod
    def _trim_iap(frame: bytes):
        """Trim HID padding via the iAP1 length field; -> (lingo, cmd, payload) or None.
        Small packet: 0x55 [len] [lingo] [cmd] [payload…] [chk] (len counts lingo..payload)."""
        i = frame.find(0x55)
        if i < 0 or len(frame) < i + 2:
            return None
        ln = frame[i + 1]
        if ln == 0x00:      # large-packet form: 0x55 0x00 <len16> … (TODO: big AppMode payloads)
            if len(frame) < i + 4:
                return None
            ln = (frame[i + 2] << 8) | frame[i + 3]
            body = frame[i + 4:i + 4 + ln]
        else:
            body = frame[i + 2:i + 2 + ln]
        if len(body) < 2:
            return None
        return body[0], body[1], bytes(body[2:])

    # --- response policy (ported baseline) -------------------------------------------------------
    def respond(self, lingo, cmd, payload) -> list[bytes]:
        if iap is None:
            print(f"  (iap1_daemon unavailable: {_IAP_IMPORT_ERR})")
            return []
        out = []

        # AppMode DataParts can arrive on any General opcode once the EA session is open; scan for it
        # (exclude the big binary auth packets so they can't false-positive).
        if (lingo == iap.LINGO_GENERAL and self.ea_opened
                and cmd not in (iap.CMD_RET_DEV_AUTHENTICATION_INFO,
                                iap.CMD_RET_DEV_AUTHENTICATION_SIGNATURE)):
            out.extend(self._handle_inbound_dataparts(cmd, payload))

        # ---- Extended-Interface (lingo 0x04) ----
        if lingo == iap.LINGO_EXTENDED_INTERFACE:
            self._mark("ei_mode")
            trans_id = payload[:2] if len(payload) >= 2 else b"\x00\x00"
            if cmd in EI_GET_RETURNS:
                ret_cmd, data = EI_GET_RETURNS[cmd]
                out.append(build_ei_packet(ret_cmd, trans_id + data))
                return out
            out.append(build_ei_packet(0x0001, trans_id + bytes([0x00, (cmd >> 8) & 0xFF, cmd & 0xFF])))
            return out

        if lingo != iap.LINGO_GENERAL:
            return out

        # ---- General Lingo ----
        if cmd == 0x05:                                   # EnterExtendedInterfaceMode
            self._mark("ei_mode")
            out.append(iap.build_ack(0x00, 0x05))
            return out

        if cmd == iap.CMD_START_IDPS:                     # 0x38
            out.append(iap.build_ack(0x00, iap.CMD_START_IDPS))
            return out

        if cmd == iap.CMD_SET_FID_TOKEN_VALUES:           # 0x39
            self._mark("fid_tokens")
            trans_id, fields = iap.parse_fid_token_values(payload)
            out.append(iap.build_ret_fid_token_value_acks(trans_id, fields))
            eaps = iap.parse_ea_protocols(fields)
            if eaps:
                self.ea_protocols = eaps
                print("  [ea] HU declared: " + ", ".join(
                    f"{p['protocol']}(idx{p['index']})" for p in eaps))
            out.append(iap.build_get_dev_authentication_info())   # auth_trigger=after_fidtokens
            return out

        if cmd == iap.CMD_END_IDPS:                       # 0x3B
            trans_id = (payload[0] << 8) | payload[1]
            out.append(iap.build_idps_status(trans_id, 0x00))     # force_idps_success
            return out

        # ---- MFi device auth (accessory proves to us; we accept). transID-correlated (auth_transid),
        #      cert accepted after the first section (cert_section_mode=ack_transid). ----
        if cmd == iap.CMD_RET_DEV_AUTHENTICATION_INFO:    # 0x15
            trans_prefix = payload[:2] if (len(payload) >= 6 and payload[0] == 0 and payload[1] == 0
                                           and payload[2] in (0x01, 0x02)) else b""
            body = payload[len(trans_prefix):]
            major = body[0] if body else 1
            non_final = major == 0x02 and len(body) >= 4 and body[2] < body[3]
            if non_final:
                out.append(iap.build_packet(iap.LINGO_GENERAL, iap.CMD_ACK,
                                            trans_prefix + bytes([0x00, iap.CMD_RET_DEV_AUTHENTICATION_INFO])))
                return out
            self._mark("mfi_auth_info")
            out.append(iap.build_packet(iap.LINGO_GENERAL, iap.CMD_ACK_DEV_AUTHENTICATION_INFO,
                                        trans_prefix + bytes([0x00])))
            challenge = os.urandom(20 if major == 0x02 else 16) + bytes([1])
            out.append(iap.build_packet(iap.LINGO_GENERAL, iap.CMD_GET_DEV_AUTHENTICATION_SIGNATURE,
                                        trans_prefix + challenge))
            return out

        if cmd == iap.CMD_RET_DEV_AUTHENTICATION_SIGNATURE:  # 0x18
            self._mark("mfi_status_acked")
            tp = payload[:2] if len(payload) >= 2 else b""
            out.append(iap.build_packet(iap.LINGO_GENERAL, iap.CMD_ACK_DEV_AUTHENTICATION_STATUS,
                                        tp + bytes([0x00])))
            return out

        if cmd == iap.CMD_GET_IPOD_OPTIONS_FOR_LINGO:     # 0x4B
            lingo_id = payload[-1]
            options = GENERAL_OPTIONS if lingo_id == iap.LINGO_GENERAL else OTHER_LINGO_OPTIONS
            prefix = payload[:2] if len(payload) >= 2 else b""     # echo_transid
            out.append(iap.build_packet(iap.LINGO_GENERAL, iap.CMD_RET_IPOD_OPTIONS_FOR_LINGO,
                                        prefix + bytes([lingo_id]) + struct.pack(">Q", options)))
            return out

        if cmd == iap.CMD_REQUEST_LINGO_PROTOCOL_VERSION:
            out.append(iap.response_lingo_protocol_version(payload[-1]))
            return out

        if cmd == iap.CMD_IDENTIFY_DEVICE_LINGOES:
            out.append(iap.build_ack(0x00, iap.CMD_IDENTIFY_DEVICE_LINGOES))
            return out

        if cmd == iap.CMD_UNKNOWN_0X11:                   # transport max-payload negotiation
            trans_id = payload[:2] if len(payload) >= 2 else b"\x00\x00"
            out.append(iap.build_packet(iap.LINGO_GENERAL, 0x12,
                                        trans_id + struct.pack(">H", MAX_PAYLOAD_SIZE)))
            return out

        if cmd in iap.REQUEST_HANDLERS:                   # iPod name/serial/model/version (device_info)
            out.append(iap.REQUEST_HANDLERS[cmd]())
            # STEP B/C: at the app-launch-stage signal, announce the app then kick the DataParts auth.
            out.extend(self._take_ea_open())
            out.extend(self._take_dp_kick())
            return out

        # post-auth SystemInit: transID-echoing ACK keeps the HU advancing (autoack_unknown)
        trans_id = payload[:2] if len(payload) >= 2 else b"\x00\x00"
        out.append(iap.build_packet(iap.LINGO_GENERAL, iap.CMD_ACK, trans_id + bytes([0x00, cmd])))
        return out

    # --- app announce + DataParts (ported) -------------------------------------------------------
    def _take_ea_open(self):
        if self.ea_opened or not self.ea_protocols:
            return []
        self.ea_opened = True
        pkts, session_id = [], 1
        for want in EA_OPEN_PROTOCOLS:
            for p in self.ea_protocols:
                if want.lower() in p["protocol"].lower():
                    pkts.append(iap.build_open_data_session_for_protocol(session_id, p["index"]))
                    if self.ea_session_id is None or "hondalink" in p["protocol"].lower():
                        self.ea_session_id = session_id
                    print(f"  [ea-open] OpenDataSessionForProtocol {p['protocol']} idx{p['index']} sess{session_id}")
                    session_id += 1
                    break
        return pkts

    def _take_dp_kick(self):
        if self.dp_kicked or self.ea_session_id is None or appmode is None:
            return []
        self.dp_kicked = True
        sid = self.ea_session_id
        session_start = appmode.build_frame(0x00, bytes([0x01, 0x01]))
        auth_request = appmode.build_frame(0x00, bytes([0x00]))
        pkts = []
        for op in DP_OPCODE_SWEEP:
            pkts.append(iap.build_ipod_data_transfer(sid, session_start, cmd=op))
            pkts.append(iap.build_ipod_data_transfer(sid, auth_request, cmd=op))
        print(f"  [dp] kick: SessionStart+AuthRequest over opcodes {[hex(o) for o in DP_OPCODE_SWEEP]}")
        return pkts

    def _handle_inbound_dataparts(self, cmd, payload):
        if appmode is None:
            return []
        _sid, app_data = iap.parse_ea_data_transfer(payload)
        frames = list(appmode.parse_frames(payload)) or list(appmode.parse_frames(app_data))
        out = []
        for f in frames:
            print(f"  [dataparts RX cmd=0x{cmd:02x}] {f.describe()}")
            if f.pack_id == 0xB1:
                self._mark("dataparts_b1")
                print(f"  *** 0xB1 StartAuth received — payload={f.payload.hex()} ***")
                b2 = self._build_b2(f)
                if b2 is not None:
                    out.append(b2)
            elif f.pack_id == 0xB3:
                self._mark("dataparts_b3")
                print("  *** 0xB3 AuthFin — AppMode auth likely COMPLETE ***")
        return out

    def _build_b2(self, b1_frame):
        if self.dp_b2_sent or self.ea_session_id is None or appmode is None:
            return None
        self.dp_b2_sent = True
        p = b1_frame.payload
        nonce = p[1:5] if len(p) >= 5 else b"\x00\x00\x00\x00"
        key = appmode.derive_key(nonce, info=b"")

        def lp(s):
            b = s.encode() if isinstance(s, str) else s
            return bytes([len(b)]) + b
        blob = (bytes([0x01]) + lp("Apple") + lp("iPhone")
                + lp("jp.co.honda.rd.dispaudio.app.hondalink") + lp("7.0")
                + lp("0000000000000001") + lp("1.0.0"))
        ct = appmode.aes_cbc_encrypt(key, blob)
        frame = appmode.build_frame(0xB2, bytes([0x00]) + ct)
        print(f"  [dp] 0xB2 AuthResponse: nonce={nonce.hex()} 6-field identity ({len(frame)}B) — encoding is a Phase-2 probe")
        return iap.build_ipod_data_transfer(self.ea_session_id, frame, cmd=DP_B2_OPCODE)


def main():
    import threading
    b = IapUsbBridge()
    b.open()
    # Kick the receive-first head unit with a proactive opener (resent until it replies), in a
    # background thread so the read loop can catch the reply. See build_opener()/opener_loop().
    threading.Thread(target=b.opener_loop, daemon=True).start()
    try:
        b.read_loop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
