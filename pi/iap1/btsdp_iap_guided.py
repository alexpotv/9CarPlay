#!/usr/bin/env python3
"""btsdp_iap_guided — an operator-guided iAP1-over-Bluetooth *hypothesis-testing harness*.

This is a testing-oriented sibling of `btsdp_iap.py`. Same transport (registers the SDP record for
`00000000-deca-fade-deca-deafdecacafe` and accepts the head unit's RFCOMM connection), same iAP1
wire framing (reused directly from `iap1_daemon.py`). The difference: instead of running one fixed
handshake strategy, it walks a numbered list of HYPOTHESES, each of which responds to the head
unit's traffic *differently*, and — because we can launch "HondaLink" from the head unit ourselves
but have NO real iPhone to compare against — it prompts the operator to launch HondaLink for each
hypothesis and records what the head unit actually did, so the whole batch can be analyzed offline
afterward.

WHY THIS EXISTS (the RE that motivated it, 2026-08-11)
------------------------------------------------------
The BT 1-15 daemon rewrites were built on the belief that the head unit's ADCL layer DROPS our
General ACK for StartIDPS because the acked command ID (0x38) exceeds a `< 0x19` bound in
`AplReceiveGeneralAckCallback`. Re-decompiling that callback AND its two siblings
(`AplReceiveSimpleAckCallback`, `AplReceiveExtendedAckCallback`) showed all three are byte-for-byte
identical — `if (param_3 < 0x19) {forward} else {FATAL "ubStatus NG"; drop}`. Because the three
lingoes have totally different command-ID ranges but share the SAME 0x19 bound, `param_3` is the
lingo-independent **ACK status byte**, not the acked command ID (the FATAL string even names it
"ubStatus"). So a status-0x00 ACK is always forwarded, whatever it acks — our StartIDPS ACK is NOT
dropped, and the accept-vs-refuse-StartIDPS thrashing was chasing a misread. The real reason the
head unit loops StartIDPS / fails to launch the app is now genuinely open, which is exactly what
this harness exists to pin down empirically. See references/cr-v/iap.md, "ADCL ACK gate re-analysed
(2026-08-11)" for the full trace.

HOW TO RUN (on the Pi, as root, alongside hfp_ag.py after setup_bt_phone.sh + pairing)
--------------------------------------------------------------------------------------
    sudo python3 btsdp_iap_guided.py

Then follow the on-screen prompts. For each hypothesis it will:
  1. tell you what it's testing and what a positive result would look like,
  2. wait for you to press Enter to "arm" it,
  3. ask you to launch HondaLink on the head unit and observe,
  4. ask you to classify the outcome (menu) and type any on-screen error text,
  5. move to the next hypothesis (you can repeat, skip, or quit at any prompt).

Everything the head unit sends/receives is logged, tagged by hypothesis, to a timestamped JSONL
file (`guided_results_<suffix>.jsonl`) plus a human-readable `guided_results_<suffix>.txt` summary.
Hand those two files back for analysis.
"""

import datetime
import json
import os
import socket
import struct
import sys
import threading
import time

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

import iap1_daemon as iap
from markers import session_suffix

# ---------------------------------------------------------------------------
# Bluetooth profile constants (identical to btsdp_iap.py — same UUID/channel).
# ---------------------------------------------------------------------------
BUS_NAME = "org.bluez"
PROFILE_MANAGER_PATH = "/org/bluez"
PROFILE_DBUS_PATH = "/9carplay/iap_bt_guided"
IAP_BT_UUID = "00000000-deca-fade-deca-deafdecacafe"
RFCOMM_CHANNEL = 2


# ===========================================================================
# Hypotheses
# ===========================================================================
# Each hypothesis is a small bundle of behavior *flags* consumed by respond_to_packet() below.
# Keeping them declarative (rather than full handler overrides) keeps the matrix easy to read and
# extend — each hypothesis differs only in a handful of decision points.
#
#   start_idps : how we answer StartIDPS (cmd 0x38). "accept" -> General ACK status 0x00;
#                "reject" -> ACK status 0x04; "ignore" -> no reply.
#   sync       : outgoing framing — "short" (bare 0x55, what the head unit transmits) or "full"
#                (0xFF 0x55).
#   run_idps_body : answer SetFIDTokenValues (0x39) and EndIDPS (0x3B) to drive IDPS to completion.
#   init_auth  : after IDPS, initiate + carry MFi device authentication, accepting whatever comes.
#   opt11_mode : how we answer cmd 0x11 (the head unit's iPod-options request; firmware
#                "RetiPodOutOption"). "unknown_id" -> ACK status 0x05 (what round 1 sent);
#                "ack_success" -> ACK status 0x00; "ret_options" -> a speculative RetiPodOptions
#                reply (cmd 0x12 = the natural Get(0x11)/Ret(0x12) pairing), echoing the request's
#                2-byte transID + `general_options` as an 8-byte big-endian field. The 0x12 command
#                id and payload shape are a GUESS pending firmware/live confirmation.
#   general_options : the 8-byte option bitmask we report for General Lingo (0x00) in both the
#                0x4b/0x4c GetiPodOptionsForLingo reply and (for "ret_options") the 0x11 reply.
#                Round 1 used 0x2000 (bit 0x0D, "communication with iPhone OS apps").
#   other_lingo_options : the option bitmask reported for every NON-General lingo the head unit
#                queries (round 1 used 0).
#
# ---------------------------------------------------------------------------------------------
# ROUND 1 RESULTS (run 20260811_113447) that motivate this round — see references/cr-v/iap.md
# "Round 1 guided run" for the full analysis. In short, the transaction ID is a global counter and
# all windows are one continuous conversation. Confirmed:
#   * accept-StartIDPS + SHORT sync WORKS: the head unit acked once (0x38x1) and advanced. FULL
#     sync (old H3) made StartIDPS loop; reject/ignore (old H4/H5) loop too. -> short sync + accept
#     is settled; those variables are done and are NOT re-run here.
#   * The real failure is one step later, in IDPS OPTIONS NEGOTIATION. After StartIDPS the head
#     unit runs: cmd 0x11 (iPod-options request) -> GetiPodOptionsForLingo (0x4b) for lingoes
#     0x00,0x02,0x03,0x04,0x0c,0x0e -> EndIDPS with accEndIDPSStatus=0x01 (= IDPS FAILED, reset &
#     retry). It never sends SetFIDTokenValues. We answered 0x11 with "unknown id" (0x05) and
#     reported General options=0x2000. One of those replies is very likely why the head unit
#     rejects IDPS. This round isolates which.
# ---------------------------------------------------------------------------------------------

GENERAL_APP_BIT = 1 << 0x0D   # 0x2000 — "communication with iPhone OS 3.x applications"

# ---------------------------------------------------------------------------------------------
# ROUND 2 RESULTS (runs 20260811_1229-1232, R1-R5) — the transID echo was the unlock, and it moved
# the wall exactly one step. With echo_transid the ~18s option stalls VANISHED (0x4b queries now
# resolve <0.1s apart) and the head unit proceeded to send its own SetFIDTokenValues (0x39) — the
# FID-token step that never appeared before. Its tokens even include the EA protocol strings
# (jp.co.honda.rd.dispaudio.app.hondalink, com.pandora.link.v1). R3/R5 (0x11 ACK, extra lingo
# options) behaved identically to R2 and R4 (speculative 0x12) no better — so the 0x11 answer and
# option bits DON'T matter; only the transID echo did.
#
# THE NEW WALL: after we ACK the FID tokens (0x3a, which correctly echoes the transID), the head
# unit goes silent for ~18s (again 3x its 6s retry unit) and then sends EndIDPS with
# accEndIDPSStatus=0x01 (still FAIL) — transID 0x0009, i.e. the very next counter value with nothing
# between. So it sends its tokens, starts an ~18s timer waiting for the iPod to act, and finalizes
# with fail when nothing comes. The most likely missing iPod action is INITIATING MFi device
# authentication (GetDevAuthenticationInfo) right after the token exchange — which our code never
# did, because it only initiated auth after EndIDPS returned status 0x00 (a state we never reach).
# Round 3 breaks that chicken-and-egg with `auth_trigger`, plus a `force_idps_success` escape hatch.
# ---------------------------------------------------------------------------------------------


class Hypothesis:
    def __init__(self, key, title, rationale, positive_signal,
                 start_idps="accept", sync="short", run_idps_body=True, init_auth=True,
                 opt11_mode="unknown_id", general_options=GENERAL_APP_BIT, other_lingo_options=0,
                 echo_transid=True, auth_trigger="after_endidps", force_idps_success=False):
        self.key = key
        self.title = title
        self.rationale = rationale
        self.positive_signal = positive_signal
        self.start_idps = start_idps
        self.sync = sync
        self.run_idps_body = run_idps_body
        self.init_auth = init_auth
        self.opt11_mode = opt11_mode
        self.general_options = general_options
        self.other_lingo_options = other_lingo_options
        self.echo_transid = echo_transid
        # auth_trigger: when to send GetDevAuthenticationInfo (0x14) to authenticate the accessory.
        #   "after_endidps"   -> only after EndIDPS resolves to success (round-2 behavior; never fired)
        #   "after_fidtokens" -> immediately after ACKing SetFIDTokenValues (0x39), i.e. inside the
        #                        ~18s window the head unit waits before EndIDPS
        self.auth_trigger = auth_trigger
        # force_idps_success: reply to EndIDPS with IDPSStatus=0x00 even when the head unit sent
        # accEndIDPSStatus=0x01. Spec-invalid, but tests whether asserting success pushes it forward.
        self.force_idps_success = force_idps_success


# ---------------------------------------------------------------------------------------------
# ROUND 3 RESULTS (runs 20260811_1253-1258, T1-T5) — the real breakthrough, hidden in the
# "unclassified" bytes. Sending GetDevAuthenticationInfo (0x14) after the FID tokens (T2/T3) did
# nothing on its own. But T5 (0x14 after tokens + force IDPSStatus=0x00) made the head unit send a
# ~498-byte blob our parser logged as garbage: reconstructed + checksum-verified, it is a LARGE
# packet (0x55 0x00 <len16> ...) carrying cmd 0x15 RetDevAuthenticationInfo with the head unit's
# real Apple MFi certificate chain ("Apple iPod Accessories Certification Authority", DER 3082...).
# So authentication ALREADY WORKS — the accessory proves itself to us — but the small-packet-only
# parser couldn't read the cert, so we never continued the handshake and IDPS looped. Two fixes
# landed from this: (1) iap1_daemon.try_parse_packet now parses the large-packet format; (2) the
# 0x15 handler here strips the 2-byte transID prefix and drives the sectioned cert -> signature ->
# status flow. Forcing IDPSStatus=0x00 was what made the head unit release the cert (T2 without it
# got no 0x15), so the winning combo is: auth after FID tokens + force IDPS success.
# ---------------------------------------------------------------------------------------------


# Round 4 puts the large-packet fix to work: complete the MFi authentication the head unit was
# already offering, then watch what unlocks next. Success signals, strongest first: we receive
# RetDevAuthenticationSignature (0x18) and ACK it (0x19) without error; the IDPS loop STOPS; a brand
# new command class appears — iPod-preferences / SystemInit (RetiPodPreferences), GetIPodInfo
# (RequestiPodName 0x07 etc.), or OpenDataSessionForProtocol (0x3f) — i.e. the head unit moves past
# identification toward launching the app. Any of those is uncharted territory past every prior wall.
HYPOTHESES = [
    Hypothesis(
        "U1", "Complete MFi auth: 0x14 after FID tokens + force IDPS success (T5 config + parser fix)",
        "The winning round-3 combo, now that we can actually read the cert. We send "
        "GetDevAuthenticationInfo after the FID tokens and assert IDPSStatus=0x00; the head unit "
        "sends its cert (0x15, large packet); we ACK sections, request its signature (0x17); it "
        "signs (0x18); we ACK status (0x19). This should finish authentication for the first time.",
        "0x18 (signature) received + 0x19 sent with no loop restart; then a NEW command class "
        "(RetiPodPreferences / GetIPodInfo 0x07 / OpenDataSession 0x3f) appears.",
        auth_trigger="after_fidtokens", force_idps_success=True),

    Hypothesis(
        "U2", "Complete MFi auth WITHOUT forcing IDPS success",
        "Same as U1 but reply to EndIDPS per spec (0x04 on the head unit's 0x01). Tests whether, now "
        "that we handle the cert, auth proceeds on its own — or whether force-IDPS-success is still "
        "required to make the head unit release the certificate.",
        "If the cert (0x15) still arrives and auth completes, force-success wasn't essential; if no "
        "0x15 appears, it was.",
        auth_trigger="after_fidtokens", force_idps_success=False),

    Hypothesis(
        "U3", "Force IDPS success first, THEN initiate auth (cleaner ordering)",
        "Assert IDPSStatus=0x00 on EndIDPS and only then send GetDevAuthenticationInfo — the more "
        "spec-plausible order (identify, close IDPS, then authenticate). Compare against U1 in case "
        "the head unit prefers auth to start after IDPS is closed rather than mid-window.",
        "Same completion signals as U1; tells us the head unit's preferred auth-start ordering.",
        auth_trigger="after_endidps", force_idps_success=True),

    Hypothesis(
        "U4", "U1 + ACK 0x11 + claim every queried lingo (kitchen sink)",
        "U1 with the extra identification niceties stacked on, as a fallback if U1 completes auth but "
        "stalls at the next step for an identification-completeness reason.",
        "Auth completes AND the head unit advances further than U1 did.",
        auth_trigger="after_fidtokens", force_idps_success=True, opt11_mode="ack_success",
        other_lingo_options=GENERAL_APP_BIT),
]


# ===========================================================================
# Per-connection response logic
# ===========================================================================

class Harness:
    """Shared state between the operator-console thread and the RFCOMM session thread(s)."""

    def __init__(self, jsonl_path, txt_path):
        self.lock = threading.Lock()
        self.jsonl = open(jsonl_path, "a")
        self.txt = open(txt_path, "a")
        self.jsonl_path = jsonl_path
        self.txt_path = txt_path
        self.current = HYPOTHESES[0]     # armed hypothesis; console thread updates this
        self.window_id = 0               # bumped each time a hypothesis is armed
        # per-window live counters, surfaced back to the operator so they can see progress
        self.rx_counts = {}              # cmd -> count within the current window
        self.connected = False

    # ---- logging (thread-safe) ----
    def log(self, direction, **fields):
        rec = {
            "ts": time.time(),
            "iso": datetime.datetime.now().isoformat(timespec="milliseconds"),
            "window": self.window_id,
            "hyp": self.current.key,
            "dir": direction,
        }
        rec.update(fields)
        with self.lock:
            self.jsonl.write(json.dumps(rec) + "\n")
            self.jsonl.flush()

    def note_txt(self, line):
        with self.lock:
            self.txt.write(line + "\n")
            self.txt.flush()

    def arm(self, hyp):
        with self.lock:
            self.current = hyp
            self.window_id += 1
            self.rx_counts = {}
            iap.OUTGOING_SYNC_MODE = "full" if hyp.sync == "full" else "short"

    def count_rx(self, cmd):
        with self.lock:
            self.rx_counts[cmd] = self.rx_counts.get(cmd, 0) + 1
            return self.rx_counts[cmd]


def respond_to_packet(harness, hyp, lingo, cmd, payload):
    """Return a list of raw packets (bytes) to send in reply to one received iAP1 packet, per the
    armed hypothesis. Reuses iap1_daemon's builders so the wire format stays identical to the
    production daemon; only the *policy* (which of them to send, and when) varies per hypothesis."""
    out = []
    if lingo != iap.LINGO_GENERAL:
        return out

    # ---- StartIDPS (0x38): the primary variable under test ----
    if cmd == iap.CMD_START_IDPS:
        if hyp.start_idps == "accept":
            out.append(iap.build_ack(0x00, iap.CMD_START_IDPS))
        elif hyp.start_idps == "reject":
            out.append(iap.build_ack(0x04, iap.CMD_START_IDPS))   # 0x04 bad-param, still delivered
        # "ignore" -> send nothing
        return out

    # ---- IDPS body (only when the hypothesis opts in) ----
    if hyp.run_idps_body and cmd == iap.CMD_SET_FID_TOKEN_VALUES:
        trans_id, fields = iap.parse_fid_token_values(payload)
        out.append(iap.build_ret_fid_token_value_acks(trans_id, fields))
        # Round 3: the head unit goes silent ~18s after this ACK before finalizing IDPS with a
        # failure. If it's waiting for the iPod to start authenticating the accessory, initiate that
        # now (inside the window) rather than waiting for an EndIDPS success that never comes.
        if hyp.auth_trigger == "after_fidtokens" and hyp.init_auth:
            out.append(iap.build_get_dev_authentication_info())
        return out

    if hyp.run_idps_body and cmd == iap.CMD_END_IDPS:
        trans_id = (payload[0] << 8) | payload[1]
        acc_status = payload[2] if len(payload) > 2 else 0
        succeed = (acc_status == 0) or hyp.force_idps_success
        out.append(iap.build_idps_status(trans_id, 0x00 if succeed else 0x04))
        if succeed and hyp.init_auth and hyp.auth_trigger == "after_endidps":
            out.append(iap.build_get_dev_authentication_info())
        return out

    # ---- MFi device authentication (accessory proves itself to us; we accept unconditionally).
    # The head unit's RetDevAuthenticationInfo (0x15) arrives as a LARGE packet (~498 B MFi cert)
    # with a 2-byte transID prefix ahead of the standard [major, minor, curSection, maxSection,
    # certData] body — strip it. The cert is split across sections: ACK every non-final section with
    # a plain ACK to pull the next, then AckDevAuthenticationInfo(0x16) + GetDevAuthenticationSignature
    # (0x17) on the final one. (Confirmed on the wire 2026-08-11; see references/cr-v/iap.md.) ----
    if hyp.init_auth and cmd == iap.CMD_RET_DEV_AUTHENTICATION_INFO:
        body = payload[2:] if (len(payload) >= 6 and payload[0] == 0 and payload[1] == 0
                               and payload[2] in (0x01, 0x02)) else payload
        major = body[0] if body else 1
        if major == 0x02 and len(body) >= 4:
            cur_section, max_section = body[2], body[3]
            if cur_section < max_section:
                out.append(iap.build_ack(0x00, iap.CMD_RET_DEV_AUTHENTICATION_INFO))
                return out   # request the next cert section before proceeding
        out.append(iap.build_ack_dev_authentication_info(0x00))
        challenge_len = 20 if major == 0x02 else 16
        out.append(iap.build_get_dev_authentication_signature(os.urandom(challenge_len), 1))
        return out

    if hyp.init_auth and cmd == iap.CMD_RET_DEV_AUTHENTICATION_SIGNATURE:
        out.append(iap.build_ack_dev_authentication_status(0x00))
        return out

    # ---- GetiPodOptionsForLingo (0x4b): report per-lingo option bits. The queried lingo id is the
    # LAST payload byte (the head unit prefixes a 2-byte transID). General Lingo (0x00) gets
    # `general_options`; every other lingo gets `other_lingo_options` — both configurable per
    # hypothesis (round 1 rejected IDPS with General=0x2000/others=0, so these are under test). ----
    if cmd == iap.CMD_GET_IPOD_OPTIONS_FOR_LINGO:
        # Request payload is [transIdHi, transIdLo, lingoId]; lingoId is the last byte. When
        # echo_transid is set, prepend the request's 2-byte transID to our 0x4c reply so the head
        # unit can correlate it (round-1 timing showed uncorrelated replies time out ~18s each).
        lingo_id = payload[-1]
        options = hyp.general_options if lingo_id == iap.LINGO_GENERAL else hyp.other_lingo_options
        prefix = payload[:2] if (hyp.echo_transid and len(payload) >= 2) else b""
        reply = iap.build_packet(iap.LINGO_GENERAL, iap.CMD_RET_IPOD_OPTIONS_FOR_LINGO,
                                 prefix + bytes([lingo_id]) + struct.pack(">Q", options))
        out.append(reply)
        return out
    if cmd == iap.CMD_REQUEST_LINGO_PROTOCOL_VERSION:
        out.append(iap.response_lingo_protocol_version(payload[-1]))
        return out
    if cmd == iap.CMD_IDENTIFY_DEVICE_LINGOES:
        out.append(iap.build_ack(0x00, iap.CMD_IDENTIFY_DEVICE_LINGOES))
        return out
    if cmd in iap.REQUEST_HANDLERS:
        out.append(iap.REQUEST_HANDLERS[cmd]())
        return out
    if cmd == iap.CMD_UNKNOWN_0X11:
        # The head unit's iPod-options request (firmware receives "RetiPodOutOption" in reply). How
        # we answer is the primary round-2 variable — see Hypothesis.opt11_mode.
        if hyp.opt11_mode == "ack_success":
            out.append(iap.build_ack(0x00, iap.CMD_UNKNOWN_0X11))
        elif hyp.opt11_mode == "ret_options":
            # Speculative RetiPodOptions: cmd 0x12 (guessed Get/Ret pairing), echo the request's
            # 2-byte transID + 8-byte big-endian option field. Shape unconfirmed — compare vs R2.
            trans_id = payload[:2] if len(payload) >= 2 else b"\x00\x00"
            out.append(iap.build_packet(iap.LINGO_GENERAL, 0x12,
                                        trans_id + struct.pack(">Q", hyp.general_options)))
        else:  # "unknown_id" — what round 1 sent
            out.append(iap.build_ack(0x05, iap.CMD_UNKNOWN_0X11))
        return out

    return out   # unrecognized -> logged by caller, no reply


def rfcomm_session(harness, fd, device):
    sock = socket.fromfd(fd, socket.AF_BLUETOOTH, socket.SOCK_STREAM)
    sock.setblocking(True)
    harness.connected = True
    harness.log("note", event="rfcomm_connected", device=str(device))
    print(f"\n[conn] RFCOMM connected from {device} (hypothesis {harness.current.key} armed)")
    rx_buf = bytearray()
    conn_t0 = time.time()   # per-connection clock, so the operator can watch step latency live
    try:
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError as e:
                harness.log("note", event="recv_error", error=str(e))
                break
            if not chunk:
                break
            rx_buf += chunk
            _drain(harness, sock, rx_buf, conn_t0)
    finally:
        harness.connected = False
        harness.log("note", event="rfcomm_closed", device=str(device))
        print(f"[conn] RFCOMM session with {device} ended")
        sock.close()


def _drain(harness, sock, rx_buf, conn_t0):
    """Parse and dispatch every complete packet currently in rx_buf."""
    progressed = True
    while progressed and rx_buf:
        progressed = False
        lingo, cmd, payload, consumed, skip = iap.try_parse_packet(bytes(rx_buf))
        hyp = harness.current
        if consumed:
            raw = bytes(rx_buf[:consumed])
            del rx_buf[:consumed]
            n = harness.count_rx(cmd)
            dt = time.time() - conn_t0
            harness.log("rx", lingo=lingo, cmd=cmd, payload=payload.hex(), raw=raw.hex(),
                        cmd_seen_in_window=n, t_since_connect=round(dt, 3))
            # +Xs is the key signal this round: a healthy handshake keeps these gaps sub-second; a
            # ~18s jump means the head unit timed out waiting for a reply it didn't accept.
            print(f"  [rx#{n} +{dt:5.1f}s] lingo=0x{lingo:02x} cmd=0x{cmd:02x} "
                  f"payload={payload.hex()}")
            for pkt in respond_to_packet(harness, hyp, lingo, cmd, payload):
                sock.send(pkt)
                harness.log("tx", raw=pkt.hex(),
                            note=f"reply under {hyp.key}/{hyp.start_idps}/{hyp.sync}")
                print(f"  [tx  ] {pkt.hex()}")
                if iap.INTER_PACKET_DELAY_S:
                    time.sleep(iap.INTER_PACKET_DELAY_S)
            progressed = True
        elif skip:
            garbage = bytes(rx_buf[:skip])
            del rx_buf[:skip]
            harness.log("rx", note="unclassified", raw=garbage.hex())
            print(f"  [rx  ] {len(garbage)} unclassified byte(s): {garbage.hex()}")
            progressed = True


# ===========================================================================
# Operator console (runs on its own thread while GLib mainloop serves D-Bus)
# ===========================================================================

OUTCOME_MENU = [
    ("1", "app_launched", "App LAUNCHED / video appeared on the head unit"),
    ("2", "phone_connected_no_app", "'Phone connected' shown, but app did NOT launch"),
    ("3", "error_message", "An error message appeared (you'll be asked to type it)"),
    ("4", "no_change", "Nothing changed on the head unit"),
    ("5", "no_connection", "Head unit never connected / no RFCOMM traffic at all"),
    ("6", "other", "Something else (you'll be asked to describe it)"),
]


def _ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        return "q"


def operator_console(harness):
    print("\n" + "=" * 78)
    print(" 9CarPlay iAP1-over-Bluetooth — GUIDED HYPOTHESIS TEST")
    print("=" * 78)
    print("Precondition: hfp_ag.py running, head unit paired, HFP connected & stable.")
    print(f"Results -> {harness.jsonl_path}")
    print(f"           {harness.txt_path}")
    print("\nAt any prompt: [Enter]=continue, 's'=skip hypothesis, 'r'=repeat, 'q'=quit.\n")

    idx = 0
    while idx < len(HYPOTHESES):
        hyp = HYPOTHESES[idx]
        print("\n" + "-" * 78)
        print(f"HYPOTHESIS {hyp.key}: {hyp.title}")
        print("-" * 78)
        print(f"  Why:            {hyp.rationale}")
        print(f"  Positive sign:  {hyp.positive_signal}")
        print(f"  Behavior:       StartIDPS={hyp.start_idps}  sync={hyp.sync}  "
              f"idps_body={hyp.run_idps_body}  init_auth={hyp.init_auth}")
        print(f"                  echo_transid={hyp.echo_transid}  cmd0x11={hyp.opt11_mode}  "
              f"general_opts=0x{hyp.general_options:x}  other_lingo_opts=0x{hyp.other_lingo_options:x}")
        print(f"                  auth_trigger={hyp.auth_trigger}  "
              f"force_idps_success={hyp.force_idps_success}")
        cmd = _ask("\n  Press Enter to ARM this hypothesis (or s/r/q): ").lower()
        if cmd == "q":
            break
        if cmd == "s":
            harness.note_txt(f"[{hyp.key}] SKIPPED by operator")
            idx += 1
            continue

        harness.arm(hyp)
        harness.note_txt(f"\n===== WINDOW {harness.window_id} :: {hyp.key} — {hyp.title} =====")
        harness.log("note", event="armed", title=hyp.title,
                    start_idps=hyp.start_idps, sync=hyp.sync,
                    run_idps_body=hyp.run_idps_body, init_auth=hyp.init_auth,
                    opt11_mode=hyp.opt11_mode, general_options=hyp.general_options,
                    other_lingo_options=hyp.other_lingo_options, echo_transid=hyp.echo_transid,
                    auth_trigger=hyp.auth_trigger, force_idps_success=hyp.force_idps_success)
        print(f"\n  >>> ARMED ({hyp.key}). Now LAUNCH HondaLink on the head unit and watch it.")
        print("      (If it's already open, back out and re-enter the HondaLink source to force a")
        print("       fresh connection.) Live rx/tx traffic prints below as it happens.")
        _ask("\n  When the head unit has settled (launched / errored / gone idle), press Enter: ")

        # summarize what was seen this window
        with harness.lock:
            seen = dict(harness.rx_counts)
        seen_str = ", ".join(f"0x{c:02x}×{n}" for c, n in sorted(seen.items())) or "(none)"
        print(f"\n  Commands received this window: {seen_str}")

        outcome = _collect_outcome(harness, hyp, seen_str)
        harness.log("result", **outcome)
        harness.note_txt(f"[{hyp.key}] outcome={outcome['outcome']} "
                         f"rx=[{seen_str}] notes={outcome.get('notes','')}")

        nxt = _ask("\n  Next: [Enter]=continue, 'r'=repeat this one, 'q'=quit: ").lower()
        if nxt == "q":
            break
        if nxt == "r":
            continue
        idx += 1

    print("\n" + "=" * 78)
    print("Test run complete. Hand these two files back for analysis:")
    print(f"  {harness.jsonl_path}")
    print(f"  {harness.txt_path}")
    print("=" * 78)
    os._exit(0)   # tear down the GLib mainloop thread too


def _collect_outcome(harness, hyp, seen_str):
    print("\n  How did the head unit respond? Choose one:")
    for num, _key, desc in OUTCOME_MENU:
        print(f"    {num}) {desc}")
    choice = _ask("  Outcome number: ").strip()
    match = next((m for m in OUTCOME_MENU if m[0] == choice), None)
    outcome_key = match[1] if match else "unparsed"
    notes = ""
    if outcome_key == "error_message":
        notes = _ask("  Type the EXACT error text shown on the head unit: ")
    elif outcome_key in ("other", "unparsed"):
        notes = _ask("  Describe what happened: ")
    else:
        extra = _ask("  Any extra detail? (optional, Enter to skip): ")
        notes = extra
    return {"outcome": outcome_key, "raw_choice": choice, "notes": notes,
            "rx_summary": seen_str}


# ===========================================================================
# D-Bus profile + main
# ===========================================================================

class GuidedProfile(dbus.service.Object):
    def __init__(self, bus, path, harness):
        super().__init__(bus, path)
        self.harness = harness

    @dbus.service.method("org.bluez.Profile1", in_signature="", out_signature="")
    def Release(self):
        print("[btsdp-guided] Release()")

    @dbus.service.method("org.bluez.Profile1", in_signature="oha{sv}", out_signature="")
    def NewConnection(self, device, fd, properties):
        real_fd = fd.take()
        threading.Thread(target=rfcomm_session,
                         args=(self.harness, real_fd, device), daemon=True).start()

    @dbus.service.method("org.bluez.Profile1", in_signature="o", out_signature="")
    def RequestDisconnection(self, device):
        print(f"[btsdp-guided] RequestDisconnection from {device}")


def main():
    if os.geteuid() != 0:
        print("Must run as root", file=sys.stderr)
        sys.exit(1)

    # We're racing the head unit's app-launch deadline (round-1 timing showed a ~18s-per-step
    # budget being blown), so drop the production daemon's 50ms inter-packet spacing — reply as fast
    # as possible. The head unit handled our back-to-back initial replies fine in round 1.
    iap.INTER_PACKET_DELAY_S = 0.0

    suffix = session_suffix()
    harness = Harness(f"guided_results_{suffix}.jsonl", f"guided_results_{suffix}.txt")

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    GuidedProfile(bus, PROFILE_DBUS_PATH, harness)
    manager = dbus.Interface(bus.get_object(BUS_NAME, PROFILE_MANAGER_PATH),
                             "org.bluez.ProfileManager1")
    opts = {
        "Name": "9CarPlay iAP1 BT (guided test)",
        "RequireAuthentication": dbus.Boolean(False),
        "RequireAuthorization": dbus.Boolean(False),
        "AutoConnect": dbus.Boolean(True),
        "Channel": dbus.UInt16(RFCOMM_CHANNEL),
    }
    manager.RegisterProfile(PROFILE_DBUS_PATH, IAP_BT_UUID, opts)
    print(f"[btsdp-guided] Registered profile (UUID={IAP_BT_UUID}, channel={RFCOMM_CHANNEL})")

    threading.Thread(target=operator_console, args=(harness,), daemon=True).start()

    try:
        GLib.MainLoop().run()
    except KeyboardInterrupt:
        manager.UnregisterProfile(PROFILE_DBUS_PATH)
        sys.exit(0)


if __name__ == "__main__":
    if not hasattr(socket, "AF_BLUETOOTH"):
        print("This Python build has no socket.AF_BLUETOOTH support — install bluez/"
              "libbluetooth-dev and use the system python3.", file=sys.stderr)
        sys.exit(1)
    main()
