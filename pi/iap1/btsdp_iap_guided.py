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

# AppMode DataParts codec (pi/appmode/appmode_proto.py) — used to decode any bytes seen on the AV/data
# SPP channels. Optional: if the module isn't importable the harness still runs (just no decode).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "appmode"))
try:
    import appmode_proto as appmode
except Exception as _e:  # pragma: no cover
    appmode = None
    print(f"[btsdp-guided] appmode_proto not available ({_e}); AV bytes logged raw only")

# ---------------------------------------------------------------------------
# Bluetooth profile constants (identical to btsdp_iap.py — same UUID/channel).
# ---------------------------------------------------------------------------
BUS_NAME = "org.bluez"
PROFILE_MANAGER_PATH = "/org/bluez"
PROFILE_DBUS_PATH = "/9carplay/iap_bt_guided"
IAP_BT_UUID = "00000000-deca-fade-deca-deafdecacafe"
RFCOMM_CHANNEL = 2

# The head unit searches the phone for THREE custom SPP UUIDs, stored consecutively (16 bytes each)
# in Communication.exe's table at file offset 0x22ed14: the iAP one above, plus the two below. After
# iAP1 auth completes, LPALM_iPodBTConnect::RequestConnectAvSpp opens one of these as the app's AV/
# data channel; with only the iAP UUID advertised, that connect fails ("Impossible de se connecter à
# l'appareil mobile via Bluetooth" — round 8). Advertise + accept both so the head unit can connect,
# and log whatever it sends to reveal the app-data (AV/screen) protocol.
AV_DATA_UUIDS = [
    ("av1", "fa592c6e-5e85-410e-8a7e-5d6373117d39", 3),
    ("av2", "453994d5-d58b-96f9-6616-b37f586ba2ec", 4),
]

# CHANGE 2 (2026-08-11): the head unit ALSO hosts av1/av2 as RFCOMM servers (seen in the
# references/guided/btmon/av_capture: av1 on ch5, av2 on ch6). In the appmode/1 capture the head unit
# searched OUR av1/av2 records post-auth but never opened a data connection, so no DataParts flowed.
# To cover the "phone connects to the head unit" direction, after iAP reaches Extended Interface we
# dial OUT to the head unit's av1/av2 channels ourselves (a controlled connect, not BlueZ AutoConnect
# which fired too early during the pairing sweep and got DISC'd). Whichever direction is correct, one
# path now establishes the channel; we decode whatever arrives as DataParts (appmode_proto).
HEAD_UNIT_AV_CHANNELS = {"av1": 5, "av2": 6}   # RFCOMM server channels the head unit hosts
CONNECT_AV_ON_EI = True                         # auto-dial the head unit's AV channels once EI starts
AV_CONNECT_DELAY_S = 1.5                         # let the head unit settle into EI before dialing
_BTPROTO_RFCOMM = getattr(socket, "BTPROTO_RFCOMM", 3)


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
                 echo_transid=True, auth_trigger="after_endidps", force_idps_success=False,
                 cert_section_mode="accept_first", auth_transid=False, defer_challenge=False,
                 challenge_retry_byte=True, autoack_unknown=False):
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
        # cert_section_mode: how to respond to a NON-final RetDevAuthenticationInfo cert section.
        #   "accept_first" -> ignore sectioning, send AckDevAuthenticationInfo + the signature
        #                     challenge after the first section (we don't validate the cert anyway)
        #   "ack_sections" -> plain ACK to pull the next section (U1 did this; head unit went silent)
        #   "poll_next"    -> re-send GetDevAuthenticationInfo to pull the next section
        #   "ack_transid"  -> plain ACK, but with the cert's 2-byte transID prefix echoed
        self.cert_section_mode = cert_section_mode
        # auth_transid: prefix the auth-phase replies we send (AckDevAuthenticationInfo 0x16,
        # GetDevAuthenticationSignature 0x17, AckDevAuthenticationStatus 0x19) with the 2-byte transID
        # the head unit used — same correlation the cert-section ACK needed in V3.
        self.auth_transid = auth_transid
        # defer_challenge: after the final cert section send only AckDevAuthenticationInfo (0x16) and
        # NOT the signature challenge (0x17), to see whether the head unit drives the next step itself.
        self.defer_challenge = defer_challenge
        # challenge_retry_byte: append a trailing retry-counter byte to the 0x17 challenge (the daemon
        # builder does). If the accessory expects a bare 20-byte challenge, that extra byte could be
        # rejected — this lets us test the challenge with/without it.
        self.challenge_retry_byte = challenge_retry_byte
        # autoack_unknown: ACK any otherwise-unrecognized General Lingo command with a transID-echoing
        # success ACK — used to walk the post-auth SystemInit phase and discover its command sequence.
        self.autoack_unknown = autoack_unknown


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


# ---------------------------------------------------------------------------------------------
# ROUND 4 RESULTS (runs 20260811_1320-1323, U1-U4) — auth is now READABLE and the IDPS loop broke
# for the first time. U1/U4 (force IDPS success + 0x14 after FID tokens) got the head unit to send
# its cert (0x15), our new large-packet parser READ it, and we replied a plain ACK for the (non-
# final, cur=0/max=1) section... after which the head unit went SILENT for ~14s and never sent cert
# section 1. Crucially the IDPS loop STOPPED (one cycle, not endless) — so we're now genuinely in
# the post-IDPS AUTH phase, just stuck on how to advance the sectioned certificate. U2 (no force
# success) got no cert and kept looping, re-confirming force-IDPS-success is required to release it.
#
# So the plain-ACK-per-section approach doesn't pull section 1 on this head unit. Round 5 resolves
# how to advance the cert via `cert_section_mode`. Since we never validate the certificate anyway,
# the leading bet is to accept after the first section and jump straight to the signature challenge.
# ---------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------
# ROUND 5 RESULTS (runs 20260811_1436-1439, V1-V4) — V3 solved cert sectioning. The transID-echoing
# section ACK PULLED cert section 1 (0x15 x2, both sections received) where U1's plain ACK stalled;
# V1 (accept after first section -> jump to challenge) made the head unit LOOP instead. So the cert
# advances only via a transID-tagged ACK — same transID-correlation lesson as every other stage.
# BUT after V3 received both sections and sent AckDevAuthenticationInfo (0x16) + the signature
# challenge (0x17), the head unit went SILENT for ~10s — no RetDevAuthenticationSignature (0x18).
# The near-certain reason: our 0x16/0x17 carried NO transID (unlike the section ACK that just
# worked). Round 6 adds `auth_transid` to prefix the whole auth phase.
# ---------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------
# ROUND 6 NOTE (runs 20260811_1448/1450): W1 was CONTAMINATED — the head unit connected before the
# operator armed it, so replies went out as full 0xFF 0x55 sync (module default) and the run died at
# the FID tokens. So the transID-on-auth fix was NEVER actually tested. W3 (control) reproduced the
# V3 stall. Harness fix landed: main() now defaults OUTGOING_SYNC_MODE="short" so an unarmed
# connection can't repeat this. Firmware (NEventWatcher SystemInit state machine) confirms the
# accessory has a dedicated `fnSystemInitAuthenticationWait` state, and that passing authentication
# leads to the display Preferences states (`fnSystemInitPreferencesScreenConfig`/`AspectRatio`,
# `SetiPodPreferences`/`RetiPodPreferences`) — i.e. the iPod-Out video setup. Auth is the real gate;
# the direction is favourable (the accessory sends its own cert). Re-run W1 cleanly; W4 is a fallback
# if the transID alone isn't enough.
# ---------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------
# ROUND 6 RESULT (clean W1 re-run, run 20260811_1504) — AUTHENTICATION COMPLETED for the first time.
# With the transID on the whole auth phase: cert section 0 -> transID ACK -> cert section 1 -> we
# send 0x16 + 0x17 (transID-tagged) -> the head unit SIGNED (RetDevAuthenticationSignature 0x18) ->
# we sent 0x19 -> and the head unit immediately sent a NEW command, cmd 0x4f (payload 000a = transID
# 0x000a, resuming the global counter). So we are past the auth gate and into the post-auth
# SystemInit phase. Firmware says that phase is: SetiPodPreferences (accessory->iPod, we ACK),
# GetiPodPreferences -> RetiPodPreferences (we return data), SetEventNotification (we ACK),
# GetSupportedEventNotification (we return data) — the iPod-Out display/preferences setup that leads
# to video. `autoack_unknown` walks it: ACK unknown post-auth commands with a transID to keep the
# head unit talking and capture the exact sequence + payloads to build real handlers from.
# ---------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------
# ROUND 7 RESULT (run 20260811_1517, X1) — the post-auth sequence started flowing. After auth the
# head unit sent General Lingo 0x4f, 0x24, 0x05 (we auto-ACKed; it advanced) — 0x05 is
# EnterExtendedInterfaceMode — and then SWITCHED INTO EXTENDED INTERFACE mode, sending Lingo 0x04
# commands (0x0026, 0x002f, ...) with 2-BYTE command IDs. Two gaps this exposed: (1) our parser read
# commands as 1 byte, mis-parsing every EI command; (2) autoack only covered General Lingo, so the
# EI commands went unanswered and timed out every 18s. Both fixed: iap1_daemon.try_parse_packet now
# reads 2-byte command IDs for Lingo 0x04, and the harness auto-ACKs EI commands with an EI ACK
# (cmd 0x0001, [transID, status, ackedCmdId]). This is the iPod-Out UI/DB setup (SetUIMode,
# ResetDBHierarchy, GetNumberCategorizedDBRecords, ...) that precedes video.
# ---------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------
# ROUND 8 RESULT (runs 20260811_1610/1612, Y1 x2) — the EI phase advanced cleanly: our EI ACKs were
# accepted and the head unit walked 0x0026 -> 0x002f -> 0x001c -> 0x002c fast (no 18s stalls), then
# went silent and showed a NEW error: "Impossible de se connecter à l'appareil mobile via Bluetooth"
# (cannot connect to the mobile device via Bluetooth). Firmware root cause: after iAP auth the head
# unit runs LPALM_iPodBTConnect::RequestConnectAvSpp — it opens a SEPARATE Bluetooth SPP connection
# for the app's AV/data, using one of two extra custom UUIDs it searched for at the start (found with
# the iAP UUID in Communication.exe's table at 0x22ed14). We only advertised the iAP UUID, so that
# connect failed. FIX: the harness now also advertises + accepts those two AV/data SPP services (see
# AV_DATA_UUIDS + DataChannelProfile) and logs whatever they carry. Re-run Y1: this should clear the
# BT-connect error and capture the app-data (AV/screen) protocol on the new channels.
# ---------------------------------------------------------------------------------------------


# Round 8/9: walk the Extended Interface / iPod-Out setup AND accept the AV/data SPP channel the head
# unit opens afterward (AV_DATA_UUIDS). Success = the "cannot connect via Bluetooth" error is gone and
# a [datachan] connection appears carrying the app AV/data protocol (logged raw for analysis).
HYPOTHESES = [
    Hypothesis(
        "Y1", "Walk General + Extended Interface post-auth phases (auto-ACK both)",
        "Full auth (proven W1 path) + autoack_unknown, now covering BOTH General Lingo (0x4f/0x24/"
        "0x05...) and Extended Interface Lingo (0x04, 2-byte commands). transID-ACK everything to "
        "walk the iPod-Out UI/DB setup as far as it will go and capture the full command sequence.",
        "The head unit advances through a run of EI commands (SetUIMode / ResetDBHierarchy / "
        "GetNumberCategorizedDBRecords / Enter-ExitExtendedInterfaceMode); each cmd id + payload is "
        "logged. Any that keep retrying every ~18s want a DATA reply, not an ACK — noted for next round.",
        cert_section_mode="ack_transid", auth_transid=True,
        auth_trigger="after_fidtokens", force_idps_success=True, autoack_unknown=True),

    Hypothesis(
        "Y2", "Control: complete auth, then STOP (no post-auth auto-ACK at all)",
        "auth completes but we answer nothing after 0x19. Confirms we still reliably reach the "
        "post-auth phase (cmd 0x4f) as the baseline for the Y1 walk.",
        "Auth completes (0x18 -> 0x19), cmd 0x4f arrives, then silence.",
        cert_section_mode="ack_transid", auth_transid=True,
        auth_trigger="after_fidtokens", force_idps_success=True, autoack_unknown=False),
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
        self.head_unit_bdaddr = None     # learned from the inbound iAP connection (device path)
        self.av_out_started = False      # guards the one-shot outbound AV connect (CHANGE 2)

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


def build_ei_packet(cmd16, payload):
    """Frame an Extended Interface Lingo (0x04) packet, whose command ID is 2 bytes wide (unlike the
    1-byte General Lingo). Honors OUTGOING_SYNC_MODE like iap1_daemon.build_packet."""
    body_payload = bytes([iap.LINGO_EXTENDED_INTERFACE, (cmd16 >> 8) & 0xFF, cmd16 & 0xFF]) + payload
    body = bytes([len(body_payload)]) + body_payload
    checksum = iap.iap1_checksum(body)
    sync = iap.SYNC if iap.OUTGOING_SYNC_MODE == "full" else iap.SYNC_SHORT
    return sync + body + bytes([checksum])


def respond_to_packet(harness, hyp, lingo, cmd, payload):
    """Return a list of raw packets (bytes) to send in reply to one received iAP1 packet, per the
    armed hypothesis. Reuses iap1_daemon's builders so the wire format stays identical to the
    production daemon; only the *policy* (which of them to send, and when) varies per hypothesis."""
    out = []
    if lingo == iap.LINGO_EXTENDED_INTERFACE:
        # CHANGE 2: EI mode means iAP auth is done and AppMode is Active — the moment the head unit
        # expects the AV/data channel. Dial its av1/av2 channels once, shortly after EI starts.
        if CONNECT_AV_ON_EI and not harness.av_out_started:
            threading.Timer(AV_CONNECT_DELAY_S, connect_head_unit_av, args=(harness,)).start()
        # Post-auth, the head unit enters Extended Interface mode (via General 0x05) and drives the
        # iPod-Out UI/DB setup with 2-byte EI commands (cmd is a 16-bit int here; iap1_daemon parses
        # the width). We don't yet know each EI command's reply, so autoack answers with an EI ACK
        # (cmd 0x0001, payload [transID(2), status=0x00, ackedCmdId(2)]) to keep it talking. Get/
        # Return-type EI commands (that want data) will retry — revealing which need real handlers.
        if hyp.autoack_unknown:
            trans_id = payload[:2] if len(payload) >= 2 else b"\x00\x00"
            out.append(build_ei_packet(0x0001, trans_id + bytes([0x00, (cmd >> 8) & 0xFF, cmd & 0xFF])))
        return out
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
        trans_prefix = payload[:2] if (len(payload) >= 6 and payload[0] == 0 and payload[1] == 0
                                       and payload[2] in (0x01, 0x02)) else b""
        body = payload[len(trans_prefix):]
        major = body[0] if body else 1
        non_final = major == 0x02 and len(body) >= 4 and body[2] < body[3]
        if non_final:
            # Round-4 U1 showed a plain ACK here does NOT pull cert section 1 — the head unit goes
            # silent. cert_section_mode picks how to advance (round 5):
            if hyp.cert_section_mode == "ack_sections":       # U1 behavior (control) — stalls
                out.append(iap.build_ack(0x00, iap.CMD_RET_DEV_AUTHENTICATION_INFO))
                return out
            if hyp.cert_section_mode == "ack_transid":        # plain ACK but echo the transID prefix
                out.append(iap.build_packet(iap.LINGO_GENERAL, iap.CMD_ACK,
                                            trans_prefix + bytes([0x00, iap.CMD_RET_DEV_AUTHENTICATION_INFO])))
                return out
            if hyp.cert_section_mode == "poll_next":          # re-request via GetDevAuthenticationInfo
                out.append(iap.build_get_dev_authentication_info())
                return out
            # "accept_first": fall through — we don't validate the cert, so accept after one section
            # and jump straight to the challenge (0x16 + 0x17).
        # Final cert section. Round 5 (V3) proved the section ACK needs the transID; round-5 V3 then
        # stalled at the challenge because our 0x16/0x17 carried NO transID. `auth_transid` prefixes
        # the whole auth phase the same way every other stage on this head unit is correlated.
        tp = trans_prefix if hyp.auth_transid else b""
        out.append(iap.build_packet(iap.LINGO_GENERAL, iap.CMD_ACK_DEV_AUTHENTICATION_INFO,
                                    tp + bytes([0x00])))
        if not hyp.defer_challenge:
            challenge_len = 20 if major == 0x02 else 16
            challenge = os.urandom(challenge_len) + (bytes([1]) if hyp.challenge_retry_byte else b"")
            out.append(iap.build_packet(iap.LINGO_GENERAL, iap.CMD_GET_DEV_AUTHENTICATION_SIGNATURE,
                                        tp + challenge))
        return out

    if hyp.init_auth and cmd == iap.CMD_RET_DEV_AUTHENTICATION_SIGNATURE:
        tp = payload[:2] if (hyp.auth_transid and len(payload) >= 2) else b""
        out.append(iap.build_packet(iap.LINGO_GENERAL, iap.CMD_ACK_DEV_AUTHENTICATION_STATUS,
                                    tp + bytes([0x00])))
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

    # Post-auth SystemInit phase (SetiPodPreferences / GetiPodPreferences / SetEventNotification /
    # GetSupportedEventNotification, per the firmware). We don't yet know each command's exact reply
    # shape, so `autoack_unknown` answers any unrecognized General Lingo command with a transID-
    # echoing ACK (status success) — the universal correlation pattern — to keep the head unit
    # talking and reveal the whole post-auth sequence. Set-type commands are satisfied by the ACK;
    # Get-type ones (that want a data reply) will stall or retry, telling us which need real handlers.
    if hyp.autoack_unknown and lingo == iap.LINGO_GENERAL:
        trans_id = payload[:2] if len(payload) >= 2 else b"\x00\x00"
        out.append(iap.build_packet(iap.LINGO_GENERAL, iap.CMD_ACK, trans_id + bytes([0x00, cmd])))
        return out

    return out   # unrecognized -> logged by caller, no reply


def rfcomm_session(harness, fd, device):
    sock = socket.fromfd(fd, socket.AF_BLUETOOTH, socket.SOCK_STREAM)
    sock.setblocking(True)
    harness.connected = True
    harness.head_unit_bdaddr = _bdaddr_from_device_path(device)
    harness.log("note", event="rfcomm_connected", device=str(device),
                bdaddr=harness.head_unit_bdaddr)
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
              f"force_idps_success={hyp.force_idps_success}  cert_section={hyp.cert_section_mode}")
        print(f"                  auth_transid={hyp.auth_transid}  defer_challenge={hyp.defer_challenge}  "
              f"autoack_unknown={hyp.autoack_unknown}")
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
                    auth_trigger=hyp.auth_trigger, force_idps_success=hyp.force_idps_success,
                    cert_section_mode=hyp.cert_section_mode, auth_transid=hyp.auth_transid,
                    defer_challenge=hyp.defer_challenge, autoack_unknown=hyp.autoack_unknown)
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


def _bdaddr_from_device_path(device):
    """'/org/bluez/hci0/dev_FC_62_B9_20_52_99' -> 'FC:62:B9:20:52:99' (None if unparseable)."""
    tail = str(device).rsplit("dev_", 1)[-1]
    mac = tail.replace("_", ":")
    return mac if len(mac) == 17 and mac.count(":") == 5 else None


def _log_dataparts(harness, tag, direction, chunk):
    """Decode any AppMode DataParts frames in a chunk and log/print them (no-op if appmode absent)."""
    if appmode is None:
        return
    try:
        frames = list(appmode.parse_frames(chunk))
    except Exception:
        return
    for f in frames:
        harness.log("note", event="dataparts", channel=tag, dir=direction,
                    pack_id=f.pack_id, name=f.name, check=f.check, check_ok=f.check_ok,
                    payload=f.payload.hex())
        print(f"  [dataparts {tag} {direction}] {f.describe()}")


def _av_out_session(harness, bdaddr, tag, channel):
    """Dial OUT to the head unit's AV/data SPP (RFCOMM server channel) and log/decode what it sends."""
    try:
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, _BTPROTO_RFCOMM)
        sock.settimeout(10.0)
        sock.connect((bdaddr, channel))
        sock.settimeout(None)
    except OSError as e:
        harness.log("note", event="av_out_connect_failed", channel=tag, chan=channel, error=str(e))
        print(f"[av-out {tag}] connect to {bdaddr} ch{channel} FAILED: {e}")
        return
    harness.log("note", event="av_out_connected", channel=tag, chan=channel, bdaddr=bdaddr)
    print(f"\n[av-out {tag}] *** CONNECTED to head unit {bdaddr} ch{channel} — dialed AV channel! ***")
    try:
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError as e:
                harness.log("note", event="av_out_recv_error", channel=tag, error=str(e))
                break
            if not chunk:
                break
            harness.log("rx", note="av_out", channel=tag, raw=chunk.hex())
            print(f"  [av-out {tag} rx] {len(chunk)} bytes: {chunk.hex()[:100]}")
            _log_dataparts(harness, tag, "rx", chunk)
    finally:
        harness.log("note", event="av_out_closed", channel=tag)
        print(f"[av-out {tag}] closed")
        sock.close()


def connect_head_unit_av(harness):
    """One-shot: dial the head unit's av1/av2 channels (CHANGE 2). Safe to call repeatedly."""
    with harness.lock:
        if harness.av_out_started:
            return
        bd = harness.head_unit_bdaddr
        if not bd:
            print("[av-out] no head-unit bdaddr known yet — skipping outbound AV connect")
            return
        harness.av_out_started = True
    print(f"[av-out] dialing head unit {bd} AV channels {dict(HEAD_UNIT_AV_CHANNELS)} ...")
    for tag, ch in HEAD_UNIT_AV_CHANNELS.items():
        threading.Thread(target=_av_out_session, args=(harness, bd, tag, ch), daemon=True).start()


def data_channel_session(harness, tag, fd, device):
    """Accept the head unit's AV/data SPP connection and log everything it sends. We don't yet know
    this channel's protocol — the point is (1) accepting it clears the 'cannot connect via Bluetooth'
    error, and (2) the captured bytes reveal the app-data / screen protocol to implement next."""
    sock = socket.fromfd(fd, socket.AF_BLUETOOTH, socket.SOCK_STREAM)
    sock.setblocking(True)
    harness.log("note", event="datachan_connected", channel=tag, device=str(device))
    print(f"\n[datachan {tag}] *** CONNECTED from {device} — head unit opened the AV/data channel! ***")
    try:
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError as e:
                harness.log("note", event="datachan_recv_error", channel=tag, error=str(e))
                break
            if not chunk:
                break
            harness.log("rx", note="datachan", channel=tag, raw=chunk.hex())
            print(f"  [datachan {tag} rx] {len(chunk)} bytes: {chunk.hex()[:100]}")
            _log_dataparts(harness, tag, "rx", chunk)
    finally:
        harness.log("note", event="datachan_closed", channel=tag, device=str(device))
        print(f"[datachan {tag}] closed")
        sock.close()


class DataChannelProfile(dbus.service.Object):
    """A raw-logging RFCOMM listener for one of the head unit's AV/data SPP UUIDs (see AV_DATA_UUIDS)."""

    def __init__(self, bus, path, harness, tag):
        super().__init__(bus, path)
        self.harness = harness
        self.tag = tag

    @dbus.service.method("org.bluez.Profile1", in_signature="", out_signature="")
    def Release(self):
        pass

    @dbus.service.method("org.bluez.Profile1", in_signature="oha{sv}", out_signature="")
    def NewConnection(self, device, fd, properties):
        real_fd = fd.take()
        threading.Thread(target=data_channel_session,
                         args=(self.harness, self.tag, real_fd, device), daemon=True).start()

    @dbus.service.method("org.bluez.Profile1", in_signature="o", out_signature="")
    def RequestDisconnection(self, device):
        pass


def main():
    if os.geteuid() != 0:
        print("Must run as root", file=sys.stderr)
        sys.exit(1)

    # We're racing the head unit's app-launch deadline (round-1 timing showed a ~18s-per-step
    # budget being blown), so drop the production daemon's 50ms inter-packet spacing — reply as fast
    # as possible. The head unit handled our back-to-back initial replies fine in round 1.
    iap.INTER_PACKET_DELAY_S = 0.0

    # Default to SHORT (bare-0x55) sync at startup, not the module default "full". If the head unit
    # opens the RFCOMM channel before the operator arms a hypothesis (it auto-connects on the SDP
    # record), replies would otherwise go out as full 0xFF 0x55 framing, which this head unit
    # rejects (round 1) — that silently wasted the W1 run. arm() still sets it per hypothesis.
    iap.OUTGOING_SYNC_MODE = "short"

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
    print(f"[btsdp-guided] Registered iAP profile (UUID={IAP_BT_UUID}, channel={RFCOMM_CHANNEL})")

    # Also advertise the two AV/data SPP services the head unit connects to after auth (see
    # AV_DATA_UUIDS). Accepting these clears the "cannot connect via Bluetooth" error and captures
    # the app-data protocol.
    for tag, uuid_str, chan in AV_DATA_UUIDS:
        path = f"/9carplay/av_{tag}"
        DataChannelProfile(bus, path, harness, tag)
        manager.RegisterProfile(path, uuid_str, {
            "Name": f"9CarPlay AV data ({tag})",
            "RequireAuthentication": dbus.Boolean(False),
            "RequireAuthorization": dbus.Boolean(False),
            # AutoConnect=False (CHANGE 2): keep HOSTING av1/av2 (accept an inbound connect from the
            # head unit) but do NOT let BlueZ auto-dial at discovery — that fired during the pairing
            # sweep and the head unit DISC'd it (references/guided/btmon/av_capture). The controlled
            # outbound dial now happens post-EI via connect_head_unit_av().
            "AutoConnect": dbus.Boolean(False),
            "Channel": dbus.UInt16(chan),
        })
        print(f"[btsdp-guided] Registered AV/data profile {tag} (UUID={uuid_str}, channel={chan})")

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
