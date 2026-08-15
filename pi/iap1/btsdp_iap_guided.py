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
import re
import socket
import struct
import subprocess
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

# CHANGE 3 (2026-08-11) — REVERTED 2026-08-12 after appmode/3. The hypothesis was that BlueZ's default
# av1/av2 record was missing 0x0006/0x0009 and the head unit refused to dial because of it. That was a
# MISDIAGNOSIS: a server legitimately returns only the attributes it holds out of those optionally
# requested, so a response of 0x0001/0x0004/0x0100 is normal. Worse, supplying a custom "ServiceRecord"
# XML made BlueZ serve an EMPTY record (appmode/3: 2-byte responses for iAP/av1/av2), REGRESSING the
# working default record from capture 2 (70-byte record WITH the RFCOMM channel in attr 0x0004).
# Crucially, in capture 2 the head unit already had a complete, dial-able av1/av2 record and STILL never
# dialed — so SDP was never the blocker. Keep the default BlueZ record (leave this False); the real
# trigger for the head unit's RequestConnectAvSpp is elsewhere (iAP app/EA-session signal), not SDP.
COMPLETE_AV_SDP = False


def build_av_service_record(uuid_str, channel, name):
    """A full SDP record for one AV/data SPP service, including the 0x0006/0x0009 attributes the head
    unit requests (missing from BlueZ's default record). The RFCOMM channel must match the profile's
    Channel option. 0x0009 advertises Serial Port profile v1.0, 0x0006 the standard en/UTF-8 base."""
    return (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        '<record>\n'
        '  <attribute id="0x0001">\n'
        f'    <sequence><uuid value="{uuid_str}" /></sequence>\n'
        '  </attribute>\n'
        '  <attribute id="0x0004">\n'
        '    <sequence>\n'
        '      <sequence><uuid value="0x0100" /></sequence>\n'
        f'      <sequence><uuid value="0x0003" /><uint8 value="0x{channel:02x}" /></sequence>\n'
        '    </sequence>\n'
        '  </attribute>\n'
        '  <attribute id="0x0005">\n'
        '    <sequence><uuid value="0x1002" /></sequence>\n'
        '  </attribute>\n'
        '  <attribute id="0x0006">\n'
        '    <sequence><uint16 value="0x656e" /><uint16 value="0x006a" /><uint16 value="0x0100" /></sequence>\n'
        '  </attribute>\n'
        '  <attribute id="0x0009">\n'
        '    <sequence>\n'
        '      <sequence><uuid value="0x1101" /><uint16 value="0x0100" /></sequence>\n'
        '    </sequence>\n'
        '  </attribute>\n'
        f'  <attribute id="0x0100"><text value="{name}" /></attribute>\n'
        '</record>\n'
    )


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
                 challenge_retry_byte=True, autoack_unknown=False,
                 ei_return_dbrecords=False, ei_return_cmd=0x2c, ei_return_count=0,
                 ei_nowplaying_returns=False,
                 ea_open_session=False, ea_open_protocols=("hondalink",),
                 ea_open_trigger="device_info", ea_open_delay=2.0,
                 dataparts_session=False, dp_ipod_transfer_cmd=0x41,
                 dp_opcode_sweep=(), dp_auto_b2=True,
                 av_spp_handshake=False, av_spp_channels=("av1", "av2")):
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
        # ei_return_dbrecords: EXPERIMENTAL (ROUND 20). For the Extended-Interface command
        # `ei_return_cmd`, reply with a typed ReturnNumberCategorizedDBRecords (EI cmd 0x0019,
        # payload = transID + uint32 count) INSTEAD of the generic EI ACK. The RE'd SystemInit state
        # machine (references/cr-v/IDPS_STATE_MAP.md, states 13-16) shows the head unit needs a
        # record COUNT here, not an ACK, to advance past EI DB setup toward StartBluetoothConnection
        # Update (the av1/av2 dial). Unverified: the exact EI opcode/format is behind the ADCL's
        # internal-id scheme, so this is a best-motivated guess — kept in its own hypothesis (Z1) so
        # the proven Y1 ACK-walk path is untouched and the stall-namer runs either way.
        self.ei_return_dbrecords = ei_return_dbrecords
        self.ei_return_cmd = ei_return_cmd
        self.ei_return_count = ei_return_count
        # ei_nowplaying_returns: ROUND 26. Answer the head unit's Extended-Interface NowPlaying Get
        # commands with real (empty/stopped) iAP1 EI *Return* responses instead of a generic EI ACK.
        # RE (Ghidra, NEventWatcher ADCL) identified the post-EI burst the head unit sends and stalls
        # on: 0x1c GetPlayStatus, 0x2c GetShuffle, 0x2f GetRepeat are Gets that need typed Returns
        # (0x26 SetPlayStatusChangeNotification is a Set — ACK is correct). See EI_GET_RETURNS.
        self.ei_nowplaying_returns = ei_nowplaying_returns
        # ea_open_session: STEP B (ROUND 29). After full iAP init the head unit runs RequestAutoStartApp
        # and — finding no HondaLink app "present" — shows "app not installed / App Store". On a real
        # iPhone the phone sends OpenDataSessionForProtocol (General Lingo 0x3F) when a matching app
        # opens its EASession, which is what registers the app on the head unit. The Pi has no such app,
        # so we synthesize that message: for each declared EA protocol whose string matches one of
        # `ea_open_protocols`, send OpenDataSessionForProtocol(sessionId, protocolIndex) using the index
        # the head unit assigned in its SetFIDTokenValues. `ea_open_trigger` picks WHEN:
        #   "device_info" -> on the first General device-info request (0x07/0x0b/0x0d/0x09), i.e. right
        #                    as the head unit is at the app-launch stage (closest wire signal).
        #   "ei_mode"     -> a fixed `ea_open_delay`s after Extended-Interface mode begins (earlier;
        #                    a fallback if device_info timing lands after the head unit already decided).
        self.ea_open_session = ea_open_session
        self.ea_open_protocols = tuple(ea_open_protocols)
        self.ea_open_trigger = ea_open_trigger
        self.ea_open_delay = ea_open_delay
        # dataparts_session: STEP C (ROUND 32). After OpenDataSessionForProtocol registers the app,
        # the head unit's HNiAPAuth::OnRecvDataFromIAppEvent waits to RECEIVE the app's first data on
        # that iAP EA session ("Session Start notification FALSE" = it got nothing) and then runs the
        # AppMode DataParts auth. So we drive it: send an iPodDataTransfer to kick the session, then
        # decode every inbound DataParts frame and (best-effort) answer 0xB1 StartAuth with 0xB2
        # AuthResponse (crypto from AppMode.md via pi/appmode/appmode_proto). The FIRST goal is to
        # CAPTURE the head unit's 0xB1 (nonce/format), which no run has yet elicited.
        self.dataparts_session = dataparts_session
        # dp_ipod_transfer_cmd: the iPodDataTransfer opcode (phone->HU app data). 0x41 assumed; the one
        # EA value not firmware-confirmed. RECEIVE is opcode-agnostic (we scan any General packet for
        # DataParts 9F02 frames), so a wrong send opcode only costs the outbound kick, not the capture.
        self.dp_ipod_transfer_cmd = dp_ipod_transfer_cmd
        # dp_opcode_sweep: candidate iPodDataTransfer wire opcodes to try IN ONE CONNECTION (the app-data
        # opcode is the one value not statically recoverable — see HONDALINK_APP_PROTOCOL.md §8). Empty =
        # just dp_ipod_transfer_cmd. The head unit ignores unrecognized opcodes cleanly, so sweeping a
        # small set is a cheap way to find the right one given the session caches between reconnects.
        self.dp_opcode_sweep = tuple(dp_opcode_sweep)
        # dp_auto_b2: on receiving a DataParts 0xB1 StartAuth, best-effort build+send a 0xB2 AuthResponse
        # (nonce taken from 0xB1 if present). Even a rejected 0xB2 is informative (0xB3 vs re-0xB1 vs
        # teardown); the 0xB1 capture is logged regardless.
        self.dp_auto_b2 = dp_auto_b2
        # av_spp_handshake: STEP C, corrected transport (ROUND 36). hondalink/3 proved the DataParts
        # app handshake does NOT ride the iAP EA session — the head unit ignored every iPodDataTransfer
        # opcode there. Instead the head unit ACCEPTED our av1/av2 SPP dials, then DISC'd ~1.2s later
        # because we sent ZERO bytes on them: it waits for the phone's first AppMode frame on the SPP
        # socket (AppMode.md §1/§8 — auth is over av1/av2 SPP, not iAP). This flag makes _av_out_session
        # push the SessionStart+AuthRequest DataParts frames on the SPP socket right after connect and
        # auto-answer a 0xB1 StartAuth with 0xB2 on the SAME socket.
        self.av_spp_handshake = av_spp_handshake
        # av_spp_channels: which dialed SPP channel(s) carry the AppMode auth handshake. AppMode.md §7
        # unknown #3 (channel 5 vs 6 assignment) is unresolved, so default to sending on both; the head
        # unit drops the wrong one cleanly.
        self.av_spp_channels = tuple(av_spp_channels)


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
# Single working hypothesis. Z2 is the MILESTONE sequence (see references/cr-v/WORKING_SEQUENCE.md):
# it drives the full iAP1-over-Bluetooth init the head unit requires and reaches the HondaLink
# app-launch stage. History of the earlier probe hypotheses (Y1/Y2/Z1) lives in git + the memory log;
# they've been removed so this just runs. To add a new probe, append another Hypothesis(...) here.
# Base kwargs for the proven full-init sequence (Z2, the WORKING_SEQUENCE milestone). EA1/EA2 layer
# the step-B app-presence emulation on top of exactly this.
_FULL_INIT = dict(cert_section_mode="ack_transid", auth_transid=True,
                  auth_trigger="after_fidtokens", force_idps_success=True, autoack_unknown=True,
                  ei_nowplaying_returns=True)

HYPOTHESES = [
    Hypothesis(
        "Z2", "CONTROL: full iAP init to the HondaLink app-launch stage",
        "The complete, RE-derived iAP1-over-BT init the head unit needs: proven MFi auth (transID'd "
        "cert->challenge->status), then it answers EVERY post-auth request the head unit's sequencer "
        "waits on — General device-info (name/version/model via REQUEST_HANDLERS), Extended-Interface "
        "NowPlaying Gets (0x1c GetPlayStatus->0x1d, 0x2c GetShuffle->0x2d, 0x2f GetRepeat->0x30, all "
        "empty/stopped) and DB-records (0x18 GetNumberCategorizedDBRecords->0x19 count=0), ACKing the "
        "Sets/EI setup. This carries the head unit through NowPlaying + SystemInit DB setup to the "
        "point where it auto-launches the HondaLink app (RequestAutoStartApp). NO app emulation — the "
        "control that reproduces the milestone.",
        "One clean connection attempt (no teardown/retry) that runs to the app-launch stage: on the "
        "screen, the 'app not installed / get it from the App Store' message (not a Bluetooth or "
        "'cannot launch' error). The namer names any NEW request if the head unit asks for more.",
        **_FULL_INIT),
    Hypothesis(
        "EA1", "STEP B: announce HondaLink app via OpenDataSessionForProtocol (hondalink idx2)",
        "Z2's full init PLUS the step-B app-presence emulation: when the head unit reaches the "
        "app-launch stage (first General device-info request), the Pi sends OpenDataSessionForProtocol "
        "(General Lingo 0x3F) for the EA protocol 'jp.co.honda.rd.dispaudio.app.hondalink' (index 0x02, "
        "read live from the head unit's own SetFIDTokenValues). On a real iPhone this is the message "
        "iOS sends when the HondaLink app opens its EASession; it is what makes the head unit register "
        "the app (SetServerVRAppData) instead of declaring it missing. Since the Pi controls the phone "
        "side, we synthesize it.",
        "The 'app not installed / App Store' message does NOT appear (or changes). Best case: the head "
        "unit registers the app and DIALS av1/av2 (av_inbound_dial) and/or sends a new app-launch / "
        "OpenDataSession response / RequestIAppLaunch command. Any change vs Z2 is signal — the namer "
        "and phase checklist capture whatever the head unit does next.",
        ea_open_session=True, ea_open_protocols=("hondalink",), ea_open_trigger="device_info",
        **_FULL_INIT),
    Hypothesis(
        "EA2", "STEP B: announce BOTH HondaLink EA protocols (general idx1 + hondalink idx2)",
        "Same as EA1, but opens data sessions for BOTH of the HondaLink app's declared protocols — "
        "'...app.general' (index 0x01) and '...app.hondalink' (index 0x02) — since the app declares "
        "both under the same bundle seed (TX6J99784P) and the head unit may want the pair before it "
        "treats the app as fully present.",
        "As EA1. If EA1 alone didn't satisfy the head unit but EA2 does, the head unit needed the full "
        "protocol set announced, not just the hondalink one.",
        ea_open_session=True, ea_open_protocols=("general", "hondalink"),
        ea_open_trigger="device_info", **_FULL_INIT),
    Hypothesis(
        "DP1", "STEP C: drive HNiAPAuth — SessionStart + AuthRequest (opcode 0x41)",
        "Full init + app announce, then the RE-derived HondaLink app handshake "
        "(references/cr-v/HONDALINK_APP_PROTOCOL.md): over the open EA session we send the two "
        "plaintext DataParts control frames the head unit waits for — Session Start (id 0x00 / payload "
        "[01 01]) then Auth Request (id 0x00 / payload [00]) — wrapped in iPodDataTransfer (opcode "
        "0x41). Per the firmware the Auth Request makes the head unit's HNiAPAuth send its StartAuth "
        "(0xB1) reply. Every inbound packet is scanned for DataParts frames; a 0xB1 is logged with its "
        "nonce and best-effort answered with 0xB2.",
        "PRIMARY WIN: a DataParts 0xB1 StartAuth arrives on the iAP channel ([dataparts RX ... 0xB1]) — "
        "the app protocol on the wire for the first time — then 0xB3 AuthFin / the app rendering over "
        "HDMI. 'No 0xB1' means opcode 0x41 is wrong; run DP2 (opcode sweep).",
        ea_open_session=True, ea_open_protocols=("hondalink",), ea_open_trigger="device_info",
        dataparts_session=True, dp_ipod_transfer_cmd=0x41, **_FULL_INIT),
    Hypothesis(
        "DP2", "STEP C: drive HNiAPAuth — sweep iPodDataTransfer opcodes 0x41/0x42/0x40/0x43",
        "Same handshake as DP1, but sends the SessionStart+AuthRequest pair over several candidate "
        "transport opcodes in one connection (0x41, 0x42, 0x40, 0x43) to find the app-data wire opcode "
        "empirically — the one value that couldn't be pinned statically. The head unit ignores "
        "unrecognized opcodes cleanly, so whichever one elicits a 0xB1 is the correct transport.",
        "A 0xB1 StartAuth appears — and the btmon/log show which opcode's iPodDataTransfer preceded it. "
        "That confirms the transport; DP1 can then be re-pinned to that opcode.",
        ea_open_session=True, ea_open_protocols=("hondalink",), ea_open_trigger="device_info",
        dataparts_session=True, dp_opcode_sweep=(0x41, 0x42, 0x40, 0x43), **_FULL_INIT),
    Hypothesis(
        "DP5", "STEP C, CORRECTED TRANSPORT: drive AppMode auth over av1/av2 SPP (not iAP EA)",
        "hondalink/3 resolved the transport: the head unit IGNORED the DataParts handshake on every iAP "
        "iPodDataTransfer opcode (DP1/DP2), but ACCEPTED our av1/av2 SPP dials and then DISC'd ~1.2s later "
        "because we sent ZERO bytes on them — it waits for the phone's first AppMode frame on the SPP "
        "socket (AppMode.md §1/§8: the 0xB1/0xB2/0xB3 auth rides av1/av2 SPP, not the iAP channel). This "
        "hypothesis keeps the EA app-announce (OpenDataSessionForProtocol, which made the head unit treat "
        "the app as present) but moves the handshake to the SPP socket: right after the av1/av2 dial we "
        "push SessionStart (id 0x00/[01 01]) + AuthRequest (id 0x00/[00]) on the SPP channel(s), then "
        "answer a 0xB1 StartAuth with a best-effort 0xB2 on the same socket.",
        "PRIMARY WIN: the av1/av2 SPP channel STAYS UP past ~1.2s (no DISC) and/or a DataParts 0xB1 "
        "StartAuth arrives on it ([dataparts av1 rx] / [av-out av1 rx]) — the AppMode auth on the wire for "
        "the first time. Even 'channel stays open longer' is signal that the first frame was accepted. If "
        "it still DISC's immediately, the first-frame format/subtype is wrong (not the transport).",
        ea_open_session=True, ea_open_protocols=("hondalink",), ea_open_trigger="device_info",
        av_spp_handshake=True, av_spp_channels=("av1", "av2"), **_FULL_INIT),
]


# ===========================================================================
# Per-connection response logic
# ===========================================================================

# ===========================================================================
# Connection-phase instrumentation (added 2026-08-12, ROUND 18 diagnostics)
# ===========================================================================
# Maps the wire-observable milestones to the head unit's firmware chain (traced in AppMode.md and
# memory ROUND 17-18):
#   iAP1 auth -> NotifyIOSAuthEvent 'AppMode Active' -> NotifyStartSmartPhoneApps
#   (guards: SPP-not-conn, m_pLPALMIf, BDaddr!=0, m_pAuthInfo) -> ConnectPhoneApp
#   -> RequestConnectAvSpp dials av1/av2 -> DataParts 0xB1/0xB2/0xB3.
# We can't read the head unit's internal guard logs, so we infer WHICH guard fails from how far this
# observable chain gets. The single most important signal is whether the head unit ever DIALS our
# av1/av2 (av_inbound_dial): reaching EI mode but never seeing that dial pins the stall to
# NotifyStartSmartPhoneApps (m_pAuthInfo or BDaddr).
PHASE_CHAIN = [
    ("rfcomm_iap",       "iAP RFCOMM channel opened by head unit"),
    ("idps_start",       "StartIDPS (0x38) received"),
    ("fid_tokens",       "SetFIDTokenValues (0x39) received"),
    ("idps_end",         "EndIDPS (0x3b) received"),
    ("mfi_auth_info",    "MFi RetDevAuthInfo (0x15) received — head unit auth begins"),
    ("mfi_signature",    "MFi RetDevAuthSignature (0x18) received"),
    ("mfi_status_acked", "we sent AckDevAuthStatus (0x19) — Layer-1 iAP auth complete on our side"),
    ("ei_mode",          "head unit entered Extended-Interface mode (0x05 / lingo 0x04)"),
    ("av_inbound_dial",  "*** head unit DIALED our av1/av2 (the AppMode AV connect) ***"),
    ("dataparts_b1",     "DataParts StartAuth (0xB1) received on the AV channel"),
]
_PHASE_DESC = dict(PHASE_CHAIN)
# non-chain markers (diagnostic flags, not linear milestones)
_PHASE_DESC["mfi_auth_reloop"] = "head unit re-sent 0x15 after our 0x19 (MFi auth not accepted)"
_PHASE_DESC["stalled_awaiting_av_dial"] = "EI reached but no av1/av2 dial within the wait window"
_PHASE_DESC["ea_open_sent"] = "we sent OpenDataSessionForProtocol announcing the HondaLink app (step B)"
_PHASE_DESC["dp_kick_sent"] = "we sent the session-start iPodDataTransfer kick (step C)"
_PHASE_DESC["dataparts_b3"] = "*** received DataParts 0xB3 AuthFin — AppMode auth likely complete ***"
STALL_AWAIT_AV_S = 12.0   # after EI mode, how long we wait for the head unit to dial av1/av2
STALL_SILENCE_S = 6.0     # post-auth: how long the head unit must go silent before we name the
                          # command it's stuck on (its retry unit is ~6s; normal gaps are sub-second)

CMD_ENTER_EI = 0x05       # General Lingo EnterExtendedInterfaceMode

# The head unit's post-auth SystemInit sequence (RE'd in references/cr-v/IDPS_STATE_MAP.md) needs a
# TYPED iAP1 response at each 'Ret/Return...Wait' state; we currently blanket-ACK, which the state
# machine rejects ("Not expect ID") and stalls on. These are the typed-response states, in order —
# each iteration should implement the next one the namer points at.
SYSTEMINIT_TYPED_STATES = [
    "SupportedEventNotification",
    "RetiPodPreferences (screen)  [class byte must match head unit's stored pref]",
    "RetiPodPreferences (aspect)  [class byte must match]",
    "ReturnExtendedInterfaceMode (enter)",
    "ResetDBHierarchy (video) ack",
    "ReturnNumberCategorizedDBRecords (video)  [return a record count]",
    "ResetDBHierarchy (audio) ack",
    "ReturnNumberCategorizedDBRecords (audio)  [return a record count]",
    "ReturnExtendedInterfaceMode (exit)",
    "BluetoothComponentInformation",
    "StartBluetoothConnectionUpdate  [terminal -> SystemInit complete -> av1/av2 dial]",
]


def _valid_bd(a):
    return a if (a and len(a) == 17 and a.count(":") == 5 and a != "00:00:00:00:00:00") else None


def _read_local_bdaddr(index=0):
    """Local adapter BD address (e.g. 'DC:A6:32:..'), or None. Tries sysfs for hci<index>, then any
    /sys/class/bluetooth/*/address, then `hciconfig`, then BlueZ D-Bus Adapter1.Address — the plain
    hci0 sysfs read returned None on the Pi (appmode/5-7), and we need this to check the BDaddr guard."""
    import glob
    try:
        with open(f"/sys/class/bluetooth/hci{index}/address") as fh:
            a = _valid_bd(fh.read().strip().upper())
        if a:
            return a
    except OSError:
        pass
    for path in sorted(glob.glob("/sys/class/bluetooth/*/address")):
        try:
            with open(path) as fh:
                a = _valid_bd(fh.read().strip().upper())
            if a:
                return a
        except OSError:
            continue
    try:
        out = subprocess.run(["hciconfig", f"hci{index}"], capture_output=True, text=True, timeout=3).stdout
        m = re.search(r"BD Address:\s*([0-9A-Fa-f:]{17})", out)
        if m:
            return _valid_bd(m.group(1).upper())
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        bus = dbus.SystemBus()
        props = dbus.Interface(bus.get_object("org.bluez", f"/org/bluez/hci{index}"),
                               "org.freedesktop.DBus.Properties")
        return _valid_bd(str(props.Get("org.bluez.Adapter1", "Address")).upper())
    except Exception:
        return None


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
        # ---- step-B EA app-session state (per-window) ----
        self.iap_sock = None             # the live iAP RFCOMM socket, for out-of-band sends (EA open)
        self.ea_protocols = []           # EA protocols the head unit declared in SetFIDTokenValues
        self.ea_opened = False           # one-shot guard: OpenDataSessionForProtocol already sent
        self.ea_session_id = None        # session id we assigned the HondaLink protocol (for data xfer)
        self.dp_kicked = False           # one-shot guard: session-start iPodDataTransfer already sent
        self.dp_b2_sent = False          # one-shot guard: best-effort 0xB2 AuthResponse already sent
        # ---- phase instrumentation (per-window) ----
        self.local_bdaddr = None         # this adapter's BD address (set once at startup)
        self.conn_t0 = None              # wall clock of the current iAP connection start
        self.phases = {}                 # phase_key -> {t_since_connect, ...}; reset each window
        # ---- stall-command namer (option b) ----
        # We blanket-ACK unknown post-auth commands; the LAST one we blanket-ACKed before the head
        # unit goes silent names the SystemInit state we must implement a typed response for next.
        self.postauth_cmds = []          # ordered [{lingo,cmd,payload,reply,t}] since MFi auth done
        self._silence_timer = None       # threading.Timer, reset on every post-auth rx
        self._stall_reported = False     # one-shot guard for the stall report this window

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
            self.phases = {}
            self.postauth_cmds = []
            self.ea_protocols = []
            self.ea_opened = False
            self.ea_session_id = None
            self.dp_kicked = False
            self.dp_b2_sent = False
            self._stall_reported = False
            if self._silence_timer:
                self._silence_timer.cancel()
                self._silence_timer = None
            iap.OUTGOING_SYNC_MODE = "full" if hyp.sync == "full" else "short"

    def count_rx(self, cmd):
        with self.lock:
            self.rx_counts[cmd] = self.rx_counts.get(cmd, 0) + 1
            return self.rx_counts[cmd]

    # ---- phase instrumentation -------------------------------------------------
    def has_phase(self, key):
        with self.lock:
            return key in self.phases

    def mark_phase(self, key, **detail):
        """Record the FIRST time a milestone is observed this window. Returns True on first hit
        (so callers can arm one-shot side effects like the stall watchdog), False on repeats."""
        with self.lock:
            if key in self.phases:
                return False
            dt = round(time.time() - self.conn_t0, 3) if self.conn_t0 else None
            self.phases[key] = {"t_since_connect": dt, **detail}
        self.log("phase", phase=key, t_since_connect=dt, **detail)
        desc = _PHASE_DESC.get(key, key)
        print(f"  [PHASE +{(dt if dt is not None else 0):>6}s] {key} — {desc}")
        return True

    # ---- stall-command namer (option b) -----------------------------------------
    def record_postauth(self, lingo, cmd, payload, reply_kind):
        """Log a post-(MFi-auth) command and how we answered it. Only records once SystemInit has
        begun (mfi_status_acked or ei_mode reached) — IDPS/auth commands are not SystemInit states."""
        with self.lock:
            if "mfi_status_acked" not in self.phases and "ei_mode" not in self.phases:
                return
            dt = round(time.time() - self.conn_t0, 3) if self.conn_t0 else None
            self.postauth_cmds.append({"lingo": lingo, "cmd": cmd,
                                       "payload": payload.hex(), "reply": reply_kind, "t": dt})

    def arm_silence_watchdog(self):
        """(Re)start the post-auth silence timer. If the head unit stays silent STALL_SILENCE_S after
        its last command, _report_stall names the command it's waiting on a typed response for."""
        with self.lock:
            post = "mfi_status_acked" in self.phases or "ei_mode" in self.phases
            done = self._stall_reported or "av_inbound_dial" in self.phases
            if self._silence_timer:
                self._silence_timer.cancel()
                self._silence_timer = None
            if not post or done:
                return
            win = self.window_id
            self._silence_timer = threading.Timer(STALL_SILENCE_S, self._report_stall, args=(win,))
            self._silence_timer.daemon = True
            self._silence_timer.start()

    def cancel_silence_watchdog(self):
        with self.lock:
            if self._silence_timer:
                self._silence_timer.cancel()
                self._silence_timer = None

    # ---- step-B EA app-session emulation -----------------------------------------
    def take_ea_open_packets(self, hyp):
        """One-shot: build the OpenDataSessionForProtocol packet(s) for the EA protocol(s) this
        hypothesis targets, using the indices the head unit declared (stored from SetFIDTokenValues).
        Returns [] if already sent, not enabled, or no matching protocol was declared. Assigns a
        fresh session id per opened protocol. Logged so the run shows exactly what we announced."""
        with self.lock:
            if self.ea_opened or not hyp.ea_open_session:
                return []
            protos = list(self.ea_protocols)
            if not protos:
                return []
            self.ea_opened = True
        pkts, opened = [], []
        session_id = 1
        for want in hyp.ea_open_protocols:
            for p in protos:
                if want.lower() in p["protocol"].lower():
                    pkts.append(iap.build_open_data_session_for_protocol(session_id, p["index"]))
                    opened.append({"session_id": session_id, "index": p["index"],
                                   "protocol": p["protocol"], "bundle_seed_id": p["bundle_seed_id"]})
                    # remember the HondaLink session for the step-C data-transfer kick (prefer the
                    # 'hondalink' protocol; fall back to the first opened session)
                    with self.lock:
                        if self.ea_session_id is None or "hondalink" in p["protocol"].lower():
                            self.ea_session_id = session_id
                    session_id += 1
                    break
        if opened:
            self.log("note", event="ea_open_session", opened=opened)
            self.mark_phase("ea_open_sent", opened=opened)
            names = ", ".join(f"{o['protocol']}(idx{o['index']},sess{o['session_id']})" for o in opened)
            print(f"  [ea-open] announcing HondaLink app via OpenDataSessionForProtocol: {names}")
        else:
            print(f"  [ea-open] no declared EA protocol matched {hyp.ea_open_protocols} — nothing sent")
        return pkts

    # ---- step-C DataParts over the iAP EA session --------------------------------
    def take_dp_kick_packets(self, hyp):
        """One-shot: drive the HNiAPAuth handshake. Per references/cr-v/HONDALINK_APP_PROTOCOL.md the
        phone must send, over the open EA session, two plaintext DataParts control frames:
            Session Start  = frame(id 0x00, payload [0x01, 0x01])   -> HU SetAuthStatus (no wire reply)
            Auth Request   = frame(id 0x00, payload [0x00])         -> HU replies (StartAuth 0xB1)
        These are wrapped in an iPodDataTransfer on the HondaLink session. The transport wire opcode is
        the one value not statically recoverable, so hyp.dp_opcode_sweep lets us try several candidates
        in one connection (the head unit ignores an unrecognized opcode cleanly). [] if disabled/already
        sent/no session/appmode missing."""
        with self.lock:
            if self.dp_kicked or not hyp.dataparts_session or self.ea_session_id is None:
                return []
            sid = self.ea_session_id
            self.dp_kicked = True
        if appmode is None:
            print("  [dp] appmode_proto unavailable — cannot build DataParts frames")
            return []
        session_start = appmode.build_frame(0x00, bytes([0x01, 0x01]))   # 9F 02 00 00 01 01 9F 03
        auth_request = appmode.build_frame(0x00, bytes([0x00]))          # 9F 02 00 00 00 9F 03
        opcodes = list(hyp.dp_opcode_sweep) if hyp.dp_opcode_sweep else [hyp.dp_ipod_transfer_cmd]
        pkts = []
        for op in opcodes:
            # Session Start first, then Auth Request — the HU wants the session marked started before
            # (or together with) the auth request that elicits its StartAuth reply.
            pkts.append(iap.build_ipod_data_transfer(sid, session_start, cmd=op))
            pkts.append(iap.build_ipod_data_transfer(sid, auth_request, cmd=op))
        self.log("note", event="dp_kick", session_id=sid, opcodes=opcodes,
                 session_start=session_start.hex(), auth_request=auth_request.hex())
        self.mark_phase("dp_kick_sent", session_id=sid, opcodes=[f"0x{o:02x}" for o in opcodes])
        print(f"  [dp] driving HNiAPAuth on session {sid}: SessionStart {session_start.hex()} + "
              f"AuthRequest {auth_request.hex()} over iPodDataTransfer opcode(s) "
              f"{', '.join(f'0x{o:02x}' for o in opcodes)}")
        return pkts

    def handle_inbound_dataparts(self, hyp, lingo, cmd, payload):
        """Scan an inbound iAP packet for DataParts frames (opcode-agnostic: the head unit's app-data
        opcode is unconfirmed, so we look for 9F02..9F03 in any General-Lingo payload). Log each frame;
        on a 0xB1 StartAuth, best-effort build a 0xB2 AuthResponse. Returns extra packets to send."""
        if not hyp.dataparts_session or appmode is None or lingo != iap.LINGO_GENERAL:
            return []
        # app data arrives as [sessionId(2), dataparts]; also scan the whole payload in case the
        # framing differs. parse_ea_data_transfer just strips a 2-byte prefix when present.
        _sid, app_data = iap.parse_ea_data_transfer(payload)
        frames = list(appmode.parse_frames(payload)) or list(appmode.parse_frames(app_data))
        if not frames:
            return []
        out = []
        for f in frames:
            self.log("note", event="dataparts_rx", cmd=cmd, pack_id=f.pack_id, name=f.name,
                     check=f.check, check_ok=f.check_ok, payload=f.payload.hex())
            print(f"  [dataparts RX cmd=0x{cmd:02x}] {f.describe()}")
            if f.pack_id == 0xB1:
                self.mark_phase("dataparts_b1", channel="iap_ea", payload=f.payload.hex())
                print(f"  *** RECEIVED 0xB1 StartAuth over the iAP EA session — payload={f.payload.hex()} ***")
                if hyp.dp_auto_b2:
                    b2 = self._build_b2_response(f)
                    if b2 is not None:
                        out.append(b2)
            elif f.pack_id == 0xB3:
                self.mark_phase("dataparts_b3", channel="iap_ea", payload=f.payload.hex())
                print("  *** RECEIVED 0xB3 AuthFin — AppMode auth likely COMPLETE ***")
        return out

    def _build_b2_frame(self, b1_payload, source="spp"):
        """Best-effort RAW 0xB2 AuthResponse DataParts frame for a received 0xB1. The nonce/info/identity
        -blob layout aren't firmware-pinned (AppMode.md §7), so this is a PROBE: derive the key from a
        candidate nonce (the 4 bytes after the 0xB1 subtype, if present), encrypt a plausible identity
        blob, and frame it. Returns the bare 9F02..9F03 frame bytes (transport-agnostic) or None. The
        head unit's reaction (0xB3 vs re-0xB1 vs teardown) tells us whether the guesses are right."""
        if appmode is None:
            return None
        # candidate nonce: 0xB1 payload is subtype(1) [+ nonce(4)] per AppMode.md taxonomy (id 0xB1,
        # subtype 00/01, len 3/5). If >=5 bytes present, take bytes [1:5] as the nonce; else zero.
        p = b1_payload
        nonce = p[1:5] if len(p) >= 5 else b"\x00\x00\x00\x00"
        key = appmode.derive_key(nonce, info=b"")
        # plausible identity blob (length-prefixed fields; layout UNCONFIRMED — a probe). Order per
        # ROUND 18: ManufactureName, ModelName, OSVersion, IndividualInfo, AppVersion, AppId.
        def lp(s):
            b = s.encode() if isinstance(s, str) else s
            return bytes([len(b)]) + b
        blob = (lp("Apple") + lp("iPhone") + lp("7.0") + lp("0000")
                + lp("1.0") + lp("jp.co.honda.rd.dispaudio.app.hondalink"))
        ct = appmode.aes_cbc_encrypt(key, blob)
        b2_payload = bytes([0x00]) + ct     # subtype 0x00 + ciphertext (best-effort)
        frame = appmode.build_frame(0xB2, b2_payload)
        self.log("note", event="dp_b2_built", source=source, nonce=nonce.hex(),
                 key=key.hex(), blob=blob.hex(), frame=frame.hex())
        print(f"  [dp] best-effort 0xB2 AuthResponse ({source}): nonce={nonce.hex()} key={key.hex()} "
              f"({len(frame)}B frame) — PROBE, format unconfirmed")
        return frame

    def _build_b2_response(self, b1_frame):
        """DEPRECATED iAP-EA transport (hondalink/3 proved the head unit ignores DataParts on the iAP
        channel). Kept so the legacy DP1/DP2 inbound path still answers a 0xB1 if one ever arrives there.
        The live transport is now av1/av2 SPP — see _av_out_session / av_spp_handshake. Sent once."""
        with self.lock:
            if self.dp_b2_sent or self.ea_session_id is None:
                return None
            sid = self.ea_session_id
            self.dp_b2_sent = True
        frame = self._build_b2_frame(b1_frame.payload, source="iap_ea")
        if frame is None:
            return None
        return iap.build_ipod_data_transfer(sid, frame, cmd=self.current.dp_ipod_transfer_cmd)

    def _report_stall(self, window_at_arm):
        with self.lock:
            if (window_at_arm != self.window_id or self._stall_reported
                    or "av_inbound_dial" in self.phases):
                return
            self._stall_reported = True
            cmds = list(self.postauth_cmds)
        text = _format_stall_report(cmds)
        self.log("stall_report", post_auth_cmds=cmds)
        self.note_txt(text)
        print(text)

    def phase_summary(self):
        """(checklist_text, interpretation) describing how far the chain got this window."""
        with self.lock:
            reached = dict(self.phases)
            postauth = list(self.postauth_cmds)
        lines = []
        seq = []   # (key, t) for reached chain phases in chain order, to find stall gaps
        for key, desc in PHASE_CHAIN:
            hit = key in reached
            t = reached[key].get("t_since_connect") if hit else None
            tstr = f" (+{t}s)" if t is not None else ""
            lines.append(f"    [{'x' if hit else ' '}] {key}{tstr} — {desc}")
            if hit and t is not None:
                seq.append((key, t))
        # flag the largest gap between consecutive milestones — a >3s jump is the head unit timing
        # out waiting for a reply it didn't accept (the ~18s IDPS/auth stalls).
        worst = None
        for (k0, t0), (k1, t1) in zip(seq, seq[1:]):
            if worst is None or (t1 - t0) > worst[0]:
                worst = (round(t1 - t0, 3), k0, k1)
        if worst and worst[0] >= 3.0:
            lines.append(f"    >> biggest stall: {worst[0]}s between '{worst[1]}' and '{worst[2]}' "
                         f"(head unit waited for a reply it didn't accept)")
        # stall-command namer: the last post-auth command we generic-ACKed is the SystemInit state
        # whose typed response we still owe (see references/cr-v/IDPS_STATE_MAP.md).
        if postauth and "av_inbound_dial" not in reached:
            stall = postauth[-1]   # last command before silence, regardless of reply type
            tail = (" (typed reply here didn't help -> stall is DOWNSTREAM: av1/av2 dial / AppMode)"
                    if stall["reply"] == "typed" else "")
            lines.append(f"    >> LAST CMD BEFORE SILENCE: lingo=0x{stall['lingo']:02x} "
                         f"cmd=0x{stall['cmd']:04x} payload={stall['payload']} "
                         f"[we answered: {stall['reply']}]  ({len(postauth)} post-auth cmd(s) seen){tail}")
        return "\n".join(lines), self._interpret(reached)

    @staticmethod
    def _interpret(reached):
        has = reached.__contains__
        if not has("rfcomm_iap"):
            return "No iAP connection — head unit never opened the RFCOMM channel this window."
        # STEP C: DataParts over the iAP EA session is the definitive breakthrough signal.
        if has("dataparts_b3"):
            return ("*** BREAKTHROUGH: received DataParts 0xB3 AuthFin over the iAP EA session — the "
                    "AppMode/HNiAPAuth handshake likely COMPLETED. The app should now be authenticated; "
                    "watch for it rendering over HDMI / the head unit connecting av1/av2 for vehicle data.")
        if has("dataparts_b1"):
            ch = reached.get("dataparts_b1", {}).get("channel", "")
            return (f"*** MAJOR: received DataParts 0xB1 StartAuth ({ch}) — the HondaLink app protocol is "
                    "on the wire for the first time. Capture its nonce/format from the log; if our "
                    "best-effort 0xB2 wasn't accepted (no 0xB3), build a correct 0xB2 from the captured "
                    "0xB1 (nonce direction + identity blob) and re-run. This confirms the transport = "
                    "iAP EA session.")
        if has("av_inbound_dial"):
            if has("dataparts_b1"):
                return ("BREAKTHROUGH: head unit dialed av1/av2 AND sent DataParts 0xB1. The L2 AppMode "
                        "auth is live — capture the 0xB1/0xB2 exchange for the identity-blob layout.")
            return ("Head unit DIALED av1/av2 but no 0xB1 yet — the AV connect works; the DataParts "
                    "auth should follow. Watch for 0xB1 on that channel.")
        if reached.get("mfi_auth_reloop"):
            return ("MFi auth is LOOPING (head unit re-sent 0x15 after our 0x19) -> it did NOT accept the "
                    "authentication -> m_pAuthInfo stays NULL -> NotifyStartSmartPhoneApps bails. "
                    "FIX TARGET: Layer-1 MFi auth completion (challenge/status handling).")
        # NOTE: reaching EI mode PROVES IDPS + MFi auth succeeded. accEndIDPSStatus=0x01 with a big
        # pre-idps_end gap is the two-attempt btmon stitching artifact (ROUND 20), NOT a real IDPS
        # failure — so only treat a nonzero accEndIDPSStatus as fatal if we never got past auth.
        if has("ei_mode") or has("mfi_status_acked"):
            if has("dp_kick_sent"):
                return ("STEP C: full init + app announce + we drove HNiAPAuth (sent SessionStart + "
                        "AuthRequest DataParts frames) but the head unit sent NO 0xB1 back. Most likely "
                        "the iPodDataTransfer wire opcode is wrong: if this was DP1 (0x41), run DP2 which "
                        "sweeps 0x41/0x42/0x40/0x43 in one connection. Check the btmon for any "
                        "ResiPodDataTransfer / reply to our iPodDataTransfer. (Frames+flow are RE-derived, "
                        "references/cr-v/HONDALINK_APP_PROTOCOL.md; the opcode is the last empirical gap.)")
            if has("ea_open_sent"):
                return ("STEP B: full iAP init reached, AND we announced the HondaLink app via "
                        "OpenDataSessionForProtocol. Now read the SCREEN + phase checklist: if the "
                        "'app not installed / App Store' message is GONE, or 'av_inbound_dial' is ticked "
                        "(head unit dialed av1/av2), or a NEW app-launch/OpenDataSession-response command "
                        "appears, the announce WORKED — proceed to the AppMode DataParts handshake "
                        "(0xB1/0xB2/0xB3) on av1/av2. If the message is unchanged, the head unit wants "
                        "more than the session-open (e.g. an app-launch reply, or a different trigger/"
                        "timing) — the namer/log shows what it did after our announce.")
            return ("Post-auth iAP init reached EI mode. If the STALL COMMAND line above shows a command "
                    "we generic-ACKed, that's the next request owed a typed reply (answer it, then re-run). "
                    "If every post-auth command got a TYPED reply and the head unit still stopped, we have "
                    "run the full init to the HondaLink APP-LAUNCH stage (RequestAutoStartApp): the screen "
                    "should show 'app not installed / App Store'. That is the milestone — the next gate is "
                    "the HondaLink app itself (EA/OpenDataSessionForProtocol + AppMode DataParts over "
                    "av1/av2), NOT more iAP init. See references/cr-v/WORKING_SEQUENCE.md + AppMode.md.")
        idps = reached.get("idps_end")
        if idps is not None and idps.get("accEndIDPSStatus") not in (0, None):
            st = idps.get("accEndIDPSStatus")
            return (f"Stalled in IDPS/auth (never reached EI mode); last EndIDPS accEndIDPSStatus=0x{st:02x}. "
                    f"Layer-1 identification/auth did not complete this window.")
        if has("idps_end") or has("mfi_signature"):
            return ("Stalled during IDPS/MFi auth (never reached EI mode). Layer-1 auth did not complete.")
        return "Stalled early in IDPS — head unit did not finish identification."


# Extended-Interface NowPlaying Get -> (Return opcode, empty/stopped data) — confirmed by Ghidra RE of
# NEventWatcher's ADCL senders + response parsers (ROUND 26, memory + IDPS_STATE_MAP.md):
#   0x1c GetPlayStatus -> 0x1d ReturnPlayStatus  [uint32 trackLen][uint32 trackPos][uint8 state] (9B);
#        state 0x00 = stopped (AplReceiveReturnPlayStatus FUN_002615ec parses exactly 4+4+1 bytes).
#   0x2c GetShuffle    -> 0x2d ReturnShuffle  [uint8 mode]  (0x00 = off)
#   0x2f GetRepeat     -> 0x30 ReturnRepeat   [uint8 mode]  (0x00 = off)
# Wire payload for each = the request's 2-byte transID (echoed) + the data bytes above. Only fires on
# the matching received Get, so entries for Gets the head unit doesn't send are harmless. 0x26
# SetPlayStatusChangeNotification is a Set and keeps the generic EI ACK (iPodAck 0x0001).
EI_GET_RETURNS = {
    0x001c: (0x001d, b"\x00" * 9),   # GetPlayStatus  -> ReturnPlayStatus: stopped, no track
    0x002c: (0x002d, b"\x00"),        # GetShuffle     -> ReturnShuffle: off
    0x002f: (0x0030, b"\x00"),        # GetRepeat      -> ReturnRepeat: off
    # ROUND 27 (appmode/8): answering the NowPlaying Gets pushed the head unit into the SystemInit DB
    # states — it then sends GetNumberCategorizedDBRecords (EI 0x18, arg = a 1-byte category) and
    # stalls on our ACK. State 14/16 (IDPS_STATE_MAP.md) read the returned count and ADVANCE when the
    # running total is 0, so return count=0 (uint32). Fires for both the video and audio DB passes.
    0x0018: (0x0019, struct.pack(">I", 0)),   # GetNumberCategorizedDBRecords -> Return…: count 0
}


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
    # STEP C: once the EA session is open, the head unit's app data (DataParts 0xB1/0xB3) can arrive on
    # any General-Lingo opcode. Scan for it here (opcode-agnostic), gated on ea_opened and excluding the
    # big binary auth packets (0x15 cert / 0x18 signature) so their bytes can't false-positive as frames.
    if (lingo == iap.LINGO_GENERAL and hyp.dataparts_session and harness.ea_opened
            and cmd not in (iap.CMD_RET_DEV_AUTHENTICATION_INFO, iap.CMD_RET_DEV_AUTHENTICATION_SIGNATURE)):
        out.extend(harness.handle_inbound_dataparts(hyp, lingo, cmd, payload))
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
        trans_id = payload[:2] if len(payload) >= 2 else b"\x00\x00"
        # EXPERIMENTAL (Z1): for the DB-records-query EI command, send a typed
        # ReturnNumberCategorizedDBRecords (cmd 0x0019, payload = transID + uint32 count) instead of
        # the generic EI ACK — the head unit needs a record COUNT to advance (IDPS_STATE_MAP.md).
        if hyp.ei_return_dbrecords and cmd == hyp.ei_return_cmd:
            out.append(build_ei_packet(0x0019, trans_id + struct.pack(">I", hyp.ei_return_count)))
            return out
        # ROUND 26: answer the NowPlaying Get burst (0x1c/0x2c/0x2f) with typed empty/stopped Returns
        # so the head unit's EI/NowPlaying sequencer can complete (-> init-complete -> AppMode dial).
        if hyp.ei_nowplaying_returns and cmd in EI_GET_RETURNS:
            ret_cmd, data = EI_GET_RETURNS[cmd]
            out.append(build_ei_packet(ret_cmd, trans_id + data))
            return out
        if hyp.autoack_unknown:
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
        # STEP B: stash the accessory's declared EA protocols (index<->string) so we can later send
        # OpenDataSessionForProtocol with the right index to announce the HondaLink app is present.
        eaps = iap.parse_ea_protocols(fields)
        if eaps:
            harness.ea_protocols = eaps
            harness.log("note", event="ea_protocols_declared", protocols=eaps)
            print("  [ea] head unit declared EA protocols: "
                  + ", ".join(f"{p['protocol']}(idx{p['index']}"
                              + (f",seed={p['bundle_seed_id']}" if p['bundle_seed_id'] else "") + ")"
                              for p in eaps))
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
        # STEP B (trigger="device_info"): the head unit requests iPod name/serial/model/version right
        # as it enters RequestAutoStartApp — the closest wire signal to the app-launch decision. Ride
        # that moment to announce the HondaLink app via OpenDataSessionForProtocol (one-shot).
        if hyp.ea_open_session and hyp.ea_open_trigger == "device_info":
            out.extend(harness.take_ea_open_packets(hyp))
            # STEP C: right after announcing the app, kick the EA session so the head unit's HNiAPAuth
            # starts the DataParts auth (sends us 0xB1). One-shot.
            if hyp.dataparts_session:
                out.extend(harness.take_dp_kick_packets(hyp))
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
    harness.iap_sock = sock          # expose for out-of-band sends (step-B EA open on a timer)
    harness.head_unit_bdaddr = _bdaddr_from_device_path(device)
    conn_t0 = time.time()   # per-connection clock, so the operator can watch step latency live
    harness.conn_t0 = conn_t0
    harness.log("note", event="rfcomm_connected", device=str(device),
                bdaddr=harness.head_unit_bdaddr, local_bdaddr=harness.local_bdaddr)
    print(f"\n[conn] RFCOMM connected from {device} (hypothesis {harness.current.key} armed)")
    harness.mark_phase("rfcomm_iap", remote_bdaddr=harness.head_unit_bdaddr,
                       local_bdaddr=harness.local_bdaddr)
    rx_buf = bytearray()
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
        harness.iap_sock = None
        # If the head unit tore the connection down while stalled (never dialed av1/av2), name the
        # stall command now — the teardown IS the stall on this head unit (it retries the whole
        # connection). Fires only if the silence watchdog hasn't already reported.
        if (harness.has_phase("mfi_status_acked") or harness.has_phase("ei_mode")) \
                and not harness.has_phase("av_inbound_dial"):
            harness._report_stall(harness.window_id)
        harness.cancel_silence_watchdog()
        harness.log("note", event="rfcomm_closed", device=str(device))
        print(f"[conn] RFCOMM session with {device} ended")
        sock.close()


def _av_dial_watchdog(harness, window_at_arm):
    """Fires STALL_AWAIT_AV_S after EI mode. If the head unit still hasn't dialed av1/av2, log a loud
    marker — that is the wire-level fingerprint of a NotifyStartSmartPhoneApps guard failing."""
    if harness.window_id != window_at_arm:
        return   # a new window was armed meanwhile; stale timer
    if harness.has_phase("av_inbound_dial"):
        return
    dt = round(time.time() - harness.conn_t0, 3) if harness.conn_t0 else None
    harness.log("phase", phase="stalled_awaiting_av_dial", t_since_connect=dt,
                waited_s=STALL_AWAIT_AV_S)
    print(f"  [PHASE] stalled_awaiting_av_dial — {STALL_AWAIT_AV_S:.0f}s after EI mode the head unit "
          f"still has NOT dialed av1/av2 => NotifyStartSmartPhoneApps guard failing (m_pAuthInfo/BDaddr)")


def _track_rx_phase(harness, lingo, cmd, payload):
    """Map an inbound iAP packet to a milestone in PHASE_CHAIN (see the block above class Harness)."""
    if lingo == iap.LINGO_GENERAL:
        if cmd == iap.CMD_START_IDPS:
            harness.mark_phase("idps_start")
        elif cmd == iap.CMD_SET_FID_TOKEN_VALUES:
            harness.mark_phase("fid_tokens")
        elif cmd == iap.CMD_END_IDPS:
            # last payload byte is accEndIDPSStatus (0x00=ok, 0x01=fail/reset per round-2 analysis)
            status = payload[-1] if payload else None
            harness.mark_phase("idps_end", accEndIDPSStatus=status)
            if status not in (0, None):
                harness.mark_phase("idps_fail", accEndIDPSStatus=status)
                print(f"  [PHASE] idps_fail — head unit ended IDPS with accEndIDPSStatus=0x{status:02x} "
                      f"(it did NOT accept our FID-token phase; AppMode won't activate)")
        elif cmd == iap.CMD_RET_DEV_AUTHENTICATION_INFO:      # 0x15
            if harness.has_phase("mfi_status_acked"):
                # head unit re-opened auth AFTER we already acked status -> it rejected the auth.
                if harness.mark_phase("mfi_auth_reloop"):
                    print("  [PHASE] mfi_auth_reloop — head unit RE-SENT 0x15 after our 0x19 "
                          "(Layer-1 MFi auth NOT accepted -> m_pAuthInfo stays NULL)")
            else:
                harness.mark_phase("mfi_auth_info")
        elif cmd == iap.CMD_RET_DEV_AUTHENTICATION_SIGNATURE:  # 0x18
            harness.mark_phase("mfi_signature")
        elif cmd == CMD_ENTER_EI:                              # 0x05
            if harness.mark_phase("ei_mode", via="cmd_0x05"):
                _on_ei_mode(harness)
    elif lingo == iap.LINGO_EXTENDED_INTERFACE:
        # any Extended-Interface (lingo 0x04) packet also proves the head unit is in EI mode
        if harness.mark_phase("ei_mode", via="lingo_0x04"):
            _on_ei_mode(harness)


def _on_ei_mode(harness):
    """First entry into Extended-Interface mode: arm the av-dial watchdog and, for a hypothesis using
    the 'ei_mode' EA trigger, schedule the OpenDataSessionForProtocol announce."""
    threading.Timer(STALL_AWAIT_AV_S, _av_dial_watchdog,
                    args=(harness, harness.window_id)).start()
    hyp = harness.current
    if hyp.ea_open_session and hyp.ea_open_trigger == "ei_mode":
        threading.Timer(hyp.ea_open_delay, send_ea_open, args=(harness, hyp)).start()


def _classify_reply(replies):
    """Classify how we answered a received command: 'generic_ack' (General ACK 0x02 or EI ACK
    0x0001 only), 'typed' (a real data response), or 'no_reply'. Used by the stall-command namer to
    flag which post-auth commands got only a blanket ACK (the ones the head unit stalls on)."""
    if not replies:
        return "no_reply"

    def is_generic(pkt):
        b = pkt[2:] if pkt[:2] == iap.SYNC else (pkt[1:] if pkt[:1] == iap.SYNC_SHORT else pkt)
        if len(b) < 3:
            return False
        lingo = b[1]
        if lingo == iap.LINGO_GENERAL:
            return b[2] == iap.CMD_ACK
        if lingo == iap.LINGO_EXTENDED_INTERFACE:
            return len(b) >= 4 and b[2] == 0x00 and b[3] == 0x01   # EI ACK cmd 0x0001
        return False

    return "generic_ack" if all(is_generic(p) for p in replies) else "typed"


def _format_stall_report(cmds):
    """Human-readable report naming the command the head unit is stalled waiting on a typed response
    for. Printed live (silence watchdog) and mirrored to the txt log."""
    lines = ["", "=" * 74,
             ">>> STALL-COMMAND NAMER — head unit went silent after auth.",
             "    The head unit drives a post-auth iAP/EI setup (see references/cr-v/IDPS_STATE_MAP.md).",
             "    Below is every post-auth command and how we answered it; the LAST one before silence",
             "    is the stall point. If we already sent it a TYPED response and it still stalled, the",
             "    block is downstream (av1/av2 dial / AppMode), not that command.", ""]
    if not cmds:
        lines.append("    (no post-auth commands recorded — the stall is before SystemInit; the head")
        lines.append("     unit went silent during IDPS/MFi auth, not in the SystemInit sequence.)")
    else:
        lines.append("    Post-auth commands, in order, and how we answered each:")
        for i, c in enumerate(cmds):
            flag = "  <-- generic ACK" if c["reply"] == "generic_ack" else ""
            lines.append(f"      #{i} +{c['t']}s  lingo=0x{c['lingo']:02x} cmd=0x{c['cmd']:04x} "
                         f"payload={c['payload']}  -> {c['reply']}{flag}")
        # The stall is at the LAST command before silence, regardless of how we answered it.
        stall = cmds[-1]
        lines += ["",
                  f"    >>> LAST COMMAND BEFORE SILENCE: lingo=0x{stall['lingo']:02x} "
                  f"cmd=0x{stall['cmd']:04x} payload={stall['payload']}  (we answered: {stall['reply']})"]
        if stall["reply"] == "typed":
            # ROUND 21 learning: a typed reply here that STILL stalls means this command is NOT the
            # gate — the head unit fires its EI setup burst and stops regardless of our reply type.
            lines += ["    We sent a TYPED response to this command and it STILL stalled at the same",
                      "    point. => this command is NOT the gate; the head unit isn't waiting on a typed",
                      "    reply to it. The block is DOWNSTREAM of iAP/EI setup — the av1/av2 dial /",
                      "    AppMode layer (NotifyStartSmartPhoneApps guard: m_pAuthInfo / BDaddr). Stop",
                      "    climbing the typed-response ladder; investigate the AV-dial gate instead."]
        else:
            lines += ["    We answered it with a generic ACK. IF the head unit is waiting on a typed",
                      "    response here it won't advance — but first confirm it isn't fire-and-forget:",
                      "    if a whole EI burst arrived in <1s and then silence, the stall is likely",
                      "    DOWNSTREAM (av1/av2 dial), not this command (see IDPS_STATE_MAP.md / ROUND 21)."]
    lines.append("=" * 74)
    return "\n".join(lines)


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
            _track_rx_phase(harness, lingo, cmd, payload)
            replies = list(respond_to_packet(harness, hyp, lingo, cmd, payload))
            for pkt in replies:
                sock.send(pkt)
                harness.log("tx", raw=pkt.hex(),
                            note=f"reply under {hyp.key}/{hyp.start_idps}/{hyp.sync}")
                print(f"  [tx  ] {pkt.hex()}")
                if iap.INTER_PACKET_DELAY_S:
                    time.sleep(iap.INTER_PACKET_DELAY_S)
            # stall-command namer: record this command + how we answered it, then (re)arm the silence
            # watchdog. Done BEFORE marking mfi_status_acked so the 0x18 auth packet itself is not
            # counted as a SystemInit command (the gate in record_postauth keys off that mark).
            harness.record_postauth(lingo, cmd, payload, _classify_reply(replies))
            harness.arm_silence_watchdog()
            # We reply 0x19 (AckDevAuthStatus) to every 0x18 under init_auth — that is our side of
            # Layer-1 MFi auth completing. Mark it AFTER the reply is actually on the wire.
            if lingo == iap.LINGO_GENERAL and cmd == iap.CMD_RET_DEV_AUTHENTICATION_SIGNATURE \
                    and hyp.init_auth:
                harness.mark_phase("mfi_status_acked")
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
        if hyp.ea_open_session:
            print(f"                  ea_open_session=ON  protocols={hyp.ea_open_protocols}  "
                  f"trigger={hyp.ea_open_trigger}")
        if hyp.dataparts_session:
            ops = (", ".join(f"0x{o:02x}" for o in hyp.dp_opcode_sweep)
                   if hyp.dp_opcode_sweep else f"0x{hyp.dp_ipod_transfer_cmd:02x}")
            print(f"                  dataparts_session=ON  HNiAPAuth handshake  "
                  f"ipod_xfer_opcode(s)={ops}  auto_b2={hyp.dp_auto_b2}")
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
                    defer_challenge=hyp.defer_challenge, autoack_unknown=hyp.autoack_unknown,
                    ea_open_session=hyp.ea_open_session, ea_open_protocols=list(hyp.ea_open_protocols),
                    ea_open_trigger=hyp.ea_open_trigger)
        print(f"\n  >>> ARMED ({hyp.key}). Now LAUNCH HondaLink on the head unit and watch it.")
        print("      (If it's already open, back out and re-enter the HondaLink source to force a")
        print("       fresh connection.) Live rx/tx traffic prints below as it happens.")
        _ask("\n  When the head unit has settled (launched / errored / gone idle), press Enter: ")

        # summarize what was seen this window
        with harness.lock:
            seen = dict(harness.rx_counts)
        seen_str = ", ".join(f"0x{c:02x}×{n}" for c, n in sorted(seen.items())) or "(none)"
        print(f"\n  Commands received this window: {seen_str}")

        # connection-phase checklist + interpretation — the diagnostic that pins the failing guard
        checklist, interp = harness.phase_summary()
        print("\n  Connection-phase reached this window:")
        print(checklist)
        print(f"\n  >>> DIAGNOSIS: {interp}")
        harness.log("result", event="phase_summary",
                    phases_reached=[k for k, _ in PHASE_CHAIN if harness.has_phase(k)],
                    interpretation=interp,
                    local_bdaddr=harness.local_bdaddr, remote_bdaddr=harness.head_unit_bdaddr)
        harness.note_txt(f"[{hyp.key}] phases: "
                         f"{','.join(k for k, _ in PHASE_CHAIN if harness.has_phase(k)) or 'none'}"
                         f"  local_bd={harness.local_bdaddr} remote_bd={harness.head_unit_bdaddr}")
        harness.note_txt(f"[{hyp.key}] DIAGNOSIS: {interp}")

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
        if f.pack_id == 0xB1 and direction == "rx":
            harness.mark_phase("dataparts_b1", channel=tag, payload=f.payload.hex())


def _av_spp_send(harness, sock, tag, frame, label):
    """Send one raw DataParts frame on an SPP socket, logging it."""
    try:
        sock.sendall(frame)
    except OSError as e:
        harness.log("note", event="av_spp_send_failed", channel=tag, error=str(e))
        print(f"[av-out {tag}] send {label} FAILED: {e}")
        return False
    harness.log("tx", note="av_spp", channel=tag, raw=frame.hex(), label=label)
    print(f"  [av-out {tag} tx] {label}: {frame.hex()}")
    return True


def _av_out_session(harness, bdaddr, tag, channel):
    """Dial OUT to the head unit's AV/data SPP (RFCOMM server channel). ROUND 36: hondalink/3 showed the
    head unit ACCEPTS this dial but DISC's ~1.2s later when we send nothing — it waits for the phone's
    first AppMode DataParts frame here (the app auth is over SPP, not the iAP EA session; AppMode.md §8).
    So, if the active hypothesis sets av_spp_handshake, push SessionStart + AuthRequest right after
    connect and answer a 0xB1 StartAuth with a best-effort 0xB2 on THIS socket."""
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

    hyp = harness.current
    do_handshake = (appmode is not None and hyp is not None
                    and getattr(hyp, "av_spp_handshake", False)
                    and tag in getattr(hyp, "av_spp_channels", ()))
    b2_sent = False
    if do_handshake:
        # The two plaintext control frames the head unit's HNiAPAuth waits for (HONDALINK_APP_PROTOCOL.md):
        # Session Start (id 0x00 / payload [01 01]) then Auth Request (id 0x00 / payload [00]).
        session_start = appmode.build_frame(0x00, bytes([0x01, 0x01]))
        auth_request = appmode.build_frame(0x00, bytes([0x00]))
        harness.log("note", event="av_spp_handshake", channel=tag,
                    session_start=session_start.hex(), auth_request=auth_request.hex())
        print(f"[av-out {tag}] driving AppMode handshake over SPP (SessionStart + AuthRequest)")
        _av_spp_send(harness, sock, tag, session_start, "SessionStart")
        _av_spp_send(harness, sock, tag, auth_request, "AuthRequest")

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
            # Answer a 0xB1 StartAuth with a best-effort 0xB2 on THIS SPP socket (the correct transport).
            if do_handshake and not b2_sent and appmode is not None:
                for f in appmode.parse_frames(chunk):
                    if f.pack_id == 0xB1:
                        frame = harness._build_b2_frame(f.payload, source=f"spp:{tag}")
                        if frame is not None and _av_spp_send(harness, sock, tag, frame, "0xB2 AuthResponse"):
                            b2_sent = True
                        break
    finally:
        harness.log("note", event="av_out_closed", channel=tag)
        print(f"[av-out {tag}] closed")
        sock.close()


def send_ea_open(harness, hyp):
    """STEP B: send the OpenDataSessionForProtocol packet(s) for this hypothesis over the live iAP
    socket (used by the 'ei_mode' trigger's timer; the 'device_info' trigger appends them inline in
    respond_to_packet instead). One-shot via take_ea_open_packets' guard."""
    pkts = harness.take_ea_open_packets(hyp)
    sock = harness.iap_sock
    if not pkts or sock is None:
        return
    for pkt in pkts:
        try:
            sock.send(pkt)
        except OSError as e:
            harness.log("note", event="ea_open_send_failed", error=str(e))
            return
        harness.log("tx", raw=pkt.hex(), note=f"ea_open under {hyp.key}")
        print(f"  [tx  ] {pkt.hex()}  (OpenDataSessionForProtocol)")


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
    harness.mark_phase("av_inbound_dial", channel=tag, device=str(device))
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

    # Record this adapter's BD address up front. The head unit's NotifyStartSmartPhoneApps bails on
    # GetBDAddress ALL 0 / "IAP_BT BDAdder Not match"; having our address in the log lets us check it
    # against the device the head unit paired with when the AV dial never happens.
    harness.local_bdaddr = _read_local_bdaddr(0)
    harness.log("note", event="startup", local_bdaddr=harness.local_bdaddr)
    print(f"[btsdp-guided] local adapter BD address: {harness.local_bdaddr or '(unknown)'}")

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
        av_opts = {
            "Name": f"9CarPlay AV data ({tag})",
            "RequireAuthentication": dbus.Boolean(False),
            "RequireAuthorization": dbus.Boolean(False),
            # AutoConnect=False (CHANGE 2): keep HOSTING av1/av2 (accept an inbound connect from the
            # head unit) but do NOT let BlueZ auto-dial at discovery — that fired during the pairing
            # sweep and the head unit DISC'd it (references/guided/btmon/av_capture). The controlled
            # outbound dial now happens post-EI via connect_head_unit_av().
            "AutoConnect": dbus.Boolean(False),
            "Channel": dbus.UInt16(chan),
        }
        # CHANGE 3: publish a complete SDP record carrying the 0x0006/0x0009 attributes the head unit
        # requests (BlueZ's default record omits them).
        if COMPLETE_AV_SDP:
            av_opts["ServiceRecord"] = build_av_service_record(
                uuid_str, chan, f"9CarPlay AV data ({tag})")
        manager.RegisterProfile(path, uuid_str, av_opts)
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
