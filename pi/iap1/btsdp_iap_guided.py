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
# ROUND 1 TIMING (run 20260811_113447) — the dominant round-2 lead. OUR side replied instantly
# (every TX shares its RX's timestamp), but the head unit stalled ~18s between consecutive
# GetiPodOptionsForLingo (0x4b) queries — ~3x its ~6s StartIDPS retry unit — i.e. it timed out
# waiting for a reply to each option query it never accepted, then moved to the next lingo. Six
# queried lingoes x ~18s ≈ 100s of pure stall, which blows the head unit's app-launch deadline
# (Communication.exe: ALApp_LaunchLimitTimer / ALApp_WaitAppStartTimer) -> "Loading..." flips to
# "Cannot launch app" while traffic is still flowing. So the deadline is the SYMPTOM; the root
# cause is that our 0x4c option replies aren't accepted. Prime suspect: the 0x4b request carries a
# 2-byte transID prefix ([transIdHi, transIdLo, lingoId]) but our 0x4c reply doesn't echo it, so it
# never correlates. `echo_transid` puts that transID back on the front of the 0x4c reply.
# ---------------------------------------------------------------------------------------------


class Hypothesis:
    def __init__(self, key, title, rationale, positive_signal,
                 start_idps="accept", sync="short", run_idps_body=True, init_auth=True,
                 opt11_mode="unknown_id", general_options=GENERAL_APP_BIT, other_lingo_options=0,
                 echo_transid=False):
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


# Round-2 keeps the settled base (accept StartIDPS, short sync, run IDPS body) constant so every row
# reaches the options step, and hunts the ~18s-per-step timeout. THE ORACLE IS NOW TIMING as much as
# content: if a change is right, the ~18s gaps between 0x4b queries collapse to well under a second
# (like the head unit's own fast initial packets), IDPS completes, and EndIDPS comes back
# accEndIDPSStatus=0x00 / a new command class appears (0x39, a GetIPodInfo request, auth 0x14+).
# The console prints each RX's seconds-since-connect so this is visible live.
HYPOTHESES = [
    Hypothesis(
        "R1", "Control: reproduce the round-1 ~18s-stall / IDPS-options failure",
        "Exactly the round-1 baseline (0x4c reply without transID echo, 0x11 -> unknown_id, General "
        "options 0x2000). Confirms the ~18s inter-query stalls and EndIDPS=0x01 still reproduce "
        "before changing anything, as a control on the same session.",
        "~18s gaps between 0x4b queries; EndIDPS accEndIDPSStatus=0x01 — same as round 1.",
        echo_transid=False, opt11_mode="unknown_id", general_options=GENERAL_APP_BIT),

    Hypothesis(
        "R2", "Echo the 2-byte transID in the 0x4c GetiPodOptionsForLingo reply",
        "THE primary lead. The head unit prefixes a transID on its 0x4b query but our reply omits "
        "it, so it likely can't correlate the response and times out ~18s each time. Echoing the "
        "transID back should make each query resolve instantly and let IDPS finish inside the "
        "launch deadline.",
        "The ~18s gaps vanish (queries now <1s apart) AND EndIDPS flips to accEndIDPSStatus=0x00 / "
        "the head unit proceeds past IDPS.",
        echo_transid=True, opt11_mode="unknown_id", general_options=GENERAL_APP_BIT),

    Hypothesis(
        "R3", "transID echo + answer cmd 0x11 with ACK success",
        "If R2 speeds things up but IDPS still doesn't complete, add the next-likeliest fix: stop "
        "telling the head unit 'unknown id' for its iPod-options request (0x11) and ACK it success.",
        "IDPS completes (EndIDPS=0x00 / new command class) on top of R2's timing fix.",
        echo_transid=True, opt11_mode="ack_success", general_options=GENERAL_APP_BIT),

    Hypothesis(
        "R4", "transID echo + RetiPodOptions data reply to 0x11 (cmd 0x12, SPECULATIVE)",
        "Like R3 but answers 0x11 with a real options reply (cmd 0x12, guessed pairing, echoing "
        "transID + options) instead of an ACK — the firmware receives a 'RetiPodOutOption', hinting "
        "0x11 wants data, not an ACK. Command id/shape are a guess; compare against R3.",
        "IDPS completes where R3 didn't — implicating 0x11 wanting a data reply.",
        echo_transid=True, opt11_mode="ret_options", general_options=GENERAL_APP_BIT),

    Hypothesis(
        "R5", "transID echo + 0x11 ACK + claim every queried lingo",
        "Stacks the remaining plausible fixes on top of the timing fix: ACK 0x11 and report a "
        "non-zero option set for the non-General lingoes the head unit specifically asks about "
        "(0x02/0x03/0x04/0x0c/0x0e), in case it requires the iPod to claim support for them.",
        "IDPS completes — then peel back which piece mattered.",
        echo_transid=True, opt11_mode="ack_success", general_options=GENERAL_APP_BIT,
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
        return out

    if hyp.run_idps_body and cmd == iap.CMD_END_IDPS:
        trans_id = (payload[0] << 8) | payload[1]
        acc_status = payload[2] if len(payload) > 2 else 0
        out.append(iap.build_idps_status(trans_id, 0x00 if acc_status == 0 else 0x04))
        if acc_status == 0 and hyp.init_auth:
            out.append(iap.build_get_dev_authentication_info())
        return out

    # ---- MFi device authentication (accessory proves itself to us; we accept unconditionally) ----
    if hyp.init_auth and cmd == iap.CMD_RET_DEV_AUTHENTICATION_INFO:
        major = payload[0] if payload else 1
        if major == 0x02:
            cur_section, max_section = payload[2], payload[3]
            if cur_section < max_section:
                out.append(iap.build_ack(0x00, iap.CMD_RET_DEV_AUTHENTICATION_INFO))
                return out
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
                    other_lingo_options=hyp.other_lingo_options, echo_transid=hyp.echo_transid)
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
