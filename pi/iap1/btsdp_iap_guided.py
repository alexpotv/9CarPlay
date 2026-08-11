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
# Keeping them as declarative flags (rather than full handler overrides) makes the matrix easy to
# read, extend, and reason about — every hypothesis differs only in the handful of decision points
# that the RE above identified as genuinely uncertain:
#
#   start_idps : how we answer the head unit's StartIDPS (cmd 0x38)
#                "accept"  -> General ACK, status 0x00 (success)
#                "reject"  -> General ACK, status 0x04 (bad param) — still status<0x19 so it IS
#                             delivered to the accessory; tests whether an explicit refusal makes
#                             it fall back to the pre-IDPS / NonIDPS path
#                "ignore"  -> send nothing; tests whether the head unit advances on its own (e.g.
#                             times out StartIDPS and drops to the NonIDPS IdentifyDeviceLingoes flow)
#   sync       : outgoing framing — "short" (bare 0x55, what the head unit itself transmits) or
#                "full" (0xFF 0x55). Tests whether the accessory's RX parser is picky about the
#                leading sync byte on OUR replies.
#   run_idps_body : if True, answer SetFIDTokenValues (0x39) and EndIDPS (0x3B) to actually drive
#                   IDPS to completion; if False, only StartIDPS is touched (isolates the very first
#                   step from everything downstream).
#   init_auth  : if True, after IDPS completes, initiate MFi device authentication
#                (GetDevAuthenticationInfo) and carry it through, accepting whatever the accessory
#                returns. If False, we stay silent after IDPS and watch what the head unit does.
#
# The ORDER below is deliberate: start from "do exactly what the corrected spec model says"
# (H1) and fan out one variable at a time, so a difference in outcome isolates one cause.

class Hypothesis:
    def __init__(self, key, title, rationale, positive_signal,
                 start_idps="accept", sync="short", run_idps_body=True, init_auth=True):
        self.key = key
        self.title = title
        self.rationale = rationale
        self.positive_signal = positive_signal
        self.start_idps = start_idps
        self.sync = sync
        self.run_idps_body = run_idps_body
        self.init_auth = init_auth


HYPOTHESES = [
    Hypothesis(
        "H1", "Baseline: accept StartIDPS + full IDPS + MFi auth (short sync)",
        "The corrected-spec path. With the ACK-drop theory refuted, a status-0x00 ACK to StartIDPS "
        "should be delivered, so IDPS should now proceed past the retry loop. This is the current "
        "iap1_daemon.py behavior and has NOT actually been trial-tested since the rewrite — so the "
        "first job is simply to see whether it already works.",
        "StartIDPS stops repeating; SetFIDTokenValues (cmd 0x39) and/or EndIDPS (0x3B) arrive; "
        "ideally the head unit stops looping and moves toward launching.",
        start_idps="accept", sync="short", run_idps_body=True, init_auth=True),

    Hypothesis(
        "H2", "Accept StartIDPS but do NOT start MFi auth",
        "Isolates IDPS from authentication. If IDPS completes here (SetFIDTokenValues + EndIDPS "
        "seen) but H1 stalled, the problem is in our auth handling, not IDPS. If the head unit "
        "launches WITHOUT us ever authenticating, then MFi device-auth isn't gating this path at all.",
        "SetFIDTokenValues + EndIDPS arrive and the head unit progresses even though we never send "
        "GetDevAuthenticationInfo.",
        start_idps="accept", sync="short", run_idps_body=True, init_auth=False),

    Hypothesis(
        "H3", "Accept StartIDPS with FULL 0xFF 0x55 sync framing",
        "Framing-sensitivity test. The head unit transmits bare-0x55 frames; we normally reply the "
        "same way. If its RX parser actually wants the canonical 0xFF 0x55 on inbound frames, our "
        "short-sync replies would be silently dropped and StartIDPS would loop regardless of "
        "content — which would look exactly like the observed failure.",
        "Behavior differs from H1 — e.g. the StartIDPS loop stops only here — implicating outbound "
        "framing as the real issue.",
        start_idps="accept", sync="full", run_idps_body=True, init_auth=True),

    Hypothesis(
        "H4", "Explicitly REJECT StartIDPS (ACK status 0x04)",
        "Tests the NonIDPS fallback. The firmware has a `[ADCLS] NonIDPS` path. A delivered refusal "
        "(status 0x04 is < 0x19, so it reaches the accessory) may make the head unit abandon IDPS "
        "and drop to the older IdentifyDeviceLingoes / NonIDPS identification flow.",
        "Head unit stops sending StartIDPS and instead sends IdentifyDeviceLingoes (cmd 0x13) or "
        "GetAccessoryInfo (0x27) — i.e. it switched paths.",
        start_idps="reject", sync="short", run_idps_body=False, init_auth=False),

    Hypothesis(
        "H5", "IGNORE StartIDPS entirely (never reply to 0x38)",
        "Tests whether the head unit advances on its own after StartIDPS times out, without any "
        "reply from us at all. Distinguishes 'it needs a specific answer' from 'it needs us to stay "
        "quiet and will fall through by timeout'.",
        "After several unanswered StartIDPS, a DIFFERENT command appears (IdentifyDeviceLingoes, "
        "GetAccessoryInfo, or an auth command) — i.e. it fell through by timeout.",
        start_idps="ignore", sync="short", run_idps_body=False, init_auth=False),
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

    # ---- Identification-time discovery queries (answered for every hypothesis, so the head unit
    # can finish identifying us regardless of the StartIDPS policy under test) ----
    if cmd == iap.CMD_GET_IPOD_OPTIONS_FOR_LINGO:
        out.append(iap.build_ret_ipod_options_for_lingo(payload[-1]))
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
        # Reserved/undocumented probe the head unit sends once after StartIDPS. Mirror the
        # production daemon: honest "unknown ID" ACK (status 0x05, < 0x19 so delivered).
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
            _drain(harness, sock, rx_buf)
    finally:
        harness.connected = False
        harness.log("note", event="rfcomm_closed", device=str(device))
        print(f"[conn] RFCOMM session with {device} ended")
        sock.close()


def _drain(harness, sock, rx_buf):
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
            harness.log("rx", lingo=lingo, cmd=cmd, payload=payload.hex(), raw=raw.hex(),
                        cmd_seen_in_window=n)
            print(f"  [rx#{n}] lingo=0x{lingo:02x} cmd=0x{cmd:02x} payload={payload.hex()}")
            for pkt in respond_to_packet(harness, hyp, lingo, cmd, payload):
                sock.send(pkt)
                harness.log("tx", raw=pkt.hex(),
                            note=f"reply under {hyp.key}/{hyp.start_idps}/{hyp.sync}")
                print(f"  [tx  ] {pkt.hex()}")
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
                    run_idps_body=hyp.run_idps_body, init_auth=hyp.init_auth)
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
