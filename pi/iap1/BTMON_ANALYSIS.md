# Bluetooth HCI trace analysis — does the head unit search for the iAP-over-BT service?

This is the recommended next step before building a Bluetooth RFCOMM/SDP server for the legacy
iAP1 path — see `references/cr-v/iap.md`, "A real iAP-over-Bluetooth transport exists" for the full
decompiled evidence this test is designed to check empirically. Short version: `Communication.exe`
hardcodes and actively uses Apple's real, public iAP-over-Bluetooth SDP service UUID
(`00000000-DECA-FADE-DECA-DEAFDECACAFF`) via a dedicated `LPALM_IApBtLink` class, but it's unknown
whether the head unit actually performs an SDP search for it in practice, or whether that code path
is unreachable/unused on this specific build. A Bluetooth HCI capture during a live pairing +
`setup_bt_phone.sh`/`hfp_ag.py` trial settles this the same way live wire captures already settled
the CDC-NCM bearer question (`pi/mirrorlink-ncm/README.md`) and the DAP gate question
(`references/cr-v/PROTOCOL_ANALYSIS.md`, "Live DAP wire capture") — with real evidence instead of
static-analysis inference.

**Do this before investing in an RFCOMM server implementation.** If the head unit never searches
for this UUID, that whole implementation would be wasted effort; if it does, the capture also tells
you the exact protocol/data element sequence to reply with.

## What you're capturing, and why `btmon`

`btmon` (part of the `bluez` package, already required by `pi/bluetooth-test/`) reads from the
kernel's Bluetooth monitor interface and can show every HCI event, L2CAP packet, and — critically —
decoded SDP (Service Discovery Protocol) PDUs in human-readable form, including the UUIDs being
searched for. This is the right tool here because the question is specifically "does the head unit
ask the Bluetooth stack to look up this UUID," which is an SDP-layer event, not something that
shows up in `bluetoothctl`'s own output or in `hfp_ag.py`'s AT-command log.

## Prerequisites

- `bluez` installed (`sudo apt install -y bluez bluez-tools` — same requirement as
  `pi/bluetooth-test/`).
- Root access (`btmon` reads a privileged kernel interface).
- `setup_bt_phone.sh` already run at least once this boot (see `pi/iap1/README.md` Quickstart step
  2) — you want the adapter already in phone-class, discoverable/pairable state before capturing.
- Optional but recommended: a way to get the capture file off the Pi afterward for closer analysis
  in Wireshark (`scp`, a mounted USB drive, etc.) — Wireshark's SDP/RFCOMM dissectors are much more
  pleasant to browse than raw `btmon` text output, though everything you strictly need is visible
  in the live text output too.

## Procedure

1. **Start the capture first, before anything else Bluetooth-related happens.** This is important
   — if the SDP search happens once, early, right after HFP connects, and you start capturing
   after that point, you'll miss it entirely.
   ```
   cd pi/iap1
   sudo btmon -w btmon_trace.btsnoop
   ```
   This writes a binary btsnoop-format capture (openable later in Wireshark) while also printing
   live human-readable decoded output to the terminal — leave this running in its own shell for
   the entire trial below. (If you only want live text output and don't need the file, plain
   `sudo btmon` with no `-w` also works — but the file is cheap to keep and lets you re-search
   after the fact without re-running the whole trial.)

2. **In a second shell, if not already running, bring up the phone-class adapter and HFP AG role**
   (see `pi/iap1/README.md` Quickstart step 2 for the full version):
   ```
   sudo ./setup_bt_phone.sh
   sudo python3 ../bluetooth-test/hfp_ag.py
   ```

3. **Pair from the head unit's own Bluetooth "add device" menu** (not from the Pi — see
   `references/cr-v/iap.md`'s note on `AccessoryMacAddress` registration for why this specific
   direction matters). Confirm/enter any passkey via `bluetoothctl` in a third shell if prompted.

4. **Watch for a stable HFP connection** — phone icon, battery/signal indicators on the head unit,
   and a completed Service Level Connection in `hfp_ag.py`'s console (not connect/disconnect
   flapping — see `pi/bluetooth-test/README.md` "Phase A" step 3 if it flaps).

5. **Leave everything connected and idle for at least 30–60 seconds** after HFP stabilizes, in case
   the SDP search happens on a short delay rather than immediately. If you have a way to trigger
   the head unit's HondaLink/phone-app UI source (e.g. it's already wired to the `pi/iap1/`
   USB gadget from a previous trial), do that too during this window — the SDP search might be
   deferred until the user actually navigates to that source rather than firing right after
   pairing.

6. **Stop `btmon`** (Ctrl-C in its shell) once you've given it enough idle time.

## What to look for

In `btmon`'s live output (or by re-reading `btmon_trace.btsnoop` with `bI` afterward), search for:

- **`SDP: Service Search Request`** or **`SDP: Service Search Attribute Request`** packets — these
  are the PDU types a Bluetooth SDP client sends when looking up a specific service. `btmon` prints
  the searched-for UUID(s) inline, formatted as a standard dashed UUID string. You're looking for:
  ```
  00000000-deca-fade-deca-deafdecacaff
  ```
  (case may vary in the printed output — grep case-insensitively, see below).
- If the head unit does a **generic SDP browse** instead of a targeted search (i.e. walks the
  Pi's entire published service list via the `PublicBrowseGroup`/`00001002-...` UUID rather than
  asking for this UUID directly), you won't see the UUID in a *request* — instead look at what
  services **our own adapter advertises in response** (`SDP: Service Search Attribute Response` /
  `Service Attribute Response` from the Pi's own BD address) and whether the head unit follows up
  with an **L2CAP connection request to PSM 0x0003** (the standard RFCOMM PSM) shortly after,
  which would indicate it found something worth connecting to.
- **`L2CAP: Connection Request` / `Connection Response`** with `PSM: 0x0003 (RFCOMM)` shortly after
  any SDP activity — this is the actual channel-open attempt, the strongest positive signal.
- If an RFCOMM channel does open, watch the subsequent data payloads for the byte sequence
  `ff 55` (the iAP1 sync bytes `pi/iap1/iap1_daemon.py` already implements — see
  `references/cr-v/iap.md`, "iAP1 packet framing") — that would confirm classic iAP1 framing is
  actually being spoken over this channel, not just a channel being opened and left idle.

## Quick command-line searches (no Wireshark needed)

Re-play the capture and grep for the UUID and related keywords directly from the terminal:

```
sudo btmon -r btmon_trace.btsnoop | grep -i -A5 -B5 "deca-fade\|deafdecacaff\|Service Search\|PSM: 0x0003\|RFCOMM"
```

`-A5 -B5` grabs surrounding context lines so you can see which device (BD address) and direction
(request/response) each hit belongs to — `btmon` prints a `>` or `<` direction indicator and the
peer address in the header line just above each decoded PDU.

## Analyzing in Wireshark instead (optional, easier for a long/noisy capture)

1. Copy `btmon_trace.btsnoop` off the Pi.
2. Open it directly in Wireshark (it understands the btsnoop format natively — no conversion step
   needed).
3. Useful display filters:
   - `btsdp` — all SDP protocol packets. Expand each `Service Search Request`/`Service Search
     Attribute Request` and check the `UUID` field(s) against
     `00000000-deca-fade-deca-deafdecacaff`.
   - `btrfcomm` — RFCOMM traffic, useful for confirming a channel actually opened and seeing its
     payload bytes (look for `ff 55` — see above).
   - `bthci_evt.code == 0x05` filters to `Disconnection Complete` events, useful for correlating
     "did the channel open and then immediately close" (a poor/rejected connection) vs. staying
     open.

## Reporting back

Whatever you find, report back (or add directly to `references/cr-v/iap.md`'s "A real
iAP-over-Bluetooth transport exists" section, under a new dated update) with:

- Did any `Service Search`/`Service Search Attribute` request for
  `00000000-deca-fade-deca-deafdecacaff` appear at all? If not, was there a generic SDP browse
  instead, and did the Pi's own advertised service list (from whatever BlueZ/`hfp_ag.py`
  advertises by default) get walked?
- Did an L2CAP connection to PSM `0x0003` (RFCOMM) ever occur, from the head unit toward the Pi?
- If a channel opened, what bytes (if any) came through it — specifically, does `ff 55` (iAP1 sync)
  appear?
- Rough timing: did anything happen right after HFP connected, or only after navigating to a
  specific source/UI screen on the head unit (and if so, which one)?

This determines whether `pi/iap1/`'s next milestone is "build an SDP service + RFCOMM server and
feed it into the existing iAP1 packet parser" (confirmed necessary) or "not needed, the HFP
precondition alone was the whole Bluetooth story" (ruled out) — see `references/cr-v/iap.md`'s
"Recommended next step for the Pi" for the implementation this capture is meant to justify (or
rule out) before it gets built.
