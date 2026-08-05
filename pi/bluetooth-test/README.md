# Bluetooth-gating test — does MirrorLink USB discovery require a prior BT pairing?

## Why this exists

Both AOA gadget modes (`aoa_gadget` direct-identity and `aoa_gadget_twostage`'s
real two-stage switch) completed standard USB enumeration against the real
head unit (`BIND`/`ENABLE`) but never received a single AOA discovery request
(`GetProtocol`/`SendString`/`Start`) — see `pi/aoa-gadget/README.md`. That
rules out "wrong identity at enumeration time" as the blocker.

Grepping `references/cr-v/strings_out.txt` turned up two things that point at
Bluetooth as a precondition rather than USB being purely self-contained:

- A dedicated `UIMirrorLink_BTManager.cpp` inside the firmware's MirrorLink UI
  service (`.../MirrorLink/src/UIService/UIMirrorLinkService/`).
- The MirrorLink connection-start request XML format includes a Bluetooth
  device address field:
  ```
  <startConnection>true</startConnection>
  <bdAddr>%0.128s</bdAddr>
  ```

There is no `vncdiscoverer-bluetooth.dll` (only `vncdiscoverer-usb.dll`), so
Bluetooth isn't a second MirrorLink *transport* — it looks like an identity/
pairing precondition the UI service checks before USB discovery is treated as
relevant to MirrorLink at all. This matches real-world MirrorLink phone
behavior: pair over Bluetooth first, then plug in USB to "unlock" the
MirrorLink app/session.

We don't have a MirrorLink-verified phone to confirm this the easy way, so
instead we make the Pi itself the Bluetooth-paired device, using its own
onboard radio — since the correlation is by BD address, and the Pi's BT MAC
and its USB AOA identity are both under our control on the same physical box.

## Phase A — plain BT pairing as a phone-class device (do this first)

Cheap, no extra protocol stack. Just gets *some* paired BT identity in front
of the head unit before the USB/AOA link comes up, and tests whether that
alone changes anything on the USB side.

1. On the Pi:
   ```
   cd pi/bluetooth-test
   sudo ./setup_bt.sh
   ```
   Sets Class of Device to Phone/Smartphone, names the adapter
   `9CarPlay AOA Bridge`, and makes it discoverable + pairable.

2. On the head unit, go to its Bluetooth "add/pair phone" menu and scan —
   the Pi should show up as `9CarPlay AOA Bridge`. Initiate pairing **from
   the car**, not from the Pi (this matches how a real phone pairing flow
   looks from the head unit's side).

3. On the Pi, in a second shell, run `bluetoothctl` to watch for and confirm
   the pairing request:
   ```
   bluetoothctl
   agent on
   default-agent
   ```
   Leave this running. When the head unit prompts for a passkey/confirmation
   on its screen, `bluetoothctl` will print the same passkey here (or a
   `[agent] Confirm passkey ... (yes/no)` prompt) — confirm on both sides.

4. Once paired, check `bluetoothctl` reports `Paired: yes` and ideally
   `Connected: yes` for the head unit's device entry (`devices` /
   `info <MAC>`). **Keep this Bluetooth session up** — don't disconnect.

5. With BT still connected, start the USB/AOA side exactly as before (see
   `pi/aoa-gadget/README.md` — either `aoa_gadget` or
   `aoa_gadget_twostage`, freshly torn down and restarted) and connect the
   Pi's peripheral USB port to the head unit.

6. Watch the daemon's console. The key question: does a `[setup]` line
   (any `GetProtocol`/`SendString`) appear now, where it never did before?
   Also recheck the head unit's MirrorLink diagnostics menu for any state
   change versus BT-unpaired.

Any change here — even partial — confirms the BT-gating theory and tells us
the gate is "is *some* paired BT device present," not "does this exact USB
device also match via a deeper HFP-level check."

## Phase B — if Phase A shows no change: add Hands-Free Profile

Plain BlueZ pairing doesn't include Hands-Free Profile (HFP), which is what
most head units actually use to recognize a paired device as "a phone" (as
opposed to a generic Bluetooth peripheral) — audio/call handling is normally
the gate for the car's phone-pairing wizard to fully accept a device. If the
head unit's `UIMirrorLink_BTManager` checks for HFP capability (via SDP)
before it will correlate a paired device with an incoming USB/AOA session,
Phase A's pairing might complete but still not be treated as a "phone" by
that manager.

This would require:
- Registering an HFP Audio-Gateway SDP record on the Pi (BlueZ supports this
  via its D-Bus profile API — no need for a full working audio path, just
  enough for the head unit's capability query to see HFP-AG advertised).
- Possibly a minimal AT-command responder over the RFCOMM channel the head
  unit opens after pairing, if the head unit actually probes past SDP into a
  live AT handshake before trusting the pairing.

Not implemented yet — only worth building if Phase A comes back negative,
since it's a meaningfully larger effort (likely `ofono` + a custom modem
backend, or a hand-rolled RFCOMM/AT responder). Come back to this file and
update it with what Phase A showed before starting Phase B.
