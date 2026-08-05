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

2. **Correction from initial testing:** the car-initiated scan never found
   the Pi (BlueZ's discoverable window times out at 180s regardless of
   `btmgmt`/`bluetoothctl` settings, and this head unit's "add device" flow
   may simply expect to be found by the phone rather than finding the phone
   itself). Pairing works the other direction instead — initiate **from the
   Pi**:
   ```
   bluetoothctl
   power on
   agent on
   default-agent
   scan on
   ```
   Put the head unit in its own discoverable/pairing-wait state on its
   screen, then watch for it to appear in the scan output (by name or MAC).
   ```
   scan off
   pair <car-MAC>
   trust <car-MAC>
   connect <car-MAC>
   ```

3. **Known issue at this point:** plain pairing bonds successfully, but
   `connect` cycles `Connected: yes`/`no` repeatedly, sometimes surfacing
   `org.bluez.Error.Failed br-connection-profile-unavailable`, and the Pi
   shows in the car's paired-device list with no phone/music icon. This is
   because the head unit is trying to open a profile session (A2DP and/or
   HFP) that a stock BlueZ install doesn't offer — see step 4.

4. Run `setup_bt_a2dp.sh` (adds A2DP sink support and makes the Class-of-
   Device setting persistent — `btmgmt class` alone doesn't survive
   `bluetoothd` restarts, which is the other reason the icon never showed
   up):
   ```
   sudo ./setup_bt_a2dp.sh
   pulseaudio --start   # as your normal user, not root
   ```
   Then re-pair from scratch (`remove <car-MAC>` first in `bluetoothctl` to
   clear the old flapping bond), and confirm a stable `Connected: yes` and a
   music-note icon on the car's device list before moving on.

5. Once paired, check `bluetoothctl` reports `Paired: yes` and ideally
   `Connected: yes` for the head unit's device entry (`devices` /
   `info <MAC>`). **Keep this Bluetooth session up** — don't disconnect.

6. With BT still connected, start the USB/AOA side exactly as before (see
   `pi/aoa-gadget/README.md` — either `aoa_gadget` or
   `aoa_gadget_twostage`, freshly torn down and restarted) and connect the
   Pi's peripheral USB port to the head unit.

7. Watch the daemon's console. The key question: does a `[setup]` line
   (any `GetProtocol`/`SendString`) appear now, where it never did before?
   Also recheck the head unit's MirrorLink diagnostics menu for any state
   change versus BT-unpaired.

Any change here — even partial — confirms the BT-gating theory and tells us
the gate is "is *some* paired BT device present," not "does this exact USB
device also match via a deeper HFP-level check."

## Phase A result (confirmed negative)

Plain pairing (bond only) and a stable A2DP connection (icon showing, no
more connect/disconnect flapping) both produced **zero change** in AOA
activity — still just `BIND`/`ENABLE` on the USB side, no `[setup]` line,
regardless of Bluetooth state. Also tried manually selecting the head unit's
"HondaLink" (this unit's MirrorLink UI) source with the Pi already on USB —
no change either. This rules out plain pairing/A2DP as the gate; if
Bluetooth is involved at all, it's specifically HFP-level phone recognition,
not just "some paired BT device is present."

## Phase B — Hands-Free Profile Audio Gateway (current)

BlueZ's `bluetoothd` only ships the **HF** (car/headset) role internally —
there is no built-in **AG** (phone) role. That's the likely reason A2DP
alone got a stable connection but never made the Pi look like "a phone" to
whatever `UIMirrorLink_BTManager` (per `strings_out.txt`) checks.

`hfp_ag.py` implements a minimal HFP Audio Gateway: it registers a custom
BlueZ D-Bus profile for the Handsfree Audio Gateway service class
(`0000111f-0000-1000-8000-00805f9b34fb`) and answers just enough AT commands
(`AT+BRSF`, `AT+CIND=?`/`AT+CIND?`, `AT+CMER`, `AT+CHLD=?`, etc.) to
complete a Service Level Connection — not a real telephony stack, just
enough for the head unit's HF client to consider us a phone. It prints every
AT command it receives, which is useful RE data on its own.

1. Install dependencies (one-time):
   ```
   sudo apt install -y python3-dbus python3-gi bluez
   ```

2. Run it (leave running in its own shell — it does not daemonize):
   ```
   sudo python3 hfp_ag.py
   ```
   It registers the profile and waits; it does not replace/stop the normal
   `bluetoothd` — leave that running as-is.

3. In `bluetoothctl`, clear the old bond and re-pair from scratch so the
   car re-discovers our new SDP records:
   ```
   remove <car-MAC>
   scan on
   pair <car-MAC>
   trust <car-MAC>
   connect <car-MAC>
   ```

4. Watch `hfp_ag.py`'s console for the AT command exchange (`<-`/`->`
   lines) — this confirms the car actually opened an HFP session with us,
   and shows exactly what it asks for. Watch the car's screen for a phone
   icon and whether it now treats the Pi as a recognized phone (e.g. shows
   it in a "connected phone" status, not just "paired device").

5. With HFP connected, repeat the USB/AOA test (`pi/aoa-gadget/README.md`,
   fresh teardown/restart) and watch for `[setup]` activity that wasn't
   there before.

If this *still* produces no change on the USB side, that's a strong signal
the BT-gating theory is wrong entirely (not just "wrong profile"), and the
next step should go back to Ghidra RE of the already-extracted
`vncdiscoverer-usb.dll` to find out what actually triggers its `GetProtocol`
probe, rather than continuing to guess from the Bluetooth side.
