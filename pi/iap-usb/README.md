# pi/iap-usb — iAP1 over USB-HID (the HondaLink AppMode data bearer)

RE (ROUND 54–55, `references/cr-v/IAP_OVER_USB.md`) proved HondaLink AppMode's data channel is
**iAP1 carried over USB HID**, not Bluetooth. The BT link stays up (HFP + it triggers the BT→USB
switch), and the Pi *additionally* presents an **Apple iAP-USB-HID device** on the head unit's USB
port (where the Pi already sits for power). This directory is that bearer.

## How it fits together

```
head unit (USB host, "iPod_Class" driver)
   │   interrupt-IN reports  ID 1..4   iPod -> HU   (our TX)
   │   SET_REPORT (OUT)      ID 5..9   HU -> iPod   (our RX)
ipod-gadget kernel module  <->  /dev/iap0   (raw HID report bytes)
   │
hid_framing.py     report fragment / reassemble  (LinkControl: Done/Continue/More)
   │
iap_usb_bridge.py  iAP1 packet layer + response policy
   │
../iap1/iap1_daemon.py   TRANSPORT-AGNOSTIC iAP1 packet builders/parsers  (REUSED)
../appmode/appmode_proto.py   AppMode DataParts codec  (REUSED)
```

The iAP1 *packets* (IDPS, MFi-auth-accept, EI, AppMode DataParts) are byte-identical to the BT
path — only the bearer changes. All the fixes from the BT saga (0x3A ACK order, `0x11` →
`RetTransportMaxPayloadSize 0x12`, etc.) carry over unchanged.

## Files

- `hid_framing.py` — Apple iAP-USB-HID link layer (report fragmentation). **Complete + unit-tested**
  (`python3 hid_framing.py`). Report defs match the confirmed descriptor.
- `iap_usb_bridge.py` — opens `/dev/iap0`, does framing + the iAP1 packet layer, reusing
  `iap1_daemon`. **Functionally complete**: the full IDPS/auth/EI/announce/DataParts response policy
  is ported from the locked BT baseline (`../iap1/btsdp_iap_guided.py:respond_to_packet`), verified to
  emit byte-identical replies for the real captured IDPS/auth sequence. Remaining: on-Pi enumeration,
  the empirical unknowns below, and (if needed) the iAP1 large-packet form for big AppMode payloads.
- `setup_ipod_gadget.sh` — build + load the `oandrew/ipod-gadget` kernel module and bind the UDC.

## The USB device (confirmed by RE)

- `idVendor 0x05AC` (Apple), `idProduct 0x1297`, `bcdDevice 0x0310`, `bcdUSB 0x0200`.
- One HID interface (class 3), one interrupt-IN endpoint (64 B, `bInterval 1`); host→device via
  `SET_REPORT` (no OUT endpoint). Apple vendor control request `bRequest 0x40` is ACKed.
- HID report descriptor: vendor usage page `0xFF00`, report size 8 bits;
  INPUT (iPod→HU) IDs 1..4 len {12,14,20,63}; OUTPUT (HU→iPod) IDs 5..9 len {8,10,14,20,63}.
- HID report on the wire: `[ReportID][LinkControl][payload…]` zero-padded to the report's fixed
  length. The HID layer carries no exact length — the iAP1 `0x55 <len>` field trims the padding.

## Dependency: the ipod-gadget kernel module

The USB-device HID layer is `oandrew/ipod-gadget` (a kernel module), not configfs `f_hid` — it
handles the Apple quirks (custom report-descriptor GET_DESCRIPTOR, vendor request 0x40, SET_REPORT
host→device with no OUT endpoint). It must be **built against the Pi's running kernel** (needs kernel
headers). `setup_ipod_gadget.sh` clones + builds + loads it; `/dev/iap0` then read/writes raw HID
reports (report-ID byte included).

## Bring-up procedure

1. Keep the BT connection running (the locked baseline — HFP + switch trigger). See
   `IAP_OVER_USB.md §Appendix`.
2. `sudo ./setup_ipod_gadget.sh` → `/dev/iap0` appears; bind the UDC.
3. `sudo python3 iap_usb_bridge.py`.
4. On the head unit, start HondaLink AppMode. Dump the HU log (`../msd-gadget/read_logs.sh`) and look
   for `GetConnectType iAP over USB` + `SwitchConnect` **success** (no `SwitchConnect Failed` /
   `iAPoverBTConnectError`), and `SetAuthStatus` holding at 2 past the 15 s window.

## Open questions (resolve empirically during bring-up)

- **idProduct**: `0x1297` (from the reference gadget) vs whatever the HU's registry expects — watch
  the HU's `RegistryInfo VendorID/ProductID` lookup / `OnDeviceChangeEvent`.
- **0xFF lead-in**: `iap1_daemon.build_packet` prefixes `0xFF` before `0x55`; the HID bearer starts
  at `0x55`, so the bridge strips it (`STRIP_FF=True`). Confirm against the first HU capture.
- **Report descriptor variant**: active full-speed set {12,14,20,63}/{8,10,14,20,63} vs the
  `LegacyReportDefs` (larger, up to 767 B) — if the HU rejects or fragments oddly, try the legacy set.
- **`EHID` vs `Function`** transport and whether **BT HFP must be actively connected** during the
  switch (`isIPhoneConnected iAP over USB connect HFP`).
- **AppMode big payloads**: whether the HU uses the iAP1 large-packet form (`0x55 0x00 <len16>`) for
  DataParts over USB — `iap_usb_bridge._trim_iap` has a TODO for it.

## Credits

USB/HID descriptors and link framing derived from **oandrew/ipod-gadget** and **oandrew/ipod** (MIT).
