"""Identity + app-manifest data for the iAP1 HondaLink test scaffold.

This is plain data, kept separate from iap1_daemon.py's protocol-framing logic so the values
below can be edited/iterated on without touching the wire-format code. See references/cr-v/iap.md
("Resolved: the app whitelist gate") for the RE evidence behind each field's meaning.

PHONE_IDENTITY maps to the six fields Communication.exe's `IsAuthInfoAllExist`
(FUN_000d1dbc) checks for *presence* (never content — see iap.md, no comparison logic was found
anywhere in that path):
  - manufacturer / model  -> length-checked string fields ("ManufactureName"/"ModelName" Non)
  - os_version            -> non-zero short ("OSVer Non")
  - individual_info       -> non-zero int ("IndividualInfo Non") — likely a device serial/UDID-
                              shaped value; exact required shape unconfirmed, only non-zero-ness is
  - app_id / app_version  -> app_id non-zero, AND (app_id == 0xff OR app_version non-zero)
                              ("AppVer Non") — 0xff is a special sentinel that skips the AppVer
                              requirement entirely (see iap.md for the decompiled branch)

None of these are validated against a reference/whitelist value anywhere in the traced code — only
presence. Values below are deliberately plausible-but-arbitrary placeholders, not attempts to
mimic a specific real device.
"""

PHONE_IDENTITY = {
    "manufacturer": "Apple Inc.",
    "model": "iPhone5,2",          # plausible 2013-era iPhone model identifier
    "os_version": 0x0701,           # encoded as a 16-bit short; placeholder ~"iOS 7.1"-shaped
    "individual_info": 0x1234ABCD,  # placeholder non-zero "serial"; real shape unconfirmed
    "app_id": 0xFF,                 # sentinel value — per IsAuthInfoAllExist, skips AppVer check
    "app_version": 0,               # unused while app_id == 0xFF, kept for when it's needed
}

# General Lingo (Lingo 0x00) identify-family fields — see iap1_daemon.py's LINGO_GENERAL handler
# table. These are the fields we DO know the wire encoding for (from the public, pre-MFi-era iPod
# Accessory Protocol documentation used throughout iap1_daemon.py), used to answer
# RequestiPodName/RequestiPodSoftwareVersion/RequestiPodSerialNum/RequestiPodModelNum. Kept
# consistent with PHONE_IDENTITY above but expressed as the strings those specific replies need.
GENERAL_LINGO_IDENTITY = {
    "ipod_name": "iPhone",
    "software_version": (7, 1, 0),   # (major, minor, revision) — matches os_version above
    "serial_number": "C39XXXXXXXXX",  # placeholder, shaped like a real Apple serial (not genuine)
    "model_number": "MD654LL",       # placeholder iPhone 5c-shaped model number
    "lingo_protocol_version": (1, 0),
}

# SetServerVRAppData(ProtocolName, BundleId, URL, AppID) — see PROTOCOL_ANALYSIS.md and iap.md.
# NOT the general app-launch/session mechanism this was originally assumed to be. Decompiling
# IPILib.dll (2026-08-10) found its only relevant strings are all "ServerVR"-prefixed IPC events
# (IPI_CommNotifyPressedServerVRKeyEvent, IPI_EnableServerVREvent, etc.) — "VR" is Voice
# Recognition (Honda's Siri/voice-button integration), not a generic app registry. iap1_daemon.py
# no longer calls anything here; the real app-launch blocker turned out to be the IDPS + MFi
# device-authentication handshake (see iap1_daemon.py's module docstring), which doesn't involve
# SetServerVRAppData at all. Left in place only as a reference for whenever the Siri/VR-button
# integration itself becomes the thing being worked on — not part of the current critical path.
APPS = [
    {
        "protocol_name": "com.honda.hondalink.test",
        "bundle_id": "com.9carplay.iap1test",
        "url": "hondalink-test://launch",
        "app_id": 0x0001,
        "display_name": "9CarPlay Test App",
    },
]
