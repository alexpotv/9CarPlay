#!/usr/bin/env python3
"""UPnP/SSDP announcer for the MirrorLink CDC-NCM bearer test — see
pi/mirrorlink-ncm/README.md and references/cr-v/PROTOCOL_ANALYSIS.md ("Update — live AOA testing
was negative...") for why this exists: ETSI TS 103 544 (the published MirrorLink spec) says the
phone-side MirrorLink Server "shall enable CDC/NCM and start advertising itself via SSDP:alive
messages" — this script is that SSDP:alive advertisement, to run once setup_ncm_gadget.sh has
brought up the USB-NCM link and an IP address.

CONFIRMED WORKING TO THE POINT OF SSDP DISCOVERY: on real hardware this produces a "Detected
Device" event in the head unit's MirrorLink diagnostics screen (see pi/mirrorlink-ncm/README.md
Quickstart), followed a few seconds later by "MirrorLink Status (disconnected)". The session does
not yet progress past that. The two UPnP service types advertised here (TmApplicationServer:1,
TmClientProfile:1) are confirmed present as literal strings in the head unit's own firmware
(strings_out.txt) — "Tm" = Terminal Mode, the CCC framework MirrorLink is built on. So are the
literal HTTP paths /description.xml and /eventSub, the CyberGarage-HTTP/1.0 UPnP stack signature
(confirming this is a standard SOAP-over-HTTP + GENA eventing UPnP control point, not something
bespoke), and SOAP action names inferred from internal C++ method names next to the two service
strings (ASSERVICE_* / CPSERVICE_*) — see references/cr-v/PROTOCOL_ANALYSIS.md for the full
writeup. This version adds real SCPD, SOAP control, and GENA subscribe endpoints based on that
evidence, to test whether the earlier 404s on those paths were what caused the disconnect.

The root DEVICE type URN is now CONFIRMED (previously a guess): the head unit's own
DHCP-client-then-M-SEARCH sequence was observed live — after it obtains a lease from
start_dhcp_server.sh, it immediately starts sending M-SEARCH for
ST: urn:schemas-upnp-org:device:TmServerDevice:1 (NOT TerminalModeDevice:1 as previously guessed).
DEVICE_TYPE below has been corrected to match.

Usage:
    sudo python3 ssdp_announce.py [--ip 192.168.42.1] [--port 8080]

Must be run where the IP given is actually reachable from the head unit over the USB-NCM link
(i.e. after setup_ncm_gadget.sh and the `ip addr add`/`ip link set up` steps in its output).
"""

import argparse
import http.server
import socket
import struct
import sys
import threading
import time
import uuid
from xml.sax.saxutils import escape as xml_escape

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
EVENT_SUB_PATH = "/eventSub"  # confirmed literal string in firmware, shared across services

# Confirmed live via the head unit's own M-SEARCH request (ST: header) — see module docstring.
DEVICE_TYPE = "urn:schemas-upnp-org:device:TmServerDevice:1"
SERVICE_TYPES = [
    "urn:schemas-upnp-org:service:TmApplicationServer:1",
    "urn:schemas-upnp-org:service:TmClientProfile:1",
]

# Action names AND argument names confirmed directly from the head unit's own application binary
# (MIrrorLink.exe, extracted from the WinCE ROM and reverse-engineered in Ghidra — see
# references/cr-v/PROTOCOL_ANALYSIS.md). This superseded an earlier guess based only on internal
# C++ method names in a different DLL (vncdiscoverer-usb.dll), which also included
# GetApplicationCertificateInfo/GetMaxNumProfiles/GetClientProfile — none of those three appear as
# real action-name strings anywhere in MIrrorLink.exe, so they've been dropped here as likely not
# actually used actions in this deployment (they may exist unused in a generic shared SDK class).
#
# Each entry: action name -> list of (argument name, direction). Directions and names below are
# confirmed from the actual SOAP-invocation-building code in MIrrorLink.exe, which constructs a
# named-argument list before calling the generic UPnP action-invoke function (thunk_FUN_0008cfc4)
# — i.e. these are the literal argument names the head unit sends/expects, not guesses. The
# exception is LaunchApplication's output argument, which is unconfirmed (no literal string found
# for it), so it's omitted rather than guessed.
SERVICE_ACTIONS = {
    "TmApplicationServer": {
        "GetApplicationList": [],
        "GetApplicationStatus": [],
        "LaunchApplication": [
            ("AppID", "in"), ("ProfileID", "in"), ("AppURI", "in"),
        ],
        "TerminateApplication": [
            ("AppID", "in"),  # confirmed via log string "TerminateApplication appID : 0x%x"
        ],
        # Backed by a class literally named UIMirrorLink_Attestation in MIrrorLink.exe — this is
        # very likely the actual DAP/certificate-attestation trigger point (see Phase 3 pairing
        # risk in PROJECT_PLAN.md). Whatever we return in CertifiedAppList almost certainly needs
        # to reflect genuine CCC certification data to be accepted, which we don't have.
        "GetCertifiedApplicationsList": [
            ("AppCertFilter", "in"), ("ProfileID", "in"), ("CertifiedAppList", "out"),
        ],
    },
    "TmClientProfile": {
        "SetClientProfile": [
            ("ProfileID", "in"), ("ClientProfile", "in"), ("ResultProfile", "out"),
        ],
    },
}

# Randomized per process run (not a fixed uuid5) so every trial presents as a genuinely new
# device — a control point that caches by UDN/USN might otherwise skip re-fetching a description
# it already saw in an earlier trial, which would look identical to "stuck" from our side. Pass
# --fixed-uuid to opt back into the deterministic UUID if that behavior is ever wanted instead.
DEVICE_UUID = str(uuid.uuid4())

DESCRIPTION_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <URLBase>{url_base}</URLBase>
  <device>
    <deviceType>{device_type}</deviceType>
    <friendlyName>9CarPlay MirrorLink Bridge</friendlyName>
    <manufacturer>9CarPlay Project</manufacturer>
    <modelName>MirrorLink NCM Bridge (dev)</modelName>
    <modelNumber>0.1</modelNumber>
    <serialNumber>0123456789abcdef</serialNumber>
    <UDN>uuid:{udn}</UDN>
    <serviceList>
{services}
    </serviceList>
    <X_mirrorLinkVersion xmlns="urn:schemas-carconnectivity-org:ml-1-1">
      <majorVersion>1</majorVersion>
      <minorVersion>1</minorVersion>
    </X_mirrorLinkVersion>
{x_signature}
    <X_presentations xmlns="urn:schemas-carconnectivity-org:ml-1-2">
      <presentation>vncu</presentation>
    </X_presentations>
    <X_mlUiMode xmlns="urn:schemas-carconnectivity-org:ml-1-3">
      <mode>classic</mode>
    </X_mlUiMode>
  </device>
</root>
"""

# ETSI TS 103 544-12 Annex A's normative XSD marks X_Signature minOccurs="1" — it is not
# optional, and clause 4.3.2 requires the MirrorLink Client to validate it and terminate the
# session on failure. We have no real signature to offer: the key is the private half of an
# application-specific key whose public half must be bound via genuine DAP/CCC attestation (see
# Phase 3 in PROJECT_PLAN.md) — credentials we don't have. This is a syntactically well-formed
# but cryptographically meaningless placeholder (DigestValue/SignatureValue are not computed over
# the actual document), included only so the description XML is schema-valid enough to test how
# far the head unit gets before it — presumably — rejects the bogus signature. That rejection
# point is itself useful diagnostic signal for Phase 3.
X_SIGNATURE_XML = """    <X_Signature xmlns="urn:schemas-carconnectivity-org:ml-1-1">
      <Signature Id="deviceSignature" xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
          <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
          <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
          <Reference URI="">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
              <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
            <DigestValue>bm90LWEtcmVhbC1zaWduYXR1cmU=</DigestValue>
          </Reference>
        </SignedInfo>
        <SignatureValue>bm90LWEtcmVhbC1zaWduYXR1cmU=</SignatureValue>
      </Signature>
    </X_Signature>"""

SERVICE_XML_TEMPLATE = """      <service>
        <serviceType>{service_type}</serviceType>
        <serviceId>urn:upnp-org:serviceId:{service_id_urn}</serviceId>
        <SCPDURL>/scpd_{service_id}.xml</SCPDURL>
        <controlURL>/control_{service_id}</controlURL>
        <eventSubURL>{event_sub_path}</eventSubURL>
      </service>"""

SCPD_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <actionList>
{actions}
  </actionList>
  <serviceStateTable>
{state_vars}
  </serviceStateTable>
</scpd>
"""

SCPD_ACTION_NO_ARGS_TEMPLATE = """    <action>
      <name>{name}</name>
    </action>"""

SCPD_ACTION_WITH_ARGS_TEMPLATE = """    <action>
      <name>{name}</name>
      <argumentList>
{arguments}
      </argumentList>
    </action>"""

SCPD_ARGUMENT_TEMPLATE = (
    '        <argument><name>{arg_name}</name><direction>{direction}</direction>'
    '<relatedStateVariable>A_ARG_TYPE_{arg_name}</relatedStateVariable></argument>'
)

SCPD_STATE_VAR_TEMPLATE = (
    '    <stateVariable sendEvents="no"><name>A_ARG_TYPE_{arg_name}</name>'
    '<dataType>string</dataType></stateVariable>'
)

SOAP_RESPONSE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action}Response xmlns:u="{service_type}">
      {body}
    </u:{action}Response>
  </s:Body>
</s:Envelope>
"""

# Per-action response bodies, using identity values consistent with the USB gadget strings
# (setup_ncm_gadget.sh) and the UPnP device description above. Output argument NAMES are now
# confirmed (see SERVICE_ACTIONS above) except for LaunchApplication, which has no confirmed
# output argument (none found as a literal string) so it's left with a generic placeholder.
# If the head unit rejects one of these with a SOAP fault (UPnPError), that fault body itself is
# useful diagnostic information — it's logged in full either way via the POST handler.
# ETSI TS 103 544-9 clause 5.2.5: "If the MirrorLink Server supports the Device Attestation
# Protocol, it shall include the Device Attestation Protocol Server as an application within
# A_ARG_TYPE_AppList... <protocolId> shall be "DAP". <appCategory> shall be "0xF0000001"." Before
# this existed, GetApplicationList always returned an empty ApplicationList, which is exactly why
# the head unit's diagnostics screen showed "MirrorLink Status (no DAP server)" — it never got as
# far as LaunchApplication. appID/name/format values are taken directly from the spec's own
# worked example in clause 5.5.4.
#
# The A_ARG_TYPE_AppList XSD (clause 6.2) marks <Signature> as minOccurs="1" on <appList> itself —
# mandatory, not optional, same situation as X_SIGNATURE_XML above. We have no real DAP-issued
# signing key, so this is the same kind of syntactically well-formed but cryptographically
# meaningless placeholder, with Reference URI="#mlServerAppList" pointing at the appList's own
# xml:id per clause 5.6.
DAP_APP_LIST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<appList xml:id="mlServerAppList" xmlns="urn:schemas-upnp-org:tmapplicationserver:applist-1-0">
  <app>
    <appID>0x9016</appID>
    <name>Device Attestation</name>
    <remotingInfo>
      <protocolID>DAP</protocolID>
      <format>1.1</format>
    </remotingInfo>
  </app>
  <Signature Id="AppListSignature" xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="#mlServerAppList">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>bm90LWEtcmVhbC1zaWduYXR1cmU=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>bm90LWEtcmVhbC1zaWduYXR1cmU=</SignatureValue>
  </Signature>
</appList>"""

_CLIENT_PROFILE_XML = (
    "&lt;modelNumber&gt;0.1&lt;/modelNumber&gt;"
    "&lt;modelName&gt;MirrorLink NCM Bridge (dev)&lt;/modelName&gt;"
    "&lt;manufacturer&gt;9CarPlay Project&lt;/manufacturer&gt;"
    "&lt;friendlyName&gt;9CarPlay MirrorLink Bridge&lt;/friendlyName&gt;"
    "&lt;clientID&gt;9carplay-001&lt;/clientID&gt;"
)
ACTION_RESPONSE_BODIES = {
    # Output argument names below are the literal names from each action's Arguments table in
    # ETSI TS 103 544-9 (clause 4.5), NOT the generic "Result"/service-name-ish guesses this
    # dict previously used — those guesses were silently wrong (GetApplicationList really
    # returns AppListing, not ApplicationList) and are the reason a real DAP app entry still
    # produced "no DAP server" on hardware: the head unit's parser looks up the response by
    # this exact element name and treats anything else as an absent/empty result.
    #
    # Escaped, since AppListing's value is itself a full XML document embedded as text content
    # of the SOAP response element (same embedding shape as ClientProfile below).
    "GetApplicationList": f"<AppListing>{xml_escape(DAP_APP_LIST_XML)}</AppListing>",  # Table 4-11
    "GetApplicationStatus": "<AppStatus></AppStatus>",  # Table 4-17
    "LaunchApplication": "<AppURI></AppURI>",  # Table 4-13 — real value is Phase B, unimplemented
    "TerminateApplication": "<TerminationResult>true</TerminationResult>",  # Table 4-15
    # Confirmed output argument name (CertifiedAppList) — empty, since we have no genuine
    # CCC-certified applications to report. This is very likely where the lack of real
    # credentials becomes visible to the head unit's attestation logic.
    "GetCertifiedApplicationsList": "<CertifiedAppList></CertifiedAppList>",
    # Confirmed output argument name (ResultProfile) — echoing back our own identity, since we
    # don't know what the head unit expects to see distinct from what it sent us.
    "SetClientProfile": f"<ResultProfile>{_CLIENT_PROFILE_XML}</ResultProfile>",
}


# TEMPORARY test override — bypasses build_description_xml() below entirely and serves this
# fixed, minimal description instead (no X_mirrorLinkVersion/X_Signature/X_presentations/
# X_mlUiMode, and eventSubURL paths differ per-service rather than the shared /eventSub), to see
# whether a leaner, more literally spec-example-shaped description changes head unit behaviour.
# Flip USE_STATIC_TEST_DESCRIPTION_XML back to False to revert to the full build_description_xml.
USE_STATIC_TEST_DESCRIPTION_XML = True

STATIC_TEST_DESCRIPTION_XML = """<?xml version="1.0" encoding="UTF-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>

  <URLBase>http://192.168.42.1:8080/</URLBase>

  <device>
    <deviceType>urn:schemas-upnp-org:device:TmServerDevice:1</deviceType>
    <friendlyName>9CarPlay MirrorLink Bridge</friendlyName>
    <manufacturer>9CarPlay Project</manufacturer>
    <modelName>MirrorLink NCM Bridge</modelName>
    <modelNumber>0.1</modelNumber>
    <serialNumber>0123456789abcdef</serialNumber>
    <UDN>uuid:{udn}</UDN>

    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:TmApplicationServer:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:TmApplicationServer1</serviceId>
        <SCPDURL>/scpd_TmApplicationServer.xml</SCPDURL>
        <controlURL>/control_TmApplicationServer</controlURL>
        <eventSubURL>/event_TmApplicationServer</eventSubURL>
      </service>

      <service>
        <serviceType>urn:schemas-upnp-org:service:TmClientProfile:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:TmClientProfile1</serviceId>
        <SCPDURL>/scpd_TmClientProfile.xml</SCPDURL>
        <controlURL>/control_TmClientProfile</controlURL>
        <eventSubURL>/event_TmClientProfile</eventSubURL>
      </service>
    </serviceList>
  </device>
</root>
"""


def build_description_xml(ip, port):
    if USE_STATIC_TEST_DESCRIPTION_XML:
        return STATIC_TEST_DESCRIPTION_XML.format(udn=DEVICE_UUID).encode("utf-8")

    services = "\n".join(
        # serviceId keeps the version digit concatenated (e.g. "TmApplicationServer1"), matching
        # the literal string in the spec's worked example in clause 5 — service_id (used for our
        # own SCPDURL/controlURL path naming, which the spec leaves implementation-defined) stays
        # short since it's also the SERVICE_ACTIONS/service_type_for_id lookup key.
        SERVICE_XML_TEMPLATE.format(
            service_type=st,
            service_id=st.split(":")[-2],
            service_id_urn=st.split(":")[-2] + st.split(":")[-1],
            event_sub_path=EVENT_SUB_PATH,
        )
        for st in SERVICE_TYPES
    )
    return DESCRIPTION_XML_TEMPLATE.format(
        url_base=f"http://{ip}:{port}/",
        device_type=DEVICE_TYPE,
        udn=DEVICE_UUID,
        services=services,
        x_signature=X_SIGNATURE_XML,
    ).encode("utf-8")


def build_scpd_xml(service_id):
    actions_def = SERVICE_ACTIONS.get(service_id, {})
    action_blocks = []
    state_var_names = set()
    for name, args in actions_def.items():
        if not args:
            action_blocks.append(SCPD_ACTION_NO_ARGS_TEMPLATE.format(name=name))
            continue
        arg_xml = "\n".join(
            SCPD_ARGUMENT_TEMPLATE.format(arg_name=arg_name, direction=direction)
            for arg_name, direction in args
        )
        action_blocks.append(SCPD_ACTION_WITH_ARGS_TEMPLATE.format(name=name, arguments=arg_xml))
        state_var_names.update(arg_name for arg_name, _ in args)
    actions_xml = "\n".join(action_blocks)
    state_vars_xml = "\n".join(
        SCPD_STATE_VAR_TEMPLATE.format(arg_name=n) for n in sorted(state_var_names)
    )
    return SCPD_XML_TEMPLATE.format(actions=actions_xml, state_vars=state_vars_xml).encode("utf-8")


def service_type_for_id(service_id):
    for st in SERVICE_TYPES:
        if st.split(":")[-2] == service_id:
            return st
    return None


class DescriptionHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Backstop for the ThreadingHTTPServer switch below: without this, a client that opens a
    # keep-alive connection and never sends a second request (or never closes the socket) would
    # tie up its handler thread in a blocking readline() forever. 30s is generous versus the
    # ~30s SSDP re-announce interval.
    timeout = 30

    def _send_xml(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Build + send the response BEFORE logging it. Printing a multi-KB XML body to the
        # console is not free (slow SSH/serial console, redirected-to-disk stdout, etc.), and
        # doing that ahead of _send_xml() puts avoidable latency directly on the critical path
        # of "first response byte out". Confirmed live: the head unit's second description.xml
        # request got a BrokenPipeError when we finally tried to write — i.e. it had ALREADY
        # closed the connection by then, consistent with a client-side receive timeout tripping
        # while we were still busy printing instead of replying. Logging after send removes that
        # self-inflicted delay; it doesn't change what's logged, only when.
        if self.path == "/description.xml":
            ip, port = self.server.server_address
            body = build_description_xml(ip, port)
            self._send_xml(body)
            print(f"[http] description.xml fetched by {self.address_string()} — replied with:\n"
                  f"{body.decode('utf-8')}")
            return
        if self.path.startswith("/scpd_") and self.path.endswith(".xml"):
            service_id = self.path[len("/scpd_"):-len(".xml")]
            if service_id in SERVICE_ACTIONS:
                self._send_xml(build_scpd_xml(service_id))
                print(f"[http] SCPD fetched for service {service_id!r} — "
                      f"head unit is reading our action list")
                return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        soapaction = self.headers.get("SOAPACTION", "")

        if self.path.startswith("/control_"):
            service_id = self.path[len("/control_"):]
            service_type = service_type_for_id(service_id)
            action = None
            if "#" in soapaction:
                action = soapaction.rsplit("#", 1)[-1].strip('"')
            if service_type and action:
                resp_body = ACTION_RESPONSE_BODIES.get(action, "")
                resp = SOAP_RESPONSE_TEMPLATE.format(
                    action=action, service_type=service_type, body=resp_body
                ).encode("utf-8")
                self._send_xml(resp)
                print(f"[http] head unit invoked action {action!r} on {service_id} — "
                      f"replied with {'a best-effort' if resp_body else 'an empty'} response\n"
                      f"POST {self.path} SOAPACTION={soapaction!r}\n{body.decode('utf-8', 'replace')}")
                return

        self.send_response(404)
        self.end_headers()
        print(f"[http] POST {self.path} SOAPACTION={soapaction!r} -> 404\n"
              f"{body.decode('utf-8', 'replace')}")

    def do_SUBSCRIBE(self):
        if self.path == EVENT_SUB_PATH:
            sid = f"uuid:{uuid.uuid4()}"
            callback = self.headers.get("CALLBACK", "")
            timeout = self.headers.get("TIMEOUT", "Second-1800")
            print(f"[http] SUBSCRIBE {self.path} CALLBACK={callback!r} TIMEOUT={timeout!r} "
                  f"-> accepting with SID={sid}")
            self.send_response(200)
            self.send_header("SID", sid)
            self.send_header("TIMEOUT", timeout)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(412)  # precondition failed — GENA's code for unknown subscription
        self.end_headers()

    def do_UNSUBSCRIBE(self):
        sid = self.headers.get("SID", "")
        print(f"[http] UNSUBSCRIBE {self.path} SID={sid!r}")
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        print(f"[http] {self.address_string()} - {fmt % args}")


class MirrorLinkHTTPServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # Default socketserver.BaseServer.handle_error() dumps a full traceback for ANY
        # exception escaping a handler thread. A client (this head unit, live) closing its
        # socket mid-response — write() then fails with BrokenPipeError/ConnectionResetError —
        # is expected/benign under ThreadingHTTPServer (it only kills that one thread), not a
        # bug, so log it as one line instead of a scary traceback. Anything else still gets the
        # full traceback since that IS worth knowing about.
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            print(f"[http] {client_address} disconnected mid-response ({exc.__class__.__name__}) "
                  f"— client closed the connection before we finished writing, not fatal")
            return
        super().handle_error(request, client_address)


def start_http_server(ip, port):
    # http.server.HTTPServer is single-threaded and synchronous: with protocol_version
    # "HTTP/1.1" (keep-alive) it fully blocks inside one connection's handle_one_request() loop
    # until that connection closes or times out, so it can't accept a second connection in the
    # meantime. Confirmed live via tcpdump: the head unit's first GET /description.xml got a
    # reply, but every subsequent GET (a new TCP connection each time) got no reply at all —
    # exactly what you'd see if the server were still wedged servicing the first connection.
    # ThreadingHTTPServer hands each connection its own thread so concurrent/repeated fetches
    # (description.xml, per-service SCPD, control, eventSub) can all be served independently.
    server = MirrorLinkHTTPServer((ip, port), DescriptionHandler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[http] serving /description.xml on http://{ip}:{port}/description.xml")
    return server


def notify_targets(ip, port):
    location = f"http://{ip}:{port}/description.xml"
    targets = [
        ("upnp:rootdevice", f"uuid:{DEVICE_UUID}::upnp:rootdevice"),
        (f"uuid:{DEVICE_UUID}", f"uuid:{DEVICE_UUID}"),
        (DEVICE_TYPE, f"uuid:{DEVICE_UUID}::{DEVICE_TYPE}"),
    ]
    for st in SERVICE_TYPES:
        targets.append((st, f"uuid:{DEVICE_UUID}::{st}"))
    return location, targets


def send_notify_alive(sock, ip, port):
    location, targets = notify_targets(ip, port)
    for nt, usn in targets:
        msg = (
            "NOTIFY * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
            "CACHE-CONTROL: max-age=1800\r\n"
            f"LOCATION: {location}\r\n"
            f"NT: {nt}\r\n"
            "NTS: ssdp:alive\r\n"
            f"USN: {usn}\r\n"
            "SERVER: 9CarPlay/0.1 UPnP/1.0 MirrorLinkBridge/0.1\r\n"
            "\r\n"
        ).encode("ascii")
        sock.sendto(msg, (SSDP_ADDR, SSDP_PORT))
        print(f"[ssdp] NOTIFY ssdp:alive NT={nt}")


def send_notify_byebye(sock):
    _, targets = notify_targets("0.0.0.0", 0)
    for nt, usn in targets:
        msg = (
            "NOTIFY * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
            f"NT: {nt}\r\n"
            "NTS: ssdp:byebye\r\n"
            f"USN: {usn}\r\n"
            "\r\n"
        ).encode("ascii")
        sock.sendto(msg, (SSDP_ADDR, SSDP_PORT))
    print("[ssdp] sent NOTIFY ssdp:byebye")


def announce_loop(ip, port, interval_s, iface):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
    # Without this, outgoing multicast sends follow the default route (e.g. wlan0/eth0)
    # rather than the NCM link, so the head unit never sees them. Binding to the NCM
    # interface's own IP forces sends out over usb0.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
    if hasattr(socket, "SO_BINDTODEVICE"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\0")
    try:
        while True:
            send_notify_alive(sock, ip, port)
            time.sleep(interval_s)
    finally:
        send_notify_byebye(sock)
        sock.close()


def msearch_responder(ip, port, iface):
    location, targets = notify_targets(ip, port)
    by_st = {nt: usn for nt, usn in targets}
    by_st["ssdp:all"] = f"uuid:{DEVICE_UUID}"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # IP_ADD_MEMBERSHIP's interface field only controls where the join is registered —
    # it does NOT stop the kernel from delivering multicast packets that arrive on other
    # interfaces to a socket bound to INADDR_ANY (confirmed live: we kept receiving
    # M-SEARCH from unrelated devices on the home LAN, e.g. 192.168.1.x, even after
    # setting it). SO_BINDTODEVICE is the actual per-socket interface filter.
    if hasattr(socket, "SO_BINDTODEVICE"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\0")
    sock.bind(("", SSDP_PORT))
    mreq = struct.pack("4s4s", socket.inet_aton(SSDP_ADDR), socket.inet_aton(ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    print(f"[ssdp] listening for M-SEARCH on {SSDP_ADDR}:{SSDP_PORT} (interface {iface}/{ip})")

    while True:
        data, addr = sock.recvfrom(4096)
        text = data.decode("ascii", errors="replace")
        if not text.startswith("M-SEARCH"):
            continue
        print(f"[ssdp] <- M-SEARCH from {addr}:\n{text}")
        st = None
        for line in text.splitlines():
            if line.upper().startswith("ST:"):
                st = line.split(":", 1)[1].strip()
                break
        if st is None:
            continue

        matches = []
        if st in ("ssdp:all",):
            matches = list(targets) + [("upnp:rootdevice", by_st["upnp:rootdevice"])]
        elif st in by_st:
            matches = [(st, by_st[st])]
        else:
            print(f"[ssdp] no match for ST={st!r}, ignoring")
            continue

        for st_match, usn in matches:
            reply = (
                "HTTP/1.1 200 OK\r\n"
                "CACHE-CONTROL: max-age=1800\r\n"
                "EXT:\r\n"
                f"LOCATION: {location}\r\n"
                f"ST: {st_match}\r\n"
                f"USN: {usn}\r\n"
                "SERVER: 9CarPlay/0.1 UPnP/1.0 MirrorLinkBridge/0.1\r\n"
                "\r\n"
            ).encode("ascii")
            sock.sendto(reply, addr)
            print(f"[ssdp] -> M-SEARCH reply to {addr}:\n{reply.decode('ascii')}")


def main():
    global DEVICE_UUID

    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.42.1", help="IP address to advertise (must match setup_ncm_gadget.sh)")
    ap.add_argument("--port", type=int, default=8080, help="HTTP port for the device description")
    ap.add_argument("--interval", type=int, default=30, help="seconds between NOTIFY ssdp:alive bursts")
    ap.add_argument("--iface", default="usb0", help="NCM network interface name (for SO_BINDTODEVICE filtering)")
    ap.add_argument("--fixed-uuid", action="store_true",
                     help="use a fixed UUID across runs instead of a fresh random one each time "
                          "(the default is randomized so a control point that caches by UDN/USN "
                          "can't skip re-fetching our description on a later trial)")
    args = ap.parse_args()

    if args.fixed_uuid:
        DEVICE_UUID = str(uuid.uuid5(uuid.NAMESPACE_DNS, "9carplay-mirrorlink-ncm-bridge"))
    print(f"[ssdp] device UUID for this run: {DEVICE_UUID}")

    start_http_server(args.ip, args.port)

    t = threading.Thread(target=msearch_responder, args=(args.ip, args.port, args.iface), daemon=True)
    t.start()

    try:
        announce_loop(args.ip, args.port, args.interval, args.iface)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
