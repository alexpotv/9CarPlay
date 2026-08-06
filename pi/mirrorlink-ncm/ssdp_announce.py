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

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
EVENT_SUB_PATH = "/eventSub"  # confirmed literal string in firmware, shared across services

# Confirmed live via the head unit's own M-SEARCH request (ST: header) — see module docstring.
DEVICE_TYPE = "urn:schemas-upnp-org:device:TmServerDevice:1"
SERVICE_TYPES = [
    "urn:schemas-upnp-org:service:TmApplicationServer:1",
    "urn:schemas-upnp-org:service:TmClientProfile:1",
]

# Action names inferred from internal C++ method names (ASSERVICE_*/CPSERVICE_*) found adjacent
# to the TmApplicationServer/TmClientProfile strings in the firmware — NOT confirmed against a
# real SCPD/WSDL, just the best available evidence. Argument lists are unknown, so actions are
# declared with no arguments for now; this is enough to be schema-valid and to observe, via the
# controlURL handler's logging, which action(s) the head unit actually tries to invoke first.
SERVICE_ACTIONS = {
    "TmApplicationServer": [
        "GetApplicationList",
        "GetApplicationStatus",
        "LaunchApplication",
        "TerminateApplication",
        "GetApplicationCertificateInfo",
        "GetCertifiedApplicationsList",
    ],
    "TmClientProfile": [
        "GetMaxNumProfiles",
        "GetClientProfile",
        "SetClientProfile",
    ],
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
    <UDN>uuid:{udn}</UDN>
    <serviceList>
{services}
    </serviceList>
  </device>
</root>
"""

SERVICE_XML_TEMPLATE = """      <service>
        <serviceType>{service_type}</serviceType>
        <serviceId>urn:upnp-org:serviceId:{service_id}</serviceId>
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
  </serviceStateTable>
</scpd>
"""

SCPD_ACTION_TEMPLATE = """    <action>
      <name>{name}</name>
    </action>"""

SOAP_RESPONSE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action}Response xmlns:u="{service_type}">
    </u:{action}Response>
  </s:Body>
</s:Envelope>
"""


def build_description_xml(ip, port):
    services = "\n".join(
        SERVICE_XML_TEMPLATE.format(
            service_type=st, service_id=st.split(":")[-2], event_sub_path=EVENT_SUB_PATH
        )
        for st in SERVICE_TYPES
    )
    return DESCRIPTION_XML_TEMPLATE.format(
        url_base=f"http://{ip}:{port}/", device_type=DEVICE_TYPE, udn=DEVICE_UUID, services=services
    ).encode("utf-8")


def build_scpd_xml(service_id):
    actions = SERVICE_ACTIONS.get(service_id, [])
    actions_xml = "\n".join(SCPD_ACTION_TEMPLATE.format(name=a) for a in actions)
    return SCPD_XML_TEMPLATE.format(actions=actions_xml).encode("utf-8")


def service_type_for_id(service_id):
    for st in SERVICE_TYPES:
        if st.split(":")[-2] == service_id:
            return st
    return None


class DescriptionHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send_xml(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/description.xml":
            ip, port = self.server.server_address
            self._send_xml(build_description_xml(ip, port))
            return
        if self.path.startswith("/scpd_") and self.path.endswith(".xml"):
            service_id = self.path[len("/scpd_"):-len(".xml")]
            if service_id in SERVICE_ACTIONS:
                print(f"[http] SCPD fetched for service {service_id!r} — "
                      f"head unit is reading our action list")
                self._send_xml(build_scpd_xml(service_id))
                return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        soapaction = self.headers.get("SOAPACTION", "")
        print(f"[http] POST {self.path} SOAPACTION={soapaction!r}\n{body.decode('utf-8', 'replace')}")

        if self.path.startswith("/control_"):
            service_id = self.path[len("/control_"):]
            service_type = service_type_for_id(service_id)
            action = None
            if "#" in soapaction:
                action = soapaction.rsplit("#", 1)[-1].strip('"')
            if service_type and action:
                print(f"[http] head unit invoked action {action!r} on {service_id} — "
                      f"replying with a stub empty success response")
                resp = SOAP_RESPONSE_TEMPLATE.format(
                    action=action, service_type=service_type
                ).encode("utf-8")
                self._send_xml(resp)
                return

        self.send_response(404)
        self.end_headers()

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


def start_http_server(ip, port):
    server = http.server.HTTPServer((ip, port), DescriptionHandler)
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
                f"LOCATION: {location}\r\n"
                f"ST: {st_match}\r\n"
                f"USN: {usn}\r\n"
                "SERVER: 9CarPlay/0.1 UPnP/1.0 MirrorLinkBridge/0.1\r\n"
                "\r\n"
            ).encode("ascii")
            sock.sendto(reply, addr)
            print(f"[ssdp] -> M-SEARCH reply ST={st_match} to {addr}")


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
