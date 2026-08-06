#!/usr/bin/env python3
"""UPnP/SSDP announcer for the MirrorLink CDC-NCM bearer test — see
pi/mirrorlink-ncm/README.md and references/cr-v/PROTOCOL_ANALYSIS.md ("Update — live AOA testing
was negative...") for why this exists: ETSI TS 103 544 (the published MirrorLink spec) says the
phone-side MirrorLink Server "shall enable CDC/NCM and start advertising itself via SSDP:alive
messages" — this script is that SSDP:alive advertisement, to run once setup_ncm_gadget.sh has
brought up the USB-NCM link and an IP address.

UNTESTED ON REAL HARDWARE. The two UPnP service types advertised here
(TmApplicationServer:1, TmClientProfile:1) are confirmed present as literal strings in the head
unit's own firmware (strings_out.txt) — "Tm" = Terminal Mode, the CCC framework MirrorLink is
built on. The root DEVICE type URN was NOT found in the firmware strings dump, so
DEVICE_TYPE below is a best-effort guess following standard UPnP naming convention
("urn:schemas-upnp-org:device:<Type>:<version>") and may need correcting once real traffic can be
observed (e.g. via a capture of the head unit's own M-SEARCH request, which would include the ST
it's actually looking for).

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

# Best-effort guess — see module docstring. Adjust if a real capture shows otherwise.
DEVICE_TYPE = "urn:schemas-upnp-org:device:TerminalModeDevice:1"
SERVICE_TYPES = [
    "urn:schemas-upnp-org:service:TmApplicationServer:1",
    "urn:schemas-upnp-org:service:TmClientProfile:1",
]

DEVICE_UUID = str(uuid.uuid5(uuid.NAMESPACE_DNS, "9carplay-mirrorlink-ncm-bridge"))

DESCRIPTION_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>{device_type}</deviceType>
    <friendlyName>9CarPlay MirrorLink Bridge</friendlyName>
    <manufacturer>9CarPlay Project</manufacturer>
    <modelName>MirrorLink NCM Bridge (dev)</modelName>
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
        <eventSubURL>/event_{service_id}</eventSubURL>
      </service>"""


def build_description_xml():
    services = "\n".join(
        SERVICE_XML_TEMPLATE.format(service_type=st, service_id=st.split(":")[-2])
        for st in SERVICE_TYPES
    )
    return DESCRIPTION_XML_TEMPLATE.format(
        device_type=DEVICE_TYPE, udn=DEVICE_UUID, services=services
    ).encode("utf-8")


class DescriptionHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/description.xml":
            body = build_description_xml()
            self.send_response(200)
            self.send_header("Content-Type", "text/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
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
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.42.1", help="IP address to advertise (must match setup_ncm_gadget.sh)")
    ap.add_argument("--port", type=int, default=8080, help="HTTP port for the device description")
    ap.add_argument("--interval", type=int, default=30, help="seconds between NOTIFY ssdp:alive bursts")
    ap.add_argument("--iface", default="usb0", help="NCM network interface name (for SO_BINDTODEVICE filtering)")
    args = ap.parse_args()

    start_http_server(args.ip, args.port)

    t = threading.Thread(target=msearch_responder, args=(args.ip, args.port, args.iface), daemon=True)
    t.start()

    try:
        announce_loop(args.ip, args.port, args.interval, args.iface)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
