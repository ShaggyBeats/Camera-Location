"""Discovery protocols: ONVIF WS-Discovery, SSDP, mDNS, port scan, RTSP probe, HTTP banner"""

from __future__ import annotations

import re
import socket
import struct
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import ONVIF_PROBE_TEMPLATE, SSDP_SEARCH_TEMPLATE, ALL_CAMERA_PORTS


# ─── ONVIF WS-Discovery ─────────────────────────────────────────────

@dataclass
class OnvifDevice:
    ip: str
    xaddrs: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)
    types: List[str] = field(default_factory=list)
    model: str = ""
    manufacturer: str = ""
    raw_response: str = ""


def send_onvif_probe(interface_ip: str = "", timeout: float = 5.0) -> List[OnvifDevice]:
    """Send ONVIF WS-Discovery probe and collect camera responses."""
    devices: List[OnvifDevice] = []
    seen_ips: set[str] = set()
    lock = threading.Lock()

    ONVIF_MULTICAST = "239.255.255.250"
    ONVIF_PORT = 3702

    message_id = str(uuid.uuid4())
    probe_msg = ONVIF_PROBE_TEMPLATE.replace("{message_id}", message_id)
    probe_bytes = probe_msg.encode("utf-8")

    def listener(sock: socket.socket):
        sock.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
                response = data.decode("utf-8", errors="replace")
                source_ip = addr[0]
                device = _parse_onvif_response(response, source_ip)
                if device:
                    with lock:
                        if source_ip not in seen_ips:
                            seen_ips.add(source_ip)
                            devices.append(device)
            except socket.timeout:
                break
            except Exception:
                continue

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if interface_ip:
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(interface_ip)
                )
            except Exception:
                pass

        sock.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
            struct.pack("b", 4)
        )

        # Bind to ONVIF port to receive direct replies
        try:
            sock.bind(("", ONVIF_PORT))
        except OSError:
            # Port in use, bind to any port
            sock.bind(("", 0))

        try:
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                socket.inet_aton(ONVIF_MULTICAST) + socket.inet_aton(interface_ip or "0.0.0.0")
            )
        except Exception:
            pass

        # Start listener thread
        listener_thread = threading.Thread(target=listener, args=(sock,), daemon=True)
        listener_thread.start()

        # Send probe to multicast and broadcast
        sock.sendto(probe_bytes, (ONVIF_MULTICAST, ONVIF_PORT))
        try:
            sock.sendto(probe_bytes, ("255.255.255.255", ONVIF_PORT))
        except Exception:
            pass

        # Send a second probe after 2 seconds
        time.sleep(2)
        try:
            sock.sendto(probe_bytes, (ONVIF_MULTICAST, ONVIF_PORT))
        except Exception:
            pass

        # Wait for listener to finish
        listener_thread.join(timeout=timeout + 1)

    finally:
        try:
            sock.close()
        except Exception:
            pass

    return devices


def _parse_onvif_response(response: str, source_ip: str) -> Optional[OnvifDevice]:
    """Parse an ONVIF WS-Discovery response."""
    try:
        # Must be a ProbeMatch response
        if "ProbeMatch" not in response and "probeMatch" not in response:
            return None

        xaddrs = []
        scopes = []
        types_list = []

        # Extract XAddrs
        xaddr_matches = re.findall(r"<d:XAddrs>(.*?)</d:XAddrs>", response, re.DOTALL)
        for xm in xaddr_matches:
            xaddrs.extend(xm.strip().split())

        # Extract Scopes
        scopes_match = re.search(r"<d:Scopes>(.*?)</d:Scopes>", response, re.DOTALL)
        if scopes_match:
            scopes = scopes_match.group(1).strip().split()

        # Extract Types
        types_matches = re.findall(r"<d:Types>(.*?)</d:Types>", response, re.DOTALL)
        types_list = [t.strip() for t in types_matches]

        # Extract model and manufacturer from scopes
        model = ""
        manufacturer = ""
        from urllib.parse import unquote
        for scope in scopes:
            name_m = re.match(r"onvif://www\.onvif\.org/name/(.+)", scope)
            if name_m:
                model = unquote(name_m.group(1))
            hw_m = re.match(r"onvif://www\.onvif\.org/hardware/(.+)", scope)
            if hw_m and not model:
                model = unquote(hw_m.group(1))
            mfr_m = re.match(r"onvif://www\.onvif\.org/manufacturer/(.+)", scope)
            if mfr_m:
                manufacturer = unquote(mfr_m.group(1))

        return OnvifDevice(
            ip=source_ip,
            xaddrs=xaddrs,
            scopes=scopes,
            types=types_list,
            model=model,
            manufacturer=manufacturer,
            raw_response=response,
        )
    except Exception:
        return None


# ─── SSDP/UPnP Discovery ────────────────────────────────────────────

@dataclass
class SsdpDevice:
    ip: str
    port: int
    location: str
    st: str
    server: str
    usn: str


def send_ssdp_search(interface_ip: str = "", timeout: float = 5.0) -> List[SsdpDevice]:
    """Send SSDP M-SEARCH and collect device responses."""
    devices: List[SsdpDevice] = []
    seen_locations: set[str] = set()
    lock = threading.Lock()

    SSDP_MULTICAST = "239.255.255.250"
    SSDP_PORT = 1900
    search_bytes = SSDP_SEARCH_TEMPLATE.encode("utf-8")

    def listener(sock: socket.socket):
        sock.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
                response = data.decode("utf-8", errors="replace")
                device = _parse_ssdp_response(response, addr[0], addr[1])
                if device and device.location not in seen_locations:
                    with lock:
                        if device.location not in seen_locations:
                            seen_locations.add(device.location)
                            devices.append(device)
            except socket.timeout:
                break
            except Exception:
                continue

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if interface_ip:
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(interface_ip)
                )
            except Exception:
                pass

        sock.bind(("", 0))

        try:
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                socket.inet_aton(SSDP_MULTICAST) + socket.inet_aton(interface_ip or "0.0.0.0")
            )
        except Exception:
            pass

        listener_thread = threading.Thread(target=listener, args=(sock,), daemon=True)
        listener_thread.start()

        sock.sendto(search_bytes, (SSDP_MULTICAST, SSDP_PORT))
        try:
            sock.sendto(search_bytes, ("255.255.255.255", SSDP_PORT))
        except Exception:
            pass

        # Second search after 2s
        time.sleep(2)
        try:
            sock.sendto(search_bytes, (SSDP_MULTICAST, SSDP_PORT))
        except Exception:
            pass

        listener_thread.join(timeout=timeout + 1)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return devices


def _parse_ssdp_response(response: str, ip: str, port: int) -> Optional[SsdpDevice]:
    """Parse an SSDP response."""
    headers: Dict[str, str] = {}
    for line in response.split("\r\n"):
        idx = line.find(":")
        if idx > 0:
            key = line[:idx].strip().lower()
            val = line[idx + 1:].strip()
            headers[key] = val

    if not headers.get("location") and not headers.get("st"):
        return None

    return SsdpDevice(
        ip=ip,
        port=port,
        location=headers.get("location", ""),
        st=headers.get("st", ""),
        server=headers.get("server", ""),
        usn=headers.get("usn", ""),
    )


# ─── TCP Port Scanner ───────────────────────────────────────────────

def scan_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    """Check if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_ports(ip: str, ports: List[int] = None, timeout: float = 1.5,
               batch_size: int = 30, callback: Callable = None) -> List[int]:
    """Scan multiple TCP ports on a host."""
    if ports is None:
        ports = ALL_CAMERA_PORTS

    open_ports: List[int] = []

    for i in range(0, len(ports), batch_size):
        batch = ports[i:i + batch_size]
        results = []
        for port in batch:
            t = threading.Thread(
                target=lambda p, r: r.append((p, scan_port(ip, p, timeout))),
                args=(port, results)
            )
            t.start()
            results.append(None)  # placeholder
            # Actually we need a different approach

        # Better approach: use ThreadPool-like pattern
        open_in_batch = _scan_port_batch(ip, batch, timeout)
        open_ports.extend(open_in_batch)

        if callback:
            callback(i + len(batch), len(ports))

    return sorted(open_ports)


def _scan_port_batch(ip: str, ports: List[int], timeout: float) -> List[int]:
    """Scan a batch of ports concurrently."""
    open_ports: List[int] = []
    lock = threading.Lock()

    def check_port(port: int):
        if scan_port(ip, port, timeout):
            with lock:
                open_ports.append(port)

    threads = []
    for port in ports:
        t = threading.Thread(target=check_port, args=(port,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=timeout + 1)

    return sorted(open_ports)


# ─── HTTP Banner Grab ───────────────────────────────────────────────

def grab_http_banner(ip: str, port: int = 80, timeout: float = 3.0) -> str:
    """Grab HTTP banner from a web server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode("utf-8"))

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 8192:
                    break
            except socket.timeout:
                break

        sock.close()
        return response.decode("utf-8", errors="replace")
    except Exception:
        return ""


# ─── RTSP Probe ─────────────────────────────────────────────────────

@dataclass
class RtspResult:
    found: bool
    banner: str


def probe_rtsp(ip: str, port: int = 554, timeout: float = 3.0) -> RtspResult:
    """Probe an RTSP server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        request = "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        sock.sendall(request.encode("utf-8"))

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 4096:
                    break
            except socket.timeout:
                break

        sock.close()
        resp_str = response.decode("utf-8", errors="replace")
        return RtspResult(found="rtsp" in resp_str.lower(), banner=resp_str)
    except Exception:
        return RtspResult(found=False, banner="")


# ─── Passive Listener ───────────────────────────────────────────────

class PassiveListener:
    """Listen for ONVIF and SSDP multicast traffic passively."""

    def __init__(self):
        self.running = False
        self._threads: List[threading.Thread] = []
        self._sockets: List[socket.socket] = []
        self.on_onvif: Optional[Callable[[str, str], None]] = None
        self.on_ssdp: Optional[Callable[[str, str], None]] = None

    def start(self, interface_ip: str = ""):
        """Start passive listening."""
        self.running = True

        # ONVIF listener
        t = threading.Thread(target=self._listen_onvif, args=(interface_ip,), daemon=True)
        t.start()
        self._threads.append(t)

        # SSDP listener
        t = threading.Thread(target=self._listen_ssdp, args=(interface_ip,), daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self):
        """Stop passive listening."""
        self.running = False
        for sock in self._sockets:
            try:
                sock.close()
            except Exception:
                pass
        for t in self._threads:
            t.join(timeout=2)

    def _listen_onvif(self, interface_ip: str):
        """Listen for ONVIF WS-Discovery traffic."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 3702))

            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton("239.255.255.250") + socket.inet_aton(interface_ip or "0.0.0.0")
                )
            except Exception:
                pass

            self._sockets.append(sock)
            sock.settimeout(1.0)

            while self.running:
                try:
                    data, addr = sock.recvfrom(65535)
                    response = data.decode("utf-8", errors="replace")
                    if "soap-envelope" in response or "discovery" in response.lower():
                        if self.on_onvif:
                            self.on_onvif(addr[0], response)
                except socket.timeout:
                    continue
                except Exception:
                    continue
        except Exception:
            pass

    def _listen_ssdp(self, interface_ip: str):
        """Listen for SSDP NOTIFY traffic."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 1900))

            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton("239.255.255.250") + socket.inet_aton(interface_ip or "0.0.0.0")
                )
            except Exception:
                pass

            self._sockets.append(sock)
            sock.settimeout(1.0)

            while self.running:
                try:
                    data, addr = sock.recvfrom(65535)
                    response = data.decode("utf-8", errors="replace")
                    if "NOTIFY" in response or "HTTP/1.1" in response:
                        if self.on_ssdp:
                            self.on_ssdp(addr[0], response)
                except socket.timeout:
                    continue
                except Exception:
                    continue
        except Exception:
            pass
