"""Discovery protocols: ONVIF WS-Discovery, SSDP, mDNS, port scan, RTSP probe, HTTP banner"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import socket
import struct
import threading
import time
import urllib.request
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


def send_onvif_probe(interface_ip: str = "", timeout: float = 3.0) -> List[OnvifDevice]:
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

        # Wait for listener to finish
        listener_thread.join(timeout=timeout)

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


def send_ssdp_search(interface_ip: str = "", timeout: float = 3.0) -> List[SsdpDevice]:
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

        listener_thread.join(timeout=timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return devices


def _parse_ssdp_response(response: str, ip: str, port: int) -> Optional[SsdpDevice]:
    """Parse an SSDP response. Prefer IP from LOCATION header over source addr."""
    headers: Dict[str, str] = {}
    for line in response.split("\r\n"):
        idx = line.find(":")
        if idx > 0:
            key = line[:idx].strip().lower()
            val = line[idx + 1:].strip()
            headers[key] = val

    if not headers.get("location") and not headers.get("st"):
        return None

    # Extract IP from LOCATION header — more reliable than source addr
    location = headers.get("location", "")
    if location:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(location)
            if parsed.hostname:
                ip = parsed.hostname
        except Exception:
            pass

    return SsdpDevice(
        ip=ip,
        port=port,
        location=location,
        st=headers.get("st", ""),
        server=headers.get("server", ""),
        usn=headers.get("usn", ""),
    )


# ─── TCP Port Scanner ───────────────────────────────────────────────

def scan_port(ip: str, port: int, timeout: float = 3.0) -> bool:
    """Check if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_ports(ip: str, ports: List[int] = None, timeout: float = 3.0,
               callback: Callable = None) -> List[int]:
    """Scan all camera ports on a host concurrently."""
    if ports is None:
        ports = ALL_CAMERA_PORTS
    open_ports = _scan_port_batch(ip, ports, timeout)
    if callback:
        callback(len(ports), len(ports))
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


# ─── ONVIF Device Info (ODM-style) ──────────────────────────────────
# Like ONVIF Device Manager: query the device directly for real model,
# firmware, serial number, and proper RTSP stream URIs instead of guessing.

def _ws_security_header(username: str, password: str) -> str:
    """Build ONVIF WS-Security PasswordDigest header.

    ONVIF cameras require: PasswordDigest = Base64(SHA1(nonce + created + password))
    HTTP Basic/Digest auth is rejected by most cameras.
    """
    nonce_bytes = os.urandom(16)
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    created_bytes = created.encode("utf-8")
    password_bytes = password.encode("utf-8")
    digest = base64.b64encode(
        hashlib.sha1(nonce_bytes + created_bytes + password_bytes).digest()
    ).decode("utf-8")
    nonce_b64 = base64.b64encode(nonce_bytes).decode("utf-8")
    return (
        '<s:Header>'
        '<Security s:mustUnderstand="1"'
        ' xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">'
        '<UsernameToken>'
        f'<Username>{username}</Username>'
        f'<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
        f'{digest}</Password>'
        f'<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
        f'{nonce_b64}</Nonce>'
        f'<Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        f'{created}</Created>'
        '</UsernameToken>'
        '</Security>'
        '</s:Header>'
    )


def _onvif_soap(url: str, username: str, password: str, body_xml: str,
                timeout: float = 5.0) -> str:
    """Send a SOAP envelope to an ONVIF endpoint using WS-Security PasswordDigest."""
    security_header = _ws_security_header(username, password) if (username or password) else ""
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl"'
        ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl"'
        ' xmlns:tt="http://www.onvif.org/ver10/schema">'
        f'{security_header}'
        f'<s:Body>{body_xml}</s:Body>'
        '</s:Envelope>'
    )
    data = envelope.encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type": 'application/soap+xml; charset=utf-8',
            "User-Agent": "CamDiscover/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(131072).decode("utf-8", errors="replace")


@dataclass
class OnvifDeviceInfo:
    manufacturer: str = ""
    model: str = ""
    firmware: str = ""
    serial: str = ""
    hardware_id: str = ""
    stream_uris: List[str] = field(default_factory=list)
    error: str = ""


def query_onvif_device_info(ip: str, onvif_url: str = "",
                             username: str = "admin", password: str = "") -> OnvifDeviceInfo:
    """
    Like ODM's device detail panel: fetch manufacturer, model, firmware,
    serial number, and real RTSP stream URIs via ONVIF SOAP calls.
    """
    if not onvif_url:
        onvif_url = f"http://{ip}:8899/onvif/device_service"

    info = OnvifDeviceInfo()

    # ── GetDeviceInformation ─────────────────────────────────────────
    try:
        resp = _onvif_soap(onvif_url, username, password,
                           "<tds:GetDeviceInformation/>")
        def _tag(name: str) -> str:
            m = re.search(rf"<[^>]*{re.escape(name)}[^>]*>([^<]+)<", resp)
            return m.group(1).strip() if m else ""
        info.manufacturer = _tag("Manufacturer")
        info.model        = _tag("Model")
        info.firmware     = _tag("FirmwareVersion")
        info.serial       = _tag("SerialNumber")
        info.hardware_id  = _tag("HardwareId")
    except Exception as e:
        info.error = str(e)
        return info

    # ── GetProfiles + GetStreamUri ────────────────────────────────────
    try:
        media_url = onvif_url.replace("device_service", "media_service")
        # Try common media service paths
        for media_path in (media_url, f"http://{ip}:8899/onvif/media_service",
                           f"http://{ip}:80/onvif/media_service",
                           f"http://{ip}:8080/onvif/media_service"):
            try:
                profiles_resp = _onvif_soap(media_path, username, password,
                                            "<trt:GetProfiles/>")
                tokens = re.findall(r'token="([^"]+)"', profiles_resp)
                for token in tokens[:4]:   # fetch up to 4 profiles
                    try:
                        stream_resp = _onvif_soap(
                            media_path, username, password,
                            f'<trt:GetStreamUri>'
                            f'  <trt:StreamSetup>'
                            f'    <tt:Stream>RTP-Unicast</tt:Stream>'
                            f'    <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>'
                            f'  </trt:StreamSetup>'
                            f'  <trt:ProfileToken>{token}</trt:ProfileToken>'
                            f'</trt:GetStreamUri>',
                        )
                        uri_m = re.search(r"<[^>]*Uri[^>]*>([^<]+)<", stream_resp)
                        if uri_m:
                            uri = uri_m.group(1).strip()
                            if uri.startswith("rtsp://") and uri not in info.stream_uris:
                                info.stream_uris.append(uri)
                    except Exception:
                        pass
                if tokens:
                    break
            except Exception:
                continue
    except Exception:
        pass

    return info


# ─── Dahua / Amcrest UDP Discovery ──────────────────────────────────

# Dahua cameras listen on UDP 37020 for a specific broadcast probe.
# Amcrest is an OEM of Dahua and uses the same protocol.
_DAHUA_PROBE = bytes.fromhex(
    "ff010000"   # magic
    "00000000"   # sequence
    "00000000"   # padding
    "00000000"
)


def send_dahua_probe(interface_ip: str = "", timeout: float = 3.0) -> List[dict]:
    """
    Broadcast Dahua/Amcrest UDP discovery on port 37020 and collect responses.
    Returns list of dicts with keys: ip, mac, sn, name, version.
    """
    found: List[dict] = []
    seen: set = set()
    lock = threading.Lock()

    def _listen(sock: socket.socket):
        sock.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
                ip = addr[0]
                with lock:
                    if ip in seen:
                        continue
                    seen.add(ip)
                info = _parse_dahua_response(data, ip)
                with lock:
                    found.append(info)
            except socket.timeout:
                break
            except Exception:
                continue

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if interface_ip:
            try:
                sock.bind((interface_ip, 0))
            except Exception:
                sock.bind(("", 0))
        else:
            sock.bind(("", 0))

        listener_t = threading.Thread(target=_listen, args=(sock,), daemon=True)
        listener_t.start()

        sock.sendto(_DAHUA_PROBE, ("255.255.255.255", 37020))

        listener_t.join(timeout=timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return found


def _parse_dahua_response(data: bytes, ip: str) -> dict:
    """Parse a Dahua UDP discovery response into a dict."""
    result = {"ip": ip, "mac": "", "sn": "", "name": "", "version": ""}
    try:
        text = data.decode("utf-8", errors="replace")
        # Dahua responses are sometimes XML-like or have ASCII fields
        mac_m = re.search(r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}", text)
        if mac_m:
            result["mac"] = mac_m.group(0).replace("-", ":").lower()
        sn_m = re.search(r"SN[:\s=]+([A-Za-z0-9\-]+)", text)
        if sn_m:
            result["sn"] = sn_m.group(1)
        name_m = re.search(r"Name[:\s=]+([A-Za-z0-9_\-]+)", text)
        if name_m:
            result["name"] = name_m.group(1)
        ver_m = re.search(r"Version[:\s=]+([^\s<&]+)", text)
        if ver_m:
            result["version"] = ver_m.group(1)
    except Exception:
        pass
    return result


# ─── Passive Listener ───────────────────────────────────────────────

class PassiveListener:
    """Listen for ONVIF and SSDP multicast traffic passively."""

    def __init__(self):
        self.running = False
        self._threads: List[threading.Thread] = []
        self._sockets: List[socket.socket] = []
        self.on_onvif: Optional[Callable[[str, str], None]] = None
        self.on_ssdp: Optional[Callable[[str, str], None]] = None
        self.on_dahua: Optional[Callable[[str, bytes], None]] = None

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

        # Dahua/Amcrest listener
        t = threading.Thread(target=self._listen_dahua, args=(interface_ip,), daemon=True)
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

    def _listen_dahua(self, interface_ip: str):
        """Listen for Dahua/Amcrest UDP discovery responses on port 37020."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if interface_ip:
                try:
                    sock.bind((interface_ip, 37020))
                except OSError:
                    sock.bind(("", 37020))
            else:
                sock.bind(("", 37020))
            self._sockets.append(sock)
            sock.settimeout(1.0)
            while self.running:
                try:
                    data, addr = sock.recvfrom(65535)
                    if data and addr[0]:
                        if self.on_dahua:
                            self.on_dahua(addr[0], data)
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
