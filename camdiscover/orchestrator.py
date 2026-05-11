"""Discovery orchestrator — coordinates all discovery modes"""

from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from . import ALL_CAMERA_PORTS, CAMERA_SUBNETS, DISCOVERY_MODES
from .discovery import (
    OnvifDevice, SsdpDevice, RtspResult,
    send_onvif_probe, send_ssdp_search,
    scan_ports, grab_http_banner, probe_rtsp,
    PassiveListener,
)
from .models import DiscoveredDevice
from .network import (
    NetworkInterface, get_interfaces, get_arp_table,
    ping_host, add_temp_ip, remove_temp_ip, ip_to_subnet,
)
from .vendor import lookup_vendor, fingerprint_device


@dataclass
class DiscoveryProgress:
    phase: str
    current: int
    total: int
    message: str


class DiscoveryOrchestrator:
    """Coordinates camera discovery across multiple modes and protocols."""

    def __init__(self):
        self.devices: Dict[str, DiscoveredDevice] = {}
        self.selected_interface: Optional[NetworkInterface] = None
        self._stopping = False
        self._passive_listener: Optional[PassiveListener] = None
        self.on_progress: Optional[Callable[[DiscoveryProgress], None]] = None
        self.on_device_found: Optional[Callable[[DiscoveredDevice], None]] = None
        self.on_device_updated: Optional[Callable[[DiscoveredDevice], None]] = None

    @property
    def discovered_devices(self) -> List[DiscoveredDevice]:
        return list(self.devices.values())

    def _emit_progress(self, phase: str, current: int, total: int, message: str):
        if self.on_progress:
            self.on_progress(DiscoveryProgress(phase, current, total, message))

    def _emit_device(self, device: DiscoveredDevice):
        if self.on_device_found:
            self.on_device_found(device)

    def _emit_device_updated(self, device: DiscoveredDevice):
        if self.on_device_updated:
            self.on_device_updated(device)

    def _get_or_create(self, ip: str, method: str = "") -> DiscoveredDevice:
        if ip not in self.devices:
            device = DiscoveredDevice(ip=ip)
            if method:
                device.discovery_methods.append(method)
            self.devices[ip] = device
            self._emit_device(device)
        return self.devices[ip]

    def select_interface(self, name: str = "") -> List[NetworkInterface]:
        interfaces = get_interfaces()
        usable = [i for i in interfaces if i.iface_type not in ("virtual", "loopback")]
        if not usable:
            usable = interfaces

        if name:
            match = next((i for i in usable if i.name == name), None)
            if match:
                self.selected_interface = match
        elif usable:
            self.selected_interface = usable[0]

        return usable

    def set_interface(self, iface: NetworkInterface):
        self.selected_interface = iface

    def stop(self):
        self._stopping = True
        if self._passive_listener:
            self._passive_listener.stop()

    def run(self, mode: str, subnets: List[str] = None) -> List[DiscoveredDevice]:
        self._stopping = False
        self.devices.clear()

        self._emit_progress("init", 0, 5, f"Starting {mode} discovery...")

        if mode == "listen":
            self._run_listen_mode()
        elif mode == "dhcp-trap":
            self._run_dhcp_trap_mode()
        elif mode == "sweep":
            self._run_sweep_mode(subnets)
        elif mode == "fingerprint":
            self._run_fingerprint_mode()
        elif mode == "report":
            pass  # report just exports existing data

        return self.discovered_devices

    # ─── Mode 1: Listen-only ──────────────────────────────────────────

    def _run_listen_mode(self):
        iface_ip = self.selected_interface.ip if self.selected_interface else ""

        self._emit_progress("listen", 1, 5, "Collecting ARP entries...")
        self._collect_arp_entries()

        self._emit_progress("listen", 2, 5, "Sending ONVIF probe...")
        onvif_devices = send_onvif_probe(iface_ip)
        self._merge_onvif_devices(onvif_devices)

        self._emit_progress("listen", 3, 5, "Searching SSDP/UPnP...")
        ssdp_devices = send_ssdp_search(iface_ip)
        self._merge_ssdp_devices(ssdp_devices)

        self._emit_progress("listen", 4, 5, "Refreshing ARP table...")
        self._collect_arp_entries()

        self._emit_progress("listen", 5, 5, "Passive scan complete")

    # ─── Mode 2: DHCP Trap ────────────────────────────────────────────

    def _run_dhcp_trap_mode(self):
        iface_ip = self.selected_interface.ip if self.selected_interface else ""

        self._emit_progress("dhcp-trap", 1, 6, "Starting passive listener...")
        self._passive_listener = PassiveListener()
        self._passive_listener.on_onvif = lambda ip, data: self._merge_from_passive(ip, "ONVIF", data)
        self._passive_listener.on_ssdp = lambda ip, data: self._merge_from_passive(ip, "SSDP", data)
        self._passive_listener.start(iface_ip)

        self._emit_progress("dhcp-trap", 2, 6, "Sending active probes...")
        onvif_devices = send_onvif_probe(iface_ip)
        self._merge_onvif_devices(onvif_devices)

        ssdp_devices = send_ssdp_search(iface_ip)
        self._merge_ssdp_devices(ssdp_devices)

        self._collect_arp_entries()

        self._emit_progress("dhcp-trap", 3, 6, "Waiting for DHCP clients (30s)...")
        for i in range(30):
            if self._stopping:
                break
            time.sleep(1)

        self._emit_progress("dhcp-trap", 4, 6, "Re-checking ARP table...")
        self._collect_arp_entries()

        if self._passive_listener:
            self._passive_listener.stop()

        self._emit_progress("dhcp-trap", 6, 6, "DHCP trap scan complete")

    # ─── Mode 3: Active Sweep ─────────────────────────────────────────

    def _run_sweep_mode(self, custom_subnets: List[str] = None):
        subnets = custom_subnets or CAMERA_SUBNETS
        iface_ip = self.selected_interface.ip if self.selected_interface else ""
        iface_name = self.selected_interface.name if self.selected_interface else "Ethernet"

        self._emit_progress("sweep", 1, 7, "Starting active sweep...")

        # Add temporary IPs on common subnets
        self._emit_progress("sweep", 2, 7, "Adding temporary subnet IPs...")
        added_ips: List[str] = []
        if iface_ip:
            for subnet in subnets:
                base = ".".join(subnet.split(".")[:3])
                temp_ip = f"{base}.100"
                if temp_ip != iface_ip:
                    if add_temp_ip(iface_name, temp_ip):
                        added_ips.append(temp_ip)

        # Ping sweep
        self._emit_progress("sweep", 3, 7, "Running ping sweep...")
        active_ips = self._ping_sweep(subnets)

        # ARP collection
        self._emit_progress("sweep", 4, 7, "Collecting ARP entries...")
        self._collect_arp_entries()

        # ONVIF + SSDP
        self._emit_progress("sweep", 5, 7, "Probing ONVIF/SSDP...")
        onvif_devices = send_onvif_probe(iface_ip)
        self._merge_onvif_devices(onvif_devices)
        ssdp_devices = send_ssdp_search(iface_ip)
        self._merge_ssdp_devices(ssdp_devices)

        # Port scan active IPs
        self._emit_progress("sweep", 6, 7, "Scanning camera ports...")
        all_ips = list(set(active_ips + list(self.devices.keys())))
        for i, ip in enumerate(all_ips):
            if self._stopping:
                break
            self._emit_progress("sweep", 6, 7, f"Scanning {ip} ({i+1}/{len(all_ips)})...")
            self._scan_and_fingerprint(ip)

        # Cleanup
        self._emit_progress("sweep", 7, 7, "Cleaning up temporary IPs...")
        for ip in added_ips:
            remove_temp_ip(iface_name, ip)

        self._emit_progress("sweep", 7, 7, "Active sweep complete")

    # ─── Mode 4: Vendor Fingerprint ───────────────────────────────────

    def _run_fingerprint_mode(self):
        self._emit_progress("fingerprint", 1, 3, "Discovering devices (listen mode)...")

        # First discover
        self._run_listen_mode()

        # Then fingerprint each
        ips = list(self.devices.keys())
        self._emit_progress("fingerprint", 2, 3, f"Fingerprinting {len(ips)} device(s)...")

        for i, ip in enumerate(ips):
            if self._stopping:
                break
            self._emit_progress("fingerprint", 2, 3, f"Fingerprinting {ip} ({i+1}/{len(ips)})...")
            self._scan_and_fingerprint(ip)

        self._emit_progress("fingerprint", 3, 3, "Fingerprint complete")

    # ─── Helpers ──────────────────────────────────────────────────────

    def _collect_arp_entries(self):
        entries = get_arp_table()
        for entry in entries:
            ip = entry["ip"]
            mac = entry["mac"]
            if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue
            if ip.startswith(("224.", "239.")):
                continue

            device = self._get_or_create(ip, "ARP")
            if not device.mac and mac:
                device.mac = mac
                device.vendor = lookup_vendor(mac)
            if "ARP" not in device.discovery_methods:
                device.discovery_methods.append("ARP")
            device.last_seen = __import__("datetime").datetime.now()
            self._emit_device_updated(device)

    def _merge_onvif_devices(self, onvif_devices: List[OnvifDevice]):
        for od in onvif_devices:
            device = self._get_or_create(od.ip, "ONVIF")
            device.onvif_status = "found"
            if "ONVIF" not in device.protocols:
                device.protocols.append("ONVIF")
            if od.xaddrs:
                device.onvif_url = od.xaddrs[0]
            if od.model:
                device.model = od.model
            if od.manufacturer and device.vendor == "Unknown":
                device.vendor = od.manufacturer
            device.raw_responses["onvif"] = od.raw_response
            if "ONVIF" not in device.discovery_methods:
                device.discovery_methods.append("ONVIF")
            device.last_seen = __import__("datetime").datetime.now()
            self._emit_device_updated(device)

    def _merge_ssdp_devices(self, ssdp_devices: List[SsdpDevice]):
        for sd in ssdp_devices:
            device = self._get_or_create(sd.ip, "SSDP")
            if "SSDP/UPnP" not in device.protocols:
                device.protocols.append("SSDP/UPnP")
            if sd.location:
                device.web_url = sd.location
            if sd.server and device.vendor == "Unknown":
                server_lower = sd.server.lower()
                if "hikvision" in server_lower:
                    device.vendor = "Hikvision"
                elif "dahua" in server_lower:
                    device.vendor = "Dahua/Amcrest"
                elif "axis" in server_lower:
                    device.vendor = "Axis"
            device.raw_responses["ssdp"] = str(sd.__dict__)
            if "SSDP" not in device.discovery_methods:
                device.discovery_methods.append("SSDP")
            device.last_seen = __import__("datetime").datetime.now()
            self._emit_device_updated(device)

    def _merge_from_passive(self, ip: str, method: str, data: str):
        device = self._get_or_create(ip, method)
        if method not in device.discovery_methods:
            device.discovery_methods.append(method)
        device.last_seen = __import__("datetime").datetime.now()
        device.raw_responses[method.lower()] = data
        self._emit_device_updated(device)

    def _ping_sweep(self, subnets: List[str]) -> List[str]:
        active_ips: List[str] = []

        for subnet in subnets:
            if self._stopping:
                break
            base = ".".join(subnet.split(".")[:3])
            self._emit_progress("sweep", 3, 7, f"Pinging {base}.0/24...")

            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {}
                for i in range(1, 255):
                    ip = f"{base}.{i}"
                    futures[executor.submit(ping_host, ip, 1000)] = ip

                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        if future.result():
                            active_ips.append(ip)
                            self._get_or_create(ip, "Ping")
                    except Exception:
                        pass

        return active_ips

    def _scan_and_fingerprint(self, ip: str):
        device = self._get_or_create(ip)

        # Port scan
        if not device.open_ports:
            device.open_ports = scan_ports(ip)

        # HTTP banner
        http_banner = ""
        if 80 in device.open_ports:
            http_banner = grab_http_banner(ip, 80)
        elif 8080 in device.open_ports:
            http_banner = grab_http_banner(ip, 8080)

        # RTSP probe
        if 554 in device.open_ports:
            rtsp_result = probe_rtsp(ip, 554)
            device.rtsp_status = "found" if rtsp_result.found else "error"
            if rtsp_result.found:
                device.rtsp_url = f"rtsp://{ip}:554/"
                if "RTSP" not in device.protocols:
                    device.protocols.append("RTSP")

        # ONVIF URL
        if device.onvif_status == "not-checked" and 8899 in device.open_ports:
            device.onvif_status = "found"
            device.onvif_url = f"http://{ip}:8899/onvif/device_service"
            if "ONVIF" not in device.protocols:
                device.protocols.append("ONVIF")

        # Construct web URL
        if not device.web_url:
            if 80 in device.open_ports:
                device.web_url = f"http://{ip}/"
            elif 8080 in device.open_ports:
                device.web_url = f"http://{ip}:8080/"
            elif 443 in device.open_ports:
                device.web_url = f"https://{ip}/"

        # Fingerprint
        onvif_response = device.raw_responses.get("onvif", "")
        fp = fingerprint_device(device.mac, device.open_ports, http_banner, onvif_response)
        if fp.vendor and fp.vendor != "Unknown":
            device.vendor = fp.vendor
        if fp.model:
            device.model = fp.model
        device.confidence = fp.confidence
        for proto in fp.protocols:
            if proto not in device.protocols:
                device.protocols.append(proto)

        # Subnet
        device.subnet = ip_to_subnet(ip)
        device.last_seen = __import__("datetime").datetime.now()

        self._emit_device_updated(device)
