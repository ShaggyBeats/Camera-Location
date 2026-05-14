"""Discovery orchestrator — coordinates all discovery modes including DPI validation"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from . import ALL_CAMERA_PORTS, CAMERA_SUBNETS, DISCOVERY_MODES
from .discovery import (
    OnvifDevice, SsdpDevice, RtspResult,
    send_onvif_probe, send_ssdp_search,
    scan_ports, grab_http_banner, probe_rtsp,
    PassiveListener, query_onvif_device_info,
    send_dahua_probe,
)
from .models import DiscoveredDevice, DPIStageResult, DPI_STAGES, SubnetZone, CapturePosition, CAPTURE_POSITIONS
from .network import (
    NetworkInterface, get_interfaces, get_arp_table,
    ping_host, add_temp_ip, remove_temp_ip, ip_to_subnet,
    add_static_route, remove_static_route,
    add_secondary_ip, remove_secondary_ip,
    test_tcp_port, probe_subnet_connectivity, get_routes,
    discover_local_subnets, SubnetSniffer, SniffedSubnet,
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
        self.on_subnet_found: Optional[Callable[[SniffedSubnet], None]] = None

        # Subnet zone management
        self.subnet_zones: Dict[str, SubnetZone] = {}
        self.capture_position: CapturePosition = CapturePosition()

        # Subnet sniffer (Wireshark-inspired: detect from traffic, not config)
        self._sniffer: Optional[SubnetSniffer] = None
        self._watch_active = False

        # Auto-detect capture position from interface type
        self._auto_detect_capture_position()

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

    # ─── Mode dispatch ────────────────────────────────────────────────

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
        elif mode == "dpi":
            self._run_dpi_mode()
        elif mode == "report":
            pass  # report just exports existing data

        return self.discovered_devices

    # ─── Mode 1: Listen-only ──────────────────────────────────────────

    def _run_listen_mode(self):
        iface_ip = self.selected_interface.ip if self.selected_interface else ""
        all_iface_ips = [ip for ip in
                         (self.selected_interface.all_ips if self.selected_interface else [iface_ip])
                         if ip and not ip.startswith("169.254")]
        if not all_iface_ips:
            all_iface_ips = [iface_ip] if iface_ip else []

        # ── Step 1: Locate ──────────────────────────────────────────────
        # ARP table (instant) + active probes in parallel
        self._emit_progress("listen", 1, 3, "Locating devices (ARP + ONVIF/SSDP/Dahua)...")
        self._collect_arp_entries()
        self._probe_all_protocols(all_iface_ips)
        self._collect_arp_entries()

        # ── Step 2: Sniff ───────────────────────────────────────────────
        # Brief passive sniff — catch anything broadcasting that ARP missed
        self._emit_progress("listen", 2, 3, "Sniffing for additional subnets (5s)...")
        self._passive_sniff(iface_ip, duration=5)

        # ── Step 3: Port check ──────────────────────────────────────────
        ips = list(self.devices.keys())
        self._emit_progress("listen", 3, 3, f"Checking ports on {len(ips)} device(s)...")
        self._fingerprint_all_concurrent(ips, phase="listen")

        self._emit_progress("listen", 3, 3, "Scan complete")

    def _passive_sniff(self, iface_ip: str, duration: float = 5.0):
        """Run SubnetSniffer for a fixed window, collect ARP on anything new."""
        new_subnets: List[str] = []
        lock = threading.Lock()

        sniffer = SubnetSniffer()
        # Seed with /24 subnets (normalize IPs to their /24 CIDR)
        known_ips = list(self.devices.keys())
        ip_subnets = [ip_to_subnet(ip) for ip in known_ips if ip]
        sniffer.seed(ip_subnets)
        sniffer.seed(discover_local_subnets())

        def _on_new(sniffed: SniffedSubnet):
            with lock:
                new_subnets.append(sniffed.subnet)
            self._get_or_create(sniffed.first_seen_ip, "Sniff")

        sniffer.on_new_subnet = _on_new
        sniffer.start(iface_ip)
        time.sleep(duration)
        sniffer.stop()

        if new_subnets:
            self._collect_arp_entries()

    def _probe_all_protocols(self, iface_ips: List[str], timeout: float = 2.0):
        """Run ONVIF, SSDP, and Dahua probes concurrently across all interface IPs."""
        from .discovery import send_onvif_probe, send_ssdp_search, send_dahua_probe
        tasks = []
        for ip in iface_ips:
            tasks.append(('onvif', ip))
            tasks.append(('ssdp', ip))
            tasks.append(('dahua', ip))

        def run_task(task):
            kind, ip = task
            if self._stopping:
                return
            try:
                if kind == 'onvif':
                    self._merge_onvif_devices(send_onvif_probe(ip, timeout=timeout))
                elif kind == 'ssdp':
                    self._merge_ssdp_devices(send_ssdp_search(ip, timeout=timeout))
                elif kind == 'dahua':
                    self._merge_dahua_devices(send_dahua_probe(ip, timeout=timeout))
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=max(len(tasks), 1)) as ex:
            list(as_completed({ex.submit(run_task, t): t for t in tasks}))

    def _fingerprint_all_concurrent(self, ips: List[str], phase: str = "verify", max_workers: int = 20):
        total = len(ips)
        done = [0]
        lock = threading.Lock()

        def do_one(ip):
            if self._stopping:
                return
            self._scan_and_fingerprint(ip)
            with lock:
                done[0] += 1
                self._emit_progress(phase, done[0], total, f"Verified {ip} ({done[0]}/{total})")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(as_completed({executor.submit(do_one, ip): ip for ip in ips}))

    # ─── Mode 2: DHCP Trap ────────────────────────────────────────────

    def _run_dhcp_trap_mode(self):
        iface_ip = self.selected_interface.ip if self.selected_interface else ""
        all_iface_ips = [ip for ip in
                         (self.selected_interface.all_ips if self.selected_interface else [iface_ip])
                         if ip and not ip.startswith("169.254")]

        # ── Step 1: Locate ──────────────────────────────────────────────
        self._emit_progress("dhcp-trap", 1, 3, "Locating devices (ARP + ONVIF/SSDP/Dahua)...")
        self._collect_arp_entries()
        self._probe_all_protocols(all_iface_ips)
        self._collect_arp_entries()

        # ── Step 2: Sniff — watch for new devices announcing themselves ─
        wait = 20
        sniffer = SubnetSniffer()
        sniffer.seed(discover_local_subnets())
        sniffer.on_new_subnet = lambda s: self._get_or_create(s.first_seen_ip, "Sniff")
        sniffer.start(iface_ip)
        for i in range(wait):
            if self._stopping:
                break
            remaining = wait - i
            self._emit_progress("dhcp-trap", 2, 3, f"Sniffing for new devices... {remaining}s")
            time.sleep(1)
        sniffer.stop()
        self._collect_arp_entries()

        # ── Step 3: Port check ──────────────────────────────────────────
        ips = list(self.devices.keys())
        self._emit_progress("dhcp-trap", 3, 3, f"Checking ports on {len(ips)} device(s)...")
        self._fingerprint_all_concurrent(ips, phase="dhcp-trap")
        self._emit_progress("dhcp-trap", 3, 3, "DHCP trap scan complete")

    # ─── Mode 3: Active Sweep ─────────────────────────────────────────

    def _run_sweep_mode(self, custom_subnets: List[str] = None):
        if custom_subnets:
            subnets = custom_subnets
        else:
            auto = discover_local_subnets()
            subnets = auto if auto else CAMERA_SUBNETS

        iface_ip = self.selected_interface.ip if self.selected_interface else ""
        iface_name = self.selected_interface.name if self.selected_interface else "Ethernet"

        self._emit_progress("sweep", 1, 7, f"Starting active sweep on {len(subnets)} subnet(s)...")

        # Add temporary IPs on common subnets
        self._emit_progress("sweep", 2, 7, "Adding temporary subnet IPs...")
        added_ips: List[str] = []
        if iface_ip:
            for subnet in subnets:
                base = ".".join(subnet.split(".")[:3])
                for candidate in (".100", ".200"):
                    temp_ip = f"{base}{candidate}"
                    if temp_ip != iface_ip and temp_ip not in added_ips:
                        if add_temp_ip(iface_name, temp_ip):
                            added_ips.append(temp_ip)
                            break

        # Ping sweep
        self._emit_progress("sweep", 3, 7, "Running ping sweep...")
        active_ips = self._ping_sweep(subnets)

        # ARP collection
        self._emit_progress("sweep", 4, 7, "Collecting ARP entries...")
        self._collect_arp_entries()

        # ONVIF + SSDP + Dahua (parallel)
        self._emit_progress("sweep", 5, 7, "Probing ONVIF/SSDP/Dahua (parallel)...")
        all_iface_ips = [ip for ip in
                         (self.selected_interface.all_ips if self.selected_interface else [iface_ip])
                         if ip and not ip.startswith("169.254")]
        self._probe_all_protocols(all_iface_ips)

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

        # Then fingerprint each (skip devices already fingerprinted by listen mode)
        ips = [ip for ip in self.devices if not self.devices[ip].open_ports]
        self._emit_progress("fingerprint", 2, 3, f"Fingerprinting {len(ips)} remaining device(s)...")

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
                if device.vendor == "Unknown":
                    device.vendor = lookup_vendor(mac)
            if "ARP" not in device.discovery_methods:
                device.discovery_methods.append("ARP")
            device.last_seen = _dt.datetime.now()
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
            device.last_seen = _dt.datetime.now()
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
            device.last_seen = _dt.datetime.now()
            self._emit_device_updated(device)

    def _merge_dahua_devices(self, dahua_devices: List[dict]):
        for dd in dahua_devices:
            ip = dd.get("ip", "")
            if not ip:
                continue
            device = self._get_or_create(ip, "Dahua-UDP")
            if "Dahua-UDP" not in device.discovery_methods:
                device.discovery_methods.append("Dahua-UDP")
            if dd.get("mac") and not device.mac:
                device.mac = dd["mac"]
                device.vendor = lookup_vendor(dd["mac"]) or "Dahua/Amcrest"
            if device.vendor == "Unknown":
                device.vendor = "Dahua/Amcrest"
            if dd.get("name") and not device.model:
                device.model = dd["name"]
            device.raw_responses["dahua_udp"] = str(dd)
            device.last_seen = _dt.datetime.now()
            self._emit_device_updated(device)

    def _merge_from_passive(self, ip: str, method: str, data: str):
        device = self._get_or_create(ip, method)
        if method not in device.discovery_methods:
            device.discovery_methods.append(method)
        device.last_seen = _dt.datetime.now()
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

        # ONVIF device info (ODM-style: get real model/firmware/stream URIs)
        if device.onvif_status == "found" and device.onvif_url:
            try:
                info = query_onvif_device_info(ip, device.onvif_url)
                if not info.error:
                    if info.manufacturer and device.vendor in ("Unknown", ""):
                        device.vendor = info.manufacturer
                    if info.model:
                        device.model = info.model
                    if info.firmware:
                        device.firmware = info.firmware
                    if info.serial:
                        device.raw_responses["onvif_serial"] = info.serial
                    # Prefer ONVIF-provided stream URIs over guessed ones
                    if info.stream_uris:
                        device.rtsp_url = info.stream_uris[0]
                        device.raw_responses["onvif_streams"] = "\n".join(info.stream_uris)
                        device.rtsp_status = "found"
                        if "RTSP" not in device.protocols:
                            device.protocols.append("RTSP")
            except Exception:
                pass

        # Subnet
        device.subnet = ip_to_subnet(ip)
        device.last_seen = _dt.datetime.now()

        self._emit_device_updated(device)

    # ─── Subnet Watch (Wireshark-inspired) ───────────────────────────
    # Any subnet we observe in live traffic gets automatically configured
    # and scanned — no user intervention required.

    def start_subnet_watch(self):
        """Start background sniffer that detects and auto-scans new subnets."""
        if self._watch_active:
            return
        self._watch_active = True
        self._sniffer = SubnetSniffer()

        # Seed with subnets we already know so they don't fire as "new"
        seeds = list(self.subnet_zones.keys())
        if self.selected_interface:
            seeds.append(ip_to_subnet(self.selected_interface.ip))
        for s in discover_local_subnets():
            seeds.append(s)
        self._sniffer.seed(seeds)

        def _on_new(sniffed: SniffedSubnet):
            self._emit_progress(
                "watch", 0, 0,
                f"New subnet sniffed: {sniffed.subnet} (via {sniffed.source}, first IP {sniffed.first_seen_ip})"
            )
            if self.on_subnet_found:
                self.on_subnet_found(sniffed)
            # Auto-configure access and scan in a background thread
            zone = SubnetZone(subnet=sniffed.subnet, label=f"Auto ({sniffed.source})", method="auto")
            self.add_subnet_zone(zone)
            threading.Thread(target=self._auto_scan_subnet, args=(sniffed.subnet,), daemon=True).start()

        self._sniffer.on_new_subnet = _on_new
        self._sniffer.start(self.selected_interface.ip if self.selected_interface else "")

    def stop_subnet_watch(self):
        self._watch_active = False
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None

    def _auto_scan_subnet(self, subnet: str):
        """Quick-scan a freshly discovered subnet for cameras."""
        base = ".".join(subnet.split(".")[:3])
        self._emit_progress("auto-scan", 0, 3, f"Auto-scanning {subnet}...")

        # Ping sweep
        active: List[str] = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(ping_host, f"{base}.{i}", 500): f"{base}.{i}"
                for i in range(1, 255)
            }
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        active.append(ip)
                        self._get_or_create(ip, "Ping")
                except Exception:
                    pass

        self._emit_progress("auto-scan", 1, 3,
                            f"Found {len(active)} host(s) in {subnet}, verifying...")

        # ARP + ONVIF/SSDP/Dahua (parallel)
        self._collect_arp_entries()
        iface_ip = self.selected_interface.ip if self.selected_interface else ""
        all_iface_ips = [ip for ip in
                         (self.selected_interface.all_ips if self.selected_interface else [iface_ip])
                         if ip and not ip.startswith("169.254")]
        self._probe_all_protocols(all_iface_ips)

        # Port scan + fingerprint
        all_ips = list({*active, *[ip for ip in self.devices if ip.startswith(base + ".")]})
        self._fingerprint_all_concurrent(all_ips, phase="auto-scan")
        self._emit_progress("auto-scan", 3, 3, f"Auto-scan of {subnet} complete")

    # ─── Mode 5: DPI Validation ───────────────────────────────────────

    def _run_dpi_mode(self):
        """Run DPI protocol-stage validation on all discovered devices."""
        # First discover
        self._run_fingerprint_mode()

        if self._stopping:
            return

        # Then validate each device's DPI stages
        ips = list(self.devices.keys())
        self._emit_progress("dpi", 1, 3, f"Running DPI validation on {len(ips)} device(s)...")

        for i, ip in enumerate(ips):
            if self._stopping:
                break
            self._emit_progress("dpi", 2, 3, f"DPI validating {ip} ({i+1}/{len(ips)})...")
            self._validate_dpi_stages(ip)

        self._emit_progress("dpi", 3, 3, "DPI validation complete")

    def _validate_dpi_stages(self, ip: str):
        """Run all DPI protocol-stage checks for a device."""
        device = self._get_or_create(ip)
        now = __import__("datetime").datetime.now

        # Stage 1: Link (L2 reachability)
        reachable = ping_host(ip, 1500)
        device.dpi_stages["link"] = DPIStageResult(
            stage="link",
            status="pass" if reachable else "fail",
            detail="ICMP reply received" if reachable else "No ICMP reply",
            timestamp=now(),
        )

        # Stage 2: DHCP/IP assignment
        # If we have ARP entry, IP is assigned (static or DHCP)
        arp_ok = bool(device.mac) and device.mac != ""
        device.dpi_stages["dhcp"] = DPIStageResult(
            stage="dhcp",
            status="pass" if arp_ok else "unchecked",
            detail=f"MAC resolved: {device.mac}" if arp_ok else "No ARP entry",
            timestamp=now(),
        )

        # Stage 3: Discovery (ONVIF/SSDP)
        discovery_ok = device.onvif_status == "found" or "SSDP" in device.discovery_methods
        methods = ", ".join(device.discovery_methods) if device.discovery_methods else "none"
        device.dpi_stages["discovery"] = DPIStageResult(
            stage="discovery",
            status="pass" if discovery_ok else "fail",
            detail=f"Methods: {methods}",
            timestamp=now(),
        )

        # Stage 4: Auth (HTTP/HTTPS admin)
        auth_ok = bool(device.web_url) and (80 in device.open_ports or 443 in device.open_ports or 8080 in device.open_ports)
        device.dpi_stages["auth"] = DPIStageResult(
            stage="auth",
            status="pass" if auth_ok else "fail",
            detail=device.web_url or "No web URL",
            timestamp=now(),
        )

        # Stage 5: RTSP
        if device.rtsp_status == "found":
            device.dpi_stages["rtsp"] = DPIStageResult(
                stage="rtsp", status="pass",
                detail=device.rtsp_url or "RTSP responding",
                timestamp=now(),
            )
        elif 554 in device.open_ports:
            device.dpi_stages["rtsp"] = DPIStageResult(
                stage="rtsp", status="fail",
                detail="Port 554 open but RTSP negotiation failed",
                timestamp=now(),
            )
        else:
            device.dpi_stages["rtsp"] = DPIStageResult(
                stage="rtsp", status="na",
                detail="No RTSP port detected",
                timestamp=now(),
            )

        # Stage 6: ONVIF Control
        if device.onvif_status == "found":
            device.dpi_stages["onvif_ctrl"] = DPIStageResult(
                stage="onvif_ctrl", status="pass",
                detail=device.onvif_url or "ONVIF endpoint found",
                timestamp=now(),
            )
        elif 8899 in device.open_ports or 3702 in device.open_ports:
            device.dpi_stages["onvif_ctrl"] = DPIStageResult(
                stage="onvif_ctrl", status="fail",
                detail="ONVIF ports open but no response",
                timestamp=now(),
            )
        else:
            device.dpi_stages["onvif_ctrl"] = DPIStageResult(
                stage="onvif_ctrl", status="na",
                detail="No ONVIF ports detected",
                timestamp=now(),
            )

        # Stage 7: NTP — UDP protocol, cannot reliably check via TCP
        if reachable:
            ntp_ok = test_tcp_port(ip, 123, 1.0)
            device.dpi_stages["ntp"] = DPIStageResult(
                stage="ntp",
                status="pass" if ntp_ok else "na",
                detail="TCP 123 reachable (may not be NTP — NTP uses UDP)" if ntp_ok else "NTP uses UDP 123 — cannot verify via TCP from this position",
                timestamp=now(),
            )
        else:
            device.dpi_stages["ntp"] = DPIStageResult(
                stage="ntp", status="na",
                detail="Device not reachable, NTP check skipped",
                timestamp=now(),
            )

        # Stage 8: DNS — requires capture at gateway to verify camera DNS queries
        device.dpi_stages["dns"] = DPIStageResult(
            stage="dns",
            status="na",
            detail="DNS check requires capture position at gateway (cannot verify from endpoint)",
            timestamp=now(),
        )

        # Stage 9: Cloud egress
        device.dpi_stages["cloud"] = DPIStageResult(
            stage="cloud",
            status="na",
            detail="Cloud/P2P egress requires capture at network egress point",
            timestamp=now(),
        )

        # Stage 10: Recording path — cameras don't run SMB/FTP servers;
        # these ports would be on the NVR, not the camera
        device.dpi_stages["recording"] = DPIStageResult(
            stage="recording",
            status="na",
            detail="Recording path must be verified at NVR/storage side, not from camera endpoint",
            timestamp=now(),
        )

        # Assign subnet zone
        device.subnet_zone = self._find_subnet_zone(ip)

        device.last_seen = now()
        self._emit_device_updated(device)

    # ─── Subnet Zone Management ───────────────────────────────────────

    def add_subnet_zone(self, zone: SubnetZone) -> bool:
        """Add a subnet zone and make it reachable."""
        self.subnet_zones[zone.subnet] = zone

        # Try to make subnet reachable based on method
        if zone.method == "route" and zone.gateway:
            success = add_static_route(zone.subnet, zone.gateway)
            if success:
                zone.routes_added.append(f"{zone.subnet} via {zone.gateway}")
            return success

        elif zone.method == "secondary_ip" and self.selected_interface:
            base = ".".join(zone.subnet.split(".")[:3])
            temp_ip = f"{base}.100"
            success = add_secondary_ip(self.selected_interface.name, temp_ip)
            if success:
                zone.added_ips.append(temp_ip)
            return success

        elif zone.method == "auto":
            # Try secondary IP first, then route
            if self.selected_interface:
                base = ".".join(zone.subnet.split(".")[:3])
                temp_ip = f"{base}.100"
                if add_secondary_ip(self.selected_interface.name, temp_ip):
                    zone.added_ips.append(temp_ip)
                    zone.method = "secondary_ip"
                    return True

            # Try default gateway for route
            if self.selected_interface and self.selected_interface.gateway:
                if add_static_route(zone.subnet, self.selected_interface.gateway):
                    zone.routes_added.append(f"{zone.subnet} via {self.selected_interface.gateway}")
                    zone.method = "route"
                    return True

        return True  # Zone added even if we can't make it reachable yet

    def remove_subnet_zone(self, subnet: str) -> bool:
        """Remove a subnet zone and clean up any added IPs/routes."""
        zone = self.subnet_zones.pop(subnet, None)
        if not zone:
            return False

        # Clean up added IPs
        if self.selected_interface:
            for ip in zone.added_ips:
                remove_secondary_ip(self.selected_interface.name, ip)

        # Clean up added routes
        for route_spec in zone.routes_added:
            parts = route_spec.split(" via ")
            if len(parts) == 2:
                remove_static_route(parts[0].strip(), parts[1].strip())

        return True

    def cleanup_all_zones(self):
        """Remove all subnet zones and clean up."""
        for subnet in list(self.subnet_zones.keys()):
            self.remove_subnet_zone(subnet)

    def probe_subnet_zone(self, subnet: str) -> dict:
        """Probe a subnet zone for connectivity."""
        return probe_subnet_connectivity(subnet)

    def _find_subnet_zone(self, ip: str) -> str:
        """Find which subnet zone an IP belongs to."""
        subnet = ip_to_subnet(ip)
        if subnet in self.subnet_zones:
            zone = self.subnet_zones[subnet]
            return zone.label or zone.subnet
        return subnet

    # ─── Capture Position ─────────────────────────────────────────────

    def _auto_detect_capture_position(self):
        """Auto-detect capture position from interface type."""
        interfaces = get_interfaces()
        ethernet = [i for i in interfaces if i.iface_type == "ethernet"]
        wifi = [i for i in interfaces if i.iface_type == "wi-fi"]

        if ethernet:
            self.capture_position = CapturePosition(
                position="ethernet_same",
                can_see_unicast=True,
                can_see_broadcast=True,
                can_see_multicast=True,
                can_see_rtsp=True,
            )
        elif wifi:
            self.capture_position = CapturePosition(
                position="wifi",
                can_see_unicast=False,
                can_see_broadcast=True,
                can_see_multicast=True,
                can_see_rtsp=False,
                notes="Wi-Fi capture: cannot see unicast camera-to-NVR traffic",
            )

    def set_capture_position(self, position: str):
        """Manually set the capture position."""
        presets = {
            "wifi": CapturePosition(position="wifi", can_see_unicast=False, can_see_broadcast=True, can_see_multicast=True, can_see_rtsp=False, notes="Wi-Fi capture: limited visibility"),
            "ethernet_same": CapturePosition(position="ethernet_same", can_see_unicast=True, can_see_broadcast=True, can_see_multicast=True, can_see_rtsp=True),
            "span_port": CapturePosition(position="span_port", can_see_unicast=True, can_see_broadcast=True, can_see_multicast=True, can_see_rtsp=True, notes="Full visibility via SPAN/mirror port"),
            "inline_tap": CapturePosition(position="inline_tap", can_see_unicast=True, can_see_broadcast=True, can_see_multicast=True, can_see_rtsp=True, notes="Full visibility via inline tap"),
            "nvr_capture": CapturePosition(position="nvr_capture", can_see_unicast=True, can_see_broadcast=True, can_see_multicast=True, can_see_rtsp=True, notes="Capture at NVR interface"),
        }
        self.capture_position = presets.get(position, CapturePosition(position=position))
