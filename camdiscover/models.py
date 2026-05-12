"""Discovered device data model + DPI protocol-stage + subnet zone models"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


# ─── DPI Protocol Stages ──────────────────────────────────────────────
# Each stage represents a layer in the camera validation pipeline.
# A device is not "fully validated" until all applicable stages pass.

DPI_STAGES = [
    "link",          # Layer-2 reachability (ARP/ping)
    "dhcp",          # DHCP assignment or static IP confirmed
    "discovery",     # ONVIF/SSDP/mDNS discovery response seen
    "auth",          # Authentication reachable (HTTP/HTTPS login page)
    "rtsp",          # RTSP session can be negotiated
    "onvif_ctrl",    # ONVIF control endpoint reachable
    "ntp",           # NTP time sync port reachable
    "dns",           # DNS resolution working
    "cloud",         # Cloud/P2P egress detected or absent
    "recording",     # Storage/export path reachable (NVR/SMB/FTP)
]

DPI_STAGE_LABELS = {
    "link":       "L2 Reachable",
    "dhcp":       "DHCP/IP Assign",
    "discovery":  "Discovery",
    "auth":       "Auth Reachable",
    "rtsp":       "RTSP Stream",
    "onvif_ctrl": "ONVIF Control",
    "ntp":        "NTP Sync",
    "dns":        "DNS",
    "cloud":      "Cloud Egress",
    "recording":  "Recording Path",
}


@dataclass
class DPIStageResult:
    stage: str
    status: str   # pass | fail | unchecked | na
    detail: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "status": self.status,
            "detail": self.detail,
            "timestamp": self.timestamp.isoformat(),
        }


# ─── Subnet Zone ───────────────────────────────────────────────────────

@dataclass
class SubnetZone:
    subnet: str               # e.g. "192.168.1.0/24"
    label: str = ""           # e.g. "Main Camera LAN"
    gateway: str = ""
    vlan_id: int = 0
    method: str = "auto"      # auto | route | secondary_ip | vlan | direct_nic | manual
    discoverable: bool = True # Whether ONVIF/SSDP discovery crosses into this zone
    dhcp_mode: str = "unknown"# static | dhcp | mixed | unknown
    nvr_access: bool = True
    internet_blocked: bool = True
    credential_profile: str = ""
    notes: str = ""
    added_ips: List[str] = field(default_factory=list)  # temp IPs we added
    routes_added: List[str] = field(default_factory=list)  # static routes we added

    def to_dict(self) -> dict:
        return {
            "subnet": self.subnet,
            "label": self.label,
            "gateway": self.gateway,
            "vlan_id": self.vlan_id,
            "method": self.method,
            "discoverable": self.discoverable,
            "dhcp_mode": self.dhcp_mode,
            "nvr_access": self.nvr_access,
            "internet_blocked": self.internet_blocked,
            "credential_profile": self.credential_profile,
            "notes": self.notes,
        }


# ─── Capture Position ─────────────────────────────────────────────────

CAPTURE_POSITIONS = {
    "wifi":           "Wi-Fi adapter (limited — broadcast/multicast only)",
    "ethernet_same":  "Ethernet same VLAN (unicast + broadcast)",
    "span_port":      "Switch SPAN/mirror port (full visibility)",
    "inline_tap":     "Inline tap between switch and NVR",
    "nvr_capture":    "Capture on NVR interface",
    "unknown":        "Unknown capture position",
}


@dataclass
class CapturePosition:
    position: str = "unknown"  # wifi | ethernet_same | span_port | inline_tap | nvr_capture | unknown
    can_see_unicast: bool = False
    can_see_broadcast: bool = True
    can_see_multicast: bool = True
    can_see_rtsp: bool = False
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "position": self.position,
            "label": CAPTURE_POSITIONS.get(self.position, self.position),
            "can_see_unicast": self.can_see_unicast,
            "can_see_broadcast": self.can_see_broadcast,
            "can_see_multicast": self.can_see_multicast,
            "can_see_rtsp": self.can_see_rtsp,
            "notes": self.notes,
        }


# ─── Discovered Device ────────────────────────────────────────────────

@dataclass
class DiscoveredDevice:
    ip: str
    mac: str = ""
    vendor: str = "Unknown"
    hostname: str = ""
    model: str = ""
    firmware: str = ""
    open_ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    onvif_status: str = "not-checked"  # found | error | not-checked
    rtsp_status: str = "not-checked"
    web_url: str = ""
    rtsp_url: str = ""
    onvif_url: str = ""
    subnet: str = ""
    confidence: int = 0
    discovery_methods: List[str] = field(default_factory=list)
    last_seen: datetime = field(default_factory=datetime.now)
    raw_responses: Dict[str, str] = field(default_factory=dict)

    # DPI protocol-stage results
    dpi_stages: Dict[str, DPIStageResult] = field(default_factory=dict)
    # Which subnet zone this device belongs to
    subnet_zone: str = ""

    @property
    def dpi_score(self) -> int:
        """0-100 based on how many DPI stages pass."""
        if not self.dpi_stages:
            return 0
        applicable = {k: v for k, v in self.dpi_stages.items() if v.status != "na"}
        if not applicable:
            return 0
        passed = sum(1 for v in applicable.values() if v.status == "pass")
        return round((passed / len(applicable)) * 100)

    @property
    def dpi_summary(self) -> str:
        """Human-readable DPI stage summary."""
        if not self.dpi_stages:
            return "No DPI validation performed"
        parts = []
        for stage in DPI_STAGES:
            result = self.dpi_stages.get(stage)
            if result and result.status != "na":
                icon = "+" if result.status == "pass" else ("-" if result.status == "fail" else "?")
                parts.append(f"{icon}{stage}")
        return " ".join(parts) if parts else "No DPI stages checked"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "model": self.model,
            "firmware": self.firmware,
            "open_ports": self.open_ports,
            "protocols": self.protocols,
            "onvif_status": self.onvif_status,
            "rtsp_status": self.rtsp_status,
            "web_url": self.web_url,
            "rtsp_url": self.rtsp_url,
            "onvif_url": self.onvif_url,
            "subnet": self.subnet,
            "confidence": self.confidence,
            "discovery_methods": self.discovery_methods,
            "last_seen": self.last_seen.isoformat(),
            "dpi_stages": {k: v.to_dict() for k, v in self.dpi_stages.items()},
            "dpi_score": self.dpi_score,
            "dpi_summary": self.dpi_summary,
            "subnet_zone": self.subnet_zone,
        }
