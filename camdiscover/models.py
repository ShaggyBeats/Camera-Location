"""Discovered device data model"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


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
        }
