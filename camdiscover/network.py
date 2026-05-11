"""Network interface detection and low-level network operations for Windows"""

from __future__ import annotations
import ipaddress
import os
import re
import socket
import subprocess
import struct
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class NetworkInterface:
    name: str
    ip: str
    netmask: str
    cidr: str
    mac: str
    iface_type: str  # ethernet | wi-fi | virtual | loopback | unknown
    is_up: bool = True
    gateway: str = ""
    subnet: str = ""

    @property
    def prefix_len(self) -> int:
        try:
            return ipaddress.IPv4Network(f"0.0.0.0/{self.netmask}", strict=False).prefixlen
        except Exception:
            return 24


def get_interfaces() -> List[NetworkInterface]:
    """Get all network interfaces, sorted by priority."""
    interfaces = []

    # Parse route print for gateways
    gateways = {}
    try:
        result = subprocess.run(
            ["route", "print", "-4", "0.0.0.0"],
            capture_output=True, text=True, timeout=10, shell=True
        )
        for m in re.finditer(r"\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)", result.stdout):
            gateways[m.group(3)] = m.group(1)
    except Exception:
        pass

    # Get interfaces via netsh
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "config"],
            capture_output=True, text=True, timeout=10, shell=True
        )
        current_iface = None
        for line in result.stdout.splitlines():
            m = re.match(r'^Configuration for interface "(.+)"', line)
            if m:
                current_iface = m.group(1)
                continue
            if current_iface:
                ip_m = re.match(r"\s+IP Address:\s+(\d+\.\d+\.\d+\.\d+)", line)
                if ip_m:
                    mask_m = re.match(r"\s+Subnet Prefix:\s+\d+\.\d+\.\d+\.\d+/(\d+)", next(
                        (l for l in result.stdout.splitlines()[result.stdout.splitlines().index(line):]), ""
                    ))
    except Exception:
        pass

    # Fallback: use socket + ipconfig
    hostname = socket.gethostname()
    try:
        local_ips = socket.getaddrinfo(hostname, None, socket.AF_INET)
    except Exception:
        local_ips = []

    # Use ipconfig /all for detailed info
    iface_data = {}
    try:
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True, text=True, timeout=10, shell=True
        )
        current_section = None
        for line in result.stdout.splitlines():
            section_m = re.match(r"^[A-Za-z].*adapter (.+):", line)
            if section_m:
                current_section = section_m.group(1)
                iface_data[current_section] = {}
                continue
            if current_section and current_section not in iface_data:
                continue

            ip_m = re.match(r"\s+IPv4 Address[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if ip_m and current_section:
                iface_data.setdefault(current_section, {})["ip"] = ip_m.group(1)

            mask_m = re.match(r"\s+Subnet Mask[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if mask_m and current_section:
                iface_data.setdefault(current_section, {})["netmask"] = mask_m.group(1)

            mac_m = re.match(r"\s+Physical Address[.\s]+:\s+([0-9A-Fa-f-]+)", line)
            if mac_m and current_section:
                iface_data.setdefault(current_section, {})["mac"] = mac_m.group(1).replace("-", ":").lower()

            desc_m = re.match(r"\s+Description[.\s]+:\s+(.+)", line)
            if desc_m and current_section:
                iface_data.setdefault(current_section, {})["description"] = desc_m.group(1)

            dhcp_m = re.match(r"\s+DHCP Enabled[.\s]+:\s+(Yes|No)", line)
            if dhcp_m and current_section:
                iface_data.setdefault(current_section, {})["dhcp"] = dhcp_m.group(1)

            gw_m = re.match(r"\s+Default Gateway[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if gw_m and current_section:
                iface_data.setdefault(current_section, {})["gateway"] = gw_m.group(1)
    except Exception:
        pass

    for name, data in iface_data.items():
        if "ip" not in data:
            continue
        ip = data["ip"]
        netmask = data.get("netmask", "255.255.255.0")
        mac = data.get("mac", "")
        gateway = data.get("gateway", "")
        description = data.get("description", "")

        iface_type = classify_interface(name, description)
        try:
            subnet = str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False).network_address)
        except Exception:
            subnet = "unknown"

        prefix_len = 24
        try:
            prefix_len = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False).prefixlen
        except Exception:
            pass

        interfaces.append(NetworkInterface(
            name=name,
            ip=ip,
            netmask=netmask,
            cidr=f"{ip}/{prefix_len}",
            mac=mac,
            iface_type=iface_type,
            gateway=gateway,
            subnet=subnet,
        ))

    # Sort: ethernet first, then wi-fi, then unknown, virtual last
    type_order = {"ethernet": 0, "wi-fi": 1, "unknown": 2, "virtual": 3, "loopback": 4}
    interfaces.sort(key=lambda i: type_order.get(i.iface_type, 3))
    return interfaces


def classify_interface(name: str, description: str = "") -> str:
    lower = (name + " " + description).lower()
    if "loopback" in lower:
        return "loopback"
    if any(x in lower for x in ["wi-fi", "wireless", "wlan", "802.11"]):
        return "wi-fi"
    if any(x in lower for x in ["ethernet", "eth", "local area", "rj45"]):
        return "ethernet"
    if any(x in lower for x in ["hyper-v", "vmware", "virtual", "vethernet", "docker", "wsl", "vnic", "vpn", "tunnel"]):
        return "virtual"
    return "unknown"


def get_arp_table() -> List[dict]:
    """Parse Windows ARP table."""
    entries = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            # Match both formats:
            #   192.168.1.195         9c-8e-cd-3f-e3-98     dynamic
            #   192.168.1.1           74-24-9f-5d-f0-aa     dynamic   0x15
            m = re.match(
                r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+(\S+)(?:\s+(\S+))?",
                line, re.IGNORECASE
            )
            if m:
                mac = m.group(2).replace("-", ":").lower()
                if mac == "ff:ff:ff:ff:ff:ff" or mac == "00:00:00:00:00:00":
                    continue
                entries.append({
                    "ip": m.group(1),
                    "mac": mac,
                    "type": m.group(3),
                    "iface": m.group(4) or "",
                })
    except Exception:
        pass
    return entries


def ping_host(ip: str, timeout: int = 2000) -> bool:
    """Ping a host. Returns True if reachable."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout // 1000 + 2
        )
        return "TTL=" in result.stdout or "Reply from" in result.stdout
    except Exception:
        return False


def add_temp_ip(interface_name: str, ip: str, netmask: str = "255.255.255.0") -> bool:
    """Add a temporary IP address to an interface (requires admin)."""
    try:
        result = subprocess.run(
            ["netsh", "interface", "ip", "add", "address",
             interface_name, ip, netmask],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def remove_temp_ip(interface_name: str, ip: str) -> bool:
    """Remove a temporary IP address from an interface (requires admin)."""
    try:
        result = subprocess.run(
            ["netsh", "interface", "ip", "delete", "address",
             interface_name, ip],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def ip_to_subnet(ip: str) -> str:
    """Get the /24 subnet for an IP."""
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
