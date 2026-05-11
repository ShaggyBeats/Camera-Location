#!/usr/bin/env python3
"""
Camera Discovery Octopus — CLI entry point

Usage:
    camera-discover scan                          # Listen-only mode (default)
    camera-discover scan --mode sweep             # Active subnet scan
    camera-discover scan --mode fingerprint       # Full vendor fingerprint
    camera-discover scan --mode dhcp-trap         # DHCP trap mode
    camera-discover scan --no-dashboard           # CLI only (no TUI)
    camera-discover interfaces                    # List network interfaces
    camera-discover ports                         # Show camera port reference
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from typing import List

from . import __version__, CAMERA_PORTS, DISCOVERY_MODES
from .models import DiscoveredDevice
from .orchestrator import DiscoveryOrchestrator
from .network import NetworkInterface
from .report import export_to_csv, export_to_json, generate_summary


def main():
    parser = argparse.ArgumentParser(
        prog="camera-discover",
        description="Camera Discovery Octopus — vendor-agnostic IP camera discovery tool",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run camera discovery scan")
    scan_parser.add_argument(
        "-m", "--mode",
        choices=list(DISCOVERY_MODES.keys()),
        default="listen",
        help="Discovery mode (default: listen)",
    )
    scan_parser.add_argument("-i", "--interface", help="Network interface name to use")
    scan_parser.add_argument("-s", "--subnet", help="Custom subnet(s), comma-separated")
    scan_parser.add_argument("-o", "--output", help="Output file (.csv or .json)")
    scan_parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Run without TUI dashboard (CLI mode only)",
    )

    # interfaces command
    subparsers.add_parser("interfaces", help="List available network interfaces")

    # ports command
    subparsers.add_parser("ports", help="Show camera port reference")

    # web command
    web_parser = subparsers.add_parser("web", help="Launch web dashboard UI")
    web_parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    web_parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args)
    elif args.command == "interfaces":
        show_interfaces()
    elif args.command == "ports":
        show_ports()
    elif args.command == "web":
        run_web(args)
    else:
        show_help()


def run_scan(args):
    """Execute a camera discovery scan."""
    mode = args.mode

    orchestrator = DiscoveryOrchestrator()
    interfaces = orchestrator.select_interface(args.interface)

    if not interfaces:
        print_error("No usable network interfaces found. Check your network connection.")
        sys.exit(1)

    # Select interface
    if args.interface:
        match = next((i for i in interfaces if i.name == args.interface), None)
        if match:
            orchestrator.set_interface(match)
        else:
            print_error(f'Interface "{args.interface}" not found.')
            print("Available interfaces:")
            for i in interfaces:
                print(f"  {i.name} ({i.ip}) — {i.iface_type}")
            sys.exit(1)
    else:
        best = next((i for i in interfaces if i.iface_type == "ethernet"), interfaces[0])
        orchestrator.set_interface(best)
        print_info(f"Auto-selected interface: {best.name} ({best.ip})")

    subnets = args.subnet.split(",") if args.subnet else None

    if not args.no_dashboard:
        # Try TUI dashboard
        try:
            from .dashboard import Dashboard
            dashboard = Dashboard(orchestrator)
            selected_iface = next(
                (i for i in interfaces if i.name == (args.interface or interfaces[0].name)),
                interfaces[0]
            )
            dashboard.set_interface(selected_iface)
            dashboard.run(mode)
            return
        except Exception as e:
            print_info(f"Dashboard unavailable ({e}), falling back to CLI mode.")

    # CLI mode
    run_cli_mode(orchestrator, mode, subnets, args.output)


def run_cli_mode(
    orchestrator: DiscoveryOrchestrator,
    mode: str,
    subnets: List[str] = None,
    output_file: str = None,
):
    """Run discovery in CLI mode (no TUI)."""
    print()
    print_header(f"  Camera Discovery Octopus — {DISCOVERY_MODES.get(mode, mode)}")
    print()

    def on_progress(p):
        print(f"\r  [{p.phase}] {p.message}          ", end="", flush=True)

    def on_device(device: DiscoveredDevice):
        print()
        print_success(f"  Found: {device.ip} — {device.vendor} {f'({device.mac})' if device.mac else ''}")

    orchestrator.on_progress = on_progress
    orchestrator.on_device_found = on_device

    try:
        devices = orchestrator.run(mode, subnets)

        # Clear progress line
        print("\r" + " " * 80 + "\r", end="")

        print_header(f"\n  ── Results: {len(devices)} device(s) found ──\n")

        if not devices:
            print_warning("  No cameras discovered. Try:")
            print("    • Use --mode sweep for active subnet scanning")
            print("    • Check that cameras are powered and connected")
            print("    • Try a different network interface with --interface")
            print()
            return

        # Print device table
        for d in devices:
            score_str = color_confidence(d.confidence)
            print(f"  {d.ip:<16} {d.mac or '---':<18} {d.vendor:<20} {score_str}")

            if d.model:
                print(f"  {'':16} Model: {d.model}")
            if d.open_ports:
                print(f"  {'':16} Ports: {', '.join(str(p) for p in d.open_ports)}")
            if d.web_url:
                print_info(f"  {'':16} Web:   {d.web_url}")
            if d.rtsp_url:
                print_info(f"  {'':16} RTSP:  {d.rtsp_url}")
            if d.onvif_url:
                print_info(f"  {'':16} ONVIF: {d.onvif_url}")
            print()

        # Export
        if output_file:
            if output_file.endswith(".json"):
                export_to_json(devices, output_file)
            else:
                export_to_csv(devices, output_file)
            print_success(f"  Exported to: {output_file}")
        else:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            csv_file = f"camera-discovery-{timestamp}.csv"
            export_to_csv(devices, csv_file)
            print_success(f"  Auto-exported to: {csv_file}")

        # Summary
        print(generate_summary(devices))

    except KeyboardInterrupt:
        orchestrator.stop()
        print_warning("\n  Scan interrupted by user.")
    except Exception as e:
        print_error(f"\n  Error: {e}")
        sys.exit(1)


def show_interfaces():
    """List available network interfaces."""
    from .network import get_interfaces

    interfaces = get_interfaces()
    type_icons = {
        "ethernet": "  ",
        "wi-fi": "  ",
        "virtual": "  ",
        "loopback": "  ",
        "unknown": "  ",
    }

    print_header("\n  Network Interfaces:\n")
    for i in interfaces:
        icon = type_icons.get(i.iface_type, "  ")
        print(f"  {icon} {i.name}")
        print(f"     IP: {i.ip}  MAC: {i.mac or 'N/A'}  Type: {i.iface_type}")
        print(f"     Subnet: {i.subnet}  Gateway: {i.gateway or 'none'}")
        print()


def show_ports():
    """Show camera port reference."""
    print_header("\n  Camera Port Reference:\n")
    for port, desc in sorted(CAMERA_PORTS.items()):
        print(f"  {port:>5}  {desc}")
    print()


def run_web(args):
    """Launch the web dashboard UI."""
    from .webapp import create_app

    app = create_app()
    host = args.host
    port = args.port

    print_header(f"\n  Camera Discovery Octopus — Web UI")
    print_info(f"  Launching at http://{host}:{port}")
    print(f"  Press Ctrl+C to stop\n")

    app.run(host=host, port=port, debug=False, threaded=True)


def show_help():
    """Show main help with mode info."""
    print_header("\n  Camera Discovery Octopus\n")
    print("  Vendor-agnostic IP camera discovery tool\n")
    print("  Modes:")
    for key, desc in DISCOVERY_MODES.items():
        print(f"    {key:<14} {desc}")
    print()
    print("  Quick start:")
    print("    camera-discover scan                          # Listen-only mode")
    print("    camera-discover scan --mode sweep             # Active subnet scan")
    print("    camera-discover scan --mode fingerprint       # Full vendor fingerprint")
    print("    camera-discover scan --mode dhcp-trap         # DHCP trap (30s wait)")
    print("    camera-discover scan --no-dashboard           # CLI only (no TUI)")
    print("    camera-discover web                           # Launch web dashboard")
    print("    camera-discover web --port 8080               # Web UI on custom port")
    print("    camera-discover interfaces                    # Show network interfaces")
    print("    camera-discover ports                         # Show camera port reference")
    print()


# ─── Output helpers ──────────────────────────────────────────────────

def color_confidence(confidence: int) -> str:
    if confidence >= 70:
        return f"\033[32m{confidence}%\033[0m"
    elif confidence >= 40:
        return f"\033[33m{confidence}%\033[0m"
    else:
        return f"\033[90m{confidence}%\033[0m"


def print_header(text: str):
    print(f"\033[36m\033[1m{text}\033[0m")


def print_success(text: str):
    print(f"\033[32m{text}\033[0m")


def print_info(text: str):
    print(f"\033[34m{text}\033[0m")


def print_warning(text: str):
    print(f"\033[33m{text}\033[0m")


def print_error(text: str):
    print(f"\033[31m{text}\033[0m")
