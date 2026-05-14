"""Flask web server + SSE API for Camera Discovery Octopus"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from typing import Dict, List

import ipaddress
import urllib.request
import urllib.error

from flask import Flask, render_template, jsonify, request, Response, send_file

from .orchestrator import DiscoveryOrchestrator
from .models import DiscoveredDevice, SubnetZone, CapturePosition, CAPTURE_POSITIONS, DPI_STAGES, DPI_STAGE_LABELS
from .network import NetworkInterface, get_interfaces
from .report import export_to_csv, export_to_json, generate_summary


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
    )

    # Global state
    orchestrator = DiscoveryOrchestrator()
    devices_lock = threading.Lock()
    scan_thread: threading.Thread | None = None
    scan_running = False
    scan_progress = {"phase": "idle", "current": 0, "total": 0, "message": "Ready"}
    event_subscribers: list = []

    def emit_event(event_type: str, data: dict):
        """Push an event to all SSE subscribers."""
        payload = json.dumps({"type": event_type, "data": data, "timestamp": datetime.now().isoformat()})
        dead = []
        for i, queue in enumerate(event_subscribers):
            try:
                queue.put_nowait(payload)
            except Exception:
                dead.append(i)
        for i in reversed(dead):
            event_subscribers.pop(i)

    def on_progress(p):
        nonlocal scan_progress
        scan_progress = {"phase": p.phase, "current": p.current, "total": p.total, "message": p.message}
        emit_event("progress", scan_progress)

    def on_device(device: DiscoveredDevice):
        emit_event("device_found", device.to_dict())

    def on_device_updated(device: DiscoveredDevice):
        emit_event("device_updated", device.to_dict())

    def on_subnet_found(sniffed):
        emit_event("subnet_sniffed", {
            "subnet": sniffed.subnet,
            "first_seen_ip": sniffed.first_seen_ip,
            "source": sniffed.source,
        })

    orchestrator.on_progress = on_progress
    orchestrator.on_device_found = on_device
    orchestrator.on_device_updated = on_device_updated
    orchestrator.on_subnet_found = on_subnet_found

    # ─── Routes ───────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/favicon.ico")
    def favicon():
        return Response(status=204)

    @app.route("/api/interfaces")
    def api_interfaces():
        interfaces = get_interfaces()
        return jsonify([{
            "name": i.name,
            "ip": i.ip,
            "netmask": i.netmask,
            "mac": i.mac,
            "iface_type": i.iface_type,
            "gateway": i.gateway,
            "subnet": i.subnet,
        } for i in interfaces])

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        nonlocal scan_thread, scan_running
        if scan_running:
            return jsonify({"error": "Scan already running"}), 409

        body = request.json or {}
        mode = body.get("mode", "listen")
        interface_name = body.get("interface", "")
        subnets = body.get("subnets", None)

        # Select interface
        interfaces = orchestrator.select_interface(interface_name)
        if interface_name:
            match = next((i for i in interfaces if i.name == interface_name), None)
            if match:
                orchestrator.set_interface(match)
        elif interfaces:
            best = next((i for i in interfaces if i.iface_type == "ethernet"), interfaces[0])
            orchestrator.set_interface(best)

        scan_running = True

        def run_scan():
            nonlocal scan_running
            try:
                orchestrator.run(mode, subnets)
            except Exception as e:
                emit_event("error", {"message": str(e)})
            finally:
                scan_running = False
                emit_event("scan_complete", {"device_count": len(orchestrator.discovered_devices)})

        scan_thread = threading.Thread(target=run_scan, daemon=True)
        scan_thread.start()

        return jsonify({"status": "started", "mode": mode})

    @app.route("/api/scan/stop", methods=["POST"])
    def api_scan_stop():
        orchestrator.stop()
        return jsonify({"status": "stopping"})

    @app.route("/api/devices")
    def api_devices():
        with devices_lock:
            return jsonify([d.to_dict() for d in orchestrator.discovered_devices])

    @app.route("/api/status")
    def api_status():
        return jsonify({
            "scanning": scan_running,
            "progress": scan_progress,
            "device_count": len(orchestrator.discovered_devices),
            "interface": orchestrator.selected_interface.name if orchestrator.selected_interface else None,
        })

    @app.route("/api/export/csv")
    def api_export_csv():
        import csv, io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "IP", "MAC", "Vendor", "Model", "Hostname", "Ports",
            "ONVIF", "RTSP", "Web URL", "RTSP URL", "ONVIF URL",
            "Subnet", "Subnet Zone", "Confidence", "DPI Score",
            "DPI Summary", "Discovery Methods", "Last Seen",
        ])
        for d in orchestrator.discovered_devices:
            writer.writerow([
                d.ip, d.mac, d.vendor, d.model, d.hostname,
                ";".join(str(p) for p in d.open_ports),
                d.onvif_status, d.rtsp_status,
                d.web_url, d.rtsp_url, d.onvif_url,
                d.subnet, d.subnet_zone, d.confidence, d.dpi_score,
                d.dpi_summary,
                ";".join(d.discovery_methods),
                d.last_seen.isoformat(),
            ])
        return Response(output.getvalue(), mimetype="text/csv", headers={
            "Content-Disposition": "attachment; filename=camera-discovery.csv"
        })

    @app.route("/api/export/json")
    def api_export_json():
        import json as _json, io
        data = [d.to_dict() for d in orchestrator.discovered_devices]
        output = io.BytesIO(_json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"))
        return send_file(output, as_attachment=True, download_name="camera-discovery.json",
                         mimetype="application/json")

    @app.route("/api/events")
    def api_events():
        """Server-Sent Events endpoint for live updates."""
        import queue
        q = queue.Queue(maxsize=100)
        event_subscribers.append(q)

        def generate():
            try:
                while True:
                    try:
                        data = q.get(timeout=30)
                        yield f"data: {data}\n\n"
                    except queue.Empty:
                        yield ": heartbeat\n\n"
            except GeneratorExit:
                if q in event_subscribers:
                    event_subscribers.remove(q)

        return Response(generate(), mimetype="text/event-stream", headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        })

    # ─── Subnet Zone APIs ─────────────────────────────────────────────

    @app.route("/api/subnets", methods=["GET"])
    def api_subnets_list():
        return jsonify([z.to_dict() for z in orchestrator.subnet_zones.values()])

    @app.route("/api/subnets", methods=["POST"])
    def api_subnets_add():
        body = request.json or {}
        zone = SubnetZone(
            subnet=body.get("subnet", ""),
            label=body.get("label", ""),
            gateway=body.get("gateway", ""),
            vlan_id=body.get("vlan_id", 0),
            method=body.get("method", "auto"),
            discoverable=body.get("discoverable", True),
            dhcp_mode=body.get("dhcp_mode", "unknown"),
            nvr_access=body.get("nvr_access", True),
            internet_blocked=body.get("internet_blocked", True),
            credential_profile=body.get("credential_profile", ""),
            notes=body.get("notes", ""),
        )
        if not zone.subnet:
            return jsonify({"error": "subnet is required"}), 400
        success = orchestrator.add_subnet_zone(zone)
        emit_event("subnet_added", zone.to_dict())
        return jsonify({"success": success, "zone": zone.to_dict()})

    @app.route("/api/subnets/<path:subnet>", methods=["DELETE"])
    def api_subnets_delete(subnet):
        success = orchestrator.remove_subnet_zone(subnet)
        emit_event("subnet_removed", {"subnet": subnet})
        return jsonify({"success": success})

    @app.route("/api/subnets/<path:subnet>/probe", methods=["POST"])
    def api_subnets_probe(subnet):
        result = orchestrator.probe_subnet_zone(subnet)
        return jsonify(result)

    @app.route("/api/routes")
    def api_routes():
        from .network import get_routes as _get_routes
        return jsonify(_get_routes())

    # ─── Capture Position APIs ────────────────────────────────────────

    @app.route("/api/capture-position", methods=["GET"])
    def api_capture_position_get():
        return jsonify(orchestrator.capture_position.to_dict())

    @app.route("/api/capture-position", methods=["POST"])
    def api_capture_position_set():
        body = request.json or {}
        position = body.get("position", "unknown")
        orchestrator.set_capture_position(position)
        emit_event("capture_position_changed", orchestrator.capture_position.to_dict())
        return jsonify(orchestrator.capture_position.to_dict())

    @app.route("/api/capture-positions")
    def api_capture_positions_list():
        return jsonify([{"id": k, "label": v} for k, v in CAPTURE_POSITIONS.items()])

    # ─── DPI APIs ─────────────────────────────────────────────────────

    @app.route("/api/dpi/stages")
    def api_dpi_stages():
        return jsonify([{"id": s, "label": DPI_STAGE_LABELS.get(s, s)} for s in DPI_STAGES])

    @app.route("/api/dpi/validate/<ip>")
    def api_dpi_validate(ip):
        if ip not in orchestrator.devices:
            return jsonify({"error": "Device not found"}), 404
        orchestrator._validate_dpi_stages(ip)
        device = orchestrator.devices[ip]
        return jsonify({
            "ip": ip,
            "dpi_stages": {k: v.to_dict() for k, v in device.dpi_stages.items()},
            "dpi_score": device.dpi_score,
            "dpi_summary": device.dpi_summary,
        })

    # ─── Subnet Watch ────────────────────────────────────────────────

    @app.route("/api/subnet-watch/start", methods=["POST"])
    def api_subnet_watch_start():
        interfaces = orchestrator.select_interface()
        if interfaces and not orchestrator.selected_interface:
            best = next((i for i in interfaces if i.iface_type == "ethernet"), interfaces[0])
            orchestrator.set_interface(best)
        orchestrator.start_subnet_watch()
        return jsonify({"status": "watching"})

    @app.route("/api/subnet-watch/stop", methods=["POST"])
    def api_subnet_watch_stop():
        orchestrator.stop_subnet_watch()
        return jsonify({"status": "stopped"})

    @app.route("/api/subnet-watch/status")
    def api_subnet_watch_status():
        return jsonify({
            "active": orchestrator._watch_active,
            "known_subnets": list(orchestrator._sniffer._known) if orchestrator._sniffer else [],
        })

    # ─── ONVIF Device Info ────────────────────────────────────────────

    @app.route("/api/devices/<ip>/onvif-info")
    def api_onvif_info(ip):
        device = orchestrator.devices.get(ip)
        username = request.args.get("user", "admin")
        password = request.args.get("pass", "")
        onvif_url = (device.onvif_url if device else "") or f"http://{ip}:8899/onvif/device_service"
        from .discovery import query_onvif_device_info
        info = query_onvif_device_info(ip, onvif_url, username, password)
        return jsonify({
            "manufacturer": info.manufacturer,
            "model": info.model,
            "firmware": info.firmware,
            "serial": info.serial,
            "hardware_id": info.hardware_id,
            "stream_uris": info.stream_uris,
            "error": info.error,
        })

    # ─── Snapshot Proxy ───────────────────────────────────────────────

    @app.route("/api/devices/<ip>/snapshot")
    def api_snapshot(ip):
        """Proxy a JPEG snapshot from the camera, trying vendor-specific URLs."""
        device = orchestrator.devices.get(ip)
        vendor = (device.vendor if device else "").lower()
        open_ports = device.open_ports if device else []
        username = request.args.get("user", "admin")
        password = request.args.get("pass", "")

        http_port = 80
        for p in (80, 8080, 443):
            if not open_ports or p in open_ports:
                http_port = p
                break

        scheme = "https" if http_port == 443 else "http"
        base = f"{scheme}://{ip}:{http_port}"

        candidate_paths = []
        if "hikvision" in vendor:
            candidate_paths = [
                "/ISAPI/Streaming/channels/101/picture",
                "/onvif-http/snapshot?Profile_1",
                "/Streaming/channels/1/picture",
            ]
        elif "dahua" in vendor or "amcrest" in vendor:
            candidate_paths = [
                "/cgi-bin/snapshot.cgi",
                "/cgi-bin/snapshot.cgi?channel=1",
                "/cgi-bin/mjpg/video.cgi?channel=0&subtype=1",
            ]
        elif "axis" in vendor:
            candidate_paths = ["/axis-cgi/jpg/image.cgi"]
        elif "reolink" in vendor:
            candidate_paths = ["/cgi-bin/api.cgi?cmd=Snap&channel=0&rs=abc"]
        elif "hanwha" in vendor or "wisenet" in vendor:
            candidate_paths = ["/cgi-bin/viewer/video.jpg"]

        candidate_paths += [
            "/snapshot.jpg", "/snap.jpg", "/image.jpg",
            "/cgi-bin/snapshot.cgi", "/jpg/image.jpg",
            "/tmpfs/auto.jpg", "/onvif/snapshot",
        ]

        for path in candidate_paths:
            url = base + path
            try:
                mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                if password:
                    mgr.add_password(None, url, username, password)
                handler = urllib.request.HTTPDigestAuthHandler(mgr)
                basic = urllib.request.HTTPBasicAuthHandler(mgr)
                opener = urllib.request.build_opener(handler, basic)
                req = urllib.request.Request(url, headers={"User-Agent": "CamDiscover/1.0"})
                with opener.open(req, timeout=4) as resp:
                    ct = resp.headers.get_content_type() or ""
                    data = resp.read(1_000_000)
                    if data[:2] == b"\xff\xd8" or "image" in ct:
                        return Response(data, mimetype="image/jpeg", headers={
                            "X-Snapshot-URL": url,
                            "Cache-Control": "no-store",
                        })
            except Exception:
                continue

        return jsonify({"error": "No snapshot available from this device"}), 404

    # ─── Set IP ───────────────────────────────────────────────────────

    @app.route("/api/devices/<ip>/set-ip", methods=["POST"])
    def api_set_ip(ip):
        """Change a camera's IP address via ONVIF or vendor API."""
        body = request.json or {}
        new_ip = body.get("new_ip", "").strip()
        netmask = body.get("netmask", "255.255.255.0").strip()
        gateway = body.get("gateway", "").strip()
        username = body.get("username", "admin")
        password = body.get("password", "")

        if not new_ip:
            return jsonify({"error": "new_ip is required"}), 400
        try:
            ipaddress.IPv4Address(new_ip)
        except ValueError:
            return jsonify({"error": f"Invalid IP: {new_ip}"}), 400

        device = orchestrator.devices.get(ip)
        vendor = (device.vendor if device else "").lower()
        result = {"ip": ip, "new_ip": new_ip, "success": False, "methods_tried": [], "message": ""}

        # Compute prefix length from netmask
        try:
            prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{netmask}", strict=False).prefixlen
        except Exception:
            prefix_len = 24

        # 1. Try ONVIF
        onvif_url = (device.onvif_url if device else "") or f"http://{ip}:8899/onvif/device_service"
        try:
            ok, msg = _set_ip_onvif(onvif_url, username, password, new_ip, prefix_len, gateway)
            result["methods_tried"].append("onvif")
            if ok:
                result["success"] = True
                result["method"] = "onvif"
                result["message"] = msg
        except Exception as e:
            result["onvif_error"] = str(e)

        # 2. Try Hikvision ISAPI
        if not result["success"] and "hikvision" in vendor:
            try:
                ok, msg = _set_ip_hikvision(ip, username, password, new_ip, netmask, gateway)
                result["methods_tried"].append("hikvision")
                if ok:
                    result["success"] = True
                    result["method"] = "hikvision"
                    result["message"] = msg
            except Exception as e:
                result["hikvision_error"] = str(e)

        # 3. Try Dahua CGI
        if not result["success"] and any(v in vendor for v in ("dahua", "amcrest")):
            try:
                ok, msg = _set_ip_dahua(ip, username, password, new_ip, netmask, gateway)
                result["methods_tried"].append("dahua")
                if ok:
                    result["success"] = True
                    result["method"] = "dahua"
                    result["message"] = msg
            except Exception as e:
                result["dahua_error"] = str(e)

        if not result["success"] and not result["message"]:
            result["message"] = "Could not change IP — check credentials and that the camera is reachable"

        return jsonify(result)

    @app.route("/api/dpi/checklist")
    def api_dpi_checklist():
        """DPI checklist reference for the UI."""
        return jsonify([
            {"layer": "DHCP", "what": "Cameras requesting IPs, DHCP offers, lease renewals",
             "missing": "Static cameras, wrong VLAN, DHCP not reaching camera subnet",
             "filter": "bootp or udp.port == 67 or udp.port == 68"},
            {"layer": "ARP", "what": "Camera MACs asking for gateway/NVR/camera peers",
             "missing": "Devices online but not visible in app, duplicate IPs, wrong gateway",
             "filter": "arp"},
            {"layer": "ONVIF Discovery", "what": "WS-Discovery probes/responses for cameras",
             "missing": "App/NVR can't auto-discover cameras",
             "filter": "udp.port == 3702"},
            {"layer": "RTSP Video", "what": "NVR pulling video streams from cameras",
             "missing": "Camera added but no video, wrong credentials, blocked stream",
             "filter": "tcp.port == 554 or udp.port == 554"},
            {"layer": "HTTP/HTTPS Admin", "what": "Web login, config pages, ISAPI/API calls",
             "missing": "Camera reachable by ping but not configurable",
             "filter": "tcp.port == 80 or tcp.port == 443 or tcp.port == 8080"},
            {"layer": "Vendor SDK Ports", "what": "Hikvision/Dahua proprietary control channels",
             "missing": "App works only with vendor tool, not ONVIF",
             "filter": "tcp.port == 8000 or tcp.port == 37777 or tcp.port == 5000"},
            {"layer": "Time Sync", "what": "Cameras/NVR syncing to NTP",
             "missing": "Wrong timestamps, evidence unusable, recording mismatch",
             "filter": "udp.port == 123"},
            {"layer": "DNS", "what": "NVR/cloud lookup, DDNS, update checks",
             "missing": "Remote app fails, cloud/P2P fails, suspicious callouts",
             "filter": "udp.port == 53 or tcp.port == 53"},
            {"layer": "Cloud/P2P", "what": "Outbound connections from NVR/cameras",
             "missing": "Unknown vendor cloud dependency or unwanted egress",
             "filter": "ip.addr == <camera_ip> and !(ip.addr == <nvr_ip>)"},
            {"layer": "Storage/Export", "what": "NAS, SMB, FTP, email alerts",
             "missing": "Recordings not saving/exporting",
             "filter": "tcp.port == 445 or tcp.port == 21 or tcp.port == 25 or tcp.port == 587"},
            {"layer": "UPnP/Port Mapping", "what": "Router/NVR trying to open external ports",
             "missing": "Hidden exposure to internet",
             "filter": "udp.port == 1900"},
        ])

    return app


# ─── IP Change Helpers ────────────────────────────────────────────────────

def _onvif_request(url: str, username: str, password: str, body_xml: str) -> str:
    """Send a SOAP request to an ONVIF endpoint using WS-Security PasswordDigest."""
    from .discovery import _ws_security_header
    security_header = _ws_security_header(username, password) if (username or password) else ""
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl"'
        ' xmlns:tt="http://www.onvif.org/ver10/schema">'
        f'{security_header}'
        f'<s:Body>{body_xml}</s:Body>'
        '</s:Envelope>'
    )
    data = envelope.encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/soap+xml; charset=utf-8", "User-Agent": "CamDiscover/1.0"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read(65536).decode("utf-8", errors="replace")


def _set_ip_onvif(onvif_url: str, username: str, password: str,
                  new_ip: str, prefix_len: int, gateway: str) -> tuple:
    body = (
        '<tds:SetNetworkInterfaces>'
        '  <tds:InterfaceToken>eth0</tds:InterfaceToken>'
        '  <tds:NetworkInterface>'
        '    <tt:IPv4><tt:Enabled>true</tt:Enabled>'
        f'   <tt:Manual><tt:Address>{new_ip}</tt:Address>'
        f'   <tt:PrefixLength>{prefix_len}</tt:PrefixLength></tt:Manual>'
        '    <tt:DHCP>false</tt:DHCP>'
        '    </tt:IPv4>'
        '  </tds:NetworkInterface>'
        '</tds:SetNetworkInterfaces>'
    )
    resp = _onvif_request(onvif_url, username, password, body)
    if "SetNetworkInterfacesResponse" in resp or "RebootNeeded" in resp:
        return True, f"ONVIF accepted — camera may reboot and reappear at {new_ip}"
    if "fault" in resp.lower() or "Fault" in resp:
        import re
        reason = re.search(r"<[^>]*[Tt]ext[^>]*>([^<]+)<", resp)
        return False, f"ONVIF fault: {reason.group(1) if reason else resp[:200]}"
    return False, "ONVIF: unexpected response"


def _set_ip_hikvision(ip: str, username: str, password: str,
                      new_ip: str, netmask: str, gateway: str) -> tuple:
    xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<NetworkInterface version="2.0">'
        f'<id>1</id>'
        f'<IPAddress><ipVersion>v4</ipVersion><addressingType>static</addressingType>'
        f'<ipAddress>{new_ip}</ipAddress><subnetMask>{netmask}</subnetMask>'
        f'<DefaultGateway><ipAddress>{gateway}</ipAddress></DefaultGateway>'
        f'</IPAddress></NetworkInterface>'
    )
    url = f"http://{ip}/ISAPI/System/Network/interfaces/1"
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, url, username, password)
    opener = urllib.request.build_opener(
        urllib.request.HTTPDigestAuthHandler(mgr),
        urllib.request.HTTPBasicAuthHandler(mgr),
    )
    req = urllib.request.Request(url, data=xml.encode(), method="PUT",
                                 headers={"Content-Type": "application/xml", "User-Agent": "CamDiscover/1.0"})
    with opener.open(req, timeout=5) as resp:
        body = resp.read(4096).decode("utf-8", errors="replace")
        if resp.status in (200, 201) or "OK" in body or "statusCode>200" in body:
            return True, f"Hikvision ISAPI accepted — camera will use {new_ip}"
        return False, f"Hikvision returned {resp.status}: {body[:200]}"


def _set_ip_dahua(ip: str, username: str, password: str,
                  new_ip: str, netmask: str, gateway: str) -> tuple:
    url = (
        f"http://{ip}/cgi-bin/configManager.cgi?action=setConfig"
        f"&Network.Interface[0].IPAddress={new_ip}"
        f"&Network.Interface[0].SubnetMask={netmask}"
        f"&Network.Interface[0].DefaultGateway={gateway}"
        f"&Network.Interface[0].DhcpEnable=false"
    )
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, url, username, password)
    opener = urllib.request.build_opener(
        urllib.request.HTTPDigestAuthHandler(mgr),
        urllib.request.HTTPBasicAuthHandler(mgr),
    )
    req = urllib.request.Request(url, headers={"User-Agent": "CamDiscover/1.0"})
    with opener.open(req, timeout=5) as resp:
        body = resp.read(4096).decode("utf-8", errors="replace")
        if "OK" in body or resp.status == 200:
            return True, f"Dahua CGI accepted — camera will use {new_ip}"
        return False, f"Dahua returned {resp.status}: {body[:200]}"
