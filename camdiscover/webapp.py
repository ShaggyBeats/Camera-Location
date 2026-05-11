"""Flask web server + SSE API for Camera Discovery Octopus"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from typing import Dict, List

from flask import Flask, render_template, jsonify, request, Response, send_file

from .orchestrator import DiscoveryOrchestrator
from .models import DiscoveredDevice
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

    orchestrator.on_progress = on_progress
    orchestrator.on_device_found = on_device
    orchestrator.on_device_updated = on_device_updated

    # ─── Routes ───────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html")

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
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        export_to_csv(orchestrator.discovered_devices, path)
        return send_file(path, as_attachment=True, download_name="camera-discovery.csv")

    @app.route("/api/export/json")
    def api_export_json():
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        export_to_json(orchestrator.discovered_devices, path)
        return send_file(path, as_attachment=True, download_name="camera-discovery.json")

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

    return app
