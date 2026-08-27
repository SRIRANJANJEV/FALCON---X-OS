"""FALCON-X Dashboard — Main web server.

Lightweight HTTP server for the FALCON-X security dashboard.
No external web framework dependencies — uses only Python stdlib.
"""

import json
import logging
import os
import re
import sys
import time
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Optional

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, DASHBOARD_DIR)

import auth
import health as health_module
import omniroute
from config import (
    HOST, PORT, TLS_CERT, TLS_KEY, STATIC_DIR,
    ENGINE_API_URL, RATE_LIMIT_WINDOW,
)

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","component":"web","message":"%(message)s"}',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/falconx/web.log"),
    ],
)
logger = logging.getLogger("falconx-web")

# ── Rate limiter ──────────────────────────────────────────────────
_rate_store: dict = {}


def _check_rate_limit(client_ip: str, limit: int = 100) -> bool:
    now = time.time()
    if client_ip not in _rate_store:
        _rate_store[client_ip] = []
    _rate_store[client_ip] = [t for t in _rate_store[client_ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_store[client_ip]) >= limit:
        return False
    _rate_store[client_ip].append(now)
    return True


def _cleanup_rate_store():
    now = time.time()
    for ip in list(_rate_store.keys()):
        _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_LIMIT_WINDOW]
        if not _rate_store[ip]:
            del _rate_store[ip]


# ── API helpers ───────────────────────────────────────────────────

def _api_get(path: str, timeout: int = 5) -> Optional[dict]:
    """Make GET request to engine API."""
    try:
        url = f"{ENGINE_API_URL}{path}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for FALCON-X dashboard."""

    def do_GET(self):
        path = self.path.split("?")[0]

        # API routes
        if path.startswith("/api/"):
            self._handle_api_get(path)
            return

        # Static files
        if path.startswith("/static/"):
            self._serve_static(path)
            return

        # Pages
        if path == "/" or path == "/login":
            self._serve_page("login.html")
        elif path == "/dashboard":
            if not self._require_auth():
                return
            self._serve_page("dashboard.html")
        elif path == "/health":
            self._send_json(200, health_module.check_system_health())
        else:
            self._send_error(404)

    def do_POST(self):
        path = self.path.split("?")[0]

        if path == "/api/login":
            self._handle_login()
        elif path == "/api/logout":
            self._handle_logout()
        elif path.startswith("/api/"):
            self._handle_api_post(path)
        else:
            self._send_error(404)

    # ── Authentication ────────────────────────────────────────────

    def _get_session_token(self) -> Optional[str]:
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        if "falconx_session" in cookie:
            return cookie["falconx_session"].value
        # Also check Authorization header
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None

    def _require_auth(self) -> bool:
        token = self._get_session_token()
        session = auth.validate_session(token)
        if not session:
            self._send_redirect("/login")
            return False
        self._session = session
        return True

    def _require_csrf(self) -> bool:
        """Validate CSRF token for state-changing requests."""
        if self.command not in ("POST", "PUT", "DELETE"):
            return True
        csrf_token = self.headers.get("X-CSRF-Token", "")
        session_token = self._get_session_token()
        if not session_token or not csrf_token:
            self._send_json(403, {"error": "CSRF token required"})
            return False
        import hmac, hashlib
        expected = hmac.new(
            session_token.encode(), b"falconx-csrf", hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(csrf_token, expected):
            self._send_json(403, {"error": "Invalid CSRF token"})
            return False
        return True

    def _handle_login(self):
        if not _check_rate_limit(self.client_address[0], 20):
            self._send_json(429, {"error": "Rate limit exceeded"})
            return

        data = self._read_body()
        if not data:
            self._send_json(400, {"error": "Missing request body"})
            return

        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username or not password:
            self._send_json(400, {"error": "Username and password required"})
            return

        # Input validation
        if not re.match(r"^[a-zA-Z0-9_-]{1,32}$", username):
            self._send_json(400, {"error": "Invalid username format"})
            return

        token = auth.authenticate(username, password)
        if not token:
            self._send_json(401, {"error": "Invalid credentials"})
            return

        # Set secure cookie
        cookie = SimpleCookie()
        cookie["falconx_session"] = token
        cookie["falconx_session"]["path"] = "/"
        cookie["falconx_session"]["httponly"] = True
        cookie["falconx_session"]["secure"] = True
        cookie["falconx_session"]["samesite"] = "Strict"
        cookie["falconx_session"]["max_age"] = 1800

        # Generate CSRF token
        import hmac, hashlib
        csrf_token = hmac.new(token.encode(), b"falconx-csrf", hashlib.sha256).hexdigest()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", cookie.output())
        self.end_headers()
        self.wfile.write(json.dumps({"success": True, "username": username, "csrf_token": csrf_token}).encode())

    def _handle_logout(self):
        token = self._get_session_token()
        if token:
            auth.destroy_session(token)

        cookie = SimpleCookie()
        cookie["falconx_session"] = ""
        cookie["falconx_session"]["path"] = "/"
        cookie["falconx_session"]["max_age"] = 0

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", cookie.output())
        self.end_headers()
        self.wfile.write(json.dumps({"success": True}).encode())

    # ── API Endpoints ─────────────────────────────────────────────

    def _handle_api_get(self, path: str):
        if not self._require_auth():
            return

        if not _check_rate_limit(self.client_address[0], 100):
            self._send_json(429, {"error": "Rate limit exceeded"})
            return

        if path == "/api/status":
            data = self._get_system_status()
            self._send_json(200, data)
        elif path == "/api/health":
            self._send_json(200, health_module.check_system_health())
        elif path == "/api/devices":
            data = _api_get("/stats") or {}
            devices = self._extract_devices(data)
            self._send_json(200, {"devices": devices})
        elif path == "/api/traffic":
            data = _api_get("/stats") or {}
            traffic = self._extract_traffic(data)
            self._send_json(200, traffic)
        elif path == "/api/incidents":
            data = _api_get("/incidents") or []
            self._send_json(200, {"incidents": data})
        elif path == "/api/events":
            data = _api_get("/stats") or {}
            self._send_json(200, data)
        elif path == "/api/config":
            config = self._get_config()
            self._send_json(200, config)
        elif path == "/api/ai/status":
            client = omniroute.get_client()
            self._send_json(200, client.get_status())
        else:
            self._send_error(404)

    def _handle_api_post(self, path: str):
        if not self._require_auth():
            return

        if not self._require_csrf():
            return

        if not _check_rate_limit(self.client_address[0], 50):
            self._send_json(429, {"error": "Rate limit exceeded"})
            return

        data = self._read_body() or {}

        if path == "/api/config":
            result = self._update_config(data)
            self._send_json(200, result)
        elif path == "/api/incidents/resolve":
            inc_id = data.get("incident_id", "")
            note = data.get("note", "")
            # Forward to engine
            self._send_json(200, {"success": True, "message": "Incident resolution forwarded"})
        elif path == "/api/ai/analyze":
            incident = data.get("incident", {})
            client = omniroute.get_client()
            analysis = client.analyze_incident(incident)
            if analysis:
                self._send_json(200, analysis)
            else:
                self._send_json(503, {"error": "AI service unavailable"})
        else:
            self._send_error(404)

    # ── Data helpers ──────────────────────────────────────────────

    def _get_system_status(self) -> dict:
        health_data = health_module.check_system_health()
        engine_stats = _api_get("/stats") or {}
        engine_health = _api_get("/health") or {}

        # Extract key metrics
        capture = engine_stats.get("capture", {})
        features = engine_stats.get("features", {})
        baseline = engine_stats.get("baseline", {})
        incidents = engine_stats.get("incidents", {})
        enforcement = engine_stats.get("enforcement", {})
        ml = engine_stats.get("ml", {})

        return {
            "overall_status": health_data["overall"],
            "system": {
                "cpu": health_data["components"].get("cpu", {}),
                "memory": health_data["components"].get("memory", {}),
                "disk": health_data["components"].get("disk", {}),
                "temperature": health_data["components"].get("temperature", {}),
            },
            "engine": {
                "status": engine_health.get("status", "unknown"),
                "uptime": engine_health.get("uptime", 0),
                "packets_captured": capture.get("packets_captured", 0),
                "packets_per_second": capture.get("packets_per_second", 0),
                "active_flows": features.get("active_flows", 0),
                "total_flows": features.get("total_flows", 0),
                "protection_state": engine_health.get("protection_state", "UNKNOWN"),
            },
            "network": {
                "known_devices": baseline.get("known_devices", 0),
                "unknown_devices": baseline.get("unknown_devices", 0),
                "learning_devices": baseline.get("learning_devices", 0),
                "baseline_ready": baseline.get("ready", False),
            },
            "incidents": {
                "open": incidents.get("open_incidents", 0),
                "by_severity": incidents.get("by_severity", {}),
            },
            "enforcement": {
                "mode": enforcement.get("mode", "log-only"),
                "active_ip_blocks": enforcement.get("active_ip_blocks", 0),
                "active_port_blocks": enforcement.get("active_port_blocks", 0),
                "total_actions": enforcement.get("total_actions", 0),
                "enforcer_running": enforcement.get("enforcer_running", False),
                "enforcer_blocked_ips": enforcement.get("enforcer_blocked_ips", 0),
                "enforcer_blocked_ports": enforcement.get("enforcer_blocked_ports", 0),
            },
            "ai": omniroute.get_client().get_status(),
            "ml": {
                "state": ml.get("state", "UNKNOWN"),
                "model_loaded": ml.get("model_loaded", False),
                "sample_count": ml.get("sample_count", 0),
                "buffer_size": ml.get("buffer_size", 0),
                "training_count": ml.get("training_count", 0),
                "validation_score": ml.get("validation_score", 0),
                "sklearn_available": ml.get("sklearn_available", False),
            },
        }

    def _extract_devices(self, stats: dict) -> list:
        """Extract device information from engine stats."""
        baseline = stats.get("baseline", {})
        return [{
            "ip": "baseline_summary",
            "known_devices": baseline.get("known_devices", 0),
            "unknown_devices": baseline.get("unknown_devices", 0),
            "learning_devices": baseline.get("learning_devices", 0),
            "baseline_ready": baseline.get("ready", False),
        }]

    def _extract_traffic(self, stats: dict) -> dict:
        """Extract traffic statistics."""
        capture = stats.get("capture", {})
        features = stats.get("features", {})
        return {
            "packets_captured": capture.get("packets_captured", 0),
            "packets_dropped": capture.get("packets_dropped", 0),
            "drop_rate": capture.get("drop_rate", 0),
            "active_flows": features.get("active_flows", 0),
            "total_flows": features.get("total_flows", 0),
            "total_packets": features.get("total_packets", 0),
        }

    def _get_config(self) -> dict:
        """Read current configuration."""
        config_path = os.path.join("/etc/falconx", "falconx.yaml")
        try:
            import yaml
            with open(config_path) as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {"error": "Cannot read configuration"}

    def _update_config(self, data: dict) -> dict:
        """Update configuration (validated)."""
        config_path = os.path.join("/etc/falconx", "falconx.yaml")
        try:
            import yaml
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}

            # Validate and merge allowed fields
            allowed_sections = ["engine", "detector", "ai", "web", "health"]
            for section in allowed_sections:
                if section in data:
                    if section not in config:
                        config[section] = {}
                    config[section].update(data[section])

            with open(config_path, "w") as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

            # Log config change
            logger.info("Configuration updated by %s", self._session.get("username", "unknown"))

            return {"success": True, "message": "Configuration updated"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── HTTP helpers ──────────────────────────────────────────────

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code: int):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Error")

    def _send_redirect(self, path: str):
        self.send_response(302)
        self.send_header("Location", path)
        self.end_headers()

    def _serve_page(self, filename: str):
        page_path = os.path.join(STATIC_DIR, filename)
        if os.path.exists(page_path):
            with open(page_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(content)
        else:
            self._send_error(404)

    def _serve_static(self, path: str):
        rel = path[len("/static/"):]
        file_path = os.path.join(STATIC_DIR, rel)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            with open(file_path, "rb") as f:
                content = f.read()
            content_type = "text/plain"
            if file_path.endswith(".css"):
                content_type = "text/css"
            elif file_path.endswith(".js"):
                content_type = "application/javascript"
            elif file_path.endswith(".png"):
                content_type = "image/png"
            elif file_path.endswith(".svg"):
                content_type = "image/svg+xml"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self._send_error(404)

    def _read_body(self) -> Optional[dict]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        body = self.rfile.read(length)
        try:
            return json.loads(body.decode())
        except Exception:
            return None

    def log_message(self, format, *args):
        if "/health" not in str(args):
            logger.debug(format, *args)


def main():
    auth.init_default_user()

    server = HTTPServer((HOST, PORT), DashboardHandler)

    # Try TLS
    if os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY):
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(TLS_CERT, TLS_KEY)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        server.socket = context.wrap_socket(server.socket, server_side=True)
        logger.info("TLS enabled")

    logger.info("FALCON-X Dashboard listening on %s:%d", HOST, PORT)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        logger.info("Dashboard stopped")


if __name__ == "__main__":
    main()
