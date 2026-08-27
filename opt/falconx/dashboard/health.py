"""FALCON-X Dashboard — Health monitoring.

Reads protection state from the engine's state machine.
Does NOT maintain its own duplicate state logic.
"""

import json
import logging
import os
import subprocess
import time
from typing import Dict, Optional

logger = logging.getLogger("falconx-web.health")


def check_system_health() -> dict:
    """Comprehensive system health check.

    Reads protection state from the engine's state machine.
    Falls back to local checks if engine is unavailable.
    """
    components = {}

    # Engine (core — runs detection, capture, everything)
    engine_ok, engine_msg = _check_service("falconx-engine", 9100)
    components["engine"] = {"status": "HEALTHY" if engine_ok else "FAILED", "message": engine_msg}

    # Web (self-check — always running if we're here)
    components["web"] = {"status": "HEALTHY", "message": "Dashboard running"}

    # Firewall
    fw_ok, fw_msg = _check_firewall()
    components["firewall"] = {"status": "HEALTHY" if fw_ok else "FAILED", "message": fw_msg}

    # Network
    net_ok, net_msg = _check_network()
    components["network"] = {"status": "HEALTHY" if net_ok else "FAILED", "message": net_msg}

    # System resources
    components["cpu"] = _check_cpu()
    components["memory"] = _check_memory()
    components["disk"] = _check_disk()
    components["temperature"] = _check_temperature()

    # Try to get protection state from engine's state machine
    protection_state = _get_protection_state()

    # If engine is available, use its state machine for overall status
    if engine_ok and protection_state:
        overall = protection_state.get("state", "UNKNOWN")
    else:
        # Fallback: compute from local checks
        overall = _compute_local_status(components)

    return {
        "overall": overall,
        "components": components,
        "protection_state": protection_state,
        "timestamp": time.time(),
    }


def _get_protection_state() -> Optional[dict]:
    """Read protection state from engine's state machine via API."""
    try:
        import urllib.request
        url = "http://127.0.0.1:9100/health"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            # The engine exposes protection_state in its health endpoint
            return data.get("protection_state")
    except Exception:
        return None


def _compute_local_status(components: dict) -> str:
    """Compute protection status from local health checks (fallback)."""
    statuses = [c["status"] for c in components.values()]

    if all(s == "HEALTHY" for s in statuses):
        return "PROTECTED"

    # Check critical components
    critical = ["engine", "firewall", "network"]
    critical_failed = any(
        components[c]["status"] == "FAILED" for c in critical if c in components
    )

    if critical_failed:
        return "UNPROTECTED"
    return "DEGRADED"


def _check_service(name: str, port: int) -> tuple:
    """Check if a service is responding on its health endpoint."""
    import urllib.request
    try:
        url = f"http://127.0.0.1:{port}/health"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "running":
                return True, f"{name} running (pid={data.get('pid', '?')})"
            return False, f"{name} status: {data.get('status', 'unknown')}"
    except ConnectionRefusedError:
        return False, f"{name} unavailable (connection refused)"
    except Exception as e:
        return False, f"{name} error: {e}"


def _check_firewall() -> tuple:
    """Check if nftables rules are active."""
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            if "falconx_filter" in result.stdout:
                return True, "nftables active (falconx_filter loaded)"
            return False, "nftables rules not loaded"
        return False, "nftables check failed"
    except FileNotFoundError:
        return False, "nftables not found"
    except Exception as e:
        return False, f"Firewall check failed: {e}"


def _check_network() -> tuple:
    """Check network connectivity."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and "default" in result.stdout:
            return True, "Default route present"
        return False, "No default route"
    except Exception as e:
        return False, f"Network check failed: {e}"


def _check_cpu() -> dict:
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        parts = line.split()
        idle = int(parts[4])
        total = sum(int(x) for x in parts[1:])
        usage = round((1 - idle / max(total, 1)) * 100, 1)
        status = "HEALTHY" if usage < 80 else "DEGRADED" if usage < 95 else "FAILED"
        return {"status": status, "message": f"CPU: {usage}%", "value": usage}
    except Exception:
        return {"status": "HEALTHY", "message": "CPU check skipped"}


def _check_memory() -> dict:
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        meminfo = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                meminfo[parts[0].rstrip(":")] = int(parts[1])
        total = meminfo.get("MemTotal", 1)
        available = meminfo.get("MemAvailable", 0)
        used_pct = round((1 - available / total) * 100, 1)
        available_mb = round(available / 1024)
        status = "HEALTHY" if used_pct < 80 else "DEGRADED" if used_pct < 95 else "FAILED"
        return {"status": status, "message": f"RAM: {used_pct}% ({available_mb}MB free)", "value": used_pct}
    except Exception:
        return {"status": "HEALTHY", "message": "Memory check skipped"}


def _check_disk() -> dict:
    try:
        stat = os.statvfs("/")
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bavail * stat.f_frsize
        used_pct = round((1 - free / total) * 100, 1) if total > 0 else 0
        free_mb = round(free / (1024 * 1024))
        status = "HEALTHY" if used_pct < 85 else "DEGRADED" if used_pct < 95 else "FAILED"
        return {"status": status, "message": f"Disk: {used_pct}% ({free_mb}MB free)", "value": used_pct}
    except Exception:
        return {"status": "HEALTHY", "message": "Disk check skipped"}


def _check_temperature() -> dict:
    thermal_zones = [
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/devices/virtual/thermal/thermal_zone0/temp",
    ]
    for path in thermal_zones:
        try:
            with open(path) as f:
                temp = int(f.read().strip()) / 1000
            status = "HEALTHY" if temp < 70 else "DEGRADED" if temp < 80 else "FAILED"
            return {"status": status, "message": f"Temperature: {temp:.1f}°C", "value": round(temp, 1)}
        except Exception:
            continue
    return {"status": "HEALTHY", "message": "Temperature sensor unavailable"}
