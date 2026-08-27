#!/usr/bin/env python3
"""FALCON-X Health Check — System health monitoring and status reporting.

Reads protection state from the engine's state machine via API.
Falls back to local checks if engine is unavailable.
"""

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Dict, Optional, Tuple

STATUS_DIR = Path("/var/lib/falconx")
CONFIG_DIR = Path("/etc/falconx")


def check_service(name: str, port: int) -> Tuple[bool, str]:
    """Check if a service is responding on its health endpoint."""
    try:
        url = f"http://127.0.0.1:{port}/health"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "running":
                return True, f"{name} running (pid={data.get('pid', '?')})"
            return False, f"{name} status: {data.get('status', 'unknown')}"
    except ConnectionRefusedError:
        return False, f"{name} unavailable (connection refused)"
    except Exception as e:
        return False, f"{name} error: {e}"


def check_firewall() -> Tuple[bool, str]:
    """Check if nftables rules are active."""
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            rule_count = len([l for l in result.stdout.split("\n") if l.strip()])
            if rule_count > 10 and "falconx_filter" in result.stdout:
                return True, f"Firewall active ({rule_count} lines, falconx_filter loaded)"
            elif rule_count > 10:
                return True, f"Firewall active ({rule_count} lines)"
            return False, "Firewall rules not loaded"
        return False, "Firewall check failed (nft returned error)"
    except FileNotFoundError:
        return False, "Firewall not available (nftables not found)"
    except Exception as e:
        return False, f"Firewall check failed: {e}"


def check_network() -> Tuple[bool, str]:
    """Check network connectivity."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and "default" in result.stdout:
            return True, "Network available (default route present)"
        return False, "No default route"
    except FileNotFoundError:
        return False, "Network check unavailable"
    except Exception as e:
        return False, f"Network check failed: {e}"


def check_disk() -> Tuple[bool, str]:
    """Check disk space."""
    try:
        stat = os.statvfs("/")
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bavail * stat.f_frsize
        used_pct = (1 - free / total) * 100 if total > 0 else 0
        free_mb = free / (1024 * 1024)
        if free_mb < 100:
            return False, f"Low disk space: {free_mb:.0f}MB free ({used_pct:.1f}% used)"
        return True, f"Disk OK: {free_mb:.0f}MB free ({used_pct:.1f}% used)"
    except Exception as e:
        return False, f"Disk check failed: {e}"


def check_memory() -> Tuple[bool, str]:
    """Check available memory."""
    try:
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
        available_mb = meminfo.get("MemAvailable", 0) / 1024
        total_mb = meminfo.get("MemTotal", 0) / 1024
        if available_mb < 50:
            return False, f"Low memory: {available_mb:.0f}MB / {total_mb:.0f}MB"
        return True, f"Memory OK: {available_mb:.0f}MB / {total_mb:.0f}MB"
    except FileNotFoundError:
        return True, "Memory check skipped (not Linux)"
    except Exception as e:
        return False, f"Memory check failed: {e}"


def get_protection_state() -> Optional[dict]:
    """Read protection state from engine's state machine."""
    try:
        url = "http://127.0.0.1:9100/health"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            return data.get("protection_state")
    except Exception:
        return None


def compute_local_status(components: dict) -> str:
    """Compute protection status from local checks (fallback when engine unavailable)."""
    critical = ["engine", "firewall", "network"]
    critical_failed = any(
        not components.get(c, {}).get("ok", False) for c in critical
    )
    if critical_failed:
        return "UNPROTECTED"
    optional = ["web"]
    optional_failed = any(
        not components.get(c, {}).get("ok", False) for c in optional
    )
    if optional_failed:
        return "DEGRADED"
    return "PROTECTED"


def get_health_status() -> dict:
    """Determine overall health status."""
    checks = {}
    protected_core = []
    protected_optional = []

    # Core components
    engine_ok, engine_msg = check_service("engine", 9100)
    checks["engine"] = {"ok": engine_ok, "message": engine_msg}
    protected_core.append(("engine", engine_ok, engine_msg))

    firewall_ok, firewall_msg = check_firewall()
    checks["firewall"] = {"ok": firewall_ok, "message": firewall_msg}
    protected_core.append(("firewall", firewall_ok, firewall_msg))

    network_ok, network_msg = check_network()
    checks["network"] = {"ok": network_ok, "message": network_msg}
    protected_core.append(("network", network_ok, network_msg))

    # Optional components
    web_ok, web_msg = check_service("web", 8443)
    checks["web"] = {"ok": web_ok, "message": web_msg}
    protected_optional.append(("web", web_ok, web_msg))

    # System checks
    disk_ok, disk_msg = check_disk()
    checks["disk"] = {"ok": disk_ok, "message": disk_msg}

    mem_ok, mem_msg = check_memory()
    checks["memory"] = {"ok": mem_ok, "message": mem_msg}

    # Try to get state from engine's state machine
    protection_state = get_protection_state()
    if protection_state:
        status = protection_state.get("state", "UNKNOWN")
    else:
        # Fallback to local computation
        status = compute_local_status(checks)

    return {
        "status": status,
        "checks": checks,
        "core_components": protected_core,
        "optional_components": protected_optional,
        "protection_state": protection_state,
    }


def format_status(health: Dict, color: bool = True) -> str:
    """Format health status for terminal display."""
    lines = []
    status = health["status"]

    if color:
        colors = {"PROTECTED": "\033[92m", "DEGRADED": "\033[93m", "UNPROTECTED": "\033[91m"}
        reset = "\033[0m"
        color_prefix = colors.get(status, "")
        lines.append(f"{color_prefix}{status}{reset}")
    else:
        lines.append(status)

    lines.append("")

    for name, ok, msg in health["core_components"]:
        symbol = "✓" if ok else "✗"
        lines.append(f"  {symbol} {msg}")

    for name, ok, msg in health["optional_components"]:
        symbol = "✓" if ok else "✗"
        lines.append(f"  {symbol} {msg}")

    # Show protection state details if available
    ps = health.get("protection_state")
    if ps:
        lines.append("")
        lines.append(f"  State: {ps.get('state', '?')} (uptime: {ps.get('uptime_in_state', 0):.0f}s)")
        components = ps.get("components", {})
        if components:
            for name, info in components.items():
                symbol = "✓" if info.get("healthy") else "✗"
                marker = " [CRITICAL]" if info.get("critical") else ""
                lines.append(f"    {symbol} {name}: {info.get('message', '')}{marker}")

    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="FALCON-X Health Check")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    args = parser.parse_args()

    health = get_health_status()

    if args.json:
        output = {
            "status": health["status"],
            "checks": {
                name: {"ok": ok, "message": msg}
                for name, ok, msg in health["core_components"] + health["optional_components"]
            },
            "protection_state": health.get("protection_state"),
        }
        print(json.dumps(output, indent=2))
    else:
        print(format_status(health, color=not args.no_color))

    status_codes = {"PROTECTED": 0, "DEGRADED": 1, "UNPROTECTED": 2}
    sys.exit(status_codes.get(health["status"], 2))


if __name__ == "__main__":
    main()
