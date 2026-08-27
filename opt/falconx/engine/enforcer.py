#!/usr/bin/env python3
"""FALCON-X Privileged Enforcement Helper.

Runs as root. Watches a controlled directory for command files.
Validates and executes nftables block/unblock operations.

Only exposes: block_ip, unblock_ip, block_port, unblock_port.
No arbitrary command execution. Strict input validation.

Security model:
- Only 4 whitelisted actions
- Input validated against strict regex
- subprocess.run with argument arrays (no shell=True)
- Command directory restricted to root:root 0700
- Maximum blocked items enforced
- All actions logged to audit trail
"""

import ipaddress
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Tuple

COMMAND_DIR = "/run/falconx/enforcer"
LOG_FILE = "/var/log/falconx/security/enforcement.log"
STATE_FILE = "/var/lib/falconx/enforcer-state.json"

# Strict whitelist of allowed actions
VALID_ACTIONS = frozenset({"block_ip", "unblock_ip", "block_port", "unblock_port"})

# Port validation: 1-65535
PORT_RE = re.compile(r"^(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$")
MAX_BLOCKED = 200
DEFAULT_TIMEOUT = 1800  # 30 minutes
MAX_TIMEOUT = 86400     # 24 hours
MIN_TIMEOUT = 60        # 1 minute

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","component":"enforcer","message":"%(message)s"}',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE),
    ],
)
logger = logging.getLogger("falconx-enforcer")

running = True


def signal_handler(signum, frame):
    global running
    logger.info("Received signal %d, shutting down", signum)
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def validate_ip(ip_str: str) -> Tuple[bool, str]:
    """Validate an IP address (IPv4 or IPv6). Returns (valid, version)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv4Address):
            return True, "ipv4"
        elif isinstance(addr, ipaddress.IPv6Address):
            # Skip loopback, link-local, multicast
            if addr.is_loopback or addr.is_link_local or addr.is_multicast:
                return False, "invalid_ipv6"
            return True, "ipv6"
    except ValueError:
        pass
    return False, "invalid"


def validate_port(port_str: str) -> bool:
    """Validate a port number (1-65535)."""
    return bool(PORT_RE.match(str(port_str)))


def validate_action(action: dict) -> Tuple[bool, str]:
    """Validate action dict. Returns (valid, error_message)."""
    if not isinstance(action, dict):
        return False, "Action must be a JSON object"

    action_type = action.get("action")
    if action_type not in VALID_ACTIONS:
        return False, f"Invalid action: {action_type}"

    target = str(action.get("target", "")).strip()
    if not target:
        return False, "Empty target"

    timeout = action.get("timeout", DEFAULT_TIMEOUT)

    if action_type in ("block_ip", "unblock_ip"):
        valid, version = validate_ip(target)
        if not valid:
            return False, f"Invalid IP address: {target}"
    elif action_type in ("block_port", "unblock_port"):
        if not validate_port(target):
            return False, f"Invalid port: {target}"

    if action_type in ("block_ip", "block_port"):
        if not isinstance(timeout, (int, float)) or timeout < MIN_TIMEOUT or timeout > MAX_TIMEOUT:
            return False, f"Invalid timeout: {timeout} (must be {MIN_TIMEOUT}-{MAX_TIMEOUT})"

    return True, ""


def ensure_nft_sets() -> bool:
    """Ensure nftables enforcement table with IPv4+IPv6 sets exists."""
    result = subprocess.run(
        ["nft", "list", "table", "inet", "falconx_enforcer"],
        capture_output=True, text=True, timeout=5
    )

    if result.returncode != 0:
        rules = """
table inet falconx_enforcer {
    set blocked_ips {
        type ipv4_addr
        flags timeout
        timeout 30m
    }

    set blocked_ipv6 {
        type ipv6_addr
        flags timeout
        timeout 30m
    }

    set blocked_ports {
        type inet_service
        flags timeout
        timeout 30m
    }

    chain input_hook {
        type filter hook input priority -10; policy accept;
        ip saddr @blocked_ips drop
        ip6 saddr @blocked_ipv6 drop
        tcp dport @blocked_ports drop
        udp dport @blocked_ports drop
    }
}
"""
        result = subprocess.run(
            ["nft", "-f", "-"],
            input=rules, capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            logger.error("Failed to create enforcement table: %s", result.stderr)
            return False
        logger.info("Created nftables enforcement table (IPv4+IPv6)")

    return True


def execute_block_ip(ip: str, timeout: int, version: str = "ipv4") -> bool:
    """Block an IP address via nftables set."""
    set_name = "blocked_ips" if version == "ipv4" else "blocked_ipv6"
    timeout_str = f"{timeout}s"
    result = subprocess.run(
        ["nft", "add", "element", "inet", "falconx_enforcer", set_name,
         "{", ip, "timeout", timeout_str, "}"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode != 0:
        logger.error("Failed to block IP %s: %s", ip, result.stderr)
        return False
    logger.info("BLOCKED IP: %s (timeout=%ds, set=%s)", ip, timeout, set_name)
    return True


def execute_unblock_ip(ip: str, version: str = "ipv4") -> bool:
    """Unblock an IP address."""
    set_name = "blocked_ips" if version == "ipv4" else "blocked_ipv6"
    result = subprocess.run(
        ["nft", "delete", "element", "inet", "falconx_enforcer", set_name,
         "{", ip, "}"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode != 0:
        logger.warning("IP %s was not blocked or already unblocked", ip)
        return True
    logger.info("UNBLOCKED IP: %s (set=%s)", ip, set_name)
    return True


def execute_block_port(port: str, timeout: int) -> bool:
    """Block a port via nftables set."""
    timeout_str = f"{timeout}s"
    result = subprocess.run(
        ["nft", "add", "element", "inet", "falconx_enforcer", "blocked_ports",
         "{", port, "timeout", timeout_str, "}"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode != 0:
        logger.error("Failed to block port %s: %s", port, result.stderr)
        return False
    logger.info("BLOCKED PORT: %s (timeout=%ds)", port, timeout)
    return True


def execute_unblock_port(port: str) -> bool:
    """Unblock a port."""
    result = subprocess.run(
        ["nft", "delete", "element", "inet", "falconx_enforcer", "blocked_ports",
         "{", port, "}"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode != 0:
        logger.warning("Port %s was not blocked or already unblocked", port)
        return True
    logger.info("UNBLOCKED PORT: %s", port)
    return True


def get_blocked_count() -> dict:
    """Get current blocked counts from nftables sets."""
    counts = {"blocked_ips": 0, "blocked_ipv6": 0, "blocked_ports": 0}

    for set_name, key in [("blocked_ips", "blocked_ips"), ("blocked_ipv6", "blocked_ipv6"), ("blocked_ports", "blocked_ports")]:
        try:
            result = subprocess.run(
                ["nft", "list", "set", "inet", "falconx_enforcer", set_name],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Count lines that contain elements (skip headers)
                lines = result.stdout.strip().split("\n")
                element_lines = [l for l in lines if l.strip() and not l.strip().startswith("table") and not l.strip().startswith("set") and not l.strip().startswith("}") and not l.strip().startswith("flags") and not l.strip().startswith("timeout") and not l.strip().startswith("type")]
                counts[key] = max(0, len(element_lines))
        except Exception:
            pass

    return counts


def log_enforcement(action: str, target: str, reason: str, actor: str, success: bool, error: str = ""):
    """Log enforcement action to audit trail."""
    entry = {
        "action": action,
        "target": target,
        "reason": reason,
        "actor": actor,
        "success": success,
        "error": error,
        "timestamp": time.time(),
        "timestamp_human": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        log_path = Path(LOG_FILE)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.error("Failed to write audit log: %s", e)


def process_command(cmd_file: Path):
    """Process a single command file. Never raises."""
    try:
        data = json.loads(cmd_file.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Invalid command file %s: %s", cmd_file.name, e)
        log_enforcement("INVALID", "?", str(e), "enforcer", False, str(e))
        cmd_file.unlink(missing_ok=True)
        return

    valid, error = validate_action(data)
    if not valid:
        logger.error("Invalid action: %s", error)
        log_enforcement(data.get("action", "INVALID"), data.get("target", "?"), error, data.get("actor", "unknown"), False, error)
        write_response(cmd_file, False, error)
        return

    action_type = data["action"]
    target = str(data["target"]).strip()
    timeout = int(data.get("timeout", DEFAULT_TIMEOUT))
    reason = data.get("reason", "")
    actor = data.get("actor", "unknown")

    # Check limits for block actions
    if "block" in action_type:
        counts = get_blocked_count()
        total = counts["blocked_ips"] + counts["blocked_ipv6"] + counts["blocked_ports"]
        if total >= MAX_BLOCKED:
            error_msg = f"Maximum blocked items reached ({MAX_BLOCKED})"
            logger.error(error_msg)
            log_enforcement(action_type, target, reason, actor, False, error_msg)
            write_response(cmd_file, False, error_msg)
            return

    success = False
    error_msg = ""

    if action_type == "block_ip":
        _, version = validate_ip(target)
        success = execute_block_ip(target, timeout, version)
    elif action_type == "unblock_ip":
        _, version = validate_ip(target)
        success = execute_unblock_ip(target, version)
    elif action_type == "block_port":
        success = execute_block_port(target, timeout)
    elif action_type == "unblock_port":
        success = execute_unblock_port(target)

    if not success:
        error_msg = "nftables execution failed"

    log_enforcement(action_type, target, reason, actor, success, error_msg)
    write_response(cmd_file, success, error_msg)


def write_response(cmd_file: Path, success: bool, error: str):
    """Write response file next to command file."""
    response_file = cmd_file.with_suffix(".response")
    response = {
        "success": success,
        "error": error,
        "timestamp": time.time(),
    }
    try:
        response_file.write_text(json.dumps(response))
    except OSError as e:
        logger.error("Failed to write response: %s", e)


def write_state():
    """Write current enforcer state."""
    counts = get_blocked_count()
    state = {
        "running": running,
        "blocked_ips": counts["blocked_ips"],
        "blocked_ipv6": counts["blocked_ipv6"],
        "blocked_ports": counts["blocked_ports"],
        "last_check": time.time(),
    }
    try:
        Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
        Path(STATE_FILE).write_text(json.dumps(state))
    except OSError:
        pass


def main():
    logger.info("FALCON-X Enforcer starting (pid=%d)", os.getpid())

    # Ensure command directory with strict permissions
    os.makedirs(COMMAND_DIR, exist_ok=True)
    os.chmod(COMMAND_DIR, 0o700)

    # Ensure nftables sets exist
    if not ensure_nft_sets():
        logger.error("Failed to initialize nftables enforcement table")
        sys.exit(1)

    logger.info("Enforcer ready. Watching %s", COMMAND_DIR)

    try:
        while running:
            try:
                for cmd_file in sorted(Path(COMMAND_DIR).glob("*.json")):
                    if cmd_file.suffix == ".json":
                        process_command(cmd_file)
                        cmd_file.unlink(missing_ok=True)
            except Exception as e:
                logger.error("Error processing commands: %s", e)

            write_state()
            time.sleep(1)
    except Exception as e:
        logger.error("Enforcer error: %s", e)
    finally:
        logger.info("Enforcer stopped")


if __name__ == "__main__":
    main()
