"""FALCON-X Engine — Enforcement abstraction layer.

Communicates with the privileged falconx-enforcer service via command files.
The engine itself does NOT have nftables access.

Flow: Detection → Risk → Policy → Command File → Enforcer → nftables

Exposed operations:
- block_ip
- unblock_ip
- block_port
- unblock_port
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("falconx-engine.enforcement")

COMMAND_DIR = "/run/falconx/enforcer"
ENFORCER_STATE = "/var/lib/falconx/enforcer-state.json"
ENFORCEMENT_LOG = "/var/log/falconx/security/enforcement.log"


class EnforcementAction:
    """A single enforcement action."""
    __slots__ = ("action_type", "target", "reason", "timestamp", "expires", "active")

    def __init__(self, action_type: str, target: str, reason: str, expires: float = 0):
        self.action_type = action_type
        self.target = target
        self.reason = reason
        self.timestamp = time.time()
        self.expires = expires
        self.active = True

    def is_expired(self) -> bool:
        return self.expires > 0 and time.time() > self.expires

    def to_dict(self) -> dict:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "expires": self.expires,
            "active": self.active,
        }


class EnforcementEngine:
    """Enforcement engine that communicates with privileged enforcer.

    Modes:
        log-only:   Only log what would be done (default, safe)
        active:     Send commands to falconx-enforcer service
    """

    def __init__(
        self,
        mode: str = "log-only",
        max_blocked: int = 100,
        auto_unblock_minutes: int = 30,
        risk_threshold_block: int = 80,
        risk_threshold_alert: int = 60,
        min_confidence: float = 0.7,
        block_timeout: int = 1800,
    ):
        self.mode = mode
        self.max_blocked = max_blocked
        self.auto_unblock_minutes = auto_unblock_minutes
        self.risk_threshold_block = risk_threshold_block
        self.risk_threshold_alert = risk_threshold_alert
        self.min_confidence = min_confidence
        self.block_timeout = block_timeout

        self._active_blocks: Dict[str, EnforcementAction] = {}
        self._active_port_blocks: Dict[str, EnforcementAction] = {}
        self._action_history: List[EnforcementAction] = []
        self._total_actions = 0

        os.makedirs(COMMAND_DIR, exist_ok=True)

    def evaluate(
        self,
        risk_score: int,
        confidence: float,
        device_ip: str,
        detection_events: list,
    ) -> Optional[EnforcementAction]:
        """Evaluate whether enforcement action should be taken."""
        if risk_score < self.risk_threshold_alert:
            return None

        if confidence < self.min_confidence:
            return None

        if risk_score >= self.risk_threshold_block and self.mode == "active":
            action = self._create_block_action(device_ip, risk_score, confidence, detection_events)
        elif risk_score >= self.risk_threshold_alert:
            action = self._create_alert_action(device_ip, risk_score, confidence, detection_events)
        else:
            return None

        if action:
            self._total_actions += 1
            self._action_history.append(action)
            self._trim_history()
            return action

        return None

    def _create_block_action(
        self, device_ip: str, risk_score: int, confidence: float, events: list
    ) -> Optional[EnforcementAction]:
        """Create a block action and send to enforcer."""
        if device_ip in self._active_blocks:
            return None

        if len(self._active_blocks) >= self.max_blocked:
            logger.warning("Max blocked IPs reached (%d)", self.max_blocked)
            return None

        descriptions = [getattr(e, "description", "") for e in events]
        reason = f"Risk={risk_score} Confidence={confidence:.2f}"

        if self.mode == "active":
            success = self._send_command("block_ip", device_ip, self.block_timeout, reason, "engine")
            if not success:
                logger.error("Failed to send block command for %s", device_ip)
                self._log_enforcement("BLOCK_IP_FAILED", device_ip, reason, "engine", False)
                return None

        expires = time.time() + (self.auto_unblock_minutes * 60)
        action = EnforcementAction("block_ip", device_ip, reason, expires)
        self._active_blocks[device_ip] = action

        self._log_enforcement("BLOCK_IP", device_ip, reason, "engine", True)
        logger.warning(
            "BLOCK: %s (risk=%d, confidence=%.2f) — expires in %d min",
            device_ip, risk_score, confidence, self.auto_unblock_minutes,
        )
        return action

    def _create_alert_action(
        self, device_ip: str, risk_score: int, confidence: float, events: list
    ) -> EnforcementAction:
        """Create an alert action."""
        descriptions = [getattr(e, "description", "") for e in events]
        action = EnforcementAction(
            "alert",
            device_ip,
            f"Risk={risk_score} Confidence={confidence:.2f} Events={len(descriptions)}",
        )
        self._log_enforcement("ALERT", device_ip, action.reason, "engine", True)
        logger.warning(
            "ALERT: %s (risk=%d, confidence=%.2f)",
            device_ip, risk_score, confidence,
        )
        return action

    def block_port(self, port: str, timeout: int = 0, reason: str = "") -> Optional[EnforcementAction]:
        """Block a TCP/UDP port via enforcer."""
        if port in self._active_port_blocks:
            return None

        if timeout <= 0:
            timeout = self.block_timeout

        if self.mode == "active":
            success = self._send_command("block_port", port, timeout, reason, "engine")
            if not success:
                self._log_enforcement("BLOCK_PORT_FAILED", port, reason, "engine", False)
                return None

        expires = time.time() + (self.auto_unblock_minutes * 60)
        action = EnforcementAction("block_port", port, reason, expires)
        self._active_port_blocks[port] = action

        self._log_enforcement("BLOCK_PORT", port, reason, "engine", True)
        logger.warning("BLOCK PORT: %s (timeout=%ds)", port, timeout)
        return action

    def unblock_port(self, port: str) -> bool:
        """Unblock a port."""
        action = self._active_port_blocks.pop(port, None)
        if action:
            action.active = False
            if self.mode == "active":
                self._send_command("unblock_port", port, 0, "Manual unblock", "engine")
            self._log_enforcement("UNBLOCK_PORT", port, "Manual unblock", "engine", True)
            logger.info("UNBLOCK PORT: %s", port)
            return True
        return False

    def _send_command(self, action: str, target: str, timeout: int, reason: str, actor: str) -> bool:
        """Send a command to the privileged enforcer via command file."""
        try:
            command = {
                "action": action,
                "target": target,
                "timeout": timeout,
                "reason": reason,
                "timestamp": time.time(),
                "actor": actor,
            }

            cmd_id = f"{int(time.time()*1000)}-{os.getpid()}"
            tmp_file = Path(COMMAND_DIR) / f"{cmd_id}.tmp"
            cmd_file = Path(COMMAND_DIR) / f"{cmd_id}.json"

            tmp_file.write_text(json.dumps(command))
            tmp_file.rename(cmd_file)

            response_file = cmd_file.with_suffix(".response")
            for _ in range(50):
                if response_file.exists():
                    try:
                        response = json.loads(response_file.read_text())
                        response_file.unlink(missing_ok=True)
                        return response.get("success", False)
                    except Exception:
                        pass
                time.sleep(0.1)

            logger.warning("Enforcer response timeout for %s %s", action, target)
            return False

        except Exception as e:
            logger.error("Failed to send enforcer command: %s", e)
            return False

    def _log_enforcement(self, action: str, target: str, reason: str, actor: str, success: bool):
        """Log enforcement action to security audit log."""
        entry = {
            "action": action,
            "target": target,
            "reason": reason,
            "actor": actor,
            "success": success,
            "timestamp": time.time(),
            "timestamp_human": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        try:
            log_path = Path(ENFORCEMENT_LOG)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def unblock(self, ip: str) -> bool:
        """Unblock an IP address."""
        action = self._active_blocks.pop(ip, None)
        if action:
            action.active = False
            if self.mode == "active":
                self._send_command("unblock_ip", ip, 0, "Manual unblock", "operator")
            self._log_enforcement("UNBLOCK_IP", ip, "Manual unblock", "operator", True)
            logger.info("UNBLOCK: %s", ip)
            return True
        return False

    def is_blocked(self, ip: str) -> bool:
        action = self._active_blocks.get(ip)
        if action is None:
            return False
        if action.is_expired():
            self._active_blocks.pop(ip, None)
            return False
        return action.active

    def is_port_blocked(self, port: str) -> bool:
        action = self._active_port_blocks.get(port)
        if action is None:
            return False
        if action.is_expired():
            self._active_port_blocks.pop(port, None)
            return False
        return action.active

    def get_enforcer_status(self) -> dict:
        """Get status from the privileged enforcer."""
        try:
            state = json.loads(Path(ENFORCER_STATE).read_text())
            return state
        except Exception:
            return {"running": False, "blocked_ips": 0, "blocked_ipv6": 0, "blocked_ports": 0}

    def _cleanup_expired(self):
        expired_ips = [ip for ip, a in self._active_blocks.items() if a.is_expired()]
        for ip in expired_ips:
            self._active_blocks.pop(ip)
            logger.info("Auto-unblocked IP: %s", ip)

        expired_ports = [port for port, a in self._active_port_blocks.items() if a.is_expired()]
        for port in expired_ports:
            self._active_port_blocks.pop(port)
            logger.info("Auto-unblocked port: %s", port)

    def _trim_history(self):
        if len(self._action_history) > 10000:
            self._action_history = self._action_history[-5000:]

    def get_active_blocks(self) -> List[dict]:
        self._cleanup_expired()
        return [a.to_dict() for a in self._active_blocks.values()]

    def get_active_port_blocks(self) -> List[dict]:
        self._cleanup_expired()
        return [a.to_dict() for a in self._active_port_blocks.values()]

    def get_stats(self) -> dict:
        self._cleanup_expired()
        enforcer = self.get_enforcer_status()
        return {
            "mode": self.mode,
            "active_ip_blocks": len(self._active_blocks),
            "active_port_blocks": len(self._active_port_blocks),
            "total_actions": self._total_actions,
            "risk_threshold_block": self.risk_threshold_block,
            "risk_threshold_alert": self.risk_threshold_alert,
            "enforcer_running": enforcer.get("running", False),
            "enforcer_blocked_ips": enforcer.get("blocked_ips", 0),
            "enforcer_blocked_ipv6": enforcer.get("blocked_ipv6", 0),
            "enforcer_blocked_ports": enforcer.get("blocked_ports", 0),
        }
