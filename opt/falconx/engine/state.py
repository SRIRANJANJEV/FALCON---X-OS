"""FALCON-X Protection State Machine.

Manages the overall protection state of the appliance.

States:
    BOOTING      — System is booting, no components checked yet
    INITIALIZING — Components are being initialized
    PROTECTED    — All critical components operational
    DEGRADED     — Non-critical component failure
    UNPROTECTED  — Critical component failure
    RECOVERY     — System is recovering from a previous failure

Component classification:
    CRITICAL (engine fails → UNPROTECTED):
        engine, capture, firewall, network, rules, baseline

    OPTIONAL (component fails → DEGRADED):
        web, ai, ml, enforcement, health

State transitions are explicit, logged, and persisted.
"""

import json
import logging
import os
import time
import threading
from enum import Enum
from typing import Dict, Optional, Callable, List

logger = logging.getLogger("falconx-state")

STATE_FILE = "/var/lib/falconx/protection-state.json"

# Components whose failure makes the system UNPROTECTED
CRITICAL_COMPONENTS = frozenset({"engine", "capture", "firewall", "network", "rules", "baseline"})

# Components whose failure makes the system DEGRADED
OPTIONAL_COMPONENTS = frozenset({"web", "health"})


class ProtectionState(Enum):
    BOOTING = "BOOTING"
    INITIALIZING = "INITIALIZING"
    PROTECTED = "PROTECTED"
    DEGRADED = "DEGRADED"
    UNPROTECTED = "UNPROTECTED"
    RECOVERY = "RECOVERY"

    def is_operational(self) -> bool:
        return self in (ProtectionState.PROTECTED, ProtectionState.DEGRADED)


# Valid transitions
_VALID_TRANSITIONS = {
    ProtectionState.BOOTING: {ProtectionState.INITIALIZING, ProtectionState.RECOVERY},
    ProtectionState.INITIALIZING: {ProtectionState.PROTECTED, ProtectionState.DEGRADED, ProtectionState.UNPROTECTED},
    ProtectionState.PROTECTED: {ProtectionState.DEGRADED, ProtectionState.UNPROTECTED, ProtectionState.RECOVERY},
    ProtectionState.DEGRADED: {ProtectionState.PROTECTED, ProtectionState.UNPROTECTED, ProtectionState.RECOVERY},
    ProtectionState.UNPROTECTED: {ProtectionState.RECOVERY, ProtectionState.DEGRADED, ProtectionState.PROTECTED},
    ProtectionState.RECOVERY: {ProtectionState.PROTECTED, ProtectionState.DEGRADED, ProtectionState.UNPROTECTED},
}


class StateManager:
    """Manages protection state transitions and component health tracking."""

    def __init__(self):
        self._state = ProtectionState.BOOTING
        self._previous_state = ProtectionState.BOOTING
        self._state_changed_at = time.time()
        self._components: Dict[str, dict] = {}
        self._transition_log: List[dict] = []
        self._lock = threading.Lock()
        self._listeners: List[Callable] = []

        self._load_state()

    @property
    def state(self) -> ProtectionState:
        return self._state

    @property
    def state_name(self) -> str:
        return self._state.value

    @property
    def uptime_in_state(self) -> float:
        return time.time() - self._state_changed_at

    def transition(self, new_state: ProtectionState, reason: str = "") -> bool:
        """Transition to a new state. Returns True if successful."""
        with self._lock:
            if new_state == self._state:
                return True

            valid = _VALID_TRANSITIONS.get(self._state, set())
            if new_state not in valid:
                logger.warning(
                    "Invalid transition: %s → %s (valid: %s)",
                    self._state.value, new_state.value,
                    [s.value for s in valid],
                )
                return False

            old_state = self._state
            self._previous_state = old_state
            self._state = new_state
            self._state_changed_at = time.time()

            entry = {
                "from": old_state.value,
                "to": new_state.value,
                "reason": reason,
                "timestamp": self._state_changed_at,
            }
            self._transition_log.append(entry)
            if len(self._transition_log) > 100:
                self._transition_log = self._transition_log[-50:]

            logger.info("State transition: %s → %s (%s)", old_state.value, new_state.value, reason)
            self._save_state()

            for listener in self._listeners:
                try:
                    listener(old_state, new_state, reason)
                except Exception as e:
                    logger.error("State listener error: %s", e)

            return True

    def update_component(self, name: str, healthy: bool, message: str = ""):
        """Update a component's health status and recalculate overall state."""
        with self._lock:
            self._components[name] = {
                "healthy": healthy,
                "message": message,
                "last_check": time.time(),
                "critical": name in CRITICAL_COMPONENTS,
            }
            self._recalculate_state()

    def _recalculate_state(self):
        """Recalculate overall state from component health.

        Logic:
        1. If no critical components have been checked yet → INITIALIZING
        2. If any critical component is unhealthy → UNPROTECTED
        3. If any optional component is unhealthy → DEGRADED
        4. If we were previously UNPROTECTED/DEGRADED and now all healthy → PROTECTED
        5. Otherwise → maintain current state
        """
        critical_healthy = True
        critical_checked = False
        optional_healthy = True
        unhealthy_components = []

        for name, info in self._components.items():
            if name in CRITICAL_COMPONENTS:
                critical_checked = True
                if not info.get("healthy", False):
                    critical_healthy = False
                    unhealthy_components.append(name)
            elif name in OPTIONAL_COMPONENTS:
                if not info.get("healthy", False):
                    optional_healthy = False
                    unhealthy_components.append(name)

        if not critical_checked:
            new_state = ProtectionState.INITIALIZING
        elif not critical_healthy:
            new_state = ProtectionState.UNPROTECTED
        elif not optional_healthy:
            new_state = ProtectionState.DEGRADED
        else:
            new_state = ProtectionState.PROTECTED

        if new_state != self._state:
            reason = f"Components changed: {unhealthy_components}" if unhealthy_components else "All components healthy"
            self.transition(new_state, reason)

    def add_listener(self, callback: Callable):
        self._listeners.append(callback)

    def get_component_status(self, name: str) -> Optional[dict]:
        return self._components.get(name)

    def get_all_components(self) -> Dict[str, dict]:
        return dict(self._components)

    def get_summary(self) -> dict:
        return {
            "state": self._state.value,
            "previous_state": self._previous_state.value,
            "uptime_in_state": round(self.uptime_in_state, 1),
            "components": {
                name: {
                    "healthy": info["healthy"],
                    "message": info.get("message", ""),
                    "critical": info.get("critical", name in CRITICAL_COMPONENTS),
                }
                for name, info in self._components.items()
            },
            "critical_components": list(CRITICAL_COMPONENTS),
            "optional_components": list(OPTIONAL_COMPONENTS),
            "recent_transitions": self._transition_log[-10:],
        }

    def _save_state(self):
        try:
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            data = {
                "state": self._state.value,
                "previous_state": self._previous_state.value,
                "state_changed_at": self._state_changed_at,
                "components": self._components,
                "transition_log": self._transition_log[-20:],
            }
            with open(STATE_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error("Failed to save state: %s", e)

    def _load_state(self):
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE) as f:
                    data = json.load(f)
                saved_state = data.get("state", "BOOTING")
                try:
                    self._state = ProtectionState(saved_state)
                except ValueError:
                    self._state = ProtectionState.BOOTING
                self._previous_state = ProtectionState(data.get("previous_state", self._state.value))
                self._state_changed_at = data.get("state_changed_at", time.time())
                self._components = data.get("components", {})
                self._transition_log = data.get("transition_log", [])
                logger.info("Loaded state: %s", self._state.value)
        except Exception as e:
            logger.error("Failed to load state: %s", e)

    def clear_state(self):
        """Reset state to BOOTING (for reboot/recovery)."""
        with self._lock:
            self._state = ProtectionState.BOOTING
            self._previous_state = ProtectionState.BOOTING
            self._state_changed_at = time.time()
            self._save_state()


# ── Global instance ───────────────────────────────────────────────
_manager: Optional[StateManager] = None


def get_state_manager() -> StateManager:
    global _manager
    if _manager is None:
        _manager = StateManager()
    return _manager
