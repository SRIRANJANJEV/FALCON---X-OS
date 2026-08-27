#!/usr/bin/env python3
"""FALCON-X Protection State Machine Tests.

Tests state transitions, component health tracking, and recovery.
Does NOT require nftables or Raspberry Pi hardware.
"""

import json
import os
import sys
import tempfile
import time
import unittest

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE_DIR)

from state import StateManager, ProtectionState, CRITICAL_COMPONENTS, OPTIONAL_COMPONENTS, get_state_manager


class TestProtectionState(unittest.TestCase):
    def test_state_values(self):
        self.assertEqual(ProtectionState.BOOTING.value, "BOOTING")
        self.assertEqual(ProtectionState.PROTECTED.value, "PROTECTED")
        self.assertEqual(ProtectionState.DEGRADED.value, "DEGRADED")
        self.assertEqual(ProtectionState.UNPROTECTED.value, "UNPROTECTED")
        self.assertEqual(ProtectionState.RECOVERY.value, "RECOVERY")

    def test_is_operational(self):
        self.assertTrue(ProtectionState.PROTECTED.is_operational())
        self.assertTrue(ProtectionState.DEGRADED.is_operational())
        self.assertFalse(ProtectionState.UNPROTECTED.is_operational())
        self.assertFalse(ProtectionState.BOOTING.is_operational())
        self.assertFalse(ProtectionState.RECOVERY.is_operational())


class TestStateMachine(unittest.TestCase):
    def setUp(self):
        # Use a fresh state manager with temp file
        self.state_file = tempfile.mktemp(suffix=".json")
        import state
        state.STATE_FILE = self.state_file
        self.sm = StateManager()
        # Clear any loaded state
        self.sm.clear_state()

    def tearDown(self):
        if os.path.exists(self.state_file):
            os.remove(self.state_file)

    def test_initial_state(self):
        self.assertEqual(self.sm.state, ProtectionState.BOOTING)

    def test_transition_to_initializing(self):
        result = self.sm.transition(ProtectionState.INITIALIZING, "test")
        self.assertTrue(result)
        self.assertEqual(self.sm.state, ProtectionState.INITIALIZING)

    def test_transition_to_protected(self):
        self.sm.transition(ProtectionState.INITIALIZING)
        result = self.sm.transition(ProtectionState.PROTECTED, "all good")
        self.assertTrue(result)
        self.assertEqual(self.sm.state, ProtectionState.PROTECTED)

    def test_transition_to_degraded(self):
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)
        result = self.sm.transition(ProtectionState.DEGRADED, "web down")
        self.assertTrue(result)
        self.assertEqual(self.sm.state, ProtectionState.DEGRADED)

    def test_transition_to_unprotected(self):
        self.sm.transition(ProtectionState.INITIALIZING)
        result = self.sm.transition(ProtectionState.UNPROTECTED, "engine down")
        self.assertTrue(result)
        self.assertEqual(self.sm.state, ProtectionState.UNPROTECTED)

    def test_recovery_from_unprotected(self):
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.UNPROTECTED)
        result = self.sm.transition(ProtectionState.RECOVERY, "attempting recovery")
        self.assertTrue(result)
        self.assertEqual(self.sm.state, ProtectionState.RECOVERY)

    def test_recovery_to_protected(self):
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.UNPROTECTED)
        self.sm.transition(ProtectionState.RECOVERY)
        result = self.sm.transition(ProtectionState.PROTECTED, "recovered")
        self.assertTrue(result)
        self.assertEqual(self.sm.state, ProtectionState.PROTECTED)

    def test_invalid_transition_blocked(self):
        self.sm.transition(ProtectionState.INITIALIZING)
        # Can't go directly from INITIALIZING to RECOVERY
        result = self.sm.transition(ProtectionState.RECOVERY, "test")
        self.assertFalse(result)
        self.assertEqual(self.sm.state, ProtectionState.INITIALIZING)

    def test_same_state_noop(self):
        self.sm.transition(ProtectionState.INITIALIZING)
        result = self.sm.transition(ProtectionState.INITIALIZING, "same state")
        self.assertTrue(result)
        self.assertEqual(self.sm.state, ProtectionState.INITIALIZING)


class TestComponentHealth(unittest.TestCase):
    def setUp(self):
        self.state_file = tempfile.mktemp(suffix=".json")
        import state
        state.STATE_FILE = self.state_file
        self.sm = StateManager()
        self.sm.clear_state()

    def tearDown(self):
        if os.path.exists(self.state_file):
            os.remove(self.state_file)

    def test_critical_component_failure(self):
        """Engine failure → UNPROTECTED."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        self.sm.update_component("engine", False, "Engine crashed")
        self.assertEqual(self.sm.state, ProtectionState.UNPROTECTED)

    def test_firewall_failure(self):
        """Firewall failure → UNPROTECTED."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        self.sm.update_component("firewall", False, "nftables not loaded")
        self.assertEqual(self.sm.state, ProtectionState.UNPROTECTED)

    def test_capture_failure(self):
        """Capture failure → UNPROTECTED."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        self.sm.update_component("capture", False, "Scapy unavailable")
        self.assertEqual(self.sm.state, ProtectionState.UNPROTECTED)

    def test_network_failure(self):
        """Network failure → UNPROTECTED."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        self.sm.update_component("network", False, "No default route")
        self.assertEqual(self.sm.state, ProtectionState.UNPROTECTED)

    def test_rules_failure(self):
        """Rules failure → UNPROTECTED."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        self.sm.update_component("rules", False, "Rules crash")
        self.assertEqual(self.sm.state, ProtectionState.UNPROTECTED)

    def test_baseline_failure(self):
        """Baseline failure → UNPROTECTED."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        self.sm.update_component("baseline", False, "Baseline corruption")
        self.assertEqual(self.sm.state, ProtectionState.UNPROTECTED)

    def test_optional_component_failure(self):
        """Web failure → DEGRADED."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        self.sm.update_component("web", False, "Dashboard down")
        self.assertEqual(self.sm.state, ProtectionState.DEGRADED)

    def test_ai_failure_is_degraded(self):
        """AI failure → DEGRADED (not UNPROTECTED)."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        self.sm.update_component("ai", False, "OmniRoute unavailable")
        self.assertEqual(self.sm.state, ProtectionState.DEGRADED)

    def test_ml_failure_is_degraded(self):
        """ML failure → DEGRADED."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        self.sm.update_component("ml", False, "Model training failed")
        self.assertEqual(self.sm.state, ProtectionState.DEGRADED)

    def test_enforcement_failure_is_degraded(self):
        """Enforcement failure → DEGRADED."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        self.sm.update_component("enforcement", False, "Enforcer down")
        self.assertEqual(self.sm.state, ProtectionState.DEGRADED)

    def test_all_critical_healthy_is_protected(self):
        """All critical + optional healthy → PROTECTED."""
        self.sm.transition(ProtectionState.INITIALIZING)

        for comp in CRITICAL_COMPONENTS:
            self.sm.update_component(comp, True, f"{comp} ok")
        for comp in OPTIONAL_COMPONENTS:
            self.sm.update_component(comp, True, f"{comp} ok")

        self.assertEqual(self.sm.state, ProtectionState.PROTECTED)

    def test_critical_and_optional_mix(self):
        """All critical healthy but some optional fail → DEGRADED."""
        self.sm.transition(ProtectionState.INITIALIZING)

        for comp in CRITICAL_COMPONENTS:
            self.sm.update_component(comp, True, f"{comp} ok")

        # Web fails
        self.sm.update_component("web", False, "Dashboard down")
        self.assertEqual(self.sm.state, ProtectionState.DEGRADED)

    def test_recovery_after_critical_failure(self):
        """UNPROTECTED → RECOVERY → PROTECTED when critical recovers."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        # Engine fails
        self.sm.update_component("engine", False, "Engine down")
        self.assertEqual(self.sm.state, ProtectionState.UNPROTECTED)

        # Recovery starts
        self.sm.transition(ProtectionState.RECOVERY, "Attempting recovery")
        self.assertEqual(self.sm.state, ProtectionState.RECOVERY)

        # Engine recovers
        self.sm.update_component("engine", True, "Engine recovered")
        self.assertEqual(self.sm.state, ProtectionState.PROTECTED)

    def test_recovery_after_optional_failure(self):
        """DEGRADED → PROTECTED when optional recovers."""
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.transition(ProtectionState.PROTECTED)

        # Web fails
        self.sm.update_component("web", False, "Dashboard down")
        self.assertEqual(self.sm.state, ProtectionState.DEGRADED)

        # Web recovers
        self.sm.update_component("web", True, "Dashboard up")
        self.assertEqual(self.sm.state, ProtectionState.PROTECTED)


class TestPersistence(unittest.TestCase):
    def setUp(self):
        self.state_file = tempfile.mktemp(suffix=".json")
        import state
        state.STATE_FILE = self.state_file

    def tearDown(self):
        if os.path.exists(self.state_file):
            os.remove(self.state_file)

    def test_state_persists_across_instances(self):
        sm1 = StateManager()
        sm1.transition(ProtectionState.INITIALIZING)
        sm1.transition(ProtectionState.PROTECTED)
        sm1.update_component("engine", True, "ok")

        # Create new instance — should load persisted state
        sm2 = StateManager()
        self.assertEqual(sm2.state, ProtectionState.PROTECTED)
        self.assertIn("engine", sm2.get_all_components())

    def test_state_file_created(self):
        sm = StateManager()
        sm.transition(ProtectionState.INITIALIZING)
        self.assertTrue(os.path.exists(self.state_file))


class TestListeners(unittest.TestCase):
    def setUp(self):
        self.state_file = tempfile.mktemp(suffix=".json")
        import state
        state.STATE_FILE = self.state_file
        self.sm = StateManager()
        self.sm.clear_state()

    def tearDown(self):
        if os.path.exists(self.state_file):
            os.remove(self.state_file)

    def test_listener_called_on_transition(self):
        transitions = []
        def listener(old, new, reason):
            transitions.append((old, new, reason))

        self.sm.add_listener(listener)
        self.sm.transition(ProtectionState.INITIALIZING, "test")

        self.assertEqual(len(transitions), 1)
        self.assertEqual(transitions[0][0], ProtectionState.BOOTING)
        self.assertEqual(transitions[0][1], ProtectionState.INITIALIZING)

    def test_listener_exception_doesnt_crash(self):
        def bad_listener(old, new, reason):
            raise RuntimeError("listener error")

        self.sm.add_listener(bad_listener)
        # Should not raise
        self.sm.transition(ProtectionState.INITIALIZING, "test")


class TestSummary(unittest.TestCase):
    def setUp(self):
        self.state_file = tempfile.mktemp(suffix=".json")
        import state
        state.STATE_FILE = self.state_file
        self.sm = StateManager()
        self.sm.clear_state()

    def tearDown(self):
        if os.path.exists(self.state_file):
            os.remove(self.state_file)

    def test_summary_structure(self):
        self.sm.transition(ProtectionState.INITIALIZING)
        self.sm.update_component("engine", True, "ok")
        self.sm.update_component("web", False, "down")

        summary = self.sm.get_summary()
        self.assertIn("state", summary)
        self.assertIn("previous_state", summary)
        self.assertIn("components", summary)
        self.assertIn("critical_components", summary)
        self.assertIn("optional_components", summary)
        self.assertIn("recent_transitions", summary)

    def test_summary_components(self):
        self.sm.update_component("engine", True, "ok")
        self.sm.update_component("web", True, "ok")

        summary = self.sm.get_summary()
        self.assertIn("engine", summary["components"])
        self.assertIn("web", summary["components"])
        self.assertTrue(summary["components"]["engine"]["healthy"])
        self.assertTrue(summary["components"]["web"]["healthy"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
