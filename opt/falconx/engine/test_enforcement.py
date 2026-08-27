#!/usr/bin/env python3
"""FALCON-X Enforcement Tests.

Tests the enforcement abstraction layer using mocked nftables.
Does NOT require root or nftables for unit tests.
Integration tests require nftables and are skipped if unavailable.
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE_DIR)

from enforcement import EnforcementEngine, EnforcementAction


class TestEnforcementAction(unittest.TestCase):
    def test_creation(self):
        action = EnforcementAction("block_ip", "10.0.0.1", "test reason")
        self.assertEqual(action.action_type, "block_ip")
        self.assertEqual(action.target, "10.0.0.1")
        self.assertEqual(action.reason, "test reason")
        self.assertTrue(action.active)
        self.assertFalse(action.is_expired())

    def test_expiry(self):
        action = EnforcementAction("block_ip", "10.0.0.1", "test", expires=time.time() - 1)
        self.assertTrue(action.is_expired())

    def test_not_expired(self):
        action = EnforcementAction("block_ip", "10.0.0.1", "test", expires=time.time() + 3600)
        self.assertFalse(action.is_expired())

    def test_to_dict(self):
        action = EnforcementAction("block_ip", "10.0.0.1", "test")
        d = action.to_dict()
        self.assertIn("action_type", d)
        self.assertIn("target", d)
        self.assertIn("reason", d)
        self.assertIn("timestamp", d)
        self.assertIn("active", d)


class TestEnforcementEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cmd_dir = os.path.join(self.tmpdir, "enforcer")
        os.makedirs(self.cmd_dir)
        os.environ["COMMAND_DIR"] = self.cmd_dir

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("enforcement.COMMAND_DIR")
    def test_log_only_mode(self, mock_cmd_dir):
        mock_cmd_dir.__class__ = str
        mock_cmd_dir.__init__ = lambda *a: None
        # Override at instance level
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="log-only", risk_threshold_alert=30, min_confidence=0.5)

        # Below threshold — no action
        result = engine.evaluate(20, 0.9, "10.0.0.1", [])
        self.assertIsNone(result)

        # Above alert threshold — creates alert (not block in log-only)
        result = engine.evaluate(65, 0.9, "10.0.0.1", [])
        self.assertIsNotNone(result)
        self.assertEqual(result.action_type, "alert")

    @patch("enforcement.COMMAND_DIR")
    def test_active_mode_block(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="active", risk_threshold_block=80, risk_threshold_alert=60, min_confidence=0.5)

        # Mock _send_command to succeed
        engine._send_command = MagicMock(return_value=True)

        # Below block threshold — alert only
        result = engine.evaluate(65, 0.9, "10.0.0.1", [])
        self.assertIsNotNone(result)
        self.assertEqual(result.action_type, "alert")

        # Above block threshold — block
        result = engine.evaluate(85, 0.9, "10.0.0.1", [])
        self.assertIsNotNone(result)
        self.assertEqual(result.action_type, "block_ip")
        self.assertTrue(engine.is_blocked("10.0.0.1"))

    @patch("enforcement.COMMAND_DIR")
    def test_duplicate_block_prevention(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="active", risk_threshold_block=80, min_confidence=0.5)
        engine._send_command = MagicMock(return_value=True)

        engine.evaluate(85, 0.9, "10.0.0.1", [])
        result = engine.evaluate(85, 0.9, "10.0.0.1", [])
        self.assertIsNone(result)  # Duplicate — should return None

    @patch("enforcement.COMMAND_DIR")
    def test_unblock_ip(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="active", risk_threshold_block=80, min_confidence=0.5)
        engine._send_command = MagicMock(return_value=True)

        engine.evaluate(85, 0.9, "10.0.0.1", [])
        self.assertTrue(engine.is_blocked("10.0.0.1"))

        result = engine.unblock("10.0.0.1")
        self.assertTrue(result)
        self.assertFalse(engine.is_blocked("10.0.0.1"))

    @patch("enforcement.COMMAND_DIR")
    def test_unblock_nonexistent(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="active")
        result = engine.unblock("10.0.0.99")
        self.assertFalse(result)

    @patch("enforcement.COMMAND_DIR")
    def test_block_port(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="active")
        engine._send_command = MagicMock(return_value=True)

        action = engine.block_port("443", reason="test")
        self.assertIsNotNone(action)
        self.assertEqual(action.action_type, "block_port")
        self.assertTrue(engine.is_port_blocked("443"))

    @patch("enforcement.COMMAND_DIR")
    def test_unblock_port(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="active")
        engine._send_command = MagicMock(return_value=True)

        engine.block_port("443")
        self.assertTrue(engine.is_port_blocked("443"))

        result = engine.unblock_port("443")
        self.assertTrue(result)
        self.assertFalse(engine.is_port_blocked("443"))

    @patch("enforcement.COMMAND_DIR")
    def test_max_blocked_limit(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="active", max_blocked=3, risk_threshold_block=60, min_confidence=0.5)
        engine._send_command = MagicMock(return_value=True)

        for i in range(3):
            engine.evaluate(85, 0.9, f"10.0.0.{i+1}", [])

        # Fourth should fail
        result = engine.evaluate(85, 0.9, "10.0.0.100", [])
        self.assertIsNone(result)

    @patch("enforcement.COMMAND_DIR")
    def test_confidence_threshold(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="active", min_confidence=0.8)

        # Low confidence — no action
        result = engine.evaluate(90, 0.5, "10.0.0.1", [])
        self.assertIsNone(result)

        # High confidence — action
        result = engine.evaluate(90, 0.9, "10.0.0.1", [])
        self.assertIsNotNone(result)

    @patch("enforcement.COMMAND_DIR")
    def test_stats(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="log-only")
        stats = engine.get_stats()
        self.assertEqual(stats["mode"], "log-only")
        self.assertEqual(stats["active_ip_blocks"], 0)
        self.assertEqual(stats["active_port_blocks"], 0)

    @patch("enforcement.COMMAND_DIR")
    def test_enforcer_status(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="log-only")
        status = engine.get_enforcer_status()
        self.assertIn("running", status)
        self.assertFalse(status["running"])

    @patch("enforcement.COMMAND_DIR")
    def test_action_history(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="log-only", risk_threshold_alert=30, min_confidence=0.5)

        for i in range(5):
            engine.evaluate(65, 0.9, f"10.0.0.{i+1}", [])

        self.assertEqual(len(engine._action_history), 5)
        self.assertEqual(engine._total_actions, 5)


class TestEnforcementIPC(unittest.TestCase):
    """Test the file-based IPC mechanism."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cmd_dir = os.path.join(self.tmpdir, "enforcer")
        os.makedirs(self.cmd_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("enforcement.COMMAND_DIR")
    def test_command_file_creation(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="active", risk_threshold_block=80, min_confidence=0.5)
        engine._send_command = MagicMock(return_value=True)

        engine.evaluate(85, 0.9, "10.0.0.1", [])
        engine._send_command.assert_called_once()

    @patch("enforcement.COMMAND_DIR")
    def test_command_file_format(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="active", risk_threshold_block=80, min_confidence=0.5)

        # Capture the command that would be sent
        sent_commands = []
        original_send = engine._send_command

        def capture_send(action, target, timeout, reason, actor):
            sent_commands.append({
                "action": action, "target": target,
                "timeout": timeout, "reason": reason, "actor": actor
            })
            return True

        engine._send_command = capture_send
        engine.evaluate(85, 0.9, "10.0.0.1", [])

        self.assertEqual(len(sent_commands), 1)
        cmd = sent_commands[0]
        self.assertEqual(cmd["action"], "block_ip")
        self.assertEqual(cmd["target"], "10.0.0.1")
        self.assertEqual(cmd["actor"], "engine")
        self.assertIn("Risk=", cmd["reason"])

    @patch("enforcement.COMMAND_DIR")
    def test_unblock_command_format(self, mock_cmd_dir):
        import enforcement
        enforcement.COMMAND_DIR = self.cmd_dir

        engine = EnforcementEngine(mode="active", risk_threshold_block=80, min_confidence=0.5)

        sent_commands = []
        def capture_send(action, target, timeout, reason, actor):
            sent_commands.append({"action": action, "target": target, "actor": actor})
            return True

        engine._send_command = capture_send

        engine.evaluate(85, 0.9, "10.0.0.1", [])
        engine.unblock("10.0.0.1")

        self.assertEqual(len(sent_commands), 2)
        self.assertEqual(sent_commands[1]["action"], "unblock_ip")
        self.assertEqual(sent_commands[1]["actor"], "operator")


if __name__ == "__main__":
    unittest.main(verbosity=2)
