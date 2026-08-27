#!/usr/bin/env python3
"""FALCON-X ML and AI Tests.

Tests ML lifecycle, data collection, training, and AI integration.
Does NOT require scikit-learn or network hardware.
"""

import json
import math
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE_DIR)

from ml_interface import MLInterface, MLState, ML_FEATURES, MIN_SAMPLES_FOR_TRAINING


class TestMLLifecycle(unittest.TestCase):
    def setUp(self):
        self.model_path = tempfile.mkdtemp()
        self.ml = MLInterface(model_path=self.model_path, enabled=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.model_path, ignore_errors=True)

    def test_initial_state_learning(self):
        """ML starts in LEARNING state when no model exists."""
        self.assertEqual(self.ml.state, MLState.LEARNING)

    def test_disabled_state(self):
        """ML in DISABLED state when enabled=False."""
        ml = MLInterface(enabled=False)
        self.assertEqual(ml.state, MLState.DISABLED)

    def test_predict_returns_collecting(self):
        """During LEARNING, predict returns collecting status."""
        features = {f: 1.0 for f in ML_FEATURES[:16]}
        result = self.ml.predict(features)
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "ml_collecting")
        self.assertEqual(result["ml_state"], "LEARNING")
        self.assertFalse(result["is_anomaly"])

    def test_data_collection(self):
        """Real traffic data is collected into buffer."""
        for i in range(10):
            features = {f: float(i) for f in ML_FEATURES[:16]}
            self.ml.predict(features)

        self.assertEqual(len(self.ml._data_buffer), 10)

    def test_sample_count(self):
        """Sample count increments with real data."""
        features = {f: 1.0 for f in ML_FEATURES[:16]}
        self.ml.update([features, features])
        self.assertEqual(self.ml._sample_count, 2)

    def test_buffer_bounded(self):
        """Data buffer is bounded to MAX_DATA_BUFFER."""
        from ml_interface import MAX_DATA_BUFFER
        features = {f: 1.0 for f in ML_FEATURES[:16]}
        for i in range(MAX_DATA_BUFFER + 100):
            self.ml.predict(features)
        self.assertLessEqual(len(self.ml._data_buffer), MAX_DATA_BUFFER)


class TestMLFeatureExtraction(unittest.TestCase):
    def setUp(self):
        self.ml = MLInterface(enabled=True)

    def test_normal_features(self):
        features = {f: 1.0 for f in ML_FEATURES[:16]}
        vec = self.ml.extract_feature_vector(features)
        self.assertIsNotNone(vec)
        self.assertEqual(len(vec), 16)

    def test_nan_handling(self):
        """NaN values are replaced with 0.0."""
        features = {f: float('nan') for f in ML_FEATURES[:16]}
        vec = self.ml.extract_feature_vector(features)
        self.assertIsNotNone(vec)
        for v in vec:
            self.assertFalse(math.isnan(v))

    def test_inf_handling(self):
        """Inf values are replaced with 0.0."""
        features = {f: float('inf') for f in ML_FEATURES[:16]}
        vec = self.ml.extract_feature_vector(features)
        self.assertIsNotNone(vec)
        for v in vec:
            self.assertFalse(math.isinf(v))

    def test_none_handling(self):
        """None values are replaced with 0.0."""
        features = {f: None for f in ML_FEATURES[:16]}
        vec = self.ml.extract_feature_vector(features)
        self.assertIsNotNone(vec)
        for v in vec:
            self.assertEqual(v, 0.0)

    def test_string_handling(self):
        """Non-numeric values are replaced with 0.0."""
        features = {f: "not_a_number" for f in ML_FEATURES[:16]}
        vec = self.ml.extract_feature_vector(features)
        self.assertIsNotNone(vec)
        for v in vec:
            self.assertEqual(v, 0.0)

    def test_extreme_values_clamped(self):
        """Extreme values are clamped to ±1e6."""
        features = {f: 1e10 for f in ML_FEATURES[:16]}
        vec = self.ml.extract_feature_vector(features)
        for v in vec:
            self.assertLessEqual(v, 1e6)

    def test_negative_values(self):
        """Negative values pass through correctly."""
        features = {f: -100.0 for f in ML_FEATURES[:16]}
        vec = self.ml.extract_feature_vector(features)
        for v in vec:
            self.assertEqual(v, -100.0)


class TestMLStats(unittest.TestCase):
    def test_stats_structure(self):
        ml = MLInterface(enabled=True)
        stats = ml.get_stats()
        self.assertIn("enabled", stats)
        self.assertIn("state", stats)
        self.assertIn("sample_count", stats)
        self.assertIn("buffer_size", stats)
        self.assertIn("training_count", stats)
        self.assertIn("validation_score", stats)

    def test_disabled_stats(self):
        ml = MLInterface(enabled=False)
        stats = ml.get_stats()
        self.assertFalse(stats["enabled"])
        self.assertEqual(stats["state"], "DISABLED")


class TestMLPersistence(unittest.TestCase):
    def setUp(self):
        self.model_path = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.model_path, ignore_errors=True)

    def test_no_model_on_disk(self):
        """No model files exist initially."""
        ml = MLInterface(model_path=self.model_path)
        self.assertFalse(os.path.exists(os.path.join(self.model_path, "anomaly_model.pkl")))


class TestMLUnavailable(unittest.TestCase):
    def test_unavailable_when_no_sklearn(self):
        """ML goes UNAVAILABLE when sklearn not present and training fails."""
        ml = MLInterface(enabled=True)
        # Simulate no sklearn
        ml._state = MLState.UNAVAILABLE
        result = ml.predict({f: 1.0 for f in ML_FEATURES[:16]})
        self.assertIsNone(result)


class TestAIOmniRoute(unittest.TestCase):
    """Test OmniRoute AI integration."""

    def setUp(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'dashboard'))
        from omniroute import OmniRouteClient
        self.client = OmniRouteClient(base_url="http://127.0.0.1:19999", timeout=2)

    def test_unavailable_by_default(self):
        """AI is unavailable when OmniRoute not running."""
        self.assertFalse(self.client.is_available())

    def test_analyze_returns_none_when_unavailable(self):
        """Analysis returns None when AI unavailable."""
        incident = {
            "event_type": "PORT_SCAN",
            "risk_score": 87,
            "device_ip": "192.168.1.20",
            "severity": "HIGH",
            "confidence": 0.9,
            "evidence": ["143 ports contacted"],
        }
        result = self.client.analyze_incident(incident)
        self.assertIsNone(result)

    def test_evidence_formatting(self):
        """Evidence is properly formatted and anonymized."""
        from omniroute import format_incident_evidence
        incident = {
            "event_type": "PORT_SCAN",
            "risk_score": 87,
            "device_ip": "192.168.1.20",
            "severity": "HIGH",
            "confidence": 0.9,
            "evidence": ["143 ports"],
            "timestamp_human": "2026-01-01T00:00:00Z",
        }
        evidence = format_incident_evidence(incident)
        self.assertIn("incident_type", evidence)
        self.assertIn("*", evidence["source_ip"])  # Anonymized
        self.assertEqual(evidence["incident_type"], "PORT_SCAN")

    def test_anonymize_ip(self):
        """IP anonymization works correctly."""
        from omniroute import _anonymize_ip
        self.assertEqual(_anonymize_ip("192.168.1.20"), "192.168.*.*")
        self.assertEqual(_anonymize_ip(""), "unknown")
        self.assertEqual(_anonymize_ip("10.0.0.1"), "10.0.*.*")

    def test_status_when_unavailable(self):
        """Status reports unavailable."""
        status = self.client.get_status()
        self.assertFalse(status["available"])
        self.assertIn("model", status)

    def test_parse_valid_json(self):
        """Valid JSON response is parsed correctly."""
        response = '{"summary":"test","possible_explanation":"test","confidence":0.8}'
        result = self.client._parse_response(response)
        self.assertIsNotNone(result)
        self.assertEqual(result["summary"], "test")
        self.assertEqual(result["confidence"], 0.8)

    def test_parse_invalid_json(self):
        """Invalid JSON falls back to free text."""
        result = self.client._parse_response("This is not JSON")
        self.assertIsNotNone(result)
        self.assertIn("summary", result)
        self.assertEqual(result["confidence"], 0.3)

    def test_parse_malformed_confidence(self):
        """Non-numeric confidence is handled."""
        response = '{"summary":"test","confidence":"not_a_number"}'
        result = self.client._parse_response(response)
        self.assertEqual(result["confidence"], 0.5)

    def test_parse_code_block(self):
        """JSON in code blocks is extracted."""
        response = '```json\n{"summary":"test","confidence":0.9}\n```'
        result = self.client._parse_response(response)
        self.assertIsNotNone(result)
        self.assertEqual(result["summary"], "test")


if __name__ == "__main__":
    unittest.main(verbosity=2)
