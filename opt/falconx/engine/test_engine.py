"""FALCON-X Engine — Test suite.

Safe synthetic traffic tests for the detection engine.
Does not require network access or Scapy.
"""

import os
import sys
import time
import unittest

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE_DIR)

from features import FeatureExtractor, Flow
from baseline import NetworkBaseline, DeviceProfile
from rules import RuleEngine
from anomaly import StatisticalDetector, StreamingStats
from risk import RiskEngine
from incidents import IncidentEngine
from enforcement import EnforcementEngine


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor(flow_timeout=5, max_flows=1000)

    def _make_packet(self, src_ip="192.168.1.10", dst_ip="8.8.8.8",
                     src_port=12345, dst_port=80, protocol="TCP",
                     size=64, is_syn=False, is_rst=False, is_fin=False):
        """Create a mock PacketMetadata-like object."""
        class MockMeta:
            pass
        m = MockMeta()
        m.timestamp = time.time()
        m.src_ip = src_ip
        m.dst_ip = dst_ip
        m.src_port = src_port
        m.dst_port = dst_port
        m.protocol = protocol
        m.size = size
        m.is_syn = is_syn
        m.is_rst = is_rst
        m.is_fin = is_fin
        m.dns_query = ""
        m.dns_type = ""
        m.icmp_type = -1
        m.arp_op = 0
        m.arp_src_mac = ""
        m.arp_dst_mac = ""
        m.raw_entropy = 0.0
        return m

    def test_basic_flow_tracking(self):
        pkts = [self._make_packet() for _ in range(5)]
        results = self.extractor.process_batch(pkts)
        self.assertEqual(len(results), 0)  # No expired flows yet

    def test_flow_expiry(self):
        pkts = [self._make_packet()]
        self.extractor.process_batch(pkts)
        # Wait for flow timeout
        time.sleep(0.1)
        self.extractor.flow_timeout = 0.05
        time.sleep(0.1)
        results = self.extractor.process_batch([self._make_packet(size=128)])
        self.assertGreater(len(results), 0)

    def test_features_extracted(self):
        pkts = [self._make_packet(size=100, is_syn=True)]
        self.extractor.process_batch(pkts)
        time.sleep(0.15)
        self.extractor.flow_timeout = 0.05
        time.sleep(0.1)
        results = self.extractor.process_batch([])
        if results:
            f = results[0]
            self.assertIn("packets_per_second", f)
            self.assertIn("byte_count", f)
            self.assertIn("tcp_syn_rate", f)

    def test_multiple_flows(self):
        pkts = [
            self._make_packet(src_ip="10.0.0.1", dst_port=80),
            self._make_packet(src_ip="10.0.0.2", dst_port=443),
            self._make_packet(src_ip="10.0.0.1", dst_port=80),
        ]
        self.extractor.process_batch(pkts)
        self.assertEqual(self.extractor.get_active_flow_count(), 2)

    def test_max_flows_eviction(self):
        extractor = FeatureExtractor(max_flows=5)
        for i in range(10):
            extractor.process_batch([
                self._make_packet(src_ip=f"10.0.0.{i}", dst_port=i)
            ])
        self.assertLessEqual(extractor.get_active_flow_count(), 5)


class TestBaseline(unittest.TestCase):
    def setUp(self):
        self.baseline = NetworkBaseline(
            learning_period_hours=0,
            min_samples=5,
            storage_path="/tmp/falconx-test-baseline",
        )

    def _make_features(self, src_ip="192.168.1.10", **kwargs):
        base = {
            "src_ip": src_ip,
            "dst_ip": "8.8.8.8",
            "dst_port": 80,
            "protocol": "TCP",
            "packets_per_second": 10.0,
            "bytes_per_second": 1000.0,
            "tcp_syn_rate": 0.1,
            "avg_packet_size": 100.0,
            "unique_dst_ports": 1,
            "byte_count": 1000,
            "packet_count": 10,
        }
        base.update(kwargs)
        return base

    def test_device_creation(self):
        features = self._make_features()
        result = self.baseline.process_features([features])
        self.assertEqual(len(result), 1)

    def test_learning_phase(self):
        for i in range(10):
            self.baseline.process_features([self._make_features()])
        stats = self.baseline.get_stats()
        self.assertGreater(stats["total_flows"], 0)

    def test_anomaly_score_baseline(self):
        # Build baseline with normal traffic
        for i in range(20):
            self.baseline.process_features([
                self._make_features(packets_per_second=10.0)
            ])
        # Anomalous traffic
        result = self.baseline.process_features([
            self._make_features(packets_per_second=1000.0)
        ])
        self.assertGreater(result[0]["anomaly_score"], 0)


class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine({
            "port_scan": {"enabled": True, "threshold_unique_ports": 5, "severity": "HIGH"},
            "syn_flood": {"enabled": True, "threshold_pps": 10, "threshold_syn_ratio": 0.8, "severity": "CRITICAL"},
            "dns_anomaly": {"enabled": True, "threshold_queries_per_minute": 5, "severity": "MEDIUM"},
            "arp_anomaly": {"enabled": True, "threshold_arp_per_second": 5, "severity": "HIGH"},
            "unknown_device": {"enabled": True, "severity": "LOW"},
            "brute_force": {"enabled": True, "threshold_attempts": 3, "severity": "HIGH"},
            "data_exfiltration": {"enabled": True, "threshold_outbound_mb": 1, "severity": "CRITICAL"},
            "icmp_flood": {"enabled": True, "threshold_pps": 5, "severity": "HIGH"},
            "unusual_protocol": {"enabled": True, "severity": "MEDIUM"},
        })

    def test_port_scan_detection(self):
        events = []
        for port in range(1, 10):
            f = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dst_port": port,
                 "protocol": "TCP", "tcp_syn_rate": 0.5}
            events.extend(self.engine.evaluate(f))
        self.assertTrue(any(e.rule_name == "port_scan" for e in events))

    def test_syn_flood_detection(self):
        events = []
        for _ in range(15):
            f = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dst_port": 80,
                 "protocol": "TCP", "tcp_syn_rate": 0.9}
            events.extend(self.engine.evaluate(f))
        self.assertTrue(any(e.rule_name == "syn_flood" for e in events))

    def test_unknown_device_detection(self):
        f = {"src_ip": "10.0.0.99", "dst_ip": "8.8.8.8", "dst_port": 80,
             "protocol": "TCP", "device_status": "UNKNOWN"}
        events = self.engine.evaluate(f)
        self.assertTrue(any(e.rule_name == "unknown_device" for e in events))

    def test_no_events_normal_traffic(self):
        f = {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_port": 80,
             "protocol": "TCP", "tcp_syn_rate": 0.1, "device_status": "KNOWN"}
        events = self.engine.evaluate(f)
        self.assertEqual(len(events), 0)


class TestStatisticalDetector(unittest.TestCase):
    def setUp(self):
        self.detector = StatisticalDetector(z_threshold=2.0, min_history=5)

    def test_normal_traffic_no_anomaly(self):
        for _ in range(20):
            result = self.detector.analyze({
                "src_ip": "10.0.0.1",
                "packets_per_second": 10.0,
                "bytes_per_second": 1000.0,
            })
        self.assertIsNone(result)

    def test_spike_detected(self):
        for _ in range(20):
            self.detector.analyze({
                "src_ip": "10.0.0.1",
                "packets_per_second": 10.0,
                "bytes_per_second": 1000.0,
            })
        result = self.detector.analyze({
            "src_ip": "10.0.0.1",
            "packets_per_second": 1000.0,
            "bytes_per_second": 100000.0,
        })
        self.assertIsNotNone(result)


class TestRiskEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RiskEngine()

    def test_low_risk(self):
        risk = self.engine.assess(
            features={"anomaly_score": 0.1, "device_reputation": 0.9, "device_status": "KNOWN"},
            detection_events=[],
        )
        self.assertLess(risk.score, 30)
        self.assertEqual(risk.level, "LOW")

    def test_critical_risk(self):
        from rules import DetectionEvent
        events = [DetectionEvent(
            rule_name="port_scan", severity="CRITICAL", confidence=0.9,
            src_ip="10.0.0.1", dst_ip="192.168.1.1", description="test",
        )]
        risk = self.engine.assess(
            features={"anomaly_score": 0.9, "device_reputation": 0.1, "device_status": "UNKNOWN"},
            detection_events=events,
        )
        self.assertGreaterEqual(risk.score, 60)

    def test_reasoning_populated(self):
        risk = self.engine.assess(
            features={"anomaly_score": 0.5, "device_status": "UNKNOWN"},
            detection_events=[],
        )
        self.assertGreater(len(risk.reasoning), 0)


class TestIncidentEngine(unittest.TestCase):
    def setUp(self):
        self.engine = IncidentEngine(storage_path="/tmp/falconx-test-incidents")

    def test_incident_creation(self):
        inc = self.engine.process_detection(
            device_ip="10.0.0.1",
            event_type="port_scan",
            severity="HIGH",
            risk_score=70,
            confidence=0.8,
        )
        self.assertIsNotNone(inc)
        self.assertEqual(inc.status, "OPEN")

    def test_deduplication(self):
        inc1 = self.engine.process_detection(
            device_ip="10.0.0.1", event_type="port_scan",
            severity="HIGH", risk_score=70, confidence=0.8,
        )
        inc2 = self.engine.process_detection(
            device_ip="10.0.0.1", event_type="port_scan",
            severity="HIGH", risk_score=70, confidence=0.8,
        )
        # Should deduplicate
        self.assertEqual(inc1.incident_id, inc2.incident_id)

    def test_incident_resolution(self):
        inc = self.engine.process_detection(
            device_ip="10.0.0.1", event_type="port_scan",
            severity="HIGH", risk_score=70, confidence=0.8,
        )
        result = self.engine.resolve_incident(inc.incident_id, note="False alarm")
        self.assertTrue(result)
        self.assertEqual(len(self.engine.get_open_incidents()), 0)

    def test_false_positive(self):
        inc = self.engine.process_detection(
            device_ip="10.0.0.1", event_type="port_scan",
            severity="HIGH", risk_score=70, confidence=0.8,
        )
        result = self.engine.mark_false_positive(inc.incident_id)
        self.assertTrue(result)


class TestEnforcementEngine(unittest.TestCase):
    def setUp(self):
        self.engine = EnforcementEngine(mode="log-only")

    def test_log_only_mode(self):
        action = self.engine.evaluate(
            risk_score=90, confidence=0.95,
            device_ip="10.0.0.1", detection_events=[],
        )
        self.assertIsNotNone(action)
        self.assertEqual(action.action_type, "alert")

    def test_below_threshold(self):
        action = self.engine.evaluate(
            risk_score=20, confidence=0.9,
            device_ip="10.0.0.1", detection_events=[],
        )
        self.assertIsNone(action)

    def test_low_confidence_blocked(self):
        action = self.engine.evaluate(
            risk_score=90, confidence=0.3,
            device_ip="10.0.0.1", detection_events=[],
        )
        self.assertIsNone(action)


class TestStreamingStats(unittest.TestCase):
    def test_basic_stats(self):
        stats = StreamingStats()
        for v in [10, 12, 11, 10, 13, 9, 11, 12, 10, 11]:
            stats.update(v)
        self.assertAlmostEqual(stats.mean, 10.9, places=1)
        self.assertGreater(stats.std(), 0)

    def test_z_score(self):
        stats = StreamingStats()
        for _ in range(20):
            stats.update(10.0)
        z = stats.z_score(10.0)
        self.assertAlmostEqual(z, 0.0, places=1)

    def test_anomalous_z_score(self):
        stats = StreamingStats()
        for _ in range(20):
            stats.update(10.0)
        z = stats.z_score(100.0)
        self.assertGreater(z, 3.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
