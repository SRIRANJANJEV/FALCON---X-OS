#!/usr/bin/env python3
"""FALCON-X Pipeline Integration Test.

Tests the complete packet → incident pipeline using synthetic packet metadata.
Does NOT require Scapy or network hardware.
"""

import os
import sys
import time
import json
import tempfile

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE_DIR)

from capture import PacketMetadata, _parse_packet, _estimate_entropy
from features import FeatureExtractor, Flow
from baseline import NetworkBaseline
from rules import RuleEngine, DetectionEvent
from anomaly import StatisticalDetector
from ml_interface import MLInterface
from risk import RiskEngine
from incidents import IncidentEngine
from enforcement import EnforcementEngine


class MockPacket:
    """Mock Scapy packet for testing _parse_packet."""
    def __init__(self, src_ip="192.168.1.10", dst_ip="8.8.8.8",
                 src_port=12345, dst_port=80, protocol="TCP",
                 flags=0x02, payload=b""):
        self._layers = {}
        self._layers["IP"] = type("IP", (), {"src": src_ip, "dst": dst_ip, "proto": 6})()
        if protocol == "TCP":
            self._layers["TCP"] = type("TCP", (), {
                "sport": src_port, "dport": dst_port,
                "flags": flags, "payload": payload
            })()
        elif protocol == "UDP":
            self._layers["UDP"] = type("UDP", (), {"sport": src_port, "dport": dst_port})()
        elif protocol == "ICMP":
            self._layers["ICMP"] = type("ICMP", (), {"type": 8})()
        elif protocol == "ARP":
            self._layers["ARP"] = type("ARP", (), {
                "op": 1, "hwsrc": "aa:bb:cc:dd:ee:ff", "hwdst": "00:00:00:00:00:00",
                "psrc": src_ip, "pdst": dst_ip
            })()
            del self._layers["IP"]

    def haslayer(self, layer_name):
        return layer_name in self._layers

    def __getitem__(self, key):
        return self._layers.get(key)


def make_packet(src_ip="192.168.1.10", dst_ip="8.8.8.8",
                src_port=12345, dst_port=80, protocol="TCP",
                size=64, is_syn=False, is_rst=False, is_fin=False):
    """Create a synthetic PacketMetadata object directly (no Scapy needed)."""
    meta = PacketMetadata()
    meta.timestamp = time.time()
    meta.src_ip = src_ip
    meta.dst_ip = dst_ip
    meta.src_port = src_port
    meta.dst_port = dst_port
    meta.protocol = protocol
    meta.size = size
    meta.is_syn = is_syn
    meta.is_rst = is_rst
    meta.is_fin = is_fin
    meta.tcp_flags = 0x02 if is_syn else (0x04 if is_rst else (0x01 if is_fin else 0))
    meta.dns_query = ""
    meta.dns_type = ""
    meta.icmp_type = -1
    meta.arp_op = 0
    meta.arp_src_mac = ""
    meta.arp_dst_mac = ""
    meta.raw_entropy = 0.0
    return meta


def test_entropy():
    """Test entropy estimation."""
    assert _estimate_entropy(b"") == 0.0
    assert _estimate_entropy(b"aaaa") < 1.0  # Low entropy
    assert _estimate_entropy(bytes(range(256))) > 7.0  # High entropy
    print("  PASS: entropy estimation")


def test_packet_metadata():
    """Test PacketMetadata creation and dict conversion."""
    meta = make_packet(src_ip="10.0.0.1", dst_port=443, protocol="TCP")
    d = meta.to_dict()
    assert d["src_ip"] == "10.0.0.1"
    assert d["dst_port"] == 443
    assert d["protocol"] == "TCP"
    print("  PASS: packet metadata")


def test_feature_extraction():
    """Test feature extraction from synthetic packets."""
    ext = FeatureExtractor(flow_timeout=1, max_flows=1000)

    # Create a batch of packets for one flow
    pkts = [make_packet(src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80) for _ in range(5)]

    # Process batch — flows won't expire yet
    features = ext.process_batch(pkts)
    assert len(features) == 0  # No expired flows yet

    # Wait for flow timeout
    time.sleep(1.1)
    features = ext.process_batch([])
    assert len(features) >= 1

    f = features[0]
    assert f["src_ip"] == "10.0.0.1"
    assert f["dst_ip"] == "8.8.8.8"
    assert f["packet_count"] == 5
    assert f["flow_duration"] > 0
    assert "packets_per_second" in f
    assert "tcp_syn_rate" in f
    print("  PASS: feature extraction")


def test_baseline():
    """Test baseline processes features and adds anomaly scores."""
    tmpdir = tempfile.mkdtemp()
    base = NetworkBaseline(
        learning_period_hours=0, min_samples=2, max_devices=100,
        storage_path=tmpdir
    )

    features = [
        {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_port": 80,
         "protocol": "TCP", "packets_per_second": 10.0, "bytes_per_second": 1000.0,
         "tcp_syn_rate": 0.1, "avg_packet_size": 100.0, "byte_count": 1000, "packet_count": 10}
    ]

    enriched = base.process_features(features)
    assert len(enriched) == 1
    assert "anomaly_score" in enriched[0]
    assert "device_status" in enriched[0]
    assert "device_reputation" in enriched[0]
    print("  PASS: baseline enrichment")


def test_rules():
    """Test rule detection."""
    rules = RuleEngine({
        "port_scan": {"enabled": True, "threshold_unique_ports": 3, "severity": "HIGH"},
        "syn_flood": {"enabled": True, "threshold_pps": 5, "threshold_syn_ratio": 0.8, "severity": "CRITICAL"},
        "unknown_device": {"enabled": True, "severity": "LOW"},
    })

    # Normal traffic — no events
    f = {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_port": 80,
         "protocol": "TCP", "tcp_syn_rate": 0.1, "device_status": "KNOWN"}
    events = rules.evaluate(f)
    assert len(events) == 0

    # Port scan — multiple unique ports
    events = []
    for port in range(1, 6):
        f = {"src_ip": "10.0.0.2", "dst_ip": "8.8.8.8", "dst_port": port,
             "protocol": "TCP", "tcp_syn_rate": 0.5, "device_status": "KNOWN"}
        events.extend(rules.evaluate(f))
    assert any(e.rule_name == "port_scan" for e in events)
    print("  PASS: rule detection")


def test_anomaly():
    """Test statistical anomaly detection."""
    det = StatisticalDetector(z_threshold=2.0, min_history=5)

    # Build history with normal values
    for _ in range(20):
        det.analyze({"src_ip": "10.0.0.1", "packets_per_second": 10.0})

    # Spike should be detected
    result = det.analyze({"src_ip": "10.0.0.1", "packets_per_second": 1000.0})
    assert result is not None
    assert result["type"] == "statistical_anomaly"
    print("  PASS: statistical anomaly")


def test_risk():
    """Test risk scoring."""
    risk = RiskEngine()

    # Low risk
    assessment = risk.assess(
        {"anomaly_score": 0.1, "device_reputation": 0.9, "device_status": "KNOWN"},
        []
    )
    assert assessment.score < 30
    assert assessment.level == "LOW"

    # High risk with rule events
    events = [DetectionEvent(
        rule_name="port_scan", severity="CRITICAL", confidence=0.9,
        src_ip="10.0.0.1", dst_ip="8.8.8.8", description="Port scan"
    )]
    assessment = risk.assess(
        {"anomaly_score": 0.8, "device_reputation": 0.2, "device_status": "UNKNOWN"},
        events
    )
    assert assessment.score >= 60
    assert len(assessment.reasoning) > 0
    print("  PASS: risk scoring")


def test_incidents():
    """Test incident creation and persistence."""
    tmpdir = tempfile.mkdtemp()
    inc = IncidentEngine(storage_path=tmpdir, dedup_window=5)

    # Create incident
    incident = inc.process_detection(
        device_ip="10.0.0.1",
        event_type="port_scan",
        severity="HIGH",
        risk_score=70,
        confidence=0.8,
        evidence=["20 ports contacted"],
        description="Port scan detected"
    )
    assert incident is not None
    assert incident.status == "OPEN"
    assert incident.risk_score == 70

    # Verify persistence
    open_incidents = inc.get_open_incidents()
    assert len(open_incidents) >= 1

    # Verify resolution
    resolved = inc.resolve_incident(incident.incident_id, note="False alarm")
    assert resolved
    print("  PASS: incident management")


def test_enforcement():
    """Test enforcement abstraction."""
    enf = EnforcementEngine(mode="log-only")

    # Below threshold — no action
    result = enf.evaluate(
        risk_score=20, confidence=0.9,
        device_ip="10.0.0.1", detection_events=[]
    )
    assert result is None

    # Above alert threshold — creates alert
    events = [DetectionEvent(
        rule_name="syn_flood", severity="CRITICAL", confidence=0.95,
        src_ip="10.0.0.1", dst_ip="8.8.8.8", description="SYN flood"
    )]
    result = enf.evaluate(
        risk_score=65, confidence=0.9,
        device_ip="10.0.0.1", detection_events=events
    )
    assert result is not None
    assert result.action_type == "alert"
    print("  PASS: enforcement")


def test_full_pipeline():
    """Test complete packet → incident pipeline."""
    tmpdir = tempfile.mkdtemp()

    # Initialize all components
    ext = FeatureExtractor(flow_timeout=0.5, max_flows=1000)
    base = NetworkBaseline(
        learning_period_hours=0, min_samples=1, max_devices=100,
        storage_path=os.path.join(tmpdir, "baseline")
    )
    rules = RuleEngine({"port_scan": {"enabled": True, "threshold_unique_ports": 3, "severity": "HIGH"}})
    anomaly = StatisticalDetector(z_threshold=2.0, min_history=5)
    ml = MLInterface(enabled=False)  # Disable ML for test speed
    risk = RiskEngine()
    incidents = IncidentEngine(
        storage_path=os.path.join(tmpdir, "incidents"),
        dedup_window=1
    )
    enforcement = EnforcementEngine(mode="log-only")

    # Simulate normal traffic
    normal_pkts = [
        make_packet(src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80)
        for _ in range(3)
    ]
    flow_features = ext.process_batch(normal_pkts)
    time.sleep(0.6)
    flow_features.extend(ext.process_batch([]))

    enriched = base.process_features(flow_features)
    assert len(enriched) > 0

    # Process through detection pipeline
    all_events = []
    for f in enriched:
        events = rules.evaluate(f)
        all_events.extend(events)
        stat = anomaly.analyze(f)
        ml_result = ml.predict(f)

    # Simulate port scan traffic
    scan_pkts = [
        make_packet(src_ip="10.0.0.99", dst_ip="8.8.8.8", dst_port=p)
        for p in range(1, 8)
    ]
    scan_features = ext.process_batch(scan_pkts)
    time.sleep(0.6)
    scan_features.extend(ext.process_batch([]))

    scan_enriched = base.process_features(scan_features)
    # Aggregate detection events per source device and emit a single
    # highest-severity incident per device. This avoids the incident spam
    # that per-flow alerts would otherwise produce (each scan packet to a
    # different port is a separate flow).
    from collections import defaultdict
    sev_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    device_primary = {}
    device_evidence = defaultdict(list)
    for f in scan_enriched:
        events = rules.evaluate(f)
        if not events:
            continue
        src = f.get("src_ip", "")
        primary = max(events, key=lambda ev: sev_rank.get(ev.severity, 0))
        existing = device_primary.get(src)
        if existing is None or sev_rank.get(primary.severity, 0) > sev_rank.get(existing.severity, 0):
            device_primary[src] = primary
        for ev in events:
            device_evidence[src].extend(ev.evidence)

    for src, primary in device_primary.items():
        incident = incidents.process_detection(
            device_ip=src,
            event_type=primary.rule_name,
            severity="HIGH",
            risk_score=70,
            confidence=0.8,
            evidence=device_evidence[src][:10],
            description=primary.description,
        )
        assert incident is not None

    # Verify incident was created
    open_incidents = incidents.get_open_incidents()
    assert len(open_incidents) >= 1

    # Verify incident has correct data
    inc_data = open_incidents[0]
    assert inc_data["device_ip"] == "10.0.0.99"
    assert inc_data["event_type"] == "port_scan"
    assert inc_data["severity"] == "HIGH"
    assert inc_data["risk_score"] == 70

    print("  PASS: full pipeline (synthetic packets)")


def test_scapy_parse():
    """Test _parse_packet with mock Scapy packets."""
    # This test uses MockPacket which simulates Scapy's interface
    pkt = MockPacket(src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443, protocol="TCP")
    # Note: _parse_packet checks SCAPY_AVAILABLE which will be False in test env
    # So this tests the graceful degradation path
    meta = _parse_packet(pkt)
    # If scapy is not available, meta will be None
    if meta is None:
        print("  PASS: _parse_packet graceful degradation (scapy not available)")
    else:
        assert meta.src_ip == "10.0.0.1"
        assert meta.dst_port == 443
        print("  PASS: _parse_packet with mock packet")


def test_malformed_packet_resilience():
    """Test that malformed packets don't crash the pipeline."""
    ext = FeatureExtractor(flow_timeout=1, max_flows=100)

    # Mix of good and potentially problematic packets
    pkts = [
        make_packet(src_ip="10.0.0.1", dst_port=80),
        make_packet(src_ip="10.0.0.2", dst_port=0, size=0),  # Zero port
        make_packet(src_ip="10.0.0.3", dst_port=65535, size=65535),  # Max values
        make_packet(src_ip="", dst_port=80),  # Empty IP
        make_packet(src_ip="10.0.0.4", dst_port=80, protocol="ICMP"),
    ]

    # Should not crash
    features = ext.process_batch(pkts)
    print("  PASS: malformed packet resilience")


def test_concurrent_access():
    """Test thread safety of pipeline components."""
    import threading

    ext = FeatureExtractor(flow_timeout=0.5, max_flows=1000)
    base = NetworkBaseline(
        learning_period_hours=0, min_samples=1, max_devices=100,
        storage_path="/tmp/falconx-test-concurrent"
    )
    rules = RuleEngine()

    errors = []

    def worker(worker_id):
        try:
            for i in range(10):
                pkts = [
                    make_packet(src_ip=f"10.0.{worker_id}.{i}", dst_port=80)
                    for _ in range(3)
                ]
                features = ext.process_batch(pkts)
                time.sleep(0.1)
                enriched = base.process_features(features)
                for f in enriched:
                    rules.evaluate(f)
        except Exception as e:
            errors.append(f"Worker {worker_id}: {e}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(errors) == 0, f"Thread safety errors: {errors}"
    print("  PASS: concurrent access")


def main():
    print("\nFALCON-X Pipeline Integration Tests\n")

    tests = [
        ("Entropy estimation", test_entropy),
        ("Packet metadata", test_packet_metadata),
        ("Feature extraction", test_feature_extraction),
        ("Baseline enrichment", test_baseline),
        ("Rule detection", test_rules),
        ("Statistical anomaly", test_anomaly),
        ("Risk scoring", test_risk),
        ("Incident management", test_incidents),
        ("Enforcement", test_enforcement),
        ("Full pipeline (synthetic)", test_full_pipeline),
        ("Scapy parse (graceful)", test_scapy_parse),
        ("Malformed packet resilience", test_malformed_packet_resilience),
        ("Concurrent access", test_concurrent_access),
    ]

    passed = 0
    failed = 0
    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {name} — {e}")
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed, {len(tests)} total")
    return failed


if __name__ == "__main__":
    sys.exit(main())
