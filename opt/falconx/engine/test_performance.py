"""FALCON-X Engine — Performance test.

Stress tests the detection engine with synthetic traffic.
Measures throughput, latency, and memory usage.
"""

import os
import sys
import time
import random

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE_DIR)

from features import FeatureExtractor
from baseline import NetworkBaseline
from rules import RuleEngine
from anomaly import StatisticalDetector
from risk import RiskEngine
from incidents import IncidentEngine
from enforcement import EnforcementEngine


def make_mock_packet(src_ip=None, dst_port=None, size=None, is_syn=False):
    class M:
        pass
    m = M()
    m.timestamp = time.time()
    m.src_ip = src_ip or f"192.168.1.{random.randint(1, 254)}"
    m.dst_ip = f"10.0.0.{random.randint(1, 254)}"
    m.src_port = random.randint(1024, 65535)
    m.dst_port = dst_port or random.choice([80, 443, 22, 53, 8080, 3306])
    m.protocol = "TCP"
    m.size = size or random.randint(64, 1500)
    m.tcp_flags = 0x02 if is_syn else 0
    m.is_syn = is_syn
    m.is_rst = False
    m.is_fin = False
    m.dns_query = ""
    m.dns_type = ""
    m.icmp_type = -1
    m.arp_op = 0
    m.arp_src_mac = ""
    m.arp_dst_mac = ""
    m.raw_entropy = random.uniform(0, 8)
    return m


def test_throughput(packets_per_batch=100, num_batches=100):
    """Test packet processing throughput."""
    print(f"\n{'='*60}")
    print(f"  Performance Test: {packets_per_batch} pkt/batch x {num_batches} batches")
    print(f"{'='*60}")

    extractor = FeatureExtractor(flow_timeout=30, max_flows=10000)
    baseline = NetworkBaseline(
        learning_period_hours=0, min_samples=10,
        storage_path="/tmp/falconx-perf-baseline",
    )
    rules = RuleEngine()
    anomaly = StatisticalDetector(z_threshold=3.0, min_history=20)
    risk = RiskEngine()
    incidents = IncidentEngine(storage_path="/tmp/falconx-perf-incidents")
    enforcement = EnforcementEngine(mode="log-only")

    # Warm up
    print("\n  Warming up...")
    for _ in range(10):
        batch = [make_mock_packet() for _ in range(50)]
        extractor.process_batch(batch)

    # Measure
    print("  Measuring...")
    total_packets = 0
    total_flows = 0
    total_detections = 0
    latencies = []

    mem_before = _get_memory_mb()

    start = time.time()
    for b in range(num_batches):
        batch_start = time.time()

        batch = [make_mock_packet() for _ in range(packets_per_batch)]
        total_packets += len(batch)

        flow_features = extractor.process_batch(batch)
        total_flows += len(flow_features)

        enriched = baseline.process_features(flow_features)

        for features in enriched:
            rule_events = rules.evaluate(features)
            stat_result = anomaly.analyze(features)
            ml_result = None  # Skip ML for perf test

            combined = None
            if stat_result:
                combined = {"confidence": stat_result.get("confidence", 0)}

            risk_result = risk.assess(features, rule_events, combined)
            total_detections += len(rule_events)

            if risk_result.score >= 30:
                incidents.process_detection(
                    device_ip=features.get("src_ip", ""),
                    event_type="test",
                    severity=risk_result.level,
                    risk_score=risk_result.score,
                    confidence=risk_result.confidence,
                )

        batch_latency = (time.time() - batch_start) * 1000
        latencies.append(batch_latency)

    elapsed = time.time() - start
    mem_after = _get_memory_mb()

    # Report
    pps = total_packets / elapsed
    fps = total_flows / elapsed
    avg_latency = sum(latencies) / len(latencies)
    max_latency = max(latencies)
    p99_latency = sorted(latencies)[int(len(latencies) * 0.99)]

    print(f"\n  {'─'*50}")
    print(f"  Results:")
    print(f"  {'─'*50}")
    print(f"  Total packets:    {total_packets:,}")
    print(f"  Total flows:      {total_flows:,}")
    print(f"  Total detections: {total_detections:,}")
    print(f"  Elapsed:          {elapsed:.2f}s")
    print(f"  Packets/sec:      {pps:,.0f}")
    print(f"  Flows/sec:        {fps:,.0f}")
    print(f"  Avg latency:      {avg_latency:.1f}ms")
    print(f"  Max latency:      {max_latency:.1f}ms")
    print(f"  P99 latency:      {p99_latency:.1f}ms")
    print(f"  Memory before:    {mem_before:.1f}MB")
    print(f"  Memory after:     {mem_after:.1f}MB")
    print(f"  Memory delta:     {mem_after - mem_before:.1f}MB")
    print(f"  {'─'*50}")

    # Pass/fail
    passed = True
    if pps < 100:
        print(f"  WARNING: Throughput below 100 pkt/s")
        passed = False
    if avg_latency > 100:
        print(f"  WARNING: Avg latency above 100ms")
        passed = False

    if passed:
        print(f"  ✓ Performance test PASSED")
    else:
        print(f"  ✗ Performance test ISSUES DETECTED")

    return {
        "packets": total_packets,
        "flows": total_flows,
        "elapsed": elapsed,
        "pps": pps,
        "fps": fps,
        "avg_latency_ms": avg_latency,
        "max_latency_ms": max_latency,
        "memory_delta_mb": mem_after - mem_before,
    }


def _get_memory_mb():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except Exception:
        pass
    return 0.0


def test_memory_stability():
    """Test that memory doesn't grow unbounded."""
    print(f"\n{'='*60}")
    print(f"  Memory Stability Test")
    print(f"{'='*60}")

    extractor = FeatureExtractor(flow_timeout=5, max_flows=1000)
    baseline = NetworkBaseline(
        learning_period_hours=0, min_samples=5,
        storage_path="/tmp/falconx-mem-baseline",
    )

    measurements = []
    for cycle in range(5):
        for _ in range(100):
            batch = [make_mock_packet() for _ in range(50)]
            extractor.process_batch(batch)
            baseline.process_features(extractor.process_batch([]))

        mem = _get_memory_mb()
        measurements.append(mem)
        print(f"  Cycle {cycle+1}/5: {mem:.1f}MB")

    delta = measurements[-1] - measurements[0]
    print(f"\n  Memory delta: {delta:.1f}MB")
    if delta < 50:
        print(f"  ✓ Memory stability PASSED")
    else:
        print(f"  ✗ Memory growth detected")


if __name__ == "__main__":
    test_throughput(packets_per_batch=100, num_batches=100)
    test_throughput(packets_per_batch=500, num_batches=20)
    test_memory_stability()
