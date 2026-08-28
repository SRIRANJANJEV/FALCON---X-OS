#!/usr/bin/env python3
"""FALCON-X Demo Mode Integration Test.

Validates that the synthetic demo scenarios produce REAL detections through
the actual detection pipeline (baseline → rules → risk → incidents).

The demo never sends traffic to real networks; it injects flow features into
the in-process pipeline, exactly as engine.main does in demo mode.
"""

import os
import sys
import tempfile

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE_DIR)

import demo as demo_module
from baseline import NetworkBaseline
from rules import RuleEngine
from anomaly import StatisticalDetector
from ml_interface import MLInterface
from risk import RiskEngine
from incidents import IncidentEngine
from enforcement import EnforcementEngine


def _build_pipeline(tmpdir):
    """Recreate the engine's pipeline (mirrors engine.main wiring)."""
    base = NetworkBaseline(
        learning_period_hours=0, min_samples=1, max_devices=100,
        storage_path=os.path.join(tmpdir, "baseline"),
    )
    rules = RuleEngine({
        "port_scan": {"enabled": True, "threshold_unique_ports": 15, "severity": "HIGH"},
        "syn_flood": {"enabled": True, "threshold_pps": 100, "threshold_syn_ratio": 0.8, "severity": "CRITICAL"},
        "dns_anomaly": {"enabled": True, "threshold_queries_per_minute": 60, "severity": "MEDIUM"},
        "unknown_device": {"enabled": True, "severity": "LOW"},
        "data_exfiltration": {"enabled": True, "threshold_outbound_mb": 100, "severity": "CRITICAL"},
        "abnormal_connection_rate": {"enabled": True, "threshold_multiplier": 3.0, "severity": "MEDIUM"},
    })
    anomaly = StatisticalDetector(z_threshold=3.0, min_history=10)
    ml = MLInterface(enabled=False)
    risk = RiskEngine()
    incidents = IncidentEngine(
        storage_path=os.path.join(tmpdir, "incidents"),
        dedup_window=1,
    )
    enforcement = EnforcementEngine(mode="log-only")
    return base, rules, anomaly, ml, risk, incidents, enforcement


def _inject(base, rules, anomaly, ml, risk, incidents, flow_features):
    """Replicate engine.main._inject_demo_flows (regular function)."""
    enriched = base.process_features(flow_features)
    ml.update(enriched)
    sev_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    created = []
    for f in enriched:
        rule_events = rules.evaluate(f)
        stat_result = anomaly.analyze(f)
        ml_result = ml.predict(f)
        combined = None
        if stat_result or ml_result:
            combined = {
                "type": "combined",
                "statistical": stat_result,
                "ml": ml_result,
                "confidence": max(
                    (stat_result or {}).get("confidence", 0),
                    (ml_result or {}).get("confidence", 0),
                ),
            }
        risk_assess = risk.assess(f, rule_events, combined)
        if risk_assess.score >= 30 or rule_events:
            if rule_events:
                primary = max(rule_events, key=lambda ev: sev_rank.get(ev.severity, 0))
                event_type, severity = primary.rule_name, primary.severity
            else:
                event_type, severity = "anomaly", "MEDIUM"
            inc = incidents.process_detection(
                device_ip=f.get("src_ip", ""),
                event_type=event_type,
                severity=severity,
                risk_score=risk_assess.score,
                confidence=risk_assess.confidence,
                evidence=[e for ev in rule_events for e in ev.evidence][:10],
                description=primary.description if rule_events else "Statistical anomaly",
            )
            if inc is not None:
                created.append({"type": event_type, "severity": severity})
    return created


def test_demo_script_builds():
    script = demo_module.build_demo_script()
    assert script
    labels = [s["label"] for s in script]
    assert "normal-traffic" in labels
    assert "port-scan" in labels
    assert "syn-flood" in labels


def test_normal_traffic_no_high_severity_incidents():
    """Benign traffic produces only LOW device-discovery alerts, never
    HIGH/CRITICAL threats. This keeps the baseline-learning phase safe."""
    tmp = tempfile.mkdtemp()
    base, rules, anomaly, ml, risk, incidents, enf = _build_pipeline(tmp)
    for i in range(1, 4):
        created = _inject(base, rules, anomaly, ml, risk, incidents,
                          demo_module.normal_traffic_batch(i))
        for c in created:
            assert c["severity"] not in ("HIGH", "CRITICAL"), \
                "Normal traffic triggered a threat alert: %s" % c


def test_port_scan_detected():
    """Port-scan batch triggers a HIGH port_scan incident."""
    tmp = tempfile.mkdtemp()
    base, rules, anomaly, ml, risk, incidents, enf = _build_pipeline(tmp)
    for i in range(1, 3):
        _inject(base, rules, anomaly, ml, risk, incidents,
                demo_module.normal_traffic_batch(i))
    _inject(base, rules, anomaly, ml, risk, incidents, demo_module.port_scan_batch())
    open_incs = incidents.get_open_incidents()
    assert any(i["event_type"] == "port_scan" for i in open_incs)


def test_attack_batch_creates_high_risk_incident():
    """The full attack script creates high-severity incidents."""
    tmp = tempfile.mkdtemp()
    base, rules, anomaly, ml, risk, incidents, enf = _build_pipeline(tmp)
    script = demo_module.build_demo_script()
    for step in script:
        _inject(base, rules, anomaly, ml, risk, incidents, step["flows"])
    open_incs = incidents.get_open_incidents()
    assert len(open_incs) >= 1
    sevs = {i["severity"] for i in open_incs}
    assert "CRITICAL" in sevs or "HIGH" in sevs, "Attack did not raise severity"
