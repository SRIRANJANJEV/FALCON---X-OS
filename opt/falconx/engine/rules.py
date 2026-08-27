"""FALCON-X Engine — Rule-based detection engine.

Deterministic detection rules for known threat patterns.
Each rule evaluates flow features and returns detection events.
"""

import collections
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("falconx-engine.rules")


@dataclass
class DetectionEvent:
    """A single detection event from a rule."""
    rule_name: str
    severity: str
    confidence: float
    src_ip: str
    dst_ip: str
    description: str
    evidence: List[str] = field(default_factory=list)
    timestamp: float = 0.0
    metadata: Dict = field(default_factory=dict)

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


class _WindowCounter:
    """Sliding window counter for tracking events per IP."""

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self._counters: Dict[str, collections.deque] = {}

    def add(self, key: str, timestamp: float):
        if key not in self._counters:
            self._counters[key] = collections.deque()
        self._counters[key].append(timestamp)
        self._trim(key, timestamp)

    def count(self, key: str, now: float) -> int:
        self._trim(key, now)
        return len(self._counters.get(key, []))

    def _trim(self, key: str, now: float):
        dq = self._counters.get(key)
        if dq is None:
            return
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()


class RuleEngine:
    """Evaluates detection rules against flow features."""

    def __init__(self, rules_config: dict = None):
        self.config = rules_config or {}
        self._syn_windows = _WindowCounter(60)
        self._port_windows = _WindowCounter(60)
        self._conn_windows = _WindowCounter(60)
        self._dns_windows = _WindowCounter(60)
        self._arp_windows = _WindowCounter(10)
        self._icmp_windows = _WindowCounter(60)
        self._outbound_windows = _WindowCounter(300)

        # Per-IP port set for scan detection
        self._ip_ports: Dict[str, set] = {}
        self._ip_ports_time: Dict[str, float] = {}

        self._detection_count = 0

    def evaluate(self, features: dict) -> List[DetectionEvent]:
        """Evaluate all rules against flow features, return detection events."""
        events = []
        now = time.time()

        for rule_func in [
            self._rule_port_scan,
            self._rule_syn_flood,
            self._rule_abnormal_connection_rate,
            self._rule_dns_anomaly,
            self._rule_arp_anomaly,
            self._rule_unknown_device,
            self._rule_brute_force,
            self._rule_data_exfiltration,
            self._rule_icmp_flood,
            self._rule_unusual_protocol,
        ]:
            try:
                ev = rule_func(features, now)
                if ev:
                    events.append(ev)
            except Exception:
                continue

        self._detection_count += len(events)
        return events

    def _rule_port_scan(self, f: dict, now: float) -> Optional[DetectionEvent]:
        cfg = self.config.get("port_scan", {})
        if not cfg.get("enabled", True):
            return None

        threshold = cfg.get("threshold_unique_ports", 15)
        src_ip = f.get("src_ip", "")
        if not src_ip:
            return None

        # Track unique destination ports per source
        if src_ip not in self._ip_ports:
            self._ip_ports[src_ip] = set()
            self._ip_ports_time[src_ip] = now

        # Reset if window expired
        if now - self._ip_ports_time.get(src_ip, 0) > cfg.get("threshold_time_seconds", 60):
            self._ip_ports[src_ip] = set()
            self._ip_ports_time[src_ip] = now

        dst_port = f.get("dst_port", 0)
        if dst_port:
            self._ip_ports[src_ip].add(dst_port)

        port_count = len(self._ip_ports[src_ip])
        if port_count >= threshold:
            return DetectionEvent(
                rule_name="port_scan",
                severity=cfg.get("severity", "HIGH"),
                confidence=min(port_count / (threshold * 2), 1.0),
                src_ip=src_ip,
                dst_ip=f.get("dst_ip", ""),
                description=f"Port scan detected: {src_ip} contacted {port_count} unique ports",
                evidence=[
                    f"Unique destination ports: {port_count}",
                    f"Threshold: {threshold}",
                    f"Protocol: {f.get('protocol', 'unknown')}",
                ],
                metadata={"port_count": port_count},
            )
        return None

    def _rule_syn_flood(self, f: dict, now: float) -> Optional[DetectionEvent]:
        cfg = self.config.get("syn_flood", {})
        if not cfg.get("enabled", True):
            return None

        src_ip = f.get("src_ip", "")
        self._syn_windows.add(src_ip, now)
        count = self._syn_windows.count(src_ip, now)

        threshold = cfg.get("threshold_pps", 100)
        syn_ratio = f.get("tcp_syn_rate", 0)

        if count >= threshold and syn_ratio >= cfg.get("threshold_syn_ratio", 0.8):
            return DetectionEvent(
                rule_name="syn_flood",
                severity=cfg.get("severity", "CRITICAL"),
                confidence=min(count / (threshold * 2), 1.0),
                src_ip=src_ip,
                dst_ip=f.get("dst_ip", ""),
                description=f"SYN flood behavior: {count} packets/sec from {src_ip}",
                evidence=[
                    f"Packets in window: {count}",
                    f"SYN ratio: {syn_ratio:.2f}",
                    f"Threshold: {threshold} pps",
                ],
                metadata={"packet_count": count, "syn_ratio": syn_ratio},
            )
        return None

    def _rule_abnormal_connection_rate(self, f: dict, now: float) -> Optional[DetectionEvent]:
        cfg = self.config.get("abnormal_connection_rate", {})
        if not cfg.get("enabled", True):
            return None

        src_ip = f.get("src_ip", "")
        self._conn_windows.add(src_ip, now)
        count = self._conn_windows.count(src_ip, now)

        # This rule needs baseline context — flag if significantly above median
        # Use a simple threshold for now
        multiplier = cfg.get("threshold_multiplier", 3.0)
        if count > 50 * multiplier:
            return DetectionEvent(
                rule_name="abnormal_connection_rate",
                severity=cfg.get("severity", "MEDIUM"),
                confidence=min(count / (50 * multiplier * 2), 1.0),
                src_ip=src_ip,
                dst_ip=f.get("dst_ip", ""),
                description=f"Abnormal connection rate: {count} connections from {src_ip}",
                evidence=[
                    f"Connections in window: {count}",
                    f"Threshold multiplier: {multiplier}x baseline",
                ],
            )
        return None

    def _rule_dns_anomaly(self, f: dict, now: float) -> Optional[DetectionEvent]:
        cfg = self.config.get("dns_anomaly", {})
        if not cfg.get("enabled", True):
            return None

        proto = f.get("protocol", "")
        if proto not in ("DNS_REQUEST", "DNS_RESPONSE"):
            return None

        src_ip = f.get("src_ip", "")
        self._dns_windows.add(src_ip, now)
        count = self._dns_windows.count(src_ip, now)

        threshold = cfg.get("threshold_queries_per_minute", 60)
        if count >= threshold:
            return DetectionEvent(
                rule_name="dns_anomaly",
                severity=cfg.get("severity", "MEDIUM"),
                confidence=min(count / (threshold * 2), 1.0),
                src_ip=src_ip,
                dst_ip=f.get("dst_ip", ""),
                description=f"Abnormal DNS activity: {count} queries from {src_ip}",
                evidence=[
                    f"DNS queries in window: {count}",
                    f"Query: {f.get('dns_query', 'N/A')}",
                    f"Threshold: {threshold}/min",
                ],
            )
        return None

    def _rule_arp_anomaly(self, f: dict, now: float) -> Optional[DetectionEvent]:
        cfg = self.config.get("arp_anomaly", {})
        if not cfg.get("enabled", True):
            return None

        if f.get("protocol") != "ARP":
            return None

        src_ip = f.get("src_ip", "")
        self._arp_windows.add(src_ip, now)
        count = self._arp_windows.count(src_ip, now)

        threshold = cfg.get("threshold_arp_per_second", 10)
        if count >= threshold:
            return DetectionEvent(
                rule_name="arp_anomaly",
                severity=cfg.get("severity", "HIGH"),
                confidence=min(count / (threshold * 2), 1.0),
                src_ip=src_ip,
                dst_ip=f.get("dst_ip", ""),
                description=f"ARP anomaly: {count} ARP packets from {src_ip}",
                evidence=[
                    f"ARP packets in window: {count}",
                    f"ARP operation: {'request' if f.get('arp_op') == 1 else 'reply'}",
                    f"Source MAC: {f.get('arp_src_mac', 'N/A')}",
                    f"Threshold: {threshold}/10s",
                ],
            )
        return None

    def _rule_unknown_device(self, f: dict, now: float) -> Optional[DetectionEvent]:
        cfg = self.config.get("unknown_device", {})
        if not cfg.get("enabled", True):
            return None

        device_status = f.get("device_status", "")
        if device_status != "UNKNOWN":
            return None

        return DetectionEvent(
            rule_name="unknown_device",
            severity=cfg.get("severity", "LOW"),
            confidence=0.5,
            src_ip=f.get("src_ip", ""),
            dst_ip=f.get("dst_ip", ""),
            description=f"Unknown device on network: {f.get('src_ip', 'unknown')}",
            evidence=[
                f"Device status: {device_status}",
                f"Total flows: {f.get('device_flows', 0)}",
            ],
        )

    def _rule_brute_force(self, f: dict, now: float) -> Optional[DetectionEvent]:
        cfg = self.config.get("brute_force", {})
        if not cfg.get("enabled", True):
            return None

        # Detect repeated connections to same port with RST (failed auth pattern)
        if not f.get("tcp_rst_rate", 0) > 0.3:
            return None

        src_ip = f.get("src_ip", "")
        dst_port = f.get("dst_port", 0)
        key = f"{src_ip}-{dst_port}"

        self._conn_windows.add(key, now)
        count = self._conn_windows.count(key, now)

        threshold = cfg.get("threshold_attempts", 10)
        if count >= threshold:
            return DetectionEvent(
                rule_name="brute_force",
                severity=cfg.get("severity", "HIGH"),
                confidence=min(count / (threshold * 2), 1.0),
                src_ip=src_ip,
                dst_ip=f.get("dst_ip", ""),
                description=f"Brute force pattern: {count} failed connections to port {dst_port}",
                evidence=[
                    f"Failed connections: {count}",
                    f"Target port: {dst_port}",
                    f"RST rate: {f.get('tcp_rst_rate', 0):.2f}",
                    f"Threshold: {threshold}",
                ],
            )
        return None

    def _rule_data_exfiltration(self, f: dict, now: float) -> Optional[DetectionEvent]:
        cfg = self.config.get("data_exfiltration", {})
        if not cfg.get("enabled", True):
            return None

        src_ip = f.get("src_ip", "")
        bps = f.get("bytes_per_second", 0)
        byte_count = f.get("byte_count", 0)

        self._outbound_windows.add(src_ip, now)
        count = self._outbound_windows.count(src_ip, now)

        # High volume outbound
        threshold_mb = cfg.get("threshold_outbound_mb", 100)
        threshold_bytes = threshold_mb * 1024 * 1024

        if byte_count > threshold_bytes:
            return DetectionEvent(
                rule_name="data_exfiltration",
                severity=cfg.get("severity", "CRITICAL"),
                confidence=min(byte_count / (threshold_bytes * 3), 1.0),
                src_ip=src_ip,
                dst_ip=f.get("dst_ip", ""),
                description=f"Possible data exfiltration: {byte_count / 1024 / 1024:.1f}MB outbound",
                evidence=[
                    f"Bytes transferred: {byte_count:,}",
                    f"Throughput: {bps:,.0f} B/s",
                    f"Threshold: {threshold_mb}MB",
                ],
            )
        return None

    def _rule_icmp_flood(self, f: dict, now: float) -> Optional[DetectionEvent]:
        cfg = self.config.get("icmp_flood", {})
        if not cfg.get("enabled", True):
            return None

        if f.get("protocol") != "ICMP":
            return None

        src_ip = f.get("src_ip", "")
        self._icmp_windows.add(src_ip, now)
        count = self._icmp_windows.count(src_ip, now)

        threshold = cfg.get("threshold_pps", 50)
        if count >= threshold:
            return DetectionEvent(
                rule_name="icmp_flood",
                severity=cfg.get("severity", "HIGH"),
                confidence=min(count / (threshold * 2), 1.0),
                src_ip=src_ip,
                dst_ip=f.get("dst_ip", ""),
                description=f"ICMP flood: {count} ICMP packets from {src_ip}",
                evidence=[
                    f"ICMP packets: {count}",
                    f"ICMP type: {f.get('icmp_type', 'unknown')}",
                    f"Threshold: {threshold}/min",
                ],
            )
        return None

    def _rule_unusual_protocol(self, f: dict, now: float) -> Optional[DetectionEvent]:
        cfg = self.config.get("unusual_protocol", {})
        if not cfg.get("enabled", True):
            return None

        proto = f.get("protocol", "")
        if proto.startswith("OTHER("):
            return DetectionEvent(
                rule_name="unusual_protocol",
                severity=cfg.get("severity", "MEDIUM"),
                confidence=0.6,
                src_ip=f.get("src_ip", ""),
                dst_ip=f.get("dst_ip", ""),
                description=f"Unusual protocol detected: {proto}",
                evidence=[f"Protocol: {proto}"],
            )
        return None

    def get_stats(self) -> dict:
        return {
            "detection_count": self._detection_count,
            "tracked_ips": len(self._ip_ports),
        }
