"""FALCON-X Engine — Demo / synthetic scenario generator.

Produces realistic synthetic flow features that exercise the REAL detection
pipeline (baseline → rules → risk → incidents). Used to demonstrate the
complete detection flow live without generating any traffic on real networks.

The demo is deterministic, repeatable, and clearly labelled DEMO mode. It
never sends packets to external networks — it injects feature data directly
into the in-process detection pipeline.
"""

import logging
import time
from typing import List

logger = logging.getLogger("falconx-engine.demo")

# Known "corporate" devices used during baseline warmup
KNOWN_DEVICES = [
    {"ip": "10.0.0.10", "name": "office-workstation"},
    {"ip": "10.0.0.11", "name": "file-server"},
    {"ip": "10.0.0.12", "name": "developer-laptop"},
]

# The attacker / unknown device
ATTACKER_IP = "10.0.0.99"
EXTERNAL = "8.8.8.8"


def _flow(
    src_ip: str,
    dst_ip: str,
    dst_port: int = 0,
    protocol: str = "TCP",
    packets_per_second: float = 1.0,
    bytes_per_second: float = 100.0,
    tcp_syn_rate: float = 0.0,
    dns_queries: float = 0.0,
    byte_count: float = 0.0,
    flow_duration: float = 1.0,
) -> dict:
    """Build a single flow feature dict (shape consumed by rules/risk)."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "tcp_syn_rate": tcp_syn_rate,
        "dns_queries": dns_queries,
        "byte_count": byte_count,
        "packet_count": int(packets_per_second * flow_duration),
        "flow_duration": flow_duration,
        "unique_dst_ports": 1 if dst_port else 0,
    }


def normal_traffic_batch(round_num: int) -> List[dict]:
    """Generate a realistic batch of benign traffic between known devices.

    Mostly HTTP/HTTPS/DNS to external servers. Produces no detection events.
    """
    flows = []
    for dev in KNOWN_DEVICES:
        src = dev["ip"]
        # Web browsing
        flows.append(_flow(src, "198.51.100.20", dst_port=443, packets_per_second=3.0,
                           bytes_per_second=8000.0, tcp_syn_rate=0.1, flow_duration=2.0))
        flows.append(_flow(src, "198.51.100.30", dst_port=80, packets_per_second=2.0,
                           bytes_per_second=4000.0, tcp_syn_rate=0.1, flow_duration=2.0))
        # DNS lookups (occasional)
        if round_num % 3 == 0:
            flows.append(_flow(src, "8.8.8.8", dst_port=53, protocol="DNS_REQUEST",
                               dns_queries=1.0, packets_per_second=0.2, flow_duration=1.0))
        # File server access (internal)
        if dev["name"] != "file-server":
            flows.append(_flow(src, "10.0.0.11", dst_port=445, packets_per_second=4.0,
                               bytes_per_second=15000.0, tcp_syn_rate=0.1, flow_duration=2.0))
    logger.info("Demo: generated %d normal flows (round %d)", len(flows), round_num)
    return flows


def port_scan_batch() -> List[dict]:
    """A single host sweeping many destination ports (port scan)."""
    flows = [
        _flow(ATTACKER_IP, EXTERNAL, dst_port=port, protocol="TCP",
              packets_per_second=40.0, tcp_syn_rate=1.0, flow_duration=1.0)
        for port in range(1, 30)
    ]
    logger.info("Demo: generated port-scan flows from %s", ATTACKER_IP)
    return flows


def syn_flood_batch() -> List[dict]:
    """SYN flood toward a single port (many packets to push the window counter
    above the configured pps threshold)."""
    flows = [
        _flow(ATTACKER_IP, "10.0.0.11", dst_port=443, protocol="TCP",
              packets_per_second=160.0, tcp_syn_rate=0.97, flow_duration=1.0)
        for _ in range(140)
    ]
    logger.info("Demo: generated SYN-flood flows from %s", ATTACKER_IP)
    return flows


def dns_anomaly_batch() -> List[dict]:
    """Abnormally high DNS query rate (possible DNS tunneling / beaconing)."""
    flows = [
        _flow(ATTACKER_IP, "8.8.8.8", dst_port=53, protocol="DNS_REQUEST",
              dns_queries=25.0, packets_per_second=20.0, flow_duration=1.0)
        for _ in range(10)
    ]
    logger.info("Demo: generated DNS-anomaly flows from %s", ATTACKER_IP)
    return flows


def data_exfiltration_batch() -> List[dict]:
    """Large outbound transfer (possible data exfiltration)."""
    flows = [
        _flow(ATTACKER_IP, "198.51.100.200", dst_port=443, protocol="TCP",
              packets_per_second=60.0, bytes_per_second=2_000_000.0,
              byte_count=300_000_000.0, flow_duration=5.0)
        for _ in range(6)
    ]
    logger.info("Demo: generated data-exfiltration flows from %s", ATTACKER_IP)
    return flows


def build_demo_script() -> List[dict]:
    """Return an ordered, timed script of demo steps.

    Each step: {"delay_before": seconds, "flows": [...], "label": str}
    The engine plays this script on a background thread during demo mode.
    """
    return [
        {"delay_before": 0.0, "label": "startup", "flows": []},
        # Baseline warm-up — establish normal behaviour for known devices
        {"delay_before": 0.5, "label": "normal-traffic", "flows": normal_traffic_batch(1)},
        {"delay_before": 1.5, "label": "normal-traffic", "flows": normal_traffic_batch(2)},
        {"delay_before": 1.5, "label": "normal-traffic", "flows": normal_traffic_batch(3)},
        # Attack phase 1 — port scan from a NEW (unknown) device
        {"delay_before": 1.5, "label": "port-scan", "flows": port_scan_batch()},
        # Attack phase 2 — SYN flood
        {"delay_before": 1.0, "label": "syn-flood", "flows": syn_flood_batch()},
        # Attack phase 3 — DNS anomaly
        {"delay_before": 1.0, "label": "dns-anomaly", "flows": dns_anomaly_batch()},
        # Attack phase 4 — data exfiltration (high risk)
        {"delay_before": 1.0, "label": "data-exfiltration", "flows": data_exfiltration_batch()},
        {"delay_before": 0.5, "label": "complete", "flows": []},
    ]
