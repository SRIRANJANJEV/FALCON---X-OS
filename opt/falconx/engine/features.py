"""FALCON-X Engine — Feature extraction pipeline.

Extracts network flow features from packet metadata.
Operates on bounded flow tables with configurable timeouts.
"""

import collections
import hashlib
import logging
import math
import time
from typing import Dict, List, Optional

logger = logging.getLogger("falconx-engine.features")


class Flow:
    """Represents a network flow (connection) with aggregated statistics."""

    __slots__ = (
        "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "start_time", "last_time", "packet_count", "byte_count",
        "syn_count", "rst_count", "fin_count",
        "dns_queries", "icmp_count", "arp_count",
        "packet_sizes", "inter_arrival_times",
        "unique_dst_ports", "is_complete",
    )

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str):
        self.flow_id = self._make_id(src_ip, dst_ip, src_port, dst_port, protocol)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        now = time.time()
        self.start_time = now
        self.last_time = now
        self.packet_count = 0
        self.byte_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self.dns_queries = 0
        self.icmp_count = 0
        self.arp_count = 0
        self.packet_sizes: List[int] = []
        self.inter_arrival_times: List[float] = []
        self.unique_dst_ports: set = set()
        self.is_complete = False

    @staticmethod
    def _make_id(src_ip, dst_ip, src_port, dst_port, protocol) -> str:
        key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    def update(self, meta) -> None:
        """Update flow with new packet metadata."""
        now = meta.timestamp
        if self.inter_arrival_times:
            dt = now - self.last_time
            if dt > 0:
                self.inter_arrival_times.append(dt)
        self.last_time = now
        self.packet_count += 1
        self.byte_count += meta.size
        self.packet_sizes.append(meta.size)
        self.unique_dst_ports.add(meta.dst_port)

        if meta.is_syn:
            self.syn_count += 1
        if meta.is_rst:
            self.rst_count += 1
        if meta.is_fin:
            self.fin_count += 1
        if meta.protocol == "DNS_REQUEST" or meta.protocol == "DNS_RESPONSE":
            self.dns_queries += 1
        if meta.protocol == "ICMP":
            self.icmp_count += 1
        if meta.protocol == "ARP":
            self.arp_count += 1


class FeatureExtractor:
    """Extracts features from flows.

    Maintains a bounded flow table with LRU-style eviction.
    Flows that exceed the timeout are marked complete and exported.
    """

    def __init__(
        self,
        flow_timeout: int = 120,
        max_flows: int = 50000,
        enabled_features: Optional[List[str]] = None,
    ):
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.enabled_features = enabled_features or self._default_features()

        self._flows: Dict[str, Flow] = {}
        self._flow_order: collections.deque = collections.deque()
        self._total_packets = 0
        self._total_flows = 0
        self._evicted_flows = 0

    @staticmethod
    def _default_features() -> List[str]:
        return [
            "flow_duration", "packet_count", "byte_count",
            "packets_per_second", "bytes_per_second",
            "unique_destinations", "unique_ports", "unique_source_ports",
            "tcp_syn_rate", "tcp_rst_rate", "tcp_fin_rate",
            "icmp_rate", "dns_request_rate", "arp_activity",
            "protocol_distribution", "avg_packet_size", "max_packet_size",
            "min_packet_size", "payload_entropy",
            "inter_arrival_time_mean", "inter_arrival_time_std",
        ]

    def process_batch(self, packets: List) -> List[dict]:
        """Process a batch of PacketMetadata, return list of completed flow features."""
        completed_features = []

        for meta in packets:
            try:
                self._total_packets += 1
                flow = self._get_or_create_flow(meta)
                flow.update(meta)
            except Exception:
                # Malformed metadata — skip silently
                continue

        # Expire old flows
        expired = self._expire_flows()
        for flow in expired:
            try:
                features = self._extract_features(flow)
                if features:
                    completed_features.append(features)
            except Exception:
                continue

        return completed_features

    def _get_or_create_flow(self, meta) -> Flow:
        """Get existing flow or create new one."""
        flow = Flow(meta.src_ip, meta.dst_ip, meta.src_port, meta.dst_port, meta.protocol)

        if flow.flow_id in self._flows:
            return self._flows[flow.flow_id]

        # Evict if at capacity
        if len(self._flows) >= self.max_flows:
            self._evict_oldest()

        self._flows[flow.flow_id] = flow
        self._flow_order.append(flow.flow_id)
        self._total_flows += 1
        return flow

    def _evict_oldest(self):
        """Evict the oldest flow."""
        if self._flow_order:
            oldest_id = self._flow_order.popleft()
            if oldest_id in self._flows:
                flow = self._flows.pop(oldest_id)
                features = self._extract_features(flow)
                self._evicted_flows += 1
                return features
        return None

    def _expire_flows(self) -> List[Flow]:
        """Mark and return flows that have timed out."""
        now = time.time()
        expired = []
        remaining = collections.deque()

        for fid in self._flow_order:
            flow = self._flows.get(fid)
            if flow is None:
                continue
            if now - flow.last_time > self.flow_timeout:
                flow.is_complete = True
                expired.append(flow)
                self._flows.pop(fid, None)
            else:
                remaining.append(fid)

        self._flow_order = remaining
        return expired

    def _extract_features(self, flow: Flow) -> dict:
        """Extract feature vector from a completed flow."""
        duration = max(flow.last_time - flow.start_time, 0.001)
        pps = flow.packet_count / duration
        bps = flow.byte_count / duration

        # Packet size stats
        sizes = flow.packet_sizes if flow.packet_sizes else [0]
        avg_size = sum(sizes) / len(sizes)
        max_size = max(sizes)
        min_size = min(sizes)

        # Inter-arrival time stats
        iats = flow.inter_arrival_times if flow.inter_arrival_times else [0.0]
        iat_mean = sum(iats) / len(iats)
        iat_std = self._std(iats) if len(iats) > 1 else 0.0

        # Rate features
        syn_rate = flow.syn_count / max(flow.packet_count, 1)
        rst_rate = flow.rst_count / max(flow.packet_count, 1)
        fin_rate = flow.fin_count / max(flow.packet_count, 1)
        icmp_rate = flow.icmp_count / max(flow.packet_count, 1)
        dns_rate = flow.dns_queries / max(flow.packet_count, 1)

        features = {
            "flow_id": flow.flow_id,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "start_time": flow.start_time,
            "end_time": flow.last_time,
            "flow_duration": duration,
            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,
            "packets_per_second": round(pps, 4),
            "bytes_per_second": round(bps, 2),
            "unique_dst_ports": len(flow.unique_dst_ports),
            "unique_source_ports": 1,
            "tcp_syn_rate": round(syn_rate, 4),
            "tcp_rst_rate": round(rst_rate, 4),
            "tcp_fin_rate": round(fin_rate, 4),
            "icmp_rate": round(icmp_rate, 4),
            "dns_request_rate": round(dns_rate, 4),
            "arp_activity": flow.arp_count,
            "avg_packet_size": round(avg_size, 2),
            "max_packet_size": max_size,
            "min_packet_size": min_size,
            "inter_arrival_time_mean": round(iat_mean, 6),
            "inter_arrival_time_std": round(iat_std, 6),
        }

        return features

    @staticmethod
    def _std(values: list) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(variance)

    def get_active_flow_count(self) -> int:
        return len(self._flows)

    def get_stats(self) -> dict:
        return {
            "active_flows": len(self._flows),
            "total_flows": self._total_flows,
            "total_packets": self._total_packets,
            "evicted_flows": self._evicted_flows,
        }
