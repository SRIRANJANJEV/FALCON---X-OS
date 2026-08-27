"""FALCON-X Engine — Statistical anomaly detector.

Uses z-score analysis and sliding window statistics to detect anomalies.
Operates independently from ML models for reliability.
"""

import logging
import math
from typing import Dict, List, Optional

logger = logging.getLogger("falconx-engine.anomaly")

# Features to analyze statistically
NUMERIC_FEATURES = [
    "flow_duration", "packet_count", "byte_count",
    "packets_per_second", "bytes_per_second",
    "tcp_syn_rate", "tcp_rst_rate", "tcp_fin_rate",
    "icmp_rate", "dns_request_rate", "arp_activity",
    "avg_packet_size", "unique_dst_ports",
]


class StreamingStats:
    """Welford's online algorithm for computing running mean and variance."""

    __slots__ = ("n", "mean", "M2", "min_val", "max_val")

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0
        self.min_val = float("inf")
        self.max_val = float("-inf")

    def update(self, value: float):
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self.M2 += delta * delta2
        self.min_val = min(self.min_val, value)
        self.max_val = max(self.max_val, value)

    def variance(self) -> float:
        if self.n < 2:
            return 0.0
        return self.M2 / (self.n - 1)

    def std(self) -> float:
        return math.sqrt(self.variance())

    def z_score(self, value: float) -> float:
        s = self.std()
        if s < 1e-10:
            return 0.0
        return (value - self.mean) / s


class StatisticalDetector:
    """Detects anomalies using z-score analysis on streaming statistics.

    Maintains per-feature, per-direction (src/dst) statistics.
    Flags features that deviate significantly from learned norms.
    """

    def __init__(
        self,
        z_threshold: float = 3.0,
        window_size: int = 100,
        min_history: int = 50,
    ):
        self.z_threshold = z_threshold
        self.window_size = window_size
        self.min_history = min_history

        # Per-IP per-feature statistics
        self._ip_stats: Dict[str, Dict[str, StreamingStats]] = {}
        self._global_stats: Dict[str, StreamingStats] = {}

        self._anomaly_count = 0

    def analyze(self, features: dict) -> Optional[dict]:
        """Analyze flow features for statistical anomalies.

        Returns anomaly dict if anomalous, None otherwise.
        Never raises.
        """
        try:
            src_ip = features.get("src_ip", "")
            anomalies = []

            for feat_name in NUMERIC_FEATURES:
                value = features.get(feat_name)
                if value is None or not isinstance(value, (int, float)):
                    continue

                # Per-IP statistics
                ip_anomaly = self._check_ip_stat(src_ip, feat_name, value)
                if ip_anomaly:
                    anomalies.append(ip_anomaly)

                # Global statistics
                global_anomaly = self._check_global_stat(feat_name, value)
                if global_anomaly:
                    anomalies.append(global_anomaly)

            if not anomalies:
                return None

            # Combine anomalies
            self._anomaly_count += 1
            max_z = max(a["z_score"] for a in anomalies)
            confidence = min(max_z / (self.z_threshold * 2), 1.0)

            return {
                "type": "statistical_anomaly",
                "src_ip": src_ip,
                "anomalies": anomalies,
                "confidence": round(confidence, 4),
                "max_z_score": round(max_z, 4),
                "features_flagged": len(anomalies),
            }
        except Exception:
            return None

    def _check_ip_stat(self, ip: str, feature: str, value: float) -> Optional[dict]:
        if ip not in self._ip_stats:
            self._ip_stats[ip] = {}

        if feature not in self._ip_stats[ip]:
            self._ip_stats[ip][feature] = StreamingStats()

        stats = self._ip_stats[ip][feature]
        z = stats.z_score(value)
        stats.update(value)

        if stats.n < self.min_history:
            return None

        if abs(z) > self.z_threshold:
            return {
                "scope": "per_ip",
                "ip": ip,
                "feature": feature,
                "value": round(value, 6),
                "mean": round(stats.mean, 6),
                "std": round(stats.std(), 6),
                "z_score": round(z, 4),
                "direction": "high" if z > 0 else "low",
            }
        return None

    def _check_global_stat(self, feature: str, value: float) -> Optional[dict]:
        if feature not in self._global_stats:
            self._global_stats[feature] = StreamingStats()

        stats = self._global_stats[feature]
        z = stats.z_score(value)
        stats.update(value)

        if stats.n < self.min_history:
            return None

        if abs(z) > self.z_threshold:
            return {
                "scope": "global",
                "feature": feature,
                "value": round(value, 6),
                "mean": round(stats.mean, 6),
                "std": round(stats.std(), 6),
                "z_score": round(z, 4),
                "direction": "high" if z > 0 else "low",
            }
        return None

    def get_stats(self) -> dict:
        return {
            "tracked_ips": len(self._ip_stats),
            "anomaly_count": self._anomaly_count,
            "z_threshold": self.z_threshold,
            "features_tracked": len(NUMERIC_FEATURES),
        }
