"""FALCON-X Engine — Behavioral baseline engine.

Learns normal network behavior per-device and per-network.
New devices are marked UNKNOWN until sufficient evidence exists.
"""

import json
import logging
import math
import os
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("falconx-engine.baseline")


class DeviceProfile:
    """Behavioral profile for a single device."""

    __slots__ = (
        "ip", "first_seen", "last_seen", "total_flows",
        "known_destinations", "known_ports", "known_protocols",
        "avg_pps", "avg_bps", "avg_packet_size",
        "max_pps", "max_bps",
        "pps_history", "bps_history",
        "reputation_score", "is_known",
    )

    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.total_flows = 0
        self.known_destinations: set = set()
        self.known_ports: set = set()
        self.known_protocols: set = set()
        self.avg_pps = 0.0
        self.avg_bps = 0.0
        self.avg_packet_size = 0.0
        self.max_pps = 0.0
        self.max_bps = 0.0
        self.pps_history: list = []
        self.bps_history: list = []
        self.reputation_score = 0.5
        self.is_known = False

    def update(self, features: dict) -> None:
        """Update profile with new flow features."""
        self.last_seen = time.time()
        self.total_flows += 1

        self.known_destinations.add(features.get("dst_ip", ""))
        self.known_ports.add(features.get("dst_port", 0))
        self.known_protocols.add(features.get("protocol", ""))

        pps = features.get("packets_per_second", 0)
        bps = features.get("bytes_per_second", 0)
        pkt_size = features.get("avg_packet_size", 0)

        self.pps_history.append(pps)
        self.bps_history.append(bps)

        # Keep bounded history
        if len(self.pps_history) > 1000:
            self.pps_history = self.pps_history[-500:]
        if len(self.bps_history) > 1000:
            self.bps_history = self.bps_history[-500:]

        # Update running averages
        n = self.total_flows
        self.avg_pps = self.avg_pps * (n - 1) / n + pps / n
        self.avg_bps = self.avg_bps * (n - 1) / n + bps / n
        self.avg_packet_size = self.avg_packet_size * (n - 1) / n + pkt_size / n
        self.max_pps = max(self.max_pps, pps)
        self.max_bps = max(self.max_bps, bps)

    def get_status(self) -> str:
        """UNKNOWN, LEARNING, or KNOWN."""
        if not self.is_known:
            hours = (time.time() - self.first_seen) / 3600
            if hours < 1:
                return "UNKNOWN"
            elif self.total_flows >= 10:
                return "LEARNING"
        return "KNOWN" if self.is_known else "LEARNING"

    def compute_anomaly_score(self, features: dict) -> float:
        """Compute how anomalous new features are compared to baseline.

        Returns 0.0 (normal) to 1.0 (highly anomalous).
        """
        if self.total_flows < 10:
            return 0.0  # Not enough history

        scores = []

        # PPS anomaly
        pps = features.get("packets_per_second", 0)
        if self.avg_pps > 0 and len(self.pps_history) > 10:
            std = self._std(self.pps_history[-100:])
            if std > 0:
                z = abs(pps - self.avg_pps) / max(std, 0.001)
                scores.append(min(z / 5.0, 1.0))

        # BPS anomaly
        bps = features.get("bytes_per_second", 0)
        if self.avg_bps > 0 and len(self.bps_history) > 10:
            std = self._std(self.bps_history[-100:])
            if std > 0:
                z = abs(bps - self.avg_bps) / max(std, 0.001)
                scores.append(min(z / 5.0, 1.0))

        # Destination anomaly
        dst = features.get("dst_ip", "")
        if dst and self.known_destinations and len(self.known_destinations) > 5:
            if dst not in self.known_destinations:
                scores.append(0.3)

        # Port anomaly
        port = features.get("dst_port", 0)
        if port and self.known_ports and len(self.known_ports) > 5:
            if port not in self.known_ports:
                scores.append(0.2)

        # SYN rate anomaly
        syn_rate = features.get("tcp_syn_rate", 0)
        if syn_rate > 0.5 and self.avg_pps > 0:
            scores.append(min(syn_rate, 1.0))

        if not scores:
            return 0.0

        return sum(scores) / len(scores)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "total_flows": self.total_flows,
            "destinations_count": len(self.known_destinations),
            "ports_count": len(self.known_ports),
            "protocols": list(self.known_protocols),
            "avg_pps": round(self.avg_pps, 4),
            "avg_bps": round(self.avg_bps, 2),
            "reputation_score": round(self.reputation_score, 4),
            "status": self.get_status(),
        }

    @staticmethod
    def _std(values: list) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(variance)


class NetworkBaseline:
    """Behavioral baseline for the entire local network."""

    def __init__(
        self,
        learning_period_hours: int = 24,
        update_interval: int = 300,
        min_samples: int = 100,
        max_devices: int = 1000,
        device_ttl_hours: int = 168,
        storage_path: str = "/var/lib/falconx/baseline",
        decay_factor: float = 0.95,
    ):
        self.learning_period_hours = learning_period_hours
        self.update_interval = update_interval
        self.min_samples = min_samples
        self.max_devices = max_devices
        self.device_ttl_hours = device_ttl_hours
        self.storage_path = storage_path
        self.decay_factor = decay_factor

        self._devices: Dict[str, DeviceProfile] = {}
        self._network_stats = {
            "total_flows": 0,
            "total_devices": 0,
            "learning_start": time.time(),
            "is_ready": False,
        }
        self._lock = threading.Lock()
        self._last_save = time.time()

    def process_features(self, features_list: List[dict]) -> List[dict]:
        """Process flow features, update baseline, return features with anomaly scores."""
        results = []

        for features in features_list:
            try:
                src_ip = features.get("src_ip", "")

                with self._lock:
                    device = self._get_or_create_device(src_ip)
                    device.update(features)
                    self._network_stats["total_flows"] += 1

                    anomaly_score = device.compute_anomaly_score(features)
                    features["anomaly_score"] = round(anomaly_score, 4)
                    features["device_status"] = device.get_status()
                    features["device_reputation"] = round(device.reputation_score, 4)
                    features["device_flows"] = device.total_flows

                    # Check if learning period is complete
                    elapsed_hours = (time.time() - self._network_stats["learning_start"]) / 3600
                    if elapsed_hours >= self.learning_period_hours and not self._network_stats["is_ready"]:
                        self._network_stats["is_ready"] = True
                        self._promote_known_devices()
                        logger.info("Baseline learning period complete. %d devices known.", len(self._devices))

                results.append(features)
            except Exception:
                continue

        # Periodic save
        now = time.time()
        if now - self._last_save > self.update_interval:
            self._save()
            self._last_save = now
            self._expire_devices()

        return results

    def _get_or_create_device(self, ip: str) -> DeviceProfile:
        if ip not in self._devices:
            if len(self._devices) >= self.max_devices:
                self._evict_oldest_device()
            self._devices[ip] = DeviceProfile(ip)
            self._network_stats["total_devices"] = len(self._devices)
        return self._devices[ip]

    def _evict_oldest_device(self):
        if not self._devices:
            return
        oldest_ip = min(self._devices, key=lambda ip: self._devices[ip].last_seen)
        del self._devices[oldest_ip]

    def _expire_devices(self):
        now = time.time()
        ttl_seconds = self.device_ttl_hours * 3600
        expired = [
            ip for ip, prof in self._devices.items()
            if now - prof.last_seen > ttl_seconds
        ]
        for ip in expired:
            del self._devices[ip]
        if expired:
            logger.info("Expired %d inactive devices", len(expired))

    def _promote_known_devices(self):
        for device in self._devices.values():
            if device.total_flows >= self.min_samples:
                device.is_known = True

    def get_device(self, ip: str) -> Optional[DeviceProfile]:
        with self._lock:
            return self._devices.get(ip)

    def is_ready(self) -> bool:
        return self._network_stats["is_ready"]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                **self._network_stats,
                "known_devices": sum(1 for d in self._devices.values() if d.is_known),
                "learning_devices": sum(1 for d in self._devices.values() if d.get_status() == "LEARNING"),
                "unknown_devices": sum(1 for d in self._devices.values() if d.get_status() == "UNKNOWN"),
                "devices": {ip: prof.to_dict() for ip, prof in self._devices.items()},
            }

    def _save(self):
        try:
            os.makedirs(self.storage_path, exist_ok=True)
            data = {
                "network_stats": self._network_stats,
                "devices": {ip: prof.to_dict() for ip, prof in self._devices.items()},
            }
            path = os.path.join(self.storage_path, "baseline.json")
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error("Failed to save baseline: %s", e)

    def load(self) -> bool:
        try:
            path = os.path.join(self.storage_path, "baseline.json")
            if not os.path.exists(path):
                return False
            with open(path) as f:
                data = json.load(f)
            self._network_stats.update(data.get("network_stats", {}))
            # Restore device profiles
            for ip, profile_data in data.get("devices", {}).items():
                device = DeviceProfile(ip)
                device.first_seen = profile_data.get("first_seen", 0)
                device.last_seen = profile_data.get("last_seen", 0)
                device.total_flows = profile_data.get("total_flows", 0)
                device.avg_pps = profile_data.get("avg_pps", 0)
                device.avg_bps = profile_data.get("avg_bps", 0)
                device.reputation_score = profile_data.get("reputation_score", 0.5)
                device.is_known = profile_data.get("status", "") == "KNOWN"
                self._devices[ip] = device
            self._network_stats["total_devices"] = len(self._devices)
            logger.info("Loaded baseline with %d devices", len(self._devices))
            return True
        except Exception as e:
            logger.error("Failed to load baseline: %s", e)
            return False
