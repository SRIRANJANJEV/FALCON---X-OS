"""FALCON-X Engine — Risk scoring engine.

Deterministic, explainable risk scoring that considers multiple factors.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("falconx-engine.risk")

# Severity to numeric mapping
SEVERITY_SCORES = {
    "LOW": 15,
    "MEDIUM": 40,
    "HIGH": 65,
    "CRITICAL": 85,
}


@dataclass
class RiskAssessment:
    """Risk assessment result with full explanation."""
    score: int  # 0-100
    level: str  # LOW, MEDIUM, HIGH, CRITICAL
    factors: List[Dict] = field(default_factory=list)
    confidence: float = 0.0
    reasoning: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "confidence": round(self.confidence, 4),
            "factors": self.factors,
            "reasoning": self.reasoning,
        }


class RiskEngine:
    """Computes deterministic risk scores from detection events and features.

    Scoring formula:
        score = w_anomaly * anomaly_score
              + w_severity * event_severity
              + w_reputation * (1 - device_reputation)
              + w_frequency * frequency_factor
              + w_confidence * confidence

    Each factor is 0-100, weighted and combined.
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        decay_factor: float = 0.9,
        max_history: int = 1000,
    ):
        self.weights = weights or {
            "anomaly_score": 0.3,
            "event_severity": 0.25,
            "device_reputation": 0.2,
            "frequency": 0.15,
            "confidence": 0.1,
        }
        self.decay_factor = decay_factor
        self.max_history = max_history

        # Per-IP risk history for frequency analysis
        self._ip_event_history: Dict[str, List[float]] = {}

    def assess(
        self,
        features: dict,
        detection_events: list,
        anomaly_result: Optional[dict] = None,
    ) -> RiskAssessment:
        """Compute risk score from all available signals."""
        factors = []
        reasoning = []

        # 1. Anomaly score (0-100)
        anomaly_val = features.get("anomaly_score", 0.0)
        if anomaly_result:
            ml_conf = anomaly_result.get("confidence", 0.0)
            anomaly_val = max(anomaly_val, ml_conf)
        anomaly_factor = min(anomaly_val * 100, 100)
        factors.append({"name": "anomaly_score", "value": round(anomaly_factor, 2)})
        if anomaly_factor > 30:
            reasoning.append(f"Anomaly score: {anomaly_factor:.0f}/100")

        # 2. Event severity (0-100)
        if detection_events:
            max_severity = max(
                SEVERITY_SCORES.get(e.severity, 0) for e in detection_events
            )
            factors.append({"name": "event_severity", "value": max_severity})
            for event in detection_events:
                reasoning.append(f"{event.rule_name}: {event.severity} — {event.description}")
        else:
            max_severity = 0
            factors.append({"name": "event_severity", "value": 0})

        # 3. Device reputation (0-100, inverted — lower reputation = higher risk)
        device_rep = features.get("device_reputation", 0.5)
        reputation_factor = (1.0 - device_rep) * 100
        factors.append({"name": "device_reputation", "value": round(reputation_factor, 2)})
        device_status = features.get("device_status", "")
        if device_status == "UNKNOWN":
            reasoning.append("Device is UNKNOWN (new to network)")
            reputation_factor = max(reputation_factor, 40)
        elif device_status == "LEARNING":
            reasoning.append("Device is still in learning phase")

        # 4. Frequency (0-100)
        src_ip = features.get("src_ip", "")
        frequency_factor = self._compute_frequency(src_ip)
        factors.append({"name": "frequency", "value": round(frequency_factor, 2)})
        if frequency_factor > 30:
            reasoning.append(f"Repeated events from {src_ip}")

        # 5. Confidence (0-100)
        if detection_events:
            avg_confidence = sum(e.confidence for e in detection_events) / len(detection_events)
        else:
            avg_confidence = anomaly_result.get("confidence", 0.0) if anomaly_result else 0.0
        confidence_factor = avg_confidence * 100
        factors.append({"name": "confidence", "value": round(confidence_factor, 2)})

        # Weighted combination
        score = 0.0
        score += self.weights["anomaly_score"] * anomaly_factor
        score += self.weights["event_severity"] * max_severity
        score += self.weights["device_reputation"] * reputation_factor
        score += self.weights["frequency"] * frequency_factor
        score += self.weights["confidence"] * confidence_factor

        # Clamp to 0-100
        score = max(0, min(100, int(score)))

        # Determine level
        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        if not reasoning:
            reasoning.append("No significant risk indicators")

        return RiskAssessment(
            score=score,
            level=level,
            factors=factors,
            confidence=round(avg_confidence, 4),
            reasoning=reasoning,
        )

    def _compute_frequency(self, src_ip: str) -> float:
        """Compute frequency factor based on recent event history."""
        now = time.time()

        if src_ip not in self._ip_event_history:
            self._ip_event_history[src_ip] = []

        history = self._ip_event_history[src_ip]
        history.append(now)

        # Keep bounded
        if len(history) > self.max_history:
            self._ip_event_history[src_ip] = history[-self.max_history // 2:]

        # Events in last 5 minutes
        cutoff = now - 300
        recent = sum(1 for t in history if t > cutoff)

        # Decay old entries
        self._ip_event_history[src_ip] = [t for t in history if t > now - 3600]

        # Score based on recent frequency
        if recent > 50:
            return 90.0
        elif recent > 20:
            return 60.0
        elif recent > 10:
            return 35.0
        elif recent > 5:
            return 15.0
        return 0.0

    def get_stats(self) -> dict:
        return {
            "tracked_ips": len(self._ip_event_history),
            "weights": self.weights,
        }
