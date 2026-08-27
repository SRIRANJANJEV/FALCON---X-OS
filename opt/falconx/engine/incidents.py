"""FALCON-X Engine — Incident management system.

Creates, tracks, and manages security incidents.
"""

import json
import logging
import os
import threading
import time
import uuid
from typing import Dict, List, Optional

logger = logging.getLogger("falconx-engine.incidents")


class Incident:
    """A structured security incident."""

    __slots__ = (
        "incident_id", "timestamp", "device_ip", "event_type",
        "severity", "risk_score", "confidence", "evidence",
        "status", "description", "detection_events",
        "last_updated", "resolution_note",
    )

    def __init__(
        self,
        device_ip: str,
        event_type: str,
        severity: str,
        risk_score: int,
        confidence: float,
        evidence: List[str] = None,
        description: str = "",
        detection_events: List[dict] = None,
    ):
        self.incident_id = f"INC-{uuid.uuid4().hex[:12].upper()}"
        self.timestamp = time.time()
        self.device_ip = device_ip
        self.event_type = event_type
        self.severity = severity
        self.risk_score = risk_score
        self.confidence = confidence
        self.evidence = evidence or []
        self.status = "OPEN"
        self.description = description
        self.detection_events = detection_events or []
        self.last_updated = self.timestamp
        self.resolution_note = ""

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "timestamp_human": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)
            ),
            "device_ip": self.device_ip,
            "event_type": self.event_type,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "confidence": round(self.confidence, 4),
            "evidence": self.evidence,
            "status": self.status,
            "description": self.description,
            "detection_events": self.detection_events,
            "last_updated": self.last_updated,
            "resolution_note": self.resolution_note,
        }

    def resolve(self, note: str = ""):
        self.status = "RESOLVED"
        self.resolution_note = note
        self.last_updated = time.time()

    def mark_investigating(self):
        self.status = "INVESTIGATING"
        self.last_updated = time.time()

    def mark_false_positive(self, note: str = ""):
        self.status = "FALSE_POSITIVE"
        self.resolution_note = note
        self.last_updated = time.time()


class IncidentEngine:
    """Manages the lifecycle of security incidents."""

    def __init__(
        self,
        storage_path: str = "/var/lib/falconx/incidents",
        max_open: int = 100,
        auto_close_hours: int = 72,
        retention_days: int = 90,
        dedup_window: int = 300,
    ):
        self.storage_path = storage_path
        self.max_open = max_open
        self.auto_close_hours = auto_close_hours
        self.retention_days = retention_days
        self.dedup_window = dedup_window

        self._open_incidents: Dict[str, Incident] = {}
        self._closed_incidents: List[Incident] = []
        self._lock = threading.Lock()
        self._last_save = time.time()

        # Deduplication
        self._recent_events: Dict[str, float] = {}

        os.makedirs(storage_path, exist_ok=True)
        self._load()

    def process_detection(
        self,
        device_ip: str,
        event_type: str,
        severity: str,
        risk_score: int,
        confidence: float,
        evidence: List[str] = None,
        description: str = "",
        detection_events: List[dict] = None,
    ) -> Optional[Incident]:
        """Process a detection and create/update incidents.

        Returns the incident if created, None if deduplicated or suppressed.
        """
        # Deduplication
        dedup_key = f"{device_ip}:{event_type}:{severity}"
        now = time.time()

        with self._lock:
            if dedup_key in self._recent_events:
                if now - self._recent_events[dedup_key] < self.dedup_window:
                    # Update existing incident instead of creating new one
                    for inc in self._open_incidents.values():
                        if (inc.device_ip == device_ip and
                                inc.event_type == event_type and
                                inc.status in ("OPEN", "INVESTIGATING")):
                            inc.risk_score = max(inc.risk_score, risk_score)
                            inc.evidence.extend(evidence or [])
                            inc.last_updated = now
                            return inc
                    return None

            self._recent_events[dedup_key] = now

            # Check open incident limit
            if len(self._open_incidents) >= self.max_open:
                self._close_oldest_incidents(5)

            # Create incident
            incident = Incident(
                device_ip=device_ip,
                event_type=event_type,
                severity=severity,
                risk_score=risk_score,
                confidence=confidence,
                evidence=evidence,
                description=description,
                detection_events=detection_events,
            )

            self._open_incidents[incident.incident_id] = incident

            logger.info(
                "Incident created: %s [%s] device=%s risk=%d — %s",
                incident.incident_id, severity, device_ip, risk_score, event_type,
            )

            # Auto-close old incidents
            self._auto_close_incidents()

            # Periodic save
            if now - self._last_save > 60:
                self._save()
                self._last_save = now

            return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        with self._lock:
            return self._open_incidents.get(incident_id)

    def get_open_incidents(self) -> List[dict]:
        with self._lock:
            return [inc.to_dict() for inc in self._open_incidents.values()]

    def get_recent_incidents(self, limit: int = 50) -> List[dict]:
        with self._lock:
            all_incidents = list(self._open_incidents.values()) + self._closed_incidents
            all_incidents.sort(key=lambda i: i.timestamp, reverse=True)
            return [inc.to_dict() for inc in all_incidents[:limit]]

    def resolve_incident(self, incident_id: str, note: str = "") -> bool:
        with self._lock:
            inc = self._open_incidents.pop(incident_id, None)
            if inc:
                inc.resolve(note)
                self._closed_incidents.append(inc)
                self._trim_closed()
                return True
            return False

    def mark_false_positive(self, incident_id: str, note: str = "") -> bool:
        with self._lock:
            inc = self._open_incidents.pop(incident_id, None)
            if inc:
                inc.mark_false_positive(note)
                self._closed_incidents.append(inc)
                self._trim_closed()
                return True
            return False

    def _auto_close_incidents(self):
        now = time.time()
        cutoff = now - (self.auto_close_hours * 3600)
        to_close = [
            iid for iid, inc in self._open_incidents.items()
            if inc.last_updated < cutoff
        ]
        for iid in to_close:
            inc = self._open_incidents.pop(iid)
            inc.resolve("Auto-closed after timeout")
            self._closed_incidents.append(inc)
        if to_close:
            logger.info("Auto-closed %d incidents", len(to_close))

    def _close_oldest_incidents(self, count: int):
        if not self._open_incidents:
            return
        oldest = sorted(
            self._open_incidents.items(), key=lambda x: x[1].timestamp
        )[:count]
        for iid, inc in oldest:
            del self._open_incidents[iid]
            inc.resolve("Closed to make room for new incidents")
            self._closed_incidents.append(inc)

    def _trim_closed(self):
        max_closed = self.retention_days * 10
        if len(self._closed_incidents) > max_closed:
            self._closed_incidents = self._closed_incidents[-max_closed:]

    def _save(self):
        try:
            data = {
                "open": {k: v.to_dict() for k, v in self._open_incidents.items()},
                "closed_count": len(self._closed_incidents),
            }
            path = os.path.join(self.storage_path, "incidents.json")
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error("Failed to save incidents: %s", e)

    def _load(self):
        try:
            path = os.path.join(self.storage_path, "incidents.json")
            if not os.path.exists(path):
                return
            with open(path) as f:
                data = json.load(f)
            # Reload open incidents
            for iid, idata in data.get("open", {}).items():
                inc = Incident(
                    device_ip=idata["device_ip"],
                    event_type=idata["event_type"],
                    severity=idata["severity"],
                    risk_score=idata["risk_score"],
                    confidence=idata["confidence"],
                    evidence=idata.get("evidence", []),
                    description=idata.get("description", ""),
                )
                inc.incident_id = idata["incident_id"]
                inc.timestamp = idata["timestamp"]
                inc.status = idata.get("status", "OPEN")
                self._open_incidents[iid] = inc
            logger.info("Loaded %d open incidents", len(self._open_incidents))
        except Exception as e:
            logger.error("Failed to load incidents: %s", e)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "open_incidents": len(self._open_incidents),
                "closed_incidents": len(self._closed_incidents),
                "by_severity": self._count_by_severity(),
            }

    def _count_by_severity(self) -> dict:
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for inc in self._open_incidents.values():
            counts[inc.severity] = counts.get(inc.severity, 0) + 1
        return counts
