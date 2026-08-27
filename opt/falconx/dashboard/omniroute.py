"""FALCON-X Dashboard — OmniRoute AI integration.

Provides optional AI analysis of security incidents.
Never sends raw system access to the AI.
Falls back gracefully when OmniRoute is unavailable.
"""

import json
import logging
import os
import time
from typing import Dict, Optional

logger = logging.getLogger("falconx-web.omniroute")

# Optional requests import
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.info("requests library not available — HTTP calls will use urllib")


def _http_post(url: str, data: dict, timeout: int = 30) -> Optional[dict]:
    """HTTP POST with fallback to urllib."""
    if REQUESTS_AVAILABLE:
        try:
            resp = requests.post(url, json=data, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("HTTP POST failed: %s", e)
            return None
    else:
        import urllib.request
        import urllib.error
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            logger.error("HTTP POST failed: %s", e)
            return None


# ── Evidence Formatter ────────────────────────────────────────────

def format_incident_evidence(incident: dict) -> dict:
    """Format incident into safe, structured evidence for AI analysis.

    Never sends:
    - System credentials or keys
    - Raw packet contents
    - Full filesystem paths
    - Internal IP ranges that aren't relevant
    - Arbitrary command output
    """
    evidence = {
        "incident_type": incident.get("event_type", "UNKNOWN"),
        "risk_score": incident.get("risk_score", 0),
        "severity": incident.get("severity", "UNKNOWN"),
        "confidence": incident.get("confidence", 0),
        "source_ip": _anonymize_ip(incident.get("device_ip", "")),
        "timestamp": incident.get("timestamp_human", ""),
        "evidence_items": incident.get("evidence", [])[:5],
        "description": incident.get("description", "")[:200],
    }

    # Add detection-specific context
    det_events = incident.get("detection_events", [])
    if det_events:
        evidence["detection_rules"] = [
            de.get("rule_name", "") if isinstance(de, dict) else str(de)
            for de in det_events[:5]
        ]

    return evidence


def _anonymize_ip(ip: str) -> str:
    """Partial IP anonymization for privacy."""
    if not ip:
        return "unknown"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.*.*"
    return ip


# ── OmniRoute Client ─────────────────────────────────────────────

class OmniRouteClient:
    """Client for OmniRoute AI analysis service."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "llama3.2",
        timeout: int = 30,
        max_tokens: int = 512,
    ):
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
        self.max_tokens = max_tokens
        self._available = False
        self._last_check = 0
        self._analysis_count = 0

    def is_available(self) -> bool:
        """Check if OmniRoute is available."""
        now = time.time()
        if now - self._last_check < 30:
            return self._available

        self._last_check = now
        try:
            url = f"{self.base_url}/api/tags"
            if REQUESTS_AVAILABLE:
                resp = requests.get(url, timeout=5)
                self._available = resp.status_code == 200
            else:
                import urllib.request
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    self._available = resp.status == 200
        except Exception:
            self._available = False

        return self._available

    def analyze_incident(self, incident: dict) -> Optional[dict]:
        """Analyze a security incident using AI.

        Returns analysis with:
        - summary
        - explanation
        - severity interpretation
        - recommended investigation
        - confidence
        """
        if not self.is_available():
            return None

        evidence = format_incident_evidence(incident)

        prompt = f"""You are a cybersecurity analyst assistant. Analyze this security incident and provide a structured response.

Incident Data:
{json.dumps(evidence, indent=2)}

Provide your analysis as JSON with these fields:
- summary: One sentence summary
- possible_explanation: What this activity likely represents
- severity_interpretation: Is the assigned severity appropriate?
- recommended_investigation: Steps an admin should take
- confidence: Your confidence (0.0-1.0)
- ioc_suggestions: Any indicators of compromise to watch for

Respond ONLY with valid JSON. No markdown, no code blocks."""

        try:
            url = f"{self.base_url}/api/generate"
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": self.max_tokens,
                    "temperature": 0.3,
                },
            }

            result = _http_post(url, payload, timeout=self.timeout)
            if result and "response" in result:
                self._analysis_count += 1
                return self._parse_response(result["response"])

        except Exception as e:
            logger.error("OmniRoute analysis failed: %s", e)

        return None

    def _parse_response(self, response: str) -> Optional[dict]:
        """Parse AI response into structured format."""
        try:
            # Try to extract JSON from response
            text = response.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                text = "\n".join(lines[1:-1])

            data = json.loads(text)

            # Validate required fields
            required = ["summary", "possible_explanation", "confidence"]
            for field in required:
                if field not in data:
                    data[field] = ""

            # Ensure confidence is float
            try:
                data["confidence"] = float(data["confidence"])
            except (ValueError, TypeError):
                data["confidence"] = 0.5

            return data

        except json.JSONDecodeError:
            # Try to extract useful info from free text
            return {
                "summary": response[:200],
                "possible_explanation": "AI analysis available",
                "severity_interpretation": "See summary",
                "recommended_investigation": "Review incident details",
                "confidence": 0.3,
                "raw_response": response[:500],
            }

    def get_status(self) -> dict:
        return {
            "available": self.is_available(),
            "model": self.model,
            "base_url": self.base_url,
            "analysis_count": self._analysis_count,
        }


# ── Global client ─────────────────────────────────────────────────
_client: Optional[OmniRouteClient] = None


def get_client() -> OmniRouteClient:
    global _client
    if _client is None:
        from config import OMNIROUTE_URL, OMNIROUTE_MODEL, OMNIROUTE_TIMEOUT
        _client = OmniRouteClient(
            base_url=OMNIROUTE_URL,
            model=OMNIROUTE_MODEL,
            timeout=OMNIROUTE_TIMEOUT,
        )
    return _client
