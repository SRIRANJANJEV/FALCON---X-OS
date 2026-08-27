"""FALCON-X Engine — Main orchestrator.

Ties together capture, features, baseline, detection, risk, incidents,
and enforcement into a single processing pipeline.
"""

import gc
import json
import logging
import os
import signal
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

# Add engine directory to path
ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE_DIR)

from capture import PacketCapture
from features import FeatureExtractor
from baseline import NetworkBaseline
from rules import RuleEngine
from anomaly import StatisticalDetector
from ml_interface import MLInterface
from risk import RiskEngine
from incidents import IncidentEngine
from enforcement import EnforcementEngine
from state import get_state_manager, ProtectionState

LOG_DIR = Path("/var/log/falconx")
CONFIG_DIR = Path("/etc/falconx")
STATUS_FILE = Path("/var/lib/falconx/engine.status")

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","component":"engine","message":"%(message)s"}',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "engine.log"),
    ],
)
logger = logging.getLogger("falconx-engine")

running = True


def signal_handler(signum, frame):
    global running
    logger.info("Received signal %d, shutting down", signum)
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


class HealthHandler(BaseHTTPRequestHandler):
    """HTTP health endpoint for the engine."""

    engine_ref = None  # Set by main

    def do_GET(self):
        if self.path == "/health":
            engine = self.engine_ref
            if engine:
                status = engine.get_health_status()
            else:
                status = {"status": "initializing"}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(status).encode())

        elif self.path == "/stats":
            engine = self.engine_ref
            if engine:
                stats = engine.get_stats()
            else:
                stats = {}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(stats, indent=2).encode())

        elif self.path == "/incidents":
            engine = self.engine_ref
            if engine:
                incidents = engine.incidents.get_open_incidents()
            else:
                incidents = []
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(incidents, indent=2).encode())

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default HTTP logging


class Engine:
    """Main FALCON-X detection engine."""

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self._status = "initializing"
        self._start_time = time.time()
        self._last_gc = time.time()
        self._last_stats = time.time()
        self._last_health_check = time.time()
        self._batch_count = 0
        self._detection_count = 0

        # Protection state machine
        self.state_manager = get_state_manager()

        # Initialize components
        cap_cfg = self.config.get("capture", {})
        self.capture = PacketCapture(
            interface=cap_cfg.get("interface", "auto"),
            bpf_filter=cap_cfg.get("bpf_filter", ""),
            snap_length=cap_cfg.get("snap_length", 96),
            buffer_size=cap_cfg.get("buffer_size", 10000),
            batch_size=cap_cfg.get("batch_size", 100),
            flush_interval_ms=cap_cfg.get("flush_interval_ms", 100),
            on_batch=self._process_batch,
        )

        feat_cfg = self.config.get("features", {})
        self.features = FeatureExtractor(
            flow_timeout=feat_cfg.get("flow_timeout_seconds", 120),
            max_flows=feat_cfg.get("max_flows", 50000),
            enabled_features=feat_cfg.get("enabled_features"),
        )

        base_cfg = self.config.get("baseline", {})
        self.baseline = NetworkBaseline(
            learning_period_hours=base_cfg.get("learning_period_hours", 24),
            update_interval=base_cfg.get("update_interval_seconds", 300),
            min_samples=base_cfg.get("min_samples", 100),
            max_devices=base_cfg.get("max_devices", 1000),
            device_ttl_hours=base_cfg.get("device_ttl_hours", 168),
            storage_path=base_cfg.get("storage_path", "/var/lib/falconx/baseline"),
        )

        det_cfg = self.config.get("detection", {})
        self.rules = RuleEngine(rules_config=det_cfg.get("rules", {}))

        stat_cfg = det_cfg.get("statistical", {})
        self.anomaly = StatisticalDetector(
            z_threshold=stat_cfg.get("z_score_threshold", 3.0),
            window_size=stat_cfg.get("window_size", 100),
            min_history=stat_cfg.get("min_history", 50),
        )

        ml_cfg = det_cfg.get("ml", {})
        self.ml = MLInterface(
            model_path=ml_cfg.get("model_path", "/opt/falconx/models"),
            confidence_threshold=ml_cfg.get("confidence_threshold", 0.8),
            max_features=ml_cfg.get("max_features", 20),
        )

        risk_cfg = self.config.get("risk", {})
        self.risk = RiskEngine(
            weights=risk_cfg.get("scoring", {}).get("weights"),
            decay_factor=risk_cfg.get("decay_factor", 0.9),
            max_history=risk_cfg.get("max_history", 1000),
        )

        inc_cfg = self.config.get("incidents", {})
        self.incidents = IncidentEngine(
            storage_path=inc_cfg.get("storage_path", "/var/lib/falconx/incidents"),
            max_open=inc_cfg.get("max_open", 100),
            auto_close_hours=inc_cfg.get("auto_close_hours", 72),
            retention_days=inc_cfg.get("retention_days", 90),
            dedup_window=det_cfg.get("deduplication_window_seconds", 300),
        )

        enfg_cfg = self.config.get("enforcement", {})
        self.enforcement = EnforcementEngine(
            mode=enfg_cfg.get("mode", "log-only"),
            max_blocked=enfg_cfg.get("max_blocked", 100),
            auto_unblock_minutes=enfg_cfg.get("auto_unblock_minutes", 30),
        )

        # Health endpoint
        self._health_port = self.config.get("health", {}).get("endpoint_port", 9100)
        self._health_server: Optional[HTTPServer] = None

    def _load_config(self, config_path: Optional[str] = None) -> dict:
        path = config_path or CONFIG_DIR / "engine.yaml"
        if os.path.exists(path):
            try:
                import yaml
                with open(path) as f:
                    return yaml.safe_load(f) or {}
            except ImportError:
                logger.warning("PyYAML not available, using defaults")
            except Exception as e:
                logger.error("Failed to load config: %s", e)
        return {}

    def _process_batch(self, batch: list):
        """Main processing pipeline for each batch of packets."""
        self._batch_count += 1

        try:
            # 1. Extract features
            flow_features = self.features.process_batch(batch)

            if not flow_features:
                return

            # 2. Update baseline and get anomaly scores
            enriched = self.baseline.process_features(flow_features)

            # 2.5 Feed real traffic data to ML for learning
            self.ml.update(enriched)

            # 3. For each flow, run detection pipeline
            for features in enriched:
                try:
                    self._process_flow(features)
                except Exception as e:
                    logger.error("Flow processing error: %s", e)
        except Exception as e:
            logger.error("Batch processing error: %s", e)

    def _process_flow(self, features: dict):
        """Run full detection pipeline on a single flow."""
        # 4. Rule-based detection
        rule_events = self.rules.evaluate(features)

        # 5. Statistical anomaly detection
        stat_result = self.anomaly.analyze(features)

        # 6. ML anomaly detection
        ml_result = self.ml.predict(features)

        # Combine anomaly signals
        combined_anomaly = None
        if stat_result or ml_result:
            combined_anomaly = {
                "type": "combined",
                "statistical": stat_result,
                "ml": ml_result,
                "confidence": max(
                    stat_result.get("confidence", 0) if stat_result else 0,
                    ml_result.get("confidence", 0) if ml_result else 0,
                ),
            }

        # 7. Risk scoring
        risk = self.risk.assess(features, rule_events, combined_anomaly)

        # 8. Incident generation
        if risk.score >= 30 or rule_events:
            all_evidence = []
            for ev in rule_events:
                all_evidence.extend(ev.evidence)

            # Include statistical/ML evidence
            if stat_result and stat_result.get("anomalies"):
                for a in stat_result["anomalies"]:
                    all_evidence.append(
                        f"Statistical: {a.get('feature', '')} z={a.get('z_score', 0):.2f} ({a.get('direction', '')})"
                    )
            if ml_result and ml_result.get("is_anomaly"):
                all_evidence.append(
                    f"ML: anomaly detected (confidence={ml_result.get('confidence', 0):.2f}, type={ml_result.get('type', '')})"
                )

            event_types = [ev.rule_name for ev in rule_events] if rule_events else ["anomaly"]
            event_type = event_types[0] if event_types else "anomaly"

            self.incidents.process_detection(
                device_ip=features.get("src_ip", ""),
                event_type=event_type,
                severity=risk.level,
                risk_score=risk.score,
                confidence=risk.confidence,
                evidence=all_evidence[:10],
                description=risk.reasoning[0] if risk.reasoning else "Risk threshold exceeded",
                detection_events=[ev.__dict__ if hasattr(ev, '__dict__') else str(ev) for ev in rule_events],
            )

        # 9. Enforcement (log-only by default)
        if risk.score >= 60:
            self.enforcement.evaluate(
                risk_score=risk.score,
                confidence=risk.confidence,
                device_ip=features.get("src_ip", ""),
                detection_events=rule_events,
            )

        self._detection_count += 1

    def _start_health_endpoint(self):
        """Start HTTP health endpoint."""
        from http.server import HTTPServer
        HealthHandler.engine_ref = self
        self._health_server = HTTPServer(("127.0.0.1", self._health_port), HealthHandler)
        thread = threading.Thread(target=self._health_server.serve_forever, daemon=True)
        thread.start()
        logger.info("Health endpoint on port %d", self._health_port)

    def start(self):
        """Start the engine."""
        logger.info("FALCON-X Engine starting (pid=%d)", os.getpid())
        self._status = "starting"
        self.state_manager.transition(ProtectionState.INITIALIZING, "Engine starting")

        # Write status
        STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._write_status("starting")

        # Load baseline
        self.baseline.load()

        # Start health endpoint
        self._start_health_endpoint()

        # Start packet capture
        if not self.capture.start():
            logger.error("Failed to start packet capture — running in offline mode")
            self._status = "degraded"
            self.state_manager.update_component("capture", False, "Packet capture unavailable")
        else:
            self._status = "running"
            self.state_manager.update_component("capture", True, "Packet capture active")

        self.state_manager.update_component("engine", True, "Engine running")
        self._write_status(self._status)
        logger.info("FALCON-X Engine running (status=%s)", self._status)

        # Main loop
        try:
            while running:
                time.sleep(1)

                now = time.time()

                # Periodic garbage collection
                if now - self._last_gc > 60:
                    gc.collect()
                    self._last_gc = now

                # Periodic stats
                if now - self._last_stats > 30:
                    self._log_stats()
                    self._last_stats = now

                # Periodic component health check (every 15 seconds)
                if now - self._last_health_check > 15:
                    self._check_component_health()
                    self._last_health_check = now

        except Exception as e:
            logger.error("Engine error: %s", e)
        finally:
            self.stop()

    def stop(self):
        """Stop the engine gracefully."""
        logger.info("Stopping FALCON-X Engine...")
        self.state_manager.update_component("engine", False, "Engine shutting down")
        self.capture.stop()

        if self._health_server:
            self._health_server.shutdown()

        self._write_status("stopped")
        logger.info(
            "Engine stopped. batches=%d detections=%d",
            self._batch_count, self._detection_count,
        )

    def _write_status(self, status: str):
        STATUS_FILE.write_text(json.dumps({
            "service": "engine",
            "status": status,
            "pid": os.getpid(),
            "started_at": self._start_time,
            "uptime": time.time() - self._start_time,
        }))

    def _log_stats(self):
        stats = self.get_stats()
        logger.info(
            "Stats: capture=%s features=%s baseline=%s rules=%s risk=%s incidents=%s",
            stats.get("capture", {}).get("packets_captured", 0),
            stats.get("features", {}).get("active_flows", 0),
            stats.get("baseline", {}).get("total_flows", 0),
            stats.get("rules", {}).get("detection_count", 0),
            stats.get("incidents", {}).get("open_incidents", 0),
            stats.get("incidents", {}).get("open_incidents", 0),
        )

    def _check_component_health(self):
        """Periodic health check — updates state machine for all components."""
        sm = self.state_manager

        # Engine — always healthy if we're running this code
        sm.update_component("engine", True, "Engine running")

        # Capture — check if sniffer is active
        cap_stats = self.capture.get_stats()
        cap_healthy = cap_stats.get("running", False)
        cap_msg = f"Captured={cap_stats.get('packets_captured', 0)} Dropped={cap_stats.get('packets_dropped', 0)}"
        sm.update_component("capture", cap_healthy, cap_msg)

        # Rules — always healthy (in-process)
        sm.update_component("rules", True, "Rule engine active")

        # Baseline — always healthy (in-process)
        base_stats = self.baseline.get_stats()
        sm.update_component("baseline", True, f"Baseline ready={base_stats.get('ready', False)}")

        # Firewall — check nftables (requires subprocess, may fail)
        try:
            import subprocess
            result = subprocess.run(
                ["nft", "list", "ruleset"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and "falconx_filter" in result.stdout:
                sm.update_component("firewall", True, "nftables active")
            else:
                sm.update_component("firewall", False, "nftables rules not loaded")
        except Exception as e:
            sm.update_component("firewall", False, f"Firewall check failed: {e}")

        # Network — check default route
        try:
            import subprocess
            result = subprocess.run(
                ["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and "default" in result.stdout:
                sm.update_component("network", True, "Default route present")
            else:
                sm.update_component("network", False, "No default route")
        except Exception as e:
            sm.update_component("network", False, f"Network check failed: {e}")

        # ML — check if model is trained
        ml_stats = self.ml.get_stats()
        ml_healthy = ml_stats.get("state") in ("ACTIVE", "LEARNING", "DISABLED")
        ml_msg = f"ML state={ml_stats.get('state', 'unknown')}"
        sm.update_component("ml", ml_healthy, ml_msg)

        # Enforcement — check if enforcer is running
        enf_stats = self.enforcement.get_stats()
        enf_healthy = enf_stats.get("enforcer_running", False) or enf_stats.get("mode") == "log-only"
        enf_msg = f"Mode={enf_stats.get('mode', 'unknown')} Blocks={enf_stats.get('active_ip_blocks', 0)}"
        sm.update_component("enforcement", enf_healthy, enf_msg)

    def get_health_status(self) -> dict:
        return {
            "service": "engine",
            "status": self._status,
            "protection_state": self.state_manager.state_name,
            "pid": os.getpid(),
            "uptime": time.time() - self._start_time,
            "components": {
                "capture": self.capture.get_stats(),
                "features": self.features.get_stats(),
                "baseline": {
                    "ready": self.baseline.is_ready(),
                    **self.baseline.get_stats(),
                },
                "incidents": self.incidents.get_stats(),
            },
        }

    def get_stats(self) -> dict:
        return {
            "capture": self.capture.get_stats(),
            "features": self.features.get_stats(),
            "baseline": self.baseline.get_stats(),
            "rules": self.rules.get_stats(),
            "anomaly": self.anomaly.get_stats(),
            "ml": self.ml.get_stats(),
            "risk": self.risk.get_stats(),
            "incidents": self.incidents.get_stats(),
            "enforcement": self.enforcement.get_stats(),
            "protection_state": self.state_manager.get_summary(),
            "engine": {
                "batch_count": self._batch_count,
                "detection_count": self._detection_count,
                "uptime": time.time() - self._start_time,
            },
        }


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    engine = Engine(config_path)
    engine.start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
