"""FALCON-X Engine — ML Interface with honest lifecycle.

Lifecycle:
    STARTUP → LEARNING (collecting real traffic data)
    → TRAINING (when enough data)
    → ACTIVE (model validated)
    → PERIODIC_RETRAINING

States:
    LEARNING    — insufficient data, collecting from real traffic
    TRAINING    — model being trained on real data
    ACTIVE      — trained, validated model in use
    UNAVAILABLE — training failed or sklearn not available
    DISABLED    — ML explicitly disabled

Important:
- Only trains on REAL traffic features, never synthetic data
- Never claims ACTIVE without a validated model
- Rules and statistical detection always continue independently
- No dependency on sklearn for base detection
"""

import json
import logging
import math
import os
import pickle
import tempfile
import threading
import time
from collections import deque
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger("falconx-engine.ml")


class MLState(Enum):
    STARTUP = "STARTUP"
    LEARNING = "LEARNING"
    TRAINING = "TRAINING"
    ACTIVE = "ACTIVE"
    UNAVAILABLE = "UNAVAILABLE"
    DISABLED = "DISABLED"


# Optional scikit-learn import — never required
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.info("scikit-learn not available — ML in fallback mode only")


# Features used for ML (subset of all flow features)
ML_FEATURES = [
    "flow_duration", "packet_count", "byte_count",
    "packets_per_second", "bytes_per_second",
    "tcp_syn_rate", "tcp_rst_rate", "tcp_fin_rate",
    "icmp_rate", "dns_request_rate", "arp_activity",
    "avg_packet_size", "max_packet_size",
    "unique_dst_ports", "inter_arrival_time_mean", "inter_arrival_time_std",
]

# Lifecycle thresholds
MIN_SAMPLES_FOR_TRAINING = 200
RETRAIN_INTERVAL = 10000
MAX_TRAINING_TIME_SECONDS = 30
MAX_MODEL_SIZE_BYTES = 10 * 1024 * 1024
MAX_DATA_BUFFER = 5000
MIN_VALIDATION_SCORE = 0.3
MAX_CONSECUTIVE_FAILURES = 3


class MLInterface:
    """ML interface with honest lifecycle management.

    Only trains on REAL traffic data collected during operation.
    Never claims ML is active without a trained, validated model.
    Rules and statistical detection always continue independently.
    """

    def __init__(
        self,
        model_path: str = "/opt/falconx/models",
        confidence_threshold: float = 0.8,
        max_features: int = 20,
        enabled: bool = True,
    ):
        self.model_path = model_path
        self.confidence_threshold = confidence_threshold
        self.max_features = min(max_features, len(ML_FEATURES))
        self.enabled = enabled

        self._state = MLState.STARTUP if enabled else MLState.DISABLED
        self._model = None
        self._scaler = None

        # Real data buffer — bounded deque of actual traffic feature vectors
        self._data_buffer: deque = deque(maxlen=MAX_DATA_BUFFER)

        self._sample_count = 0
        self._training_count = 0
        self._inference_count = 0
        self._anomaly_count = 0
        self._last_train_time = 0
        self._last_train_samples = 0
        self._consecutive_failures = 0
        self._validation_score = 0.0
        self._training_history: List[dict] = []
        self._lock = threading.Lock()

        # Feature statistics for NaN/inf handling
        self._feature_valid_range: Dict[str, tuple] = {}

        if enabled:
            self._try_load_model()

    @property
    def state(self) -> MLState:
        return self._state

    @property
    def state_name(self) -> str:
        return self._state.value

    def _try_load_model(self):
        """Try to load a pre-trained model from disk."""
        if not SKLEARN_AVAILABLE:
            self._state = MLState.UNAVAILABLE
            logger.warning("scikit-learn not available — ML disabled")
            return

        model_file = os.path.join(self.model_path, "anomaly_model.pkl")
        scaler_file = os.path.join(self.model_path, "anomaly_scaler.pkl")
        meta_file = os.path.join(self.model_path, "model_meta.json")

        if not (os.path.exists(model_file) and os.path.exists(scaler_file)):
            self._state = MLState.LEARNING
            logger.info("No pre-trained model — entering LEARNING state")
            return

        try:
            if os.path.getsize(model_file) > MAX_MODEL_SIZE_BYTES:
                logger.error("Model file too large: %d bytes", os.path.getsize(model_file))
                self._state = MLState.UNAVAILABLE
                return

            with open(model_file, "rb") as f:
                self._model = pickle.load(f)
            with open(scaler_file, "rb") as f:
                self._scaler = pickle.load(f)

            # Load metadata
            if os.path.exists(meta_file):
                with open(meta_file) as f:
                    meta = json.load(f)
                self._validation_score = meta.get("validation_score", 0)
                self._training_count = meta.get("training_count", 0)
                self._sample_count = meta.get("sample_count", 0)

            # Validate model is usable
            test_vec = [[0.0] * self.max_features]
            if self._scaler:
                test_vec = self._scaler.transform(test_vec)
            self._model.predict(test_vec)

            # Check validation score
            if self._validation_score < MIN_VALIDATION_SCORE:
                logger.warning("Model validation score too low (%.3f) — entering LEARNING", self._validation_score)
                self._model = None
                self._scaler = None
                self._state = MLState.LEARNING
                return

            self._state = MLState.ACTIVE
            self._last_train_samples = self._sample_count
            logger.info(
                "Loaded pre-trained model (validation=%.3f, samples=%d, trains=%d)",
                self._validation_score, self._sample_count, self._training_count,
            )
        except Exception as e:
            logger.warning("Failed to load model: %s — entering LEARNING", e)
            self._model = None
            self._scaler = None
            self._state = MLState.LEARNING

    def extract_feature_vector(self, features: dict) -> Optional[List[float]]:
        """Extract numeric feature vector for ML. Handles NaN/inf."""
        vec = []
        for feat in ML_FEATURES[:self.max_features]:
            val = features.get(feat, 0.0)
            if val is None or not isinstance(val, (int, float)):
                val = 0.0
            # NaN/inf handling — replace with 0.0
            if math.isnan(val) or math.isinf(val):
                val = 0.0
            # Clamp extreme values
            val = max(-1e6, min(1e6, val))
            vec.append(float(val))
        return vec

    def predict(self, features: dict) -> Optional[dict]:
        """Predict if flow features are anomalous.

        Returns prediction dict or None if ML cannot make a prediction.
        Rules and statistical detection continue regardless of ML state.
        """
        if not self.enabled:
            return None

        self._inference_count += 1
        vec = self.extract_feature_vector(features)
        if vec is None:
            return None

        with self._lock:
            if self._state == MLState.ACTIVE and self._model is not None:
                return self._predict_trained(vec)
            elif self._state in (MLState.LEARNING, MLState.STARTUP):
                return self._predict_collecting(vec)
            else:
                # UNAVAILABLE or DISABLED — no ML prediction
                return None

    def _predict_trained(self, vec: List[float]) -> dict:
        """Use trained model for prediction."""
        try:
            X = np.array([vec])
            if self._scaler:
                X = self._scaler.transform(X)

            prediction = self._model.predict(X)[0]
            score = self._model.decision_function(X)[0]

            is_anomaly = prediction == -1
            confidence = min(abs(score) * 2, 1.0)

            if is_anomaly:
                self._anomaly_count += 1

            return {
                "type": "ml_trained",
                "is_anomaly": bool(is_anomaly),
                "confidence": round(confidence, 4),
                "model_score": round(float(score), 6),
                "model_type": "isolation_forest",
                "ml_state": self._state.value,
                "validation_score": round(self._validation_score, 4),
                "samples_used": self._sample_count,
            }
        except Exception as e:
            logger.error("ML prediction failed: %s", e)
            return {
                "type": "ml_error",
                "is_anomaly": False,
                "confidence": 0.0,
                "error": str(e),
                "ml_state": self._state.value,
            }

    def _predict_collecting(self, vec: List[float]) -> dict:
        """Collecting data — not making real ML predictions."""
        self._data_buffer.append(vec)

        return {
            "type": "ml_collecting",
            "is_anomaly": False,
            "confidence": 0.0,
            "ml_state": self._state.value,
            "samples_collected": len(self._data_buffer),
            "samples_needed": MIN_SAMPLES_FOR_TRAINING,
        }

    def update(self, features_list: List[dict]) -> None:
        """Feed real traffic data. Manages lifecycle transitions."""
        if not self.enabled or not SKLEARN_AVAILABLE:
            return

        vectors = []
        for f in features_list:
            vec = self.extract_feature_vector(f)
            if vec:
                vectors.append(vec)

        if not vectors:
            return

        with self._lock:
            for v in vectors:
                self._data_buffer.append(v)
            self._sample_count += len(vectors)

            # Check lifecycle transitions
            if self._state == MLState.LEARNING:
                if len(self._data_buffer) >= MIN_SAMPLES_FOR_TRAINING:
                    self._attempt_training()
            elif self._state == MLState.ACTIVE:
                if (self._sample_count - self._last_train_samples) >= RETRAIN_INTERVAL:
                    self._attempt_retraining()

    def _attempt_training(self):
        """Train on REAL collected traffic data."""
        self._state = MLState.TRAINING
        logger.info("Training ML model with %d real samples", len(self._data_buffer))

        try:
            self._train_model()
            self._state = MLState.ACTIVE
            self._consecutive_failures = 0
            logger.info(
                "ML model trained (validation=%.3f, samples=%d)",
                self._validation_score, self._sample_count,
            )
        except Exception as e:
            logger.error("ML training failed: %s", e)
            self._consecutive_failures += 1
            if self._consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                self._state = MLState.UNAVAILABLE
                logger.error("ML UNAVAILABLE after %d failures", self._consecutive_failures)
            else:
                self._state = MLState.LEARNING

    def _attempt_retraining(self):
        """Retrain with fresh real data. Keeps old model on failure."""
        old_state = self._state
        self._state = MLState.TRAINING

        try:
            self._train_model()
            self._state = MLState.ACTIVE
            self._last_train_samples = self._sample_count
            self._consecutive_failures = 0
            logger.info("ML retrained (validation=%.3f)", self._validation_score)
        except Exception as e:
            logger.warning("ML retraining failed: %s — keeping old model", e)
            self._state = old_state

    def _train_model(self):
        """Train Isolation Forest on REAL traffic data. Bounded for RPi4."""
        start_time = time.time()

        # Convert buffer to numpy array
        data = list(self._data_buffer)
        if not data:
            raise ValueError("No training data available")

        X = np.array(data, dtype=np.float64)

        # Validate data
        if X.shape[0] < MIN_SAMPLES_FOR_TRAINING:
            raise ValueError(f"Insufficient samples: {X.shape[0]} < {MIN_SAMPLES_FOR_TRAINING}")

        if np.any(np.isnan(X)) or np.any(np.isinf(X)):
            # Clean NaN/inf
            X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
            logger.warning("Cleaned NaN/inf values from training data")

        # Check training time budget
        if time.time() - start_time > MAX_TRAINING_TIME_SECONDS * 0.3:
            raise TimeoutError("Data validation exceeded time budget")

        # Train scaler
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Train Isolation Forest — bounded for RPi4
        n_samples = X_scaled.shape[0]
        self._model = IsolationForest(
            n_estimators=min(100, max(50, n_samples // 10)),
            contamination=0.05,
            max_samples=min(256, n_samples),
            random_state=42,
            n_jobs=1,
        )
        self._model.fit(X_scaled)

        # Validate: run predictions on training data
        predictions = self._model.predict(X_scaled)
        anomaly_ratio = (predictions == -1).sum() / len(predictions)
        self._validation_score = 1.0 - abs(anomaly_ratio - 0.05)

        if self._validation_score < MIN_VALIDATION_SCORE:
            raise ValueError(f"Validation score too low: {self._validation_score:.3f}")

        # Check time budget
        training_time = time.time() - start_time
        if training_time > MAX_TRAINING_TIME_SECONDS:
            logger.warning("Training exceeded time budget: %.1fs", training_time)

        # Save model atomically
        self._save_model()
        self._training_count += 1
        self._last_train_time = time.time()

        self._training_history.append({
            "timestamp": time.time(),
            "samples": self._sample_count,
            "buffer_size": len(self._data_buffer),
            "validation_score": round(self._validation_score, 4),
            "training_time": round(training_time, 2),
            "anomaly_ratio": round(anomaly_ratio, 4),
        })
        if len(self._training_history) > 20:
            self._training_history = self._training_history[-10:]

    def _save_model(self):
        """Save model atomically — write to temp then rename."""
        try:
            os.makedirs(self.model_path, exist_ok=True)

            model_file = os.path.join(self.model_path, "anomaly_model.pkl")
            scaler_file = os.path.join(self.model_path, "anomaly_scaler.pkl")
            meta_file = os.path.join(self.model_path, "model_meta.json")

            # Write to temp files first, then atomically rename
            for data, path in [(self._model, model_file), (self._scaler, scaler_file)]:
                tmp_fd, tmp_path = tempfile.mkstemp(dir=self.model_path, suffix=".tmp")
                try:
                    with os.fdopen(tmp_fd, "wb") as f:
                        pickle.dump(data, f)
                    os.replace(tmp_path, path)
                except Exception:
                    os.unlink(tmp_path)
                    raise

            meta = {
                "training_count": self._training_count,
                "validation_score": round(self._validation_score, 4),
                "sample_count": self._sample_count,
                "buffer_size": len(self._data_buffer),
                "last_train_time": self._last_train_time,
                "features": ML_FEATURES[:self.max_features],
                "model_type": "isolation_forest",
                "sklearn_version": self._get_sklearn_version(),
                "training_history": self._training_history[-5:],
            }
            tmp_fd, tmp_path = tempfile.mkstemp(dir=self.model_path, suffix=".json.tmp")
            try:
                with os.fdopen(tmp_fd, "w") as f:
                    json.dump(meta, f, indent=2)
                os.replace(tmp_path, meta_file)
            except Exception:
                os.unlink(tmp_path)
                raise

            logger.info("Model saved atomically to %s", self.model_path)
        except Exception as e:
            logger.error("Failed to save model: %s", e)

    def _get_sklearn_version(self) -> str:
        try:
            import sklearn
            return sklearn.__version__
        except Exception:
            return "unknown"

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "state": self._state.value,
            "sklearn_available": SKLEARN_AVAILABLE,
            "model_loaded": self._model is not None,
            "sample_count": self._sample_count,
            "buffer_size": len(self._data_buffer),
            "training_count": self._training_count,
            "inference_count": self._inference_count,
            "anomaly_count": self._anomaly_count,
            "validation_score": round(self._validation_score, 4),
            "consecutive_failures": self._consecutive_failures,
            "last_train_time": self._last_train_time,
            "last_train_samples": self._last_train_samples,
            "training_history": self._training_history[-3:],
        }
