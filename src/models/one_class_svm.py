"""
One-Class SVM novelty detector.
Trained on normal log features. Inputs outside the learned boundary
score high. Falls back to distance-based scoring when untrained.
"""
import logging
import pickle
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)
SAVED_PATH = Path(__file__).parent / "saved" / "ocsvm.pkl"


class OneClassSVMModel:
    """
    Wraps sklearn OneClassSVM with RBF kernel.
    decision_function < 0  →  outside normal boundary  →  anomaly.
    """

    def __init__(self):
        self._model = None
        self._scaler = None
        self._trained = False
        self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, text: str) -> dict:
        from src.models.isolation_forest_model import IsolationForestModel
        features = IsolationForestModel._extract_features(text)
        vec = np.array(features["vector"], dtype=np.float64).reshape(1, -1)

        if self._trained:
            try:
                scaled = self._scaler.transform(vec)
                raw = float(self._model.decision_function(scaled)[0])
                # raw: positive = inside boundary (normal), negative = outside (anomaly)
                score = int(max(0, min(100, (-raw + 0.5) * 100)))
                confidence = min(abs(raw), 1.0)
                return self._result(score, confidence, "ocsvm-rbf",
                                    {"decision_value": round(raw, 4), "is_outlier": raw < 0})
            except Exception as exc:
                logger.warning("[OCSVM] Scoring error: %s", exc)

        return self._heuristic_score(features)

    def fit(self, texts: list[str]):
        try:
            from sklearn.svm import OneClassSVM
            from sklearn.preprocessing import StandardScaler
            from src.models.isolation_forest_model import IsolationForestModel

            vectors = np.array([IsolationForestModel._extract_features(t)["vector"] for t in texts])
            self._scaler = StandardScaler().fit(vectors)
            scaled = self._scaler.transform(vectors)

            self._model = OneClassSVM(kernel="rbf", nu=0.05, gamma="scale")
            self._model.fit(scaled)
            self._trained = True
            self._save()
            logger.info("[OCSVM] Trained on %d samples", len(texts))
        except Exception as exc:
            logger.error("[OCSVM] Training failed: %s", exc)

    def is_trained(self) -> bool:
        return self._trained

    # ── Persistence ───────────────────────────────────────────────────────────

    def _save(self):
        SAVED_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SAVED_PATH, "wb") as f:
            pickle.dump({"model": self._model, "scaler": self._scaler}, f)

    def _load(self):
        if SAVED_PATH.exists():
            try:
                with open(SAVED_PATH, "rb") as f:
                    state = pickle.load(f)
                self._model = state["model"]
                self._scaler = state["scaler"]
                self._trained = True
                logger.info("[OCSVM] Loaded saved model")
            except Exception as exc:
                logger.warning("[OCSVM] Load failed: %s", exc)

    # ── Heuristic fallback ────────────────────────────────────────────────────

    @staticmethod
    def _heuristic_score(features: dict) -> dict:
        kw = features.get("keyword_hits", 0)
        ent = features.get("entropy", 0.0)
        vec = features.get("vector", [0] * 20)
        score = min(kw * 8 + int(max(ent - 3.8, 0) * 20) + int(vec[2] * 40), 100)
        return OneClassSVMModel._result(score, 0.3, "heuristic-fallback", {})

    @staticmethod
    def _result(score: int, confidence: float, method: str, details: dict) -> dict:
        return {
            "threat_score": score,
            "confidence": round(confidence, 4),
            "detection_method": f"ocsvm:{method}",
            "details": details,
        }
