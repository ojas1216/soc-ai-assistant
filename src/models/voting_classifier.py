"""
Weighted ensemble voting classifier.
Combines scores from all 5 detectors into a final verdict.

Weights (must sum to 1.0):
  BERT             0.25  — semantic / language understanding
  Isolation Forest 0.20  — statistical anomaly
  LSTM             0.20  — temporal / sequence anomaly
  Autoencoder      0.20  — reconstruction-based anomaly
  One-Class SVM    0.15  — boundary-based novelty
"""
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

WEIGHTS = {
    "bert":             0.25,
    "isolation_forest": 0.20,
    "lstm":             0.20,
    "autoencoder":      0.20,
    "ocsvm":            0.15,
}

ALERT_THRESHOLD = 75  # weighted score ≥ 75 triggers alert


@dataclass
class ModelResult:
    model_name: str
    threat_score: int        # 0–100
    confidence: float        # 0–1
    detection_method: str
    details: dict = field(default_factory=dict)
    weight: float = 0.0


@dataclass
class VerdictResult:
    weighted_score: float
    alert: bool
    severity: str            # INFO | LOW | MEDIUM | HIGH | CRITICAL
    model_results: list[ModelResult]
    dominant_detector: str
    explanation: str
    raw_scores: dict         # model_name → score


class VotingClassifier:
    """
    Aggregates individual model outputs into a final threat verdict.
    Confidence-weighted scoring: a low-confidence model contributes less.
    """

    def vote(self, results: dict) -> VerdictResult:
        """
        Parameters
        ----------
        results : dict of model_name → raw result dict
                  Keys: bert, isolation_forest, lstm, autoencoder, ocsvm

        Returns
        -------
        VerdictResult with all fields populated
        """
        model_results: list[ModelResult] = []
        raw_scores: dict = {}

        for name, weight in WEIGHTS.items():
            raw = results.get(name, {})
            score = int(raw.get("threat_score", 0))
            conf = float(raw.get("confidence", 0.5))
            mr = ModelResult(
                model_name=name,
                threat_score=score,
                confidence=conf,
                detection_method=raw.get("detection_method", f"{name}:unknown"),
                details=raw.get("details", {}),
                weight=weight,
            )
            model_results.append(mr)
            raw_scores[name] = score

        weighted_score = self._weighted_average(model_results)
        dominant = max(model_results, key=lambda m: m.threat_score * m.weight)
        severity = self._severity(weighted_score)
        alert = weighted_score >= ALERT_THRESHOLD

        explanation = self._explain(weighted_score, model_results, dominant)

        return VerdictResult(
            weighted_score=round(weighted_score, 2),
            alert=alert,
            severity=severity,
            model_results=model_results,
            dominant_detector=dominant.model_name,
            explanation=explanation,
            raw_scores=raw_scores,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _weighted_average(results: list[ModelResult]) -> float:
        """Confidence-adjusted weighted average."""
        total_w = 0.0
        total_score = 0.0
        for r in results:
            adj_weight = r.weight * (0.5 + r.confidence * 0.5)  # confidence boosts weight
            total_score += r.threat_score * adj_weight
            total_w += adj_weight
        return (total_score / total_w) if total_w > 0 else 0.0

    @staticmethod
    def _severity(score: float) -> str:
        if score < 20:
            return "INFO"
        if score < 40:
            return "LOW"
        if score < 60:
            return "MEDIUM"
        if score < 80:
            return "HIGH"
        return "CRITICAL"

    @staticmethod
    def _explain(score: float, results: list[ModelResult], dominant: ModelResult) -> str:
        high_models = [r.model_name for r in results if r.threat_score >= 60]
        lines = []
        lines.append(f"Ensemble weighted threat score: {score:.1f}/100.")
        if high_models:
            lines.append(f"High-confidence signals from: {', '.join(high_models)}.")
        lines.append(
            f"Primary detection driver: {dominant.model_name} "
            f"(score={dominant.threat_score}, confidence={dominant.confidence:.2f})."
        )
        if score >= ALERT_THRESHOLD:
            lines.append("ALERT: Score exceeds threshold — immediate investigation recommended.")
        return " ".join(lines)

    def to_dict(self, verdict: VerdictResult) -> dict:
        return {
            "weighted_score": verdict.weighted_score,
            "alert": verdict.alert,
            "severity": verdict.severity,
            "dominant_detector": verdict.dominant_detector,
            "explanation": verdict.explanation,
            "raw_scores": verdict.raw_scores,
            "model_details": [
                {
                    "model": r.model_name,
                    "score": r.threat_score,
                    "confidence": r.confidence,
                    "method": r.detection_method,
                    "weight": r.weight,
                    "details": r.details,
                }
                for r in verdict.model_results
            ],
        }
