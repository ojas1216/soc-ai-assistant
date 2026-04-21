"""
Ensemble detector — orchestrates all 5 models and produces a VerdictResult.
This is the primary entry point for threat scoring.
"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

logger = logging.getLogger(__name__)


class EnsembleDetector:
    """
    Lazy-loads the 5 models on first use.
    Runs each model in a separate thread for speed.
    """

    def __init__(self):
        self._bert = None
        self._iforest = None
        self._lstm = None
        self._ae = None
        self._ocsvm = None
        self._voter = None
        self._ready = False

    def load(self):
        """Initialise all models. Call once at startup."""
        if self._ready:
            return
        logger.info("[Ensemble] Loading models ...")
        t0 = time.time()

        from src.models.bert_analyzer import BERTAnalyzer
        from src.models.isolation_forest_model import IsolationForestModel
        from src.models.lstm_predictor import LSTMPredictor
        from src.models.autoencoder_model import AutoencoderModel
        from src.models.one_class_svm import OneClassSVMModel
        from src.models.voting_classifier import VotingClassifier

        self._bert    = BERTAnalyzer()
        self._iforest = IsolationForestModel()
        self._lstm    = LSTMPredictor()
        self._ae      = AutoencoderModel()
        self._ocsvm   = OneClassSVMModel()
        self._voter   = VotingClassifier()
        self._ready   = True

        logger.info("[Ensemble] All models loaded in %.2f s", time.time() - t0)

    def detect(self, text: str, parallel: bool = True) -> dict:
        """
        Run all 5 detectors on text and return a full verdict dict.

        Parameters
        ----------
        text     : raw log / PCAP text (up to 8 KB used; truncated beyond)
        parallel : run models in parallel threads (default True)

        Returns
        -------
        dict with keys: verdict (VerdictResult as dict), timing, input_chars
        """
        if not self._ready:
            self.load()

        text = str(text)[:8192]
        t0 = time.time()

        if parallel:
            raw_results = self._run_parallel(text)
        else:
            raw_results = self._run_sequential(text)

        verdict = self._voter.vote(raw_results)
        elapsed = round(time.time() - t0, 3)

        return {
            "verdict": self._voter.to_dict(verdict),
            "timing_seconds": elapsed,
            "input_chars": len(text),
        }

    def training_status(self) -> dict:
        if not self._ready:
            return {"loaded": False}
        return {
            "loaded": True,
            "isolation_forest_trained": self._iforest.is_trained(),
            "lstm_trained":             self._lstm.is_trained(),
            "autoencoder_trained":      self._ae.is_trained(),
            "ocsvm_trained":            self._ocsvm.is_trained(),
            "bert_transformer_mode":    self._bert._use_transformers,
        }

    # ── Execution strategies ──────────────────────────────────────────────────

    def _run_parallel(self, text: str) -> dict:
        tasks = {
            "bert":             lambda: self._bert.analyze(text),
            "isolation_forest": lambda: self._iforest.analyze(text),
            "lstm":             lambda: self._lstm.analyze(text),
            "autoencoder":      lambda: self._ae.analyze(text),
            "ocsvm":            lambda: self._ocsvm.analyze(text),
        }
        results = {}
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(fn): name for name, fn in tasks.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result(timeout=30)
                except Exception as exc:
                    logger.error("[Ensemble] %s failed: %s", name, exc)
                    results[name] = {"threat_score": 0, "confidence": 0.0,
                                     "detection_method": f"{name}:error", "details": {}}
        return results

    def _run_sequential(self, text: str) -> dict:
        return {
            "bert":             self._bert.analyze(text),
            "isolation_forest": self._iforest.analyze(text),
            "lstm":             self._lstm.analyze(text),
            "autoencoder":      self._ae.analyze(text),
            "ocsvm":            self._ocsvm.analyze(text),
        }
