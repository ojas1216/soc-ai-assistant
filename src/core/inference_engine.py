"""
Production inference engine — the single entry point for all analysis.
Orchestrates ensemble ML, zero-day detection, existing threat detection,
kill chain reconstruction, and report generation.
"""
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class InferenceEngine:
    """
    Thread-safe analysis engine.
    Lazy-loads all subsystems on first call.
    """

    _instance: Optional["InferenceEngine"] = None

    def __init__(self, config: dict = None):
        self._cfg = config or {}
        self._ensemble = None
        self._zd_detector = None
        self._existing = None
        self._report_gen = None
        self._ready = False

    @classmethod
    def get_instance(cls, config: dict = None) -> "InferenceEngine":
        """Singleton accessor — reuse loaded models across requests."""
        if cls._instance is None:
            cls._instance = cls(config)
        return cls._instance

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(
        self,
        log_text: str = "",
        pcap_text: str = "",
        ioc: str = "",
        customer_id: str = "",
        mode: str = "tool",
    ) -> dict:
        """
        Full analysis pipeline.

        Returns a complete result dict suitable for JSON serialisation
        and PDF report generation.
        """
        if not self._ready:
            self._load_subsystems()

        t_start = time.time()
        combined = "\n".join(filter(None, [log_text, pcap_text]))

        if not combined and not ioc:
            return self._empty_result("No input provided")

        if ioc and not combined:
            combined = f"IOC under analysis: {ioc}"

        # 1. Ensemble ML scoring
        logger.info("[Engine] Running ensemble detector ...")
        ensemble_result = self._ensemble.detect(combined)

        # 2. Zero-day detection
        logger.info("[Engine] Running zero-day detector ...")
        zd_result = self._zd_detector.detect(log_text or combined, pcap_text)

        # 3. Existing threat detection (YARA, Sigma, CVE, MITRE)
        logger.info("[Engine] Running existing threat detector ...")
        existing_result = self._existing.detect(combined)

        # 4. Kill chain reconstruction (only if IOC provided)
        kill_chain = None
        if ioc:
            logger.info("[Engine] Reconstructing kill chain for IOC: %s", ioc)
            from backend.kill_chain import reconstruct_kill_chain
            kill_chain = reconstruct_kill_chain(
                ioc=ioc,
                log_text=log_text,
                pcap_text=pcap_text,
                cve_list=[c["cve_id"] for c in existing_result.get("cves", [])],
                config=self._cfg,
            )

        # 5. Composite risk score
        risk = self._composite_risk(ensemble_result, zd_result, existing_result)

        elapsed = round(time.time() - t_start, 3)
        logger.info("[Engine] Analysis complete in %.2f s", elapsed)

        result = {
            "meta": {
                "generated_at":  datetime.now(timezone.utc).isoformat(),
                "analysis_time": elapsed,
                "customer_id":   customer_id,
                "mode":          mode,
                "tool_version":  "2.0.0",
            },
            "risk": risk,
            "ensemble":    ensemble_result,
            "zero_day":    zd_result,
            "existing":    existing_result,
            "kill_chain":  kill_chain,
            "inputs": {
                "log_chars":  len(log_text),
                "pcap_chars": len(pcap_text),
                "ioc":        ioc,
            },
        }
        return result

    def generate_pdf(self, result: dict) -> bytes:
        """Generate a PDF report from a completed analysis result."""
        if self._report_gen is None:
            from src.utils.report_generator import AdvancedReportGenerator
            self._report_gen = AdvancedReportGenerator()
        return self._report_gen.generate(result)

    def training_status(self) -> dict:
        if not self._ready:
            return {"ready": False, "message": "Engine not loaded yet"}
        return {
            "ready": True,
            "ensemble": self._ensemble.training_status(),
        }

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load_subsystems(self):
        logger.info("[Engine] Loading subsystems ...")
        t0 = time.time()

        from src.core.ensemble_detector import EnsembleDetector
        from src.core.zero_day_detector import ZeroDayDetector
        from src.core.existing_threat_detector import ExistingThreatDetector

        self._ensemble = EnsembleDetector()
        self._ensemble.load()

        self._zd_detector = ZeroDayDetector()
        self._existing    = ExistingThreatDetector()
        self._ready       = True
        logger.info("[Engine] All subsystems ready in %.2f s", time.time() - t0)

    # ── Risk aggregation ──────────────────────────────────────────────────────

    @staticmethod
    def _composite_risk(ensemble: dict, zd: dict, existing: dict) -> dict:
        ensemble_score = ensemble.get("verdict", {}).get("weighted_score", 0)
        zd_score       = zd.get("zero_day_score", 0)
        hit_count      = existing.get("hit_count", 0)

        # Composite: 50% ensemble + 30% zero-day + 20% rule hits
        rule_score = min(hit_count * 5, 100)
        composite  = ensemble_score * 0.50 + zd_score * 0.30 + rule_score * 0.20
        composite  = round(composite, 2)

        if composite >= 80:
            level = "CRITICAL"
        elif composite >= 60:
            level = "HIGH"
        elif composite >= 40:
            level = "MEDIUM"
        elif composite >= 20:
            level = "LOW"
        else:
            level = "INFO"

        return {
            "composite_score": composite,
            "level":           level,
            "ensemble_score":  ensemble_score,
            "zero_day_score":  zd_score,
            "rule_score":      rule_score,
            "alert":           composite >= 60,
        }

    @staticmethod
    def _empty_result(reason: str) -> dict:
        return {
            "meta":      {"generated_at": datetime.now(timezone.utc).isoformat(), "error": reason},
            "risk":      {"composite_score": 0, "level": "INFO", "alert": False},
            "ensemble":  {},
            "zero_day":  {},
            "existing":  {},
            "kill_chain": None,
        }
