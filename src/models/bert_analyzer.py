"""
BERT-based semantic threat analyzer.
Uses DistilBERT (260 MB) for offline embedding extraction.
Scores logs by cosine similarity to a threat centroid computed
from known-malicious pattern templates.
"""
import logging
import os
import math
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_THREAT_TEMPLATES = [
    "powershell encoded command execution base64 bypass amsi",
    "mimikatz credential dumping lsass process injection",
    "lateral movement smb pass the hash wmi remote execution",
    "command and control beaconing c2 reverse shell netcat",
    "data exfiltration large transfer suspicious outbound dns tunneling",
    "privilege escalation token impersonation uac bypass",
    "persistence registry run key scheduled task startup folder",
    "defense evasion log clearing process hollowing dll injection",
    "brute force failed authentication ssh rdp repeated login",
    "ransomware file encryption mass modification shadow copy delete",
    "sql injection union select drop table xss script injection",
    "port scanning nmap masscan reconnaissance network sweep",
    "rootkit kernel module hidden process file system manipulation",
    "spear phishing malicious attachment macro execution vba",
]

_BENIGN_TEMPLATES = [
    "normal user login successful authentication session started",
    "scheduled backup completed successfully no errors",
    "software update applied package installed version upgrade",
    "routine network connection established internal service",
    "log rotation completed disk usage within normal parameters",
]

SAVED_DIR = Path(__file__).parent / "saved" / "bert"


class BERTAnalyzer:
    """
    Wraps DistilBERT sentence embeddings for threat scoring.
    Falls back to a TF-IDF keyword scorer if transformers is not installed.
    """

    def __init__(self):
        self._model = None
        self._threat_centroid: Optional[np.ndarray] = None
        self._benign_centroid: Optional[np.ndarray] = None
        self._use_transformers = False
        self._tfidf_keywords = self._build_keyword_weights()
        self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, text: str) -> dict:
        """
        Returns:
            threat_score  : int  0–100
            confidence    : float 0–1
            detection_method : str
            details       : dict
        """
        text = str(text).strip()[:2048]
        if not text:
            return self._result(0, 0.0, "empty input")

        if self._use_transformers and self._threat_centroid is not None:
            return self._transformer_score(text)
        return self._keyword_score(text)

    def is_ready(self) -> bool:
        return self._use_transformers or True  # keyword fallback always ready

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load(self):
        try:
            from sentence_transformers import SentenceTransformer

            model_path = str(SAVED_DIR) if SAVED_DIR.exists() else "distilbert-base-nli-mean-tokens"
            logger.info("[BERT] Loading sentence transformer: %s", model_path)
            self._model = SentenceTransformer(model_path)
            self._threat_centroid = self._centroid(_THREAT_TEMPLATES)
            self._benign_centroid = self._centroid(_BENIGN_TEMPLATES)
            self._use_transformers = True
            logger.info("[BERT] Sentence transformer loaded — transformer mode active")

            if not SAVED_DIR.exists():
                SAVED_DIR.mkdir(parents=True, exist_ok=True)
                self._model.save(str(SAVED_DIR))
                logger.info("[BERT] Model cached to %s", SAVED_DIR)

        except Exception as exc:
            logger.warning("[BERT] Transformers unavailable (%s) — using keyword fallback", exc)
            self._use_transformers = False

    def _centroid(self, texts: list) -> np.ndarray:
        embeddings = self._model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
        return embeddings.mean(axis=0)

    # ── Scoring strategies ────────────────────────────────────────────────────

    def _transformer_score(self, text: str) -> dict:
        embedding = self._model.encode([text], convert_to_numpy=True, show_progress_bar=False)[0]
        threat_sim = float(self._cosine(embedding, self._threat_centroid))
        benign_sim = float(self._cosine(embedding, self._benign_centroid))

        # Normalise: push threat similarity into 0–100 range
        raw = (threat_sim - benign_sim + 1.0) / 2.0  # maps [-1,1] → [0,1]
        raw = max(0.0, min(1.0, raw))
        score = int(raw * 100)
        confidence = abs(threat_sim - benign_sim)

        return self._result(
            score,
            min(confidence, 1.0),
            "distilbert-sentence-transformer",
            {"threat_similarity": round(threat_sim, 4), "benign_similarity": round(benign_sim, 4)},
        )

    def _keyword_score(self, text: str) -> dict:
        lower = text.lower()
        hit_weight = 0.0
        hits = []
        for keyword, weight in self._tfidf_keywords.items():
            if keyword in lower:
                hit_weight += weight
                hits.append(keyword)

        raw = min(hit_weight / 10.0, 1.0)
        score = int(raw * 100)
        confidence = min(len(hits) / 5.0, 1.0)

        return self._result(score, confidence, "keyword-tfidf-fallback", {"keywords_matched": hits[:10]})

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _cosine(a: np.ndarray, b: np.ndarray) -> float:
        denom = (np.linalg.norm(a) * np.linalg.norm(b))
        if denom == 0:
            return 0.0
        return float(np.dot(a, b) / denom)

    @staticmethod
    def _build_keyword_weights() -> dict:
        high = {
            "mimikatz": 3.0, "meterpreter": 3.0, "cobalt strike": 3.0,
            "powershell -enc": 2.5, "base64": 2.0, "invoke-expression": 2.5,
            "iex(": 2.5, "downloadstring": 2.0, "bypass": 1.8,
            "lsass": 2.5, "procdump": 2.5, "secretsdump": 2.5,
            "wce.exe": 3.0, "fgdump": 3.0, "hashdump": 2.5,
            "reverse_tcp": 3.0, "reverse_https": 3.0, "bind_tcp": 2.5,
            "c2": 2.0, "beacon": 2.0, "dropper": 2.5,
            "shadow copy": 2.0, "vssadmin delete": 3.0, "ransomware": 3.0,
            "cryptolocker": 3.0, "wannacry": 3.0,
        }
        medium = {
            "powershell": 1.0, "cmd.exe": 0.8, "wscript": 1.2,
            "cscript": 1.2, "regsvr32": 1.5, "rundll32": 1.5,
            "certutil": 1.5, "bitsadmin": 1.5, "mshta": 1.5,
            "wmic": 1.2, "psexec": 1.8, "pass-the-hash": 2.0,
            "lateral": 1.5, "exfil": 2.0, "exfiltrat": 2.0,
            "persistence": 1.5, "scheduled task": 1.3, "autorun": 1.3,
            "failed login": 0.5, "brute": 1.5, "port scan": 1.8,
            "sql injection": 2.0, "xss": 1.8, "shellcode": 2.5,
        }
        return {**high, **medium}

    @staticmethod
    def _result(score: int, confidence: float, method: str, details: dict = None) -> dict:
        return {
            "threat_score": score,
            "confidence": round(confidence, 4),
            "detection_method": f"bert:{method}",
            "details": details or {},
        }
