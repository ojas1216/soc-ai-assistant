"""
Isolation Forest anomaly detector.
Trained on a baseline of normal log feature vectors.
Untrained instances use statistical heuristics as fallback.
"""
import logging
import os
import pickle
import re
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)
SAVED_PATH = Path(__file__).parent / "saved" / "isolation_forest.pkl"


class IsolationForestModel:
    """
    Extracts 20 statistical features from log text, then
    applies a trained IsolationForest for anomaly scoring.
    """

    def __init__(self):
        self._model = None
        self._scaler = None
        self._trained = False
        self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, text: str) -> dict:
        features = self._extract_features(text)
        vec = np.array(features["vector"], dtype=np.float64).reshape(1, -1)

        if self._trained and self._model is not None:
            try:
                scaled = self._scaler.transform(vec)
                raw_score = float(self._model.decision_function(scaled)[0])
                # decision_function: negative = more anomalous
                # map [-0.5, 0.5] → [100, 0]
                score = int(max(0, min(100, (-raw_score + 0.5) * 100)))
                confidence = min(abs(raw_score) * 2, 1.0)
                return self._result(score, confidence, "isolation-forest-trained", features)
            except Exception as exc:
                logger.warning("[IForest] Scoring failed: %s", exc)

        # Statistical fallback when not trained
        score = self._heuristic_score(features)
        return self._result(score, 0.5, "statistical-heuristic", features)

    def fit(self, texts: list[str]):
        """Train on a corpus of normal (benign) log lines."""
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler

            vectors = np.array([self._extract_features(t)["vector"] for t in texts])
            self._scaler = StandardScaler().fit(vectors)
            scaled = self._scaler.transform(vectors)
            self._model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
            self._model.fit(scaled)
            self._trained = True
            self._save()
            logger.info("[IForest] Trained on %d samples", len(texts))
        except Exception as exc:
            logger.error("[IForest] Training failed: %s", exc)

    def is_trained(self) -> bool:
        return self._trained

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self):
        if SAVED_PATH.exists():
            try:
                with open(SAVED_PATH, "rb") as f:
                    state = pickle.load(f)
                self._model = state["model"]
                self._scaler = state["scaler"]
                self._trained = True
                logger.info("[IForest] Loaded saved model from %s", SAVED_PATH)
            except Exception as exc:
                logger.warning("[IForest] Could not load saved model: %s", exc)

    def _save(self):
        SAVED_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SAVED_PATH, "wb") as f:
            pickle.dump({"model": self._model, "scaler": self._scaler}, f)

    # ── Feature extraction ────────────────────────────────────────────────────

    @staticmethod
    def _extract_features(text: str) -> dict:
        t = str(text)
        lower = t.lower()
        length = len(t)
        words = t.split()
        unique_chars = len(set(t))

        def _entropy(s: str) -> float:
            if not s:
                return 0.0
            freq = {}
            for c in s:
                freq[c] = freq.get(c, 0) + 1
            n = len(s)
            return -sum((f / n) * __import__("math").log2(f / n) for f in freq.values())

        base64_ratio = len(re.findall(r"[A-Za-z0-9+/=]{20,}", t)) / max(len(words), 1)
        hex_ratio = len(re.findall(r"[0-9a-fA-F]{8,}", t)) / max(len(words), 1)
        ip_count = len(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", t))
        url_count = len(re.findall(r"https?://\S+", lower))
        special_ratio = sum(1 for c in t if not c.isalnum() and c not in " \t\n") / max(length, 1)
        upper_ratio = sum(1 for c in t if c.isupper()) / max(length, 1)
        digit_ratio = sum(1 for c in t if c.isdigit()) / max(length, 1)
        avg_word_len = sum(len(w) for w in words) / max(len(words), 1)
        line_count = t.count("\n") + 1

        # Suspicious keyword flags
        danger_words = ["mimikatz", "meterpreter", "shellcode", "payload", "exploit",
                        "reverse_tcp", "beacon", "lsass", "procdump", "vssadmin",
                        "invoke-expression", "iex", "downloadstring", "certutil",
                        "base64", "bypass", "amsi", "powershell", "wscript", "cscript"]
        keyword_hits = sum(1 for w in danger_words if w in lower)

        vector = [
            min(length / 1000.0, 10.0),   # 0  text length (normalised)
            _entropy(t),                    # 1  overall entropy
            base64_ratio,                   # 2  base64 density
            hex_ratio,                      # 3  hex string density
            float(ip_count),                # 4  IP address count
            float(url_count),               # 5  URL count
            special_ratio,                  # 6  special char ratio
            upper_ratio,                    # 7  uppercase ratio
            digit_ratio,                    # 8  digit ratio
            avg_word_len,                   # 9  average word length
            float(line_count),              # 10 line count
            float(unique_chars),            # 11 character vocabulary size
            float(len(words)),              # 12 word count
            float(keyword_hits),            # 13 dangerous keyword count
            float(len(re.findall(r"-[A-Za-z]+", t))),  # 14 flag-like tokens
            float(len(re.findall(r"\b(cmd|exe|bat|ps1|vbs|js)\b", lower))),  # 15 exec extensions
            float(len(re.findall(r"\\\\|/etc/|/proc/", t))),  # 16 path tokens
            float(t.count(";")),            # 17 semicolons (command chains)
            float(t.count("|")),            # 18 pipes
            float(t.count("&")),            # 19 ampersands
        ]
        return {"vector": vector, "keyword_hits": keyword_hits, "entropy": _entropy(t)}

    @staticmethod
    def _heuristic_score(features: dict) -> int:
        kw = features.get("keyword_hits", 0)
        ent = features.get("entropy", 0.0)
        vec = features.get("vector", [0] * 20)
        score = 0
        score += min(kw * 12, 50)
        if ent > 4.5:
            score += 20
        if vec[2] > 0.3:  # base64 heavy
            score += 15
        if vec[3] > 0.3:  # hex heavy
            score += 10
        return min(score, 100)

    @staticmethod
    def _result(score: int, confidence: float, method: str, features: dict) -> dict:
        return {
            "threat_score": score,
            "confidence": round(confidence, 4),
            "detection_method": f"isolation_forest:{method}",
            "details": {
                "entropy": round(features.get("entropy", 0.0), 4),
                "keyword_hits": features.get("keyword_hits", 0),
            },
        }
