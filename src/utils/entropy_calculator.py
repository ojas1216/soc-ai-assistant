"""
Entropy calculation utilities.
Shannon entropy, byte entropy, n-gram entropy, and sliding window analysis.
"""
import math
import re
from collections import Counter
from typing import Generator


class EntropyCalculator:
    """Multi-mode entropy analysis for payload anomaly detection."""

    # ── Shannon entropy ───────────────────────────────────────────────────────

    @staticmethod
    def shannon(data: str | bytes) -> float:
        """Shannon entropy in bits. Range: 0 (constant) – 8 (random bytes)."""
        if not data:
            return 0.0
        counts = Counter(data)
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    @staticmethod
    def normalised_shannon(data: str | bytes) -> float:
        """Shannon entropy normalised to [0, 1]."""
        return EntropyCalculator.shannon(data) / 8.0

    # ── Sliding window entropy ────────────────────────────────────────────────

    @staticmethod
    def sliding_window(text: str, window: int = 64, step: int = 16) -> list[dict]:
        """
        Compute entropy over a sliding window.
        Useful for finding high-entropy regions (encoded payloads, shellcode).
        Returns list of {"offset": int, "entropy": float, "text": str}
        """
        results = []
        for i in range(0, max(len(text) - window, 1), step):
            chunk = text[i: i + window]
            ent = EntropyCalculator.shannon(chunk)
            results.append({"offset": i, "entropy": round(ent, 4), "snippet": chunk[:20]})
        return results

    @staticmethod
    def high_entropy_regions(text: str, threshold: float = 5.0,
                             window: int = 64) -> list[dict]:
        """Return only sliding-window segments above the entropy threshold."""
        return [
            r for r in EntropyCalculator.sliding_window(text, window)
            if r["entropy"] >= threshold
        ]

    # ── Token entropy ─────────────────────────────────────────────────────────

    @staticmethod
    def token_entropy(text: str, min_len: int = 12) -> list[dict]:
        """
        Entropy of individual whitespace-separated tokens longer than min_len.
        Flags base64 blobs, encoded commands, long hashes.
        """
        results = []
        for token in re.findall(r"\S{" + str(min_len) + r",}", text):
            ent = EntropyCalculator.shannon(token)
            results.append({
                "token":   token[:60],
                "length":  len(token),
                "entropy": round(ent, 4),
                "flag":    ent > 4.5,
            })
        return sorted(results, key=lambda x: x["entropy"], reverse=True)

    # ── N-gram entropy ────────────────────────────────────────────────────────

    @staticmethod
    def ngram_entropy(text: str, n: int = 2) -> float:
        """
        N-gram entropy — measures linguistic randomness.
        Natural language has low n-gram entropy; encrypted/encoded text has high.
        """
        if len(text) < n:
            return 0.0
        grams = [text[i: i + n] for i in range(len(text) - n + 1)]
        return EntropyCalculator.shannon(grams)

    # ── Payload classification ────────────────────────────────────────────────

    @staticmethod
    def classify_payload(text: str) -> dict:
        """
        Classify a text payload based on entropy profile.
        Returns label: plaintext | base64 | encrypted | compressed | shellcode
        """
        ent = EntropyCalculator.shannon(text)
        bi_ent = EntropyCalculator.ngram_entropy(text, 2)
        high_regions = EntropyCalculator.high_entropy_regions(text)

        label = "plaintext"
        confidence = 0.9

        if ent > 7.5:
            label, confidence = "encrypted_or_compressed", 0.95
        elif ent > 6.0:
            # Check for base64 pattern
            if re.search(r"^[A-Za-z0-9+/]{40,}={0,2}$", text.strip()):
                label, confidence = "base64", 0.90
            else:
                label, confidence = "high_entropy_unknown", 0.75
        elif ent > 5.0 and len(high_regions) > 2:
            label, confidence = "partially_encoded", 0.70
        elif re.search(r"(\\x[0-9a-f]{2}){8,}", text.lower()):
            label, confidence = "shellcode_hex", 0.85
        elif bi_ent > 5.5:
            label, confidence = "obfuscated", 0.65

        return {
            "label":       label,
            "confidence":  confidence,
            "entropy":     round(ent, 4),
            "bigram_entropy": round(bi_ent, 4),
            "high_entropy_regions": len(high_regions),
        }
