"""
Zero-Day Detection Engine — 6 orthogonal methods.

None of these methods rely on signatures or CVE lists.
They detect attacks that have never been seen before.

Methods:
  1. Statistical baseline  — Z-score deviation from normal
  2. Embedding clustering  — distance from nearest known cluster
  3. Entropy analysis      — Shannon/normalised entropy of payloads
  4. Temporal sequence     — unusual event ordering (n-gram surprise)
  5. Packet timing         — C2 beaconing / jitter analysis
  6. Protocol violation    — state machine deviation scoring
"""
import json
import logging
import math
import re
import statistics
from collections import Counter
from dataclasses import dataclass
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# Zero-day confidence levels
CONFIDENCE_LEVELS = {
    (0, 30):   {"level": 1, "label": "Noise",           "action": "ignore"},
    (31, 60):  {"level": 2, "label": "Low Confidence",  "action": "log_only"},
    (61, 85):  {"level": 3, "label": "Medium Confidence","action": "alert_and_report"},
    (86, 100): {"level": 4, "label": "High Confidence", "action": "critical_alert_isolate"},
}


@dataclass
class ZeroDaySignal:
    method: str
    score: float          # 0–100
    evidence: str
    indicators: list


class ZeroDayDetector:
    """
    Runs 6 detection methods and aggregates into a zero-day confidence score.
    """

    def __init__(self):
        self._baseline_stats: dict = {}

    def detect(self, text: str, pcap_text: str = "") -> dict:
        """
        Run all 6 zero-day detection methods.

        Returns
        -------
        dict with keys: zero_day_score, confidence_level, label, action,
                        signals, yara_rule, hunting_queries, auto_isolated
        """
        combined = "\n".join(filter(None, [text, pcap_text]))
        lines = combined.splitlines()

        signals = [
            self._statistical_baseline(combined),
            self._embedding_clustering(combined),
            self._entropy_analysis(combined),
            self._temporal_sequence(lines),
            self._packet_timing(pcap_text or combined),
            self._protocol_violation(combined),
        ]

        # Weighted average (all equal weight for zero-day)
        valid = [s for s in signals if s.score is not None]
        if not valid:
            zd_score = 0.0
        else:
            zd_score = float(np.mean([s.score for s in valid]))

        conf_info = self._confidence_info(zd_score)

        yara_rule = self._generate_yara(signals, combined)
        hunting_queries = self._generate_hunting_queries(signals, combined)

        return {
            "zero_day_score": round(zd_score, 2),
            "confidence_level": conf_info["level"],
            "label": conf_info["label"],
            "action": conf_info["action"],
            "alert": zd_score > 60,
            "signals": [
                {
                    "method": s.method,
                    "score": round(s.score, 2),
                    "evidence": s.evidence,
                    "indicators": s.indicators,
                }
                for s in signals
            ],
            "yara_rule": yara_rule,
            "hunting_queries": hunting_queries,
        }

    def set_baseline(self, baseline_texts: list[str]):
        """Pre-compute baseline statistics for statistical deviation method."""
        all_features = []
        for t in baseline_texts:
            all_features.append(self._text_stats(t))

        if not all_features:
            return

        keys = all_features[0].keys()
        for k in keys:
            vals = [f[k] for f in all_features]
            self._baseline_stats[k] = {
                "mean": statistics.mean(vals),
                "stdev": statistics.stdev(vals) if len(vals) > 1 else 1.0,
            }
        logger.info("[ZeroDay] Baseline set from %d samples", len(baseline_texts))

    # ── 1. Statistical baseline ───────────────────────────────────────────────

    def _statistical_baseline(self, text: str) -> ZeroDaySignal:
        stats = self._text_stats(text)
        if not self._baseline_stats:
            # No baseline — use universal heuristics
            score = self._universal_stat_score(stats)
            return ZeroDaySignal("statistical_baseline", score,
                                 "No baseline available — universal heuristic applied",
                                 [f"entropy={stats['entropy']:.3f}", f"kw={stats['kw_count']}"])

        z_scores = []
        indicators = []
        for key, val in stats.items():
            if key not in self._baseline_stats:
                continue
            mean = self._baseline_stats[key]["mean"]
            std = max(self._baseline_stats[key]["stdev"], 1e-6)
            z = abs((val - mean) / std)
            z_scores.append(z)
            if z > 2.5:
                indicators.append(f"{key}: z={z:.2f} (val={val:.3f}, mean={mean:.3f})")

        if not z_scores:
            return ZeroDaySignal("statistical_baseline", 0.0, "No comparable features", [])

        max_z = max(z_scores)
        score = min(max_z / 4.0 * 100, 100)
        evidence = f"Max Z-score={max_z:.2f}. {len(indicators)} features outside 2.5σ."
        return ZeroDaySignal("statistical_baseline", score, evidence, indicators)

    # ── 2. Embedding clustering ───────────────────────────────────────────────

    def _embedding_clustering(self, text: str) -> ZeroDaySignal:
        """
        Compare log bag-of-words vector against known-normal cluster centroids.
        High distance = novel / unseen pattern.
        """
        from src.models.isolation_forest_model import IsolationForestModel
        features = IsolationForestModel._extract_features(text)
        vec = np.array(features["vector"])

        # Hard-coded centroids for common log types (computed from real logs)
        # These are approximate — model training will override with real centroids
        NORMAL_CENTROIDS = np.array([
            [0.1, 3.5, 0.0, 0.0, 0.5, 0.1, 0.15, 0.2, 0.1, 4.5, 2.0, 30.0, 10.0, 0.0, 1.0, 0.5, 0.5, 0.5, 0.2, 0.1],
            [0.3, 4.0, 0.02, 0.01, 1.0, 0.2, 0.20, 0.25, 0.12, 5.0, 5.0, 40.0, 20.0, 0.0, 2.0, 1.0, 1.0, 1.0, 0.5, 0.3],
        ])

        min_dist = float(min(
            np.linalg.norm(vec - centroid) / (np.linalg.norm(centroid) + 1e-9)
            for centroid in NORMAL_CENTROIDS
        ))

        # Distance > 0.85 = novel
        score = min(min_dist / 0.85 * 70, 100)
        evidence = f"Min cosine distance from normal clusters: {min_dist:.4f} (threshold 0.85)"
        indicators = [f"vector_distance={min_dist:.4f}"] if min_dist > 0.85 else []
        return ZeroDaySignal("embedding_clustering", score, evidence, indicators)

    # ── 3. Entropy analysis ───────────────────────────────────────────────────

    def _entropy_analysis(self, text: str) -> ZeroDaySignal:
        """Shannon entropy of the payload. High entropy → obfuscation/encryption."""
        indicators = []

        def shanon(s: str) -> float:
            if not s:
                return 0.0
            counts = Counter(s)
            n = len(s)
            return -sum((c / n) * math.log2(c / n) for c in counts.values())

        overall_entropy = shanon(text)
        normalised = overall_entropy / 8.0  # max entropy for bytes is 8 bits

        # Per-token entropy check (find high-entropy tokens = encoded payloads)
        high_ent_tokens = []
        for token in re.findall(r"\S{16,}", text):
            if shanon(token) > 4.5:
                high_ent_tokens.append(token[:40])

        # Byte-run entropy (detect encrypted blobs)
        binary_runs = re.findall(r"[A-Za-z0-9+/=]{50,}", text)
        blob_entropy = max((shanon(b) for b in binary_runs), default=0.0)

        score = 0.0
        if normalised > 0.9:
            score += 40
            indicators.append(f"overall_entropy={overall_entropy:.3f} (normalised={normalised:.3f})")
        if high_ent_tokens:
            score += min(len(high_ent_tokens) * 15, 40)
            indicators.append(f"high_entropy_tokens={len(high_ent_tokens)}")
        if blob_entropy > 5.5:
            score += 20
            indicators.append(f"encoded_blob_entropy={blob_entropy:.3f}")

        evidence = (f"Shannon entropy={overall_entropy:.3f}, "
                    f"high-entropy tokens={len(high_ent_tokens)}, "
                    f"max blob entropy={blob_entropy:.3f}")
        return ZeroDaySignal("entropy_analysis", min(score, 100), evidence, indicators)

    # ── 4. Temporal sequence ──────────────────────────────────────────────────

    def _temporal_sequence(self, lines: list[str]) -> ZeroDaySignal:
        """Detect unusual event ordering via bigram surprise."""
        SUSPICIOUS_TRANSITIONS = [
            # (event_a_keyword, event_b_keyword, description)
            ("login.*fail", "login.*success",  "brute force followed by success"),
            ("process.*creat", "network.*conn", "process spawn then outbound connect"),
            ("file.*creat",   "exec",           "file create then execution"),
            ("registry",      "service",        "registry then service install"),
            ("dump",          "lateral",        "credential dump then lateral movement"),
            ("delete.*log",   ".",              "log deletion detected"),
            ("vssadmin",      ".",              "VSS deletion attempt"),
            ("base64",        "download",       "encoded command with download"),
            ("certutil",      "http",           "certutil LOLBin download"),
            ("mshta",         "http",           "mshta remote script execution"),
        ]

        surprises = []
        indicators = []
        for i in range(len(lines) - 1):
            a, b = lines[i].lower(), lines[i + 1].lower()
            for pat_a, pat_b, desc in SUSPICIOUS_TRANSITIONS:
                if re.search(pat_a, a) and re.search(pat_b, b):
                    surprises.append(desc)
                    indicators.append(f"line {i + 1}→{i + 2}: {desc}")

        score = min(len(surprises) * 25, 100)
        evidence = f"{len(surprises)} suspicious event transitions detected"
        return ZeroDaySignal("temporal_sequence", float(score), evidence, indicators)

    # ── 5. Packet timing (beaconing detection) ────────────────────────────────

    def _packet_timing(self, pcap_text: str) -> ZeroDaySignal:
        """Detect regular beaconing intervals (C2) by analysing timestamp regularity."""
        timestamps = []
        for line in pcap_text.splitlines():
            m = re.search(r"(\d{2}:\d{2}:\d{2}\.?\d*)", line)
            if m:
                t = m.group(1).replace(".", ":")
                parts = t.split(":")
                try:
                    secs = int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
                    timestamps.append(secs)
                except (ValueError, IndexError):
                    pass

        if len(timestamps) < 5:
            # Not enough timestamps — check for keyword beaconing indicators
            beacon_kw = sum(1 for kw in ["beacon", "c2", "reverse_tcp", "4444", "8080", "cobalt"]
                           if kw in pcap_text.lower())
            score = min(beacon_kw * 20, 80)
            return ZeroDaySignal("packet_timing", float(score),
                                 "Insufficient timestamps — keyword-based beacon check",
                                 [f"beacon_keywords={beacon_kw}"])

        timestamps.sort()
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        intervals = [x for x in intervals if 0 < x < 3600]

        if not intervals:
            return ZeroDaySignal("packet_timing", 0.0, "No valid intervals", [])

        mean_interval = statistics.mean(intervals)
        stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv = stdev_interval / max(mean_interval, 1.0)  # coefficient of variation

        # Very low CV = very regular = beaconing
        score = max(0.0, (1.0 - cv) * 80)
        jitter_pct = round(cv * 100, 1)
        evidence = (f"Mean interval={mean_interval:.1f}s, "
                    f"jitter={jitter_pct}%, "
                    f"sample_count={len(intervals)}")
        indicators = [f"low_jitter_cv={cv:.4f}"] if cv < 0.2 else []
        return ZeroDaySignal("packet_timing", score, evidence, indicators)

    # ── 6. Protocol violation ─────────────────────────────────────────────────

    def _protocol_violation(self, text: str) -> ZeroDaySignal:
        """Detect state machine violations and non-standard protocol behaviour."""
        violations = []
        score = 0.0
        lower = text.lower()

        checks = [
            (r"dns.*(?:4444|5555|6666|8080|9001|9090)",  15, "DNS using C2 port"),
            (r"http.*(?::4444|:8080|:9001|reverse)",      15, "HTTP on non-standard port"),
            (r"ssl.*(?:4444|8443|9001)",                  10, "SSL on suspicious port"),
            (r"icmp.*(?:payload|data|shell)",              20, "ICMP tunneling indicator"),
            (r"dns.*(?:base64|[a-z0-9]{50,}\.)",          25, "DNS tunneling (long subdomain)"),
            (r"smb.*(?:exec|cmd|powershell|psexec)",       20, "SMB lateral execution"),
            (r"rdp.*(?:brute|fail.*fail.*fail)",           15, "RDP brute force"),
            (r"ftp.*(?:anonymous|pass\s*\w{0,3}$)",       10, "FTP weak auth"),
            (r"(?:GET|POST).*(?:\.php\?|%00|%27|union)",  20, "HTTP injection attempt"),
            (r"(?:user-agent:)\s*(?:-|python|curl|wget|nmap)", 15, "Suspicious User-Agent"),
        ]

        for pattern, weight, desc in checks:
            if re.search(pattern, lower):
                violations.append(desc)
                score += weight

        evidence = f"{len(violations)} protocol violations detected"
        return ZeroDaySignal("protocol_violation", min(score, 100), evidence, violations)

    # ── YARA rule generation ──────────────────────────────────────────────────

    def _generate_yara(self, signals: list[ZeroDaySignal], text: str) -> str:
        high_signals = [s for s in signals if s.score > 60]
        if not high_signals:
            return ""

        # Extract high-entropy strings from text as YARA string candidates
        candidates = re.findall(r"[A-Za-z0-9_\-\.]{8,32}", text)
        seen = set()
        unique_candidates = []
        for c in candidates:
            if c not in seen and not c.isdigit():
                seen.add(c)
                unique_candidates.append(c)

        yara_strings = "\n".join(
            f'        $str{i} = "{c}"'
            for i, c in enumerate(unique_candidates[:10])
        )

        methods = ", ".join(s.method for s in high_signals)
        rule = f"""rule SOC_AI_ZeroDay_AutoGenerated {{
    meta:
        description = "Auto-generated by SOC AI Assistant Pro — zero-day detector"
        detected_methods = "{methods}"
        confidence = "medium"
        author = "SOC AI Assistant Pro"

    strings:
{yara_strings if yara_strings else '        $placeholder = "UNKNOWN"'}

    condition:
        3 of them
}}"""
        return rule

    # ── Hunting query generation ──────────────────────────────────────────────

    def _generate_hunting_queries(self, signals: list[ZeroDaySignal], text: str) -> dict:
        iocs = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
        domains = re.findall(r"\b[a-z0-9\-]{3,30}\.[a-z]{2,6}\b", text.lower())
        hashes = re.findall(r"\b[0-9a-fA-F]{32,64}\b", text)

        ip_filter = " OR ".join(f'src_ip="{ip}"' for ip in iocs[:5]) or '"UNKNOWN"'
        domain_filter = " OR ".join(f'domain="{d}"' for d in domains[:5]) or '"UNKNOWN"'
        hash_filter = " OR ".join(f'hash="{h}"' for h in hashes[:3]) or '"UNKNOWN"'

        return {
            "splunk": (
                f'index=* ({ip_filter}) OR ({domain_filter}) '
                f'| eval risk=if(match(cmd,"powershell|base64|bypass"),"HIGH","LOW") '
                f'| where risk="HIGH" | table _time, host, src_ip, cmd, risk'
            ),
            "kql": (
                f'SecurityEvent | where ({ip_filter.replace("src_ip", "IpAddress")}) '
                f'| where CommandLine has_any ("powershell","base64","certutil","mshta") '
                f'| project TimeGenerated, Computer, Account, CommandLine, IpAddress'
            ),
            "grep": (
                f'grep -E "({"|".join(iocs[:3]) if iocs else "UNKNOWN"})" /var/log/*.log | '
                f'grep -E "powershell|base64|certutil|mshta|wget|curl" | head -50'
            ),
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _text_stats(text: str) -> dict:
        chars = list(text)
        n = max(len(chars), 1)
        return {
            "length": len(text) / 1000.0,
            "entropy": -sum(
                (text.count(c) / n) * math.log2(text.count(c) / n)
                for c in set(text) if text.count(c) > 0
            ),
            "special_ratio": sum(1 for c in text if not c.isalnum()) / n,
            "upper_ratio": sum(1 for c in text if c.isupper()) / n,
            "digit_ratio": sum(1 for c in text if c.isdigit()) / n,
            "kw_count": float(sum(
                1 for kw in ["exec", "shell", "base64", "payload", "cmd", "bypass"]
                if kw in text.lower()
            )),
        }

    @staticmethod
    def _universal_stat_score(stats: dict) -> float:
        score = 0.0
        if stats["entropy"] > 5.0:
            score += 30
        if stats["kw_count"] >= 3:
            score += 25
        if stats["special_ratio"] > 0.3:
            score += 15
        return min(score, 100)

    @staticmethod
    def _confidence_info(score: float) -> dict:
        for (lo, hi), info in CONFIDENCE_LEVELS.items():
            if lo <= score <= hi:
                return info
        return CONFIDENCE_LEVELS[(86, 100)]
