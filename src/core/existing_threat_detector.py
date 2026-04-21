"""
Existing threat detector — signature and rule-based coverage.
Complements zero-day ML detection with YARA, Sigma, CVE, MITRE ATT&CK,
IOC matching, and Snort/Suricata-style pattern rules.
"""
import json
import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

RULES_DIR    = Path(__file__).parents[1] / "rules"
CVE_DB_PATH  = RULES_DIR / "cve_db.json"
MITRE_PATH   = RULES_DIR / "mitre_mapping.json"
YARA_DIR     = RULES_DIR / "yara"
SIGMA_PATH   = RULES_DIR / "sigma" / "sigma_rules.yml"


class ExistingThreatDetector:
    """
    Runs YARA matching, Sigma rule evaluation, CVE correlation,
    MITRE ATT&CK technique mapping, and IOC extraction.
    """

    def __init__(self):
        self._yara_rules = None
        self._cve_db: dict = {}
        self._mitre_map: dict = {}
        self._sigma_rules: list = []
        self._snort_patterns: list = []
        self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def detect(self, text: str) -> dict:
        iocs         = self._extract_iocs(text)
        yara_hits    = self._yara_scan(text)
        sigma_hits   = self._sigma_match(text)
        cves         = self._correlate_cves(text, iocs)
        mitre_hits   = self._map_mitre(text)
        snort_hits   = self._snort_match(text)

        severity = self._aggregate_severity(yara_hits, sigma_hits, cves, mitre_hits)

        return {
            "iocs":         iocs,
            "yara_hits":    yara_hits,
            "sigma_hits":   sigma_hits,
            "cves":         cves,
            "mitre_hits":   mitre_hits,
            "snort_hits":   snort_hits,
            "severity":     severity,
            "hit_count":    len(yara_hits) + len(sigma_hits) + len(cves) + len(mitre_hits),
        }

    # ── IOC extraction ────────────────────────────────────────────────────────

    @staticmethod
    def _extract_iocs(text: str) -> dict:
        ips = list(set(re.findall(
            r"\b(?!10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.|127\.)"
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            text
        )))
        domains = list(set(re.findall(
            r"\b(?:[a-z0-9\-]{2,63}\.)+(?:com|net|org|io|cc|xyz|ru|cn|to|onion)\b",
            text.lower()
        )))
        md5s  = list(set(re.findall(r"\b[0-9a-fA-F]{32}\b", text)))
        sha1s = list(set(re.findall(r"\b[0-9a-fA-F]{40}\b", text)))
        sha256= list(set(re.findall(r"\b[0-9a-fA-F]{64}\b", text)))
        cves  = list(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)))
        emails= list(set(re.findall(r"\b[\w.+-]+@[\w-]+\.\w{2,6}\b", text)))

        return {
            "ips":     ips[:20],
            "domains": domains[:20],
            "hashes":  (md5s + sha1s + sha256)[:15],
            "cves":    cves[:15],
            "emails":  emails[:10],
        }

    # ── YARA scanning ─────────────────────────────────────────────────────────

    def _yara_scan(self, text: str) -> list[dict]:
        hits = []
        if self._yara_rules:
            try:
                matches = self._yara_rules.match(data=text.encode("utf-8", errors="replace"))
                for m in matches:
                    hits.append({
                        "rule": m.rule,
                        "tags": list(m.tags),
                        "strings": [(hex(s.offset), s.identifier) for s in m.strings[:5]],
                    })
            except Exception as exc:
                logger.warning("[YARA] Match error: %s", exc)
        else:
            # Inline pattern fallback when yara-python not installed
            hits = self._yara_inline_fallback(text)
        return hits

    def _yara_inline_fallback(self, text: str) -> list[dict]:
        """Python-native YARA-equivalent for when yara-python is unavailable."""
        INLINE_RULES = [
            ("Mimikatz",         ["mimikatz", "sekurlsa", "logonpasswords", "wce.exe"]),
            ("PowerShell_Obf",   ["invoke-expression", "iex(", "-encodedcommand", "-enc ", "frombase64string"]),
            ("Reverse_Shell",    ["reverse_tcp", "reverse_https", "bash -i >& /dev/tcp", "nc -e /bin/bash"]),
            ("Ransomware",       ["vssadmin delete shadows", "shadow copy", "recover_files", "your_files_are_encrypted"]),
            ("Lateral_Movement", ["pass-the-hash", "wmiexec", "psexec", "smbexec", "dcom"]),
            ("C2_Beacon",        ["beacon.", "sleep(", "checksum8", "cobalt strike"]),
            ("Credential_Dump",  ["procdump", "comsvcs.dll", "minidump", "lsass.dmp"]),
            ("LOLBins",          ["certutil -decode", "bitsadmin /transfer", "mshta http", "regsvr32 /s /u /i:http"]),
            ("DNS_Tunneling",    ["iodine", "dnscat", "dns2tcp", re.compile(r"[a-z0-9]{40,}\.[a-z]{2,6}")]),
        ]
        lower = text.lower()
        hits = []
        for rule_name, patterns in INLINE_RULES:
            matched = []
            for pat in patterns:
                if isinstance(pat, str):
                    if pat in lower:
                        matched.append(pat)
                else:
                    if pat.search(lower):
                        matched.append(pat.pattern)
            if len(matched) >= 1:
                hits.append({"rule": rule_name, "tags": ["malware"], "strings": matched[:3]})
        return hits

    # ── Sigma rules ───────────────────────────────────────────────────────────

    def _sigma_match(self, text: str) -> list[dict]:
        hits = []
        lower = text.lower()
        for rule in self._sigma_rules:
            try:
                detection = rule.get("detection", {})
                keywords = detection.get("keywords", [])
                condition = detection.get("condition", "keywords")

                if not keywords:
                    continue

                matched_kw = [kw for kw in keywords if kw.lower() in lower]
                if condition == "keywords" and matched_kw:
                    hits.append({
                        "rule_id": rule.get("id", "unknown"),
                        "title":   rule.get("title", "Sigma rule"),
                        "level":   rule.get("level", "medium"),
                        "matched": matched_kw[:5],
                    })
                elif "all of" in condition and len(matched_kw) == len(keywords):
                    hits.append({
                        "rule_id": rule.get("id", "unknown"),
                        "title":   rule.get("title", "Sigma rule"),
                        "level":   rule.get("level", "medium"),
                        "matched": matched_kw[:5],
                    })
            except Exception:
                pass
        return hits

    # ── CVE correlation ───────────────────────────────────────────────────────

    def _correlate_cves(self, text: str, iocs: dict) -> list[dict]:
        found = []
        mentioned_cves = set(iocs.get("cves", []))
        also_in_text = set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE))
        all_cves = mentioned_cves | also_in_text

        for cve_id in all_cves:
            cve_id_upper = cve_id.upper()
            if cve_id_upper in self._cve_db:
                entry = self._cve_db[cve_id_upper]
                found.append({
                    "cve_id":      cve_id_upper,
                    "description": entry.get("description", ""),
                    "cvss_score":  entry.get("cvss", 0.0),
                    "severity":    entry.get("severity", "UNKNOWN"),
                })
            else:
                found.append({
                    "cve_id":      cve_id_upper,
                    "description": "CVE found in input — not in local DB. Check NVD.",
                    "cvss_score":  0.0,
                    "severity":    "UNKNOWN",
                })
        return found

    # ── MITRE ATT&CK ──────────────────────────────────────────────────────────

    def _map_mitre(self, text: str) -> list[dict]:
        lower = text.lower()
        hits = []
        for technique_id, entry in self._mitre_map.items():
            keywords = entry.get("keywords", [])
            matched = [kw for kw in keywords if kw in lower]
            if matched:
                hits.append({
                    "technique_id":   technique_id,
                    "name":           entry.get("name", ""),
                    "tactic":         entry.get("tactic", ""),
                    "matched_on":     matched[:3],
                })
        return hits

    # ── Snort/Suricata patterns ───────────────────────────────────────────────

    def _snort_match(self, text: str) -> list[dict]:
        hits = []
        for pattern in self._snort_patterns:
            name    = pattern["name"]
            regex   = pattern["regex"]
            severity= pattern["severity"]
            if re.search(regex, text, re.IGNORECASE):
                m = re.search(regex, text, re.IGNORECASE)
                hits.append({
                    "rule":    name,
                    "severity": severity,
                    "match":   m.group(0)[:60] if m else "",
                })
        return hits

    # ── Severity aggregation ──────────────────────────────────────────────────

    @staticmethod
    def _aggregate_severity(yara_hits, sigma_hits, cves, mitre_hits) -> str:
        score = 0
        score += len(yara_hits) * 3
        for sh in sigma_hits:
            score += {"critical": 5, "high": 4, "medium": 2, "low": 1}.get(sh.get("level", "low"), 1)
        for cve in cves:
            cvss = cve.get("cvss_score", 0.0)
            if cvss >= 9.0:
                score += 5
            elif cvss >= 7.0:
                score += 3
            elif cvss >= 4.0:
                score += 1
        score += len(mitre_hits) * 2

        if score >= 20:
            return "CRITICAL"
        if score >= 12:
            return "HIGH"
        if score >= 6:
            return "MEDIUM"
        if score >= 2:
            return "LOW"
        return "INFO"

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load(self):
        self._load_yara()
        self._load_cve_db()
        self._load_mitre()
        self._load_sigma()
        self._load_snort_patterns()

    def _load_yara(self):
        try:
            import yara
            yar_files = list(YARA_DIR.glob("*.yar")) + list(YARA_DIR.glob("*.yara"))
            if yar_files:
                sources = {f.stem: str(f) for f in yar_files}
                self._yara_rules = yara.compile(filepaths=sources)
                logger.info("[Existing] Compiled %d YARA files", len(yar_files))
        except ImportError:
            logger.info("[Existing] yara-python not installed — using inline fallback")
        except Exception as exc:
            logger.warning("[Existing] YARA compile error: %s", exc)

    def _load_cve_db(self):
        if CVE_DB_PATH.exists():
            try:
                self._cve_db = json.loads(CVE_DB_PATH.read_text())
                logger.info("[Existing] CVE DB loaded (%d entries)", len(self._cve_db))
            except Exception as exc:
                logger.warning("[Existing] CVE DB load failed: %s", exc)

    def _load_mitre(self):
        if MITRE_PATH.exists():
            try:
                self._mitre_map = json.loads(MITRE_PATH.read_text())
                logger.info("[Existing] MITRE map loaded (%d techniques)", len(self._mitre_map))
            except Exception as exc:
                logger.warning("[Existing] MITRE map load failed: %s", exc)

    def _load_sigma(self):
        if SIGMA_PATH.exists():
            try:
                import yaml
                docs = list(yaml.safe_load_all(SIGMA_PATH.read_text()))
                self._sigma_rules = [d for d in docs if isinstance(d, dict)]
                logger.info("[Existing] Sigma rules loaded (%d rules)", len(self._sigma_rules))
            except Exception as exc:
                logger.warning("[Existing] Sigma load failed: %s", exc)

    def _load_snort_patterns(self):
        self._snort_patterns = [
            {"name": "EXPLOIT_SHELLCODE",   "severity": "CRITICAL",
             "regex": r"\\x90{4,}|\\x4d\\x5a|\\x7f\\x45\\x4c\\x46"},
            {"name": "SQL_INJECTION",       "severity": "HIGH",
             "regex": r"(?:union\s+select|'--|\bOR\b\s+['\"0-9]\s*=\s*['\"0-9]|\bDROP\b\s+TABLE)"},
            {"name": "XSS_ATTEMPT",         "severity": "MEDIUM",
             "regex": r"<script[^>]*>|javascript:|onerror\s*=|onload\s*="},
            {"name": "CMD_INJECTION",       "severity": "HIGH",
             "regex": r";\s*(?:cat|ls|id|whoami|uname|wget|curl)\b|&&\s*(?:cmd|powershell|bash)\b"},
            {"name": "PATH_TRAVERSAL",      "severity": "MEDIUM",
             "regex": r"(?:\.\./){3,}|\.\.%2f|%2e%2e%2f"},
            {"name": "SCANNING_NMAP",       "severity": "LOW",
             "regex": r"nmap|masscan|zmap|-sV|-sS|-O\s"},
            {"name": "C2_HTTP_BEACON",      "severity": "HIGH",
             "regex": r"(?:GET|POST)\s+/[a-z0-9]{4,10}\s+HTTP.*(?:Mozilla/[45]|curl|python)"},
            {"name": "MIME_TYPE_MISMATCH",  "severity": "MEDIUM",
             "regex": r"Content-Type:\s*(?:text/html|application/json).*\.(?:exe|dll|ps1|vbs|js)"},
        ]
