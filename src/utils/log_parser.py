"""
Multi-format log parser.
Supports: JSON, JSON-lines, syslog, Windows Event Log (EVTX via text),
Sysmon, CEF (Common Event Format), CSV, and plain text.
Returns a normalised list of event dicts.
"""
import csv
import io
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

TIMESTAMP_PATTERNS = [
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
    r"(\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})",
    r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})",
    r"(\d{10,13})",  # Unix timestamp
]


class LogParser:
    """Parse diverse log formats into a normalised event list."""

    def parse(self, content: str, filename: str = "") -> list[dict]:
        """Auto-detect format and return normalised events."""
        content = content.strip()
        if not content:
            return []

        ext = Path(filename).suffix.lower()

        # Try JSON array / NDJSON
        if ext == ".json" or content.startswith("[") or content.startswith("{"):
            events = self._parse_json(content)
            if events:
                return events

        # CSV
        if ext == ".csv" or self._looks_like_csv(content):
            events = self._parse_csv(content)
            if events:
                return events

        # CEF
        if "CEF:" in content[:100]:
            return self._parse_cef(content)

        # Sysmon (XML-ish JSON export)
        if '"EventID"' in content or "EventID" in content[:200]:
            events = self._parse_json(content)
            if events:
                return events

        # Syslog / plain text
        return self._parse_syslog(content)

    def parse_file(self, path: str | Path) -> list[dict]:
        """Read a file and parse its contents."""
        p = Path(path)
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            return self.parse(content, p.name)
        except Exception as exc:
            logger.error("[LogParser] Failed to read %s: %s", path, exc)
            return []

    def to_text(self, events: list[dict]) -> str:
        """Flatten event list back to a single text block for ML processing."""
        lines = []
        for e in events:
            parts = []
            if ts := e.get("timestamp"):
                parts.append(str(ts))
            if src := e.get("source_ip"):
                parts.append(f"src={src}")
            if dst := e.get("dest_ip"):
                parts.append(f"dst={dst}")
            if evt := e.get("event_type"):
                parts.append(evt)
            if msg := e.get("message"):
                parts.append(msg)
            if proc := e.get("process"):
                parts.append(f"proc={proc}")
            if cmd := e.get("command_line"):
                parts.append(f"cmd={cmd}")
            lines.append(" | ".join(filter(None, parts)))
        return "\n".join(lines)

    # ── Format parsers ────────────────────────────────────────────────────────

    def _parse_json(self, content: str) -> list[dict]:
        events = []
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    events.append(self._normalise_json_event(item))
            elif isinstance(data, dict):
                events.append(self._normalise_json_event(data))
            return events
        except json.JSONDecodeError:
            pass

        # Try NDJSON (one JSON object per line)
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(self._normalise_json_event(obj))
            except json.JSONDecodeError:
                pass
        return events

    def _parse_syslog(self, content: str) -> list[dict]:
        events = []
        for line in content.splitlines():
            if not line.strip():
                continue
            ts = self._extract_timestamp(line)
            hostname = self._extract_hostname(line)
            message = line

            # Extract IPs from the line
            ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)

            events.append({
                "timestamp":  ts,
                "hostname":   hostname,
                "source_ip":  ips[0] if ips else "",
                "dest_ip":    ips[1] if len(ips) > 1 else "",
                "message":    message,
                "event_type": self._classify_syslog_line(line),
                "raw":        line,
            })
        return events

    def _parse_csv(self, content: str) -> list[dict]:
        events = []
        try:
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                events.append(self._normalise_csv_row(dict(row)))
        except Exception as exc:
            logger.debug("[LogParser] CSV parse error: %s", exc)
        return events

    def _parse_cef(self, content: str) -> list[dict]:
        """Parse ArcSight Common Event Format."""
        events = []
        cef_pattern = re.compile(
            r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)"
        )
        for line in content.splitlines():
            m = cef_pattern.match(line)
            if not m:
                continue
            ext_str = m.group(8)
            ext = {}
            for kv in re.finditer(r"(\w+)=([^ ]+(?:\s+[^ ]+)*?)(?=\s+\w+=|$)", ext_str):
                ext[kv.group(1)] = kv.group(2)
            events.append({
                "timestamp":    self._extract_timestamp(line),
                "vendor":       m.group(2).strip(),
                "product":      m.group(3).strip(),
                "severity":     m.group(7).strip(),
                "event_type":   m.group(5).strip(),
                "message":      m.group(6).strip(),
                "source_ip":    ext.get("src", ""),
                "dest_ip":      ext.get("dst", ""),
                "extensions":   ext,
                "raw":          line,
            })
        return events

    # ── Normalisation helpers ─────────────────────────────────────────────────

    @staticmethod
    def _normalise_json_event(obj: dict) -> dict:
        ts_keys = ["timestamp", "Timestamp", "@timestamp", "TimeCreated", "time", "Time"]
        src_keys = ["source_ip", "src_ip", "sourceIp", "src", "SourceAddress"]
        dst_keys = ["destination_ip", "dest_ip", "dst_ip", "dst", "DestinationAddress"]
        msg_keys = ["message", "Message", "msg", "description", "alert", "event"]
        proc_keys = ["process", "Process", "processName", "ImageFileName"]
        cmd_keys = ["command_line", "CommandLine", "cmdline", "cmd"]

        def first(d, keys):
            for k in keys:
                if k in d:
                    return str(d[k])
            return ""

        return {
            "timestamp":    first(obj, ts_keys),
            "source_ip":    first(obj, src_keys),
            "dest_ip":      first(obj, dst_keys),
            "message":      first(obj, msg_keys) or json.dumps(obj)[:200],
            "process":      first(obj, proc_keys),
            "command_line": first(obj, cmd_keys),
            "event_type":   str(obj.get("event_type", obj.get("EventID", obj.get("type", "")))),
            "severity":     str(obj.get("severity", obj.get("Severity", ""))),
            "raw":          json.dumps(obj)[:500],
        }

    @staticmethod
    def _normalise_csv_row(row: dict) -> dict:
        lower = {k.lower().strip(): v for k, v in row.items()}
        return {
            "timestamp":    lower.get("timestamp", lower.get("time", lower.get("date", ""))),
            "source_ip":    lower.get("source_ip", lower.get("src_ip", lower.get("src", ""))),
            "dest_ip":      lower.get("dest_ip", lower.get("dst_ip", lower.get("dst", ""))),
            "message":      lower.get("message", lower.get("msg", lower.get("description", ""))),
            "event_type":   lower.get("event_type", lower.get("type", lower.get("event", ""))),
            "severity":     lower.get("severity", lower.get("level", "")),
            "raw":          str(row)[:500],
        }

    @staticmethod
    def _extract_timestamp(line: str) -> str:
        for pattern in TIMESTAMP_PATTERNS:
            m = re.search(pattern, line)
            if m:
                return m.group(1)
        return ""

    @staticmethod
    def _extract_hostname(line: str) -> str:
        parts = line.split()
        if len(parts) >= 4:
            return parts[3]
        return ""

    @staticmethod
    def _classify_syslog_line(line: str) -> str:
        lower = line.lower()
        if any(kw in lower for kw in ["accepted password", "logged in", "authentication success"]):
            return "login_success"
        if any(kw in lower for kw in ["failed password", "authentication fail", "invalid user"]):
            return "login_failure"
        if any(kw in lower for kw in ["process", "execve", "/bin/", "/usr/bin/"]):
            return "process_create"
        if any(kw in lower for kw in ["connection", "connect", "tcp", "udp"]):
            return "network_connect"
        if any(kw in lower for kw in ["file", "open", "write", "create"]):
            return "file_event"
        return "syslog"

    @staticmethod
    def _looks_like_csv(content: str) -> bool:
        lines = content.splitlines()[:5]
        for line in lines:
            if line.count(",") >= 3:
                return True
        return False
