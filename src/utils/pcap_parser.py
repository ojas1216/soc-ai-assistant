"""
PCAP parser — extracts network conversations, DNS queries, HTTP transactions,
timing metadata, and generates a structured summary for the ML pipeline.
Uses scapy when available; falls back to heuristic text parsing otherwise.
"""
import logging
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class PCAPParser:
    """Parse binary PCAP or pre-extracted PCAP summary text."""

    def __init__(self):
        self._scapy_available = False
        try:
            import scapy.all  # noqa
            self._scapy_available = True
            logger.info("[PCAP] Scapy available — binary PCAP parsing enabled")
        except ImportError:
            logger.info("[PCAP] Scapy not installed — text-based PCAP parsing only")

    # ── Public API ────────────────────────────────────────────────────────────

    def parse(self, source: str | Path | bytes) -> dict:
        """
        Parse a PCAP file (binary) or PCAP summary text.
        Returns a structured dict and a flat text summary for ML input.
        """
        if isinstance(source, bytes):
            return self._parse_binary(source)
        p = Path(source) if not isinstance(source, str) else Path(source)
        if p.exists():
            if p.suffix.lower() in (".pcap", ".cap", ".pcapng"):
                return self._parse_binary_file(p)
            content = p.read_text(encoding="utf-8", errors="replace")
        else:
            content = str(source)
        return self._parse_text(content)

    def to_text(self, parsed: dict) -> str:
        """Convert parsed PCAP dict to a flat text summary for ML ingestion."""
        lines = []

        for conv in parsed.get("conversations", [])[:30]:
            lines.append(
                f"CONV {conv['src']}:{conv.get('sport','')} -> "
                f"{conv['dst']}:{conv.get('dport','')} "
                f"proto={conv.get('protocol','')} pkts={conv.get('packets','')} "
                f"flags={conv.get('flags','')}"
            )

        for dns in parsed.get("dns_queries", [])[:20]:
            lines.append(f"DNS {dns['query']} -> {dns.get('response','')} ttl={dns.get('ttl','')}")

        for http in parsed.get("http_requests", [])[:20]:
            lines.append(f"HTTP {http.get('method','')} {http.get('url','')} {http.get('status','')} {http.get('size','')}b")

        for flag in parsed.get("flags", []):
            lines.append(f"FLAG [{flag['severity']}] {flag['description']}")

        timing = parsed.get("timing", {})
        if timing:
            lines.append(f"TIMING mean_interval={timing.get('mean_interval',0):.2f}s jitter_cv={timing.get('jitter_cv',0):.4f}")

        return "\n".join(lines)

    # ── Binary PCAP parsing (scapy) ───────────────────────────────────────────

    def _parse_binary_file(self, path: Path) -> dict:
        if not self._scapy_available:
            logger.warning("[PCAP] Scapy not available — reading as text")
            return self._parse_text(path.read_text(encoding="utf-8", errors="replace"))
        return self._parse_binary(path.read_bytes())

    def _parse_binary(self, data: bytes) -> dict:
        if not self._scapy_available:
            return self._parse_text(data.decode("utf-8", errors="replace"))

        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, HTTPRequest
            from io import BytesIO
            packets = rdpcap(BytesIO(data))
        except Exception as exc:
            logger.error("[PCAP] Scapy parse error: %s", exc)
            return {"error": str(exc), "text_summary": "", "conversations": [], "flags": []}

        conversations = defaultdict(lambda: {"packets": 0, "bytes": 0, "timestamps": []})
        dns_queries = []
        http_requests = []
        timestamps = []

        for pkt in packets:
            if pkt.time:
                timestamps.append(float(pkt.time))

            if IP not in pkt:
                continue

            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
            sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
            dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)

            key = (src, dst, proto, dport)
            conversations[key]["packets"] += 1
            conversations[key]["bytes"] += len(pkt)
            conversations[key]["src"] = src
            conversations[key]["dst"] = dst
            conversations[key]["protocol"] = proto
            conversations[key]["sport"] = sport
            conversations[key]["dport"] = dport
            if pkt.time:
                conversations[key]["timestamps"].append(float(pkt.time))

            if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                dns_queries.append({
                    "query": pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip("."),
                    "response": "",
                    "ttl": 0,
                })

            if TCP in pkt and Raw in pkt:
                raw = pkt[Raw].load
                if raw.startswith(b"GET ") or raw.startswith(b"POST ") or raw.startswith(b"HEAD "):
                    lines = raw.decode("utf-8", errors="replace").splitlines()
                    if lines:
                        method, *rest = lines[0].split()
                        url = rest[0] if rest else ""
                        host = next((l.split(":",1)[1].strip() for l in lines if l.startswith("Host:")), dst)
                        http_requests.append({
                            "method": method,
                            "url": f"http://{host}{url}",
                            "status": "",
                            "size": len(raw),
                        })

        conv_list = [v for v in conversations.values()]
        timing = self._analyse_timing(timestamps)
        flags = self._generate_flags(conv_list, dns_queries, http_requests, timing)

        result = {
            "packet_count":  len(packets),
            "conversations": conv_list[:50],
            "dns_queries":   dns_queries[:30],
            "http_requests": http_requests[:20],
            "timing":        timing,
            "flags":         flags,
        }
        result["text_summary"] = self.to_text(result)
        return result

    # ── Text-based PCAP summary parsing ──────────────────────────────────────

    def _parse_text(self, content: str) -> dict:
        """Parse a human-readable PCAP summary (e.g. from Zeek / tshark -z)."""
        conversations = []
        dns_queries = []
        http_requests = []
        timestamps = []

        for line in content.splitlines():
            lower = line.lower()

            # Parse conversation lines
            conv_m = re.search(
                r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?\s*[<>\-]+\s*(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?",
                line
            )
            if conv_m:
                conversations.append({
                    "src":      conv_m.group(1),
                    "sport":    conv_m.group(2) or "",
                    "dst":      conv_m.group(3),
                    "dport":    conv_m.group(4) or "",
                    "protocol": "TCP" if "tcp" in lower else "UDP" if "udp" in lower else "IP",
                    "flags":    re.search(r"\[([A-Z ,]+)\]", line).group(1) if re.search(r"\[([A-Z ,]+)\]", line) else "",
                    "packets":  re.search(r"(\d+)\s*pkts?", line).group(1) if re.search(r"(\d+)\s*pkts?", line) else "",
                })

            # DNS queries
            dns_m = re.search(r"DNS\s+(\S+)\s*[->\s]+\s*(\S+)?", line, re.IGNORECASE)
            if dns_m:
                dns_queries.append({
                    "query":    dns_m.group(1),
                    "response": dns_m.group(2) or "",
                    "ttl":      re.search(r"TTL[:\s]+(\d+)", line).group(1) if re.search(r"TTL[:\s]+(\d+)", line) else "",
                })

            # HTTP requests
            http_m = re.search(r"(GET|POST|PUT|DELETE|HEAD)\s+(\S+)", line)
            if http_m:
                http_requests.append({
                    "method": http_m.group(1),
                    "url":    http_m.group(2),
                    "status": re.search(r"\b([245]\d{2})\b", line).group(1) if re.search(r"\b([245]\d{2})\b", line) else "",
                    "size":   re.search(r"(\d+)\s*bytes?", line).group(1) if re.search(r"(\d+)\s*bytes?", line) else "",
                })

            # Timestamps
            ts_m = re.search(r"\b(\d{2}:\d{2}:\d{2}\.?\d*)\b", line)
            if ts_m:
                parts = ts_m.group(1).replace(".", ":").split(":")
                try:
                    secs = int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
                    timestamps.append(secs)
                except (ValueError, IndexError):
                    pass

        timing = self._analyse_timing(timestamps)
        flags  = self._generate_flags(conversations, dns_queries, http_requests, timing)

        result = {
            "conversations": conversations[:50],
            "dns_queries":   dns_queries[:30],
            "http_requests": http_requests[:20],
            "timing":        timing,
            "flags":         flags,
        }
        result["text_summary"] = self.to_text(result)
        return result

    # ── Analysis helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _analyse_timing(timestamps: list) -> dict:
        if len(timestamps) < 3:
            return {}
        timestamps = sorted(timestamps)
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        intervals = [x for x in intervals if 0 < x < 3600]
        if not intervals:
            return {}
        mean = statistics.mean(intervals)
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv = stdev / max(mean, 1e-6)
        return {
            "mean_interval": round(mean, 3),
            "stdev":         round(stdev, 3),
            "jitter_cv":     round(cv, 4),
            "sample_count":  len(intervals),
            "beaconing_suspected": cv < 0.15 and mean < 300,
        }

    @staticmethod
    def _generate_flags(convs, dns, http, timing) -> list[dict]:
        flags = []
        # Beaconing
        if timing.get("beaconing_suspected"):
            flags.append({"severity": "HIGH",
                          "description": f"C2 beaconing suspected: interval={timing['mean_interval']}s jitter={timing['jitter_cv']:.3f}"})

        # Large outbound transfer
        for c in convs:
            b = int(str(c.get("bytes", 0) or 0))
            if b > 10 * 1024 * 1024:
                flags.append({"severity": "MEDIUM",
                               "description": f"Large transfer: {c.get('src')} -> {c.get('dst')} ({b // 1024} KB)"})

        # Long DNS names (tunneling)
        for d in dns:
            if len(str(d.get("query", ""))) > 60:
                flags.append({"severity": "HIGH",
                               "description": f"DNS tunneling indicator: {d['query'][:80]}"})

        # Non-standard HTTP ports
        for c in convs:
            dport = str(c.get("dport", ""))
            if c.get("protocol") in ("TCP",) and dport in ("4444", "5555", "8080", "9001", "1337"):
                flags.append({"severity": "HIGH",
                               "description": f"Suspicious port {dport}: {c.get('src')} -> {c.get('dst')}"})
        return flags
