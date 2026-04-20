"""
Kill chain reconstruction: one IOC seed → full correlated attack timeline.

Given a single IP / domain / file hash / CVE ID, this module:
  1. Scans all log lines and PCAP lines mentioning that IOC
  2. Pivots to related IOCs discovered in those lines
  3. Sorts correlated events chronologically
  4. Maps to MITRE ATT&CK stages
  5. Asks the local LLM to narrate the kill chain + recommend containment
"""
import re
from datetime import datetime
from backend.llm_engine import query_llm
from backend.threat_intel import extract_iocs
from backend.risk_scorer import calculate_risk_score

MITRE_STAGES = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

_TS_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",   # ISO 8601
    r"\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2}",   # syslog: Jan  5 14:23:01
    r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}",     # 01/05/2024 14:23:01
]


def _extract_timestamp(line: str) -> str:
    for pattern in _TS_PATTERNS:
        m = re.search(pattern, line)
        if m:
            return m.group()
    return ""


def _scan_source(lines: list[str], targets: set[str], source_label: str) -> list[dict]:
    """Return all lines that mention any target IOC."""
    hits = []
    for i, line in enumerate(lines):
        low = line.lower()
        if any(t.lower() in low for t in targets):
            hits.append({
                "source": source_label,
                "line_num": i + 1,
                "content": line.strip(),
                "timestamp": _extract_timestamp(line),
            })
    return hits


def reconstruct_kill_chain(
    ioc: str,
    log_text: str = "",
    pcap_text: str = "",
    cve_list: list = None,
    config: dict = None,
) -> dict:
    """
    Reconstruct a full attack kill chain from a single IOC seed.

    Parameters
    ----------
    ioc       : The seed indicator — IP, domain, file hash, or CVE ID.
    log_text  : Raw content of the log file (already read to string).
    pcap_text : Raw content of the PCAP summary (already read to string).
    cve_list  : Any CVE IDs already known from prior extraction (optional).
    config    : Pipeline config dict (used to pick LLM model).

    Returns
    -------
    dict with keys: seed_ioc, related_iocs, timeline_events, timeline,
                    risk_score, mitre_techniques, kill_chain_analysis,
                    cves_correlated, generated_at
    """
    cfg = config or {}
    llm_model = cfg.get("llm", {}).get("model", "mistral")

    log_lines  = log_text.splitlines()  if log_text  else []
    pcap_lines = pcap_text.splitlines() if pcap_text else []

    # --- Phase 1: Direct IOC scan ---
    pivot_set: set[str] = {ioc}
    timeline: list[dict] = []

    log_hits  = _scan_source(log_lines,  pivot_set, "log")
    pcap_hits = _scan_source(pcap_lines, pivot_set, "pcap")

    # --- Phase 2: Pivot — find new IOCs mentioned in matched lines ---
    for hit in log_hits + pcap_hits:
        new_iocs = extract_iocs(hit["content"])
        for category in ("ips", "hashes", "cves"):
            pivot_set.update(new_iocs.get(category, []))

    # Re-scan both sources with expanded IOC set
    timeline  = _scan_source(log_lines,  pivot_set, "log")
    timeline += _scan_source(pcap_lines, pivot_set, "pcap")

    # Deduplicate by (source, line_num)
    seen = set()
    deduped = []
    for event in timeline:
        key = (event["source"], event["line_num"])
        if key not in seen:
            seen.add(key)
            deduped.append(event)
    timeline = deduped

    # Sort chronologically (events without timestamps go last)
    timeline.sort(key=lambda e: (e["timestamp"] == "", e["timestamp"]))

    # --- Phase 3: Score + MITRE mapping ---
    combined_evidence = "\n".join(e["content"] for e in timeline)
    risk_score, mitre_hits = calculate_risk_score(combined_evidence)

    # --- Phase 4: LLM kill chain narrative ---
    evidence_block = combined_evidence[:4000] or f"No correlated events found. IOC: {ioc}"
    related_display = ", ".join(sorted(pivot_set - {ioc})) or "none discovered"
    mitre_display   = ", ".join(f"{tid}" for tid, _ in mitre_hits) or "none identified"
    cve_display     = ", ".join(cve_list or []) or "none"

    prompt = f"""You are a senior SOC analyst performing kill chain reconstruction.

SEED IOC: {ioc}
PIVOTED IOCs: {related_display}
MITRE TECHNIQUES DETECTED: {mitre_display}
CVEs: {cve_display}
CORRELATED EVENTS: {len(timeline)} events across log + PCAP

EVIDENCE (chronological):
{evidence_block}

Produce a structured kill chain report:

1. INITIAL VECTOR
   How did the threat actor first appear? What technique?

2. ATTACK TIMELINE (bullet points, chronological)
   3–6 bullets narrating what happened step-by-step.

3. MITRE ATT&CK STAGE MAPPING
   For each of these stages, state Observed / Not Observed / Inferred:
   {" | ".join(MITRE_STAGES)}

4. IOC PIVOT GRAPH
   Format: <IOC_A> --> led to --> <IOC_B> (explain relationship)
   List all pivot relationships found.

5. CONTAINMENT ACTIONS (exactly 3, numbered)
   Specific, actionable steps a SOC analyst can execute right now.

6. CONFIDENCE LEVEL: Low / Medium / High
   Justify based on evidence quality and quantity.

Be concise and technical. Use SOC analyst language."""

    llm_analysis = query_llm(prompt, model=llm_model)

    return {
        "seed_ioc": ioc,
        "related_iocs": sorted(pivot_set),
        "pivot_count": len(pivot_set) - 1,
        "timeline_events": len(timeline),
        "timeline": timeline,
        "risk_score": risk_score,
        "mitre_techniques": mitre_hits,
        "kill_chain_analysis": llm_analysis,
        "cves_correlated": cve_list or [],
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
