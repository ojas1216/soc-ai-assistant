"""
Unified analysis pipeline — called by both the CLI (soc_assist.py) and Flask API.
Accepts optional log path, PCAP path, and/or a single IOC seed.
Returns a dict with keys: pdf (bytes), json (dict).
"""
import json
import os
from datetime import datetime
from pathlib import Path

from backend.llm_engine import query_llm, generate_remediation_steps
from backend.threat_intel import enrich_with_threat_intel, extract_iocs
from backend.risk_scorer import calculate_risk_score
from backend.report_generator import generate_incident_report


def _read_file(path: str) -> str:
    if not path or not Path(path).exists():
        return ""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return f"[Error reading {path}: {e}]"


def _load_log(log_path: str) -> str:
    """Read log — handles JSON list, JSON dict, or plain text."""
    raw = _read_file(log_path)
    if not raw:
        return ""
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return "\n".join(json.dumps(entry) for entry in data)
        return json.dumps(data, indent=2)
    except json.JSONDecodeError:
        return raw


def _apply_watermark(pdf_bytes: bytes, customer_id: str) -> bytes:
    """Stamp a simple watermark text into PDF metadata area (lightweight approach)."""
    # Inject a UTF-8 comment into the PDF stream — visible to PDF readers in metadata
    # For a proper page watermark, use reportlab directly in generate_incident_report.
    # This is a lightweight marker that survives without extra dependencies.
    marker = f"\n%% SOC AI Assistant Pro | Customer: {customer_id} | {datetime.utcnow().date()}\n".encode()
    return pdf_bytes + marker


def _log_usage(customer_id: str, output_folder: str):
    log_path = os.path.join(output_folder, "usage_log.jsonl")
    entry = {"ts": datetime.utcnow().isoformat() + "Z", "customer_id": customer_id}
    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def run_pipeline(log_path: str = None, pcap_path: str = None,
                 ioc: str = None, config: dict = None) -> dict:
    """
    Main analysis pipeline.
    Returns: {"pdf": bytes, "json": dict}
    """
    cfg = config or {}
    out_cfg = cfg.get("output", {})
    offline = cfg.get("offline_mode", True)
    llm_cfg = cfg.get("llm", {})

    os.makedirs(cfg.get("inputs", {}).get("output_folder", "./outputs/"), exist_ok=True)

    # 1. Ingest
    log_text = _load_log(log_path) if log_path else ""
    pcap_text = _read_file(pcap_path) if pcap_path else ""
    combined_text = "\n".join(filter(None, [log_text, pcap_text]))

    if ioc and not combined_text:
        combined_text = f"IOC under analysis: {ioc}"

    # 2. Kill chain reconstruction (when IOC provided)
    kill_chain_result = None
    if ioc:
        from backend.kill_chain import reconstruct_kill_chain
        ioc_data = extract_iocs(combined_text)
        cve_list = ioc_data.get("cves", [])
        kill_chain_result = reconstruct_kill_chain(
            ioc=ioc,
            log_text=log_text,
            pcap_text=pcap_text,
            cve_list=cve_list,
            config=cfg
        )

    # 3. LLM threat summary
    analysis_prompt = f"""You are a senior SOC analyst. Analyze the following security data and produce a concise incident summary.
Identify: threat type, affected systems, attack vector, severity, and key indicators.

DATA:
{combined_text[:4000]}

Respond in 3-5 sentences. Be direct and technical."""
    llm_summary = query_llm(analysis_prompt, model=llm_cfg.get("model", "mistral"))

    # 4. Threat intel enrichment (skip if offline)
    intel_list = []
    if not offline and combined_text:
        intel_list = enrich_with_threat_intel(combined_text)
    elif combined_text:
        ioc_data = extract_iocs(combined_text)
        for category, items in ioc_data.items():
            for item in items:
                intel_list.append(f"[offline] {category.upper()}: {item}")

    # 5. Risk score + MITRE mapping
    risk_score, mitre_hits = calculate_risk_score(combined_text, intel_list)

    # 6. Remediation
    threat_context = kill_chain_result["kill_chain_analysis"] if kill_chain_result else llm_summary
    remediation = generate_remediation_steps(threat_context, model=llm_cfg.get("model", "mistral"))

    # 7. Build JSON result
    result_json = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "customer_id": out_cfg.get("customer_id", ""),
        "risk_score": risk_score,
        "mitre_techniques": mitre_hits,
        "llm_summary": llm_summary,
        "threat_intel": intel_list,
        "remediation": remediation,
        "kill_chain": kill_chain_result,
        "inputs": {
            "log": log_path,
            "pcap": pcap_path,
            "ioc": ioc
        }
    }

    # 8. Build PDF
    pdf_bytes = generate_incident_report(
        llm_summary=llm_summary,
        intel_list=intel_list,
        remediation=remediation,
        risk_score=risk_score,
        mitre_hits=mitre_hits
    ) or b""

    if out_cfg.get("watermark") and out_cfg.get("customer_id"):
        pdf_bytes = _apply_watermark(pdf_bytes, out_cfg["customer_id"])
        _log_usage(out_cfg["customer_id"], cfg.get("inputs", {}).get("output_folder", "./outputs/"))

    return {"pdf": pdf_bytes, "json": result_json}
