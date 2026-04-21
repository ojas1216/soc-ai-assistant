#!/usr/bin/env python3
"""SOC AI Assistant Pro — CLI entrypoint (v2.0)"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

import yaml


def _banner():
    print("""
  ╔═══════════════════════════════════════════╗
  ║     SOC AI ASSISTANT PRO  v2.0            ║
  ║     5-Model Ensemble · Zero-Day · MITRE   ║
  ╚═══════════════════════════════════════════╝
""")


def load_config(path: str = "config.yaml") -> dict:
    cfg_path = Path(path)
    if not cfg_path.exists():
        return {}
    with open(cfg_path) as f:
        return yaml.safe_load(f) or {}


def main():
    parser = argparse.ArgumentParser(
        prog="soc_assist",
        description="SOC AI Assistant Pro — Offline multi-algorithm threat analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Analyze a log file:
    python soc_assist.py --log sample_inputs/sample_syslog.txt

  Full correlation (log + PCAP):
    python soc_assist.py --log sample_inputs/sample_syslog.txt \\
                         --pcap sample_inputs/sample_pcap_summary.txt --format both

  Kill chain from one IOC:
    python soc_assist.py --ioc 185.220.101.42 --log sample_inputs/sample_syslog.txt

  Launch web UI:
    python soc_assist.py --ui

  Train ML models on baseline logs:
    python soc_assist.py --train --train-data ./baseline_logs/

  Service mode (watermarked PDF + usage log):
    python soc_assist.py --mode service --customer-id CUST-001 \\
                         --log sample_inputs/sample_syslog.txt
        """
    )

    # Input sources
    parser.add_argument("--log",   help="Path to syslog / JSON / CSV / EVTX log file")
    parser.add_argument("--pcap",  help="Path to PCAP or PCAP summary text file")
    parser.add_argument("--ioc",   help="Single IOC: IP, domain, file hash, or CVE-ID")

    # Output control
    parser.add_argument("--output", help="Output base path (default: ./outputs/report)")
    parser.add_argument("--format", choices=["pdf", "json", "both"], default="json",
                        help="Output format (default: json)")

    # Operation modes
    parser.add_argument("--mode", choices=["tool", "service"], default="tool",
                        help="tool = single-user, service = watermarked + usage-logged")
    parser.add_argument("--customer-id", dest="customer_id",
                        help="Customer ID (required in --mode service)")
    parser.add_argument("--ui", action="store_true",
                        help="Launch Flask web UI instead of CLI analysis")
    parser.add_argument("--ui-port", type=int, default=5000,
                        help="Port for the web UI (default: 5000)")
    parser.add_argument("--train", action="store_true",
                        help="Train all 5 ML models before running analysis")
    parser.add_argument("--train-data", dest="train_data", default="./baseline_logs/",
                        help="Folder containing baseline log files for training")

    # Config / license
    parser.add_argument("--config",     default="config.yaml",
                        help="Path to config.yaml")
    parser.add_argument("--no-license", action="store_true",
                        help="Skip license check (demo / dev mode)")
    parser.add_argument("--hardware-id", dest="hardware_id", action="store_true",
                        help="Print this machine's hardware ID and exit")

    args = parser.parse_args()

    _banner()

    # Hardware ID utility
    if args.hardware_id:
        from src.security.license_manager import LicenseManager
        hw = LicenseManager._compute_hardware_id()
        print(f"Hardware ID: {hw}")
        print("Send this ID to purchase@agentmario1216@gmail.com to receive your license key.")
        sys.exit(0)

    # License validation
    if not args.no_license:
        from src.security.license_manager import LicenseManager
        cfg_tmp = load_config(args.config)
        key_path = cfg_tmp.get("license", {}).get("key_file", "./license.txt")
        mgr = LicenseManager(key_path=key_path)
        valid, msg = mgr.validate()
        if not valid:
            print(f"[!] License: {msg}")
            print("    Place your license key in license.txt")
            print("    Use --no-license for demo mode (limited output)")
            print()

    # Web UI mode
    if args.ui:
        cfg = load_config(args.config)
        print(f"[*] Starting web UI on http://127.0.0.1:{args.ui_port}")
        print("    Press Ctrl+C to stop.\n")
        from src.frontend.app import create_app
        app = create_app(cfg)
        app.run(host="127.0.0.1", port=args.ui_port, debug=False, threaded=True)
        return

    # CLI analysis — require at least one input
    if not any([args.log, args.pcap, args.ioc]):
        parser.error("Provide at least one input: --log, --pcap, or --ioc  (or --ui for web interface)")

    cfg = load_config(args.config)

    # Training mode
    if args.train:
        print(f"[*] Training ML ensemble on: {args.train_data}")
        train_path = Path(args.train_data)
        if not train_path.exists():
            print(f"[!] Training data folder not found: {args.train_data}")
            print("    Create the folder and add baseline log files.")
            sys.exit(1)
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "src.models.train_ensemble", "--data", args.train_data],
            check=False
        )
        if result.returncode != 0:
            print("[!] Training encountered errors — see output above.")
        print()

    # Service mode checks
    if args.mode == "service" and not args.customer_id:
        parser.error("--customer-id is required in --mode service")

    # Read input files
    log_text = ""
    pcap_text = ""

    if args.log:
        log_path = Path(args.log)
        if not log_path.exists():
            print(f"[ERROR] Log file not found: {args.log}")
            sys.exit(1)
        from src.utils.log_parser import LogParser
        raw = log_path.read_bytes()
        parsed = LogParser().parse(raw.decode("utf-8", errors="replace"), log_path.name)
        log_text = LogParser().to_text(parsed) if parsed else raw.decode("utf-8", errors="replace")
        print(f"[+] Log     : {args.log}  ({len(log_text):,} chars, {len(parsed)} events)")

    if args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.exists():
            print(f"[ERROR] PCAP file not found: {args.pcap}")
            sys.exit(1)
        raw = pcap_path.read_bytes()
        if pcap_path.suffix.lower() in (".pcap", ".cap", ".pcapng"):
            from src.utils.pcap_parser import PCAPParser
            parsed_pcap = PCAPParser().parse(raw)
            pcap_text = parsed_pcap.get("text_summary", "")
        else:
            pcap_text = raw.decode("utf-8", errors="replace")
        print(f"[+] PCAP    : {args.pcap}  ({len(pcap_text):,} chars)")

    if args.ioc:
        from src.security.input_sanitizer import InputSanitizer
        ok, ioc_type = InputSanitizer().validate_ioc(args.ioc)
        if not ok:
            print(f"[ERROR] Invalid IOC: {args.ioc}")
            print("        Accepted: IPv4, domain, MD5/SHA1/SHA256, CVE-YYYY-NNNN")
            sys.exit(1)
        print(f"[+] IOC     : {args.ioc}  (type: {ioc_type})")

    print(f"[+] Mode    : {args.mode}")
    print()

    # Run analysis
    print("[*] Running 5-algorithm ensemble analysis...")
    t0 = time.perf_counter()

    from src.core.inference_engine import InferenceEngine
    engine = InferenceEngine.get_instance(cfg)

    result = engine.analyze(
        log_text=log_text,
        pcap_text=pcap_text,
        ioc=args.ioc or "",
        customer_id=args.customer_id or "",
        mode=args.mode,
    )

    elapsed = time.perf_counter() - t0
    print(f"[+] Analysis complete in {elapsed:.2f}s\n")

    # Print summary
    _print_summary(result)

    # Save outputs
    os.makedirs("outputs", exist_ok=True)
    out_base = args.output or f"outputs/report_{int(time.time())}"

    saved = []
    fmt = args.format

    if fmt in ("json", "both"):
        json_path = out_base + ".json"
        Path(json_path).write_text(json.dumps(result, indent=2, default=str))
        saved.append(json_path)

    if fmt in ("pdf", "both"):
        pdf_bytes = engine.generate_pdf(result)
        if pdf_bytes:
            pdf_path = out_base + ".pdf"
            Path(pdf_path).write_bytes(pdf_bytes)
            saved.append(pdf_path)
        else:
            print("[!] PDF generation failed — saving JSON only")
            if fmt == "pdf":
                json_path = out_base + ".json"
                Path(json_path).write_text(json.dumps(result, indent=2, default=str))
                saved.append(json_path)

    print("[+] Output files:")
    for s in saved:
        print(f"    => {s}")
    print()


def _print_summary(result: dict):
    risk    = result.get("risk_score", 0)
    sev     = result.get("severity", "UNKNOWN")
    ens     = result.get("ensemble", {})
    zd      = result.get("zero_day", {})
    threats = result.get("existing_threats", {})

    sev_color = {"INFO": "", "LOW": "", "MEDIUM": "*** ", "HIGH": "!!! ", "CRITICAL": ">>> "}.get(sev, "")

    print(f"  {sev_color}RISK SCORE : {risk}/100  [{sev}]")
    print(f"  Ensemble   : {ens.get('weighted_score', 0):.1f}/100  "
          f"(dominant: {ens.get('dominant_detector', 'N/A')})")
    print(f"  Zero-Day   : {zd.get('zero_day_score', 0):.1f}/100  "
          f"({zd.get('label', 'N/A')})")

    iocs = threats.get("iocs", {})
    total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
    if total_iocs:
        print(f"  IOCs found : {total_iocs} "
              f"(IPs: {len(iocs.get('ips', []))}, domains: {len(iocs.get('domains', []))}, "
              f"hashes: {len(iocs.get('hashes', []))})")

    mitre_hits = threats.get("mitre_hits", [])
    if mitre_hits:
        print(f"  MITRE      : {len(mitre_hits)} technique(s) detected")
        for hit in mitre_hits[:3]:
            print(f"               {hit.get('id','?')} — {hit.get('name','?')} [{hit.get('tactic','?')}]")
        if len(mitre_hits) > 3:
            print(f"               ... and {len(mitre_hits) - 3} more")

    yara_hits = threats.get("yara_hits", [])
    if yara_hits:
        print(f"  YARA rules : {len(yara_hits)} match(es) — {', '.join(yara_hits[:4])}")

    cves = threats.get("cves", [])
    if cves:
        top = cves[0]
        print(f"  CVE alert  : {top.get('cve_id','?')} CVSS {top.get('cvss','?')} — {top.get('description','')[:60]}")

    kill = result.get("kill_chain")
    if kill and kill.get("timeline"):
        print(f"  Kill chain : {len(kill['timeline'])} stage(s) reconstructed")

    yara_rule = zd.get("yara_rule")
    if yara_rule:
        print(f"  Auto-YARA  : Generated (score ≥ 60)")

    print()


if __name__ == "__main__":
    main()
