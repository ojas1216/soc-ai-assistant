#!/usr/bin/env python3
"""SOC AI Assistant Pro — CLI entrypoint"""
import argparse
import json
import os
import sys
from pathlib import Path

import yaml


def load_config(path: str = "config.yaml") -> dict:
    cfg_path = Path(path)
    if not cfg_path.exists():
        print(f"[ERROR] Config file not found: {path}")
        print("        Run the installer or copy config.yaml.example to config.yaml")
        sys.exit(1)
    with open(cfg_path) as f:
        return yaml.safe_load(f)


def check_license(cfg: dict) -> str:
    key_file = Path(cfg.get("license", {}).get("key_file", "./license.txt"))
    if not key_file.exists():
        print("[ERROR] license.txt not found.")
        print("        Place your license key (from Gumroad) in ./license.txt")
        sys.exit(1)
    key = key_file.read_text().strip()
    # Offline validation: SOC-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXX (36 chars)
    if not (key.startswith("SOC-") and len(key) == 36):
        print("[ERROR] Invalid license key. Expected format: SOC-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXX")
        sys.exit(1)
    return key


def main():
    parser = argparse.ArgumentParser(
        prog="soc_assist",
        description="SOC AI Assistant Pro — Offline threat correlation engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Analyze a log file:
    python soc_assist.py --log inputs/high_risk.json

  Full correlation (log + PCAP):
    python soc_assist.py --log inputs/syslog.txt --pcap inputs/capture_summary.txt --format both

  Kill chain from one IOC:
    python soc_assist.py --ioc 185.220.101.42 --log inputs/high_risk.json

  Service mode (watermarked PDF + usage log):
    python soc_assist.py --mode service --customer-id CUST-001 --log inputs/syslog.txt
        """
    )

    parser.add_argument("--log",         help="Path to syslog / JSON log file")
    parser.add_argument("--pcap",        help="Path to PCAP summary text file")
    parser.add_argument("--ioc",         help="Single IOC seed: IP, domain, file hash, or CVE ID")
    parser.add_argument("--output",      help="Output base path (default: ./outputs/report)")
    parser.add_argument("--format",      choices=["pdf", "json", "both"], default=None,
                        help="Output format (overrides config.yaml)")
    parser.add_argument("--mode",        choices=["tool", "service"], default="tool",
                        help="tool = single-user, service = watermarked + usage-logged")
    parser.add_argument("--customer-id", dest="customer_id",
                        help="Customer ID (required in --mode service)")
    parser.add_argument("--config",      default="config.yaml",
                        help="Path to config.yaml (default: ./config.yaml)")
    parser.add_argument("--offline",     action="store_true",
                        help="Force offline mode (skip all external API calls)")
    parser.add_argument("--no-license",  action="store_true",
                        help="Skip license check (demo/dev mode)")

    args = parser.parse_args()

    if not any([args.log, args.pcap, args.ioc]):
        parser.error("Provide at least one of: --log, --pcap, --ioc")

    cfg = load_config(args.config)

    if not args.no_license:
        check_license(cfg)

    # CLI overrides
    if args.format:
        cfg["output"]["format"] = args.format
    if args.customer_id:
        cfg["output"]["customer_id"] = args.customer_id
    if args.offline:
        cfg["offline_mode"] = True

    if args.mode == "service":
        cfg["output"]["watermark"] = True
        if not args.customer_id:
            parser.error("--customer-id is required in --mode service")

    out_folder = cfg.get("inputs", {}).get("output_folder", "./outputs/")
    os.makedirs(out_folder, exist_ok=True)

    out_fmt = cfg["output"].get("format", "pdf")
    cid = cfg["output"].get("customer_id") or "local"
    out_base = args.output or os.path.join(out_folder, f"report_{cid}")

    print(f"[*] SOC AI Assistant Pro")
    print(f"[*] Mode    : {args.mode}")
    print(f"[*] Offline : {cfg.get('offline_mode', True)}")
    if args.log:  print(f"[*] Log     : {args.log}")
    if args.pcap: print(f"[*] PCAP    : {args.pcap}")
    if args.ioc:  print(f"[*] IOC     : {args.ioc}")
    print()

    from backend.pipeline import run_pipeline

    result = run_pipeline(
        log_path=args.log,
        pcap_path=args.pcap,
        ioc=args.ioc,
        config=cfg
    )

    saved = []
    if out_fmt in ("pdf", "both") and result.get("pdf"):
        pdf_path = out_base + ".pdf"
        Path(pdf_path).write_bytes(result["pdf"])
        saved.append(pdf_path)

    if out_fmt in ("json", "both"):
        json_path = out_base + ".json"
        Path(json_path).write_text(json.dumps(result["json"], indent=2))
        saved.append(json_path)

    print("[+] Analysis complete.")
    for s in saved:
        print(f"    => {s}")

    # Print quick summary to terminal
    r = result["json"]
    print(f"\n--- Quick Summary ---")
    print(f"Risk Score : {r.get('risk_score', 'N/A')} / 10")
    mitre = r.get("mitre_techniques", [])
    if mitre:
        print(f"MITRE Hits : {len(mitre)} technique(s) detected")
        for tid, desc in mitre[:3]:
            print(f"             {tid} — {desc}")
    if r.get("kill_chain"):
        print(f"Kill Chain : {r['kill_chain'].get('timeline_events', 0)} correlated events")
    print()


if __name__ == "__main__":
    main()
