# SOC AI Assistant Pro

**Turns 4 hours of log correlation into 4 minutes. 100% offline. Air-gap safe.**

> Feed it a suspicious IP, a log file, or a PCAP — get back a full kill chain, MITRE ATT&CK heatmap, auto-generated YARA rules, and a PDF incident report. No cloud. No Ollama. No API keys required.

[![Demo Video](https://img.shields.io/badge/Watch-Demo%20Video-red?logo=google-drive)](https://drive.google.com/file/d/1sH6hOsyFiEVD1jhPGRnBkK16AAegsiSj/view?usp=sharing)
[![License](https://img.shields.io/badge/License-Commercial-blue)](#license)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![Offline](https://img.shields.io/badge/Mode-100%25%20Offline-green)](#)

---

## The Problem This Solves

SOC teams lose 70% of their time switching between tools — logs in one window, PCAP in another, CVEs in a browser, MITRE ATT&CK in a fourth. By the time manual correlation happens, the attacker has moved laterally.

SOC AI Assistant Pro collapses that entire workflow into one command.

---

## What's New in v2.0

| Upgrade | v1 | v2 |
|---|---|---|
| Threat detection | Single LLM call | **5-algorithm ML ensemble** |
| Zero-day coverage | None | **6 orthogonal anomaly methods** |
| LLM dependency | Ollama required | **Zero — fully embedded models** |
| Frontend | CLI only | **Cyberpunk web UI (Flask)** |
| YARA rules | None | **15 production rules + auto-generation** |
| License | Open-source | **Commercial RSA-signed** |

---

## Features

### 5-Algorithm ML Ensemble
| Algorithm | Weight | Role |
|---|---|---|
| BERT / DistilBERT | 25% | Semantic understanding of log content |
| Isolation Forest | 20% | Statistical anomaly detection on 20 log features |
| LSTM Predictor | 20% | Sequential event pattern surprise scoring |
| MLP Autoencoder | 20% | Reconstruction-error anomaly detection |
| One-Class SVM | 15% | Boundary-based novelty scoring |

Weighted confidence voting: `adj_weight = weight × (0.5 + confidence × 0.5)`. Alert threshold: 75/100.

### Zero-Day Detection (6 Methods)
1. **Statistical Baseline** — Z-score deviation from trained distribution
2. **Embedding Clustering** — Cosine distance from known-good centroids
3. **Entropy Analysis** — Shannon entropy + high-entropy token detection
4. **Temporal Sequence** — N-gram transition surprise scoring
5. **Packet Timing** — Beaconing detection via CV of inter-arrival times
6. **Protocol Violation** — State-machine regex checks (DNS C2, ICMP tunneling, etc.)

Auto-generates YARA hunting rules and Splunk/KQL/grep queries for every detection.

### Rules & Intelligence
- **15 YARA rules** — Mimikatz, Cobalt Strike, PowerShell obfuscation, ransomware, LOLBins, web shells
- **15 Sigma rules** — Mapped to detection logic
- **15 critical CVEs** — Log4Shell (CVSS 10.0), Zerologon, ProxyShell, etc.
- **40+ MITRE ATT&CK techniques** — Automatic technique ID mapping

### Kill Chain Reconstruction
Feed one IOC (IP / hash / CVE) → auto-pivot across logs + PCAP → full attack timeline with MITRE ATT&CK stage labels.

### Web UI
Cyberpunk dark-theme Flask interface: real-time analysis terminal, interactive MITRE heatmap (D3.js), risk gauge, one-click PDF/JSON/CSV export. No Node.js or build step required.

### PDF Reports
Professional PDF with dark cyberpunk theme — risk banner, ML score table, zero-day intelligence, MITRE technique table, kill chain timeline, remediation checklist.

---

## Installation

### Requirements
- Python 3.9+
- 4 GB RAM minimum (8 GB recommended)
- 500 MB disk space (+ ~250 MB for DistilBERT weights on first run)

### Linux / macOS

```bash
git clone https://github.com/Mario121625/soc-ai-assistant.git
cd soc-ai-assistant
chmod +x installer.sh
./installer.sh
```

Optionally compile a standalone binary:
```bash
./installer.sh --compile
```

### Windows

```bat
git clone https://github.com/Mario121625/soc-ai-assistant.git
cd soc-ai-assistant
installer.bat
```

### Manual Installation

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

### Web UI (Recommended)

```bash
source .venv/bin/activate
python soc_assist.py --ui
```

Open **http://127.0.0.1:5000** — drag and drop logs or PCAPs, enter an IOC, watch the real-time terminal feed, and export your report.

### CLI — Quick Start

```bash
# Activate environment
source .venv/bin/activate

# Analyze a log file (JSON report)
python soc_assist.py --log sample_inputs/sample_syslog.txt

# Full analysis — log + PCAP → PDF + JSON
python soc_assist.py \
  --log sample_inputs/sample_syslog.txt \
  --pcap sample_inputs/sample_pcap_summary.txt \
  --format both

# Kill chain from a single IOC
python soc_assist.py --ioc 185.220.101.42 --log sample_inputs/sample_syslog.txt

# Service mode — watermarked PDF for a client
python soc_assist.py \
  --mode service \
  --customer-id ACME-001 \
  --log /path/to/client_logs.txt \
  --format pdf
```

### CLI Flag Reference

| Flag | Description |
|---|---|
| `--log FILE` | Syslog / JSON / CSV / EVTX / TXT log file |
| `--pcap FILE` | PCAP or PCAP summary text file |
| `--ioc VALUE` | Single IOC: IPv4, domain, MD5/SHA1/SHA256, CVE-ID |
| `--format` | `json` (default) · `pdf` · `both` |
| `--output PATH` | Output base path (default: `./outputs/report_<timestamp>`) |
| `--mode` | `tool` (single user) · `service` (watermarked + usage log) |
| `--customer-id ID` | Required with `--mode service` |
| `--ui` | Launch Flask web UI |
| `--ui-port N` | Web UI port (default: 5000) |
| `--train` | Train ML models before analysis |
| `--train-data DIR` | Baseline log folder for training (default: `./baseline_logs/`) |
| `--hardware-id` | Print this machine's hardware fingerprint and exit |
| `--no-license` | Skip license check (demo mode) |
| `--config FILE` | Path to `config.yaml` (default: `./config.yaml`) |

---

## Training the ML Models

For best detection accuracy, train the ensemble on your environment's baseline logs:

```bash
# 1. Add representative benign logs to baseline_logs/
#    (at least 50-100 log files recommended)
mkdir -p baseline_logs
cp /var/log/syslog baseline_logs/syslog_$(date +%Y%m%d).log
# ... add more logs

# 2. Train
python soc_assist.py --train --train-data ./baseline_logs/

# Or directly:
python -m src.models.train_ensemble --data ./baseline_logs/
```

Without training, all 5 models fall back to robust statistical heuristics — the tool works immediately out of the box.

---

## Supported Input Formats

| Format | Description |
|---|---|
| Syslog | Standard `RFC 3164` / `RFC 5424` syslog |
| JSON / NDJSON | Structured log events (field-name auto-mapping) |
| CSV | Tabular logs with header detection |
| CEF | ArcSight Common Event Format |
| EVTX / XML | Windows Event Log (text summary) |
| PCAP / CAP | Binary packet captures (via Scapy) |
| PCAP summary | Text-format PCAP summaries |

---

## Running Tests

```bash
source .venv/bin/activate

# Full test suite
python -m pytest tests/ -v

# Individual test files
python -m pytest tests/test_zero_day_simulator.py -v
python -m pytest tests/test_license.py -v
python -m pytest tests/test_security.py -v
python -m pytest tests/test_performance.py -v
```

---

## Project Structure

```
soc-ai-assistant/
├── soc_assist.py              # CLI entrypoint
├── installer.sh / .bat        # Setup scripts
├── requirements.txt
├── config.yaml                # Central configuration
├── license.txt                # Your license key (not in git)
├── sample_inputs/             # Example logs and PCAP summaries
│
├── src/
│   ├── models/                # 5 ML algorithms + voting + training
│   │   ├── bert_analyzer.py
│   │   ├── isolation_forest_model.py
│   │   ├── lstm_predictor.py
│   │   ├── autoencoder_model.py
│   │   ├── one_class_svm.py
│   │   ├── voting_classifier.py
│   │   └── train_ensemble.py
│   │
│   ├── core/                  # Orchestration engines
│   │   ├── inference_engine.py
│   │   ├── ensemble_detector.py
│   │   ├── zero_day_detector.py
│   │   └── existing_threat_detector.py
│   │
│   ├── security/              # License, anti-tamper, input validation
│   │   ├── license_manager.py
│   │   ├── anti_tamper.py
│   │   ├── secure_delete.py
│   │   └── input_sanitizer.py
│   │
│   ├── utils/                 # Parsers, report generator, entropy
│   │   ├── log_parser.py
│   │   ├── pcap_parser.py
│   │   ├── report_generator.py
│   │   └── entropy_calculator.py
│   │
│   ├── rules/                 # Detection rules
│   │   ├── yara/threats.yar
│   │   ├── sigma/sigma_rules.yml
│   │   ├── cve_db.json
│   │   └── mitre_mapping.json
│   │
│   └── frontend/              # Flask web UI
│       ├── app.py
│       ├── templates/index.html
│       └── static/ (app.js, style.css)
│
└── tests/
    ├── test_zero_day_simulator.py
    ├── test_license.py
    ├── test_security.py
    └── test_performance.py
```

---

## Pricing

| Product | Price | What's Included |
|---|---|---|
| **Tool License** | $49 one-time | CLI + Web UI, unlimited analyses, 1 machine |
| **Report Service** | $299/report | You send logs, we deliver a PDF incident report within 24h |
| **Enterprise** | Contact | Multi-seat, custom YARA/Sigma rules, priority support |

Purchase at [Gumroad](#) → Enter license key in `license.txt` → Done.

---

## License

**Commercial License — Single User**

This software is proprietary. Purchase of a license grants a single non-transferable right to use this software on one machine. Redistribution, resale, reverse engineering, and sublicensing are prohibited.

© 2025 ojas1216 / Mario121625 — All rights reserved  
Contact: agentmario1216@gmail.com
