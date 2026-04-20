# SOC AI Assistant Pro

**Turns 4 hours of log correlation into 4 minutes. 100% offline. Air-gap safe.**

> Give it one suspicious IP, a log file, or a PCAP summary.  
> Get back a full kill chain reconstruction, MITRE ATT&CK mapping, and a 3-step containment plan — in a single PDF.

[![Demo Video](https://img.shields.io/badge/Watch-Demo%20Video-red?logo=google-drive)](https://drive.google.com/file/d/1sH6hOsyFiEVD1jhPGRnBkK16AAegsiSj/view?usp=sharing)
[![License](https://img.shields.io/badge/License-Commercial-blue)](#license)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![Offline](https://img.shields.io/badge/Mode-100%25%20Offline-green)](#)

---

## The Problem This Solves

SOC teams lose 70% of their time switching between tools — checking logs in one window, PCAP in another, CVEs in a browser tab, MITRE ATT&CK in a fourth. By the time correlation happens, the attacker has moved laterally.

SOC AI Assistant Pro collapses that entire workflow into one command.

---

## Features

| Feature | Description |
|---|---|
| **Kill Chain Reconstruction** | Feed one IOC (IP / hash / CVE) → auto-pivot across logs + PCAP → full attack timeline |
| **MITRE ATT&CK Mapping** | Automatic technique detection across all 14 kill chain stages |
| **LLM Threat Analysis** | Local AI (Ollama) generates incident summaries and remediation — no cloud, no data leakage |
| **Threat Intel Enrichment** | Optional AbuseIPDB, VirusTotal, NVD lookups (or run fully offline) |
| **PDF + JSON Reports** | Executive-ready PDF with risk score, MITRE techniques, and 3-step remediation |
| **Service Mode** | Watermarked reports + usage logging for MSPs and enterprise billing |
| **Streamlit Web UI** | Browser-based upload and analysis interface |
| **Air-gap Safe** | Core analysis runs with zero internet connectivity |

---

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.9+ | [python.org](https://python.org) |
| Ollama | Latest | [ollama.com/download](https://ollama.com/download) |
| LLM Model | — | Run `ollama pull mistral` after installing Ollama |
| RAM | 8 GB min | 16 GB recommended for `llama3` |

---

## Installation

### Option 1 — Automated (recommended)

**Linux / macOS:**
```bash
git clone https://github.com/ojas1216/soc-ai-assistant.git
cd soc-ai-assistant
bash installer.sh
```

**Windows:**
```
git clone https://github.com/ojas1216/soc-ai-assistant.git
cd soc-ai-assistant
installer.bat
```

### Option 2 — Manual

```bash
# 1. Clone
git clone https://github.com/ojas1216/soc-ai-assistant.git
cd soc-ai-assistant

# 2. Create and activate virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Pull the LLM model (requires Ollama running)
ollama pull mistral

# 5. Configure
cp .env.example .env    # then edit .env with your API keys (optional)
```

---

## Configuration

Edit `config.yaml` before first run:

```yaml
llm:
  model: "mistral"        # or llama3 for higher accuracy

offline_mode: true        # set false to enable AbuseIPDB / VirusTotal enrichment
```

For threat intel enrichment, add your API keys to `.env`:

```env
ABUSEIPDB_API_KEY=your_key_here
VT_API_KEY=your_key_here
NVD_API_KEY=your_key_here
```

Free keys: [AbuseIPDB](https://www.abuseipdb.com/) · [VirusTotal](https://www.virustotal.com/gui/join-us) · [NVD](https://nvd.nist.gov/developers/request-an-api-key)

---

## Running the Tool

### CLI (recommended)

```bash
# Analyze a log file — outputs PDF report
python soc_assist.py --log sample_inputs/high_risk.json

# Full correlation: log + PCAP summary
python soc_assist.py --log sample_inputs/sample_syslog.txt \
                     --pcap sample_inputs/sample_pcap_summary.txt \
                     --format both

# Kill chain from one IOC  ← flagship feature
python soc_assist.py --ioc 185.220.101.42 \
                     --log sample_inputs/sample_syslog.txt \
                     --format both

# Service mode (watermarked PDF + usage log)
python soc_assist.py --mode service \
                     --customer-id CLIENT-001 \
                     --log sample_inputs/high_risk.json
```

All outputs saved to `outputs/`.

**CLI flags reference:**

| Flag | Description |
|---|---|
| `--log PATH` | Syslog or JSON log file |
| `--pcap PATH` | PCAP summary text file |
| `--ioc VALUE` | Single IOC: IP, domain, file hash, or CVE ID |
| `--format` | `pdf` \| `json` \| `both` (default: `pdf`) |
| `--mode` | `tool` (default) \| `service` |
| `--customer-id` | Required in `--mode service` |
| `--output PATH` | Custom output base path |
| `--offline` | Force offline mode (skip all API calls) |
| `--config PATH` | Custom config.yaml path |

### Web UI

```bash
streamlit run frontend/app.py
```

Open [http://localhost:8501](http://localhost:8501), upload a log from `sample_inputs/`, and download the generated report.

---

## Sample Inputs

Ready-to-run scenarios in `sample_inputs/`:

| File | Scenario |
|---|---|
| `high_risk.json` | RDP brute force → lateral movement → mimikatz + CVE-2023-23397 |
| `zero_day.json` | Zero-day exfiltration via PowerShell + registry persistence |
| `sysmon_log.json` | Windows Sysmon events — encoded PowerShell + regsvr32 living-off-the-land |
| `sample_syslog.txt` | SSH brute force → C2 beacon → credential exfiltration |
| `sample_pcap_summary.txt` | Matching PCAP for the syslog scenario |

**Demo run:**
```bash
python soc_assist.py --ioc 185.220.101.42 \
  --log sample_inputs/sample_syslog.txt \
  --pcap sample_inputs/sample_pcap_summary.txt \
  --format both
```

---

## Project Structure

```
soc-ai-assistant/
├── soc_assist.py              # CLI entrypoint
├── config.yaml                # Central configuration
├── requirements.txt
├── installer.sh / .bat        # One-click setup
├── backend/
│   ├── pipeline.py            # Unified analysis pipeline
│   ├── kill_chain.py          # IOC → kill chain reconstruction
│   ├── llm_engine.py          # Ollama LLM interface
│   ├── threat_intel.py        # IOC enrichment (AbuseIPDB, VT, NVD)
│   ├── risk_scorer.py         # MITRE ATT&CK mapping + risk scoring
│   ├── report_generator.py    # PDF generation
│   ├── preprocessor.py        # Log normalization
│   └── whitelist.py           # IOC whitelisting
├── frontend/
│   └── app.py                 # Streamlit web UI
├── sample_inputs/             # Ready-to-run test scenarios
└── outputs/                   # Generated reports (gitignored)
```

---

## License

**SOC AI Assistant Pro — Commercial License**

One license key = one seat. You may use this software for paid client work and internal SOC operations. Redistribution and resale are prohibited.

For multi-seat or enterprise/MSP licensing: agentmario1216@gmail.com

See [LICENSE](./LICENSE) for full terms.

---

## Disclaimer

This tool is intended for authorized security operations, incident response, and defensive research. Use only on systems and networks you own or have explicit written permission to test.
