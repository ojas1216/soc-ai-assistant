#!/bin/bash
# SOC AI Assistant Pro — Linux/macOS Installer
set -e

echo ""
echo "======================================="
echo "  SOC AI Assistant Pro — Installer"
echo "======================================="
echo ""

# 1. Python check
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python 3 not found. Install from https://python.org"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PY_VER" -lt 9 ]; then
    echo "[ERROR] Python 3.9 or higher required."
    exit 1
fi

echo "[+] Python 3 found: $(python3 --version)"

# 2. Virtual environment
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate
echo "[+] Virtual environment activated."

# 3. Dependencies
echo "[*] Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "[+] Dependencies installed."

# 4. Directories
mkdir -p outputs sample_inputs
echo "[+] Output directories created."

# 5. License file placeholder
if [ ! -f "license.txt" ]; then
    echo "PASTE-YOUR-LICENSE-KEY-HERE" > license.txt
    echo "[!] Created license.txt — replace with your Gumroad license key."
fi

# 6. Ollama reminder
echo ""
echo "======================================="
echo "  IMPORTANT: Ollama required for LLM"
echo "======================================="
echo "  Install: https://ollama.com/download"
echo "  Then run: ollama pull mistral"
echo ""
echo "[+] Installation complete!"
echo ""
echo "  Quick start:"
echo "    source .venv/bin/activate"
echo "    python soc_assist.py --log inputs/high_risk.json --format both"
echo ""
