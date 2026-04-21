#!/bin/bash
# SOC AI Assistant Pro — Linux / macOS Installer v2.0
# Installs dependencies, downloads ML model weights, generates hardware ID,
# and optionally compiles a standalone binary with PyInstaller.
set -e

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

info()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
step()  { echo -e "\n${BOLD}$*${RESET}"; }

echo ""
echo "======================================================="
echo "   SOC AI ASSISTANT PRO  v2.0  —  Installer"
echo "======================================================="
echo ""

# ── 1. Python version check ────────────────────────────────────────────────
step "Step 1 — Checking Python version"
command -v python3 &>/dev/null || error "Python 3 not found. Install from https://python.org"

PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")

[ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -ge 9 ] || \
    error "Python 3.9+ required. Found: $(python3 --version)"

info "Python $(python3 --version) — OK"

# ── 2. Virtual environment ─────────────────────────────────────────────────
step "Step 2 — Virtual environment"
if [ ! -d ".venv" ]; then
    echo "    Creating .venv ..."
    python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
info "Virtual environment activated: $(which python)"

# ── 3. Core dependencies ───────────────────────────────────────────────────
step "Step 3 — Installing Python dependencies"
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
info "Dependencies installed."

# ── 4. PyTorch check (CPU-only fallback) ──────────────────────────────────
step "Step 4 — Verifying PyTorch"
if python3 -c "import torch; print('torch', torch.__version__)" 2>/dev/null; then
    info "PyTorch available — LSTM + Autoencoder models enabled."
else
    warn "PyTorch not installed. Installing CPU-only build..."
    pip install torch --index-url https://download.pytorch.org/whl/cpu --quiet
    info "PyTorch (CPU) installed."
fi

# ── 5. Download DistilBERT model weights (one-time, ~250 MB) ──────────────
step "Step 5 — Downloading DistilBERT model weights"
MODEL_CACHE=".model_cache"
mkdir -p "$MODEL_CACHE"

if python3 -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('distilbert-base-nli-mean-tokens', cache_folder='.model_cache')" 2>/dev/null; then
    info "DistilBERT sentence-transformer ready."
else
    warn "sentence-transformers not available or download failed."
    warn "BERT analyzer will fall back to keyword scoring (still functional)."
fi

# ── 6. Create required directories ────────────────────────────────────────
step "Step 6 — Creating directories"
mkdir -p outputs sample_inputs baseline_logs tests
info "Directories: outputs/, sample_inputs/, baseline_logs/, tests/"

# ── 7. License setup ──────────────────────────────────────────────────────
step "Step 7 — License setup"
if [ ! -f "license.txt" ]; then
    echo "PASTE-YOUR-LICENSE-KEY-HERE" > license.txt
    warn "Created license.txt — replace with your Gumroad license key before use."
else
    info "license.txt found."
fi

# Print hardware ID for license generation
HW_ID=$(python3 -c "
import sys; sys.path.insert(0,'.')
from src.security.license_manager import LicenseManager
print(LicenseManager._compute_hardware_id())
" 2>/dev/null || echo "N/A")

echo ""
echo "  ┌─────────────────────────────────────────────────┐"
echo "  │  Your Hardware ID (for license activation):     │"
echo "  │                                                   │"
printf "  │  %-49s│\n" "  $HW_ID"
echo "  │                                                   │"
echo "  │  Email to: agentmario1216@gmail.com              │"
echo "  └─────────────────────────────────────────────────┘"
echo ""

# ── 8. Generate integrity manifest ────────────────────────────────────────
step "Step 8 — Generating integrity manifest"
if python3 -c "
import sys; sys.path.insert(0,'.')
from src.security.anti_tamper import AntiTamper
AntiTamper().generate_manifest()
print('Manifest written.')
" 2>/dev/null; then
    info "Integrity manifest (.integrity.json) generated."
else
    warn "Could not generate integrity manifest — skipping."
fi

# ── 9. Optional: Train ML models ──────────────────────────────────────────
step "Step 9 — ML model training (optional)"
if [ -d "baseline_logs" ] && [ "$(ls -A baseline_logs 2>/dev/null)" ]; then
    echo "    Found baseline_logs/ — training ensemble..."
    python3 -m src.models.train_ensemble --data ./baseline_logs/ || \
        warn "Training failed — models will use heuristic fallbacks."
    info "ML models trained."
else
    warn "baseline_logs/ is empty — skipping training."
    warn "Models will use statistical fallbacks until trained."
    warn "Add representative benign logs to baseline_logs/ and re-run:"
    warn "  python3 -m src.models.train_ensemble --data ./baseline_logs/"
fi

# ── 10. Optional: PyInstaller binary ──────────────────────────────────────
step "Step 10 — PyInstaller binary (optional)"
if [[ "${1}" == "--compile" ]]; then
    echo "    Compiling standalone binary with PyInstaller..."
    pip install pyinstaller --quiet

    pyinstaller soc_assist.py \
        --onefile \
        --name soc_assist \
        --add-data "src/rules:src/rules" \
        --add-data "src/frontend/templates:src/frontend/templates" \
        --add-data "src/frontend/static:src/frontend/static" \
        --add-data ".model_cache:.model_cache" \
        --hidden-import sklearn \
        --hidden-import torch \
        --hidden-import transformers \
        --hidden-import sentence_transformers \
        --hidden-import yara \
        --hidden-import flask \
        --hidden-import flask_limiter \
        --hidden-import flask_cors \
        --hidden-import reportlab \
        --distpath ./dist \
        --workpath ./build \
        --noconfirm \
        --log-level WARN

    if [ -f "dist/soc_assist" ]; then
        info "Binary compiled: dist/soc_assist"
        info "Test: ./dist/soc_assist --no-license --log sample_inputs/sample_syslog.txt"
    else
        warn "PyInstaller build failed — use Python CLI instead."
    fi
else
    echo "    (Skip — pass --compile to build a standalone binary)"
fi

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo "======================================================="
echo -e "${GREEN}  Installation complete!${RESET}"
echo "======================================================="
echo ""
echo "  Quick start:"
echo "    source .venv/bin/activate"
echo ""
echo "  CLI analysis:"
echo "    python soc_assist.py --log sample_inputs/sample_syslog.txt --format both"
echo ""
echo "  Web UI:"
echo "    python soc_assist.py --ui"
echo "    Open: http://127.0.0.1:5000"
echo ""
echo "  Train models:"
echo "    python soc_assist.py --train --train-data ./baseline_logs/"
echo ""
echo "  Run tests:"
echo "    python -m pytest tests/ -v"
echo ""
