@echo off
setlocal enabledelayedexpansion

echo.
echo =======================================
echo   SOC AI Assistant Pro -- Installer
echo =======================================
echo.

:: 1. Python check
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install from https://python.org
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [+] Python found: %PYVER%

:: 2. Virtual environment
if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
)
call .venv\Scripts\activate.bat
echo [+] Virtual environment activated.

:: 3. Dependencies
echo [*] Installing dependencies...
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo [+] Dependencies installed.

:: 4. Directories
if not exist "outputs" mkdir outputs
if not exist "sample_inputs" mkdir sample_inputs
echo [+] Output directories created.

:: 5. License placeholder
if not exist "license.txt" (
    echo PASTE-YOUR-LICENSE-KEY-HERE> license.txt
    echo [!] Created license.txt -- replace with your Gumroad license key.
)

echo.
echo =======================================
echo   IMPORTANT: Ollama required for LLM
echo =======================================
echo   Install: https://ollama.com/download
echo   Then run: ollama pull mistral
echo.
echo [+] Installation complete!
echo.
echo   Quick start:
echo     .venv\Scripts\activate.bat
echo     python soc_assist.py --log inputs/high_risk.json --format both
echo.
pause
