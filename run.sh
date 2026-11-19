#!/usr/bin/env bash
# Shodan IP Collector Launcher for Linux / macOS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================================================"
echo "                     Shodan IP Collector Launcher                       "
echo "========================================================================"
echo ""

# Find Python 3
if command -v python3 &>/dev/null; then
    PY_CMD="python3"
elif command -v python &>/dev/null; then
    PY_CMD="python"
else
    echo "[!] ERROR: Python 3 is not installed or not in PATH."
    echo "Please install Python 3 using your system package manager (e.g. apt, brew)."
    exit 1
fi

echo "[*] Using Python: $($PY_CMD --version)"

# Check and install dependencies
echo "[*] Verifying dependencies from requirements.txt..."
$PY_CMD -m pip install -r "$SCRIPT_DIR/requirements.txt" --quiet 2>/dev/null || {
    echo "[!] Note: Could not auto-install with pip; continuing if packages already exist."
}

echo "[*] Starting Shodan Collector..."
echo ""

# Execute python script
$PY_CMD "$SCRIPT_DIR/shodan_scraper.py" "$@"
EXIT_CODE=$?

echo ""
echo "========================================================================"
echo "Execution finished with status code $EXIT_CODE"
exit $EXIT_CODE
