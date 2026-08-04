#!/bin/bash
# BRAT - BLE Recon and Attack Toolkit
# One-line installer

set -e

echo "=== BRAT Installer ==="
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is required but not installed."
    echo "        Install with: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[+] Found Python $PYTHON_VERSION"

# Check for venv module
if ! python3 -c "import venv" &> /dev/null; then
    echo "[ERROR] Python venv module not found."
    echo "        Install with: sudo apt install python3-venv"
    exit 1
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
else
    echo "[+] Virtual environment already exists"
fi

# Activate and install
echo "[+] Installing BRAT and dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -e '.[peripheral]' -q

echo ""
echo "=== Installation Complete ==="
echo ""
echo "To use BRAT, first activate the virtual environment:"
echo ""
echo "    source venv/bin/activate"
echo ""
echo "Then run any command:"
echo ""
echo "    brat doctor              # Check your setup"
echo "    sudo brat scan           # Find BLE devices"
echo "    brat --help              # See all commands"
echo ""
echo "When done, deactivate with:"
echo ""
echo "    deactivate"
echo ""
