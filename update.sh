#!/bin/bash
# ============================================================================
# PegaProx Update Script
# ============================================================================
#
# Simple update script for PegaProx users.
# Downloads the latest version from GitHub and restarts the service.
#
# Usage:
#   ./update.sh              # Normal update
#   ./update.sh --force      # Force update (skip version check)
#
# MK: Created 25.01.2026 - the web updater was buggy, this is more reliable
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# GitHub raw URL
GITHUB_RAW="https://raw.githubusercontent.com/PegaProx/project-pegaprox/main"

# Find script directory (where PegaProx is installed)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║               PegaProx Update Script                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root (needed for service restart)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}⚠ Not running as root - service restart may fail${NC}"
    echo "  Run with: sudo ./update.sh"
    echo ""
fi

# Check current version
CURRENT_VERSION="unknown"
if [ -f "version.json" ]; then
    CURRENT_VERSION=$(grep -o '"version": *"[^"]*"' version.json | cut -d'"' -f4)
fi
echo -e "Current version: ${BLUE}$CURRENT_VERSION${NC}"

# Get latest version from GitHub
echo -n "Checking for updates... "
LATEST_VERSION=$(curl -s "$GITHUB_RAW/version.json" 2>/dev/null | grep -o '"version": *"[^"]*"' | cut -d'"' -f4)

if [ -z "$LATEST_VERSION" ]; then
    echo -e "${RED}Failed${NC}"
    echo "Could not connect to GitHub. Check your internet connection."
    exit 1
fi

echo -e "${GREEN}OK${NC}"
echo -e "Latest version:  ${GREEN}$LATEST_VERSION${NC}"
echo ""

# Compare versions (skip if --force)
if [ "$1" != "--force" ] && [ "$CURRENT_VERSION" == "$LATEST_VERSION" ]; then
    echo -e "${GREEN}✓ You're already on the latest version!${NC}"
    echo ""
    echo "Use ./update.sh --force to re-download anyway"
    exit 0
fi

# Confirm update
echo -e "${YELLOW}Ready to update from $CURRENT_VERSION to $LATEST_VERSION${NC}"
echo ""
read -p "Continue? [y/N] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Update cancelled."
    exit 0
fi

echo ""
echo -e "${YELLOW}Updating...${NC}"

# Create backup
BACKUP_DIR="backups/backup_${CURRENT_VERSION}_$(date +%Y%m%d_%H%M%S)"
echo -n "Creating backup in $BACKUP_DIR... "
mkdir -p "$BACKUP_DIR"

# Backup important files (not config - that stays)
[ -f "pegaprox_multi_cluster.py" ] && cp pegaprox_multi_cluster.py "$BACKUP_DIR/"
[ -f "web/index.html" ] && mkdir -p "$BACKUP_DIR/web" && cp web/index.html "$BACKUP_DIR/web/"
[ -f "version.json" ] && cp version.json "$BACKUP_DIR/"
[ -f "requirements.txt" ] && cp requirements.txt "$BACKUP_DIR/"

echo -e "${GREEN}OK${NC}"

# Download new files
echo ""
echo "Downloading new files..."

download_file() {
    local file=$1
    local dir=$(dirname "$file")
    
    [ "$dir" != "." ] && mkdir -p "$dir"
    
    echo -n "  $file... "
    if curl -sfL "$GITHUB_RAW/$file" -o "$file.tmp" 2>/dev/null; then
        mv "$file.tmp" "$file"
        echo -e "${GREEN}OK${NC}"
        return 0
    else
        rm -f "$file.tmp"
        echo -e "${RED}FAILED${NC}"
        return 1
    fi
}

# Core files to update
download_file "pegaprox_multi_cluster.py"
download_file "web/index.html"
download_file "web/index.html.original"
download_file "version.json"
download_file "requirements.txt"
download_file "deploy.sh"
download_file "update.sh"
download_file "web/Dev/build.sh"
download_file "web/Dev/_Normal_Users_No_Touchies_Devs_always_welcome"

# Make scripts executable
chmod +x deploy.sh build.sh update.sh 2>/dev/null || true

# Install/update Python packages
echo ""
echo -n "Installing Python packages... "

# Try different pip methods
if [ -f "venv/bin/pip" ]; then
    # Virtual environment
    venv/bin/pip install -q -r requirements.txt 2>/dev/null && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}Warning${NC}"
elif command -v pip3 &> /dev/null; then
    # System pip with sudo
    if [ "$EUID" -eq 0 ]; then
        pip3 install -q -r requirements.txt 2>/dev/null && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}Warning${NC}"
    else
        pip3 install -q --user -r requirements.txt 2>/dev/null && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}Warning${NC}"
    fi
else
    echo -e "${YELLOW}Skipped (pip not found)${NC}"
fi

# Restart service
echo ""
echo -n "Restarting PegaProx service... "

if systemctl is-active --quiet pegaprox 2>/dev/null; then
    if systemctl restart pegaprox 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}Failed - restart manually${NC}"
    fi
elif systemctl is-active --quiet pegaprox.service 2>/dev/null; then
    if systemctl restart pegaprox.service 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}Failed - restart manually${NC}"
    fi
else
    echo -e "${YELLOW}No systemd service found${NC}"
    echo "  If running manually, restart with: python3 pegaprox_multi_cluster.py"
fi

# Done!
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Update Complete! ✓                            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Updated to version: ${GREEN}$LATEST_VERSION${NC}"
echo -e "  Backup saved to:    ${BLUE}$BACKUP_DIR${NC}"
echo ""
echo "If something went wrong, restore with:"
echo "  cp $BACKUP_DIR/* ."
echo "  cp $BACKUP_DIR/web/* web/"
echo ""