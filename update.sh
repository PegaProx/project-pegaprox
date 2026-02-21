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
# Note: Safe to run as root - automatically preserves original file ownership
#
# MK: Created 25.01.2026 - the web updater was buggy, this is more reliable
# MK: Updated it on 26.01
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

# MK: Figure out who owns this installation
# We check config/ because that folder never gets overwritten by updates
# Learned this the hard way when everything became root:root...
ORIGINAL_OWNER=""
if [ -d "config" ]; then
    ORIGINAL_OWNER=$(stat -c '%U:%G' config 2>/dev/null || stat -f '%Su:%Sg' config 2>/dev/null)
elif [ -f "cert.pem" ]; then
    ORIGINAL_OWNER=$(stat -c '%U:%G' cert.pem 2>/dev/null || stat -f '%Su:%Sg' cert.pem 2>/dev/null)
elif [ -d "ssl" ]; then
    ORIGINAL_OWNER=$(stat -c '%U:%G' ssl 2>/dev/null || stat -f '%Su:%Sg' ssl 2>/dev/null)
fi

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║               PegaProx Update Script                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${BLUE}Running as root${NC}"
    if [ -n "$ORIGINAL_OWNER" ]; then
        echo -e "  Will restore ownership to: ${GREEN}$ORIGINAL_OWNER${NC}"
    fi
    echo ""
else
    echo -e "${YELLOW}Tip: sudo ./update.sh for auto service restart${NC}"
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
[ -f "web/index.html.original" ] && cp web/index.html.original "$BACKUP_DIR/web/"
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
chmod +x deploy.sh update.sh 2>/dev/null || true
chmod +x web/Dev/build.sh 2>/dev/null || true

# Fix ownership if running as root
# otherwise the service user can't read the files and everything breaks
if [ "$EUID" -eq 0 ] && [ -n "$ORIGINAL_OWNER" ] && [ "$ORIGINAL_OWNER" != "root:root" ]; then
    echo -n "Fixing file ownership ($ORIGINAL_OWNER)... "
    chown "$ORIGINAL_OWNER" pegaprox_multi_cluster.py version.json requirements.txt 2>/dev/null
    chown "$ORIGINAL_OWNER" deploy.sh update.sh 2>/dev/null
    chown "$ORIGINAL_OWNER" web/index.html web/index.html.original 2>/dev/null
    chown -R "$ORIGINAL_OWNER" web/Dev/ 2>/dev/null
    chown -R "$ORIGINAL_OWNER" backups/ 2>/dev/null
    echo -e "${GREEN}OK${NC}"
fi

# Restore restrictive permissions on config and ssl directories.
# These must be 0700 so that only the service user can read the encrypted
# database and SSL private keys. An update that runs as root via sudo can
# inadvertently leave them world-readable if umask is permissive.
if [ -d "config" ]; then
    chmod 700 config 2>/dev/null || true
fi
if [ -d "config/ssl" ]; then
    chmod 700 config/ssl 2>/dev/null || true
elif [ -d "ssl" ]; then
    chmod 700 ssl 2>/dev/null || true
fi

# Install/update Python packages
echo ""
echo -n "Installing Python packages... "

# Try different pip methods - everyone has a different setup lol
PIP_SUCCESS=false

# venv with python -m pip (the "proper" way)
if [ -f "venv/bin/python" ] && [ "$PIP_SUCCESS" = false ]; then
    ./venv/bin/python -m pip install -q -r requirements.txt 2>/dev/null && PIP_SUCCESS=true
fi

# venv with direct pip
if [ -f "venv/bin/pip" ] && [ "$PIP_SUCCESS" = false ]; then
    ./venv/bin/pip install -q -r requirements.txt 2>/dev/null && PIP_SUCCESS=true
fi

# system pip as root
if [ "$EUID" -eq 0 ] && command -v pip3 &> /dev/null && [ "$PIP_SUCCESS" = false ]; then
    pip3 install -q -r requirements.txt 2>/dev/null && PIP_SUCCESS=true
fi

# system pip with --user (non-root)
if command -v pip3 &> /dev/null && [ "$PIP_SUCCESS" = false ]; then
    pip3 install -q --user -r requirements.txt 2>/dev/null && PIP_SUCCESS=true
fi

# last resort: python3 -m pip
if command -v python3 &> /dev/null && [ "$PIP_SUCCESS" = false ]; then
    python3 -m pip install -q --user -r requirements.txt 2>/dev/null && PIP_SUCCESS=true
fi

if [ "$PIP_SUCCESS" = true ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}Couldn't install - run: pip install -r requirements.txt${NC}"
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
