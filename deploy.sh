#!/bin/bash
# ============================================================================
# PegaProx Deploy Script - All-in-One Installation v2.0
# Downloads, installs, and starts PegaProx on any Linux system
#
# Usage: curl -sSL https://raw.githubusercontent.com/.../deploy.sh | sudo bash
#    or: sudo ./deploy.sh
#    or: sudo ./deploy.sh --port=443 --no-interactive
#
# Tested on: Debian 12/13, Ubuntu 22.04/24.04 LTS
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
INSTALL_DIR="/opt/PegaProx"
SERVICE_USER="pegaprox"
SERVICE_GROUP="pegaprox"
GITHUB_REPO="https://github.com/PegaProx/project-pegaprox.git"
PYTHON_FILE="pegaprox_multi_cluster.py"

# Default options
ACCESS_PORT=5000
INTERACTIVE=true
DOWNLOAD_OFFLINE=true

# ============================================================================
# Parse Arguments
# ============================================================================
for arg in "$@"; do
    case $arg in
        --port=*)
            ACCESS_PORT="${arg#*=}"
            ;;
        --no-interactive)
            INTERACTIVE=false
            ;;
        --no-offline)
            DOWNLOAD_OFFLINE=false
            ;;
        --help|-h)
            echo "PegaProx Deploy Script"
            echo ""
            echo "Usage: sudo ./deploy.sh [options]"
            echo ""
            echo "Options:"
            echo "  --port=PORT       Set web port (default: 5000, use 443 for HTTPS)"
            echo "  --no-interactive  Skip interactive prompts"
            echo "  --no-offline      Skip offline assets download"
            echo "  --help            Show this help"
            echo ""
            echo "Examples:"
            echo "  sudo ./deploy.sh                     # Interactive install"
            echo "  sudo ./deploy.sh --port=443          # Use port 443"
            echo "  sudo ./deploy.sh --no-interactive    # Non-interactive with defaults"
            exit 0
            ;;
    esac
done

# ============================================================================
# Helper Functions
# ============================================================================
print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                           ║"
    echo "║   ██████╗ ███████╗ ██████╗  █████╗ ██████╗ ██████╗  ██████╗ ██╗  ██╗     ║"
    echo "║   ██╔══██╗██╔════╝██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝     ║"
    echo "║   ██████╔╝█████╗  ██║  ███╗███████║██████╔╝██████╔╝██║   ██║ ╚███╔╝      ║"
    echo "║   ██╔═══╝ ██╔══╝  ██║   ██║██╔══██║██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗      ║"
    echo "║   ██║     ███████╗╚██████╔╝██║  ██║██║     ██║  ██║╚██████╔╝██╔╝ ██╗     ║"
    echo "║   ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝     ║"
    echo "║                                                                           ║"
    echo "║                    All-in-One Deploy Script v2.0                          ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}\n"
}

print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_info() { echo -e "${CYAN}ℹ${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }

# ============================================================================
# Main Installation
# ============================================================================
main() {
    print_banner

    # Check root
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root: sudo $0"
        exit 1
    fi

    # Check internet
    if ! ping -c 1 github.com &>/dev/null; then
        print_error "No internet connection. Cannot download PegaProx."
        exit 1
    fi

    # =========================================================================
    # Step 1: System Dependencies
    # =========================================================================
    print_step "Step 1/6: Installing System Dependencies"

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq

    print_info "Installing packages..."
    apt-get install -y -qq python3 python3-pip python3-venv curl wget git openssl \
        sshpass ca-certificates sudo sqlite3 > /dev/null 2>&1

    print_success "System dependencies installed"

    # =========================================================================
    # Step 2: Create User & Directories
    # =========================================================================
    print_step "Step 2/6: Creating User & Directories"

    # Service user (system user - no login)
    if id "$SERVICE_USER" &>/dev/null; then
        print_info "Service user '$SERVICE_USER' already exists"
    else
        useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
        print_success "Service user '$SERVICE_USER' created"
    fi

    mkdir -p "$INSTALL_DIR"/{config,logs,ssl,static,web,images,backups}
    print_success "Directory structure created"

    # =========================================================================
    # Step 3: Download PegaProx from GitHub
    # =========================================================================
    print_step "Step 3/6: Downloading PegaProx from GitHub"

    # NS: feb 2026 - detect if running from a checkout that already has the files
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"

    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$PYTHON_FILE" ] && [ -d "$SCRIPT_DIR/pegaprox" ]; then
        # Running from existing checkout - copy directly instead of cloning
        print_info "Found local installation files in $SCRIPT_DIR"

        if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
            cp "$SCRIPT_DIR/$PYTHON_FILE" "$INSTALL_DIR/"
            cp -r "$SCRIPT_DIR/pegaprox" "$INSTALL_DIR/"
            [ -d "$SCRIPT_DIR/web" ] && cp -r "$SCRIPT_DIR/web/"* "$INSTALL_DIR/web/" 2>/dev/null || true
            [ -d "$SCRIPT_DIR/images" ] && cp -r "$SCRIPT_DIR/images/"* "$INSTALL_DIR/images/" 2>/dev/null || true
            [ -d "$SCRIPT_DIR/static" ] && cp -r "$SCRIPT_DIR/static/"* "$INSTALL_DIR/static/" 2>/dev/null || true
            [ -f "$SCRIPT_DIR/version.json" ] && cp "$SCRIPT_DIR/version.json" "$INSTALL_DIR/"
            [ -f "$SCRIPT_DIR/requirements.txt" ] && cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
            [ -f "$SCRIPT_DIR/update.sh" ] && cp "$SCRIPT_DIR/update.sh" "$INSTALL_DIR/"
            [ -f "$SCRIPT_DIR/deploy.sh" ] && cp "$SCRIPT_DIR/deploy.sh" "$INSTALL_DIR/"
        fi

        print_success "Files copied from local checkout"
    else
        # Download from GitHub
        TEMP_DIR=$(mktemp -d)
        print_info "Cloning repository..."

        if git clone --depth 1 --quiet "$GITHUB_REPO" "$TEMP_DIR/pegaprox" 2>/dev/null; then
            print_success "Repository cloned"

            # Copy ALL files from repo
            cp -r "$TEMP_DIR/pegaprox/"* "$INSTALL_DIR/" 2>/dev/null || true

            # Move index.html to web folder if exists in root
            [ -f "$INSTALL_DIR/index.html" ] && mv "$INSTALL_DIR/index.html" "$INSTALL_DIR/web/" 2>/dev/null || true

            # Remove git folder
            rm -rf "$INSTALL_DIR/.git" 2>/dev/null || true

            print_success "All files copied to $INSTALL_DIR"
        else
            print_error "Failed to clone repository"
            rm -rf "$TEMP_DIR"
            exit 1
        fi

        rm -rf "$TEMP_DIR"
    fi

    # Make scripts executable
    chmod +x "$INSTALL_DIR/deploy.sh" "$INSTALL_DIR/update.sh" 2>/dev/null || true

    # =========================================================================
    # Step 4: Python Virtual Environment & Dependencies
    # =========================================================================
    print_step "Step 4/6: Setting up Python Environment"

    # Python version sanity. We test against 3.10–3.13. 3.14 is too new for
    # parts of our stack (gevent, websockets, pyvmomi may have edge cases the
    # ecosystem hasn't worked through yet — issue #388 had a Python 3.14
    # report where the SSH WebSocket subprocess couldn't bind cleanly). 3.9
    # and earlier hit the urllib3/cryptography floor in requirements.txt.
    PYTHON_BIN="python3"
    PY_VER=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)
    if [ -z "$PY_VER" ]; then
        echo -e "${RED}python3 is not callable. Install it first: apt-get install python3 python3-venv${NC}"
        exit 1
    fi
    print_info "Detected Python: $PY_VER"
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [ "$PY_MAJOR" -ne 3 ]; then
        echo -e "${RED}Unsupported Python major version: $PY_VER. PegaProx requires Python 3.10–3.13.${NC}"
        exit 1
    fi
    if [ "$PY_MINOR" -lt 10 ]; then
        echo -e "${RED}Python $PY_VER is too old. Minimum supported: 3.10. Recommended: 3.12.${NC}"
        echo -e "${RED}Older versions hit the urllib3 / cryptography floors in requirements.txt.${NC}"
        exit 1
    fi
    if [ "$PY_MINOR" -ge 14 ]; then
        echo -e "${YELLOW}WARNING: Python $PY_VER is newer than what PegaProx is tested on (3.10–3.13).${NC}"
        echo -e "${YELLOW}Known issue on 3.14: SSH/VNC WebSocket subprocesses may fail to bind${NC}"
        echo -e "${YELLOW}cleanly (issue #388). If you hit a console-not-working bug, downgrade to${NC}"
        echo -e "${YELLOW}python3.12 (Ubuntu 24.04 default) or python3.13 and run deploy.sh again.${NC}"
        if [ -t 0 ] && [ -z "$DEPLOY_FORCE_PY" ]; then
            read -r -p "Continue anyway? [y/N] " _ans
            case "$_ans" in
                y|Y|yes|YES) ;;
                *) echo "Aborted. Set DEPLOY_FORCE_PY=1 to skip this prompt in non-interactive runs."; exit 1 ;;
            esac
        else
            print_info "Non-interactive run or DEPLOY_FORCE_PY set — proceeding on $PY_VER."
        fi
    fi

    print_info "Creating virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"

    print_info "Installing Python packages..."
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q 2>/dev/null

    # Use requirements.txt from repo if exists
    if [ -f "$INSTALL_DIR/requirements.txt" ]; then
        print_info "Installing from requirements.txt..."
        "$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt" 2>/dev/null
    else
        # Fallback to hardcoded list
        print_info "No requirements.txt found, using defaults..."
        "$INSTALL_DIR/venv/bin/pip" install -q \
            flask flask-cors flask-sock flask-compress \
            requests urllib3 cryptography pyopenssl \
            argon2-cffi paramiko websockets websocket-client \
            gevent gevent-websocket pyotp "qrcode[pil]" pyvmomi 2>/dev/null
    fi

    print_success "Python environment ready"

    # =========================================================================
    # Step 5: Download Offline Assets (Optional)
    # =========================================================================
    if [ "$DOWNLOAD_OFFLINE" = true ]; then
        print_step "Step 5/6: Downloading Offline Assets"

        cd "$INSTALL_DIR"
        print_info "Downloading static files for offline mode..."

        if "$INSTALL_DIR/venv/bin/python" "$PYTHON_FILE" --download-static 2>&1 | while read line; do echo -n "."; done; then
            echo ""
            print_success "Offline assets downloaded"
        else
            echo ""
            print_warning "Some assets may have failed (non-critical)"
        fi
    else
        print_step "Step 5/6: Skipping Offline Assets"
        print_info "Use --download-static later if needed"
    fi

    # =========================================================================
    # Step 6: Configure & Start Service
    # =========================================================================
    print_step "Step 6/6: Configuring Service"

    # Interactive port selection
    if [ "$INTERACTIVE" = true ]; then
        echo -e "${YELLOW}Select access port:${NC}"
        echo "  1) Default (5000) - Standard ports"
        echo "  2) HTTPS (443)    - Professional setup"
        echo "  3) Custom         - Enter your own"
        echo ""

        while true; do
            read -p "Choice [1-3, default=1]: " PORT_CHOICE < /dev/tty
            case "${PORT_CHOICE:-1}" in
                1)
                    ACCESS_PORT=5000
                    break
                    ;;
                2)
                    ACCESS_PORT=443
                    break
                    ;;
                3)
                    read -p "Enter port (1-65535): " CUSTOM_PORT < /dev/tty
                    if [[ "$CUSTOM_PORT" =~ ^[0-9]+$ ]] && [ "$CUSTOM_PORT" -ge 1 ] && [ "$CUSTOM_PORT" -le 65535 ]; then
                        ACCESS_PORT=$CUSTOM_PORT
                        break
                    else
                        echo -e "${RED}Invalid port${NC}"
                    fi
                    ;;
                *)
                    echo "Please enter 1, 2, or 3"
                    ;;
            esac
        done
    fi

    echo -e "${GREEN}✓ Using ports: $ACCESS_PORT (Web), $((ACCESS_PORT+1)) (VNC), $((ACCESS_PORT+2)) (SSH)${NC}"
    [ "$ACCESS_PORT" -lt 1024 ] && echo -e "${CYAN}  (privileged ports via CAP_NET_BIND_SERVICE)${NC}"

    # Create systemd service
    cat > /etc/systemd/system/pegaprox.service << EOF
[Unit]
Description=PegaProx - Proxmox Cluster Management
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$INSTALL_DIR

# Custom PATH for wrappers
Environment=PATH=$INSTALL_DIR/bin:/usr/local/bin:/usr/bin:/bin

ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/$PYTHON_FILE
Restart=always
RestartSec=5

# Allow binding to privileged ports (443, 80)
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Minimal security
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pegaprox

[Install]
WantedBy=multi-user.target
EOF

    # Create wrapper scripts for auto-update
    mkdir -p "$INSTALL_DIR/bin"

    # systemctl wrapper
    cat > "$INSTALL_DIR/bin/systemctl" << 'WRAPPEREOF'
#!/bin/bash
# Intelligent systemctl wrapper for PegaProx auto-update
if [ "$1" = "sudo" ]; then
    shift
fi
case "$*" in
    *pegaprox*)
        exec /usr/bin/sudo /usr/bin/systemctl "$@"
        ;;
    *)
        exec /usr/bin/systemctl "$@"
        ;;
esac
WRAPPEREOF
    chmod 755 "$INSTALL_DIR/bin/systemctl"

    # sudo wrapper
    cat > "$INSTALL_DIR/bin/sudo" << 'SUDOWRAPPER'
#!/bin/bash
# Sudo wrapper - prevents double sudo
if [ "$1" = "sudo" ]; then
    shift
fi
exec /usr/bin/sudo "$@"
SUDOWRAPPER
    chmod 755 "$INSTALL_DIR/bin/sudo"

    # Create sudoers rules
    cat > /etc/sudoers.d/pegaprox << EOF
# PegaProx service management (for auto-update)
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart pegaprox
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart pegaprox.service
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop pegaprox
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop pegaprox.service
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl start pegaprox
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl start pegaprox.service
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl status pegaprox
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl status pegaprox.service
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active pegaprox
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active pegaprox.service
EOF
    chmod 440 /etc/sudoers.d/pegaprox

    # Set ownership
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"

    # Harden sensitive dirs
    [ -d "$INSTALL_DIR/config" ] && chmod 700 "$INSTALL_DIR/config"
    [ -d "$INSTALL_DIR/ssl" ] && chmod 700 "$INSTALL_DIR/ssl"

    # MK May 2026 — master-key bootstrap (Tier-4: /etc/pegaprox/secret.key).
    # Fresh installs get the key OUTSIDE $INSTALL_DIR/config so a backup of the
    # config dir doesn't pick up the decryption key. Idempotent: only acts when
    # no key already exists (neither at the new location nor in the legacy spot).
    #
    # MK May 2026 (#417 / tgmct) — mode is 0640 (NOT 0600). File is owned by
    # root:$SERVICE_GROUP; the systemd unit runs as $SERVICE_USER which is in
    # $SERVICE_GROUP, so group-read is required to load the key at boot.
    # The previous 0600 root:pegaprox combo made the key unreadable to the
    # service and pegaprox.service failed to start on every fresh install.
    LEGACY_KEY="$INSTALL_DIR/config/.pegaprox.key"
    SYS_KEY_DIR="/etc/pegaprox"
    SYS_KEY="$SYS_KEY_DIR/secret.key"

    if [ -f "$SYS_KEY" ]; then
        # Repair-on-upgrade: prior deploy.sh versions wrote 0600. Bump to 0640
        # so the systemd service can actually read its own key after upgrade.
        cur_mode=$(stat -c '%a' "$SYS_KEY" 2>/dev/null || echo "")
        if [ "$cur_mode" = "600" ] || [ "$cur_mode" = "400" ]; then
            print_info "Found $SYS_KEY at mode $cur_mode — bumping to 0640 (#417 repair)"
            chmod 640 "$SYS_KEY"
            chown "root:$SERVICE_GROUP" "$SYS_KEY" 2>/dev/null || true
        else
            print_info "Master key already at $SYS_KEY (mode $cur_mode) — leaving untouched"
        fi
    elif [ -f "$LEGACY_KEY" ]; then
        print_warning "Legacy key at $LEGACY_KEY detected"
        print_info "  PegaProx will keep using it but emit a deprecation warning."
        print_info "  Migrate with:  sudo mv \"$LEGACY_KEY\" \"$SYS_KEY\" && sudo chmod 640 \"$SYS_KEY\" && sudo chown root:$SERVICE_GROUP \"$SYS_KEY\""
    else
        # No key anywhere — generate the new default at the secure location.
        mkdir -p "$SYS_KEY_DIR"
        chmod 750 "$SYS_KEY_DIR"
        chown "root:$SERVICE_GROUP" "$SYS_KEY_DIR" 2>/dev/null || true

        # 32 raw bytes -> urlsafe-base64. Python is already a hard dep at this
        # point in the install so we don't need a bash-only fallback.
        if "$INSTALL_DIR/venv/bin/python3" -c "
import base64, os, secrets, sys
key = base64.urlsafe_b64encode(secrets.token_bytes(32))
fd = os.open('$SYS_KEY', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
try:
    os.write(fd, key)
finally:
    os.close(fd)
" 2>/dev/null; then
            chmod 640 "$SYS_KEY"
            chown "root:$SERVICE_GROUP" "$SYS_KEY" 2>/dev/null || \
                chown "root:root" "$SYS_KEY"
            print_success "Generated master key at $SYS_KEY (0640 root:$SERVICE_GROUP)"
            print_info "  Loader tier: 4 (system-service default — outside $INSTALL_DIR/config)"
            print_info "  Stronger: wrap with systemd-creds — see docs/SECURITY.md §5"
        else
            print_warning "Could not pre-generate $SYS_KEY — PegaProx will fall back to legacy path on first boot"
        fi
    fi

    # Enable and start service
    systemctl daemon-reload
    systemctl enable pegaprox
    systemctl start pegaprox

    print_success "Systemd service created and started"

    # Wait for database initialization
    echo "Waiting for database initialization..."
    sleep 8

    # Set port in database if not default
    if [ "$ACCESS_PORT" != 5000 ]; then
        print_info "Configuring port $ACCESS_PORT..."
        PEGAPROX_DB="$INSTALL_DIR/config/pegaprox.db"

        if [ -f "$PEGAPROX_DB" ]; then
            sqlite3 "$PEGAPROX_DB" "INSERT OR REPLACE INTO server_settings (key, value) VALUES ('port', '$ACCESS_PORT');" 2>/dev/null && {
                echo "Restarting with new port..."
                systemctl restart pegaprox
                sleep 5
                print_success "Port set to $ACCESS_PORT"
            } || print_warning "Set port manually in Settings > Server"
        fi
    fi

    # Check if running
    if systemctl is-active --quiet pegaprox; then
        print_success "PegaProx is running!"
    else
        print_error "PegaProx failed to start - check: journalctl -u pegaprox"
    fi

    # =========================================================================
    # Done!
    # =========================================================================
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Installation Complete! 🎉                               ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Get current IP
    CURRENT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -z "$CURRENT_IP" ] && CURRENT_IP="<your-ip>"

    if [ "$ACCESS_PORT" = 443 ]; then
        echo -e "  Web Interface: ${CYAN}${BOLD}https://${CURRENT_IP}${NC}"
        echo -e "  VNC WebSocket: ${CYAN}https://${CURRENT_IP}:444${NC}"
        echo -e "  SSH WebSocket: ${CYAN}https://${CURRENT_IP}:445${NC}"
    else
        echo -e "  Web Interface: ${CYAN}${BOLD}https://${CURRENT_IP}:${ACCESS_PORT}${NC}"
        echo -e "  VNC WebSocket: ${CYAN}https://${CURRENT_IP}:$((ACCESS_PORT+1))${NC}"
        echo -e "  SSH WebSocket: ${CYAN}https://${CURRENT_IP}:$((ACCESS_PORT+2))${NC}"
    fi

    echo ""
    echo -e "${YELLOW}💡 Tip: Check for updates in PegaProx Web UI${NC}"
    echo -e "   Settings → Updates → Check for Updates"
    echo ""
    echo -e "Commands:"
    echo -e "  ${CYAN}systemctl status pegaprox${NC}    - Check status"
    echo -e "  ${CYAN}journalctl -u pegaprox -f${NC}    - View logs"
    echo -e "  ${CYAN}systemctl restart pegaprox${NC}   - Restart service"
    echo ""
}

main "$@"
