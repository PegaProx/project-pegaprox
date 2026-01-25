#!/bin/bash
# ============================================================================
# PegaProx Deployment Script
# Tested on: Debian 13, Ubuntu 22.04/24.04 LTS
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              PegaProx Deployment Script                      ║"
echo "║                    Version 1.0                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./deploy.sh)${NC}"
    exit 1
fi

# Configuration
INSTALL_DIR="/opt/PegaProx"
SERVICE_USER="pegaprox"
SERVICE_GROUP="pegaprox"
PEGAPROX_PORT=5000
PYTHON_FILE="pegaprox_multi_cluster.py"

# Parse arguments
SKIP_USER=false
SKIP_SERVICE=false
for arg in "$@"; do
    case $arg in
        --skip-user) SKIP_USER=true ;;
        --skip-service) SKIP_SERVICE=true ;;
        --port=*) PEGAPROX_PORT="${arg#*=}" ;;
        --help|-h)
            echo "Usage: ./deploy.sh [options]"
            echo ""
            echo "Options:"
            echo "  --skip-user      Don't create pegaprox user"
            echo "  --skip-service   Don't create systemd service"
            echo "  --port=PORT      Set default port (default: 5000)"
            echo "  --help, -h       Show this help"
            exit 0
            ;;
    esac
done

# ============================================================================
# Step 1: System Update & Dependencies
# ============================================================================
echo -e "\n${YELLOW}[1/6] Installing system dependencies...${NC}"

apt-get update -qq
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    git \
    openssl \
    sshpass \
    > /dev/null

echo -e "${GREEN}✓ System dependencies installed${NC}"

# ============================================================================
# Step 2: Create User
# ============================================================================
if [ "$SKIP_USER" = false ]; then
    echo -e "\n${YELLOW}[2/6] Creating service user...${NC}"
    
    if id "$SERVICE_USER" &>/dev/null; then
        echo -e "${GREEN}✓ User '$SERVICE_USER' already exists${NC}"
    else
        useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
        echo -e "${GREEN}✓ User '$SERVICE_USER' created${NC}"
    fi
else
    echo -e "\n${YELLOW}[2/6] Skipping user creation${NC}"
fi

# ============================================================================
# Step 3: Create Installation Directory
# ============================================================================
echo -e "\n${YELLOW}[3/6] Setting up installation directory...${NC}"

mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/config"
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/ssl"
mkdir -p "$INSTALL_DIR/static"
mkdir -p "$INSTALL_DIR/web"
mkdir -p "$INSTALL_DIR/images"

echo -e "${GREEN}✓ Directory structure created at $INSTALL_DIR${NC}"

# ============================================================================
# Step 4: Install Python Dependencies
# ============================================================================
echo -e "\n${YELLOW}[4/6] Installing Python dependencies...${NC}"

pip3 install --break-system-packages -q \
    flask>=2.3.0 \
    flask-cors>=4.0.0 \
    flask-sock>=0.6.0 \
    requests>=2.28.0 \
    urllib3>=1.26.0 \
    cryptography>=41.0.0 \
    pyopenssl>=23.0.0 \
    argon2-cffi>=23.0.0 \
    paramiko>=3.0.0 \
    websockets>=11.0 \
    websocket-client>=1.6.0 \
    gevent>=23.0.0 \
    gevent-websocket>=0.10.0 \
    pyotp>=2.9.0 \
    "qrcode[pil]>=7.4.0"

echo -e "${GREEN}✓ Python dependencies installed${NC}"

# ============================================================================
# Step 5: Copy Files (placeholder - user copies manually)
# ============================================================================
echo -e "\n${YELLOW}[5/6] Preparing for file deployment...${NC}"

cat > "$INSTALL_DIR/README.txt" << EOF
PegaProx Installation Directory
================================

Copy your files here:
  - $PYTHON_FILE   (Backend)
  - web/index.html         (Frontend)

Start manually:
  cd $INSTALL_DIR
  python3 $PYTHON_FILE

Or use the systemd service:
  systemctl start pegaprox
  systemctl enable pegaprox  # Auto-start on boot
EOF

echo -e "${GREEN}✓ Directory prepared - copy $PYTHON_FILE and web/index.html here${NC}"

# ============================================================================
# Step 6: Create Systemd Service
# ============================================================================
if [ "$SKIP_SERVICE" = false ]; then
    echo -e "\n${YELLOW}[6/6] Creating systemd service...${NC}"
    
    cat > /etc/systemd/system/pegaprox.service << EOF
[Unit]
Description=PegaProx - Proxmox Cluster Management
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/$PYTHON_FILE
Restart=always
RestartSec=5
Environment=PEGAPROX_PORT=$PEGAPROX_PORT

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pegaprox

[Install]
WantedBy=multi-user.target
EOF

    # Set permissions
    if [ "$SKIP_USER" = false ]; then
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    fi
    
    systemctl daemon-reload
    
    echo -e "${GREEN}✓ Systemd service created${NC}"
else
    echo -e "\n${YELLOW}[6/6] Skipping service creation${NC}"
    
    if [ "$SKIP_USER" = false ]; then
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    fi
fi

# ============================================================================
# Done!
# ============================================================================
echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}              ${GREEN}Installation Complete!${NC}                         ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}Next steps:${NC}"
echo -e "  1. Copy your files to $INSTALL_DIR:"
echo -e "     ${BLUE}cp $PYTHON_FILE $INSTALL_DIR/${NC}"
echo -e "     ${BLUE}cp index.html $INSTALL_DIR/web/${NC}"
echo ""
echo -e "  2. (Optional) Download static files for offline mode:"
echo -e "     ${BLUE}cd $INSTALL_DIR && python3 $PYTHON_FILE --download-static${NC}"
echo ""
echo -e "  3. Start PegaProx:"
echo -e "     ${BLUE}systemctl start pegaprox${NC}"
echo -e "     ${BLUE}systemctl enable pegaprox${NC}  # Auto-start on boot"
echo ""
echo -e "  4. Access the web interface:"
echo -e "     ${BLUE}https://$(hostname -I | awk '{print $1}'):$PEGAPROX_PORT${NC}"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo -e "  Status:   ${BLUE}systemctl status pegaprox${NC}"
echo -e "  Logs:     ${BLUE}journalctl -u pegaprox -f${NC}"
echo -e "  Restart:  ${BLUE}systemctl restart pegaprox${NC}"
echo ""