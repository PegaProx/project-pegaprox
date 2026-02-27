<p align="center">
  <img src="https://pegaprox.com/pictures/pegaprox-logo.png" alt="PegaProx Logo" width="200"/>
</p>

<h1 align="center">PegaProx</h1>

<p align="center">
  <strong>Modern Multi-Cluster Management for Proxmox VE</strong>
</p>

<p align="center">
  <a href="https://pegaprox.com">Website</a> •
  <a href="https://docs.pegaprox.com">Documentation</a> •
  <a href="https://github.com/PegaProx/project-pegaprox/releases">Releases</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.9.0.2-blue" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.8+-green" alt="Python"/>
  <img src="https://img.shields.io/badge/license-AGPL--3.0--License-orange" alt="License"/>
</p>

---

## 🚀 What is PegaProx?

PegaProx is a powerful web-based management interface for Proxmox VE clusters. Manage multiple clusters from a single dashboard with features like live monitoring, VM management, automated tasks, and more.

<p align="center">
  <img src="https://pegaprox.com/pictures/pegaprox.png" alt="Dashboard Screenshot" width="800"/>
</p>

## ✨ Features

### Multi-Cluster Management
- 🖥️ **Unified Dashboard** - Manage all your Proxmox clusters from one place
- 📊 **Live Metrics** - Real-time CPU, RAM, and storage monitoring via SSE
- 🔄 **Live Migration** - Migrate VMs between nodes with one click
- ⚖️ **Cross-Cluster Load Balancing** - Distribute workloads across clusters

### VM & Container Management
- ▶️ **Quick Actions** - Start, stop, restart VMs and containers
- ⚙️ **VM Configuration** - Edit CPU, RAM, disks, network, EFI, Secure Boot & more
- 📸 **Snapshots** - Standard and space-efficient LVM snapshots for shared storage
- 💾 **Backups** - Schedule and manage backups
- 🖱️ **noVNC / xterm.js Console** - Browser-based console for QEMU and LXC
- ⚖️ **Load Balancing** - Automatic VM distribution across nodes
- 🔁 **High Availability** - Auto-restart VMs on node failure with configurable timing
- 📍 **Affinity Rules** - Keep VMs together or apart on hosts (QEMU + LXC)

### ESXi Migration
- 🔀 **ESXi Import Wizard** - Migrate VMs from ESXi hosts to Proxmox
- ⚡ **Near-Zero Downtime** - Transfer running VMs with minimal interruption (max. 1 VM recommended)
- 🔌 **Offline Migration** - Shut down and transfer for maximum reliability
- 🔑 **SSH Required** - ESXi host must have SSH enabled

### Security & Access Control
- 👥 **Multi-User Support** - Role-based access control (Admin, Operator, Viewer)
- 🛠️ **API Token Management** - Create, list, and revoke Bearer tokens
- 🔐 **2FA Authentication** - TOTP-based two-factor authentication (with force option)
- 🏛️ **LDAP / OIDC** - Active Directory, OpenLDAP, Entra ID, Keycloak, Google Workspace
- 🛡️ **VM-Level ACLs** - Fine-grained permissions per VM
- 🏢 **Multi-Tenancy** - Isolate clusters for different customers
- 🚫 **IP Whitelisting / Blacklisting** - Restrict access by IP or CIDR range
- 🔒 **AES-256-GCM Encryption** - All stored credentials encrypted at rest

### Automation & Monitoring
- ⏰ **Scheduled Tasks** - Automate VM actions (start, stop, snapshot, backup)
- 🔄 **Rolling Node Updates** - Update cluster nodes one by one with automatic evacuation
- 🚨 **Alerts** - Get notified on high CPU, memory, or disk usage
- 📜 **Audit Logging** - Track all user actions with IP addresses
- 🔧 **Custom Scripts** - Run scripts across nodes
- 💿 **Ceph Management** - Monitor and manage Ceph storage pools

### Advanced Features
- 🌐 **Offline Mode** - Works without internet (local assets)
- 🎨 **Themes** - Dark mode, Proxmox theme, and more
- 🏢 **Corporate Layout** - Tree-based sidebar with dense tables (experimental)
- 🌍 **Multi-Language** - English and German
- 📱 **Responsive** - Works on desktop and mobile
- 📦 **PBS Integration** - Proxmox Backup Server management

## 📋 Requirements

- Python 3.8+
- Proxmox VE 8.0+ or 9.0+
- Modern web browser (Chrome, Firefox, Edge, Safari)

## ⚡ Quick Start

### Option 1: Automated Installation

```bash
curl -O https://raw.githubusercontent.com/PegaProx/project-pegaprox/refs/heads/main/deploy.sh
chmod +x deploy.sh
sudo ./deploy.sh
```

### Option 2: Manual Installation

```bash
git clone https://github.com/PegaProx/project-pegaprox.git
cd project-pegaprox
pip install -r requirements.txt
python3 pegaprox_multi_cluster.py
```

### Option 3: Docker

```bash
git clone https://github.com/PegaProx/project-pegaprox.git
cd project-pegaprox

# Production
docker build -t pegaprox .
docker run -d --name pegaprox \
  -p 5000:5000 \
  -v pegaprox-config:/app/config \
  -v pegaprox-logs:/app/logs \
  --restart unless-stopped \
  pegaprox

# Development
docker run -p 5000:5000 pegaprox --debug
```

## 🔄 Updating

**Option 1: Update Script (Recommended)**
```bash
cd /opt/PegaProx
curl -O https://raw.githubusercontent.com/PegaProx/project-pegaprox/refs/heads/main/update.sh
chmod +x update.sh
sudo ./update.sh
```

**Option 2: Web UI**

Go to Settings → Updates and click "Check for Updates".

## 🔧 Configuration

After starting PegaProx, open your browser and navigate to:

```
https://your-server-ip:5000
```

Default credentials:

```
Username: pegaprox
Password: admin
```

1. **First Login**: Create your admin account on the setup page
2. **Add Cluster**: Go to Settings → Clusters → Add your Proxmox credentials
3. **Done!** Start managing your VMs

## 📁 Directory Structure

```
/opt/PegaProx/
├── pegaprox_multi_cluster.py   # Entry point
├── pegaprox/                   # Application package
│   ├── app.py                  # Flask app factory
│   ├── constants.py            # Configuration constants
│   ├── globals.py              # Shared state
│   ├── api/                    # REST API blueprints
│   ├── core/                   # Business logic (manager, db, cache)
│   ├── background/             # Background tasks (scheduler, alerts)
│   ├── utils/                  # Utilities (auth, RBAC, LDAP, OIDC)
│   └── models/                 # Data models
├── web/
│   ├── index.html              # Compiled frontend
│   └── src/                    # Frontend source (JSX)
├── config/
│   └── pegaprox.db             # SQLite database (credentials encrypted)
├── static/                     # JS/CSS libraries (offline mode)
├── logs/                       # Application logs
└── update.sh                   # Update script
```

## 🔒 Security

- Credentials (Cluster PW, SSH Keys, TOTP, LDAP Bind) → AES-256-GCM
- API Tokens → SHA-256 Hash
- Passwords → Argon2id
- HTTPS required for production
- Session tokens expire after inactivity
- Rate limiting on all endpoints
- Input sanitization and RBAC enforcement

## 📖 Documentation

Full documentation is available at **[docs.pegaprox.com](https://docs.pegaprox.com)**

## 📜 License

This project is licensed under the AGPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

- 📧 Email: support@pegaprox.com
- 🐛 Issues: [GitHub Issues](https://github.com/PegaProx/project-pegaprox/issues)

## ⭐ Star History

If you find PegaProx useful, please consider giving it a star! ⭐

---

<p align="center">
  Made with ❤️ by the PegaProx Team
</p>
