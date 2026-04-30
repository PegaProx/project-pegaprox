<p align="center">
  <img src="https://pegaprox.com/pictures/pegaprox-logo.png" alt="PegaProx Logo" width="200"/>
</p>

<h1 align="center">PegaProx</h1>

<p align="center">
  <strong>Modern Multi-Cluster Management for Proxmox VE & XCP-ng</strong>
</p>

<p align="center">
  <a href="https://pegaprox.com">Website</a> •
  <a href="https://docs.pegaprox.com">Documentation</a> •
  <a href="https://github.com/PegaProx/project-pegaprox/releases">Releases</a> •
  <a href="https://opencollective.com/pegaprox">Sponsoring</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.9.8.2--beta-blue" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.8+-green" alt="Python"/>
  <img src="https://img.shields.io/badge/license-AGPL--3.0--License-orange" alt="License"/>
</p>
---

## 🚀 What is PegaProx?

PegaProx is a powerful web-based management interface for Proxmox VE and XCP-ng clusters. Manage multiple clusters from a single dashboard with features like live monitoring, VM management, automated tasks, and more.

<p align="center">
  <img src="https://pegaprox.com/pictures/pegaprox.png" alt="Dashboard Screenshot" width="800"/>
</p>

## ❤️ Sponsors

### 💎 Platinum

<p align="center">
  <a href="https://www.netwolk.ch">
    <img src="images/sponsors/sponsor2.png" alt="netwolk GmbH" width="200"/>
  </a>
</p>

### 🥇 Gold

<p align="center">
  <a href="https://socialfurr.com">
    <img src="images/sponsors/sponsor1.png" alt="SocialFurr" width="120"/>
  </a>
</p>

### 🥈 Silver

<p align="center">
  <a href="https://uvensys.de/">
    <img src="images/sponsors/uvensys.png" alt="uvensys GmbH" width="160"/>
  </a>
</p>

### 🥉 Bronze

<p align="center">
  <a href="https://idkmanager.com/">
    <img src="images/sponsors/idkmanager.png" alt="IDK Manager" width="120"/>
  </a>
</p>

<p align="center">
  <a href="mailto:sponsor@pegaprox.com">Become a Sponsor</a> •
  <a href="https://opencollective.com/pegaprox">Open Collective</a>
</p>

## ✨ Features

### Multi-Cluster Management
- 🖥️ **Unified Dashboard** - Manage all your Proxmox clusters from one place
- 📊 **Live Metrics** - Real-time CPU, RAM, and storage monitoring via SSE
- 🔄 **Live Migration** - Migrate VMs between nodes with one click
- ⚖️ **Cross-Cluster Load Balancing** - Distribute workloads across clusters
- 🔄 **Cross-Hypervisor Migration** - Migrate VMs between ESXi, Proxmox VE, and XCP-ng 

### VM & Container Management
- ▶️ **Quick Actions** - Start, stop, restart VMs and containers
- ⚙️ **VM Configuration** - Edit CPU, RAM, disks, network, EFI, Secure Boot & more
- 📸 **Snapshots** - Standard and space-efficient LVM snapshots for shared storage
- 🔁 **Snapshot Replication** - Storage-agnostic replication for clusters without ZFS
- 💾 **Backups** - Schedule and manage backups
- ✅ **Backup Verification** *(Experimental)* - Automated restore → boot → health check → cleanup (ISO 27001, SOC 2, HIPAA compliance)
- 🖱️ **noVNC / xterm.js Console** - Browser-based console for QEMU and LXC
- ⚖️ **Load Balancing** - Automatic VM distribution across nodes
- 🔁 **High Availability** - Auto-restart VMs on node failure with configurable timing
- 📍 **Affinity Rules** - Keep VMs together or apart on hosts (QEMU + LXC)

### XCP-ng Integration (Tech Preview)
- 🟢 **XCP-ng Pool Support** - Connect XCP-ng / Xen hypervisor pools alongside Proxmox clusters
- ▶️ **VM Power Actions** - Start, stop, shutdown, reboot, suspend/resume
- 🖥️ **VNC Console** - Browser-based remote console via XAPI
- 💽 **Disk & Network Management** - Add, resize, remove disks and NICs
- 🔧 **Maintenance Mode** - Enter/exit with automatic VM evacuation

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
- 🔍 **CVE Scanner** - Per-node package vulnerability scanning via debsecan
- 🛡️ **CIS Hardening** - One-click security audit and hardening against CIS benchmarks

### Automation & Monitoring
- ⏰ **Scheduled Tasks** - Automate VM actions (start, stop, snapshot, backup)
- 🔄 **Rolling Node Updates** - Update cluster nodes one by one with automatic evacuation
- 🚨 **Alerts** - Get notified on high CPU, memory, or disk usage
- 📜 **Audit Logging** - Track all user actions with IP addresses
- 🔧 **Custom Scripts** - Run scripts across nodes
- 💿 **Ceph Management** - Monitor and manage Ceph storage pools, RBD mirroring
- 🔐 **ACME / Let's Encrypt** - Automatic SSL certificate renewal with HTTP-01 challenge (+ custom ACME CAs)
- 📋 **Integrated Syslog Server** - Receive and view syslog messages (UDP/TCP) with filtering, search, and severity-based coloring

### Plugins
- 🌐 **Client Portal** - Self-service portal for hosting customers with VM power actions, noVNC console, snapshots, 2FA, and password management
- 📊 **Public Status Page** - Cluster health dashboard for monitoring screens with URL-based auth key (no login required)
- 🔌 **Plugin Config Editor** - Edit plugin configuration directly from the UI

### Advanced Features
- 🌐 **Offline Mode** - Works without internet (local assets)
- 🎨 **Themes** - Dark mode, Proxmox theme, and more
- 🏢 **Corporate Layout** - Tree-based sidebar with dense tables
- 🌍 **Multi-Language** - English, German, French, Spanish, Portuguese, Korean, Italian
- 📱 **Responsive** - Works on desktop and mobile
- 📦 **PBS Integration** - Proxmox Backup Server management with backup verification

## 📋 Requirements

- Python 3.8+
- Proxmox VE 8.0+ or 9.0+ and/or XCP-ng 8.2+
- Modern web browser (Chrome, Firefox, Edge, Safari)

## ⚡ Quick Start / Installation

### Automated Installation
This installation method pulls the deployment script directly from the current HEAD of the main branch. This means you will always receive the latest available version, including the most recent features and improvements. However, because it is not tied to a specific release, it may also contain unreleased changes or bugs that have not yet been fully tested. If you prefer a stable and tested version, consider installing PegaProx from a tagged release instead.

```bash
curl -O https://raw.githubusercontent.com/PegaProx/project-pegaprox/refs/heads/main/deploy.sh
chmod +x deploy.sh
sudo ./deploy.sh
```

### Debian Repository
This installation method uses the official APT repository provided by gyptazy. The repository and its associated build and packaging pipeline are fully hosted and maintained by <a href="https://github.com/gyptazy">gyptazy</a>, where PegaProx releases are automatically built and published as Debian packages. Unlike the automated installation script, which pulls the latest code directly from the repository branch, the APT repository distributes packaged and versioned releases. This generally provides a more stable and predictable installation, making it the recommended approach for production environments.
```bash
curl https://git.gyptazy.com/api/packages/gyptazy/debian/repository.key -o /etc/apt/keyrings/gyptazy.asc
echo "deb [signed-by=/etc/apt/keyrings/gyptazy.asc] https://packages.gyptazy.com/api/packages/gyptazy/debian trixie main" | sudo tee -a /etc/apt/sources.list.d/gyptazy.list
apt-get update

apt-get -y install pegaprox
```

## Installation from Source
This installation methods run PegaProx directly from the source code repository. It is primarily intended for development, testing, or advanced users who want full control over the codebase or want to modify and extend the project.

By default, cloning the repository will pull the latest state of the main branch, which contains the most recent changes and features. While this ensures you always have the newest code available, it may also include in-progress changes that are not part of an official release yet.
If you prefer a more stable version, you can optionally checkout a specific release tag from the repository before installing dependencies and starting the application. This allows you to run the exact code corresponding to an official release while still using the source-based installation method.

Running PegaProx from source can be useful for debugging, contributing to the project, or integrating custom functionality, since you have direct access to the entire codebase and can easily update it using standard Git workflows.

### Manual Installation
```bash
git clone https://github.com/PegaProx/project-pegaprox.git
cd project-pegaprox
pip install -r requirements.txt
python3 pegaprox_multi_cluster.py
```

### Docker
```bash
docker compose up -d
```

Or without Compose:
```bash
docker run -d --name pegaprox \
  -p 5000:5000 -p 5001:5001 -p 5002:5002 \
  -v pegaprox-config:/app/config \
  -v pegaprox-logs:/app/logs \
  --restart unless-stopped \
  ghcr.io/pegaprox/pegaprox:latest
```

For local builds:
```bash
git clone https://github.com/PegaProx/project-pegaprox.git
cd project-pegaprox
docker build -t pegaprox .
docker run -d --name pegaprox \
  -p 5000:5000 -p 5001:5001 -p 5002:5002 \
  -v pegaprox-config:/app/config \
  -v pegaprox-logs:/app/logs \
  --restart unless-stopped \
  pegaprox
```

### Debian Package (.deb build)
```bash
git clone https://github.com/PegaProx/project-pegaprox.git
cd project-pegaprox

dpkg-buildpackage -us -uc
sudo dpkg -i ../pegaprox_*.deb
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

- 💬 Discord: [Community Server](https://discord.gg/AJPf3H62QW)
- 📧 Email: support@pegaprox.com
- 🐛 Issues: [GitHub Issues](https://github.com/PegaProx/project-pegaprox/issues)

## 🤖 Development Tools

Like most modern dev teams, we use AI-assisted tooling (code completion, docs generation, review automation, security audits). All architecture decisions, implementation, and testing are handled by our three-person team. — see [IBM](https://www.ibm.com/solutions/ai-coding) , [IBM Case Studies](https://www.ibm.com/case-studies/ibm-software-team) , [MIT Tech Review](https://www.technologyreview.com/2025/12/15/1128352/rise-of-ai-coding-developers-2026/)

AI-driven security auditing is an industry-standard practice — see [Hacker News](https://thehackernews.com/2026/02/claude-opus-46-finds-500-high-severity.html), [IBM Research](https://www.ibm.com/think/insights/chatgpt-4-exploits-87-percent-one-day-vulnerabilities).

## ⭐ Star History

If you find PegaProx useful, please consider giving it a star! ⭐

---

<p align="center">
  Made with ❤️ by the PegaProx Team
</p>
