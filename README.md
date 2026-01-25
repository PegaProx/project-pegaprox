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
  <img src="https://img.shields.io/badge/version-0.5.1-blue" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.8+-green" alt="Python"/>
  <img src="https://img.shields.io/badge/license-AGPL-3.0-License-orange" alt="License"/>
</p>

---

## 🚀 What is PegaProx?

PegaProx is a powerful web-based management interface for Proxmox VE clusters. Manage multiple clusters from a single dashboard with features like live monitoring, VM management, automated tasks, and more.

<p align="center">
  <img src="https://pegaprox.com/screenshots/dashboard.png" alt="Dashboard Screenshot" width="800"/>
</p>

## ✨ Features

### Multi-Cluster Management
- 🖥️ **Unified Dashboard** - Manage all your Proxmox clusters from one place
- 📊 **Live Metrics** - Real-time CPU, RAM, and storage monitoring
- 🔄 **Live Migration** - Migrate VMs between nodes with one click

### VM & Container Management
- ▶️ **Quick Actions** - Start, stop, restart VMs and containers
- 📸 **Snapshots** - Create and restore snapshots
- 💾 **Backups** - Schedule and manage backups
- 🖱️ **noVNC Console** - Direct browser-based console access
- ⚖️ **Load Balancing** - Automatic VM distribution across nodes
- 🔁 **High Availability** - Auto-restart VMs on node failure
- 📍 **Affinity Rules** - Keep VMs together or apart on hosts

### Security & Access Control
- 👥 **Multi-User Support** - Role-based access control (Admin, Operator, Viewer)
- 🔐 **2FA Authentication** - TOTP-based two-factor authentication
- 🛡️ **VM-Level ACLs** - Fine-grained permissions per VM
- 🏢 **Multi-Tenancy** - Isolate clusters for different customers

### Automation & Monitoring
- ⏰ **Scheduled Tasks** - Automate VM actions (start, stop, snapshot, backup)
- 🚨 **Alerts** - Get notified on high CPU, memory, or disk usage
- 📜 **Audit Logging** - Track all user actions
- 🔧 **Custom Scripts** - Run scripts across nodes

### Advanced Features
- 🌐 **Offline Mode** - Works without internet (local assets)
- 🎨 **Themes** - Dark mode, Proxmox theme, and more
- 🌍 **Multi-Language** - English and German language support
- 📱 **Responsive** - Works on desktop and mobile

## 📋 Requirements

- Python 3.8+
- Proxmox VE 8.0+ or 9.0+
- Modern web browser (Chrome, Firefox, Edge, Safari)

## ⚡ Quick Start

### Option 1: Semi Automated Installation

```bash
# Download the project
git clone https://github.com/PegaProx/project-pegaprox.git
cd project-pegaprox

# Run the deployment script
sudo ./deploy.sh

# Copy the application files
sudo cp pegaprox_multi_cluster.py /opt/PegaProx/
sudo cp web/index.html /opt/PegaProx/web/

# Fix permissions
sudo chown -R pegaprox:pegaprox /opt/PegaProx

# (Optional) Download static files for offline mode
sudo -u pegaprox bash -c "cd /opt/PegaProx && ./venv/bin/python3 pegaprox_multi_cluster.py --download-static"

# Start the service
sudo systemctl start pegaprox
sudo systemctl enable pegaprox

```

### Option 2: Manual Installation

```bash
# Clone the repository
git clone https://github.com/PegaProx/project-pegaprox.git
cd project-pegaprox

# Install dependencies
pip install -r requirements.txt

# Run PegaProx
python3 pegaprox_multi_cluster.py
```


## Updating to v0.6.1

**Option 1: Update Script (Recommended)**
```bash
#Download it
curl -O https://raw.githubusercontent.com/PegaProx/project-pegaprox/refs/heads/main/update.sh

#Permissions
chmod +x update.sh

#Execute
./update.sh
```

**Option 2: Manual**
```bash
curl -O https://raw.githubusercontent.com/PegaProx/project-pegaprox/main/pegaprox_multi_cluster.py
curl -O web/index.html https://raw.githubusercontent.com/PegaProx/project-pegaprox/main/web/index.html
curl -O https://raw.githubusercontent.com/PegaProx/project-pegaprox/main/requirements.txt

# Install dependencies (choose one):
pip3 install -r requirements.txt                # System Python
./venv/bin/python -m pip install -r requirements.txt      # Virtual environment
Can also work with: ./venv/bin/pip install -r requirements.txt 

sudo systemctl restart pegaprox
```

### What's New in v0.6.1
- Fixed Force Stop for LXC containers
- Fixed Web Updater
- Fixed pagination error in pre-compiled builds ([#4](https://github.com/PegaProx/project-pegaprox/issues/4))
- Added `update.sh` for easy updates
- Added `build.sh` for JSX pre-compilation (devs only)

## 🔧 Configuration

After starting PegaProx, open your browser and navigate to:

```
https://your-server-ip:5000
```

Please use the following default credentials for the first login:

```
Username: pegaprox
Password: admin
```

Afterwards, please proceed with the following steps:

1. **First Login**: Create your admin account on the setup page
2. **Add Cluster**: Go to Settings → Clusters → Add your Proxmox credentials
3. **Done!** Start managing your VMs

## 📁 Directory Structure

```
/opt/PegaProx/
├── pegaprox_multi_cluster.py   # Main application
├── web/
│   └── index.html              # Frontend
├── config/
│   ├── pegaprox.db             # SQLite database (encrypted)
│   └── ssl/                    # SSL certificates
├── logs/                       # Application logs
└── static/                     # Offline assets (optional)
```

## 🔒 Security Notes

- All data is encrypted with AES-256-GCM
- Passwords are hashed with Argon2id
- HTTPS is required for production use
- Session tokens expire after inactivity
- Rate limiting protects against brute force

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
