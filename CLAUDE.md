# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PegaProx is a web-based management interface for Proxmox VE and XCP-ng clusters. It provides unified multi-cluster management with live monitoring, VM management, automated tasks, security hardening, cross-hypervisor migration, and site recovery.

- **License:** AGPL-3.0
- **Python:** 3.8+ (Docker uses 3.12-slim)
- **Frontend:** React + JSX (compiled via Babel)

## Running Locally

```bash
pip install -r requirements.txt
python3 pegaprox_multi_cluster.py
```

Ports: 5000 (web UI + API), 5001 (VNC console), 5002 (SSH shell).

Environment variables: `PEGAPROX_PORT`, `PEGAPROX_NO_GEVENT`, `PEGAPROX_BEHIND_PROXY`, `PEGAPROX_API_RATE_LIMIT`, `PEGAPROX_API_RATE_WINDOW`. See `constants.py` for all options.

## Frontend Build

**After any change to `web/src/*.js`, you must rebuild:**

```bash
cd web/Dev && ./build.sh
```

This concatenates 17 JSX source files in dependency order, compiles with Babel, and inlines into `web/index.html`. The compiled `web/index.html` is what gets deployed.

- `./build.sh --restore` switches to dev mode (browser-side Babel, slower but hot-editable)
- Requires Node.js 16+
- Source files live in `web/src/`, the HTML shell is `web/index.html.original`

Source file dependency order (defined in build.sh):
constants.js -> translations.js -> contexts.js -> auth.js -> icons.js -> ui.js -> datacenter.js -> security.js -> storage.js -> networking.js -> tables.js -> vm_modals.js -> vm_config.js -> node_modals.js -> create_modals.js -> settings_modal.js -> dashboard.js

## Architecture

```
Entry point: pegaprox_multi_cluster.py (gevent monkey-patch, then Flask)

pegaprox/
├── app.py              # Flask app factory, middleware, SSL, CORS
├── constants.py        # Config constants (no pegaprox imports - safe to import anywhere)
├── globals.py          # Global mutable state containers
├── api/                # REST API blueprints (auth, vms, clusters, nodes, storage, etc.)
├── core/               # Business logic
│   ├── manager.py      # PegaProxManager - main cluster operations (largest file)
│   ├── db.py           # SQLite + AES-256-GCM encryption
│   ├── v2p.py          # VMware-to-Proxmox migration
│   ├── xcpng.py        # XCP-ng hypervisor integration
│   ├── xhm.py          # Cross-hypervisor migration
│   └── vmware.py       # VMware/ESXi integration
├── background/         # Background threads (scheduler, alerts, metrics, broadcast)
├── utils/              # Auth, RBAC, LDAP, OIDC, SSH, audit, sanitization
└── models/             # Permission schemas, task definitions

web/
├── src/                # 17 JSX source files (edit these)
├── index.html          # Compiled production output (do not edit directly)
├── index.html.original # HTML shell template
└── Dev/
    └── build.sh        # JSX pre-compiler

static/                 # Vendored client libraries (React, Babel, Chart.js, xterm, noVNC)
config/                 # Runtime data (SQLite DB, encrypted users, audit logs, scheduled tasks)
plugins/                # Plugin system (see plugins/hello_world for example)
```

## Key Architectural Patterns

- **Gevent monkey-patching** is applied at startup and MUST remain the first import. Do not move or reorganize imports above it in `pegaprox_multi_cluster.py`.
- **No ORM** - direct SQLite with AES-256-GCM encryption for credentials via `core/db.py`.
- **Three WebSocket servers** on separate ports: Flask-Sock (5000), noVNC (5001), SSH/xterm (5002).
- **In-memory sessions** protected by `threading.Lock`.
- **Background threads** for broadcasting, alerts, scheduling, cross-cluster load balancing, and site recovery.
- **Proxmox API** is accessed via a custom HTTP client (no official SDK).
- The frontend is a single-page app using vendored React/Tailwind (no npm/webpack in production). Static assets in `static/` enable offline/air-gapped deployments.

## Dev Team Initials in Comments

Code comments are tagged with developer initials: NS (Nico Schmidt, Lead), MK (Marcus Kellermann, Backend), LW (Laura Weber, Frontend).

## Testing

No formal test framework. Testing is manual + Docker CI builds via GitHub Actions (`.github/workflows/docker.yml`).

## Deployment

- **Docker:** `docker compose up -d` (multi-arch: amd64, arm64, pushes to ghcr.io/pegaprox/pegaprox)
- **Debian:** `dpkg-buildpackage -us -uc` (packaging in `debian/`)
- **Bare metal:** `deploy.sh` (automated installer for Debian/Ubuntu)
- **Updates:** `update.sh` (archive-based in-place update)
- **Systemd:** service files in `systemd/`
