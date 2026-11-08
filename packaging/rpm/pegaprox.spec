Version:        0.6.6
Name:		pegaprox
Release:        1%{?dist}
Summary:        Multi-cluster Proxmox VE management dashboard

License:        AGPL-3.0-only
URL:            https://github.com/PegaProx/project-pegaprox
Source0:        %{name}-%{version}.tar.xz

BuildArch:      noarch
BuildRequires:  python3-devel

# Runtime dependencies (system python packages)
Requires:       python3
Requires:       python3-flask
Requires:       python3-flask-cors
Requires:       python3-requests
Requires:       python3-cryptography
Requires:       python3-argon2-cffi
Requires:       python3-pyotp
Requires:       python3-qrcode
Requires:       python3-pyOpenSSL

#Custom Build Python Package
Requires:       python3-backports-zstd
Requires:       python3-flask-compress
Requires:       python3-flask-cors
Requires:       python3-flask-sock
Requires:       python3-qrcode
Requires:       python3-simple-websocket
Requires:       python3-wsproto
Requires:       python3-pypng

# Optional (if available in EPEL)
Requires:       python3-gevent
Requires:       python3-websockets
Requires:       python3-paramiko

%description
PegaProx is a web-based multi-cluster management interface for
Proxmox VE clusters. It provides unified dashboards, VM management,
load balancing, migration features, and role-based access control.

%prep
%autosetup

%build
# Nothing to compile
true

%install
rm -rf %{buildroot}

# Application directory
install -d %{buildroot}%{_libexecdir}/pegaprox

# Copy source files
cp -a * %{buildroot}%{_libexecdir}/pegaprox/

# Create executable wrapper
install -d %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/pegaprox << 'EOF'
#!/bin/bash
exec /usr/bin/python3 /usr/libexec/pegaprox/pegaprox_multi_cluster.py "$@"
EOF
chmod 0755 %{buildroot}%{_bindir}/pegaprox

# Systemd service
install -d %{buildroot}%{_unitdir}
cat > %{buildroot}%{_unitdir}/pegaprox.service << 'EOF'
[Unit]
Description=PegaProx Multi-Cluster Management Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/libexec/pegaprox/pegaprox_multi_cluster.py
WorkingDirectory=/usr/libexec/pegaprox
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

%files
%license LICENSE
%doc README.md
%{_libexecdir}/pegaprox
%{_bindir}/pegaprox
%{_unitdir}/pegaprox.service

%post
%systemd_post pegaprox.service

%preun
%systemd_preun pegaprox.service

%postun
%systemd_postun_with_restart pegaprox.service

%changelog
* Mon Feb 23 2026 Zakir Hossain <zakirpcs@gmail.com> - 0.6.6-1
- Initial RPM build for RHEL 9
