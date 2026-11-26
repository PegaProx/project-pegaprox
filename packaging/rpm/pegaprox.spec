Version:        1.5.1
Name:		pegaprox
Release:        1%{?dist}
Summary:        Multi-cluster Proxmox VE management dashboard

License:        AGPL-3.0-only
URL:            https://github.com/PegaProx/project-pegaprox
Source0:        %{name}-%{version}.tar.xz

BuildArch:      noarch
BuildRequires:  python3-devel

# Runtime dependencies (system python packages)
# NS Nov 2026 - one for every module PegaProx imports, the set debian/control depends on.
# packaging/apt/deb_imports.py maps the modules, tests/test_rpm_spec_requires.py holds this
# list to it. Names as in Fedora; on RHEL 9, EPEL has the ones the base lacks.
Requires:       python3
Requires:       python3-flask
Requires:       python3-werkzeug
Requires:       python3-requests
Requires:       python3-requests-toolbelt
Requires:       python3-urllib3
Requires:       python3-dns
Requires:       python3-cryptography
Requires:       python3-argon2-cffi
# NS Nov 2026 - 2.8.0 is the first PyJWT whose PyJWKClient takes lifespan and ssl_context
# (utils/oidc.py); with EPEL 9's 2.4.0 every OIDC sign-in is refused. requirements.txt asks
# 2.15.1 (no JWKS redirect followed before 2.14.0), which no released Fedora or EPEL has yet
Requires:       python3-jwt >= 2.8.0
Requires:       python3-pyotp
Requires:       python3-pyOpenSSL
Requires:       python3-pillow
Requires:       python3-ldap3
Requires:       python3-websocket-client
Requires:       python3-greenlet
Requires:       python3-defusedxml
Requires:       python3-pyvmomi

#Custom Build Python Package
# gevent-websocket, XenAPI and sqlcipher3 are in neither Fedora nor EPEL; the apt repo builds
# the last two (and flask-sock) from PyPI the same way (packaging/apt/build-python-debs.py).
# No sqlcipher here: nothing runs that CLI, and python3-sqlcipher3 brings its own SQLCipher
# (the wheel has it built in; a build from source links the system library, and rpmbuild
# adds that Requires by itself)
Requires:       python3-backports-zstd
Requires:       python3-flask-compress
Requires:       python3-flask-cors
Requires:       python3-flask-sock
Requires:       python3-qrcode
Requires:       python3-simple-websocket
Requires:       python3-wsproto
Requires:       python3-pypng
Requires:       python3-gevent-websocket
Requires:       python3-xenapi
Requires:       python3-sqlcipher3

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

# The QNetd helper and its installer, root-owned in /usr/lib/pegaprox/qnetd as on Debian.
# No sudo rule: PegaProx runs as root under this unit (docs/qdevice.md)
install -d %{buildroot}%{_prefix}/lib/pegaprox/qnetd
install -m 0755 packaging/qnetd/pegaprox-qnetd-helper %{buildroot}%{_prefix}/lib/pegaprox/qnetd/pegaprox-qnetd-helper
install -m 0755 packaging/qnetd/install.sh %{buildroot}%{_prefix}/lib/pegaprox/qnetd/install.sh

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
%dir %attr(0755,root,root) %{_prefix}/lib/pegaprox
%dir %attr(0755,root,root) %{_prefix}/lib/pegaprox/qnetd
%attr(0755,root,root) %{_prefix}/lib/pegaprox/qnetd/pegaprox-qnetd-helper
%attr(0755,root,root) %{_prefix}/lib/pegaprox/qnetd/install.sh

%post
%systemd_post pegaprox.service

%preun
%systemd_preun pegaprox.service

%postun
%systemd_postun_with_restart pegaprox.service

%changelog
* Thu Nov 26 2026 MrMasterbay <gamesucht1236@gmail.com> - 1.5.1-1
- Update to 1.5.1
- Require python3-jwt >= 2.8.0 and python3-websocket-client, both imported at
  runtime (OIDC token verification, the console and linked mode); an older
  PyJWT has no lifespan and ssl_context for its JWKS client
- Require every other module PegaProx imports, the same set as debian/control:
  python3-werkzeug, python3-requests-toolbelt, python3-urllib3, python3-dns,
  python3-greenlet, python3-pillow, python3-ldap3, python3-defusedxml,
  python3-pyvmomi and the locally built python3-gevent-websocket,
  python3-xenapi and python3-sqlcipher3
- Name python3-flask-cors and python3-qrcode once

* Mon Feb 23 2026 Zakir Hossain <zakirpcs@gmail.com> - 0.6.6-1
- Initial RPM build for RHEL 9
