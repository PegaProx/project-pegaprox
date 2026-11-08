#!/usr/bin/env bash
# Runs inside a fresh debian:trixie container for the smoke test of apt-repo.yml.
#
#   smoke-install.sh <pegaprox version the build job made>
#
# Adds the repository the build job signed with a throwaway key (served on
# 127.0.0.1:8079, key in /smoke/key.asc) next to Debian's own trixie sources, installs
# pegaprox with the lines the README gives users, and checks what it got. Nothing else
# is configured: every dependency has to come from trixie or from that repository.
# The workflow boots the resulting tree with systemd-nspawn afterwards.
#
# NS Oct 2026
set -euo pipefail

want=${1:?expected pegaprox version}
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
# what a Debian host has anyway: the postinst enables the unit with systemctl, and the
# tree is booted with systemd next
apt-get install -y -q --no-install-recommends systemd systemd-sysv dbus </dev/null

install -d -m 0755 /etc/apt/keyrings
install -m 0644 /smoke/key.asc /etc/apt/keyrings/pegaprox.asc
echo "deb [signed-by=/etc/apt/keyrings/pegaprox.asc] http://127.0.0.1:8079 trixie main" \
  > /etc/apt/sources.list.d/pegaprox.list
apt-get update -q
apt-get install -y -q pegaprox </dev/null

apt-cache policy pegaprox python3-flask-sock python3-xenapi
got=$(dpkg-query -W -f '${Version}' pegaprox)
[ "$got" = "$want" ] || { echo "smoke: pegaprox $got is installed, the build made $want" >&2; exit 1; }
for pkg in python3-flask-sock python3-xenapi; do
  dpkg-query -W -f '${Package} ${Version} ${db:Status-Status}\n' "$pkg"
done

echo "--- the modules the package depends on, and the optional ones"
python3 -I -B /smoke/deb_imports.py

# nothing above may have left bytecode in the package tree (python3 -B, and the
# service runs as a user that cannot write there). find stops at the first one by itself:
# piped into grep -q, a long list got find a SIGPIPE, pipefail made the pipe fail and the
# check passed on exactly the tree it is there for
if [ -n "$(find /usr/lib/pegaprox -name __pycache__ -print -quit)" ]; then
  echo "smoke: __pycache__ under /usr/lib/pegaprox after the install" >&2
  exit 1
fi
systemctl is-enabled pegaprox.service
