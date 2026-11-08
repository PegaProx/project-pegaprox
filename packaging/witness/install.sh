#!/bin/sh
# PegaProx witness installer (#625) - NS Oct 2026
#
# Installs the witness of an automatic PegaProx group on this host: the third vote, at a
# third site, never on a host that runs PegaProx. Run it with the line "Add witness" on
# the leader's HA page shows: that line checks this file against the SHA-256 the leader
# worked out from its own copy before anything of it runs.
#
#   sh install.sh --code <code> [--url https://<this host>:5005] [--port 5005]
#                 [--allow <cidr>]... [--no-auto-update | --auto-update]
#   printf '%s\n' <code> | sh install.sh --code -     the code on stdin, as the lines do
#   sh install.sh                      paired already: repair, and update from the leader
#   sh install.sh --uninstall [--force]
#
# It installs python 3.9 or later with cryptography, gevent and requests from the system
# packages (what has none comes from PyPI into a virtualenv next to them), makes the user
# pegaprox-witness, fetches the witness code from the leader named in the code - TLS
# pinned to the fingerprint the code carries - into /opt/pegaprox-witness/<version> with
# a link 'current', and installs the command /usr/local/bin/pegaprox-witness (linked from
# /usr/bin, where sudo looks on RHEL) and the systemd unit. Then it pairs, starts the
# witness, checks that it answers at the address it paired with and says what to open in
# the firewall. Running it again repairs and updates, the
# start script included; the witness also updates itself from the leader (turn that off
# with --no-auto-update). A paired witness keeps its address: another --url or --port
# needs a new pairing. A new code on a host that is paired already pairs anew only once
# the old group let the witness go.
#
# For the tests: PEGAPROX_WITNESS_ROOT puts every path under another root,
# PEGAPROX_PORT is the port of a PegaProx instance it looks for on this host,
# PEGAPROX_WITNESS_WAIT how long it waits for the witness to answer.
set -eu
umask 022
# python runs as root below, and the directory this was started from may be anybody's
# (/tmp): every python call is isolated (-I, no cwd on sys.path), and the work is done in /
case $0 in
    /*) SELF=$0 ;;
    *) SELF="$(pwd)/$0" ;;
esac
cd /

ROOT=${PEGAPROX_WITNESS_ROOT:-}
OPT="$ROOT/opt/pegaprox-witness"
STATE="$ROOT/var/lib/pegaprox-witness"
BIN="$ROOT/usr/local/bin/pegaprox-witness"
# sudo on RHEL and its rebuilds looks in its secure_path only (/sbin:/bin:/usr/sbin:/usr/bin)
LINK="$ROOT/usr/bin/pegaprox-witness"
LINK_TO=../local/bin/pegaprox-witness
UNIT_DIR="$ROOT/etc/systemd/system"
UNIT="$UNIT_DIR/pegaprox-witness.service"
DROPIN="$UNIT_DIR/pegaprox-witness.service.d"
SVC=pegaprox-witness.service
USER_NAME=pegaprox-witness
APP_PORT=${PEGAPROX_PORT:-5000}
WAIT=${PEGAPROX_WITNESS_WAIT:-60}
MODULES="cryptography gevent requests"

CODE=
URL=
URL_AUTO=
PORT=
ALLOW=
AUTO=
UNINSTALL=
FORCE=
PY=
TMP=

say() { printf 'pegaprox-witness: %s\n' "$*"; }
die() { printf 'pegaprox-witness: %s\n' "$*" >&2; exit 1; }

usage() {
    # the comment at the head of this file
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$SELF"
}

need_value() {
    [ "$2" -ge 2 ] || die "$1 needs a value (see --help)"
}

while [ $# -gt 0 ]; do
    case $1 in
        --code) need_value "$1" $#; CODE=$2; shift 2 ;;
        --code=*) CODE=${1#*=}; shift ;;
        --url) need_value "$1" $#; URL=$2; shift 2 ;;
        --url=*) URL=${1#*=}; shift ;;
        --port) need_value "$1" $#; PORT=$2; shift 2 ;;
        --port=*) PORT=${1#*=}; shift ;;
        --allow) need_value "$1" $#; ALLOW="${ALLOW:+$ALLOW,}$2"; shift 2 ;;
        --allow=*) ALLOW="${ALLOW:+$ALLOW,}${1#*=}"; shift ;;
        --no-auto-update) AUTO=0; shift ;;
        --auto-update) AUTO=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        --force) FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

if [ "$CODE" = - ]; then
    # the code on stdin, as the lines of "Add witness" hand it over: on a command line any
    # user of this host reads it (ps) until it is spent, minutes later
    IFS= read -r CODE || [ -n "$CODE" ] || die "--code - reads the code from stdin, and there was none"
fi
# what goes into a file or a command line below is checked here, character by character
case $CODE in
    '') ;;
    pgxwt1_*) case ${CODE#pgxwt1_} in *[!A-Za-z0-9_-]*|'') die "the code is damaged - copy it again" ;; esac ;;
    *) die "this is not a PegaProx witness code (it starts with pgxwt1_)" ;;
esac
# (the address itself is checked by `pegaprox-witness join`, it only travels as an argument)
case $URL in
    ''|https://*) ;;
    *) die "--url takes https://host:port, the address the members reach this witness at" ;;
esac
case $PORT in
    '') ;;
    *[!0-9]*|0*) die "--port takes a number from 1 to 65535" ;;
    *) { [ ${#PORT} -le 5 ] && [ "$PORT" -le 65535 ]; } || die "--port takes a number from 1 to 65535" ;;
esac
case $ALLOW in
    *[!0-9A-Fa-f.:/,]*) die "--allow takes networks like 192.0.2.0/24 or 2001:db8::/48" ;;
esac

cleanup() { [ -z "$TMP" ] || rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 130' INT TERM

# --- this host ------------------------------------------------------------------------

need_root() {
    [ "$(id -u)" -eq 0 ] || die "run it as root (sudo sh install.sh ...)"
}

refuse_pegaprox_service() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet pegaprox.service 2>/dev/null; then
        die "PegaProx runs on this host (pegaprox.service is active). The witness belongs on a host of its own at a third site - next to a member, the vote of that site would count twice."
    fi
}

refuse_pegaprox_port() {
    # a PegaProx instance answers /api/health with its version, in a container too; asked
    # straight, never through a proxy of the environment
    if "$PY" -I - "$APP_PORT" <<'EOF'
import json, ssl, sys, urllib.request
for scheme in ('https', 'http'):
    try:
        ctx = ssl._create_unverified_context() if scheme == 'https' else None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=ctx))
        with opener.open(f'{scheme}://127.0.0.1:{sys.argv[1]}/api/health', timeout=3) as resp:
            data = json.loads(resp.read(4096) or b'{}')
        if isinstance(data, dict) and data.get('status') == 'ok' and 'version' in data:
            sys.exit(0)
    except Exception:
        pass
sys.exit(1)
EOF
    then
        die "PegaProx answers on port $APP_PORT of this host. The witness belongs on a host of its own at a third site - next to a member, the vote of that site would count twice."
    fi
}

pkg_install() {
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" >/dev/null 2>&1 || {
            DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
        }
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y "$@"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "$@"
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install "$@"
    else
        return 1
    fi
}

pkg_each() {
    # one package at a time where the package manager drops the whole transaction for one
    # name it does not find (dnf, yum, zypper: python3-gevent is only in EPEL on RHEL 9, and
    # cryptography and requests come from the distribution all the same); apt-get takes
    # them in one
    if command -v apt-get >/dev/null 2>&1; then
        pkg_install "$@"
        return
    fi
    each_rc=0
    for p in "$@"; do
        pkg_install "$p" || each_rc=1
    done
    return $each_rc
}

rhel_like() {
    # RHEL and its rebuilds, where EPEL is the place of what the distribution does not
    # carry (Fedora carries python3-gevent itself)
    { command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; } &&
        ! grep -qs '^ID="\{0,1\}fedora' /etc/os-release
}

missing_modules() {
    out=
    for mod in $MODULES; do
        "$PY" -I -c "import $mod" >/dev/null 2>&1 || out="$out $mod"
    done
    printf '%s' "$out"
}

find_python() {
    # python3 where it is 3.9 or later (the module packages of the system are its own),
    # else the newest python3.X next to it: RHEL 8 and openSUSE Leap 15 keep 3.6 as python3
    for name in python3 python3.13 python3.12 python3.11 python3.10 python3.9; do
        found=$(command -v "$name" 2>/dev/null) || continue
        if "$found" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
            printf '%s' "$found"
            return 0
        fi
    done
    return 1
}

newer_python() {
    # python3 is too old here and there is no newer one next to it: the distribution's
    # (python3.11 or python39 on RHEL 8 and its relatives, python311 or python39 on openSUSE)
    if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        mgr=yum
        if command -v dnf >/dev/null 2>&1; then mgr=dnf; fi
        for p in python3.11 python311 python39; do
            say "python3 is too old - installing $p next to it"
            "$mgr" install -y "$p" >/dev/null 2>&1 && return 0
        done
    elif command -v zypper >/dev/null 2>&1; then
        for p in python311 python39; do
            say "python3 is too old - installing $p next to it"
            zypper --non-interactive install "$p" >/dev/null 2>&1 && return 0
        done
    fi
    return 1
}

ensure_python() {
    if [ -x "$OPT/venv/bin/python3" ] && [ -z "$(PY=$OPT/venv/bin/python3 missing_modules)" ]; then
        # a virtualenv a run before made, because the system had no packages
        PY="$OPT/venv/bin/python3"
        return
    fi
    PY=$(find_python) || PY=
    if [ -z "$PY" ] && ! command -v python3 >/dev/null 2>&1; then
        say "installing python3"
        pkg_install python3 || true
        PY=$(find_python) || PY=
    fi
    if [ -z "$PY" ]; then
        newer_python || true
        PY=$(find_python) ||
            die "$(command -v python3 >/dev/null 2>&1 && python3 -V 2>&1 || echo 'python3 is missing') - the witness needs python 3.9 or later: install it (python3.11 or python39 of the distribution) and run this again"
    fi
    need=$(missing_modules)
    [ -n "$need" ] || return 0
    epel=
    case ${PY##*/} in
        python3)
            pkgs=
            for mod in $need; do pkgs="$pkgs python3-$mod"; done
            say "installing$pkgs"
            # shellcheck disable=SC2086
            pkg_each $pkgs || true
            case " $(missing_modules) " in
                *" gevent "*)
                    if rhel_like; then
                        # not enabled from here: a repository is the admin's to add
                        epel="python3-gevent is in EPEL: dnf install epel-release, then run this again"
                        say "$epel - until then gevent comes from PyPI"
                    fi
                    ;;
            esac
            ;;
        *)
            # a python next to the system's: its modules are packaged as python3.11-<module>
            # (RHEL 8) or python311-<module> (openSUSE, and python39 on RHEL 8), where at all
            v=${PY##*/python}
            say "installing what there is of$need for python$v"
            for mod in $need; do
                for pkg in "python$v-$mod" "python$(printf '%s' "$v" | tr -d .)-$mod"; do
                    pkg_install "$pkg" >/dev/null 2>&1 && break
                done
            done
            ;;
    esac
    need=$(missing_modules)
    [ -n "$need" ] || return 0
    say "no system packages for$need - using a virtualenv in $OPT/venv"
    mkdir -p "$OPT"
    # it sees the system's packages: only what has none comes from PyPI
    if ! "$PY" -I -m venv "$OPT/venv" --system-site-packages >/dev/null 2>&1; then
        pkg_install "${PY##*/}-venv" >/dev/null 2>&1 || true
        "$PY" -I -m venv "$OPT/venv" --system-site-packages || die "could not make a virtualenv (install ${PY##*/}-venv)"
    fi
    # shellcheck disable=SC2086
    "$OPT/venv/bin/python3" -I -m pip install --quiet $need ||
        die "could not install$need with pip - ${epel:-install them as system packages and run this again}"
    PY="$OPT/venv/bin/python3"
}

ensure_user() {
    if ! getent passwd "$USER_NAME" >/dev/null 2>&1; then
        shell=/bin/false
        for s in /usr/sbin/nologin /sbin/nologin; do
            if [ -x "$s" ]; then shell=$s; break; fi
        done
        useradd --system --user-group --home-dir /var/lib/pegaprox-witness --no-create-home \
            --shell "$shell" "$USER_NAME" || die "could not make the user $USER_NAME"
    fi
    mkdir -p "$STATE"
    chown "$USER_NAME:$USER_NAME" "$STATE"
    chmod 700 "$STATE"
}

is_paired() {
    # read as root by python itself: no code of the state directory runs as root
    [ -f "$STATE/ha_witness.json" ] && "$PY" -I - "$STATE/ha_witness.json" <<'EOF'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as fh:
        st = json.load(fh)
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(st, dict) and isinstance(st.get('cfg'), dict) and st.get('instance_id') else 1)
EOF
}

# --- the witness code, from the leader --------------------------------------------------

fetch_bundle() {
    # the bundle the leader serves to the holder of its open code; the pin in the code is
    # checked before the code is sent. Straight to the leader (http.client takes no proxy
    # of the environment), as the witness talks to its members later. The code goes in the
    # environment, which only root reads, never on a command line
    PEGAPROX_WITNESS_CODE=$CODE "$PY" -I - "$TMP" <<'EOF'
import base64, hashlib, http.client, io, json, os, ssl, sys, tarfile, urllib.parse
code, out = os.environ['PEGAPROX_WITNESS_CODE'], sys.argv[1]


def fail(text):
    print(f'pegaprox-witness: {text}', file=sys.stderr)
    sys.exit(1)


raw = code[len('pgxwt1_'):]
try:
    info = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))
    url, pin, key = str(info.get('u') or ''), str(info.get('f') or '').upper(), str(info.get('c') or '')
except Exception:
    fail('the code is damaged - copy it again')
parts = urllib.parse.urlsplit(url)
if parts.scheme != 'https' or not parts.hostname or not key:
    fail('the code carries no https:// address of the leader')
if pin:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
else:
    ctx = ssl.create_default_context()
conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=ctx, timeout=60)
try:
    conn.connect()
except (OSError, ssl.SSLError) as e:
    fail(f'cannot reach the leader at {url}: {e}')
if pin:
    got = ':'.join(f'{b:02X}' for b in hashlib.sha256(conn.sock.getpeercert(binary_form=True)).digest())
    if got != pin:
        fail(f'the certificate at {url} does not match the pin in the code - is this the leader?')
body = json.dumps({'code': key}).encode()
try:
    conn.request('POST', parts.path.rstrip('/') + '/api/ha/witness/bundle', body=body,
                 headers={'Content-Type': 'application/json', 'Accept': 'application/json',
                          'X-Requested-With': 'XMLHttpRequest'})
    resp = conn.getresponse()
    data = resp.read(16 * 1024 * 1024 + 1)
except (OSError, ssl.SSLError, http.client.HTTPException) as e:
    fail(f'the leader at {url} did not answer: {e}')
try:
    ans = json.loads(data)
except ValueError:
    ans = None
if resp.status == 403 and isinstance(ans, dict) and ans.get('error') == 'Access denied' and 'ip' in ans:
    # the IP allow list of the leader (Settings > Security), before the route saw the code
    import ipaddress
    try:
        ip = str(ipaddress.ip_address(str(ans.get('ip'))[:64]))
    except ValueError:
        ip = 'the address of this host'
    fail(f"the leader's IP allow list refuses this host - add {ip} there (Settings > Security on the leader), "
         'then run this line again (the code is good for 15 minutes from Add witness)')
if resp.status != 200 or not isinstance(ans, dict):
    why = ans.get('error') if isinstance(ans, dict) else None
    fail(f'the leader refused the witness code: {why or f"HTTP {resp.status}"}')
manifest = ans.get('manifest') if isinstance(ans.get('manifest'), dict) else {}
try:
    archive = base64.b64decode(ans.get('archive') or '', validate=True)
except ValueError:
    fail('the witness code from the leader is damaged')
if hashlib.sha256(archive).hexdigest() != manifest.get('sha256'):
    fail('the witness code from the leader does not match its digest')
with open(os.path.join(out, 'bundle.tar.gz'), 'wb') as fh:
    fh.write(archive)
with open(os.path.join(out, 'manifest.json'), 'w', encoding='utf-8') as fh:
    json.dump(manifest, fh)
# what checks and unpacks the rest comes out first
try:
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        member = tar.getmember('pegaprox/witness_boot.py')
        if not member.isreg() or member.size > 1024 * 1024:
            raise ValueError(member.name)
        with open(os.path.join(out, 'boot.py'), 'wb') as fh:
            fh.write(tar.extractfile(member).read())
except (KeyError, ValueError, tarfile.TarError) as e:
    fail(f'the witness code from the leader is incomplete ({e})')
print(manifest.get('release') or '?')
EOF
}

install_bundle() {
    mkdir -p "$OPT"
    chmod 755 "$OPT"
    "$PY" -I - "$TMP" "$OPT" <<'EOF'
import importlib.util, json, os, sys
tmp, opt = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location('witness_boot', os.path.join(tmp, 'boot.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
with open(os.path.join(tmp, 'bundle.tar.gz'), 'rb') as fh:
    archive = fh.read()
with open(os.path.join(tmp, 'manifest.json'), encoding='utf-8') as fh:
    manifest = json.load(fh)
try:
    path = boot.install_bundle(archive, manifest, opt)
except boot.BootError as e:
    print(f'pegaprox-witness: {e}', file=sys.stderr)
    sys.exit(1)
boot.switch(opt, os.path.basename(path))
boot.prune(opt)
print(os.path.basename(path))
EOF
}

# --- the command, the unit ------------------------------------------------------------

write_command() {
    cp "$OPT/current/pegaprox/witness_boot.py" "$OPT/boot.py.new"
    chmod 644 "$OPT/boot.py.new"
    mv -f "$OPT/boot.py.new" "$OPT/boot.py"
    # this file, for `pegaprox-witness uninstall`
    if [ -f "$SELF" ] && [ "$SELF" != "$OPT/install.sh" ]; then
        cp "$SELF" "$OPT/install.sh.new"
        chmod 644 "$OPT/install.sh.new"
        mv -f "$OPT/install.sh.new" "$OPT/install.sh"
    fi
    mkdir -p "$(dirname "$BIN")"
    # the port and the allow list as write_unit settled them: `pegaprox-witness health`
    # outside the unit checks the port the service listens on
    cat > "$BIN.new" <<EOF
#!/bin/sh
# PegaProx witness (#625) - written by packaging/witness/install.sh, again on each run of
# it. boot.py picks the code: the one installed here, or a newer one the witness fetched
# from its leader. As root it runs as $USER_NAME, the owner of the state directory.
PEGAPROX_WITNESS_BASE='$OPT/current'
PEGAPROX_WITNESS_DIR=\${PEGAPROX_WITNESS_DIR:-'$STATE'}
PEGAPROX_WITNESS_PORT=\${PEGAPROX_WITNESS_PORT:-'$PORT'}
PEGAPROX_WITNESS_ALLOW=\${PEGAPROX_WITNESS_ALLOW:-'$ALLOW'}
PEGAPROX_WITNESS_INSTALL=systemd
export PEGAPROX_WITNESS_BASE PEGAPROX_WITNESS_DIR PEGAPROX_WITNESS_PORT PEGAPROX_WITNESS_ALLOW PEGAPROX_WITNESS_INSTALL
if [ "\${1:-}" = uninstall ]; then
    shift
    exec sh '$OPT/install.sh' --uninstall "\$@"
fi
if [ "\${1:-}" = update ] && [ "\$(id -u)" -eq 0 ]; then
    # as root: and the service starts into what the update put in place, if anything
    before=\$(readlink "\$PEGAPROX_WITNESS_DIR/code/current" 2>/dev/null || true)
    '$PY' -I '$OPT/boot.py' "\$@" || exit \$?
    after=\$(readlink "\$PEGAPROX_WITNESS_DIR/code/current" 2>/dev/null || true)
    if [ "\$after" != "\$before" ] && [ -z "\${PEGAPROX_WITNESS_NO_RESTART:-}" ]; then
        systemctl try-restart $SVC
    fi
    exit 0
fi
exec '$PY' -I '$OPT/boot.py' "\$@"
EOF
    chmod 755 "$BIN.new"
    mv -f "$BIN.new" "$BIN"
    link_command
}

link_command() {
    # `sudo pegaprox-witness` finds the command where sudo's path has no /usr/local/bin;
    # a file of that name that is not this link stays as it is
    if [ -L "$LINK" ] && [ "$(readlink "$LINK")" = "$LINK_TO" ]; then
        return 0
    fi
    if [ -e "$LINK" ] || [ -L "$LINK" ]; then
        say "$LINK is there already and not the witness's - left as it is; where sudo does not find pegaprox-witness, call $BIN"
        return 0
    fi
    mkdir -p "$(dirname "$LINK")"
    ln -s "$LINK_TO" "$LINK" 2>/dev/null ||
        say "could not link $LINK - where sudo does not find pegaprox-witness, call $BIN"
}

setting() {
    # a setting the drop-in of an earlier run holds: Environment=NAME=value
    [ -f "$DROPIN/install.conf" ] || return 0
    sed -n "s/^Environment=$1=//p" "$DROPIN/install.conf" | tail -n 1
}

unit_text() {
    # systemd/pegaprox-witness.service, for a leader whose code bundle carries none (an
    # install from a checkout before deploy.sh copied it); a test keeps the two the same
    cat <<'EOF'
[Unit]
Description=PegaProx witness - the third vote of an automatic group
After=network-online.target
Wants=network-online.target
# MK Oct 2026 (#625): installed and enabled by packaging/witness/install.sh, which
# also makes the user, the command /usr/local/bin/pegaprox-witness and the pairing.
# It never runs next to a PegaProx instance on the same host: the vote of a site
# would count twice.
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=pegaprox-witness
Group=pegaprox-witness
StateDirectory=pegaprox-witness
StateDirectoryMode=0700
WorkingDirectory=/var/lib/pegaprox-witness
# Firewall the witness port so that only the networks of the members reach it.
# Where you cannot, name those networks with --allow (before `run`) or here:
#Environment=PEGAPROX_WITNESS_ALLOW=192.0.2.0/24,2001:db8:1::/48
# The installer writes PEGAPROX_WITNESS_AUTO_UPDATE=0 into a drop-in for --no-auto-update
ExecStart=/usr/local/bin/pegaprox-witness run

Restart=on-failure
RestartSec=5
# 75: it stopped to start into an update it fetched from the leader. 78: a setting
# that has to be fixed by hand, which starting again does not fix (code on trial
# stops with 1 instead, and the next start goes back to the code before it)
RestartForceExitStatus=75
SuccessExitStatus=75
RestartPreventExitStatus=78

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

StandardOutput=journal
StandardError=journal
SyslogIdentifier=pegaprox-witness

[Install]
WantedBy=multi-user.target
EOF
}

write_unit() {
    mkdir -p "$UNIT_DIR"
    if [ -f "$OPT/current/systemd/pegaprox-witness.service" ]; then
        cp "$OPT/current/systemd/pegaprox-witness.service" "$UNIT.new"
    else
        unit_text > "$UNIT.new"
    fi
    chmod 644 "$UNIT.new"
    mv -f "$UNIT.new" "$UNIT"
    # what was not given this time stays as the run before set it
    if [ -z "$AUTO" ]; then
        if [ "$(setting PEGAPROX_WITNESS_AUTO_UPDATE)" = 0 ]; then AUTO=0; else AUTO=1; fi
    fi
    [ -n "$ALLOW" ] || ALLOW=$(setting PEGAPROX_WITNESS_ALLOW)
    [ -n "$PORT" ] || PORT=$(setting PEGAPROX_WITNESS_PORT)
    [ -n "$PORT" ] || PORT=5005
    mkdir -p "$DROPIN"
    {
        echo '# written by packaging/witness/install.sh'
        echo '[Service]'
        if [ "$AUTO" = 0 ]; then echo 'Environment=PEGAPROX_WITNESS_AUTO_UPDATE=0'; fi
        if [ -n "$ALLOW" ]; then echo "Environment=PEGAPROX_WITNESS_ALLOW=$ALLOW"; fi
        if [ "$PORT" != 5005 ]; then echo "Environment=PEGAPROX_WITNESS_PORT=$PORT"; fi
    } > "$DROPIN/install.conf"
}

own_url() {
    # the address of this host towards the leader: what the members most likely reach
    PEGAPROX_WITNESS_CODE=$CODE "$PY" -I - "$PORT" <<'EOF'
import base64, json, os, socket, sys, urllib.parse
raw = os.environ['PEGAPROX_WITNESS_CODE'][len('pgxwt1_'):]
info = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))
parts = urllib.parse.urlsplit(info['u'])
family, _t, _p, _c, addr = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)[0]
with socket.socket(family, socket.SOCK_DGRAM) as s:
    s.connect(addr)
    me = s.getsockname()[0]
print(f'https://[{me}]:{sys.argv[1]}' if ':' in me else f'https://{me}:{sys.argv[1]}')
EOF
}

port_of() {
    # the port the https:// address $1 names, nothing where it names none
    "$PY" -I -c 'import sys, urllib.parse
try:
    print(urllib.parse.urlsplit(sys.argv[1]).port or "")
except ValueError:
    print("")' "$1"
}

same_url() {
    "$PY" -I -c 'import sys, urllib.parse
def key(url):
    p = urllib.parse.urlsplit(url.strip())
    return p.scheme.lower(), (p.hostname or "").lower(), p.port or 443, p.path.rstrip("/")
try:
    sys.exit(0 if key(sys.argv[1]) == key(sys.argv[2]) else 1)
except ValueError:
    sys.exit(1)' "$1" "$2"
}

url_family() {
    # 4 or 6 for an address of that family, "4 6" for a name, which may be either
    "$PY" -I -c 'import ipaddress, sys, urllib.parse
try:
    print(ipaddress.ip_address(urllib.parse.urlsplit(sys.argv[1]).hostname or "").version)
except ValueError:
    print("4 6")' "$1"
}

leader_host() {
    "$PY" -I - "$STATE/ha_witness.json" <<'EOF' 2>/dev/null || true
import json, sys, urllib.parse
with open(sys.argv[1], encoding='utf-8') as fh:
    print(urllib.parse.urlsplit((json.load(fh).get('paired') or {}).get('url') or '').hostname or '')
EOF
}

paired_url() {
    # the address the witness paired with, the one the members call
    "$PY" -I - "$STATE/ha_witness.json" <<'EOF' 2>/dev/null || true
import json, sys
with open(sys.argv[1], encoding='utf-8') as fh:
    print(json.load(fh).get('own_url') or '')
EOF
}

wait_for_it() {
    i=0
    while [ "$i" -lt "$WAIT" ]; do
        if "$BIN" status 2>/dev/null | "$PY" -I -c 'import json, sys; sys.exit(0 if json.load(sys.stdin).get("paired") else 1)' 2>/dev/null; then
            break
        fi
        sleep 2
        i=$((i + 2))
    done
    is_paired || die "the witness is not paired - see the lines above, and journalctl -u $SVC"
    i=0
    while [ "$i" -lt "$WAIT" ]; do
        if "$BIN" health >/dev/null 2>&1; then
            check_own_url
            return 0
        fi
        sleep 2
        i=$((i + 2))
    done
    say "it does not answer on port $PORT yet - look at: journalctl -u $SVC"
}

check_own_url() {
    # loopback answering says little about the address the members call: dialled from
    # here too, where it can be (an address behind NAT may not answer from inside)
    own=$(paired_url)
    i=0
    while ! "$BIN" health --own-url >/dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -ge 5 ]; then
            if [ -n "$URL_AUTO" ]; then
                die "the witness answers on this host, but not at $own, the address it paired with - the members will not reach it there either. Look at: journalctl -u $SVC. Then remove it (sudo pegaprox-witness uninstall), make a new code with Add witness on the leader's HA page (this one is used up) and run its line with --url https://<an address of this host>:$PORT"
            fi
            say "it does not answer at $own from this host - behind NAT that can be right; check it from a member: curl -k $own/api/ha/peer/status (a 401 is the right answer)"
            return 0
        fi
        sleep 1
    done
}

firewall_text() {
    leader=$(leader_host)
    # the members call the address it paired with: theirs are of its family, and of
    # either for a name
    families=$(url_family "$(paired_url)")
    say "Open TCP port $PORT on this host for the members of the group${leader:+ (the leader is $leader)} and nothing else, e.g."
    for f in $families; do
        who='<member address>'
        if [ "$families" != "$f" ]; then who="<member IPv$f address>"; fi
        if command -v ufw >/dev/null 2>&1; then
            say "  ufw allow proto tcp from $who to any port $PORT"
        elif command -v firewall-cmd >/dev/null 2>&1; then
            say "  firewall-cmd --permanent --add-rich-rule='rule family=ipv$f source address=$who port port=$PORT protocol=tcp accept' && firewall-cmd --reload"
        elif [ "$f" = 6 ]; then
            say "  nft add rule inet filter input ip6 saddr $who tcp dport $PORT accept"
        else
            say "  nft add rule inet filter input ip saddr $who tcp dport $PORT accept"
        fi
    done
    say "Where you cannot firewall it, run this again with --allow <member network> for each."
    say "Check it: sudo pegaprox-witness status here, and the HA tab on the leader."
}

# --- a code on a host that is paired already -------------------------------------------

settle_code() {
    # the same line again, or a new pairing: only once the old group let the witness go
    verdict=$(printf '%s\n' "$CODE" | "$BIN" check-code -) ||
        die "could not check the code against the pairing of this host (see above)"
    case $verdict in
        same)
            say "paired already - the code is left out; repairing and updating"
            CODE=
            ;;
        stale)
            say "the group this host was the witness of let it go - leaving it here and pairing with the new code"
            systemctl stop $SVC >/dev/null 2>&1 || true
            "$BIN" leave --force >/dev/null || die "could not leave the old pairing here (see above)"
            # its updates came from the old group
            rm -rf "$STATE/code" "$STATE/update.json"
            ;;
        held)
            die "this host is still the witness of another group (the leader is $(leader_host)), and its members still count its vote - remove the witness there first (Remove witness on its HA page) or run this with --uninstall, then this line again"
            ;;
        *)
            die "this host is still paired with another group - run it with --uninstall --force, then this line again"
            ;;
    esac
}

# --- the start script, from the newest update that came up healthy ------------------------

save_trust() {
    # the keys of the data voters as the pairing just brought them, kept by root: an update
    # the witness fetched later is checked against them before /opt takes it (refresh_base)
    "$PY" -I - "$STATE/ha_witness.json" "$OPT/trust.json.new" <<'EOF'
import json, sys
with open(sys.argv[1], encoding='utf-8') as fh:
    st = json.load(fh)
voters = ((st.get('cfg') or {}).get('body') or {}).get('voters') or []
keys = {v['id']: v['public_key'] for v in voters
        if isinstance(v, dict) and v.get('voter') and isinstance(v.get('id'), str)
        and isinstance(v.get('public_key'), str)}
with open(sys.argv[2], 'w', encoding='utf-8') as fh:
    json.dump({'keys': keys, 'leader': (st.get('paired') or {}).get('instance_id')}, fh, indent=2,
              sort_keys=True)
EOF
    chmod 644 "$OPT/trust.json.new"
    mv -f "$OPT/trust.json.new" "$OPT/trust.json"
}

refresh_base() {
    # as root: the base in $OPT and boot.py from the newest update that came up healthy
    # here, from the bundle the witness kept of it - checked again (the signature of a data
    # voter of the pairing, then check_bundle) before anything of it is taken. The state
    # directory is the service user's, and boot.py runs as root. Healthy is what ran its
    # first minutes without a stop (witness_boot.SOAK): an update this run just started
    # into is taken by a run after that. While update --to-leader holds the leader's older
    # code, nothing newer than the release the leader last told goes in; code of the
    # base's own release goes in where the witness took it from its leader (a fix under
    # the same release string)
    [ -f "$OPT/trust.json" ] || return 0
    name=$("$PY" -I - "$OPT" "$STATE" <<'EOF'
import base64, json, os, sys
opt, state = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(opt, 'current'))
from pegaprox import witness_boot as wb
from pegaprox.core import ha_wire
SUFFIX = '.bundle.json'
with open(os.path.join(opt, 'trust.json'), encoding='utf-8') as fh:
    keys = json.load(fh).get('keys') or {}
root = os.path.realpath(os.path.join(state, wb.UPDATES))
have = wb.release_key(*(wb.code_version(os.path.join(opt, 'current')) or ('', 0)))
here = os.path.basename(os.path.realpath(os.path.join(opt, 'current')))


def read(path):
    # what the service user wrote: it only ever holds back what goes in here
    try:
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


marks = read(os.path.join(root, wb.HEALTH))
same = marks.get('same') if isinstance(marks.get('same'), str) else ''
cap = None
held = (marks.get('down') or {}).get('version') if isinstance(marks.get('down'), dict) else None
if isinstance(held, list) and len(held) == 2:
    told = read(os.path.join(state, wb.UPDATE_NAME)).get('leader')
    told = told if isinstance(told, dict) and isinstance(told.get('release'), str) else {}
    cap = wb.release_key(told['release'], told.get('wire')) if told else wb.release_key(*held)


def kept(name):
    fd = os.open(os.path.join(root, name + SUFFIX), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as fh:
        return json.loads(fh.read(2 * wb.MAX_BUNDLE + 65536))


best = None
health = wb.load_health(root)
for path in health['ok']:
    name = os.path.basename(path)
    if os.path.dirname(path) != root or not wb.NAME_RE.fullmatch(name) or path in health['bad']:
        continue
    try:
        data = kept(name)
        manifest = data['manifest']
        archive = base64.b64decode(data['archive'], validate=True)
        key = keys.get(manifest.get('by'))
        if not key or not ha_wire.cfg_signed(key, ha_wire.bundle_message(manifest), data.get('sig')):
            print(f'pegaprox-witness: {name} is not signed by a member of the pairing - left out',
                  file=sys.stderr)
            continue
        if wb.check_bundle(archive, manifest) != name:
            continue
    except (OSError, ValueError, KeyError, TypeError, AttributeError, wb.BootError):
        continue
    k = wb.release_key(manifest['release'], manifest.get('wire'))
    if cap is not None and k > cap:
        continue
    if (k > have or (k == have and path == same and name != here)) and (best is None or k > best[0]):
        best = (k, archive, manifest)
if best is not None:
    path = wb.install_bundle(best[1], best[2], opt)
    wb.switch(opt, os.path.basename(path))
    wb.prune(opt)
    print(os.path.basename(path))
EOF
) || return 0
    [ -n "$name" ] || return 0
    cp "$OPT/current/pegaprox/witness_boot.py" "$OPT/boot.py.new"
    chmod 644 "$OPT/boot.py.new"
    mv -f "$OPT/boot.py.new" "$OPT/boot.py"
    say "the start script and $OPT/current are up to date with $name"
}

# --- the address the members call ---------------------------------------------------------

settle_url_port() {
    # a new pairing: --url names the port the members call, and the witness listens on
    # that very port. A NAT that maps one port to another is not told apart from a typo
    [ -n "$URL" ] || return 0
    uport=$(port_of "$URL")
    [ -n "$uport" ] || die "--url needs the port the witness listens on, as in https://<this host>:${PORT:-5005}"
    if [ -z "$PORT" ]; then
        PORT=$uport
    elif [ "$PORT" != "$uport" ]; then
        die "--port $PORT and --url $URL name two ports - the witness listens on the port the members call: give the same one to both"
    fi
}

check_address() {
    # a paired witness keeps the address the members call: another --url or --port, or a
    # listener on another port than that address names, would leave them calling where
    # nothing answers
    own=$(paired_url)
    [ -n "$own" ] || return 0
    oport=$(port_of "$own")
    oport=${oport:-443}
    way="a new address needs a new pairing: remove the witness on the leader's HA page (Remove witness), make a new code there with Add witness and run its line with"
    if [ -n "$URL" ] && ! same_url "$URL" "$own"; then
        die "this witness is paired as $own, the address the members call - $way --url $URL"
    fi
    if [ -n "$PORT" ] && [ "$PORT" != "$oport" ]; then
        die "this witness is paired as $own, the address the members call - $way --port $PORT (and --url https://<this host>:$PORT where you name one)"
    fi
    listen=$(setting PEGAPROX_WITNESS_PORT)
    listen=${listen:-5005}
    if [ -z "$PORT" ] && [ "$listen" != "$oport" ]; then
        die "the witness listens on port $listen, but it is paired as $own, the address the members call - run this with --port $oport, or $way --port $listen"
    fi
}

# --- remove ---------------------------------------------------------------------------

uninstall() {
    need_root
    PY=$(find_python || command -v python3 || true)
    if [ -x "$OPT/venv/bin/python3" ]; then PY="$OPT/venv/bin/python3"; fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop $SVC >/dev/null 2>&1 || true
    fi
    if [ -n "$PY" ] && [ -x "$BIN" ] && is_paired; then
        if [ -n "$FORCE" ]; then
            "$BIN" leave --force || true
        elif ! "$BIN" leave; then
            systemctl start $SVC >/dev/null 2>&1 || true
            die "the leader did not take the witness out (see above) - fix that on the leader, or run this with --uninstall --force to remove it here all the same (then remove it on the leader's HA page)"
        fi
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable $SVC >/dev/null 2>&1 || true
    fi
    rm -f "$UNIT"
    rm -rf "$DROPIN"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    rm -f "$BIN"
    if [ -L "$LINK" ] && [ "$(readlink "$LINK")" = "$LINK_TO" ]; then
        rm -f "$LINK"
    fi
    rm -rf "$OPT" "$STATE"
    if getent passwd "$USER_NAME" >/dev/null 2>&1; then
        userdel "$USER_NAME" >/dev/null 2>&1 || true
    fi
    say "the witness is removed from this host"
}

# --- the run --------------------------------------------------------------------------

if [ -n "$UNINSTALL" ]; then
    uninstall
    exit 0
fi

need_root
command -v systemctl >/dev/null 2>&1 || die "this installer needs systemd - use the Docker command from \"Add witness\" instead"
refuse_pegaprox_service
ensure_python
refuse_pegaprox_port
ensure_user
TMP=$(mktemp -d)

if is_paired && [ -n "$CODE" ]; then
    if [ ! -x "$BIN" ] && [ -d "$OPT/current" ]; then
        # the command it asks with, put back first
        write_unit
        write_command
    fi
    settle_code
fi

# the unit first: it settles the port and the allow list the command takes as defaults
if is_paired; then
    [ -d "$OPT/current" ] || die "this witness is paired, and its code in $OPT is gone - run this with --uninstall, then install it anew with a new code"
    check_address
    write_unit
    write_command
else
    [ -n "$CODE" ] || die "--code is needed: \"Add witness\" on the leader's HA page shows the line with it"
    settle_url_port
    if [ -f "$STATE/ha_witness.json" ]; then
        # a group let this witness go (Remove witness): its process still holds the state
        # until it stops, and the updates here came from that group
        systemctl stop $SVC >/dev/null 2>&1 || true
        rm -rf "$STATE/code" "$STATE/update.json"
    fi
    say "fetching the witness code from the leader"
    release=$(fetch_bundle) || die "could not fetch the witness code from the leader"
    name=$(install_bundle) || die "could not install the witness code"
    say "release $release installed in $OPT/$name"
    write_unit
    write_command
    if [ -z "$URL" ]; then
        URL=$(own_url) || die "could not work out the address of this host - pass --url https://<this host>:$PORT"
        URL_AUTO=1
    fi
    say "pairing as $URL"
    # the code on stdin here too; the start is this installer's, not the admin's
    printf '%s\n' "$CODE" | PEGAPROX_WITNESS_BY_INSTALLER=1 "$BIN" join - --url "$URL" ||
        die "the pairing failed (see the line above)"
    save_trust
fi

if [ -z "$CODE" ]; then
    # repaired: and the newest code of the leader, with the updates off too; the restart
    # below starts into it
    PEGAPROX_WITNESS_NO_RESTART=1 "$BIN" update || say "could not update from the leader now - it tries again by itself"
fi
systemctl daemon-reload
systemctl enable $SVC >/dev/null 2>&1 || systemctl enable $SVC
systemctl restart $SVC
wait_for_it
refresh_base
say "the witness runs (state in $STATE, updates from the leader $([ "$AUTO" = 0 ] && echo off || echo on))"
firewall_text
