#!/bin/sh
# PegaProx QNetd installer - MK Oct 2026
#
# Makes the host PegaProx runs on a QNetd host for it: the external vote of the corosync
# QDevice of 2-node (and other even-sized) Proxmox clusters. Not where PegaProx runs as a
# VM of a cluster it should vote for, and not on a member of a PegaProx HA pair: that vote
# would go down with its own machine, use an ssh QNetd host there (docs/qdevice.md).
# Run it as root, from a copy only root can change:
#
#   sh /usr/lib/pegaprox/qnetd/install.sh                      apt or rpm package, appliance
#   sh /usr/lib/pegaprox/qnetd/install.sh --uninstall          the socket and the helper go, the CA stays
#   sh /usr/lib/pegaprox/qnetd/install.sh --uninstall --purge  ... and the CA with its NSS database too
#
# A git install keeps this file in /opt/PegaProx, which the service user can change: see
# docs/qdevice.md (Updates) for the safe way to run it there.
#
# It copies pegaprox-qnetd-helper root-owned to /usr/lib/pegaprox/qnetd/, runs its init
# (corosync-qnetd and the NSS tools from apt-get, dnf, yum or zypper where they are
# missing, TLS required on a corosync-qnetd it installs, the CA in
# /etc/corosync/qnetd/nssdb, corosync-qnetd started), and lets PegaProx reach the helper
# through a root-owned socket unit:
# pegaprox-qnetd-helper.socket (/run/pegaprox-qnetd/local.sock, root and the pegaprox
# group) starts pegaprox-qnetd-helper@.service as root for each connection. No sudo rule;
# the sudo rule and the service drop-in an earlier version wrote are taken out again.
# Running it again changes nothing that is in place. After an update of PegaProx run it
# again: PegaProx cannot replace a root-owned helper, it says when this one is behind.
#
# For the tests: PEGAPROX_QNETD_ROOT puts every path under another root.
set -eu
umask 022
case $0 in
    /*) SELF=$0 ;;
    *) SELF="$(pwd)/$0" ;;
esac
SRC_DIR=$(dirname "$SELF")
cd /

ROOT=${PEGAPROX_QNETD_ROOT:-}
BASE="$ROOT/usr/lib/pegaprox"
LIB="$BASE/qnetd"
HELPER="$LIB/pegaprox-qnetd-helper"
UNIT_DIR="$ROOT/etc/systemd/system"
SOCKET_UNIT="$UNIT_DIR/pegaprox-qnetd-helper.socket"
SERVICE_UNIT="$UNIT_DIR/pegaprox-qnetd-helper@.service"
QNETD_DIR="$ROOT/etc/corosync/qnetd"
QNETD_DEFAULTS="$ROOT/etc/default/corosync-qnetd"
QNETD_SYSCONFIG="$ROOT/etc/sysconfig/corosync-qnetd"
# what an earlier version wrote for sudo
OLD_SUDOERS_DIR="$ROOT/etc/sudoers.d"
OLD_SUDOERS="$OLD_SUDOERS_DIR/pegaprox-qnetd"
OLD_DROPIN_DIR="$ROOT/etc/systemd/system/pegaprox.service.d"
OLD_DROPIN="$OLD_DROPIN_DIR/pegaprox-qnetd.conf"
# what the units name, also when a test root is in front of the files
HELPER_PATH=/usr/lib/pegaprox/qnetd/pegaprox-qnetd-helper
LOCAL_SOCKET=/run/pegaprox-qnetd/local.sock
SVC_USER=pegaprox

UNINSTALL=
PURGE=
TMPF=
RESTART=
RELOAD=

say() { printf 'pegaprox-qnetd: %s\n' "$*"; }
warn() { printf 'pegaprox-qnetd: %s\n' "$*" >&2; }
die() { printf 'pegaprox-qnetd: %s\n' "$*" >&2; exit 1; }

usage() {
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$SELF"
}

while [ $# -gt 0 ]; do
    case $1 in
        --uninstall) UNINSTALL=1; shift ;;
        --purge) PURGE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done
[ -z "$PURGE" ] || [ -n "$UNINSTALL" ] || die "--purge goes with --uninstall"

cleanup() { [ -z "$TMPF" ] || rm -f "$TMPF"; }
trap cleanup EXIT
trap 'exit 130' INT TERM

if [ -z "$ROOT" ]; then
    # the helper takes these for an unprivileged test run only, and refuses them as root
    unset PEGAPROX_QNETD_CONFIG_DIR PEGAPROX_QNETD_BIN_DIR PEGAPROX_QNETD_RUN_DIR PEGAPROX_QNETD_SERVICE_USER \
        PEGAPROX_QNETD_STATE_DIR || true
fi

need_root() {
    [ "$(id -u)" -eq 0 ] || die "run it as root: sh $SELF"
}

need_systemd() {
    command -v systemctl >/dev/null 2>&1 ||
        die "this host has no systemd: PegaProx reaches the helper through a socket unit - add a QNetd host of the kind ssh instead"
}

# the group of the socket: the service user's, or root's where PegaProx runs as root (rpm)
socket_group() {
    if getent group "$SVC_USER" >/dev/null 2>&1; then
        printf '%s' "$SVC_USER"
    else
        printf 'root'
    fi
}

# --- packages ---------------------------------------------------------------------------

package_manager() {
    # the one the helper's init uses, in its order
    for pm in apt-get dnf yum zypper; do
        if command -v "$pm" >/dev/null 2>&1; then
            printf '%s' "$pm"
            return 0
        fi
    done
    return 1
}

missing_packages() {
    case $1 in
        apt-get) nss=libnss3-tools ;;
        zypper) nss=mozilla-nss-tools ;;
        *) nss=nss-tools ;;
    esac
    out=
    command -v corosync-qnetd >/dev/null 2>&1 || out="$out corosync-qnetd"
    command -v certutil >/dev/null 2>&1 || out="$out $nss"
    printf '%s' "$out"
}

check_packages() {
    # the helper's init installs them (and requires TLS on a corosync-qnetd it installed):
    # here only whether it can, before anything is put in place
    pm=$(package_manager) || pm=
    need=$(missing_packages "$pm")
    [ -n "$need" ] || return 0
    [ -n "$pm" ] ||
        die "this host has no apt-get, dnf, yum or zypper - install$need with its package manager (on RHEL and its rebuilds: corosync-qnetd and nss-tools), then run this again"
    say "the helper's init installs$need with $pm"
}

# --- the helper -------------------------------------------------------------------------

safe_dir() {
    # a directory only root writes to: the file in it runs as root
    if [ ! -e "$1" ] && [ ! -L "$1" ]; then
        install -d -o root -g root -m 0755 "$1"
        return 0
    fi
    [ ! -L "$1" ] && [ -d "$1" ] || die "$1 is not a plain directory - refusing to put a root helper there"
    owner=$(stat -c %u "$1")
    mode=$(stat -c %a "$1")
    if [ -z "$ROOT" ] && [ "$owner" != 0 ]; then
        die "$1 belongs to uid $owner, not root - a root helper must not sit where another user can swap it (chown root:root $1, then run this again)"
    fi
    [ $((0$mode & 022)) -eq 0 ] ||
        die "$1 is writable by group or others (mode $mode) - refusing to put a root helper there"
}

warn_source() {
    # what is copied runs as root: say so where someone else could have changed it first
    for f in "$SRC_DIR" "$SRC_DIR/pegaprox-qnetd-helper" "$SELF"; do
        [ -e "$f" ] || continue
        owner=$(stat -c %u "$f")
        mode=$(stat -c %a "$f")
        if { [ -z "$ROOT" ] && [ "$owner" != 0 ]; } || [ $((0$mode & 022)) -ne 0 ]; then
            warn "WARNING: $f can be changed by uid $owner (mode $mode), and it is about to run as root."
            warn "Whatever runs as that user could have rewritten it. docs/qdevice.md (Updates) shows how to"
            warn "run this from a copy only root can change."
            return 0
        fi
    done
}

put_file() {
    # $1 into place as $2, root-owned, mode $3: through a temp file and a rename, so a
    # call in the middle never runs half a file
    if [ "$1" -ef "$2" ]; then
        # this is the installed copy (apt and rpm put it there): owner and mode only
        chown root:root "$2"
        chmod "$3" "$2"
        return 0
    fi
    install -o root -g root -m "$3" "$1" "$2.new"
    mv -f "$2.new" "$2"
}

put_helper() {
    [ -f "$SRC_DIR/pegaprox-qnetd-helper" ] ||
        die "there is no pegaprox-qnetd-helper next to this installer in $SRC_DIR"
    safe_dir "$BASE"
    safe_dir "$LIB"
    put_file "$SRC_DIR/pegaprox-qnetd-helper" "$HELPER" 0755
    # this file too, root-owned, for --uninstall and later runs from a place the service
    # user cannot change
    put_file "$SELF" "$LIB/install.sh" 0755
}

# --- the socket unit --------------------------------------------------------------------

socket_unit() {
    cat <<EOF
# PegaProx QNetd helper - written by packaging/qnetd/install.sh, removed by its --uninstall.
# PegaProx asks the root helper on this socket: one JSON line in, one out, a new
# pegaprox-qnetd-helper@.service for each connection.
[Unit]
Description=PegaProx QNetd helper socket

[Socket]
ListenStream=$LOCAL_SOCKET
SocketUser=root
SocketGroup=$1
SocketMode=0660
DirectoryMode=0755
Accept=yes
MaxConnections=8
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
EOF
}

service_unit() {
    cat <<EOF
# PegaProx QNetd helper - written by packaging/qnetd/install.sh, removed by its --uninstall.
# One request of pegaprox-qnetd-helper.socket, answered by the root helper. It checks the
# peer of the connection itself (root and the pegaprox user only) and every field of the
# request.
[Unit]
Description=PegaProx QNetd helper (one request)
CollectMode=inactive-or-failed

[Service]
ExecStart=$HELPER_PATH serve
StandardInput=socket
StandardOutput=socket
StandardError=journal
User=root
# init installs corosync-qnetd with apt-get: well past the helper's own time limits
RuntimeMaxSec=1800
# init runs apt-get, dpkg and their maintainer scripts (they write /usr, /etc and /var
# and add a system user) and systemctl. dpkg may first finish whatever package was left
# half configured, a kernel or a foreign architecture one too: no ProtectSystem,
# NoNewPrivileges, RestrictSUIDSGID, MemoryDenyWriteExecute, PrivateDevices,
# ProtectKernelModules (hides /usr/lib/modules), ProtectClock (closes the devices) or
# SystemCallArchitectures here. What none of it needs:
PrivateTmp=yes
ProtectHome=read-only
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectHostname=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
UMask=0077
EOF
}

put_unit() {
    # $2 as the file $1, through a temp file; nothing happens where it is the same
    TMPF=$(mktemp "$UNIT_DIR/.pegaprox-qnetd.XXXXXX")
    printf '%s\n' "$2" > "$TMPF"
    chmod 0644 "$TMPF"
    if [ -f "$1" ] && [ ! -L "$1" ] && cmp -s "$TMPF" "$1"; then
        rm -f "$TMPF"
        TMPF=
        return 0
    fi
    chown root:root "$TMPF"
    mv -f "$TMPF" "$1"
    TMPF=
    CHANGED=1
}

put_units() {
    [ -d "$UNIT_DIR" ] || install -d -o root -g root -m 0755 "$UNIT_DIR"
    group=$(socket_group)
    CHANGED=
    put_unit "$SOCKET_UNIT" "$(socket_unit "$group")"
    put_unit "$SERVICE_UNIT" "$(service_unit)"
    if [ -n "$CHANGED" ]; then
        systemctl daemon-reload
        systemctl enable pegaprox-qnetd-helper.socket >/dev/null 2>&1 ||
            die "systemd does not take pegaprox-qnetd-helper.socket (systemctl status pegaprox-qnetd-helper.socket)"
        # a socket that ran with the old unit takes the new one only on a restart
        systemctl restart pegaprox-qnetd-helper.socket ||
            die "pegaprox-qnetd-helper.socket does not start (journalctl -u pegaprox-qnetd-helper.socket)"
        say "the helper socket $LOCAL_SOCKET answers root and the group $group"
    else
        systemctl enable --now pegaprox-qnetd-helper.socket >/dev/null 2>&1 ||
            die "pegaprox-qnetd-helper.socket does not start (journalctl -u pegaprox-qnetd-helper.socket)"
    fi
}

ours() {
    # a file an earlier run of this installer wrote: a plain file with its name in it
    [ -f "$1" ] && [ ! -L "$1" ] && grep -q 'packaging/qnetd/install.sh' "$1"
}

drop_old_sudo() {
    # an earlier version reached the helper through sudo: its rule goes, and the drop-in
    # that took NoNewPrivileges off the whole PegaProx unit for it. A file of either name
    # without our line in it is someone else's and stays
    if ours "$OLD_SUDOERS"; then
        rm -f "$OLD_SUDOERS"
        say "removed the sudo rule of an earlier version ($OLD_SUDOERS)"
    fi
    rm -f "$OLD_SUDOERS_DIR"/.pegaprox-qnetd.* 2>/dev/null || true
    if ours "$OLD_DROPIN"; then
        rm -f "$OLD_DROPIN"
        rmdir "$OLD_DROPIN_DIR" 2>/dev/null || true
        RELOAD=1
        RESTART=1
        say "removed the drop-in that took NoNewPrivileges off the pegaprox unit ($OLD_DROPIN)"
    fi
    if [ -n "$RELOAD" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
}

# --- what to enter in PegaProx ----------------------------------------------------------

qnetd_defaults() {
    # the environment file of corosync-qnetd's unit: /etc/default on Debian and Ubuntu,
    # /etc/sysconfig on RHEL and SUSE
    if [ ! -f "$QNETD_DEFAULTS" ] && [ -f "$QNETD_SYSCONFIG" ]; then
        printf '%s' "$QNETD_SYSCONFIG"
    else
        printf '%s' "$QNETD_DEFAULTS"
    fi
}

qnetd_port() {
    # -p in the options of the unit's environment file, 5403 where none is set
    port=
    f=$(qnetd_defaults)
    if [ -f "$f" ]; then
        port=$(sed -n 's/^[[:space:]]*COROSYNC_QNETD_OPTIONS=//p' "$f" | tail -n 1 |
            sed -n 's/.*-p[[:space:]]*\([0-9][0-9]*\).*/\1/p')
    fi
    printf '%s' "${port:-5403}"
}

answer_field() {
    # $2 of the helper's JSON answer $1: a text as it is, true / false, nothing where it
    # is not there
    printf '%s' "$1" | python3 -I -c 'import json, sys
try:
    v = json.load(sys.stdin).get(sys.argv[1])
except (ValueError, AttributeError):
    v = None
print("" if v is None else v if isinstance(v, str) else json.dumps(v))' "$2" 2>/dev/null || true
}

run_init() {
    out=$("$HELPER" init </dev/null) || {
        why=$(answer_field "$out" error)
        die "the helper could not set up corosync-qnetd: ${why:-no answer (see above)}"
    }
    case $(answer_field "$out" created) in
        true) say "made the QNetd CA in $QNETD_DIR/nssdb" ;;
        *) say "the QNetd CA in $QNETD_DIR/nssdb is in place - left as it is" ;;
    esac
    if [ "$(answer_field "$out" tls_set)" = true ]; then
        say "corosync-qnetd requires TLS from its clients (-s req in $(qnetd_defaults))"
    fi
}

tls_note() {
    # a corosync-qnetd that was here before keeps its options: say what they mean
    st=$("$HELPER" status </dev/null) || return 0
    if [ "$(answer_field "$st" tls_required)" = false ]; then
        warn "corosync-qnetd here lets a client skip TLS (-s on), and such a client is asked for no"
        warn "certificate. Every QDevice PegaProx sets up speaks TLS: put -s req into COROSYNC_QNETD_OPTIONS"
        warn "in $(qnetd_defaults) and restart corosync-qnetd (docs/qdevice.md, TLS)."
    fi
}

next_steps() {
    port=$(qnetd_port)
    addrs=$(hostname -I 2>/dev/null || true)
    say "corosync-qnetd runs on this host, port $port."
    say "In PegaProx, add a QNetd host of the kind 'local' (this host). As its address, give the one"
    say "the Proxmox nodes reach this host at${addrs:+ - one of: $addrs} - and port $port."
    say "Open TCP port $port here for every node of the clusters that vote through it, nothing else -"
    say "with ufw or firewalld, the setup of a QDevice in PegaProx can do that for each cluster."
    if [ -n "$RESTART" ]; then
        say "Restart PegaProx once, so its service runs with NoNewPrivileges again: systemctl restart pegaprox"
    fi
}

# --- remove -----------------------------------------------------------------------------

packaged() {
    # a file the apt or rpm package owns stays: the package removes it
    if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -S "$1" >/dev/null 2>&1; then
        return 0
    fi
    command -v rpm >/dev/null 2>&1 && rpm -qf "$1" >/dev/null 2>&1
}

purge_ca() {
    # the CA goes, and with it every cluster certificate this QNetd signed: no cluster may
    # vote through it any more
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet corosync-qnetd.service 2>/dev/null; then
        listing=$(corosync-qnetd-tool -l 2>/dev/null) ||
            die "corosync-qnetd runs and does not say which clusters use it - nothing purged (stop it first: systemctl stop corosync-qnetd)"
        # the names are what the clients sent: nothing but plain characters reaches the terminal
        clusters=$(printf '%s\n' "$listing" | sed -n 's/^Cluster "\(.*\)":$/\1/p' |
            LC_ALL=C tr -c 'A-Za-z0-9._\n-' '?' | tr '\n' ' ')
        [ -z "$clusters" ] ||
            die "these clusters still vote through this QNetd: $clusters- remove their QDevice in PegaProx first; nothing purged"
        systemctl disable --now corosync-qnetd.service >/dev/null 2>&1 || true
    fi
    rm -rf "$QNETD_DIR/nssdb"
    say "the QNetd CA and its NSS database are gone; the packages stay (remove corosync-qnetd with the package manager)"
}

remove_units() {
    if [ -e "$SOCKET_UNIT" ] || [ -e "$SERVICE_UNIT" ]; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now pegaprox-qnetd-helper.socket >/dev/null 2>&1 || true
        fi
        rm -f "$SOCKET_UNIT" "$SERVICE_UNIT"
        RELOAD=1
        say "the helper socket is gone ($SOCKET_UNIT, $SERVICE_UNIT)"
    fi
}

uninstall() {
    need_root
    [ -z "$PURGE" ] || purge_ca
    remove_units
    drop_old_sudo
    for f in "$HELPER" "$LIB/install.sh"; do
        if [ -e "$f" ] && ! packaged "${f#"$ROOT"}"; then
            rm -f "$f"
        fi
    done
    rmdir "$LIB" 2>/dev/null || true
    rmdir "$BASE" 2>/dev/null || true
    if [ -z "$PURGE" ]; then
        say "the helper is gone; corosync-qnetd and its CA in $QNETD_DIR/nssdb stay (--uninstall --purge removes the CA)"
    else
        say "the helper is gone"
    fi
    if [ -n "$RESTART" ]; then
        say "Restart PegaProx once, so its service runs with NoNewPrivileges again: systemctl restart pegaprox"
    fi
}

# --- the run ----------------------------------------------------------------------------

if [ -n "$UNINSTALL" ]; then
    uninstall
    exit 0
fi

need_root
need_systemd
check_packages
warn_source
put_helper
run_init
put_units
drop_old_sudo
tls_note
next_steps
