"""How the QNetd helper reaches each kind of install: packaging/qnetd/install.sh (git, apt,
appliance), the --qnetd flag of the witness installer, the Docker image and compose file,
and the deb and rpm packages.

install.sh runs for real in a root of its own (PEGAPROX_QNETD_ROOT). PATH holds only the
stand-ins of test_qnetd_helper plus id, getent, install, chown, hostname and dpkg-query
stand-ins and a handful of plain tools: no real apt-get, systemctl or chown can be
reached from here. The helper it installs and runs is the real one, against the stand-in
certutil. The units it writes are checked with systemd-analyze where there is one.

MK Oct 2026
"""
import os
import re
import shlex
import shutil
import subprocess
import sys

import pytest

from test_qnetd_helper import FakeBins, HELPER, LISTING, ROOT, slurp

INSTALLER = os.path.join(ROOT, 'packaging', 'qnetd', 'install.sh')
OLD_RULE = ('# PegaProx QNetd helper - written by packaging/qnetd/install.sh, removed by its\n'
            '# --uninstall. The PegaProx service runs this one root-owned file as root and nothing\n'
            '# else; the helper checks every argument itself.\n'
            'pegaprox ALL=(root) NOPASSWD: /usr/lib/pegaprox/qnetd/pegaprox-qnetd-helper\n')
OLD_DROPIN = ('# written by packaging/qnetd/install.sh, removed by its --uninstall: sudo for the QNetd\n'
              '# helper (/etc/sudoers.d/pegaprox-qnetd) needs the service without NoNewPrivileges\n'
              '[Service]\nNoNewPrivileges=no\n')

TOOLS = ('sh', 'sed', 'awk', 'mktemp', 'stat', 'cat', 'chmod', 'mv', 'rm', 'mkdir', 'rmdir', 'grep', 'tr',
         'tail', 'dirname', 'touch', 'cp', 'ls', 'head', 'env', 'sleep', 'basename', 'readlink', 'cmp')

FAKES = {
    'id': '#!/bin/sh\nif [ "$1" = -u ] && [ $# -eq 1 ]; then cat "$(dirname "$0")/uid" 2>/dev/null || echo 0; '
          'exit 0; fi\nexec REAL_ID "$@"\n',
    'getent': '#!/bin/sh\nHERE=$(dirname "$0")\nif [ "$2" = pegaprox ] && [ -f "$HERE/state-user" ]; then\n'
              '    case $1 in\n'
              '        passwd) echo "pegaprox:x:999:999::/var/lib/pegaprox:/usr/sbin/nologin"; exit 0 ;;\n'
              '        group) echo "pegaprox:x:999:"; exit 0 ;;\n'
              '    esac\nfi\nexit 2\n',
    'chown': '#!/bin/sh\necho "chown $*" >> "$(dirname "$0")/calls.txt"\n',
    'chgrp': '#!/bin/sh\necho "chgrp $*" >> "$(dirname "$0")/calls.txt"\n',
    'hostname': '#!/bin/sh\n[ "$1" = -I ] && echo "192.0.2.10 2001:db8::10 "\n',
    'dpkg-query': '#!/bin/sh\n[ -f "$(dirname "$0")/state-packaged" ]\n',
    'install': r'''#!PYTHON -I
import os, subprocess, sys
args = sys.argv[1:]
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'calls.txt'), 'a') as fh:
    fh.write('install ' + ' '.join(args) + '\n')
out, i = [], 0
while i < len(args):
    if args[i] in ('-o', '-g'):
        i += 2
        continue
    out.append(args[i])
    i += 1
sys.exit(subprocess.call(['REAL_INSTALL'] + out))
''',
}


class QBox:
    """The PegaProx host install.sh runs on: a root, the stand-ins in $ROOT/bin."""

    def __init__(self, tmp):
        self.root = str(tmp / 'root')
        self.host = FakeBins(self.root)
        self.bin = self.host.bin
        for name, text in FAKES.items():
            self.host.write(name, text.replace('REAL_ID', shutil.which('id'))
                            .replace('REAL_INSTALL', shutil.which('install')))
        os.symlink(sys.executable, os.path.join(self.bin, 'python3'))
        self.tools = str(tmp / 'tools')
        os.makedirs(self.tools)
        for name in TOOLS:
            os.symlink(shutil.which(name), os.path.join(self.tools, name))
        self.flag('state-user')
        self.lib = os.path.join(self.root, 'usr', 'lib', 'pegaprox', 'qnetd')
        units = os.path.join(self.root, 'etc', 'systemd', 'system')
        self.socket_unit = os.path.join(units, 'pegaprox-qnetd-helper.socket')
        self.service_unit = os.path.join(units, 'pegaprox-qnetd-helper@.service')
        self.sudoers = os.path.join(self.root, 'etc', 'sudoers.d', 'pegaprox-qnetd')
        self.dropin = os.path.join(units, 'pegaprox.service.d', 'pegaprox-qnetd.conf')

    def flag(self, name, on=True):
        self.host.flag(name, on)

    def env(self):
        env = self.host.env(PEGAPROX_QNETD_ROOT=self.root, PATH='%s:%s' % (self.bin, self.tools),
                            TMPDIR=os.path.join(self.root, 'tmp'))
        os.makedirs(env['TMPDIR'], exist_ok=True)
        return env

    def run(self, *args, script=INSTALLER):
        return subprocess.run([shutil.which('sh'), script] + list(args), env=self.env(), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=180, cwd=self.root, universal_newlines=True)

    def calls(self):
        return self.host.calls()

    def write(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fh:
            fh.write(text)

    def tree(self):
        out = {}
        for base, _dirs, files in os.walk(self.root):
            if base.startswith((self.bin, os.path.join(self.root, 'tmp'), os.path.join(self.root, 'run'))):
                continue
            for f in files:
                p = os.path.join(base, f)
                with open(p, 'rb') as fh:
                    out[os.path.relpath(p, self.root)] = (fh.read(), os.stat(p).st_mode & 0o7777)
        return out


@pytest.fixture
def box(tmp_path):
    return QBox(tmp_path)


def ok(out):
    assert out.returncode == 0, out.stdout + out.stderr
    return out


def _unit(path):
    """{section: {key: value}} of a unit file, comments left out."""
    out, sec = {}, None
    for line in slurp(path).decode().splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        m = re.match(r'^\[(\w+)\]$', line)
        if m:
            sec = out.setdefault(m.group(1), {})
            continue
        k, _sep, v = line.partition('=')
        assert k not in sec, k
        sec[k] = v
    return out


# --- install.sh ---------------------------------------------------------------------------

def test_install_puts_the_helper_the_socket_and_the_ca_in_place(box):
    out = ok(box.run())
    helper = os.path.join(box.lib, 'pegaprox-qnetd-helper')
    with open(HELPER, 'rb') as a, open(helper, 'rb') as b:
        assert a.read() == b.read()
    assert os.stat(helper).st_mode & 0o777 == 0o755
    with open(INSTALLER, 'rb') as a, open(os.path.join(box.lib, 'install.sh'), 'rb') as b:
        assert a.read() == b.read()
    calls = box.calls()
    # root-owned, through a temp file and a rename
    assert 'install -o root -g root -m 0755 %s/pegaprox-qnetd-helper %s.new' % (os.path.dirname(INSTALLER), helper) \
        in calls
    assert 'install -d -o root -g root -m 0755 %s' % os.path.dirname(box.lib) in calls
    assert not os.path.exists(helper + '.new')
    # the socket: root's and the pegaprox group's, one helper per connection
    sock = _unit(box.socket_unit)
    assert sock['Socket'] == {'ListenStream': '/run/pegaprox-qnetd/local.sock', 'SocketUser': 'root',
                              'SocketGroup': 'pegaprox', 'SocketMode': '0660', 'DirectoryMode': '0755',
                              'Accept': 'yes', 'MaxConnections': '8', 'RemoveOnStop': 'yes'}
    assert sock['Install'] == {'WantedBy': 'sockets.target'}
    svc = _unit(box.service_unit)['Service']
    assert svc['ExecStart'] == '/usr/lib/pegaprox/qnetd/pegaprox-qnetd-helper serve'
    assert (svc['StandardInput'], svc['StandardOutput'], svc['User']) == ('socket', 'socket', 'root')
    # hardened where it does not stand in the way of apt-get, certutil and systemctl
    for k in ('PrivateTmp', 'ProtectKernelLogs', 'ProtectControlGroups', 'LockPersonality'):
        assert svc[k] == 'yes', k
    # nothing that stands between dpkg and a package it has to finish first (a kernel, a
    # foreign architecture): /usr, /etc, /var, /usr/lib/modules and the devices stay open
    for k in ('ProtectSystem', 'NoNewPrivileges', 'RestrictSUIDSGID', 'MemoryDenyWriteExecute', 'PrivateDevices',
              'ReadOnlyPaths', 'CapabilityBoundingSet', 'DynamicUser', 'ProtectKernelModules', 'ProtectClock',
              'DeviceAllow', 'DevicePolicy', 'SystemCallArchitectures', 'SystemCallFilter'):
        assert k not in svc, k
    assert 'AF_UNIX' in svc['RestrictAddressFamilies'] and 'AF_INET6' in svc['RestrictAddressFamilies']
    for path in (box.socket_unit, box.service_unit):
        assert os.stat(path).st_mode & 0o777 == 0o644
    assert calls.index('systemctl daemon-reload') < calls.index('systemctl enable pegaprox-qnetd-helper.socket') \
        < calls.index('systemctl restart pegaprox-qnetd-helper.socket')
    assert not [n for n in os.listdir(os.path.dirname(box.socket_unit)) if n.startswith('.')]
    # no sudo of any kind
    assert not os.path.exists(box.sudoers) and not os.path.exists(box.dropin)
    assert not [c for c in calls if c.startswith(('visudo', 'systemctl show'))]
    # init ran: the CA, the service
    assert os.path.isfile(os.path.join(box.host.db, 'qnetd-cacert.crt'))
    assert 'systemctl enable --now corosync-qnetd.service' in calls
    assert 'made the QNetd CA' in out.stdout
    # what to enter in PegaProx
    assert 'port 5403' in out.stdout and '192.0.2.10 2001:db8::10' in out.stdout
    assert "kind 'local'" in out.stdout and 'Restart PegaProx' not in out.stdout
    assert not [c for c in calls if c.startswith('apt-get')]


def test_a_second_run_changes_nothing(box):
    ok(box.run())
    before = box.tree()
    n = len(box.calls())
    out = ok(box.run())
    assert box.tree() == before
    assert 'left as it is' in out.stdout
    again = box.calls()[n:]
    assert 'systemctl enable --now pegaprox-qnetd-helper.socket' in again
    assert not [c for c in again if c.startswith(('apt-get', 'systemctl daemon-reload', 'systemctl restart'))]


def test_a_changed_unit_is_put_back_and_the_socket_restarted(box):
    ok(box.run())
    with open(box.socket_unit, 'a') as fh:
        fh.write('ListenStream=0.0.0.0:5404\n')
    n = len(box.calls())
    ok(box.run())
    assert 'ListenStream=0.0.0.0' not in slurp(box.socket_unit).decode()
    assert 'systemctl restart pegaprox-qnetd-helper.socket' in box.calls()[n:]


def test_it_refuses_to_run_without_root(box):
    with open(os.path.join(box.bin, 'uid'), 'w') as fh:
        fh.write('1000\n')
    for args in ((), ('--uninstall',)):
        out = box.run(*args)
        assert out.returncode == 1 and 'run it as root' in out.stderr
    assert not os.path.exists(box.lib) and not os.path.exists(box.socket_unit)
    assert not os.path.exists(box.host.db)


def test_options_are_strict(box):
    for args in (('--purge',), ('--user', 'root'), ('--uninstall', '--force'), ('x',)):
        out = box.run(*args)
        assert out.returncode == 1, args
    assert not os.path.exists(box.lib)
    assert ok(box.run('--help')).stdout.startswith('PegaProx QNetd installer')


def test_without_systemd_nothing_is_put_in_place(box):
    os.unlink(os.path.join(box.bin, 'systemctl'))
    out = box.run()
    assert out.returncode == 1 and 'no systemd' in out.stderr and 'ssh' in out.stderr
    assert not os.path.exists(box.lib) and not os.path.exists(box.socket_unit)


# --- an earlier version's sudo rule and drop-in ---------------------------------------------

def test_the_sudo_rule_and_the_drop_in_of_an_earlier_version_go(box):
    box.write(box.sudoers, OLD_RULE)
    box.write(os.path.join(os.path.dirname(box.sudoers), '.pegaprox-qnetd.AbC123'), OLD_RULE)
    box.write(box.dropin, OLD_DROPIN)
    out = ok(box.run())
    assert not os.path.exists(box.sudoers) and not os.listdir(os.path.dirname(box.sudoers))
    assert not os.path.exists(box.dropin) and not os.path.exists(os.path.dirname(box.dropin))
    assert 'removed the sudo rule' in out.stdout and 'NoNewPrivileges' in out.stdout
    # the unit gets NoNewPrivileges back on the next start: the admin is told to restart once
    assert 'systemctl daemon-reload' in box.calls() and 'systemctl restart pegaprox' in out.stdout


def test_files_of_those_names_someone_else_wrote_stay(box):
    theirs = 'qnetd-admin ALL=(root) NOPASSWD: /usr/lib/pegaprox/qnetd/pegaprox-qnetd-helper\n'
    box.write(box.sudoers, theirs)
    box.write(box.dropin, '[Service]\nLimitNOFILE=65536\n')
    out = ok(box.run())
    assert slurp(box.sudoers).decode() == theirs
    assert slurp(box.dropin).decode() == '[Service]\nLimitNOFILE=65536\n'
    assert 'removed' not in out.stdout and 'Restart PegaProx' not in out.stdout


def test_uninstall_takes_an_earlier_sudo_rule_too(box):
    ok(box.run())
    box.write(box.sudoers, OLD_RULE)
    box.write(box.dropin, OLD_DROPIN)
    out = ok(box.run('--uninstall'))
    assert not os.path.exists(box.sudoers) and not os.path.exists(box.dropin)
    assert 'systemctl restart pegaprox' in out.stdout


# --- packages and TLS -------------------------------------------------------------------------

PACKAGE_DEFAULTS = 'COROSYNC_QNETD_OPTIONS=""\nCOROSYNC_QNETD_RUNAS=""\n'


def test_packages_come_from_apt_get_through_the_helper_and_require_tls(box):
    stash = os.path.join(box.bin, 'apt-stash')
    os.makedirs(stash)
    for name in ('certutil', 'corosync-qnetd'):
        shutil.move(os.path.join(box.bin, name), os.path.join(stash, name))
    defaults = os.path.join(box.root, 'etc', 'default', 'corosync-qnetd')
    box.write(defaults, PACKAGE_DEFAULTS)
    out = ok(box.run())
    apt = [c for c in box.calls() if c.startswith('apt-get')]
    assert apt == ['apt-get -q -y -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confdef '
                   '-o Dpkg::Options::=--force-confold install --no-install-recommends corosync-qnetd '
                   'libnss3-tools DEBIAN_FRONTEND=noninteractive']
    assert 'installs corosync-qnetd libnss3-tools with apt-get' in out.stdout
    assert slurp(defaults).decode() == 'COROSYNC_QNETD_OPTIONS="-s req"\nCOROSYNC_QNETD_RUNAS=""\n'
    assert 'requires TLS' in out.stdout
    assert 'systemctl restart corosync-qnetd.service' in box.calls()
    # no sudo is installed for anything any more
    assert not [c for c in apt if ' sudo' in c]


def test_a_qnetd_that_was_there_keeps_its_options_and_is_named(box):
    defaults = os.path.join(box.root, 'etc', 'default', 'corosync-qnetd')
    box.write(defaults, PACKAGE_DEFAULTS)
    box.write(os.path.join(box.bin, 'status.txt'), 'TLS:\t\t\t\tSupported (client certificate required)\n')
    out = ok(box.run())
    assert slurp(defaults).decode() == PACKAGE_DEFAULTS
    assert 'skip TLS' in out.stderr and '-s req' in out.stderr
    assert not [c for c in box.calls() if c.startswith('systemctl restart corosync')]
    os.unlink(os.path.join(box.bin, 'status.txt'))
    box.write(os.path.join(box.bin, 'status.txt'), 'TLS:\t\t\t\tRequired (client certificate required)\n')
    assert 'skip TLS' not in ok(box.run()).stderr


def test_without_apt_get_it_says_what_to_install(tmp_path):
    box = QBox(tmp_path)
    os.unlink(os.path.join(box.bin, 'corosync-qnetd'))
    os.unlink(os.path.join(box.bin, 'apt-get'))
    out = box.run()
    assert out.returncode == 1 and 'no apt-get, dnf, yum or zypper' in out.stderr and 'nss-tools' in out.stderr
    assert not os.path.exists(box.lib) and not os.path.exists(box.socket_unit)


def test_without_apt_get_the_init_installs_with_dnf(box):
    os.unlink(os.path.join(box.bin, 'apt-get'))
    stash = os.path.join(box.bin, 'pm-stash')
    os.makedirs(stash)
    for name in ('certutil', 'corosync-qnetd'):
        shutil.move(os.path.join(box.bin, name), os.path.join(stash, name))
    box.host.write('dnf', '#!/bin/sh\nHERE=$(dirname "$0")\necho "dnf $*" >> "$HERE/calls.txt"\n'
                          'cp -p "$HERE"/pm-stash/* "$HERE"/\n')
    sysconfig = os.path.join(box.root, 'etc', 'sysconfig', 'corosync-qnetd')
    box.write(sysconfig, 'COROSYNC_QNETD_OPTIONS="-p 5404"\nCOROSYNC_QNETD_RUNAS="coroqnetd"\n')
    out = ok(box.run())
    assert 'installs corosync-qnetd nss-tools with dnf' in out.stdout
    assert [c for c in box.calls() if c.startswith('dnf ')] == [
        'dnf -y --setopt=timeout=15 --setopt=retries=2 --setopt=install_weak_deps=False install corosync-qnetd '
        'nss-tools']
    # TLS required in the file of the rpm, and its port named
    assert slurp(sysconfig).decode() == 'COROSYNC_QNETD_OPTIONS="-p 5404 -s req"\nCOROSYNC_QNETD_RUNAS="coroqnetd"\n'
    assert 'requires TLS' in out.stdout and sysconfig in out.stdout and 'port 5404' in out.stdout
    assert not os.path.exists(os.path.join(box.root, 'etc', 'default', 'corosync-qnetd'))


# --- remove -------------------------------------------------------------------------------------

def test_uninstall_keeps_the_ca_and_purge_takes_it(box):
    ok(box.run())
    ca = slurp(os.path.join(box.host.db, 'qnetd-cacert.crt'))
    out = ok(box.run('--uninstall'))
    assert not os.path.exists(box.socket_unit) and not os.path.exists(box.service_unit)
    assert 'systemctl disable --now pegaprox-qnetd-helper.socket' in box.calls()
    assert not os.path.exists(box.lib) and not os.path.exists(os.path.dirname(box.lib))
    assert slurp(os.path.join(box.host.db, 'qnetd-cacert.crt')) == ca
    assert 'CA' in out.stdout and '--purge' in out.stdout
    # again, and a purge while clusters vote through it is refused
    ok(box.run())
    box.host.listing(LISTING)
    out = box.run('--uninstall', '--purge')
    assert out.returncode == 1 and 'PVE-Lab' in out.stderr
    assert os.path.exists(box.host.db) and os.path.exists(box.socket_unit)
    # a QNetd that runs and does not say: refused as well
    box.flag('state-tool-down')
    out = box.run('--uninstall', '--purge')
    assert out.returncode == 1 and os.path.exists(box.host.db)
    box.flag('state-tool-down', on=False)
    box.host.listing('')
    out = ok(box.run('--uninstall', '--purge'))
    assert not os.path.exists(box.host.db) and not os.path.exists(box.socket_unit)
    assert 'systemctl disable --now corosync-qnetd.service' in box.calls()


def test_a_directory_others_can_write_is_refused(box):
    base = os.path.dirname(box.lib)
    os.makedirs(base)
    os.chmod(base, 0o777)
    out = box.run()
    assert out.returncode == 1 and 'writable by group or others' in out.stderr
    assert not os.path.exists(box.lib) and not os.path.exists(box.socket_unit)
    os.chmod(base, 0o755)
    os.symlink(os.path.join(box.root, 'tmp'), box.lib)
    out = box.run()
    assert out.returncode == 1 and 'not a plain directory' in out.stderr


def test_a_copy_others_can_change_is_named_before_it_runs_as_root(box, tmp_path):
    src = tmp_path / 'checkout'
    src.mkdir()
    for f in (HELPER, INSTALLER):
        shutil.copy2(f, str(src))
    os.chmod(str(src), 0o777)
    out = ok(box.run(script=str(src / 'install.sh')))
    assert 'WARNING' in out.stderr and 'only root can change' in out.stderr
    os.chmod(str(src), 0o755)
    for f in os.listdir(str(src)):
        os.chmod(str(src / f), 0o755)
    assert 'WARNING' not in ok(box.run(script=str(src / 'install.sh'))).stderr


def test_the_packaged_copy_is_used_where_it_is(box):
    """apt and rpm put the helper and install.sh into /usr/lib/pegaprox/qnetd themselves."""
    os.makedirs(box.lib)
    for d in (box.lib, os.path.dirname(box.lib)):
        os.chmod(d, 0o755)
    for src in (HELPER, INSTALLER):
        shutil.copy2(src, box.lib)
    ok(box.run(script=os.path.join(box.lib, 'install.sh')))
    calls = box.calls()
    assert not [c for c in calls if c.startswith('install ') and 'pegaprox-qnetd-helper' in c]
    assert 'chown root:root %s/pegaprox-qnetd-helper' % box.lib in calls
    assert os.path.exists(box.socket_unit)
    # the package owns them: uninstall takes the units and leaves the files to the package
    box.flag('state-packaged')
    ok(box.run('--uninstall', script=os.path.join(box.lib, 'install.sh')))
    assert not os.path.exists(box.socket_unit) and not os.path.exists(box.service_unit)
    assert os.path.isfile(os.path.join(box.lib, 'pegaprox-qnetd-helper'))


def test_without_the_service_user_the_socket_is_roots(box):
    """The rpm unit runs PegaProx as root: no pegaprox group, the same socket for root."""
    box.flag('state-user', on=False)
    ok(box.run())
    assert _unit(box.socket_unit)['Socket']['SocketGroup'] == 'root'
    assert os.path.isfile(os.path.join(box.lib, 'pegaprox-qnetd-helper'))
    assert os.path.isfile(os.path.join(box.host.db, 'qnetd-cacert.crt'))


def test_a_failing_init_is_said(box):
    box.flag('flag-fail-ca')
    out = box.run()
    assert out.returncode == 1 and 'could not set up corosync-qnetd' in out.stderr
    assert 'making the CA failed' in out.stderr
    assert not os.path.exists(box.socket_unit)


def test_the_port_from_the_environment_file(box):
    box.write(os.path.join(box.root, 'etc', 'default', 'corosync-qnetd'), '# options\nCOROSYNC_QNETD_OPTIONS="-p 5404 -d"\n')
    out = ok(box.run())
    assert 'port 5404' in out.stdout


@pytest.mark.skipif(not shutil.which('systemd-analyze'), reason='no systemd-analyze here')
def test_the_units_are_ones_systemd_takes(box, tmp_path):
    ok(box.run())
    units = tmp_path / 'units'
    units.mkdir()
    exe = tmp_path / 'helper'
    exe.write_text('#!/bin/sh\nexit 0\n')
    exe.chmod(0o755)
    for path in (box.socket_unit, box.service_unit):
        text = slurp(path).decode().replace('/usr/lib/pegaprox/qnetd/pegaprox-qnetd-helper', str(exe))
        text = text.replace('SocketGroup=pegaprox', 'SocketGroup=root')
        (units / os.path.basename(path)).write_text(text)
    p = subprocess.run(['systemd-analyze', 'verify', '--man=no', str(units / 'pegaprox-qnetd-helper.socket')],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60,
                       env=dict(os.environ, SYSTEMD_UNIT_PATH='%s:' % units))
    text = p.stdout.decode()
    ours = [ln for ln in text.splitlines() if 'pegaprox-qnetd-helper' in ln]
    assert p.returncode == 0 and not ours, text


def test_the_installer_keeps_to_its_rules():
    with open(INSTALLER) as fh:
        text = fh.read()
    assert text.startswith('#!/bin/sh\n') and '\nset -eu\n' in text
    assert os.access(INSTALLER, os.X_OK) and os.access(HELPER, os.X_OK)
    with open(HELPER, 'rb') as fh:
        assert fh.readline() == b'#!/usr/bin/python3 -I\n'
    assert 'install -o root -g root -m "$3"' in text
    # no sudo anywhere: no rule, no visudo, no drop-in that lifts NoNewPrivileges
    for word in ('visudo', 'NOPASSWD', 'NoNewPrivileges=no', 'sudo -n'):
        assert word not in text, word
    # root is checked before anything happens, the units go in after init worked
    main = text[text.index('# --- the run ---'):]
    assert main.index('need_root') < main.index('check_packages') < main.index('put_helper') \
        < main.index('run_init') < main.index('put_units')


# --- the witness host (--qnetd) ---------------------------------------------------------------

QNETD_CERTUTIL = r'''#!/bin/sh
echo "corosync-qnetd-certutil $*" >> "$FAKE_LOG"
db="$PEGAPROX_WITNESS_ROOT/etc/corosync/qnetd/nssdb"
mkdir -p "$db"
for f in cert9.db key4.db pkcs11.txt qnetd-cacert.crt; do echo x > "$db/$f"; done
'''

WITNESS_APT = r'''#!/bin/sh
echo "apt-get $*" >> "$FAKE_LOG"
[ -z "$FAKE_APT_FAIL" ] || exit 100
for a in "$@"; do
    case $a in
        python3-*) touch "$FAKE_STATE/pkg-${a#python3-}" ;;
        corosync-qnetd) for f in corosync-qnetd certutil corosync-qnetd-certutil; do
                cp "$FAKE_STATE/stash/$f" "$(dirname "$0")/$f"; done ;;
    esac
done
'''


def test_the_witness_host_becomes_a_qnetd_host_on_request(tmp_path):
    from test_ha_witness_install import Box, Leader
    box = Box(tmp_path)
    leader = Leader(tmp_path / 'leader')
    try:
        stash = box.state / 'stash'
        stash.mkdir()
        for name, text in (('corosync-qnetd', '#!/bin/sh\nexit 0\n'), ('certutil', '#!/bin/sh\nexit 0\n'),
                           ('corosync-qnetd-certutil', QNETD_CERTUTIL)):
            (stash / name).write_text(text)
            (stash / name).chmod(0o755)
        (box.fake / 'apt-get').write_text(WITNESS_APT)
        defaults = box.root / 'etc' / 'default'
        defaults.mkdir(parents=True)
        (defaults / 'corosync-qnetd').write_text('# stock\nCOROSYNC_QNETD_OPTIONS=""\nCOROSYNC_QNETD_RUNAS=""\n')
        out = box.run('--code', leader.code, '--port', str(box.port), '--qnetd')
        assert out.returncode == 0, out.stdout + out.stderr
        did = box.did()
        assert 'apt-get install -y --no-install-recommends corosync-qnetd libnss3-tools' in did
        assert 'corosync-qnetd-certutil -i -G' in did
        assert 'systemctl enable --now corosync-qnetd.service' in did
        # the QNetd it installed asks for TLS, restarted after the options are in place
        assert (defaults / 'corosync-qnetd').read_text() == \
            '# stock\nCOROSYNC_QNETD_OPTIONS="-s req"\nCOROSYNC_QNETD_RUNAS=""\n'
        assert oct((defaults / 'corosync-qnetd').stat().st_mode & 0o777) == '0o644'
        assert did.index('systemctl enable --now corosync-qnetd.service') \
            < did.index('systemctl restart corosync-qnetd.service')
        assert '-s req' in out.stdout
        assert (box.root / 'etc' / 'corosync' / 'qnetd' / 'nssdb' / 'cert9.db').is_file()
        assert 'add this host as a QNetd host over SSH' in out.stdout and 'port 5403' in out.stdout
        # the witness itself is what it was
        assert box.status()['paired'] is True
        # again: the CA is there, nothing is made anew
        n = len(did)
        out = box.run('--qnetd')
        assert out.returncode == 0, out.stdout + out.stderr
        assert not [d for d in box.did()[n:] if d.startswith(('corosync-qnetd-certutil', 'apt-get'))]
        # removing the witness leaves the QNetd alone
        out = box.run('--uninstall', '--force')
        assert out.returncode == 0, out.stdout + out.stderr
        assert 'corosync-qnetd stays' in out.stdout
        assert (box.root / 'etc' / 'corosync' / 'qnetd' / 'nssdb' / 'cert9.db').is_file()
        assert not [d for d in box.did() if 'disable' in d and 'corosync-qnetd' in d]
    finally:
        box.stop()
        leader.close()


@pytest.mark.parametrize('text,changed', [
    ('# stock\nCOROSYNC_QNETD_OPTIONS=""\n', '# stock\nCOROSYNC_QNETD_OPTIONS="-s req"\n'),
    (None, 'COROSYNC_QNETD_OPTIONS="-s req"\n'),
    ('', 'COROSYNC_QNETD_OPTIONS="-s req"\n'),
    ('# stock\n', '# stock\nCOROSYNC_QNETD_OPTIONS="-s req"\n'),
    ('COROSYNC_QNETD_OPTIONS="-d"\n', None),
    ('COROSYNC_QNETD_OPTIONS=""\n  COROSYNC_QNETD_OPTIONS="-s on"\n', None),
    ('COROSYNC_QNETD_OPTIONS="$(id)"\n', None),
])
def test_the_witness_sets_tls_only_on_the_file_the_package_ships(tmp_path, text, changed):
    """require_qnetd_tls on its own: the stock line or none gets -s req, any other options
    line is the admin's and stays (the run then warns)."""
    root = tmp_path / 'root'
    (root / 'etc' / 'default').mkdir(parents=True)
    f = root / 'etc' / 'default' / 'corosync-qnetd'
    if text is not None:
        f.write_text(text)
    fake = tmp_path / 'bin'
    fake.mkdir()
    (fake / 'apt-get').write_text('#!/bin/sh\nexit 0\n')
    (fake / 'apt-get').chmod(0o755)
    with open(os.path.join(ROOT, 'packaging', 'witness', 'install.sh')) as fh:
        src = fh.read()
    body = src[src.index('qnetd_options_file() {'):src.index('setup_qnetd() {')]
    script = 'set -eu\nROOT=%s\n%s\nif require_qnetd_tls; then echo SET; else echo LEFT; fi\n' % (
        shlex.quote(str(root)), body)
    p = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=30,
                       env=dict(os.environ, PATH='%s:/usr/bin:/bin' % fake))
    assert p.returncode == 0, p.stderr
    if changed is None:
        assert p.stdout.strip() == 'LEFT' and f.read_text() == text
    else:
        assert p.stdout.strip() == 'SET' and f.read_text() == changed
    assert [x.name for x in f.parent.iterdir()] == ['corosync-qnetd']


def test_the_witness_installer_without_the_flag_leaves_corosync_alone():
    with open(os.path.join(ROOT, 'packaging', 'witness', 'install.sh')) as fh:
        text = fh.read()
    assert '--qnetd) QNETD=1; shift ;;' in text
    tail = text[text.index('# --- the run ---'):]
    assert 'if [ -n "$QNETD" ]; then\n    setup_qnetd\nfi' in tail
    assert tail.count('setup_qnetd') == 1


# --- Docker, compose, deb, rpm -------------------------------------------------------------

def _instructions(path):
    """The Dockerfile as instructions, continuation lines joined, comments left out."""
    out, cur = [], ''
    with open(path) as fh:
        for line in fh:
            s = line.rstrip('\n')
            if not cur and (not s.strip() or s.lstrip().startswith('#')):
                continue
            if cur and s.lstrip().startswith('#'):
                continue
            cur += s.rstrip('\\').strip() + ' '
            if not s.endswith('\\'):
                out.append(cur.strip())
                cur = ''
    return out


def test_the_image_has_the_qnetd_without_a_baked_in_ca():
    ins = _instructions(os.path.join(ROOT, 'Dockerfile'))
    apt = [i for i in ins if i.startswith('RUN') and 'corosync-qnetd' in i and 'apt-get install' in i]
    assert len(apt) == 1 and 'libnss3-tools' in apt[0]
    # the CA the package makes on install goes in the same layer
    assert 'rm -rf /etc/corosync/qnetd/nssdb' in apt[0]
    assert apt[0].index('apt-get install') < apt[0].index('rm -rf /etc/corosync/qnetd/nssdb')
    assert 'COPY --chown=pegaprox:pegaprox packaging/qnetd/pegaprox-qnetd-helper ' \
           'packaging/qnetd/pegaprox-qnetd-helper' in ins
    dirs = [i for i in ins if i.startswith('RUN') and '/run/pegaprox-qnetd' in i][0]
    assert 'chown pegaprox:pegaprox /etc/corosync/qnetd /run/corosync-qnetd /run/pegaprox-qnetd' in dirs
    assert 'chmod 0770 /run/corosync-qnetd /run/pegaprox-qnetd' in dirs and 'chmod 0750 /etc/corosync/qnetd' in dirs
    users = [n for n, i in enumerate(ins) if 'useradd' in i][0]
    assert users < ins.index(dirs)
    assert 'EXPOSE 5403' in ins
    hc = [i for i in ins if i.startswith('HEALTHCHECK')][0]
    assert 'if [ -f /etc/corosync/qnetd/nssdb/cert9.db ]; then exec python3 pegaprox_multi_cluster.py qnetd health; fi' in hc
    assert not [i for i in ins if i.startswith('VOLUME') and 'qnetd' in i]


def _block(lines, head):
    """The lines of the YAML mapping that starts with the line head, up to the next line
    indented as little (no PyYAML in CI)."""
    start = lines.index(head)
    indent = len(head) - len(head.lstrip())
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or lines[end].lstrip().startswith('#')
                                or len(lines[end]) - len(lines[end].lstrip()) > indent):
        end += 1
    return [ln for ln in lines[start:end] if ln.strip() and not ln.lstrip().startswith('#')]


def test_compose_has_the_sidecar_in_a_profile_and_keeps_the_ca_out_of_pegaprox():
    with open(os.path.join(ROOT, 'docker-compose.yml')) as fh:
        lines = fh.read().splitlines()
    side = _block(lines, '  pegaprox-qnetd:')
    for want in ('    profiles: ["qdevice"]', '    command: ["qnetd", "run"]', '      - "5403:5403"',
                 '      - pegaprox-qnetd:/etc/corosync/qnetd', '      - pegaprox-qnetd-sock:/run/pegaprox-qnetd',
                 '      PEGAPROX_QNETD_HOST_UUID: "${PEGAPROX_QNETD_HOST_UUID:-}"',
                 '      test: ["CMD", "python3", "pegaprox_multi_cluster.py", "qnetd", "health"]',
                 '    restart: unless-stopped'):
        assert want in side, want
    # nothing of the host is mounted for the uuid: a host without the file would not start it
    assert not [ln for ln in side if '/sys/' in ln or ln.strip().startswith('- /')]
    # how to fill it is said next to it
    text = '\n'.join(lines)
    assert 'PEGAPROX_QNETD_HOST_UUID=$(sudo cat /sys/class/dmi/id/product_uuid)" >> .env' in text
    assert 'docker compose --profile qdevice up -d' in text
    # the pegaprox service: the socket volume always (empty without the sidecar), never the CA
    svc = _block(lines, '  pegaprox:')
    assert '      - pegaprox-qnetd-sock:/run/pegaprox-qnetd' in svc
    assert not [ln for ln in svc if '/etc/corosync/qnetd' in ln or 'profiles' in ln]
    # named volumes, declared
    vols = _block(lines, 'volumes:')
    assert '  pegaprox-qnetd:' in vols and '  pegaprox-qnetd-sock:' in vols
    # the witness stays as it was: commented out
    assert '  # pegaprox-witness:' in lines and '  pegaprox-witness:' not in lines


def test_the_qdevice_lines_of_compose_keep_the_house_rules():
    # the file holds older lines of its own; the sidecar's block is this feature's
    with open(os.path.join(ROOT, 'docker-compose.yml'), encoding='utf-8') as fh:
        text = fh.read()
    block = text[text.index('  # MK Oct 2026 - the QNetd'):text.index('\nvolumes:')]
    assert chr(0x2014) not in block and chr(0x2013) not in block
    assert not re.search('vm' + 'ware|v' + 'center', block, re.I)


def test_compose_parses_where_pyyaml_is_there():
    yaml = pytest.importorskip('yaml')
    with open(os.path.join(ROOT, 'docker-compose.yml')) as fh:
        doc = yaml.safe_load(fh)
    side = doc['services']['pegaprox-qnetd']
    assert side['profiles'] == ['qdevice'] and side['command'] == ['qnetd', 'run']
    assert 'profiles' not in doc['services']['pegaprox']
    assert 'pegaprox-qnetd-sock:/run/pegaprox-qnetd' in doc['services']['pegaprox']['volumes']
    assert set(doc['volumes']) >= {'pegaprox-qnetd', 'pegaprox-qnetd-sock'}


def test_the_deb_ships_the_helper_root_owned_and_enables_nothing():
    with open(os.path.join(ROOT, 'debian', 'install')) as fh:
        rows = [ln.split() for ln in fh.read().splitlines() if ln.strip()]
    assert ['packaging/qnetd/pegaprox-qnetd-helper', 'usr/lib/pegaprox/qnetd'] in rows
    assert ['packaging/qnetd/install.sh', 'usr/lib/pegaprox/qnetd'] in rows
    for name in os.listdir(os.path.join(ROOT, 'debian')):
        path = os.path.join(ROOT, 'debian', name)
        if os.path.isfile(path):
            with open(path, errors='replace') as fh:
                text = fh.read()
            assert 'sudoers' not in text or name == 'changelog', name
            assert 'pegaprox-qnetd' not in text or name == 'install', name


def test_the_rpm_ships_the_helper_root_owned():
    with open(os.path.join(ROOT, 'packaging', 'rpm', 'pegaprox.spec')) as fh:
        text = fh.read()
    for name in ('pegaprox-qnetd-helper', 'install.sh'):
        assert 'install -m 0755 packaging/qnetd/%s %%{buildroot}%%{_prefix}/lib/pegaprox/qnetd/%s' % (name, name) in text
        assert '%%attr(0755,root,root) %%{_prefix}/lib/pegaprox/qnetd/%s' % name in text
    assert 'sudoers' not in text


# --- the docs -----------------------------------------------------------------------------

def test_the_docs_cover_every_way_in():
    with open(os.path.join(ROOT, 'docs', 'qdevice.md')) as fh:
        doc = fh.read()
    for want in ('5403', 'install.sh', '/usr/lib/pegaprox/qnetd/install.sh', '/opt/PegaProx/packaging/qnetd/install.sh',
                 'qnetd run', 'pegaprox-qnetd-sock', '--qnetd', '--uninstall', '--purge', 'product_uuid',
                 'corosync-qdevice', 'pegaprox-qnetd-helper.socket', 'replace',
                 # protocol 2: the wizard, the agreement, the firewall, the package managers, compose
                 'helper protocol 2', 'I agree that PegaProx makes these changes on', 'consent_required',
                 'plan_changed', 'Open port 5403 on the QNetd host for the cluster nodes', 'firewalld', 'ufw',
                 'pve-firewall', 'firewall_unmanaged', 'state_untrusted', '/var/lib/pegaprox-qnetd/firewall.json',
                 'dnf', 'yum', 'zypper', 'mozilla-nss-tools', 'nss-tools', '/etc/sysconfig/corosync-qnetd',
                 'High Availability', '--profile qdevice', 'Docker publishes port 5403', '.env',
                 '--gpg-auto-import-keys'):
        assert want in doc, want
    for heading in ('## Updates', '## Remove', '## Troubleshooting', '## The firewall', '## Set up a cluster'):
        assert heading in doc, heading
    # what the new behaviour made wrong is gone
    for gone in ('Nothing to install by hand on Debian or Ubuntu.', 'uncomment the service',
                 'comment the sidecar out again', 'Debian and Ubuntu only'):
        assert gone not in doc, gone
    # every link inside the page goes to a heading of it
    anchors = {re.sub(r'[^a-z0-9 -]', '', h.lower()).replace(' ', '-')
               for h in re.findall(r'^#+ (.+)$', doc, re.M)}
    for target in re.findall(r'\]\(#([^)]+)\)', doc):
        assert target in anchors, target
    with open(os.path.join(ROOT, 'docs', 'ha-witness.md')) as fh:
        assert 'qdevice.md' in fh.read()


@pytest.mark.parametrize('rel', [
    'packaging/qnetd/pegaprox-qnetd-helper', 'packaging/qnetd/install.sh', 'docs/qdevice.md',
    'tests/test_qnetd_helper.py', 'tests/test_qnetd_packaging.py', 'tests/test_qnetd_followups.py',
    'tests/test_qnetd_firewall.py', 'tests/test_qnetd_pkgmgr.py', 'packaging/witness/install.sh',
])
def test_house_rules(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
        text = fh.read()
    assert chr(0x2014) not in text and chr(0x2013) not in text
    # the new files name the hypervisor ESXi, never its vendor or its manager
    if rel.endswith(('qnetd-helper', 'qnetd/install.sh', 'qdevice.md', 'test_qnetd_firewall.py',
                     'test_qnetd_pkgmgr.py')):
        assert not re.search('vm' + 'ware|v' + 'center', text, re.I)


def _needs_312(path):
    """The f-strings of `path` that only python 3.12 parses (PEP 701): inside the {} of an
    f-string its own quote, a backslash or a comment. Read with the 3.12 tokenizer, which
    takes them; the 3.10 and 3.11 this project runs on stop at the whole module."""
    import tokenize

    def delim(text):
        body = text.lstrip('rRbBfFuU')
        return body[:3] if body[:3] in ('"""', "'''") else body[:1]

    bad, stack = [], []                # per open f-string: [its quote, depth of {}]
    with open(path, 'rb') as fh:
        for tok in tokenize.tokenize(fh.readline):
            in_expr = bool(stack) and (stack[-1][1] > 0 or any(s[1] > 0 for s in stack[:-1]))
            if tok.type == tokenize.FSTRING_START:
                if in_expr and any(s[0] in delim(tok.string) for s in stack):
                    bad.append(tok.start[0])
                stack.append([delim(tok.string), 0])
            elif tok.type == tokenize.FSTRING_END:
                stack.pop()
            elif not stack:
                continue
            elif tok.type == tokenize.OP and tok.string in '{}':
                stack[-1][1] += 1 if tok.string == '{' else -1
            elif tok.type == tokenize.FSTRING_MIDDLE:
                if any(s[1] > 0 for s in stack[:-1]) and '\\' in tok.string:
                    bad.append(tok.start[0])
            elif stack[-1][1] > 0 and (tok.type == tokenize.COMMENT or (
                    tok.type == tokenize.STRING and ('\\' in tok.string or any(s[0] in delim(tok.string)
                                                                              for s in stack)))):
                bad.append(tok.start[0])
    return sorted(set(bad))


QDEVICE_PY = ['pegaprox/core/qnetd.py', 'pegaprox/api/qnetd.py', 'pegaprox/core/qdevice.py',
              'packaging/qnetd/pegaprox-qnetd-helper'] + sorted(
    'tests/' + f for f in os.listdir(os.path.join(ROOT, 'tests'))
    if f.endswith('.py') and f.startswith(('test_qnetd_', 'test_qdevice')))


@pytest.mark.skipif(sys.version_info < (3, 12), reason='before 3.12 such a module does not even get collected')
def test_no_f_string_needs_python_3_12(tmp_path):
    # the check sees one: the f-string's own quote nested, a backslash, a comment
    probe = tmp_path / 'probe.py'
    probe.write_text('x = 1\ny = f"a {str("b")} c"\nz = f"{x!r} {\'ok\'}"\n'
                     'w = f"{\'\\n\'.join([])}"\nv = f\'\'\'{x  # no\n}\'\'\'\nu = f"{f\'{x}\'}"\n')
    assert _needs_312(str(probe)) == [2, 4, 5]
    found = {rel: _needs_312(os.path.join(ROOT, rel)) for rel in QDEVICE_PY}
    assert len(found) > 15 and {rel: lines for rel, lines in found.items() if lines} == {}
