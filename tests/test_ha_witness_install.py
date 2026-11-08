"""packaging/witness/install.sh, run for real in a root of its own (#625 stage 2).

Everything that would touch the host is a stand-in on PATH: id says root, useradd and
getent keep the user as a file, chown does nothing, apt-get "installs" a module by a
file the python3 in front of the real one looks for, and systemctl starts and stops the
witness the installer put in place as a process of the test. The leader is a TLS server
in this process that serves the bundle to the open code, pairs and lets the witness
leave, with a certificate pinned in the code. The witness the installer starts is the
real one, on a free port, and answers its health check.

MK Oct 2026 (#625)
"""
import base64
import hashlib
import itertools
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pegaprox import witness as wm
from pegaprox import witness_boot as wb
from pegaprox.core import ha_wire
from test_ha_witness import A, KEYS, genesis, pub

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER = os.path.join(ROOT, 'packaging', 'witness', 'install.sh')

FAKES = {
    'id': '#!/bin/sh\nif [ "$1" = -u ] && [ $# -eq 1 ]; then echo "${FAKE_UID:-0}"; exit 0; fi\n'
          'exec /usr/bin/id "$@"\n',
    'getent': '#!/bin/sh\nif [ "$1" = passwd ] && [ -f "$FAKE_STATE/user-$2" ]; then\n'
              '    echo "$2:x:999:999::/var/lib/$2:/usr/sbin/nologin"; exit 0\nfi\nexit 2\n',
    'useradd': '#!/bin/sh\necho "useradd $*" >> "$FAKE_LOG"\nfor last; do :; done\n'
               'touch "$FAKE_STATE/user-$last"\n',
    'userdel': '#!/bin/sh\necho "userdel $*" >> "$FAKE_LOG"\nrm -f "$FAKE_STATE/user-$1"\n',
    'chown': '#!/bin/sh\necho "chown $*" >> "$FAKE_LOG"\n',
    'apt-get': '#!/bin/sh\necho "apt-get $*" >> "$FAKE_LOG"\n[ -z "$FAKE_APT_FAIL" ] || exit 100\n'
               'for a in "$@"; do case $a in python3-*) touch "$FAKE_STATE/pkg-${a#python3-}" ;; esac; done\n',
    'systemctl': r'''#!/bin/sh
echo "systemctl $*" >> "$FAKE_LOG"
stop() {
    if [ -f "$FAKE_STATE/pid" ]; then
        pid=$(cat "$FAKE_STATE/pid")
        kill "$pid" 2>/dev/null
        i=0
        while kill -0 "$pid" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
        rm -f "$FAKE_STATE/pid"
    fi
}
start() {
    nohup "$FAKE_WITNESS" run >> "$FAKE_STATE/witness.log" 2>&1 &
    echo $! > "$FAKE_STATE/pid"
}
case "$1" in
    is-active) if [ "$3" = pegaprox.service ] && [ -n "$FAKE_PEGAPROX_ACTIVE" ]; then exit 0; fi; exit 3 ;;
    restart) stop; start ;;
    start) start ;;
    try-restart) if [ -f "$FAKE_STATE/pid" ]; then stop; start; fi ;;
    stop) stop ;;
esac
exit 0
''',
    'python3': r'''#!/bin/sh
# the installer runs every python isolated (-I); what follows it is what is looked at
iso=
if [ "$1" = -I ]; then iso=-I; shift; fi
if [ "$1" = -c ]; then
    case $2 in
        "import "*) mod=${2#import }
            case " $FAKE_MISSING " in *" $mod "*) [ -f "$FAKE_STATE/pkg-$mod" ] || exit 1 ;; esac ;;
    esac
fi
if [ "$1" = -m ] && [ "$2" = venv ]; then
    echo "venv $3" >> "$FAKE_LOG"
    mkdir -p "$3/bin"
    printf '#!/bin/sh\nFAKE_MISSING= exec %s "$@"\n' "$0" > "$3/bin/python3"
    chmod 755 "$3/bin/python3"
    exit 0
fi
if [ "$1" = -m ] && [ "$2" = pip ]; then echo "pip $iso $*" >> "$FAKE_LOG"; exit 0; fi
exec REAL_PYTHON $iso "$@"
''',
}


_PORTS = itertools.count()


def _free_port():
    # A port closed here is free for anyone until the witness binds it, and with the ports the system hands out
    # that was once another worker's witness: the test then talked to it. So every worker keeps to its own.
    worker = int(os.environ.get('PYTEST_XDIST_WORKER', 'gw0')[2:])
    for _ in range(200):
        port = 20000 + worker * 200 + next(_PORTS) % 200
        with socket.socket() as s:
            try:
                s.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port
    raise AssertionError(f'no free port for worker {worker}')


def _alive(pid):
    """Whether process `pid` runs (a zombie, ended and not reaped yet, does not)."""
    try:
        with open(f'/proc/{pid}/stat', encoding='utf-8') as fh:
            return fh.read().rsplit(')', 1)[1].split()[0] != 'Z'
    except (OSError, IndexError):
        return False


class Leader:
    """The leader of the group, as far as the installer and the witness see it."""

    def __init__(self, path):
        cert, key, self.pin = wm.tls_pair(str(path))
        self.secret = secrets.token_urlsafe(32)
        self.spent = False
        self.refuse_leave = False
        self.calls = []
        self.witness = None
        leader = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
                status, out = leader.answer(self.path, dict(self.headers), body)
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.url = f'https://127.0.0.1:{self.server.server_address[1]}'
        self.code = ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, self.url, self.pin, self.secret, A)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def _signed(self, path, headers, body):
        if not self.witness or headers.get(ha_wire.PEER_HEADER) != self.witness['instance_id']:
            return False
        return ha_wire.signature_verdict(headers, 'POST', path, body, self.witness['instance_id'],
                                         self.witness['public_key'], A, time.time(), 0) == 'ok'

    def bundle(self):
        from pegaprox.core import ha
        entries = {}
        for rel in ha.WITNESS_BUNDLE_FILES:
            with open(os.path.join(ROOT, rel), 'rb') as fh:
                entries[rel] = fh.read()
        from pegaprox.constants import PEGAPROX_VERSION
        entries['version.json'] = json.dumps({'version': PEGAPROX_VERSION, 'wire': ha_wire.WITNESS_WIRE}).encode()
        archive = ha.pack_bundle(entries)
        digest = hashlib.sha256(archive).hexdigest()
        manifest = {'release': PEGAPROX_VERSION, 'wire': ha_wire.WITNESS_WIRE, 'sha256': digest,
                    'size': len(archive), 'files': sorted(entries), 'by': A,
                    'name': wb.bundle_name(PEGAPROX_VERSION, digest)}
        sig = ha_wire.private_key(KEYS[A]).sign(ha_wire.bundle_message(manifest))
        return {'manifest': manifest, 'sig': base64.b64encode(sig).decode(),
                'archive': base64.b64encode(archive).decode()}

    def answer(self, path, headers, body):
        data = json.loads(body or b'{}')
        signed = self._signed(path, headers, body)
        self.calls.append((path, 'signed' if signed else data.get('code')))
        if path == '/api/ha/witness/bundle':
            if headers.get(ha_wire.PEER_HEADER):
                # a signed call, as the route takes it: the witness, or nobody
                if not signed:
                    return 401, {'error': 'Not the witness of this group', 'instance_id': A}
                if data.get('check') is True:
                    return 200, {'witness': True, 'instance_id': A}
                return 200, self.bundle()
            if data.get('code') == self.secret and not self.spent:
                return 200, self.bundle()
            return 403, {'error': 'The pairing code is wrong or has expired'}
        if path == '/api/ha/peer/pair-witness':
            if data.get('code') != self.secret or self.spent:
                return 403, {'error': 'The pairing code is wrong or has expired'}
            self.spent = True
            self.witness = {'instance_id': data['instance_id'], 'public_key': data['public_key'],
                            'url': data['url']}
            payload = {'public_key': pub(A), 'epoch': 1, 'chain': [genesis()], 'mode': 'manual'}
            return 200, {'instance_id': A, 'epoch': 1,
                         'sealed': ha_wire.seal(self.secret, payload, aad=data['instance_id'])}
        if path == '/api/ha/peer/witness-leave':
            if not signed:
                return 401, {'error': 'Not the witness of this group'}
            if self.refuse_leave:
                return 409, {'code': 'HA_AUTO_MODE', 'error': 'Without the witness this group would have '
                                                            'fewer than 3 votes'}
            self.witness = None
            return 200, {'success': True}
        return 404, {'error': 'Not found'}


class Box:
    """The host the witness goes on: a root, the stand-ins, the log of what they did."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.root = tmp / 'root'
        self.root.mkdir()
        self.fake = tmp / 'fake'
        self.fake.mkdir()
        self.state = tmp / 'fake-state'
        self.state.mkdir()
        self.log = tmp / 'fake.log'
        self.log.write_text('')
        for name, text in FAKES.items():
            (self.fake / name).write_text(text.replace('REAL_PYTHON', sys.executable))
            (self.fake / name).chmod(0o755)
        self.port = _free_port()
        self.bin = str(self.root / 'usr' / 'local' / 'bin' / 'pegaprox-witness')
        self.opt = self.root / 'opt' / 'pegaprox-witness'
        self.var = self.root / 'var' / 'lib' / 'pegaprox-witness'
        self.env = dict(os.environ, PATH=f"{self.fake}:{os.environ['PATH']}", TMPDIR=str(tmp),
                        PEGAPROX_WITNESS_ROOT=str(self.root), PEGAPROX_WITNESS_WAIT='30',
                        PEGAPROX_PORT=str(_free_port()), PEGAPROX_WITNESS_PORT=str(self.port),
                        PEGAPROX_WITNESS_HOST='127.0.0.1', FAKE_LOG=str(self.log),
                        FAKE_STATE=str(self.state), FAKE_WITNESS=self.bin, FAKE_MISSING='',
                        FAKE_APT_FAIL='', FAKE_PEGAPROX_ACTIVE='')
        for var in ('PEGAPROX_WITNESS_DIR', 'STATE_DIRECTORY', 'PEGAPROX_WITNESS_CODE_DIR',
                    'PEGAPROX_WITNESS_INSTALL', 'PEGAPROX_WITNESS_AUTO_UPDATE'):
            self.env.pop(var, None)

    def run(self, *args, script=INSTALLER, **env):
        return subprocess.run(['sh', script] + list(args), env=dict(self.env, **env), capture_output=True,
                              text=True, timeout=240, cwd=str(self.tmp))

    def cmd(self, *args, **env):
        return subprocess.run([self.bin] + list(args), env=dict(self.env, **env), capture_output=True,
                              text=True, timeout=120, cwd=str(self.tmp))

    def did(self):
        return self.log.read_text().splitlines()

    def stop(self):
        pid = self.state / 'pid'
        if not pid.exists():
            return
        try:
            n = int(pid.read_text())
            os.kill(n, 15)
        except (OSError, ValueError):
            return
        # and gone, also where it does not stop when asked (code that hangs): no process
        # of a test outlives it
        for _ in range(100):
            if not _alive(n):
                return
            time.sleep(0.1)
        try:
            os.kill(n, 9)
        except OSError:
            pass

    def status(self):
        out = self.cmd('status')
        assert out.returncode == 0, out.stderr
        return json.loads(out.stdout)


@pytest.fixture
def box(tmp_path):
    b = Box(tmp_path)
    yield b
    b.stop()


@pytest.fixture
def leader(tmp_path):
    lead = Leader(tmp_path / 'leader')
    yield lead
    lead.close()


def _installed_name(box):
    return os.readlink(box.opt / 'current')


def test_the_installer_puts_the_witness_on_the_host_and_starts_it(box, leader):
    out = box.run('--code', leader.code, '--port', str(box.port))
    assert out.returncode == 0, out.stdout + out.stderr
    from pegaprox.constants import PEGAPROX_VERSION
    # the code, versioned, with the link; boot.py and the installer next to it
    name = _installed_name(box)
    assert name.startswith(f'{PEGAPROX_VERSION}-') and wb.NAME_RE.fullmatch(name)
    with open(os.path.join(ROOT, 'pegaprox', 'witness_boot.py'), 'rb') as fh:
        assert (box.opt / 'boot.py').read_bytes() == fh.read()
    with open(INSTALLER, 'rb') as fh:
        assert (box.opt / 'install.sh').read_bytes() == fh.read()
    assert (box.opt / name / 'pegaprox' / 'witness.py').is_file()
    assert oct((box.opt / name).stat().st_mode & 0o777) == '0o755'
    # the command, the unit as the repository has it, and what this run set
    launcher = open(box.bin).read()
    assert f"PEGAPROX_WITNESS_BASE='{box.opt}/current'" in launcher
    assert f"exec '{box.fake}/python3' -I '{box.opt}/boot.py'" in launcher
    with open(os.path.join(ROOT, 'systemd', 'pegaprox-witness.service'), 'rb') as fh:
        unit = box.root / 'etc' / 'systemd' / 'system' / 'pegaprox-witness.service'
        assert unit.read_bytes() == fh.read()
    dropin = (unit.parent / 'pegaprox-witness.service.d' / 'install.conf').read_text()
    assert f'Environment=PEGAPROX_WITNESS_PORT={box.port}' in dropin and 'AUTO_UPDATE' not in dropin
    did = box.did()
    assert any(d.startswith('useradd --system --user-group --home-dir /var/lib/pegaprox-witness') and
               d.endswith('pegaprox-witness') for d in did)
    assert f'chown pegaprox-witness:pegaprox-witness {box.var}' in did
    for d in ('systemctl daemon-reload', 'systemctl enable pegaprox-witness.service',
              'systemctl restart pegaprox-witness.service'):
        assert d in did, d
    assert not [d for d in did if d.startswith('apt-get')]
    # the bundle for the open code, then the pairing that spends it
    assert [c[0] for c in leader.calls[:2]] == ['/api/ha/witness/bundle', '/api/ha/peer/pair-witness']
    assert leader.calls[0][1] == leader.secret
    assert leader.witness['url'] == f'https://127.0.0.1:{box.port}'
    # paired, running, healthy, and the admin is told what to open
    st = box.status()
    assert st['paired'] is True and st['leader'] == leader.url and st['release'] == PEGAPROX_VERSION
    assert st['auto_update'] is True
    assert box.cmd('health').returncode == 0
    assert 'does not answer' not in out.stdout
    assert f'Open TCP port {box.port} on this host for the members of the group (the leader is 127.0.0.1)' \
        in out.stdout
    assert 'the witness runs' in out.stdout and 'updates from the leader on' in out.stdout


def test_run_again_it_repairs_and_updates_and_keeps_what_was_set(box, leader):
    assert box.run('--code', leader.code, '--port', str(box.port), '--no-auto-update').returncode == 0
    name = _installed_name(box)
    unit_dir = box.root / 'etc' / 'systemd' / 'system'
    os.unlink(box.bin)
    (unit_dir / 'pegaprox-witness.service').write_text('broken')
    # the same line again: the code is spent by now, and left out
    out = box.run('--code', leader.code)
    assert out.returncode == 0, out.stdout + out.stderr
    assert 'paired already - the code is left out' in out.stdout
    assert os.access(box.bin, os.X_OK) and (unit_dir / 'pegaprox-witness.service').read_text() != 'broken'
    # it asked its leader for newer code with its own signature, and there was none
    assert leader.calls[-1] == ('/api/ha/witness/bundle', 'signed') and 'already' in out.stdout
    assert [c[0] for c in leader.calls].count('/api/ha/peer/pair-witness') == 1
    assert _installed_name(box) == name
    dropin = (unit_dir / 'pegaprox-witness.service.d' / 'install.conf').read_text()
    assert 'Environment=PEGAPROX_WITNESS_AUTO_UPDATE=0' in dropin
    assert f'Environment=PEGAPROX_WITNESS_PORT={box.port}' in dropin
    assert 'updates from the leader off' in out.stdout
    # and turned back on
    out = box.run('--auto-update', '--allow', '192.0.2.0/24', '--allow', '2001:db8::/48')
    assert out.returncode == 0, out.stdout + out.stderr
    dropin = (unit_dir / 'pegaprox-witness.service.d' / 'install.conf').read_text()
    assert 'AUTO_UPDATE' not in dropin and 'Environment=PEGAPROX_WITNESS_ALLOW=192.0.2.0/24,2001:db8::/48' in dropin


def test_uninstall_leaves_the_group_and_removes_everything(box, leader):
    assert box.run('--code', leader.code, '--port', str(box.port)).returncode == 0
    wid = leader.witness['instance_id']
    leader.refuse_leave = True
    out = box.cmd('uninstall')
    assert out.returncode != 0 and 'the leader did not take the witness out' in out.stderr
    assert box.var.is_dir() and os.path.exists(box.bin) and (box.state / 'pid').exists()
    assert box.did()[-1] == 'systemctl start pegaprox-witness.service'
    leader.refuse_leave = False
    out = box.cmd('uninstall')
    assert out.returncode == 0, out.stdout + out.stderr
    assert leader.witness is None and ('/api/ha/peer/witness-leave', 'signed') in leader.calls
    left = [os.path.relpath(os.path.join(d, f), box.root) for d, _dirs, files in os.walk(box.root) for f in files]
    assert left == [] and not box.opt.exists() and not box.var.exists()
    assert not (box.root / 'etc' / 'systemd' / 'system' / 'pegaprox-witness.service.d').exists()
    assert 'userdel pegaprox-witness' in box.did() and not (box.state / 'user-pegaprox-witness').exists()
    assert not (box.state / 'pid').exists()
    del wid


def test_uninstall_force_removes_it_when_the_leader_cannot_be_told(box, leader):
    assert box.run('--code', leader.code, '--port', str(box.port)).returncode == 0
    leader.close()
    out = box.run('--uninstall', '--force', script=str(box.opt / 'install.sh'))
    assert out.returncode == 0, out.stdout + out.stderr
    assert not box.opt.exists() and not box.var.exists() and not os.path.exists(box.bin)


@pytest.mark.parametrize('case', ['service', 'port'])
def test_it_refuses_a_host_that_runs_pegaprox(box, leader, case):
    env = {}
    if case == 'service':
        env['FAKE_PEGAPROX_ACTIVE'] = '1'
        said = 'PegaProx runs on this host (pegaprox.service is active)'
    else:
        app = ThreadingHTTPServer(('127.0.0.1', 0), _Health)
        threading.Thread(target=app.serve_forever, daemon=True).start()
        env['PEGAPROX_PORT'] = str(app.server_address[1])
        said = f"PegaProx answers on port {app.server_address[1]} of this host"
    try:
        out = box.run('--code', leader.code, **env)
    finally:
        if case == 'port':
            app.shutdown()
            app.server_close()
    assert out.returncode == 1 and said in out.stderr and 'third site' in out.stderr
    assert leader.calls == [] and not box.opt.exists()


class _Health(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        data = json.dumps({'status': 'ok', 'version': '1.2.0'}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def test_missing_modules_come_from_the_package_manager(box, leader):
    out = box.run('--code', leader.code, '--port', str(box.port), FAKE_MISSING='gevent requests')
    assert out.returncode == 0, out.stdout + out.stderr
    apt = [d for d in box.did() if d.startswith('apt-get install')]
    assert apt == ['apt-get install -y --no-install-recommends python3-gevent python3-requests']
    assert not (box.opt / 'venv').exists()


def test_without_packages_a_virtualenv(box, leader):
    out = box.run('--code', leader.code, '--port', str(box.port), FAKE_MISSING='gevent', FAKE_APT_FAIL='1')
    assert out.returncode == 0, out.stdout + out.stderr
    did = box.did()
    assert f'venv {box.opt}/venv' in did
    # next to the system's packages: only what has none comes from PyPI
    assert any(d.startswith('pip -I -m pip install --quiet gevent') for d in did), did
    assert f"'{box.opt}/venv/bin/python3' -I '{box.opt}/boot.py'" in open(box.bin).read()
    assert 'using a virtualenv' in out.stdout


@pytest.mark.parametrize('case', ['not root', 'no code', 'not a code', 'shell in the code', 'wrong pin',
                                  'used code', 'bad allow'])
def test_it_stops_with_a_clear_word(box, leader, tmp_path, case):
    env, args = {}, ['--code', leader.code]
    if case == 'not root':
        env['FAKE_UID'] = '1000'
        said = 'run it as root'
    elif case == 'no code':
        args = []
        said = '--code is needed'
    elif case == 'not a code':
        args = ['--code', 'pgxha1_abc']
        said = 'not a PegaProx witness code'
    elif case == 'shell in the code':
        args = ['--code', 'pgxwt1_$(touch /tmp/x)']
        said = 'the code is damaged'
    elif case == 'wrong pin':
        _c, _k, other = wm.tls_pair(str(tmp_path / 'other'))
        info = ha_wire.decode_code(ha_wire.WITNESS_CODE_PREFIX, leader.code)
        args = ['--code', ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, info['url'], other, info['secret'], A)]
        said = 'does not match the pin in the code'
    elif case == 'used code':
        leader.spent = True
        said = 'the leader refused the witness code: The pairing code is wrong or has expired'
    else:
        args += ['--allow', '10.0.0.0/8;reboot']
        said = '--allow takes networks'
    out = box.run(*args, **env)
    assert out.returncode != 0 and said in out.stderr, out.stdout + out.stderr
    assert not (box.var / 'ha_witness.json').exists() and not (box.state / 'pid').exists()
    if case in ('wrong pin', 'shell in the code', 'not a code'):
        assert leader.calls == []


def _shellcheck():
    return os.environ.get('SHELLCHECK') or shutil.which('shellcheck')


@pytest.mark.skipif(not _shellcheck(), reason='shellcheck is not installed')
def test_shellcheck_has_nothing_to_say(box, leader):
    out = subprocess.run([_shellcheck(), '-s', 'sh', INSTALLER], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout
    # and nothing about the command it writes either
    assert box.run('--code', leader.code, '--port', str(box.port)).returncode == 0
    out = subprocess.run([_shellcheck(), '-s', 'sh', box.bin], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout


def test_the_help_is_the_head_of_the_file():
    out = subprocess.run(['sh', INSTALLER, '--help'], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0 and out.stdout.startswith('PegaProx witness installer')
    assert '--uninstall' in out.stdout and 'set -eu' not in out.stdout
