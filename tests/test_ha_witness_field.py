"""The witness on the hosts of many admins (#625 stage 2), what a fourth look found.

sudo on RHEL and its rebuilds, whose path has no /usr/local/bin; the commands next to an
update that has not run yet; the leader's IP allow list in front of the installer and of
the witness's update; RHEL 9, where python3-gevent is only in EPEL; the Docker line on a
Testing build and on a release whose image has no witness; update --to-leader and the
installer run again; code changed under the same release; the last update that read
"installed" for ever; an update that hangs; the placeholder in the Docker and manual
lines; the same line after the leader updated; the lines on a witness host of its own,
over IPv4 and IPv6 and behind a proxy. Each runs the way it failed: the installer for
real in a root of its own
(tests/test_ha_witness_install.py), the group in process (tests/test_ha_witness_group.py),
a start as a process of its own, the witness host in a network namespace of its own
where this host allows one.

MK Oct 2026 (#625)
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time

import pytest

from pegaprox import witness as wm
from pegaprox import witness_boot as wb
from pegaprox.core import ha_wire
from test_ha_witness import A, KEYS
from test_ha_witness_install import Box, Leader, _alive, _free_port
from test_ha_witness_install import box, leader  # noqa: F401  (fixtures)
from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_members import IDS, _sync, group  # noqa: F401  (the fixture)
from test_ha_witness_group import WURL, _code, _form
from test_ha_witness_delivery import host, _entries, _release, _secret, _tree, BUNDLE, INSTALLER  # noqa: F401
from test_ha_witness_hosts import SYSTEMCTL_WITH_DROPIN, _answers, _bundle_of, _checkout, _manual_env, _until
from test_ha_witness_rollout import GetLeader, INSTALLER_PATH, HANG, QUICK, UP_THEN_HANG, _ended, _start, \
    _tree_with

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
SVC = 'pegaprox-witness.service'


def _read(*rel):
    with open(os.path.join(ROOT, *rel), encoding='utf-8') as fh:
        return fh.read()


def _doc():
    return ' '.join(_read('docs', 'ha-witness.md').split())


def _state(box):
    st = json.load(open(box.var / 'ha_witness.json'))
    _c, _k, pin = wm.tls_pair(str(box.var))
    return st['instance_id'], pin


def _tell(box, leader, release='9.9.9', update=True, name=None):
    """The leader's word to the installed witness, signed as the leader signs it."""
    wid, pin = _state(box)
    data = {'release': release, 'wire': ha_wire.WITNESS_WIRE, 'update': update, 'url': leader.url,
            'fingerprint': leader.pin}
    if name:
        data['name'] = name
    body = ha_wire.wire_body(data)
    h = ha_wire.signed_headers(ha_wire.private_key(KEYS[A]), A, wid, 'POST', wm.UPDATE_PATH, body, time.time())
    return wm.https_call('POST', f'https://127.0.0.1:{box.port}', pin, wm.UPDATE_PATH, body, h)


def _cmd(box, *args, timeout=60, **env):
    """A pegaprox-witness command on the witness host, which has to end by itself."""
    try:
        return subprocess.run([box.bin] + list(args), env=dict(box.env, **env), capture_output=True, text=True,
                              timeout=timeout, cwd=str(box.tmp))
    except subprocess.TimeoutExpired:
        pytest.fail(f'pegaprox-witness {" ".join(args)} gave no answer within {timeout} s')


def _healthy(box):
    return _answers('127.0.0.1', box.port) is True


def _service_gone(box):
    pid = int((box.state / 'pid').read_text())
    return _until(lambda: not _alive(pid), 60)


def _install(box, leader, *args):
    out = box.run('--code', leader.code, '--port', str(box.port), *args)
    assert out.returncode == 0, out.stdout[-1500:] + out.stderr[-1500:]
    assert _until(lambda: _healthy(box), 30)
    return out


# --- (a) sudo on RHEL and its rebuilds -------------------------------------------------------------------------

# sudo as RHEL 8/9 and their rebuilds ship it: Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/bin. It looks
# the command up there alone (inside the root of the test, where the installer puts everything); the rest of
# the host is the test's
RHEL_SUDO = '''#!/bin/sh
R=$PEGAPROX_WITNESS_ROOT
cmd=
for d in "$R/sbin" "$R/bin" "$R/usr/sbin" "$R/usr/bin"; do
    if [ -x "$d/$1" ]; then cmd="$d/$1"; break; fi
done
[ -n "$cmd" ] || { echo "sudo: $1: command not found" >&2; exit 1; }
shift
exec "$cmd" "$@"
'''


def _rhel_sudo(box):
    (box.fake / 'sudo').write_text(RHEL_SUDO)
    (box.fake / 'sudo').chmod(0o755)


def _sudo(box, line):
    return subprocess.run(['sh', '-c', f'sudo {line}'], env=box.env, capture_output=True, text=True, timeout=120,
                          cwd=str(box.tmp))


def test_sudo_finds_the_command_where_its_path_has_no_usr_local_bin(box, leader):
    out = _install(box, leader)
    link = box.root / 'usr' / 'bin' / 'pegaprox-witness'
    assert os.readlink(link) == '../local/bin/pegaprox-witness'
    assert 'sudo pegaprox-witness status' in out.stdout
    _rhel_sudo(box)
    st = _sudo(box, 'pegaprox-witness status')
    assert st.returncode == 0, st.stderr
    assert json.loads(st.stdout)['paired'] is True
    # what the leader shows for an update by hand works there too
    assert wb.UPDATE_COMMANDS['systemd'] == 'sudo pegaprox-witness update'
    up = _sudo(box, 'pegaprox-witness update')
    assert up.returncode == 0 and 'already' in up.stdout, up.stdout + up.stderr
    # run again it keeps the link; uninstall takes it with everything else
    assert box.run(script=str(box.opt / 'install.sh')).returncode == 0
    assert os.readlink(link) == '../local/bin/pegaprox-witness'
    un = _sudo(box, 'pegaprox-witness uninstall')
    assert un.returncode == 0, un.stdout + un.stderr
    assert leader.witness is None and not os.path.lexists(link)


def test_a_command_of_that_name_that_is_not_the_witness_stays(box, leader):
    other = box.root / 'usr' / 'bin' / 'pegaprox-witness'
    other.parent.mkdir(parents=True)
    other.write_text('#!/bin/sh\necho somebody else\n')
    out = _install(box, leader)
    assert other.read_text() == '#!/bin/sh\necho somebody else\n'
    assert f'{other} is there already and not the witness\'s - left as it is' in out.stdout
    assert box.cmd('uninstall').returncode == 0
    assert other.read_text() == '#!/bin/sh\necho somebody else\n'
    assert 'linked from /usr/bin' in _doc() and 'sudo: pegaprox-witness: command not found' in _doc()


# --- (b) the commands next to an update that has not run yet ---------------------------------------------------

BROKEN = {
    'crash': b'raise SystemExit("this release is broken")\n',
    'exit78': (b'import sys\n'
               b'def main(argv=None):\n'
               b'    print("pegaprox-witness: ha_witness.json is no witness state file", file=sys.stderr)\n'
               b'    return 78\n'),
    'hang': b'import time\ndef main(argv=None):\n    time.sleep(10 ** 6)\n',
}


@pytest.mark.parametrize('kind', ['crash', 'hang'])
def test_the_commands_next_to_an_update_that_has_not_run_yet(box, leader, kind):
    _install(box, leader)
    before = box.status()['release']
    leader.bundle = lambda: _bundle_of('9.9.9', {'pegaprox/witness.py': BROKEN[kind]})
    assert _tell(box, leader) == (200, {'accepted': True})
    # it puts the update in place and stops (75) for the start into it, which is the unit's to make
    assert _service_gone(box)
    assert os.readlink(box.var / 'code' / 'current').startswith('9.9.9-')
    st = _cmd(box, 'status')
    assert st.returncode == 0, st.stderr
    said = json.loads(st.stdout)
    # the release the service ran, not that of this command's code or of the update
    assert said['release'] == before and said['last_update']['state'] == 'installed'
    assert _cmd(box, 'fingerprint').returncode == 0
    # nothing answers on the port now, and it says so in time
    assert _cmd(box, 'health').returncode == 1
    # the leader moves on to code that works: taken by hand, from the code before
    leader.bundle = lambda: _bundle_of('9.9.10')
    up = _cmd(box, 'update', PEGAPROX_WITNESS_NO_RESTART='1')
    assert up.returncode == 0 and 'Release 9.9.10 is in place' in up.stdout, up.stdout + up.stderr
    un = _cmd(box, 'uninstall', timeout=120)
    assert un.returncode == 0, un.stdout + un.stderr
    assert leader.witness is None


def _fake_tree(path, release, main):
    os.makedirs(os.path.join(path, 'pegaprox', 'core'), exist_ok=True)
    with open(os.path.join(path, 'version.json'), 'w') as fh:
        json.dump({'version': release}, fh)
    with open(os.path.join(path, 'pegaprox', '__init__.py'), 'w') as fh:
        fh.write('')
    with open(os.path.join(path, 'pegaprox', 'core', 'ha_wire.py'), 'w') as fh:
        fh.write('WITNESS_WIRE = 2\n')
    with open(os.path.join(path, 'pegaprox', 'witness.py'), 'w') as fh:
        fh.write(main)
    return os.path.realpath(str(path))


def test_a_command_runs_the_code_that_came_up_before_an_update_nobody_tried(tmp_path):
    state = str(tmp_path / 'state')
    root = os.path.join(state, wb.UPDATES)
    say = 'def main(argv=None):\n    return 0\n'
    base = _fake_tree(tmp_path / 'base', '1.0.0', say)
    old = _fake_tree(os.path.join(root, '1.1.0-aaaaaaaaaaaa'), '1.1.0', say)
    new = _fake_tree(os.path.join(root, '1.2.0-bbbbbbbbbbbb'), '1.2.0', say)
    wb.switch(root, '1.1.0-aaaaaaaaaaaa')
    wb.mark_ok(state, old)
    wb.switch(root, '1.2.0-bbbbbbbbbbbb')
    # previous, which came up here
    assert wb.choose(base, state, counting=False) == (old, False)
    # the start of the service still tries it, and once it came up the commands run it too
    assert wb.choose(base, state) == (new, True)
    wb.mark_ok(state, new)
    assert wb.choose(base, state, counting=False) == (new, False)
    # a previous that never came up either: the base
    newer = _fake_tree(os.path.join(root, '1.3.0-cccccccccccc'), '1.3.0', say)
    nxt = _fake_tree(os.path.join(root, '1.4.0-dddddddddddd'), '1.4.0', say)
    wb.switch(root, '1.3.0-cccccccccccc')
    wb.switch(root, '1.4.0-dddddddddddd')
    assert newer and wb.choose(base, state, counting=False) == (base, False)
    assert wb.choose(base, state) == (nxt, True)
    # the only code there is runs, tried or not
    lone = str(tmp_path / 'lone')
    _fake_tree(os.path.join(lone, wb.UPDATES, '2.0.0-eeeeeeeeeeee'), '2.0.0', say)
    wb.switch(os.path.join(lone, wb.UPDATES), '2.0.0-eeeeeeeeeeee')
    assert wb.choose(str(tmp_path / 'nothing'), lone, counting=False)[0].endswith('2.0.0-eeeeeeeeeeee')


def test_no_command_waits_for_ever(tmp_path, monkeypatch):
    tree = _fake_tree(tmp_path / 'tree', '1.0.0', 'import time\ndef main(argv=None):\n    time.sleep(10 ** 6)\n')
    env = wb.runner_env(tree, False, 'systemd', environ=dict(os.environ), limit=2)
    t0 = time.time()
    proc = subprocess.Popen([PY, '-I', '-c', wb.RUNNER, 'status'], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    _out, err = _ended(proc)
    assert proc.returncode == 1 and 'this command did not finish within 2 s - stopped' in err, err
    assert time.time() - t0 < 30
    # every command but run, update a little longer
    assert wb.command_limit(['--dir', '/x', 'run']) is None and wb.command_limit([]) is None
    assert wb.command_limit(['--dir', '/x', 'status']) == wb.COMMAND_LIMIT
    assert wb.command_limit(['update', '--to-leader']) == wb.COMMAND_LIMITS['update'] > wb.COMMAND_LIMIT
    got = []
    monkeypatch.setattr(wb.os, 'execve', lambda exe, argv, env: got.append(env))
    wb.run(tree, ['--dir', str(tmp_path), 'leave'])
    wb.run(tree, ['--dir', str(tmp_path), 'run'])
    assert got[0]['PEGAPROX_WITNESS_LIMIT'] == str(wb.COMMAND_LIMIT) and 'PEGAPROX_WITNESS_LIMIT' not in got[1]


def test_status_says_the_release_the_service_runs(tmp_path, capsys):
    d = wm.check_dir(str(tmp_path / 'w'))
    with open(os.path.join(d, wm.UPDATE_NAME), 'w') as fh:
        json.dump({'running': {'release': '9.9.9', 'wire': 3, 'auto_update': True, 'install': 'systemd',
                               'code': '/x'}, 'leader': {'release': '9.9.10', 'wire': 3}}, fh)
    assert wm.main(['--dir', d, 'status']) == 0
    st = json.loads(capsys.readouterr().out)
    assert (st['release'], st['wire'], st['auto_update']) == ('9.9.9', 3, True)
    # against what the service runs, not this command's code
    assert st['outdated']['release'] == '9.9.10'
    os.unlink(os.path.join(d, wm.UPDATE_NAME))
    assert wm.main(['--dir', d, 'status']) == 0
    assert json.loads(capsys.readouterr().out)['release'] == wm.RELEASE


# --- (c) the leader's IP allow list ---------------------------------------------------------------------------

WIP = '203.0.113.50'
_XHR = {'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json'}


def _from(auto, n, method, path, body, headers, ip=WIP):
    with auto.g.at(n):
        return auto.g.client.open(path, method=method, data=body or None, headers=headers,
                                  base_url='http://localhost', environ_base={'REMOTE_ADDR': ip})


def _allow_only(monkeypatch, nets, blocked=()):
    import pegaprox.api.settings as st
    monkeypatch.setattr(st, '_ip_whitelist_enabled', True)
    monkeypatch.setattr(st, '_ip_whitelist', set(nets))
    monkeypatch.setattr(st, '_ip_blacklist', set(blocked))


def _signed(host, path, raw, key=None):
    key = key or host.file()['signing_key']
    h = ha_wire.signed_headers(ha_wire.private_key(key), host.w.instance_id(), IDS['a'], 'POST', path, raw,
                               time.time())
    return dict(h, **_XHR)


def test_the_allow_list_lets_the_witness_signature_through_and_keeps_the_open_code_out(auto, host, seed,
                                                                                      monkeypatch):
    import pegaprox.api.ha as ha_api
    import pegaprox.api.settings as st
    auto.pair(seed, 'b')
    code = _code(auto).get_json()['code']
    # the admin keeps the leader to the admin network, as Settings > Security offers
    _allow_only(monkeypatch, {'10.20.0.0/24'})
    ha_api._bundle_attempts.reset()
    # the open code stays behind the list: the download, the installer's bundle, the pairing
    raw = json.dumps({'code': _secret(code)}).encode()
    for method, path, body in (('GET', INSTALLER, b''), ('POST', BUNDLE, raw), ('POST', wm.PAIR_PATH, raw)):
        r = _from(auto, 'a', method, path, body, _XHR if body else {})
        assert r.status_code == 403 and r.get_json()['error'] == 'Access denied', path
    said = wm.allow_list_refusal(r.status_code, r.get_json())
    assert said.startswith(f"The leader's IP allow list refuses this host - add {WIP} there")
    # paired (from an address the list names - here with the list off for a moment)
    monkeypatch.setattr(st, '_ip_whitelist_enabled', False)
    host.w.join(code, WURL)
    host.w.start()
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    _allow_only(monkeypatch, {'10.20.0.0/24'})
    # its update: signed with its key, it passes the list as a member's signed call does
    body = ha_wire.wire_body({'release': '1.0.0', 'wire': ha_wire.WITNESS_WIRE})
    r = _from(auto, 'a', 'POST', BUNDLE, body, _signed(host, BUNDLE, body))
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['manifest']['release'] == _release()
    # with another key it is the list that refuses, before the route
    ha_api._peer_failures.reset()
    r = _from(auto, 'a', 'POST', BUNDLE, body, _signed(host, BUNDLE, body, key=ha_wire.new_signing_key()))
    assert r.status_code == 403 and r.get_json()['error'] == 'Access denied'
    # a blacklist entry stays a no
    _allow_only(monkeypatch, {'10.20.0.0/24'}, blocked={WIP})
    r = _from(auto, 'a', 'POST', BUNDLE, body, _signed(host, BUNDLE, body))
    assert r.status_code == 403
    _allow_only(monkeypatch, {'10.20.0.0/24'})
    # its signature opens nothing else: a member's route stays shut to it
    renew = ha_wire.wire_body({})
    r = _from(auto, 'a', 'POST', wm.RENEW_PATH, renew, _signed(host, wm.RENEW_PATH, renew))
    assert r.status_code == 403 and r.get_json()['error'] == 'Access denied'
    # and its leaving passes the list to the route, which takes it out
    leave = ha_wire.wire_body({'epoch': host.file().get('epoch') or 0})
    r = _from(auto, 'a', 'POST', wm.LEAVE_PATH, leave, _signed(host, wm.LEAVE_PATH, leave))
    assert r.status_code == 200, r.get_json()
    assert not auto.file('a').get('witness')


class _DeniedLeader(Leader):
    """A leader whose IP allow list does not name the witness host."""

    def answer(self, path, headers, body):
        self.calls.append((path, 'denied'))
        return 403, {'error': 'Access denied', 'message': 'Your IP address is not allowed to access this service',
                     'ip': WIP}


def test_the_installer_says_so_when_the_leaders_allow_list_refuses_it(box, tmp_path):
    lead = _DeniedLeader(tmp_path / 'denied')
    try:
        out = box.run('--code', lead.code, '--port', str(box.port))
    finally:
        lead.close()
    assert out.returncode != 0
    assert f"the leader's IP allow list refuses this host - add {WIP} there" in out.stderr, out.stderr
    assert 'the leader refused the witness code' not in out.stderr
    assert not (box.var / 'ha_witness.json').exists()
    doc = _doc()
    assert "the leader's IP allow list refuses this host" in doc and 'pass the list' in doc


# --- (d) RHEL, Rocky Linux and AlmaLinux 9: python3-gevent is in EPEL --------------------------------------------

# what dnf does there without EPEL: a name it has no match for, and nothing of the whole transaction goes in
DNF = r'''#!/bin/sh
echo "dnf $*" >> "$FAKE_LOG"
for a in "$@"; do
    case $a in python3-gevent) echo "No match for argument: python3-gevent" >&2
                               echo "Error: Unable to find a match: python3-gevent" >&2; exit 1 ;; esac
done
for a in "$@"; do case $a in python3-*) touch "$FAKE_STATE/pkg-${a#python3-}" ;; esac; done
'''


def _rhel_path(box):
    """A PATH like a RHEL host's: dnf, no apt-get, and everything else of this host."""
    d = box.tmp / 'rhelbin'
    d.mkdir()
    for src in ('/usr/bin', '/bin', '/usr/sbin', '/sbin'):
        if not os.path.isdir(src):
            continue
        for name in os.listdir(src):
            if name.startswith('apt') or name in ('dpkg', 'ufw') or (d / name).exists():
                continue
            try:
                os.symlink(os.path.join(src, name), d / name)
            except OSError:
                pass
    (box.fake / 'apt-get').unlink()
    (box.fake / 'dnf').write_text(DNF)
    (box.fake / 'dnf').chmod(0o755)
    return f'{box.fake}:{d}'


@pytest.mark.parametrize('online', [True, False], ids=['pypi', 'offline'])
def test_rhel9_takes_what_the_distribution_has_and_names_epel(box, leader, online):
    path = _rhel_path(box)
    if not online:
        # no way to PyPI: pip finds nothing
        py = (box.fake / 'python3').read_text().replace(
            'if [ "$1" = -m ] && [ "$2" = pip ]; then echo "pip $iso $*" >> "$FAKE_LOG"; exit 0; fi',
            'if [ "$1" = -m ] && [ "$2" = pip ]; then echo "pip $iso $*" >> "$FAKE_LOG"; '
            'echo "ERROR: Could not find a version that satisfies the requirement gevent" >&2; exit 1; fi')
        (box.fake / 'python3').write_text(py)
    out = box.run('--code', leader.code, '--port', str(box.port), PATH=path, FAKE_MISSING='cryptography gevent requests')
    did = box.did()
    # one package at a time: the one without a match does not take the others with it
    assert [d for d in did if d.startswith('dnf')] == [
        'dnf install -y python3-cryptography', 'dnf install -y python3-gevent', 'dnf install -y python3-requests']
    assert (box.state / 'pkg-cryptography').exists() and (box.state / 'pkg-requests').exists()
    assert 'python3-gevent is in EPEL: dnf install epel-release' in out.stdout + out.stderr
    # only gevent from PyPI, next to the distribution's two
    assert [d for d in did if d.startswith('pip')] == ['pip -I -m pip install --quiet gevent']
    assert not [d for d in did if 'epel' in d]
    if online:
        assert out.returncode == 0, out.stdout[-1500:] + out.stderr[-1500:]
        assert f"'{box.opt}/venv/bin/python3' -I '{box.opt}/boot.py'" in open(box.bin).read()
    else:
        assert out.returncode != 0
        assert ('could not install gevent with pip - python3-gevent is in EPEL: dnf install epel-release, then '
                'run this again') in out.stderr
        assert leader.calls == []
    doc = _doc()
    assert 'python3-gevent only from EPEL' in doc and 'dnf install epel-release' in doc
    assert 'without internet there is no PyPI to fall back on' in doc


def test_apt_still_takes_the_modules_in_one(box, leader):
    out = box.run('--code', leader.code, '--port', str(box.port), FAKE_MISSING='gevent requests')
    assert out.returncode == 0, out.stdout + out.stderr
    assert [d for d in box.did() if d.startswith('apt-get install')] == [
        'apt-get install -y --no-install-recommends python3-gevent python3-requests']
    assert 'EPEL' not in out.stdout + out.stderr


# --- (e) the image of the Docker line ---------------------------------------------------------------------------

@pytest.mark.parametrize('version, branch, image', [
    ('1.2.0', 'main', None),
    ('1.1.1', 'main', None),
    ('1.2.0', 'Testing', 'ghcr.io/pegaprox/pegaprox-testing:latest'),
    ('1.2.1', 'main', 'ghcr.io/pegaprox/pegaprox:1.2.1'),
    ('1.3.0-rc1', 'main', 'ghcr.io/pegaprox/pegaprox:1.3.0-rc1'),
    ('1.3.0', 'testing', 'ghcr.io/pegaprox/pegaprox-testing:latest'),
])
def test_the_docker_line_names_an_image_whose_witness_command_runs_the_witness(monkeypatch, version, branch, image):
    import pegaprox.api.ha as ha_api
    import pegaprox.constants as constants
    monkeypatch.setattr(constants, 'PEGAPROX_VERSION', version)
    inst = ha_api.witness_install_commands('https://leader.example:5000', 'pgxwt1_abc', branch=branch)
    assert inst['image'] == image and inst['version'] == version and inst['branch'] == branch
    assert inst['linux'] and inst['offline'] and inst['manual']
    if image:
        assert f' {image} witness run ' in inst['docker'] and inst['docker_note'] is None
        assert inst['placeholder_in'] == ['docker', 'manual'] and 'Docker and manual commands' in inst['note']
    else:
        assert inst['docker'] is None and inst['placeholder_in'] == ['manual']
        assert inst['docker_note'] == (f'The Docker image of release {version} has no witness yet, so there is no '
                                       'Docker line: use the Linux line, or the line by hand.')
        assert inst['docker_note'] in inst['note'] and 'Docker and manual' not in inst['note']


def test_the_branch_this_instance_follows(tmp_path, monkeypatch):
    import pegaprox.api.ha as ha_api
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'code_root', lambda: str(tmp_path))
    monkeypatch.delenv('PEGAPROX_BRANCH', raising=False)
    assert ha_api.update_branch() == 'main'
    # a git checkout, and a worktree of one
    (tmp_path / '.git').mkdir()
    (tmp_path / '.git' / 'HEAD').write_text('ref: refs/heads/Testing\n')
    assert ha_api.update_branch() == 'Testing'
    shutil.rmtree(tmp_path / '.git')
    gitdir = tmp_path / 'repo' / 'worktrees' / 'w'
    gitdir.mkdir(parents=True)
    (gitdir / 'HEAD').write_text('ref: refs/heads/some-fix\n')
    (tmp_path / '.git').write_text(f'gitdir: {gitdir}\n')
    assert ha_api.update_branch() == 'some-fix'
    # what deploy.sh and update.sh wrote goes before the checkout
    (tmp_path / '.pegaprox-branch').write_text('Testing\n')
    assert ha_api.update_branch() == 'Testing'
    # and the environment of the image before both
    monkeypatch.setenv('PEGAPROX_BRANCH', 'main')
    assert ha_api.update_branch() == 'main'
    monkeypatch.setenv('PEGAPROX_BRANCH', '$(reboot)')
    assert ha_api.update_branch() == 'main'


@pytest.mark.parametrize('script, start', [
    ('update.sh', 'if [ "$GITHUB_BRANCH" = main ]; then\n    rm -f .pegaprox-branch'),
    ('deploy.sh', 'if [ "$GITHUB_BRANCH" = main ]; then\n                rm -f "$INSTALL_DIR/.pegaprox-branch"'),
])
def test_an_install_from_a_branch_writes_down_which(tmp_path, script, start):
    text = _read(script)
    at = text.index(start)
    block = text[at:text.index('fi\n', at) + 3]
    for branch, want in (('Testing', 'Testing\n'), ('main', None), ('Testing', 'Testing\n')):
        out = subprocess.run(['bash', '-c', block], cwd=str(tmp_path), capture_output=True, text=True, timeout=30,
                             env=dict(os.environ, GITHUB_BRANCH=branch, INSTALL_DIR=str(tmp_path)))
        assert out.returncode == 0, out.stderr
        marker = tmp_path / '.pegaprox-branch'
        assert (marker.read_text() if marker.exists() else None) == want


def test_every_testing_image_says_so_and_the_release_images_do_not():
    wf = _read('.github', 'workflows', 'docker-testing.yml')
    assert 'images: ghcr.io/pegaprox/pegaprox-testing' in wf
    assert 'build-args: |\n            PEGAPROX_BRANCH=Testing' in wf
    for other in ('docker.yml', 'release-images.yml'):
        assert 'PEGAPROX_BRANCH' not in _read('.github', 'workflows', other), other
    docker = _read('Dockerfile')
    assert 'ARG PEGAPROX_BRANCH=main\nENV PEGAPROX_BRANCH=${PEGAPROX_BRANCH}\n' in docker
    # it carries the witness: the code, the installer and the unit
    assert 'COPY --chown=pegaprox:pegaprox pegaprox/ pegaprox/' in docker
    assert 'packaging/witness/install.sh' in docker and 'systemd/pegaprox-witness.service' in docker
    # the updater of the app takes main: what it leaves follows main
    settings = _read('pegaprox', 'api', 'settings.py')
    assert "os.unlink(os.path.join(install_dir, '.pegaprox-branch'))" in settings
    doc = _doc()
    assert 'ghcr.io/pegaprox/pegaprox-testing:latest' in doc and '1.2.0 and older have no witness' in doc


# --- (f) update --to-leader, then the installer again ------------------------------------------------------------

def _released(box, release):
    def check():
        if not _healthy(box):
            return False
        st = _cmd(box, 'status')
        return st.returncode == 0 and json.loads(st.stdout)['release'] == release
    return _until(check, 90)


def test_update_to_leader_holds_through_the_installer_run_again_and_the_next_start(box, leader):
    _install(box, leader)
    # the leader runs 9.9.9, the witness follows it (by hand here) and runs it its three minutes
    leader.bundle = lambda: _bundle_of('9.9.9')
    assert _cmd(box, 'update').returncode == 0
    assert _released(box, '9.9.9')
    root = box.var / 'code'
    newer = os.path.realpath(root / 'current')
    wb.mark_ok(str(box.var), newer)
    # the leader goes back to 9.0.0 and says so; the admin takes it, as the HA tab says
    leader.bundle = lambda: _bundle_of('9.0.0')
    assert _tell(box, leader, release='9.0.0', update=False) == (200, {'accepted': False, 'reason': 'NOT_NEWER'})
    assert json.loads(_cmd(box, 'status').stdout)['ahead']['release'] == '9.0.0'
    down = _cmd(box, 'update', '--to-leader')
    assert down.returncode == 0, down.stdout + down.stderr
    assert _released(box, '9.0.0')
    older = os.path.realpath(root / 'current')
    wb.mark_ok(str(box.var), older)
    # later the admin runs the installer again to repair something, as the docs say
    again = box.run(script=str(box.opt / 'install.sh'))
    assert again.returncode == 0, again.stdout[-1500:] + again.stderr[-1500:]
    # the start script and the base take nothing newer than the release the leader told
    assert not os.readlink(box.opt / 'current').startswith('9.9.9-')
    assert _released(box, '9.0.0')
    # and the next restart (a reboot, the next update) still runs the leader's release
    subprocess.run(['systemctl', 'restart', SVC], env=box.env, timeout=60)
    assert _released(box, '9.0.0')
    assert wb.choose(str(box.opt / 'current'), str(box.var), counting=False) == (older, False)
    assert 'running the installer again, or a newer image, does not bring the newer code back' in _doc()


# --- (g) code changed under the same release ---------------------------------------------------------------------

def _fixed_bundle():
    src = _read('pegaprox', 'witness.py').encode()
    return _bundle_of(_release(), {'pegaprox/witness.py': src + b'\n# a fix pushed under the same release string\n'})


def test_code_changed_under_the_same_release_reaches_the_installed_witness(box, leader):
    _install(box, leader)
    installed = os.readlink(box.opt / 'current')
    bundle = _fixed_bundle()
    name = bundle['manifest']['name']
    assert name != installed and name.startswith(f'{_release()}-')
    leader.bundle = lambda: bundle
    # the leader's word names the code it serves: taken by itself
    assert _tell(box, leader, release=_release(), name=name) == (200, {'accepted': True})
    assert _service_gone(box)
    assert os.readlink(box.var / 'code' / 'current') == name
    # the start into it runs it, though it ties with the base
    subprocess.run(['systemctl', 'start', SVC], env=box.env, timeout=60)
    assert _until(lambda: _healthy(box), 60)
    running = json.load(open(box.var / wm.UPDATE_NAME))['running']
    assert running['release'] == _release() and os.path.basename(running['code']) == name


def test_by_hand_the_update_takes_other_code_of_the_same_release(box, leader):
    _install(box, leader)
    bundle = _fixed_bundle()
    name = bundle['manifest']['name']
    leader.bundle = lambda: bundle
    # the word of a leader that names no code (one of before): nothing to take by itself
    assert _tell(box, leader, release=_release()) == (200, {'accepted': False, 'reason': 'NOT_NEWER'})
    up = _cmd(box, 'update', PEGAPROX_WITNESS_NO_RESTART='1')
    assert up.returncode == 0 and f'is in place ({name})' in up.stdout, up.stdout + up.stderr
    assert os.readlink(box.var / 'code' / 'current') == name
    # once it came up, the same code again is nothing to do
    wb.mark_ok(str(box.var), os.path.realpath(box.var / 'code' / name))
    same = _cmd(box, 'update', PEGAPROX_WITNESS_NO_RESTART='1')
    assert same.returncode == 0 and 'already' in same.stdout, same.stdout + same.stderr


def test_the_leader_tells_a_witness_that_runs_other_code_of_its_own_release(auto, host, seed, tmp_path,
                                                                           monkeypatch):
    from pegaprox.core import ha as core
    _form(auto, host, seed)
    auto.run(10)
    # the witness runs the very bundle the leader serves, as the installer put it there
    archive, files, digest = core._bundle_archive()
    manifest = {'release': _release(), 'wire': ha_wire.WITNESS_WIRE, 'sha256': digest, 'size': len(archive),
                'files': files}
    base = wb.install_bundle(archive, manifest, str(tmp_path / 'opt'))
    host.code_dir = base
    host.w.code_dir, host.w.auto_update, host.w.install = base, True, 'systemd'
    wid = host.w.instance_id()
    with auto.at('a') as ha:
        ha._ask_witness()
        assert ha._rt().seen[wid]['code'] == os.path.basename(base)
        assert ha._witness_update_check() is None
    # the same release told without a name, or with the name of what runs, is not taken
    for name in (None, os.path.basename(base)):
        word = {'release': _release(), 'wire': ha_wire.WITNESS_WIRE, 'update': True, 'url': 'https://a.example:5000'}
        if name:
            word['name'] = name
        assert host.w._told(IDS['a'], word) == {'accepted': False, 'reason': 'NOT_NEWER'}
    # a fix lands on the leader under the same release
    src = _read('pegaprox', 'witness.py').encode()
    entries = _entries(_release(), {'pegaprox/witness.py': src + b'\n# a fix\n'})
    fixed = core.pack_bundle(entries)
    monkeypatch.setattr(core, '_bundle_archive', lambda: (fixed, sorted(entries), hashlib.sha256(fixed).hexdigest()))
    name = wb.bundle_name(_release(), hashlib.sha256(fixed).hexdigest())
    with auto.at('a') as ha:
        ha._ask_witness()
        said = ha._witness_update_check()
    assert said == {'update': True, 'status': 200, 'answer': {'accepted': True}}
    stopped = []
    host.w.upkeep(lambda: stopped.append(True), lambda: True)
    assert stopped == [True] and host.w.exit_code == wm.EXIT_UPDATED
    root = os.path.join(host.dir, wb.UPDATES)
    assert os.readlink(os.path.join(root, 'current')) == name
    tree = os.path.realpath(os.path.join(root, name))
    assert wb.choose(base, host.dir) == (tree, True)
    # code no bundle named (the image's own) is not told apart by itself
    host.w.code_dir = str(tmp_path / 'app')
    word = {'release': _release(), 'wire': ha_wire.WITNESS_WIRE, 'update': True, 'url': 'https://a.example:5000',
            'name': name}
    host.w.exit_code = 0
    assert host.w._told(IDS['a'], word) == {'accepted': False, 'reason': 'NOT_NEWER'}
    assert 'reaches the witness too' in _doc()


# --- (h) the last update once it came up --------------------------------------------------------------------------

def test_the_update_it_started_into_reads_up_to_date_once_it_came_up(tmp_path):
    state = wm.check_dir(str(tmp_path / 'state'))
    tree = _tree(tmp_path / 'opt', wm.RELEASE)
    wm.Witness(state, code_dir=tree, auto_update=True).note_update(
        last={'state': 'installed', 'release': wm.RELEASE, 'name': os.path.basename(tree), 'error': None,
              'at': '2026-10-01T08:00:00+00:00'})
    now = [0.0]
    w = wm.Witness(state, clock=lambda: now[0], code_dir=tree, auto_update=True)

    def rest(_s):
        now[0] += 10
        if now[0] > wm.SOAK + 20:
            raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        w.upkeep(lambda: None, lambda: True, sleep=rest)
    last = json.load(open(os.path.join(state, wm.UPDATE_NAME)))['last']
    assert (last['state'], last['release'], last['name']) == ('current', wm.RELEASE, os.path.basename(tree))
    assert os.path.realpath(tree) in wb.load_health(os.path.join(state, wb.UPDATES))['ok']
    # a failed one stays what it was
    w.note_update(last={'state': 'failed', 'release': '9.9.9', 'error': 'x', 'at': 'y', 'back': True})
    w.came_up()
    assert w.update_state['last']['state'] == 'failed'


# --- (i) an update that hangs ----------------------------------------------------------------------------------------

def test_code_on_trial_that_never_answers_spends_its_tries_in_one_start(tmp_path):
    state = str(tmp_path / 'state')
    os.makedirs(state, mode=0o700)
    base = _tree(tmp_path / 'opt', '1.0.0')
    tree = _tree_with(os.path.join(state, wb.UPDATES), '9.9.9', HANG)
    assert wb.choose(base, state) == (tree, True)
    # the code's own check: it served, but nothing answers on its port
    now = [100.0]
    w = wm.Witness(wm.check_dir(state), clock=lambda: now[0], code_dir=tree, auto_update=True)
    w.trial = True
    stopped = []

    def rest(_s):
        now[0] += 10
    w.upkeep(lambda: stopped.append(True), lambda: False, sleep=rest)
    assert stopped == [True] and w.exit_code == 1
    said = []
    assert wb.choose(base, state, say=said.append) == (os.path.realpath(base), False)
    assert f'did not come up healthy in {wb.TRIES} starts' in said[0]


def test_code_on_trial_that_answers_and_then_hangs_keeps_its_second_start(tmp_path):
    state = str(tmp_path / 'state')
    os.makedirs(state, mode=0o700)
    base = _tree(tmp_path / 'opt', '1.0.0')
    tree = _tree_with(os.path.join(state, wb.UPDATES), '9.9.9', UP_THEN_HANG)
    path, trial = wb.choose(base, state)
    proc = _start(path, state, trial, QUICK)
    _out, err = _ended(proc)
    assert proc.returncode == 1 and 'did not come up healthy within' in err
    assert wb.choose(base, state) == (tree, True)


SUPERVISE = r'''#!/bin/sh
# what systemd does with pegaprox-witness.service: Restart=on-failure, RestartSec=5,
# RestartForceExitStatus=75, SuccessExitStatus=75, RestartPreventExitStatus=78,
# StartLimitIntervalSec=120, StartLimitBurst=5
log="$FAKE_STATE/exits"
child=
trap 'touch "$FAKE_STATE/stopping"; [ -n "$child" ] && kill "$child" 2>/dev/null; [ -n "$child" ] && wait "$child"; exit 0' TERM
starts=
while :; do
    now=$(date +%s)
    recent=0
    keep=
    for t in $starts; do
        if [ $((now - t)) -lt 120 ]; then recent=$((recent + 1)); keep="$keep $t"; fi
    done
    if [ "$recent" -ge 5 ]; then echo "start-limit-hit $now" >> "$log"; break; fi
    starts="$keep $now"
    echo "start $now" >> "$log"
    "$FAKE_WITNESS" run >> "$FAKE_STATE/witness.log" 2>&1 &
    child=$!
    wait "$child"
    rc=$?
    child=
    echo "exit $rc $(date +%s)" >> "$log"
    [ -f "$FAKE_STATE/stopping" ] && break
    case $rc in
        0|78) echo "not restarted ($rc)" >> "$log"; break ;;
    esac
    sleep 5
done
'''

SYSTEMCTL_SUPERVISED = r'''#!/bin/sh
echo "systemctl $*" >> "$FAKE_LOG"
stop() {
    if [ -f "$FAKE_STATE/pid" ]; then
        pid=$(cat "$FAKE_STATE/pid")
        kill "$pid" 2>/dev/null
        i=0
        while kill -0 "$pid" 2>/dev/null && [ $i -lt 200 ]; do sleep 0.1; i=$((i + 1)); done
        rm -f "$FAKE_STATE/pid"
    fi
}
start() {
    rm -f "$FAKE_STATE/stopping"
    nohup sh "$FAKE_SUPERVISE" >> "$FAKE_STATE/supervise.log" 2>&1 &
    echo $! > "$FAKE_STATE/pid"
}
case "$1" in
    is-active) exit 3 ;;
    restart) stop; start ;;
    start) start ;;
    try-restart) if [ -f "$FAKE_STATE/pid" ]; then stop; start; fi ;;
    stop) stop ;;
esac
exit 0
'''
# the bound to answer of the start script in the test, and with it the watchdog's (WATCH_UP)
BOUND = 6


@pytest.mark.parametrize('kind', ['good', 'crash', 'exit78', 'hang'])
def test_an_update_under_the_unit_comes_up_or_goes_back(box, leader, kind):
    (box.fake / 'supervise').write_text(SUPERVISE)
    (box.fake / 'systemctl').write_text(SYSTEMCTL_SUPERVISED)
    box.env['FAKE_SUPERVISE'] = str(box.fake / 'supervise')
    _install(box, leader)
    boot = box.opt / 'boot.py'
    src = boot.read_text()
    assert 'HEALTH_BOUND = 90\n' in src
    boot.write_text(src.replace('HEALTH_BOUND = 90\n', f'HEALTH_BOUND = {BOUND}\n'))
    before = box.status()['release']
    leader.bundle = lambda: _bundle_of('9.9.9', {'pegaprox/witness.py': BROKEN[kind]} if kind in BROKEN else None)
    t0 = time.time()
    assert _tell(box, leader) == (200, {'accepted': True})

    def settled():
        if not _healthy(box):
            return False
        st = json.loads(_cmd(box, 'status').stdout)
        if kind == 'good':
            return st['release'] == '9.9.9'
        return (st.get('last_update') or {}).get('back') is True and st['release'] == before
    assert _until(settled, 150), (box.state / 'exits').read_text()
    took = time.time() - t0
    exits = [line.split()[1] for line in (box.state / 'exits').read_text().splitlines() if line.startswith('exit ')]
    assert exits[0] == '75' and 'start-limit-hit' not in (box.state / 'exits').read_text()
    if kind == 'good':
        assert exits == ['75']
    elif kind == 'hang':
        # it never answered: one start, ended by the watchdog, and the next one goes back
        assert exits == ['75', '1'], exits
        assert took < 2 * (BOUND + 15) + 30, took
    else:
        # it stopped at once: each start counts, two of them
        assert exits == ['75', '1', '1'], exits


def test_a_word_of_the_leader_counts_once(box, leader):
    _install(box, leader)
    wid, pin = _state(box)
    body = ha_wire.wire_body({'release': _release(), 'wire': ha_wire.WITNESS_WIRE, 'update': False,
                              'url': leader.url, 'fingerprint': leader.pin})
    h = ha_wire.signed_headers(ha_wire.private_key(KEYS[A]), A, wid, 'POST', wm.UPDATE_PATH, body, time.time())
    url = f'https://127.0.0.1:{box.port}'
    assert wm.https_call('POST', url, pin, wm.UPDATE_PATH, body, h) == (200, {'accepted': False,
                                                                            'reason': 'NOT_NEWER'})
    # the same call again: refused, at the head or by the route
    try:
        status, _data = wm.https_call('POST', url, pin, wm.UPDATE_PATH, body, h)
    except wm.WitnessError:
        status = None
    assert status != 200


def test_with_the_updates_off_the_word_is_kept_and_the_update_taken_by_hand(box, leader):
    # the service gets what the drop-in of the installer says, as from systemd
    (box.fake / 'systemctl').write_text(SYSTEMCTL_WITH_DROPIN)
    _install(box, leader, '--no-auto-update')
    leader.bundle = lambda: _bundle_of('9.9.9')
    assert _tell(box, leader) == (200, {'accepted': False, 'reason': 'AUTO_UPDATE_OFF'})
    st = box.status()
    assert st['auto_update'] is False and st['outdated']['release'] == '9.9.9'
    assert 'automatic updates are off' in st['outdated']['note']
    assert _cmd(box, 'update').returncode == 0
    assert _released(box, '9.9.9')


# --- (j) the placeholder in the Docker and manual lines ---------------------------------------------------------------

_DOCKER = '#!/bin/sh\nfor a in "$@"; do printf \'%s\\n\' "$a"; done\n'


def test_a_placeholder_left_in_the_lines_reaches_the_witness_which_says_what_to_put_there(tmp_path, leader):
    import pegaprox.api.ha as ha_api
    inst = ha_api.witness_install_commands(leader.url, leader.code, branch='Testing')
    for way in ('docker', 'manual'):
        assert inst[way].endswith(" --url 'https://<witness-host>:5005'"), way
    # the manual line, pasted as it is in a checkout
    app = _checkout(tmp_path)
    work = tmp_path / 'work'
    work.mkdir()
    line = inst['manual'].replace('python3 pegaprox_multi_cluster.py', f"'{PY}' '{app}/pegaprox_multi_cluster.py'")
    out = subprocess.run(['sh', '-c', line], cwd=str(work), env=_manual_env(_free_port()), capture_output=True,
                         text=True, timeout=120)
    assert out.returncode == wm.EXIT_CONFIG, out.stdout[-800:] + out.stderr[-800:]
    assert '--url https://<witness-host>:5005 still holds the placeholder' in out.stderr
    assert not (work / 'witness-host').exists() and leader.calls == []
    # the Docker line hands docker the address as one argument, placeholder and all
    fake = tmp_path / 'bin'
    fake.mkdir()
    (fake / 'docker').write_text(_DOCKER)
    (fake / 'docker').chmod(0o755)
    out = subprocess.run(['sh', '-c', inst['docker']], env=dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}"),
                         capture_output=True, text=True, timeout=60, cwd=str(work))
    assert out.returncode == 0 and out.stdout.splitlines()[-2:] == ['--url', 'https://<witness-host>:5005']
    assert "--url 'https://<witness-host>:5005'" in _doc()


# --- (k) the same line after the leader updated ------------------------------------------------------------------------

class _NewerLeader(GetLeader):
    """The fake leader, which serves an installer that changed once `extra` is set."""

    def __init__(self, path):
        super().__init__(path)
        self.extra = b''
        handler = self.server.RequestHandlerClass
        lead = self
        plain = handler.do_GET

        def do_GET(h):
            if not lead.extra:
                return plain(h)
            lead.gets.append(h.path)
            data = _read('packaging', 'witness', 'install.sh').encode() + lead.extra
            h.send_response(200)
            h.send_header('Content-Length', str(len(data)))
            h.end_headers()
            h.wfile.write(data)
        handler.do_GET = do_GET


def test_the_same_line_after_the_leader_updated_says_where_to_go(box, tmp_path):
    import pegaprox.api.ha as ha_api
    lead = _NewerLeader(tmp_path / 'leader')
    try:
        line = ha_api.witness_install_commands(lead.url, lead.code, branch='Testing')['offline'] + f' --port {box.port}'
        first = subprocess.run(['sh', '-c', line], env=box.env, capture_output=True, text=True, timeout=240,
                               cwd=str(box.tmp))
        assert first.returncode == 0, first.stderr
        # the leader moved on to a release whose installer differs
        lead.extra = b'# a later release\n'
        again = subprocess.run(['sh', '-c', line], env=dict(box.env, LC_ALL='C'), capture_output=True, text=True,
                               timeout=240, cwd=str(box.tmp))
    finally:
        lead.close()
    assert again.returncode != 0 and 'FAILED' in again.stdout + again.stderr
    assert ('pegaprox-witness: no install.sh that matches this line - it works while the leader runs the release '
            'that made it. Where the witness is installed: sudo sh /opt/pegaprox-witness/install.sh') in again.stderr
    # nothing of it ran: the witness runs on as it was
    assert _healthy(box) and box.status()['paired'] is True
    doc = _doc()
    assert 'only while the leader runs the release that made it' in doc
    assert 'no install.sh that matches this line' in doc


# --- the lines on a witness host of its own ----------------------------------------------------------------------------
#
# The witness host is a network namespace of its own, the leader a TLS server across a veth, and no route leads
# anywhere else; the witness runs on its real defaults (:: and 5005). The outer test makes the namespaces, the
# inner ones (test_inside_host_*) run in there: the leader on its side, every command of the host on the other.

_HOST_NS, _HOST_FAM = 'PEGAPROX_TEST_WITNESS_HOST_NS', 'PEGAPROX_TEST_WITNESS_HOST_FAMILY'
ADDRS = {'v4': ('198.51.100.10', '198.51.100.5', '24'), 'v6': ('2001:db8:1::10', '2001:db8:1::5', '64')}


def _namespaces():
    if not all(shutil.which(t) for t in ('unshare', 'nsenter', 'ip')):
        return False
    try:
        return subprocess.run(['unshare', '-rn', 'true'], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.mark.skipif(not _namespaces(), reason='no unprivileged network namespace on this host')
@pytest.mark.parametrize('fam', ['v4', 'v6'])
def test_the_lines_on_a_witness_host_of_its_own(tmp_path, fam):
    ip = shutil.which('ip')
    lead, wit, bits = ADDRS[fam]
    six = '-6 ' if fam == 'v6' else ''
    flags = ' nodad' if fam == 'v6' else ''
    script = (f"set -e\n{ip} link set lo up\nunshare -n sleep 100000 &\nCH=$!\nsleep 0.5\n"
              f"{ip} link add v0 type veth peer name v1 netns \"$CH\"\n"
              f"{ip} {six}addr add {lead}/{bits} dev v0{flags}\n{ip} link set v0 up\n"
              f"nsenter -t \"$CH\" -n sh -c '{ip} link set lo up; {ip} link set v1 up; "
              f"{ip} {six}addr add {wit}/{bits} dev v1{flags}'\n"
              "sleep 2\nset +e\n"
              f"{_HOST_NS}=$CH {_HOST_FAM}={fam} '{PY}' -m pytest -q -p no:cacheprovider -k inside_host "
              f"'{os.path.abspath(__file__)}'\n"
              "rc=$?\nkill \"$CH\"\nexit $rc\n")
    out = subprocess.run(['unshare', '-rn', 'sh', '-c', script], cwd=ROOT, capture_output=True, text=True,
                         timeout=1500)
    said = out.stdout[-4000:] + out.stderr[-2000:]
    assert out.returncode == 0 and re.search(r'\b5 passed\b', out.stdout) and 'failed' not in out.stdout, said


class _HostBox(Box):
    """The witness host in the namespace the test above made."""

    def __init__(self, tmp, ns):
        super().__init__(tmp)
        self.ns = ns
        for var in ('PEGAPROX_WITNESS_PORT', 'PEGAPROX_WITNESS_HOST'):
            self.env.pop(var, None)
        self.port = 5005

    def _in(self, argv):
        return ['nsenter', '-t', self.ns, '-n'] + argv

    def paste(self, line, **env):
        return subprocess.run(self._in(['sh', '-c', line]), env=dict(self.env, **env), capture_output=True,
                              text=True, timeout=600, cwd=str(self.tmp))

    def run(self, *args, script=None, **env):
        return subprocess.run(self._in(['sh', script or str(self.opt / 'install.sh')] + list(args)),
                              env=dict(self.env, **env), capture_output=True, text=True, timeout=600,
                              cwd=str(self.tmp))

    def cmd(self, *args, **env):
        return subprocess.run(self._in([self.bin] + list(args)), env=dict(self.env, **env), capture_output=True,
                              text=True, timeout=120, cwd=str(self.tmp))


def _url_host(addr):
    return f'[{addr}]' if ':' in addr else addr


def _leader_at(tmp_path, addr):
    import socket
    from http.server import ThreadingHTTPServer
    import test_ha_witness_install as ti

    class V6(ThreadingHTTPServer):
        address_family = socket.AF_INET6
    orig = ti.ThreadingHTTPServer
    ti.ThreadingHTTPServer = lambda _addr, handler: (V6 if ':' in addr else orig)((addr, 0), handler)
    try:
        lead = GetLeader(tmp_path / 'leader')
    finally:
        ti.ThreadingHTTPServer = orig
    lead.url = f'https://{_url_host(addr)}:{lead.server.server_address[1]}'
    lead.code = ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, lead.url, lead.pin, lead.secret, A)
    return lead


def _host_lines(lead):
    import pegaprox.api.ha as ha_api
    return ha_api.witness_install_commands(lead.url, lead.code, branch='main')


inside = pytest.mark.skipif(not os.environ.get(_HOST_NS), reason='runs in the namespaces of the test above')


@pytest.fixture
def where(tmp_path):
    """(the witness host, the leader, the address of the witness host)."""
    lead_addr, wit_addr, _bits = ADDRS[os.environ.get(_HOST_FAM) or 'v4']
    lead = _leader_at(tmp_path, lead_addr)
    host_box = _HostBox(tmp_path, os.environ.get(_HOST_NS) or '')
    yield host_box, lead, wit_addr
    host_box.stop()
    lead.close()


@inside
@pytest.mark.parametrize('way', ['linux', 'offline'])
def test_inside_host_the_lines_behind_a_proxy_that_does_not_reach_the_leader(where, way):
    host_box, lead, wit = where
    dead = f'http://127.0.0.1:{_free_port()}'
    out = host_box.paste(_host_lines(lead)[way], https_proxy=dead, HTTPS_PROXY=dead, http_proxy=dead, no_proxy='',
                         NO_PROXY='')
    assert out.returncode == 0, out.stdout[-1500:] + out.stderr[-1500:]
    assert lead.gets == [INSTALLER_PATH]
    assert lead.witness['url'] == f'https://{_url_host(wit)}:5005' and _answers(wit, 5005) is True


@inside
def test_inside_host_the_line_again_a_new_code_and_uninstall(where):
    host_box, lead, wit = where
    out = host_box.paste(_host_lines(lead)['linux'])
    assert out.returncode == 0, out.stdout[-1500:] + out.stderr[-1500:]
    assert _answers(wit, 5005) is True
    # the same line again, while the leader runs the release that made it
    out = host_box.paste(_host_lines(lead)['linux'])
    assert out.returncode == 0 and 'paired already' in out.stdout, out.stdout[-1500:] + out.stderr[-1500:]
    # removed on the leader, a new code
    host_box.stop()
    lead.witness = None
    lead.secret = secrets.token_urlsafe(32)
    lead.spent = False
    lead.code = ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, lead.url, lead.pin, lead.secret, A)
    out = host_box.paste(_host_lines(lead)['linux'])
    assert out.returncode == 0, out.stdout[-1500:] + out.stderr[-1500:]
    assert lead.witness and _answers(wit, 5005) is True
    out = host_box.cmd('uninstall')
    assert out.returncode == 0 and lead.witness is None, out.stdout + out.stderr


@inside
def test_inside_host_the_offline_line_with_a_port_of_its_own(where):
    host_box, lead, wit = where
    out = host_box.paste(_host_lines(lead)['offline'] + ' --port 5007')
    assert out.returncode == 0, out.stdout[-1500:] + out.stderr[-1500:]
    assert lead.witness['url'] == f'https://{_url_host(wit)}:5007' and _answers(wit, 5007) is True
    assert host_box.cmd('health').returncode == 0


@inside
def test_inside_host_a_run_with_another_port_changes_nothing_and_the_firewall_hint_speaks_its_family(where):
    host_box, lead, wit = where
    # a host with firewalld and no ufw
    (host_box.fake / 'firewall-cmd').write_text('#!/bin/sh\nexit 0\n')
    (host_box.fake / 'firewall-cmd').chmod(0o755)
    path = ':'.join(p for p in host_box.env['PATH'].split(':') if p not in ('/usr/sbin', '/sbin', '/usr/local/sbin'))
    out = host_box.paste(_host_lines(lead)['offline'], PATH=path)
    assert out.returncode == 0, out.stdout[-1500:] + out.stderr[-1500:]
    family = 'ipv6' if ':' in wit else 'ipv4'
    assert f'rule family={family} source address=<member address>' in out.stdout
    assert ('family=ipv4' if family == 'ipv6' else 'family=ipv6') not in out.stdout
    again = host_box.run('--port', '5007')
    assert again.returncode != 0 and 'this witness is paired as' in again.stderr
    # the members still reach it where it paired
    assert _answers(wit, 5005) is True and _answers(wit, 5007) is not True
