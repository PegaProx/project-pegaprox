"""The witness on the hosts it meets (#625 stage 2).

What a review found once the delivery ran on real hosts: a leader that pairs over IPv6, a
proxy in the environment, a leader installed by deploy.sh from a checkout, a custom port,
an update that does not come up (under the unit, and told again by the leader), the
witness run by hand, a new code on a host that is still paired, the start script that
never changed, a status asked without sudo, and root's groups. Each one runs the way it
failed: the installer for real in a root of its own (tests/test_ha_witness_install.py),
the group in process (tests/test_ha_witness_group.py), the witness as a process of its
own where it has to start again.

MK Oct 2026 (#625)
"""
import base64
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time

import pytest

from pegaprox import witness as wm
from pegaprox import witness_boot as wb
from pegaprox.core import ha_wire
from test_ha_witness import A, C, KEYS, pub
from test_ha_witness_install import INSTALLER, Leader, _free_port
from test_ha_witness_install import box, leader  # noqa: F401  (fixtures)
from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_members import group  # noqa: F401  (the fixture)
from test_ha_witness_group import _form
from test_ha_witness_delivery import host as dhost, _base, _entries, _run_tree, _release  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def _bundle_of(release, replace=None, drop=(), key=A):
    """A bundle as a leader serves it: the witness code of this tree, as `release`."""
    from pegaprox.core import ha
    entries = {}
    for rel in ha.WITNESS_BUNDLE_FILES:
        if rel in drop:
            continue
        with open(os.path.join(ROOT, rel), 'rb') as fh:
            entries[rel] = fh.read()
    entries['version.json'] = json.dumps({'version': release, 'wire': ha_wire.WITNESS_WIRE}).encode()
    entries.update(replace or {})
    archive = ha.pack_bundle(entries)
    digest = hashlib.sha256(archive).hexdigest()
    manifest = {'release': release, 'wire': ha_wire.WITNESS_WIRE, 'sha256': digest, 'size': len(archive),
                'files': sorted(entries), 'by': key, 'name': wb.bundle_name(release, digest)}
    sig = ha_wire.private_key(KEYS[key]).sign(ha_wire.bundle_message(manifest))
    return {'manifest': manifest, 'sig': base64.b64encode(sig).decode(),
            'archive': base64.b64encode(archive).decode()}


def _answers(host, port, timeout=2):
    """True when a TLS server answers at host:port, else what went wrong."""
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw):
                return True
    except OSError as e:
        return f'{type(e).__name__}: {e}'


def _until(check, seconds=60, step=0.5):
    end = time.time() + seconds
    while time.time() < end:
        if check():
            return True
        time.sleep(step)
    return check()


def _tell(leader, wurl, wid, wpin, release='9.9.9', update=True):
    body = ha_wire.wire_body({'release': release, 'wire': ha_wire.WITNESS_WIRE, 'update': update,
                              'url': leader.url, 'fingerprint': leader.pin})
    h = ha_wire.signed_headers(ha_wire.private_key(KEYS[A]), A, wid, 'POST', wm.UPDATE_PATH, body, time.time())
    return wm.https_call('POST', wurl, wpin, wm.UPDATE_PATH, body, h)


def _has_ipv6():
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(('::1', 0))
        return True
    except OSError:
        return False


def _new_code(leader):
    """The leader makes a new code with "Add witness"."""
    leader.secret = secrets.token_urlsafe(32)
    leader.spent = False
    leader.code = ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, leader.url, leader.pin, leader.secret, A)
    return leader.code


# --- (a) a leader reached over IPv6 ------------------------------------------------------------------

@pytest.mark.skipif(not _has_ipv6(), reason='this host has no IPv6 loopback')
def test_a_leader_over_ipv6_pairs_a_witness_that_listens_there(box, tmp_path):
    """The installer works out the address of this host towards the leader: over IPv6 an
    IPv6 address, which the witness has to listen on - and the installer checks there."""
    import test_ha_witness_install as ti
    from http.server import ThreadingHTTPServer

    class V6(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    orig = ti.ThreadingHTTPServer
    ti.ThreadingHTTPServer = lambda addr, handler: V6(('::1', 0), handler)
    try:
        lead = Leader(tmp_path / 'leader6')
    finally:
        ti.ThreadingHTTPServer = orig
    lead.url = f'https://[::1]:{lead.server.server_address[1]}'
    lead.code = ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, lead.url, lead.pin, lead.secret, A)
    try:
        # the default, as the unit runs it
        box.env.pop('PEGAPROX_WITNESS_HOST', None)
        out = box.run('--code', lead.code, '--port', str(box.port))
        assert out.returncode == 0, out.stdout + out.stderr
        assert lead.witness['url'] == f'https://[::1]:{box.port}'
        # one socket for both: the members reach it over IPv6, health over IPv4 loopback
        assert _answers('::1', box.port) is True and _answers('127.0.0.1', box.port) is True
        assert 'does not answer' not in out.stdout
        assert box.cmd('health', '--own-url').returncode == 0
    finally:
        lead.close()


@pytest.mark.skipif(not _has_ipv6(), reason='this host has no IPv6 loopback')
def test_the_installer_says_so_when_the_witness_does_not_answer_where_it_paired(box, tmp_path):
    """Loopback answering is not the address the members call: a witness held to IPv4
    (--host 127.0.0.1 here) that paired over IPv6 is told apart, not reported as running."""
    import test_ha_witness_install as ti
    from http.server import ThreadingHTTPServer

    class V6(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    orig = ti.ThreadingHTTPServer
    ti.ThreadingHTTPServer = lambda addr, handler: V6(('::1', 0), handler)
    try:
        lead = Leader(tmp_path / 'leader6')
    finally:
        ti.ThreadingHTTPServer = orig
    lead.url = f'https://[::1]:{lead.server.server_address[1]}'
    lead.code = ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, lead.url, lead.pin, lead.secret, A)
    try:
        assert box.env['PEGAPROX_WITNESS_HOST'] == '127.0.0.1'
        out = box.run('--code', lead.code, '--port', str(box.port))
        assert out.returncode != 0
        assert f'answers on this host, but not at https://[::1]:{box.port}, the address it paired with' in out.stderr
        assert '--url https://<an address of this host>' in out.stderr
        assert 'the witness runs' not in out.stdout
    finally:
        lead.close()


def test_the_default_listener_takes_ipv6_and_ipv4_and_falls_back_without_ipv6(monkeypatch):
    if socket.has_dualstack_ipv6():
        sock, where = wm._listener('::', 0)
        try:
            assert sock.family == socket.AF_INET6 and where.startswith('[::]:')
            assert sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 0
            port = sock.getsockname()[1]
            with socket.create_connection(('127.0.0.1', port), timeout=2):
                peer, _addr = sock.accept()
                with peer:
                    # an IPv4 peer as the dual-stack socket names it, and as _ip reads it
                    got = peer.getpeername()
                    assert got[0] == '::ffff:127.0.0.1'
                    assert str(wm._ip(got)) == '127.0.0.1'
        finally:
            sock.close()
    # a host without IPv6: IPv4 alone, on every address
    monkeypatch.setattr(socket, 'has_dualstack_ipv6', lambda: False)
    sock, where = wm._listener('::', 0)
    try:
        assert sock.family == socket.AF_INET and sock.getsockname()[0] == '0.0.0.0'
        assert where.startswith('0.0.0.0:')
    finally:
        sock.close()
    # any other address as it is
    sock, where = wm._listener('127.0.0.1', 0)
    sock.close()
    assert where.startswith('127.0.0.1:')
    assert wm.parser().parse_args([]).host == '::'


def test_the_allow_list_reads_ipv4_peers_of_the_dual_stack_socket():
    nets = wm.allow_list(['192.0.2.0/24'])
    assert wm._allowed(('::ffff:192.0.2.7', 5005, 0, 0), nets)
    assert not wm._allowed(('::ffff:198.51.100.7', 5005, 0, 0), nets)
    assert wm._allowed(('::ffff:127.0.0.1', 5005, 0, 0), nets) and wm._allowed(('::1', 5005, 0, 0), nets)
    # an IPv4 network written the IPv6 way is that IPv4 network
    mapped = wm.allow_list(['::ffff:192.0.2.0/120'])
    assert ipaddress.ip_network('192.0.2.0/24') in mapped
    assert wm._allowed(('192.0.2.9', 1), mapped) and wm._allowed(('::ffff:192.0.2.9', 1, 0, 0), mapped)
    assert not wm._allowed(('192.0.3.9', 1), mapped)


def _own_ipv4():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('192.0.2.1', 9))
            ip = s.getsockname()[0]
    except OSError:
        return None
    return None if ip.startswith('127.') else ip


@pytest.mark.skipif(not _own_ipv4(), reason='this host has no address besides loopback')
def test_with_an_allow_list_this_host_still_reaches_the_address_it_paired_with(tmp_path):
    """health --own-url dials the address the members call. A plain connection from this
    host comes from that address, which no allow list of member networks names, and is
    closed as any other; the check dials from loopback, which the list always lets in."""
    from test_ha_witness_server import KEYS as SKEYS, W as SW, A as SA, _genesis
    from pegaprox.core import ha_vote as hv
    ip = _own_ipv4()
    d = wm.check_dir(str(tmp_path / 'w'))
    wm.tls_pair(d)
    port = _free_port()
    wm.Witness(d, started=0, boot_id='x').write({
        'role': hv.ROLE_WITNESS, 'instance_id': SW, 'signing_key': SKEYS[SW], 'own_url': f'https://{ip}:{port}',
        'paired': {'instance_id': SA, 'url': 'https://127.0.0.1:1', 'fingerprint': '', 'at': 'x'},
        'epoch': 1, 'voted_for': None, 'gen': 0, 'cfg': _genesis(), 'cfg_chain': [], 'floor_cv': [0, 0],
        'led': None, 'released': None, 'campaign_after': None, 'promised': None})
    env = dict(os.environ, PYTHONPATH=ROOT, PEGAPROX_WITNESS_PORT=str(port))
    env.pop('PEGAPROX_WITNESS_HOST', None)
    # the default address, and an allow list that names neither loopback nor this host
    proc = subprocess.Popen([PY, '-m', 'pegaprox.witness', '--dir', d, '--allow', '203.0.113.0/24', 'run'],
                            env=env, cwd=str(tmp_path), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert _until(lambda: _answers('127.0.0.1', port) is True, 30)
        # the allow list holds: no way around it from this host's own address
        assert _answers(ip, port) is not True
        out = subprocess.run([PY, '-m', 'pegaprox.witness', '--dir', d, 'health', '--own-url'], env=env,
                             cwd=str(tmp_path), capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


# --- (b) a leader installed from a checkout -------------------------------------------------------------

def _deploy_copy_block():
    with open(os.path.join(ROOT, 'deploy.sh'), encoding='utf-8') as fh:
        text = fh.read()
    start = text.index('        if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then\n')
    end = text.index('\n        fi\n', start) + len('\n        fi\n')
    return text[start:end]


def test_deploy_from_a_checkout_ships_the_installer_and_the_unit(tmp_path, monkeypatch):
    """The LXC appliance creator clones the repository and runs deploy.sh in it: the
    local-checkout branch is what puts the leader on the disk. Run as deploy.sh runs it."""
    from pegaprox.core import ha
    import pegaprox.api.ha as ha_api
    dest = tmp_path / 'PegaProx'
    for d in ('web', 'images', 'static'):
        (dest / d).mkdir(parents=True)
    script = 'set -e\n' + _deploy_copy_block()
    out = subprocess.run(['bash', '-c', script], env=dict(os.environ, SCRIPT_DIR=ROOT, INSTALL_DIR=str(dest),
                                                          PYTHON_FILE='pegaprox_multi_cluster.py'),
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    for rel in ('packaging/witness/install.sh', 'systemd/pegaprox-witness.service'):
        with open(os.path.join(ROOT, rel), 'rb') as a, open(dest / rel, 'rb') as b:
            assert a.read() == b.read(), rel
    monkeypatch.setattr(ha, 'code_root', lambda: str(dest))
    ha._bundle_held.clear()
    try:
        archive, files, _digest = ha._bundle_archive()
        assert 'systemd/pegaprox-witness.service' in files
        assert ha_api.witness_installer() is not None
        assert ha_api.witness_install_commands('https://leader.example:5000', 'pgxwt1_x')['linux']
    finally:
        ha._bundle_held.clear()


def test_a_leader_without_the_unit_serves_its_code_without_it(tmp_path, monkeypatch):
    """An install from a checkout before deploy.sh copied the unit: the bundle leaves it
    out, and the witness takes such a bundle."""
    from pegaprox.core import ha
    tree = tmp_path / 'leader'
    for rel in ha.WITNESS_BUNDLE_FILES:
        if rel.startswith('systemd/'):
            continue
        os.makedirs(tree / os.path.dirname(rel), exist_ok=True)
        shutil.copy(os.path.join(ROOT, rel), tree / rel)
    monkeypatch.setattr(ha, 'code_root', lambda: str(tree))
    ha._bundle_held.clear()
    try:
        archive, files, digest = ha._bundle_archive()
    finally:
        ha._bundle_held.clear()
    assert 'systemd/pegaprox-witness.service' not in files and 'pegaprox/witness.py' in files
    manifest = {'release': _release(), 'wire': ha_wire.WITNESS_WIRE, 'sha256': digest, 'size': len(archive),
                'files': files}
    assert wb.check_bundle(archive, manifest) == wb.bundle_name(_release(), digest)
    # a file the witness needs is still needed
    os.unlink(tree / 'pegaprox' / 'witness_boot.py')
    with pytest.raises(OSError):
        ha._bundle_archive()
    ha._bundle_held.clear()


def test_the_installer_writes_the_unit_itself_when_the_bundle_has_none(box, leader):
    leader.bundle = lambda: _bundle_of(_release(), drop=('systemd/pegaprox-witness.service',))
    out = box.run('--code', leader.code, '--port', str(box.port))
    assert out.returncode == 0, out.stdout + out.stderr
    assert not (box.opt / 'current' / 'systemd').exists()
    with open(os.path.join(ROOT, 'systemd', 'pegaprox-witness.service'), 'rb') as fh:
        assert (box.root / 'etc' / 'systemd' / 'system' / 'pegaprox-witness.service').read_bytes() == fh.read()
    assert box.cmd('health').returncode == 0


def test_the_unit_in_the_installer_is_the_unit_of_the_repository():
    with open(INSTALLER, encoding='utf-8') as fh:
        text = fh.read()
    start = text.index("unit_text() {")
    body = text[text.index("cat <<'EOF'\n", start) + len("cat <<'EOF'\n"):text.index('\nEOF\n', start) + 1]
    with open(os.path.join(ROOT, 'systemd', 'pegaprox-witness.service'), encoding='utf-8') as fh:
        assert body == fh.read()


# --- (c) an update that stops with 78 under the unit ----------------------------------------------------

def test_code_on_trial_that_stops_with_78_stops_with_1_so_the_unit_starts_it_again(auto, dhost, seed, tmp_path,
                                                                                monkeypatch):
    """RestartPreventExitStatus=78: a new release that refuses the state the old one wrote
    would stay down for good and never go back. On trial the runner turns it into 1."""
    from pegaprox.core import ha as core
    host = dhost
    _form(auto, host, seed)
    auto.run(10)
    base = _base(host, tmp_path)
    monkeypatch.setattr(wm, 'RELEASE', '1.1.0')
    broken = (b'import sys\n'
              b'def main(argv=None):\n'
              b'    print("pegaprox-witness: ha_witness.json is no witness state file", file=sys.stderr)\n'
              b'    return 78\n')
    entries = _entries('9.0.0', {'pegaprox/witness.py': broken})
    archive = core.pack_bundle(entries)
    monkeypatch.setattr(core, 'PEGAPROX_VERSION', '9.0.0')
    monkeypatch.setattr(core, '_bundle_archive',
                        lambda: (archive, sorted(entries), hashlib.sha256(archive).hexdigest()))
    with auto.at('a') as ha:
        ha._ask_witness()
        assert ha._witness_update_check()['answer'] == {'accepted': True}
    host.w.upkeep(lambda: None, lambda: True)
    assert host.w.exit_code == wm.EXIT_UPDATED
    unit = open(os.path.join(ROOT, 'systemd', 'pegaprox-witness.service')).read()
    assert 'RestartPreventExitStatus=78' in unit and 'Restart=on-failure' in unit
    for attempt in range(wb.TRIES):
        path, trial = wb.choose(base, host.dir)
        assert trial, attempt
        env = wb.runner_env(path, trial, 'systemd')
        out = subprocess.run([PY, '-I', '-c', wb.RUNNER, '--dir', host.dir, 'run'], env=env,
                             capture_output=True, text=True, timeout=120)
        assert out.returncode == 1, (out.returncode, out.stderr)
        assert 'no witness state file' in out.stderr
    # and the start after them goes back to the code installed before
    said = []
    assert wb.choose(base, host.dir, say=said.append) == (os.path.realpath(base), False)
    assert 'did not come up healthy' in said[0]
    # not on trial a 78 stays a 78: a setting to fix by hand
    env = wb.runner_env(path, False, 'systemd')
    out = subprocess.run([PY, '-I', '-c', wb.RUNNER, 'run'], env=env, capture_output=True, text=True,
                         timeout=120)
    assert out.returncode == 78


# --- (d) the update that did not come up, told again -------------------------------------------------------

def test_an_update_that_went_back_is_not_fetched_and_started_into_again(auto, dhost, seed, tmp_path,
                                                                        monkeypatch):
    from pegaprox.core import ha as core
    host = dhost
    _form(auto, host, seed)
    auto.run(10)
    base = _base(host, tmp_path)
    monkeypatch.setattr(wm, 'RELEASE', '1.1.0')
    entries = _entries('9.0.0', {'pegaprox/witness.py': b'raise SystemExit("this release is broken")\n'})
    archive = core.pack_bundle(entries)
    monkeypatch.setattr(core, 'PEGAPROX_VERSION', '9.0.0')
    monkeypatch.setattr(core, '_bundle_archive',
                        lambda: (archive, sorted(entries), hashlib.sha256(archive).hexdigest()))
    with auto.at('a') as ha:
        ha._ask_witness()
        assert ha._witness_update_check()['answer'] == {'accepted': True}
    host.w.upkeep(lambda: None, lambda: True)
    assert host.w.exit_code == wm.EXIT_UPDATED
    root = os.path.join(host.dir, wb.UPDATES)
    broken = os.path.realpath(os.path.join(root, 'current'))
    # the bundle as it came is kept next to its tree
    kept = json.load(open(os.path.join(root, os.path.basename(broken) + wb.BUNDLE_SUFFIX)))
    assert kept['manifest']['name'] == os.path.basename(broken) and kept['sig'] and kept['archive']
    for _attempt in range(wb.TRIES):
        path, trial = wb.choose(base, host.dir)
        assert (path, trial) == (broken, True)
        assert _run_tree(path, host.dir, '--dir', host.dir, 'run').returncode != 0
    assert wb.choose(base, host.dir)[0] == os.path.realpath(base)
    # the go-back said so where the witness and the leader read it
    host.code_dir = base
    host.restart()
    last = host.w.update_state['last']
    assert last['state'] == 'failed' and last['release'] == '9.0.0' and 'did not come up healthy' in last['error']
    loops = 0
    for _cycle in range(3):
        with auto.at('a') as ha:
            ha._ask_witness()
            f = next(f for f in ha.auto_findings() if f['code'] == 'WITNESS_OUTDATED')
            assert 'last update failed' in f['text'] and 'did not come up healthy' in f['text']
            assert f['command'] == 'sudo pegaprox-witness update' and f['command'] in f['text']
            ha._rt().witness_told = None
            said = ha._witness_update_check()
            assert said['answer'] == {'accepted': False, 'reason': 'FAILED_BEFORE'}
            assert ha.witness_view()['update']['state'] == 'failed'
        host.w.exit_code = 0
        _upkeep_once(host.w)
        if host.w.exit_code == wm.EXIT_UPDATED:
            loops += 1
        assert wb.choose(base, host.dir) == (os.path.realpath(base), False)
        host.restart()
    assert loops == 0
    assert host.w.update_state['last']['state'] == 'failed'


class _Rested(Exception):
    pass


def _upkeep_once(w):
    """One round of Witness.upkeep: it returns when it stops for an update, and rests
    otherwise, which ends the round here."""
    def rest(_s):
        raise _Rested
    try:
        w.upkeep(lambda: None, lambda: True, sleep=rest)
    except _Rested:
        pass


def test_without_the_name_the_witness_refuses_that_code_at_the_fetch_and_takes_it_by_hand(auto, dhost, seed,
                                                                                        tmp_path, monkeypatch):
    """A leader of before the name in the word: the same code is refused once fetched; by
    hand (pegaprox-witness update, after the cause was fixed) it is taken again, on trial."""
    from pegaprox.core import ha as core
    host = dhost
    _form(auto, host, seed)
    auto.run(10)
    base = _base(host, tmp_path)
    monkeypatch.setattr(wm, 'RELEASE', '1.1.0')
    with auto.at('a') as ha:
        ha._ask_witness()
        ha._witness_update_check()
    host.w.upkeep(lambda: None, lambda: True)
    root = os.path.join(host.dir, wb.UPDATES)
    tree = os.path.realpath(os.path.join(root, 'current'))
    health = wb.load_health(root)
    health['bad'].append(tree)
    wb.save_health(root, health)
    wb._go_back(root, health)
    host.code_dir = base
    host.restart()
    job = {'instance_id': auto_ids()['a'], 'url': auto_urls()['a'], 'fingerprint': '', 'release': _release()}
    assert host.w.run_update(job) is False
    assert 'not taken again by itself' in host.w.update_state['last']['error']
    assert not os.path.lexists(os.path.join(root, 'current'))
    assert host.w.run_update(job, retry=True) is True
    assert os.path.realpath(os.path.join(root, 'current')) == tree
    assert tree not in wb.load_health(root)['bad']
    assert wb.choose(base, host.dir) == (tree, True)
    del core


def auto_ids():
    from test_ha_members import IDS
    return IDS


def auto_urls():
    from test_ha_members import URLS
    return URLS


# --- (e) the witness run by hand ---------------------------------------------------------------------

def _checkout(tmp_path):
    """A checkout of this tree, as the manual line runs in one."""
    app = tmp_path / 'app'
    app.mkdir()
    shutil.copy(os.path.join(ROOT, 'pegaprox_multi_cluster.py'), app)
    shutil.copytree(os.path.join(ROOT, 'pegaprox'), app / 'pegaprox', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy(os.path.join(ROOT, 'version.json'), app)
    return app


def _manual_env(port):
    env = dict(os.environ, PEGAPROX_WITNESS_PORT=str(port), PEGAPROX_WITNESS_HOST='127.0.0.1')
    for var in ('PEGAPROX_WITNESS_DIR', 'STATE_DIRECTORY', 'PEGAPROX_WITNESS_CODE_DIR', 'PEGAPROX_WITNESS_INSTALL',
                'PEGAPROX_WITNESS_AUTO_UPDATE', 'PEGAPROX_WITNESS_AGAIN', 'PEGAPROX_WITNESS_TRIAL'):
        env.pop(var, None)
    return env


def test_the_witness_run_by_hand_starts_itself_again_into_an_update(tmp_path, leader):
    """The manual line of "Add witness", in a checkout: nobody supervises it, so after an
    update it starts the start script again in place - same process, new code."""
    port = _free_port()
    work = tmp_path / 'manual'
    work.mkdir()
    app = _checkout(tmp_path)
    wurl = f'https://127.0.0.1:{port}'
    proc = subprocess.Popen([PY, str(app / 'pegaprox_multi_cluster.py'), 'witness', 'run', '--join', leader.code,
                             '--url', wurl], cwd=str(work), env=_manual_env(port),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        assert _until(lambda: _answers('127.0.0.1', port) is True), 'it never answered'
        state = work / 'witness'
        wid = json.load(open(state / 'ha_witness.json'))['instance_id']
        _c, _k, wpin = wm.tls_pair(str(state))
        leader.bundle = lambda: _bundle_of('9.9.9')
        status, ans = _tell(leader, wurl, wid, wpin)
        assert status == 200 and ans == {'accepted': True}
        # it goes down for the start into the update, and comes back by itself: on trial, it
        # answers (healthy is for later, once it ran witness_boot.SOAK)

        def runs_the_update():
            try:
                with open(state / 'update.json', encoding='utf-8') as fh:
                    rel = (json.load(fh).get('running') or {}).get('release')
            except (OSError, ValueError):
                return False
            trial = wb.load_health(str(state / 'code'))['trial']
            return rel == '9.9.9' and bool(trial.get('up')) and _answers('127.0.0.1', port) is True
        assert _until(runs_the_update, 90), 'the update never came up'
        assert proc.poll() is None, proc.stdout.read()[-2000:]
        assert _answers('127.0.0.1', port) is True
        st = subprocess.run([PY, str(app / 'pegaprox_multi_cluster.py'), 'witness', 'status'], cwd=str(work),
                            env=_manual_env(port), capture_output=True, text=True, timeout=60)
        out = json.loads(st.stdout[st.stdout.index('{'):])
        assert out['release'] == '9.9.9' and out['paired'] is True
        assert out['last_update']['state'] == 'installed'
    finally:
        # its output is a pipe: read to the end, so the process never waits on a full one
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()


def _fake_tree(path, release, code=0, marker=None, flips=None):
    """A witness tree whose main says `marker` and returns `code`; with `flips`, a file
    that once there makes it return 0."""
    os.makedirs(os.path.join(path, 'pegaprox', 'core'), exist_ok=True)
    with open(os.path.join(path, 'version.json'), 'w') as fh:
        json.dump({'version': release}, fh)
    open(os.path.join(path, 'pegaprox', '__init__.py'), 'w').close()
    with open(os.path.join(path, 'pegaprox', 'core', 'ha_wire.py'), 'w') as fh:
        fh.write('WITNESS_WIRE = 2\n')
    with open(os.path.join(path, 'pegaprox', 'witness.py'), 'w') as fh:
        fh.write('import os\n'
                 'def main(argv):\n'
                 f'    print({marker!r}, os.getpid(), flush=True)\n'
                 f'    flips = {flips!r}\n'
                 '    if flips and os.path.exists(flips):\n'
                 '        return 0\n'
                 '    if flips:\n'
                 '        open(flips, "w").close()\n'
                 f'    return {code}\n')
    return str(path)


def _boot(tmp_path, base, state, install='manual'):
    env = dict(os.environ, PEGAPROX_WITNESS_BASE=base, PEGAPROX_WITNESS_INSTALL=install)
    for var in ('PEGAPROX_WITNESS_DIR', 'STATE_DIRECTORY', 'PEGAPROX_WITNESS_CODE_DIR', 'PEGAPROX_WITNESS_AGAIN',
                'PEGAPROX_WITNESS_TRIAL'):
        env.pop(var, None)
    return subprocess.run([PY, os.path.join(ROOT, 'pegaprox', 'witness_boot.py'), '--dir', state, 'run'],
                          env=env, cwd=str(tmp_path), capture_output=True, text=True, timeout=120)


def test_by_hand_a_start_on_trial_that_fails_starts_again_and_goes_back(tmp_path):
    state = str(tmp_path / 'state')
    root = os.path.join(state, wb.UPDATES)
    base = _fake_tree(tmp_path / 'base', '1.0.0', marker='old code')
    _fake_tree(os.path.join(root, '1.1.0-aaaaaaaaaaaa'), '1.1.0', code=3, marker='new code')
    wb.switch(root, '1.1.0-aaaaaaaaaaaa')
    out = _boot(tmp_path, base, state)
    lines = [line.split()[:2] for line in out.stdout.splitlines()]
    assert [' '.join(x) for x in lines] == ['new code'] * wb.TRIES + ['old code'], out.stdout + out.stderr
    # one process all along: started again in place
    assert len({line.split()[-1] for line in out.stdout.splitlines()}) == 1
    assert out.returncode == 0
    assert 'did not come up healthy' in out.stderr
    last = json.load(open(os.path.join(state, wb.UPDATE_NAME)))['last']
    assert last['state'] == 'failed' and last['release'] == '1.1.0' and last['name'] == '1.1.0-aaaaaaaaaaaa'
    # under systemd the unit starts it again, not the runner
    os.unlink(os.path.join(state, wb.UPDATE_NAME))
    shutil.rmtree(root)
    _fake_tree(os.path.join(root, '1.1.0-aaaaaaaaaaaa'), '1.1.0', code=3, marker='new code')
    wb.switch(root, '1.1.0-aaaaaaaaaaaa')
    out = _boot(tmp_path, base, state, install='systemd')
    assert out.stdout.split()[:2] == ['new', 'code'] and out.stdout.count('code') == 1
    assert out.returncode == 3


def test_by_hand_the_stop_for_an_update_starts_it_again(tmp_path):
    state = str(tmp_path / 'state')
    flips = str(tmp_path / 'updated')
    base = _fake_tree(tmp_path / 'base', '1.0.0', code=75, marker='running', flips=flips)
    out = _boot(tmp_path, base, state)
    assert out.stdout.count('running') == 2 and out.returncode == 0, out.stdout + out.stderr
    assert len({line.split()[-1] for line in out.stdout.splitlines()}) == 1
    # Ctrl-C is no failure to start again from
    os.unlink(flips)
    stop = _fake_tree(tmp_path / 'stop', '1.0.0', marker='stopped')
    with open(os.path.join(stop, 'pegaprox', 'witness.py'), 'w') as fh:
        fh.write('def main(argv):\n    print("stopped", flush=True)\n    raise KeyboardInterrupt\n')
    out = _boot(tmp_path, stop, state)
    assert out.stdout.count('stopped') == 1 and out.returncode == 130


# --- (f) a new code on a host that is still paired ------------------------------------------------------

def test_a_new_code_after_the_leader_removed_the_witness_pairs_again(box, leader):
    out = box.run('--code', leader.code, '--port', str(box.port))
    assert out.returncode == 0, out.stderr
    old = box.status()['instance_id']
    # the admin removes the witness on the leader while its host is off, then "Add witness"
    box.stop()
    leader.witness = None
    code = _new_code(leader)
    out = box.run('--code', code)
    assert out.returncode == 0, out.stdout + out.stderr
    assert 'let it go - leaving it here and pairing with the new code' in out.stdout
    assert 'paired already' not in out.stdout
    assert leader.spent is True and leader.witness and leader.witness['instance_id'] == old
    st = box.status()
    assert st['paired'] is True and st['leader'] == leader.url
    assert box.cmd('health').returncode == 0
    # and the same line again is the same line again
    out = box.run('--code', code)
    assert out.returncode == 0 and 'paired already - the code is left out' in out.stdout


def test_a_code_of_another_group_while_this_one_still_counts_the_witness_is_refused(box, leader, tmp_path):
    assert box.run('--code', leader.code, '--port', str(box.port)).returncode == 0
    other = Leader(tmp_path / 'other')
    try:
        out = box.run('--code', other.code)
        assert out.returncode != 0
        assert 'still the witness of another group (the leader is 127.0.0.1)' in out.stderr
        assert 'Remove witness on its HA page' in out.stderr and '--uninstall' in out.stderr
        assert other.calls == [] and leader.witness is not None
        assert box.status()['leader'] == leader.url
        # the old leader cannot be asked: the way out is named
        leader.close()
        out = box.run('--code', other.code)
        assert out.returncode != 0
        assert ('this host is still paired with another group - run it with --uninstall --force, then this '
                'line again') in out.stderr
        assert other.calls == []
    finally:
        other.close()


def test_docker_run_join_on_an_old_volume(tmp_path, leader):
    """docker run ... --join <new code> on a volume that is still paired: the same check."""
    path = wm.check_dir(str(tmp_path / 'volume'))
    url = 'https://witness.example:5005'
    wm._join_once(path, leader.code, url)
    first = wm.Witness(path).instance_id()
    assert leader.witness['instance_id'] == first
    # the same code at every start after: no question asked
    calls = len(leader.calls)
    wm._join_once(path, leader.code, url)
    assert len(leader.calls) == calls
    other = Leader(tmp_path / 'other')
    try:
        with pytest.raises(wm.WitnessError, match='still votes in the group of'):
            wm._join_once(path, other.code, url)
        assert other.calls == []
        # removed there: the new code pairs it
        leader.witness = None
        wm._join_once(path, other.code, url)
        w = wm.Witness(path)
        assert w.paired() and w.st['paired']['url'] == other.url and other.witness['instance_id'] == first
    finally:
        other.close()


def test_the_leader_says_whether_it_still_counts_the_witness_without_the_code(auto, dhost, seed):
    import pegaprox.api.ha as ha_api
    from test_ha_witness_group import _pair
    host = dhost
    auto.pair(seed, 'b')
    _pair(auto, host)
    host.w.call = host._to_member
    assert host.w.still_held() == {auto_urls()['a']: True}
    wid = host.w.instance_id()
    raw = ha_wire.wire_body({'release': '1.0', 'wire': 2, 'check': True})
    h = ha_wire.signed_headers(ha_wire.private_key(host.file()['signing_key']), wid, auto_ids()['a'], 'POST',
                               '/api/ha/witness/bundle', raw, time.time())
    h.update({'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json'})
    r = auto.g._serve('a', 'POST', '/api/ha/witness/bundle', raw, h)
    assert r.status_code == 200 and r.json() == {'witness': True, 'instance_id': auto_ids()['a']}
    # a key that is not the witness's learns nothing
    ha_api._peer_failures.reset()
    h = ha_wire.signed_headers(ha_wire.private_key(ha_wire.new_signing_key()), wid, auto_ids()['a'], 'POST',
                               '/api/ha/witness/bundle', raw, time.time())
    h.update({'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json'})
    r = auto.g._serve('a', 'POST', '/api/ha/witness/bundle', raw, h)
    assert r.status_code == 401 and 'witness' not in r.json()
    # removed: the leader says no
    with auto.at('a') as ha:
        ha.remove_witness()
    assert host.w.still_held() == {auto_urls()['a']: False}


# --- (g) a proxy in the environment ------------------------------------------------------------------------

def test_a_proxy_in_the_environment_is_not_used_for_the_members(box, leader):
    """/etc/environment sets https_proxy on many hosts, and sudo hands it on: the bundle
    came straight, the pairing and every call after went into the proxy."""
    dead = _free_port()
    proxies = {'https_proxy': f'http://127.0.0.1:{dead}', 'HTTPS_PROXY': f'http://127.0.0.1:{dead}',
               'http_proxy': f'http://127.0.0.1:{dead}', 'no_proxy': '', 'NO_PROXY': ''}
    out = box.run('--code', leader.code, '--port', str(box.port), **proxies)
    assert out.returncode == 0, out.stdout + out.stderr
    assert [c[0] for c in leader.calls[:2]] == ['/api/ha/witness/bundle', '/api/ha/peer/pair-witness']
    # and the updates by hand too
    leader.bundle = lambda: _bundle_of('9.9.9')
    up = box.cmd('update', PEGAPROX_WITNESS_NO_RESTART='1', **proxies)
    assert up.returncode == 0, up.stdout + up.stderr
    assert 'Release 9.9.9 is in place' in up.stdout


def test_a_failed_call_says_why_and_a_spent_code_says_so(tmp_path, leader):
    port = _free_port()
    with pytest.raises(wm.WitnessError) as e:
        wm.https_call('POST', f'https://127.0.0.1:{port}', '', '/x', b'{}', {}, timeout=5)
    assert 'Connection refused' in str(e.value) and 'object at 0x' not in str(e.value)
    w = wm.Witness(wm.check_dir(str(tmp_path / 'w')))
    leader.spent = True
    with pytest.raises(wm.WitnessError) as e:
        w.join(leader.code, 'https://witness.example:5005')
    assert 'The pairing code is wrong or has expired' in str(e.value) and 'Add witness' in str(e.value)
    with open(INSTALLER, encoding='utf-8') as fh:
        text = fh.read()
    # the installer no longer blames the code for whatever went wrong
    assert 'die "the pairing failed (see the line above)"' in text
    assert 'a code is good for 15 minutes and one witness; get a new one' not in text


# --- (h) a port of its own ------------------------------------------------------------------------------

SYSTEMCTL_WITH_DROPIN = r'''#!/bin/sh
echo "systemctl $*" >> "$FAKE_LOG"
unset PEGAPROX_WITNESS_PORT PEGAPROX_WITNESS_ALLOW PEGAPROX_WITNESS_AUTO_UPDATE
conf="$PEGAPROX_WITNESS_ROOT/etc/systemd/system/pegaprox-witness.service.d/install.conf"
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
    # what systemd hands the service: the Environment= lines of the drop-in
    if [ -f "$conf" ]; then
        for kv in $(sed -n 's/^Environment=//p' "$conf"); do export "$kv"; done
    fi
    nohup "$FAKE_WITNESS" run >> "$FAKE_STATE/witness.log" 2>&1 &
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


def test_with_a_port_of_its_own_the_installer_and_health_check_that_port(box, leader):
    (box.fake / 'systemctl').write_text(SYSTEMCTL_WITH_DROPIN)
    box.env.pop('PEGAPROX_WITNESS_PORT', None)
    out = box.run('--code', leader.code, '--port', str(box.port), '--allow', '192.0.2.0/24',
                  PEGAPROX_WITNESS_WAIT='20')
    assert out.returncode == 0, out.stdout + out.stderr
    assert 'does not answer' not in out.stdout
    assert _answers('127.0.0.1', box.port) is True
    launcher = open(box.bin).read()
    assert f"PEGAPROX_WITNESS_PORT=${{PEGAPROX_WITNESS_PORT:-'{box.port}'}}" in launcher
    assert "PEGAPROX_WITNESS_ALLOW=${PEGAPROX_WITNESS_ALLOW:-'192.0.2.0/24'}" in launcher
    # as the admin runs it, outside the unit
    assert box.cmd('health').returncode == 0
    # a run after that without --port keeps it, in the drop-in and in the command
    again = box.run(PEGAPROX_WITNESS_WAIT='20')
    assert again.returncode == 0, again.stdout + again.stderr
    assert f"PEGAPROX_WITNESS_PORT=${{PEGAPROX_WITNESS_PORT:-'{box.port}'}}" in open(box.bin).read()
    assert box.cmd('health').returncode == 0


# --- (i) status without sudo -----------------------------------------------------------------------------

def test_status_without_sudo_says_to_use_sudo(box, leader):
    out = box.run('--code', leader.code, '--port', str(box.port))
    assert out.returncode == 0, out.stderr
    assert 'Check it: sudo pegaprox-witness status here' in out.stdout
    f = box.var / 'ha_witness.json'
    f.chmod(0)
    try:
        if os.access(f, os.R_OK):
            pytest.skip('this test runs as root, which reads the file anyway')
        st = box.cmd('status')
    finally:
        f.chmod(0o600)
    assert st.returncode == 78
    assert 'run it as root or as pegaprox-witness (sudo pegaprox-witness status)' in st.stderr
    assert 'fix or remove it' not in st.stderr
    with open(os.path.join(ROOT, 'docs', 'ha-witness.md'), encoding='utf-8') as fh:
        doc = fh.read()
    assert 'sudo pegaprox-witness status' in doc
    assert '\npegaprox-witness status\n' not in doc and '`pegaprox-witness status`' not in doc


# --- (j) the start script after a re-run -----------------------------------------------------------------

def test_a_re_run_brings_the_start_script_up_to_date(box, leader):
    out = box.run('--code', leader.code, '--port', str(box.port))
    assert out.returncode == 0, out.stderr
    trust = json.load(open(box.opt / 'trust.json'))
    assert trust['keys'][A] == pub(A) and trust['leader'] == A
    boot_src = open(os.path.join(ROOT, 'pegaprox', 'witness_boot.py'), 'rb').read()
    fixed = boot_src.replace(b'TRIES = 2', b'TRIES = 3  # a later fix of the start script')
    assert fixed != boot_src
    leader.bundle = lambda: _bundle_of('9.9.9', {'pegaprox/witness_boot.py': fixed})
    # the leader runs 9.9.9: by hand, then the installer again, as the docs say
    up = box.cmd('update', PEGAPROX_WITNESS_NO_RESTART='1')
    assert up.returncode == 0, up.stderr
    again = box.run()
    assert again.returncode == 0, again.stdout + again.stderr
    # it runs 9.9.9 now, on trial: the start script comes only from code that ran its first
    # minutes without a stop (witness_boot.SOAK), so not from this run
    tree = os.path.realpath(box.var / 'code' / 'current')
    assert os.path.basename(tree).startswith('9.9.9-') and tree not in wb.load_health(str(box.var / 'code'))['ok']
    assert (box.opt / 'boot.py').read_bytes() == boot_src and 'the start script and' not in again.stdout
    # once the soak went by (as the witness marks it), the next run takes it
    assert wb.mark_ok(str(box.var), tree)
    again = box.run()
    assert again.returncode == 0, again.stdout + again.stderr
    assert (box.opt / 'boot.py').read_bytes() == fixed
    assert os.readlink(box.opt / 'current').startswith('9.9.9-')
    assert 'the start script and' in again.stdout
    # the start after that runs the base, which is that same code
    st = box.status()
    assert st['release'] == '9.9.9'


@pytest.mark.parametrize('how', ['another key', 'changed tree', 'not healthy'])
def test_the_start_script_is_never_taken_from_what_the_service_user_could_change(box, leader, how):
    """The state directory is the service user's; boot.py runs as root. Only a bundle a
    data voter of the pairing signed, checked again as root, and one that came up healthy."""
    assert box.run('--code', leader.code, '--port', str(box.port)).returncode == 0
    boot_src = open(os.path.join(ROOT, 'pegaprox', 'witness_boot.py'), 'rb').read()
    newer = boot_src.replace(b'TRIES = 2', b'TRIES = 2  # the leader signed this')
    leader.bundle = lambda: _bundle_of('9.9.9', {'pegaprox/witness_boot.py': newer})
    assert box.cmd('update', PEGAPROX_WITNESS_NO_RESTART='1').returncode == 0
    code = box.var / 'code'
    name = os.readlink(code / 'current')
    kept = code / (name + wb.BUNDLE_SUFFIX)
    if how == 'another key':
        # the same code, signed by a key that is no data voter of the pairing
        data = json.loads(kept.read_text())
        data['manifest']['by'] = C
        data['sig'] = base64.b64encode(ha_wire.private_key(KEYS[C]).sign(
            ha_wire.bundle_message(data['manifest']))).decode()
        kept.write_text(json.dumps(data))
    elif how == 'changed tree':
        # the tree on disk is not what the bundle holds: the bundle is what is taken
        (code / name / 'pegaprox' / 'witness_boot.py').write_bytes(newer + b'\n# changed on disk\n')
    else:
        (box.fake / 'systemctl').write_text(FAKE_SYSTEMCTL_NO_START)
    if how != 'not healthy':
        # it ran its first minutes without a stop: healthy, as far as that goes
        assert wb.mark_ok(str(box.var), str(code / name))
    again = box.run(PEGAPROX_WITNESS_WAIT='6')
    assert again.returncode == 0, again.stdout + again.stderr
    if how == 'changed tree':
        assert (box.opt / 'boot.py').read_bytes() == newer
        assert os.readlink(box.opt / 'current') == name
        return
    assert (box.opt / 'boot.py').read_bytes() == boot_src, again.stdout + again.stderr
    assert not os.readlink(box.opt / 'current').startswith('9.9.9-')
    if how == 'another key':
        assert 'is not signed by a member of the pairing' in again.stderr


FAKE_SYSTEMCTL_NO_START = '#!/bin/sh\necho "systemctl $*" >> "$FAKE_LOG"\n' \
                          'case "$1" in is-active) exit 3 ;; esac\nexit 0\n'


# --- (k) root's groups --------------------------------------------------------------------------------------

@pytest.mark.parametrize('which', ['boot', 'witness'])
def test_dropping_root_drops_its_groups_first(tmp_path, monkeypatch, which):
    state = tmp_path / 'state'
    state.mkdir()
    calls = []
    real = os.stat(state)

    class _St:
        st_mode, st_uid, st_gid = real.st_mode, 999, 998
    # only for the call: pytest itself goes on with the real ones
    with monkeypatch.context() as m:
        m.setattr(os, 'geteuid', lambda: 0)
        m.setattr(os, 'stat', lambda *_a, **_k: _St())
        for name in ('setgroups', 'setgid', 'setuid'):
            m.setattr(os, name, lambda v, _n=name: calls.append((_n, v)))
        (wb.drop_root if which == 'boot' else wm._drop_root)(str(state))
    assert calls == [('setgroups', []), ('setgid', 998), ('setuid', 999)]
