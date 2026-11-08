"""The witness on its way to many hosts (#625 stage 2), what a third look found.

An update that answers once and fails a little later, or hangs before it serves; a
witness at a third site that reaches the leader only at the address it paired with; the
installer started from a directory anybody writes; a re-run with another --port or --url;
the lines behind a proxy, and where the way out is dropped; a witness ahead of its leader;
docker run --join on an old volume; the firewall hint over IPv6; a host whose python3 is
too old; what the installer says; a fetch that failed once; the open code in the process
list. Each runs the way it failed: the installer for real in a root of its own
(tests/test_ha_witness_install.py), the group in process (tests/test_ha_witness_group.py),
the code a start runs as a process of its own, and the dropped way out in a network
namespace of its own where this host allows one.

MK Oct 2026 (#625)
"""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from http.server import ThreadingHTTPServer

import pytest

from pegaprox import witness as wm
from pegaprox import witness_boot as wb
from pegaprox.core import ha_wire
from test_ha_witness import A
from test_ha_witness_install import Leader, _free_port
from test_ha_witness_install import box  # noqa: F401  (the fixture)
from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_api import ADMIN_PW
from test_ha_members import IDS, URLS, _sync, group  # noqa: F401  (the fixture)
from test_ha_witness_group import WURL, _form, _pair
from test_ha_witness_delivery import host, _base, _entries, _release, _tree  # noqa: F401  (host: a fixture)
from test_ha_witness_hosts import SYSTEMCTL_WITH_DROPIN, _answers, _bundle_of, _has_ipv6, _new_code, _until, \
    _upkeep_once

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER_PATH = '/api/ha/witness/installer'


class GetLeader(Leader):
    """The fake leader, which also serves GET /api/ha/witness/installer as the route does."""

    def __init__(self, path):
        super().__init__(path)
        handler = self.server.RequestHandlerClass
        lead = self
        self.gets = []

        def do_GET(h):
            lead.gets.append(h.path)
            if h.path != INSTALLER_PATH:
                h.send_response(404)
                h.end_headers()
                return
            with open(os.path.join(ROOT, 'packaging', 'witness', 'install.sh'), 'rb') as fh:
                data = fh.read()
            h.send_response(200)
            h.send_header('Content-Type', 'text/x-shellscript')
            h.send_header('Content-Length', str(len(data)))
            h.end_headers()
            h.wfile.write(data)
        handler.do_GET = do_GET


@pytest.fixture
def gleader(tmp_path):
    lead = GetLeader(tmp_path / 'leader')
    yield lead
    lead.close()


def _lines(lead):
    import pegaprox.api.ha as ha_api
    return ha_api.witness_install_commands(lead.url, lead.code)


def _paste(box, line, **env):
    """A line of "Add witness" as the admin pastes it into a shell on the witness host."""
    t0 = time.time()
    out = subprocess.run(['sh', '-c', line], env=dict(box.env, **env), capture_output=True, text=True,
                         timeout=600, cwd=str(box.tmp))
    return out, time.time() - t0


def _dropin(box):
    return (box.root / 'etc' / 'systemd' / 'system' / 'pegaprox-witness.service.d' / 'install.conf').read_text()


def _v6_leader(tmp_path):
    import test_ha_witness_install as ti

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
    return lead


# --- (a) an update that answers once and fails a little later ---------------------------------------------

def test_an_update_that_answers_once_and_then_fails_goes_back(box, gleader):
    """Healthy is what ran SOAK seconds answering on its port, not its first answer: each
    exit before that is a failed start, and the start after TRIES of them goes back."""
    leader = gleader
    assert box.run('--code', leader.code, '--port', str(box.port)).returncode == 0
    with open(os.path.join(ROOT, 'pegaprox', 'witness.py'), 'rb') as fh:
        src = fh.read()
    # the new release answers on its port, then dies in something it does a little later
    crashy = src + (b'\n_real_main = main\n\n\ndef main(argv=None):\n'
                    b'    import threading\n'
                    b'    if (argv or [])[-1:] == ["run"]:\n'
                    b'        threading.Timer(8, lambda: os._exit(1)).start()\n'
                    b'    return _real_main(argv)\n')
    leader.bundle = lambda: _bundle_of('9.9.9', {'pegaprox/witness.py': crashy})
    up = box.cmd('update', PEGAPROX_WITNESS_NO_RESTART='1')
    assert up.returncode == 0, up.stdout + up.stderr
    box.stop()
    root = box.var / 'code'
    tree = os.path.realpath(root / 'current')
    assert os.path.basename(tree).startswith('9.9.9-')
    # the starts as the unit makes them: it answers (up), it is never healthy, and it ends
    for _start in range(wb.TRIES):
        p = subprocess.run([box.bin, 'run'], env=box.env, capture_output=True, text=True, timeout=120)
        health = wb.load_health(str(root))
        assert p.returncode == 1, p.stdout[-600:] + p.stderr[-600:]
        assert tree not in health['ok'] and health['trial'].get('path') == tree and health['trial'].get('up')
    proc = subprocess.Popen([box.bin, 'run'], env=box.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # the start after them goes back to the code installed by hand, and stays
        assert _until(lambda: box.cmd('health').returncode == 0, 60)
        health = wb.load_health(str(root))
        assert tree in health['bad'] and not os.path.lexists(root / 'current')
        st = box.status()
        assert st['release'] == _release()
        assert st['last_update']['state'] == 'failed' and st['last_update']['back'] is True
        time.sleep(10)
        assert proc.poll() is None
    finally:
        proc.terminate()
        try:
            proc.wait(20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


# --- (b) an update that hangs before it serves ---------------------------------------------------------------

HANG = (b'import time\n'
        b'def main(argv=None):\n'
        b'    print("new code: waiting for something that never comes", flush=True)\n'
        b'    time.sleep(10 ** 6)\n')
# what the witness does first for run: the hub takes over threads and sleep
HANG_PATCHED = (b'import time\n'
                b'def main(argv=None):\n'
                b'    from gevent import monkey\n'
                b'    monkey.patch_all()\n'
                b'    print("new code: patched, then waiting", flush=True)\n'
                b'    time.sleep(10 ** 6)\n')
UP_THEN_HANG = (b'import os, time\n'
                b'from pegaprox import witness_boot\n'
                b'def main(argv=None):\n'
                b'    witness_boot.mark_up(os.environ["PEGAPROX_WITNESS_DIR"], os.environ["PEGAPROX_WITNESS_CODE_DIR"])\n'
                b'    time.sleep(10 ** 6)\n')
OK_THEN_EXIT = (b'import os, time\n'
                b'from pegaprox import witness_boot\n'
                b'def main(argv=None):\n'
                b'    witness_boot.mark_ok(os.environ["PEGAPROX_WITNESS_DIR"], os.environ["PEGAPROX_WITNESS_CODE_DIR"])\n'
                b'    time.sleep(6)\n'
                b'    return 0\n')


def _tree_with(root, release, witness_src):
    """An update tree under `root` whose pegaprox/witness.py is `witness_src`, made current."""
    from pegaprox.core import ha
    entries = _entries(release, {'pegaprox/witness.py': witness_src})
    archive = ha.pack_bundle(entries)
    manifest = {'release': release, 'wire': ha_wire.WITNESS_WIRE, 'sha256': hashlib.sha256(archive).hexdigest(),
                'size': len(archive), 'files': sorted(entries)}
    path = wb.install_bundle(archive, manifest, str(root))
    wb.switch(str(root), os.path.basename(path))
    return os.path.realpath(path)


def _start(path, state, trial, bounds=None, again=None):
    """One start of the tree `path` as witness_boot.run makes it, the watchdog's bounds
    shortened to `bounds`."""
    env = wb.runner_env(path, trial, 'systemd', again=again,
                        environ=dict(os.environ, PEGAPROX_WITNESS_DIR=state), state=state)
    if bounds and 'PEGAPROX_WITNESS_WATCH' in env:
        watch = json.loads(env['PEGAPROX_WITNESS_WATCH'])
        watch.update(bounds)
        env['PEGAPROX_WITNESS_WATCH'] = json.dumps(watch)
    return subprocess.Popen([sys.executable, '-I', '-c', wb.RUNNER, '--dir', state, 'run'], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


QUICK = {'up': 2, 'ok': 5, 'step': 0.2}


def _ended(proc, timeout=60):
    """(stdout, stderr) of a start that ends by itself; one that does not is killed, and
    no process of the test is left behind either way."""
    try:
        return proc.communicate(timeout=timeout)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()


@pytest.mark.parametrize('code', [HANG, HANG_PATCHED], ids=['plain', 'monkey-patched'])
def test_an_update_that_hangs_before_it_serves_is_ended_and_goes_back(tmp_path, code):
    state = str(tmp_path / 'state')
    os.makedirs(state, mode=0o700)
    base = _tree(tmp_path / 'opt', '1.0.0')
    tree = _tree_with(os.path.join(state, wb.UPDATES), '9.9.9', code)
    path, trial = wb.choose(base, state)
    assert (path, trial) == (tree, True)
    t0 = time.time()
    proc = _start(path, state, trial, QUICK)
    out, err = _ended(proc)
    assert proc.returncode == 1, (out, err)
    assert 'did not answer on its port within' in err and 'this start counts as failed' in err
    assert time.time() - t0 < 30
    # it never answered: that start was all of its tries, the next one goes back
    said = []
    assert wb.choose(base, state, say=said.append) == (os.path.realpath(base), False)
    assert 'did not come up healthy' in said[0]
    last = json.load(open(os.path.join(state, wb.UPDATE_NAME)))['last']
    assert last['state'] == 'failed' and last['back'] is True


def test_the_watchdog_waits_while_it_answers_and_lets_healthy_code_be(tmp_path):
    state = str(tmp_path / 'state')
    os.makedirs(state, mode=0o700)
    base = _tree(tmp_path / 'opt', '1.0.0')
    root = os.path.join(state, wb.UPDATES)
    # it answers: the bound to answer is off, the one to come up healthy holds
    tree = _tree_with(root, '9.9.9', UP_THEN_HANG)
    path, trial = wb.choose(base, state)
    t0 = time.time()
    proc = _start(path, state, trial, QUICK)
    _out, err = _ended(proc)
    took = time.time() - t0
    assert proc.returncode == 1 and 'did not come up healthy within' in err, err
    assert took >= QUICK['ok'] - 0.5
    assert wb.load_health(root)['trial']['up']
    # it answered: one start of its tries, not all of them
    assert wb.choose(base, state) == (tree, True)
    # healthy code is left alone: it ends when it ends, past every bound
    tree = _tree_with(root, '9.9.10', OK_THEN_EXIT)
    path, trial = wb.choose(base, state)
    assert (path, trial) == (tree, True)
    proc = _start(path, state, trial, QUICK)
    _out, err = _ended(proc)
    assert proc.returncode == 0, err
    # and code not on trial has no watchdog at all
    tree = _tree_with(root, '9.9.11', HANG)
    assert 'PEGAPROX_WITNESS_WATCH' not in wb.runner_env(tree, False, 'systemd', state=state)
    proc = _start(tree, state, False, QUICK)
    try:
        time.sleep(QUICK['ok'] + 2)
        assert proc.poll() is None
    finally:
        proc.kill()
        proc.communicate()


def test_by_hand_the_watchdog_starts_the_start_script_again(tmp_path):
    """A witness nobody supervises: ended by the watchdog, it starts the start script again
    in place (PEGAPROX_WITNESS_AGAIN), which counts the start and goes back."""
    state = str(tmp_path / 'state')
    os.makedirs(state, mode=0o700)
    tree = _tree_with(os.path.join(state, wb.UPDATES), '9.9.9', HANG)
    again = [sys.executable, '-c', 'import os, sys; print("started again", sys.argv[1:], '
                                   '"PEGAPROX_WITNESS_WATCH" in os.environ)']
    proc = _start(tree, state, True, QUICK, again=again)
    out, err = _ended(proc)
    assert proc.returncode == 0, err
    assert f"started again ['--dir', '{state}', 'run'] False" in out


def test_the_start_script_hands_the_watchdog_its_state(tmp_path):
    state = str(tmp_path / 'state')
    os.makedirs(state, mode=0o700)
    base = _tree(tmp_path / 'opt', '1.0.0')
    tree = _tree_with(os.path.join(state, wb.UPDATES), '9.9.9', HANG)
    got = []
    wb.main(['--dir', state, 'run'], base=base, install='systemd', start=lambda *a: got.append(a) or 0)
    path, _argv, trial, install, again, st, b = got[0]
    assert (path, trial, st, b) == (tree, True, state, base)
    env = wb.runner_env(path, trial, install, again, state=st, base=b)
    assert json.loads(env['PEGAPROX_WITNESS_WATCH']) == {
        'health': os.path.join(state, wb.UPDATES, wb.HEALTH), 'tree': tree, 'up': wb.WATCH_UP,
        'ok': wb.WATCH_OK, 'step': wb.WATCH_STEP, 'tries': wb.TRIES}
    assert env['PEGAPROX_WITNESS_BASE'] == base
    # a margin over what the code checks itself: the watchdog is for code that hangs
    assert wb.WATCH_UP > wb.HEALTH_BOUND == wm.HEALTH_BOUND and wb.WATCH_OK > wb.SOAK == wm.SOAK
    assert wb.SOAK >= 120


# --- (c) where a witness at a third site fetches its update --------------------------------------------------

PUBLIC = 'https://pegaprox.example.org:5000'


def test_a_witness_at_a_third_site_fetches_from_the_address_it_paired_with(auto, host, seed, tmp_path,
                                                                          monkeypatch):
    # the third site reaches the leader at a public name; the members talk on their own addresses
    auto.g.by_url[PUBLIC] = auto.g.by_url[URLS['a'].rstrip('/')]
    auto.pair(seed, 'b')
    r = auto.post('a', '/api/ha/witness/pairing-code', {'url': PUBLIC, 'user_password': ADMIN_PW, 'site': 'dc3'})
    assert r.status_code == 200, r.data
    code = r.get_json()['code']
    real_call = host.w.call
    reached = []

    def from_the_third_site(method, url, fingerprint, path, raw, headers, timeout=15):
        reached.append(url.rstrip('/'))
        if url.rstrip('/') != PUBLIC:
            raise wm.WitnessError(f'Cannot reach {url}: ConnectTimeoutError: timed out')
        return real_call(method, url, fingerprint, path, raw, headers, timeout=timeout)
    host.w.call = from_the_third_site
    assert host.w.join(code, WURL) == IDS['a']
    host.w.start()
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    r = auto.switch_on()
    assert r.status_code == 200, r.data
    auto.run(10)
    # later the admin adds a member: the leader's own address is the one the members reach
    r = auto.post('a', '/api/ha/pairing-code', {'url': URLS['a'], 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    _base(host, tmp_path)
    monkeypatch.setattr(wm, 'RELEASE', '1.1.0')
    with auto.at('a') as ha:
        assert ha._load()['own_url'].rstrip('/') == URLS['a'].rstrip('/')
        ha._ask_witness()
        assert ha._witness_update_check()['answer'] == {'accepted': True}
    # the word named the other data voters too
    assert host.w.update_state['voters'][IDS['b']]['url'].rstrip('/') == URLS['b'].rstrip('/')
    reached.clear()
    _upkeep_once(host.w)
    assert host.w.exit_code == wm.EXIT_UPDATED, host.w.update_state.get('last')
    assert host.w.update_state['last']['state'] == 'installed'
    assert reached == [URLS['a'].rstrip('/'), PUBLIC]


def test_the_places_an_update_is_fetched_from(auto, host, seed):
    auto.pair(seed, 'b')
    _pair(auto, host)
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    w = host.w
    paired = w.st['paired']['url']
    w.note_update(leader={'instance_id': IDS['b'], 'url': 'https://told.example:5000', 'fingerprint': '',
                          'release': '9.9.9', 'wire': 2},
                  voters={IDS['b']: {'url': URLS['b'], 'fingerprint': ''},
                          'c' * 32: {'url': 'https://not-a-voter.example:5000', 'fingerprint': ''}})
    # told, paired, the other data voters it knows; nobody twice, no one who is no data voter
    assert [(t['instance_id'], t['url']) for t in w.update_targets()] == [
        (IDS['b'], 'https://told.example:5000'), (IDS['a'], paired), (IDS['b'], URLS['b'])]
    assert w.update_target()['url'] == 'https://told.example:5000'
    first = {'instance_id': IDS['a'], 'url': paired + '/', 'fingerprint': '', 'release': '9.9.9'}
    assert [t['url'] for t in w.update_targets(first)] == [paired + '/', URLS['b']]


# --- (d) the installer started from a directory anybody writes ------------------------------------------------

def test_the_installer_imports_nothing_from_the_directory_it_was_started_in(box, gleader):
    # sudo sh /opt/pegaprox-witness/install.sh from /tmp: anybody can drop json.py there
    marker = box.tmp / 'ran-as-installer'
    (box.tmp / 'json.py').write_text(f"open({str(marker)!r}, 'a').write('imported from the cwd\\n')\n"
                                     "raise SystemExit(3)\n")
    out = box.run('--code', gleader.code, '--port', str(box.port))
    assert out.returncode == 0, out.stdout + out.stderr
    assert not marker.exists()
    # and every python it starts, and writes into the command, is isolated
    with open(os.path.join(ROOT, 'packaging', 'witness', 'install.sh'), encoding='utf-8') as fh:
        text = fh.read()
    import re
    started = re.findall(r'''(?:"\$PY"|'\$PY'|"\$found"|/venv/bin/python3")[ \t]+(\S+)''', text)
    assert started and all(arg in ('-I', ']', '];') for arg in started), started
    assert open(box.bin).read().count(" -I '") == 2


def test_uninstall_from_a_shared_directory_imports_nothing_from_it(box, gleader):
    assert box.run('--code', gleader.code, '--port', str(box.port)).returncode == 0
    shared = box.tmp / 'shared'
    shared.mkdir()
    marker = box.tmp / 'ran-uninstall'
    (shared / 'json.py').write_text(f"open({str(marker)!r}, 'a').write('x')\nraise SystemExit(3)\n")
    out = subprocess.run([box.bin, 'uninstall'], env=box.env, capture_output=True, text=True, timeout=120,
                         cwd=str(shared))
    assert out.returncode == 0, out.stdout + out.stderr
    assert not marker.exists() and gleader.witness is None and not box.opt.exists()


# --- (e) a re-run with another --port or --url -------------------------------------------------------------

@pytest.mark.parametrize('flag', ['port', 'url'])
def test_a_paired_witness_keeps_the_address_the_members_call(box, gleader, flag):
    (box.fake / 'systemctl').write_text(SYSTEMCTL_WITH_DROPIN)
    box.env.pop('PEGAPROX_WITNESS_PORT', None)
    out = box.run('--code', gleader.code, '--port', str(box.port), PEGAPROX_WITNESS_WAIT='20')
    assert out.returncode == 0, out.stdout + out.stderr
    url = gleader.witness['url']
    args = ['--port', str(_free_port())] if flag == 'port' else ['--url', f'https://witness.example.net:{box.port}']
    done = len(box.did())
    again = box.run(*args, script=str(box.opt / 'install.sh'), PEGAPROX_WITNESS_WAIT='20')
    assert again.returncode != 0
    assert f'this witness is paired as {url}, the address the members call' in again.stderr
    assert 'Remove witness' in again.stderr and 'make a new code there with Add witness' in again.stderr
    assert f'run its line with --{flag}' in again.stderr
    # nothing changed: the members reach it where they call it
    assert f'Environment=PEGAPROX_WITNESS_PORT={box.port}' in _dropin(box)
    assert box.status()['own_url'] == url and _answers('127.0.0.1', box.port) is True
    assert not [d for d in box.did()[done:] if 'restart' in d]
    # the address it has is no change
    same = ['--port', str(box.port)] if flag == 'port' else ['--url', url]
    out = box.run(*same, script=str(box.opt / 'install.sh'), PEGAPROX_WITNESS_WAIT='20')
    assert out.returncode == 0, out.stdout + out.stderr


def test_a_listener_on_another_port_than_its_address_stops_the_run(box, gleader):
    (box.fake / 'systemctl').write_text(SYSTEMCTL_WITH_DROPIN)
    box.env.pop('PEGAPROX_WITNESS_PORT', None)
    assert box.run('--code', gleader.code, '--port', str(box.port), PEGAPROX_WITNESS_WAIT='20').returncode == 0
    url = gleader.witness['url']
    conf = box.root / 'etc' / 'systemd' / 'system' / 'pegaprox-witness.service.d' / 'install.conf'
    other = _free_port()
    conf.write_text(conf.read_text().replace(f'PORT={box.port}', f'PORT={other}'))
    again = box.run(script=str(box.opt / 'install.sh'), PEGAPROX_WITNESS_WAIT='20')
    assert again.returncode != 0
    assert f'the witness listens on port {other}, but it is paired as {url}' in again.stderr
    assert f'run this with --port {box.port}' in again.stderr
    # the way out it names
    fixed = box.run('--port', str(box.port), script=str(box.opt / 'install.sh'), PEGAPROX_WITNESS_WAIT='20')
    assert fixed.returncode == 0, fixed.stdout + fixed.stderr
    assert f'Environment=PEGAPROX_WITNESS_PORT={box.port}' in _dropin(box)
    assert box.cmd('health', '--own-url').returncode == 0


def test_a_new_pairing_listens_on_the_port_its_address_names(box, gleader):
    (box.fake / 'systemctl').write_text(SYSTEMCTL_WITH_DROPIN)
    box.env.pop('PEGAPROX_WITNESS_PORT', None)
    # two ports, or none in the address: stopped before anything is fetched or spent
    out = box.run('--code', gleader.code, '--url', f'https://127.0.0.1:{_free_port()}', '--port', str(box.port))
    assert out.returncode != 0 and 'name two ports' in out.stderr
    out = box.run('--code', gleader.code, '--url', 'https://witness.example.net')
    assert out.returncode != 0 and '--url needs the port the witness listens on' in out.stderr
    assert gleader.calls == [] and not gleader.spent
    # the port in --url is the port it listens on
    out = box.run('--code', gleader.code, '--url', f'https://127.0.0.1:{box.port}', PEGAPROX_WITNESS_WAIT='20')
    assert out.returncode == 0, out.stdout + out.stderr
    assert gleader.witness['url'] == f'https://127.0.0.1:{box.port}'
    assert f'Environment=PEGAPROX_WITNESS_PORT={box.port}' in _dropin(box)
    assert box.cmd('health', '--own-url').returncode == 0


# --- (f) the lines behind a proxy of the environment ----------------------------------------------------------

@pytest.mark.parametrize('way', ['linux', 'offline'])
def test_the_lines_reach_the_leader_past_a_proxy_of_the_environment(box, gleader, way):
    """https_proxy as a host behind a proxy has it, a proxy that does not reach the leader
    (a dead port here; Squid by default refuses CONNECT to any port but 443)."""
    dead = _free_port()
    proxies = {'https_proxy': f'http://127.0.0.1:{dead}', 'HTTPS_PROXY': f'http://127.0.0.1:{dead}',
               'no_proxy': '', 'NO_PROXY': ''}
    out, _took = _paste(box, _lines(gleader)[way] + f' --port {box.port}', **proxies)
    assert out.returncode == 0, out.stdout[-1500:] + out.stderr[-1500:]
    assert gleader.gets == [INSTALLER_PATH] and gleader.witness
    with open(os.path.join(ROOT, 'docs', 'ha-witness.md'), encoding='utf-8') as fh:
        doc = fh.read()
    assert "--noproxy '*'" in doc and 'never through a proxy' in doc


# --- (g) a witness ahead of its leader -------------------------------------------------------------------------

def test_a_witness_ahead_of_its_leader_votes_and_goes_down_by_hand_only(auto, host, seed, tmp_path, monkeypatch,
                                                                       capsys):
    # the leader went back to an older release after the witness had updated itself
    monkeypatch.setattr(wm, 'RELEASE', '9.0.0')
    auto.pair(seed, 'b')
    _pair(auto, host)
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    wid = host.w.instance_id()
    # judged by the wire: two apart is too far to vote with
    monkeypatch.setattr(wm, 'WIRE', ha_wire.WITNESS_WIRE + 2)
    with auto.at('a') as ha:
        ha._ask_witness()
        far = {f['code']: f['level'] for f in ha.auto_findings() if f.get('member') == wid}
    assert far.get('WITNESS_AHEAD') == 'block' and 'RELEASE_MISMATCH' not in far
    monkeypatch.setattr(wm, 'WIRE', ha_wire.WITNESS_WIRE)
    with auto.at('a') as ha:
        ha._ask_witness()
        found = {f['code']: f for f in ha.auto_findings() if f.get('member') == wid}
        view = ha.witness_view()
    f = found['WITNESS_AHEAD']
    assert 'RELEASE_MISMATCH' not in found and f['level'] == 'warn'
    assert '9.0.0' in f['text'] and _release() in f['text'] and 'votes with this release as it is' in f['text']
    assert f['command'] == 'sudo pegaprox-witness update --to-leader' and f['command'] in f['text']
    assert view['ahead'] is True and view['outdated'] is False
    assert view['to_leader_command'] == 'sudo pegaprox-witness update --to-leader'
    # automatic failover goes on, the warning ticked
    r = auto.switch_on(accept=['WITNESS_AHEAD'])
    assert r.status_code == 200, r.data
    auto.run(10)
    assert auto.leader() == 'a'
    # the leader tells it what it runs, never to update: nothing goes down by itself
    with auto.at('a') as ha:
        ha._ask_witness()
        said = ha._witness_update_check()
    assert said['update'] is False and said['answer'] == {'accepted': False, 'reason': 'NOT_NEWER'}
    assert host.w.job is None and host.w.update_state['leader']['release'] == _release()
    assert host.w.ahead()['command'] == 'sudo pegaprox-witness update --to-leader'
    # by hand, from a base the installer put there at 9.0.0
    opt = tmp_path / 'opt'
    base_tree = _base(host, tmp_path, release='9.0.0')
    base = str(opt / 'current')
    monkeypatch.setattr(wm, 'https_call', host._to_member)
    monkeypatch.setenv('PEGAPROX_WITNESS_CODE_DIR', base_tree)
    monkeypatch.setenv('PEGAPROX_WITNESS_INSTALL', 'systemd')
    monkeypatch.setenv('PEGAPROX_WITNESS_BASE', base)
    assert wm.main(['--dir', host.dir, 'update']) == 0
    assert 'already' in capsys.readouterr().out
    assert not os.path.lexists(os.path.join(host.dir, wb.UPDATES, 'current'))
    assert wm.main(['--dir', host.dir, 'update', '--to-leader']) == 0
    assert 'is in place' in capsys.readouterr().out
    tree = os.path.realpath(os.path.join(host.dir, wb.UPDATES, 'current'))
    assert os.path.basename(tree).startswith(f'{_release()}-')
    # the leader's older code runs, on trial, although the base is newer
    assert wb.choose(base, host.dir) == (tree, True)
    # and once it came up, through another base too (a new image, the installer run
    # again): what holds it is the leader's release, not the base (test_ha_witness_field.py)
    wb.mark_ok(host.dir, tree)
    newer = _tree(tmp_path / 'opt2', '9.1.0')
    assert wb.choose(newer, host.dir, counting=False) == (tree, False)
    assert wb.choose(newer, host.dir) == (tree, False)


# --- (i) docker run --join with a new code on an old volume -----------------------------------------------------

@pytest.mark.parametrize('runs_from', ['image', 'volume'])
def test_a_new_code_on_an_old_volume_leaves_the_old_groups_updates(tmp_path, gleader, monkeypatch, runs_from):
    leader = gleader
    vol = tmp_path / 'volume'
    vol.mkdir(mode=0o700)
    url = 'https://127.0.0.1:5999'
    wm._join_once(str(vol), leader.code, url)
    # the old group had updated the witness to its newer release, into the volume
    root = vol / wb.UPDATES
    tree = _tree(root, '9.0.0')
    wb.switch(str(root), os.path.basename(tree))
    wb.mark_ok(str(vol), tree)
    with open(vol / wb.UPDATE_NAME, 'w') as fh:
        json.dump({'last': {'state': 'failed', 'release': '9.1.0', 'error': 'old group', 'at': 'x'}}, fh)
    if runs_from == 'volume':
        # this very process runs from that tree: what it imports later still has to be there
        monkeypatch.setenv('PEGAPROX_WITNESS_CODE_DIR', tree)
    # the old group let it go; a new group makes a new code
    leader.witness = None
    _new_code(leader)
    wm._join_once(str(vol), leader.code, url)
    assert leader.witness and wm.Witness(str(vol)).paired()
    assert not (vol / wb.UPDATE_NAME).exists()
    assert not os.path.lexists(root / 'current') and not (root / wb.HEALTH).exists()
    assert os.path.isdir(tree) == (runs_from == 'volume')
    # the start after it runs the image, not the code of the old group
    assert wb.choose(ROOT, str(vol), counting=False) == (os.path.realpath(ROOT), False)


# --- (j) the firewall hint speaks the family of the address the members call -----------------------------------

@pytest.mark.skipif(not _has_ipv6(), reason='this host has no IPv6 loopback')
@pytest.mark.parametrize('tool', ['firewall-cmd', 'nft'])
def test_the_firewall_hint_over_ipv6(box, tmp_path, tool):
    lead = _v6_leader(tmp_path)
    try:
        box.env.pop('PEGAPROX_WITNESS_HOST', None)
        # no ufw: firewalld (RHEL), or plain nftables
        path = ':'.join(p for p in box.env['PATH'].split(':') if p not in ('/usr/sbin', '/sbin', '/usr/local/sbin'))
        if tool == 'firewall-cmd':
            (box.fake / 'firewall-cmd').write_text('#!/bin/sh\nexit 0\n')
            (box.fake / 'firewall-cmd').chmod(0o755)
        out = box.run('--code', lead.code, '--port', str(box.port), PATH=path)
        assert out.returncode == 0, out.stdout + out.stderr
        assert lead.witness['url'].startswith('https://[::1]:')
        if tool == 'firewall-cmd':
            assert "rule family=ipv6 source address=<member address>" in out.stdout
            assert 'family=ipv4' not in out.stdout
        else:
            assert f'nft add rule inet filter input ip6 saddr <member address> tcp dport {box.port} accept' \
                in out.stdout
            assert ' ip saddr' not in out.stdout
    finally:
        lead.close()


def test_the_firewall_hint_for_a_name_names_both_families(box, gleader):
    path = ':'.join(p for p in box.env['PATH'].split(':') if p not in ('/usr/sbin', '/sbin', '/usr/local/sbin'))
    out = box.run('--code', gleader.code, '--port', str(box.port), '--url', f'https://localhost:{box.port}',
                  PATH=path)
    assert out.returncode == 0, out.stdout + out.stderr
    assert 'ip saddr <member IPv4 address>' in out.stdout and 'ip6 saddr <member IPv6 address>' in out.stdout


# --- (k) a host whose python3 is too old -------------------------------------------------------------------------

OLD_PYTHON3 = '#!/bin/sh\n# python 3.6, as python3 is on RHEL 8 and openSUSE Leap 15\n' \
              'case "$*" in -V) echo "Python 3.6.8"; exit 0 ;; esac\nexit 1\n'
NOT_THERE = '#!/bin/sh\nexit 127\n'


def _old_host(box, have=()):
    """python3 is 3.6; of python3.9 to python3.13 only `have` is there (the real one)."""
    (box.fake / 'python3').write_text(OLD_PYTHON3)
    for minor in range(9, 14):
        name = f'python3.{minor}'
        (box.fake / name).write_text(f'#!/bin/sh\nexec {sys.executable} "$@"\n' if name in have else NOT_THERE)
        (box.fake / name).chmod(0o755)


def test_a_host_with_an_old_python3_takes_the_newer_one_next_to_it(box, gleader):
    _old_host(box, have=('python3.9',))
    out = box.run('--code', gleader.code, '--port', str(box.port))
    assert out.returncode == 0, out.stdout + out.stderr
    assert f"exec '{box.fake}/python3.9' -I '{box.opt}/boot.py'" in open(box.bin).read()
    assert box.cmd('health').returncode == 0


def test_a_host_with_an_old_python3_and_none_next_to_it_gets_one(box, gleader):
    _old_host(box)
    # dnf has python3.11 (RHEL 8): it puts it on the host
    (box.fake / 'dnf').write_text(
        '#!/bin/sh\necho "dnf $*" >> "$FAKE_LOG"\n'
        'case "$*" in *python3.11*) printf \'#!/bin/sh\\nexec %s "$@"\\n\' "$REAL_PY" > "$FAKE_DIR/python3.11" ;; '
        '*) exit 1 ;; esac\n')
    (box.fake / 'dnf').chmod(0o755)
    out = box.run('--code', gleader.code, '--port', str(box.port), REAL_PY=sys.executable, FAKE_DIR=str(box.fake))
    assert out.returncode == 0, out.stdout + out.stderr
    assert 'dnf install -y python3.11' in box.did()
    assert f"exec '{box.fake}/python3.11' -I '{box.opt}/boot.py'" in open(box.bin).read()


def test_a_host_with_an_old_python3_says_what_it_needs(box, gleader):
    _old_host(box)
    (box.fake / 'dnf').write_text('#!/bin/sh\necho "dnf $*" >> "$FAKE_LOG"\nexit 1\n')
    (box.fake / 'dnf').chmod(0o755)
    out = box.run('--code', gleader.code)
    assert out.returncode != 0
    assert 'Python 3.6.8 - the witness needs python 3.9 or later' in out.stderr
    assert [d for d in box.did() if d.startswith('dnf')] == ['dnf install -y python3.11', 'dnf install -y python311',
                                                            'dnf install -y python39']
    assert gleader.calls == []
    with open(os.path.join(ROOT, 'docs', 'ha-witness.md'), encoding='utf-8') as fh:
        doc = fh.read()
    for name in ('Debian 11', 'Ubuntu 22.04', 'RHEL', 'openSUSE Leap'):
        assert name in doc, name


# --- (l) what the installer says ----------------------------------------------------------------------------------

def test_the_way_out_the_installer_names_when_the_address_does_not_answer(box, gleader):
    # the service listens elsewhere than the address worked out (its port, here), the
    # installer stops, and the way out it names works: the code is used up by then
    out, _took = _paste(box, _lines(gleader)['offline'])
    assert out.returncode != 0
    assert 'make a new code with Add witness on the leader\'s HA page (this one is used up)' in out.stderr
    assert 'run its line with --url https://<an address of this host>' in out.stderr
    assert 'Start the witness now' not in out.stdout
    assert box.cmd('uninstall').returncode == 0 and gleader.witness is None
    _new_code(gleader)
    again, _took = _paste(box, _lines(gleader)['offline'] + f' --url https://127.0.0.1:{box.port}')
    assert again.returncode == 0, again.stdout + again.stderr
    assert 'Start the witness now' not in again.stdout and 'the witness runs' in again.stdout


# --- (m) a fetch that failed once --------------------------------------------------------------------------------

def test_a_fetch_that_failed_once_is_tried_again_with_the_leaders_next_word(auto, host, seed, tmp_path,
                                                                            monkeypatch):
    _form(auto, host, seed)
    auto.run(10)
    _base(host, tmp_path)
    monkeypatch.setattr(wm, 'RELEASE', '1.1.0')
    real = host.w.call
    cut = [True]

    def flaky(*a, **kw):
        if cut[0]:
            raise wm.WitnessError('Cannot reach https://active.example:5000: ReadTimeoutError: timed out')
        return real(*a, **kw)
    host.w.call = flaky
    with auto.at('a') as ha:
        ha._ask_witness()
        assert ha._witness_update_check()['answer'] == {'accepted': True}
    _upkeep_once(host.w)
    last = host.w.update_state['last']
    assert last['state'] == 'failed' and last['back'] is False and 'Cannot reach' in last['error']
    with auto.at('a') as ha:
        ha._ask_witness()
        f = next(f for f in ha.auto_findings() if f['code'] == 'WITNESS_OUTDATED')
        assert 'tries again when the leader says so again' in f['text'] and 'by hand' not in f['text']
        assert ha.witness_view()['update']['back'] is False
        # the next word, five minutes later
        ha._rt().witness_told = None
        assert ha._witness_update_check()['answer'] == {'accepted': True}
    cut[0] = False
    stopped = []
    host.w.upkeep(lambda: stopped.append(True), lambda: True)
    assert stopped == [True] and host.w.exit_code == wm.EXIT_UPDATED


# --- (n) the open code in the process list -------------------------------------------------------------------------

def test_the_code_stays_off_the_process_list(box, gleader):
    # apt takes a while on a fresh host; the code is not spent until the pairing after it
    (box.fake / 'apt-get').write_text('#!/bin/sh\necho "apt-get $*" >> "$FAKE_LOG"\nsleep 3\n'
                                      'for a in "$@"; do case $a in python3-*) '
                                      'touch "$FAKE_STATE/pkg-${a#python3-}" ;; esac; done\n')
    # pasted into a shell: in no process's arguments, as a file here
    pasted = box.tmp / 'pasted.sh'
    pasted.write_text(_lines(gleader)['offline'] + f' --port {box.port}\n')
    proc = subprocess.Popen(['sh', str(pasted)], env=dict(box.env, FAKE_MISSING='gevent'), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, cwd=str(box.tmp))
    seen, looks = [], 0
    try:
        end = time.time() + 300
        while proc.poll() is None and time.time() < end:
            ps = subprocess.run(['ps', '-ewwo', 'pid,args'], capture_output=True, text=True, timeout=30).stdout
            looks += 1
            seen += [line for line in ps.splitlines() if gleader.code in line]
            time.sleep(0.05)
    finally:
        # stdout and stderr are pipes: read to the end, so a full one never holds the line
        if proc.poll() is None:
            proc.kill()
        out, err = proc.communicate()
    assert proc.returncode == 0, out[-1500:] + err[-1500:]
    assert gleader.spent and looks > 20
    assert seen == []
    assert 'apt-get install -y --no-install-recommends python3-gevent' in box.did()


# --- (h) the Linux line where the way out is dropped -----------------------------------------------------------------

_INSIDE = 'PEGAPROX_TEST_DROPPED_WAY_OUT'


def _netns():
    if not shutil.which('unshare') or not shutil.which('ip') or not shutil.which('mount'):
        return False
    try:
        return subprocess.run(['unshare', '-rnm', 'true'], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.mark.skipif(not _netns(), reason='no unprivileged network namespace on this host')
def test_the_linux_line_gives_up_on_a_dropped_way_out_in_time(tmp_path):
    """A network namespace of its own: loopback, and a default route into a dummy device
    where packets go nowhere; GitHub and the mirror resolve into it. The test below runs in
    there."""
    hosts = tmp_path / 'hosts'
    hosts.write_text('127.0.0.1 localhost\n::1 localhost\n203.0.113.1 raw.githubusercontent.com\n'
                     '203.0.113.2 updates.pegaprox.com\n')
    ip = shutil.which('ip')
    script = (f"set -e\nmount --bind '{hosts}' /etc/hosts\n{ip} link set lo up\n{ip} link add d0 type dummy\n"
              f"{ip} link set d0 up\n{ip} addr add 192.0.2.5/24 dev d0\n{ip} route add default dev d0\n"
              f"exec '{sys.executable}' -m pytest -q -p no:cacheprovider "
              f"'{os.path.abspath(__file__)}::test_inside_a_dropped_way_out'\n")
    out = subprocess.run(['unshare', '-rnm', 'sh', '-c', script], env=dict(os.environ, **{_INSIDE: '1'}),
                         cwd=ROOT, capture_output=True, text=True, timeout=900)
    assert out.returncode == 0 and '1 passed' in out.stdout, out.stdout[-4000:] + out.stderr[-2000:]


@pytest.mark.skipif(not os.environ.get(_INSIDE), reason='runs in the namespace of the test above')
def test_inside_a_dropped_way_out(box, gleader):
    out, took = _paste(box, _lines(gleader)['linux'] + f' --port {box.port}')
    assert out.returncode == 0, out.stdout[-1500:] + out.stderr[-1500:]
    # two public sources at most 10 s each to connect, then the leader: minutes before
    assert gleader.gets == [INSTALLER_PATH] and took < 120, took


def test_a_new_code_after_remove_witness_pairs_while_the_host_is_on(box, tmp_path):
    """Remove witness on the leader tells the witness, which lets go and keeps running
    (it holds its state). The new code's line stops it, drops the old group's updates and
    pairs."""
    import secrets
    import ssl
    import pegaprox.api.ha as ha_api
    from test_ha_witness import KEYS

    def answers():
        try:
            with socket.create_connection(('127.0.0.1', box.port), timeout=2) as raw:
                with ssl._create_unverified_context().wrap_socket(raw):
                    return True
        except OSError:
            return False
    lead = GetLeader(tmp_path / 'leader')
    try:
        assert box.run('--code', lead.code, '--port', str(box.port)).returncode == 0
        deadline = time.time() + 30
        while not answers() and time.time() < deadline:
            time.sleep(0.5)
        st = json.load(open(box.var / 'ha_witness.json'))
        _c, _k, pin = wm.tls_pair(str(box.var))
        body = ha_wire.wire_body({'removed': True})
        headers = ha_wire.signed_headers(ha_wire.private_key(KEYS[A]), A, st['instance_id'], 'POST',
                                         wm.UNPAIRED_PATH, body, time.time())
        wm.https_call('POST', f'https://127.0.0.1:{box.port}', pin, wm.UNPAIRED_PATH, body, headers)
        (box.var / 'code').mkdir(exist_ok=True)
        (box.var / 'update.json').write_text('{"last": {"state": "failed", "back": true}}')
        lead.witness, lead.spent = None, False
        lead.secret = secrets.token_urlsafe(32)
        lead.code = ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, lead.url, lead.pin, lead.secret, A)

        out = subprocess.run(['sh', '-c', ha_api.witness_install_commands(lead.url, lead.code)['offline']],
                             env=box.env, capture_output=True, text=True, timeout=240, cwd=str(box.tmp))

        assert out.returncode == 0, out.stderr[-800:]
        assert lead.witness and lead.spent
        assert not (box.var / 'update.json').exists() or 'failed' not in (box.var / 'update.json').read_text()
    finally:
        lead.close()
