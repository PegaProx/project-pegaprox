"""How a witness gets onto its host and stays current (#625 stage 2).

"Add witness" answers with one command per way to install, the code in it; the Linux
line runs packaging/witness/install.sh only when it matches the SHA-256 of the leader's
own copy. The installer and the witness take the witness code from the leader as one
signed bundle (/api/ha/witness/bundle): the installer for the open code, the paired
witness for its signature. A leader that runs newer code tells its witness once the data
voters hold a majority without it; the witness fetches, checks, unpacks next to what
runs and exits, and witness_boot starts the newer code, or goes back to the code before
it when that does not come up.

The group is the in-process harness of tests/test_ha_witness_group.py. The code a
restart would run is run for real, in a fresh interpreter, from the tree the update
unpacked. The installer itself is tests/test_ha_witness_install.py, the witness of the
first wire next to these members tests/test_ha_witness_n1.py.

MK Oct 2026 (#625)
"""
import ast
import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import time

import pytest

from pegaprox import witness as wm
from pegaprox import witness_boot as wb
from pegaprox.core import ha_vote as hv
from pegaprox.core import ha_wire
from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_api import ADMIN_PW, _audit
from test_ha_members import IDS, URLS, _sync, group  # noqa: F401  (the fixture)
from test_ha_witness_group import WURL, Host, _code, _form, _pair, _wid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE = '/api/ha/witness/bundle'
INSTALLER = '/api/ha/witness/installer'
# runs the witness module of the tree witness_boot hands over, and says which file it is
PROBE = ('import json, os, sys\n'
         'sys.path.insert(0, os.environ["PEGAPROX_WITNESS_CODE_DIR"])\n'
         'import pegaprox.witness as w\n'
         'print(json.dumps({"file": w.__file__, "release": w.RELEASE, "wire": w.WIRE}))\n')


def _release():
    from pegaprox.constants import PEGAPROX_VERSION
    return PEGAPROX_VERSION


class UpdHost(Host):
    """The witness as witness_boot starts it: from a code tree it names, updates on."""

    code_dir = None

    def make(self):
        w = super().make()
        w.code_dir, w.auto_update, w.install = self.code_dir, True, 'systemd'
        return w


@pytest.fixture
def host(auto, tmp_path, monkeypatch):
    return UpdHost(auto, tmp_path, monkeypatch)


def _entries(release=None, replace=None):
    """The files of the witness bundle as the leader packs them, with `replace` in place
    of some ({'pegaprox/witness.py': b'...'})."""
    from pegaprox.core import ha
    out = {}
    for rel in ha.WITNESS_BUNDLE_FILES:
        with open(os.path.join(ROOT, rel), 'rb') as fh:
            out[rel] = fh.read()
    out['version.json'] = json.dumps({'version': release or _release(),
                                      'wire': ha_wire.WITNESS_WIRE}).encode()
    out.update(replace or {})
    return out


def _tree(path, release):
    """A witness code tree as an install leaves it, under `path`; returns its directory."""
    from pegaprox.core import ha
    entries = _entries(release)
    archive = ha.pack_bundle(entries)
    manifest = {'release': release, 'wire': ha_wire.WITNESS_WIRE, 'sha256': hashlib.sha256(archive).hexdigest(),
                'size': len(archive), 'files': sorted(entries)}
    return wb.install_bundle(archive, manifest, str(path))


def _base(host, tmp_path, release='1.1.0'):
    """The witness `host` runs from an installed tree of `release`, older than the leader."""
    base = _tree(tmp_path / 'opt', release)
    wb.switch(str(tmp_path / 'opt'), os.path.basename(base))
    host.code_dir = base
    host.w.code_dir, host.w.auto_update, host.w.install = base, True, 'systemd'
    return base


def _run_tree(tree, state, *argv, probe=False):
    env = dict(os.environ, PEGAPROX_WITNESS_CODE_DIR=tree, PEGAPROX_WITNESS_DIR=state)
    code = PROBE if probe else wb.RUNNER
    return subprocess.run([sys.executable, '-I', '-c', code] + list(argv), env=env,
                          capture_output=True, text=True, timeout=120)


def _post_installer(auto, on, body):
    import pegaprox.api.ha as ha_api
    ha_api._bundle_attempts.reset()
    raw = json.dumps(body).encode()
    return auto.g._serve(on, 'POST', BUNDLE, raw, {'X-Requested-With': 'XMLHttpRequest',
                                                   'Content-Type': 'application/json'})


def _secret(code):
    return ha_wire.decode_code(ha_wire.WITNESS_CODE_PREFIX, code)['secret']


def _public(auto, n):
    with auto.at(n) as ha:
        return ha.own_public_key()


# --- what goes into the bundle -------------------------------------------------------------

def _imports(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
        tree = ast.parse(fh.read())
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            out.add(node.module)
            out.update(f'{node.module}.{a.name}' for a in node.names)
    return out


def _module_file(name):
    parts = name.split('.')
    for rel in ('/'.join(parts) + '.py', '/'.join(parts) + '/__init__.py'):
        if os.path.isfile(os.path.join(ROOT, rel)):
            return rel
    return None


def test_the_bundle_is_what_the_witness_imports_and_its_unit():
    """Followed from witness.py and witness_boot.py, every pegaprox module the witness can
    import is in the bundle, with the packages around them; outside the standard library
    it needs cryptography, gevent and requests, the three the installer installs."""
    from pegaprox.core import ha
    files = set(ha.WITNESS_BUNDLE_FILES)
    todo, seen, third = ['pegaprox/witness.py', 'pegaprox/witness_boot.py'], set(), set()
    while todo:
        rel = todo.pop()
        if rel in seen:
            continue
        seen.add(rel)
        for name in _imports(rel):
            top = name.split('.')[0]
            if top == 'pegaprox':
                found = _module_file(name)
                if found:
                    todo.append(found)
                    parts = found.split('/')[:-1]
                    for i in range(1, len(parts) + 1):
                        todo.append('/'.join(parts[:i]) + '/__init__.py')
            elif top not in sys.stdlib_module_names:
                third.add(top)
    assert seen <= files, sorted(seen - files)
    assert files - seen == {'systemd/pegaprox-witness.service'}
    assert third == {'cryptography', 'gevent', 'requests'}
    with open(os.path.join(ROOT, 'packaging', 'witness', 'install.sh'), encoding='utf-8') as fh:
        assert 'MODULES="cryptography gevent requests"' in fh.read()


def test_the_bundle_is_the_same_on_every_member_and_signed_by_the_one_that_serves(auto, host, seed):
    from pegaprox.core import ha
    auto.pair(seed, 'b')
    _pair(auto, host)
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    out = {}
    for n in 'ab':
        with auto.at(n) as h:
            out[n] = h.witness_bundle()
    ma, mb = out['a']['manifest'], out['b']['manifest']
    assert ma['sha256'] == mb['sha256'] and ma['by'] == IDS['a'] and mb['by'] == IDS['b']
    for n in 'ab':
        m = out[n]['manifest']
        assert ha_wire.cfg_signed(_public(auto, n), ha_wire.bundle_message(m), out[n]['sig'])
        assert m['release'] == _release() and m['wire'] == ha_wire.WITNESS_WIRE
        assert m['name'] == f"{_release()}-{m['sha256'][:12]}"
    archive = base64.b64decode(out['a']['archive'])
    assert hashlib.sha256(archive).hexdigest() == ma['sha256'] and len(archive) == ma['size']
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        members = {m.name: tar.extractfile(m).read() for m in tar.getmembers()}
    assert sorted(members) == ma['files'] == sorted(set(ha.WITNESS_BUNDLE_FILES) | {'version.json'})
    for rel in ha.WITNESS_BUNDLE_FILES:
        with open(os.path.join(ROOT, rel), 'rb') as fh:
            assert members[rel] == fh.read(), rel
    assert json.loads(members['version.json']) == {'version': _release(), 'wire': ha_wire.WITNESS_WIRE}


# --- who may fetch it ------------------------------------------------------------------------

def test_the_installer_fetches_it_with_the_open_code_and_the_code_stays_good(auto, host, seed):
    auto.pair(seed, 'b')
    code = _code(auto).get_json()['code']
    r = _post_installer(auto, 'a', {'code': _secret(code)})
    assert r.status_code == 200, r.content[:200]
    data = r.json()
    assert ha_wire.cfg_signed(_public(auto, 'a'), ha_wire.bundle_message(data['manifest']), data['sig'])
    assert 'witness_pairing' in auto.file('a')
    # looked at, not spent: the witness pairs with it afterwards
    assert host.w.join(code, WURL) == IDS['a']
    assert _post_installer(auto, 'a', {'code': _secret(code)}).status_code == 403


@pytest.mark.parametrize('case', ['wrong', 'none', 'expired', 'standby', 'query', 'member', 'forged',
                                  'skewed', 'flood'])
def test_nobody_else_gets_it(auto, host, seed, case):
    import pegaprox.api.ha as ha_api
    auto.pair(seed, 'b')
    code = _pair(auto, host) if case in ('member', 'forged', 'skewed') else _code(auto).get_json()['code']
    wid = host.w.instance_id()
    raw = ha_wire.wire_body({'release': '1.0', 'wire': 2})
    on, expected = 'a', 403
    if case in ('wrong', 'none', 'expired', 'standby', 'flood'):
        body = {'code': 'x' * 43} if case == 'wrong' else {} if case == 'none' else {'code': _secret(code)}
        if case == 'expired':
            with auto.at('a') as ha:
                st = ha._load()
                ha._update(witness_pairing=dict(st['witness_pairing'], expires=int(time.time()) - 1))
        if case == 'standby':
            on = 'b'
        if case == 'flood':
            ha_api._bundle_attempts.reset()
            for _ in range(10):
                auto.g._serve('a', 'POST', BUNDLE, b'{"code": "nope"}',
                              {'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json'})
            r = auto.g._serve('a', 'POST', BUNDLE, json.dumps(body).encode(),
                              {'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json'})
            assert r.status_code == 429
            return
        r = _post_installer(auto, on, body)
    elif case == 'query':
        r = auto.g._serve('a', 'POST', BUNDLE + '?file=pegaprox/core/db.py', b'{}',
                          {'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json'})
        expected = 400
    else:
        expected = 401
        if case == 'member':
            # a member is no witness: its own key under its own id
            with auto.at('b') as ha:
                h = ha._signed_headers(ha._signer().private, IDS['b'], IDS['a'], 'POST', BUNDLE, raw)
        elif case == 'forged':
            h = ha_wire.signed_headers(ha_wire.private_key(ha_wire.new_signing_key()), wid, IDS['a'], 'POST',
                                       BUNDLE, raw, time.time())
        else:
            h = ha_wire.signed_headers(ha_wire.private_key(host.file()['signing_key']), wid, IDS['a'], 'POST',
                                       BUNDLE, raw, time.time() - 600)
        h.update({'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json'})
        ha_api._peer_failures.reset()
        r = auto.g._serve('a', 'POST', BUNDLE, raw, h)
    assert r.status_code == expected, (case, r.content[:200])
    if case == 'skewed':
        assert r.json()['code'] == 'HA_CLOCK'
    assert 'archive' not in r.json()


def test_the_paired_witness_fetches_it_from_any_member_and_nothing_else_comes_with_it(auto, host, seed,
                                                                                      monkeypatch):
    auto.pair(seed, 'b')
    code = _code(auto).get_json()['code']
    # whatever the body asks for, the bundle is the one list of files
    r = _post_installer(auto, 'a', {'code': _secret(code), 'files': ['pegaprox/core/db.py'],
                                    'path': '../../config/pegaprox.db', 'name': '../x'})
    assert r.status_code == 200
    listed = r.json()['manifest']['files']
    assert 'pegaprox/core/db.py' not in listed and not any('..' in f or f.startswith('/') for f in listed)
    with auto.at('a'):
        assert auto.admin.get(BUNDLE).status_code == 405
        assert auto.admin.post(BUNDLE + '/pegaprox/core/db.py', json={}).status_code == 404
    host.w.join(code, WURL)
    host.w.start()
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    monkeypatch.setattr(wm, 'RELEASE', '1.0.0')
    for n in 'ab':
        data = host.w.fetch_bundle({'instance_id': IDS[n], 'url': URLS[n], 'fingerprint': ''})
        manifest, archive = host.w.verify_bundle(data)
        assert manifest['by'] == IDS[n] and manifest['files'] == listed
        assert hashlib.sha256(archive).hexdigest() == manifest['sha256']


def test_the_witness_takes_only_a_bundle_a_data_voter_signed_over_what_it_holds(auto, host, seed,
                                                                               monkeypatch):
    from pegaprox.core import ha
    auto.pair(seed, 'b')
    _pair(auto, host)
    monkeypatch.setattr(wm, 'RELEASE', '1.0.0')
    with auto.at('a') as h:
        good = h.witness_bundle()
        key = h._signer().private

    def signed(manifest, archive, by_key=key):
        return {'manifest': manifest, 'archive': base64.b64encode(archive).decode(),
                'sig': base64.b64encode(by_key.sign(ha_wire.bundle_message(manifest))).decode()}

    def bundle(entries, **manifest):
        archive = ha.pack_bundle(entries)
        m = dict(good['manifest'], sha256=hashlib.sha256(archive).hexdigest(), size=len(archive),
                 files=sorted(entries))
        m.update(manifest)
        return m, archive

    assert host.w.verify_bundle(good)[0] == good['manifest']
    m, archive = dict(good['manifest']), base64.b64decode(good['archive'])
    cases = {
        'another key': signed(m, archive, ha_wire.private_key(ha_wire.new_signing_key())),
        'the witness itself': signed(dict(m, by=host.w.instance_id()), archive,
                                     ha_wire.private_key(host.file()['signing_key'])),
        'a changed archive': dict(good, archive=base64.b64encode(archive[:-1] + b'x').decode()),
        'another digest': signed(dict(m, sha256='0' * 64), archive),
        'a file it does not list': signed(*bundle(dict(_entries(), **{'pegaprox/core/db.py': b'x'}),
                                                  files=sorted(_entries()))),
        'a path out of the tree': signed(*bundle(dict(_entries(), **{'../evil.py': b'x'}))),
        'the database': signed(*bundle(dict(_entries(), **{'config/pegaprox.db': b'x'}))),
        'no boot': signed(*bundle({k: v for k, v in _entries().items() if k != 'pegaprox/witness_boot.py'})),
        'a bad release': signed(dict(m, release='../1.2'), archive),
    }
    for what, data in cases.items():
        with pytest.raises((wm.WitnessError, wb.BootError)):
            host.w.verify_bundle(data)
            pytest.fail(what)
    # a link in the archive is refused too
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for name, data in _entries().items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo('pegaprox/utils/evil.py')
        link.type, link.linkname = tarfile.SYMTYPE, '/etc/shadow'
        tar.addfile(link)
    raw = buf.getvalue()
    names = sorted(list(_entries()) + ['pegaprox/utils/evil.py'])
    with pytest.raises(wb.BootError, match='holds what it may not'):
        host.w.verify_bundle(signed(dict(m, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw),
                                         files=names), raw))
    # and code that is not newer than what runs is no update
    monkeypatch.setattr(wm, 'RELEASE', _release())
    with pytest.raises(wm.UpToDate):
        host.w.verify_bundle(good)


# --- "Add witness" ---------------------------------------------------------------------------

def test_add_witness_answers_with_one_command_per_way(auto, host, seed, monkeypatch):
    import pegaprox.api.ha as ha_api
    # an instance that follows Testing: the image of this release has no witness yet
    # (tests/test_ha_witness_field.py has the release side)
    monkeypatch.setattr(ha_api, 'update_branch', lambda: 'Testing')
    auto.pair(seed, 'b')
    r = _code(auto)
    assert r.status_code == 200
    code, inst = r.get_json()['code'], r.get_json()['install']
    with open(os.path.join(ROOT, 'packaging', 'witness', 'install.sh'), 'rb') as fh:
        sha = hashlib.sha256(fh.read()).hexdigest()
    assert inst['installer_sha256'] == sha and inst['version'] == _release()
    image = 'ghcr.io/pegaprox/pegaprox-testing:latest'
    assert inst['image'] == image and inst['branch'] == 'Testing' and inst['docker_note'] is None
    gh = 'https://raw.githubusercontent.com/PegaProx/project-pegaprox/main/packaging/witness/install.sh'
    mirror = 'https://updates.pegaprox.com/packaging/witness/install.sh'
    here = f"{URLS['a']}/api/ha/witness/installer"
    linux = inst['linux']
    assert linux.index(gh) < linux.index(mirror) < linux.index(here)
    # the code goes to the installer on stdin, by the shell's own printf: never in an argument
    run = f"printf '%s\\n' '{code}' | $([ \"$(id -u)\" -eq 0 ] || echo sudo) sh install.sh --code -"
    checked = f"{{ echo '{sha}  install.sh' | sha256sum -c || {{ echo 'pegaprox-witness: no install.sh"
    # the installer last: --url or --port go at the end of the line
    assert checked in linux and linux.endswith(f">&2; false; }}; }} && {run}")
    assert linux.count(code) == 1 and linux.count(f"'{sha}  install.sh'") == 2
    # no plain pipe of a download into a shell, and -k only for the leader's copy, checked after
    assert '| sh ' not in linux.replace(run, '') and '| bash' not in linux
    # GitHub and the mirror through a proxy of the environment and in bounded time, the leader
    # straight (a proxy may not reach it)
    assert linux.count("curl -fsSLko install.sh --noproxy '*' ") == 1
    assert linux.count('curl -fsSL --connect-timeout 10 --max-time 120 -o install.sh "$u"') == 1
    assert linux.count('--noproxy') == 1
    hint = ("echo 'pegaprox-witness: no install.sh that matches this line - it works while the leader runs the "
            "release that made it. Where the witness is installed: sudo sh /opt/pegaprox-witness/install.sh - else "
            "make a new code with Add witness on the leader' >&2")
    # nothing downloaded: the line names the way to the leader (a 403 is its allow list),
    # not a release that does not match
    got = (f"{{ [ -f install.sh ] || {{ echo 'pegaprox-witness: could not download install.sh from {here} "
           "(curl says why above; a 403 there is the IP allow list of the leader - add this host in "
           "Settings > Security)' >&2; false; }; }")
    assert inst['offline'] == (f"cd \"$(mktemp -d)\" && curl -fsSLko install.sh --noproxy '*' '{here}'; {got} && "
                               f"{{ echo '{sha}  install.sh' | sha256sum -c || {{ {hint}; false; }}; }} && {run}")
    assert f'{got} && ' in linux
    assert inst['docker'] == (f"docker run -d --name pegaprox-witness --restart unless-stopped -p 5005:5005 "
                              f"-v pegaprox-witness:/app/witness {image} "
                              f"witness run --join '{code}' --url 'https://<witness-host>:5005'")
    assert inst['manual'] == (f"python3 pegaprox_multi_cluster.py witness run --join '{code}' "
                              f"--url 'https://<witness-host>:5005'")
    for way in ('linux', 'offline', 'docker', 'manual'):
        assert (inst['placeholder'] in inst[way]) == (way in inst['placeholder_in']), way
    assert inst['placeholder'] in inst['note'] and '5005' in inst['firewall']
    # the older field still names commands that exist
    assert r.get_json()['commands']['docker'] == inst['docker']
    # an instance that ships no installer still offers Docker and the checkout
    assert ha_api.witness_installer() is not None


def test_the_installer_route_serves_exactly_that_file_or_nothing(auto, host, seed, monkeypatch, tmp_path):
    from pegaprox.core import ha
    import pegaprox.api.ha as ha_api
    auto.pair(seed, 'b')
    with open(os.path.join(ROOT, 'packaging', 'witness', 'install.sh'), 'rb') as fh:
        mine = fh.read()
    for n in 'ab':
        r = auto.g._serve(n, 'GET', INSTALLER, b'', {})
        assert r.status_code == 200 and r.content == mine
        assert r.headers['X-Checksum-Sha256'] == hashlib.sha256(mine).hexdigest()
        assert r.headers['Content-Type'].startswith('text/x-shellscript')
    assert auto.g._serve('a', 'GET', INSTALLER + '/../../pegaprox/core/db.py', b'', {}).status_code == 404
    monkeypatch.setattr(ha, 'code_root', lambda: str(tmp_path))
    assert auto.g._serve('a', 'GET', INSTALLER, b'', {}).status_code == 404
    inst = ha_api.witness_install_commands(URLS['a'], 'pgxwt1_x', branch='Testing')
    assert inst['linux'] is None and inst['offline'] is None and inst['docker'] and inst['manual']


# the Linux line itself, run by sh with a curl that serves from a table and a sudo that
# runs what it is given: which file runs, and that nothing runs that does not match

_CURL = r'''#!PYTHON
import json, os, sys
args = sys.argv[1:]
url = args[-1]
out = None
for i, a in enumerate(args):
    if a.startswith('-') and not a.startswith('--') and a.endswith('o'):
        out = args[i + 1]
with open(os.environ['FAKE_LOG'], 'a') as fh:
    fh.write(json.dumps(args) + '\n')
what = json.loads(os.environ['FAKE_NET']).get(url, 'fail')
if what == 'fail':
    sys.exit(7)
with open(out, 'wb') as fh:
    fh.write(os.environ['FAKE_' + what.upper()].encode())
    if what == 'partial':
        sys.exit(18)
'''
_SUDO = '#!/bin/sh\necho "sudo $*" >> "$FAKE_LOG"\nexec "$@"\n'


@pytest.mark.parametrize('net, runs, sources', [
    ({'gh': 'stub'}, True, ['gh']),
    ({'gh': 'fail', 'mirror': 'stub'}, True, ['gh', 'mirror']),
    ({'gh': 'partial', 'mirror': 'stub'}, True, ['gh', 'mirror']),
    ({'gh': 'other', 'mirror': 'other', 'here': 'stub'}, True, ['gh', 'mirror', 'here']),
    ({'gh': 'fail', 'mirror': 'fail', 'here': 'stub'}, True, ['gh', 'mirror', 'here']),
    ({'gh': 'other', 'mirror': 'fail', 'here': 'other'}, False, ['gh', 'mirror', 'here']),
])
def test_the_linux_line_runs_the_installer_only_when_it_matches(tmp_path, monkeypatch, net, runs, sources):
    import pegaprox.api.ha as ha_api
    stub = '#!/bin/sh\nread -r code\necho "installer ran with $* and $code"\n'
    monkeypatch.setattr(ha_api, 'witness_installer', lambda: (stub.encode(), hashlib.sha256(stub.encode()).hexdigest()))
    inst = ha_api.witness_install_commands('https://leader.example:5000', 'pgxwt1_abc-_9')
    urls = {'gh': ha_api.INSTALLER_SOURCES[0], 'mirror': ha_api.INSTALLER_SOURCES[1],
            'here': 'https://leader.example:5000/api/ha/witness/installer'}
    fake = tmp_path / 'bin'
    fake.mkdir()
    (fake / 'curl').write_text(_CURL.replace('PYTHON', sys.executable))
    (fake / 'sudo').write_text(_SUDO)
    for f in fake.iterdir():
        f.chmod(0o755)
    log = tmp_path / 'log'
    env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}", FAKE_LOG=str(log), TMPDIR=str(tmp_path),
               FAKE_NET=json.dumps({urls[k]: v for k, v in net.items()}), FAKE_STUB=stub,
               FAKE_OTHER='#!/bin/sh\necho "SOMETHING ELSE RAN"\n', FAKE_PARTIAL=stub[:9])
    out = subprocess.run(['sh', '-c', inst['linux']], env=env, capture_output=True, text=True, timeout=60)
    calls = [json.loads(line) for line in log.read_text().splitlines() if line.startswith('[')]
    assert [next(k for k, u in urls.items() if c[-1] == u) for c in calls] == sources
    # -k only towards the leader, never towards GitHub or the mirror
    assert all(('k' in c[0]) == (c[-1] == urls['here']) for c in calls)
    assert 'SOMETHING ELSE RAN' not in out.stdout
    if runs:
        assert out.returncode == 0, out.stderr
        assert "installer ran with --code - and pgxwt1_abc-_9" in out.stdout
    else:
        assert out.returncode != 0 and 'installer ran' not in out.stdout


# --- the leader keeps its witness current -------------------------------------------------------

def test_an_older_witness_is_told_updates_itself_and_starts_into_the_new_code(auto, host, seed, tmp_path,
                                                                            monkeypatch):
    _form(auto, host, seed)
    auto.run(10)
    base = _base(host, tmp_path)
    monkeypatch.setattr(wm, 'RELEASE', '1.1.0')
    wid = _wid(host)
    with auto.at('a') as ha:
        ha._ask_witness()
        seen = ha._rt().seen[wid]
        assert (seen['release'], seen['wire'], seen['auto_update'], seen['install']) == \
            ('1.1.0', ha_wire.WITNESS_WIRE, True, 'systemd')
        f = next(f for f in ha.auto_findings() if f['code'] == 'WITNESS_OUTDATED')
        assert f['level'] == 'warn' and 'updates itself' in f['text'] and f['member'] == wid
        assert ha.witness_view()['outdated'] is True
        said = ha._witness_update_check()
        assert said == {'update': True, 'status': 200, 'answer': {'accepted': True}}
        # said once, not with every look at the group
        assert ha._witness_update_check() is None
    assert len(_audit('ha.witness_update')) == 1
    stopped = []
    host.w.upkeep(lambda: stopped.append(True), lambda: True)
    assert stopped == [True] and host.w.exit_code == wm.EXIT_UPDATED
    root = os.path.join(host.dir, wb.UPDATES)
    name = os.readlink(os.path.join(root, 'current'))
    assert name.startswith(f'{_release()}-') and wb.NAME_RE.fullmatch(name)
    assert host.w.update_state['last']['state'] == 'installed'
    # the fetch was the witness's own signed call to the leader
    with open(os.path.join(host.dir, wm.UPDATE_NAME), encoding='utf-8') as fh:
        assert json.load(fh)['leader']['instance_id'] == IDS['a']
    # the start after the exit: witness_boot runs the newer tree, on trial
    path, trial = wb.choose(base, host.dir)
    assert path == os.path.realpath(os.path.join(root, name)) and trial
    out = _run_tree(path, host.dir, probe=True)
    assert out.returncode == 0, out.stderr
    said = json.loads(out.stdout)
    assert said['file'] == os.path.join(path, 'pegaprox', 'witness.py') and said['release'] == _release()
    out = _run_tree(path, host.dir, '--dir', host.dir, 'status')
    assert out.returncode == 0, out.stderr
    status = json.loads(out.stdout)
    assert status['paired'] is True and status['release'] == _release() and status['instance_id'] == wid
    # once it answers on its port it is healthy: no trial at the next start
    assert wb.mark_ok(host.dir, path)
    assert wb.choose(base, host.dir) == (path, False)
    # the new process runs the leader's release: nothing to say any more
    monkeypatch.setattr(wm, 'RELEASE', _release())
    host.code_dir = path
    host.restart()
    with auto.at('a') as ha:
        ha._ask_witness()
        assert not [f for f in ha.auto_findings() if f['code'] == 'WITNESS_OUTDATED']
        assert ha._witness_update_check() is None and ha.witness_view()['outdated'] is False
    auto.run(10)
    assert auto.leader() == 'a' and host.node.promise_to == IDS['a']


def test_no_update_while_a_data_voter_is_missing_and_none_with_the_updates_off(auto, host, seed, tmp_path,
                                                                              monkeypatch):
    _form(auto, host, seed)
    auto.run(10)
    _base(host, tmp_path)
    monkeypatch.setattr(wm, 'RELEASE', '1.1.0')
    auto.crash('b')
    auto.run(T.R * 4, members='a')
    with auto.at('a') as ha:
        ha._ask_witness()
        assert auto.leader() == 'a'
        said = ha._witness_update_check()
    # without b the witness's vote is the majority: told, and told not now
    assert said['update'] is False and said['answer'] == {'accepted': False, 'reason': 'NOT_NOW'}
    assert host.w.job is None and host.w.outdated()['release'] == _release()
    auto.back('b')
    auto.run(10)
    # the updates off: told all the same, for its own status, and nothing is fetched
    host.w.auto_update = False
    with auto.at('a') as ha:
        ha._ask_witness()
        ha._rt().witness_told = None
        said = ha._witness_update_check()
        f = next(f for f in ha.auto_findings() if f['code'] == 'WITNESS_OUTDATED')
    assert said['update'] is False and said['answer']['reason'] == 'AUTO_UPDATE_OFF'
    assert f['command'] == 'sudo pegaprox-witness update' and 'Automatic updates are off' in f['text']
    assert host.w.job is None
    st = host.w.outdated()
    assert st == {'code': 'WITNESS_OUTDATED', 'release': _release(), 'wire': ha_wire.WITNESS_WIRE,
                  'command': 'sudo pegaprox-witness update'}


def test_by_hand_the_update_comes_from_the_member_that_said_it(auto, host, seed, tmp_path, monkeypatch, capsys):
    _form(auto, host, seed)
    auto.run(10)
    base = _base(host, tmp_path)
    monkeypatch.setattr(wm, 'RELEASE', '1.1.0')
    host.w.auto_update = False
    with auto.at('a') as ha:
        ha._ask_witness()
        ha._witness_update_check()
    monkeypatch.setattr(wm, 'https_call', host._to_member)
    monkeypatch.setenv('PEGAPROX_WITNESS_CODE_DIR', base)
    monkeypatch.setenv('PEGAPROX_WITNESS_INSTALL', 'systemd')
    assert wm.main(['--dir', host.dir, 'update']) == 0
    assert 'is in place' in capsys.readouterr().out
    tree = os.path.join(host.dir, wb.UPDATES, 'current')
    assert os.readlink(tree).startswith(_release())
    # and the code that runs now is that update's
    monkeypatch.setattr(wm, 'RELEASE', _release())
    monkeypatch.setenv('PEGAPROX_WITNESS_CODE_DIR', os.path.realpath(tree))
    assert wm.main(['--dir', host.dir, 'update']) == 0
    assert 'already' in capsys.readouterr().out


def test_an_update_that_does_not_come_up_goes_back_to_the_code_before_it(auto, host, seed, tmp_path,
                                                                       monkeypatch):
    from pegaprox.core import ha as core
    _form(auto, host, seed)
    auto.run(10)
    base = _base(host, tmp_path)
    # a first update that came up
    monkeypatch.setattr(wm, 'RELEASE', '1.1.0')
    with auto.at('a') as ha:
        ha._ask_witness()
        ha._witness_update_check()
    host.w.upkeep(lambda: None, lambda: True)
    root = os.path.join(host.dir, wb.UPDATES)
    good = os.path.realpath(os.path.join(root, 'current'))
    wb.mark_ok(host.dir, good)
    monkeypatch.setattr(wm, 'RELEASE', _release())
    host.code_dir = good
    host.restart()
    # then the leader moves on to code that cannot even be imported
    entries = _entries('9.0.0', {'pegaprox/witness.py': b'raise SystemExit("this release is broken")\n'})
    archive = core.pack_bundle(entries)
    monkeypatch.setattr(core, 'PEGAPROX_VERSION', '9.0.0')
    monkeypatch.setattr(core, '_bundle_archive',
                        lambda: (archive, sorted(entries), hashlib.sha256(archive).hexdigest()))
    with auto.at('a') as ha:
        ha._ask_witness()
        assert ha._witness_update_check()['answer'] == {'accepted': True}
    host.w.exit_code = 0
    host.w.upkeep(lambda: None, lambda: True)
    assert host.w.exit_code == wm.EXIT_UPDATED
    broken = os.path.realpath(os.path.join(root, 'current'))
    assert broken != good and os.path.realpath(os.path.join(root, 'previous')) == good
    # the starts after it: TRIES of them fail, the one after goes back
    for attempt in range(wb.TRIES):
        path, trial = wb.choose(base, host.dir)
        assert (path, trial) == (broken, True), attempt
        out = _run_tree(path, host.dir, '--dir', host.dir, 'run')
        assert out.returncode != 0 and 'this release is broken' in out.stderr
    said = []
    path, trial = wb.choose(base, host.dir, say=said.append)
    assert (path, trial) == (good, False) and 'did not come up healthy' in said[0]
    assert os.path.realpath(os.path.join(root, 'current')) == good
    assert broken in wb.load_health(root)['bad']
    out = _run_tree(path, host.dir, '--dir', host.dir, 'status')
    assert out.returncode == 0 and json.loads(out.stdout)['release'] == _release()
    # and the leader hears that the update did not take: the witness says so in its status
    host.w.update_state['last'] = dict(json.load(open(os.path.join(host.dir, wb.UPDATE_NAME)))['last'],
                                       state='failed', release='9.0.0', error='did not come up')
    assert host.w.update_state['last']['back'] is True
    with auto.at('a') as ha:
        ha._ask_witness()
        f = next(f for f in ha.auto_findings() if f['code'] == 'WITNESS_OUTDATED')
    assert 'last update failed' in f['text'] and 'update it by hand once that is fixed' in f['text']


def test_code_on_trial_that_does_not_answer_gives_up_and_healthy_code_is_marked(tmp_path):
    state = wm.check_dir(str(tmp_path / 'state'))
    tree = _tree(tmp_path / 'opt', '1.0.0')
    now = [100.0]
    w = wm.Witness(state, clock=lambda: now[0], code_dir=tree, auto_update=True)
    w.trial = True
    stopped = []

    def sleep(_s):
        now[0] += 10
    w.upkeep(lambda: stopped.append(True), lambda: False, sleep=sleep)
    assert stopped == [True] and w.exit_code == 1 and now[0] - 100 > wm.HEALTH_BOUND
    w = wm.Witness(state, clock=lambda: now[0], code_dir=tree, auto_update=True)
    w.trial = True
    calls = []

    def stop_after_soak(_s):
        # healthy only once it ran SOAK answering: not at its first answer
        if now[0] - 200 < wm.SOAK:
            assert os.path.realpath(tree) not in wb.load_health(os.path.join(state, wb.UPDATES))['ok']
        calls.append(1)
        now[0] += 10
        if now[0] - 200 > wm.SOAK + 30:
            raise KeyboardInterrupt
    now[0] = 200.0
    with pytest.raises(KeyboardInterrupt):
        w.upkeep(lambda: None, lambda: True, sleep=stop_after_soak)
    assert len(calls) > wm.SOAK // 10
    assert os.path.realpath(tree) in wb.load_health(os.path.join(state, wb.UPDATES))['ok']


# --- what starts the witness ---------------------------------------------------------------------

def _fake_tree(path, release, marker=None):
    os.makedirs(os.path.join(path, 'pegaprox', 'core'), exist_ok=True)
    with open(os.path.join(path, 'version.json'), 'w') as fh:
        json.dump({'version': release}, fh)
    with open(os.path.join(path, 'pegaprox', '__init__.py'), 'w') as fh:
        fh.write('')
    with open(os.path.join(path, 'pegaprox', 'core', 'ha_wire.py'), 'w') as fh:
        fh.write('WITNESS_WIRE = 2\n')
    with open(os.path.join(path, 'pegaprox', 'witness.py'), 'w') as fh:
        fh.write(f'def main(argv):\n    print({marker!r}, argv)\n    return 0\n')
    return str(path)


def test_the_newer_of_the_image_and_the_volume_runs_and_a_newer_image_wins(tmp_path):
    state = str(tmp_path / 'state')
    root = os.path.join(state, wb.UPDATES)
    image = _fake_tree(tmp_path / 'image', '1.2.0')
    vol = _fake_tree(os.path.join(root, '1.3.0-aaaaaaaaaaaa'), '1.3.0')
    wb.switch(root, '1.3.0-aaaaaaaaaaaa')
    # code that came up here (a command runs nothing else, see test_ha_witness_field.py)
    wb.mark_ok(state, vol)
    assert wb.choose(image, state, counting=False) == (os.path.realpath(vol), False)
    # a newer image (docker pull, a new container on the same volume)
    image2 = _fake_tree(tmp_path / 'image2', '1.4.0')
    assert wb.choose(image2, state, counting=False) == (os.path.realpath(image2), False)
    # the same release: the image, which nobody changed
    image3 = _fake_tree(tmp_path / 'image3', '1.3.0')
    assert wb.choose(image3, state, counting=False)[0] == os.path.realpath(image3)
    # the same release on a newer wire is newer code
    with open(os.path.join(vol, 'pegaprox', 'core', 'ha_wire.py'), 'w') as fh:
        fh.write('WITNESS_WIRE = 3\n')
    assert wb.choose(image3, state, counting=False)[0] == os.path.realpath(vol)
    # code that failed here is not taken again, the image is
    health = wb.load_health(root)
    health['bad'].append(os.path.realpath(vol))
    wb.save_health(root, health)
    assert wb.choose(image, state, counting=False)[0] == os.path.realpath(image)


def test_the_image_runs_the_witness_through_the_volume_code(tmp_path):
    state = tmp_path / 'state'
    root = state / wb.UPDATES
    vol = _fake_tree(root / '99.0.0-aaaaaaaaaaaa', '99.0.0', marker='volume code')
    wb.switch(str(root), '99.0.0-aaaaaaaaaaaa')
    wb.mark_ok(str(state), vol)
    cwd = tmp_path / 'cwd'
    cwd.mkdir()
    env = dict(os.environ, PEGAPROX_WITNESS_DIR=str(state))
    run = [sys.executable, os.path.join(ROOT, 'pegaprox_multi_cluster.py'), 'witness', 'status']
    out = subprocess.run(run, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert "volume code ['status']" in out.stdout
    # older code in the volume than in the image: the image's own witness runs
    _fake_tree(root / '0.0.1-bbbbbbbbbbbb', '0.0.1', marker='old volume code')
    wb.switch(str(root), '0.0.1-bbbbbbbbbbbb')
    out = subprocess.run(run, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert 'volume code' not in out.stdout
    assert json.loads(out.stdout[out.stdout.index('{'):])['release'] == _release()


def test_a_start_of_run_counts_against_the_trial_and_nothing_else_does(tmp_path):
    state = str(tmp_path / 'state')
    root = os.path.join(state, wb.UPDATES)
    base = _fake_tree(tmp_path / 'base', '1.0.0')
    old = _fake_tree(os.path.join(root, '1.1.0-aaaaaaaaaaaa'), '1.1.0')
    new = _fake_tree(os.path.join(root, '1.2.0-bbbbbbbbbbbb'), '1.2.0')
    wb.switch(root, '1.1.0-aaaaaaaaaaaa')
    wb.mark_ok(state, old)
    wb.switch(root, '1.2.0-bbbbbbbbbbbb')
    new, old = os.path.realpath(new), os.path.realpath(old)
    assert wb.command_of(['--dir', '/x', '--port', '5', 'status']) == ('/x', 'status')
    assert wb.command_of(['--allow=10.0.0.0/8']) == (None, 'run')
    assert wb.command_of(['--help']) == (None, 'help')
    # a command runs the code that ran before it, and counts nothing
    for _ in range(5):
        assert wb.choose(base, state, counting=False) == (old, False)
    assert wb.load_health(root)['trial'] == {}
    assert wb.choose(base, state) == (new, True)
    assert wb.choose(base, state) == (new, True)
    # the third start of run goes back to previous, which came up before
    assert wb.choose(base, state) == (old, False)
    assert os.readlink(os.path.join(root, 'current')) == '1.1.0-aaaaaaaaaaaa'
    assert not os.path.lexists(os.path.join(root, 'previous'))
    # a single tree is never on trial: there is nothing to go back to
    lone = str(tmp_path / 'lone')
    assert wb.choose(base, lone) == (os.path.realpath(base), False)
    with pytest.raises(wb.BootError):
        wb.choose(str(tmp_path / 'nothing'), lone)
    # and the boot main says so and exits for the admin to look
    assert wb.main(['--dir', lone, 'status'], base=str(tmp_path / 'nothing'),
                   start=lambda *a: 0) == wb.EXIT_CONFIG


def test_prune_keeps_current_previous_and_a_few_more(tmp_path):
    root = str(tmp_path / 'code')
    for i in range(6):
        _fake_tree(os.path.join(root, f'1.{i}.0-{i:012d}'), f'1.{i}.0')
        os.utime(os.path.join(root, f'1.{i}.0-{i:012d}'), (1000 + i, 1000 + i))
    wb.switch(root, '1.0.0-000000000000')
    wb.switch(root, '1.1.0-000000000001')
    os.makedirs(os.path.join(root, '1.9.0-999999999999.tmp-1'))
    os.utime(os.path.join(root, '1.9.0-999999999999.tmp-1'), (0, 0))
    wb.prune(root)
    left = sorted(n for n in os.listdir(root) if wb.NAME_RE.fullmatch(n))
    assert left == ['1.0.0-000000000000', '1.1.0-000000000001', '1.4.0-000000000004', '1.5.0-000000000005']


def test_run_join_pairs_on_the_first_start_only(auto, host, seed, monkeypatch, capsys):
    auto.pair(seed, 'b')
    code = _code(auto).get_json()['code']
    monkeypatch.setattr(wm, 'https_call', host._to_member)
    wm._join_once(host.dir, code, WURL)
    assert 'Paired with' in capsys.readouterr().out
    assert auto.file('a')['witness']['url'] == WURL
    # the second start, the code long spent: it just runs
    wm._join_once(host.dir, code, WURL)
    assert 'Paired already' in capsys.readouterr().out
    other = wm.check_dir(os.path.join(os.path.dirname(host.dir), 'other'))
    with pytest.raises(wm.WitnessError, match='--join needs --url'):
        wm._join_once(other, code, None)


# --- every way the leader runs ships what a witness host fetches from it ----------------------------

def test_every_install_of_the_leader_ships_the_installer_and_the_unit():
    def read(*rel):
        with open(os.path.join(ROOT, *rel), encoding='utf-8') as fh:
            return fh.read()
    deb = [line.split() for line in read('debian', 'install').splitlines() if line.strip()]
    assert ['packaging/witness/install.sh', 'usr/lib/pegaprox/packaging/witness'] in deb
    assert ['systemd/pegaprox-witness.service', 'usr/lib/pegaprox/systemd'] in deb
    docker = read('Dockerfile')
    assert 'COPY --chown=pegaprox:pegaprox packaging/witness/install.sh packaging/witness/install.sh' in docker
    assert 'COPY --chown=pegaprox:pegaprox systemd/pegaprox-witness.service systemd/pegaprox-witness.service' \
        in docker
    # the RPM copies the whole tree
    assert 'cp -a * %{buildroot}%{_libexecdir}/pegaprox/' in read('packaging', 'rpm', 'pegaprox.spec')
    manifest = json.loads(read('version.json'))['update_files']
    for rel in ('packaging/witness/install.sh', 'systemd/pegaprox-witness.service', 'pegaprox/witness_boot.py',
                'docs/ha-witness.md'):
        assert rel in manifest, rel
    # the command the unit starts is the one the installer writes, as the user it makes
    unit = read('systemd', 'pegaprox-witness.service').splitlines()
    installer = read('packaging', 'witness', 'install.sh')
    assert 'ExecStart=/usr/local/bin/pegaprox-witness run' in unit
    assert 'BIN="$ROOT/usr/local/bin/pegaprox-witness"' in installer
    assert 'USER_NAME=pegaprox-witness' in installer and 'User=pegaprox-witness' in unit
    # the Docker image's witness is the command `witness`, through witness_boot
    assert "from pegaprox.witness_boot import main as _witness_boot" in read('pegaprox_multi_cluster.py')


def test_a_clean_stop_after_it_answered_is_no_failed_start(tmp_path):
    """A restart, a reboot or the installer run again stops code on trial that answered
    on its port: that start does not count, however often it happens. A start that
    ended any other way still does."""
    state = str(tmp_path / 'state')
    root = os.path.join(state, wb.UPDATES)
    base = _fake_tree(tmp_path / 'base', '1.0.0')
    old = _fake_tree(os.path.join(root, '1.1.0-aaaaaaaaaaaa'), '1.1.0')
    new = _fake_tree(os.path.join(root, '1.2.0-bbbbbbbbbbbb'), '1.2.0')
    wb.switch(root, '1.1.0-aaaaaaaaaaaa')
    wb.mark_ok(state, old)
    wb.switch(root, '1.2.0-bbbbbbbbbbbb')
    new = os.path.realpath(new)
    for _ in range(5):
        assert wb.choose(base, state) == (new, True)
        wb.mark_up(state, new)
        wb.mark_stopped(state, new)
    assert new not in wb.load_health(root)['bad']
    # then it crashes before it answers, start after start: those count, and after
    # TRIES of them it goes back
    for _ in range(wb.TRIES):
        assert wb.choose(base, state) == (new, True)
        wb.mark_stopped(state, new)          # never answered: nothing to forgive
    assert wb.choose(base, state)[0] != new
    assert new in wb.load_health(root)['bad']


def test_going_back_from_a_same_release_fix_keeps_the_fix_before_it(tmp_path):
    """Testing keeps its release string: the base A, the leader's fix B that came up, then
    a fix C that never does. Going back from C runs B again, not the older base A."""
    state = str(tmp_path / 'state')
    root = os.path.join(state, wb.UPDATES)
    base = _fake_tree(tmp_path / 'base', '1.2.0', marker='A')
    b = _fake_tree(os.path.join(root, '1.2.0-bbbbbbbbbbbb'), '1.2.0', marker='B')
    wb.switch(root, '1.2.0-bbbbbbbbbbbb')
    wb.mark_same(state, b)
    wb.mark_ok(state, b)
    c = _fake_tree(os.path.join(root, '1.2.0-cccccccccccc'), '1.2.0', marker='C')
    wb.switch(root, '1.2.0-cccccccccccc')
    wb.mark_same(state, c)
    b, c = os.path.realpath(b), os.path.realpath(c)
    assert wb.choose(base, state) == (c, True)
    assert wb.choose(base, state) == (c, True)
    assert wb.choose(base, state) == (b, False)
    assert wb.load_health(root)['same'] == b
