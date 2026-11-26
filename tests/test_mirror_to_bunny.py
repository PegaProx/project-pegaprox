# -*- coding: utf-8 -*-
"""The update mirror: .github/scripts/mirror_to_bunny.py and .github/workflows/mirror.yml.

What is pinned here: the zone gets what the lftp cron put there and nothing else, the
archive is the same bytes for the same commit and both updaters take it, the single files
go up first and then the archive's .sha256, the archive and version.json, so at no moment
but the last step does the zone serve an archive of another release than its version.json,
a failed upload holds back version.json and every delete, the in-app updater takes nothing
from a zone between two releases, a dry run writes nothing, the zone password shows up nowhere, certificates are checked, and
the workflow keeps the secret in one step of a main-only job. The zone is a fake of the
Bunny storage API on 127.0.0.1 behind TLS. The workflow is read as text, CI has no PyYAML.

NS Nov 2026
"""
import argparse
import contextlib
import datetime
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import threading
import types
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WF_DIR = ROOT / '.github' / 'workflows'
WORKFLOW = (WF_DIR / 'mirror.yml').read_text(encoding='utf-8')
BASELINE = json.loads((ROOT / '.github' / 'watchdog' / 'baseline.json').read_text(encoding='utf-8'))
_spec = importlib.util.spec_from_file_location('mirror_to_bunny', ROOT / '.github' / 'scripts' / 'mirror_to_bunny.py')
mirror = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mirror)

PASSWORD = 'zone-pw-Qx7!rT2-9184'
ZONE_NAME = 'updates-pegaprox-com'
GH_ARCHIVE = 'https://github.com/PegaProx/project-pegaprox/archive/refs/heads/main.tar.gz'
WHEN = '2026-11-01T12:00:00+00:00'
WHEN_TS = int(datetime.datetime.fromisoformat(WHEN).timestamp())

RELEASE = {
    'pegaprox_multi_cluster.py': '# the new entry point\n',
    'version.json': json.dumps({'version': '9.9.9', 'update_archive': GH_ARCHIVE}) + '\n',
    'requirements.txt': 'flask\n',
    'pegaprox/__init__.py': '',
    'pegaprox/archive/keep.py': '# archive/ below the top is an ordinary directory\n',
    'plugins/.gitkeep': '',
    'plugins/hello/__init__.py': '# a plugin\n',
    'tools/run.sh': '#!/bin/sh\necho run\n',
    'web/index.html': '<html>page</html>\n',
}
EXECUTABLE = {'tools/run.sh'}
# tracked, and still not for the zone
NOT_IN_ZONE = {
    '.gitignore': '*.pyc\n',
    '.github/workflows/x.yml': 'name: x\n',
    '.github/scripts/y.py': '# y\n',
    'old.py.bak': '# a backup\n',
    'docs/notes.md.bak': 'notes\n',
    'web/.gitattributes': '* text\n',
    'archive/stray.txt': 'stray\n',
    'SHA256SUMS': 'deadbeef  main.tar.gz\n',
}
ZONE_FILES = (set(RELEASE) - {'plugins/.gitkeep'}) | {mirror.ARCHIVE, mirror.ARCHIVE_SUM}
# the cron's tar kept .gitignore and the like, only .git, .github and archive/ stayed out
ARCHIVE_FILES = set(RELEASE) | {'.gitignore', 'web/.gitattributes'}


# ---------------------------------------------------------------------------------------
# a git repo to mirror

def _git(repo, *args, when=WHEN):
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, HOME=str(repo),
               GIT_AUTHOR_NAME='NS', GIT_AUTHOR_EMAIL='ns@example.test',
               GIT_COMMITTER_NAME='NS', GIT_COMMITTER_EMAIL='ns@example.test',
               GIT_AUTHOR_DATE=when, GIT_COMMITTER_DATE=when)
    r = subprocess.run(['git', '-C', str(repo), *args], capture_output=True, env=env)
    assert r.returncode == 0, r.stderr.decode()
    return r.stdout.decode()


def _write(repo, files):
    for rel, text in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding='utf-8')
        p.chmod(0o755 if rel in EXECUTABLE else 0o644)


def commit(repo, files=None, remove=(), add=(), when=WHEN):
    # paths named one by one: the untracked junk in the checkout stays untracked
    files = files or {}
    _write(repo, files)
    if files or add:
        _git(repo, 'add', '--', *files, *add)
    if remove:
        _git(repo, 'rm', '-q', '--', *remove)
    _git(repo, 'commit', '-q', '--allow-empty', '-m', 'release', when=when)
    head = _git(repo, 'rev-parse', 'HEAD').strip()
    # what actions/checkout of main leaves behind: origin/main at the commit
    if _git(repo, 'symbolic-ref', '--short', 'HEAD').strip() == 'main':
        _git(repo, 'update-ref', 'refs/remotes/origin/main', head)
    return head


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / 'repo'
    r.mkdir()
    _git(r, 'init', '-q', '-b', 'main')
    commit(r, {**RELEASE, **NOT_IN_ZONE})
    # lying around in the checkout, never tracked
    (r / 'junk.txt').write_text('untracked\n')
    (r / 'cache.pyc').write_bytes(b'ignored')
    return r


def tracked(repo):
    return set(_git(repo, 'ls-files').split())


def zone_dir_files(out):
    return {p.relative_to(out).as_posix() for p in Path(out).rglob('*') if p.is_file()}


def archive_members(path):
    with tarfile.open(path, 'r:gz') as tar:
        return [(m, tar.extractfile(m).read() if m.isfile() else None) for m in tar.getmembers()]


# ---------------------------------------------------------------------------------------
# the tree and the archive

def test_the_zone_gets_what_the_cron_published_and_nothing_else(repo, tmp_path):
    tree = mirror.build_tree(repo, tmp_path / 'out')
    assert set(tree.files) == ZONE_FILES
    assert zone_dir_files(tmp_path / 'out') == ZONE_FILES
    for rel in RELEASE:
        if rel in ZONE_FILES:
            assert (tmp_path / 'out' / rel).read_text(encoding='utf-8') == RELEASE[rel]
            assert tree.files[rel] == (hashlib.sha256(RELEASE[rel].encode()).hexdigest().upper(),
                                       len(RELEASE[rel].encode()))
    assert (tmp_path / 'out' / 'tools' / 'run.sh').stat().st_mode & 0o777 == 0o755
    assert (tmp_path / 'out' / 'web' / 'index.html').stat().st_mode & 0o777 == 0o644
    # counterproof: everything left out is really tracked, and the junk is really there
    assert set(NOT_IN_ZONE) <= tracked(repo) and 'plugins/.gitkeep' in tracked(repo)
    assert (repo / 'junk.txt').exists() and 'junk.txt' not in tracked(repo)
    # archive/ is ours only at the top
    assert 'pegaprox/archive/keep.py' in tree.files


def test_the_archive_holds_the_tracked_files_under_one_top_directory(repo, tmp_path):
    tree = mirror.build_tree(repo, tmp_path / 'out')
    members = archive_members(tmp_path / 'out' / mirror.ARCHIVE)
    names = [m.name for m, _ in members]
    keys = [m.name + '/' if m.isdir() else m.name for m, _ in members]
    assert keys == sorted(keys)
    assert all(n == mirror.ARCHIVE_TOP or n.startswith(mirror.ARCHIVE_TOP + '/') for n in names)
    files = {m.name[len(mirror.ARCHIVE_TOP) + 1:]: (m, data) for m, data in members if m.isfile()}
    assert set(files) == ARCHIVE_FILES
    for rel, (m, data) in files.items():
        want = RELEASE.get(rel, NOT_IN_ZONE.get(rel))
        assert data == want.encode(), rel
        assert m.mode == (0o755 if rel in EXECUTABLE else 0o644), rel
    for m, _ in members:
        assert (m.uid, m.gid, m.uname, m.gname, m.mtime) == (0, 0, '', '', WHEN_TS), m.name
        assert m.isdir() or m.isfile(), m.name
        if m.isdir():
            assert m.mode == 0o755
    dirs = {m.name for m, _ in members if m.isdir()}
    assert {mirror.ARCHIVE_TOP, f'{mirror.ARCHIVE_TOP}/pegaprox/archive', f'{mirror.ARCHIVE_TOP}/web'} <= dirs
    # the digest the tree reports is the file's
    assert tree.digest == hashlib.sha256((tmp_path / 'out' / mirror.ARCHIVE).read_bytes()).hexdigest()


def test_the_archive_is_the_same_bytes_for_the_same_commit(repo, tmp_path):
    a = mirror.build_tree(repo, tmp_path / 'a')
    old = os.umask(0o077)
    try:
        b = mirror.build_tree(repo, tmp_path / 'b')
    finally:
        os.umask(old)
    blob = (tmp_path / 'a' / mirror.ARCHIVE).read_bytes()
    assert blob == (tmp_path / 'b' / mirror.ARCHIVE).read_bytes()
    assert a.digest == b.digest and a.files == b.files
    # gzip without a name and without a time
    assert blob[:3] == b'\x1f\x8b\x08' and not blob[3] & 0x08 and blob[4:8] == b'\0\0\0\0'
    # counterproof: another commit time gives other bytes, so the time inside is the
    # commit's and not the clock's; another content gives another digest as well
    head = commit(repo, when='2026-11-02T08:00:00+00:00')
    c = mirror.build_tree(repo, tmp_path / 'c')
    assert c.commit == head and c.digest != a.digest and c.files[mirror.MANIFEST] == a.files[mirror.MANIFEST]
    commit(repo, {'web/index.html': '<html>changed</html>\n'})
    d = mirror.build_tree(repo, tmp_path / 'd')
    assert d.digest not in (a.digest, c.digest)


def test_the_sha256_file_reads_like_sha256sum(repo, tmp_path):
    tree = mirror.build_tree(repo, tmp_path / 'out')
    line = (tmp_path / 'out' / mirror.ARCHIVE_SUM).read_bytes()
    assert line == f'{tree.digest}  main.tar.gz\n'.encode()
    if shutil.which('sha256sum'):
        r = subprocess.run(['sha256sum', '--strict', '-c', 'main.tar.gz.sha256'],
                           cwd=tmp_path / 'out' / 'archive', capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr


def test_no_sha256sums_is_ever_published(repo, tmp_path):
    # update.sh fetches SHA256SUMS from GitHub, then from the mirror, and holds GitHub's
    # archive against it: a mirror copy would stop every update
    mirror.build_tree(repo, tmp_path / 'out')
    assert 'SHA256SUMS' in tracked(repo)
    assert not [p for p in zone_dir_files(tmp_path / 'out') if p.rsplit('/', 1)[-1] == 'SHA256SUMS']
    names = [m.name for m, _ in archive_members(tmp_path / 'out' / mirror.ARCHIVE)]
    assert not [n for n in names if n.rsplit('/', 1)[-1] == 'SHA256SUMS']


def test_a_symlink_or_a_broken_tree_is_refused(repo, tmp_path):
    os.symlink('web/index.html', repo / 'link.html')
    commit(repo, add=['link.html'])
    with pytest.raises(mirror.MirrorError, match='120000'):
        mirror.build_tree(repo, tmp_path / 'a')
    commit(repo, remove=['link.html', 'version.json'])
    with pytest.raises(mirror.MirrorError, match='version.json'):
        mirror.build_tree(repo, tmp_path / 'b')
    # counterproof: with both back it builds
    commit(repo, {'version.json': RELEASE['version.json']})
    assert mirror.MANIFEST in mirror.build_tree(repo, tmp_path / 'c').files


def test_the_output_directory_must_be_new_or_empty(repo, tmp_path):
    (tmp_path / 'out').mkdir()
    (tmp_path / 'out' / 'left.txt').write_text('x')
    with pytest.raises(mirror.MirrorError, match='not empty'):
        mirror.build_tree(repo, tmp_path / 'out')


def test_this_repository_has_nothing_the_mirror_refuses():
    if not (ROOT / '.git').exists():
        pytest.skip('not a git checkout')
    commit_id, _, entries = mirror.tracked_entries(ROOT)
    paths = {p for p, _, _ in entries}
    assert set(mirror.REQUIRED) <= paths, commit_id
    assert not [p for p in paths if p.rsplit('/', 1)[-1] == 'SHA256SUMS']
    assert not [p for p in paths if p.split('/')[0] == 'archive']


# ---------------------------------------------------------------------------------------
# both updaters take the archive

class _Resp:
    def __init__(self, status, content=b''):
        self.status_code = status
        self.content = content

    def json(self):
        return json.loads(self.content)

    def iter_content(self, size):
        yield self.content


def cron_archive(repo, path):
    """What the cron built: tar -czf main.tar.gz -C repo . (entries under ./)."""
    _, ctime, entries = mirror.tracked_entries(repo)
    keep = [(p, m, b) for p, m, b in entries if mirror.in_archive(p)]
    with tarfile.open(path, 'w:gz') as tar:
        for (rel, mode, _), data in zip(keep, mirror._blobs(repo, [b for _, _, b in keep])):
            info = tarfile.TarInfo(f'./{rel}')
            info.size, info.mode, info.mtime = len(data), mode, ctime
            tar.addfile(info, io.BytesIO(data))


@pytest.mark.parametrize('layout, method', [('mirror', 'archive'), ('cron', 'individual')])
def test_the_in_app_updater_takes_the_mirror_archive(api, seed, repo, tmp_path, monkeypatch, layout, method):
    """GitHub down, everything from updates.pegaprox.com: the in-app updater unpacks the new
    archive. Counterproof: the cron's flat archive it never took, it went file by file."""
    import pegaprox.api.settings as settings
    tree = mirror.build_tree(repo, tmp_path / 'zone')
    blob = (tmp_path / 'zone' / mirror.ARCHIVE).read_bytes()
    if layout == 'cron':
        cron_archive(repo, tmp_path / 'cron.tar.gz')
        blob = (tmp_path / 'cron.tar.gz').read_bytes()

    def get(url, *a, **kw):
        if url.startswith(('https://github.com/', 'https://raw.githubusercontent.com/', 'https://api.github.com/')):
            raise settings.requests.ConnectionError('GitHub is down in this test')
        if url == settings.MIRROR_ARCHIVE_URL:
            return _Resp(200, blob)
        if url.startswith(settings.MIRROR_RAW_URL + '/'):
            p = tree.out / url[len(settings.MIRROR_RAW_URL) + 1:]
            return _Resp(200, p.read_bytes()) if p.is_file() else _Resp(404)
        return _Resp(404)

    install = tmp_path / 'opt-pegaprox'
    (install / 'pegaprox' / 'api').mkdir(parents=True)
    live = install / 'plugins'
    live.mkdir()
    monkeypatch.setattr(settings, '__file__', str(install / 'pegaprox' / 'api' / 'settings.py'))
    monkeypatch.setattr(settings, 'PLUGINS_DIR', str(live))
    monkeypatch.setattr(settings, 'CONFIG_DIR', str(tmp_path / 'config'))
    monkeypatch.setattr(settings, '_detect_install_method', lambda d: 'source')
    monkeypatch.setattr(settings.requests, 'get', get)
    # no pip and a failed crypto preflight, so nothing restarts (the git calls are done)
    monkeypatch.setattr(settings.subprocess, 'run', lambda *a, **kw: types.SimpleNamespace(
        returncode=1, stdout='', stderr='not in a test'))
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post('/api/pegaprox/update', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['update_method'] == method, body
    assert not body['files_failed'], body
    assert (install / 'pegaprox_multi_cluster.py').read_text() == RELEASE['pegaprox_multi_cluster.py']


CURL_STUB = r'''#!/bin/bash
# GitHub is down; updates.pegaprox.com serves the zone directory $ZONE
out=""; url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift ;;
        http*) url="$1" ;;
    esac
    shift
done
case "$url" in
    https://updates.pegaprox.com/*) src="$ZONE/${url#https://updates.pegaprox.com/}" ;;
    *) exit 6 ;;
esac
[ -f "$src" ] || exit 22
if [ -n "$out" ]; then cp "$src" "$out"; else cat "$src"; fi
'''


@pytest.mark.parametrize('layout, ok', [('mirror', True), ('two-deep', False)])
def test_update_sh_takes_the_mirror_archive(repo, tmp_path, layout, ok):
    """Counterproof: an archive two directories deep is one update.sh refuses, so this
    would notice a layout it cannot read."""
    mirror.build_tree(repo, tmp_path / 'zone')
    zone = tmp_path / 'zone'
    if layout == 'two-deep':
        arc = zone / mirror.ARCHIVE
        with tarfile.open(arc, 'r:gz') as src:
            members = [(m, src.extractfile(m).read() if m.isfile() else None) for m in src.getmembers()]
        with tarfile.open(arc, 'w:gz') as tar:
            for m, data in members:
                m.name = f'extra/{m.name}'
                tar.addfile(m, io.BytesIO(data) if data is not None else None)
    inst = tmp_path / 'opt' / 'PegaProx'
    inst.mkdir(parents=True)
    shutil.copy(ROOT / 'update.sh', inst)
    (inst / 'version.json').write_text(RELEASE['version.json'])
    (inst / 'pegaprox_multi_cluster.py').write_text('# the old entry point\n')
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    (stubs / 'curl').write_text(CURL_STUB)
    for cmd, code in (('systemctl', 3), ('dpkg', 1), ('pip3', 0)):
        (stubs / cmd).write_text(f'#!/bin/sh\nexit {code}\n')
    (stubs / 'python3').write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    env = dict(os.environ, PATH=f'{stubs}:{os.environ.get("PATH", "")}', ZONE=str(zone), HOME=str(tmp_path))
    env.pop('PEGAPROX_BRANCH', None)
    r = subprocess.run(['bash', str(inst / 'update.sh'), '--force'], env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=120)
    assert 'OK (Mirror)' in r.stdout, r.stdout[-3000:] + r.stderr[-3000:]
    assert 'falling back to individual files' not in r.stdout
    if ok:
        assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
        assert (inst / 'pegaprox_multi_cluster.py').read_text() == RELEASE['pegaprox_multi_cluster.py']
        assert (inst / 'web' / 'index.html').read_text() == RELEASE['web/index.html']
    else:
        assert r.returncode != 0 and 'Archive does not contain pegaprox_multi_cluster.py' in r.stdout
        assert (inst / 'pegaprox_multi_cluster.py').read_text() == '# the old entry point\n'


# ---------------------------------------------------------------------------------------
# a fake Bunny storage zone

@pytest.fixture(scope='module')
def tls(tmp_path_factory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    d = tmp_path_factory.mktemp('tls')
    now = datetime.datetime.now(datetime.timezone.utc)

    def usage(ca):
        return x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                             data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                             encipher_only=False, decipher_only=False)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mirror test CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(usage(True), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(usage(False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (d / 'ca.pem').write_bytes(ca.public_bytes(pem))
    (d / 'leaf.pem').write_bytes(leaf.public_bytes(pem))
    (d / 'leaf.key').write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / 'leaf.pem', d / 'leaf.key')
    return types.SimpleNamespace(ca=d / 'ca.pem', ctx=ctx)


def _parents(rel):
    parts = rel.split('/')[:-1]
    return {'/'.join(parts[:i]) for i in range(1, len(parts) + 1)}


class FakeZone:
    """GET <dir>/ lists, PUT stores (and checks Checksum, upper-case hex), DELETE removes a
    file or a directory with everything in it. The listing carries the fields Bunny sends,
    Checksum included."""

    def __init__(self, password):
        self.password = password
        self.files = {}
        self.dirs = set()
        self.events = []          # (start|done, method, path)
        self.states = []          # (method, path, the files right after that write)
        self.faults = {}          # (method, path) -> [status, 'reset' or (status, Location), ...]
        self.keys_seen = []
        self.no_checksum = set()
        self.echo_key = False
        self.lock = threading.Lock()
        self.url = ''

    def all_dirs(self):
        out = set()
        for p in list(self.files) + [d + '/' for d in self.dirs]:
            out |= _parents(p)
        return out

    def listing(self, d):
        prefix = d + '/' if d else ''
        items = []
        for f in sorted(self.files):
            if f.startswith(prefix) and '/' not in f[len(prefix):]:
                data = self.files[f]
                items.append({'Guid': 'g', 'StorageZoneName': ZONE_NAME, 'Path': f'/{ZONE_NAME}/{prefix}',
                              'ObjectName': f[len(prefix):], 'Length': len(data),
                              'LastChanged': '2026-11-16T00:00:00', 'IsDirectory': False, 'ServerId': 1,
                              'UserId': 'u', 'DateCreated': '2026-11-16T00:00:00', 'StorageZoneId': 1,
                              'Checksum': None if f in self.no_checksum else hashlib.sha256(data).hexdigest().upper(),
                              'ReplicatedZones': '', 'ArrayNumber': 0, 'ContentType': ''})
        for sub in sorted(self.all_dirs()):
            if sub.startswith(prefix) and sub != d and '/' not in sub[len(prefix):]:
                items.append({'Guid': 'g', 'StorageZoneName': ZONE_NAME, 'Path': f'/{ZONE_NAME}/{prefix}',
                              'ObjectName': sub[len(prefix):], 'Length': 0, 'IsDirectory': True,
                              'Checksum': None})
        return items

    def ops(self, method=None, kind='start'):
        return [(m, p) for k, m, p in self.events if k == kind and (method is None or m == method)]


def _handler(zone):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body=b'', location=None):
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            if location:
                self.send_header('Location', location)
            self.end_headers()
            self.wfile.write(body)

        def _gate(self, method):
            path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
            parts = path.split('/')
            rel = '/'.join(parts[2:]) if len(parts) >= 2 and parts[1] == ZONE_NAME else None
            key = self.headers.get('AccessKey', '')
            with zone.lock:
                zone.keys_seen.append(key)
                zone.events.append(('start', method, rel))
                todo = zone.faults.get((method, rel))
                fault = todo.pop(0) if todo else None
            if fault == 'reset':
                self.close_connection = True
                return None
            if isinstance(fault, tuple):
                self._send(fault[0], b'{}', location=fault[1])
                return None
            if fault:
                self._send(fault, json.dumps({'HttpCode': fault, 'Message': 'injected'}).encode())
                return None
            if rel is None:
                self._send(404)
                return None
            if key != zone.password:
                msg = 'Unauthorized' + (f', you sent {key}' if zone.echo_key else '')
                self._send(401, json.dumps({'HttpCode': 401, 'Message': msg}).encode())
                return None
            return rel

        def _done(self, method, rel):
            with zone.lock:
                zone.events.append(('done', method, rel))

        def do_GET(self):
            rel = self._gate('GET')
            if rel is None:
                return
            d = rel.rstrip('/')
            if rel and not rel.endswith('/'):
                data = zone.files.get(rel)
                self._send(200, data) if data is not None else self._send(404)
            elif d and d not in zone.all_dirs():
                self._send(404, b'{"HttpCode":404,"Message":"Object Not Found"}')
            else:
                self._send(200, json.dumps(zone.listing(d)).encode())
            self._done('GET', rel)

        def do_PUT(self):
            body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
            rel = self._gate('PUT')
            if rel is None:
                return
            want = self.headers.get('Checksum')
            if want is not None and want != hashlib.sha256(body).hexdigest().upper():
                return self._send(400, b'{"HttpCode":400,"Message":"Checksum mismatch"}')
            with zone.lock:
                zone.files[rel] = body
                # Bunny keeps a directory when its last file goes
                zone.dirs |= _parents(rel)
                zone.states.append(('PUT', rel, dict(zone.files)))
            self._done('PUT', rel)
            self._send(201, b'{"HttpCode":201,"Message":"File uploaded."}')

        def do_DELETE(self):
            rel = self._gate('DELETE')
            if rel is None:
                return
            with zone.lock:
                if rel.endswith('/'):
                    d = rel.rstrip('/')
                    hit = d in zone.all_dirs()
                    for f in [f for f in zone.files if f.startswith(d + '/')]:
                        del zone.files[f]
                    zone.dirs = {x for x in zone.dirs if x != d and not x.startswith(d + '/')}
                else:
                    hit = zone.files.pop(rel, None) is not None
                zone.states.append(('DELETE', rel, dict(zone.files)))
            self._done('DELETE', rel)
            self._send(200 if hit else 404, b'{}')
    return H


def _serve(tls, fz):
    srv = ThreadingHTTPServer(('127.0.0.1', 0), _handler(fz))
    srv.daemon_threads = True
    srv.socket = tls.ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    fz.url = f'https://127.0.0.1:{srv.server_address[1]}/{ZONE_NAME}'
    fz.ca = tls.ca
    return srv


@pytest.fixture
def zone(tls, monkeypatch):
    fz = FakeZone(PASSWORD)
    srv = _serve(tls, fz)
    # the script's default context trusts the test CA through OpenSSL's own variable
    monkeypatch.setenv('SSL_CERT_FILE', str(tls.ca))
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    for var in ('https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY', 'all_proxy', 'ALL_PROXY'):
        monkeypatch.delenv(var, raising=False)
    yield fz
    srv.shutdown()
    srv.server_close()


def run(zone, repo, *args, password=PASSWORD, zone_url=None, sleeps=None):
    out, err = io.StringIO(), io.StringIO()
    env = {'BUNNY_STORAGE_URL': zone_url or zone.url}
    if password is not None:
        env['BUNNY_STORAGE_PASSWORD'] = password
    code = mirror.main(['--root', str(repo), '--jobs', '4', *args], env=env,
                       sleep=(sleeps.append if sleeps is not None else (lambda s: None)),
                       stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def expected_zone(repo, tmp_path, name='expect'):
    tree = mirror.build_tree(repo, tmp_path / name)
    return {rel: tree.read(rel) for rel in tree.files}


def release_two(repo):
    """The next commit: a changed page and manifest, one plugin file gone."""
    return commit(repo, {'web/index.html': '<html>page two</html>\n',
                         'version.json': json.dumps({'version': '9.9.10', 'update_archive': GH_ARCHIVE}) + '\n'},
                  remove=['plugins/hello/__init__.py'])


# ---------------------------------------------------------------------------------------
# the sync

def test_a_first_sync_fills_the_zone_and_puts_the_manifest_last(zone, repo, tmp_path):
    code, out, err = run(zone, repo)
    assert code == 0, out + err
    assert zone.files == expected_zone(repo, tmp_path)
    assert re.search(rf'^synced [0-9a-f]{{12}}: {len(ZONE_FILES)} uploaded, 0 unchanged, 0 deleted, \d+ bytes sent$',
                     out, re.M), out
    starts = zone.ops('PUT')
    ev = zone.events
    at = {(k, p): i for i, (k, m, p) in enumerate(ev) if m == 'PUT'}
    tail = [mirror.ARCHIVE_SUM, mirror.ARCHIVE, mirror.MANIFEST]
    singles = [p for _, p in starts if p not in tail]
    assert singles
    # the .sha256 starts once every single file is done, then the archive, then version.json,
    # each once the one before is done
    assert all(at[('start', mirror.ARCHIVE_SUM)] > at[('done', p)] for p in singles)
    assert at[('start', mirror.ARCHIVE)] > at[('done', mirror.ARCHIVE_SUM)]
    assert at[('start', mirror.MANIFEST)] > at[('done', mirror.ARCHIVE)]
    assert [p for _, p in starts][-3:] == tail
    # counterproof: in plain sorted order version.json would not come last, and the archive
    # would go up among the first
    assert sorted(ZONE_FILES)[-1] != mirror.MANIFEST
    assert sorted(ZONE_FILES)[0] == mirror.ARCHIVE


def test_a_second_sync_uploads_nothing_and_a_changed_file_goes_up_again(zone, repo, tmp_path):
    assert run(zone, repo)[0] == 0
    zone.events.clear()
    code, out, _ = run(zone, repo)
    assert code == 0
    assert zone.ops('PUT') == [] and zone.ops('DELETE') == []
    assert f'0 uploaded, {len(ZONE_FILES)} unchanged, 0 deleted, 0 bytes sent' in out
    # counterproof: a file the zone holds with other content, and one whose checksum the
    # zone does not report, are uploaded again, and only those
    zone.files['requirements.txt'] = b'tampered\n'
    zone.no_checksum.add('web/index.html')
    zone.events.clear()
    code, out, _ = run(zone, repo)
    assert code == 0
    assert sorted(p for _, p in zone.ops('PUT')) == ['requirements.txt', 'web/index.html']
    assert zone.files['requirements.txt'] == RELEASE['requirements.txt'].encode()


def test_the_next_release_uploads_what_changed_and_deletes_what_is_gone(zone, repo, tmp_path):
    assert run(zone, repo)[0] == 0
    zone.files['stale.txt'] = b'from long ago\n'
    zone.files['old/deep/gone.py'] = b'# gone\n'
    zone.dirs.add('empty/dir')
    release_two(repo)
    zone.events.clear()
    code, out, err = run(zone, repo)
    assert code == 0, out + err
    want = expected_zone(repo, tmp_path)
    assert zone.files == want
    assert zone.all_dirs() == set().union(*(_parents(p) for p in want))
    assert sorted(p for _, p in zone.ops('PUT')) == sorted(
        ['web/index.html', mirror.MANIFEST, mirror.ARCHIVE, mirror.ARCHIVE_SUM])
    assert sorted(p for _, p in zone.ops('DELETE')) == sorted(
        ['plugins/hello/__init__.py', 'stale.txt', 'old/deep/gone.py', 'old/deep/', 'old/', 'empty/dir/',
         'empty/', 'plugins/hello/', 'plugins/'])
    # deletes only after the last upload, a directory only after what was in it
    ev = [(k, m, p) for k, m, p in zone.events if m in ('PUT', 'DELETE')]
    last_put = max(i for i, (k, m, _) in enumerate(ev) if m == 'PUT' and k == 'done')
    assert all(i > last_put for i, (k, m, _) in enumerate(ev) if m == 'DELETE')
    order = [p for _, p in zone.ops('DELETE')]
    assert order.index('old/deep/gone.py') < order.index('old/deep/') < order.index('old/')
    assert ' 4 uploaded, ' in out and ' 9 deleted, ' in out
    # counterproof: nothing main still has was deleted
    assert set(want) <= set(zone.files)


def test_a_failed_upload_holds_back_the_manifest_and_every_delete(zone, repo, tmp_path):
    assert run(zone, repo)[0] == 0
    before = dict(zone.files)
    zone.files['stale.txt'] = b'stale\n'
    release_two(repo)
    zone.faults[('PUT', 'web/index.html')] = [500] * (mirror.RETRIES + 1)
    zone.events.clear()
    sleeps = []
    code, out, err = run(zone, repo, sleeps=sleeps)
    assert code == 1, out + err
    assert 'FAILED web/index.html' in out and out.strip().splitlines()[-1].startswith('stopped ')
    assert zone.files[mirror.MANIFEST] == before[mirror.MANIFEST]
    assert zone.files[mirror.ARCHIVE_SUM] == before[mirror.ARCHIVE_SUM]
    assert 'stale.txt' in zone.files and 'plugins/hello/__init__.py' in zone.files
    assert zone.ops('DELETE') == []
    assert (mirror.MANIFEST not in [p for _, p in zone.ops('PUT')]
            and mirror.ARCHIVE_SUM not in [p for _, p in zone.ops('PUT')])
    # it was tried with backoff before giving up
    assert zone.ops('PUT').count(('PUT', 'web/index.html')) == mirror.RETRIES + 1
    assert sleeps[:mirror.RETRIES] == [1, 2, 4, 8]
    # counterproof: the same run without the fault does publish and delete
    code, out, err = run(zone, repo)
    assert code == 0, out + err
    assert zone.files == expected_zone(repo, tmp_path)


# ---------------------------------------------------------------------------------------
# a zone between two releases (#1390): Bunny cannot switch many files at once

def archive_version(blob):
    """The version in the version.json inside an archive of the zone."""
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as tar:
        return json.loads(tar.extractfile(f'{mirror.ARCHIVE_TOP}/version.json').read())['version']


def manifest(version, files=None):
    doc = {'version': version, 'update_archive': GH_ARCHIVE}
    if files is not None:
        doc['update_files'] = sorted(files)
    return json.dumps(doc) + '\n'


NEXT_ENTRY = '# the entry point of 9.9.10\n'


def test_at_no_moment_but_the_last_step_does_the_zone_serve_two_releases(zone, repo):
    """What a reader of the zone sees after every write of a sync: every file its
    version.json lists is there, and the archive is of the release version.json names, but
    in the one state right before version.json goes up (two uploads never land at once).
    The in-app updater reads exactly that pair and drops to single files when they differ.
    Deletes wait for version.json."""
    one = set(RELEASE) - {'plugins/.gitkeep'}
    commit(repo, {'version.json': manifest('9.9.9', one)})
    assert run(zone, repo)[0] == 0
    two = (one - {'plugins/hello/__init__.py'}) | {'pegaprox/new.py'}
    commit(repo, {'pegaprox/new.py': '# new in 9.9.10\n', 'web/index.html': '<html>page two</html>\n',
                  'pegaprox_multi_cluster.py': NEXT_ENTRY, 'version.json': manifest('9.9.10', two)},
           remove=['plugins/hello/__init__.py'])
    zone.states.clear()
    code, out, err = run(zone, repo)
    assert code == 0, out + err
    writes = [(m, p) for m, p, _ in zone.states]
    assert ('PUT', 'pegaprox/new.py') in writes and ('DELETE', 'plugins/hello/__init__.py') in writes
    apart = []
    for i, (method, rel, files) in enumerate(zone.states):
        listed = json.loads(files[mirror.MANIFEST])
        missing = [f for f in listed['update_files'] if f not in files]
        assert not missing, (method, rel, missing)
        if archive_version(files[mirror.ARCHIVE]) != listed['version']:
            apart.append(((method, rel), writes[i + 1] if i + 1 < len(writes) else None))
    assert apart == [(('PUT', mirror.ARCHIVE), ('PUT', mirror.MANIFEST))], apart
    first_delete = min(i for i, (m, _) in enumerate(writes) if m == 'DELETE')
    assert writes.index(('PUT', mirror.MANIFEST)) < first_delete


@pytest.mark.parametrize('failing', ['web/index.html', mirror.ARCHIVE_SUM, mirror.ARCHIVE])
def test_a_run_that_fails_before_version_json_leaves_the_archive_of_that_version(zone, repo, failing):
    """What a failed run leaves stays until the next run, up to an hour: the archive is still
    the one version.json announces, so the in-app updater takes it whole."""
    assert run(zone, repo)[0] == 0
    release_two(repo)
    zone.faults[('PUT', failing)] = [500] * (mirror.RETRIES + 1)
    code, out, err = run(zone, repo)
    assert code == 1 and f'FAILED {failing}:' in out, out + err
    assert json.loads(zone.files[mirror.MANIFEST])['version'] == '9.9.9'
    assert archive_version(zone.files[mirror.ARCHIVE]) == '9.9.9'
    # counterproof: the next run goes through, and both are of the next release
    assert run(zone, repo)[0] == 0
    assert json.loads(zone.files[mirror.MANIFEST])['version'] == '9.9.10'
    assert archive_version(zone.files[mirror.ARCHIVE]) == '9.9.10'


OLD_ENTRY = '# the old entry point\n'
OLD_MANIFEST = manifest('9.9.8')


def in_app_updater(mp, settings, tmp_path, get):
    """An install the in-app updater writes into, with requests.get answered by get. Patches
    subprocess.run (no pip, a failed crypto preflight, so nothing restarts), so no git call
    of the mirror script while mp is active."""
    install = tmp_path / 'opt-pegaprox'
    if not install.exists():
        (install / 'pegaprox' / 'api').mkdir(parents=True)
        (install / 'plugins').mkdir()
        (install / 'pegaprox_multi_cluster.py').write_text(OLD_ENTRY)
        (install / 'version.json').write_text(OLD_MANIFEST)
    mp.setattr(settings, '__file__', str(install / 'pegaprox' / 'api' / 'settings.py'))
    mp.setattr(settings, 'PLUGINS_DIR', str(install / 'plugins'))
    mp.setattr(settings, 'CONFIG_DIR', str(tmp_path / 'config'))
    mp.setattr(settings, '_detect_install_method', lambda d: 'source')
    mp.setattr(settings.requests, 'get', get)
    mp.setattr(settings.subprocess, 'run', lambda *a, **kw: types.SimpleNamespace(
        returncode=1, stdout='', stderr='not in a test'))
    return install


def github_down(settings, files):
    """requests.get with GitHub unreachable and updates.pegaprox.com serving files."""
    def get(url, *a, **kw):
        if url.startswith(('https://github.com/', 'https://raw.githubusercontent.com/', 'https://api.github.com/')):
            raise settings.requests.ConnectionError('GitHub is down in this test')
        if url.startswith(settings.MIRROR_RAW_URL + '/'):
            data = files.get(url[len(settings.MIRROR_RAW_URL) + 1:])
            return _Resp(200, data) if data is not None else _Resp(404)
        return _Resp(404)
    return get


def test_the_in_app_updater_installs_nothing_from_a_zone_between_two_releases(
        api, seed, zone, repo, tmp_path, monkeypatch):
    """The state no upload order avoids, here for an hour: the run's version.json upload
    failed after the archive went up. The single files are of the new release, version.json
    of the old one, and the updater used to fall back to them, a mix it did not notice (the
    version.json it installed matched the one it had read)."""
    import pegaprox.api.settings as settings
    assert run(zone, repo)[0] == 0
    commit(repo, {'pegaprox_multi_cluster.py': NEXT_ENTRY, 'version.json': manifest('9.9.10')})
    zone.faults[('PUT', mirror.MANIFEST)] = [500] * (mirror.RETRIES + 1)
    assert run(zone, repo)[0] == 1
    assert archive_version(zone.files[mirror.ARCHIVE]) == '9.9.10'
    assert json.loads(zone.files[mirror.MANIFEST])['version'] == '9.9.9'
    assert zone.files['pegaprox_multi_cluster.py'] == NEXT_ENTRY.encode()
    admin = api.as_user(seed.user('root', role='admin'))
    with monkeypatch.context() as mp:
        install = in_app_updater(mp, settings, tmp_path, github_down(settings, zone.files))
        r = admin.post('/api/pegaprox/update', json={})
    # neither the new entry point nor the old version.json
    assert (install / 'pegaprox_multi_cluster.py').read_text() == OLD_ENTRY
    assert (install / 'version.json').read_text() == OLD_MANIFEST
    assert r.status_code == 503, r.get_data(as_text=True)
    assert 'between two releases' in r.get_json()['error']
    # counterproof: once the next run is through, the same updater takes the archive
    assert run(zone, repo)[0] == 0
    with monkeypatch.context() as mp:
        in_app_updater(mp, settings, tmp_path, github_down(settings, zone.files))
        r = admin.post('/api/pegaprox/update', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['update_method'] == 'archive' and not r.get_json()['files_failed']
    assert (install / 'pegaprox_multi_cluster.py').read_text() == NEXT_ENTRY
    assert json.loads((install / 'version.json').read_text())['version'] == '9.9.10'


@pytest.mark.parametrize('archive_from', ['github', 'mirror'])
def test_a_stale_archive_next_to_githubs_version_json_still_goes_to_githubs_files(
        api, seed, repo, tmp_path, monkeypatch, archive_from):
    """The stale archive check was made for GitHub, whose CDN hands out the old archive for
    minutes after a push; its raw files are the fallback. With version.json from GitHub that
    stays as it was, whichever archive came back."""
    import pegaprox.api.settings as settings
    stale = mirror.build_tree(repo, tmp_path / 'old').read(mirror.ARCHIVE)
    commit(repo, {'pegaprox_multi_cluster.py': NEXT_ENTRY, 'version.json': manifest('9.9.10')})
    new = mirror.build_tree(repo, tmp_path / 'new')

    def get(url, *a, **kw):
        if url == GH_ARCHIVE:
            if archive_from == 'mirror':
                raise settings.requests.ConnectionError('only the archive of GitHub is down')
            return _Resp(200, stale)
        if url == settings.MIRROR_ARCHIVE_URL:
            return _Resp(200, stale)
        if url.startswith(settings.GITHUB_RAW_URL + '/'):
            p = new.out / url[len(settings.GITHUB_RAW_URL) + 1:]
            return _Resp(200, p.read_bytes()) if p.is_file() else _Resp(404)
        return _Resp(404)

    with monkeypatch.context() as mp:
        install = in_app_updater(mp, settings, tmp_path, get)
        r = api.as_user(seed.user('root', role='admin')).post('/api/pegaprox/update', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['update_method'] == 'individual' and not r.get_json()['files_failed']
    assert (install / 'pegaprox_multi_cluster.py').read_text() == NEXT_ENTRY
    assert json.loads((install / 'version.json').read_text())['version'] == '9.9.10'


def test_passing_errors_are_retried_and_others_are_not(zone, repo):
    zone.faults[('GET', '')] = [502]
    zone.faults[('PUT', 'web/index.html')] = [503, 'reset']
    code, out, err = run(zone, repo)
    assert code == 0, out + err
    assert zone.ops('GET').count(('GET', '')) == 2
    assert zone.ops('PUT').count(('PUT', 'web/index.html')) == 3
    assert zone.files['web/index.html'] == RELEASE['web/index.html'].encode()
    # a refusal is no hiccup: one try, the run fails
    zone.files['requirements.txt'] = b'old\n'
    zone.faults[('PUT', 'requirements.txt')] = [403]
    zone.events.clear()
    code, out, err = run(zone, repo)
    assert code == 1
    assert zone.ops('PUT').count(('PUT', 'requirements.txt')) == 1
    assert 'HTTP 403' in out


def test_a_dry_run_writes_nothing(zone, repo, tmp_path):
    assert run(zone, repo)[0] == 0
    zone.files['stale.txt'] = b'stale\n'
    release_two(repo)
    files, dirs = dict(zone.files), set(zone.dirs)
    zone.events.clear()
    code, out, err = run(zone, repo, '--dry-run')
    assert code == 0, out + err
    assert zone.files == files and zone.dirs == dirs
    assert {m for _, m, _ in zone.events} == {'GET'}
    assert 'would upload web/index.html' in out and 'would upload version.json' in out
    assert 'would delete stale.txt' in out and 'would delete plugins/hello/__init__.py' in out
    assert out.strip().splitlines()[-1].endswith('nothing written')
    # counterproof: the real run changes the zone
    assert run(zone, repo)[0] == 0
    assert zone.files == expected_zone(repo, tmp_path)


def test_the_password_shows_up_nowhere(zone, repo, tmp_path, capsys):
    outputs = []
    outputs.append(run(zone, repo))
    outputs.append(run(zone, repo, '--dry-run'))
    zone.files['web/index.html'] = b'x'
    zone.faults[('PUT', 'web/index.html')] = [500] * (mirror.RETRIES + 1)
    outputs.append(run(zone, repo))
    # a server that echoes the key it got back into its error
    zone.password = 'the-zone-has-another-one'
    zone.echo_key = True
    zone.events.clear()
    outputs.append(run(zone, repo))
    assert outputs[-1][0] != 0 and '401' in outputs[-1][2] and '***' in outputs[-1][2]
    with pytest.raises(mirror.ZoneError) as exc:
        mirror.Zone(zone.url, PASSWORD, sleep=lambda s: None).request('GET', '', directory=True)
    # by mistake on the command line, without the variable even being set
    outputs.append(run(zone, repo, '--password', PASSWORD, password=None))
    assert outputs[-1][0] == 2 and 'unknown argument' in outputs[-1][2]
    for code, out, err in outputs:
        assert PASSWORD not in out and PASSWORD not in err
    assert PASSWORD not in str(exc.value) and PASSWORD not in repr(exc.value)
    assert PASSWORD not in repr(mirror.Zone(zone.url, PASSWORD))
    captured = capsys.readouterr()
    assert PASSWORD not in captured.out and PASSWORD not in captured.err
    # counterproof: the key really went out, the server really echoed it, and a plain
    # argparse would have printed it back
    assert PASSWORD in zone.keys_seen
    with contextlib.redirect_stderr(io.StringIO()) as plain, pytest.raises(SystemExit):
        argparse.ArgumentParser().parse_args(['--password', PASSWORD])
    assert PASSWORD in plain.getvalue()


def test_no_password_no_request(zone, repo):
    code, out, err = run(zone, repo, password=None)
    assert code == 2 and 'BUNNY_STORAGE_PASSWORD is not set' in err
    assert zone.events == []
    # counterproof: with it the zone is asked
    assert run(zone, repo)[0] == 0 and zone.events


def test_the_certificate_is_checked(zone, repo, monkeypatch):
    monkeypatch.delenv('SSL_CERT_FILE')
    sleeps = []
    code, out, err = run(zone, repo, sleeps=sleeps)
    assert code != 0 and 'certificate' in (out + err)
    # the handshake failed, so not one request reached the zone, and it was not retried
    assert zone.events == [] and zone.files == {} and sleeps == []
    # counterproof: trusting the test CA it works
    monkeypatch.setenv('SSL_CERT_FILE', str(zone.ca))
    assert run(zone, repo)[0] == 0 and zone.files


@pytest.mark.parametrize('method, status', [('GET', 302), ('GET', 307), ('PUT', 307)])
def test_a_redirect_is_not_followed(zone, tls, repo, method, status):
    """The AccessKey would go along to wherever the Location points. urllib never follows
    a PUT anyway, the listing it would."""
    elsewhere = FakeZone(PASSWORD)
    srv = _serve(tls, elsewhere)
    try:
        target = (method, '')
        if method == 'PUT':
            assert run(zone, repo)[0] == 0
            zone.files['requirements.txt'] = b'old\n'
            zone.events.clear()
            target = (method, 'requirements.txt')
        zone.faults[target] = [(status, elsewhere.url + '/' + target[1])]
        sleeps = []
        code, out, err = run(zone, repo, sleeps=sleeps)
        assert code != 0 and f'HTTP {status}' in out + err, out + err
        assert elsewhere.events == [] and elsewhere.keys_seen == []
        assert PASSWORD not in out + err and sleeps == []
        assert zone.ops(method).count(target) == 1
        if method == 'GET':
            # counterproof: a plain urllib opener follows this very answer, and the other
            # server gets the key
            zone.faults[target] = [(status, elsewhere.url + '/')]
            req = urllib.request.Request(zone.url + '/', headers={'AccessKey': PASSWORD})
            ctx = ssl.create_default_context(cafile=str(tls.ca))
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                assert resp.status == 200
            assert elsewhere.keys_seen == [PASSWORD]
    finally:
        srv.shutdown()
        srv.server_close()


def test_a_password_with_a_newline_is_trimmed_and_a_control_character_refused(zone, repo):
    # pasted from a file, or set with gh secret set < file
    code, out, err = run(zone, repo, password=PASSWORD + '\n')
    assert code == 0, out + err
    assert set(zone.keys_seen) == {PASSWORD}
    zone.events.clear()
    zone.keys_seen.clear()
    head, tail = PASSWORD[:8], PASSWORD[8:]
    for bad in (head + '\r\n' + tail, PASSWORD + '\x7f', PASSWORD + 'é', ' \t\n'):
        code, out, err = run(zone, repo, password=bad)
        assert code == 2, (bad, out + err)
        assert ('is not set' if not bad.strip() else 'control or non-ASCII character') in err, err
        assert head not in out + err and tail not in out + err
    # nothing went out, not even a listing
    assert zone.events == [] and zone.keys_seen == []


def test_the_password_is_masked_also_in_the_form_repr_gives_it(monkeypatch, repo):
    # a backslash and both quotes, which repr doubles and escapes
    secret = 'zone\\pw\'-Qx7"9184'

    def boom(tree, zone, dry_run=False, say=print):
        raise ValueError(f'Invalid header value {(secret + chr(10)).encode()!r}, as str {secret!r}')

    monkeypatch.setattr(mirror, 'sync', boom)
    err = io.StringIO()
    code = mirror.main(['--root', str(repo)], env={'BUNNY_STORAGE_PASSWORD': secret},
                       stdout=io.StringIO(), stderr=err)
    text = err.getvalue()
    assert code == 2 and 'ValueError: Invalid header value' in text and '***' in text, text
    for form in (secret, repr(secret)[1:-1], repr(secret.encode())[2:-1], 'Qx7'):
        assert form not in text, form
    # counterproof: replacing the plain value alone leaves the repr forms standing
    msg = f'{(secret + chr(10)).encode()!r}, as str {secret!r}'
    assert 'Qx7' in msg.replace(secret, '***')
    assert 'Qx7' not in mirror.mask(msg, secret)


def test_only_the_head_of_origin_main_goes_to_the_zone(zone, repo, tmp_path):
    main_commit = _git(repo, 'rev-parse', 'HEAD').strip()
    _git(repo, 'checkout', '-q', '-b', 'Testing')
    commit(repo, {'web/index.html': '<html>testing</html>\n'})
    assert _git(repo, 'rev-parse', 'origin/main').strip() == main_commit
    # the default HEAD is Testing here: refused, the dry run as well
    for args in ((), ('--dry-run',)):
        code, out, err = run(zone, repo, *args)
        assert code == 2 and 'is not the head of origin/main' in err, out + err
    assert zone.events == []
    # --ref origin/main publishes main, whatever the checkout is on
    code, out, err = run(zone, repo, '--ref', 'origin/main')
    assert code == 0, out + err
    assert f'synced {main_commit[:12]}: ' in out
    assert zone.files['web/index.html'] == RELEASE['web/index.html'].encode()
    # --any-ref means it
    code, out, err = run(zone, repo, '--any-ref')
    assert code == 0, out + err
    assert zone.files['web/index.html'] == b'<html>testing</html>\n'
    # no origin/main at all is no main either
    _git(repo, 'checkout', '-q', 'main')
    _git(repo, 'update-ref', '-d', 'refs/remotes/origin/main')
    zone.events.clear()
    code, out, err = run(zone, repo)
    assert code == 2 and 'no origin/main here' in err and zone.events == []
    # building the tree needs no main
    assert mirror.main(['--root', str(repo), '--tree-only', '--out', str(tmp_path / 't')], env={},
                       stdout=io.StringIO()) == 0


def test_the_zone_url_is_https_and_nothing_else():
    assert mirror.DEFAULT_ZONE_URL == 'https://storage.bunnycdn.com/updates-pegaprox-com'
    assert mirror.check_zone_url(mirror.DEFAULT_ZONE_URL + '/') == mirror.DEFAULT_ZONE_URL
    for bad in ('http://storage.bunnycdn.com/updates-pegaprox-com',
                'https://user:pw@storage.bunnycdn.com/updates-pegaprox-com',
                'https://storage.bunnycdn.com/', 'https://storage.bunnycdn.com/z?x=1',
                'https://storage.bunnycdn.com/z#f', 'storage.bunnycdn.com/z', ''):
        with pytest.raises(mirror.MirrorError):
            mirror.check_zone_url(bad)


def test_the_zone_url_comes_from_the_option_then_the_variable(zone, repo):
    dead = 'https://127.0.0.1:9/nothing-here'
    code, out, err = run(zone, repo, '--zone-url', zone.url, zone_url=dead)
    assert code == 0, out + err
    code, _, err = run(zone, repo, zone_url='http://127.0.0.1:9/plain')
    assert code == 2 and 'https://' in err


def test_the_archive_has_to_be_the_attested_one(zone, repo, tmp_path):
    code, out, err = run(zone, repo, '--expect-archive-sha256', '0' * 64)
    assert code == 2 and 'nothing uploaded' in err
    assert zone.events == []
    # counterproof: with the digest of this commit's archive it goes ahead
    digest = mirror.build_tree(repo, tmp_path / 'once').digest
    assert run(zone, repo, '--expect-archive-sha256', digest.upper())[0] == 0
    assert zone.files[mirror.ARCHIVE] == (tmp_path / 'once' / mirror.ARCHIVE).read_bytes()


def test_parallel_requests_stay_between_one_and_eight(monkeypatch, repo):
    seen = []
    monkeypatch.setattr(mirror, 'sync', lambda tree, z, dry_run=False, say=print: seen.append(z.jobs) or True)
    env = {'BUNNY_STORAGE_PASSWORD': PASSWORD}
    for jobs, want in (('50', 8), ('0', 1), ('6', 6)):
        assert mirror.main(['--root', str(repo), '--jobs', jobs], env=env, stdout=io.StringIO()) == 0
        assert seen[-1] == want


def test_tree_only_needs_no_password_and_no_network(repo, tmp_path):
    out = io.StringIO()
    assert mirror.main(['--root', str(repo), '--tree-only', '--out', str(tmp_path / 't')], env={}, stdout=out) == 0
    assert zone_dir_files(tmp_path / 't') == ZONE_FILES
    assert 'archive/main.tar.gz sha256 ' in out.getvalue()
    assert mirror.main(['--root', str(repo), '--tree-only'], env={}, stderr=io.StringIO()) == 2


# ---------------------------------------------------------------------------------------
# the workflow, read as text

def run_blocks(text):
    """The text of every run: value, block scalars included, by indentation."""
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        m = re.match(r'^(\s*)(?:- )?run:\s*(.*)$', line)
        if not m:
            continue
        indent, value = len(m.group(1)), m.group(2)
        body = [value]
        if value.strip() in ('|', '>', '|-', '>-', ''):
            for nxt in lines[i + 1:]:
                if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                    break
                body.append(nxt)
        out.append('\n'.join(body))
    return out


def _code(text):
    return '\n'.join(ln for ln in text.splitlines() if not ln.lstrip().startswith('#'))


def jobs():
    body = WORKFLOW.split('\njobs:\n', 1)[1]
    heads = list(re.finditer(r'^  ([a-z][a-z0-9_-]*):\n', body, re.M))
    return {m.group(1): _code(body[m.start():heads[i + 1].start() if i + 1 < len(heads) else len(body)])
            for i, m in enumerate(heads)}


def steps(job):
    return re.split(r'\n(?=      - )', job)[1:]


def permissions(block, indent):
    m = re.search(rf'^{" " * indent}permissions:\n((?:{" " * (indent + 2)}\S.*\n?)+)', block, re.M)
    assert m, block[:200]
    return dict(re.findall(r'([a-z-]+): (read|write|none)', m.group(1)))


def test_triggers():
    head = _code(WORKFLOW.split('\njobs:\n', 1)[0])
    assert re.search(r'^  push:\n    branches: \[main\]$', head, re.M)
    assert re.search(r'^  workflow_dispatch:\n    inputs:\n      dry_run:\n', head, re.M)
    assert re.search(r'^        type: boolean\n        default: false$', head, re.M)
    crons = re.findall(r"^\s+- cron: '([^']+)'", head, re.M)
    assert len(crons) == 1
    minute, *rest = crons[0].split()
    # hourly, away from :00 and :30
    assert minute.isdigit() and int(minute) not in (0, 30) and 0 < int(minute) < 60
    assert rest == ['*', '*', '*', '*']
    assert 'pull_request' not in head


def test_every_job_is_guarded_and_only_main_syncs():
    js = jobs()
    assert set(js) == {'build', 'sync'}
    for name, job in js.items():
        cond = re.search(r'^    if: (.+)$', job, re.M).group(1)
        assert "github.repository == 'PegaProx/project-pegaprox'" in cond, name
    assert "github.ref == 'refs/heads/main'" in re.search(r'^    if: (.+)$', js['sync'], re.M).group(1)
    assert re.search(r'^    needs: build$', js['sync'], re.M)


def test_concurrency_never_cancels_a_sync():
    m = re.search(r'^concurrency:\n  group: (.+)\n  cancel-in-progress: (\w+)$', WORKFLOW, re.M)
    assert m and m.group(2) == 'false'
    assert 'mirror' in m.group(1) and 'github.event' not in m.group(1)


def test_permissions_are_narrow():
    assert permissions(WORKFLOW.split('\njobs:\n', 1)[0] + '\n', 0) == {'contents': 'read'}
    js = jobs()
    assert permissions(js['build'], 4) == {'contents': 'read', 'id-token': 'write', 'attestations': 'write'}
    assert permissions(js['sync'], 4) == {'contents': 'read'}


def test_the_secret_lives_in_the_mirror_environment_and_one_step():
    js = jobs()
    code = _code(WORKFLOW)
    assert code.count('secrets.') == 1
    assert re.search(r'^    environment:\n      name: mirror$', js['sync'], re.M)
    assert 'environment' not in js['build'] and 'secrets.' not in js['build']
    holders = [s for s in steps(js['sync']) if 'secrets.' in s]
    assert len(holders) == 1
    step = holders[0]
    assert re.search(r'^        env:\n(?:          .*\n)*?          BUNNY_STORAGE_PASSWORD: '
                     r'\$\{\{ secrets\.BUNNY_STORAGE_PASSWORD \}\}$', step, re.M)
    assert 'uses:' not in step, 'no action gets the secret'
    assert 'python3 -I .github/scripts/mirror_to_bunny.py' in step


def test_every_action_is_pinned_and_the_attest_pin_is_the_repos():
    uses = re.findall(r'^\s*(?:- )?uses:\s*(\S+)\s*(#.*)?$', _code(WORKFLOW), re.M)
    assert uses
    for ref, comment in uses:
        assert re.fullmatch(r'[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}', ref), ref
        assert re.fullmatch(r'# v\d+\.\d+\.\d+', comment.strip()), (ref, comment)
    ours = {r for r, _ in uses if r.startswith('actions/attest@')}
    assert len(ours) == 1
    elsewhere = set()
    for p in WF_DIR.glob('*.yml'):
        if p.name != 'mirror.yml':
            elsewhere |= set(re.findall(r'uses:\s*(actions/attest@[0-9a-f]{40})', p.read_text(encoding='utf-8')))
    assert ours == elsewhere


def test_checkouts_keep_no_credentials():
    found = 0
    for job in jobs().values():
        for step in steps(job):
            if 'actions/checkout@' in step:
                found += 1
                assert re.search(r'^          persist-credentials: false$', step, re.M)
                assert re.search(r'^          fetch-depth: 1$', step, re.M)
    assert found == 2


def test_no_expression_inside_a_run_block():
    blocks = run_blocks(WORKFLOW)
    assert len(blocks) == 4
    for b in blocks:
        assert '${{' not in b, b
    # counterproof for the scanner
    sample = 'steps:\n  - name: x\n    run: |\n      echo hi\n      echo ${{ github.event.head_commit.message }}\n'
    assert any('${{' in b for b in run_blocks(sample))


def test_build_attests_then_sync_checks_the_digest():
    js = jobs()
    build, sync = js['build'], js['sync']
    assert build.index('--tree-only') < build.index('actions/attest@')
    attest = next(s for s in steps(build) if 'actions/attest@' in s)
    assert "github.ref == 'refs/heads/main'" in attest
    assert 'subject-path: ${{ runner.temp }}/mirror/archive/main.tar.gz' in attest
    assert 'digest: ${{ steps.tree.outputs.digest }}' in build
    assert 'ATTESTED_SHA256: ${{ needs.build.outputs.digest }}' in sync
    assert '--expect-archive-sha256 "$ATTESTED_SHA256"' in sync and '--tree-only' not in sync
    assert 'DRY_RUN: ${{ inputs.dry_run }}' in sync
    assert re.search(r'if \[ "\$DRY_RUN" = true \]; then\n\s+args\+=\(--dry-run\)', sync)
    # the checkout of main is HEAD and origin/main at once; nothing waves the check through
    assert '--any-ref' not in WORKFLOW and '--ref' not in sync
    # the check for an earlier attestation asks for this workflow on main, nothing looser
    seen = next(s for s in steps(build) if 'gh attestation verify' in s)
    assert '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/mirror.yml"' in seen
    assert '--source-ref refs/heads/main' in seen and '--deny-self-hosted-runners' in seen


def test_a_rerun_of_an_old_commit_leaves_the_zone_alone():
    sync = steps(jobs()['sync'])
    head = next(s for s in sync if 'id: head' in s)
    assert 'gh api "repos/$GITHUB_REPOSITORY/branches/main" --jq .commit.sha' in head
    assert 'if [ "$head" = "$GITHUB_SHA" ]; then' in head
    assert "echo 'current=false'" in head and 'exit 1' not in head
    # the guard comes first, and everything after it waits for its answer
    assert sync.index(head) == 0
    for s in sync[1:]:
        assert "if: steps.head.outputs.current == 'true'" in s, s[:80]


def test_the_watchdog_knows_the_mirror_as_a_publisher():
    assert 'mirror.yml' in BASELINE['workflows']['publishers']
    assert 'mirror.yml' not in BASELINE['workflows'].get('attach_to_releases', [])
    fallback = (WF_DIR / 'watchdog.yml').read_text(encoding='utf-8')
    assert 'mirror.yml' in re.search(r"publishers='([^']+)'", fallback).group(1).split()


def test_the_watchdog_alarms_unless_the_environment_deploys_from_main_only():
    # the environment is what keeps the password from other branches, and GitHub creates
    # an open one by itself; the baseline makes a missing or loosened one an alarm
    name = re.search(r'^    environment:\n      name: (\S+)$', jobs()['sync'], re.M).group(1)
    assert BASELINE['environments'][name] == {
        'deployment_branch_policy': {'custom_branch_policies': True, 'protected_branches': False},
        'branch_policies': [['main', 'branch']],
    }
    # counterproof: the signing environment next to it also lets v* tags in, this one not
    assert ['v*', 'tag'] in BASELINE['environments']['apt-signing']['branch_policies']


def test_the_doc_says_how_it_works():
    doc = (ROOT / 'docs' / 'update-mirror.md').read_text(encoding='utf-8')
    for must in ('BUNNY_STORAGE_PASSWORD', '`mirror`', 'dry_run', '--tree-only',
                 'gh attestation verify main.tar.gz -R PegaProx/project-pegaprox', 'SHA256SUMS'):
        assert must in doc, must
    minute = re.search(r"- cron: '(\d+) ", WORKFLOW).group(1)
    assert f':{minute}' in doc


def test_the_doc_says_how_to_set_up_the_environment():
    doc = (ROOT / 'docs' / 'update-mirror.md').read_text(encoding='utf-8')
    setup = doc.split('## Setting up\n', 1)[1].split('\n## ', 1)[0]
    for must in ('Settings, Environments', 'name `mirror`', 'Selected branches', 'rule `main`',
                 'Environment secrets', 'BUNNY_STORAGE_PASSWORD', 'Never as a repository secret',
                 'Only then merge to `main`'):
        assert must in setup, must
    # and the limits no longer say the environment is left out of the baseline
    assert 'not in the watchdog baseline' not in doc


def test_every_documented_command_mirrors_origin_main():
    # --ref defaults to HEAD, and a maintainer's checkout is on Testing
    doc = (ROOT / 'docs' / 'update-mirror.md').read_text(encoding='utf-8')
    commands = [ln for ln in doc.splitlines() + mirror.__doc__.splitlines()
                if ln.startswith('    ') and 'mirror_to_bunny.py' in ln]
    assert len(commands) == 5, commands
    for ln in commands:
        assert '--ref origin/main' in ln, ln


def test_house_rules_in_the_new_files():
    files = [ROOT / '.github' / 'scripts' / 'mirror_to_bunny.py', WF_DIR / 'mirror.yml',
             ROOT / 'docs' / 'update-mirror.md', Path(__file__)]
    # spelled out piecewise, or this file would trip over its own list
    banned = [chr(0x2014), chr(0x2013), 'VM' + 'ware', 'v' + 'Center']
    for p in files:
        text = p.read_text(encoding='utf-8')
        for word in banned:
            assert word not in text, (p.name, word)
    for p in files[:2]:
        assert 'NS Nov 2026' in p.read_text(encoding='utf-8'), p.name
