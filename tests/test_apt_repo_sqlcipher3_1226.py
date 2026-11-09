"""#1226 - our APT repository carries python3-sqlcipher3, and its smoke test checks encryption.

debian/control depends on python3-sqlcipher3, which Debian does not package: an apt install
from apt.pegaprox.com failed on that Depends. The repo now builds it from upstream's manylinux
wheels of sqlcipher3 (SQLCipher built in), pinned by hash like the other two, one package per
architecture and tied to trixie's Python, where the other repo ships the x86_64 build as
Architecture: all. The smoke test used to say "no sqlcipher3 in Debian"; it now checks that
a fresh install starts with a SQLCipher database and its own key in /etc/pegaprox.

NS Nov 2026
"""
import base64
import email.parser
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import zipfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MY_GID = os.getgid()


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


debs = _load('build_python_debs_1226', 'packaging/apt/build-python-debs.py')
smoke = _load('smoke_encrypted_1226', 'packaging/apt/smoke_encrypted.py')


def _read(*rel):
    with open(os.path.join(ROOT, *rel), encoding='utf-8') as fh:
        return fh.read()


# --- the package ---------------------------------------------------------------------------

def test_a_manylinux_wheel_becomes_a_package_of_its_architecture_and_python():
    spec, name, version, arch, base = debs._wheel('sqlcipher3-0.6.4-cp313-cp313-manylinux_2_28_x86_64.whl')
    assert (spec['deb'], name, version, arch) == ('python3-sqlcipher3', 'sqlcipher3', '0.6.4', 'amd64')
    assert base == ['python3 (>= 3.13~)', 'python3 (<< 3.14)', 'libc6 (>= 2.28)']
    assert debs._wheel('sqlcipher3-0.6.4-cp313-cp313-manylinux_2_28_aarch64.whl')[3] == 'arm64'
    assert debs._wheel('flask_sock-0.7.0-py3-none-any.whl')[3:] == ('all', ['python3:any'])


@pytest.mark.parametrize('fname', [
    'sqlcipher3-0.6.4-py3-none-any.whl',                         # a pure build of the binary one
    'flask_sock-0.7.0-cp313-cp313-manylinux_2_28_x86_64.whl',    # a binary build of a pure one
    'sqlcipher3-0.6.4-cp313-cp313-manylinux_2_28_i686.whl',      # a machine the repo does not carry
    'sqlcipher3-0.6.4-cp313-cp313-musllinux_1_2_x86_64.whl',
    'somethingelse-1.0-py3-none-any.whl',
])
def test_any_other_wheel_stops_the_build(fname):
    with pytest.raises(SystemExit):
        debs._wheel(fname)


def test_the_build_wants_the_binary_one_for_every_architecture(tmp_path):
    for f in ('flask_sock-0.7.0-py3-none-any.whl', 'xenapi-26.20.0-py3-none-any.whl',
              'sqlcipher3-0.6.4-cp313-cp313-manylinux_2_28_x86_64.whl'):
        (tmp_path / f).write_bytes(b'')
    with pytest.raises(SystemExit) as e:
        debs.main(['x', str(tmp_path), str(tmp_path / 'out')])
    assert "('sqlcipher3', 'arm64')" in str(e.value)


def _fake_wheel(path, name='sqlcipher3', version='0.6.4', tag='cp313-cp313-manylinux_2_28_x86_64',
                purelib=False):
    files = {
        f'{name}/__init__.py': b'from .dbapi2 import *\n',
        f'{name}/_sqlite3.cpython-313-x86_64-linux-gnu.so': b'\x7fELF not really',
        f'{name}-{version}.dist-info/METADATA': f'Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n'.encode(),
        f'{name}-{version}.dist-info/WHEEL': (f'Wheel-Version: 1.0\nRoot-Is-Purelib: {str(purelib).lower()}\n'
                                              f'Tag: {tag}\n').encode(),
    }
    record = ''.join(f'{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b"=").decode()},{len(d)}\n'
                     for n, d in files.items()) + f'{name}-{version}.dist-info/RECORD,,\n'
    files[f'{name}-{version}.dist-info/RECORD'] = record.encode()
    with zipfile.ZipFile(path, 'w') as zf:
        for n, d in files.items():
            zi = zipfile.ZipInfo(n, date_time=(2026, 10, 13, 17, 57, 0))
            zf.writestr(zi, d)
    return path


@pytest.mark.skipif(not shutil.which('dpkg-deb'), reason='needs dpkg-deb')
def test_the_binary_package_names_its_architecture_python_and_glibc(tmp_path):
    whl = _fake_wheel(tmp_path / 'sqlcipher3-0.6.4-cp313-cp313-manylinux_2_28_x86_64.whl')
    out = debs.build(str(whl), str(tmp_path / 'out'))
    assert os.path.basename(out) == 'python3-sqlcipher3_0.6.4-0pegaprox1_amd64.deb'
    fields = email.parser.Parser().parsestr(subprocess.run(
        ['dpkg-deb', '-f', out], capture_output=True, text=True, check=True).stdout)
    assert fields['Architecture'] == 'amd64'
    assert fields['Depends'] == 'python3 (>= 3.13~), python3 (<< 3.14), libc6 (>= 2.28)'
    listing = subprocess.run(['dpkg-deb', '-c', out], capture_output=True, text=True, check=True).stdout
    assert './usr/lib/python3/dist-packages/sqlcipher3/_sqlite3.cpython-313-x86_64-linux-gnu.so' in listing
    assert './usr/share/doc/python3-sqlcipher3/copyright' in listing
    # the same wheel gives the same bytes
    again = debs.build(str(whl), str(tmp_path / 'again'))
    with open(out, 'rb') as a, open(again, 'rb') as b:
        assert a.read() == b.read()


def test_a_binary_wheel_that_says_it_is_pure_is_refused(tmp_path):
    whl = _fake_wheel(tmp_path / 'sqlcipher3-0.6.4-cp313-cp313-manylinux_2_28_x86_64.whl', purelib=True)
    with pytest.raises(SystemExit) as e:
        debs.build(str(whl), str(tmp_path / 'out'))
    assert 'Root-Is-Purelib' in str(e.value)


def test_the_workflow_downloads_a_wheel_for_every_architecture_of_the_package():
    build = _read('.github', 'workflows', 'apt-repo.yml')
    m = re.search(r'for platform in ([^;]+); do\n(.*?)\n\s*done', build, re.S)
    assert m, 'the per-platform download is gone'
    assert sorted(m.group(1).split()) == sorted(f'manylinux_2_28_{machine}' for machine in debs.ARCHES)
    loop = ' '.join(m.group(2).replace('\\\n', ' ').split())
    for part in ('--require-hashes', '--no-deps', '--only-binary=:all:', '--platform "$platform"',
                 '--python-version 3.13', '--implementation cp', '--abi cp313',
                 '-r packaging/apt/python-debs/requirements.txt'):
        assert part in loop, part
    # the Python of the wheels is trixie's, the one the Depends ties the package to
    pins = _read('packaging', 'apt', 'python-debs', 'requirements.txt')
    assert re.search(r'^sqlcipher3==0\.6\.4 \\$', pins, re.M)


def test_the_repo_lists_a_package_of_one_architecture_in_its_index():
    script = _read('packaging', 'apt', 'build-apt-repo.sh')
    assert 'binary-*/Packages' in script
    publish = _read('.github', 'workflows', 'apt-repo.yml')
    assert '"$site"/dists/trixie/main/binary-*/Packages' in publish


# --- the smoke test ------------------------------------------------------------------------------

KEY = base64.urlsafe_b64encode(bytes(range(32)))


def _status(**over):
    st = {'keystore': {'ok': True, 'source': '/etc/pegaprox/secret.key',
                       'source_path': '/etc/pegaprox/secret.key', 'tier': 4, 'is_legacy': False},
          'db': {'backend': 'sqlcipher', 'encrypted_at_rest': True,
                 'files': {'/var/lib/pegaprox/config/pegaprox.db': 'encrypted',
                           '/var/lib/pegaprox/config/syslog.db': 'missing'}}}
    for path, value in over.items():
        part, key = path.split('__')
        st[part][key] = value
    return st


def _rootfs(tmp_path, key=KEY, mode=0o640, fernet=None):
    root = tmp_path / 'rootfs'
    (root / 'etc' / 'pegaprox').mkdir(parents=True)
    (root / 'var' / 'lib' / 'pegaprox' / 'config').mkdir(parents=True)
    (root / 'etc' / 'group').write_text(f'root:x:0:\npegaprox:x:{MY_GID}:\n')
    k = root / 'etc' / 'pegaprox' / 'secret.key'
    k.write_bytes(key)
    k.chmod(mode)
    (root / 'var' / 'lib' / 'pegaprox' / 'config' / '.pegaprox.key').write_bytes(
        fernet or base64.urlsafe_b64encode(bytes(range(1, 33))))
    (root / 'var' / 'lib' / 'pegaprox' / 'config' / 'pegaprox.db').write_bytes(os.urandom(4096))
    return root


def test_a_fresh_encrypted_install_passes(tmp_path):
    assert smoke.check(_status(), str(_rootfs(tmp_path)), owner=os.getuid()) == []


@pytest.mark.parametrize('over,says', [
    ({'keystore__source_path': '/var/lib/pegaprox/config/.pegaprox.key', 'keystore__tier': 6,
      'keystore__is_legacy': True}, 'not /etc/pegaprox/secret.key'),
    ({'db__backend': 'sqlite-plain'}, 'python3-sqlcipher3 does not import'),
    ({'db__files': {'/var/lib/pegaprox/config/pegaprox.db': 'plain'}, 'db__encrypted_at_rest': False},
     'pegaprox.db is plain'),
])
def test_what_keystore_status_must_not_say(tmp_path, over, says):
    bad = smoke.check(_status(**over), str(_rootfs(tmp_path)), owner=os.getuid())
    assert len(bad) == 1 and says in bad[0], bad


def test_the_key_next_to_the_database_fails(tmp_path):
    """The case the PR is about: the database key in the config directory."""
    bad = smoke.check(_status(), str(_rootfs(tmp_path, fernet=KEY + b'\n')), owner=os.getuid())
    assert bad == ['/var/lib/pegaprox/config/.pegaprox.key holds the master key, next to the database']


def test_a_key_file_the_service_group_does_not_get_fails(tmp_path):
    bad = smoke.check(_status(), str(_rootfs(tmp_path, mode=0o600)), owner=os.getuid())
    assert len(bad) == 1 and 'not 0640' in bad[0]
    bad = smoke.check(_status(), str(_rootfs(tmp_path / 'b')), owner=os.getuid() + 1)
    assert len(bad) == 1 and 'not 0640' in bad[0]


def test_the_script_reads_the_status_file_and_fails_loudly(tmp_path):
    root = _rootfs(tmp_path)
    status = tmp_path / 'status.json'
    status.write_text('some log line\n' + json.dumps(_status(db__backend='sqlite-plain')))
    r = subprocess.run(['python3', '-I', os.path.join(ROOT, 'packaging', 'apt', 'smoke_encrypted.py'),
                        str(status), str(root)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 1
    assert '::error::the database backend is sqlite-plain' in r.stdout
    status.write_text('')
    r = subprocess.run(['python3', '-I', os.path.join(ROOT, 'packaging', 'apt', 'smoke_encrypted.py'),
                        str(status), str(root)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 1 and 'no --keystore-status JSON' in r.stderr


def test_the_workflow_runs_the_check_after_the_boot():
    build = _read('.github', 'workflows', 'apt-repo.yml')
    status_at = build.index('--keystore-status \\\n            > "$smoke/keystore-status.json"')
    check_at = build.index('sudo python3 -I packaging/apt/smoke_encrypted.py "$smoke/keystore-status.json" "$root"')
    assert status_at < build.index('machinectl poweroff pegaprox-smoke') < check_at
    assert 'no sqlcipher3 in Debian' not in build
    install = _read('packaging', 'apt', 'smoke-install.sh')
    assert 'for pkg in python3-flask-sock python3-xenapi python3-sqlcipher3; do' in install
