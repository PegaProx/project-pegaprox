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
import sys
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
                purelib=False, machine='x86_64'):
    files = {
        f'{name}/__init__.py': b'from .dbapi2 import *\n',
        f'{name}/_sqlite3.cpython-313-{machine}-linux-gnu.so': b'\x7fELF not really',
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


# --- one architecture, for the appliance images (NS Nov 2026) ------------------------------------
# release-images.yml builds the python3-sqlcipher3 of each leg with build-sqlcipher3-deb.sh: the
# wheels pip fetches for that one machine, build-python-debs.py --arch.

HELPER = os.path.join(ROOT, 'packaging', 'apt', 'build-sqlcipher3-deb.sh')
needs_dpkg_deb = pytest.mark.skipif(not shutil.which('dpkg-deb'), reason='needs dpkg-deb')


def _wheels(d, machines=('aarch64',), module=None):
    d.mkdir()
    _fake_wheel(d / 'flask_sock-0.7.0-py3-none-any.whl', name='flask_sock', version='0.7.0',
                tag='py3-none-any', purelib=True)
    _fake_wheel(d / 'xenapi-26.20.0-py3-none-any.whl', name='xenapi', version='26.20.0',
                tag='py3-none-any', purelib=True)
    for m in machines:
        _fake_wheel(d / f'sqlcipher3-0.6.4-cp313-cp313-manylinux_2_28_{m}.whl',
                    tag=f'cp313-cp313-manylinux_2_28_{m}', machine=module or m)
    return d


@needs_dpkg_deb
def test_with_arch_the_build_takes_the_wheels_of_that_one_machine(tmp_path):
    out = tmp_path / 'out'
    debs.main(['x', '--arch', 'arm64', str(_wheels(tmp_path / 'w')), str(out)])
    assert sorted(os.listdir(out)) == ['python3-flask-sock_0.7.0-0pegaprox1_all.deb',
                                       'python3-sqlcipher3_0.6.4-0pegaprox1_arm64.deb',
                                       'python3-xenapi_26.20.0-0pegaprox1_all.deb']


@pytest.mark.parametrize('arch,machines', [
    ('amd64', ('aarch64',)),             # the wheel of another machine
    ('arm64', ('x86_64', 'aarch64')),    # one too many
    ('arm64', ()),
])
def test_with_arch_the_wheels_have_to_be_exactly_those_of_that_machine(tmp_path, arch, machines):
    with pytest.raises(SystemExit) as e:
        debs.main(['x', '--arch', arch, str(_wheels(tmp_path / 'w', machines)), str(tmp_path / 'out')])
    assert str(e.value).startswith("build-python-debs: expected one wheel each for [('flask-sock', 'all'), "
                                   f"('sqlcipher3', '{arch}'), ('xenapi', 'all')], found")
    assert not (tmp_path / 'out').exists()


@pytest.mark.parametrize('args', [
    ['--arch', 'i386', 'w', 'o'], ['--arch', 'arm64', 'w'], ['--arch', 'arm64'], ['--arch', 'w', 'o'],
    ['w'], ['w', 'o', 'x'],
])
def test_a_wrong_command_line_is_refused(args):
    with pytest.raises(SystemExit) as e:
        debs.main(['x', *args])
    assert str(e.value).startswith('usage: build-python-debs.py [--arch amd64|arm64]')


def _pip_stub(tmp_path, wheels):
    """python3 for build-sqlcipher3-deb.sh: `-m pip download` logs its arguments and copies the
    wheels of the --platform it was asked for out of `wheels`; anything else is this Python."""
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    log = tmp_path / 'pip.log'
    stub = bindir / 'python3'
    stub.write_text(
        '#!/bin/sh\n'
        'if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then\n'
        f'  echo "$*" >> "{log}"\n'
        '  while [ $# -gt 0 ]; do\n'
        '    case $1 in --platform) platform=$2; shift ;; -d) dest=$2; shift ;; esac\n'
        '    shift\n'
        '  done\n'
        '  mkdir -p "$dest"\n'
        f'  cp "{wheels}"/*-py3-none-any.whl "{wheels}"/*"_${{platform#manylinux_2_28_}}.whl" "$dest"/\n'
        '  exit 0\n'
        'fi\n'
        f'exec "{sys.executable}" "$@"\n')
    stub.chmod(0o755)
    return bindir, log


def _helper(tmp_path, arch, wheels):
    bindir, log = _pip_stub(tmp_path, wheels)
    (tmp_path / 'tmp').mkdir()
    r = subprocess.run(['bash', HELPER, arch, str(tmp_path / 'out')], capture_output=True, text=True,
                       timeout=60, env={'PATH': f'{bindir}:/usr/bin:/bin', 'TMPDIR': str(tmp_path / 'tmp')})
    return r, log


@needs_dpkg_deb
@pytest.mark.parametrize('arch,machine', [('amd64', 'x86_64'), ('arm64', 'aarch64')])
def test_the_image_step_builds_the_package_of_its_arch_from_the_pins(tmp_path, arch, machine):
    r, log = _helper(tmp_path, arch, _wheels(tmp_path / 'w', ('x86_64', 'aarch64')))
    assert r.returncode == 0, r.stdout + r.stderr
    deb = tmp_path / 'out' / 'python3-sqlcipher3.deb'
    assert os.listdir(tmp_path / 'out') == ['python3-sqlcipher3.deb']
    fields = subprocess.run(['dpkg-deb', '-f', str(deb), 'Architecture', 'Version'],
                            capture_output=True, text=True, check=True).stdout
    assert fields == f'Architecture: {arch}\nVersion: 0.6.4-0pegaprox1\n'
    listing = subprocess.run(['dpkg-deb', '-c', str(deb)], capture_output=True, text=True, check=True).stdout
    assert f'/sqlcipher3/_sqlite3.cpython-313-{machine}-linux-gnu.so' in listing
    # one download, for that machine and trixie's Python, of the file apt.pegaprox.com is built from
    call = log.read_text().split()
    assert ' '.join(call).startswith('-m pip download ')
    for flag in ('--require-hashes', '--no-deps', '--only-binary=:all:'):
        assert flag in call, flag
    assert call[call.index('--platform') + 1] == f'manylinux_2_28_{machine}'
    assert call[call.index('--implementation') + 1] == 'cp'
    assert call[call.index('--python-version') + 1] == '3.13'
    assert call[call.index('--abi') + 1] == 'cp313'
    assert call[call.index('-r') + 1] == os.path.join(ROOT, 'packaging', 'apt', 'python-debs', 'requirements.txt')
    assert not os.listdir(tmp_path / 'tmp')


@needs_dpkg_deb
def test_a_package_for_arm64_with_the_x86_64_module_is_refused(tmp_path):
    """What the CDN package was: a module of the wrong machine under a name that installs."""
    r, _ = _helper(tmp_path, 'arm64', _wheels(tmp_path / 'w', ('aarch64',), module='x86_64'))
    assert r.returncode == 1
    assert 'python3-sqlcipher3_0.6.4-0pegaprox1_arm64.deb has no aarch64 module' in r.stderr
    assert not (tmp_path / 'out').exists()


def test_the_image_step_knows_no_other_arch(tmp_path):
    r, log = _helper(tmp_path, 'i386', tmp_path)
    assert r.returncode == 1 and 'no wheel machine for i386' in r.stderr
    assert not log.exists()


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


def test_a_package_that_does_not_load_is_reported_with_its_reason(tmp_path):
    why = "ModuleNotFoundError: No module named 'sqlcipher3._sqlite3'"
    bad = smoke.check(_status(db__backend='sqlite-plain', db__sqlcipher_error=why),
                      str(_rootfs(tmp_path)), owner=os.getuid())
    assert bad == [f'the database backend is sqlite-plain: python3-sqlcipher3 is installed and '
                   f'does not load ({why})']


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
