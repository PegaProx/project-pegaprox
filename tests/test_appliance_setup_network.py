"""The VM appliance's setup puts the search domain where systemd-resolved reads it.

The appliance resolves through systemd-resolved, and resolved hands a short host name
(an ESXi host added as esx01) to the DNS servers only with a search domain on the link.
The wizard never asked for one, and wrote its nameservers into /etc/resolv.conf, which is
resolved's stub and was rewritten within seconds. Both wizards now take an optional search
domain into 10-pegaprox.network and leave resolv.conf alone. The image cleanup also drops
the netplan file cloud-init wrote for the smoke boot's NIC.

The scripts run here as the workflow ships them, with /etc moved into a temp dir and the
system tools stubbed.
MK Nov 2026

Further down: each image gets the python3-sqlcipher3 of its own architecture, and its smoke
test fails unless PegaProx reports SQLCipher (#1226). NS Nov 2026
"""
import importlib.util
import json
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = os.path.join(ROOT, '.github', 'workflows', 'release-images.yml')
NET = 'etc/systemd/network/10-pegaprox.network'

STUBS = {
    'ip': """#!/bin/sh
case "$*" in
  "-o link show") printf '1: lo: <LOOPBACK,UP>\\n2: ens18: <BROADCAST,MULTICAST,UP>\\n';;
  *) printf '    inet 10.99.99.10/24 brd 10.99.99.255 scope global ens18\\n';;
esac
""",
    'systemctl': '#!/bin/sh\nexit 0\n',
    'sleep': '#!/bin/sh\nexit 0\n',
    'clear': '#!/bin/sh\nexit 0\n',
    'passwd': '#!/bin/sh\nexit 0\n',
    'sqlite3': '#!/bin/sh\nexit 0\n',
    'sudo': '#!/bin/sh\nexec "$@"\n',
}


def _read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def _dedent(block, indent):
    return ''.join(line[len(indent):] if line.startswith(indent) else line.lstrip(' ')
                   for line in block.splitlines(True))


def _heredoc(name):
    """The script the workflow writes with `cat > name <<'TAG'`, as it lands in the image."""
    m = re.search(rf"^( *)cat > {re.escape(name)} <<'(\w+)'\n(.*?)^\1\2$", _read(WF), re.M | re.S)
    assert m, f'{name} is not written by release-images.yml'
    return _dedent(m.group(3), m.group(1))


def _cleanup_scrub():
    """The part of the cleanup step that works on the mounted image, from R= to the sync."""
    text = _read(WF)
    step = text[text.index('- name: Zustand des Testboots aus dem Image entfernen'):]
    m = re.search(r'^( *)R=/mnt/img\n(.*?)^\1sudo sync$', step, re.M | re.S)
    assert m, 'the cleanup step lost its R=/mnt/img ... sudo sync part'
    return _dedent(m.group(2), m.group(1))


@pytest.fixture
def sandbox(tmp_path):
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for name, body in STUBS.items():
        p = bindir / name
        p.write_text(body)
        p.chmod(0o755)
    (tmp_path / 'root').mkdir()
    return tmp_path


def _run(sandbox, script, args=(), stdin='', env=None, move_etc=True):
    root = sandbox / 'root'
    src = script.replace('/etc/', f'{root}/etc/') if move_etc else script
    src = src.replace('[ "$EUID" -ne 0 ]', 'false')
    path = sandbox / 'script.sh'
    path.write_text(src)
    e = {'PATH': f"{sandbox / 'bin'}:/usr/bin:/bin", 'HOME': str(sandbox), 'TERM': 'dumb'}
    e.update(env or {})
    return subprocess.run(['bash', str(path), *args], input=stdin, capture_output=True,
                          text=True, env=e, timeout=30)


def _network(sandbox):
    return (sandbox / 'root' / NET).read_text()


def _domains_ok(value):
    fn = re.search(r'^valid_domains\(\) \{\n.*?^\}\n', _heredoc('pegaprox-setup'), re.M | re.S)
    assert fn, 'pegaprox-setup has no valid_domains'
    r = subprocess.run(['bash', '-c', fn.group(0) + 'valid_domains "$1"', '_', value], timeout=10)
    return r.returncode == 0


@pytest.mark.parametrize('name', ['pegaprox-setup', 'pegaprox-setup-auto'])
def test_the_scripts_parse_and_leave_resolv_conf_alone(name):
    script = _heredoc(name)
    subprocess.run(['bash', '-n'], input=script, text=True, check=True, timeout=10)
    assert not re.search(r'>\s*/etc/resolv\.conf', script)


@pytest.mark.parametrize('value', ['', 'example.lan', 'lan', 'example.lan corp.example.lan',
                                   'xn--bcher-kva.example'])
def test_a_search_domain_is_taken(value):
    assert _domains_ok(value)


@pytest.mark.parametrize('value', ['-bad.lan', 'bad-.lan', 'a..lan', 'exa_mple.lan', 'domain!',
                                   'example.lan.', 'a' * 64 + '.lan', 'ok.lan bad!'])
def test_a_broken_search_domain_is_refused(value):
    assert not _domains_ok(value)


def test_the_wizard_writes_the_search_domain_next_to_the_static_address(sandbox):
    answers = ['', '1', '10.99.99.10', '24', '10.99.99.1', '10.99.99.53 10.99.99.54',
               'bad_domain!', 'example.lan corp.example.lan', 'y', '1', '', 'n']
    r = _run(sandbox, _heredoc('pegaprox-setup'), stdin='\n'.join(answers) + '\n')
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'Invalid domain' in r.stdout
    assert _network(sandbox) == ('[Match]\nName=ens18\n\n[Network]\nAddress=10.99.99.10/24\n'
                                 'Gateway=10.99.99.1\nDNS=10.99.99.53\nDNS=10.99.99.54\n'
                                 'Domains=example.lan corp.example.lan\n')
    assert not (sandbox / 'root' / 'etc' / 'resolv.conf').exists()
    assert (sandbox / 'root' / 'etc' / 'pegaprox' / '.setup-complete').exists()


@pytest.mark.parametrize('domain,line', [('example.lan', 'Domains=example.lan\n'), ('', '')])
def test_the_wizard_asks_for_the_search_domain_with_dhcp_too(sandbox, domain, line):
    r = _run(sandbox, _heredoc('pegaprox-setup'), stdin='\n'.join(['', '2', domain, '1', '', 'n']) + '\n')
    assert r.returncode == 0, r.stdout + r.stderr
    assert _network(sandbox) == '[Match]\nName=ens18\n\n[Network]\nDHCP=yes\n' + line


def test_the_unattended_setup_writes_the_search_domain(sandbox):
    r = _run(sandbox, _heredoc('pegaprox-setup-auto'),
             ['--ip=10.99.99.10', '--cidr=24', '--gateway=10.99.99.1', '--dns=10.99.99.53',
              '--domain=example.lan'])
    assert r.returncode == 0, r.stdout + r.stderr
    assert _network(sandbox) == ('[Match]\nName=ens18\n\n[Network]\nAddress=10.99.99.10/24\n'
                                 'Gateway=10.99.99.1\nDNS=10.99.99.53\nDomains=example.lan\n')
    assert not (sandbox / 'root' / 'etc' / 'resolv.conf').exists()


def test_the_unattended_setup_takes_the_domain_from_the_environment_with_dhcp(sandbox):
    r = _run(sandbox, _heredoc('pegaprox-setup-auto'), ['--dhcp'],
             env={'PEGAPROX_DOMAIN': 'example.lan corp.example.lan'})
    assert r.returncode == 0, r.stdout + r.stderr
    assert _network(sandbox).endswith('DHCP=yes\nDomains=example.lan corp.example.lan\n')


def test_the_unattended_setup_refuses_a_broken_domain_before_it_touches_the_network(sandbox):
    r = _run(sandbox, _heredoc('pegaprox-setup-auto'),
             ['--ip=10.99.99.10', '--gateway=10.99.99.1', '--domain=ok.lan bad!'])
    assert r.returncode == 1
    assert 'invalid search domain: bad!' in r.stdout
    assert not (sandbox / 'root' / NET).exists()


def _smoke_boot_root(root):
    for d in ('etc/ssh', 'etc/netplan', 'etc/systemd/system/multi-user.target.wants', 'var/lib/pegaprox/config',
              'var/lib/cloud/instance', 'var/lib/dbus', 'var/log/journal/abc'):
        (root / d).mkdir(parents=True)
    (root / 'etc/passwd').write_text('root:x:0:0::/root:/bin/bash\n')
    (root / 'etc/machine-id').write_text('0123456789abcdef0123456789abcdef\n')
    (root / 'etc/ssh/ssh_host_ed25519_key').write_text('key')
    (root / 'var/lib/pegaprox/config/pegaprox.db').write_text('db')
    (root / 'etc/netplan/50-cloud-init.yaml').write_text(
        'network:\n  version: 2\n  ethernets:\n    ens3:\n      match:\n'
        '        macaddress: "52:54:00:12:34:56"\n      dhcp4: true\n')


def test_the_cleanup_drops_the_smoke_boots_netplan_file(sandbox):
    root = sandbox / 'root'
    _smoke_boot_root(root)
    script = f'R={root}\n' + _cleanup_scrub() + '[ "$FAIL" -eq 0 ] || exit 1\n'
    r = _run(sandbox, script, move_etc=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (root / 'etc/netplan/50-cloud-init.yaml').exists()
    assert (root / 'etc/netplan').is_dir()


def test_the_cleanup_refuses_an_image_that_still_has_it(sandbox):
    root = sandbox / 'root'
    _smoke_boot_root(root)
    scrub = _cleanup_scrub()
    keep = re.sub(r'^sudo rm -f "\$R/etc/netplan/50-cloud-init\.yaml"\n', '', scrub, flags=re.M)
    assert keep != scrub
    r = _run(sandbox, f'R={root}\n' + keep + '[ "$FAIL" -eq 0 ] || exit 1\n', move_etc=False)
    assert r.returncode == 1
    assert "the smoke boot's netplan file is in the image" in r.stdout


# --- NS Nov 2026: the port, and the master key of the smoke boot (#1226) ------------------------

def _port_stubs(sandbox, answer=0):
    log = sandbox / 'calls.log'
    for cmd, code in (('runuser', answer), ('sqlite3', 0)):
        p = sandbox / 'bin' / cmd
        p.write_text(f'#!/bin/sh\necho "$PWD {cmd} $*" >> "{log}"\nexit {code}\n')
        p.chmod(0o755)
    (sandbox / 'root' / 'var' / 'lib' / 'pegaprox').mkdir(parents=True)
    return log


def _with_state_dir(sandbox, script):
    return script.replace('/var/lib/pegaprox', f"{sandbox / 'root'}/var/lib/pegaprox")


@pytest.mark.parametrize('answer', [0, 4])
def test_the_wizard_sets_the_port_through_pegaprox(sandbox, answer):
    """The sqlite3 CLI cannot open the SQLCipher database the appliance has: the port goes
    in through the PegaProx CLI, as the service user in its directory."""
    log = _port_stubs(sandbox, answer)
    r = _run(sandbox, _with_state_dir(sandbox, _heredoc('pegaprox-setup')),
             stdin='\n'.join(['', '2', '', '2', '', 'n']) + '\n')
    assert r.returncode == 0, r.stdout + r.stderr
    calls = log.read_text().splitlines()
    assert calls == [f"{sandbox / 'root'}/var/lib/pegaprox runuser -u pegaprox -- "
                     '/usr/bin/pegaprox/pegaprox-wrapper --set-port 443']
    assert ('Port set to 443' in r.stdout) == (answer == 0)
    assert ('Could not set port automatically' in r.stdout) == (answer != 0)


@pytest.mark.parametrize('answer', [0, 4])
def test_the_unattended_setup_sets_the_port_through_pegaprox(sandbox, answer):
    log = _port_stubs(sandbox, answer)
    r = _run(sandbox, _with_state_dir(sandbox, _heredoc('pegaprox-setup-auto')), ['--dhcp', '--port=8443'])
    assert r.returncode == 0, r.stdout + r.stderr
    assert log.read_text().splitlines() == [
        f"{sandbox / 'root'}/var/lib/pegaprox runuser -u pegaprox -- /usr/bin/pegaprox/pegaprox-wrapper --set-port 8443"]
    assert ('Port set to 8443' in r.stdout) == (answer == 0)


def test_the_cleanup_drops_the_master_key_of_the_smoke_boot(sandbox):
    """The smoke boot installs the package with systemd running, so its postinst puts a
    master key in /etc/pegaprox. Shipped, every appliance would have that one key."""
    root = sandbox / 'root'
    _smoke_boot_root(root)
    (root / 'etc/pegaprox').mkdir()
    (root / 'etc/pegaprox/secret.key').write_text('smoke-boot key')
    (root / 'etc/pegaprox/secret.key.new.1234').write_text('half written')
    (root / 'etc/pegaprox/.setup-complete').write_text('')
    r = _run(sandbox, f'R={root}\n' + _cleanup_scrub() + '[ "$FAIL" -eq 0 ] || exit 1\n', move_etc=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert sorted(os.listdir(root / 'etc/pegaprox')) == ['.setup-complete']


def test_the_cleanup_refuses_an_image_with_a_master_key(sandbox):
    root = sandbox / 'root'
    _smoke_boot_root(root)
    (root / 'etc/pegaprox').mkdir()
    (root / 'etc/pegaprox/secret.key').write_text('smoke-boot key')
    scrub = _cleanup_scrub()
    keep = re.sub(r'^sudo sh -c "rm -f \$R/etc/pegaprox/secret\.key .*"\n', '', scrub, flags=re.M)
    assert keep != scrub
    r = _run(sandbox, f'R={root}\n' + keep + '[ "$FAIL" -eq 0 ] || exit 1\n', move_etc=False)
    assert r.returncode == 1
    assert 'the master key of the smoke boot is in the image' in r.stdout


# --- NS Nov 2026: python3-sqlcipher3 of the image's own architecture (#1226) --------------------
# The images took python3-sqlcipher3_0.6.4_all.deb from gyptazy's CDN. It holds the x86_64 module
# only: on arm64 it installed, the import failed and PegaProx ran on plain SQLite, and the smoke
# tests only waited for port 5000. Each leg now builds the package of its own arch from the pins
# of apt.pegaprox.com (packaging/apt/build-sqlcipher3-deb.sh), and every smoke test has PegaProx
# say which database backend it runs on (packaging/apt/smoke_backend.py).

HELPER = os.path.join(ROOT, 'packaging', 'apt', 'build-sqlcipher3-deb.sh')
REQS = os.path.join(ROOT, 'packaging', 'apt', 'python-debs', 'requirements.txt')
SMOKE_BACKEND = os.path.join(ROOT, 'packaging', 'apt', 'smoke_backend.py')
IMAGE_DEB = '/var/cache/pegaprox-image/python3-sqlcipher3.deb'
BUILD = 'bash packaging/apt/build-sqlcipher3-deb.sh "${{ matrix.arch }}" "$RUNNER_TEMP/sqlcipher3-deb"'
CHECK = 'python3 -I packaging/apt/smoke_backend.py "$RUNNER_TEMP/keystore-status.json"'


def _flat(text):
    return ' '.join(text.replace('\\\n', ' ').split())


def _job(name):
    m = re.search(rf'^  {re.escape(name)}:\n(.*?)(?=^  [a-z][\w-]*:$|\Z)', _read(WF), re.M | re.S)
    assert m, f'release-images.yml has no job {name}'
    return m.group(1)


def _step(job, name):
    text = _job(job)
    start = text.index(f'      - name: {name}\n')
    nxt = re.search(r'^      - (name|uses):', text[start + 1:], re.M)
    return text[start:start + 1 + nxt.start()] if nxt else text[start:]


def _from_line(step, first):
    """The run block of a step from the line holding `first` on, as the runner sees it."""
    at = step.rindex('\n', 0, step.index(first)) + 1
    return _dedent(step[at:], ' ' * 10)


def _definition():
    """The distrobuilder definition of build-lxc (an unquoted heredoc, the runner expands it)."""
    m = re.search(r'^( *)cat > packaging/lxc/pegaprox-lxc\.yaml <<YAML\n(.*?)^\1YAML$', _read(WF), re.M | re.S)
    assert m, 'build-lxc no longer writes its distrobuilder definition'
    return _dedent(m.group(2), m.group(1))


def test_no_image_takes_python3_sqlcipher3_from_the_cdn():
    wf = _read(WF)
    assert 'cdn.gyptazy.com/debian/python3-sqlcipher3' not in wf
    assert not re.search(r'python3-sqlcipher3_\S*_all\.deb', wf)
    assert '6f6c099beecc54f53808d94ed43c43d41e872a572ba3aff3b83c7a035f5e06c2' not in wf
    # the pins of the other two CDN packages stay as they were, in both jobs
    for pin in ('125ec5a4e2bbc10c57b7b9e3ab05aecda5edf1b8f6646aff4131cab441b53c24  python3-flask-sock_0.7.1_all.deb',
                'db36397c5db4448459dee349fc2a0b6f147ddf4b346dc8480687903c38fc822e  python3-xenapi_26.8.1_all.deb'):
        assert wf.count(pin) == 2, pin


@pytest.mark.parametrize('job,image_step', [('build-lxc', 'distrobuilder-Definition schreiben'),
                                            ('build-vm', 'Dateien per qemu-nbd einhängen')])
def test_both_image_jobs_build_it_for_the_arch_of_their_leg(job, image_step):
    text = _job(job)
    assert re.search(r'^      matrix:\n        arch: \[amd64, arm64\]$', text, re.M)
    assert BUILD in _step(job, 'python3-sqlcipher3 bauen')
    assert text.index('- name: python3-sqlcipher3 bauen') < text.index(f'- name: {image_step}')
    assert 'python3-pip' in _step(job, 'Tools installieren')


def test_the_build_step_takes_the_pins_of_the_apt_repo_and_keeps_no_copy_of_them():
    helper = _read(HELPER)
    flat = _flat(helper)
    for part in ('--require-hashes', '--no-deps', '--only-binary=:all:', '--platform "manylinux_2_28_$machine"',
                 '--python-version 3.13', '--implementation cp', '--abi cp313',
                 '-r "$here/python-debs/requirements.txt"',
                 'python3 -I "$here/build-python-debs.py" --arch "$arch" "$work/wheels" "$work/debs"'):
        assert part in flat, part
    spec = importlib.util.spec_from_file_location('build_python_debs_img', os.path.join(ROOT, 'packaging', 'apt',
                                                                                         'build-python-debs.py'))
    debs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(debs)
    assert dict(re.findall(r'^  (\w+)\) machine=(\w+) ;;$', helper, re.M)) == {a: m for m, a in debs.ARCHES.items()}
    pins = re.findall(r'--hash=sha256:([0-9a-f]{64})', _read(REQS))
    assert len(pins) == 4
    for text in (_read(WF), helper):
        assert not [p for p in pins if p in text]


def test_the_lxc_rootfs_gets_it_before_pegaprox():
    d = _definition()
    files = re.search(r'^files:\n(.*?)^\S', d, re.M | re.S)
    assert files, 'the definition has no files section'
    assert re.search(r'^  - generator: copy\n    source: \$\{RUNNER_TEMP\}/sqlcipher3-deb/python3-sqlcipher3\.deb\n'
                     rf'    path: {re.escape(IMAGE_DEB)}\n', files.group(1), re.M)
    # distrobuilder copies files in after post-packages: the install is a post-files action
    assert re.findall(r'^  - trigger: (\S+)$', d, re.M) == ['post-files']
    action = d[d.index('  - trigger: post-files'):]
    assert action.index(f'dpkg -i {IMAGE_DEB}\n') < action.index('rm -rf /var/cache/pegaprox-image\n') \
        < action.index('apt-get -y install pegaprox sshpass')


def _installer_stubs(sandbox):
    log = sandbox / 'calls.log'
    for cmd in ('apt-get', 'wget', 'dpkg', 'sha256sum', 'useradd', 'usermod', 'chpasswd', 'systemctl'):
        p = sandbox / 'bin' / cmd
        p.write_text(f'#!/bin/sh\necho "{cmd} $*" >> "{log}"\nexit 0\n')
        p.chmod(0o755)
    (sandbox / 'bin' / 'id').write_text('#!/bin/sh\nexit 1\n')
    (sandbox / 'bin' / 'id').chmod(0o755)
    (sandbox / 'bin' / 'runuser').write_text(
        f'#!/bin/sh\necho "$PWD runuser $*" >> "{log}"\nprintf \'{{\\n  "db": {{"backend": "sqlcipher"}}\\n}}\\n\'\n')
    (sandbox / 'bin' / 'runuser').chmod(0o755)
    return log


def test_the_vm_installer_installs_it_before_pegaprox_and_has_pegaprox_report_its_backend(sandbox):
    root = sandbox / 'root'
    for d in ('tmp', 'var/lib/pegaprox', 'var/cache/pegaprox-image'):
        (root / d).mkdir(parents=True)
    (root / IMAGE_DEB.lstrip('/')).write_bytes(b'the deb')
    log = _installer_stubs(sandbox)
    # /var and /tmp into the sandbox as well, in one pass
    script = re.sub(r'(?<![\w/])/(var|tmp)/', lambda m: f'{root}/{m.group(1)}/', _heredoc('install-pegaprox.sh'))
    r = _run(sandbox, script)
    assert r.returncode == 0, r.stdout + r.stderr
    calls = log.read_text().splitlines()
    assert calls.index(f'dpkg -i {root}{IMAGE_DEB}') < calls.index('apt-get -y install pegaprox sshpass')
    assert f'{root}/var/lib/pegaprox runuser -u pegaprox -- /usr/bin/pegaprox/pegaprox-wrapper --keystore-status' \
        in calls
    assert sorted(os.listdir(root / 'var/cache/pegaprox-image')) == ['keystore-status.json']
    assert json.loads((root / 'var/cache/pegaprox-image/keystore-status.json').read_text()) \
        == {'db': {'backend': 'sqlcipher'}}


def test_the_vm_job_puts_the_package_into_the_image():
    flat = _flat(_step('build-vm', 'Dateien per qemu-nbd einhängen'))
    assert (f'sudo install -D -m 0644 "$RUNNER_TEMP/sqlcipher3-deb/python3-sqlcipher3.deb" /mnt/img{IMAGE_DEB}'
            in flat)
    assert flat.index('sudo mount "$ROOT" /mnt/img') < flat.index(f'/mnt/img{IMAGE_DEB}') \
        < flat.index('sudo umount /mnt/img')


def test_the_cleanup_drops_what_the_build_brought_into_the_image(sandbox):
    root = sandbox / 'root'
    _smoke_boot_root(root)
    (root / 'var/cache/pegaprox-image').mkdir(parents=True)
    (root / 'var/cache/pegaprox-image/keystore-status.json').write_text('{}')
    r = _run(sandbox, f'R={root}\n' + _cleanup_scrub() + '[ "$FAIL" -eq 0 ] || exit 1\n', move_etc=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (root / 'var/cache/pegaprox-image').exists()
    assert (root / 'var/cache').is_dir()


def test_the_lxc_smoke_test_asks_pegaprox_on_both_archs():
    step = _step('build-lxc', 'Smoke-Test (Container starten + HTTP-Check)')
    flat = _flat(step)
    amd64 = ('sudo systemd-nspawn -D /tmp/ct/rootfs --quiet --pipe --register=no --user=pegaprox '
             '--chdir=/var/lib/pegaprox /usr/bin/pegaprox/pegaprox-wrapper --keystore-status '
             '> "$RUNNER_TEMP/keystore-status.json"')
    arm64 = ('sudo docker exec -u pegaprox -w /var/lib/pegaprox pegaprox-test /usr/bin/pegaprox/pegaprox-wrapper '
             '--keystore-status > "$RUNNER_TEMP/keystore-status.json"')
    # amd64: a second nspawn on the tree, once the booted one is gone; arm64: in the running container
    assert flat.index('NSPAWN_PID=$!') < flat.index('sudo machinectl terminate pegaprox-test') \
        < flat.index('ps -p "$NSPAWN_PID"') < flat.index(amd64)
    assert flat.index(arm64) < flat.index('sudo docker rm -f pegaprox-test')
    # and the check fails the step, after the port check
    assert step.startswith('      - name: Smoke-Test') and '          set -e\n' in step
    assert f'          {CHECK}\n' in step
    assert step.index('PegaProx kam im LXC nicht hoch') < step.index(CHECK) < step.index('LXC Smoke-Test erfolgreich')


def test_the_vm_cleanup_checks_what_the_smoke_boot_said():
    step = _step('build-vm', 'Zustand des Testboots aus dem Image entfernen')
    read = ('sudo cat /mnt/img/var/cache/pegaprox-image/keystore-status.json > "$RUNNER_TEMP/keystore-status.json"'
            ' || true')
    assert step.index('sudo mount "$ROOT" /mnt/img') < step.index(read) < step.index('R=/mnt/img')
    assert step.index('sudo qemu-nbd --disconnect /dev/nbd0') < step.index(f'{CHECK} || FAIL=1\n') \
        < step.index('[ "$FAIL" -eq 0 ] || exit 1')


@pytest.mark.parametrize('job', ['build-lxc', 'build-vm'])
def test_the_check_comes_before_the_upload(job):
    text = _job(job)
    assert text.count(CHECK) == 1
    assert text.index(CHECK) < text.index('- name: Artefakt sichern')


def _status_file(tmp_path, monkeypatch, backend):
    """--keystore-status as PegaProx prints it, with `backend` as the driver it found."""
    from pegaprox.core import dbcrypto
    monkeypatch.setattr(dbcrypto, 'BACKEND', backend)
    out = ('Gevent monkey-patching applied\n'
           + json.dumps({'keystore': {'ok': False, 'source': 'none'}, 'db': dbcrypto.backend_status()}, indent=2)
           + '\n')
    path = tmp_path / 'keystore-status.json'
    path.write_text(out)
    return path


def _tail_env(sandbox, tmp_path):
    for cmd in ('umount', 'qemu-nbd', 'sync'):
        p = sandbox / 'bin' / cmd
        p.write_text('#!/bin/sh\nexit 0\n')
        p.chmod(0o755)
    (sandbox / 'bin' / 'python3').write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    (sandbox / 'bin' / 'python3').chmod(0o755)
    return {'PATH': f"{sandbox / 'bin'}:/usr/bin:/bin", 'RUNNER_TEMP': str(tmp_path)}


@pytest.mark.parametrize('backend,ok', [('sqlcipher', True), ('sqlite-plain', False)])
def test_the_smoke_steps_fail_on_plain_sqlite(sandbox, tmp_path, monkeypatch, backend, ok):
    """Both ends of the steps as the runner has them, on what a good and a broken image say."""
    _status_file(tmp_path, monkeypatch, backend)
    env = _tail_env(sandbox, tmp_path)
    lxc = _from_line(_step('build-lxc', 'Smoke-Test (Container starten + HTTP-Check)'),
                     'echo "----- --keystore-status -----"')
    vm = _from_line(_step('build-vm', 'Zustand des Testboots aus dem Image entfernen'), 'sudo umount /mnt/img')
    for script, done in (('OK=1\n' + lxc, 'LXC Smoke-Test erfolgreich.'), ('FAIL=0\n' + vm, 'Image bereinigt.')):
        r = subprocess.run(['bash', '-c', 'set -e\n' + script], cwd=ROOT, capture_output=True, text=True,
                           env=env, timeout=60)
        assert (r.returncode == 0) == ok, r.stdout + r.stderr
        assert (done in r.stdout) == ok
        if not ok:
            assert ('::error::PegaProx in the image runs its database on sqlite-plain: '
                    'python3-sqlcipher3 does not import there') in r.stdout


def _smoke_backend(path):
    return subprocess.run([sys.executable, '-I', SMOKE_BACKEND, str(path)], capture_output=True, text=True,
                          timeout=30)


def test_the_backend_check_passes_sqlcipher(tmp_path, monkeypatch):
    r = _smoke_backend(_status_file(tmp_path, monkeypatch, 'sqlcipher'))
    assert r.returncode == 0, r.stdout
    assert r.stdout == 'smoke: PegaProx in the image runs its database on SQLCipher\n'


def test_the_backend_check_fails_plain_sqlite(tmp_path, monkeypatch):
    """What PegaProx on an arm64 image with the CDN package said: the module did not import."""
    r = _smoke_backend(_status_file(tmp_path, monkeypatch, 'sqlite-plain'))
    assert r.returncode == 1
    assert r.stdout == ('::error::PegaProx in the image runs its database on sqlite-plain: '
                        'python3-sqlcipher3 does not import there\n')


@pytest.mark.parametrize('text', [
    '',                                                                   # docker exec or nspawn failed
    'Gevent monkey-patching applied\nTraceback (most recent call last):\n  ...\n',
    '{\n  "db": {"backend": "sqlcipher"\n',                               # cut off
    '{\n  "keystore": {"ok": true}\n}\n',
])
def test_no_answer_is_no_pass(tmp_path, text):
    path = tmp_path / 'keystore-status.json'
    path.write_text(text)
    r = _smoke_backend(path)
    assert r.returncode == 1
    assert r.stdout.startswith('::error::no --keystore-status JSON from PegaProx in the image')


def test_a_missing_status_file_is_no_pass(tmp_path):
    r = _smoke_backend(tmp_path / 'nothing.json')
    assert r.returncode == 1 and r.stdout.startswith('::error::no --keystore-status of PegaProx in the image')


def test_a_brace_in_a_log_line_ahead_of_the_status_is_not_taken_for_it(tmp_path, monkeypatch):
    path = _status_file(tmp_path, monkeypatch, 'sqlite-plain')
    path.write_text('[KEYSTORE] {"backend": "sqlcipher"} said someone\n' + path.read_text())
    r = _smoke_backend(path)
    assert r.returncode == 1 and 'runs its database on sqlite-plain' in r.stdout
