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
"""
import os
import re
import subprocess

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
