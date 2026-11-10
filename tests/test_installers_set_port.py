"""deploy.sh sets a port other than 5000 through PegaProx, not with the sqlite3 CLI.

The sqlite3 CLI cannot open a SQLCipher database, and deploy.sh installs the SQLCipher
package of requirements.txt: its port write failed on every such install, quietly, and said
"set port manually". The block runs here as deploy.sh has it, with runuser, systemctl and
sleep stubbed. The appliance setup scripts are tested in test_appliance_setup_network.py.

NS Nov 2026
"""
import os
import re
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*rel):
    with open(os.path.join(ROOT, *rel), encoding='utf-8') as fh:
        return fh.read()


def _port_block():
    text = _read('deploy.sh')
    m = re.search(r'^    # Set port in database if not default\n(.*?)^    fi\n', text, re.M | re.S)
    assert m, 'deploy.sh lost its port block'
    return m.group(0)


@pytest.mark.parametrize('answer,works', [(0, True), (4, False)])
def test_deploy_sets_the_port_as_the_service_user_in_its_directory(tmp_path, answer, works):
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    log = tmp_path / 'calls.log'
    for cmd, code in (('runuser', answer), ('systemctl', 0), ('sleep', 0), ('sqlite3', 0)):
        (stubs / cmd).write_text(f'#!/bin/sh\necho "$PWD {cmd} $*" >> "{log}"\nexit {code}\n')
        (stubs / cmd).chmod(0o755)
    install = tmp_path / 'opt'
    install.mkdir()
    script = ('set -e\nprint_info() { echo "$1"; }\nprint_success() { echo "$1"; }\n'
              'print_warning() { echo "WARN $1"; }\n'
              f'INSTALL_DIR={install}\nSERVICE_USER=pegaprox\nPYTHON_FILE=pegaprox_multi_cluster.py\n'
              'ACCESS_PORT=8443\n' + _port_block())
    r = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=30,
                       env={'PATH': f'{stubs}:/usr/bin:/bin'})
    assert r.returncode == 0, r.stdout + r.stderr
    calls = log.read_text().splitlines()
    assert calls[0] == (f'{install} runuser -u pegaprox -- {install}/venv/bin/python '
                        f'{install}/pegaprox_multi_cluster.py --set-port 8443')
    assert not any(' sqlite3 ' in c for c in calls)
    if works:
        assert any(c.endswith(' systemctl restart pegaprox') for c in calls)
        assert 'Port set to 8443' in r.stdout
    else:
        assert not any('systemctl' in c for c in calls)
        assert 'WARN Set port manually' in r.stdout


def test_no_installer_writes_the_database_with_the_sqlite3_cli():
    for rel in (('deploy.sh',), ('.github', 'workflows', 'release-images.yml')):
        text = _read(*rel)
        assert not re.search(r'sqlite3 "\$\w+" "(INSERT|UPDATE)', text), rel
        assert '--set-port' in text, rel
