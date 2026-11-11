"""The SMBIOS auto-configurator a node runs writes smbios1 the way the PVE GUI does.

qemu-server takes only [A-Za-z0-9+/]+={0,2} in an smbios1 value (QemuServer.pm
$smbios1_fmt) and says in base64=1 that the values are base64. The daemon wrote them plain,
so a manufacturer with a space, a dot or a hyphen, which the settings allow, made `qm set`
fail: the VM was never marked done and was tried again every 30 seconds. An smbios1 the
PVE GUI wrote (base64=1) was read as its encoded text.

These render SMBIOS_SCRIPT_TEMPLATE with format() as the deploy routes do and run its
functions against a fake qm that checks the smbios1 format and writes the conf into a tmp
dir. MK Nov 2026
"""
import base64
import os
import sys

import pytest

from pegaprox.api.nodes import SMBIOS_SCRIPT_TEMPLATE

UUID = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'

# qm set <vmid> -smbios1 <value>: the checks of $smbios1_fmt and maxLength, then the conf line
FAKE_QM = r'''
import os, re, sys
UUID = re.compile(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}')
TEXT = re.compile(r'[A-Za-z0-9+/]+={0,2}')
FIELDS = ('manufacturer', 'product', 'version', 'serial', 'sku', 'family')
_, cmd, vmid, opt, value = sys.argv
if cmd != 'set' or opt != '-smbios1' or len(value) > 512:
    sys.exit('400 Parameter verification failed')
for part in value.split(','):
    key, _, val = part.partition('=')
    if key == 'uuid':
        ok = UUID.fullmatch(val)
    elif key == 'base64':
        ok = val in ('0', '1', 'on', 'off', 'yes', 'no', 'true', 'false')
    else:
        ok = key in FIELDS and TEXT.fullmatch(val)
    if not ok:
        sys.exit(f"400 Parameter verification failed. smbios1: invalid format - value '{val}'")
path = os.path.join(os.environ['FAKE_QM_CONF_DIR'], vmid + '.conf')
with open(path) as f:
    lines = f.read().splitlines()
# the main section ends at the first [section]; a snapshot keeps its own line
at = next((i for i, l in enumerate(lines) if l.startswith('[')), len(lines))
main = ['smbios1: ' + value] + [l for l in lines[:at] if not l.startswith('smbios1:')]
with open(path, 'w') as f:
    f.write('\n'.join(main + lines[at:]) + '\n')
'''


def _b64(text):
    return base64.b64encode(text.encode('utf-8')).decode('ascii')


@pytest.fixture
def node(tmp_path, monkeypatch):
    conf = tmp_path / 'qemu-server'
    conf.mkdir()
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    qm = bindir / 'qm'
    qm.write_text('#!' + sys.executable + '\n' + FAKE_QM)
    qm.chmod(0o755)
    monkeypatch.setenv('PATH', str(bindir) + os.pathsep + os.environ.get('PATH', ''))
    monkeypatch.setenv('FAKE_QM_CONF_DIR', str(conf))
    return conf


def _daemon(conf, **values):
    """The script as a deploy renders it, loaded without running main()"""
    settings = dict(manufacturer='Proxmox', product='PegaProxManagment', version='v1', family='ProxmoxVE')
    settings.update(values)
    ns = {'__name__': 'smbios_daemon'}
    exec(compile(SMBIOS_SCRIPT_TEMPLATE.format(**settings), 'smbios_daemon.py', 'exec'), ns)
    ns['CONF_DIR'] = str(conf)
    ns['logged'] = logged = []
    ns['log_message'] = logged.append
    return ns


def _smbios1(conf, vmid):
    lines = (conf / f'{vmid}.conf').read_text().splitlines()
    value = next(l for l in lines if l.startswith('smbios1:')).split(':', 1)[1].strip()
    return dict(p.split('=', 1) for p in value.split(','))


def test_values_with_spaces_dots_and_hyphens_reach_the_vm(node):
    (node / '100.conf').write_text('name: win\nmemory: 4096\n')
    d = _daemon(node, manufacturer='Acme Corp.', product='Box-1 Pro', version='v1.2', family='Lab_Family')
    assert d['set_smbios']('100') is True, d['logged']
    got = _smbios1(node, '100')
    assert got.pop('base64') == '1'
    decoded = {k: base64.b64decode(v).decode('utf-8') for k, v in got.items()}
    assert decoded.pop('serial').startswith('PVE')
    assert decoded == {'manufacturer': 'Acme Corp.', 'product': 'Box-1 Pro', 'version': 'v1.2',
                       'family': 'Lab_Family'}
    # done: the next cycle leaves it alone
    assert d['needs_smbios_update']('100') is False


def test_a_gui_written_smbios1_reads_decoded_and_keeps_its_uuid(node):
    gui = f'uuid={UUID},manufacturer={_b64("Old Vendor GmbH")},product={_b64("Müller Box")},base64=1'
    (node / '101.conf').write_text(f'smbios1: {gui}\nname: win\n\n[snap1]\nsmbios1: uuid={UUID}\n')
    d = _daemon(node, manufacturer='New Vendor')
    assert d['parse_smbios_string'](gui) == {'uuid': UUID, 'manufacturer': 'Old Vendor GmbH',
                                             'product': 'Müller Box'}
    assert d['needs_smbios_update']('101') is False
    assert d['set_smbios']('101') is True, d['logged']
    got = _smbios1(node, '101')
    assert got['uuid'] == UUID and got['base64'] == '1'
    assert base64.b64decode(got['manufacturer']).decode() == 'New Vendor'
    # the snapshot section keeps its own line
    assert (node / '101.conf').read_text().endswith(f'[snap1]\nsmbios1: uuid={UUID}\n')


def test_an_empty_value_is_left_out(node):
    """a field saved empty is no field: qemu-server takes no empty value"""
    (node / '102.conf').write_text('name: lin\n')
    d = _daemon(node, family='', version='')
    assert d['set_smbios']('102') is True, d['logged']
    got = _smbios1(node, '102')
    assert 'family' not in got and 'version' not in got
    assert base64.b64decode(got['manufacturer']).decode() == 'Proxmox'
