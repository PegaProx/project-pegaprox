"""Node temperatures on a stock Proxmox node, and none of that on a cluster without SSH (#601).

Proxmox does not install lm-sensors, so `sensors -j` and `sensors` both came back empty
and a homelab node showed no temperatures and fed nothing to the temperature alert. The
kernel has the readings anyway: /sys/class/hwmon is what lm-sensors reads itself. The
probe now falls back to those files in the same SSH call and maps them to the rows the
lm-sensors paths return, so the Sensors panel and the alert take them as they are.

The probe is a shell command, so the parsing tests run the real command against a fake
sysfs tree laid out like the kernel's (symlinked hwmon class entries, device links into
pci/platform/thermal paths, millidegree files) with only bash builtins, grep and
readlink on PATH - the same tools a stock node has. lm-sensors is on this machine, so
it is kept off PATH unless a test puts a fake one there.

The second half is a live-test finding: on a cluster with SSH switched off, the
temperature collector still resolved every node's address - TCP connects to each IP the
node reports - before the SSH call itself was refused. MK
"""
import os
import shutil
import socket
import subprocess
import time
import types

import pytest

from pegaprox.models.tasks import PegaProxConfig


# ------------------------------------------------------------------ fake sysfs

def _chip(root, devpath, name, files, idx, device_link=True):
    """One hwmon chip under <root>/devices/<devpath>, linked from <root>/class/hwmon
    the way the kernel does it. name=None leaves the name file out."""
    dev = root / 'devices' / devpath
    hw = dev / 'hwmon' / f'hwmon{idx}' if device_link else dev / f'hwmon{idx}'
    hw.mkdir(parents=True)
    if name is not None:
        (hw / 'name').write_text(name + '\n')
    for fname, content in files.items():
        (hw / fname).write_text(f'{content}\n')
    if device_link:
        (hw / 'device').symlink_to(dev)
    cls = root / 'class' / 'hwmon'
    cls.mkdir(parents=True, exist_ok=True)
    (cls / f'hwmon{idx}').symlink_to(hw)


def _amd_homelab(root):
    """Ryzen board: k10temp, two NVMe drives (the second one hot, alarm up), an ACPI
    thermal zone without a device link and without labels."""
    _chip(root, 'pci0000:00/0000:00:18.3', 'k10temp',
          {'temp1_input': 45250, 'temp1_label': 'Tctl',
           'temp3_input': 41500, 'temp3_label': 'Tccd1'}, 0)
    _chip(root, 'pci0000:00/0000:00:01.2/0000:01:00.0/nvme/nvme0', 'nvme',
          {'temp1_input': 38850, 'temp1_label': 'Composite', 'temp1_max': 81850,
           'temp1_crit': 84850, 'temp1_min': -273150, 'temp1_alarm': 0,
           # "Sensor 1" has no thresholds: the drive answers 0xffff K for the max
           'temp2_input': 38850, 'temp2_label': 'Sensor 1', 'temp2_max': 65261850,
           'temp2_min': -273150}, 1)
    _chip(root, 'pci0000:00/0000:00:01.3/0000:02:00.0/nvme/nvme1', 'nvme',
          {'temp1_input': 83850, 'temp1_label': 'Composite', 'temp1_max': 81850,
           'temp1_crit': 84850, 'temp1_alarm': 1}, 2)
    _chip(root, 'virtual/thermal/thermal_zone0', 'acpitz',
          {'temp1_input': 27800, 'temp1_crit': 105000}, 3, device_link=False)


def _intel_server(root):
    """Xeon box: coretemp with a crit alarm on one core, the PCH thermal zone, a SATA
    disk through drivetemp, a Super-IO chip with an unconnected input and a label that
    has no reading, and one chip with no name file at all."""
    _chip(root, 'platform/coretemp.0', 'coretemp',
          {'temp1_input': 52000, 'temp1_label': 'Package id 0', 'temp1_max': 80000,
           'temp1_crit': 100000, 'temp1_crit_alarm': 0,
           'temp2_input': 49000, 'temp2_label': 'Core 0', 'temp2_max': 80000,
           'temp2_crit': 100000, 'temp2_crit_alarm': 0,
           'temp10_input': 101000, 'temp10_label': 'Core 8', 'temp10_max': 80000,
           'temp10_crit': 100000, 'temp10_crit_alarm': 1}, 0)
    _chip(root, 'virtual/thermal/thermal_zone2', 'pch_cannonlake',
          {'temp1_input': 47000}, 1, device_link=False)
    _chip(root, 'pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0', 'drivetemp',
          {'temp1_input': 34000, 'temp1_max': 60000, 'temp1_crit': 70000}, 2)
    _chip(root, 'platform/it87.2608', 'it8686',
          {'temp1_input': 36000, 'temp1_label': 'SYSTIN',
           'temp2_input': -128000,                      # nothing wired to it
           'temp4_label': 'AUXTIN'}, 3)                  # label, no reading
    _chip(root, 'platform/acme-hwmon.1', None, {'temp1_input': 30000}, 4)


@pytest.fixture
def toolbin(tmp_path):
    """A PATH with grep and readlink only - lm-sensors is installed here, not on a
    stock node. GNU grep, not whatever the developer's shell aliases it to."""
    b = tmp_path / 'bin'
    b.mkdir()
    for tool in ('grep', 'readlink'):
        src = shutil.which(tool, path='/usr/bin:/bin')
        assert src, f'{tool} missing'
        (b / tool).symlink_to(src)
    return b


def _fake_sensors(toolbin, stdout_by_flag):
    """An lm-sensors stand-in: prints the text for its first argument ('-j' or '')."""
    script = toolbin / 'sensors'
    lines = ['#!/bin/sh', 'case "$1" in']
    for flag, out in stdout_by_flag.items():
        body = out.replace("'", "'\\''")
        lines.append(f"  '{flag}') printf '%s' '{body}';;")
    lines += ['esac', 'exit 0']
    script.write_text('\n'.join(lines) + '\n')
    script.chmod(0o755)


SHELLS = [s for s in ('bash', 'dash') if shutil.which(s)]


def _run_probe(sysroot, toolbin, command, shell='bash'):
    """What the node's shell answers to `command`, with /sys swapped for the fake tree."""
    cmd = command.replace('/sys/class/hwmon', str(sysroot / 'class' / 'hwmon'))
    r = subprocess.run([shutil.which(shell), '-c', cmd], capture_output=True, text=True,
                       env={'PATH': str(toolbin)}, timeout=20)
    return r


# ------------------------------------------------------------------ manager

def _cfg(**kw):
    base = {'name': 'c', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'pw'}
    base.update(kw)
    return PegaProxConfig(base)


def _manager(cfg, calls=None):
    """A bare manager carrying what get_node_sensors touches. Building a real one would
    connect to Proxmox. `calls` records the address lookup and every SSH command."""
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = cfg
    m.id = 'c1'
    m.logger = types.SimpleNamespace(
        info=lambda *a, **k: None, debug=lambda *a, **k: None,
        warning=lambda *a, **k: None, error=lambda *a, **k: None)
    m._last_ssh_block_logged = None
    m.is_connected = True
    calls = calls if calls is not None else []
    m.connect_to_proxmox = lambda: calls.append(('connect',)) or True
    m._get_node_ip = lambda node: calls.append(('lookup', node)) or '10.0.0.11'
    return m


def _wire_ssh(m, calls, answer):
    """Route the manager's SSH reads to answer(command) and record them. The whole
    key / own keys / password ladder is replaced, so a None here never goes on to a real
    password login (test_node_reads_cluster_key_601 covers the ladder)."""
    def run(ip, user, command, timeout=30):
        calls.append(('ssh', command))
        return answer(command)
    m._ssh_read_output = run


def _probe_cmd():
    from pegaprox.core.manager import PegaProxManager
    return PegaProxManager._SENSORS_PROBE


def _by(rows):
    return {(r['chip'], r['label']): r for r in rows}


# ------------------------------------------------------------------ hwmon parsing

@pytest.mark.parametrize('shell', SHELLS)
def test_a_stock_amd_node_reads_its_temperatures_from_hwmon(tmp_path, toolbin, shell):
    _amd_homelab(tmp_path)
    calls = []
    m = _manager(_cfg(), calls)
    _wire_ssh(m, calls, lambda cmd: _run_probe(tmp_path, toolbin, cmd, shell).stdout)

    res = m.get_node_sensors('pve1')

    assert res.get('source') == 'hwmon', res
    rows = _by(res['sensors'])
    assert res['count'] == len(res['sensors']) == 6
    assert rows[('k10temp-pci-00c3', 'Tctl')]['value'] == 45.25     # 45250 millidegrees
    assert rows[('k10temp-pci-00c3', 'Tccd1')]['value'] == 41.5
    # two drives, both called "nvme" by the kernel, kept apart by their PCI address
    first, second = rows[('nvme-pci-0100', 'Composite')], rows[('nvme-pci-0200', 'Composite')]
    assert (first['value'], first['max'], first['crit'], first['alarm']) == (38.85, 81.85, 84.85, False)
    assert (second['value'], second['alarm']) == (83.85, True)
    # a threshold the drive does not have is no threshold, not 65261 degrees
    assert rows[('nvme-pci-0100', 'Sensor 1')]['max'] is None
    # no label file: lm-sensors calls it temp1 too
    assert rows[('acpitz-acpi-0', 'temp1')] == {
        'chip': 'acpitz-acpi-0', 'label': 'temp1', 'kind': 'temp', 'value': 27.8,
        'max': None, 'crit': 105.0, 'alarm': False}
    assert all(r['kind'] == 'temp' for r in res['sensors'])
    # one SSH call: no lm-sensors on the node, so the plain `sensors` retry is not made
    assert [c[0] for c in calls] == ['lookup', 'ssh']


@pytest.mark.parametrize('shell', SHELLS)
def test_a_stock_intel_node_reads_its_temperatures_from_hwmon(tmp_path, toolbin, shell):
    _intel_server(tmp_path)
    calls = []
    m = _manager(_cfg(), calls)
    _wire_ssh(m, calls, lambda cmd: _run_probe(tmp_path, toolbin, cmd, shell).stdout)

    res = m.get_node_sensors('pve1')

    assert res.get('source') == 'hwmon', res
    rows = _by(res['sensors'])
    assert rows[('coretemp-isa-0000', 'Package id 0')]['value'] == 52.0
    assert rows[('coretemp-isa-0000', 'Package id 0')]['crit'] == 100.0
    # temp10 sorts after temp2, and its crit_alarm is the alarm
    core_labels = [r['label'] for r in res['sensors'] if r['chip'] == 'coretemp-isa-0000']
    assert core_labels == ['Package id 0', 'Core 0', 'Core 8']
    assert rows[('coretemp-isa-0000', 'Core 8')]['alarm'] is True
    assert rows[('coretemp-isa-0000', 'Core 0')]['alarm'] is False
    assert rows[('pch_cannonlake-virtual-0', 'temp1')]['value'] == 47.0
    assert rows[('drivetemp-scsi-0-0', 'temp1')]['crit'] == 70.0
    # the Super-IO chip: the unconnected input (-128 degrees) and the reading-less
    # label are dropped, the real one stays
    assert [r['label'] for r in res['sensors'] if r['chip'] == 'it8686-isa-0a30'] == ['SYSTIN']
    # no name file: the hwmon entry names the chip
    assert rows[('hwmon4-isa-0001', 'temp1')]['value'] == 30.0


def test_hwmon_parse_alone_handles_ragged_input():
    from pegaprox.core.manager import PegaProxManager
    dump = '\n'.join([
        '__PP_NO_LMSENSORS__',
        '/sys/class/hwmon/hwmon7/device:',                 # no device link at all
        '/sys/class/hwmon/hwmon7/name:cpu_thermal',
        '/sys/class/hwmon/hwmon7/temp1_input:51540',
        '/sys/class/hwmon/hwmon7/temp2_input:garbage',
        '/sys/class/hwmon/hwmon7/temp3_input:-273150',
        'grep: noise without the hwmon shape',
        '/sys/class/hwmon/hwmon10/name:nvme',
        '/sys/class/hwmon/hwmon10/device:/sys/devices/pci0000:40/0000:40:03.1/0000:41:00.0/nvme/nvme3',
        '/sys/class/hwmon/hwmon10/temp1_input:41850',
        '/sys/class/hwmon/hwmon10/temp1_label:Composite',
    ])
    rows = PegaProxManager._parse_hwmon_dump(dump)
    assert [(r['chip'], r['label'], r['value']) for r in rows] == [
        ('cpu_thermal-virtual-0', 'temp1', 51.54),
        ('nvme-pci-4100', 'Composite', 41.85),
    ]
    assert PegaProxManager._parse_hwmon_dump('') == []
    assert PegaProxManager._parse_hwmon_dump(None) == []


@pytest.mark.parametrize('dev,expected', [
    ('/sys/devices/pci0000:00/0000:00:18.3', 'x-pci-00c3'),
    ('/sys/devices/pci0000:00/0000:00:08.1/0000:0b:00.0', 'x-pci-0b00'),
    ('/sys/devices/pci0001:00/0001:00:02.0', 'x-pci-10010'),
    ('/sys/devices/platform/coretemp.1', 'x-isa-0001'),
    ('/sys/devices/platform/nct6775.656', 'x-isa-0290'),
    ('/sys/devices/pci0000:00/0000:00:1f.4/i2c-0/0-004c', 'x-i2c-0-4c'),
    ('/sys/devices/pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0', 'x-scsi-1-0'),
    ('/sys/devices/virtual/thermal/thermal_zone3', 'x-virtual-0'),
    ('', 'x-virtual-0'),
    ('/sys/devices/something/odd', 'x-hwmon5'),
])
def test_chip_names_follow_lm_sensors(dev, expected):
    from pegaprox.core.manager import PegaProxManager
    assert PegaProxManager._hwmon_chip('x', dev, 'hwmon5') == expected


# ------------------------------------------------------------------ fallback order

_JSON = ('{"k10temp-pci-00c3":{"Adapter":"PCI adapter","Tctl":{"temp1_input":44.875}},'
         '"nvme-pci-0100":{"Adapter":"PCI adapter","Composite":{"temp1_input":38.850,'
         '"temp1_max":81.850,"temp1_crit":84.850,"temp1_alarm":0.000}}}')
# lm-sensors 3.5: no commas between chips
_BROKEN_JSON = ('{"k10temp-pci-00c3":{"Adapter":"PCI adapter","Tctl":{"temp1_input":44.875}}'
                '"nvme-pci-0100":{"Adapter":"PCI adapter","Composite":{"temp1_input":38.850}}}')
_TEXT = ('k10temp-pci-00c3\nAdapter: PCI adapter\nTctl:         +44.9°C\n\n'
         'nvme-pci-0100\nAdapter: PCI adapter\nComposite:    +38.9°C  (high = +81.8°C)\n')


def test_lm_sensors_json_comes_first_and_hwmon_is_not_read(tmp_path, toolbin):
    _amd_homelab(tmp_path)
    _fake_sensors(toolbin, {'-j': _JSON})
    calls = []
    m = _manager(_cfg(), calls)
    out = {}
    _wire_ssh(m, calls, lambda cmd: out.setdefault('o', _run_probe(tmp_path, toolbin, cmd).stdout))

    res = m.get_node_sensors('pve1')

    assert 'source' not in res and res['count'] == 2
    assert _by(res['sensors'])[('nvme-pci-0100', 'Composite')]['max'] == 81.85
    assert '__PP_HWMON__' not in out['o']        # the probe stopped after the JSON
    assert [c[0] for c in calls] == ['lookup', 'ssh']


def test_broken_json_still_goes_to_the_text_parser_before_hwmon(tmp_path, toolbin):
    _amd_homelab(tmp_path)
    _fake_sensors(toolbin, {'-j': _BROKEN_JSON, '': _TEXT})
    calls = []
    m = _manager(_cfg(), calls)
    _wire_ssh(m, calls, lambda cmd: _run_probe(tmp_path, toolbin, cmd).stdout)

    res = m.get_node_sensors('pve1')

    assert res['source'] == 'text' and res['count'] == 2
    assert [c[1] for c in calls if c[0] == 'ssh'][1] == 'sensors 2>/dev/null'


def test_old_lm_sensors_without_json_prefers_its_text_over_hwmon(tmp_path, toolbin):
    """lm-sensors < 3.5 prints nothing for -j: the probe adds hwmon, the text call still
    runs because lm-sensors is there, and its rows win (sensors.conf labels)."""
    _amd_homelab(tmp_path)
    _fake_sensors(toolbin, {'-j': '', '': _TEXT})
    calls = []
    m = _manager(_cfg(), calls)
    _wire_ssh(m, calls, lambda cmd: _run_probe(tmp_path, toolbin, cmd).stdout)

    res = m.get_node_sensors('pve1')

    assert res['source'] == 'text'
    assert len([c for c in calls if c[0] == 'ssh']) == 2


def test_lm_sensors_with_nothing_to_say_falls_to_hwmon(tmp_path, toolbin):
    _intel_server(tmp_path)
    _fake_sensors(toolbin, {'-j': '', '': ''})
    calls = []
    m = _manager(_cfg(), calls)
    _wire_ssh(m, calls, lambda cmd: _run_probe(tmp_path, toolbin, cmd).stdout)

    res = m.get_node_sensors('pve1')

    assert res['source'] == 'hwmon' and res['count'] == 7


def test_json_with_no_chips_and_no_hwmon_stays_an_empty_answer(tmp_path, toolbin):
    (tmp_path / 'class' / 'hwmon').mkdir(parents=True)
    _fake_sensors(toolbin, {'-j': '{}'})
    calls = []
    m = _manager(_cfg(), calls)
    _wire_ssh(m, calls, lambda cmd: _run_probe(tmp_path, toolbin, cmd).stdout)

    assert m.get_node_sensors('pve1') == {'sensors': [], 'count': 0}
    assert len([c for c in calls if c[0] == 'ssh']) == 1


def test_a_vm_without_lm_sensors_or_hwmon_says_so(tmp_path, toolbin):
    (tmp_path / 'class' / 'hwmon').mkdir(parents=True)
    calls = []
    m = _manager(_cfg(), calls)
    _wire_ssh(m, calls, lambda cmd: _run_probe(tmp_path, toolbin, cmd).stdout)

    res = m.get_node_sensors('pve1')

    assert 'lm-sensors is not installed' in res['error']
    assert len([c for c in calls if c[0] == 'ssh']) == 1


def test_the_probe_exits_zero_even_with_nothing_there(tmp_path, toolbin):
    """_ssh_run_command_output returns None on any non-zero exit - the hwmon half
    would be thrown away with it."""
    for shell in SHELLS:
        r = _run_probe(tmp_path, toolbin, _probe_cmd(), shell)
        assert r.returncode == 0, (shell, r.stderr)
        assert '__PP_HWMON__' in r.stdout and '__PP_NO_LMSENSORS__' in r.stdout


def test_a_failed_ssh_call_is_not_retried_with_plain_sensors():
    calls = []
    m = _manager(_cfg(), calls)
    _wire_ssh(m, calls, lambda cmd: None)

    res = m.get_node_sensors('pve1')

    assert 'no answer' in res['error']
    assert len([c for c in calls if c[0] == 'ssh']) == 1


def test_the_hottest_hwmon_reading_feeds_the_temperature_metric(tmp_path, toolbin):
    """The alert and the history chart take the hottest temp row - hwmon rows count."""
    from pegaprox.background.metrics import _node_hottest_temp
    _amd_homelab(tmp_path)
    calls = []
    m = _manager(_cfg(), calls)
    _wire_ssh(m, calls, lambda cmd: _run_probe(tmp_path, toolbin, cmd).stdout)

    assert _node_hottest_temp(m, 'pve1') == 83.8
    assert 'pve1' not in m._node_temp_probe_backoff


# ------------------------------------------------------------------ SSH off

SSH_OFF = [
    pytest.param(dict(ssh_disabled=True, ssh_key='-----BEGIN KEY-----'), 'SSH_DISABLED', id='switched-off'),
    pytest.param({'user': 'root@pam!automation', 'pass': 'tok'}, 'SSH_NO_CREDENTIALS', id='token-only'),
]


@pytest.fixture
def no_sockets(monkeypatch):
    """Any TCP connect the address lookup would make fails the test."""
    import pegaprox.core.manager as mgrmod
    tried = []

    def refuse(*a, **k):
        tried.append(a)
        raise AssertionError(f'TCP connect attempted: {a}')
    monkeypatch.setattr(socket, 'create_connection', refuse)
    monkeypatch.setattr(mgrmod.socket, 'create_connection', refuse)
    return tried


@pytest.mark.parametrize('cfg,code', SSH_OFF)
def test_ssh_off_answers_before_any_address_lookup(cfg, code, no_sockets):
    from pegaprox.core.manager import PegaProxManager
    calls = []
    m = _manager(_cfg(**cfg), calls)
    _wire_ssh(m, calls, lambda cmd: None)  # recorded, the assert below names it

    res = m.get_node_sensors('pve1')

    assert calls == [] and no_sockets == []
    assert res['code'] == code and 'SSH' in res['error']
    assert PegaProxManager.ssh_blocked_reason(m) == code


@pytest.mark.parametrize('cfg,code', SSH_OFF)
def test_the_collector_skips_a_cluster_with_ssh_off(cfg, code, monkeypatch, no_sockets):
    """Through the real 5-minute collector: three online nodes, SSH off - no lookup, no
    SSH, no temp, and no backoff, so switching SSH on reads them on the next cycle."""
    import pegaprox.background.metrics as metrics
    import pegaprox.api.nodes as nodes_api
    from pegaprox.core import ha
    calls = []
    m = _manager(_cfg(**cfg), calls)
    _wire_ssh(m, calls, lambda cmd: None)  # recorded, the assert below names it
    # what the `nodes` property hands out while its 30s cache is fresh
    m._cached_node_dict = {f'pve{i}': {'status': 'online', 'cpu': 0.1, 'maxcpu': 4, 'mem': 1,
                                       'maxmem': 8} for i in (1, 2, 3)}
    m._nodes_cache_time = time.time()
    m.get_vm_resources = lambda: []
    m.current_host = None
    m._create_session = lambda: types.SimpleNamespace(
        get=lambda url, timeout=None: types.SimpleNamespace(status_code=500, json=lambda: {}))
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    monkeypatch.setattr(nodes_api, '_hw_consent_state', lambda: (False, {}))
    monkeypatch.setattr(nodes_api, '_redfish_consent_state', lambda: (False, {}))
    monkeypatch.setattr(metrics, 'run_per_node',
                        lambda node_calls, **kw: {n: fn(n) for n, fn in node_calls.items()})
    monkeypatch.setattr(metrics, 'cluster_managers', {'c1': m})

    snap = metrics.collect_metrics_snapshot()

    nodes = snap['clusters']['c1']['nodes']
    assert set(nodes) == {'pve1', 'pve2', 'pve3'}
    assert not any('temp' in n for n in nodes.values())
    assert calls == [] and no_sockets == []
    assert not getattr(m, '_node_temp_probe_backoff', {})

    # and the same collector with SSH on does look the nodes up - the spies work
    m.config = _cfg()
    _wire_ssh(m, calls, lambda cmd: '__PP_HWMON__\n__PP_NO_LMSENSORS__\n')
    metrics.collect_metrics_snapshot()
    assert sorted(c[1] for c in calls if c[0] == 'lookup') == ['pve1', 'pve2', 'pve3']


def test_the_metric_skip_does_not_trip_on_a_manager_without_the_predicate():
    """XCP-ng and ESXi managers have no ssh_blocked_reason; they go on as before."""
    from pegaprox.background.metrics import _node_hottest_temp
    seen = []
    mgr = types.SimpleNamespace(get_node_sensors=lambda n: seen.append(n) or {
        'sensors': [{'kind': 'temp', 'value': 40.0}]})
    assert _node_hottest_temp(mgr, 'host1') == 40.0 and seen == ['host1']
