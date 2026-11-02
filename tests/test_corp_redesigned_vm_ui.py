"""The summary of a VM or container in Corporate Redesigned (Preview), in the browser.

The summary keeps the classic arrangement (console and usage on top, hardware next to the
related objects) and adds the operational health of the guest, the last 60 minutes of its
metrics and its file systems. Every line of the health says what it rests on: the guest list
row (hastate, lock), the reads the view makes on open (lock, guest agent, config, HA
resources), the backup list the dashboard polls (only when it is of this cluster), the restore
report of the guest (read when the line group is expanded, never on open) and the migration
preflight (on a click). A read that was refused, failed or never ran is unknown, never
healthy. The sparklines come from the hour of metrics the view already loads, keep their gaps
and say how old they are. The hardware groups open the configuration dialog on their tab, for
a user with vm.config. File systems use the 70/85 storage tones, leave read-only images
uncoloured and show an unknown use as unknown.

The fake serves the shapes of pegaprox/api/vms.py (lock, guest-info, config, rrd),
pegaprox/api/clusters.py (proxmox-ha/resources), pegaprox/api/pbs.py (vms-backup-status,
recovery-report/<vmid>) and core/preflight.py (migration-preflight). PEGAPROX_CR_BUNDLE=<file>
serves another bundle (the counterproof against the build before stage H). Skips without
Playwright. LW Oct 2026
"""
import copy
import json
import os
import re
import time

import pytest

from test_corp_redesigned_dashboard_ui import _crumbs, _DashServer
from test_corp_redesigned_guard_ui import CT, DETERMINISTIC, FIXED, VM, VM_OFF, _GuardApp
from test_ha_ui import BASE

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
GIB = 1024 ** 3

# the guest list rows (pegaprox/core/manager.py get_vm_resources): PVE's hastate and lock, and
# agent_running from the IP sweep (absent: never probed)
WEB = dict(VM, hastate='started', agent_running=True, disk=6 * GIB, maxdisk=32 * GIB, tags='web;prod')
CT1 = dict(CT, disk=2 * GIB, maxdisk=8 * GIB, uptime=7200)
DB = dict(VM_OFF, maxdisk=64 * GIB)
LOCKED = dict(VM, vmid=103, name='app01', lock='backup', uptime=600)
GUESTS = [WEB, CT1, DB, LOCKED]

FS = [
    {'name': 'sda1', 'mountpoint': '/', 'type': 'ext4', 'used_bytes': 6 * GIB, 'total_bytes': 10 * GIB, 'used_pct': 60.0},
    {'name': 'sda2', 'mountpoint': '/var', 'type': 'ext4', 'used_bytes': 7 * GIB, 'total_bytes': 10 * GIB, 'used_pct': 70.0},
    {'name': 'sdb1', 'mountpoint': '/srv', 'type': 'xfs', 'used_bytes': 85 * GIB, 'total_bytes': 100 * GIB, 'used_pct': 85.0},
    {'name': 'sdc1', 'mountpoint': '/data', 'type': 'xfs', 'used_bytes': 923 * GIB, 'total_bytes': 1000 * GIB, 'used_pct': 92.3},
    {'name': 'loop0', 'mountpoint': '/snap/core22/1612', 'type': 'squashfs', 'used_bytes': 77 * 1024 ** 2,
     'total_bytes': 77 * 1024 ** 2, 'used_pct': 100.0},
    {'name': 'odd', 'mountpoint': '/mnt/odd', 'type': 'fuse.sshfs', 'used_bytes': 3 * GIB, 'total_bytes': None, 'used_pct': None},
]
GUEST_INFO = {
    'agent_running': True, 'hostname': 'web01', 'os_pretty_name': 'Debian GNU/Linux 12 (bookworm)', 'os_id': 'debian',
    'os_version': '12', 'os_kernel': '6.1.0-26-amd64', 'os_machine': 'x86_64', 'ip_addresses': ['10.0.0.50', 'fe80::1'],
    'kernel_version': '#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1',
    'interfaces': [{'name': 'lo', 'mac': '00:00:00:00:00:00', 'ips': [{'address': '127.0.0.1', 'family': 'ipv4', 'prefix': 8}]},
                   {'name': 'eth0', 'mac': 'bc:24:11:aa:bb:cc', 'ips': [{'address': '10.0.0.50', 'family': 'ipv4', 'prefix': 24}]}],
    'users': [{'user': 'root', 'domain': None, 'login_time': FIXED - 3600}],
    'filesystems': FS, 'guest_time_ns': (FIXED + 2.5) * 1e9,
}
# the guest-fsinfo route (vms.py): its own read of the same list, with the reason when it has none
FSINFO = {'agent_running': True, 'filesystems': FS, 'reason': None}
# the agent short-circuit of the route: PVE said "not running"
AGENT_DOWN = {'agent_running': False, 'hostname': None, 'os_pretty_name': None, 'os_id': None, 'os_version': None,
              'os_kernel': None, 'os_machine': None, 'ip_addresses': [], 'kernel_version': None, 'interfaces': [],
              'users': [], 'filesystems': [], 'guest_time_ns': None}
CT_INFO = {'agent_running': False, 'is_lxc': True, 'hostname': 'ct01', 'os_pretty_name': 'Debian', 'os_id': None,
           'os_version': None, 'os_kernel': None, 'ip_addresses': ['10.0.0.60'], 'interfaces': []}

WEB_RAW = {'name': 'web01', 'cores': 2, 'sockets': 2, 'memory': '4096', 'balloon': '1024', 'cpu': 'x86-64-v2-AES',
           'bios': 'ovmf', 'machine': 'q35', 'scsihw': 'virtio-scsi-single', 'agent': '1,fstrim_cloned_disks=1',
           'description': 'Web front end\nbehind the proxy', 'ostype': 'l26',
           'scsi0': 'local-lvm:vm-100-disk-0,size=32G', 'efidisk0': 'local-lvm:vm-100-disk-1,size=4M',
           'ide2': 'none,media=cdrom', 'net0': 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1,tag=20',
           'unused0': 'local-lvm:vm-100-disk-9', 'digest': 'x'}


def _disk(key, value):
    storage, volume = value.split(',')[0].split(':')
    size = next((p.split('=', 1)[1] for p in value.split(',')[1:] if p.startswith('size=')), '')
    return {'id': key, 'value': value, 'storage': storage, 'size': size, 'format': '', 'cache': '', 'iothread': 0,
            'ssd': 0, 'volume': volume}


def _vm_config(raw, **over):
    """GET .../config as pegaprox/core/manager.py get_vm_config parses a QEMU config."""
    cfg = {
        'general': {'name': raw.get('name', ''), 'description': raw.get('description', ''), 'vmgenid': '', 'tags': ''},
        'hardware': {'cores': raw.get('cores', 1), 'sockets': raw.get('sockets', 1), 'cpu': raw.get('cpu', 'host'),
                     'memory': raw.get('memory', 512), 'balloon': raw.get('balloon', 0), 'numa': 0, 'vga': 'std',
                     'machine': raw.get('machine', ''), 'bios': raw.get('bios', 'seabios'), 'scsihw': raw.get('scsihw', 'lsi')},
        'disks': [_disk(k, v) for k, v in raw.items() if re.match(r'^(scsi|virtio|sata|efidisk)\d+$', k)]
                 + [{'id': k, 'value': v, 'storage': '', 'size': '', 'media': 'cdrom', 'volume': 'none'}
                    for k, v in raw.items() if k.startswith('ide') and 'media=cdrom' in v],
        'networks': [{'id': k, 'value': v, 'bridge': 'vmbr0', 'firewall': 1, 'tag': '20', 'rate': '', 'mtu': '', 'queues': '',
                      'link_down': False, 'model': 'virtio', 'macaddr': 'BC:24:11:AA:BB:CC'}
                     for k, v in raw.items() if k.startswith('net')],
        'options': {'onboot': 0, 'boot': '', 'bootdisk': '', 'ostype': raw.get('ostype', 'other'), 'agent': raw.get('agent', '0'),
                    'protection': 0, 'tablet': 1, 'hotplug': '', 'acpi': 1, 'kvm': 1, 'smbios1': ''},
        'unused_disks': [{'id': k, 'value': v, 'storage': v.split(':')[0], 'volume': v.split(':')[1]}
                         for k, v in raw.items() if k.startswith('unused')],
        'raw': dict(raw), 'status': {'status': 'running'}, 'vmid': 100, 'node': 'pve1', 'type': 'qemu',
        'lock': {'locked': False},
    }
    cfg.update(over)
    return cfg


CT_RAW = {'hostname': 'ct01', 'cores': 1, 'cpulimit': 0, 'memory': 1024, 'swap': 512, 'ostype': 'debian',
          'rootfs': 'local-lvm:vm-101-disk-0,size=8G', 'mp0': 'tank:subvol-101-disk-1,mp=/srv/data,size=50G',
          'net0': 'name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:11:22,ip=dhcp,type=veth', 'unprivileged': 1}
CT_CONFIG = {
    'general': {'hostname': 'ct01', 'description': '', 'tags': '', 'ostype': 'debian', 'arch': 'amd64'},
    'hardware': {'cores': 1, 'cpulimit': 0, 'cpuunits': 1024, 'memory': 1024, 'swap': 512},
    'options': {'onboot': 0, 'protection': 0, 'unprivileged': 1, 'features': '', 'startup': '', 'nameserver': '', 'searchdomain': ''},
    'disks': [{'id': 'rootfs', 'value': CT_RAW['rootfs'], 'storage': 'local-lvm', 'size': '8G', 'mountpoint': '', 'volume': 'vm-101-disk-0'},
              {'id': 'mp0', 'value': CT_RAW['mp0'], 'storage': 'tank', 'size': '50G', 'mountpoint': '/srv/data', 'volume': 'subvol-101-disk-1'}],
    'networks': [{'id': 'net0', 'value': CT_RAW['net0'], 'bridge': 'vmbr0', 'firewall': 0, 'tag': '', 'rate': '', 'mtu': '', 'queues': '',
                  'link_down': False, 'name': 'eth0', 'hwaddr': 'BC:24:11:00:11:22', 'ip': 'dhcp', 'gw': '', 'ip6': '', 'gw6': ''}],
    'unused_disks': [], 'raw': CT_RAW, 'status': {'status': 'running'}, 'vmid': 101, 'node': 'pve1', 'type': 'lxc',
    'lock': {'locked': False},
}
LOCK_OK = {'locked': False, 'lock_reason': None, 'lock_description': None, 'unlock_command': 'qm unlock 100'}
# what the route answers when it could not read the config (vms.py get_vm_lock_status_api)
LOCK_UNREAD = {'locked': False, 'lock_reason': None, 'lock_description': None, 'unlock_command': None,
               'note': 'Could not determine lock status'}
LOCK_BACKUP = {'locked': True, 'lock_reason': 'backup', 'lock_description': 'Backup in progress',
               'unlock_command': 'qm unlock 103'}
HA_RES = [{'sid': 'vm:100', 'state': 'started', 'group': 'ha-web', 'max_restart': 1, 'max_relocate': 2, 'type': 'vm',
           'digest': 'abc'},
          {'sid': 'vm:300', 'state': 'started', 'max_restart': 1, 'max_relocate': 1, 'type': 'vm', 'digest': 'abc'}]
BACKUPS = [
    {'vmid': 100, 'last_backup_ts': FIXED - 5 * 3600, 'last_backup_age_hours': 5.0, 'count_30d': 30, 'encrypted': True,
     'last_verify_age_hours': 4.0, 'status': 'ok'},
    {'vmid': 102, 'last_backup_ts': FIXED - 200 * 3600, 'last_backup_age_hours': 200.0, 'count_30d': 2, 'encrypted': False,
     'last_verify_age_hours': None, 'status': 'stale'},
]

CHECKS = [{'check': 'agent', 'target': '', 'ok': True, 'detail': 'answers'},
          {'check': 'port', 'target': '443', 'ok': True, 'detail': 'listening'},
          {'check': 'command', 'target': 'systemctl is-active nginx', 'ok': True, 'detail': 'exit code 0'}]


def _guest_row(**over):
    """recovery.guest_row of pegaprox/core/recovery.py (a guest that passed a day ago)."""
    g = {'vmid': 100, 'name': 'web01', 'type': 'qemu', 'node': 'pve1', 'tags': ['prod', 'web'], 'state': 'ok',
         'last_test_at': '2026-10-29T03:10:00', 'last_result': 'passed', 'last_success_at': '2026-10-29T03:10:00',
         'last_success_age_days': 1.2, 'tested_backup_at': '2026-10-28T22:00:00', 'tested_backup_age_hours': 35.0,
         'measured_seconds': 184.2, 'rto_seconds': 600, 'rto_state': 'met', 'last_checks': CHECKS,
         'newest_backup_at': '2026-10-30T04:00:00', 'newest_backup_age_hours': 5.0, 'backup_count': 30,
         'sla_hours': 24, 'rpo_state': 'ok', 'last_failure_at': None, 'last_failure_cause': None,
         'cluster_id': 'c1', 'cluster_name': 'Testi'}
    g.update(over)
    return g


def _report(guest=None, history=None):
    return {'guest': guest or _guest_row(),
            'checks': {'agent': 'auto', 'ports': [443], 'command': 'systemctl is-active nginx', 'rto_seconds': 600, 'source': 'default'},
            'history': [{'id': 'v2', 'started_at': '2026-10-29T03:05:12.123456', 'completed_at': '2026-10-29T03:10:00.5',
                         'status': 'passed', 'backup_time': '2026-10-28T22:00:00', 'duration_seconds': 288.0,
                         'measured_seconds': 184.2, 'rto_met': True, 'checks': CHECKS, 'source': 'schedule', 'cause': ''},
                        {'id': 'v1', 'started_at': '2026-10-22T03:05:00.000001', 'completed_at': '2026-10-22T03:07:00.0',
                         'status': 'failed', 'backup_time': '2026-10-21T22:00:00', 'duration_seconds': 120.0,
                         'measured_seconds': None, 'rto_met': None, 'checks': [], 'source': 'manual',
                         'cause': 'guest agent did not answer'}] if history is None else history,
            'backups': [{'volid': 'pbs:backup/vm/100/2026-10-30T04:00:00Z', 'ctime': FIXED - 5 * 3600, 'storage': 'pbs'}]}


def _preflight(verdict='ready', reasons=(), unread=(), to='pve2', vmid=100, name='web01'):
    """core/preflight.py intra() for one guest."""
    return {'kind': 'intra', 'supported': True, 'cluster_id': 'c1', 'cluster': 'Testi', 'checked_at': FIXED, 'scoped': False,
            'guests': [{'vmid': vmid, 'name': name, 'type': 'qemu', 'node': 'pve1', 'status': 'running', 'to': to,
                        'verdict': verdict, 'overridable': False, 'overridden': False, 'reasons': list(reasons), 'abort': ''}],
            'totals': {'guests': 1, 'ready': int(verdict == 'ready'), 'warning': int(verdict == 'warning'),
                       'blocked': int(verdict == 'blocked'), 'overridable': 0, 'overridden': 0, 'moving': int(verdict != 'blocked')},
            'capacity': [], 'steps': [], 'abort': [], 'unread': list(unread), 'target': None, 'online': True,
            'with_local_disks': False, 'mode': None, 'parallel': None}


LOCAL_DISKS = {'level': 'blocked', 'code': 'local_disks', 'overridable': False, 'args': {'names': 'scsi0 on local-lvm'},
               'text': "It has local disks (scsi0 on local-lvm): a live migration needs 'migrate local disks'"}

# one hour of PVE samples, one a minute, as the rrd route formats them (the newest slot is the
# fixed clock); cpu has a three minute gap and its newest slot is empty
STEP = 60
STAMPS = [FIXED - STEP * (69 - i) for i in range(70)]


def _rrd_series(base, spread, gaps=()):
    return [None if i in gaps else round(base + spread * ((i * 7) % 11) / 10, 2) for i in range(70)]


RRD = {'timeframe': 'hour', 'vmid': 100, 'node': 'pve1', 'type': 'qemu', 'timestamps': STAMPS, 'metrics': {
    'cpu': _rrd_series(4, 6, gaps=(40, 41, 42, 69)), 'memory': _rrd_series(30, 10),
    'disk_read': _rrd_series(2048, 4096), 'disk_write': _rrd_series(8192, 2048),
    'net_in': _rrd_series(1500, 900), 'net_out': [None] * 70}}


class _VmServer(_DashServer):
    """The dashboard fake plus what the guest view and its health read, each answer settable:
    a (code, body) pair per route; 'abort' drops the connection, 'hold' keeps the answer back."""

    def __init__(self, guests=None, lock=None, agent=None, config=None, ha=None, backups=None, report=None,
                 preflight=None, ha_write=None, rrd=None, perms=None, admin=True, fsinfo=None, **kw):
        self.vm_perms = set(perms or [])
        super().__init__(resources=list(GUESTS if guests is None else guests), admin=admin,
                         permissions=sorted(self.vm_perms), **kw)
        self.routes = {
            ('GET', '/api/clusters/c1/vms/pve1/qemu/100/lock'): lock or (200, LOCK_OK),
            ('GET', '/api/clusters/c1/vms/pve1/qemu/100/guest-info'): agent or (200, GUEST_INFO),
            ('GET', '/api/clusters/c1/vms/pve1/qemu/100/config'): config or (200, _vm_config(WEB_RAW)),
            ('GET', '/api/clusters/c1/vms/pve1/qemu/100/guest-fsinfo'): fsinfo or (200, FSINFO),
            ('GET', '/api/clusters/c1/vms/pve1/lxc/101/lock'): (200, dict(LOCK_OK, unlock_command='pct unlock 101')),
            ('GET', '/api/clusters/c1/vms/pve1/lxc/101/guest-info'): (200, CT_INFO),
            ('GET', '/api/clusters/c1/vms/pve1/lxc/101/config'): (200, CT_CONFIG),
            ('GET', '/api/clusters/c1/vms/pve2/qemu/102/lock'): (200, dict(LOCK_OK, unlock_command='qm unlock 102')),
            ('GET', '/api/clusters/c1/vms/pve2/qemu/102/config'): (200, _vm_config(dict(WEB_RAW, name='db01', agent='0'),
                                                                                 vmid=102, node='pve2')),
            ('GET', '/api/clusters/c1/vms/pve1/qemu/103/lock'): (200, LOCK_BACKUP),
            ('GET', '/api/clusters/c1/vms/pve1/qemu/103/guest-info'): (200, AGENT_DOWN),
            ('GET', '/api/clusters/c1/vms/pve1/qemu/103/config'): (200, _vm_config(dict(WEB_RAW, name='app01', lock='backup'), vmid=103)),
            ('GET', '/api/clusters/c1/proxmox-ha/resources'): ha or (200, HA_RES),
            ('GET', '/api/clusters/c1/vms-backup-status'): backups or (200, BACKUPS),
            ('GET', '/api/clusters/c1/recovery-report/100'): report or (200, _report()),
            ('GET', '/api/clusters/c1/recovery-report/101'): (200, _report(_guest_row(vmid=101, name='ct01', type='lxc',
                last_checks=[{'check': 'booted', 'target': '', 'ok': True, 'detail': 'running'},
                             {'check': 'port', 'target': '22', 'ok': None, 'detail': 'no shell into the container: denied'}]))),
            ('POST', '/api/clusters/c1/migration-preflight'): preflight or (200, _preflight()),
            ('POST', '/api/clusters/c1/proxmox-ha/resources'): ha_write or (200, {'success': True}),
            ('DELETE', '/api/clusters/c1/proxmox-ha/resources/vm:100'): ha_write or (200, {'success': True}),
        }
        self.rrd = rrd or (200, RRD)
        self.held = []
        self.writes = []

    def release(self, answer=(200, None)):
        held, self.held = self.held, []
        for route, path in held:
            code, data = answer
            if data is None:
                data = _report()
            route.fulfill(status=code, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def handle(self, route):
        req = route.request
        if not req.url.startswith(BASE):
            return super().handle(route)
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        rrd = re.fullmatch(r'/api/clusters/c1/vms/[^/]+/(qemu|lxc)/\d+/rrd/(hour|day|week|month|year)', path)
        how = self.routes.get((req.method, path))
        if rrd:
            how = self.rrd
            if rrd.group(2) != 'hour' and isinstance(how, tuple) and isinstance(how[1], dict):
                how = (how[0], dict(how[1], timeframe=rrd.group(2)))
        if how is None:
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        if req.method != 'GET':
            try:
                self.writes.append((req.method, path, json.loads(req.post_data) if req.post_data else None))
            except Exception:
                self.writes.append((req.method, path, None))
        if how == 'abort':
            return route.abort('connectionrefused')
        if how == 'hold':
            self.held.append((route, path))
            return None
        code, data = how
        return route.fulfill(status=code, body=json.dumps(data), headers={'Content-Type': 'application/json'})


@pytest.fixture(scope='module')
def playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    yield pw
    pw.stop()


@pytest.fixture(scope='module')
def browser(playwright):
    try:
        br = playwright.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture(scope='module')
def firefox(playwright):
    try:
        br = playwright.firefox.launch(headless=True)
    except Exception as e:
        pytest.skip(f'no Firefox for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, theme='', storage=None, viewport=(1600, 1000), br=None, **kw):
        app = _GuardApp(br or browser, _VmServer(layout=layout, bundle=BUNDLE, **kw), corp_theme=theme,
                        storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


# --- helpers -------------------------------------------------------------------------------------

def _open_guest(page, name, kind='vm'):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text=name).first.click()
    page.locator(f'[data-cr-objhead="{kind}"]').wait_for(timeout=10000)
    page.locator('[data-cr-vm-health]').wait_for(timeout=8000)


def _wait(page, fn, seconds=5):
    deadline = time.time() + seconds
    while time.time() < deadline and not fn():
        page.wait_for_timeout(100)
    return fn()


def _health(page):
    """{id: (state, badge, detail, when)} of the health lines."""
    return page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-vm-h]')).map(r => [
        r.dataset.crVmH, [r.dataset.crVmHstate, r.querySelector('.cr-badge').innerText.trim(),
                          r.querySelector('[data-cr-vm-hdetail]').innerText.trim(), r.querySelector('[data-cr-vm-hwhen]').innerText.trim()]]))''')


def _settled_health(page, ids=('backup', 'agent', 'ha', 'lock'), seconds=6):
    """The health once the reads on open came back (none of the given lines says loading)."""
    _wait(page, lambda: all(not _health(page).get(i, ('', 'Loading'))[1].startswith('Loading') for i in ids), seconds)
    return _health(page)


def _calls(app, part, method=None):
    return [c for c in app.server.calls if part in c[1] and (method is None or c[0] == method)]


def _no_errors(app, dropped=False):
    # a dropped connection is logged by the classic fetch helpers; nothing else may be
    errors = [e for e in app.errors if not (dropped and 'Failed to fetch' in e)]
    assert not errors, errors


def _open_recovery(page):
    page.locator('[data-cr-vm-recovery]').click()
    page.locator('[data-cr-vm-recovery="open"]').wait_for(timeout=3000)


def _clock(page, sec):
    """hh:mm of an epoch second as fmtClock writes it (browser zone, 24 h)."""
    return page.evaluate('''(ms) => new Intl.DateTimeFormat(undefined, {hour: '2-digit', minute: '2-digit', hour12: false})
        .format(new Date(ms))''', sec * 1000)


# --- the health on open ----------------------------------------------------------------------------

def test_runtime_a_running_vm_shows_its_health_from_the_reads_it_already_makes(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    h = _settled_health(page)
    assert list(h) == ['backup', 'sla', 'restore', 'agent', 'ha', 'lock', 'migrate', 'audit'], list(h)
    now = _clock(page, FIXED)
    assert h['backup'] == ['healthy', 'Last backup 5.0 h ago', '30 in the last 30 days · encrypted · PBS verified 4.0 h ago',
                           _clock(page, FIXED - 5 * 3600)], h['backup']
    # PBS verification is called what it is, never a verified recovery
    assert 'recovery' not in h['backup'][2].lower()
    assert h['agent'] == ['healthy', 'Answers', 'Enabled in the VM options · Debian GNU/Linux 12 (bookworm)', now]
    # the HA limits are the resource's own, not a constant 3
    assert h['ha'] == ['healthy', 'HA state: started',
                       'group ha-web · max restart 1, max relocate 2 · requested started · live state from the guest list', now]
    assert h['lock'][:2] == ['healthy', 'Not locked']
    # the restore report and the preflight are not read on open
    assert h['sla'][:2] == ['unknown', 'Not loaded'] and h['restore'][:2] == ['unknown', 'Not loaded']
    assert h['migrate'][:2] == ['unknown', 'Not checked']
    assert h['audit'][:2] == ['na', 'Not per guest']
    counts = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-vm-hcount]'))
        .map(c => [c.dataset.crVmHcount, c.innerText.trim()]))''')
    assert counts == {'healthy': '4 healthy', 'unknown': '3 unknown', 'na': '1 not applicable'}, counts
    _no_errors(app)


def test_runtime_opening_a_guest_asks_nothing_heavy(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    page.locator('[data-cr-vm-sparks="ready"]').wait_for(timeout=5000)
    page.wait_for_timeout(500)
    for part in ('/recovery-report', '/migration-preflight', '/audit/integrity', '/backup-sla', '/recovery-assurance',
                 '/backup-verify', '/guest-fsinfo', '/pbs/verify-schedule'):
        assert not _calls(app, part), (part, _calls(app, part))
    # one read each, the metrics included: the sparklines take the hour the view loads anyway
    for part in ('/qemu/100/lock', '/qemu/100/guest-info', '/qemu/100/config', '/qemu/100/rrd/hour', '/proxmox-ha/resources'):
        assert len(_calls(app, part)) == 1, (part, _calls(app, part))
    _no_errors(app)


def test_runtime_a_stopped_guest_shows_dashes_and_asks_its_agent_nothing(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'db01')
    usage = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-vm-usage] [data-cr-stat]'))
        .map(s => [s.dataset.crStat, s.querySelector('.cr-stat-value').innerText.trim()]))''')
    assert usage == {'cpu': '-', 'mem': '-', 'disk': '-', 'uptime': '-'}, usage
    assert page.locator('[data-cr-vm-usage] .cr-stat-bar').count() == 0
    h = _settled_health(page, ids=('backup', 'ha', 'lock'))
    assert h['agent'][:2] == ['unconfigured', 'Not enabled'], h['agent']
    assert h['backup'][:2] == ['critical', 'Last backup 8.3 days ago'], h['backup']
    assert page.locator('[data-cr-vm-sparks="stopped"]').count() == 1
    assert page.locator('[data-cr-vm-fs="stopped"]').count() == 1
    assert not _calls(app, '/qemu/102/rrd/') and not _calls(app, '/qemu/102/guest-info')
    _no_errors(app)


# --- backup -------------------------------------------------------------------------------------

def test_runtime_a_guest_without_a_backup_row_is_no_backup_found_never_green(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'ct01', kind='ct')
    h = _settled_health(page)
    assert h['backup'][:2] == ['unknown', 'No backup found'], h['backup']
    assert 'leaves out guests without a backup' in h['backup'][2]
    _no_errors(app)


@pytest.mark.parametrize('answer', [(500, {'error': 'scan failed'}), (403, {'error': 'Permission denied'}), 'abort'])
def test_runtime_a_failed_backup_list_is_not_read(open_app, answer):
    app = open_app(backups=answer)
    page = app.page
    _open_guest(page, 'web01')
    h = _settled_health(page)
    assert h['backup'][:2] == ['unknown', 'Read failed'], h['backup']
    _no_errors(app, dropped=answer == 'abort')


def test_runtime_the_backup_list_of_another_cluster_is_never_read_as_this_guests(open_app):
    """vmids repeat across clusters and the dashboard keeps its last map on a cluster switch: a
    guest of Prod with the vmid 100 must not show web01's backup of Testi."""
    twin = dict(WEB, vmid=100, name='app00', node='prod1')
    app = open_app(extra={('GET', '/api/clusters/c2/resources'): (200, [twin])})
    app.server.routes[('GET', '/api/clusters/c2/vms-backup-status')] = 'hold'
    page = app.page
    _open_guest(page, 'web01')
    assert _settled_health(page)['backup'][1] == 'Last backup 5.0 h ago'
    page.locator('.corp-tree-item', has_text='Prod').first.click()
    page.locator('.corp-tree-child', has_text='app00').first.click()
    page.locator('[data-cr-objhead="vm"] .cr-objhead-name', has_text='app00').wait_for(timeout=8000)
    _wait(page, lambda: _calls(app, '/api/clusters/c2/vms-backup-status'))
    h = _health(page)
    assert h['backup'][:2] == ['unknown', 'Not read'], h['backup']
    assert h['backup'][2] == 'The backup list of this cluster has not been read yet.'
    app.server.release((200, []))
    assert _wait(page, lambda: _health(page)['backup'][1] == 'No backup found'), _health(page)['backup']
    _no_errors(app)


# --- backup SLA and restore test ------------------------------------------------------------------

def test_runtime_the_restore_report_is_read_on_expand_once(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    btn = page.locator('[data-cr-vm-recovery]')
    assert btn.get_attribute('aria-expanded') == 'false'
    btn.focus()
    page.keyboard.press('Enter')
    page.locator('[data-cr-vm-recovery-body="ok"]').wait_for(timeout=5000)
    assert btn.get_attribute('aria-expanded') == 'true'
    assert len(_calls(app, '/recovery-report/100')) == 1
    h = _health(page)
    assert h['sla'] == ['healthy', 'Within the SLA', 'newest backup 5.0 h old, 30 backups · SLA 24 h', '10-30 04:00'], h['sla']
    assert h['restore'][:2] == ['healthy', 'Passed'], h['restore']
    assert h['restore'][2] == ('last pass 2026-10-29 03:10 (1.2 days ago) · recovery time 3.1 min, target 10.0 min · '
                               'checks: 3 passed, 0 failed, 0 not run'), h['restore']
    checks = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vm-check]'))
        .map(c => [c.dataset.crVmCheck, c.dataset.crVmCheckOk])''')
    assert checks == [['agent', 'ok'], ['port', 'ok'], ['command', 'ok']], checks
    runs = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vm-run]')).map(r => r.dataset.crVmRun)''')
    assert runs == ['passed', 'failed']
    # "Proven" belongs to the assurance proof, not to a restore test line
    assert 'Proven' not in page.locator('[data-cr-vm-h="restore"]').inner_text()
    # closing and opening again reads nothing; Read again reads once more
    btn.click()
    btn.click()
    page.wait_for_timeout(300)
    assert len(_calls(app, '/recovery-report/100')) == 1
    page.locator('[data-cr-vm-rr-reload]').click()
    assert _wait(page, lambda: len(_calls(app, '/recovery-report/100')) == 2)
    _no_errors(app)


def test_runtime_a_report_on_its_way_shows_loading_and_starts_once(open_app):
    app = open_app(report='hold')
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    _open_recovery(page)
    page.locator('[data-cr-vm-recovery-body="loading"]').wait_for(timeout=3000)
    assert _health(page)['sla'][:2] == ['unknown', 'Loading...']
    page.locator('[data-cr-vm-recovery]').click()
    page.locator('[data-cr-vm-recovery]').click()
    page.wait_for_timeout(300)
    assert len(_calls(app, '/recovery-report/100')) == 1
    app.server.release()
    page.locator('[data-cr-vm-recovery-body="ok"]').wait_for(timeout=5000)
    assert _health(page)['restore'][1] == 'Passed'
    _no_errors(app)


@pytest.mark.parametrize('answer,badge,text', [
    ((403, {'error': 'Permission denied: backup.view'}), 'No permission', 'No permission: Permission denied: backup.view'),
    ((404, {'error': 'Guest not found'}), 'Not in the report', 'Not in the restore report: a template, a restore test copy or a guest outside your reach.'),
    ((503, {'error': 'cluster offline'}), 'Cluster offline', 'The cluster is offline.'),
    ((500, {'error': 'The recovery report could not be made'}), 'Read failed', 'Could not be read: The recovery report could not be made'),
    ('abort', 'Read failed', 'PegaProx could not be reached.'),
])
def test_runtime_a_report_that_could_not_be_read_is_named_never_green(open_app, answer, badge, text):
    app = open_app(report=answer)
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    _open_recovery(page)
    page.locator('[data-cr-vm-recovery-body]:not([data-cr-vm-recovery-body="loading"])').wait_for(timeout=5000)
    h = _health(page)
    for line in ('sla', 'restore'):
        assert h[line][:3] == ['unknown', badge, text], (line, h[line])
    assert page.locator('[data-cr-vm-recovery-body] [role="alert"]').inner_text().startswith(text)
    page.locator('[data-cr-vm-rr-retry]').click()
    assert _wait(page, lambda: len(_calls(app, '/recovery-report/100')) == 2)
    _no_errors(app, dropped=answer == 'abort')


@pytest.mark.parametrize('over,sla,restore', [
    ({'rpo_state': 'unknown', 'backup_count': None, 'newest_backup_at': None, 'newest_backup_age_hours': None},
     ['unknown', 'Backups not readable'], ['healthy', 'Passed']),
    ({'rpo_state': 'disabled', 'sla_hours': None}, ['unconfigured', 'No SLA set'], ['healthy', 'Passed']),
    ({'rpo_state': 'no_backup', 'backup_count': 0, 'newest_backup_at': None, 'newest_backup_age_hours': None},
     ['critical', 'No backup'], ['healthy', 'Passed']),
    ({'rpo_state': 'warning', 'newest_backup_age_hours': 20.0}, ['warning', 'Close to the SLA'], ['healthy', 'Passed']),
    ({'rpo_state': 'breached', 'newest_backup_age_hours': 30.0}, ['critical', 'SLA breached'], ['healthy', 'Passed']),
    ({'state': 'failing', 'last_result': 'failed', 'last_failure_at': '2026-10-30T03:10:00',
      'last_failure_cause': 'port 443 not listening'}, ['healthy', 'Within the SLA'], ['critical', 'Failing']),
    ({'state': 'never', 'last_test_at': None, 'last_result': None, 'last_success_at': None, 'last_success_age_days': None,
      'measured_seconds': None, 'rto_state': 'none', 'last_checks': []}, ['healthy', 'Within the SLA'], ['unknown', 'Never tested']),
    ({'state': 'stale', 'last_success_at': '2026-09-20T03:10:00', 'last_success_age_days': 40.2},
     ['healthy', 'Within the SLA'], ['warning', 'Pass older than 30 days']),
    ({'state': 'rto_missed', 'measured_seconds': 900.0, 'rto_state': 'missed'},
     ['healthy', 'Within the SLA'], ['warning', 'Recovery time missed']),
])
def test_runtime_every_state_of_the_report_has_its_own_word(open_app, over, sla, restore):
    app = open_app(report=(200, _report(_guest_row(**over))))
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    _open_recovery(page)
    page.locator('[data-cr-vm-recovery-body="ok"]').wait_for(timeout=5000)
    h = _health(page)
    assert h['sla'][:2] == sla, h['sla']
    assert h['restore'][:2] == restore, h['restore']
    if over.get('state') == 'failing':
        assert h['restore'][2] == 'Last failure: port 443 not listening (2026-10-30 03:10)'
    if over.get('rpo_state') == 'no_backup':
        assert 'found no backup' in h['sla'][2]
    _no_errors(app)


def test_runtime_a_pass_without_checks_says_so(open_app):
    app = open_app(report=(200, _report(_guest_row(last_checks=[]))))
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    _open_recovery(page)
    page.locator('[data-cr-vm-rr-nochecks]').wait_for(timeout=5000)
    assert _health(page)['restore'][2].endswith('restored and booted, no further check ran')
    _no_errors(app)


def test_runtime_a_container_says_why_it_is_never_proven(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'ct01', kind='ct')
    _settled_health(page)
    _open_recovery(page)
    page.locator('[data-cr-vm-recovery-body="ok"]').wait_for(timeout=5000)
    h = _health(page)
    assert h['restore'][:2] == ['healthy', 'Passed']
    assert h['restore'][2].endswith('checks: 1 passed, 0 failed, 1 not run. A container is never proven: its restore test runs no guest agent check.')
    assert page.locator('[data-cr-vm-check="port"]').get_attribute('data-cr-vm-check-ok') == 'skipped'
    assert page.locator('[data-cr-vm-ct-proof]').count() == 1
    _no_errors(app)


def test_runtime_without_backup_view_the_report_is_not_asked(open_app):
    app = open_app(admin=False, perms=['vm.view', 'cluster.view', 'ha.view'])
    page = app.page
    _open_guest(page, 'web01')
    h = _settled_health(page)
    for line in ('sla', 'restore'):
        assert h[line][:3] == ['unknown', 'No permission', 'Needs the backup.view permission.'], h[line]
    assert page.locator('[data-cr-vm-recovery]').count() == 0
    page.wait_for_timeout(300)
    assert not _calls(app, '/recovery-report')
    _no_errors(app)


# --- guest agent, lock, HA ----------------------------------------------------------------------

@pytest.mark.parametrize('case', ['silent', 'off', 'failed'])
def test_runtime_the_guest_agent_has_four_honest_states(open_app, case):
    raw = dict(WEB_RAW, agent='0') if case == 'off' else WEB_RAW
    agent = (500, {'error': 'agent read failed'}) if case == 'failed' else (200, AGENT_DOWN)
    app = open_app(agent=agent, config=(200, _vm_config(raw)))
    page = app.page
    _open_guest(page, 'web01')
    h = _settled_health(page)
    want = {'silent': ['warning', 'Does not answer'], 'off': ['unconfigured', 'Not enabled'],
            'failed': ['unknown', 'Read failed']}[case]
    assert h['agent'][:2] == want, h['agent']
    fs = {'silent': 'down', 'off': 'down', 'failed': 'failed'}[case]
    page.locator(f'[data-cr-vm-fs="{fs}"]').wait_for(timeout=3000)
    assert page.locator('[data-cr-vm-fsrow]').count() == 0
    _no_errors(app)


def test_runtime_an_agent_of_old_options_reads_like_the_server(open_app):
    """enabled=0 with fstrim on is off: the server's test, not a search for a 1."""
    app = open_app(agent=(200, AGENT_DOWN), config=(200, _vm_config(dict(WEB_RAW, agent='enabled=0,fstrim_cloned_disks=1'))))
    page = app.page
    _open_guest(page, 'web01')
    assert _settled_health(page)['agent'][:2] == ['unconfigured', 'Not enabled']
    _no_errors(app)


@pytest.mark.parametrize('lock,want', [
    ((200, LOCK_UNREAD), ['unknown', 'Read failed']),
    ((500, {'error': 'boom'}), ['unknown', 'Read failed']),
])
def test_runtime_a_lock_that_could_not_be_read_is_not_not_locked(open_app, lock, want):
    app = open_app(lock=lock)
    page = app.page
    _open_guest(page, 'web01')
    h = _settled_health(page)
    assert h['lock'][:2] == want, h['lock']
    if lock[1] is LOCK_UNREAD:
        assert 'without knowing' in h['lock'][2]
    _no_errors(app)


def test_runtime_a_locked_guest_says_so_and_unlock_keeps_its_question(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'app01')
    h = _settled_health(page)
    assert h['lock'][:3] == ['warning', 'Locked: backup', 'Backup in progress'], h['lock']
    banner = page.locator('[data-cr-vm-locked="backup"]')
    assert 'This guest is locked (backup).' in banner.inner_text()
    banner.locator('[data-cr-vm-unlock]').click()
    page.get_by_text('Unlock VM').first.wait_for(timeout=3000)
    page.wait_for_timeout(200)
    assert not _calls(app, '/unlock')
    _no_errors(app)


def test_runtime_the_guest_list_names_a_lock_the_read_could_not(open_app):
    app = open_app()
    app.server.routes[('GET', '/api/clusters/c1/vms/pve1/qemu/103/lock')] = (500, {'error': 'boom'})
    page = app.page
    _open_guest(page, 'app01')
    h = _settled_health(page)
    assert h['lock'][:3] == ['warning', 'Locked: backup', 'From the guest list: the lock read on open did not work.'], h['lock']
    # nothing the read confirmed, so no Unlock
    assert page.locator('[data-cr-vm-locked="backup"]').count() == 1
    assert page.locator('[data-cr-vm-unlock]').count() == 0
    _no_errors(app)


def test_runtime_a_lock_read_that_worked_wins_over_an_old_row(open_app):
    """The polled row is replaced only when cpu, memory or status change; a lock gone since
    then is gone as the read on open says."""
    app = open_app()
    app.server.routes[('GET', '/api/clusters/c1/vms/pve1/qemu/103/lock')] = (200, dict(LOCK_OK, unlock_command='qm unlock 103'))
    page = app.page
    _open_guest(page, 'app01')
    h = _settled_health(page)
    assert h['lock'][:2] == ['healthy', 'Not locked'], h['lock']
    assert page.locator('[data-cr-vm-locked]').count() == 0
    _no_errors(app)


@pytest.mark.parametrize('case', ['forbidden', 'empty', 'other', 'error_state', 'no_live'])
def test_runtime_proxmox_ha_is_never_disabled_when_unknown(open_app, case):
    # the live state is the hastate of the guest list row; without it only the HA read speaks
    web = dict(WEB, hastate='error') if case == 'error_state' else {k: v for k, v in WEB.items() if k != 'hastate'}
    guests = [web, CT1, DB, LOCKED]
    ha = {'forbidden': (403, {'error': 'Permission denied: ha.view'}), 'empty': (200, []), 'other': (200, HA_RES[1:]),
          'error_state': (200, HA_RES), 'no_live': (200, HA_RES)}[case]
    app = open_app(guests=guests, ha=ha)
    page = app.page
    _open_guest(page, 'web01')
    h = _settled_health(page)
    want = {'forbidden': ['unknown', 'No permission', 'Needs the ha.view permission.'],
            'empty': ['unconfigured', 'Not HA managed',
                      'The cluster lists no Proxmox HA resources. The server also answers an empty list when it cannot read them.'],
            'other': ['unconfigured', 'Not HA managed', 'Not among the Proxmox HA resources of this cluster.'],
            'error_state': ['critical', 'HA state: error'],
            'no_live': ['unknown', 'Configured']}[case]
    assert h['ha'][:len(want)] == want, h['ha']
    _no_errors(app)


def test_runtime_the_ha_switch_shows_the_refusal_and_keeps_the_state(open_app):
    app = open_app(ha_write=(403, {'error': 'Permission denied: ha.config'}))
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    page.locator('[data-cr-vm-ha-toggle="off"]').click()
    msg = page.locator('[data-cr-vm-ha-msg="error"]')
    msg.wait_for(timeout=5000)
    assert msg.inner_text() == 'Not done: No permission: Permission denied: ha.config'
    assert app.server.writes == [('DELETE', '/api/clusters/c1/proxmox-ha/resources/vm:100', None)]
    assert _health(page)['ha'][1] == 'HA state: started'
    assert len(_calls(app, '/proxmox-ha/resources', 'GET')) == 1
    _no_errors(app)


def test_runtime_adding_to_ha_sends_the_classic_body_and_reads_again(open_app):
    app = open_app(guests=[{k: v for k, v in WEB.items() if k != 'hastate'}, CT1, DB, LOCKED], ha=(200, []))
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    page.locator('[data-cr-vm-ha-toggle="on"]').click()
    page.locator('[data-cr-vm-ha-msg="success"]').wait_for(timeout=5000)
    assert app.server.writes == [('POST', '/api/clusters/c1/proxmox-ha/resources',
                                  {'vmid': 100, 'type': 'vm', 'max_restart': 3, 'max_relocate': 3})]
    assert _wait(page, lambda: len(_calls(app, '/proxmox-ha/resources', 'GET')) == 2)
    _no_errors(app)


def test_runtime_without_ha_config_there_is_no_ha_switch(open_app):
    app = open_app(admin=False, perms=['vm.view', 'cluster.view', 'ha.view', 'backup.view'])
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    assert page.locator('[data-cr-vm-ha-toggle]').count() == 0
    _no_errors(app)


# --- migration readiness ---------------------------------------------------------------------------

@pytest.mark.parametrize('answer,want', [
    ((200, _preflight()), ['healthy', 'Ready', 'best fit: pve2']),
    ((200, _preflight(unread=['guest configurations on Testi'])),
     ['warning', 'Ready, not fully checked', 'best fit: pve2 · not read: guest configurations on Testi']),
    ((200, _preflight('blocked', [LOCAL_DISKS])), ['critical', 'Blocked']),
    ((403, {'error': 'Permission denied: vm.migrate'}), ['unknown', 'Check failed', 'No permission: Permission denied: vm.migrate']),
])
def test_runtime_migration_readiness_is_the_servers_preflight_on_a_click(open_app, answer, want):
    app = open_app(preflight=answer)
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    assert not _calls(app, '/migration-preflight')
    page.locator('[data-cr-vm-pf]').click()
    assert _wait(page, lambda: _health(page)['migrate'][1] not in ('Not checked', 'Checking...'))
    h = _health(page)
    assert h['migrate'][:len(want)] == want, h['migrate']
    assert app.server.writes == [('POST', '/api/clusters/c1/migration-preflight', {'vms': [100]})]
    if want[1] == 'Blocked':
        reason = page.locator('[data-cr-vm-pf-reason="local_disks"]').inner_text()
        assert 'local disks (scsi0 on local-lvm)' in reason, reason
    _no_errors(app)


def test_runtime_a_check_on_its_way_cannot_start_twice(open_app):
    app = open_app(preflight='hold')
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    page.locator('[data-cr-vm-pf]').click()
    assert _wait(page, lambda: page.locator('[data-cr-vm-pf]').is_disabled())
    page.locator('[data-cr-vm-pf]').click(force=True)
    page.wait_for_timeout(300)
    assert len(_calls(app, '/migration-preflight')) == 1
    app.server.release((200, _preflight()))
    assert _wait(page, lambda: _health(page)['migrate'][1] == 'Ready')
    _no_errors(app)


def test_runtime_without_vm_migrate_nothing_is_checked(open_app):
    app = open_app(admin=False, perms=['vm.view', 'cluster.view', 'ha.view', 'backup.view'])
    page = app.page
    _open_guest(page, 'web01')
    h = _settled_health(page)
    assert h['migrate'][:3] == ['unknown', 'Not checked', 'Needs the vm.migrate permission.']
    assert page.locator('[data-cr-vm-pf]').count() == 0
    _no_errors(app)


# --- the last 60 minutes ----------------------------------------------------------------------------

def _window(series):
    end = STAMPS[-1]
    return [(t, v) for t, v in zip(STAMPS, series) if t >= end - 3600]


def test_runtime_the_sparklines_keep_their_gaps_and_say_how_old_they_are(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-sparks="ready"]').wait_for(timeout=8000)
    tiles = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vm-spark]')).map(s => ({
        id: s.dataset.crVmSpark, samples: Number(s.dataset.crVmSparkSamples), gaps: s.dataset.crVmSparkGaps,
        segs: s.querySelector('svg') ? Number(s.querySelector('svg').dataset.segments) : null,
        now: (s.querySelector('[data-cr-vm-spark-now]') || {}).innerText || null,
        range: (s.querySelector('[data-cr-vm-spark-range]') || {}).innerText || null}))''')
    assert [x['id'] for x in tiles] == ['cpu', 'memory', 'disk_read', 'disk_write', 'net_in', 'net_out']
    cpu = _window(RRD['metrics']['cpu'])
    vals = [v for _, v in cpu if v is not None]
    assert tiles[0]['samples'] == len(vals) == 57 and tiles[0]['gaps'] == '4'
    # 3 minutes without a sample split the line, the empty newest slot only ends it
    assert tiles[0]['segs'] == 2
    assert tiles[0]['now'] == f'{vals[-1]:.1f}%'
    assert tiles[0]['range'] == f'min {min(vals):.1f}% · max {max(vals):.1f}% · 4 min without a sample'
    mem = [v for _, v in _window(RRD['metrics']['memory'])]
    assert tiles[1]['now'] == f'{mem[-1]:.1f}%' and tiles[1]['segs'] == 1
    # a series PVE has no sample of is said to be, not drawn as a flat 0
    assert tiles[5]['samples'] == 0 and tiles[5]['segs'] is None
    assert page.locator('[data-cr-vm-spark="net_out"]').inner_text().endswith('No samples')
    assert page.locator('[data-cr-vm-asof]').inner_text() == f'as of {_clock(page, STAMPS[-1])}'
    _no_errors(app)


def test_runtime_another_range_on_monitor_hides_the_hour_until_asked(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-sparks="ready"]').wait_for(timeout=8000)
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="monitor"]').click()
    page.locator('[data-cr-perf] [data-cr-range="day"]').click()
    page.locator('[data-cr-perf="ready"] [data-cr-range="day"][aria-pressed="true"]').wait_for(timeout=5000)
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="summary"]').click()
    page.locator('[data-cr-vm-sparks="range"]').wait_for(timeout=5000)
    assert page.locator('[data-cr-vm-spark]').count() == 0
    page.locator('[data-cr-vm-spark-hour]').click()
    page.locator('[data-cr-vm-sparks="ready"]').wait_for(timeout=5000)
    assert [u.rsplit('/', 1)[1] for u in app.server.urls if '/qemu/100/rrd/' in u] == ['hour', 'day', 'hour']
    _no_errors(app)


def test_runtime_failed_metrics_are_said_to_be(open_app):
    app = open_app(rrd=(500, {'error': 'rrd went away'}))
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-sparks="error"]').wait_for(timeout=8000)
    app.server.rrd = (200, RRD)
    page.locator('[data-cr-vm-spark-retry]').click()
    page.locator('[data-cr-vm-sparks="ready"]').wait_for(timeout=5000)
    _no_errors(app)


# --- file systems ------------------------------------------------------------------------------------

def test_runtime_file_systems_take_the_storage_tones_and_say_what_is_unknown(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-fs="ready"]').wait_for(timeout=8000)
    rows = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vm-fsrow]')).map(r => [
        r.dataset.crVmFsrow, r.dataset.crVmFstone, Array.from(r.querySelectorAll('td')).map(td => td.innerText.trim())])''')
    tones = {r[0]: r[1] for r in rows}
    # below 70 normal, 70 and 85 warning, above 85 critical; an image is not coloured; unknown is unknown
    assert tones == {'/': 'success', '/var': 'warning', '/srv': 'warning', '/data': 'error',
                     '/snap/core22/1612': 'neutral', '/mnt/odd': 'unknown'}, tones
    cells = {r[0]: r[2] for r in rows}
    assert cells['/'][2:6] == ['6.0 GB', '4.0 GB', '10.0 GB', '60.0%'], cells['/']
    assert cells['/mnt/odd'][2:6] == ['3.0 GB', '-', '-', 'not reported'], cells['/mnt/odd']
    assert 'image' in cells['/snap/core22/1612'][1]
    assert page.locator('[data-cr-vm-fsrow="/mnt/odd"] .cr-meter').count() == 0
    _no_errors(app)


def test_runtime_an_agent_without_file_systems_says_so(open_app):
    # guest-info sends [] also when its file system call failed: only the route of its own that
    # answers with the agent running and no reason says the agent reported none
    app = open_app(agent=(200, dict(GUEST_INFO, filesystems=[])), fsinfo=(200, dict(FSINFO, filesystems=[])))
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-fs="none"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-vm-fsnote]').inner_text() == 'The guest agent reported no file systems.'
    assert len(_calls(app, '/guest-fsinfo')) == 1
    _no_errors(app)


def test_runtime_a_container_has_its_root_file_system_only(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'ct01', kind='ct')
    page.locator('[data-cr-vm-fs="lxc"]').wait_for(timeout=8000)
    cells = page.locator('[data-cr-vm-fsrow="/"] td').all_inner_texts()
    assert [c.strip() for c in cells][2:6] == ['2.0 GB', '6.0 GB', '8.0 GB', '25.0%'], cells
    assert 'Root file system only' in page.locator('[data-cr-vm-fs="lxc"]').inner_text()
    _no_errors(app)


# --- hardware ------------------------------------------------------------------------------------------

def _modal_tab(page):
    page.locator('.corp-vm-modal').wait_for(timeout=8000)
    return page.locator('.corp-vm-modal-tab.active').inner_text().strip()


@pytest.mark.parametrize('group,tab', [('cpu', 'Hardware'), ('disks', 'Disks'), ('network', 'Network'), ('firmware', 'Hardware')])
def test_runtime_a_hardware_group_opens_its_tab_of_the_configuration(open_app, group, tab):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-hw="ok"]').wait_for(timeout=8000)
    page.locator(f'[data-cr-vm-hwgroup="{group}"] [data-cr-vm-hwopen]').click()
    assert _modal_tab(page) == tab
    _no_errors(app)


def test_runtime_the_hardware_groups_read_the_config(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-hw="ok"]').wait_for(timeout=8000)
    text = lambda g: page.locator(f'[data-cr-vm-hwgroup="{g}"]').inner_text()  # noqa: E731
    assert '2 sockets x 2 cores = 4 vCPUs' in text('cpu') and 'x86-64-v2-AES' in text('cpu')
    assert '4.0 GB' in text('memory') and 'balloon minimum 1.0 GB' in text('memory')
    assert 'scsi0' in text('disks') and 'local-lvm · 32G' in text('disks') and 'CD/DVD: empty' in text('disks')
    assert 'unused disks: 1' in text('disks')
    assert 'virtio · vmbr0 · VLAN 20' in text('network')
    assert 'UEFI (OVMF)' in text('firmware') and 'Machine: q35' in text('firmware')
    _no_errors(app)


def test_runtime_a_container_opens_its_resources_tab(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'ct01', kind='ct')
    page.locator('[data-cr-vm-hw="ok"]').wait_for(timeout=8000)
    assert 'mp0' in page.locator('[data-cr-vm-hwgroup="disks"]').inner_text()
    page.locator('[data-cr-vm-hwgroup="cpu"] [data-cr-vm-hwopen]').press('Enter')
    assert _modal_tab(page) == 'Resources'
    _no_errors(app)


def test_runtime_without_vm_config_the_groups_open_nothing(open_app):
    app = open_app(admin=False, perms=['vm.view', 'cluster.view', 'ha.view', 'backup.view'])
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-hw="ok"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-vm-hwopen]').count() == 0
    assert 'Needs the vm.config permission.' in page.locator('[data-cr-vm-hw]').inner_text()
    _no_errors(app)


def test_runtime_an_unread_config_falls_back_to_the_guest_list(open_app):
    app = open_app(config=(500, {'error': 'config read failed'}))
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-hw="fallback"]').wait_for(timeout=8000)
    assert 'could not be read' in page.locator('[data-cr-vm-hw-note]').inner_text()
    assert '2 vCPUs' in page.locator('[data-cr-vm-hwgroup="cpu"]').inner_text()
    assert _settled_health(page)['agent'][2].startswith('The VM options could not be read')
    _no_errors(app)


def test_runtime_the_configure_button_still_opens_the_general_tab(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-hwgroup="disks"] [data-cr-vm-hwopen]').click()
    assert _modal_tab(page) == 'Disks'
    page.locator('.corp-vm-modal button', has_text=re.compile(r'^\s*Close\s*$')).first.click()
    page.locator('.corp-vm-modal').wait_for(state='detached', timeout=5000)
    page.locator('[data-cr-objhead="vm"] .cr-objhead-actions > button', has_text='Configure').click()
    assert _modal_tab(page) == 'General'
    _no_errors(app)


# --- links to the modules -------------------------------------------------------------------------------

def test_runtime_the_lines_lead_to_their_modules(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    _open_recovery(page)
    page.locator('[data-cr-vm-recovery-body="ok"]').wait_for(timeout=5000)
    page.locator('[data-cr-vm-hlink="sla"]').click()
    page.locator('.corp-tab-strip button.active', has_text='Backup SLA').wait_for(timeout=8000)
    assert _crumbs(page) == ['All', 'Testi', 'Datastore']
    assert _wait(page, lambda: _calls(app, '/api/clusters/c1/backup-sla'))
    _open_guest(page, 'web01')
    _open_recovery(page)
    page.locator('[data-cr-vm-hlink="restore"]').click()
    page.locator('.corp-tab-strip button.active[data-rtest-tab]').wait_for(timeout=8000)
    _open_guest(page, 'web01')
    before = len(_calls(app, '/proxmox-ha/resources', 'GET'))
    page.locator('[data-cr-vm-hlink="ha"]').click()
    page.wait_for_function('() => Array.from(document.querySelectorAll(".cr-crumbs li")).some(li => li.innerText.includes("Datacenter"))', timeout=8000)
    assert _wait(page, lambda: len(_calls(app, '/proxmox-ha/resources', 'GET')) > before)
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-hlink="audit"]').click()
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="timeline"][aria-selected="true"]').wait_for(timeout=5000)
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="summary"]').click()
    page.locator('[data-cr-vm-hlink="backup"]').click()
    assert _modal_tab(page) == 'Backups'
    _no_errors(app)


# --- classic, language, layout --------------------------------------------------------------------------

@pytest.mark.parametrize('layout', ['corporate'])
def test_runtime_classic_corporate_keeps_the_classic_summary(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='web01').first.click()
    page.locator('.corp-property-grid', has_text='QEMU Agent').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-vm-summary], [data-cr-vm-health]').count() == 0
    assert _wait(page, lambda: _calls(app, '/qemu/100/guest-fsinfo'))
    assert not _calls(app, '/lxc/')
    _no_errors(app)


def test_runtime_the_summary_speaks_german(open_app):
    app = open_app(language='de')
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page, ids=('agent', 'ha', 'lock'))
    assert page.locator('[data-cr-vm-health] .cr-panel-title').inner_text().strip().lower() == 'betriebszustand'
    assert _health(page)['agent'][1] == 'Antwortet'
    _no_errors(app)


@pytest.mark.parametrize('engine,width', [('chromium', 1280), ('chromium', 1600), ('firefox', 1280), ('firefox', 1600)])
def test_runtime_nothing_overlaps_at_desktop_widths(open_app, firefox, engine, width, request):
    app = open_app(viewport=(width, 1000), br=firefox if engine == 'firefox' else None)
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    _open_recovery(page)
    page.locator('[data-cr-vm-recovery-body="ok"]').wait_for(timeout=5000)
    page.locator('[data-cr-vm-sparks="ready"]').wait_for(timeout=5000)
    found = page.evaluate('''() => {
        const out = [];
        const doc = document.documentElement;
        if (doc.scrollWidth > window.innerWidth) out.push('page scrolls sideways: ' + doc.scrollWidth);
        const panel = document.querySelector('[data-cr-vm-summary]').getBoundingClientRect();
        document.querySelectorAll('[data-cr-vm-h]').forEach(r => {
            const cells = Array.from(r.children).filter(c => getComputedStyle(c).display !== 'none').map(c => c.getBoundingClientRect());
            for (let i = 1; i < cells.length; i++) {
                if (cells[i].top < cells[i - 1].bottom - 1 && cells[i].left < cells[i - 1].right - 1) out.push(r.dataset.crVmH + ' cell ' + i);
            }
            const b = r.getBoundingClientRect();
            if (b.right > panel.right + 1) out.push(r.dataset.crVmH + ' leaves the summary');
        });
        document.querySelectorAll('[data-cr-vm-spark], [data-cr-vm-hwgroup], [data-cr-vm-fstable]').forEach(e => {
            const b = e.getBoundingClientRect();
            if (b.right > panel.right + 1) out.push((e.dataset.crVmSpark || e.dataset.crVmHwgroup || 'fs') + ' leaves the summary');
        });
        const badges = document.querySelectorAll('[data-cr-vm-h] .cr-vm-hbadge .cr-badge');
        badges.forEach(b => { if (b.scrollWidth > b.clientWidth + 1) out.push('badge cut: ' + b.innerText); });
        return out;
    }''')
    assert found == [], found
    _no_errors(app)


# --- after the review of round 3 -------------------------------------------------------------------

def _read_guests_again(page):
    """The dashboard's own refresh key: the guest list is read and its frame announced once more."""
    page.locator('[data-cr-vm-health] .cr-panel-title').click()
    page.keyboard.press('r')


def test_runtime_removing_ha_is_not_contradicted_by_the_old_row(open_app):
    # a stopped guest: cpu, mem and status stay put, so the dashboard keeps the row object it had
    web = dict(WEB, status='stopped', hastate='stopped', cpu=0, mem=0, uptime=0)
    app = open_app(guests=[web, CT1, DB, LOCKED])
    page = app.page
    _open_guest(page, 'web01')
    h = _settled_health(page)
    assert h['ha'][:2] == ['healthy', 'HA state: stopped'], h['ha']
    # the removal goes through, and the list read after it no longer holds the guest
    app.server.routes[('GET', '/api/clusters/c1/proxmox-ha/resources')] = (200, HA_RES[1:])
    page.locator('[data-cr-vm-ha-toggle="off"]').click()
    page.locator('[data-cr-vm-ha-msg="success"]').wait_for(timeout=5000)
    assert _wait(page, lambda: _health(page)['ha'][0] != 'healthy'), _health(page)['ha']
    h = _health(page)
    assert h['ha'][:2] == ['unknown', 'Lists disagree'], h['ha']
    assert 'do not hold this guest' in h['ha'][2] and '"stopped"' in h['ha'][2], h['ha']
    # the switch follows the resource list: nothing offers to remove what is gone
    assert page.locator('[data-cr-vm-ha-toggle="off"]').count() == 0
    assert page.locator('[data-cr-vm-ha-toggle="on"]').count() == 1
    # the next frame of the guest list has no HA state any more: it settles
    app.server.resources = [{k: v for k, v in web.items() if k != 'hastate'}, CT1, DB, LOCKED]
    _read_guests_again(page)
    assert _wait(page, lambda: _health(page)['ha'][:2] == ['unconfigured', 'Not HA managed'], 8), _health(page)['ha']
    assert app.server.writes == [('DELETE', '/api/clusters/c1/proxmox-ha/resources/vm:100', None)]
    _no_errors(app)


def test_runtime_an_ha_state_that_turns_to_error_shows_while_the_view_is_open(open_app):
    web = dict(WEB, status='stopped', hastate='stopped', cpu=0, mem=0, uptime=0)
    app = open_app(guests=[web, CT1, DB, LOCKED])
    page = app.page
    _open_guest(page, 'web01')
    assert _settled_health(page)['ha'][:2] == ['healthy', 'HA state: stopped']
    # only hastate changes: the row object of the dashboard stays, the frame carries it
    app.server.resources = [dict(web, hastate='error'), CT1, DB, LOCKED]
    _read_guests_again(page)
    assert _wait(page, lambda: _health(page)['ha'][:2] == ['critical', 'HA state: error'], 8), _health(page)['ha']
    _no_errors(app)


def test_runtime_at_1280_every_line_keeps_its_time_and_the_basis_can_be_read(open_app):
    app = open_app(viewport=(1280, 900))
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    cells = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vm-h]')).map(r => {
        const w = r.querySelector('[data-cr-vm-hwhen]'); const b = w.getBoundingClientRect();
        return [r.dataset.crVmH, w.innerText.trim(), getComputedStyle(w).display, b.width, b.height]; })''')
    timed = [c for c in cells if c[1]]
    assert {c[0] for c in timed} >= {'backup', 'agent', 'ha', 'lock'}, cells
    assert all(c[2] != 'none' and c[3] > 0 and c[4] > 0 for c in timed), cells
    # what a line rests on and whose clock its time is: a button, by keyboard, not a title only
    btn = page.locator('[data-cr-vm-hbasis-toggle]')
    assert btn.get_attribute('aria-expanded') == 'false'
    assert page.locator('[data-cr-vm-hbasis]').count() == 0
    btn.focus()
    page.keyboard.press('Enter')
    page.locator('[data-cr-vm-hbasis="backup"]').wait_for(timeout=3000)
    assert btn.get_attribute('aria-expanded') == 'true'
    backup = page.locator('[data-cr-vm-hbasis="backup"]').inner_text()
    assert 'below 36 h healthy' in backup and 'Time of the newest backup' in backup, backup
    assert page.locator('[data-cr-vm-hbasis="agent"]').inner_text() == f'Read at (your clock): {_clock(page, FIXED)}'
    assert 'A live migration without local disks' in page.locator('[data-cr-vm-hbasis="migrate"]').inner_text()
    _open_recovery(page)
    page.locator('[data-cr-vm-hbasis="sla"]').wait_for(timeout=5000)
    sla = page.locator('[data-cr-vm-hbasis="sla"]').inner_text()
    assert 'warning from 80%' in sla and '(server time)' in sla, sla
    _no_errors(app)


@pytest.mark.parametrize('answer,why', [
    ((200, {'agent_running': False, 'filesystems': [], 'reason': 'proxmox_500'}), 'Proxmox answered HTTP 500'),
    ((200, {'agent_running': False, 'filesystems': [], 'reason': 'agent_not_running'}), 'the guest agent is not running'),
    ((200, {'agent_running': False, 'filesystems': [], 'reason': 'error: Read timed out. (read timeout=10)'}),
     'Read timed out. (read timeout=10)'),
    ((500, {'error': 'upstream down'}), 'Could not be read: upstream down'),
])
def test_runtime_an_empty_file_system_list_is_asked_once_more_and_never_called_none(open_app, answer, why):
    # get-fsinfo failed inside guest-info (it then sends []), while the agent answered the rest
    app = open_app(agent=(200, dict(GUEST_INFO, filesystems=[])), fsinfo=answer)
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-fs="unread"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-vm-fsnote]').inner_text() == f'No data: the file system list could not be read ({why}).'
    assert 'reported no file systems' not in page.locator('[data-cr-vm-fs]').inner_text()
    assert len(_calls(app, '/guest-fsinfo')) == 1
    _no_errors(app)


def test_runtime_a_list_the_second_read_has_is_drawn(open_app):
    app = open_app(agent=(200, dict(GUEST_INFO, filesystems=[])))
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-fs="ready"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-vm-fsrow]').count() == len(FS)
    assert len(_calls(app, '/guest-fsinfo')) == 1
    _no_errors(app)


def test_runtime_an_answer_of_the_wrong_shape_stops_the_summary_not_the_app(open_app):
    # list fields of another type are no lists: the summary draws (ip_addresses is also read by the
    # header of the view, which is not part of the summary)
    odd = dict(GUEST_INFO, interfaces='x', users='x')
    app = open_app(agent=(200, odd))
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    page.locator('[data-cr-vm-agentinfo="fresh"]').wait_for(timeout=5000)
    assert page.locator('[data-cr-boundary]').count() == 0
    _no_errors(app)
    # a value React cannot draw stops this view with a note; the header, the tabs and the app stay
    app2 = open_app(agent=(200, dict(GUEST_INFO, kernel_version={'release': '6.1'})))
    page2 = app2.page
    page2.locator('.corp-tree-item', has_text='Testi').first.click()
    page2.locator('.corp-tree-child', has_text='web01').first.click()
    note = page2.locator('[data-cr-boundary="vm-summary"]')
    note.wait_for(timeout=10000)
    assert 'This view could not be drawn' in note.inner_text()
    assert page2.locator('[data-cr-objhead="vm"]').count() == 1
    assert page2.locator('.corp-tree-child', has_text='db01').count() == 1
    # another guest draws its summary
    page2.locator('.corp-tree-child', has_text='db01').first.click()
    page2.locator('[data-cr-vm-health]').wait_for(timeout=8000)
    assert not [e for e in app2.errors if e.startswith('pageerror')], app2.errors
