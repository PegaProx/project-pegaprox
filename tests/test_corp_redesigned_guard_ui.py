"""Pixel guard for the Corporate Redesigned preview.

The preview is a scoped skin on top of Corporate. Whatever it adds must not move a single
pixel of the layouts people use today: classic Corporate (dark and light), Modern and Cloud.
Each view is rendered twice, once with the bundle of the base revision (git show) and once
with web/index.html of this checkout, with the same fake data, the same frozen clock and the
same 1600x1000 viewport, and the screenshots must be identical. Nothing is masked: the clock
is fixed, Chromium rasters synchronously, transitions are off and Playwright freezes CSS
animations, so a base run is deterministic by itself. A differing view is shot as one more
base/new pair: a change in the bundle differs again and fails (then the two base shots tell a
flaky page from a change), a one-off hiccup of a busy machine passes with a warning.

Skips without Playwright, Chromium or Pillow (CI has none of them), and when the base revision
is not in the clone. PEGAPROX_GUARD_BASE picks another base revision, PEGAPROX_UI_SHOTS keeps
the shots of a failing view. LW Oct 2026
"""
import calendar
import datetime
import io
import json
import os
import re
import subprocess
import time
import warnings

import pytest

from test_ha_ui import BASE, CLUSTER, NODE_METRICS, VM, VM_CONFIG
from test_hardening_custom_profiles_ui import _ProfileServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# the Testing revision the preview landed on (it was built on b41902c4, the classic fixes since
# then are in the base). A deliberate change to classic Corporate, Modern or Cloud differs from
# it on purpose: once PEGAPROX_UI_SHOTS showed that only the intended views moved, set this to
# the commit of that change (PEGAPROX_GUARD_BASE does it for one run). fe7c2099 put the switch
# and the frozen notice into every classic Corporate view, d72aceb8 the sixth sponsor into the footer,
# a27042b1 the "Contributing" label of the node hardware health that showed its key name,
# c61a5e24 the Modern resources list that scrolls sideways instead of cutting columns off,
# 5d61ba09 the Modern resources search with one icon, which moves the list up by its height
BASE_REV = os.environ.get('PEGAPROX_GUARD_BASE', '5d61ba09')

# 2026-10-30 09:00:00 UTC, what Date.now() says in every guarded page
FIXED = calendar.timegm((2026, 10, 30, 9, 0, 0))

CT = dict(VM, vmid=101, name='ct01', type='lxc', cpu=0.02, cpu_percent=2, maxcpu=1, mem=268435456,
          maxmem=1073741824, mem_percent=25, maxdisk=8589934592)
VM_OFF = dict(VM, vmid=102, name='db01', node='pve2', status='stopped', cpu=0, cpu_percent=0, mem=0,
              mem_percent=0, uptime=0)
RESOURCES = [VM, CT, VM_OFF]
METRICS = {'pve1': dict(NODE_METRICS['pve1']),
           'pve2': dict(NODE_METRICS['pve1'], cpu_percent=12.0, mem_percent=35.0, score=55.0)}


def _upid(node, n, kind, vmid, user='root@pam'):
    return f'UPID:{node}:{n:08X}:00000000:{FIXED:08X}:{kind}:{vmid}:{user}:'


# one per state the task bar knows. The running one started long ago, so the rule of #738
# (open the bar for a task the user just started) stays out of it
TASKS = [
    {'upid': _upid('pve1', 1, 'qmigrate', 100), 'node': 'pve1', 'type': 'qmigrate', 'vmid': '100',
     'status': 'running', 'starttime': FIXED - 600, 'user': 'root@pam', 'pegaprox_user': 'admin'},
    {'upid': _upid('pve2', 2, 'vzdump', 102), 'node': 'pve2', 'type': 'vzdump', 'vmid': '102',
     'status': 'stopped', 'exitstatus': 'OK', 'starttime': FIXED - 3600, 'endtime': FIXED - 3300,
     'user': 'root@pam'},
    {'upid': _upid('pve1', 3, 'vzstart', 101), 'node': 'pve1', 'type': 'vzstart', 'vmid': '101',
     'status': 'stopped', 'exitstatus': 'command failed', 'starttime': FIXED - 7200,
     'endtime': FIXED - 7195, 'user': 'root@pam'},
    {'upid': _upid('pve1', 4, 'qmsnapshot', 100, 'admin@pve'), 'node': 'pve1', 'type': 'qmsnapshot',
     'vmid': '100', 'status': 'error', 'starttime': FIXED - 9000, 'endtime': FIXED - 8990,
     'user': 'admin@pve'},
]

# the three reads of the drift sub tab, in the shapes pegaprox/api/drift.py answers (times are
# naive server time). Round 3 builds the preview's drift page on DriftTab, so the classic one is
# guarded too
DRIFT_STATUS = {
    'cluster_id': 'c1', 'open_total': 3,
    'by_kind': {'vm_config': {'critical': 0, 'warning': 1, 'info': 1}, 'access': {'critical': 1, 'warning': 0, 'info': 0}},
    'by_severity': {'critical': 1, 'warning': 1, 'info': 1},
    'by_category': {'deviation': 2, 'policy_violation': 1, 'incident': 0},
    'planned': 0, 'baselines': 14, 'last_event_at': '2026-10-30T08:10:04.512000',
    'kinds': {'vm_config': 'checked', 'storage': 'checked', 'network': 'partial', 'cluster_options': 'checked',
              'firewall': 'not_checked', 'ha_rules': 'no_baseline', 'backup_jobs': 'checked', 'access': 'checked'},
    'coverage': {'vm_config': {'scopes': 3, 'baselined': 3}, 'storage': {'scopes': 2, 'baselined': 2},
                 'network': {'scopes': 4, 'baselined': 4}, 'cluster_options': {'scopes': 1, 'baselined': 1},
                 'ha_rules': {'scopes': 1, 'baselined': 0}, 'access': {'scopes': 4, 'baselined': 4}},
    'last_scan_at': '2026-10-30T08:30:00.000000',
}
DRIFT_EVENTS = [
    {'id': 31, 'cluster_id': 'c1', 'kind': 'vm_config', 'scope': 'qemu/100', 'severity': 'warning',
     'summary': 'vm_config qemu/100: cores, memory', 'detected_at': '2026-10-30T08:10:04.512000', 'status': 'open',
     'acknowledged_at': None, 'acknowledged_by': None, 'category': 'deviation', 'confirmed_by': None,
     'confirmed_at': None, 'change_id': None,
     'diff': [{'path': 'cores', 'op': 'changed', 'before': 4, 'after': 8},
              {'path': 'memory', 'op': 'changed', 'before': '8192', 'after': '16384'}]},
    {'id': 30, 'cluster_id': 'c1', 'kind': 'access', 'scope': 'policy:access_admin_role', 'severity': 'critical',
     'summary': 'policy access_admin_role: ops@pve', 'detected_at': '2026-10-30T07:40:00.100000', 'status': 'open',
     'acknowledged_at': None, 'acknowledged_by': None, 'category': 'policy_violation', 'confirmed_by': None,
     'confirmed_at': None, 'change_id': None,
     'diff': [{'path': 'ops@pve', 'op': 'violation', 'before': None, 'after': 'Administrator on /'}]},
    {'id': 29, 'cluster_id': 'c1', 'kind': 'vm_config', 'scope': 'lxc/101', 'severity': 'info',
     'summary': 'vm_config lxc/101: description', 'detected_at': '2026-10-29T20:00:00.000000', 'status': 'open',
     'acknowledged_at': None, 'acknowledged_by': None, 'category': 'deviation', 'confirmed_by': None,
     'confirmed_at': None, 'change_id': None,
     'diff': [{'path': 'description', 'op': 'added', 'before': None, 'after': 'web cache'}]},
]
DRIFT_POLICY = {'last_scan_at': '2026-10-30T08:30:00.000000', 'checks': [
    {'id': 'access_admin_role', 'kind': 'access', 'severity': 'critical', 'enabled': True, 'allow': ['root@pam'],
     'status': 'fail', 'violations': [{'path': 'ops@pve', 'detail': 'Administrator on /'}]},
    {'id': 'access_token_expiry', 'kind': 'access', 'severity': 'warning', 'enabled': True, 'status': 'pass', 'violations': []},
    {'id': 'firewall_cluster_enabled', 'kind': 'firewall', 'severity': 'warning', 'enabled': True,
     'status': 'not_checked', 'violations': []},
    {'id': 'backup_none_disabled', 'kind': 'backup_jobs', 'severity': 'warning', 'enabled': False,
     'status': 'disabled', 'violations': []},
]}
DRIFT_READS = {
    ('GET', '/api/clusters/c1/drift/status'): (200, DRIFT_STATUS),
    ('GET', '/api/clusters/c1/drift/events'): (200, {'events': DRIFT_EVENTS}),
    ('GET', '/api/clusters/c1/drift/policy'): (200, DRIFT_POLICY),
}

GUARD_READS = {
    ('GET', '/api/clusters/c1/tasks'): (200, TASKS),
    ('GET', '/api/clusters/c1/vms/pve1/qemu/100/config'): (200, VM_CONFIG),
    **DRIFT_READS,
}

# the Storage Balancing sub tab of the Datastore tab: the datastore list, two storage clusters as
# pegaprox/api/storage.py lists them and the status of the first (an imbalance with one move).
# Round 3 builds the preview's balancing page on this tab, so the classic one is guarded too. Only
# the balancing view is served these, the other views keep the reads they always had
_GIB = 1024 ** 3


def _sb_store(name, kind, total, used, **kw):
    s = {'storage': name, 'type': kind, 'content': 'images,rootdir', 'total': total * _GIB, 'used': used * _GIB,
         'avail': (total - used) * _GIB, 'active': 1, 'enabled': 1, 'shared': True,
         'active_on': ['pve1', 'pve2'], 'inactive_on': []}
    s.update(kw)
    return s


SB_DATASTORES = {'shared': [_sb_store('ceph-a', 'rbd', 1000, 820), _sb_store('ceph-b', 'rbd', 1000, 415),
                            _sb_store('nfs-1', 'nfs', 500, 100), _sb_store('nfs-2', 'nfs', 500, 300)],
                 'local': {'pve1': [], 'pve2': []}, 'nodes': ['pve1', 'pve2'], 'offline_nodes': []}
SB_GROUPS = [
    {'id': 'a1b2c3d4', 'name': 'Ceph pools', 'storages': ['ceph-a', 'ceph-b'], 'threshold': 20, 'enabled': True,
     'auto_balance': True, 'max_concurrent': 1, 'check_interval': 3600, 'last_auto_run': '2026-10-30T08:00:00.000000',
     'created': '2026-10-01T10:00:00.000000', 'type': 'ceph', 'nodes': []},
    {'id': 'e5f6a7b8', 'name': 'NFS shares', 'storages': ['nfs-1', 'nfs-2'], 'threshold': 15, 'enabled': False,
     'auto_balance': False, 'max_concurrent': 1, 'check_interval': 3600, 'last_auto_run': None,
     'created': '2026-10-02T10:00:00.000000', 'type': 'ceph', 'nodes': []},
]
SB_STATUS = {'id': 'a1b2c3d4', 'name': 'Ceph pools', 'enabled': True, 'imbalance': 40.5, 'threshold': 20,
             'storages': [{'storage': 'ceph-a', 'type': 'rbd', 'total': 1000 * _GIB, 'used': 820 * _GIB,
                           'avail': 180 * _GIB, 'usage_percent': 82.0},
                          {'storage': 'ceph-b', 'type': 'rbd', 'total': 1000 * _GIB, 'used': 415 * _GIB,
                           'avail': 585 * _GIB, 'usage_percent': 41.5}],
             'recommendations': [{'type': 'move_disk', 'vmid': 100, 'vm_name': 'web01', 'vm_status': 'running',
                                  'disk': 'scsi0', 'source': 'ceph-a', 'target': 'ceph-b', 'disk_size': 32 * _GIB,
                                  'reason': 'Balance: ceph-a (82.0%) → ceph-b (41.5%)'}],
             '_stats': {'rate_limiter': {}, 'cache': {}, 'cache_hit': False}}
BALANCE_READS = {
    ('GET', '/api/clusters/c1/datastores'): (200, SB_DATASTORES),
    ('GET', '/api/clusters/c1/storage-clusters'): (200, SB_GROUPS),
    ('GET', '/api/clusters/c1/storage-clusters/a1b2c3d4/status'): (200, SB_STATUS),
}

# Round 11 draws Restore tests anew in Corporate Redesigned (Datastore sub tab), so the classic panel is
# guarded with every read it makes: the report, the assurance, the settings and the weekly run,
# in the shapes pegaprox/api/pbs.py answers (times fixed to FIXED)


def _rt_row(vmid, name, state, **kw):
    r = {'vmid': vmid, 'name': name, 'type': 'qemu', 'node': 'pve1', 'tags': [], 'state': state,
         'last_test_at': None, 'last_result': None, 'last_success_at': None, 'last_success_age_days': None,
         'tested_backup_at': None, 'tested_backup_age_hours': None, 'measured_seconds': None, 'rto_seconds': None,
         'rto_state': 'none', 'newest_backup_at': '2026-10-30T02:00:00', 'newest_backup_age_hours': 7.0,
         'backup_count': 4, 'sla_hours': 24, 'rpo_state': 'ok', 'last_failure_at': None, 'last_failure_cause': None,
         'cluster_id': 'c1', 'cluster_name': 'Testi'}
    r.update(kw)
    return r


RT_ROWS = [
    _rt_row(101, 'db01', 'failing', tags=['critical'], last_test_at='2026-10-29T04:10:00', last_result='failed',
            last_failure_at='2026-10-29T04:10:00', last_failure_cause='port 5432: nothing listens',
            rpo_state='breached', newest_backup_age_hours=30.0),
    _rt_row(102, 'mail01', 'never', rpo_state='no_backup', backup_count=0, newest_backup_at=None,
            newest_backup_age_hours=None),
    _rt_row(100, 'web01', 'ok', tags=['critical', 'web'], last_test_at='2026-10-28T16:05:00',
            last_success_at='2026-10-28T16:05:00', last_success_age_days=1.7, tested_backup_at='2026-10-28T02:00:00',
            tested_backup_age_hours=55.0, measured_seconds=245.0, rto_seconds=600, rto_state='met', last_result='passed'),
]
RT_REPORT = {'cluster_id': 'c1', 'cluster_name': 'Testi', 'backups_read_at': '2026-10-30T08:55:00', 'backups_state': 'ok',
             'sla_hours': 24, 'stale_days': 30, 'guests': RT_ROWS,
             'summary': {'ok': 1, 'stale': 0, 'failing': 1, 'never': 1, 'rto_missed': 0, 'total': 3, 'rpo_breached': 1,
                         'no_backup': 1},
             'settings': {'rto_minutes': 10, 'isolation': 'link_down', 'test_bridge': '', 'test_storage': '',
                          'boot_timeout': 180, 'agent': 'auto', 'ports': [], 'command': ''}}
RT_SETTINGS = {'cluster': {'rto_minutes': 10, 'agent': 'auto', 'ports': [22], 'command': '', 'isolation': 'link_down',
                           'test_bridge': '', 'test_storage': '', 'boot_timeout': 180, 'critical_tags': ['critical']},
               'guests': [{'scope': 'guest', 'scope_key': '101', 'rto_minutes': 5, 'agent': None, 'ports': [5432],
                           'command': 'pg_isready', 'updated_at': '2026-10-29T10:00:00', 'updated_by': 'admin'}],
               'tags': [{'scope': 'tag', 'scope_key': 'web', 'rto_minutes': None, 'agent': 'require', 'ports': [443],
                         'command': None, 'updated_at': '2026-10-29T10:00:00', 'updated_by': 'admin'}],
               'can_edit': True, 'limits': {}}
RT_GUESTS = [dict(r, critical='critical' in r['tags'], agent_ok=r['vmid'] == 100, app_ok=False,
                  proof='not_proven', confirmation=None,
                  missing=['application_check'] if r['vmid'] == 100 else ['restore_test', 'agent_check', 'application_check'],
                  gaps={100: ['no_app_checks'], 101: ['app_failing', 'backup_old'], 102: ['no_backup']}[r['vmid']])
             for r in RT_ROWS]
RT_GUESTS[1]['confirmation'] = {'id': '0123456789abcdef', 'vmid': 102, 'text': 'Restored by hand', 'confirmed_by': 'admin',
                                'confirmed_at': '2026-10-29T10:00:00', 'expires_at': '2026-11-29T10:00:00',
                                'revoked_at': None, 'revoked_by': None, 'active': True}
RT_ASSURANCE = {'cluster_id': 'c1', 'cluster_name': 'Testi', 'stale_days': 30, 'backups_state': 'ok',
                'critical_tags': ['critical'],
                'coverage': {'critical': {'total': 2, 'proven': 0, 'not_proven': 2, 'percent': 0.0},
                             'all': {'total': 3, 'proven': 0, 'not_proven': 3, 'percent': 0.0}},
                'gap_counts': {'app_failing': 1, 'no_app_checks': 1, 'backup_old': 1, 'no_backup': 1},
                'gaps': [{'kind': k, 'vmid': g['vmid'], 'name': g['name'], 'critical': g['critical'], 'cluster_id': 'c1',
                          'cluster_name': 'Testi'} for g in RT_GUESTS for k in g['gaps']],
                'plan_gaps': [], 'gaps_truncated': False, 'guests': RT_GUESTS}
RT_POLICY = {'enabled': True, 'weekly_count': 5, 'day': 'sun', 'hour': 4, 'scope': 'latest_per_vm', 'max_age_days': 30,
             'max_backup_gb': 32, 'confirmed_at': FIXED - 30 * 86400}
RT_STATUS = {'policy': RT_POLICY, 'next_run': '2026-11-01T04:00:00', 'running': False, 'timezone': 'Europe/Vienna',
             'last_run': {'slot': '2026-10-25T04:00:00', 'state': 'done', 'started_at': FIXED - 5 * 86400 - 18000,
                          'finished_at': FIXED - 5 * 86400 - 16200, 'reason': '',
                          'picked': [{'cluster_id': 'c1', 'vmid': 101, 'volid': 'pbs:backup/vm/101/a'},
                                     {'cluster_id': 'c1', 'vmid': 100, 'volid': 'pbs:backup/vm/100/a'}],
                          'results': [{'cluster_id': 'c1', 'vmid': 103, 'name': 'big01', 'status': 'skipped',
                                       'reason': 'too_large', 'size': 80 * _GIB, 'limit_gb': 32, 'cause': ''},
                                      {'cluster_id': 'c1', 'vmid': 101, 'name': 'db01', 'status': 'failed',
                                       'cause': 'port 5432: nothing listens', 'task_id': 't1', 'measured_seconds': None},
                                      {'cluster_id': 'c1', 'vmid': 100, 'name': 'web01', 'status': 'passed', 'cause': '',
                                       'task_id': 't2', 'measured_seconds': 245.0, 'rto_met': True}],
                          'counts': {'picked': 2, 'passed': 1, 'failed': 1, 'skipped': 1}}}
RT_READS = {
    ('GET', '/api/clusters/c1/datastores'): (200, SB_DATASTORES),
    ('GET', '/api/clusters/c1/storage-clusters'): (200, []),
    ('GET', '/api/clusters/c1/recovery-report'): (200, RT_REPORT),
    ('GET', '/api/clusters/c1/recovery-assurance'): (200, RT_ASSURANCE),
    ('GET', '/api/clusters/c1/recovery-settings'): (200, RT_SETTINGS),
    ('GET', '/api/pbs/verify-schedule/status'): (200, RT_STATUS),
    ('GET', '/api/pbs/verify-schedule'): (200, RT_POLICY),
}

# Round 11 draws Backup SLA anew in Corporate Redesigned (Datastore sub tab), so the classic sub tab is
# guarded with its read in the shape pegaprox/api/clusters.py answers: one guest per state (expired,
# missing, at risk, compliant), ages on the fixed clock


def _sla_vm(vmid, name, status, age, source='pbs', vtype='vm', node='pve1', power='running'):
    ts = FIXED - int(age * 3600) if age is not None else 0
    return {'vmid': str(vmid), 'type': vtype, 'name': name, 'node': node, 'status': power, 'last_backup_ts': ts,
            'age_hours': age, 'sla_status': status, 'backup_source': source if age is not None else None}


SLA_VMS = [_sla_vm(101, 'db01', 'breached', 30.0), _sla_vm(102, 'mail01', 'no-backup', None, node='pve2', power='stopped'),
           _sla_vm(103, 'proxy01', 'warning', 20.5, source='local', vtype='ct'), _sla_vm(100, 'web01', 'ok', 7.0)]
SLA_REPORT = {'enabled': True, 'max_age_hours': 24, 'now': FIXED, 'cluster_id': 'c1',
              'summary': {'total': 4, 'ok': 1, 'warning': 1, 'breached': 1, 'no_backup': 1, 'disabled': 0,
                          'compliance_pct': 25.0},
              'vms': SLA_VMS}
SLA_READS = {
    ('GET', '/api/clusters/c1/datastores'): (200, SB_DATASTORES),
    ('GET', '/api/clusters/c1/storage-clusters'): (200, []),
    ('GET', '/api/clusters/c1/backup-sla'): (200, SLA_REPORT),
}

# Round 11 draws ISO Sync anew in Corporate Redesigned (Datastore sub tab), so the classic sub tab is
# guarded with its read in the shape get_content_sync_status (pegaprox/core/manager.py) answers: the
# online nodes, one file on every node, one missing on a node, one on a second storage
SYNC_STATUS = {'nodes': ['pve1', 'pve2'],
               'files': [{'name': 'debian-12.7.0-amd64-netinst.iso', 'storage': 'local', 'size': 658505728},
                         {'name': 'ubuntu-24.04.1-live-server-amd64.iso', 'storage': 'local', 'size': 2773874688},
                         {'name': 'virtio-win-0.1.262.iso', 'storage': 'isos', 'size': 739573760}],
               'matrix': {'local:debian-12.7.0-amd64-netinst.iso': {'pve1': True, 'pve2': True},
                          'local:ubuntu-24.04.1-live-server-amd64.iso': {'pve1': True, 'pve2': False},
                          'isos:virtio-win-0.1.262.iso': {'pve1': False, 'pve2': True}}}
# the storages of each node as /datastores lists them (pegaprox/api/vms.py): 'local' on both nodes,
# 'isos' on pve2 only, one shared storage with images
def _sync_local(name, content='iso,vztmpl,backup', **kw):
    return dict({'storage': name, 'type': 'dir', 'content': content, 'total': 100 * _GIB, 'used': 40 * _GIB,
                 'avail': 60 * _GIB, 'used_fraction': 0.4, 'active': 1, 'enabled': 1, 'shared': False,
                 'path': f'/var/lib/{name}', 'nodes': ''}, **kw)


SYNC_DATASTORES = {'shared': [_sb_store('nfs-iso', 'nfs', 500, 100, content='iso,images')],
                   'local': {'pve1': [_sync_local('local')], 'pve2': [_sync_local('local'), _sync_local('isos', 'iso')]},
                   'nodes': ['pve1', 'pve2'], 'offline_nodes': []}
SYNC_READS = {
    ('GET', '/api/clusters/c1/datastores'): (200, SYNC_DATASTORES),
    ('GET', '/api/clusters/c1/storage-clusters'): (200, []),
    ('GET', '/api/clusters/c1/iso-sync/status'): (200, SYNC_STATUS),
    ('GET', '/api/clusters/c1/iso-sync/last-result'): (200, {}),
}

# the Reports summary and the Insights sub tab of a cluster, in the shapes pegaprox/api/reports.py,
# alerts.py and insights.py answer: a day of snapshots (times with the server's offset), the
# top-vms list, a forecast with a storage, right-sizing with two flagged guests, top talkers and
# tag rollups. Round 3 builds the preview's two pages on them, so the classic ones are guarded too
def _report_ts(n, step):
    return [datetime.datetime.fromtimestamp(FIXED - step * (n - 1 - i), tz=datetime.timezone.utc).isoformat()
            for i in range(n)]


def _wave(n, base, spread):
    return [round(base + spread * ((i * 7) % 11) / 10, 1) for i in range(n)]


REPORT_DAY = {
    'period': 'day', 'cluster_id': 'c1', 'cluster_name': 'Testi', 'data_points': 48,
    'timestamps': _report_ts(48, 1800),
    'cpu': {'avg': 9.6, 'min': 4.0, 'max': 15.0, 'current': 11.7, 'samples': _wave(48, 4, 11)},
    'memory': {'avg': 33.4, 'min': 28.0, 'max': 39.0, 'current': 35.0, 'samples': _wave(48, 28, 11)},
    'vms_running': {'avg': 2.5, 'min': 2, 'max': 3, 'current': 2, 'samples': [2 + (i % 2) for i in range(48)]},
    'live': {'cpu_percent': 8.5, 'mem_percent': 27.5, 'vms_running': 1, 'cts_running': 1, 'cpu_total': 0,
             'mem_total': 68719476736, 'mem_used': 18897856102},
}
TOP_VMS = [{'vmid': 100, 'name': 'web01', 'node': 'pve1', 'type': 'qemu', 'cpu': 0.05, 'mem': 1073741824,
            'maxmem': 4294967296, 'mem_percent': 25.0},
           {'vmid': 101, 'name': 'ct01', 'node': 'pve1', 'type': 'lxc', 'cpu': 0.02, 'mem': 268435456,
            'maxmem': 1073741824, 'mem_percent': 25.0}]
INSIGHTS_FORECAST = {
    'cluster_id': 'c1', 'window_days': 30, 'threshold_pct': 90.0, 'snapshots_in_window': 720, 'enough_data': True,
    'forecasts': [
        {'metric': 'cluster_cpu', 'kind': 'cluster', 'current_pct': 11.7, 'slope_per_day_pct': 0.012, 'r_squared': 0.04,
         'threshold_pct': 90.0, 'eta_days': None, 'eta_iso': None, 'status': 'stable', 'samples': 720},
        {'metric': 'cluster_memory', 'kind': 'cluster', 'current_pct': 35.0, 'slope_per_day_pct': 0.41, 'r_squared': 0.18,
         'threshold_pct': 90.0, 'eta_days': 134.1, 'eta_iso': '2027-03-13T11:24:00', 'status': 'trending_up', 'samples': 720},
        {'metric': 'local-lvm', 'kind': 'storage', 'current_pct': 81.2, 'slope_per_day_pct': 0.9, 'r_squared': 0.86,
         'threshold_pct': 90.0, 'eta_days': 9.8, 'eta_iso': '2026-11-09T04:12:00', 'status': 'warning', 'samples': 720,
         'storage': 'local-lvm'},
    ]}
INSIGHTS_RIGHTSIZING = {
    'cluster_id': 'c1', 'window_days': 30, 'snapshots_in_window': 720, 'min_samples_required': 24,
    'summary': {'oversized_cpu': 1, 'oversized_mem': 1, 'undersized_cpu': 0, 'undersized_mem': 0, 'idle': 0,
                'no_data': 1, 'ok': 0},
    'total_vms': 3, 'computed_at': '2026-10-30T08:58:00+00:00', 'refreshing': False,
    'recommendations': [
        {'vmid': '100', 'type': 'qemu', 'name': 'web01', 'node': 'pve1', 'cpu_avg': 2.1, 'cpu_p95': 9.4, 'mem_avg': 18.0,
         'mem_max': 31.0, 'maxcpu': 4, 'maxmem_gb': 4.0, 'samples': 700, 'flags': [
             {'kind': 'oversized_cpu', 'severity': 'info', 'detail': 'avg 2.1% / p95 9.4% on 4 cores', 'current': 4,
              'recommended': 2, 'rationale': 'low CPU utilisation across window - halve cores'},
             {'kind': 'oversized_mem', 'severity': 'info', 'detail': 'avg 18.0% / max 31.0% of 4.0 GB',
              'current_gb': 4.0, 'recommended_gb': 2.0, 'rationale': 'RAM heavily underutilised - halve allocation'}]},
    ]}
INSIGHTS_TOP = {'metric': 'cpu', 'unit': '%', 'limit': 10, 'only_running': True, 'total_vms': 2, 'top': [
    {'vmid': 100, 'name': 'web01', 'type': 'qemu', 'node': 'pve1', 'status': 'running', 'cpu_percent': 5.0,
     'mem_percent': 25.0, 'disk_percent': 0.0, 'disk_io': 7340032000, 'net_io': 1288490188, 'uptime': 3600, 'value': 5.0},
    {'vmid': 101, 'name': 'ct01', 'type': 'lxc', 'node': 'pve1', 'status': 'running', 'cpu_percent': 2.0,
     'mem_percent': 25.0, 'disk_percent': 12.5, 'disk_io': 52428800, 'net_io': 10485760, 'uptime': 7200, 'value': 2.0}]}
INSIGHTS_ROLLUPS = {'group_by': 'tag', 'only_running': False, 'total_vms': 3, 'group_count': 2, 'truncated': False,
                    'limit': 100, 'groups': [
    {'key': '(untagged)', 'vm_count': 2, 'running_count': 1, 'cpu_sum_pct': 2.0, 'mem_used_bytes': 268435456,
     'mem_max_bytes': 5368709120, 'disk_used_bytes': 0, 'disk_max_bytes': 42949672960, 'diskread_bytes': 0,
     'diskwrite_bytes': 0, 'netin_bytes': 0, 'netout_bytes': 0, 'mem_pct': 5.0, 'disk_pct': 0.0},
    {'key': 'web', 'vm_count': 1, 'running_count': 1, 'cpu_sum_pct': 5.0, 'mem_used_bytes': 1073741824,
     'mem_max_bytes': 4294967296, 'disk_used_bytes': 0, 'disk_max_bytes': 34359738368, 'diskread_bytes': 5242880,
     'diskwrite_bytes': 2097152, 'netin_bytes': 1048576, 'netout_bytes': 524288, 'mem_pct': 25.0, 'disk_pct': 0.0}]}
REPORT_READS = {
    ('GET', '/api/clusters/c1/reports/summary'): (200, REPORT_DAY),
    ('GET', '/api/clusters/c1/reports/top-vms'): (200, TOP_VMS),
}
INSIGHTS_READS = {
    ('GET', '/api/clusters/c1/insights/forecast'): (200, INSIGHTS_FORECAST),
    ('GET', '/api/clusters/c1/insights/right-sizing'): (200, INSIGHTS_RIGHTSIZING),
    ('GET', '/api/clusters/c1/insights/top-talkers'): (200, INSIGHTS_TOP),
    ('GET', '/api/clusters/c1/insights/rollups'): (200, INSIGHTS_ROLLUPS),
}
# Reports > What-if: the picker's options and the report of pve1 failing, as pegaprox/core/whatif.py
# answers them for the two nodes and the guests above (generated by the engine, the clock fixed).
# Round 3 builds the preview's what-if page on this sub tab, so the classic one is guarded with a
# report drawn
_WI_GUEST = {'type': 'qemu', 'node': 'pve1', 'outcome': 'down', 'target': None, 'target_basis': None,
             'reason': {'code': 'quorum_lost', 'args': {}}, 'text': 'the cluster loses quorum, HA restarts nothing',
             'basis': 'calculated', 'tenants': [],
             'restore': {'state': 'not_proven', 'detail': 'never', 'last_success_at': None, 'basis': 'known'}}
_WI_NODE = {'cores': 16, 'mem_total': 64 * _GIB, 'cpu_before': 10.0, 'mem_before': 18.8, 'mem_used_before': 12 * _GIB,
            'cpu_threshold': 80.0, 'mem_threshold': 90.0, 'over_cpu': False, 'over_mem': False, 'overcommitted': False,
            'basis': {'before': 'known', 'after': 'calculated'}}
WHATIF_OPTIONS = {
    'supported': True,
    'nodes': [{'name': 'pve1', 'status': 'online', 'maintenance': False}, {'name': 'pve2', 'status': 'online', 'maintenance': False}],
    'storages': [{'storage': 'ceph', 'type': 'rbd', 'nodes': ['pve1', 'pve2'], 'shared': True},
                 {'storage': 'local-lvm', 'type': 'lvmthin', 'nodes': ['pve1', 'pve2'], 'shared': False}],
    'pbs': [{'storage': 'backups', 'nodes': []}], 'critical_tags': {'tags': ['critical'], 'source': 'default'},
    'bridges': [{'name': 'vmbr0', 'nodes': ['pve1', 'pve2'], 'vlan_aware': False}], 'vnets': [],
    'ha': {'readable': True, 'resources': 1, 'pegaprox_ha': False},
    'thresholds': {'cpu': 80.0, 'memory': 90.0, 'cpu_source': 'default', 'memory_source': 'default'}}
WHATIF_REPORT = {
    'supported': True, 'scenario': {'type': 'node_failure', 'memory': 'configured', 'nodes': ['pve1']},
    'generated_at': '2026-10-30T09:00:00Z',
    'summary': {'down': 2, 'degraded': 0, 'restarted': 0, 'moved': 0, 'unknown': 0, 'unaffected': 0, 'running': 2,
                'stopped': 1, 'guests': 3},
    'guests': [dict(_WI_GUEST, vmid=100, name='web01', tags=['critical', 'web'], critical=True),
               dict(_WI_GUEST, vmid=101, name='ct01', type='lxc', tags=[], critical=False)],
    'nodes': [dict(_WI_NODE, node='pve1', state='failed', cpu_after=None, mem_after=None, mem_used_after=None,
                   guests_in=0, guests_out=2),
              dict(_WI_NODE, node='pve2', state='up', cpu_after=10.0, mem_after=18.8, mem_used_after=12 * _GIB,
                   guests_in=0, guests_out=0)],
    'limits': [{'code': 'quorum_lost', 'basis': 'calculated', 'args': {'left': 1, 'need': 2}, 'guests': [],
                'text': 'No quorum: 1 votes are left and 2 are needed, HA restarts nothing'}],
    'reserve': {'mem_to_threshold': 48962627174, 'mem_to_full': 55834574848, 'cpu_to_threshold': 11.2, 'cpu_to_full': 14.4,
                'basis': 'calculated'},
    'thresholds': {'cpu': 80.0, 'memory': 90.0},
    'assumptions': [
        {'code': 'no_service_model', 'args': {}, 'text': 'Services that depend on other guests are not modeled'},
        {'code': 'votes', 'args': {'votes': 2}, 'text': 'Each node has one vote; 2 votes in all'},
        {'code': 'fence_delay', 'args': {}, 'text': 'Restarts begin once the failed node is fenced, about two minutes after it fails'},
        {'code': 'stopped_guests', 'args': {'count': 1},
         'text': 'Stopped guests (1) are not counted as affected or unaffected, they are not running'},
        {'code': 'critical_tags', 'args': {'tags': ['critical']}, 'text': 'Guests tagged critical count as critical'},
        {'code': 'tenant_by_cluster', 'args': {},
         'text': 'A guest has no tenant of its own: it counts for every tenant whose clusters include this one'},
        {'code': 'restore_marks', 'args': {},
         'text': 'A restore is proven by the last restore test of the guest; a guest never tested is not proven'}],
    'reads': {'configs_read': 0, 'configs_cached': 0, 'configs_unread': 0},
    'risk': {'critical': {'tags': ['critical'], 'source': 'default', 'tags_basis': 'known', 'in_cluster': 1, 'affected': 1,
                          'down': 1, 'basis': 'calculated'},
             'tenants': {'items': [], 'readable': True, 'basis': 'assumed'},
             'restore': {'proven': 0, 'not_proven': 2, 'failing': 0, 'unknown': 0, 'basis': 'known'},
             'weight': {'value': 4.0, 'outcomes': {'down': 1.0, 'degraded': 0.5, 'unknown': 0.5, 'restarted': 0.25, 'moved': 0.0},
                        'critical_factor': 3, 'basis': 'calculated'}},
    'verdict': {'level': 'blocked', 'reasons': [
        {'level': 'blocked', 'code': 'guests_down', 'args': {'count': 2}, 'text': '2 guests cannot be placed anywhere and stay down'},
        {'level': 'warning', 'code': 'critical_affected', 'args': {'count': 1, 'names': 'web01'},
         'text': '1 critical guest is affected: web01'},
        {'level': 'warning', 'code': 'restore_unproven', 'args': {'count': 1}, 'text': '1 affected guest has no proven restore'}]},
    'guests_hidden': 0, 'guests_truncated': 0}
WHATIF_READS = {
    ('GET', '/api/clusters/c1/whatif/options'): (200, WHATIF_OPTIONS),
    ('POST', '/api/clusters/c1/whatif'): (200, WHATIF_REPORT),
}
# round 4: the classic node and cluster banners. The HA monitor of Testi reports pve2 offline
# (the red banner of NodeAlertBanner), Edge is not connected and Testi's hardware is degraded
# (the yellow Corporate banner). The preview puts its own strip in their place, so the classic
# ones are guarded with both drawn
ALERT_EDGE = {'id': 'c3', 'name': 'Edge', 'display_name': 'Edge', 'host': '10.0.2.1', 'connected': False,
              'status': 'error', 'cluster_type': 'proxmox', 'enabled': True}
ALERT_STATUS = {'cluster': {'name': 'testi', 'quorate': True, 'standalone': False, 'version': 4},
                'nodes': {'online': 1, 'offline': 1, 'total': 2},
                'guests': {'vms': {'running': 1, 'stopped': 1, 'total': 2}, 'containers': {'running': 1, 'stopped': 0, 'total': 1}},
                'resources': {'cpu': {'total': 16, 'used': 2.4, 'percent': 15.0},
                              'memory': {'total': 64 * _GIB, 'used': 20 * _GIB, 'percent': 31.2},
                              'storage': {'total': 1024 * _GIB, 'used': 300 * _GIB, 'percent': 29.3}},
                'hardware': {'health': 'warning', 'degraded': 1, 'checked': 2}}
ALERT_READS = {
    ('GET', '/api/clusters/c1/ha/status'): (200, {'nodes': {
        'pve1': {'status': 'online', 'last_seen': '2026-10-30T08:59:50', 'consecutive_failures': 0},
        'pve2': {'status': 'offline', 'last_seen': '2026-10-30T08:55:00', 'consecutive_failures': 3}}}),
    ('GET', '/api/clusters/c1/datacenter/status'): (200, ALERT_STATUS),
}


# round 4: the Timeline tab of a cluster. The preview opens it with a kind and a severity picked, so
# the classic one is guarded with rows drawn (times relative to the frozen clock, server shapes of
# pegaprox/api/timeline.py)
def _tl_time(sec_ago):
    return datetime.datetime.fromtimestamp(FIXED - sec_ago, tz=datetime.timezone.utc).isoformat()


def _tl_event(eid, kind, sec_ago, severity, what, title='', node=None, guest=None, guest_name='', params=None):
    return {'id': eid, 'kind': kind, 'time': _tl_time(sec_ago), 'severity': severity, 'cluster': 'c1', 'node': node,
            'guest': guest, 'guest_name': guest_name, 'title': title, 'details': '', 'what': what,
            'params': params or {}, 'source': {'route': '', 'id': eid}, 'anchor': False, 'shortly_before': []}


TIMELINE_READS = {('GET', '/api/timeline'): (200, {
    'events': [_tl_event('node:3', 'node', 300, 'critical', 'node.offline', node='pve2',
                         params={'node': 'pve2', 'previous': 'online'}),
               _tl_event('alert:a1', 'alert', 900, 'warning', 'alert.fired', 'web01 CPU above 80%', guest=100,
                         guest_name='web01'),
               _tl_event('task:u1', 'task', 1800, 'info', 'task', 'qmstart 100', node='pve1', guest=100,
                         guest_name='web01', params={'type': 'qmstart', 'status': 'OK'})],
    'next_before': None, 'sources': {}, 'correlation': {'window_minutes': 10, 'note': ''}})}

# round 4: Datacenter > Summary of Testi with its two reads answered (the status with one node offline
# and the corosync node list, shapes of pegaprox/api/vms.py). The preview draws its own summary there
DC_STATUS = {'cluster': {'name': 'testi', 'quorate': True, 'standalone': False, 'version': 4},
             'nodes': {'online': 1, 'offline': 1, 'total': 2},
             'guests': {'vms': {'running': 1, 'stopped': 1, 'total': 2}, 'containers': {'running': 1, 'stopped': 0, 'total': 1}},
             'resources': {'cpu': {'total': 16, 'used': 2.4, 'percent': 15.0},
                           'memory': {'total': 64 * _GIB, 'used': 20 * _GIB, 'percent': 31.2},
                           'storage': {'total': 1024 * _GIB, 'used': 300 * _GIB, 'percent': 29.3}},
             'hardware': None}
DC_READS = {
    ('GET', '/api/clusters/c1/datacenter/status'): (200, DC_STATUS),
    ('GET', '/api/clusters/c1/datacenter/cluster-info'): (200, [
        {'name': 'pve1', 'node': 'pve1', 'nodeid': '1', 'quorum_votes': '1', 'ring0_addr': '10.0.0.11', 'online': 1},
        {'name': 'pve2', 'node': 'pve2', 'nodeid': '2', 'quorum_votes': '1', 'ring0_addr': '10.0.0.12', 'online': 0}]),
}

# round 4: the Update Manager of the cluster Settings tab, expanded with the package list of pve1 open.
# Its last check is in the browser's copy (updateCheck_<id>, an hour old), so the section shows it and
# fires no check of its own; the status poll answers no run, the schedule its default row (shapes of
# pegaprox/api/settings.py and schedules.py). The preview puts a link card there and draws the Update
# Manager as an Automation sub tab, so the classic one is guarded as it opens
UPD_PKGS = [{'Package': 'pve-manager', 'OldVersion': '9.0.3', 'Version': '9.0.10', 'Origin': 'Proxmox', 'Section': 'admin'},
            {'Package': 'proxmox-kernel-6.14', 'OldVersion': '6.14.8-2', 'Version': '6.14.11-1', 'Origin': 'Proxmox', 'Section': 'kernel'},
            {'Package': 'libssl3', 'OldVersion': '3.0.15-1~deb12u1', 'Version': '3.0.17-1~deb12u2', 'Origin': 'Debian', 'Section': 'libs'}]
UPD_SUMMARY = {'total_updates': 3, 'nodes_with_updates': 1, 'nodes_failed': 0, 'total_nodes': 2, 'pbs_with_updates': 0,
               'total_pbs': 0, 'checked_at': '2026-10-30 08:00:00'}
UPD_NODES = {'pve1': {'success': True, 'updates': UPD_PKGS, 'count': 3, 'retries': 0, 'channel': 'no-subscription',
                      'repo_warnings': 0, 'subscription': 'notfound'},
             'pve2': {'success': True, 'updates': [], 'count': 0, 'retries': 0, 'channel': 'no-subscription',
                      'repo_warnings': 0, 'subscription': 'notfound'}}
UPD_READS = {
    ('GET', '/api/clusters/c1/updates/status'): (200, {'success': True, 'rolling_update': None, 'last_check': '2026-10-30 08:00:00'}),
    ('GET', '/api/clusters/c1/updates/schedule'): (200, {
        'enabled': False, 'schedule_type': 'recurring', 'day': 'sunday', 'time': '03:00', 'include_reboot': True,
        'skip_evacuation': False, 'skip_up_to_date': True, 'evacuation_timeout': 1800, 'migrate_templates': False,
        'relax_anti_affinity': False, 'last_run': None, 'next_run': None}),
    ('GET', '/api/alert-channels'): (200, []),
}
UPD_STORAGE = {'updateCheck_c1': json.dumps({'time': '2026-10-30T08:00:00.000Z', 'summary': UPD_SUMMARY, 'nodes': UPD_NODES})}

# round 4: the performance charts of a node and a guest with their RRD answered (70 slots of the hour
# preset as PVE gives them, a stretch without samples, the two newest slots still empty, the PSI series of
# PVE 9; shapes of get_node_rrddata / get_vm_rrd in pegaprox/core/manager.py). The preview adds options to
# the shared LineChart, so the classic charts are guarded drawn: classic Corporate node Monitor and guest
# summary, the Modern node dialog and metrics dialog, the Cloud metrics dialog
_PERF_TS = [FIXED - 60 * (71 - i) for i in range(70)]


def _perf_wave(base, spread, gap=(30, 34)):
    vals = [round(base + spread * (((i * 7) % 11) / 10.0), 2) for i in range(70)]
    return [None if gap[0] <= i < gap[1] or i >= 68 else v for i, v in enumerate(vals)]


_PERF_PSI = {'pressurecpusome': _perf_wave(1, 2), 'pressurecpufull': _perf_wave(0, 0.5),
             'pressurememorysome': _perf_wave(0.5, 1), 'pressurememoryfull': _perf_wave(0, 0.3),
             'pressureiosome': _perf_wave(2, 3), 'pressureiofull': _perf_wave(1, 2)}
PERF_NODE_RRD = {'timeframe': 'hour', 'node': 'pve1', 'timestamps': _PERF_TS, 'metrics': dict({
    'cpu': _perf_wave(8, 20), 'memory': _perf_wave(40, 6), 'swap': _perf_wave(2, 0.5), 'iowait': _perf_wave(0.5, 3),
    'loadavg': _perf_wave(0.4, 1.2), 'net_in': _perf_wave(120, 80), 'net_out': _perf_wave(60, 50),
    'rootfs': _perf_wave(31, 0.2)}, **_PERF_PSI)}
PERF_GUEST_RRD = {'timeframe': 'hour', 'vmid': 100, 'node': 'pve1', 'type': 'qemu', 'timestamps': _PERF_TS, 'metrics': dict({
    'cpu': _perf_wave(4, 30), 'memory': _perf_wave(45, 10), 'disk_read': _perf_wave(20000, 90000),
    'disk_write': _perf_wave(50000, 120000), 'net_in': _perf_wave(3000, 9000), 'net_out': _perf_wave(1500, 4000)}, **_PERF_PSI)}
PERF_READS = {('GET', '/api/clusters/c1/nodes/pve1/rrddata'): (200, PERF_NODE_RRD)}
PERF_READS.update({('GET', f'/api/clusters/c1/vms/pve1/qemu/100/rrd/{tf}'): (200, PERF_GUEST_RRD)
                   for tf in ('hour', 'day', 'week', 'month', 'year')})

# Round 5 redraws the configuration dialog of a QEMU VM in the preview: its General, Hardware and
# Options tabs are guarded in the classic layouts with a running VM whose config sets the keys these
# tabs draw (and some they do not), the way pegaprox/core/manager.py get_vm_config parses them
# round 6, B1: the node's Configure > Network sub tab and its Summary with the reads they show.
# The list is what PVE's nodes/<node>/network answers (get_node_network_config passes its data
# on): two ports in a bond, a bridge on the bond with the node's address, a VLAN on the bridge,
# a bridge without ports and a VLAN with its raw device set. PVE leaves out 'active' of a down one
NODE_NET = [
    {'iface': 'eno1', 'type': 'eth', 'active': 1, 'exists': 1, 'families': ['inet'], 'method': 'manual'},
    {'iface': 'eno2', 'type': 'eth', 'active': 1, 'exists': 1, 'families': ['inet'], 'method': 'manual'},
    {'iface': 'bond0', 'type': 'bond', 'active': 1, 'slaves': 'eno1 eno2', 'bond_mode': '802.3ad',
     'families': ['inet'], 'method': 'manual'},
    {'iface': 'vmbr0', 'type': 'bridge', 'active': 1, 'autostart': 1, 'bridge_ports': 'bond0',
     'cidr': '10.0.0.11/24', 'address': '10.0.0.11', 'netmask': '24', 'gateway': '10.0.0.254',
     'families': ['inet'], 'method': 'static', 'comments': 'management'},
    {'iface': 'vmbr0.20', 'type': 'vlan', 'active': 1, 'cidr': '10.0.20.11/24', 'families': ['inet'],
     'method': 'static'},
    {'iface': 'vmbr1', 'type': 'bridge', 'autostart': 1, 'bridge_ports': '', 'families': ['inet'],
     'method': 'manual', 'comments': 'guests only'},
    {'iface': 'vlan30', 'type': 'vlan', 'vlan-raw-device': 'bond0', 'vlan-id': 30,
     'families': ['inet'], 'method': 'manual'},
]
NODE_IP = {'ip': '10.0.0.11', 'node': 'pve1', 'source': 'corosync'}
NODE_SUMMARY = {'pveversion': 'pve-manager/9.0.3/abcdef', 'kversion': 'Linux 6.14.8-2-pve #1 SMP',
                'cpuinfo': {'model': 'Intel(R) Xeon(R) CPU E5-2680 v4', 'cores': 4, 'cpus': 8, 'sockets': 1},
                'uptime': 86400, 'cpu': 0.05, 'swap': {'used': 536870912, 'total': 8589934592}, 'ksm': {'shared': 0},
                'loadavg': ['0.10', '0.20', '0.30'], 'memory': {'used': 6871947673, 'total': 34359738368},
                'rootfs': {'used': 10737418240, 'total': 107374182400}}
NODE_BASE_READS = {('GET', '/api/clusters/c1/nodes/pve1/ip'): (200, NODE_IP),
                   ('GET', '/api/clusters/c1/nodes/pve1/summary'): (200, NODE_SUMMARY)}
NODE_NET_READS = {**NODE_BASE_READS, ('GET', '/api/clusters/c1/nodes/pve1/network'): (200, NODE_NET)}

# round 6, B2: the node's Hardware tab and its Configure > Disks sub tab. The sensors are rows of
# get_node_sensors (`sensors -j` flattened: thresholds where the chip has them, a value that is
# missing or text), the history is load_node_temps of 5-minute snapshots (ISO times, as stored), the
# in-band monitoring is switched on and answers as bmc.parse_sensors makes the rows
NODE_SENSORS = {'sensors': [
    {'chip': 'coretemp-isa-0000', 'label': 'Package id 0', 'kind': 'temp', 'value': 54.0, 'max': 80.0, 'crit': 100.0, 'alarm': False},
    {'chip': 'coretemp-isa-0000', 'label': 'Core 0', 'kind': 'temp', 'value': 83.0, 'max': 80.0, 'crit': 100.0, 'alarm': False},
    {'chip': 'coretemp-isa-0000', 'label': 'Core 1', 'kind': 'temp', 'value': 101.0, 'max': 80.0, 'crit': 100.0, 'alarm': True},
    {'chip': 'acpitz-acpi-0', 'label': 'temp1', 'kind': 'temp', 'value': 27.8, 'max': None, 'crit': None, 'alarm': False},
    {'chip': 'acpitz-acpi-0', 'label': 'temp2', 'kind': 'temp', 'value': None, 'max': None, 'crit': None, 'alarm': False},
    {'chip': 'it8728-isa-0a30', 'label': 'temp3', 'kind': 'temp', 'value': '+127.0 (sensor = thermistor)', 'max': None,
     'crit': None, 'alarm': False},
    {'chip': 'it8728-isa-0a30', 'label': 'fan1', 'kind': 'fan', 'value': 1250.0, 'max': None, 'crit': None, 'alarm': False},
    {'chip': 'it8728-isa-0a30', 'label': 'fan2', 'kind': 'fan', 'value': 0.0, 'max': None, 'crit': None, 'alarm': False},
    {'chip': 'it8728-isa-0a30', 'label': 'Vcore', 'kind': 'volt', 'value': 0.95, 'max': 1.74, 'crit': None, 'alarm': False},
    {'chip': 'power_meter-acpi-0', 'label': 'power1', 'kind': 'other', 'value': 112.0, 'max': None, 'crit': None, 'alarm': False},
], 'count': 10}
NODE_TEMPS = {'series': [{'ts': f'2026-10-30T0{h}:{m:02d}:00.123456', 'temp': 48.0 + ((h * 12 + m // 5) % 9)}
                         for h in range(6, 9) for m in range(0, 60, 5)], 'unit': '\u00b0C', 'count': 36}
HW_CONSENT = {'enabled': True, 'current_version': 1, 'acknowledged_by': 'admin', 'acknowledged_at': '2026-10-01T08:00:00',
              'ack_lang': 'en', 'warning': {'title': 'Hardware monitoring', 'body': 'Reads sensors on the node.'}}
RF_CONSENT = {'enabled': False, 'current_version': 1, 'warning': {'title': 'Out-of-band', 'body': 'Uses BMC credentials.'}}
NODE_HW = {'available': True, 'source': 'inband', 'health': 'warning',
           'health_reasons': [{'source': 'sensor', 'label': 'PS2 Status', 'severity': 'warning'}],
           'sensors': [{'name': 'Inlet Temp', 'kind': 'temp', 'value': 24.0, 'unit': '\u00b0C', 'reading': '24 degrees C', 'status': 'ok'},
                       {'name': 'FAN1', 'kind': 'fan', 'value': 5640.0, 'unit': 'RPM', 'reading': '5640 RPM', 'status': 'ok'},
                       {'name': 'FAN4', 'kind': 'fan', 'value': None, 'unit': 'RPM', 'reading': 'No Reading', 'status': 'na'},
                       {'name': 'PS1 Status', 'kind': 'discrete', 'value': None, 'unit': '', 'reading': 'Presence detected', 'status': 'ok'},
                       {'name': 'PS2 Status', 'kind': 'discrete', 'value': None, 'unit': '', 'reading': 'Power Supply AC lost', 'status': 'warning'},
                       {'name': 'Pwr Consumption', 'kind': 'power', 'value': 182.0, 'unit': 'W', 'reading': '182 Watts', 'status': 'ok'},
                       {'name': 'Voltage 1', 'kind': 'volt', 'value': 230.0, 'unit': 'V', 'reading': '230 Volts', 'status': 'ok'}],
           'chassis': {'power': 'on', 'intrusion': 'inactive'}, 'power_w': 182,
           'fru': {'manufacturer': 'Example Systems', 'product': 'R-2U', 'serial': 'SN0001'},
           'events': [{'time': '10/30/2026 07:12:01', 'sensor': 'PS2 Status', 'description': 'Power Supply AC lost', 'severity': 'warning'}]}
NODE_HW_READS = {**NODE_BASE_READS,
                 ('GET', '/api/clusters/c1/nodes/pve1/sensors'): (200, NODE_SENSORS),
                 ('GET', '/api/clusters/c1/nodes/pve1/temperature-history'): (200, NODE_TEMPS),
                 ('GET', '/api/hardware-monitoring/consent'): (200, HW_CONSENT),
                 ('GET', '/api/hardware-monitoring/redfish-consent'): (200, RF_CONSENT),
                 ('GET', '/api/clusters/c1/nodes/pve1/hardware'): (200, NODE_HW)}
# PVE's disks/list as get_node_disks passes it on (wearout is what is left, 'N/A' where PVE has none),
# disks/lvm as the tree PVE answers (volume groups with their physical volumes), lvmthin and zfs lists
NODE_DISKS = [
    {'devpath': '/dev/nvme0n1', 'type': 'nvme', 'size': 1000204886016, 'model': 'NVMe SSD 1TB', 'serial': 'S5GXNX0R000001',
     'vendor': 'unknown', 'health': 'PASSED', 'wearout': 97, 'used': 'LVM', 'gpt': 1, 'rpm': 0, 'osdid': -1,
     'by_id_link': '/dev/disk/by-id/nvme-NVMe_SSD_1TB_S5GXNX0R000001', 'wwn': 'eui.0025385b01234567'},
    {'devpath': '/dev/sda', 'type': 'hdd', 'size': 4000787030016, 'model': 'HDD_4TB', 'serial': 'ZC100001', 'vendor': 'ATA     ',
     'health': 'PASSED', 'wearout': 'N/A', 'used': 'ZFS', 'gpt': 1, 'rpm': 7200, 'osdid': -1,
     'by_id_link': '/dev/disk/by-id/ata-HDD_4TB_ZC100001', 'wwn': '0x5000c500a1b2c3d4'},
    {'devpath': '/dev/sdb', 'type': 'hdd', 'size': 4000787030016, 'model': 'HDD_4TB', 'serial': 'ZC100002', 'vendor': 'ATA     ',
     'health': 'FAILED!', 'wearout': 'N/A', 'used': 'ZFS', 'gpt': 1, 'rpm': 7200, 'osdid': -1,
     'by_id_link': '/dev/disk/by-id/ata-HDD_4TB_ZC100002', 'wwn': '0x5000c500a1b2c3d5'},
    {'devpath': '/dev/sdc', 'type': 'ssd', 'size': 960197124096, 'model': 'SSD_960', 'serial': 'PHYS0003', 'vendor': 'ATA     ',
     'health': 'UNKNOWN', 'wearout': 'N/A', 'used': 'LVM', 'gpt': 0, 'rpm': 0, 'osdid': '3', 'osdid-list': ['3'],
     'by_id_link': '/dev/disk/by-id/ata-SSD_960_PHYS0003', 'wwn': 'unknown'},
    {'devpath': '/dev/sdd', 'type': 'unknown', 'size': 32017047552, 'model': '', 'serial': '', 'vendor': '',
     'health': '', 'wearout': 'N/A', 'used': '', 'gpt': 0, 'rpm': -1, 'osdid': -1},
]
NODE_LVM = {'leaf': 0, 'children': [
    {'leaf': 0, 'name': 'pve', 'size': 999070629888, 'free': 17184063488, 'lvcount': 4,
     'children': [{'leaf': 1, 'name': '/dev/nvme0n1p3', 'size': 999070629888, 'free': 17184063488}]},
    {'leaf': 0, 'name': 'ceph-5a1f', 'size': 960193953792, 'free': 0, 'lvcount': 1,
     'children': [{'leaf': 1, 'name': '/dev/sdc', 'size': 960193953792, 'free': 0}]}]}
NODE_LVMTHIN = [{'lv': 'data', 'vg': 'pve', 'lv_size': 852819443712, 'used': 240580365071, 'metadata_size': 8698986496,
                 'metadata_used': 85250067, 'lv_state': 'a', 'lv_type': 't'}]
NODE_ZFS = [{'name': 'tank', 'size': 3985729650688, 'alloc': 1099511627776, 'free': 2886218022912, 'frag': 3,
             'dedup': 1.0, 'health': 'DEGRADED'}]
NODE_DISK_READS = {**NODE_BASE_READS,
                   ('GET', '/api/clusters/c1/nodes/pve1/disks'): (200, NODE_DISKS),
                   ('GET', '/api/clusters/c1/nodes/pve1/disks/lvm'): (200, NODE_LVM),
                   ('GET', '/api/clusters/c1/nodes/pve1/disks/lvmthin'): (200, NODE_LVMTHIN),
                   ('GET', '/api/clusters/c1/nodes/pve1/disks/zfs'): (200, NODE_ZFS)}

# round 7, B1: the node's Configure > DNS, Hosts File, Time, Certificates and Syslog sub tabs. All five
# come from one read (loadTabData('system')); the answers are what the routes pass on from PVE:
# dns with its digest, the hosts file as {data}, time in epoch seconds (localtime is the shifted
# epoch), the syslog lines newest first, and certificates/info with the fields PVE documents
NODE_DNS = {'search': 'lab.example', 'dns1': '10.0.0.1', 'dns2': '9.9.9.9', 'digest': '4f2a9c'}
NODE_HOSTS = {'data': '127.0.0.1 localhost.localdomain localhost\n10.0.0.11 pve1.lab.example pve1\n\n'
                      '# The following lines are desirable for IPv6 capable hosts\n::1     ip6-localhost ip6-loopback\n'}
NODE_TIME = {'timezone': 'Europe/Vienna', 'time': FIXED, 'localtime': FIXED + 3600}
NODE_SYSLOG = [f'Oct 30 09:{59 - i:02d}:00 pve1 pvedaemon[1{i:03d}]: <root@pam> successful auth for user' for i in range(12)]
NODE_CERTS = [
    {'filename': 'pve-root-ca.pem', 'subject': '/CN=Proxmox Virtual Environment/OU=5a1f/O=PVE Cluster Manager CA',
     'issuer': '/CN=Proxmox Virtual Environment/OU=5a1f/O=PVE Cluster Manager CA', 'notbefore': FIXED - 400 * 86400,
     'notafter': FIXED + 3200 * 86400, 'fingerprint': 'AB:CD:EF:01:23:45', 'public-key-type': 'rsaEncryption',
     'public-key-bits': 4096, 'san': []},
    {'filename': 'pve-ssl.pem', 'subject': '/OU=PVE Cluster Node/O=Proxmox Virtual Environment/CN=pve1.lab.example',
     'issuer': '/CN=Proxmox Virtual Environment/OU=5a1f/O=PVE Cluster Manager CA', 'notbefore': FIXED - 300 * 86400,
     'notafter': FIXED + 20 * 86400, 'fingerprint': '12:34:56:78:9A:BC', 'public-key-type': 'rsaEncryption',
     'public-key-bits': 2048, 'san': ['127.0.0.1', 'localhost', '10.0.0.11', 'pve1', 'pve1.lab.example']},
]
NODE_SYS_READS = {**NODE_BASE_READS,
                  ('GET', '/api/clusters/c1/nodes/pve1/dns'): (200, NODE_DNS),
                  ('GET', '/api/clusters/c1/nodes/pve1/hosts'): (200, NODE_HOSTS),
                  ('GET', '/api/clusters/c1/nodes/pve1/time'): (200, NODE_TIME),
                  ('GET', '/api/clusters/c1/nodes/pve1/syslog'): (200, NODE_SYSLOG),
                  ('GET', '/api/clusters/c1/nodes/pve1/certificates'): (200, NODE_CERTS)}
# the sub nav label of each view and a text it waits for
SYS_VIEWS = {'node_dns': ('DNS', '9.9.9.9'), 'node_hosts': ('Hosts File', 'ip6-loopback'),
             'node_time': ('Time Configuration', '10:00:00'), 'node_certs': ('Certificates', 'pve-ssl.pem'),
             'node_syslog': ('Syslog', 'pvedaemon[1011]')}

# round 7, B2: Configure > LVM, LVM-Thin, ZFS (the disks read above), Repositories and Ceph. The
# repositories are what api/settings.py get_node_repos builds from PVE's apt/repositories: the known
# ones always (exists false where the node has none), the PVE entry under content, and an unknown
# Proxmox source as is_other. Ceph is ceph -s through nodes/<node>/ceph/status, the flattened OSD
# tree, the monitors and the pools as PVE lists them
def _repo(rid, name, enabled, exists, sub, uri='', comp='', file='', index=None, other=False, desc=''):
    content = ({'Types': ['deb'], 'URIs': [uri], 'Suites': ['trixie'], 'Components': [comp],
                'Enabled': 1 if enabled else 0, 'FileType': 'sources'} if exists else None)
    row = {'id': rid, 'name': name, 'description': desc or f'{name} repository', 'requires_subscription': sub,
           'file': file or f'/etc/apt/sources.list.d/{rid}.list', 'actual_file': file if exists else None,
           'expected_line': f'deb {uri} trixie {comp}', 'enabled': bool(enabled and exists), 'exists': exists,
           'content': content, 'index': index}
    if other:
        row.update(uri=uri, is_other=True)
    return row


NODE_REPOS = {'success': True, 'node': 'pve1', 'repositories': [
    _repo('pve-enterprise', 'Proxmox VE Enterprise', False, True, True, 'https://enterprise.proxmox.com/debian/pve',
          'pve-enterprise', '/etc/apt/sources.list.d/pve-enterprise.sources', 0),
    _repo('pve-no-subscription', 'Proxmox VE No-Subscription', True, True, False, 'http://download.proxmox.com/debian/pve',
          'pve-no-subscription', '/etc/apt/sources.list.d/proxmox.sources', 0),
    _repo('ceph-squid', 'Ceph Squid (19.x)', True, True, False, 'http://download.proxmox.com/debian/ceph-squid',
          'no-subscription', '/etc/apt/sources.list.d/ceph.sources', 0),
    _repo('ceph-reef', 'Ceph Reef (18.x)', False, False, False),
    _repo('ceph-quincy', 'Ceph Quincy (17.x)', False, False, False),
    _repo('ceph-enterprise', 'Ceph Enterprise', False, False, True),
    _repo('other-4711', 'download.proxmox.com', False, True, False, 'http://download.proxmox.com/debian/pbs-client',
          'pbs-client', '/etc/apt/sources.list.d/pbs-client.sources', 1, other=True,
          desc='Found in /etc/apt/sources.list.d/pbs-client.sources'),
]}
NODE_CEPH_STATUS = {
    'fsid': '5a1f0c2e-0000-4000-8000-000000000001',
    'health': {'status': 'HEALTH_WARN', 'checks': {
        'OSD_NEARFULL': {'severity': 'HEALTH_WARN', 'summary': {'message': '1 nearfull osd(s)', 'count': 1}, 'muted': False},
        'POOL_NO_REDUNDANCY': {'severity': 'HEALTH_WARN', 'summary': {'message': '1 pool(s) have no replicas configured', 'count': 1}, 'muted': False}}},
    'quorum_names': ['pve1', 'pve2'],
    'monmap': {'num_mons': 3},
    'osdmap': {'epoch': 412, 'num_osds': 3, 'num_up_osds': 3, 'num_in_osds': 2},
    'pgmap': {'pgs_by_state': [{'state_name': 'active+clean', 'count': 96}, {'state_name': 'active+clean+scrubbing', 'count': 1}],
              'num_pgs': 97, 'num_pools': 2, 'bytes_used': 1288490188800, 'bytes_avail': 1610612736000,
              'bytes_total': 2899102924800, 'read_bytes_sec': 2097152, 'write_bytes_sec': 524288},
}
NODE_CEPH_OSD = [
    {'id': 0, 'name': 'osd.0', 'type': 'osd', 'status': 'up', 'in': 1, 'device_class': 'ssd', 'host': 'pve1',
     'percent_used': 86.4, 'total_space': 960193953792, 'bytes_used': 829607576330},
    {'id': 1, 'name': 'osd.1', 'type': 'osd', 'status': 'up', 'in': 1, 'device_class': 'ssd', 'host': 'pve2',
     'percent_used': 40.2, 'total_space': 960193953792, 'bytes_used': 385997969424},
    {'id': 2, 'name': 'osd.2', 'type': 'osd', 'status': 'up', 'in': 0, 'device_class': 'hdd', 'host': 'pve2'},
]
NODE_CEPH_MON = [{'name': 'pve1', 'host': 'pve1', 'addr': '10.0.0.11:6789/0', 'rank': 0, 'quorum': 1},
                 {'name': 'pve2', 'host': 'pve2', 'addr': '10.0.0.12:6789/0', 'rank': 1, 'quorum': 1},
                 {'name': 'pve3', 'host': 'pve3', 'addr': '10.0.0.13:6789/0', 'rank': 2}]
NODE_CEPH_POOL = [{'pool': 1, 'pool_name': '.mgr', 'size': 3, 'min_size': 2, 'pg_num': 1, 'crush_rule': 0,
                   'type': 'replicated', 'bytes_used': 2310144, 'percent_used': 0.0000014,
                   'application_metadata': {'mgr': {}}},
                  {'pool': 2, 'pool_name': 'rbd-vm', 'size': 1, 'min_size': 1, 'pg_num': 96, 'crush_rule': 0,
                   'type': 'replicated', 'bytes_used': 1215652007936, 'percent_used': 0.43,
                   'application_metadata': {'rbd': {}}}]
NODE_STORE_READS = {**NODE_DISK_READS,
                    ('GET', '/api/clusters/c1/nodes/pve1/repos'): (200, NODE_REPOS),
                    ('GET', '/api/clusters/c1/nodes/pve1/ceph/status'): (200, NODE_CEPH_STATUS),
                    ('GET', '/api/clusters/c1/nodes/pve1/ceph/osd'): (200, NODE_CEPH_OSD),
                    ('GET', '/api/clusters/c1/nodes/pve1/ceph/mon'): (200, NODE_CEPH_MON),
                    ('GET', '/api/clusters/c1/nodes/pve1/ceph/pool'): (200, NODE_CEPH_POOL)}
# the sub nav label of each view and a text the classic Corporate view shows once it is drawn (the
# classic LVM table reads a list, so for the tree PVE answers it shows its head and no row)
STORE_VIEWS = {'node_lvm': ('LVM', 'VG'), 'node_lvmthin': ('LVM-Thin', 'Pool'),
               'node_zfs': ('ZFS', 'DEGRADED'), 'node_repos': ('Repositories', 'apt update'),
               'node_ceph': ('Ceph', 'HEALTH_WARN')}

# round 6, B3: the node's Monitor > Tasks sub tab and its VMs tab. The tasks are what PVE's
# nodes/<node>/tasks answers (get_node_tasks passes its data on): a running one has no end time
# and no status, a finished one says OK, WARNINGS: n or the error text. The guests are the
# cluster resources of the node, a template, a stopped guest and a running VM whose agent the IP
# sweep did not find among them (agent_running is set only for running QEMU guests)
def _node_task(n, kind, vmid, ago, took=None, status=None, user='root@pam'):
    row = {'upid': _upid('pve1', n, kind, vmid, user), 'node': 'pve1', 'pid': 4000 + n, 'pstart': 9000 + n,
           'starttime': FIXED - ago, 'type': kind, 'id': str(vmid) if vmid else '', 'user': user}
    if took is not None:
        row['endtime'] = FIXED - ago + took
        row['status'] = status
    return row


NODE_TASK_LIST = [
    _node_task(0x21, 'vzdump', 100, 90),
    _node_task(0x22, 'qmstart', 100, 1800, 3, 'OK'),
    _node_task(0x23, 'vzdump', 101, 3600, 340, 'WARNINGS: 2'),
    _node_task(0x24, 'qmigrate', 100, 5400, 41, 'migration aborted', user='admin@pve'),
    _node_task(0x25, 'aptupdate', '', 7200, 12, 'OK'),
    _node_task(0x26, 'vzstart', 101, 9000, 2, "command 'lxc-start -n 101' failed: exit code 1"),
]
NODE_TASK_READS = {**NODE_BASE_READS, ('GET', '/api/clusters/c1/nodes/pve1/tasks'): (200, NODE_TASK_LIST)}
VM_AGENT = dict(VM, agent_running=True)
GUESTS_PVE1 = [VM_AGENT, CT, VM_OFF,
               dict(VM, vmid=103, name='app02', cpu=0.41, cpu_percent=41, mem=3221225472, mem_percent=75,
                    agent_running=False),
               dict(VM, vmid=104, name='tpl-debian', status='stopped', template=1, cpu=0, cpu_percent=0, mem=0,
                    mem_percent=0, uptime=0),
               dict(CT, vmid=105, name='ct02', status='stopped', cpu=0, cpu_percent=0, mem=0, mem_percent=0, uptime=0)]

# round 9, B1: the node's Monitor > Timeline, a guest's Timeline, the node Shell and the node Subscription.
# The subscription is what PVE's nodes/<node>/subscription answers (get_node_subscription passes its data on)
NODE_SUB = {'status': 'active', 'serverid': '4A1B2C3D4E5F60718293A4B5C6D7E8F9', 'level': 'c',
            'productname': 'Proxmox VE Community Subscription 1 CPU/year', 'key': 'pve1c-0a1b2c3d4e',
            'regdate': '2026-01-15 00:00:00', 'nextduedate': '2027-01-15', 'checktime': FIXED - 86400,
            'url': 'https://www.proxmox.com/en/proxmox-virtual-environment/pricing', 'message': ''}
NODE_SUB_READS = {**NODE_BASE_READS, ('GET', '/api/clusters/c1/nodes/pve1/subscription'): (200, NODE_SUB)}

# round 9, B3: the five classic Reports modules Corporate Redesigned draws anew (CVE Scanner, Cost Dashboard,
# Power & Carbon, Network Topology, API Health), in the shapes pegaprox/api/reports.py, costs.py,
# power.py, topology.py and clusters.py answer. The CVE scan is the POST the button sends
REP_CVE = {
    'cluster_id': 'c1', 'cluster_name': 'Testi', 'scanned_at': '2026-10-30T09:00:00+00:00',
    'nodes': [
        {'node': 'pve1', 'timestamp': '2026-10-30T08:59:40+00:00', 'os': 'Debian GNU/Linux 13 (trixie)',
         'kernel': '6.14.8-2-pve', 'pve_version': 'pve-manager/9.0.10/0123456789abcdef (running kernel: 6.14.8-2-pve)',
         'reboot_required': True, 'debsecan_available': True, 'suite': 'trixie', 'cve_mode': 'fixed', 'cve_total': 3,
         'cve_truncated': False,
         'cves': [
             {'cve': 'CVE-2026-1001', 'package': 'openssl', 'urgency': 'high', 'status': 'fixed, remotely exploitable',
              'fixed': True, 'remote': True, 'obsolete': False, 'first_seen': '2026-10-20T08:00:00', 'fix_type': 'apt'},
             {'cve': 'CVE-2026-1002', 'package': 'pve-qemu-kvm', 'urgency': 'medium', 'status': 'fixed', 'fixed': True,
              'remote': False, 'obsolete': False, 'first_seen': '2026-10-25T08:00:00', 'fix_type': 'pve_upgrade'},
             {'cve': 'CVE-2025-0999', 'package': 'libxml2', 'urgency': 'low', 'status': '', 'fixed': False,
              'remote': False, 'obsolete': False, 'first_seen': '2026-09-01T08:00:00', 'fix_type': 'none'}],
         'packages': [
             {'name': 'openssl', 'current': '3.5.1-1', 'available': '3.5.1-1+deb13u1',
              'source': 'Debian-Security:13/stable-security [amd64]', 'security': True, 'severity': 'critical'},
             {'name': 'curl', 'current': '8.14.1-2', 'available': '8.14.1-2+deb13u1',
              'source': 'Debian-Security:13/stable-security [amd64]', 'security': True, 'severity': 'security'},
             {'name': 'proxmox-widget-toolkit', 'current': '5.0.5', 'available': '5.0.6',
              'source': 'Proxmox:bookworm/pve-no-subscription [all]', 'security': False, 'severity': 'normal'}],
         'cve_count': 3, 'security_count': 2, 'total_count': 3},
        {'node': 'pve2', 'error': 'Node offline'}],
    'summary': {'nodes_scanned': 2, 'nodes_ok': 0, 'total_cves': 3, 'total_security': 2, 'total_updates': 3,
                'debsecan_available': True}}
REP_COST_RATES = {'cluster_id': 'c1', 'cpu_per_core_h': 0.012, 'mem_per_gb_h': 0.0035, 'storage_per_gb_month': 0.1,
                  'currency': 'EUR', 'notes': '', 'updated_at': '2026-10-01 10:00:00', 'updated_by': 'admin'}
REP_COST_ROWS = [
    {'vmid': 100, 'name': 'web01', 'node': 'pve1', 'type': 'qemu', 'avg_cpu_pct': 12.4, 'avg_mem_pct': 48.0,
     'running_ratio': 1.0, 'cores': 4, 'memory_gb': 8.0, 'disk_gb': 32.0, 'cost_cpu': 4.29, 'cost_memory': 9.68,
     'cost_storage': 3.2, 'cost_total': 17.17, 'low_data': False, 'monthly_total': 17.17},
    {'vmid': 101, 'name': 'ct01', 'node': 'pve1', 'type': 'lxc', 'avg_cpu_pct': 2.0, 'avg_mem_pct': 25.0,
     'running_ratio': 1.0, 'cores': 1, 'memory_gb': 1.0, 'disk_gb': 8.0, 'cost_cpu': 0.17, 'cost_memory': 0.63,
     'cost_storage': 0.8, 'cost_total': 1.6, 'low_data': False, 'monthly_total': 1.6},
    {'vmid': 102, 'name': 'db01', 'node': 'pve2', 'type': 'qemu', 'avg_cpu_pct': 0.0, 'avg_mem_pct': 0.0,
     'running_ratio': 0.0, 'cores': 2, 'memory_gb': 4.0, 'disk_gb': 64.0, 'cost_cpu': 0.0, 'cost_memory': 0.0,
     'cost_storage': 6.4, 'cost_total': 6.4, 'low_data': True, 'monthly_total': 6.4}]
REP_COST_SUMMARY = {'enough_data': True, 'cluster_id': 'c1', 'days': 30, 'snapshots_count': 720, 'rates': REP_COST_RATES,
                    'total_window': 25.17, 'monthly_total': 25.17,
                    'monthly_breakdown': {'cpu': 4.46, 'memory': 10.31, 'storage': 10.4},
                    'by_node': {'pve1': 18.77, 'pve2': 6.4}, 'top_spenders': REP_COST_ROWS, 'vm_count': 3,
                    'computed_at': '2026-10-30T08:58:00+00:00', 'refreshing': False}
REP_POWER_RATES = {'cluster_id': 'c1', 'node_idle_w': 80.0, 'node_max_w': 300.0, 'mem_w_per_gb': 0.3, 'pue': 1.5,
                   'kwh_price': 0.3, 'kg_co2_per_kwh': 0.4, 'currency': 'EUR', 'notes': ''}


def _rep_money(kwh):
    return {'kwh': kwh, 'cost': round(kwh * 0.3, 2), 'kg_co2': round(kwh * 0.4, 2)}


def _rep_host(node, profile, idle, mx, kwh, unallocated, status='online'):
    return {'node': node, 'status': status, 'profile': profile, 'idle_w': idle, 'max_w': mx, 'online_h': 720.0,
            'avg_w': round(kwh * 1000 / 1.5 / 720, 1), 'monthly': _rep_money(kwh), 'monthly_unallocated': _rep_money(unallocated)}


REP_POWER_SUMMARY = {
    'enough_data': True, 'cluster_id': 'c1', 'days': 30, 'snapshots_count': 720, 'rates': REP_POWER_RATES,
    'scoped': False, 'vm_count': 2,
    'coverage': {'window_h': 720, 'covered_h': 600.0, 'missing_h': 120.0, 'node_estimated_vms': 1},
    'window': _rep_money(150.0), 'monthly': _rep_money(150.0),
    'by_node': {'pve1': _rep_money(40.0), 'pve2': _rep_money(110.0)}, 'top_consumers': [],
    'hosts': [_rep_host('pve1', 'host', 9.0, 65.0, 40.0, 5.5), _rep_host('pve2', 'cluster', 80.0, 300.0, 110.0, 110.0, 'offline')],
    'allocated': {'window': _rep_money(34.5), 'monthly': _rep_money(34.5)},
    'unallocated': {'window': _rep_money(115.5), 'monthly': _rep_money(115.5)},
    'computed_at': '2026-10-30T08:58:00+00:00', 'refreshing': False}
REP_POWER_ROWS = [
    {'vmid': '100', 'name': 'web01', 'node': 'pve1', 'type': 'qemu', 'avg_cpu_pct': 5.0, 'avg_mem_pct': 25.0,
     'cores': 2, 'memory_gb': 4.0, 'running_h': 720.0, 'kwh': 30.0, 'cost': 9.0, 'kg_co2': 12.0, 'low_data': False,
     'by_node': {'pve1': 20.0, 'pve2': 10.0}, 'node_estimated': True,
     'monthly_kwh': 30.0, 'monthly_cost': 9.0, 'monthly_co2': 12.0},
    {'vmid': '101', 'name': 'ct01', 'node': '', 'type': 'lxc', 'avg_cpu_pct': 1.0, 'avg_mem_pct': 104.0,
     'cores': 1, 'memory_gb': 1.0, 'running_h': 300.0, 'kwh': 4.5, 'cost': 1.35, 'kg_co2': 1.8, 'low_data': True,
     'by_node': {}, 'node_estimated': False, 'monthly_kwh': 4.5, 'monthly_cost': 1.35, 'monthly_co2': 1.8}]
REP_POWER_HOSTS = {'cluster_id': 'c1', 'cluster_profile': {'idle_w': 80.0, 'max_w': 300.0}, 'hosts': [
    {'node': 'pve1', 'in_cluster': True, 'status': 'online', 'cores': 8, 'memory_gb': 32.0, 'profile': 'host',
     'idle_w': 9.0, 'max_w': 65.0, 'notes': 'Small box', 'updated_at': None, 'updated_by': 'root'},
    {'node': 'pve2', 'in_cluster': True, 'status': 'offline', 'cores': 20, 'memory_gb': 64.0, 'profile': 'cluster',
     'idle_w': 80.0, 'max_w': 300.0, 'notes': '', 'updated_at': None, 'updated_by': ''}]}
REP_TOPOLOGY = {
    'cluster': {'id': 'c1', 'name': 'Testi'},
    'nodes': [
        {'id': 'cluster:c1', 'kind': 'cluster', 'label': 'Testi'},
        {'id': 'node:pve1', 'kind': 'node', 'label': 'pve1', 'parent_id': 'cluster:c1',
         'meta': {'cpu_pct': 8.5, 'maxcpu': 16, 'mem_pct': 27.5, 'status': 'online'}},
        {'id': 'node:pve2', 'kind': 'node', 'label': 'pve2', 'parent_id': 'cluster:c1',
         'meta': {'cpu_pct': 0.0, 'maxcpu': 8, 'mem_pct': 0.0, 'status': 'offline'}},
        {'id': 'br:pve1:vmbr0', 'kind': 'bridge', 'label': 'vmbr0', 'parent_id': 'node:pve1',
         'meta': {'address': '10.0.0.11', 'type': 'bridge', 'vlan_aware': True, 'ports': 'bond0'}},
        {'id': 'br:pve1:bond0', 'kind': 'bond', 'label': 'bond0', 'parent_id': 'node:pve1',
         'meta': {'address': '', 'type': 'bond', 'vlan_aware': False, 'ports': 'eno1 eno2'}},
        {'id': 'br:pve2:vmbr0', 'kind': 'bridge', 'label': 'vmbr0', 'parent_id': 'node:pve2',
         'meta': {'address': '10.0.0.12', 'type': 'bridge', 'vlan_aware': False, 'ports': 'eno1'}},
        {'id': 'sdn:vnet1', 'kind': 'sdn_vnet', 'label': 'vnet1', 'parent_id': 'cluster:c1',
         'meta': {'zone': 'zone1', 'tag': 100, 'alias': 'tenant net'}},
        {'id': 'vm:100', 'kind': 'vm', 'label': 'web01', 'parent_id': 'node:pve1', 'meta': {'vmid': 100, 'status': 'running', 'tags': 'web'}},
        {'id': 'ct:101', 'kind': 'ct', 'label': 'ct01', 'parent_id': 'node:pve1', 'meta': {'vmid': 101, 'status': 'running', 'tags': ''}},
        {'id': 'vm:102', 'kind': 'vm', 'label': 'db01', 'parent_id': 'node:pve2', 'meta': {'vmid': 102, 'status': 'stopped', 'tags': ''}}],
    'links': [
        {'source': 'cluster:c1', 'target': 'node:pve1', 'kind': 'tree'},
        {'source': 'cluster:c1', 'target': 'node:pve2', 'kind': 'tree'},
        {'source': 'node:pve1', 'target': 'br:pve1:vmbr0', 'kind': 'has-iface'},
        {'source': 'node:pve1', 'target': 'br:pve1:bond0', 'kind': 'has-iface'},
        {'source': 'node:pve2', 'target': 'br:pve2:vmbr0', 'kind': 'has-iface'},
        {'source': 'cluster:c1', 'target': 'sdn:vnet1', 'kind': 'sdn'},
        {'source': 'vm:100', 'target': 'br:pve1:vmbr0', 'kind': 'attached'},
        {'source': 'ct:101', 'target': 'sdn:vnet1', 'kind': 'attached'}],
    'counts': {'nodes': 2, 'bridges': 3, 'vms': 2, 'cts': 1}}
_REP_MS = [22.0, 31.5, 18.2, 40.0, 1180.0, 25.1, 36.0, 210.4, 19.9, 44.2] * 3
REP_API = {
    'samples': 42, 'window_seconds': 300, 'p50': 38.2, 'p95': 210.4, 'p99': 640.1, 'avg': 61.7, 'max': 1180.0,
    'error_rate': 4.8,
    'recent': [{'ts': FIXED - (29 - i) * 10, 'duration_ms': ms, 'status': 500 if i in (4, 17) else 200, 'method': 'GET'}
               for i, ms in enumerate(_REP_MS)],
    'by_endpoint': [
        {'endpoint': 'GET /nodes/{node}/qemu/{vmid}/status/current', 'count': 18, 'total_ms': 1450.2, 'max_ms': 1180.0,
         'errors': 2, 'avg_ms': 80.6},
        {'endpoint': 'GET /cluster/resources', 'count': 12, 'total_ms': 520.0, 'max_ms': 64.0, 'errors': 0, 'avg_ms': 43.3},
        {'endpoint': 'GET /nodes/{node}/status', 'count': 12, 'total_ms': 380.4, 'max_ms': 40.0, 'errors': 0, 'avg_ms': 31.7}]}
REP_READS = {
    'rep_cve': {('POST', '/api/clusters/c1/reports/cve-scan'): (200, REP_CVE)},
    'rep_costs': {('GET', '/api/clusters/c1/costs/summary'): (200, REP_COST_SUMMARY),
                  ('GET', '/api/clusters/c1/costs/per-vm'): (200, {'enough_data': True, 'cluster_id': 'c1', 'days': 30,
                                                                    'rates': REP_COST_RATES, 'rows': REP_COST_ROWS,
                                                                    'computed_at': '2026-10-30T08:58:00+00:00', 'refreshing': False}),
                  ('GET', '/api/cost/rates/c1'): (200, REP_COST_RATES)},
    'rep_power': {('GET', '/api/clusters/c1/power/summary'): (200, REP_POWER_SUMMARY),
                  ('GET', '/api/clusters/c1/power/per-vm'): (200, {'enough_data': True, 'cluster_id': 'c1', 'days': 30,
                                                                    'rates': REP_POWER_RATES, 'rows': REP_POWER_ROWS}),
                  ('GET', '/api/clusters/c1/power/hosts'): (200, REP_POWER_HOSTS),
                  ('GET', '/api/power/rates/c1'): (200, REP_POWER_RATES)},
    'rep_topology': {('GET', '/api/clusters/c1/topology'): (200, REP_TOPOLOGY)},
    'rep_api': {('GET', '/api/clusters/c1/api-latency'): (200, REP_API)},
}
# round 9, B4: the snapshot overview of Resources as vms.snapshots_overview answers it (oldest first)
RES_SNAPS = {'snapshots': [
    {'vmid': 101, 'vm_name': 'db01', 'vm_type': 'qemu', 'node': 'pve1', 'snapshot_name': 'pre-upgrade',
     'snapshot_date': '2026-08-02 06:10', 'snapshot_ts': 1785651000, 'age': '89 days', 'cluster_id': 'c1'},
    {'vmid': 102, 'vm_name': 'ct01', 'vm_type': 'lxc', 'node': 'pve2', 'snapshot_name': 'before_php84',
     'snapshot_date': '2026-10-28 21:45', 'snapshot_ts': 1793223900, 'age': '1 days', 'cluster_id': 'c1'},
    {'vmid': 100, 'vm_name': 'web01', 'vm_type': 'qemu', 'node': 'pve1', 'snapshot_name': 'nightly',
     'snapshot_date': '2026-10-30 07:00', 'snapshot_ts': 1793336400, 'age': '3 h', 'cluster_id': 'c1'}]}
# and Automation > Affinity Rules as history.get_affinity_rules answers it
AUTO_AFFINITY = {'rules': [
    {'id': 'a1b2c3d4', 'name': 'db pair', 'type': 'separate', 'vms': [100, 101], 'vm_ids': [100, 101], 'enforce': True,
     'enabled': True, 'created_at': '2026-10-12T14:03:11.204512'},
    {'id': 'e5f6a7b8', 'name': 'web with cache', 'type': 'together', 'vms': [100, 999], 'vm_ids': [100, 999], 'enforce': False,
     'enabled': True, 'created_at': '2026-10-20T08:30:00.000001'}]}
# (#1220) Automation > Cloud-Init Template Library as templates_lib.py answers it: the redesign draws
# its own Blueprints & Images there, the classic cards stay
AUTO_TEMPLATES = {
    ('GET', '/api/templates/catalog'): (200, {'templates': [
        {'id': 'debian-13', 'name': 'Debian 13 (Trixie)', 'distro': 'debian', 'version': '13', 'default_user': 'debian',
         'cores': 1, 'memory': 1024, 'disk_gb': 8, 'description': 'Lean Debian generic-cloud image.', 'tags': ['lean']},
        {'id': 'c0ffee12', 'name': 'Company Ubuntu', 'distro': 'ubuntu', 'version': '24.04', 'default_user': 'ops',
         'cores': 2, 'memory': 2048, 'disk_gb': 20, 'description': 'Our hardened base', 'tags': ['custom'], 'custom': True}]}),
    ('GET', '/api/clusters/c1/templates/deployments'): (200, {'deployments': [
        {'id': 't1', 'cluster_id': 'c1', 'node': 'pve1', 'template_id': 'debian-13', 'template_name': 'Debian 13 (Trixie)',
         'vmid': 9001, 'storage': 'local-lvm', 'status': 'completed', 'progress': 100, 'error': '', 'started_by': 'admin',
         'started_at': '2026-10-30T08:30:00', 'finished_at': '2026-10-30T08:32:00'}]}),
    ('GET', '/api/clusters/c1/templates/existing'): (200, {'templates': [{'vmid': 9001, 'name': 'tpl-debian-13', 'node': 'pve1'}]}),
    # Modern draws its blueprints above the cards (#1220): one of them and its deploy
    ('GET', '/api/blueprints'): (200, {'blueprints': [
        {'id': 'b1', 'name': 'web-small', 'description': 'Small web front end', 'source_kind': 'library', 'os': 'linux',
         'templates': {}, 'template_id': 'debian-13', 'template_name': 'Debian 13 (Trixie)', 'template_missing': False,
         'cores': 2, 'memory': 2048, 'disk_gb': 20, 'cpu': '', 'nics': [{'bridge': 'vmbr0', 'vlan': None, 'model': 'virtio', 'firewall': True}],
         'ciuser': 'debian', 'sshkeys': '', 'ip_mode': 'dhcp', 'nameserver': '', 'searchdomain': '', 'ciupgrade': True,
         'tags': ['web'], 'start': True, 'created_by': 'admin', 'created_at': '2026-10-30T08:00:00',
         'updated_at': '2026-10-30T08:00:00', 'can_edit': True}]}),
    ('GET', '/api/blueprints/deployments'): (200, {'deployments': [
        {'id': 'r1', 'blueprint_id': 'b1', 'blueprint_name': 'web-small', 'cluster_id': 'c1', 'node': 'pve1', 'vmid': 120,
         'name': 'web-01', 'status': 'completed', 'step': 'done', 'progress': 100, 'error': '', 'started_by': 'admin',
         'started_at': '2026-10-30T08:40:00', 'finished_at': '2026-10-30T08:42:00'}]}),
}
RES_READS = {'res_snapshots': {('POST', '/api/snapshots/overview'): (200, RES_SNAPS)},
             'auto_affinity': {('GET', '/api/clusters/c1/affinity-rules'): (200, AUTO_AFFINITY)},
             'auto_templates': AUTO_TEMPLATES}
# the Reports sub tab of each (classic label) and the Cloud nav entry that mounts the same component
REP_TABS = {'rep_cve': ('CVE Scanner', None), 'rep_costs': ('Cost Dashboard', 'Costs'),
            'rep_power': ('Power & Carbon', 'Power & Carbon'), 'rep_topology': ('Network Topology', 'Topology'),
            'rep_api': ('API Health', None)}

CFG_RAW = {'name': 'web01', 'tags': 'prod;web', 'description': 'Web front end\n\n**behind** the proxy',
           'cores': 2, 'sockets': 2, 'cpu': 'x86-64-v2-AES,flags=+aes;-pcid', 'memory': '8192', 'balloon': '2048',
           'numa': 1, 'bios': 'ovmf', 'machine': 'pc-q35-8.1', 'scsihw': 'virtio-scsi-single', 'vga': 'std',
           'efidisk0': 'local-lvm:vm-100-disk-1,efitype=4m,pre-enrolled-keys=1,size=4M',
           'scsi0': 'local-lvm:vm-100-disk-0,iothread=1,size=32G', 'ide2': 'none,media=cdrom',
           'net0': 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1', 'onboot': 1, 'protection': 0,
           'agent': '1,fstrim_cloned_disks=1', 'hotplug': 'network,disk,usb', 'ostype': 'l26',
           'boot': 'order=scsi0;ide2;net0', 'cpuunits': 200, 'startup': 'order=2,up=30', 'tablet': 0,
           'meta': 'creation-qemu=8.1.5,ctime=1700000000', 'digest': 'x'}
CFG_RICH = {
    'general': {'name': 'web01', 'description': CFG_RAW['description'], 'tags': CFG_RAW['tags'], 'vmgenid': ''},
    'hardware': {'cores': 2, 'sockets': 2, 'cpu': CFG_RAW['cpu'], 'memory': '8192', 'balloon': '2048', 'numa': 1,
                 'vga': 'std', 'machine': 'pc-q35-8.1', 'bios': 'ovmf', 'scsihw': 'virtio-scsi-single'},
    'disks': [{'id': 'scsi0', 'value': CFG_RAW['scsi0'], 'storage': 'local-lvm', 'size': '32G', 'format': '', 'cache': '',
               'iothread': 1, 'ssd': 0, 'volume': 'vm-100-disk-0'},
              {'id': 'efidisk0', 'value': CFG_RAW['efidisk0'], 'storage': 'local-lvm', 'size': '4M', 'format': '',
               'cache': '', 'iothread': 0, 'ssd': 0, 'volume': 'vm-100-disk-1'},
              {'id': 'ide2', 'value': CFG_RAW['ide2'], 'storage': '', 'size': '', 'media': 'cdrom', 'volume': 'none'}],
    'networks': [{'id': 'net0', 'value': CFG_RAW['net0'], 'bridge': 'vmbr0', 'firewall': 1, 'tag': '', 'rate': '',
                  'mtu': '', 'queues': '', 'link_down': False, 'model': 'virtio', 'macaddr': 'BC:24:11:AA:BB:CC'}],
    'options': {'onboot': 1, 'boot': CFG_RAW['boot'], 'bootdisk': '', 'ostype': 'l26', 'agent': CFG_RAW['agent'],
                'protection': 0, 'tablet': 0, 'hotplug': CFG_RAW['hotplug'], 'acpi': 1, 'kvm': 1, 'smbios1': ''},
    'unused_disks': [], 'raw': CFG_RAW, 'status': {'status': 'running', 'cpu': 0.031, 'mem': 3 * 1024 ** 3},
    'vmid': 100, 'node': 'pve1', 'type': 'qemu', 'lock': {'locked': False}}
CFG_READS = {('GET', '/api/clusters/c1/vms/pve1/qemu/100/config'): (200, CFG_RICH)}
# the tab each configuration view shows, and a text that is on it once it is drawn
CFG_TABS = {'config': ('Hardware', 'Sockets'), 'config_general': (None, 'behind'),
            'config_hardware': ('Hardware', 'Sockets'), 'config_options': ('Options', 'Boot Order'),
            # round 5, B3: the Disks and the Network tab with the rich config
            'config_disks': ('Disks', 'vm-100-disk-0'), 'config_network': ('Network', 'BC:24:11:AA:BB:CC')}

VIEW_READS = {'config_general': CFG_READS, 'config_hardware': CFG_READS, 'config_options': CFG_READS,
              'config_disks': CFG_READS, 'config_network': CFG_READS,
              'balancing': BALANCE_READS, 'recovery': RT_READS, 'sla': SLA_READS, 'sync': SYNC_READS, 'reports': REPORT_READS, 'insights': {**REPORT_READS, **INSIGHTS_READS},
              'whatif': {**REPORT_READS, **WHATIF_READS}, 'alerts': ALERT_READS, 'timeline': TIMELINE_READS,
              'datacenter': DC_READS, 'updates': UPD_READS, 'perf': PERF_READS, 'vmperf': PERF_READS,
              'node_summary': NODE_BASE_READS, 'node_network': NODE_NET_READS,
              'node_hardware': NODE_HW_READS, 'node_disks': NODE_DISK_READS,
              'node_tasks': NODE_TASK_READS, 'node_guests': NODE_BASE_READS,
              **{v: NODE_SYS_READS for v in SYS_VIEWS}, **{v: NODE_STORE_READS for v in STORE_VIEWS},
              'node_timeline': {**NODE_BASE_READS, **TIMELINE_READS}, 'vm_timeline': TIMELINE_READS,
              'node_shell': NODE_BASE_READS, 'node_subscription': NODE_SUB_READS, **REP_READS, **RES_READS}
VIEW_CLUSTERS = {'alerts': [CLUSTER, ALERT_EDGE]}
VIEW_RESOURCES = {'node_guests': GUESTS_PVE1}
VIEW_STORAGE = {'updates': UPD_STORAGE}
# Cloud has no Reports summary; its Insights entry mounts the same InsightsTab and is guarded
NOT_IN = {('cloud', 'reports'): 'Cloud has no Reports summary (its Insights entry is guarded)',
          ('cloud', 'harden'): 'Cloud has no Harden PVE Node tab',
          ('cloud', 'alerts'): 'Cloud mounts its own shell, without the node and cluster banners',
          ('cloud', 'datacenter'): 'Cloud has no Datacenter tab (DatacenterTab is not mounted there)',
          ('cloud', 'perf'): 'Cloud draws no node charts (its metrics dialog of a guest is guarded in vmperf)',
          ('cloud', 'node_summary'): 'Cloud has no node summary (its Hosts page is guarded in node)',
          ('cloud', 'node_network'): 'Cloud has no node network configuration',
          ('cloud', 'node_hardware'): 'Cloud has no node hardware tab',
          ('cloud', 'node_disks'): 'Cloud has no node disk list',
          ('cloud', 'node_tasks'): 'Cloud has no node task list (its Tasks page is guarded in tasks)',
          ('cloud', 'node_guests'): 'Cloud has no guest list of one node',
          ('modern', 'node_guests'): 'The Modern node dialog has no guest list',
          **{('cloud', v): 'Cloud has no node configuration' for v in SYS_VIEWS},
          # these five are sub tabs of the Corporate node view only; the Modern node dialog has its own
          # System tab (not this code), its dialog is guarded in node and node_summary
          **{('modern', v): 'The Modern node dialog has no such Configure sub tab' for v in SYS_VIEWS},
          # B2: the storage, repository and Ceph sub tabs of the Corporate node view (Modern has its own dialog)
          **{('cloud', v): 'Cloud has no node configuration' for v in STORE_VIEWS},
          **{('modern', v): 'The Modern node dialog has no such Configure sub tab' for v in STORE_VIEWS},
          # round 9, B1: Cloud has no node or guest timeline (its cluster Timeline is guarded in timeline),
          # no node shell and no node subscription; the Modern subscription tab is its own code, not touched
          ('cloud', 'node_timeline'): 'Cloud has no node timeline (its cluster Timeline is guarded in timeline)',
          ('cloud', 'vm_timeline'): 'Cloud has no guest timeline (its cluster Timeline is guarded in timeline)',
          ('cloud', 'node_shell'): 'Cloud has no node shell',
          ('cloud', 'node_subscription'): 'Cloud has no node subscription',
          ('modern', 'node_subscription'): 'The Modern node dialog draws its own subscription tab (not this code)',
          # round 9, B3: Cloud draws its own CVE page (CloudCVE) and mounts ApiLatencyDashboard itself (not touched)
          ('cloud', 'rep_cve'): 'Cloud draws its own CVE page (CloudCVE, not this code)',
          ('cloud', 'rep_api'): 'Cloud mounts ApiLatencyDashboard itself, the Reports call site is not on its path',
          # round 9, B4: Cloud lists snapshots on its own page (not the Resources sub tab)
          ('cloud', 'res_snapshots'): 'Cloud has no Resources snapshot overview (its own snapshot page is not this code)',
          ('cloud', 'auto_affinity'): 'Cloud has no Automation tab (its affinity page is not this code)',
          # (#1220) the library and the Resources list with its create buttons: Cloud has its own pages for both
          ('cloud', 'auto_templates'): 'Cloud has no Automation tab (it has no template library page)',
          ('cloud', 'res_list'): 'Cloud lists guests on its own pages (not the Resources tab)'}


class _GuardServer(_ProfileServer):
    """The profile fake (hardening, compliance) with more guests, two nodes, tasks, and the
    bundle under test at /."""

    def __init__(self, bundle=None, extra=None, resources=None, metrics=None, **kw):
        reads = dict(GUARD_READS)
        reads.update(extra or {})
        super().__init__(extra=reads, **kw)
        self.resources = list(RESOURCES if resources is None else resources)
        self.metrics = dict(METRICS if metrics is None else metrics)
        self.bundle = bundle

    def handle(self, route):
        path = re.sub(r'^https?://[^/]+', '', route.request.url).split('?')[0]
        if self.bundle is not None and route.request.url.startswith(BASE) and path in ('/', '/index.html'):
            return route.fulfill(status=200, body=self.bundle, headers={'Content-Type': 'text/html; charset=utf-8'})
        return super().handle(route)


class _GuardApp:
    """_App of test_ha_ui with a frozen clock and a theme picked before the first paint."""

    def __init__(self, browser, server, corp_theme='', storage=None, viewport=(1600, 1000)):
        self.server = server
        self.ctx = browser.new_context(viewport={'width': viewport[0], 'height': viewport[1]})
        # a number would be read as seconds here, a datetime is unambiguous
        self.ctx.clock.set_fixed_time(datetime.datetime.fromtimestamp(FIXED, tz=datetime.timezone.utc))
        seed = {'pegaprox-shortcuts-hint-shown': '1'}
        if corp_theme:
            seed['corp-theme'] = corp_theme
        seed.update(storage or {})
        self.ctx.add_init_script("""(() => { try {
            if (sessionStorage.getItem('guard-seeded')) return;
            sessionStorage.setItem('guard-seeded', '1');
            for (const u of ['admin', 'viewer']) localStorage.setItem('pegaprox_sponsor_v2:' + u, String(Date.now() + 1e10));
            const seed = %s;
            for (const k of Object.keys(seed)) localStorage.setItem(k, seed[k]);
        } catch (e) {} })();""" % json.dumps(seed))
        self.page = self.ctx.new_page()
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(f'pageerror: {e}'))
        self.page.on('console', self._console)
        self.page.route('**/*', server.handle)
        self.page.goto(BASE + '/', wait_until='load')
        self.wait_for_app()
        # no transitions: an element that grows (the task bar, 300 ms) must not leave a row
        # half a pixel off when a busy machine renders it mid-way. Rest states are untouched
        self.page.add_style_tag(content='*, *::before, *::after { transition: none !important; }')
        self.ready = time.time()

    def _console(self, msg):
        if msg.type == 'error' and 'Failed to load resource' not in msg.text and 'net::ERR' not in msg.text:
            self.errors.append(f'console: {msg.text[:300]}')

    def wait_for_app(self):
        self.page.wait_for_function(
            '() => document.querySelector("header") || document.querySelector(".cloud-shell")', timeout=30000)
        self.page.wait_for_timeout(500)

    def open_settings(self):
        self.page.locator('body').click(position={'x': 5, 'y': 400})
        self.page.keyboard.press('g')
        self.page.keyboard.press(',')
        self.page.get_by_text('PegaProx Settings').first.wait_for(timeout=5000)

    def close(self):
        self.ctx.close()


# the fake answers no event stream, and ConnectionLostBanner (ui.js) shows 4 s after that is
# known: every shot waits for it, so no view is taken a moment before or after it appears
BANNER_AFTER = 5.0


def _settle(app, tries=14):
    """The screenshot once two in a row agree: every fetch answered and every list drawn."""
    page = app.page
    page.mouse.move(0, 0)
    wait = BANNER_AFTER - (time.time() - app.ready)
    if wait > 0:
        page.wait_for_timeout(int(wait * 1000))
    prev = None
    for _ in range(tries):
        page.wait_for_timeout(300)
        png = page.screenshot(animations='disabled', caret='hide')
        if png == prev:
            return png
        prev = png
    return prev


# Chromium decodes images and rasters tiles off the main thread by default; then a flag image
# or a gradient edge can land a few anti-aliased pixels apart from one load to the next. These
# switches make it draw everything on the spot, the same way every time
DETERMINISTIC = ['--disable-gpu', '--disable-partial-raster', '--disable-checker-imaging',
                 '--disable-skia-runtime-opts', '--force-color-profile=srgb', '--disable-lcd-text',
                 '--run-all-compositor-stages-before-draw', '--disable-threaded-animation',
                 '--disable-threaded-scrolling', '--disable-image-animation-resync']


@pytest.fixture(scope='module')
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    try:
        br = pw.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()
    pw.stop()


# --- the views ---------------------------------------------------------------------------------

VIEWS = ['dashboard', 'node', 'vm', 'ct', 'config', 'config_general', 'config_hardware', 'config_options', 'config_disks',
         'config_network', 'compliance', 'drift', 'balancing', 'recovery', 'sla', 'sync', 'reports', 'insights',
         'whatif', 'topology', 'settings', 'tasks', 'harden', 'alerts', 'timeline', 'datacenter', 'updates', 'perf',
         'vmperf', 'node_summary', 'node_network', 'node_hardware', 'node_disks', 'node_tasks', 'node_guests',
         'node_dns', 'node_hosts', 'node_time', 'node_certs', 'node_syslog',
         'node_lvm', 'node_lvmthin', 'node_zfs', 'node_repos', 'node_ceph',
         'node_timeline', 'vm_timeline', 'node_shell', 'node_subscription',
         'rep_cve', 'rep_costs', 'rep_power', 'rep_topology', 'rep_api', 'res_snapshots', 'auto_affinity',
         'auto_templates', 'res_list']
RUNS = {'corporate-dark': ('corporate', ''), 'corporate-light': ('corporate', 'light'),
        'modern': ('modern', ''), 'cloud': ('cloud', '')}


def _exact(text):
    return re.compile(r'^\s*' + re.escape(text) + r'\s*$')


def _settled(locator, tries=20):
    """The element once it stays put. A click scrolls it into view, and a page that is still
    laying itself out (a busy machine) would be scrolled to a different spot for each bundle."""
    locator.wait_for(timeout=8000)
    prev = None
    for _ in range(tries):
        box = locator.bounding_box()
        if box is not None and box == prev:
            break
        prev = box
        locator.page.wait_for_timeout(150)
    return locator


def _corp_cluster(page):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='web01').first.wait_for(timeout=8000)


def _modern_cluster(page):
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Node Configuration"]').first.wait_for(timeout=8000)


def _modern_guest(page, name):
    _modern_cluster(page)
    page.locator('button', has_text=_exact('Resources')).first.click()
    page.get_by_placeholder('Search by name or ID...').first.fill(name)
    page.wait_for_timeout(400)
    _settled(page.locator('button[title="Configuration"]').first).click()


def _cloud_nav(page, label):
    page.locator('.cloud-nav-item', has_text=_exact(label)).first.click()


def _cloud_menu_item(page, label):
    # not a mouse click: a base bundle from before the menu moved to the body cuts it off inside the
    # card, and Playwright scrolls the card to reach it, whose scroll event then closes the menu
    page.locator('.cloud-menu-item', has_text=_exact(label)).first.dispatch_event('click')


def _drift_drawn(page):
    # every read answered: the kind tiles, the policy checks and the list
    page.locator('[data-drift-kind="vm_config"]').first.wait_for(timeout=8000)
    page.locator('[data-drift-check="backup_none_disabled"]').first.wait_for(timeout=8000)
    page.get_by_text('qemu/100').first.wait_for(timeout=8000)


def _balancing_drawn(page):
    # the classic sub tab with the first storage cluster open: its toggles, bars and the one move
    page.locator('button', has_text=_exact('Storage Balancing')).first.click()
    page.get_by_text('NFS shares').first.wait_for(timeout=8000)
    page.locator('div.cursor-pointer', has=page.locator('span', has_text=_exact('Ceph pools'))).first.click()
    page.get_by_text('40.5%').first.wait_for(timeout=8000)
    page.get_by_text('Balance: ceph-a').first.wait_for(timeout=8000)


def _recovery_drawn(page):
    # round 11: the classic Restore tests sub tab with every read answered: the weekly run, the
    # assurance tiles, the settings with their rules and the guest table
    page.locator('[data-rtest-tab]').first.click()
    page.locator('[data-rtest-row="100"]').first.wait_for(timeout=8000)
    page.locator('[data-rasr-tile="critical"]').first.wait_for(timeout=8000)
    page.locator('[data-rtest-rule="tag:web"]').first.wait_for(timeout=8000)
    page.locator('[data-rtest-skip="103"]').first.wait_for(timeout=8000)


def _sla_drawn(page):
    # round 11: the classic Backup SLA sub tab with its read answered: the target, the five tiles and
    # one guest per state
    page.locator('button', has_text=_exact('Backup SLA')).first.click()
    page.get_by_text('no-backup', exact=True).first.wait_for(timeout=8000)
    page.get_by_text('proxy01', exact=True).first.wait_for(timeout=8000)
    page.get_by_text('25%', exact=True).first.wait_for(timeout=8000)


def _sync_drawn(page):
    # round 11: the classic ISO Sync sub tab with its read answered: the node columns, a file on every
    # node, one missing on each node
    page.locator('button', has_text=_exact('ISO Sync')).first.click()
    page.get_by_text('virtio-win-0.1.262.iso', exact=True).first.wait_for(timeout=8000)
    page.get_by_text('ubuntu-24.04.1-live-server-amd64.iso', exact=True).first.wait_for(timeout=8000)


def _config_drawn(page, view='config'):
    # the guest's configuration dialog on its hardware tab. Round 3 lets the preview open it on
    # a tab of its choice, so the classic dialog is guarded as it opens and as it switches.
    # Round 5: the General tab as it opens and the Options tab, with the rich config
    tab, mark = CFG_TABS[view]
    page.locator('input[value="web01"]').first.wait_for(timeout=8000)
    if tab:
        page.locator('button', has_text=_exact(tab)).last.click()
    page.get_by_text(mark).first.wait_for(timeout=8000)


def _reports_drawn(page):
    # the summary with its reads answered: the gauges, both charts, the top lists, the node disks
    page.get_by_text('Highest Memory Usage').first.wait_for(timeout=8000)
    page.get_by_text('web01').first.wait_for(timeout=8000)
    page.get_by_text('48 data points', exact=False).first.wait_for(timeout=8000)
    page.wait_for_function('() => document.querySelectorAll("#report-summary-content canvas").length >= 2', timeout=8000)


def _rep_drawn(page, view):
    # round 9, B3: each classic module with its reads answered (the CVE scan started and pve1 opened)
    if view == 'rep_cve':
        page.locator('button', has_text=_exact('Scan All Nodes')).first.click()
        page.locator('#cve-report-content button', has_text='pve1').first.click()
        page.get_by_text('CVE-2026-1001').first.wait_for(timeout=8000)
    elif view == 'rep_costs':
        page.get_by_text('Cost by Node').first.wait_for(timeout=8000)
        page.get_by_text('db01').first.wait_for(timeout=8000)
    elif view == 'rep_power':
        page.get_by_text('Per host').first.wait_for(timeout=8000)
        page.get_by_text('ct01').first.wait_for(timeout=8000)
    elif view == 'rep_topology':
        page.locator('svg text', has_text='vnet1').first.wait_for(timeout=8000)
    elif view == 'rep_api':
        page.get_by_text('Top endpoints by total time').first.wait_for(timeout=8000)
        page.get_by_text('/cluster/resources').first.wait_for(timeout=8000)


def _insights_drawn(page):
    # every card of the sub tab answered: forecast, top talkers, rollups, right-sizing
    page.get_by_text('local-lvm').first.wait_for(timeout=8000)
    page.get_by_text('#101').first.wait_for(timeout=8000)
    page.get_by_text('(untagged)').first.wait_for(timeout=8000)
    page.get_by_text('vmid 100', exact=False).first.wait_for(timeout=8000)


def _whatif_drawn(page):
    # the picker read its options; pve1 picked and run: the verdict, limits, nodes and guests drawn
    page.locator('[data-whatif-node="pve1"]').first.wait_for(timeout=8000)
    page.locator('[data-whatif-node="pve1"]').first.check()
    page.locator('[data-whatif="run"]').first.click()
    page.locator('[data-whatif="report"] [data-whatif-guest="101"]').first.wait_for(timeout=8000)
    page.locator('[data-whatif-assumption="restore_marks"]').first.wait_for(timeout=8000)


def _harden_drawn(page):
    # round 4: Automation > Harden PVE Node with pve1 checked, the summary and the control cards
    page.locator('button', has_text=_exact('Automation')).first.click()
    page.locator('button', has_text=_exact('Harden PVE Node')).first.click()
    page.locator('select', has=page.locator('option', has_text='pve1')).first.select_option('pve1')
    page.locator('button', has_text=_exact('Check Status')).first.click()
    page.get_by_text('controls active', exact=False).first.wait_for(timeout=8000)
    page.get_by_text('Disable Unused Filesystem Modules').first.wait_for(timeout=8000)


def _alerts_drawn(page, layout):
    # round 4: both banners of the scene drawn, the red one from the HA status of the selected cluster
    page.get_by_text('Node pve2 is offline').first.wait_for(timeout=8000)
    if layout.startswith('corporate'):
        page.locator('.corp-warning-banner', has_text='degraded hardware').first.wait_for(timeout=8000)


def _timeline_drawn(page):
    # round 4: the cluster's Timeline tab with its three rows
    page.locator('[data-tl-row="node:3"]').first.wait_for(timeout=8000)
    page.locator('[data-tl-row="task:u1"]').first.wait_for(timeout=8000)


def _datacenter_drawn(page):
    # round 4: the Datacenter tab on its Summary, drawn once the status read answered
    page.locator('button', has_text=_exact('Datacenter')).first.click()
    page.get_by_text('Quorate: Yes', exact=False).first.wait_for(timeout=8000)


def _updates_drawn(page):
    # round 4: the Update Manager section opened, with the package list of pve1 under its card
    head = page.locator('h3', has_text=_exact('Update Manager')).first
    head.wait_for(timeout=8000)
    page.get_by_text('3 Updates available', exact=False).first.wait_for(timeout=8000)
    card = page.locator('div.bg-proxmox-card', has=head).first
    _settled(head).click()
    _settled(card.locator('span', has_text=_exact('pve1')).first).click()
    card.get_by_text('proxmox-kernel-6.14').first.wait_for(timeout=8000)
    head.scroll_into_view_if_needed()


def _charts_drawn(page, n):
    # round 4: n Chart.js charts drawn on their canvases
    page.wait_for_function('(n) => [...document.querySelectorAll("canvas")].filter(c => window.Chart && window.Chart.getChart(c)).length >= n',
                           arg=n, timeout=10000)


def go(app, layout, view):
    """Open a view the way a user would, in the layout's own navigation."""
    page = app.page
    if view == 'dashboard':
        return
    if view == 'settings':
        if layout == 'cloud':
            page.locator('button[title="Settings"]').first.click()
            page.get_by_text('PegaProx Settings').first.wait_for(timeout=5000)
        else:
            app.open_settings()
        return
    if layout == 'cloud':
        if view == 'node':
            _cloud_nav(page, 'Hosts')
        elif view in ('vm', 'ct'):
            _cloud_nav(page, 'Virtual Machines' if view == 'vm' else 'Containers')
            page.locator('.cloud-table-row', has_text='web01' if view == 'vm' else 'ct01').first.click()
        elif view == 'compliance':
            _cloud_nav(page, 'Compliance')
            page.get_by_text('pve1', exact=True).first.wait_for(timeout=8000)
        elif view == 'drift':
            _cloud_nav(page, 'Config Drift')
            _drift_drawn(page)
        elif view == 'balancing':
            _cloud_nav(page, 'Storage Config')
            _balancing_drawn(page)
        elif view == 'recovery':
            _cloud_nav(page, 'Storage Config')
            _recovery_drawn(page)
        elif view == 'sla':
            _cloud_nav(page, 'Storage Config')
            _sla_drawn(page)
        elif view == 'sync':
            _cloud_nav(page, 'Storage Config')
            _sync_drawn(page)
        elif view == 'insights':
            _cloud_nav(page, 'Insights')
            _insights_drawn(page)
        elif view == 'whatif':
            _cloud_nav(page, 'What-if')
            _whatif_drawn(page)
        elif view in CFG_TABS:
            _cloud_nav(page, 'Virtual Machines')
            page.locator('.cloud-table-row', has_text='web01').first.locator('button').last.click()
            _cloud_menu_item(page, 'Edit')
            _config_drawn(page, view)
        elif view == 'topology':
            _cloud_nav(page, 'Topology')
        elif view == 'tasks':
            _cloud_nav(page, 'Tasks')
        elif view == 'timeline':
            _cloud_nav(page, 'Timeline')
            _timeline_drawn(page)
        elif view == 'updates':
            _cloud_nav(page, 'Update Manager')
            _updates_drawn(page)
        elif view in REP_TABS:
            _cloud_nav(page, REP_TABS[view][1])
            _rep_drawn(page, view)
        elif view == 'vmperf':
            _cloud_nav(page, 'Virtual Machines')
            page.locator('.cloud-table-row', has_text='web01').first.locator('button').last.click()
            _cloud_menu_item(page, 'Metrics')
            _charts_drawn(page, 9)
        return
    corp = layout.startswith('corporate')
    if view == 'topology' and corp:
        page.locator('[data-corp-tool="topology"]').first.click()
        page.locator('svg').first.wait_for(timeout=8000)
        return
    if corp:
        _corp_cluster(page)
    elif view not in ('vm', 'ct', 'vmperf', 'vm_timeline') and view not in CFG_TABS:
        _modern_cluster(page)
    if view == 'node':
        if corp:
            page.locator('.corp-tree-child', has_text='pve1').first.click()
        else:
            _settled(page.locator('button[title="Node Configuration"]').first).click()
    elif view in ('vm', 'ct'):
        name = 'web01' if view == 'vm' else 'ct01'
        if corp:
            page.locator('.corp-tree-child', has_text=name).first.click()
        else:
            _modern_guest(page, name)
    elif view in CFG_TABS:
        if corp:
            page.locator('.corp-tree-child', has_text='web01').first.click()
            page.locator('.corp-toolbar button', has_text=_exact('Configure')).first.click()
        else:
            _modern_guest(page, 'web01')
        _config_drawn(page, view)
    elif view == 'compliance':
        page.locator('button', has_text=_exact('Compliance')).first.click()
        page.get_by_text('pve1', exact=True).first.wait_for(timeout=8000)
    elif view == 'drift':
        page.locator('button', has_text=_exact('Compliance')).first.click()
        page.locator('[data-compliance-sub="drift"]').first.click()
        _drift_drawn(page)
    elif view == 'balancing':
        page.locator('button', has_text=_exact('Datastore')).first.click()
        _balancing_drawn(page)
    elif view == 'recovery':
        page.locator('button', has_text=_exact('Datastore')).first.click()
        _recovery_drawn(page)
    elif view == 'sla':
        page.locator('button', has_text=_exact('Datastore')).first.click()
        _sla_drawn(page)
    elif view == 'sync':
        page.locator('button', has_text=_exact('Datastore')).first.click()
        _sync_drawn(page)
    elif view in ('reports', 'insights', 'whatif'):
        page.locator('button', has_text=_exact('Reports')).first.click()
        if view == 'reports':
            _reports_drawn(page)
        elif view == 'insights':
            page.locator('button', has_text=_exact('Insights')).first.click()
            _insights_drawn(page)
        else:
            page.locator('button', has_text=_exact('What-if')).first.click()
            _whatif_drawn(page)
    elif view in REP_TABS:
        page.locator('button', has_text=_exact('Reports')).first.click()
        page.locator('button', has_text=_exact(REP_TABS[view][0])).first.click()
        _rep_drawn(page, view)
    elif view == 'topology':
        page.locator('button', has_text=_exact('Resources')).first.click()
        page.locator('button', has_text=_exact('Topology')).first.click()
    elif view == 'res_snapshots':
        # round 9, B4: Resources > Snapshot Overview with its read answered
        page.locator('button', has_text=_exact('Resources')).first.click()
        page.locator('button', has_text='Snapshot').first.click()
        page.get_by_text('before_php84').first.wait_for(timeout=8000)
    elif view == 'auto_affinity':
        page.locator('button', has_text=_exact('Automation')).first.click()
        page.locator('button', has_text='Affinity').first.click()
        page.get_by_text('web with cache').first.wait_for(timeout=8000)
    elif view == 'auto_templates':
        # (#1220) the library cards with what the cluster has of each; Modern names the sub tab after the
        # blueprints it draws above them
        page.locator('button', has_text=_exact('Automation')).first.click()
        page.locator('button', has_text=re.compile(r'^\s*(Cloud-Init Template Library|Blueprints & Templates)\s*$')).first.click()
        page.get_by_text('Company Ubuntu').first.wait_for(timeout=8000)
    elif view == 'res_list':
        # (#1220) the guest list with the create buttons under it
        page.locator('button', has_text=_exact('Resources')).first.click()
        page.get_by_text('Create new VM').first.wait_for(timeout=8000)
    elif view == 'harden':
        _harden_drawn(page)
    elif view == 'alerts':
        _alerts_drawn(page, layout)
    elif view == 'timeline':
        page.locator('button', has_text=_exact('Timeline')).first.click()
        _timeline_drawn(page)
    elif view == 'datacenter':
        _datacenter_drawn(page)
    elif view == 'updates':
        page.locator('button', has_text=_exact('Settings')).last.click()
        page.locator('[data-update-manager]').first.wait_for(timeout=8000)
        _updates_drawn(page)
    elif view == 'perf':
        if corp:
            page.locator('.corp-tree-child', has_text='pve1').first.click()
            page.locator('.corp-tab-strip button', has_text=_exact('Monitor')).first.click()
            _charts_drawn(page, 7)
        else:
            _settled(page.locator('button[title="Node Configuration"]').first).click()
            page.locator('button', has_text=_exact('Performance')).first.click()
            _charts_drawn(page, 10)
    elif view == 'vmperf':
        if corp:
            page.locator('.corp-tree-child', has_text='web01').first.click()
            _charts_drawn(page, 6)
        else:
            _modern_cluster(page)
            page.locator('button', has_text=_exact('Resources')).first.click()
            page.get_by_text('web01').first.wait_for(timeout=8000)
            page.locator('button[title="List View"]').first.click()
            row = page.locator('table tbody tr', has=page.get_by_text('web01', exact=True)).first
            _settled(row.locator('button[title="Metrics"]')).click()
            _charts_drawn(page, 9)
    elif view == 'node_summary':
        if corp:
            page.locator('.corp-tree-child', has_text='pve1').first.click()
        else:
            _settled(page.locator('button[title="Node Configuration"]').first).click()
        page.get_by_text('E5-2680').first.wait_for(timeout=8000)
    elif view == 'node_network':
        if corp:
            page.locator('.corp-tree-child', has_text='pve1').first.click()
            page.locator('.corp-tab-strip button', has_text=_exact('Configure')).first.click()
        else:
            _settled(page.locator('button[title="Node Configuration"]').first).click()
            page.locator('button', has_text=_exact('Network')).last.click()
        page.get_by_text('vmbr0.20').first.wait_for(timeout=8000)
    elif view == 'node_hardware':
        if corp:
            page.locator('.corp-tree-child', has_text='pve1').first.click()
            page.locator('.corp-tab-strip button', has_text=_exact('Hardware')).first.click()
        else:
            _settled(page.locator('button[title="Node Configuration"]').first).click()
            page.locator('button', has_text=_exact('Hardware')).last.click()
        # the Modern hardware tab is the in-band panel alone (its lm-sensors sit in System)
        if corp:
            page.get_by_text('Package id 0').first.wait_for(timeout=8000)
        page.get_by_text('Pwr Consumption').first.wait_for(timeout=8000)
    elif view == 'node_disks':
        if corp:
            page.locator('.corp-tree-child', has_text='pve1').first.click()
            page.locator('.corp-tab-strip button', has_text=_exact('Configure')).first.click()
            page.locator('.corp-subnav-item', has_text=_exact('Disks')).first.click()
        else:
            _settled(page.locator('button[title="Node Configuration"]').first).click()
            page.locator('button', has_text=_exact('Disks')).last.click()
        page.get_by_text('/dev/nvme0n1').first.wait_for(timeout=8000)
    elif view == 'node_tasks':
        if corp:
            page.locator('.corp-tree-child', has_text='pve1').first.click()
            page.locator('.corp-tab-strip button', has_text=_exact('Monitor')).first.click()
            page.locator('.corp-subnav-item', has_text=_exact('Tasks')).first.click()
            page.get_by_text('migration aborted').first.wait_for(timeout=8000)
        else:
            _settled(page.locator('button[title="Node Configuration"]').first).click()
            page.locator('button', has_text=_exact('Tasks')).last.click()
            page.get_by_text('admin@pve').first.wait_for(timeout=8000)
    elif view in SYS_VIEWS or view in STORE_VIEWS:
        label, text = SYS_VIEWS[view] if view in SYS_VIEWS else STORE_VIEWS[view]
        page.locator('.corp-tree-child', has_text='pve1').first.click()
        page.locator('.corp-tab-strip button', has_text=_exact('Configure')).first.click()
        page.locator('.corp-subnav-item', has_text=_exact(label)).first.click()
        page.get_by_text(text, exact=False).first.wait_for(timeout=8000)
    elif view == 'node_guests':
        page.locator('.corp-tree-child', has_text='pve1').first.click()
        page.locator('.corp-tab-strip button', has_text=_exact('VMs')).first.click()
        page.get_by_text('tpl-debian').first.wait_for(timeout=8000)
    elif view == 'node_timeline':
        if corp:
            page.locator('.corp-tree-child', has_text='pve1').first.click()
            page.locator('.corp-tab-strip button', has_text=_exact('Monitor')).first.click()
            page.locator('[data-corp-node-timeline]').first.click()
        else:
            _settled(page.locator('button[title="Node Configuration"]').first).click()
            page.locator('button', has_text=_exact('Timeline')).last.click()
        _timeline_drawn(page)
    elif view == 'vm_timeline':
        if corp:
            page.locator('.corp-tree-child', has_text='web01').first.click()
            page.locator('[data-corp-vm-timeline]').first.click()
        else:
            # the guest panel of the compact view carries it, opened on demand
            _modern_cluster(page)
            page.locator('button', has_text=_exact('Resources')).first.click()
            page.get_by_text('web01').first.wait_for(timeout=8000)
            page.locator('button[title="Compact View"]').first.click()
            page.locator('div.cursor-pointer', has_text='web01').first.click()
            toggle = page.locator('[data-vm-timeline-toggle]').first
            toggle.wait_for(timeout=8000)
            toggle.scroll_into_view_if_needed()
            _settled(toggle).click()
        _timeline_drawn(page)
    elif view == 'node_shell':
        # the terminal loads, asks for the login; the socket to the shell port finds nobody
        if corp:
            page.locator('.corp-tree-child', has_text='pve1').first.click()
            page.locator('.corp-tab-strip button', has_text=_exact('Shell')).first.click()
        else:
            _settled(page.locator('button[title="Node Configuration"]').first).click()
            page.locator('button', has_text=_exact('Shell')).last.click()
        page.locator('[data-shell-login]').first.wait_for(timeout=8000)
        page.locator('.xterm').first.wait_for(timeout=8000)
    elif view == 'node_subscription':
        page.locator('.corp-tree-child', has_text='pve1').first.click()
        page.locator('.corp-tab-strip button', has_text=_exact('Subscription')).first.click()
        page.get_by_text('Community Subscription', exact=False).first.wait_for(timeout=8000)
    elif view == 'tasks':
        page.locator('.pp-taskbar .cursor-pointer').first.click()
        page.get_by_text('VM Migration').first.wait_for(timeout=8000)
        # the bar grows with a 300 ms transition
        page.wait_for_function('() => document.querySelector(".pp-taskbar").offsetHeight >= 300', timeout=5000)


def shoot(browser, bundle, layout, theme, view):
    server = _GuardServer(bundle=bundle, layout=layout, extra=VIEW_READS.get(view), resources=VIEW_RESOURCES.get(view))
    if view in VIEW_CLUSTERS:
        server.clusters = list(VIEW_CLUSTERS[view])
    app = _GuardApp(browser, server, corp_theme=theme, storage=VIEW_STORAGE.get(view))
    try:
        go(app, layout, view)
        return _settle(app)
    finally:
        app.close()


# --- comparing ---------------------------------------------------------------------------------

def _image(png):
    from PIL import Image
    return Image.open(io.BytesIO(png)).convert('RGB')


def diff_box(a, b):
    """None when the two screenshots are pixel-identical, else (bbox, differing pixel count)."""
    from PIL import ImageChops
    if a == b:
        return None
    ia, ib = _image(a), _image(b)
    if ia.size != ib.size:
        return ((0, 0) + ia.size, ia.size[0] * ia.size[1])
    d = ImageChops.difference(ia, ib)
    box = d.getbbox()
    if box is None:
        return None
    r, g, b = d.split()
    any_band = ImageChops.lighter(ImageChops.lighter(r, g), b).point(lambda v: 255 if v else 0)
    return box, any_band.histogram()[255]


def keep(name, **pngs):
    """Write the shots of a failing view where a human can look at them."""
    out = os.environ.get('PEGAPROX_UI_SHOTS')
    if not out:
        return ''
    os.makedirs(out, exist_ok=True)
    for label, png in pngs.items():
        with open(os.path.join(out, f'guard-{name}-{label}.png'), 'wb') as fh:
            fh.write(png)
    if 'base' in pngs and 'new' in pngs:
        from PIL import ImageChops
        ImageChops.difference(_image(pngs['base']), _image(pngs['new'])).save(
            os.path.join(out, f'guard-{name}-diff.png'))
    return out


@pytest.fixture(scope='module')
def bundles():
    pytest.importorskip('PIL')
    try:
        base = subprocess.run(['git', 'show', f'{BASE_REV}:web/index.html'], cwd=ROOT,
                              capture_output=True, check=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip(f'the base revision {BASE_REV} is not in this clone')
    with open(os.path.join(ROOT, 'web', 'index.html'), 'rb') as fh:
        new = fh.read()
    return {'base': base, 'new': new}


def same_pixels(browser, bundles, run, view):
    """One view of one layout against the base. One test file per layout: this is about 180 shots of
    20 seconds and more, and pytest-xdist's loadfile keeps a file on one worker, so as one file
    it set the length of the whole suite."""
    layout, theme = RUNS[run]
    if (layout, view) in NOT_IN:
        pytest.skip(NOT_IN[(layout, view)])
    base = shoot(browser, bundles['base'], layout, theme, view)
    new = shoot(browser, bundles['new'], layout, theme, view)
    found = diff_box(base, new)
    if found is None:
        return
    # A change in the bundle shows on every load. Under a heavily loaded machine a single
    # load can still land one anti-aliased line apart, so a differing view gets one more pair
    base2 = shoot(browser, bundles['base'], layout, theme, view)
    new2 = shoot(browser, bundles['new'], layout, theme, view)
    if diff_box(base2, new2) is None:
        where = keep(f'{run}-{view}-hiccup', base=base, new=new)
        warnings.warn(f'{run}/{view}: one load differed ({found[1]} pixels in {found[0]}), the next pair '
                      f'was identical. Shots: {where or "-"}')
        return
    flaky = diff_box(base, base2)
    where = keep(f'{run}-{view}', base=base, new=new, again=base2)
    if flaky is not None:
        pytest.fail(f'{run}/{view}: the base bundle itself renders differently from one load to the '
                    f'next ({flaky[1]} pixels in {flaky[0]}), so the guard cannot tell. Shots: {where or "-"}')
    pytest.fail(f'{run}/{view}: {found[1]} pixels differ from {BASE_REV} in {found[0]}. Shots: {where or "-"}')


@pytest.mark.parametrize('view', VIEWS)
def test_classic_corporate_dark_renders_the_same_pixels(browser, bundles, view):
    same_pixels(browser, bundles, 'corporate-dark', view)


def test_the_guard_sees_a_change(browser, bundles):
    """Counterproof: the same view in the preview skin is not pixel-identical to classic
    Corporate, so a zero above means nothing moved, not that the comparison is blind."""
    classic = shoot(browser, bundles['new'], 'corporate', '', 'dashboard')
    preview = shoot(browser, bundles['new'], 'corporate-redesigned', '', 'dashboard')
    found = diff_box(classic, preview)
    assert found is not None and found[1] > 1000, found
