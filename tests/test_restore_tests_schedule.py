"""The weekly restore tests run (background/restore_tests.py).

The PBS view's auto-verify dialog stored a policy (day, hour, how many backups, latest per
guest or any, how old a backup may be) in pegaprox_kv and nothing ever read it: no test
ran. The loop runs it now, on the active instance only:

  * the latest slot of the policy is owed once; it is written as taken before anything
    runs, so a restart or the next leader never runs it again
  * a slot missed while the process was down runs once afterwards, never once per missed
    week; a slot before the policy was switched on is not owed
  * never two runs at once, one test after another, each after a confirmed lease
  * the pick: backups of the guests whose last test is oldest first, never tested before
    all, nothing older than max_age_days, nothing on a node that is not online; one read
    of the guest list and one of the backup storages per cluster, at 10k guests too
  * nothing larger than max_backup_gb (32 for a policy stored before it), nothing of
    unknown size, and nothing onto a storage without the backup's size free or whose
    free space cannot be read; the run says which it left out and why

MK Oct 2026
"""
import re
import threading
import time
import types
from datetime import datetime, timedelta

import pytest

from pegaprox.background import restore_tests as RT
from pegaprox.core import recovery
from pegaprox.core import backup_verify as bv
from pegaprox.globals import cluster_managers

from test_ha_loop_gates import _drive, _recorder, role  # noqa: F401

SUNDAY = datetime(2026, 10, 11, 4, 0)
POLICY = dict(recovery.SCHEDULE_DEFAULT, enabled=True, day='sun', hour=4, weekly_count=3, max_age_days=7)


def _wall(dt):
    return dt.timestamp()


def at_wall(ts):
    return datetime.fromtimestamp(ts)


# --- when a run is owed --------------------------------------------------------------------

def test_the_slot_is_owed_at_its_hour_and_then_not_again():
    state = {'armed_wall': _wall(SUNDAY - timedelta(days=3))}
    assert recovery.due_slot(POLICY, state, SUNDAY - timedelta(minutes=1), at_wall) is None
    assert recovery.due_slot(POLICY, state, SUNDAY + timedelta(seconds=30), at_wall) == SUNDAY
    state['fired_wall'] = _wall(SUNDAY + timedelta(seconds=30))
    assert recovery.due_slot(POLICY, state, SUNDAY + timedelta(hours=5), at_wall) is None
    assert recovery.due_slot(POLICY, state, SUNDAY + timedelta(days=6, hours=23), at_wall) is None
    assert recovery.due_slot(POLICY, state, SUNDAY + timedelta(days=7), at_wall) == SUNDAY + timedelta(days=7)
    assert recovery.next_slot(POLICY, state, SUNDAY + timedelta(hours=5), at_wall) == SUNDAY + timedelta(days=7)


def test_a_missed_slot_runs_once_not_once_per_missed_week():
    # the last run was three weeks ago; the process was down over the two Sundays since
    state = {'fired_wall': _wall(SUNDAY - timedelta(days=21))}
    tuesday = SUNDAY + timedelta(days=2, hours=10)
    assert recovery.due_slot(POLICY, state, tuesday, at_wall) == SUNDAY
    state['fired_wall'] = _wall(tuesday)
    assert recovery.due_slot(POLICY, state, tuesday + timedelta(minutes=1), at_wall) is None
    assert recovery.due_slot(POLICY, state, SUNDAY + timedelta(days=6), at_wall) is None


def test_a_slot_before_the_policy_was_switched_on_is_not_owed():
    state = {'armed_wall': _wall(SUNDAY + timedelta(days=3))}
    assert recovery.due_slot(POLICY, state, SUNDAY + timedelta(days=3, minutes=5), at_wall) is None
    assert recovery.due_slot(POLICY, state, SUNDAY + timedelta(days=7, seconds=5), at_wall) == SUNDAY + timedelta(days=7)
    assert recovery.due_slot(dict(POLICY, enabled=False), {}, SUNDAY, at_wall) is None


def test_switching_on_or_moving_the_slot_arms_it_from_now(db):
    recovery.save_schedule(dict(POLICY, enabled=False))
    assert 'armed_wall' not in recovery.load_state()
    recovery.save_schedule(POLICY, recovery.load_schedule(), now=1000.0)
    assert recovery.load_state()['armed_wall'] == 1000.0
    recovery.save_schedule(dict(POLICY, weekly_count=9), POLICY, now=2000.0)
    assert recovery.load_state()['armed_wall'] == 1000.0           # the count is no new slot
    recovery.save_schedule(dict(POLICY, hour=5), POLICY, now=3000.0)
    assert recovery.load_state()['armed_wall'] == 3000.0


# --- the tick ------------------------------------------------------------------------------

@pytest.fixture
def clock(monkeypatch):
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'schedule_at', at_wall)
    monkeypatch.setattr(RT, '_current', {'thread': None})


def test_a_policy_nobody_ran_yet_starts_with_the_next_slot(db, clock):
    recovery._kv_write(recovery.SCHEDULE_KEY, POLICY)       # stored before this release
    assert RT.tick(now=SUNDAY + timedelta(minutes=1), wall=_wall(SUNDAY + timedelta(minutes=1)), start=False) is None
    assert recovery.load_state()['armed_wall'] == _wall(SUNDAY + timedelta(minutes=1))
    nxt = SUNDAY + timedelta(days=7)
    assert RT.tick(now=nxt, wall=_wall(nxt), start=False) == nxt


def test_the_slot_is_taken_before_anything_runs_and_only_once(db, clock):
    recovery._kv_write(recovery.SCHEDULE_KEY, POLICY)
    recovery.save_state({'armed_wall': _wall(SUNDAY - timedelta(days=1))})
    at = SUNDAY + timedelta(seconds=20)
    assert RT.tick(now=at, wall=_wall(at), start=False) == SUNDAY
    state = recovery.load_state()
    assert state['fired_wall'] == _wall(at) and state['last_run']['state'] == 'starting'
    # a restart: the state is all it has, and the slot is not owed again
    assert RT.tick(now=at + timedelta(minutes=1), wall=_wall(at) + 60, start=False) is None


def test_never_two_runs_at_once(db, clock, monkeypatch):
    recovery._kv_write(recovery.SCHEDULE_KEY, POLICY)
    recovery.save_state({'armed_wall': _wall(SUNDAY - timedelta(days=1))})
    hold = threading.Event()
    t = threading.Thread(target=hold.wait, daemon=True)
    t.start()
    monkeypatch.setattr(RT, '_current', {'thread': t})
    try:
        assert RT.busy()
        assert RT.tick(now=SUNDAY, wall=_wall(SUNDAY), start=False) is None
        assert 'fired_wall' not in recovery.load_state()
    finally:
        hold.set()
        t.join(5)
    assert RT.tick(now=SUNDAY, wall=_wall(SUNDAY), start=False) == SUNDAY


def test_a_slot_a_new_leader_holds_is_reported_not_run(db, clock, monkeypatch):
    from pegaprox.core import ha
    recovery._kv_write(recovery.SCHEDULE_KEY, POLICY)
    recovery.save_state({'armed_wall': _wall(SUNDAY - timedelta(days=1))})
    monkeypatch.setattr(ha, 'schedule_held', lambda at=None: True)
    said = []
    monkeypatch.setattr(ha, 'missed_schedules', lambda kind, names, window, why='': said.append((kind, names)))
    at = SUNDAY + timedelta(hours=2)
    assert RT.tick(now=at, wall=_wall(at), start=False) is None
    assert said == [('restore tests', ['weekly restore test'])]
    assert recovery.load_state()['last_run']['state'] == 'missed'
    assert RT.tick(now=at, wall=_wall(at) + 60, start=False) is None
    assert len(said) == 1


@pytest.mark.parametrize('which,ticks', [('standby', 0), ('active', 1), ('standalone', 1)])
def test_only_the_active_instance_looks_at_the_schedule(which, ticks, role, monkeypatch):  # noqa: F811
    role(which)
    calls = _recorder(monkeypatch, RT, 'tick')
    monkeypatch.setattr(RT, '_running', True)
    _drive(monkeypatch, RT, RT._loop)
    assert len(calls) == ticks


# --- the pick ------------------------------------------------------------------------------

class _Resp:
    def __init__(self, code, data):
        self.status_code, self._data = code, data

    def json(self):
        return {'data': self._data}


NOW = _wall(SUNDAY)
GIB = 1024 ** 3
# what the backup holds, as extractconfig hands it out: one disk, a CD drive
BACKUP_CONFIG = 'name: g\nscsi0: local-lvm:vm-100-disk-0,size=8G\nide2: none,media=cdrom\n'


def _bk(vmid, hours_ago, kind='qemu', storage='pbs', size=2 * GIB):
    t = int(NOW - hours_ago * 3600)
    iso = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(t))
    out = {'volid': f"{storage}:backup/{'vm' if kind == 'qemu' else 'ct'}/{vmid}/{iso}", 'vmid': vmid,
           'ctime': t, 'subtype': kind, 'content': 'backup', 'format': 'pbs-vm'}
    if size is not None:
        out['size'] = size
    return out


class _Mgr:
    cluster_type, is_connected = 'proxmox', True
    host, api_port = 'pve.example', 8006

    def __init__(self, guests, content, nodes=('pve1', 'pve2'), offline=(), storages=None, free=None,
                 backup_config=BACKUP_CONFIG):
        self.config = types.SimpleNamespace(name='Testi', backup_sla_max_age_hours=24)
        self.guests, self.content = guests, content
        self.nodes, self.offline = nodes, offline
        self.storages = storages or [{'storage': 'pbs', 'type': 'pbs', 'content': 'backup'}]
        # bytes free per storage; a storage not named has 500 GB, None does not answer
        self.free, self.backup_config = free or {}, backup_config
        self.calls = []

    def get_vm_resources(self, max_age=0):
        return list(self.guests)

    def _api_get(self, url, timeout=None, params=None):
        path = url.split('/api2/json', 1)[1]
        self.calls.append(path)
        if path == '/nodes':
            return _Resp(200, [{'node': n, 'status': 'online'} for n in self.nodes]
                         + [{'node': n, 'status': 'offline'} for n in self.offline])
        if path == '/storage':
            return _Resp(200, self.storages)
        m = re.fullmatch(r'/nodes/([^/]+)/storage/([^/]+)/content', path)
        if m:
            got = self.content.get(m.group(2))
            if callable(got):
                got = got(m.group(1))
            return _Resp(200, got) if got is not None else _Resp(500, None)
        m = re.fullmatch(r'/nodes/([^/]+)/storage/([^/]+)/status', path)
        if m:
            free = self.free.get(m.group(2), 500 * GIB)
            if free is None:
                return _Resp(500, None)
            return _Resp(200, {'total': 1000 * GIB, 'used': 1000 * GIB - free, 'avail': free, 'active': 1})
        if re.fullmatch(r'/nodes/[^/]+/vzdump/extractconfig', path):
            return _Resp(200, self.backup_config) if self.backup_config is not None else _Resp(500, None)
        return _Resp(404, None)


def _g(vmid, node='pve1', kind='qemu', **kw):
    return dict({'vmid': vmid, 'type': kind, 'node': node, 'name': f'g{vmid}', 'status': 'running'}, **kw)


class _SlotClock:
    """recovery's clock, a minute after the test slot. A run names no time, so pick() reads
    the clock, and the backups here are hours older than SUNDAY: against the real clock
    they went past max_age_days a week after it, and every run test picked nothing."""
    def __getattr__(self, name):
        return getattr(time, name)

    @staticmethod
    def time():
        return NOW + 60


@pytest.fixture
def clusters(db, monkeypatch):
    monkeypatch.setattr(recovery, '_backups', {})
    monkeypatch.setattr(recovery, 'time', _SlotClock())
    saved = dict(cluster_managers)
    cluster_managers.clear()
    yield cluster_managers
    cluster_managers.clear()
    cluster_managers.update(saved)


def _mark(cid, vmid, at, result='passed'):
    recovery.note_result({'cluster_id': cid, 'vmid': vmid, 'status': result, 'id': 'x',
                          'restore_ok': True, 'boot_ok': result == 'passed'}, at=at)


def test_the_guests_tested_longest_ago_come_first(clusters):
    clusters['c1'] = _Mgr([_g(100), _g(101), _g(102), _g(103)],
                          {'pbs': [_bk(100, 2), _bk(100, 30), _bk(101, 3), _bk(102, 4), _bk(103, 5)]})
    _mark('c1', 100, NOW - 86400)          # yesterday
    _mark('c1', 101, NOW - 30 * 86400)     # a month ago
    _mark('c1', 103, NOW - 3600, 'failed')  # an hour ago, failed: tested recently all the same
    picks = recovery.pick(POLICY, clusters, now=NOW)
    # 102 never tested, then 101, then 100; the newest backup of each
    assert [(p['vmid'], p['volid']) for p in picks] == [
        (102, _bk(102, 4)['volid']), (101, _bk(101, 3)['volid']), (100, _bk(100, 2)['volid'])]
    assert picks[0]['node'] == 'pve1' and picks[0]['backup_ts'] == _bk(102, 4)['ctime']


def test_scope_all_takes_another_backup_than_the_one_last_tested(clusters):
    clusters['c1'] = _Mgr([_g(100)], {'pbs': [_bk(100, 2), _bk(100, 26), _bk(100, 50)]})
    recovery.note_result({'cluster_id': 'c1', 'vmid': 100, 'status': 'passed', 'id': 'x',
                          'backup_ts': _bk(100, 2)['ctime']}, at=NOW - 3600)
    picks = recovery.pick(dict(POLICY, scope='all'), clusters, now=NOW)
    assert [p['volid'] for p in picks] == [_bk(100, 26)['volid'], _bk(100, 50)['volid']]
    assert [p['volid'] for p in recovery.pick(POLICY, clusters, now=NOW)] == [_bk(100, 2)['volid']]


def test_what_is_left_out(clusters):
    guests = [_g(100), _g(101, node='pve3'), _g(102, template=1), _g(103, tags='pegaprox-verify'),
              _g(104), _g(105, kind='lxc'), _g(106)]
    content = {'pbs': [_bk(100, 2), _bk(101, 2), _bk(102, 2), _bk(103, 2), _bk(104, 24 * 8),
                       _bk(105, 2, kind='qemu'), _bk(106, 2)]}
    clusters['c1'] = _Mgr(guests, content, offline=('pve3',))
    clusters['c2'] = _Mgr([_g(100)], {'pbs': [_bk(100, 1)]})
    clusters['c2'].is_connected = False
    picks = recovery.pick(dict(POLICY, weekly_count=50), clusters, now=NOW, busy={('c1', 106)})
    # 101: its node is offline; 102 a template; 103 a test guest; 104 too old (7 days);
    # 105 an LXC whose VMID has a VM backup; 106 being tested; c2 not connected
    assert [(p['cluster_id'], p['vmid']) for p in picks] == [('c1', 100)]


def test_a_backup_on_a_local_storage_is_restored_on_its_node(clusters):
    storages = [{'storage': 'local', 'type': 'dir', 'content': 'iso,backup'}]
    content = {'local': lambda node: [dict(_bk(100, 2, storage='local'), volid=f'local:backup/vzdump-qemu-100-{node}.vma.zst')]
               if node == 'pve2' else []}
    clusters['c1'] = _Mgr([_g(100, node='pve1')], content, storages=storages)
    picks = recovery.pick(POLICY, clusters, now=NOW)
    assert picks[0]['node'] == 'pve2'
    # a local storage is listed on every node, a shared one once
    assert sorted(c for c in clusters['c1'].calls if c.endswith('/content')) == [
        '/nodes/pve1/storage/local/content', '/nodes/pve2/storage/local/content']


def test_ten_thousand_guests_cost_three_reads(clusters):
    guests = [_g(1000 + i, node=f'pve{i % 100}') for i in range(10000)]
    content = {'pbs': [_bk(1000 + i, 1 + i % 50) for i in range(10000)]}
    clusters['c1'] = _Mgr(guests, content, nodes=tuple(f'pve{i}' for i in range(100)))
    from pegaprox.core.db import get_db
    conn = get_db().conn
    conn.executemany("INSERT INTO restore_test_marks (cluster_id, vmid, last_at, last_result, ok_at) "
                     "VALUES ('c1', ?, ?, 'passed', ?)",
                     [(1000 + i, NOW - 86400 - i, NOW - 86400 - i) for i in range(0, 10000, 2)])
    conn.commit()
    started = time.time()
    picks = recovery.pick(dict(POLICY, weekly_count=50), clusters, now=NOW)
    assert time.time() - started < 10
    assert len(picks) == 50 and all(p['vmid'] % 2 == 1 for p in picks)      # never tested first
    assert clusters['c1'].calls == ['/nodes', '/storage', '/nodes/pve0/storage/pbs/content']
    # and the next ask within BACKUPS_FRESH reads nothing
    recovery.pick(POLICY, clusters, now=NOW + 60)
    assert len(clusters['c1'].calls) == 3


# --- the size cap --------------------------------------------------------------------------

def test_a_backup_over_the_cap_or_of_unknown_size_is_left_out_and_said_why(clusters):
    clusters['c1'] = _Mgr([_g(100, name='db01'), _g(101), _g(102)],
                          {'pbs': [_bk(100, 2, size=300 * GIB), _bk(101, 3), _bk(102, 4, size=None)]})
    skipped = []
    picks = recovery.pick(POLICY, clusters, now=NOW, skipped=skipped)
    assert [p['vmid'] for p in picks] == [101] and picks[0]['size'] == 2 * GIB
    assert [(s['vmid'], s['reason'], s['size']) for s in skipped] == [
        (100, 'too_large', 300 * GIB), (102, 'size_unknown', None)]
    assert skipped[0]['name'] == 'db01' and skipped[0]['volid'] == _bk(100, 2)['volid']
    # the cap is the policy's: at 512 GB the large one is tested, the unknown one never is
    skipped = []
    picks = recovery.pick(dict(POLICY, max_backup_gb=512), clusters, now=NOW, skipped=skipped)
    assert [p['vmid'] for p in picks] == [100, 101] and [s['vmid'] for s in skipped] == [102]
    # exactly at the cap is within it
    clusters['c1'].content['pbs'][0]['size'] = 32 * GIB
    recovery.forget_backups()
    assert [p['vmid'] for p in recovery.pick(POLICY, clusters, now=NOW)] == [100, 101]


def test_a_policy_stored_before_the_cap_is_held_to_32_gb(clusters):
    old = {k: v for k, v in POLICY.items() if k not in ('max_backup_gb', 'confirmed_at')}
    recovery._kv_write(recovery.SCHEDULE_KEY, old)            # as the dialog stored it months ago
    assert recovery.load_schedule()['max_backup_gb'] == 32
    assert recovery.load_schedule()['enabled'] is True and recovery.load_schedule()['confirmed_at'] is None
    clusters['c1'] = _Mgr([_g(100), _g(101)], {'pbs': [_bk(100, 2, size=33 * GIB), _bk(101, 3, size=31 * GIB)]})
    skipped = []
    assert [p['vmid'] for p in recovery.pick(old, clusters, now=NOW, skipped=skipped)] == [101]
    assert [(s['vmid'], s['reason']) for s in skipped] == [(100, 'too_large')]
    assert recovery.backup_cap(old) == 32 * GIB == recovery.backup_cap(recovery.load_schedule())


def test_only_what_the_run_would_have_tested_is_reported_left_out(clusters):
    # weekly_count 1: 100 (never tested, too large) ranks ahead of 101, the one picked; 102 was
    # tested yesterday and too large, it would not have been tested this week anyway
    clusters['c1'] = _Mgr([_g(100), _g(101), _g(102)],
                          {'pbs': [_bk(100, 2, size=99 * GIB), _bk(101, 3), _bk(102, 1, size=99 * GIB)]})
    _mark('c1', 102, NOW - 86400)
    skipped = []
    picks = recovery.pick(dict(POLICY, weekly_count=1), clusters, now=NOW, skipped=skipped)
    assert [p['vmid'] for p in picks] == [101] and [s['vmid'] for s in skipped] == [100]
    # with the week not full every left-out backup is said, at most SKIPPED_MAX of them
    skipped = []
    recovery.pick(dict(POLICY, weekly_count=5), clusters, now=NOW, skipped=skipped)
    assert [s['vmid'] for s in skipped] == [100, 102]
    many = [_g(1000 + i) for i in range(300)]
    clusters['c1'] = _Mgr(many, {'pbs': [_bk(1000 + i, 1, size=99 * GIB) for i in range(300)]})
    recovery.forget_backups()
    skipped = []
    assert recovery.pick(POLICY, clusters, now=NOW, skipped=skipped) == []
    assert len(skipped) == recovery.SKIPPED_MAX


# --- the free space ------------------------------------------------------------------------

_VOL = 'pbs:backup/vm/100/2026-10-10T02:00:00Z'


def test_room_is_read_on_each_storage_the_restore_writes_to():
    cfg = ('scsi0: local-lvm:vm-100-disk-0,size=8G\nefidisk0: ceph:vm-100-disk-1,size=4M\n'
           'scsi1: big:vm-100-disk-2,backup=0\nide2: local:iso/x.iso,media=cdrom\n'
           'sata0: /dev/disk/by-id/ata-x\nnet0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0\n')
    mgr = _Mgr([], {}, free={'local-lvm': 10 * GIB, 'ceph': 3 * GIB}, backup_config=cfg)
    assert bv.room_for(mgr, 'pve1', _VOL, 'qemu', {'test_storage': ''}, 2 * GIB) is None
    # not the disk left out of the backup, not the CD, not a disk of the node
    assert sorted(c for c in mgr.calls if c.endswith('/status')) == [
        '/nodes/pve1/storage/ceph/status', '/nodes/pve1/storage/local-lvm/status']
    short = bv.room_for(mgr, 'pve1', _VOL, 'qemu', {}, 4 * GIB)
    assert short['reason'] == 'no_space' and short['storage'] == 'ceph' and short['free'] == 3 * GIB
    assert short['size'] == 4 * GIB and '3.0 GB free' in short['cause']
    # the cluster's test storage is where it goes, the backup's config is not read for it
    mgr.calls.clear()
    assert bv.room_for(mgr, 'pve2', _VOL, 'qemu', {'test_storage': 'scratch'}, 4 * GIB) is None
    assert mgr.calls == ['/nodes/pve2/storage/scratch/status']
    # a container without one goes back to the storages of its volumes (#1168), not its
    # bind mount; one whose rootfs cannot be placed is left to Proxmox, which takes 'local'
    mgr.calls.clear()
    mgr.backup_config = ('rootfs: data-pool:subvol-100-disk-0,size=8G\n'
                         'mp0: vm-pool:vm-100-disk-1,mp=/srv,size=32G\nmp1: /mnt/nas,mp=/nas\n')
    mgr.free['vm-pool'] = GIB
    short = bv.room_for(mgr, 'pve1', 'pbs:backup/ct/100/x', 'lxc', {}, 2 * GIB)
    assert short['reason'] == 'no_space' and short['storage'] == 'vm-pool'
    assert sorted(c for c in mgr.calls if c.endswith('/status')) == [
        '/nodes/pve1/storage/data-pool/status', '/nodes/pve1/storage/vm-pool/status']
    mgr.calls.clear()
    mgr.backup_config = 'rootfs: data-pool:subvol-100-disk-0\n'
    mgr.free['local'] = GIB
    assert bv.room_for(mgr, 'pve1', 'pbs:backup/ct/100/x', 'lxc', {}, 2 * GIB)['storage'] == 'local'
    assert [c for c in mgr.calls if c.endswith('/status')] == ['/nodes/pve1/storage/local/status']


@pytest.mark.parametrize('case', ['status_error', 'not_active', 'no_avail', 'raises', 'config_unreadable',
                                  'odd_storage_name'])
def test_free_space_that_cannot_be_read_is_no_room(case, monkeypatch):
    mgr = _Mgr([], {}, backup_config='scsi0: local-lvm:vm-100-disk-0,size=8G\n')
    if case == 'status_error':
        mgr.free['local-lvm'] = None
    elif case in ('not_active', 'no_avail'):
        real = mgr._api_get

        def get(url, timeout=None, params=None):
            r = real(url, timeout, params)
            if url.endswith('/status'):
                data = dict(r._data, active=0) if case == 'not_active' else {'active': 1, 'total': GIB}
                return _Resp(200, data)
            return r
        monkeypatch.setattr(mgr, '_api_get', get)
    elif case == 'raises':
        real = mgr._api_get

        def get(url, timeout=None, params=None):
            if url.endswith('/status'):
                raise TimeoutError('read timed out')
            return real(url, timeout, params)
        monkeypatch.setattr(mgr, '_api_get', get)
    elif case == 'config_unreadable':
        mgr.backup_config = None
    else:
        mgr.backup_config = 'scsi0: ../../access:vm-100-disk-0\n'
    short = bv.room_for(mgr, 'pve1', _VOL, 'qemu', {}, 2 * GIB)
    assert short and short['reason'] == 'space_unknown', short
    assert not any('access' in c for c in mgr.calls)


# --- the run -------------------------------------------------------------------------------

def test_the_run_tests_one_after_another_and_says_how_each_went(clusters, monkeypatch, db):
    clusters['c1'] = _Mgr([_g(100), _g(101), _g(102)], {'pbs': [_bk(100, 2), _bk(101, 2), _bk(102, 2)]})
    recovery.save_rule('c1', 'cluster', '', {'rto_minutes': 20}, 'root')
    seen, running = [], []

    def fake_run(mgr, params):
        running.append(params['vmid'])
        assert len(running) - len(seen) == 1          # one at a time
        seen.append(params)
        ok = params['vmid'] != 101
        return {'id': f"t{params['vmid']}", 'status': 'passed' if ok else 'failed',
                'cause': '' if ok else 'port 443: nothing listens', 'measured_seconds': 300.0, 'rto_met': True}
    monkeypatch.setattr(bv, 'run_verification', fake_run)
    RT._run_slot(SUNDAY, POLICY)
    assert [p['vmid'] for p in seen] == [100, 101, 102]
    p = seen[0]
    assert p['source'] == 'schedule' and p['plan']['rto_seconds'] == 1200 and p['plan']['isolation'] == 'link_down'
    assert p['backup_volid'] == _bk(100, 2)['volid'] and p['node'] == 'pve1' and p['auto_cleanup'] is True
    last = recovery.load_state()['last_run']
    assert last['state'] == 'done' and len(last['picked']) == 3
    assert [(r['vmid'], r['status'], r['cause']) for r in last['results']] == [
        (100, 'passed', ''), (101, 'failed', 'port 443: nothing listens'), (102, 'passed', '')]
    audit = db.conn.execute("SELECT details FROM audit_log WHERE action = 'backup.verify_scheduled'").fetchone()
    assert '3 picked, 2 passed, 1 failed' in audit[0]


def test_without_a_confirmed_lease_nothing_is_restored(clusters, monkeypatch, db):
    from pegaprox.core import ha
    clusters['c1'] = _Mgr([_g(100)], {'pbs': [_bk(100, 2)]})
    monkeypatch.setattr(ha, 'confirm_step', lambda what, need=None: False)
    calls = _recorder(monkeypatch, bv, 'run_verification')
    RT._run_slot(SUNDAY, POLICY)
    assert calls == []
    last = recovery.load_state()['last_run']
    assert last['state'] == 'stopped' and 'lease' in last['reason']


def test_an_instance_that_stopped_being_active_stops_the_run(clusters, monkeypatch, db):
    from pegaprox.core import ha
    clusters['c1'] = _Mgr([_g(100), _g(101)], {'pbs': [_bk(100, 2), _bk(101, 2)]})
    answers = iter([True, False])
    monkeypatch.setattr(ha, 'is_active', lambda: next(answers))
    calls = []
    monkeypatch.setattr(bv, 'run_verification', lambda m, p: calls.append(p['vmid']) or {'id': 'x', 'status': 'passed'})
    RT._run_slot(SUNDAY, POLICY)
    assert len(calls) == 1 and recovery.load_state()['last_run']['state'] == 'stopped'


def test_a_test_running_by_hand_is_skipped_not_doubled(clusters, monkeypatch, db):
    clusters['c1'] = _Mgr([_g(100), _g(101)], {'pbs': [_bk(100, 2), _bk(101, 2)]})
    monkeypatch.setattr(bv, 'running_guests', lambda: {('c1', 100)})
    calls = []
    monkeypatch.setattr(bv, 'run_verification', lambda m, p: calls.append(p['vmid']) or {'id': 'x', 'status': 'passed'})
    RT._run_slot(SUNDAY, POLICY)
    assert calls == [101]


def _runs(monkeypatch):
    calls = []
    monkeypatch.setattr(bv, 'run_verification',
                        lambda m, p: calls.append(p['vmid']) or {'id': f"t{p['vmid']}", 'status': 'passed'})
    return calls


def test_the_run_restores_nothing_over_the_cap_and_says_so(clusters, monkeypatch, db):
    clusters['c1'] = _Mgr([_g(100, name='db01'), _g(101), _g(102)],
                          {'pbs': [_bk(100, 2, size=300 * GIB), _bk(101, 3), _bk(102, 4, size=None)]})
    calls = _runs(monkeypatch)
    RT._run_slot(SUNDAY, POLICY)
    assert calls == [101]
    last = recovery.load_state()['last_run']
    assert last['state'] == 'done' and [p['vmid'] for p in last['picked']] == [101]
    got = {r['vmid']: r for r in last['results']}
    assert (got[100]['status'], got[100]['reason'], got[100]['size'], got[100]['limit_gb']) == (
        'skipped', 'too_large', 300 * GIB, 32)
    assert got[100]['cause'] == 'the backup is 300.0 GB, the schedule restores up to 32 GB'
    assert (got[102]['status'], got[102]['reason']) == ('skipped', 'size_unknown')
    assert got[101]['status'] == 'passed'
    audit = db.conn.execute("SELECT details FROM audit_log WHERE action = 'backup.verify_scheduled'").fetchone()
    assert '1 picked, 1 passed, 0 failed, 2 skipped' in audit[0]


def test_the_run_restores_nothing_onto_a_storage_without_room(clusters, monkeypatch, db):
    clusters['c1'] = _Mgr([_g(100), _g(101)], {'pbs': [_bk(100, 2), _bk(101, 3, size=GIB // 2)]},
                          free={'local-lvm': GIB})
    calls = _runs(monkeypatch)
    RT._run_slot(SUNDAY, POLICY)
    # 100 needs 2 GB on local-lvm, where 1 GB is free; 101 fits
    assert calls == [101]
    r = recovery.load_state()['last_run']['results'][0]
    assert (r['vmid'], r['status'], r['reason'], r['storage'], r['free'], r['size']) == (
        100, 'skipped', 'no_space', 'local-lvm', GIB, 2 * GIB)
    assert r['task_id'] is None and 'local-lvm on pve1 has 1.0 GB free' in r['cause']


def test_the_run_restores_nothing_where_the_free_space_is_unknown(clusters, monkeypatch, db):
    clusters['c1'] = _Mgr([_g(100)], {'pbs': [_bk(100, 2)]}, free={'local-lvm': None})
    calls = _runs(monkeypatch)
    RT._run_slot(SUNDAY, POLICY)
    assert calls == []
    r = recovery.load_state()['last_run']['results'][0]
    assert (r['status'], r['reason'], r['storage']) == ('skipped', 'space_unknown', 'local-lvm')


def test_the_run_reads_the_room_of_the_clusters_test_storage(clusters, monkeypatch, db):
    clusters['c1'] = _Mgr([_g(100)], {'pbs': [_bk(100, 2)]}, free={'local-lvm': 0, 'scratch': 50 * GIB})
    recovery.save_rule('c1', 'cluster', '', {'test_storage': 'scratch'}, 'root')
    calls = _runs(monkeypatch)
    RT._run_slot(SUNDAY, POLICY)
    assert calls == [100]
    assert '/nodes/pve1/storage/scratch/status' in clusters['c1'].calls
    assert not [c for c in clusters['c1'].calls if 'local-lvm' in c or 'extractconfig' in c]
