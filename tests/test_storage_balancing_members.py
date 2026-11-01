"""Storage balancing groups: what the status route and the auto-balance worker compare.

  * a member storage that is not active, switched off, gone, without a size or could not be
    read counted as 0 % used, became the emptiest member and the target of every move; it is
    now reported as such and left out of the spread, and a group with fewer than two usable
    members gets no recommendation and no move (logged once by the worker)
  * the figures were read from the first node of /nodes even when that node was offline, and
    a shared member came from that one node too; it now comes from /cluster/resources, usable
    when a node that is up reports it available
  * a local member's figures are those of the node they were read on, so only guests on
    that node are moved between local members
  * a container volume went through the QEMU move_disk call, which PVE does not have for
    containers (501); it moves with move_volume while the container is stopped, and a
    running container's volume is marked as not movable
  * a refused move said '{"data":null}'; it now says what PVE refused and why
  * a status where no member could be read says why (read_error)
  * the tolerance the UI sends is kept, and the worker waits for threshold + tolerance

The PVE side is a fake of the few reads and the one write these paths make. NS Nov 2026
"""
import json
import logging
import re
import threading
import time
import types

import pytest

CLUSTER = 'cluster_1'
GiB = 2 ** 30


def _resp(status, data=None, text=None, reason=''):
    body = json.dumps({'data': data}) if text is None else text
    return types.SimpleNamespace(status_code=status, text=body, reason=reason,
                                 json=lambda: json.loads(body))


def _store(name, used_pct, total=100 * GiB, active=1, enabled=1, shared=1, type_='rbd'):
    used = int(total * used_pct / 100) if total else 0
    return {'storage': name, 'type': type_, 'content': 'images,rootdir', 'total': total, 'used': used,
            'avail': total - used, 'active': active, 'enabled': enabled, 'shared': shared}


class _Pve:
    """/nodes, /nodes/<n>/storage, cluster/resources, a guest's status and config, the move."""

    def __init__(self, storage, guests=(), configs=None, nodes=None, status=None, post=None, resources=None):
        # the node list, or an HTTP status for a refused read
        self.nodes = nodes if nodes is not None else [{'node': 'n1', 'status': 'online'}]
        self.storage = storage           # node -> rows, or an HTTP status for a failed read
        self.resources = resources       # the storage rows of /cluster/resources, else built from storage
        self.guests = list(guests)
        self.configs = configs or {}
        self.status = status or {}       # vmid -> status/current
        self.post_answer = post or _resp(200, 'UPID:n1:00001:move:')
        self.gets, self.posts = [], []

    def storage_resources(self):
        """What PVE's /cluster/resources?type=storage says for the per-node lists: a row per
        node a storage is enabled on, with figures only where pvestatd has some (active)."""
        if self.resources is not None:
            return self.resources
        rows = []
        for node, listed in self.storage.items():
            for s in ([] if isinstance(listed, int) else listed):
                if not s.get('enabled', 1):
                    continue
                row = {'id': f"storage/{node}/{s['storage']}", 'type': 'storage', 'node': node,
                       'storage': s['storage'], 'plugintype': s.get('type'), 'shared': s.get('shared', 0),
                       'content': s.get('content'), 'status': 'unknown'}
                if s.get('active', 1):
                    row.update(status='available', disk=s.get('used', 0), maxdisk=s.get('total', 0))
                rows.append(row)
        return rows

    def get(self, url, **kw):
        path = url.split('/api2/json', 1)[1]
        self.gets.append(path)
        if path == '/nodes':
            return _resp(self.nodes, text='') if isinstance(self.nodes, int) else _resp(200, self.nodes)
        m = re.fullmatch(r'/nodes/([^/]+)/storage', path)
        if m:
            rows = self.storage.get(m.group(1), 595)
            return _resp(rows, text='') if isinstance(rows, int) else _resp(200, rows)
        if path == '/cluster/resources?type=storage':
            return _resp(200, self.storage_resources())
        if path.startswith('/cluster/resources'):
            return _resp(200, self.guests)
        m = re.fullmatch(r'/nodes/[^/]+/(?:qemu|lxc)/(\d+)/status/current', path)
        if m:
            return _resp(200, self.status.get(int(m.group(1)), {}))
        m = re.fullmatch(r'/nodes/[^/]+/(?:qemu|lxc)/(\d+)/config', path)
        if m:
            return _resp(200, self.configs.get(int(m.group(1)), {}))
        return _resp(404, text='')

    def post(self, url, data=None, **kw):
        self.posts.append((url.split('/api2/json', 1)[1], dict(data or {})))
        return self.post_answer


def _guest(vmid, kind='qemu', node='n1', status='running'):
    return {'vmid': vmid, 'name': f'g{vmid}', 'type': kind, 'node': node, 'status': status}


@pytest.fixture
def storage(api, monkeypatch):
    import pegaprox.api.storage as mod
    from pegaprox.core.cache import APIRateLimiter
    # a limiter of its own: the module's one is shared by every test in this process
    monkeypatch.setattr(mod, '_api_rate_limiter', APIRateLimiter(calls_per_second=1000, burst_limit=1000))
    mod._storage_cache.invalidate(CLUSTER)
    # the worker says once per group that it cannot compare it; a test before this one must
    # not have said it already
    mod._unbalanceable_groups.clear()
    yield mod
    mod._storage_cache.invalidate(CLUSTER)
    mod._unbalanceable_groups.clear()


@pytest.fixture
def pve(api, storage):
    holder = {}

    def _install(fake, groups):
        m = api.make_fake_manager(cluster_id=CLUSTER)
        m.is_connected = True
        m.config.name = CLUSTER
        m.host, m.api_port = '192.0.2.10', 8006
        m._create_session.return_value.get.side_effect = fake.get
        m._create_session.return_value.post.side_effect = fake.post
        api.set_manager(CLUSTER, m)
        storage.storage_clusters_config.clear()
        storage.storage_clusters_config[CLUSTER] = {'clusters': [dict(g) for g in groups]}
        holder['fake'] = fake
        return fake
    yield _install
    storage.storage_clusters_config.clear()


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('sb-admin', role='admin'))


def _group(storages, **kw):
    # auto_balance off unless a worker test arms it: the real worker thread of this process
    # must find nothing to do in the route tests
    g = {'id': 'sc1', 'name': 'pool', 'storages': list(storages), 'threshold': 20, 'enabled': True,
         'auto_balance': False, 'max_concurrent': 1, 'check_interval': 0, 'last_auto_run': None}
    g.update(kw)
    return g


def _status(admin):
    r = admin.get(f'/api/clusters/{CLUSTER}/storage-clusters/sc1/status')
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def _members(st):
    return {s['storage']: s for s in st['storages']}


DISKS = {100: {'scsi0': 'full:vm-100-disk-0,size=8G'}, 101: {'scsi0': 'full:vm-101-disk-0,size=4G'}}


# --- the status route ---------------------------------------------------------------------

@pytest.mark.parametrize('dead,state', [
    (dict(active=0, total=0), 'unavailable'),
    (dict(active=0, total=0, shared=0), 'inactive'),
    (dict(enabled=0, active=0, total=0), 'disabled'),
    (dict(total=0), 'no_size'),
])
def test_a_member_that_is_not_usable_is_no_target(admin, pve, dead, state):
    pve(_Pve({'n1': [_store('full', 90), _store('half', 50), _store('dead', 0, **dead)]},
             guests=[_guest(100), _guest(101)], configs=DISKS),
        [_group(['full', 'half', 'dead'])])
    st = _status(admin)
    # the disks go to the emptiest member that could be compared, not to the dead one
    assert st['recommendations'], st
    assert {r['target'] for r in st['recommendations']} == {'half'}
    assert {r['source'] for r in st['recommendations']} == {'full'}
    # the spread is the one of the members that could be compared
    assert st['imbalance'] == 40.0
    members = _members(st)
    assert members['dead']['usable'] is False and members['dead']['state'] == state
    # an unknown figure is no figure, not 0 %
    assert members['dead']['usage_percent'] is None
    assert members['full']['usable'] is True and members['half']['usable'] is True


def test_a_member_the_node_does_not_list_is_reported_not_dropped(admin, pve):
    pve(_Pve({'n1': [_store('full', 90), _store('half', 50)]}, guests=[_guest(100)], configs=DISKS),
        [_group(['full', 'half', 'gone'])])
    members = _members(_status(admin))
    assert sorted(members) == ['full', 'gone', 'half']
    assert members['gone']['usable'] is False and members['gone']['state'] == 'missing'


def test_a_read_that_failed_is_no_balanced_group(admin, pve):
    pve(_Pve({'n1': 500}, guests=[_guest(100)], configs=DISKS), [_group(['full', 'half'])])
    st = _status(admin)
    # not "0 points apart", which the UI showed as balanced
    assert st['imbalance'] is None
    assert st['recommendations'] == []
    assert [(s['storage'], s['usable'], s['state']) for s in st['storages']] == [
        ('full', False, 'unreadable'), ('half', False, 'unreadable')]


def test_one_usable_member_gives_no_recommendation(admin, pve):
    pve(_Pve({'n1': [_store('full', 90), _store('dead', 0, active=0, total=0)]},
             guests=[_guest(100)], configs=DISKS),
        [_group(['full', 'dead'])])
    st = _status(admin)
    assert st['recommendations'] == []
    assert st['imbalance'] is None


def test_the_figures_come_from_a_node_that_is_online(admin, pve):
    fake = pve(_Pve({'n2': [_store('full', 90), _store('half', 50)]}, guests=[_guest(100)], configs=DISKS,
                    nodes=[{'node': 'n1', 'status': 'offline'}, {'node': 'n2', 'status': 'online'}]),
               [_group(['full', 'half'])])
    st = _status(admin)
    assert '/nodes/n1/storage' not in fake.gets
    assert {s['storage']: (s['usable'], s['node']) for s in st['storages']} == {
        'full': (True, 'n2'), 'half': (True, 'n2')}
    assert st['imbalance'] == 40.0


def test_local_members_only_move_guests_of_the_node_they_were_read_on(admin, pve):
    configs = {100: {'scsi0': 'full:vm-100-disk-0,size=8G'}, 200: {'scsi0': 'full:vm-200-disk-0,size=8G'}}
    pve(_Pve({'n1': [_store('full', 90, shared=0), _store('half', 50, shared=0)]},
             guests=[_guest(100, node='n1'), _guest(200, node='n2')], configs=configs,
             nodes=[{'node': 'n1', 'status': 'online'}, {'node': 'n2', 'status': 'online'}]),
        [_group(['full', 'half'])])
    st = _status(admin)
    assert [r['vmid'] for r in st['recommendations']] == [100]


def test_shared_members_move_guests_of_every_node(admin, pve):
    configs = {100: {'scsi0': 'full:vm-100-disk-0,size=8G'}, 200: {'scsi0': 'full:vm-200-disk-0,size=8G'}}
    pve(_Pve({'n1': [_store('full', 90), _store('half', 50)]},
             guests=[_guest(100, node='n1'), _guest(200, node='n2')], configs=configs,
             nodes=[{'node': 'n1', 'status': 'online'}, {'node': 'n2', 'status': 'online'}]),
        [_group(['full', 'half'])])
    assert sorted(r['vmid'] for r in _status(admin)['recommendations']) == [100, 200]


def test_a_running_containers_volume_is_marked_not_movable(admin, pve):
    configs = {300: {'rootfs': 'full:vm-300-disk-0,size=8G'}, 301: {'rootfs': 'full:vm-301-disk-0,size=8G'},
               100: {'scsi0': 'full:vm-100-disk-0,size=8G'}}
    pve(_Pve({'n1': [_store('full', 90), _store('half', 50)]},
             guests=[_guest(300, 'lxc', status='running'), _guest(301, 'lxc', status='stopped'),
                     _guest(100, 'qemu', status='running')], configs=configs),
        [_group(['full', 'half'])])
    recs = {r['vmid']: r for r in _status(admin)['recommendations']}
    assert recs[300].get('movable', True) is False and recs[300]['blocked'] == 'ct_running'
    assert 'stopped' in recs[300]['blocked_reason']
    # a stopped container and a running VM can move
    assert recs[301]['movable'] is True and recs[100]['movable'] is True
    assert (recs[300]['vm_type'], recs[100]['vm_type']) == ('lxc', 'qemu')


def test_the_status_says_the_tolerance(admin, pve):
    pve(_Pve({'n1': [_store('full', 60), _store('half', 50)]}), [_group(['full', 'half'], tolerance=9)])
    st = _status(admin)
    assert st['tolerance'] == 9 and st['imbalance'] == 10.0


TWO_UP = [{'node': 'n1', 'status': 'online'}, {'node': 'n2', 'status': 'online'}]


def test_a_shared_member_inactive_on_the_first_node_is_read_on_another(admin, pve):
    # a bad mount on n1 alone no longer takes the member out of its group
    fake = pve(_Pve({'n1': [_store('full', 90), _store('half', 0, active=0, total=0)],
                     'n2': [_store('full', 90), _store('half', 50)]},
                    guests=[_guest(100)], configs=DISKS, nodes=TWO_UP),
               [_group(['full', 'half'])])
    st = _status(admin)
    half = _members(st)['half']
    assert (half['usable'], half['state'], half['node'], half['usage_percent']) == (True, 'ok', 'n2', 50.0)
    assert st['imbalance'] == 40.0 and st['read_error'] is None
    assert [(r['source'], r['target']) for r in st['recommendations']] == [('full', 'half')]
    # one read for every node's view of the shared members, no per-node storage list
    assert '/cluster/resources?type=storage' in fake.gets
    assert not [g for g in fake.gets if re.fullmatch(r'/nodes/[^/]+/storage', g)], fake.gets


def test_a_shared_member_available_on_no_node_that_is_up_is_not_usable(admin, pve):
    # n2 is down; what its last figure said does not count
    rows = [{'type': 'storage', 'node': 'n1', 'storage': 'half', 'shared': 1, 'status': 'unknown'},
            {'type': 'storage', 'node': 'n2', 'storage': 'half', 'shared': 1, 'status': 'available',
             'disk': 10 * GiB, 'maxdisk': 100 * GiB},
            {'type': 'storage', 'node': 'n1', 'storage': 'full', 'shared': 1, 'status': 'available',
             'disk': 90 * GiB, 'maxdisk': 100 * GiB}]
    pve(_Pve({}, guests=[_guest(100)], configs=DISKS, resources=rows,
             nodes=[{'node': 'n1', 'status': 'online'}, {'node': 'n2', 'status': 'offline'}]),
        [_group(['full', 'half'])])
    st = _status(admin)
    half = _members(st)['half']
    assert (half['usable'], half['state'], half['usage_percent']) == (False, 'unavailable', None)
    assert _members(st)['full']['usable'] is True
    assert st['imbalance'] is None and st['recommendations'] == []


def test_a_mixed_group_reads_shared_members_cluster_wide_and_local_ones_on_the_first_node(admin, pve):
    configs = {100: {'scsi0': 'ceph:vm-100-disk-0,size=8G'}, 200: {'scsi0': 'ceph:vm-200-disk-0,size=8G'}}
    fake = pve(_Pve({'n1': [_store('ceph', 0, active=0, total=0), _store('lvm', 30, shared=0, type_='lvmthin')],
                     'n2': [_store('ceph', 90), _store('lvm', 70, shared=0, type_='lvmthin')]},
                    guests=[_guest(200, node='n2'), _guest(100, node='n1')], configs=configs, nodes=TWO_UP),
               [_group(['ceph', 'lvm'])])
    st = _status(admin)
    members = _members(st)
    assert (members['ceph']['node'], members['ceph']['usage_percent'], members['ceph']['shared']) == ('n2', 90.0, True)
    assert (members['lvm']['node'], members['lvm']['usage_percent'], members['lvm']['shared']) == ('n1', 30.0, False)
    assert st['imbalance'] == 60.0
    # the local member's figure is n1's, so only a guest on n1 may move onto it
    assert [(r['vmid'], r['target']) for r in st['recommendations']] == [(100, 'lvm')]
    assert '/nodes/n1/storage' in fake.gets and '/nodes/n2/storage' not in fake.gets


@pytest.mark.parametrize('nodes,said', [
    (401, 'The node list could not be read (HTTP 401)'),
    ([{'node': 'n1', 'status': 'offline'}, {'node': 'n2', 'status': 'offline'}], 'No node of the cluster is online'),
])
def test_a_status_where_no_member_could_be_read_says_why(admin, pve, nodes, said):
    pve(_Pve({'n1': [_store('full', 90), _store('half', 50)]}, nodes=nodes), [_group(['full', 'half'])])
    st = _status(admin)
    assert st['read_error'] == said
    assert st['imbalance'] is None
    assert {s['state'] for s in st['storages']} == {'unreadable'}


def test_a_failed_storage_list_is_the_reason_given(admin, pve):
    pve(_Pve({'n1': 500}), [_group(['full', 'half'])])
    assert _status(admin)['read_error'] == 'The storage list of n1 could not be read (HTTP 500)'


def test_a_cdrom_on_a_member_is_not_recommended(admin, pve):
    configs = {100: {'ide2': 'full:iso/debian.iso,media=cdrom', 'ide0': 'full:vm-100-cloudinit,media=cdrom',
                     'scsi0': 'full:vm-100-disk-0,size=8G'}}
    pve(_Pve({'n1': [_store('full', 90), _store('half', 50)]}, guests=[_guest(100)], configs=configs),
        [_group(['full', 'half'])])
    assert [r['disk'] for r in _status(admin)['recommendations']] == ['scsi0']


@pytest.mark.parametrize('sent,count', [('abc', 2), ('1', 1), ('-4', 1)])
def test_max_recommendations_is_held_to_a_range(admin, pve, sent, count):
    pve(_Pve({'n1': [_store('full', 90), _store('half', 50)]}, guests=[_guest(100), _guest(101)], configs=DISKS),
        [_group(['full', 'half'])])
    r = admin.get(f'/api/clusters/{CLUSTER}/storage-clusters/sc1/status?max_recommendations={sent}')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert len(r.get_json()['recommendations']) == count


# --- the migrate route ----------------------------------------------------------------------

def _migrate(admin, vmid, disk, target='half'):
    return admin.post(f'/api/clusters/{CLUSTER}/storage-balancing/migrate',
                      json={'vmid': vmid, 'disk': disk, 'target': target})


def test_a_stopped_container_moves_its_volume_with_move_volume(admin, pve):
    fake = pve(_Pve({}, guests=[_guest(301, 'lxc', status='stopped')], status={301: {'status': 'stopped'}}),
               [_group(['full', 'half'])])
    r = _migrate(admin, 301, 'rootfs')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert fake.posts == [('/nodes/n1/lxc/301/move_volume', {'volume': 'rootfs', 'storage': 'half', 'delete': 1})]


def test_a_running_container_is_refused_with_a_reason_and_nothing_is_sent(admin, pve):
    fake = pve(_Pve({}, guests=[_guest(300, 'lxc')], status={300: {'status': 'running'}}),
               [_group(['full', 'half'])])
    r = _migrate(admin, 300, 'mp0')
    assert r.status_code == 409
    assert 'running' in r.get_json()['error'] and 'stopped' in r.get_json()['error']
    assert fake.posts == []


def test_a_vm_disk_still_moves_with_move_disk(admin, pve):
    fake = pve(_Pve({}, guests=[_guest(100)], status={100: {'status': 'running'}}), [_group(['full', 'half'])])
    r = _migrate(admin, 100, 'scsi0')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert fake.posts == [('/nodes/n1/qemu/100/move_disk', {'disk': 'scsi0', 'storage': 'half', 'delete': 1})]


def test_a_refused_move_says_what_was_refused_and_why(admin, pve):
    # PVE puts the reason into the status line and sends {"data":null}
    refused = _resp(500, text='{"data":null}', reason="can't lock file '/var/lock/qemu-server/lock-100.conf' - got timeout")
    pve(_Pve({}, guests=[_guest(100)], post=refused), [_group(['full', 'half'])])
    r = _migrate(admin, 100, 'scsi0')
    err = r.get_json()['error']
    assert r.status_code == 500
    assert '{"data":null}' not in err
    assert "can't lock file" in err and 'scsi0' in err and '100' in err and 'half' in err


def test_a_refusal_with_a_message_in_the_body_says_that_message(admin, pve):
    refused = _resp(400, text=json.dumps({'data': None, 'errors': {'storage': 'storage half does not exist'}}),
                    reason='Parameter verification failed.')
    pve(_Pve({}, guests=[_guest(100)], post=refused), [_group(['full', 'half'])])
    err = _migrate(admin, 100, 'scsi0').get_json()['error']
    assert 'storage half does not exist' in err


def test_a_refusal_whose_message_has_a_raw_newline_still_says_it(admin, pve):
    # PVE ends its messages with a newline inside the JSON string
    refused = _resp(500, text='{"data":null,"message":"cannot move volumes of a running container\n"}',
                    reason='Internal Server Error')
    pve(_Pve({}, guests=[_guest(100)], post=refused), [_group(['full', 'half'])])
    err = _migrate(admin, 100, 'scsi0').get_json()['error']
    assert 'cannot move volumes of a running container' in err, err


@pytest.mark.parametrize('where', ['body', 'reason'])
def test_a_quote_in_the_refusal_reads_as_a_quote(admin, pve, where):
    said = "can't lock file '/var/lock/qemu-server/lock-100.conf'"
    refused = (_resp(500, text=json.dumps({'data': None, 'message': said}), reason='x') if where == 'body'
               else _resp(500, text='{"data":null}', reason=said))
    pve(_Pve({}, guests=[_guest(100)], post=refused), [_group(['full', 'half'])])
    err = _migrate(admin, 100, 'scsi0').get_json()['error']
    assert said in err and '&#x27;' not in err, err


def test_a_vmid_sent_as_a_string_finds_its_guest(admin, pve):
    fake = pve(_Pve({}, guests=[_guest(301, 'lxc', status='stopped')], status={301: {'status': 'stopped'}}),
               [_group(['full', 'half'])])
    r = _migrate(admin, '301', 'rootfs')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert [p for p, _ in fake.posts] == ['/nodes/n1/lxc/301/move_volume']


def test_a_vmid_that_is_no_number_is_refused(admin, pve):
    pve(_Pve({}, guests=[_guest(100)]), [_group(['full', 'half'])])
    r = _migrate(admin, 'abc', 'scsi0')
    assert r.status_code == 400 and 'vmid' in r.get_json()['error']


def _audits(storage, monkeypatch):
    said = []
    monkeypatch.setattr(storage, 'log_audit', lambda user, action, text, **kw: said.append((action, text)))
    return said


def test_the_audit_of_a_moved_container_volume_says_container(admin, pve, storage, monkeypatch):
    said = _audits(storage, monkeypatch)
    pve(_Pve({}, guests=[_guest(301, 'lxc', status='stopped')], status={301: {'status': 'stopped'}}),
        [_group(['full', 'half'])])
    assert _migrate(admin, 301, 'rootfs').status_code == 200
    assert ('storage_balancing.disk_moved', 'Moved rootfs of container 301 to half') in said, said


# --- the worker -------------------------------------------------------------------------------

class _Stop(BaseException):
    """Ends the worker loop; it catches Exception, not this."""


def _cycles(monkeypatch, storage, n=1):
    naps = []

    def nap(seconds):
        naps.append(seconds)
        if len(naps) > n:
            raise _Stop()
    monkeypatch.setattr(storage, 'time', types.SimpleNamespace(sleep=nap, time=time.time,
                                                               monotonic=time.monotonic))
    # active for this pass only, not for the worker thread the import started
    me = threading.current_thread()
    monkeypatch.setattr(storage.ha, 'is_active', lambda: threading.current_thread() is me)
    monkeypatch.setattr(storage.ha, 'confirm_step', lambda *a, **k: True)
    storage.active_auto_migrations.clear()
    with pytest.raises(_Stop):
        storage.run_auto_storage_balance()


def test_the_worker_does_not_move_onto_an_inactive_member(storage, pve, monkeypatch):
    fake = pve(_Pve({'n1': [_store('full', 90), _store('half', 50), _store('dead', 0, active=0, total=0)]},
                    guests=[_guest(100)], configs=DISKS), [_group(['full', 'half', 'dead'], auto_balance=True)])
    _cycles(monkeypatch, storage)
    assert fake.posts == [('/nodes/n1/qemu/100/move_disk', {'disk': 'scsi0', 'storage': 'half', 'delete': 1})]


def test_the_worker_leaves_a_group_it_cannot_compare_and_says_so_once(storage, pve, monkeypatch, caplog):
    fake = pve(_Pve({'n1': [_store('full', 90), _store('dead', 0, active=0, total=0)]},
                    guests=[_guest(100)], configs=DISKS), [_group(['full', 'dead'], auto_balance=True)])
    storage._storage_cache.invalidate(CLUSTER)
    with caplog.at_level(logging.WARNING):
        _cycles(monkeypatch, storage, n=3)
    assert fake.posts == []
    said = [r for r in caplog.records if 'pool' in r.getMessage() and 'fewer than two' in r.getMessage()]
    assert len(said) == 1, [r.getMessage() for r in caplog.records]


def test_the_worker_moves_a_stopped_containers_volume_and_skips_a_running_one(storage, pve, monkeypatch):
    configs = {300: {'rootfs': 'full:vm-300-disk-0,size=8G'}, 301: {'mp0': 'full:vm-301-disk-1,size=8G'}}
    fake = pve(_Pve({'n1': [_store('full', 90), _store('half', 50)]},
                    guests=[_guest(300, 'lxc', status='running'), _guest(301, 'lxc', status='stopped')],
                    configs=configs, status={300: {'status': 'running'}, 301: {'status': 'stopped'}}),
               [_group(['full', 'half'], auto_balance=True)])
    _cycles(monkeypatch, storage)
    assert fake.posts == [('/nodes/n1/lxc/301/move_volume', {'volume': 'mp0', 'storage': 'half', 'delete': 1})]


def test_the_worker_skips_a_container_that_started_since_the_list_was_read(storage, pve, monkeypatch):
    configs = {300: {'rootfs': 'full:vm-300-disk-0,size=8G'}}
    fake = pve(_Pve({'n1': [_store('full', 90), _store('half', 50)]},
                    guests=[_guest(300, 'lxc', status='stopped')], configs=configs,
                    status={300: {'status': 'running'}}),
               [_group(['full', 'half'], auto_balance=True)])
    _cycles(monkeypatch, storage)
    assert fake.posts == []


@pytest.mark.parametrize('tolerance,moved', [(12, False), (5, True)])
def test_the_worker_waits_for_threshold_plus_the_stored_tolerance(storage, pve, monkeypatch, admin, tolerance, moved):
    fake = pve(_Pve({'n1': [_store('full', 80), _store('half', 50)]}, guests=[_guest(100)], configs=DISKS), [])
    r = admin.post(f'/api/clusters/{CLUSTER}/storage-clusters',
                   json={'name': 'pool', 'storages': ['full', 'half'], 'threshold': 20,
                         'tolerance': tolerance, 'auto_balance': True})
    assert r.status_code == 201, r.data
    _cycles(monkeypatch, storage)
    # 30 points apart: above 20 + 5, not above 20 + 12
    assert bool(fake.posts) is moved


def test_the_worker_moves_between_local_members_only_guests_of_the_node_they_were_read_on(storage, pve, monkeypatch):
    configs = {200: {'scsi0': 'full:vm-200-disk-0,size=8G'}, 101: {'scsi0': 'full:vm-101-disk-0,size=8G'}}
    fake = pve(_Pve({'n1': [_store('full', 90, shared=0), _store('half', 50, shared=0)]},
                    guests=[_guest(200, node='n2'), _guest(101, node='n1')], configs=configs, nodes=TWO_UP),
               [_group(['full', 'half'], auto_balance=True)])
    _cycles(monkeypatch, storage)
    # 200 comes first in the guest list, but its node's 'full' is another storage
    assert fake.posts == [('/nodes/n1/qemu/101/move_disk', {'disk': 'scsi0', 'storage': 'half', 'delete': 1})]


def test_the_worker_reads_a_local_group_on_the_next_node_when_the_first_is_down(storage, pve, monkeypatch):
    configs = {200: {'scsi0': 'full:vm-200-disk-0,size=8G'}}
    fake = pve(_Pve({'n1': 595, 'n2': [_store('full', 90, shared=0), _store('half', 50, shared=0)]},
                    guests=[_guest(200, node='n2')], configs=configs,
                    nodes=[{'node': 'n1', 'status': 'offline'}, {'node': 'n2', 'status': 'online'}]),
               [_group(['full', 'half'], auto_balance=True)])
    _cycles(monkeypatch, storage)
    assert fake.posts == [('/nodes/n2/qemu/200/move_disk', {'disk': 'scsi0', 'storage': 'half', 'delete': 1})]


def test_the_worker_takes_a_shared_figure_from_a_node_that_is_up(storage, pve, monkeypatch):
    # n1 is down and its last figures said the two were even; n2 sees them 40 points apart
    rows = [{'type': 'storage', 'node': n, 'storage': name, 'shared': 1, 'status': 'available',
             'disk': used * GiB, 'maxdisk': 100 * GiB}
            for n, name, used in [('n1', 'full', 50), ('n1', 'half', 50), ('n2', 'full', 90), ('n2', 'half', 50)]]
    fake = pve(_Pve({}, guests=[_guest(100, node='n2')], configs=DISKS, resources=rows,
                    nodes=[{'node': 'n1', 'status': 'offline'}, {'node': 'n2', 'status': 'online'}]),
               [_group(['full', 'half'], auto_balance=True)])
    _cycles(monkeypatch, storage)
    assert fake.posts == [('/nodes/n2/qemu/100/move_disk', {'disk': 'scsi0', 'storage': 'half', 'delete': 1})]


def test_the_worker_does_not_move_a_cdrom(storage, pve, monkeypatch):
    configs = {100: {'ide2': 'full:iso/debian.iso,media=cdrom', 'scsi0': 'full:vm-100-disk-0,size=8G'}}
    fake = pve(_Pve({'n1': [_store('full', 90), _store('half', 50)]}, guests=[_guest(100)], configs=configs),
               [_group(['full', 'half'], auto_balance=True)])
    _cycles(monkeypatch, storage)
    assert fake.posts == [('/nodes/n1/qemu/100/move_disk', {'disk': 'scsi0', 'storage': 'half', 'delete': 1})]


def test_the_worker_audit_says_container_for_a_container(storage, pve, monkeypatch):
    said = _audits(storage, monkeypatch)
    fake = pve(_Pve({'n1': [_store('full', 90), _store('half', 50)]},
                    guests=[_guest(301, 'lxc', status='stopped')], configs={301: {'mp0': 'full:vm-301-disk-1,size=8G'}},
                    status={301: {'status': 'stopped'}}),
               [_group(['full', 'half'], auto_balance=True)])
    _cycles(monkeypatch, storage)
    assert fake.posts
    assert ('storage_balancing.auto_migrate', 'Auto-migrated mp0 of container 301 from full to half') in said, said


def test_a_deleted_group_is_forgotten_by_the_say_once_list(admin, pve, storage):
    pve(_Pve({}), [_group(['full', 'half'])])
    storage._unbalanceable_groups.add(f'{CLUSTER}:sc1')
    assert admin.delete(f'/api/clusters/{CLUSTER}/storage-clusters/sc1').status_code == 200
    assert f'{CLUSTER}:sc1' not in storage._unbalanceable_groups


def test_the_worker_drops_groups_that_are_gone_from_the_say_once_list(storage, pve, monkeypatch):
    pve(_Pve({'n1': [_store('full', 90), _store('half', 50)]}), [_group(['full', 'half'])])
    storage._unbalanceable_groups.update({f'{CLUSTER}:sc1', f'{CLUSTER}:gone', 'other:sc9'})
    _cycles(monkeypatch, storage)
    assert storage._unbalanceable_groups == {f'{CLUSTER}:sc1'}


# --- the tolerance is kept ----------------------------------------------------------------------

def test_the_tolerance_survives_create_update_and_a_reload(admin, pve, storage):
    pve(_Pve({}), [])
    r = admin.post(f'/api/clusters/{CLUSTER}/storage-clusters',
                   json={'name': 'tol', 'storages': ['full', 'half'], 'tolerance': 8})
    assert r.status_code == 201, r.data
    sc = r.get_json()
    assert sc['tolerance'] == 8
    url = f"/api/clusters/{CLUSTER}/storage-clusters/{sc['id']}"
    assert admin.put(url, json={'tolerance': 12}).get_json()['tolerance'] == 12
    storage.load_storage_clusters()
    listed = admin.get(f'/api/clusters/{CLUSTER}/storage-clusters').get_json()
    assert [(g['name'], g['tolerance']) for g in listed] == [('tol', 12)]


@pytest.mark.parametrize('sent,kept', [(25, 20), (-3, 0), ('7', 7), ('a lot', 5), (None, 5)])
def test_a_tolerance_out_of_range_is_held_to_the_range(admin, pve, sent, kept):
    pve(_Pve({}), [])
    r = admin.post(f'/api/clusters/{CLUSTER}/storage-clusters',
                   json={'name': 'tol', 'storages': ['full', 'half'], 'tolerance': sent})
    assert r.status_code == 201, r.data
    assert r.get_json()['tolerance'] == kept
    put = admin.put(f"/api/clusters/{CLUSTER}/storage-clusters/{r.get_json()['id']}", json={'tolerance': sent})
    assert put.get_json()['tolerance'] == kept


def test_a_group_created_without_a_tolerance_gets_the_one_the_worker_used(admin, pve):
    pve(_Pve({}), [])
    r = admin.post(f'/api/clusters/{CLUSTER}/storage-clusters', json={'name': 'old', 'storages': ['a', 'b']})
    assert r.get_json()['tolerance'] == 5


@pytest.mark.parametrize('sent,kept', [(90, 50), (1, 5), ('30', 30), ('high', 20)])
def test_a_threshold_out_of_range_is_held_to_the_range(admin, pve, sent, kept):
    pve(_Pve({}), [])
    r = admin.post(f'/api/clusters/{CLUSTER}/storage-clusters',
                   json={'name': 'thr', 'storages': ['full', 'half'], 'threshold': sent})
    assert r.status_code == 201, r.data
    assert r.get_json()['threshold'] == kept
    put = admin.put(f"/api/clusters/{CLUSTER}/storage-clusters/{r.get_json()['id']}", json={'threshold': sent})
    assert put.get_json()['threshold'] == kept


# --- the container disk move dialog (manager.move_disk) -------------------------------------------

@pytest.mark.parametrize('vm_type,disk,path,key', [
    ('lxc', 'mp0', '/nodes/n1/lxc/301/move_volume', 'volume'),
    ('qemu', 'scsi0', '/nodes/n1/qemu/100/move_disk', 'disk'),
])
def test_the_disk_move_dialog_names_the_volume_the_way_pve_wants(monkeypatch, vm_type, disk, path, key):
    import pegaprox.core.manager as mgrmod
    m = object.__new__(mgrmod.PegaProxManager)
    m.id, m.is_connected, m.current_host = CLUSTER, True, None
    m.config = types.SimpleNamespace(host='192.0.2.10', api_port=8006)
    m.logger = logging.getLogger('test.storage_balancing')
    posts = []
    m._api_post = lambda url, data=None, **kw: posts.append((url.split('/api2/json', 1)[1], data)) or _resp(200, 'UPID:n1:1:')
    monkeypatch.setattr(mgrmod, 'get_db', lambda: (_ for _ in ()).throw(RuntimeError('no db here')))
    vmid = 301 if vm_type == 'lxc' else 100
    assert m.move_disk('n1', vmid, vm_type, disk, 'half')['success'] is True
    # move_volume takes 'volume' and refuses any other parameter
    assert posts == [(path, {key: disk, 'storage': 'half', 'delete': 1})]
