"""Search by MAC address, IP address and notes.

/cluster/resources carries names, ids and the agent's IPs, no MAC and no description;
those are in each guest's config. The guest search index (background/guest_index.py)
takes the configs the drift sweep and the config route read anyway, and a refresher
with a budget per pass reads the rest. /api/global/search looks there after name, id,
node, IP and tag, and says which field matched and with what value.

The route tests drive real requests through the real app, the managers faked.
MK Oct 2026
"""
import re
import time

import pytest

import pegaprox.utils.rbac as rbac

MAC_WEB = 'BC:24:11:AA:BB:01'
MAC_DB = 'BC:24:11:AA:BB:02'
MAC_CT = 'BC:24:11:CC:DD:03'

VMS = [
    {'vmid': 100, 'name': 'web01', 'node': 'n1', 'type': 'qemu', 'status': 'running',
     'ip': '10.1.0.10', 'ip_addresses': ['10.1.0.10', '172.16.5.10'], 'tags': ''},
    {'vmid': 101, 'name': 'db01', 'node': 'n1', 'type': 'qemu', 'status': 'stopped', 'tags': ''},
    {'vmid': 900, 'name': 'cache', 'node': 'n2', 'type': 'lxc', 'status': 'stopped', 'tags': ''},
]

CONFIGS = {
    ('qemu', 100): {'net0': f'virtio={MAC_WEB},bridge=vmbr0,firewall=1', 'name': 'web01',
                    'description': 'Frontend for the shop.\nBackup window 02:00 - 03:00, ask ops first.'},
    ('qemu', 101): {'net0': f'virtio={MAC_DB},bridge=vmbr0', 'net1': 'e1000=BC:24:11:AA:BB:12,bridge=vmbr1',
                    'ipconfig0': 'ip=10.2.0.20/24,gw=10.2.0.1', 'ipconfig1': 'ip=dhcp,ip6=fd00:2::21/64',
                    'description': 'Primary database'},
    ('lxc', 900): {'net0': f'name=eth0,bridge=vmbr0,hwaddr={MAC_CT},ip=192.168.9.30/24,gw=192.168.9.1',
                   'net1': 'name=eth1,bridge=vmbr1,hwaddr=BC:24:11:CC:DD:04,ip=dhcp',
                   'description': 'redis cache'},
}


def _manager(api, cluster_id='cluster_1', vms=VMS):
    m = api.make_fake_manager(cluster_id=cluster_id, get_vm_resources=[dict(v) for v in vms])
    m.is_connected = True
    m.config.name = cluster_id
    m.nodes = {}
    api.set_manager(cluster_id, m)
    return m


def _open_config(client, mgr, vm_type, vmid, node='n1', cluster_id='cluster_1'):
    """The config dialog of the UI: GET .../config, the manager answering with the raw config."""
    mgr.get_vm_config.return_value = {'success': True, 'config': {
        'raw': dict(CONFIGS[(vm_type, vmid)]), 'vmid': vmid, 'node': node, 'type': vm_type}}
    r = client.get(f'/api/clusters/{cluster_id}/vms/{node}/{vm_type}/{vmid}/config')
    assert r.status_code == 200, r.get_data(as_text=True)


def _search(client, q):
    r = client.get('/api/global/search', query_string={'q': q})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()['results']


def _hits(results):
    return sorted((x['vmid'], x['match_field']) for x in results if x.get('vmid') is not None)


def _index_all(cluster_id='cluster_1'):
    from pegaprox.background import guest_index
    for (vm_type, vmid), cfg in CONFIGS.items():
        guest_index.ingest(cluster_id, vm_type, vmid, cfg)


# -- the core: a config read once is found by its MAC ------------------------------------------

def test_a_config_opened_once_is_found_by_its_mac_in_any_spelling(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    _open_config(admin, _manager(api), 'qemu', 101)
    for q in ('BC:24:11:AA:BB:02', 'bc:24:11:aa:bb:02', 'bc-24-11-aa-bb-02', 'bc2411aabb02',
              'BC24.11AA.BB02', 'aa:bb:02'):
        results = _search(admin, q)
        assert [(x['vmid'], x['match_field'], x.get('match_value'), x.get('match_net')) for x in results] == [
            (101, 'mac', MAC_DB, 'net0')], q


def test_the_second_nic_says_which_one(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    _manager(api)
    _index_all()
    hit = _search(admin, 'bc2411aabb12')
    assert [(x['vmid'], x['match_value'], x['match_net']) for x in hit] == [(101, 'BC:24:11:AA:BB:12', 'net1')]


def test_a_mac_prefix_finds_every_guest_of_the_range(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    _manager(api)
    _index_all()
    assert _hits(_search(admin, 'mac:bc:24:11')) == [(100, 'mac'), (101, 'mac'), (900, 'mac')]
    assert _hits(_search(admin, 'BC-24-11-CC')) == [(900, 'mac')]
    # mac: takes two hex digits, without it a part of a MAC is four at least
    assert _hits(_search(admin, 'mac:cc')) == [(900, 'mac')]


def test_an_ip_or_an_id_is_not_read_as_a_mac(api, seed):
    """10.2.0.20 holds the digits of no MAC here, 1102 would: a MAC ending in ...11:02
    must not come up for a query that is a VMID or an address."""
    from pegaprox.background import guest_index
    admin = api.as_user(seed.user('root', role='admin'))
    _manager(api, vms=[dict(VMS[1], vmid=101)])
    guest_index.ingest('cluster_1', 'qemu', 101, {'net0': 'virtio=BC:24:11:00:11:02,bridge=vmbr0'})
    assert _search(admin, '1102') == []
    assert _search(admin, '00.11.02') == []
    assert _hits(_search(admin, 'mac:1102')) == [(101, 'mac')]
    assert _hits(_search(admin, '00:11:02')) == [(101, 'mac')]


def test_notes_are_found_with_the_words_around_the_hit(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    _manager(api)
    _index_all()
    results = _search(admin, 'backup window')
    assert _hits(results) == [(100, 'notes')]
    assert results[0]['match_value'] == ('Frontend for the shop. Backup window 02:00 - 03:00, '
                                         'ask ops first.')
    assert _hits(_search(admin, 'notes:REDIS')) == [(900, 'notes')]
    assert _search(admin, 'notes:web01') == [], 'notes: looks at the notes only, not the name'


def test_every_known_ip_is_searched(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    _manager(api)
    _index_all()
    # the second address the agent reports: the old search looked at the first one only
    second = _search(admin, '172.16.5')
    assert [(x['vmid'], x['match_field'], x['match_value']) for x in second] == [(100, 'ip', '172.16.5.10')]
    # the static address of a stopped VM (cloud-init) and of a stopped container
    assert [(x['vmid'], x['match_value'], x['match_net']) for x in _search(admin, '10.2.0.20')] == [
        (101, '10.2.0.20', 'net0')]
    assert [(x['vmid'], x['match_value'], x['match_net']) for x in _search(admin, 'ip:192.168.9')] == [
        (900, '192.168.9.30', 'net0')]
    assert [(x['vmid'], x['match_value']) for x in _search(admin, 'ip:fd00:2::21')] == [(101, 'fd00:2::21')]
    # the first one still answers as before, with the value said
    assert [(x['vmid'], x['match_field'], x['match_value']) for x in _search(admin, '10.1.0.10')] == [
        (100, 'ip', '10.1.0.10')]


def test_a_name_hit_stays_a_name_hit(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    _manager(api)
    _index_all()
    results = _search(admin, 'cache')
    assert _hits(results) == [(900, 'name')]
    assert 'match_value' not in results[0]


def test_a_guest_the_index_has_not_read_yet_is_no_error(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    _manager(api)
    assert _search(admin, 'bc2411aabb01') == []
    assert _hits(_search(admin, 'web')) == [(100, 'name')]


# -- who sees what -----------------------------------------------------------------------------

def _pool_user(seed, name='mallory'):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user(name, role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', name, ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache['cluster_1'] = {'data': {'100:qemu': 'pool_1'}, 'timestamp': time.time(),
                                                    'refreshing': False}
    return u


def test_a_pool_user_finds_the_mac_and_notes_of_their_own_guest_only(api, seed):
    mallory = api.as_user(_pool_user(seed))
    _manager(api)
    _index_all()
    assert _hits(_search(mallory, 'mac:bc:24:11')) == [(100, 'mac')]
    assert _search(mallory, MAC_DB) == []
    assert _search(mallory, 'primary database') == []
    assert _search(mallory, '10.2.0.20') == []
    assert _hits(_search(mallory, 'backup window')) == [(100, 'notes')]


def test_an_acl_user_finds_the_one_guest_they_were_given(api, seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    alice = api.as_user(seed.user('alice', role='viewer', tenant_id='tenant_x'))
    seed.vm_acl('cluster_1', 900, ['alice'], inherit_role=False, permissions=['vm.view'])
    _manager(api)
    _index_all()
    assert _hits(_search(alice, 'mac:bc:24:11')) == [(900, 'mac')]
    assert _search(alice, 'backup window') == []


def test_another_tenant_and_a_confined_admin_find_nothing(api, seed):
    _manager(api)
    _manager(api, cluster_id='cluster_2', vms=[])
    _index_all()
    seed.tenant('tenant_x', clusters=['cluster_1'])
    seed.tenant('globex', clusters=['cluster_2'])
    callers = {
        'other tenant': seed.user('milton', role='user', tenant_id='globex'),
        'confined admin': seed.user('gx', role='admin', tenant_id='globex',
                                    tenant_permissions={'globex': {'role': 'user'}}),
    }
    for who, user in callers.items():
        client = api.as_user(user)
        for q in ('mac:bc:24:11', MAC_WEB, 'backup window', 'notes:redis', '10.2.0.20', 'ip:192.168.9'):
            assert _search(client, q) == [], (who, q)


def test_the_operator_of_the_cluster_finds_them_all(api, seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    otto = api.as_user(seed.user('otto', role='viewer', tenant_id='tenant_x'))
    _manager(api)
    _index_all()
    assert _hits(_search(otto, 'mac:bc:24:11')) == [(100, 'mac'), (101, 'mac'), (900, 'mac')]


# -- what feeds the index ----------------------------------------------------------------------

class _Resp:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data

    def json(self):
        return {'data': self._data}


class _Pve:
    """A Proxmox manager as the drift sweep and the refresher use it."""
    cluster_type = 'proxmox'
    host, api_port = 'pve.test', 8006

    def __init__(self, guests, configs, connected=True):
        self.is_connected = connected
        self.guests = guests
        self.configs = configs
        self.nodes = {}
        self.reads = []
        self.timeouts = []
        self.broken = set()
        self.list_ages = []

    def get_vm_resources(self, max_age=0.0):
        self.list_ages.append(max_age)
        return [dict(g) for g in self.guests]

    def _api_get(self, url, **kw):
        m = re.search(r'/nodes/([^/]+)/(qemu|lxc)/(\d+)/config$', url)
        if not m:
            return _Resp(404, None)
        key = (m.group(2), int(m.group(3)))
        self.reads.append(key)
        self.timeouts.append(kw.get('timeout'))
        if key in self.broken or key not in self.configs:
            return _Resp(500, None)
        return _Resp(200, dict(self.configs[key]))


def _guests(n, start=100, node='n1'):
    return [{'vmid': start + i, 'name': f'g{start + i}', 'node': node, 'type': 'qemu', 'status': 'running'}
            for i in range(n)]


def _cfgs(guests):
    out = {}
    for g in guests:
        mac = 'BC:24:11:00:%02X:%02X' % divmod(g['vmid'], 256)
        out[('qemu', g['vmid'])] = {'net0': f'virtio={mac},bridge=vmbr0', 'description': f'guest {g["vmid"]}'}
    return out


@pytest.fixture
def index():
    import pegaprox.globals as ppglobals
    from pegaprox.background import guest_index
    guest_index.clear()
    saved = dict(ppglobals.cluster_managers)
    ppglobals.cluster_managers.clear()
    yield guest_index
    ppglobals.cluster_managers.clear()
    ppglobals.cluster_managers.update(saved)
    guest_index.clear()


def test_the_drift_sweep_feeds_the_index(index):
    from pegaprox.api import drift
    vms = [dict(v) for v in VMS]
    pve = _Pve(vms, CONFIGS)
    drift._fetch_state(pve, 'cluster_1')
    got = index.snapshot('cluster_1')
    assert sorted(got) == [('lxc', 900), ('qemu', 100), ('qemu', 101)]
    assert [m[1] for m in got[('qemu', 101)]['macs']] == [MAC_DB, 'BC:24:11:AA:BB:12']
    assert got[('lxc', 900)]['ips'] == [('net0', '192.168.9.30')]


def test_a_pass_reads_at_most_its_budget_and_never_read_guests_first(index):
    import pegaprox.globals as ppglobals
    guests = _guests(120)
    pve = _Pve(guests, _cfgs(guests))
    ppglobals.cluster_managers['c1'] = pve
    assert index.refresh_pass(budget=50) == 50
    assert len(pve.reads) == 50 and len(set(pve.reads)) == 50
    assert index.refresh_pass(budget=50) == 50
    assert index.refresh_pass(budget=50) == 20
    assert sorted(v for _, v in pve.reads) == list(range(100, 220))
    # everything read and fresh: the next pass reads nothing
    assert index.refresh_pass(budget=50) == 0
    # the guest list it works from may be minutes old, it is no walk of PVE per pass,
    # and a node that does not answer holds a read for seconds, not for the API timeout
    assert set(pve.list_ages) == {index.LIST_MAX_AGE}
    assert set(pve.timeouts) == {index.READ_TIMEOUT}
    # a new guest is read in the next pass, before any stale one
    new = _guests(1, start=500)
    pve.guests += new
    pve.configs.update(_cfgs(new))
    for key, entry in list(index.snapshot('c1').items()):
        index._index['c1'][key] = dict(entry, at=entry['at'] - index.STALE_AFTER - 1)
    pve.reads.clear()
    index.refresh_pass(budget=3)
    assert pve.reads[0] == ('qemu', 500)
    assert len(pve.reads) == 3


def test_the_budget_goes_round_the_clusters(index):
    import pegaprox.globals as ppglobals
    big, small = _guests(100), _guests(4, start=1000)
    a, b = _Pve(big, _cfgs(big)), _Pve(small, _cfgs(small))
    ppglobals.cluster_managers.update({'big': a, 'small': b})
    index.refresh_pass(budget=10)
    assert (len(a.reads), len(b.reads)) == (6, 4)


def test_a_pass_stops_at_its_deadline(index, monkeypatch):
    import pegaprox.globals as ppglobals
    guests = _guests(30)
    pve = _Pve(guests, _cfgs(guests))
    ppglobals.cluster_managers['c1'] = pve
    clock = [1000.0]
    monkeypatch.setattr(index.time, 'monotonic', lambda: clock[0])
    real_read = pve._api_get

    def slow(url, **kw):
        clock[0] += 5     # every read takes five seconds
        return real_read(url, **kw)
    pve._api_get = slow
    assert index.refresh_pass(budget=50, deadline=20) == 4


def test_a_failed_read_waits_for_its_turn(index):
    import pegaprox.globals as ppglobals
    guests = _guests(3)
    pve = _Pve(guests, _cfgs(guests))
    pve.broken.add(('qemu', 101))
    ppglobals.cluster_managers['c1'] = pve
    assert index.refresh_pass() == 3
    assert index.snapshot('c1')[('qemu', 101)]['macs'] == []
    assert index.refresh_pass() == 0, 'the broken guest was read again at once'


def test_a_node_that_does_not_answer_costs_one_read_per_pass(index):
    import pegaprox.globals as ppglobals
    up, down = _guests(5, node='n1'), _guests(5, start=200, node='n2')
    pve = _Pve(up + down, _cfgs(up + down))
    real_read = pve._api_get

    def read(url, **kw):
        if '/nodes/n2/' in url:
            pve.reads.append('n2')
            raise TimeoutError('read timed out')
        return real_read(url, **kw)
    pve._api_get = read
    ppglobals.cluster_managers['c1'] = pve
    index.refresh_pass()
    assert pve.reads.count('n2') == 1
    assert len([r for r in pve.reads if r != 'n2']) == 5
    # and a guest PVE reports as unknown (its node is down) is not tried at all
    pve.guests = [dict(g, status='unknown') for g in down[1:]]
    pve.reads.clear()
    index.forget('c1')
    assert index.refresh_pass() == 0 and pve.reads == []


def test_gone_guests_and_gone_clusters_leave_the_index(index):
    import pegaprox.globals as ppglobals
    guests = _guests(3)
    pve = _Pve(guests, _cfgs(guests))
    ppglobals.cluster_managers['c1'] = pve
    index.refresh_pass()
    pve.guests = guests[:2]
    index.refresh_pass()
    assert sorted(index.snapshot('c1')) == [('qemu', 100), ('qemu', 101)]
    # an empty list is as likely a failed read: nothing is dropped for it
    pve.guests = []
    index.refresh_pass()
    assert len(index.snapshot('c1')) == 2
    del ppglobals.cluster_managers['c1']
    index.refresh_pass()
    assert index.snapshot('c1') == {}


def test_only_connected_proxmox_clusters_are_read(index):
    import pegaprox.globals as ppglobals
    guests = _guests(2)
    off = _Pve(guests, _cfgs(guests), connected=False)
    xcp = _Pve(guests, _cfgs(guests))
    xcp.cluster_type = 'xcpng'
    ppglobals.cluster_managers.update({'off': off, 'xcp': xcp})
    assert index.refresh_pass() == 0
    assert off.reads == [] and xcp.reads == []


def test_the_loop_reads_only_where_users_are_served(index, monkeypatch):
    from pegaprox.core import ha
    calls = []
    monkeypatch.setattr(index, 'refresh_pass', lambda: calls.append(1))

    class _Stop(Exception):
        pass

    def run(active, serving):
        monkeypatch.setattr(ha, 'is_active', lambda: active)
        monkeypatch.setattr(ha, 'serve_assigned', lambda: serving)
        sleeps = []

        def sleep(_s):
            sleeps.append(_s)
            if len(sleeps) > 2:
                raise _Stop()
        monkeypatch.setattr(index.time, 'sleep', sleep)
        calls.clear()
        with pytest.raises(_Stop):
            index._loop()
        return len(calls)

    assert run(active=True, serving=False) == 2
    assert run(active=False, serving=True) == 2
    assert run(active=False, serving=False) == 0


# -- parsing ------------------------------------------------------------------------------------

def test_the_mac_needle():
    from pegaprox.background.guest_index import mac_needle
    assert mac_needle('BC:24:11:AA:BB:CC') == 'bc2411aabbcc'
    assert mac_needle('bc-24-11') == 'bc2411'
    assert mac_needle('BC24.11AA.BBCC') == 'bc2411aabbcc'
    assert mac_needle('bc 24 11') == 'bc2411'
    assert mac_needle('web01') is None
    assert mac_needle('10.0.0.5') is None
    assert mac_needle('1234') is None
    assert mac_needle('fd00::5') is None
    assert mac_needle('bc2') is None
    assert mac_needle('1234', prefixed=True) == '1234'
    assert mac_needle('bc', prefixed=True) == 'bc'


def test_a_config_without_any_of_it_is_an_empty_entry():
    from pegaprox.background.guest_index import parse_config
    assert parse_config('qemu', {'memory': 2048, 'net0': 'virtio,bridge=vmbr0'}) == {
        'macs': [], 'ips': [], 'notes': '', 'notes_lc': ''}
    assert parse_config('qemu', None)['macs'] == []


def test_the_nics_come_in_their_order():
    from pegaprox.background.guest_index import parse_config
    cfg = {'net10': 'virtio=BC:24:11:00:00:0A,bridge=vmbr0', 'net2': 'virtio=BC:24:11:00:00:02,bridge=vmbr0',
           'ipconfig10': 'ip=10.0.10.1/24', 'ipconfig2': 'ip=10.0.2.1/24'}
    got = parse_config('qemu', cfg)
    assert [m[0] for m in got['macs']] == ['net2', 'net10']
    assert got['ips'] == [('net2', '10.0.2.1'), ('net10', '10.0.10.1')]


def test_long_notes_are_cut(index):
    index.ingest('c1', 'qemu', 100, {'description': 'x' * 10000})
    assert len(index.snapshot('c1')[('qemu', 100)]['notes']) == index.NOTES_MAX


def test_no_em_dash_in_the_new_code():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, 'pegaprox', 'background', 'guest_index.py'), encoding='utf-8') as fh:
        assert '\u2014' not in fh.read()
