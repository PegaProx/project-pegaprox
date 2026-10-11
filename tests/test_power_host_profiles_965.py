# #965 - Power & Carbon with a power profile per host. The model is computed per host and
# per snapshot interval and handed down to the guests that ran there, so an empty host's
# baseline is counted, a migrated guest is charged to each host it ran on, and
# guests + unallocated always add up to what the hosts drew.
import time

import pytest

import pegaprox.api.power as power
import pegaprox.utils.rbac as rbac

GIB = 1024 ** 3

RATES = {'node_idle_w': 80.0, 'node_max_w': 300.0, 'mem_w_per_gb': 0.0, 'pue': 1.0,
         'kwh_price': 0.30, 'kg_co2_per_kwh': 0.40, 'currency': 'EUR'}
N1_PROFILE = {'n1': {'idle_w': 10.0, 'max_w': 60.0, 'notes': '', 'updated_at': None, 'updated_by': ''}}


def _node(cpu, cores=4, mem_pct=50.0, mem_gib=8):
    return {'cpu': cpu, 'maxcpu': cores, 'mem_percent': mem_pct, 'maxmem': mem_gib * GIB}


def _vm(node, cpu, vcpus=2, mem=50.0, mem_gib=2, running=True):
    v = {'t': 'qemu', 'r': running, 'cpu': cpu if running else None,
         'mem': mem if running else None, 'maxcpu': vcpus, 'maxmem': mem_gib * GIB}
    if node is not None:
        v['n'] = node
    return v


def _snap(ts, vms, n1_cpu=50.0, n2_cpu=0.0):
    return (ts, {'nodes': {'n1': _node(n1_cpu), 'n2': _node(n2_cpu)}, 'vms': vms})


def _live(resources=()):
    """The live guest list _compute_power takes for names and today's placement."""
    return list(resources)


def _two_hours(vms_first, vms_second=None, gap=3600):
    return [_snap(0, vms_first), _snap(gap, vms_second if vms_second is not None else vms_first)]


def _power(snaps, live, rates, profiles):
    # the model tests read one snapshot an hour, so an hour is the cadence
    return power._compute_power(snaps, live, rates, profiles, step=3600)


def _row(res, vmid):
    return next(r for r in res['rows'] if r['vmid'] == vmid)


# ── the model ────────────────────────────────────────────────────────────

def test_host_profile_splits_idle_by_vcpu_and_active_by_used_cores():
    # n1 (own profile 10 W idle / 60 W max) at 50% CPU draws 10 + 50 * 0.5 = 35 W.
    # Idle: 2.5 W per vCPU over the 4 running vCPUs. Active: 12.5 W per used core.
    res = _power(_two_hours({'100': _vm('n1', 50.0), '101': _vm('n1', 0.0)}),
                               _live(), RATES, N1_PROFILE)
    assert _row(res, '100')['kwh_exact'] == pytest.approx((2 * 2.5 + 1 * 12.5) * 2 / 1000)
    assert _row(res, '101')['kwh_exact'] == pytest.approx(2 * 2.5 * 2 / 1000)
    n1 = res['hosts']['n1']
    assert n1['kwh'] == pytest.approx(35 * 2 / 1000)
    # the host's CPU that no guest accounts for stays with the host
    assert n1['kwh_unallocated'] == pytest.approx(12.5 * 2 / 1000)
    assert n1['online_h'] == pytest.approx(2.0)


def test_an_online_host_without_guests_still_draws_its_baseline():
    res = _power(_two_hours({'100': _vm('n1', 50.0)}), _live(), RATES, N1_PROFILE)
    # n2 inherits the cluster's 80 W idle and runs nothing: all of it is unallocated
    assert res['hosts']['n2']['kwh'] == pytest.approx(80 * 2 / 1000)
    assert res['hosts']['n2']['kwh_unallocated'] == pytest.approx(80 * 2 / 1000)


def test_guests_plus_unallocated_add_up_to_the_hosts():
    vms = {'100': _vm('n1', 80.0, vcpus=4), '101': _vm('n1', 10.0), '102': _vm('n2', 30.0),
           '103': _vm('n2', 0.0, running=False)}
    res = _power(_two_hours(vms), _live(), {**RATES, 'mem_w_per_gb': 0.5}, N1_PROFILE)
    hosts_total = sum(h['kwh'] for h in res['hosts'].values())
    unallocated = sum(h['kwh_unallocated'] for h in res['hosts'].values())
    guests = sum(r['kwh_exact'] for r in res['rows'])
    assert guests + unallocated == pytest.approx(hosts_total)
    assert _row(res, '103')['kwh_exact'] == 0


def test_guests_are_never_handed_more_than_the_host_drew():
    # guest samples ahead of the host's: 2 guests at 100% of 4 vCPUs on a 4-core host at 10%
    vms = {'100': _vm('n1', 100.0, vcpus=4), '101': _vm('n1', 100.0, vcpus=4)}
    res = _power([_snap(0, vms, n1_cpu=10.0), _snap(3600, vms, n1_cpu=10.0)],
                               _live(), RATES, N1_PROFILE)
    guests = sum(r['kwh_exact'] for r in res['rows'])
    assert guests == pytest.approx(res['hosts']['n1']['kwh'])
    assert res['hosts']['n1']['kwh_unallocated'] == pytest.approx(0)


def test_a_migrated_guest_is_charged_to_each_host_it_ran_on():
    snaps = [_snap(0, {'100': _vm('n1', 50.0)}), _snap(3600, {'100': _vm('n2', 50.0)}, n2_cpu=50.0)]
    res = _power(snaps, _live([{'vmid': 100, 'name': 'db', 'node': 'n2'}]), RATES, N1_PROFILE)
    row = _row(res, '100')
    assert set(row['by_node']) == {'n1', 'n2'}
    # first hour on n1 (10/60 W profile), second on n2 (cluster's 80/300 W, 55 W per core)
    assert row['by_node']['n1'] == pytest.approx((10.0 + 12.5 * 1) / 1000, abs=1e-3)
    assert row['by_node']['n2'] == pytest.approx((80.0 + 55.0 * 1) / 1000, abs=1e-3)
    assert row['node'] == 'n2' and not row['node_estimated']


def test_history_without_a_host_falls_back_to_todays_placement_and_says_so():
    res = _power(_two_hours({'100': _vm(None, 50.0)}),
                               _live([{'vmid': 100, 'name': 'db', 'node': 'n1'}]), RATES, N1_PROFILE)
    row = _row(res, '100')
    assert row['node_estimated'] is True
    assert set(row['by_node']) == {'n1'} and row['kwh_exact'] > 0


def test_ram_watts_only_on_hosts_without_their_own_whole_system_profile():
    rates = {**RATES, 'mem_w_per_gb': 1.0}
    vms = {'100': _vm('n1', 0.0), '101': _vm('n2', 0.0)}
    res = _power([_snap(0, vms, n1_cpu=0.0), _snap(3600, vms, n1_cpu=0.0)],
                               _live(), rates, N1_PROFILE)
    # n1 has its own profile: idle + CPU only. n2 inherits: + 50% of 8 GiB at 1 W/GB
    assert res['hosts']['n1']['kwh'] == pytest.approx(10 * 2 / 1000)
    assert res['hosts']['n2']['kwh'] == pytest.approx((80 + 4) * 2 / 1000)
    # the guest on n2 uses 1 GiB: 1 W of it, plus the whole idle (only guest there)
    assert _row(res, '101')['kwh_exact'] == pytest.approx((80 + 1) * 2 / 1000)


def test_a_gap_in_the_history_is_not_bridged():
    snaps = [(0, {}), (300, {}), (600, {}), (7200, {})]
    assert [round(h * 3600) for h in power._intervals(snaps)] == [300, 300, 900, 300]


def test_a_long_gap_in_a_sparse_history_stays_missing():
    # three snapshots, the last after 10 h without one: the gap must not become the
    # step every snapshot is measured by, so it does not count as covered
    snaps = [(0, {}), (300, {}), (36300, {})]
    assert [round(h * 3600) for h in power._intervals(snaps, 300)] == [300, 900, 300]


def test_pue_scales_every_figure():
    vms = {'100': _vm('n1', 50.0)}
    one = _power(_two_hours(vms), _live(), RATES, N1_PROFILE)
    two = _power(_two_hours(vms), _live(), {**RATES, 'pue': 2.0}, N1_PROFILE)
    assert two['hosts']['n1']['kwh'] == pytest.approx(2 * one['hosts']['n1']['kwh'])
    assert _row(two, '100')['kwh_exact'] == pytest.approx(2 * _row(one, '100')['kwh_exact'])


# ── the routes ───────────────────────────────────────────────────────────

_NODES = {'n1': {'status': 'online', 'maxcpu': 4, 'maxmem': 8 * GIB},
          'n2': {'status': 'online', 'maxcpu': 4, 'maxmem': 8 * GIB}}
_RESOURCES = [{'vmid': 100, 'name': 'db01', 'node': 'n1', 'type': 'qemu'},
              {'vmid': 101, 'name': 'web01', 'node': 'n1', 'type': 'qemu'}]


def _cluster(api, monkeypatch, snaps=None):
    m = api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(_RESOURCES))
    m.is_connected = True
    m.nodes = dict(_NODES)
    api.set_manager('cluster_1', m)
    snaps = snaps if snaps is not None else _two_hours({'100': _vm('n1', 50.0), '101': _vm('n1', 0.0)}, gap=300)
    monkeypatch.setattr(power, '_load_history', lambda *a, **k: snaps)
    return m


def _admin(seed):
    return seed.user('root', role='admin', tenant_id='default')


def _plain_rates(api, seed):
    # PUE 1 and no RAM watts, so the expected figures stay readable
    r = api.as_user(_admin(seed)).put('/api/power/rates/cluster_1', json={
        'node_idle_w': 80, 'node_max_w': 300, 'mem_w_per_gb': 0, 'pue': 1,
        'kwh_price': 0.30, 'kg_co2_per_kwh': 0.40})
    assert r.status_code == 200, r.get_data(as_text=True)


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _pool_user(seed, perms=None):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x', permissions=perms or [])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


def test_hosts_are_discovered_and_inherit_until_given_a_profile(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    c = api.as_user(_admin(seed))
    hosts = {h['node']: h for h in c.get('/api/clusters/cluster_1/power/hosts').get_json()['hosts']}
    assert set(hosts) == {'n1', 'n2'}
    assert hosts['n1']['profile'] == 'cluster' and hosts['n1']['idle_w'] == 80.0

    r = c.put('/api/clusters/cluster_1/power/hosts/n1', json={'idle_w': 9, 'max_w': 65, 'notes': 'G6 mini'})
    assert r.status_code == 200, r.get_data(as_text=True)
    hosts = {h['node']: h for h in c.get('/api/clusters/cluster_1/power/hosts').get_json()['hosts']}
    assert (hosts['n1']['profile'], hosts['n1']['idle_w'], hosts['n1']['max_w']) == ('host', 9.0, 65.0)
    assert hosts['n1']['notes'] == 'G6 mini' and hosts['n1']['updated_by'] == 'root'
    assert hosts['n2']['profile'] == 'cluster'

    assert c.delete('/api/clusters/cluster_1/power/hosts/n1').status_code == 200
    hosts = {h['node']: h for h in c.get('/api/clusters/cluster_1/power/hosts').get_json()['hosts']}
    assert hosts['n1']['profile'] == 'cluster'


@pytest.mark.parametrize('body', [
    {'idle_w': 50, 'max_w': 40},            # max below idle
    {'idle_w': -1, 'max_w': 40},
    {'idle_w': 'nan', 'max_w': 40},
    {'idle_w': 10, 'max_w': 'inf'},
    {'idle_w': 10, 'max_w': 1e9},
    {'idle_w': 10},
    {'idle_w': 'ten', 'max_w': 40},
])
def test_host_profile_rejects_nonsense(api, seed, monkeypatch, body):
    _cluster(api, monkeypatch)
    r = api.as_user(_admin(seed)).put('/api/clusters/cluster_1/power/hosts/n1', json=body)
    assert r.status_code == 400, r.get_data(as_text=True)


def test_host_profile_only_for_a_host_of_the_cluster(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    c = api.as_user(_admin(seed))
    assert c.put('/api/clusters/cluster_1/power/hosts/n9', json={'idle_w': 1, 'max_w': 2}).status_code == 404
    assert c.put('/api/clusters/cluster_1/power/hosts/bad%20name', json={'idle_w': 1, 'max_w': 2}).status_code == 400


def test_a_confined_caller_cannot_reprice_a_host(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    u = _pool_user(seed, perms=['cluster.config', 'cluster.view'])
    c = api.as_user(u)
    assert c.put('/api/clusters/cluster_1/power/hosts/n1', json={'idle_w': 1, 'max_w': 2}).status_code == 403
    assert c.delete('/api/clusters/cluster_1/power/hosts/n1').status_code == 403


def test_viewer_cannot_write_a_host_profile(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    seed.tenant('tenant_x', clusters=['cluster_1'])
    v = seed.user('vic', role='viewer', tenant_id='tenant_x')
    r = api.as_user(v).put('/api/clusters/cluster_1/power/hosts/n1', json={'idle_w': 1, 'max_w': 2})
    assert r.status_code == 403


def test_summary_totals_are_the_hosts_and_name_the_unallocated_part(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    _plain_rates(api, seed)
    c = api.as_user(_admin(seed))
    c.put('/api/clusters/cluster_1/power/hosts/n1', json={'idle_w': 10, 'max_w': 60})
    s = c.get('/api/clusters/cluster_1/power/summary?days=1').get_json()
    assert s['enough_data'] and not s['scoped']
    hosts = {h['node']: h for h in s['hosts']}
    assert hosts['n1']['profile'] == 'host' and hosts['n2']['profile'] == 'cluster'
    # n1 at 35 W, n2 idle at 80 W; two 5-minute snapshots of a 24 h window
    assert hosts['n1']['avg_w'] == pytest.approx(35.0) and hosts['n2']['avg_w'] == pytest.approx(80.0)
    assert s['coverage']['covered_h'] == 0.2 and s['coverage']['missing_h'] == 23.8
    # monthly extrapolates from the covered hours: 115 W for 720 h
    assert s['monthly']['kwh'] == pytest.approx(115 * 720 / 1000, abs=0.01)
    assert s['monthly']['kwh'] == pytest.approx(sum(h['monthly']['kwh'] for h in s['hosts']), abs=0.02)
    assert s['allocated']['monthly']['kwh'] + s['unallocated']['monthly']['kwh'] == \
        pytest.approx(s['monthly']['kwh'], abs=0.02)
    assert s['unallocated']['monthly']['kwh'] == pytest.approx((12.5 + 80) * 720 / 1000, abs=0.01)


def test_a_confined_caller_sees_their_guests_share_not_the_hosts(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    _plain_rates(api, seed)
    s = api.as_user(_pool_user(seed)).get('/api/clusters/cluster_1/power/summary?days=1').get_json()
    assert s['scoped'] is True
    assert 'hosts' not in s and 'unallocated' not in s
    assert [r['vmid'] for r in s['top_consumers']] == ['100']
    assert s['vm_count'] == 1
    # vm 100 alone: n1 inherits 80/300 W - 2 of the 4 running vCPUs' idle + 1 used core at 55 W
    assert s['monthly']['kwh'] == pytest.approx((40 + 55) * 720 / 1000, abs=0.01)


def test_per_vm_rows_carry_monthly_figures_and_the_hosts_they_ran_on(api, seed, monkeypatch):
    _cluster(api, monkeypatch, snaps=_two_hours({'100': _vm('n1', 50.0)}, {'100': _vm('n2', 50.0)}, gap=300))
    d = api.as_user(_admin(seed)).get('/api/clusters/cluster_1/power/per-vm?days=1').get_json()
    row = next(r for r in d['rows'] if r['vmid'] == '100')
    assert set(row['by_node']) == {'n1', 'n2'}
    assert 'kwh_exact' not in row
    assert row['monthly_cost'] == pytest.approx(row['monthly_kwh'] * 0.30, abs=0.01)


def test_power_host_profiles_are_swept_with_their_cluster(db):
    db.conn.execute("INSERT INTO power_host_profiles (cluster_id, node, idle_w, max_w) VALUES ('c9', 'n1', 1, 2)")
    db.conn.commit()
    db.delete_cluster('c9')
    assert db.conn.execute("SELECT COUNT(*) FROM power_host_profiles WHERE cluster_id='c9'").fetchone()[0] == 0


def test_a_new_host_profile_shows_up_at_once(api, seed, monkeypatch):
    # the summary and the per-VM table share one computed result for a minute -
    # a changed profile must not wait for it
    _cluster(api, monkeypatch)
    _plain_rates(api, seed)
    c = api.as_user(_admin(seed))
    before = c.get('/api/clusters/cluster_1/power/summary?days=1').get_json()
    c.put('/api/clusters/cluster_1/power/hosts/n1', json={'idle_w': 10, 'max_w': 60})
    after = c.get('/api/clusters/cluster_1/power/summary?days=1').get_json()
    n1 = lambda s: next(h for h in s['hosts'] if h['node'] == 'n1')
    assert n1(before)['avg_w'] == pytest.approx(80 + 110) and n1(after)['avg_w'] == pytest.approx(35)


def test_summary_and_per_vm_share_one_run(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    runs = []
    real = power._compute_power
    monkeypatch.setattr(power, '_compute_power', lambda *a, **k: runs.append(1) or real(*a, **k))
    c = api.as_user(_admin(seed))
    assert c.get('/api/clusters/cluster_1/power/summary?days=1').status_code == 200
    assert c.get('/api/clusters/cluster_1/power/per-vm?days=1').status_code == 200
    assert len(runs) == 1
    # and the per-VM route did not write its monthly figures into the shared rows
    assert all('monthly_kwh' not in r for r in power._results[('cluster_1', 1)][3]['rows'])


def test_a_confined_caller_cannot_read_the_host_profiles(api, seed, monkeypatch):
    # whole-host settings (watts, notes) - a pool user sees their guests' share only
    _cluster(api, monkeypatch)
    r = api.as_user(_pool_user(seed)).get('/api/clusters/cluster_1/power/hosts')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_host_profile_changes_are_audited(api, seed, monkeypatch, db):
    _cluster(api, monkeypatch)
    c = api.as_user(_admin(seed))
    c.put('/api/clusters/cluster_1/power/hosts/n1', json={'idle_w': 9, 'max_w': 65})
    c.delete('/api/clusters/cluster_1/power/hosts/n1')
    c.delete('/api/clusters/cluster_1/power/hosts/n1')  # nothing left to remove: no entry
    rows = db.conn.execute("SELECT user, action, details, cluster_id FROM audit_log "
                           "WHERE action LIKE 'power.host_profile%' ORDER BY id").fetchall()
    assert [(r['user'], r['action'], r['cluster_id']) for r in rows] == [
        ('root', 'power.host_profile_set', 'cluster_1'), ('root', 'power.host_profile_removed', 'cluster_1')]
    assert '9 W idle, 65 W full load' in rows[0]['details'] and 'n1' in rows[1]['details']
