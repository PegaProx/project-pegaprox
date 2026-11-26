"""ESXi migration: the VMID the guest lands under (#1339).

A caller may name the VMID, per guest in a bulk run too. It is checked when the migration
is asked for (a whole number Proxmox VE takes, inside the tenant range of a caller who is no
admin, free on the target, not promised to another migration of this process) and asked of
Proxmox VE again right before the VM shell is created. Taken by then, the migration fails:
no other id is picked in its place. Without one the guest gets the next free id inside the
caller's tenant range, the cluster's next id otherwise.

The ESXi server and the Proxmox target only exist in this file and the bulk test next to it;
the routes run through the real app, the migration job itself is replaced by one that only
records the task (the allocation is driven on its own and through a whole offline run).

MK Nov 2026
"""
import re
import time
import types

import pytest

from pegaprox.core import esxi_bulk as ebulk
from pegaprox.core import target_vmid as tvmid

from test_esxi_bulk import Esxi, Pve as _BulkPve, Runner, _Resp as _BulkResp, _vm, _wait, PW

CID = 'pve-cl'


class _Resp(_BulkResp):
    def __init__(self, data, status=200, errors=None):
        super().__init__(data, status)
        self._errors = errors

    def json(self):
        out = {'data': self._data}
        if self._errors:
            out['errors'] = self._errors
        return out


class Pve(_BulkPve):
    """The target cluster: which VMIDs its guests have, which ones its next-id setting refuses."""

    def __init__(self, taken=()):
        super().__init__()
        self.taken = set(taken)
        self.used_before = set()
        self.enforce = None             # (lower, upper) of a next-id range with 'enforce'
        self.down = False
        self.listed = None              # what /cluster/resources shows, when it is behind
        self.asked = []
        self.cache = False              # answer a fresh enough walk again, as the manager's read cache does
        self.walks = 0
        self.resource_reads = []
        self._walked = None

    def _api_get(self, url, **kw):
        m = re.search(r'/api2/json/cluster/nextid(?:\?vmid=(\d+))?$', url)
        if not m:
            return super()._api_get(url, **kw)
        self.gets.append(url)
        if self.down:
            raise ConnectionError('no route to host')
        if m.group(1) is None:
            return _Resp(next(v for v in range(100, 10 ** 6) if v not in self.taken))
        v = int(m.group(1))
        self.asked.append(v)
        if v in self.taken:
            return _Resp(None, 400, {'vmid': f'guest ID {v} is already in use\n'})
        if self.enforce and not self.enforce[0] <= v < self.enforce[1]:
            return _Resp(None, 400, {'vmid': f'guest ID {v} is below the lower boundary {self.enforce[0]} '
                                             f'of the next-id range\n'})
        if v in self.used_before:
            return _Resp(None, 400, {'vmid': f'guest ID {v} was used before\n'})
        return _Resp(v)

    def get_vm_resources(self, max_age=0):
        self.resource_reads.append(max_age)
        if self.listed == 'fail':
            from pegaprox.core.manager import UnreadList
            return UnreadList('boom', 500)
        if self.cache and max_age > 0 and self._walked and time.time() - self._walked[0] < max_age:
            return self._walked[1]
        self.walks += 1
        ids = self.taken if self.listed is None else self.listed
        rows = [{'vmid': v, 'type': 'qemu'} for v in sorted(ids)]
        self._walked = (time.time(), rows)
        return rows


def _task(mid='m1', vmid=None, start=0, end=0, strict=False, owner=None, bind=True):
    t = types.SimpleNamespace(id=mid, target_cluster=CID, status='running')
    if bind:
        tvmid.bind(t, vmid, start, end, strict, owner or f'task:{mid}')
    return t


@pytest.fixture(autouse=True)
def _no_holds():
    tvmid.reset_for_tests()
    yield
    tvmid.reset_for_tests()


# --------------------------------------------------------------------------- the module

@pytest.mark.parametrize('raw, want', [(None, None), ('', None), ('  ', None), (1200, 1200), ('1200', 1200),
                                       (' 2001 ', 2001), (100, 100), (999999999, 999999999)])
def test_a_chosen_vmid_is_a_whole_number_proxmox_takes(raw, want):
    assert tvmid.parse(raw) == want


@pytest.mark.parametrize('raw', [99, 0, -5, 1000000000, '12a', 'abc', '1e3', '-1200', '١٢٣',
                                 True, 12.0, [1200], {'v': 1}, '12 00'])
def test_anything_else_is_refused(raw):
    with pytest.raises(ValueError, match='whole number from 100 to 999999999'):
        tvmid.parse(raw)


def test_proxmox_says_whether_a_vmid_is_free_taken_or_outside_its_next_id_range():
    pve = Pve(taken={120})
    pve.used_before = {130}
    pve.enforce = (100, 5000)
    assert tvmid.ask(pve, 121) == ('free', '')
    assert tvmid.ask(pve, 120) == ('taken', 'guest ID 120 is already in use')
    assert tvmid.ask(pve, 130) == ('taken', 'guest ID 130 was used before')
    state, why = tvmid.ask(pve, 6000)
    assert state == 'range' and 'lower boundary' in why
    pve.down = True
    assert tvmid.ask(pve, 121)[0] == 'unknown'


def test_the_chosen_vmid_is_asked_again_and_used_when_still_free():
    pve = Pve(taken={100, 101})
    t = _task(vmid=1300)
    assert tvmid.allocate(pve, t) == (1300, None)
    assert pve.asked == [1300]
    assert not [u for u in pve.gets if u.endswith('/cluster/nextid')], 'asked for the next id as well'
    assert tvmid.holder(CID, 1300) == 'task:m1'
    t.status = 'completed'
    assert tvmid.holder(CID, 1300) is None


def test_a_chosen_vmid_taken_between_the_check_and_the_allocation_fails_and_no_other_is_picked():
    pve = Pve(taken={100})
    t = _task(vmid=1300)
    # the check of the request found it free; minutes later someone created a guest there
    pve.taken.add(1300)
    got, why = tvmid.allocate(pve, t)
    assert got is None
    assert 'VMID 1300 was taken on the target cluster after the migration was checked' in why
    assert 'guest ID 1300 is already in use' in why and 'Nothing was created' in why
    assert pve.asked == [1300] and not [u for u in pve.gets if u.endswith('/cluster/nextid')]
    assert tvmid.holder(CID, 1300) is None


def test_a_chosen_vmid_another_migration_here_holds_fails_the_allocation():
    pve = Pve()
    tvmid.claim(CID, 1300, 'task:other', lambda: True)
    got, why = tvmid.allocate(pve, _task(vmid=1300))
    assert got is None and 'went to another ESXi migration' in why
    assert pve.asked == []


def test_a_chosen_vmid_the_cluster_does_not_answer_for_fails_closed():
    pve = Pve()
    pve.down = True
    got, why = tvmid.allocate(pve, _task(vmid=1300))
    assert got is None and 'could not say whether VMID 1300 is still free' in why


def test_the_automatic_vmid_comes_from_inside_the_tenant_range():
    pve = Pve(taken={100, 2000, 2001})
    tvmid.claim(CID, 2002, 'task:other', lambda: True)     # given to a migration not there yet
    pve.listed = {100, 2000}                                 # the guest list is behind on 2001
    got, why = tvmid.allocate(pve, _task(start=2000, end=2999, strict=True))
    assert (got, why) == (2003, None)
    assert pve.asked == [2001, 2003]
    assert tvmid.holder(CID, 2003) == 'task:m1'
    assert tvmid.holder(CID, 2001) is None, 'a refused candidate stayed held'


def test_a_full_tenant_range_fails_a_confined_caller_and_falls_back_for_an_admin():
    pve = Pve(taken={100, 2000, 2001})
    got, why = tvmid.allocate(pve, _task(start=2000, end=2001, strict=True))
    assert got is None and 'No free VMID is left in the tenant range 2000-2001' in why
    got, why = tvmid.allocate(pve, _task('m2', start=2000, end=2001, strict=False))
    assert (got, why) == (101, None)


def test_a_next_id_range_that_refuses_the_tenant_range_says_so():
    pve = Pve()
    pve.enforce = (100, 1000)
    got, why = tvmid.allocate(pve, _task(start=2000, end=2999, strict=True))
    assert got is None and 'VMID 2000' in why and 'lower boundary' in why
    assert pve.asked == [2000]


def test_unreadable_guests_pick_no_vmid_in_a_range():
    pve = Pve()
    pve.listed = 'fail'
    got, why = tvmid.allocate(pve, _task(start=2000, end=2999, strict=True))
    assert got is None and 'could not be read' in why
    assert pve.asked == []


def test_without_a_range_the_cluster_next_id_and_the_next_one_up_when_held():
    pve = Pve(taken={100})
    assert tvmid.allocate(pve, _task('m1')) == (101, None)
    # the first job has 101 but no guest there yet, so Proxmox VE answers 101 again
    assert tvmid.allocate(pve, _task('m2')) == (102, None)
    assert pve.asked == [102]
    assert {tvmid.holder(CID, 101), tvmid.holder(CID, 102)} == {'task:m1', 'task:m2'}


def test_two_migrations_in_one_range_never_get_the_same_vmid():
    pve = Pve(taken={2000})
    got = {tvmid.allocate(pve, _task(f'm{i}', start=2000, end=2999, strict=True))[0] for i in range(5)}
    assert got == {2001, 2002, 2003, 2004, 2005}


def test_the_automatic_picks_of_many_guests_share_one_walk_of_the_cluster():
    # a bulk run of 200 guests in a tenant range must not walk /cluster/resources 200 times
    pve = Pve(taken={2000})
    pve.cache = True
    got = [tvmid.allocate(pve, _task(f'm{i}', start=2000, end=2999, strict=True))[0] for i in range(5)]
    assert got == [2001, 2002, 2003, 2004, 2005]
    assert pve.walks == 1
    assert set(pve.resource_reads) == {tvmid.RESOURCES_MAX_AGE} and tvmid.RESOURCES_MAX_AGE > 0


def test_a_task_no_route_bound_takes_the_cluster_next_id_as_before():
    pve = Pve(taken={100})
    tvmid.claim(CID, 101, 'task:other', lambda: True)
    assert tvmid.allocate(pve, _task(bind=False)) == (101, None)
    assert pve.asked == [] and tvmid.holder(CID, 101) == 'task:other'


def test_a_hold_for_a_migration_never_registered_lapses(monkeypatch):
    alive = tvmid.until_over(lambda mid: None, 'm9')
    tvmid.claim(CID, 1400, 'task:m9', alive)
    assert tvmid.holder(CID, 1400) == 'task:m9'
    monkeypatch.setattr(tvmid, 'UNSTARTED_SECONDS', 0)
    assert tvmid.holder(CID, 1400) is None


# --------------------------------------------------------------------------- a whole migration

def test_the_migration_creates_its_guest_under_the_chosen_vmid(monkeypatch):
    from test_esxi_mapping_verify import Run
    r = Run(monkeypatch, mode='offline', config={'verify': 'off'})
    tvmid.bind(r.task, 1300, 0, 0, False, 'task:t1')
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert r.task.proxmox_vmid == 1300
    create = [p for p in r.posts() if p[1] == '/nodes/pve1/qemu']
    assert len(create) == 1 and ('vmid', 1300) in create[0][2]
    assert any('/cluster/nextid?vmid=1300' in u for u in r.pve.gets)


def test_a_chosen_vmid_taken_by_then_fails_the_migration_before_the_vm_shell(monkeypatch):
    from test_esxi_mapping_verify import Run
    r = Run(monkeypatch, mode='offline')
    plain = r.pve._api_get

    def _get(url, **kw):
        if url.endswith('/cluster/nextid?vmid=1300'):
            r.pve.gets.append(url)
            return _Resp(None, 400, {'vmid': 'guest ID 1300 is already in use\n'})
        return plain(url, **kw)
    monkeypatch.setattr(r.pve, '_api_get', _get)
    tvmid.bind(r.task, 1300, 0, 0, False, 'task:t1')
    r.go()
    assert r.task.status == 'failed'
    assert 'VMID 1300 was taken on the target cluster after the migration was checked' in r.task.error
    assert r.task.proxmox_vmid is None
    assert not [p for p in r.posts() if p[1] == '/nodes/pve1/qemu'], 'a VM shell was created anyway'
    assert not [u for u in r.pve.gets if u.endswith('/cluster/nextid')], 'another VMID was asked for'


# --------------------------------------------------------------------------- the routes

def _tenant(seed, tid='acme', start=2000, end=2999):
    from pegaprox.utils import rbac
    seed.db.save_tenant(tid, {'id': tid, 'name': tid.title(), 'clusters': [CID],
                              'vmid_range_start': start, 'vmid_range_end': end})
    rbac.invalidate_tenants_cache()


@pytest.fixture
def env(api, seed, monkeypatch):
    import pegaprox.globals as g
    import pegaprox.api.vmware as vmwareapi
    from pegaprox.utils import rbac
    monkeypatch.setattr(ebulk, 'POLL_SECONDS', 0.02)
    ebulk.reset_for_tests()
    rbac.invalidate_vm_acls_cache()
    esxi = Esxi({'vm-1': _vm('web01'), 'vm-2': _vm('db01'), 'vm-3': _vm('app01'), 'vm-4': _vm('mail01')})
    pve = Pve(taken={100, 101, 1200, 2000})
    api.set_manager(CID, pve)
    g.vmware_managers['vw1'] = esxi
    runner = Runner()
    monkeypatch.setattr(vmwareapi, '_run_v2p_migration', runner)
    monkeypatch.setattr(vmwareapi, '_vmware_migrations', {})
    admin = api.as_user(seed.user('root', role='admin'))

    def tenant_user(name='bob', tid='acme'):
        u = seed.user(name, role='user', tenant_id=tid)
        for vm in ('vm-1', 'vm-2', 'vm-3'):
            seed.vm_acl('vmware:vw1', vm, [name], inherit_role=False, permissions=['vmware.vm.migrate'])
        rbac.invalidate_vm_acls_cache()
        return api.as_user(u)

    def migrate(client=None, vm='vm-1', **kw):
        body = {'target_cluster': CID, 'target_node': 'pve1', 'target_storage': 'local-lvm',
                'transfer_mode': 'offline', 'esxi_password': PW}
        body.update(kw)
        return (client or admin).post(f'/api/vmware/vw1/vms/{vm}/migrate',
                                      json={k: v for k, v in body.items() if v is not None})

    def bulk(client=None, **kw):
        body = {'vms': ['vm-1', 'vm-2'], 'target_cluster': CID, 'target_node': 'pve1',
                'target_storage': 'local-lvm', 'transfer_mode': 'offline', 'esxi_password': PW}
        body.update(kw)
        return (client or admin).post('/api/vmware/vw1/bulk-migrate',
                                      json={k: v for k, v in body.items() if v is not None})

    ns = types.SimpleNamespace(api=api, seed=seed, esxi=esxi, pve=pve, runner=runner, admin=admin,
                               migrate=migrate, bulk=bulk, tenant_user=tenant_user, rbac=rbac)
    yield ns
    for run in ebulk.runs():
        ebulk.cancel(run, 'teardown')
    deadline = time.time() + 5
    while time.time() < deadline and any(r.state == 'running' for r in ebulk.runs()):
        runner.end_all()
        time.sleep(0.02)
    ebulk.reset_for_tests()
    rbac.invalidate_vm_acls_cache()
    g.vmware_managers.pop('vw1', None)


def test_the_single_route_hands_a_free_chosen_vmid_to_the_task(env):
    r = env.migrate(target_vmid='1300')
    assert r.status_code == 202, r.get_data(as_text=True)
    _wait(lambda: env.runner.names() == ['web01'])
    t = env.runner.task('web01')
    assert t._vmid_pick == {'vmid': 1300, 'range': None, 'strict': False, 'owner': f'task:{t.id}'}
    assert env.pve.asked == [1300]
    # the migration holds it while it runs: no other one gets it
    assert tvmid.holder(CID, 1300) == f'task:{t.id}'
    r = env.migrate(vm='vm-2', target_vmid=1300)
    assert r.status_code == 409 and 'promised to another ESXi migration' in r.get_json()['error']
    env.runner.end('web01')
    assert tvmid.holder(CID, 1300) is None


def test_the_dry_run_shows_the_chosen_vmid_and_refuses_a_taken_one(env):
    r = env.migrate(dry_run=True, esxi_password=None, target_vmid=1300)
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert d['ok'] is True and d['target_vmid'] == 1300 and d['vmid_range'] is None
    r = env.migrate(dry_run=True, esxi_password=None, target_vmid=1200)
    d = r.get_json()
    assert r.status_code == 200 and d['ok'] is False
    assert any('VMID 1200 cannot be used on the target cluster: guest ID 1200 is already in use' in e
               for e in d['errors']), d['errors']
    # without one: the next free id, nothing asked
    d = env.migrate(dry_run=True, esxi_password=None).get_json()
    assert d['ok'] is True and d['target_vmid'] is None
    assert env.pve.asked == [1300, 1200]
    time.sleep(0.05)
    assert env.runner.tasks == []


def test_a_taken_vmid_refuses_the_start(env):
    r = env.migrate(target_vmid=1200)
    assert r.status_code == 409, r.get_data(as_text=True)
    assert 'guest ID 1200 is already in use' in r.get_json()['error']
    env.pve.enforce = (100, 1000)
    r = env.migrate(target_vmid=1300)
    assert r.status_code == 409 and 'lower boundary' in r.get_json()['error']
    env.pve.enforce, env.pve.down = None, True
    r = env.migrate(target_vmid=1300)
    assert r.status_code == 502 and 'could not say whether VMID 1300 is free' in r.get_json()['error']
    time.sleep(0.05)
    assert env.runner.tasks == []


@pytest.mark.parametrize('bad', ['12a', 50, 1000000000, True, [1300], '1300.5'])
def test_a_malformed_vmid_is_refused_at_the_door(env, bad):
    r = env.migrate(target_vmid=bad)
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'target_vmid is a whole number from 100 to 999999999' in r.get_json()['error']
    assert env.pve.asked == []


def test_a_vmid_outside_the_tenant_range_is_refused_and_never_asked_of_proxmox(env):
    _tenant(env.seed)
    bob = env.tenant_user()
    r = env.migrate(bob, target_vmid=1300)
    assert r.status_code == 403, r.get_data(as_text=True)
    assert "VMID 1300 is outside this tenant's range (2000-2999)" in r.get_json()['error']
    d = env.migrate(bob, dry_run=True, esxi_password=None, target_vmid=1300).get_json()
    assert d['ok'] is False and any('outside this tenant' in e for e in d['errors'])
    assert env.pve.asked == []
    r = env.migrate(bob, target_vmid=2500)
    assert r.status_code == 202, r.get_data(as_text=True)
    _wait(lambda: env.runner.names() == ['web01'])
    assert env.runner.task('web01')._vmid_pick['vmid'] == 2500


def test_an_admin_may_name_a_vmid_outside_their_tenant_range(env):
    _tenant(env.seed)
    boss = env.api.as_user(env.seed.user('boss', role='admin', tenant_id='acme'))
    r = env.migrate(boss, target_vmid=1300)
    assert r.status_code == 202, r.get_data(as_text=True)
    _wait(lambda: env.runner.names() == ['web01'])
    # without one an admin's pick still starts in the range, but may leave it once it is full
    assert env.runner.task('web01')._vmid_pick['range'] == (2000, 2999)
    assert env.runner.task('web01')._vmid_pick['strict'] is False


def test_the_automatic_path_carries_the_callers_tenant_range_to_the_task(env):
    _tenant(env.seed)
    bob = env.tenant_user()
    d = env.migrate(bob, dry_run=True, esxi_password=None).get_json()
    assert d['ok'] is True and d['target_vmid'] is None and d['vmid_range'] == [2000, 2999]
    r = env.migrate(bob)
    assert r.status_code == 202, r.get_data(as_text=True)
    _wait(lambda: env.runner.names() == ['web01'])
    t = env.runner.task('web01')
    assert t._vmid_pick == {'vmid': None, 'range': (2000, 2999), 'strict': True, 'owner': f'task:{t.id}'}
    # what the job does with it, without a request around it
    assert tvmid.allocate(env.pve, t) == (2001, None)


def test_an_unreadable_tenant_table_starts_nothing_for_a_tenant_user(env, monkeypatch):
    _tenant(env.seed)
    bob = env.tenant_user()

    def _unread(tid):
        raise env.rbac.TenantRangeUnknown(tid)
    monkeypatch.setattr(env.rbac, 'tenant_vmid_range', _unread)
    for kw in ({}, {'target_vmid': 2500}):
        r = env.migrate(bob, **kw)
        assert r.status_code == 403, r.get_data(as_text=True)
        assert 'Cannot verify the tenant VMID range' in r.get_json()['error']
    time.sleep(0.05)
    assert env.runner.tasks == []
    # an admin is held to no range: the cluster's next id
    assert env.migrate().status_code == 202


def test_a_start_that_breaks_after_the_vmid_was_claimed_lets_go_of_it(env, monkeypatch):
    import pegaprox.api.vmware as vmwareapi

    def _broken(*a, **kw):
        raise RuntimeError('the task could not be built')
    monkeypatch.setattr(vmwareapi, 'V2PMigrationTask', _broken)
    with pytest.raises(RuntimeError):
        env.migrate(target_vmid=1300)
    # free at once, not only after the grace of a migration that never got registered
    assert tvmid.holder(CID, 1300) is None
    monkeypatch.undo()
    assert env.migrate(target_vmid=1300).status_code == 202


def test_the_audit_line_names_the_chosen_vmid(env):
    assert env.migrate(target_vmid=1300).status_code == 202
    rows = env.seed.db.conn.execute(
        "SELECT details FROM audit_log WHERE action = 'vmware.migration.started'").fetchall()
    assert any('as VMID 1300' in r[0] for r in rows), rows


# --------------------------------------------------------------------------- bulk

def test_a_bulk_run_refuses_one_vmid_for_two_guests(env):
    r = env.bulk(dry_run=True, esxi_password=None,
                 vms=[{'vm_id': 'vm-1', 'target_vmid': 1300}, {'vm_id': 'vm-2', 'target_vmid': '1300'}])
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()['error'] == 'vms gives VMID 1300 to vm-1 and vm-2'
    r = env.bulk(dry_run=True, esxi_password=None, vms=[{'vm_id': 'vm-1', 'target_vmid': 'x'}])
    assert r.status_code == 400 and 'target_vmid is a whole number' in r.get_json()['error']
    # one VMID for every guest of a run makes no sense
    r = env.bulk(dry_run=True, esxi_password=None, target_vmid=1300)
    assert r.status_code == 400 and "'target_vmid' is not a setting" in r.get_json()['error']
    assert env.pve.asked == []


def test_a_bulk_dry_run_asks_for_each_chosen_vmid_and_fails_only_that_guest(env):
    r = env.bulk(dry_run=True, esxi_password=None,
                 vms=[{'vm_id': 'vm-1', 'target_vmid': 1300}, {'vm_id': 'vm-2', 'target_vmid': 1200}, 'vm-3'])
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    items = {it['vm_id']: it for it in d['items']}
    assert items['vm-1']['ok'] is True and items['vm-1']['target_vmid'] == 1300
    assert items['vm-2']['ok'] is False and items['vm-2']['target_vmid'] == 1200
    assert any('guest ID 1200 is already in use' in e for e in items['vm-2']['errors'])
    assert items['vm-3']['ok'] is True and items['vm-3']['target_vmid'] is None
    assert d['ok'] is False and d['vmid_range'] is None
    assert sorted(env.pve.asked) == [1200, 1300]
    # without the dry run that refuses the whole request
    r = env.bulk(vms=[{'vm_id': 'vm-1', 'target_vmid': 1300}, {'vm_id': 'vm-2', 'target_vmid': 1200}])
    assert r.status_code == 400 and '1 of 2 guests' in r.get_json()['error']
    assert ebulk.runs() == [] and tvmid.holder(CID, 1300) is None


def test_a_bulk_run_hands_each_guest_its_vmid_and_holds_them_till_then(env):
    r = env.bulk(width=1, vms=[{'vm_id': 'vm-1', 'target_vmid': 1300}, {'vm_id': 'vm-2', 'target_vmid': 1301}, 'vm-3'])
    assert r.status_code == 202, r.get_data(as_text=True)
    run_id = r.get_json()['run']['id']
    run = ebulk.get(run_id)
    _wait(lambda: env.runner.names() == ['web01'])
    web = env.runner.task('web01')
    assert web._vmid_pick['vmid'] == 1300 and tvmid.holder(CID, 1300) == f'task:{web.id}'
    # db01 waits its turn: the run holds its VMID, the single route cannot have it
    assert tvmid.holder(CID, 1301) == run.holder
    r = env.migrate(vm='vm-4', target_vmid=1301)
    assert r.status_code == 409 and 'promised to another ESXi migration' in r.get_json()['error']
    env.runner.end('web01')
    _wait(lambda: env.runner.names() == ['web01', 'db01'])
    db = env.runner.task('db01')
    assert db._vmid_pick['vmid'] == 1301 and tvmid.holder(CID, 1301) == f'task:{db.id}'
    env.runner.end('db01')
    _wait(lambda: env.runner.names() == ['web01', 'db01', 'app01'])
    assert env.runner.task('app01')._vmid_pick['vmid'] is None
    env.runner.end('app01')
    _wait(lambda: run.state != 'running', what='the end of the run')
    assert tvmid.claimed(CID) == set()


def test_a_bulk_run_refused_at_the_register_lets_go_of_its_vmids_at_once(env, monkeypatch):
    real = ebulk.register

    def _full(run):
        raise ebulk.TooMany('enough bulk migrations are running')
    monkeypatch.setattr(ebulk, 'register', _full)
    vms = [{'vm_id': 'vm-1', 'target_vmid': 1300}, {'vm_id': 'vm-2', 'target_vmid': 1301}]
    r = env.bulk(vms=vms)
    assert r.status_code == 409, r.get_data(as_text=True)
    assert tvmid.claimed(CID) == set()
    # asked again right away, its own VMIDs are not promised to another migration
    monkeypatch.setattr(ebulk, 'register', real)
    r = env.bulk(vms=vms)
    assert r.status_code == 202, r.get_data(as_text=True)


def test_a_bulk_guest_that_breaks_after_its_vmid_was_handed_over_lets_go_of_it(env, monkeypatch):
    import pegaprox.api.vmware as vmwareapi

    def _broken(*a, **kw):
        raise RuntimeError('the task could not be built')
    monkeypatch.setattr(vmwareapi, 'V2PMigrationTask', _broken)
    r = env.bulk(width=1, vms=[{'vm_id': 'vm-1', 'target_vmid': 1300}])
    assert r.status_code == 202, r.get_data(as_text=True)
    run = ebulk.get(r.get_json()['run']['id'])
    _wait(lambda: run.state != 'running', what='the end of the run')
    assert run.items_copy()[0]['state'] == 'failed'
    assert tvmid.holder(CID, 1300) is None


def test_a_guests_vmid_taken_before_its_turn_fails_that_guest_only(env):
    r = env.bulk(width=1, vms=[{'vm_id': 'vm-1', 'target_vmid': 1300}, {'vm_id': 'vm-2', 'target_vmid': 1301}, 'vm-3'])
    assert r.status_code == 202, r.get_data(as_text=True)
    run_id = r.get_json()['run']['id']
    _wait(lambda: env.runner.names() == ['web01'])
    # someone creates a guest under 1301 straight on Proxmox VE while web01 migrates
    env.pve.taken.add(1301)
    env.runner.end('web01')
    _wait(lambda: env.runner.names() == ['web01', 'app01'])
    items = {it['vm_id']: it for it in ebulk.get(run_id).items_copy()}
    assert items['vm-2']['state'] == 'failed'
    assert 'VMID 1301 cannot be used on the target cluster: guest ID 1301 is already in use' in items['vm-2']['note']


def test_a_bulk_vmid_outside_the_tenant_range_fails_that_guest(env):
    _tenant(env.seed)
    bob = env.tenant_user()
    r = env.bulk(bob, dry_run=True, esxi_password=None,
                 vms=[{'vm_id': 'vm-1', 'target_vmid': 1300}, {'vm_id': 'vm-2', 'target_vmid': 2100}])
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    items = {it['vm_id']: it for it in d['items']}
    assert items['vm-1']['ok'] is False and "outside this tenant's range (2000-2999)" in items['vm-1']['errors'][0]
    assert items['vm-2']['ok'] is True
    assert d['vmid_range'] == [2000, 2999]
    assert env.pve.asked == [2100]


def test_a_bulk_check_never_asks_about_a_guest_the_caller_may_not_migrate(env):
    bob = env.seed.user('bob', role='user')
    env.seed.vm_acl('vmware:vw1', 'vm-1', ['bob'], inherit_role=False, permissions=['vmware.vm.migrate'])
    env.rbac.invalidate_vm_acls_cache()
    r = env.bulk(env.api.as_user(bob), dry_run=True, esxi_password=None,
                 vms=[{'vm_id': 'vm-1', 'target_vmid': 1300}, {'vm_id': 'vm-2', 'target_vmid': 1200}])
    assert r.status_code == 200, r.get_data(as_text=True)
    assert env.pve.asked == [1300]
