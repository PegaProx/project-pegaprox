"""Attacks on the migration preflight and the runs that consult it.

Each test asserts a property the preflight promises and fails on ac231cd for the reason
its docstring gives. The clusters are the fakes of tests/test_migration_preflight.py.
"""
import re
import time

import pytest

from test_ha_api import _audit
from test_migration_preflight import (_fresh, _Pve, _guest, _node, _store, CFG, _two, _xrun,  # noqa: F401 (autouse)
                                      no_cleanup_thread, _rows, _codes, CID, TGT, BM, PF)

import pegaprox.core.preflight as pf
import pegaprox.utils.rbac as rbac
from pegaprox.core import bulk_migrate as bulk


def _together(monkeypatch, vms, enforce=True, kind='together', name='web+db'):
    import pegaprox.api.history as history
    rules = [{'cluster_id': CID, 'enabled': True, 'enforce': enforce, 'type': kind, 'name': name,
              'vms': list(vms)}]
    monkeypatch.setattr(history, 'load_affinity_rules', lambda: {'rules': [dict(r) for r in rules]})


# --- 1. a target in another shape switches the preflight off ------------------------------------

@pytest.mark.parametrize('who', ['root', 'portal'])
def test_a_list_target_does_not_switch_off_the_bulk_preflight(api, seed, monkeypatch, who):
    """bulk-migrate without a mode takes `target` unchecked. ['pve2'] makes preflight.intra
    raise (a list is no dict key), _bulk_preflight answers {} ("go as before it existed")
    and every guest goes to Proxmox; requests form-encodes ['pve2'] as target=pve2. An
    enforced affinity rule (that only PegaProx knows) is passed without override,
    confirmation or audit line, also by a VM-ACL user the single migrate refuses with 409."""
    _together(monkeypatch, [100, 555], kind='separate', name='apart')
    seed.tenant('acme', clusters=[CID])
    seed.vm_acl(CID, 100, users=['portal'])
    # MK Nov 2026 - 101 on pve2 is theirs: a confined caller moves guests onto a node of theirs
    seed.vm_acl(CID, 101, users=['portal'])
    m = _Pve(api, guests=[_guest(100), _guest(555, node='pve2'), _guest(101, node='pve2')],
             configs={100: CFG, 555: CFG, 101: CFG})
    u = seed.user('root', role='admin') if who == 'root' else seed.user('portal', role='user', tenant_id='acme')
    c = api.as_user(u)
    body = {'vms': [{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}], 'target': 'pve2'}
    # counterproof: as a string the preflight holds it back
    r = c.post(BM, json=body)
    assert r.status_code == 200 and r.get_json()['results'][0]['success'] is False
    assert 'apart' in r.get_json()['results'][0]['error'] and m.started == []
    r = c.post(BM, json=dict(body, target=['pve2']))
    assert m.started == [], (f'the guest the preflight blocks went to Proxmox: {m.started}, '
                             f'override audit {_audit("vm.migrate_block_overridden")}')


def test_a_list_target_node_does_not_switch_off_the_cross_cluster_preflight(api, seed, no_cleanup_thread):
    """cross-cluster-migrate checks target_node only for being truthy. ['far1'] makes
    preflight.cross raise, _cross_preflight_for answers (None, None) and the migration
    starts; remote_migrate_vm never sees target_node at all. A hard block (the bridge is
    not on the target node) is passed, and so would any overridable one without
    confirm_override and without its audit line."""
    src, dst = _two(api)
    c = api.as_user(seed.user('root', role='admin'))
    # counterproof: the same body with the node as a name is refused
    r = _xrun(c, target_bridge='vmbr9')
    assert r.status_code == 409 and 'vmbr9' in r.get_json()['error']
    assert dst.tokens == [] and src.started == []
    r = _xrun(c, target_bridge='vmbr9', target_node=['far1'])
    assert src.started == [] and dst.tokens == [], (
        f'blocked guest migrated ({r.status_code}): tokens {dst.tokens}, started {src.started}')


# --- 2. dry_run: 1 is "true or false" and starts the migrations -------------------------------------

@pytest.mark.parametrize('extra', [{}, {'mode': 'sequential'}], ids=['no-mode', 'sequential'])
def test_a_dry_run_given_as_one_starts_nothing(api, seed, extra):
    """`data.get('dry_run', False) not in (True, False)` lets 1 through (1 == True), and
    `data.get('dry_run') is True` then reads it as false: the call that asked for a dry run
    migrates the guests (without a mode) or registers and launches a run (with one)."""
    m = _Pve(api, guests=[_guest(100)], configs={100: CFG})
    c = api.as_user(seed.user('root', role='admin'))
    body = dict({'vms': [{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}], 'target': 'pve2', 'dry_run': 1}, **extra)
    r = c.post(BM, json=body)
    time.sleep(0.2)
    assert m.started == [] and bulk.runs() == [], f'dry_run: 1 started work ({r.status_code}): {m.started}'
    assert _audit('vm.bulk_migrated') == []
    assert r.status_code == 400 or r.get_json().get('dry_run') is True, r.get_data(as_text=True)


# --- 3. the quota hold of the gate is counted again by the preflight ------------------------------

def test_a_cross_cluster_copy_that_fits_the_quota_is_not_refused_by_its_own_hold(api, seed, no_cleanup_thread,
                                                                                    monkeypatch):
    """The tenant has 2 guests and room for 3. tenant_quota_gate lets the copy through and
    holds one guest for it; preflight.cross then asks check_tenant_quota for one more on top
    of that hold (3 + 1 > 3) and blocks it as 'quota', which cannot be overridden. The dry
    run, which takes no hold, says it fits: the run refuses what its own dry run promised."""
    seed.db.save_tenant('acme', {'id': 'acme', 'name': 'Acme', 'clusters': [CID, TGT],
                                 'quota_enforcement': 'block', 'quota_max_vms': 3})
    rbac.invalidate_tenants_cache()
    src, dst = _two(api)
    op = api.as_user(seed.user('op', role='user', tenant_id='acme'))
    r = _xrun(op, dry_run=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert 'quota' not in _codes(_rows(r.get_json()['preflight'])[100])
    # counterproof of the cause: with the gate keeping no hold the copy is counted once and starts
    with monkeypatch.context() as mp:
        mp.setattr(rbac, 'quota_hold', lambda *a, **k: None)
        assert _xrun(op).status_code == 200 and len(dst.tokens) == 1
    dst.tokens.clear()
    src.started.clear()
    r = _xrun(op)
    assert r.status_code == 200 and len(dst.tokens) == 1, (
        f'the copy that fits was refused ({r.status_code}): {r.get_data(as_text=True)[:300]}')


# --- 4. a caller confined to one guest overrides an enforced rule of the admin -------------------

def test_a_guest_scoped_caller_does_not_override_an_enforced_affinity_rule(api, seed, monkeypatch):
    """An enforced affinity rule is made by an admin (history.py: roles=[admin]). The single
    migrate and the node's migrate-all refuse a guest it holds, with no way round. The bulk
    route lets anyone with vm.migrate on the guest override it with confirm_override: a
    VM-ACL user who may not touch the rule moves the guest where the rule forbids."""
    _together(monkeypatch, [100, 555], kind='separate', name='apart')
    seed.tenant('acme', clusters=[CID])
    seed.vm_acl(CID, 100, users=['portal'])
    # MK Nov 2026 - 101 on pve2 is theirs: the node may take their guest, the rule may not
    seed.vm_acl(CID, 101, users=['portal'])
    m = _Pve(api, guests=[_guest(100), _guest(555, node='pve2'), _guest(101, node='pve2')],
             configs={100: CFG, 555: CFG, 101: CFG})
    portal = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    r = portal.post(f'/api/clusters/{CID}/vms/pve1/qemu/100/migrate', json={'target': 'pve2'})
    assert r.status_code == 409 and r.get_json().get('affinity_violation') is True
    r = portal.post(BM, json={'vms': [100], 'target': 'pve2', 'mode': 'all', 'override': [100],
                              'confirm_override': True})
    time.sleep(0.3)
    assert m.started == [], (f'the confined caller broke the admin rule ({r.status_code}): {m.started}; '
                             f'audit {_audit("vm.migrate_block_overridden")}')


# --- 5. an overridden guest is placed as if it stayed ----------------------------------------------

def test_an_overridden_guest_counts_for_the_affinity_of_the_set(api, monkeypatch):
    """web (100) and db (101) are held together by an enforced rule; both go to pve2, web
    does not fit the memory there and the caller overrides that. `planned` keeps every
    blocked guest on its node, overridden or not, so web's own verdict sees db arriving and
    has no affinity block, db's says web stays. The run moves web alone and splits the pair:
    the enforced rule is broken with only a memory override confirmed and audited."""
    _together(monkeypatch, [100, 101])
    m = _Pve(api, guests=[_guest(100, mem_gb=200), _guest(101)], configs={100: CFG, 101: CFG})
    res = pf.intra(CID, m, [100, 101], 'pve2', override={100})
    rows = _rows(res)
    moving = {v for v, r in rows.items() if pf.moving(r)}
    if moving == {100}:
        assert 'affinity' in _codes(rows[100], 'blocked'), (
            f"web moves without db, yet its verdict names no affinity rule: {rows[100]['reasons']}")


def test_an_overridden_guest_counts_for_the_memory_of_the_guests_after_it(api):
    """pve2 has 56 GB free. 100 needs 60 GB (blocked, overridden), 101 needs 30 GB. _Sim.take
    returns before counting a guest that does not fit, so 101 is judged on a node without
    100 and comes out ready, though with 100 overridden both land there: 98 GB on 64."""
    m = _Pve(api, guests=[_guest(100, mem_gb=60), _guest(101, mem_gb=30)], configs={100: CFG, 101: CFG})
    rows = _rows(pf.intra(CID, m, [100, 101], 'pve2', override={100}))
    assert rows[100]['overridden'] is True
    assert rows[101]['verdict'] == 'blocked' and 'memory_short' in _codes(rows[101], 'blocked'), (
        f"101 judged as if the overridden 100 stayed: {rows[101]['verdict']} {rows[101]['reasons']}")


# --- 6. the call without a mode moves what another run moves ----------------------------------------

def test_the_call_without_a_mode_skips_a_guest_another_run_moves(api, seed, monkeypatch):
    """The dry run of the call without a mode passes busy= and answers 'Skip 101: Another
    bulk migration moves it already' (a block nothing overrides). The call itself hands
    _bulk_preflight no busy set and sends 101 to Proxmox, while the run still has it waiting
    and will move it again, from wherever the call put it."""
    monkeypatch.setattr(bulk, 'POLL_SECONDS', 0.02)
    m = _Pve(api, guests=[_guest(100), _guest(101)], configs={100: CFG, 101: CFG})
    c = api.as_user(seed.user('root', role='admin'))
    r = c.post(BM, json={'vms': [100, 101], 'target': 'pve3', 'mode': 'sequential'})
    assert r.status_code == 202, r.get_data(as_text=True)
    run_id = r.get_json()['run']['id']
    deadline = time.time() + 5
    while time.time() < deadline and not m.started:
        time.sleep(0.02)
    assert [v for v, _t in m.started] == [100] and 101 in bulk.busy_vmids(CID)
    body = {'vms': [{'vmid': 101, 'node': 'pve1', 'type': 'qemu'}], 'target': 'pve2'}
    dry = c.post(BM, json=dict(body, dry_run=True)).get_json()
    assert _codes(_rows(dry['preflight'])[101], 'blocked') == ['busy']
    try:
        c.post(BM, json=body)
        assert (101, 'pve2') not in m.started, f'the dry run said skip, the call moved it: {m.started}'
    finally:
        run = bulk.get(run_id)
        bulk.cancel(run, 'teardown')
        m.get_task_status = lambda node, upid: {'status': 'stopped', 'exitstatus': 'OK', 'upid': upid}
        deadline = time.time() + 5
        while time.time() < deadline and run.state == 'running':
            time.sleep(0.02)


# --- 7. a node figure in a scoped answer ------------------------------------------------------------

def test_a_scoped_caller_reads_no_cpu_count_of_a_node(api, seed):
    """'a caller confined to some guests reads no figures of a node' (_Sim, _close drops the
    capacity). The vcpus block still says how many CPUs the target node has."""
    seed.tenant('acme', clusters=[CID])
    seed.vm_acl(CID, 100, users=['portal'])
    nodes = {'pve1': _node(cpus=64), 'pve2': _node(cpus=37), 'pve3': _node()}
    _Pve(api, guests=[_guest(100, cpus=48)], configs={100: CFG}, nodes=nodes)
    portal = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    r = portal.post(PF, json={'vms': [100], 'target': 'pve2'})
    assert r.status_code == 200 and r.get_json()['scoped'] is True
    text = next(x['text'] for x in _rows(r.get_json())[100]['reasons'] if x['code'] == 'vcpus')
    assert '37' not in text, f'the node figure reaches a scoped caller: {text!r}'


# --- the fixes, each on its own -------------------------------------------------------------------

@pytest.mark.parametrize('target', [['pve2'], {'pve2': 1}, 'pve2;x'])
def test_a_target_in_another_shape_is_a_400_before_any_preflight(api, seed, no_cleanup_thread, monkeypatch, target):
    """The run routes check the node as the preflight routes do; a 500 of a preflight that broke
    on it would be safe too, but the caller sent a bad body"""
    _two(api)
    called = []
    monkeypatch.setattr(pf, 'intra', lambda *a, **k: called.append('intra'))
    monkeypatch.setattr(pf, 'cross', lambda *a, **k: called.append('cross'))
    c = api.as_user(seed.user('root', role='admin'))
    r = c.post(BM, json={'vms': [{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}], 'target': target})
    assert r.status_code == 400 and r.get_json()['error'] == 'Target node is required', r.get_data(as_text=True)
    r = _xrun(c, target_node=target)
    assert r.status_code == 400 and 'Target node is required' in r.get_json()['error']
    assert called == []


@pytest.mark.parametrize('extra', [{}, {'mode': 'sequential'}], ids=['no-mode', 'sequential'])
def test_a_bulk_migration_whose_preflight_breaks_starts_nothing(api, seed, monkeypatch, extra):
    """Fails without the fix: the call without a mode sent every guest to Proxmox, a run
    started them all, as if no rule of PegaProx existed"""
    m = _Pve(api, guests=[_guest(100)], configs={100: CFG})

    def broken(*a, **k):
        raise RuntimeError('preflight bug')
    monkeypatch.setattr(pf, 'intra', broken)
    c = api.as_user(seed.user('root', role='admin'))
    r = c.post(BM, json=dict({'vms': [{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}], 'target': 'pve2'}, **extra))
    time.sleep(0.2)
    assert r.status_code == 500 and 'preflight failed' in r.get_json()['error'], r.get_data(as_text=True)
    assert m.started == [] and bulk.runs() == [] and _audit('vm.bulk_migrated') == []


def test_a_cross_cluster_migration_whose_preflight_breaks_starts_nothing(api, seed, no_cleanup_thread, monkeypatch):
    """Fails without the fix: (None, None) went on to mint the token and start the migration"""
    src, dst = _two(api)

    def broken(*a, **k):
        raise RuntimeError('preflight bug')
    monkeypatch.setattr(pf, 'cross', broken)
    r = _xrun(api.as_user(seed.user('root', role='admin')))
    assert r.status_code == 500 and 'preflight failed' in r.get_json()['error'], r.get_data(as_text=True)
    assert dst.tokens == [] and src.started == []


def test_a_target_vmid_in_another_shape_is_refused(api, seed, no_cleanup_thread):
    """[105] had the preflight look at VMID 100 (free) while Proxmox got target-vmid=105, taken"""
    src, dst = _two(api, tgt_guests=[_guest(105, node='far1')])
    c = api.as_user(seed.user('root', role='admin'))
    r = _xrun(c, target_vmid=[105])
    assert r.status_code == 400 and r.get_json()['error'] == 'target_vmid is one VMID', r.get_data(as_text=True)
    assert dst.tokens == [] and src.started == []
    # as a number or its digits the preflight sees it
    for value in (105, '105'):
        r = _xrun(c, target_vmid=value)
        assert r.status_code == 409 and 'VMID 105 is taken' in r.get_json()['error'], value
    assert _xrun(c, target_vmid=106).status_code == 200 and src.started[0][7] == 106


def test_an_enforced_affinity_rule_is_overridden_by_an_admin_only(api, seed, monkeypatch):
    """The caller that may change the rule may override it; a VM-ACL user and an operator of
    the tenant read the block as one that cannot be overridden"""
    _together(monkeypatch, [100, 555], kind='separate', name='apart')
    seed.tenant('acme', clusters=[CID])
    seed.vm_acl(CID, 100, users=['portal'])
    m = _Pve(api, guests=[_guest(100), _guest(555, node='pve2')], configs={100: CFG, 555: CFG})
    body = {'vms': [100], 'target': 'pve2'}
    for who in (seed.user('portal', role='user', tenant_id='acme'), seed.user('op', role='user', tenant_id='acme')):
        row = _rows(api.as_user(who).post(PF, json=body).get_json())[100]
        assert _codes(row, 'blocked') == ['affinity'] and row['overridable'] is False, who['username']
    root = api.as_user(seed.user('root', role='admin'))
    row = _rows(root.post(PF, json=body).get_json())[100]
    assert _codes(row, 'blocked') == ['affinity'] and row['overridable'] is True
    r = root.post(BM, json=dict(body, mode='all', override=[100], confirm_override=True))
    assert r.status_code == 202, r.get_data(as_text=True)
    deadline = time.time() + 5
    while time.time() < deadline and not m.started:
        time.sleep(0.02)
    assert m.started == [(100, 'pve2')]
    (entry,) = _audit('vm.migrate_block_overridden')
    assert entry['user'] == 'root' and "'apart'" in entry['details']


def test_a_guest_a_rule_holds_back_stays_for_the_others(api, monkeypatch):
    """web and db go together; db may not join 555 on pve2. One pass judged web on db
    arriving and let it go alone: the pair split although both rules are enforced."""
    import pegaprox.api.history as history
    rules = [{'cluster_id': CID, 'enabled': True, 'enforce': True, 'type': 'together', 'name': 'web+db',
              'vms': [100, 101]},
             {'cluster_id': CID, 'enabled': True, 'enforce': True, 'type': 'separate', 'name': 'db-apart',
              'vms': [101, 555]}]
    monkeypatch.setattr(history, 'load_affinity_rules', lambda: {'rules': [dict(r) for r in rules]})
    m = _Pve(api, guests=[_guest(100), _guest(101), _guest(555, node='pve2')], configs={v: CFG for v in (100, 101)})
    rows = _rows(pf.intra(CID, m, [100, 101], 'pve2'))
    assert not any(pf.moving(r) for r in rows.values()), {v: r['reasons'] for v, r in rows.items()}
    assert "'web+db'" in rows[100]['reasons'][-1]['text'] and "'db-apart'" in rows[101]['reasons'][-1]['text']
    # counterproof: to pve3 nothing holds db back, and both go
    rows = _rows(pf.intra(CID, m, [100, 101], 'pve3'))
    assert all(pf.moving(r) for r in rows.values())


def test_an_overridden_guest_is_where_it_goes_for_the_affinity_rules(api, monkeypatch):
    """web's disk does not fit pve2's local storage and the caller overrides that; db (on
    shared storage) fits. Both go, so the rule holds. Fails without the fix: web counted as
    staying, db was held back by the rule and web went alone."""
    _together(monkeypatch, [100, 101])
    stores = [_store(n, 'local-lvm', free_gb=40 if n == 'pve2' else 500) for n in ('pve1', 'pve2', 'pve3')] + [
        _store(n, 'ceph', shared=True, plugintype='rbd', content='images') for n in ('pve1', 'pve2', 'pve3')]
    configs = {100: {'scsi0': 'local-lvm:vm-100-disk-0,size=50G', 'net0': 'virtio=x,bridge=vmbr0'}, 101: CFG}
    m = _Pve(api, guests=[_guest(100, status='stopped'), _guest(101)], configs=configs, storages=stores)
    rows = _rows(pf.intra(CID, m, [100, 101], 'pve2', override={100}))
    assert rows[100]['overridden'] is True and _codes(rows[100], 'blocked') == ['storage_full']
    assert pf.moving(rows[101]) and 'affinity' not in _codes(rows[101]), rows[101]['reasons']
    # counterproof: not overridden, web stays and the rule holds db back
    rows = _rows(pf.intra(CID, m, [100, 101], 'pve2'))
    assert not pf.moving(rows[100]) and _codes(rows[101], 'blocked') == ['affinity']


def test_an_overridden_guest_counts_for_the_disk_space_of_the_guests_after_it(api):
    """local-lvm on pve2 has 40 GB free: 100 needs 50 (blocked, overridden), 101 needs 10.
    Fails without the fix: 101 was judged on the 40 GB 100 had not taken."""
    stores = [_store(n, 'local-lvm', free_gb=40 if n == 'pve2' else 500) for n in ('pve1', 'pve2', 'pve3')]
    configs = {100: {'scsi0': 'local-lvm:vm-100-disk-0,size=50G', 'net0': 'virtio=x,bridge=vmbr0'},
               101: {'scsi0': 'local-lvm:vm-101-disk-0,size=10G', 'net0': 'virtio=x,bridge=vmbr0'}}
    m = _Pve(api, guests=[_guest(100, status='stopped'), _guest(101, status='stopped')], configs=configs,
             storages=stores)
    rows = _rows(pf.intra(CID, m, [100, 101], 'pve2', override={100}))
    assert rows[100]['overridden'] is True
    assert _codes(rows[101], 'blocked') == ['storage_full'], rows[101]['reasons']
    # counterproof: not overridden, 100 stays and 101 fits
    rows = _rows(pf.intra(CID, m, [100, 101], 'pve2'))
    assert rows[100]['verdict'] == 'blocked' and rows[101]['verdict'] != 'blocked'


def test_a_scoped_caller_reads_no_cpu_model_of_a_node(api, seed):
    """cpu_vendor and cpu_model carried the vendors and models of both nodes"""
    seed.tenant('acme', clusters=[CID])
    seed.vm_acl(CID, 100, users=['portal'])
    nodes = {'pve1': _node(model='Intel(R) Xeon(R) Gold 6230'), 'pve2': _node(model='AMD EPYC 7543'),
             'pve3': _node(model='Intel(R) Xeon(R) Silver 4210')}
    _Pve(api, guests=[_guest(100)], configs={100: dict(CFG, cpu='host')}, nodes=nodes)
    portal = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    root = api.as_user(seed.user('root', role='admin'))
    for target, code in (('pve2', 'cpu_vendor'), ('pve3', 'cpu_model')):
        texts = {}
        for name, c in (('portal', portal), ('root', root)):
            row = _rows(c.post(PF, json={'vms': [100], 'target': target}).get_json())[100]
            texts[name] = next(x['text'] for x in row['reasons'] if x['code'] == code)
        assert not re.search(r'(?i)intel|amd|xeon|epyc', texts['portal']), texts['portal']
        assert re.search(r'(?i)intel|amd|xeon|epyc', texts['root']), texts['root']
