"""A migration to XCP-ng starts without a target_node.

The start route asks for target_node only when the target is Proxmox, since an XCP-ng
pool places the new VM itself and its runners never read the field. The task was still
built from data['target_node'], so an API client that left the field out got a 500
before the task was registered. Now the task carries an empty node, the way the UI sends
it, and the audit line reads the same.
"""
import types

import pytest

import pegaprox.api.xhm as xhm_api
import pegaprox.globals as ppglobals

XCP = 'xcp1'
SOURCES = {'pve_to_xcpng': ('pve1', 'proxmox', '_run_pve_to_xcpng'),
           'esxi_to_xcpng': ('esxi1', 'esxi', '_run_esxi_to_xcpng')}


@pytest.fixture
def started(api, monkeypatch):
    reg, ran = {}, []
    monkeypatch.setattr(ppglobals, '_xhm_migrations', reg)
    monkeypatch.setattr(xhm_api, '_xhm_migrations', reg)
    for _sid, _kind, runner in SOURCES.values():
        monkeypatch.setattr(xhm_api, runner, lambda task, _r=runner: ran.append((_r, task)))
    # run the runner in place, no thread
    monkeypatch.setattr(xhm_api.threading, 'Thread',
                        lambda target=None, args=(), **k: types.SimpleNamespace(start=lambda: target(*args)))
    audit = []
    monkeypatch.setattr(xhm_api, 'log_audit', lambda *a, **k: audit.append(a))
    api.set_manager(XCP, api.make_fake_manager(XCP, cluster_type='xcpng'))
    return types.SimpleNamespace(registry=reg, ran=ran, audit=audit)


@pytest.mark.parametrize('direction', sorted(SOURCES))
def test_the_start_takes_no_target_node(api, seed, started, monkeypatch, direction):
    sid, kind, runner = SOURCES[direction]
    api.set_manager(sid, api.make_fake_manager(sid, cluster_type=kind))
    if kind == 'esxi':
        monkeypatch.setitem(ppglobals.vmware_managers, sid, types.SimpleNamespace(linked_clusters=[], host='10.0.0.5'))
    admin = api.as_user(seed.user('root_admin', role='admin'))
    body = {'source_cluster': sid, 'source_node': 'pve1' if kind == 'proxmox' else '', 'source_vmid': '105',
            'target_cluster': XCP, 'target_storage': 'sr1'}
    r = admin.post('/api/xhm/migrate', json=body)
    assert r.status_code == 202, r.get_data(as_text=True)
    task = r.get_json()['task']
    assert task['direction'] == direction and task['target_node'] == ''
    assert list(started.registry) == [r.get_json()['migration_id']]
    assert [name for name, _t in started.ran] == [runner]
    (_user, action, details), = started.audit
    assert action == 'xhm.migration.started' and details.endswith(f'-> {XCP}/')


def test_a_proxmox_target_still_needs_one(api, seed, started):
    api.set_manager('pve2', api.make_fake_manager('pve2'))
    admin = api.as_user(seed.user('root_admin', role='admin'))
    r = admin.post('/api/xhm/migrate', json={'source_cluster': XCP, 'source_vmid': '105',
                                             'target_cluster': 'pve2', 'target_storage': 'local-lvm'})
    assert r.status_code == 400 and 'target_node' in r.get_json()['error']
    assert started.registry == {} and started.ran == []
