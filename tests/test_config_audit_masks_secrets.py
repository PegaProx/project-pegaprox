"""A config change names a secret key in its audit line and never writes the value.

PUT /api/clusters/<id>/vms/<node>/<type>/<vmid>/config writes the first five keys of the
body into the audit line as key=value. The line goes to the audit table, the text log,
every SIEM target, the timeline and its evidence export, and the per-cluster trail is
read with cluster.view. A cloud-init password (and a container root password) is now
written as cipassword=*** there; every other key keeps its value, and the cluster still
gets the password as sent.
"""
import json
import logging
import time
import types

import pytest

import pegaprox.utils.rbac as rbac

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/vms/pve1/qemu/100/config'
SECRET = 'Cl0ud-1nit, pass [word]'


@pytest.fixture
def env(api, seed):
    m = api.make_fake_manager(cluster_id=CID,
                              update_vm_config={'success': True, 'message': 'Config updated'},
                              get_vm_config={'success': True, 'config': {'raw': {}}},
                              get_tasks=[])
    m.is_connected = True
    m.id = CID
    m.cluster_type = 'proxmox'
    m.config = types.SimpleNamespace(name='lab')
    m._vm_resources_cache = (time.time(), [
        {'vmid': 100, 'type': 'qemu', 'node': 'pve1', 'name': 'web01', 'status': 'running'}])
    m._node_status_cache = (time.monotonic(), {})
    api.set_manager(CID, m)
    # the built-in user role holds vm.config and nothing of the admin side
    writer = api.as_user(seed.user('opsuser', role='user'))
    return types.SimpleNamespace(m=m, writer=writer)


def _put(client, body, url=URL):
    # sent as raw JSON so the keys keep the order a real client sends them in
    return client.put(url, data=json.dumps(body), content_type='application/json')


def _write(env, body=None, url=URL):
    body = body or {'ciuser': 'deploy', 'cipassword': SECRET}
    r = _put(env.writer, body, url)
    assert r.status_code == 200, r.get_data(as_text=True)
    return body


def _rows(entries):
    return [e for e in entries if e.get('action') == 'vm.config_changed']


def test_the_cluster_gets_the_password_and_the_audit_row_masks_it(env, api, seed):
    _write(env)
    # what went to PVE is the password as sent
    assert env.m.update_vm_config.call_args.args[3]['cipassword'] == SECRET
    admin = api.as_user(seed.user('root', role='admin'))
    rows = _rows(admin.get('/api/audit?limit=50').get_json())
    assert rows, 'no vm.config_changed row'
    assert rows[0]['details'] == 'QEMU 100 config updated: ciuser=deploy, cipassword=*** [lab]'


def test_a_viewer_of_the_cluster_reads_the_masked_line(env, api, seed):
    _write(env)
    viewer = api.as_user(seed.user('vera', role='viewer'))
    for url in (f'/api/clusters/{CID}/audit?limit=50', f'/api/clusters/{CID}/audit?vmid=100&limit=50'):
        r = viewer.get(url)
        assert r.status_code == 200, r.get_data(as_text=True)
        rows = _rows(r.get_json())
        assert rows, f'{url}: no row for the viewer'
        assert 'cipassword=***' in rows[0]['details']
        assert 'Cl0ud-1nit' not in r.get_data(as_text=True), url


def test_a_tenant_viewer_and_a_pool_confined_reader_get_it_masked(env, api, seed):
    """The viewer of the tenant that owns the cluster reads the whole trail; a reader
    confined to the pool that holds VM 100 reads the rows of that VM."""
    seed.tenant('acme', clusters=[CID])
    tina = api.as_user(seed.user('tina', role='viewer', tenant_id='acme'))
    pia_user = seed.user('pia', role='viewer', tenant_id='acme', permissions=['cluster.view'])
    seed.pool(CID, 'pool_1', 'pia', ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'100:qemu': 'pool_1'},
                                            'timestamp': time.time(), 'refreshing': False}
    _write(env)
    from pegaprox.api.helpers import caller_is_scoped
    assert caller_is_scoped(pia_user, CID), 'the pool reader must be a confined one'
    for client in (tina, api.as_user(pia_user)):
        r = client.get(f'/api/clusters/{CID}/audit?limit=50')
        assert r.status_code == 200, r.get_data(as_text=True)
        rows = _rows(r.get_json())
        assert rows, r.get_json()
        assert 'cipassword=***' in rows[0]['details']
        assert 'Cl0ud-1nit' not in r.get_data(as_text=True)


def test_the_timeline_and_its_evidence_export_carry_the_masked_line(env, api, seed):
    _write(env)
    viewer = api.as_user(seed.user('vera', role='viewer'))
    r = viewer.get(f'/api/timeline?cluster={CID}&kinds=audit')
    assert r.status_code == 200, r.get_data(as_text=True)
    text = r.get_data(as_text=True)
    assert 'config updated' in text, text[:300]
    assert 'Cl0ud-1nit' not in text

    r = viewer.get(f'/api/timeline/evidence?clusters={CID}&kinds=audit')
    assert r.status_code == 200, r.get_data(as_text=True)
    doc = json.loads(r.get_data(as_text=True))
    events = [e for e in doc['events'] if 'config updated' in (e.get('details') or '')]
    assert events, [e.get('kind') for e in doc['events']]
    assert 'cipassword=***' in events[0]['details']
    assert 'Cl0ud-1nit' not in r.get_data(as_text=True)


def test_siem_and_the_text_log_get_the_masked_line(env, monkeypatch, caplog):
    from pegaprox.api import siem
    sent = []
    monkeypatch.setattr(siem, 'enqueue', lambda evt: sent.append(evt))
    caplog.set_level(logging.INFO)
    _write(env)
    events = [e for e in sent if e.get('action') == 'vm.config_changed']
    assert events, 'no SIEM event for the change'
    assert 'cipassword=***' in events[0]['details'] and 'Cl0ud-1nit' not in events[0]['details']
    lines = [r.getMessage() for r in caplog.records if 'vm.config_changed' in r.getMessage()]
    assert lines, 'no Audit: line in the text log'
    assert 'cipassword=***' in lines[0] and 'Cl0ud-1nit' not in lines[0]


def test_a_container_root_password_is_masked_too(env, api, seed):
    _write(env, {'hostname': 'ct1', 'password': SECRET}, url=f'/api/clusters/{CID}/vms/pve1/lxc/200/config')
    admin = api.as_user(seed.user('root', role='admin'))
    rows = _rows(admin.get('/api/audit?limit=50').get_json())
    assert rows and rows[0]['details'] == 'LXC 200 config updated: hostname=ct1, password=*** [lab]'


def test_the_other_keys_keep_their_values(env, api, seed):
    """The line still says what changed, in the order sent, five keys at most."""
    _write(env, {'cores': 4, 'cipassword': SECRET, 'ciuser': 'deploy', 'memory': 2048,
                 'name': 'web01', 'onboot': 1})
    admin = api.as_user(seed.user('root', role='admin'))
    rows = _rows(admin.get('/api/audit?limit=50').get_json())
    assert rows and rows[0]['details'] == ('QEMU 100 config updated: cores=4, cipassword=***, '
                                           'ciuser=deploy, memory=2048, name=web01 [lab]')


@pytest.mark.parametrize('vm_type,key', [('qemu', 'cipassword'), ('lxc', 'password')])
def test_the_manager_log_line_leaves_the_password_out(caplog, vm_type, key):
    """PegaProxManager.update_vm_config logs the whole body before the PUT, all keys and
    whatever PVE then answers. PVE gets the password, the log line does not."""
    from unittest.mock import MagicMock
    from pegaprox.core.manager import PegaProxManager
    me = MagicMock()
    me.is_connected = True
    me.host, me.api_port = '10.0.0.1', 8006
    me.logger = logging.getLogger('test.config_audit.manager')
    me._api_put.return_value = MagicMock(status_code=200)
    caplog.set_level(logging.INFO, logger='test.config_audit.manager')
    body = {'cores': 4, 'memory': 2048, 'name': 'web01', 'onboot': 1, 'ciuser': 'deploy', key: SECRET}
    assert PegaProxManager.update_vm_config(me, 'pve1', 100, vm_type, dict(body))['success']
    assert me._api_put.call_args.kwargs['data'] == body
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith('Updating ')]
    assert lines, 'no Updating ... config line'
    assert 'Cl0ud-1nit' not in lines[0], lines[0]
    assert f"'{key}': " in lines[0] and "'cores': 4" in lines[0] and "'ciuser': 'deploy'" in lines[0]
