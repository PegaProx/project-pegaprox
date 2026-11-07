"""The backup SLA goes by the backup, not by what its storage is called.

The type came from anywhere in the volid, storage name included, so every VM on a storage called pbs-lxc had "no backup",
and every container on one called qemu-store too.
"""
import time
from types import SimpleNamespace

import pytest

import pegaprox.api.clusters as cl
import pegaprox.background.alerts as al

CID = 'c1'
NOW = int(time.time())

CASES = [
    ('qemu', 100, 'pbs-lxc:backup/vm/100/2026-11-06T00:00:00Z'),
    ('lxc', 101, 'qemu-store:backup/ct/101/2026-11-06T00:00:00Z'),
    ('lxc', 101, 'qemu-store:backup/vzdump-lxc-101-2026_11_06-00_00_00.tar.zst'),
    ('qemu', 100, 'local:backup/vzdump-qemu-100-2026_11_06-00_00_00.vma.zst'),
]


@pytest.mark.parametrize('gtype,vmid,volid', CASES)
def test_a_guest_on_such_a_storage_has_its_backup(api, seed, monkeypatch, gtype, vmid, volid):
    mgr = api.make_fake_manager(cluster_id=CID)
    mgr.host, mgr.api_port = 'pve', 8006
    mgr.config.name = CID
    mgr.config.backup_sla_max_age_hours = 24
    mgr.is_connected = True
    session = mgr._create_session.return_value
    session.get.side_effect = lambda url, **k: SimpleNamespace(status_code=200, json=lambda: {'data': [{'node': 'pveA', 'status': 'online'}]}, text='')
    mgr.get_vm_resources.return_value = [{'type': gtype, 'vmid': vmid, 'name': 'a', 'node': 'pveA', 'status': 'running'}]
    api.set_manager(CID, mgr)
    monkeypatch.setattr(cl, '_sla_scan', lambda m, base, nodes: ([('s', [{'volid': volid, 'ctime': NOW - 60, 'vmid': vmid}])], []))
    body = api.as_user(seed.user('root', role='admin', tenant_id='default')).get(f'/api/clusters/{CID}/backup-sla').get_json()
    assert body['vms'][0]['sla_status'] != 'no-backup', body['vms']


class _Answer:
    def __init__(self, data):
        self.status_code, self.text, self._data = 200, '', data

    def json(self):
        return {'data': self._data}


@pytest.mark.parametrize('gtype,vmid,volid', CASES)
def test_the_alert_loop_reads_it_the_same_way(db, monkeypatch, gtype, vmid, volid):
    store = volid.split(':', 1)[0]

    def get(url, params=None, timeout=None, **kw):
        path = url.split('/api2/json', 1)[1]
        if path == '/nodes':
            return _Answer([{'node': 'n1', 'status': 'online'}])
        if path.endswith('/storage'):
            return _Answer([{'storage': store, 'content': 'backup'}])
        return _Answer([{'volid': volid, 'vmid': vmid, 'ctime': NOW - 60}])

    mgr = SimpleNamespace(config=SimpleNamespace(name=CID, backup_sla_max_age_hours=24), host='pve', api_port=8006,
                          get_vm_resources=lambda: [{'type': gtype, 'vmid': vmid}], get_node_status=lambda: {},
                          _create_session=lambda: SimpleNamespace(get=get))
    monkeypatch.setattr(al, 'cluster_managers', {CID: mgr})
    monkeypatch.setattr(al, '_alert_last_sent', {})
    monkeypatch.setattr(al, 'load_alerts_config', lambda: {'enabled': True, 'alerts': [
        {'id': 'a1', 'cluster_id': CID, 'metric': 'backup_sla_breached_pct', 'threshold': 0, 'operator': '>',
         'target_type': 'cluster'}]})
    monkeypatch.setattr(al, 'load_server_settings', lambda: {})
    monkeypatch.setattr(al, 'active_mutes', lambda: [])
    monkeypatch.setattr(al, 'dispatch_alert', lambda *a, **k: ([], False, '', ''))
    monkeypatch.setattr(al, '_upsert_active_alert', lambda *a, **k: None)
    seen = {}
    monkeypatch.setattr(al, '_record_eval', lambda alert_id, **fields: seen.update(fields))
    al.check_and_send_alerts()
    assert seen.get('current_value') == 0.0, seen
