"""The backup SLA goes by the backup, not by what its storage is called.

The type came from anywhere in the volid, storage name included, so every VM on a storage called pbs-lxc had "no backup".
"""
import time
from types import SimpleNamespace

import pytest

import pegaprox.api.clusters as cl

CID = 'c1'


@pytest.mark.parametrize('volid', ['pbs-lxc:backup/vm/100/2026-11-06T00:00:00Z', 'lxc-store:backup/vzdump-qemu-100-2026_11_06-00_00_00.vma.zst',
                                   'local:backup/vzdump-qemu-100-2026_11_06-00_00_00.vma.zst'])
def test_a_vm_on_such_a_storage_has_its_backup(api, seed, monkeypatch, volid):
    mgr = api.make_fake_manager(cluster_id=CID)
    mgr.host, mgr.api_port = 'pve', 8006
    mgr.config.name = CID
    mgr.config.backup_sla_max_age_hours = 24
    mgr.is_connected = True
    session = mgr._create_session.return_value
    session.get.side_effect = lambda url, **k: SimpleNamespace(status_code=200, json=lambda: {'data': [{'node': 'pveA', 'status': 'online'}]}, text='')
    mgr.get_vm_resources.return_value = [{'type': 'qemu', 'vmid': 100, 'name': 'a', 'node': 'pveA', 'status': 'running'}]
    api.set_manager(CID, mgr)
    now = int(time.time())
    monkeypatch.setattr(cl, '_sla_scan', lambda m, base, nodes: ([('s', [{'volid': volid, 'ctime': now - 60, 'vmid': 100}])], []))
    body = api.as_user(seed.user('root', role='admin', tenant_id='default')).get(f'/api/clusters/{CID}/backup-sla').get_json()
    assert body['vms'][0]['sla_status'] != 'no-backup', body['vms']


def test_the_alert_loop_cuts_it_off_the_same_way():
    src = open(__import__('pegaprox.background.alerts', fromlist=['x']).__file__, encoding='utf-8').read()
    assert "volid = (it.get('volid') or '').split(':', 1)[-1]" in src
