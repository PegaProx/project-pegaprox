"""An audit row written before the config line masked secrets is handed out masked.

Such a row holds "cipassword=<the password>" as the config change was sent. The row stays
in the table as it was signed, so the integrity check still finds the chain whole. The
routes that hand rows out replace the value (and the rest of the change list, which the
password may run into) with ***: the per-cluster trail and the timeline with its evidence
events for a cluster viewer, /api/audit with its CSV and the search for admin.audit, and
the audit part of the support bundle. A row of the new form keeps every other value.
"""
import csv
import io
import json
import time
import types
import zipfile

import pytest

CID = 'cluster_1'
OLD = 'QEMU 100 config updated: ciuser=deploy, cipassword=0ld-pw, cores=9 [x] [lab]'
NEW = 'QEMU 100 config updated: cipassword=***, cores=4, ciuser=deploy [lab]'


@pytest.fixture
def env(api, seed):
    m = api.make_fake_manager(cluster_id=CID, get_tasks=[])
    m.is_connected = True
    m.id = CID
    m.cluster_type = 'proxmox'
    m.config.name = 'lab'
    m.config.host = '10.0.0.1'
    m._vm_resources_cache = (time.time(), [
        {'vmid': 100, 'type': 'qemu', 'node': 'pve1', 'name': 'web01', 'status': 'running'}])
    m._node_status_cache = (time.monotonic(), {})
    api.set_manager(CID, m)
    # the row as the config route wrote it before, through the same signed insert
    seed.db.add_audit_entry('opsuser', 'vm.config_changed', OLD, '10.0.0.7', 'lab', cluster_id=CID)
    seed.db.add_audit_entry('opsuser', 'vm.config_changed', NEW, '10.0.0.7', 'lab', cluster_id=CID)
    return types.SimpleNamespace(admin=api.as_user(seed.user('root', role='admin')),
                                 viewer=api.as_user(seed.user('vera', role='viewer')))


def _details(rows):
    return sorted(r['details'] for r in rows if r.get('action', r.get('title')) == 'vm.config_changed')


MASKED = sorted(['QEMU 100 config updated: ciuser=deploy, cipassword=*** [lab]', NEW])


def test_the_cluster_trail_masks_it_for_a_viewer(env):
    r = env.viewer.get(f'/api/clusters/{CID}/audit?limit=50')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _details(r.get_json()) == MASKED
    assert '0ld-pw' not in r.get_data(as_text=True)


def test_the_timeline_and_the_evidence_events_mask_it(env):
    r = env.viewer.get(f'/api/timeline?cluster={CID}&kinds=audit')
    assert r.status_code == 200, r.get_data(as_text=True)
    events = [e for e in r.get_json()['events'] if e['title'] == 'vm.config_changed']
    assert sorted(e['details'] for e in events) == MASKED
    assert '0ld-pw' not in r.get_data(as_text=True)

    r = env.viewer.get(f'/api/timeline/evidence?clusters={CID}&kinds=audit')
    assert r.status_code == 200, r.get_data(as_text=True)
    doc = json.loads(r.get_data(as_text=True))
    assert sorted(e['details'] for e in doc['events'] if e.get('title') == 'vm.config_changed') == MASKED
    assert '0ld-pw' not in r.get_data(as_text=True)


def test_the_audit_api_its_csv_and_the_search_mask_it(env, seed):
    r = env.admin.get('/api/audit?limit=50&verify=true')
    assert r.status_code == 200, r.get_data(as_text=True)
    rows = [e for e in r.get_json() if e['action'] == 'vm.config_changed']
    assert _details(rows) == MASKED
    # verified as stored: the mask is on the way out only
    assert all(e['integrity_verified'] for e in rows)

    r = env.admin.get('/api/audit?limit=50&format=csv')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _details(csv.DictReader(io.StringIO(r.get_data(as_text=True)))) == MASKED

    r = env.admin.get('/api/audit/search?q=config+updated')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _details(r.get_json()['entries']) == MASKED
    for got in (r, env.admin.get('/api/audit?limit=50&format=csv')):
        assert '0ld-pw' not in got.get_data(as_text=True)

    # the table keeps the row as it was signed, and the chain over it stays whole
    stored = [r['details'] for r in seed.db.conn.execute(
        "SELECT details FROM audit_log WHERE action = 'vm.config_changed' ORDER BY id")]
    assert stored == [OLD, NEW]
    r = env.admin.get('/api/audit/integrity')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['intact'] is True, r.get_json()


def test_the_support_bundle_masks_it(env):
    # the bundle describes every connected cluster as well, which a fake one cannot
    from pegaprox.globals import cluster_managers
    cluster_managers.pop(CID)
    r = env.admin.get('/api/support-bundle')
    assert r.status_code == 200, r.data[:300]
    with zipfile.ZipFile(io.BytesIO(r.data)) as zf:
        name = next(n for n in zf.namelist() if n.endswith('/audit_log.json'))
        rows = json.loads(zf.read(name))
    assert _details(rows) == MASKED
    assert '0ld-pw' not in json.dumps(rows)
