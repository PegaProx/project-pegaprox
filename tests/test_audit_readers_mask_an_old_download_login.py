"""An ISO download row written before the line named the host only is handed out without
the mirror login.

Such a row holds the first 50 characters of the URL and '...', a user:password@ in them
included. The row stays in the table as it was signed. The routes that hand rows out show
its URL the way a new row shows it: the login (to the last '@' of the netloc, blanks in it
too) goes, and a URL cut off before its path goes whole. The same goes for the cluster
viewer's trail and timeline, /api/audit with its CSV and the search, and the audit part and
the log part of the support bundle.
"""
import csv
import io
import json
import time
import types
import zipfile

import pytest

from pegaprox.api import settings as settings_mod

CID = 'cluster_1'
URLS = [
    'http://mirroruser:p@ssw0rd@93.184.216.34/isos/debian-12.iso',
    'http://mirroruser:Sec r3t@93.184.216.34/isos/debian-12.iso',
    'http://mirroruser:' + 'Zq' * 20 + '@93.184.216.34/isos/debian.iso',
    'https://93.184.216.34/d.iso?token=tok3n-value',
]
# the line as the download route wrote it then
OLD = [f'Started download: debian.iso from {u[:50]}...' for u in URLS]
SHOWN = sorted([
    'Started download: debian.iso from http://93.184.216.34/isos/[REDACTED]... [lab]',
    'Started download: debian.iso from http://93.184.216.34/isos/[REDACTED]... [lab]',
    'Started download: debian.iso from http://[REDACTED]... [lab]',
    'Started download: debian.iso from https://93.184.216.34/[REDACTED]?token=[REDACTED]... [lab]',
    'Started download: debian.iso from http://93.184.216.34/isos/[REDACTED] [lab]',
])
SECRETS = ('mirroruser', 'ssw0rd', 'Sec r3t', 'r3t', 'ZqZq', 'tok3n')


@pytest.fixture
def env(api, seed):
    m = api.make_fake_manager(cluster_id=CID, get_tasks=[])
    m.is_connected = True
    m.id = CID
    m.cluster_type = 'proxmox'
    m.config.name = 'lab'
    m.config.host = '10.0.0.1'
    m._vm_resources_cache = (time.time(), [])
    m._node_status_cache = (time.monotonic(), {})
    api.set_manager(CID, m)
    for line in OLD:
        seed.db.add_audit_entry('opsuser', 'storage.download', f'{line} [lab]', '10.0.0.7', 'lab', cluster_id=CID)
    # a row of the new form stays as it is
    seed.db.add_audit_entry('opsuser', 'storage.download',
                            'Started download: debian.iso from http://93.184.216.34/isos/[REDACTED] [lab]',
                            '10.0.0.7', 'lab', cluster_id=CID)
    return types.SimpleNamespace(admin=api.as_user(seed.user('root', role='admin')),
                                 viewer=api.as_user(seed.user('vera', role='viewer')))


def _details(rows):
    return sorted(r['details'] for r in rows if r.get('action', r.get('title')) == 'storage.download')


def _none_in(text):
    for part in SECRETS:
        assert part not in text, (part, text)


def test_the_cluster_trail_and_the_timeline_show_it_without_the_login(env):
    r = env.viewer.get(f'/api/clusters/{CID}/audit?limit=50')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _details(r.get_json()) == SHOWN
    _none_in(r.get_data(as_text=True))

    r = env.viewer.get(f'/api/timeline?cluster={CID}&kinds=audit')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _details(r.get_json()['events']) == SHOWN
    _none_in(r.get_data(as_text=True))

    r = env.viewer.get(f'/api/timeline/evidence?clusters={CID}&kinds=audit')
    assert r.status_code == 200, r.get_data(as_text=True)
    doc = json.loads(r.get_data(as_text=True))
    assert _details(doc['events']) == SHOWN


def test_the_audit_api_its_csv_and_the_search_show_it_without_the_login(env, seed):
    r = env.admin.get('/api/audit?limit=50&verify=true')
    assert r.status_code == 200, r.get_data(as_text=True)
    rows = [e for e in r.get_json() if e['action'] == 'storage.download']
    assert _details(rows) == SHOWN
    assert all(e['integrity_verified'] for e in rows)
    _none_in(r.get_data(as_text=True))

    r = env.admin.get('/api/audit?limit=50&format=csv')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _details(csv.DictReader(io.StringIO(r.get_data(as_text=True)))) == SHOWN

    r = env.admin.get('/api/audit/search?q=Started+download')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _details(r.get_json()['entries']) == SHOWN

    # the table keeps the rows as they were signed
    stored = [r['details'] for r in seed.db.conn.execute(
        "SELECT details FROM audit_log WHERE action = 'storage.download' ORDER BY id")]
    assert stored[:4] == [f'{line} [lab]' for line in OLD]


def test_the_support_bundle_shows_it_without_the_login(env, tmp_path, monkeypatch):
    from pegaprox.globals import cluster_managers
    cluster_managers.pop(CID)
    (tmp_path / 'pegaprox.log').write_text(''.join(
        f'INFO Audit: opsuser - storage.download [lab] - {line}\n' for line in OLD))
    monkeypatch.setattr(settings_mod, 'LOG_DIR', str(tmp_path))
    r = env.admin.get('/api/support-bundle')
    assert r.status_code == 200, r.data[:300]
    with zipfile.ZipFile(io.BytesIO(r.data)) as zf:
        rows = json.loads(zf.read(next(n for n in zf.namelist() if n.endswith('/audit_log.json'))))
        log = zf.read(next(n for n in zf.namelist() if n.endswith('/pegaprox.log'))).decode()
    assert _details(rows) == SHOWN
    _none_in(json.dumps(rows))
    _none_in(log)
    assert log.count('Started download: debian.iso from ') == len(OLD), log
