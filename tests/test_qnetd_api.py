"""The QNetd and QDevice routes (api/qnetd.py) through the real app.

Every one of them is for administrators: the cluster routes run root commands on the
nodes and rewrite corosync.conf, the host routes hold a root login of the QNetd host.
The core behind them is faked here (tests/test_qnetd_core.py drives it); what is shown
is who gets in, what goes back out, what is stored sealed and what the standby does.
MK Oct 2026
"""
import json

import pytest

from pegaprox.core import qnetd

ADMIN_ROUTES = [
    ('get', '/api/qnetd/hosts'),
    ('post', '/api/qnetd/hosts'),
    ('put', '/api/qnetd/hosts/aaaaaaaaaaaa'),
    ('delete', '/api/qnetd/hosts/aaaaaaaaaaaa'),
    ('post', '/api/qnetd/hosts/aaaaaaaaaaaa/check'),
    ('get', '/api/qnetd/hosts/aaaaaaaaaaaa/status'),
    ('post', '/api/qnetd/hosts/aaaaaaaaaaaa/bulk-setup'),
    ('get', '/api/qnetd/jobs'),
    ('get', '/api/qnetd/jobs/0123456789abcdef'),
    ('get', '/api/clusters/c1/qdevice/preflight?qnetd_id=aaaaaaaaaaaa'),
    ('get', '/api/clusters/c1/qdevice/plan?qnetd_id=aaaaaaaaaaaa'),
    ('post', '/api/clusters/c1/qdevice/setup'),
    ('post', '/api/clusters/c1/qdevice/remove'),
]

SSH_HOST = {'name': 'witness', 'kind': 'ssh', 'address': '192.0.2.50', 'ssh_user': 'root',
            'password': 'hunter2-secret'}
DIGEST = 'ab' * 32
CONSENT = {'accepted': True, 'digest': DIGEST}


@pytest.fixture
def env(api, seed, monkeypatch):
    qnetd.reset_for_tests()
    api.set_manager('c1', api.make_fake_manager('c1'))
    monkeypatch.setattr(qnetd, 'transports_available', lambda max_age=60: {
        'local': {'available': False, 'reason': 'x'}, 'sidecar': {'available': False, 'reason': 'x'}})
    launched = []
    monkeypatch.setattr(qnetd, 'launch', lambda job, fn, *a: launched.append((job, fn, a)))
    admin = api.as_user(seed.user('root', role='admin'))
    yield type('E', (), {'api': api, 'seed': seed, 'admin': admin, 'launched': launched, 'db': seed.db})
    qnetd.reset_for_tests()


def _host(env, **kw):
    r = env.admin.post('/api/qnetd/hosts', json=dict(SSH_HOST, **kw))
    assert r.status_code == 201, r.data
    return r.get_json()['host']


def test_every_route_is_for_administrators_only(env):
    _host(env)
    user = env.api.as_user(env.seed.user('ops', role='user', permissions=[
        'cluster.config', 'node.shell', 'node.update', 'admin.settings', 'node.view']))
    viewer = env.api.as_user(env.seed.user('vic', role='viewer'))
    for client, code in ((env.api.anon(), 401), (user, 403), (viewer, 403)):
        for method, path in ADMIN_ROUTES:
            r = getattr(client, method)(path, json={})
            assert r.status_code == code, (method, path, r.status_code)
    assert env.launched == []


def test_an_admin_a_tenant_mapping_lowers_gets_nowhere(env):
    """An account whose global role is admin but whose own tenant maps it down to user
    acts as a user here, on every route."""
    lowered = env.api.as_user(env.seed.user('ladmin', role='admin',
                                            tenant_permissions={'default': {'role': 'user'}}))
    host = _host(env)
    for method, path in ADMIN_ROUTES:
        r = getattr(lowered, method)(path.replace('aaaaaaaaaaaa', host['id']), json={'qnetd_id': host['id']})
        assert r.status_code == 403, (method, path, r.status_code)
    assert env.launched == []


def test_a_pool_scoped_user_with_every_permission_gets_nowhere(env):
    env.seed.pool('c1', 'pool1', 'pooly', ['vm.view', 'vm.config', 'node.shell', 'cluster.config'])
    pooly = env.api.as_user(env.seed.user('pooly', role='user', permissions=['cluster.config', 'node.shell']))
    host = _host(env)
    for method, path in (('post', '/api/clusters/c1/qdevice/setup'), ('post', '/api/clusters/c1/qdevice/remove'),
                         ('get', f"/api/clusters/c1/qdevice/preflight?qnetd_id={host['id']}"),
                         ('get', f"/api/clusters/c1/qdevice/plan?qnetd_id={host['id']}")):
        assert getattr(pooly, method)(path, json={'qnetd_id': host['id'], 'consent': CONSENT}).status_code == 403
    assert env.launched == []


def test_a_new_ssh_host_keeps_its_secrets_sealed_and_to_itself(env):
    host = _host(env, ssh_key='')
    assert 'password' not in host and host['has_password'] is True and host['has_ssh_key'] is False
    raw = env.db.conn.execute('SELECT password_encrypted FROM qnetd_hosts WHERE id = ?',
                              (host['id'],)).fetchone()[0]
    assert raw.startswith('aes256:') and 'hunter2' not in raw
    listed = env.admin.get('/api/qnetd/hosts').get_json()
    assert 'hunter2' not in json.dumps(listed)
    assert listed['hosts'][0]['id'] == host['id'] and listed['protocol'] == qnetd.PROTOCOL == 2
    assert listed['ha_members'] == 1
    rows = env.db.conn.execute("SELECT action, details FROM audit_log WHERE action LIKE 'qnetd.%'").fetchall()
    assert [r[0] for r in rows] == ['qnetd.host_added'] and 'hunter2' not in rows[0][1]


@pytest.mark.parametrize('bad', [
    {'address': '-oProxyCommand=id'}, {'address': '127.0.0.1'}, {'address': 'a;b'},
    {'ssh_user': 'root;id'}, {'ssh_user': '-l'}, {'port': 70000}, {'kind': 'telnet'},
    {'name': ''}, {'name': '<script>'}, {'password': '', 'ssh_key': ''},
    {'ssh_key': 'not a key'}, {'ssh_host': '$(id)'},
])
def test_a_host_with_a_bad_field_is_refused(env, bad):
    r = env.admin.post('/api/qnetd/hosts', json=dict(SSH_HOST, **bad))
    assert r.status_code == 400, (bad, r.data)
    assert env.db.list_qnetd_hosts() == []


def test_one_local_host_and_names_are_unique(env):
    _host(env, kind='local', name='here', address='192.0.2.1')
    assert env.admin.post('/api/qnetd/hosts', json={'name': 'here2', 'kind': 'local',
                                                    'address': '192.0.2.2'}).status_code == 409
    assert env.admin.post('/api/qnetd/hosts', json=dict(SSH_HOST, name='HERE')).status_code == 409


def test_an_update_keeps_the_password_and_a_used_host_keeps_its_address(env):
    host = _host(env)
    r = env.admin.put(f"/api/qnetd/hosts/{host['id']}", json={'name': 'witness-2'})
    assert r.status_code == 200, r.data
    assert qnetd.get_qnetd(host['id'])['password'] == 'hunter2-secret'
    env.db.save_qnetd_attachment('c1', host['id'], 'pve', 'root')
    r = env.admin.put(f"/api/qnetd/hosts/{host['id']}", json={'address': '192.0.2.51'})
    assert r.status_code == 409 and r.get_json()['clusters'] == ['pve']
    assert env.admin.delete(f"/api/qnetd/hosts/{host['id']}").status_code == 409
    env.db.delete_qnetd_attachment('c1')
    assert env.admin.delete(f"/api/qnetd/hosts/{host['id']}").status_code == 200
    assert env.db.list_qnetd_hosts() == []


def test_another_machine_behind_a_host_forgets_its_ca_pin(env):
    host = _host(env)
    env.db.set_qnetd_ca_pin(host['id'], 'a' * 64)
    env.admin.put(f"/api/qnetd/hosts/{host['id']}", json={'name': 'renamed'})
    assert qnetd.get_qnetd(host['id'])['ca_sha256'] == 'a' * 64
    r = env.admin.put(f"/api/qnetd/hosts/{host['id']}", json={'ssh_host': '192.0.2.60',
                                                              'password': 'hunter2-secret'})
    assert r.status_code == 200, r.data
    assert qnetd.get_qnetd(host['id'])['ca_sha256'] == ''


def test_check_hands_back_what_the_core_found(env, monkeypatch):
    host = _host(env)
    seen = []
    monkeypatch.setattr(qnetd, 'check_host', lambda rec, init=True, upgrade=True: seen.append(
        (rec['password'], init)) or {'ok': True, 'active': True, 'protocol': 1, 'error': ''})
    r = env.admin.post(f"/api/qnetd/hosts/{host['id']}/check", json={'init': False})
    assert r.status_code == 200 and r.get_json()['ok'] is True
    assert seen == [('hunter2-secret', False)]
    assert 'hunter2' not in r.get_data(as_text=True)


def test_preflight_passes_the_options_through(env, monkeypatch):
    host = _host(env)
    got = []
    monkeypatch.setattr(qnetd, 'inspect', lambda cid, mgr, rec, install_packages=False, confirm_unverified=False,
                        replace_certificate=False:
                        got.append((cid, rec['id'], install_packages, confirm_unverified, replace_certificate))
                        or {'ok': True})
    r = env.admin.get(f"/api/clusters/c1/qdevice/preflight?qnetd_id={host['id']}&install_packages=1")
    assert r.status_code == 200 and got == [('c1', host['id'], True, False, False)]
    # read as the plan reads it: a certificate of an earlier setup passes with replace
    r = env.admin.get(f"/api/clusters/c1/qdevice/preflight?qnetd_id={host['id']}&replace_certificate=1")
    assert r.status_code == 200 and got[-1] == ('c1', host['id'], False, False, True)
    assert env.admin.get('/api/clusters/c1/qdevice/preflight?qnetd_id=nope').status_code == 404
    assert env.admin.get(f"/api/clusters/zz/qdevice/preflight?qnetd_id={host['id']}").status_code == 404


def test_a_standby_asks_no_qnetd_host_itself(env, monkeypatch):
    from pegaprox.core import ha
    host = _host(env)
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha, 'forwards_read', lambda rule, view_args=None: False)
    monkeypatch.setattr(qnetd, 'inspect', lambda *a, **k: pytest.fail('asked the nodes'))
    monkeypatch.setattr(qnetd, 'plan', lambda *a, **k: pytest.fail('asked the nodes'))
    monkeypatch.setattr(qnetd, 'status', lambda *a, **k: pytest.fail('asked the host'))
    assert env.admin.get(f"/api/clusters/c1/qdevice/preflight?qnetd_id={host['id']}").status_code == 503
    assert env.admin.get(f"/api/clusters/c1/qdevice/plan?qnetd_id={host['id']}").status_code == 503
    assert env.admin.get(f"/api/qnetd/hosts/{host['id']}/status").status_code == 503


def test_the_job_reads_and_the_qnetd_views_go_to_the_active():
    from pegaprox.core import ha
    for rule in ('/api/qnetd/jobs', '/api/qnetd/jobs/<job_id>', '/api/qnetd/hosts',
                 '/api/qnetd/hosts/<host_id>/status', '/api/clusters/<cluster_id>/qdevice/preflight',
                 '/api/clusters/<cluster_id>/qdevice/plan'):
        assert ha.forwards_read(rule)
    assert {'qnetd_hosts', 'qnetd_attachments'} <= set(ha.SYNC_TABLES)
    assert ha.ENCRYPTED_COLUMNS['qnetd_hosts'] == ('password_encrypted', 'ssh_key_encrypted')


def test_every_read_of_these_routes_goes_to_the_active(api):
    """Each GET here answers a standby with 503 itself (_standby_refusal): one that a
    forwarding standby does not hand on is a dead end there. The wizard and the bulk dialog
    get their plan from /qdevice/plan, without it no setup can start on that instance."""
    from pegaprox.core import ha
    reads = sorted(r.rule for r in api.app.url_map.iter_rules()
                   if r.endpoint.startswith('qnetd.') and 'GET' in r.methods)
    assert '/api/clusters/<cluster_id>/qdevice/plan' in reads and len(reads) >= 6
    assert [rule for rule in reads if not ha.forwards_read(rule, {'cluster_id': 'c1'})] == []


def test_setup_starts_a_job_and_a_second_one_waits(env):
    host = _host(env)
    r = env.admin.post('/api/clusters/c1/qdevice/setup', json={'qnetd_id': host['id'], 'install_packages': True,
                                                               'consent': CONSENT})
    assert r.status_code == 202, r.data
    body = r.get_json()
    job, fn, args = env.launched[0]
    assert body['job_id'] == job.id and fn is qnetd.run_setup
    assert args[1] == {'install_packages': True, 'open_firewall': False, 'confirm_unverified_host': False,
                       'replace_certificate': False, 'consents': {'c1': DIGEST}}
    r = env.admin.post('/api/clusters/c1/qdevice/setup', json={'qnetd_id': host['id'], 'consent': CONSENT})
    assert r.status_code == 409
    r = env.admin.post('/api/clusters/c1/qdevice/remove', json={})
    assert r.status_code == 409
    got = env.admin.get(f"/api/qnetd/jobs/{job.id}").get_json()
    assert got['state'] == 'running' and got['clusters']['c1']['state'] == 'waiting'
    assert env.admin.get('/api/qnetd/jobs').get_json()['jobs'][0]['id'] == job.id
    assert env.admin.get('/api/qnetd/jobs/../etc').status_code == 404
    actions = [r[0] for r in env.db.conn.execute("SELECT action FROM audit_log").fetchall()]
    assert 'qdevice.setup_started' in actions


def test_bulk_takes_known_clusters_only(env):
    host = _host(env)
    url = f"/api/qnetd/hosts/{host['id']}/bulk-setup"
    assert env.admin.post(url, json={'cluster_ids': []}).status_code == 400
    assert env.admin.post(url, json={'cluster_ids': 'c1'}).status_code == 400
    assert env.admin.post(url, json={'cluster_ids': ['c' + str(i) for i in range(qnetd.BULK_MAX + 1)]}).status_code == 400
    r = env.admin.post(url, json={'cluster_ids': ['c1', 'ghost'], 'consents': {'c1': DIGEST, 'ghost': DIGEST}})
    assert r.status_code == 404 and r.get_json()['cluster_id'] == 'ghost'
    assert env.launched == []
    r = env.admin.post(url, json={'cluster_ids': ['c1', 'c1'], 'consents': {'c1': DIGEST}, 'open_firewall': True})
    assert r.status_code == 202
    job, fn, args = env.launched[0]
    assert job.cluster_ids == ['c1'] and fn is qnetd.run_bulk
    assert args[1]['consents'] == {'c1': DIGEST} and args[1]['open_firewall'] is True


def test_remove_starts_a_job_without_a_qnetd_host(env):
    r = env.admin.post('/api/clusters/c1/qdevice/remove', json={})
    assert r.status_code == 202
    job, fn, _a = env.launched[0]
    assert fn is qnetd.run_remove and job.qnetd_id is None


def test_the_routes_are_described_as_admin_only(env):
    with open('docs/openapi.json', encoding='utf-8') as fh:
        doc = json.load(fh)
    paths = {p: v for p, v in doc['paths'].items() if p.startswith('/api/qnetd') or '/qdevice/' in p}
    assert len(paths) == 11 and '/api/clusters/{cluster_id}/qdevice/plan' in paths
    for p, ops in paths.items():
        for m, op in ops.items():
            assert op.get('x-pegaprox-roles') == ['admin'], (p, m)
