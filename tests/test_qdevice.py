"""The QDevice of a cluster (#1137): the read, the route, the alert rule and the exporter.

Proxmox answers GET /cluster/config/qdevice from the corosync-qdevice daemon of the node
that serves the call (PVE::API2::ClusterConfig, `status verbose` on its socket) with the
keys Algorithm, Echo reply, Last poll call, Model, QNetd host, State and Tie-breaker, and
with {} where no daemon runs. There is no node parameter, so core/qdevice.py asks every node
it can reach at an address of its own - the API host, the registered and the fallback hosts,
with the cluster's session - and lists the others as not asked.

The cluster below answers per address the way that works: an address belongs to a node, the
node behind it answers /cluster/status with itself as `local` and its own daemon's view.
The routes go through the real app, the alert rule tick by tick like the other event rules
(tests/test_alert_events.py), the exporter through /api/metrics.
MK Oct 2026
"""
import os
import re
import time
import types

import pytest
import requests

from pegaprox.background import alert_events as E
from pegaprox.background import alerts as A
from pegaprox.core import qdevice
from pegaprox.core.manager import PegaProxManager

from test_alert_events import NOW, _closed, _mute, _open, _rule, _rules, _store, _who, sent  # noqa: F401
from test_ha_api import ha_env, _standby_of_active  # noqa: F401
from test_ha_loop_gates import _drive, role  # noqa: F401
from test_metrics_exporter_breadth import _find, _fresh, _fresh_now, _one, _scrape  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QPATH = '/cluster/config/qdevice'


def _q(state='Connected', qnetd='10.0.0.9:5403'):
    """What the daemon prints, the way ClusterConfig.pm hands it on."""
    return {'Algorithm': 'Fifty-Fifty split', 'Echo reply': '2026-10-08T09:12:00 (1s)',
            'Last poll call': '2026-10-08T09:12:01 (cast vote)', 'Model': 'Net',
            'QNetd host': qnetd, 'State': state, 'Tie-breaker': 'Node with lowest node ID'}


class _Resp:
    def __init__(self, code, data):
        self.status_code, self._data = code, data

    def json(self):
        return {'data': self._data}


class _Session:
    def __init__(self, cluster):
        self.cluster = cluster

    def get(self, url, timeout=None, **kw):
        return self.cluster._answer('session', url, timeout)


class _QC:
    """A Proxmox VE cluster at its addresses. nodes: name -> (ip, online); at: address ->
    the node behind it; q: node -> what its daemon says ({}: none, an exception: no answer,
    a tuple: (HTTP status, data))."""
    api_port, cluster_type = 8006, 'proxmox'
    _bracket_ipv6 = staticmethod(PegaProxManager._bracket_ipv6)

    def __init__(self, n=3, fallbacks=None, name='Testi'):
        self.nodes = {f'pve{i}': (f'10.0.0.{i}', True) for i in range(1, n + 1)}
        self.at = {ip: node for node, (ip, _on) in self.nodes.items()}
        self.q = {node: _q() for node in self.nodes}
        fallbacks = [ip for ip, _ in list(self.nodes.values())[1:]] if fallbacks is None else fallbacks
        self.config = types.SimpleNamespace(name=name, host='10.0.0.1', fallback_hosts=list(fallbacks))
        self.current_host = '10.0.0.1'
        self.is_connected = True
        self.calls = []
        self.resolved = []

    @property
    def host(self):
        return self._bracket_ipv6(self.current_host)

    @staticmethod
    def _resolve_host(h):
        return h

    def _status(self, local):
        return [{'type': 'cluster', 'name': 'Testi', 'quorate': 1, 'nodes': len(self.nodes)}] + [
            {'type': 'node', 'name': n, 'ip': ip, 'online': int(on), 'local': int(n == local), 'nodeid': i}
            for i, (n, (ip, on)) in enumerate(sorted(self.nodes.items()), 1)]

    def _answer(self, via, url, timeout):
        m = re.match(r'https://\[?([^\]/]+?)\]?:8006/api2/json(/.*)$', url)
        host, path = m.group(1), m.group(2)
        self.calls.append((via, host, path))
        if path in (QPATH, '/cluster/status'):
            assert timeout and timeout <= 10, f'a read without a short timeout: {url}'
        node = self.at.get(host)
        if node is None or not self.nodes[node][1]:
            raise requests.exceptions.ConnectionError(f'{host}: connection refused')
        if path == '/cluster/status':
            return _Resp(200, self._status(node))
        if path == QPATH:
            a = self.q.get(node, {})
            if isinstance(a, Exception):
                raise a
            if isinstance(a, tuple):
                return _Resp(*a)
            return _Resp(200, a)
        return _Resp(404, None)

    def _api_get(self, url, timeout=10, **_kw):
        return self._answer('api', url, timeout)

    def _create_session(self):
        return _Session(self)

    def asked(self, path=QPATH):
        return sorted((via, host) for via, host, p in self.calls if p == path)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for name in ('_views', '_places', '_locks'):
        monkeypatch.setattr(qdevice, name, {})
    monkeypatch.setattr(qdevice, '_seen', set())


def _rows(v):
    return {r['node']: r for r in v['nodes']}


# --- the read ----------------------------------------------------------------------------

def test_each_node_is_asked_at_its_own_address():
    c = _QC()
    c.q['pve3'] = _q('Connect failed')
    v = qdevice.read('c1', c)
    # the API host through the cluster's normal read, the others at their own address
    assert c.asked() == [('api', '10.0.0.1'), ('session', '10.0.0.2'), ('session', '10.0.0.3')]
    rows = _rows(v)
    assert (v['present'], v['answered_by'], v['state'], v['qnetd_host']) == (True, 'pve1', 'Connected', '10.0.0.9:5403')
    assert (v['model'], v['algorithm'], v['tie_breaker']) == ('Net', 'Fifty-Fifty split', 'Node with lowest node ID')
    assert v['last_poll'] == '2026-10-08T09:12:01 (cast vote)' and v['echo_reply'] == '2026-10-08T09:12:00 (1s)'
    assert [rows[n]['connected'] for n in ('pve1', 'pve2', 'pve3')] == [True, True, False]
    assert rows['pve3']['state'] == 'Connect failed' and rows['pve1']['api_host'] and not rows['pve2']['api_host']
    assert re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00', v['read_at'])
    # counterproof: without fallback hosts only the API host can be asked
    c = _QC(fallbacks=[])
    v = qdevice.read('c2', c)
    assert c.asked() == [('api', '10.0.0.1')]
    assert [(r['node'], r['asked'], r['answered']) for r in v['nodes']] == [
        ('pve1', True, True), ('pve2', False, False), ('pve3', False, False)]


def test_the_api_host_answers_for_itself_and_a_fallback_api_host_too():
    c = _QC()
    # connected to a fallback: pve2 is the API host now, its local flag says so
    c.current_host = '10.0.0.2'
    v = qdevice.read('c1', c)
    assert v['api_node'] == 'pve2' and v['answered_by'] == 'pve2'
    assert c.asked() == [('api', '10.0.0.2'), ('session', '10.0.0.1'), ('session', '10.0.0.3')]


def test_an_address_the_node_list_does_not_name_names_itself():
    """A management address next to the corosync one: placed by the local flag of its own
    /cluster/status, once per PLACE_EVERY."""
    c = _QC(fallbacks=['192.168.7.2'])
    c.at['192.168.7.2'] = 'pve2'
    v = qdevice.read('c1', c, now=1000.0)
    assert _rows(v)['pve2']['answered'] and ('session', '192.168.7.2') in c.asked()
    assert c.asked('/cluster/status') == [('api', '10.0.0.1'), ('session', '192.168.7.2')]
    qdevice.read('c1', c, now=1030.0)
    assert c.asked('/cluster/status').count(('session', '192.168.7.2')) == 1
    # counterproof: an address that answers nothing is placed nowhere and asks nothing
    c = _QC(fallbacks=['192.168.7.9'])
    v = qdevice.read('c2', c)
    assert c.asked() == [('api', '10.0.0.1')] and not _rows(v)['pve2']['asked']


def test_offline_nodes_are_listed_not_asked():
    c = _QC()
    c.nodes['pve3'] = ('10.0.0.3', False)
    v = qdevice.read('c1', c)
    assert ('session', '10.0.0.3') not in c.asked()
    assert (_rows(v)['pve3']['online'], _rows(v)['pve3']['asked']) == (False, False)


def test_an_empty_answer_everywhere_has_no_qdevice():
    c = _QC()
    c.q = {n: {} for n in c.nodes}
    v = qdevice.read('c1', c)
    assert v['present'] is False and v['answered_by'] is None and v['removed'] is True
    assert all(r['answered'] and r['present'] is False for r in v['nodes'])
    assert qdevice.public(v) == {'present': False}


def test_a_node_without_a_daemon_next_to_one_with_it():
    c = _QC()
    c.q['pve1'] = {}
    v = qdevice.read('c1', c)
    # the API host has none: the fields come from the next node that has one
    assert v['present'] and v['answered_by'] == 'pve2' and v['state'] == 'Connected'
    assert (_rows(v)['pve1']['present'], _rows(v)['pve1']['connected']) == (False, False)
    assert v['removed'] is False


def test_errors_are_said_per_node():
    c = _QC()
    c.q['pve2'] = (403, None)
    c.q['pve3'] = requests.exceptions.ReadTimeout('read timed out')
    v = qdevice.read('c1', c)
    rows = _rows(v)
    assert rows['pve2']['error'] == 'HTTP 403' and rows['pve2']['answered'] is False
    assert rows['pve3']['error'] == 'timed out' and rows['pve3']['connected'] is None
    # what an exception says about addresses and pools stays in the debug log
    c.q['pve3'] = requests.exceptions.ConnectionError("HTTPSConnectionPool(host='10.0.0.3', port=8006): refused")
    qdevice._places.clear()
    assert _rows(qdevice.read('c1', c))['pve3']['error'] == 'connection failed'


def test_an_unreadable_node_list_is_no_view():
    c = _QC()
    c.at.pop('10.0.0.1')
    assert qdevice.read('c1', c) is None


def test_parse_keeps_the_seven_keys_and_text_only():
    got = qdevice.parse(dict(_q(), **{'Node ID': '1', 'Model': 'Net', 'State': ['x'], 'Tie-breaker': ''}))
    assert set(got) == {'algorithm', 'echo_reply', 'last_poll', 'model', 'qnetd_host'}
    assert qdevice.parse([]) == {} and qdevice.parse(None) == {}
    assert len(qdevice.parse({'QNetd host': 'x' * 900})['qnetd_host']) == qdevice.TEXT_MAX


def test_one_read_per_fresh_window_whoever_asks():
    c = _QC()
    qdevice.view('c1', c, now=1000.0)
    qdevice.view('c1', c, now=1000.0 + qdevice.FRESH - 1)
    assert len(c.asked()) == 3 and len(c.asked('/cluster/status')) == 1
    qdevice.view('c1', c, now=1000.0 + qdevice.FRESH)
    assert len(c.asked()) == 6
    # a failed read is kept as long: a dead cluster is not asked on every request
    d = _QC()
    d.at.clear()
    assert qdevice.view('c9', d, now=1000.0) is None and qdevice.view('c9', d, now=1010.0) is None
    assert len(d.calls) == 1
    # the exporter takes what is kept and never reads
    assert qdevice.cached('c1', now=1000.0 + qdevice.FRESH)['present'] is True
    assert qdevice.cached('c1', now=1000.0 + qdevice.FRESH + qdevice.SERVE_MAX) is None
    assert qdevice.cached('c9', now=1001.0) is None and qdevice.cached('nope') is None


def test_a_hundred_nodes_cost_one_get_each_per_window():
    c = _QC(n=100)
    v = qdevice.view('big', c, now=2000.0)
    assert len(v['nodes']) == 100 and all(r['connected'] for r in v['nodes'])
    assert len(c.asked()) == 100 and len(c.asked('/cluster/status')) == 1
    qdevice.view('big', c, now=2010.0)
    assert len(c.calls) == 101
    assert not any(re.search(r'/(qemu|lxc)/', p) for _v, _h, p in c.calls)


def test_the_session_is_the_clusters_own_tls_policy_and_credentials(monkeypatch):
    """A fallback address gets the session connect() and every other read use: the CA check
    when the cluster verifies, the token or ticket of the cluster. Nothing here sets verify
    or opens a session of its own."""
    from pegaprox.core.manager import _NoHostnameCheckAdapter
    sent_out = []

    def send(adapter, request, **kw):
        sent_out.append((type(adapter), request.url, dict(request.headers), kw.get('verify')))
        r = requests.Response()
        r.status_code, r._content = 200, b'{"data": {"State": "Connected"}}'
        return r
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)

    def mgr(verify, token=None, ticket=None):
        m = PegaProxManager.__new__(PegaProxManager)
        m._api_token, m._ticket, m._csrf_token, m._ssl_verify = token, ticket, 'csrf' if ticket else None, verify
        m.config = types.SimpleNamespace(api_port=8006)
        return m

    assert qdevice._get(mgr(True, token='root@pam!pp=s3cret'), 'fd00::2', QPATH) == (200, {'State': 'Connected'}, None)
    adapter, url, headers, verify = sent_out[-1]
    assert url == 'https://[fd00::2]:8006/api2/json/cluster/config/qdevice'
    assert headers['Authorization'] == 'PVEAPIToken=root@pam!pp=s3cret'
    assert verify and verify is not False and adapter is requests.adapters.HTTPAdapter
    qdevice._get(mgr(True, ticket='PVE:root@pam:ABC'), '10.0.0.2', QPATH)
    assert 'PVEAuthCookie=PVE:root@pam:ABC' in sent_out[-1][2]['Cookie']
    # counterproof: a cluster set up without verification keeps that, as connect() does
    qdevice._get(mgr(False, token='t=s'), '10.0.0.2', QPATH)
    assert sent_out[-1][3] is False and sent_out[-1][0] is _NoHostnameCheckAdapter

    src = open(os.path.join(ROOT, 'pegaprox', 'core', 'qdevice.py'), encoding='utf-8').read()
    code = src.split('"""', 2)[2]
    for word in ('verify', 'requests', 'ssh', 'paramiko', 'Session(', 'subprocess'):
        assert word not in code, word


# --- the route ---------------------------------------------------------------------------

PATH = '/api/clusters/c1/qdevice'


@pytest.fixture
def qapi(api, seed):
    c = api.set_manager('c1', _QC())
    api.set_manager('c2', _QC(name='Other'))
    return types.SimpleNamespace(api=api, seed=seed, c=c, admin=api.as_user(seed.user('root', role='admin')))


def test_the_route_answers_in_the_agreed_shape(qapi):
    qapi.c.q['pve3'] = _q('Connect failed')
    r = qapi.admin.get(PATH)
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert set(body) == {'present', 'answered_by', 'state', 'qnetd_host', 'model', 'algorithm', 'tie_breaker',
                         'last_poll', 'echo_reply', 'nodes', 'read_at'}
    assert (body['present'], body['answered_by'], body['state']) == (True, 'pve1', 'Connected')
    assert [(n['node'], n['state'], n['connected']) for n in body['nodes']] == [
        ('pve1', 'Connected', True), ('pve2', 'Connected', True), ('pve3', 'Connect failed', False)]


def test_the_route_says_present_false_and_nothing_else(qapi):
    qapi.c.q = {n: {} for n in qapi.c.nodes}
    r = qapi.admin.get(PATH)
    assert r.status_code == 200 and r.get_json() == {'present': False}
    # counterproof: one daemon is enough
    qdevice._views.clear()
    qapi.c.q['pve2'] = _q()
    assert qapi.admin.get(PATH).get_json()['present'] is True


def test_the_route_reads_once_per_window(qapi):
    qapi.admin.get(PATH)
    qapi.admin.get(PATH)
    assert len(qapi.c.asked()) == 3


@pytest.mark.parametrize('case,code', [('unreadable', 503), ('no_answer', 503), ('offline', 503), ('xcpng', 200)])
def test_the_route_when_there_is_nothing_to_show(qapi, case, code):
    if case == 'unreadable':
        qapi.c.at.pop('10.0.0.1')
    elif case == 'no_answer':
        qapi.c.q = {n: requests.exceptions.ReadTimeout('x') for n in qapi.c.nodes}
    elif case == 'offline':
        qapi.c.is_connected = False
    else:
        x = qapi.api.set_manager('x1', qapi.api.make_fake_manager('x1', cluster_type='xcpng'))
        r = qapi.admin.get('/api/clusters/x1/qdevice')
        assert r.status_code == 200 and r.get_json() == {'present': False}
        assert not x.method_calls
        return
    r = qapi.admin.get(PATH)
    assert r.status_code == code and r.get_json().get('error'), r.data
    if case == 'no_answer':
        assert [n['node'] for n in r.get_json()['nodes']] == ['pve1', 'pve2', 'pve3']
    if case == 'offline':
        assert qapi.c.calls == []


def test_a_viewer_of_the_owning_tenant_reads_it(qapi):
    qapi.seed.tenant('acme', ['c1'])
    c = qapi.api.as_user(qapi.seed.user('v', role='viewer', tenant_id='acme'))
    assert c.get(PATH).status_code == 200


@pytest.mark.parametrize('kind', ['no_node_view', 'pool_confined', 'portal', 'capped_admin', 'other_tenant', 'anon'])
def test_who_is_refused_reads_nothing(qapi, kind):
    seed, api = qapi.seed, qapi.api
    if kind == 'no_node_view':
        c = api.as_user(seed.user('plain', role='user', denied=['node.view']))
    elif kind == 'pool_confined':
        from test_audit_bola_high_2026_09 import _seed_pool_membership
        seed.tenant('t_confined', [])
        seed.pool('c1', 'pool1', 'pooled', ['vm.view'])
        _seed_pool_membership('c1', {101: ('qemu', 'pool1')})
        c = api.as_user(seed.user('pooled', role='user', tenant_id='t_confined'))
    elif kind == 'portal':
        seed.tenant('acme', ['c1'])
        seed.vm_acl('c1', 101, users=['portal'])
        c = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    elif kind == 'capped_admin':
        seed.tenant('globex', ['c2'])
        c = api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                  tenant_permissions={'globex': {'role': 'user'}}))
        assert c.get('/api/clusters/c2/qdevice').status_code == 200
        qapi.c.calls.clear()
    elif kind == 'other_tenant':
        seed.tenant('acme', ['c1'])
        seed.tenant('initech', ['c2'])
        c = api.as_user(seed.user('milton', role='user', tenant_id='initech'))
    else:
        c = api.anon()
    r = c.get(PATH)
    assert r.status_code == (401 if kind == 'anon' else 403), (kind, r.data)
    if kind in ('pool_confined', 'portal'):
        assert 'whole cluster' in r.get_json()['error']
    assert qapi.c.calls == []


def test_a_standby_reads_it_like_the_other_node_reads_and_writes_nothing(ha_env, seed, db):  # noqa: F811
    api = ha_env.api
    c = api.set_manager('c1', _QC())
    admin = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    before = db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    r = admin.get(PATH)
    assert r.status_code == 200 and r.get_json()['state'] == 'Connected' and len(c.asked()) == 3
    assert db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0] == before
    # counterproof: a write on the same standby is refused as before
    assert admin.post('/api/clusters/c1/alerts', json={'name': 'q', 'metric': 'qdevice'}).status_code == 409


def test_the_route_is_served_once_and_described(api):
    import json
    rules = [r for r in api.app.url_map.iter_rules() if r.rule == '/api/clusters/<cluster_id>/qdevice']
    assert [sorted(r.methods - {'HEAD', 'OPTIONS'}) for r in rules] == [['GET']]
    with open(os.path.join(ROOT, 'docs', 'openapi.json'), encoding='utf-8') as fh:
        op = json.load(fh)['paths']['/api/clusters/{cluster_id}/qdevice']['get']
    assert op['x-pegaprox-permissions'] == ['node.view']
    with open(os.path.join(ROOT, 'version.json'), encoding='utf-8') as fh:
        assert 'pegaprox/core/qdevice.py' in json.load(fh)['update_files']


# --- the alert rule ----------------------------------------------------------------------

@pytest.fixture
def qc(db, monkeypatch):
    from pegaprox.globals import cluster_managers
    for name in ('_tasks', '_ceph', '_repl', '_snaps', '_status'):
        monkeypatch.setattr(E, name, {})
    monkeypatch.setattr(E, '_last_prune', [0.0])
    c = _QC()
    cluster_managers['c1'] = c
    yield c
    cluster_managers.pop('c1', None)


def _qrule(**kw):
    r = _rule('task_failed', **kw)
    for k in ('task_type', 'task_status', 'task_warnings'):
        r.pop(k, None)
    r.update(metric='qdevice', name=kw.get('name', 'QDevice'), threshold=0)
    return r


def test_a_node_not_connected_alerts_once_on_every_path_and_resolves(qc, sent, monkeypatch, db):
    _rules(monkeypatch, _qrule())
    qc.q['pve3'] = _q('Connect failed')

    E.check_event_alerts(NOW)

    assert sent.names() == ['QDevice not connected on pve3']
    (hook, ids), = sent.hooks
    assert ids == ['hook1'] and hook['event'] == 'firing' and hook['metric'] == 'qdevice'
    assert hook['current_value'] == 'Connect failed' and '10.0.0.9:5403' in hook['message']
    assert len(sent.mail) == 1 and 'QNetd host: 10.0.0.9:5403' in sent.mail[0][2]
    row, = _open(db)
    assert (row['target_type'], row['target_id'], row['object_key'], row['severity']) == (
        'node', 'pve3', 'qdevice:pve3', 'warning')
    # one read per cluster and tick, said once
    E.check_event_alerts(NOW + 60)
    assert len(qc.asked()) == 6 and len(sent.push) == 1

    qc.q['pve3'] = _q()
    E.check_event_alerts(NOW + 120)
    assert sent.names()[-1] == 'Resolved: QDevice on pve3' and sent.hooks[-1][0]['event'] == 'resolved'
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'clear'


def test_the_api_host_stops_answering_with_its_qdevice(qc, sent, monkeypatch, db):
    """Only the API host can be asked: {} after a QDevice was seen is a daemon that stopped."""
    qc.config.fallback_hosts = []
    _rules(monkeypatch, _qrule())
    E.check_event_alerts(NOW)
    assert sent.push == []
    qc.q['pve1'] = {}
    E.check_event_alerts(NOW + 60)
    assert sent.names() == ['QDevice daemon not answering on pve1']
    assert 'corosync-qdevice daemon is not running' in sent.push[0]['message']
    qc.q['pve1'] = _q()
    E.check_event_alerts(NOW + 120)
    assert sent.names()[-1] == 'Resolved: QDevice on pve1' and _open(db) == []


def test_without_a_qdevice_seen_nothing_is_said(qc, sent, monkeypatch, db):
    qc.config.fallback_hosts = []
    qc.q = {n: {} for n in qc.nodes}
    _rules(monkeypatch, _qrule())
    for i in range(3):
        E.check_event_alerts(NOW + 60 * i)
    assert sent.push == [] and _open(db) == []
    # counterproof: the same answer once a QDevice was seen raises it
    qdevice._views.clear()
    qc.q['pve1'] = _q()
    E.check_event_alerts(NOW + 300)
    qc.q['pve1'] = {}
    E.check_event_alerts(NOW + 360)
    assert sent.names() == ['QDevice daemon not answering on pve1']


def test_a_daemon_down_next_to_a_connected_one(qc, sent, monkeypatch, db):
    _rules(monkeypatch, _qrule())
    qc.q['pve2'] = {}
    E.check_event_alerts(NOW)
    assert sent.names() == ['QDevice daemon not answering on pve2']


def test_a_qdevice_taken_out_closes_quietly(qc, sent, monkeypatch, db):
    _rules(monkeypatch, _qrule())
    qc.q['pve3'] = _q('Connect failed')
    E.check_event_alerts(NOW)
    assert len(_open(db)) == 1
    qc.q = {n: {} for n in qc.nodes}
    sent.push.clear()
    E.check_event_alerts(NOW + 60)
    assert _open(db) == [] and sent.push == [] and _closed(db)[0]['resolved_by'] == 'gone'


def test_no_node_connected_is_critical(qc, sent, monkeypatch, db):
    _rules(monkeypatch, _qrule())
    qc.q = {n: _q('Connect failed') for n in qc.nodes}
    E.check_event_alerts(NOW)
    assert len(_open(db)) == 3 and {r['severity'] for r in _open(db)} == {'critical'}
    assert 'may have lost the vote of the QDevice' in sent.push[0]['message']


def test_what_cannot_be_read_changes_nothing(qc, sent, monkeypatch, db):
    _rules(monkeypatch, _qrule())
    qc.q['pve3'] = _q('Connect failed')
    E.check_event_alerts(NOW)
    # pve3 does not answer, then the whole cluster does not: the incident stays as it is
    qc.q['pve3'] = requests.exceptions.ReadTimeout('x')
    E.check_event_alerts(NOW + 60)
    qc.at.clear()
    E.check_event_alerts(NOW + 120)
    assert len(_open(db)) == 1 and len(sent.push) == 1
    # a node that left the cluster takes its incident along
    qc.at = {'10.0.0.1': 'pve1', '10.0.0.2': 'pve2'}
    del qc.nodes['pve3']
    E.check_event_alerts(NOW + 180)
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'gone' and len(sent.push) == 1


def test_a_node_rule_and_a_node_mute(qc, sent, monkeypatch, db):
    _rules(monkeypatch, _qrule(rid='r1'), _qrule(rid='r2', target_type='node', target_id='pve2'))
    _mute(db, object_key='node:pve3')
    qc.q['pve2'] = _q('Connect failed')
    qc.q['pve3'] = _q('Connect failed')
    E.check_event_alerts(NOW)
    assert sorted((r['alert_id'], r['object_key']) for r in _open(db)) == [('r1', 'qdevice:pve2'), ('r2', 'qdevice:pve2')]
    assert sent.names() == ['QDevice not connected on pve2', 'QDevice not connected on pve2']
    assert E._target_key_of('qdevice:pve3') == 'node:pve3'


def test_without_a_qdevice_rule_nothing_is_read(qc, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('clock_drift'))
    E.check_event_alerts(NOW)
    assert qc.asked() == [] and qc.asked('/cluster/status') == []


@pytest.mark.parametrize('which', ['standby', 'active'])
def test_only_the_active_instance_reads_and_sends(which, role, qc, sent, monkeypatch, db):  # noqa: F811
    role(which)
    _rules(monkeypatch, _qrule())
    qc.q['pve3'] = _q('Connect failed')
    for name in ('check_and_send_alerts', 'process_alert_lifecycle', 'check_node_status_transitions',
                 'check_update_available_alert', '_periodic_session_cleanup', '_periodic_audit_cleanup'):
        monkeypatch.setattr(A, name, lambda *a, **k: None)
    monkeypatch.setattr(A, '_alert_running', False)
    _drive(monkeypatch, A, A.alert_check_loop)
    if which == 'standby':
        assert qc.calls == [] and sent.push == sent.hooks == sent.mail == []
    else:
        assert len(qc.asked()) == 3 and sent.names() == ['QDevice not connected on pve3']
        assert len(sent.hooks) == len(sent.mail) == 1


# --- the rule through the routes ---------------------------------------------------------

@pytest.fixture
def routes(api, seed):
    api.set_manager('c1', api.make_fake_manager('c1'))
    return types.SimpleNamespace(api=api, seed=seed, admin=api.as_user(seed.user('root', role='admin')))


def test_a_qdevice_rule_takes_its_defaults(routes, monkeypatch):
    store = _store(monkeypatch)
    # what the dialog sends for a rule without a number
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'Q', 'metric': 'qdevice', 'threshold': 1,
                                                           'operator': 'event'})
    assert r.status_code == 200, r.data
    rule = r.get_json()['alert']
    assert (rule['operator'], rule['threshold'], rule['target_type'], rule['notify_resolved']) == (
        'event', 0, 'cluster', True)
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'Q2', 'metric': 'qdevice',
                                                           'target_type': 'node', 'target_id': 'pve2'})
    assert r.get_json()['alert']['target_id'] == 'pve2' and len(store['c1']) == 2
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'x', 'metric': 'qdevice', 'target_type': 'vm',
                                                           'target_id': '101'})
    assert r.status_code == 400 and 'QDevice rule' in r.get_json()['error'] and len(store['c1']) == 2


@pytest.mark.parametrize('kind,code', [('operator', 200), ('no_permission', 403), ('pool_confined', 403),
                                       ('capped_admin', 403), ('other_tenant', 403)])
def test_who_may_set_a_qdevice_rule(routes, monkeypatch, kind, code):
    store = _store(monkeypatch)
    r = _who(routes, kind).post('/api/clusters/c1/alerts', json={'name': 'n', 'metric': 'qdevice'})
    assert r.status_code == code, (kind, r.data)
    assert len(store['c1']) == (1 if code == 200 else 0)


def _incident(db, obj, ttype, tid, metric='qdevice', rid='r1'):
    db.conn.execute(
        "INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, target_type, target_id, "
        "target_name, message, object_key, triggered_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (f'i-{obj}', f'{rid}:c1:{obj}', rid, 'c1', metric, ttype, tid, tid, 'x', obj, '2026-10-08T00:00:00'))
    db.conn.commit()


def test_a_confined_caller_sees_no_qdevice_incident(routes, monkeypatch, db):
    _incident(db, 'qdevice:pve1', 'node', 'pve1')
    _incident(db, 'vm:101', 'vm', '101', metric='restart_loop')
    _mute(db, object_key='qdevice:pve1')
    from pegaprox.utils import rbac
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda u, cid, vmid, perm='vm.view', vt=None: int(vmid) == 101)
    _store(monkeypatch)
    c = _who(routes, 'pool_confined')
    assert [i['object_key'] for i in c.get('/api/clusters/c1/active-alerts').get_json()['active_alerts']] == ['vm:101']
    assert c.get('/api/clusters/c1/alert-mutes').get_json()['mutes'] == []
    # counterproof: the admin sees it and its mute
    rows = routes.admin.get('/api/clusters/c1/active-alerts').get_json()['active_alerts']
    assert sorted(i['object_key'] for i in rows) == ['qdevice:pve1', 'vm:101']
    assert len(routes.admin.get('/api/clusters/c1/alert-mutes').get_json()['mutes']) == 1


def test_an_acknowledged_incident_stays_quiet_and_still_closes(routes, qc, sent, monkeypatch, db):
    _rules(monkeypatch, _qrule())
    qc.q['pve3'] = _q('Connect failed')
    E.check_event_alerts(NOW)
    row, = _open(db)
    r = routes.admin.post(f"/api/clusters/c1/active-alerts/{row['id']}/ack")
    assert r.status_code == 200 and _open(db)[0]['acked_by'] == 'root'
    E.check_event_alerts(NOW + 60)
    assert len(sent.push) == 1
    qc.q['pve3'] = _q()
    E.check_event_alerts(NOW + 120)
    assert _open(db) == [] and sent.names()[-1] == 'Resolved: QDevice on pve3'


def test_a_qdevice_incident_mutes_its_node(routes, monkeypatch, db):
    _store(monkeypatch, [_qrule()])
    _incident(db, 'qdevice:pve2', 'node', 'pve2')
    r = routes.admin.post('/api/clusters/c1/alert-mutes', json={'active_alert_id': 'i-qdevice:pve2', 'minutes': 60,
                                                                'whole_object': True})
    assert r.status_code == 200 and r.get_json()['mute']['object_key'] == 'node:pve2'


def test_a_standby_takes_no_qdevice_rule(ha_env, seed, monkeypatch):  # noqa: F811
    api = ha_env.api
    store = _store(monkeypatch)
    api.set_manager('c1', api.make_fake_manager('c1'))
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = c.post('/api/clusters/c1/alerts', json={'name': 'q', 'metric': 'qdevice'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY' and store['c1'] == []


# --- the exporter ------------------------------------------------------------------------

class _ExpQC(_QC):
    """The cluster as the scrape sees it, next to its QDevice."""

    def get_node_status(self):
        return {n: {'status': 'online' if on else 'offline', 'cpu': 0.1, 'mem_percent': 5, 'uptime': 10}
                for n, (_ip, on) in self.nodes.items()}

    def get_node_apt_updates(self, node):
        return []

    def get_ceph_health_summary(self):
        return None

    def get_vm_resources(self, max_age=0):
        return []


def test_the_exporter_hands_out_the_last_read_only(api):
    c = api.set_manager('c1', _ExpQC())
    c.q['pve3'] = _q('Connect failed')
    c.config.fallback_hosts = ['10.0.0.3']          # pve2 is not asked
    body = _scrape(api)
    # nothing read yet: a scrape asks nobody
    assert _find(body, 'pegaprox_cluster_qdevice_connected') == [] and c.asked() == []
    assert body.count('# TYPE pegaprox_cluster_qdevice_connected gauge') == 1
    qdevice.view('c1', c)
    body = _scrape(api)
    assert _one(body, 'pegaprox_cluster_qdevice_connected', cluster_id='c1', cluster='Testi', node='pve1') == 1
    assert _one(body, 'pegaprox_cluster_qdevice_connected', cluster_id='c1', node='pve3') == 0
    assert _find(body, 'pegaprox_cluster_qdevice_connected', node='pve2') == []
    assert len(c.asked()) == 2


def test_the_exporter_says_nothing_for_a_cluster_without_one(api):
    c = api.set_manager('c1', _ExpQC())
    c.q = {n: {} for n in c.nodes}
    qdevice.view('c1', c)
    assert _find(_scrape(api), 'pegaprox_cluster_qdevice_connected') == []
    # counterproof: seen before, a node without a daemon is a 0
    qdevice._views.clear()
    qdevice._seen.add('c1')
    c.config.fallback_hosts = []
    qdevice.view('c1', c)
    assert _one(_scrape(api), 'pegaprox_cluster_qdevice_connected', node='pve1') == 0


def test_the_series_is_documented():
    with open(os.path.join(ROOT, 'misc', 'grafana', 'README.md'), encoding='utf-8') as fh:
        doc = fh.read()
    assert '`pegaprox_cluster_qdevice_connected`' in doc and 'QNetd host of a QDevice is no Proxmox node' in doc
