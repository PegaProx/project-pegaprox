"""The connection check of one PVE cluster (core/conncheck.py, POST .../connection-check).

What it must never do matters as much as what it finds: no SSH login where ssh_diagnose
objects (no credential, SSH off, node in backoff, node offline), at most one login per
node, and no credentials sent to any address while the cluster is not connected.
"""
import types

import pytest

from pegaprox.core import conncheck


FP_A = 'AA:' * 31 + 'AA'
FP_B = 'BB:' * 31 + 'BB'
FP_C = 'CC:' * 31 + 'CC'
ROOT_PERMS = {'/': {p: 1 for privs, _path, _f in conncheck.PRIVILEGE_NEEDS for p in privs}}


class _Resp:
    def __init__(self, status, data=None):
        self.status_code = status
        self._data = data

    def json(self):
        return {'data': self._data}


class _Session:
    def __init__(self, answers):
        self.answers = answers
        self.urls = []
        self.trust_env = True

    def get(self, url, **kw):
        self.urls.append(url)
        host = url.split('//')[1].split(':')[0]
        ans = self.answers.get(host, 200)
        if isinstance(ans, Exception):
            raise ans
        return _Resp(ans, {'version': '9.0.3'})

    def close(self):
        pass


class _Client:
    def __init__(self, sudo_rc=0):
        self.sudo_rc = sudo_rc
        self.closed = False
        self.commands = []

    def exec_command(self, cmd, timeout=None):
        self.commands.append(cmd)
        chan = types.SimpleNamespace(recv_exit_status=lambda: self.sudo_rc)
        return None, types.SimpleNamespace(channel=chan), None

    def close(self):
        self.closed = True


class FakeMgr:
    """The PegaProxManager surface conncheck uses, with three nodes behind it."""

    api_port = 8006
    per_node_timeout = 4
    host = '10.0.0.1'

    def __init__(self, **kw):
        self.config = types.SimpleNamespace(
            name='lab', host='10.0.0.1', fallback_hosts=['10.0.0.2', '10.0.0.3'],
            user='root@pam', pass_='secret', api_token_user='root@pam!pegaprox',
            api_token_secret='tok', ssh_user='', ssh_key='', ssl_verification=False,
            ssh_disabled=False)
        self.is_connected = True
        self.connection_error = None
        self.connection_error_code = None
        self._api_token = 'root@pam!pegaprox=tok'
        self._using_api_token = True
        self._ticket = None
        self.nodes = [('pve1', '10.0.0.1', 1), ('pve2', '10.0.0.2', 1), ('pve3', '10.0.0.3', 1)]
        self.quorate = 1
        self.perms = ROOT_PERMS
        self.versions = {'pve1': '9.0.3', 'pve2': '9.0.3', 'pve3': '9.0.5'}
        self.skew = {}
        self.node_fps = {'pve1': FP_A, 'pve2': FP_B, 'pve3': FP_C}
        self.wire_fps = {'10.0.0.1': FP_A, '10.0.0.2': FP_B, '10.0.0.3': FP_C}
        self.http = {}
        self.blocked = None
        self.diag = {}
        self.ssh_fail = {}
        self.sudo_rc = 0
        self.auth_blocked = (False, 0)
        self.api_calls = []
        self.ssh_calls = []
        self.clients = []
        self.session = _Session(self.http)
        for k, v in kw.items():
            setattr(self, k, v)

    # --- API ---
    def _api_get(self, url, **kw):
        ep = url.split('/api2/json', 1)[1]
        self.api_calls.append(ep)
        if ep == '/cluster/status':
            rows = [{'type': 'node', 'name': n, 'ip': ip, 'online': on} for n, ip, on in self.nodes]
            if len(self.nodes) > 1:
                rows.append({'type': 'cluster', 'name': 'lab', 'quorate': self.quorate})
            return _Resp(200, rows)
        if ep == '/access/permissions':
            return _Resp(200, self.perms)
        node = ep.split('/')[2]
        if ep.endswith('/version'):
            return _Resp(200, {'version': self.versions[node], 'release': self.versions[node][:3]})
        if ep.endswith('/time'):
            import time
            return _Resp(200, {'time': int(time.time() + self.skew.get(node, 0))})
        if ep.endswith('/certificates/info'):
            return _Resp(200, [{'filename': 'pve-root-ca.pem', 'fingerprint': 'FF'},
                               {'filename': 'pve-ssl.pem', 'fingerprint': self.node_fps[node]}])
        raise AssertionError(ep)

    def _create_session(self):
        return self.session

    def tls_fingerprint(self, host, port, timeout=None):
        fp = self.wire_fps.get(host)
        if isinstance(fp, Exception):
            raise fp
        return fp

    @staticmethod
    def _bracket_ipv6(h):
        return h

    @staticmethod
    def _resolve_host(h):
        return h

    def _is_auth_blocked(self):
        return self.auth_blocked

    # --- SSH ---
    def ssh_blocked_reason(self):
        return self.blocked

    def ssh_diagnose(self, node):
        if node in self.diag:
            return self.diag[node]
        if self.blocked:
            return (self.blocked, f'{self.blocked} detail')
        return None

    def _get_node_ip(self, node):
        return dict((n, ip) for n, ip, _ in self.nodes).get(node)

    def _ssh_connect(self, host, retries=3, retry_delay=2.0, connect_timeout=30, failure=None):
        self.ssh_calls.append((host, retries, connect_timeout))
        if host in self.ssh_fail:
            failure.update(kind=self.ssh_fail[host], detail='nope')
            return None
        c = _Client(self.sudo_rc)
        self.clients.append(c)
        return c


def _items(report, kind):
    return [i for i in report['items'] if i['kind'] == kind]


def _one(report, kind):
    found = _items(report, kind)
    assert len(found) == 1, found
    return found[0]


# --- privileges -------------------------------------------------------------------------------

def test_a_privilege_counts_on_its_path_or_propagated_from_above():
    assert conncheck.holds_privilege({'/vms': {'VM.Audit': 0}}, '/vms', ('VM.Audit',)) == 'yes'
    assert conncheck.holds_privilege({'/': {'VM.Audit': 1}}, '/vms', ('VM.Audit',)) == 'yes'
    # a grant on / that does not propagate is not a grant on /vms
    assert conncheck.holds_privilege({'/': {'VM.Audit': 0}}, '/vms', ('VM.Audit',)) == 'no'
    # PVE listed /vms itself without it: that is the answer, / does not override it
    assert conncheck.holds_privilege({'/': {'VM.Audit': 1}, '/vms': {}}, '/vms', ('VM.Audit',)) == 'no'
    # on one pool or guest only
    assert conncheck.holds_privilege({'/vms/100': {'VM.Audit': 1}}, '/vms', ('VM.Audit',)) == 'partial'
    # either name of the guest agent privilege
    assert conncheck.holds_privilege({'/vms': {'VM.Monitor': 1}}, '/vms',
                                     ('VM.GuestAgent.Audit', 'VM.Monitor')) == 'yes'


def test_missing_privileges_name_the_features_they_turn_off():
    assert conncheck.missing_privileges(ROOT_PERMS) == []
    perms = {'/': {'Sys.Audit': 1}, '/vms': {'VM.Audit': 1, 'VM.PowerMgmt': 1}, '/storage': {'Datastore.Audit': 1}}
    missing = {m['privs'][0]: m for m in conncheck.missing_privileges(perms)}
    assert missing['VM.Migrate']['features'] == ['migration'] and missing['VM.Migrate']['path'] == '/vms'
    assert missing['VM.Console']['features'] == ['consoles']
    assert 'Sys.Audit' not in missing and 'VM.PowerMgmt' not in missing


# --- credentials ------------------------------------------------------------------------------

def test_the_three_credential_kinds():
    m = FakeMgr()
    assert conncheck.credential_info(m)['type'] == 'minted_token'
    assert conncheck.credential_info(m)['active'] == 'token'
    m.config.api_token_user = m.config.api_token_secret = ''
    m._api_token, m._using_api_token, m._ticket = None, False, 'PVE:ticket'
    info = conncheck.credential_info(m)
    assert info['type'] == 'password' and info['active'] == 'ticket' and info['has_password']
    m.config.user = 'ops@pve!pegaprox'
    info = conncheck.credential_info(m)
    assert info['type'] == 'api_token' and info['token_id'] == 'ops@pve!pegaprox'
    assert info['user'] == 'ops@pve' and info['has_password'] is False


def test_a_rejected_minted_token_is_a_warning():
    m = FakeMgr(_api_token=None, _using_api_token=False, _ticket='PVE:t')
    item = conncheck.check_credentials(m)
    assert item['status'] == 'warn' and item['hint'] == 'cred_token_rejected'


# --- the whole check --------------------------------------------------------------------------

def test_a_healthy_cluster_passes_and_each_node_gets_one_ssh_login():
    m = FakeMgr()
    report = conncheck.run_check(m)
    assert report['summary']['fail'] == 0 and report['summary']['warn'] == 0, report['items']
    hosts = _items(report, 'api_host')
    assert [h['host'] for h in hosts] == ['10.0.0.1', '10.0.0.2', '10.0.0.3']
    assert all(h['tls'] == 'match' and h['http'] == 200 for h in hosts)
    assert {h['node'] for h in hosts} == {'pve1', 'pve2', 'pve3'}
    assert _one(report, 'versions')['nodes'] == m.versions     # 9.0.3 and 9.0.5: same release
    assert _one(report, 'quorum')['quorate'] is True
    ssh = _items(report, 'ssh')
    assert sorted(i['node'] for i in ssh) == ['pve1', 'pve2', 'pve3'] and all(i['status'] == 'ok' for i in ssh)
    assert sorted(c[0] for c in m.ssh_calls) == ['10.0.0.1', '10.0.0.2', '10.0.0.3']
    assert all(retries == 1 and timeout == conncheck.SSH_TIMEOUT for _h, retries, timeout in m.ssh_calls)
    assert all(c.closed for c in m.clients)
    # root logs in as root: no sudo test
    assert all(not c.commands for c in m.clients)


def test_no_ssh_credential_means_no_ssh_attempt_at_all():
    m = FakeMgr(blocked='SSH_NO_CREDENTIALS')
    report = conncheck.run_check(m)
    item = _one(report, 'ssh')
    assert item['status'] == 'warn' and item['code'] == 'SSH_NO_CREDENTIALS'
    assert item['hint'] == 'ssh_no_credentials'
    assert m.ssh_calls == []


def test_ssh_switched_off_is_skipped_without_attempt():
    m = FakeMgr(blocked='SSH_DISABLED')
    item = _one(conncheck.run_check(m), 'ssh')
    assert item['status'] == 'skip' and item['hint'] == 'ssh_disabled'
    assert m.ssh_calls == []


def test_backoff_and_offline_nodes_are_not_contacted():
    m = FakeMgr(diag={'pve2': ('NODE_BACKOFF', 'pve2 is in reachability backoff')})
    m.nodes = [('pve1', '10.0.0.1', 1), ('pve2', '10.0.0.2', 1), ('pve3', '10.0.0.3', 0)]
    report = conncheck.run_check(m)
    ssh = {i['node']: i for i in _items(report, 'ssh')}
    assert ssh['pve2']['code'] == 'NODE_BACKOFF' and ssh['pve2']['status'] == 'warn'
    assert ssh['pve3']['code'] == 'NODE_OFFLINE' and ssh['pve3']['status'] == 'skip'
    assert [c[0] for c in m.ssh_calls] == ['10.0.0.1']
    # an offline node is not asked for its version or clock either
    assert not any('/nodes/pve3/' in ep for ep in m.api_calls)
    q = _one(report, 'quorum')
    assert q['status'] == 'warn' and q['offline'] == ['pve3']


def test_the_check_says_which_node_refused_and_why():
    m = FakeMgr(ssh_fail={'10.0.0.2': 'auth', '10.0.0.3': 'host_key'})
    ssh = {i['node']: i for i in _items(conncheck.run_check(m), 'ssh')}
    assert ssh['pve1']['status'] == 'ok'
    assert ssh['pve2']['status'] == 'fail' and ssh['pve2']['code'] == 'AUTH_REFUSED'
    assert ssh['pve2']['hint'] == 'ssh_auth_refused' and ssh['pve2']['ip'] == '10.0.0.2'
    assert ssh['pve3']['code'] == 'HOST_KEY' and ssh['pve3']['hint'] == 'ssh_host_key'
    # still one attempt per node, no retry after a refusal
    assert len(m.ssh_calls) == 3


def test_a_non_root_ssh_user_has_sudo_checked_in_the_same_login():
    m = FakeMgr(sudo_rc=1)
    m.config.ssh_user = 'pegaprox'
    ssh = _items(conncheck.run_check(m), 'ssh')
    assert all(i['status'] == 'warn' and i['code'] == 'SUDO_REFUSED' and i['user'] == 'pegaprox' for i in ssh)
    assert all(c.commands == ['sudo -n true'] for c in m.clients)
    assert len(m.ssh_calls) == 3


def test_a_foreign_certificate_and_a_dead_fallback():
    m = FakeMgr()
    m.wire_fps['10.0.0.2'] = FP_C                      # not what pve2 says it serves
    m.wire_fps['10.0.0.3'] = ConnectionRefusedError('Connection refused')
    hosts = {h['host']: h for h in _items(conncheck.run_check(m), 'api_host')}
    assert hosts['10.0.0.1']['status'] == 'ok'
    assert hosts['10.0.0.2']['status'] == 'warn' and hosts['10.0.0.2']['hint'] == 'api_tls_mismatch'
    assert hosts['10.0.0.3']['status'] == 'fail' and hosts['10.0.0.3']['hint'] == 'api_unreachable'
    assert 'refused' in hosts['10.0.0.3']['detail']


def test_a_fallback_that_refuses_the_session_is_named():
    m = FakeMgr()
    m.http['10.0.0.3'] = 401
    hosts = {h['host']: h for h in _items(conncheck.run_check(m), 'api_host')}
    assert hosts['10.0.0.3']['status'] == 'fail' and hosts['10.0.0.3']['hint'] == 'api_auth'


def test_one_address_for_a_cluster_of_three_is_a_warning():
    m = FakeMgr()
    m.config.fallback_hosts = []
    item = _one(conncheck.run_check(m), 'api_fallbacks')
    assert item['status'] == 'warn' and item['hint'] == 'api_no_fallback'


def test_clock_versions_privileges_and_quorum_findings():
    m = FakeMgr(skew={'pve3': 120}, perms={'/': {'Sys.Audit': 1}}, quorate=0)
    m.versions = {'pve1': '9.0.3', 'pve2': '8.4.1', 'pve3': '9.0.3'}
    report = conncheck.run_check(m)
    clock = _one(report, 'clock')
    assert clock['status'] == 'fail' and clock['hint'] == 'clock_skew' and clock['max_skew'] >= 119
    assert _one(report, 'versions')['hint'] == 'ver_mixed'
    priv = _one(report, 'privileges')
    assert priv['status'] == 'warn' and priv['hint'] == 'priv_missing'
    assert any(x['privs'] == ['VM.Migrate'] for x in priv['missing'])
    assert _one(report, 'quorum')['status'] == 'fail'


def test_an_end_of_life_release_is_flagged():
    m = FakeMgr()
    m.versions = {'pve1': '7.4-3', 'pve2': '7.4-3', 'pve3': '7.4-3'}
    item = _one(conncheck.run_check(m), 'versions')
    assert item['hint'] == 'ver_old' and item['old'] == ['pve1', 'pve2', 'pve3']


def test_not_connected_sends_no_credentials_and_skips_the_rest(monkeypatch):
    m = FakeMgr(is_connected=False, connection_error='Authentication failed', _api_token=None,
                _using_api_token=False)
    plain = _Session({'10.0.0.1': 401, '10.0.0.2': 401, '10.0.0.3': 401})
    monkeypatch.setattr(conncheck.requests, 'Session', lambda: plain)
    report = conncheck.run_check(m)
    cred = _one(report, 'credentials')
    assert cred['status'] == 'fail' and cred['hint'] == 'cred_not_connected'
    assert cred['detail'] == 'Authentication failed'
    # the cluster's own session never went out, the plain one found pveproxy answering
    assert m.session.urls == [] and len(plain.urls) == 3
    assert all(h['status'] == 'ok' and h['http'] == 401 for h in _items(report, 'api_host'))
    assert m.api_calls == [] and m.ssh_calls == []
    for kind in ('privileges', 'versions', 'clock', 'quorum', 'ssh'):
        assert _one(report, kind)['status'] == 'skip'


def test_two_factor_and_the_login_backoff_have_their_own_hints():
    m = FakeMgr(is_connected=False, connection_error_code='NEEDS_2FA')
    assert conncheck.check_credentials(m)['hint'] == 'cred_needs_2fa'
    m = FakeMgr(is_connected=False, auth_blocked=(True, 240))
    item = conncheck.check_credentials(m)
    assert item['hint'] == 'cred_auth_backoff' and item['retry_in'] == 240


def test_without_ssh_no_node_is_contacted_over_ssh():
    m = FakeMgr()
    report = conncheck.run_check(m, include_ssh=False)
    assert _items(report, 'ssh') == [] and m.ssh_calls == []


# --- _ssh_connect reports why it gave up ------------------------------------------------------

def _bare_manager(**cfg):
    from pegaprox.core.manager import PegaProxManager
    mgr = PegaProxManager.__new__(PegaProxManager)
    base = dict(name='lab', host='10.0.0.1', user='root@pam', pass_='pw', ssh_user='', ssh_key='',
                ssh_port=22, ssh_disabled=False)
    base.update(cfg)
    mgr.config = types.SimpleNamespace(**base)
    import logging
    mgr.logger = logging.getLogger('conncheck-test')
    return mgr


def test_ssh_connect_names_a_refused_login_after_one_attempt(monkeypatch):
    import paramiko
    import pegaprox.core.manager as manager_mod
    attempts = []

    class _Refusing:
        def set_missing_host_key_policy(self, *a):
            pass

        def load_host_keys(self, *a):
            pass

        def connect(self, **kw):
            attempts.append(kw)
            raise paramiko.ssh_exception.AuthenticationException('Authentication failed.')

    fake = types.SimpleNamespace(SSHClient=_Refusing, ssh_exception=paramiko.ssh_exception,
                                 RSAKey=paramiko.RSAKey, Ed25519Key=paramiko.Ed25519Key,
                                 ECDSAKey=paramiko.ECDSAKey)
    import threading
    from pegaprox import globals as g
    monkeypatch.setattr(manager_mod, 'get_paramiko', lambda: fake)
    monkeypatch.setattr('pegaprox.utils.ssh_security.apply_host_key_policy', lambda c, p: None)
    monkeypatch.setattr(g, '_ssh_semaphore', threading.Semaphore(4))
    failure = {}
    assert _bare_manager()._ssh_connect('10.0.0.9', retries=1, connect_timeout=10, failure=failure) is None
    assert failure['kind'] == 'auth' and len(attempts) == 1
    assert attempts[0]['timeout'] == 10 and attempts[0]['password'] == 'pw'


def test_ssh_connect_with_a_token_secret_never_opens_a_socket(monkeypatch):
    import pegaprox.core.manager as manager_mod
    monkeypatch.setattr(manager_mod, 'get_paramiko', lambda: pytest.fail('no SSH for a token cluster'))
    failure = {}
    mgr = _bare_manager(user='ops@pve!pegaprox', pass_='token-secret-value')
    assert mgr._ssh_connect('10.0.0.9', retries=1, failure=failure) is None
    assert failure == {'kind': 'blocked', 'detail': 'SSH_NO_CREDENTIALS'}


# --- the route --------------------------------------------------------------------------------

PATH = '/api/clusters/cluster_1/connection-check'
REPORT = {'cluster_type': 'proxmox', 'connected': True, 'checked_at': 'now', 'duration_ms': 5,
          'summary': {'ok': 3, 'warn': 1, 'fail': 0, 'skip': 0}, 'items': []}


@pytest.fixture
def runs(monkeypatch):
    calls = []

    def fake_run(mgr, include_ssh=True):
        calls.append(include_ssh)
        return {**REPORT, 'summary': dict(REPORT['summary']), 'items': []}
    monkeypatch.setattr(conncheck, 'run_check', fake_run)
    return calls


def _fake(api, cid='cluster_1', cluster_type='proxmox'):
    fake = api.make_fake_manager(cluster_id=cid, cluster_type=cluster_type)
    fake.config.name = cid
    return api.set_manager(cid, fake)


def test_an_admin_runs_it_and_it_is_audited(api, seed, runs):
    from pegaprox.core.db import get_db
    admin = seed.user('root', role='admin')
    _fake(api)
    r = api.as_user(admin).post(PATH, json={})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['cluster_id'] == 'cluster_1' and body['ssh_checked'] is True and runs == [True]
    rows = get_db().query("SELECT * FROM audit_log WHERE action = 'cluster.connection_check'")
    assert rows and '3 ok, 1 warnings, 0 failed' in rows[-1]['details']


def test_ssh_false_leaves_the_logins_out(api, seed, runs):
    _fake(api)
    r = api.as_user(seed.user('root', role='admin')).post(PATH, json={'ssh': False})
    assert r.status_code == 200 and r.get_json()['ssh_checked'] is False and runs == [False]


def test_xcpng_is_told_it_is_pve_only(api, seed, runs):
    _fake(api, cluster_type='xcpng')
    r = api.as_user(seed.user('root', role='admin')).post(PATH, json={})
    assert r.status_code == 400 and r.get_json()['code'] == 'PVE_ONLY' and runs == []


def test_unknown_cluster_404(api, seed, runs):
    r = api.as_user(seed.user('root', role='admin')).post('/api/clusters/ghost/connection-check', json={})
    assert r.status_code == 404


@pytest.mark.parametrize('kind', ['user', 'viewer', 'capped_admin', 'other_tenant', 'pool_scoped'])
def test_who_may_not_run_it(api, seed, runs, kind):
    _fake(api)
    if kind == 'user':
        caller = seed.user('joe', role='user')
    elif kind == 'viewer':
        caller = seed.user('watcher', role='viewer')
    elif kind == 'capped_admin':
        seed.tenant('globex', ['cluster_globex'])
        caller = seed.user('gx', role='admin', tenant_id='globex',
                           tenant_permissions={'globex': {'role': 'user'}})
    elif kind == 'other_tenant':
        seed.tenant('acme', ['cluster_acme'])
        caller = seed.user('acmeops', role='user', tenant_id='acme', permissions=['cluster.config'])
    else:
        # reaches cluster_1 through a pool grant only: whole-cluster checks are not theirs
        seed.tenant('acme', ['cluster_acme'])
        caller = seed.user('poolops', role='user', tenant_id='acme', permissions=['cluster.config'])
        seed.pool('cluster_1', 'pool1', 'poolops', ['vm.view'])
    r = api.as_user(caller).post(PATH, json={})
    assert r.status_code == 403, (kind, r.data)
    if kind == 'pool_scoped':
        assert b'whole cluster' in r.data, r.data        # require_unconfined, not the permission
    if kind == 'other_tenant':
        assert b'Access denied to this cluster' in r.data, r.data
    assert runs == []


def test_the_other_tenant_runs_it_on_its_own_cluster(api, seed, runs):
    """The positive control of other_tenant above: the 403 came from the tenant, not the permission."""
    seed.tenant('acme', ['cluster_acme'])
    caller = seed.user('acmeops', role='user', tenant_id='acme', permissions=['cluster.config'])
    _fake(api, cid='cluster_acme')
    r = api.as_user(caller).post('/api/clusters/cluster_acme/connection-check', json={})
    assert r.status_code == 200, r.data


def test_a_standby_does_not_run_it(api, seed, runs, monkeypatch):
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha, 'forwarding', lambda: False)
    monkeypatch.setattr(ha, 'forward_writes', lambda: False)
    _fake(api)
    r = api.as_user(seed.user('root', role='admin')).post(PATH, json={})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert runs == []
