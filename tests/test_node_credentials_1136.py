"""Root passwords of single nodes (#1136).

PegaProx logged in to every node of a cluster with the cluster's one password. A node
with a root password of its own keeps it in cluster_node_credentials now, and a password
step to that node offers it instead. What matters most is where it never goes: node B's
password to node A, to an address outside the membership, to an address the manager
could not place on exactly one node, or out through a response, a log or an audit entry.
MK Oct 2026
"""
import io
import json
import logging
import threading
import types
import zipfile
from unittest.mock import MagicMock

import pytest

from pegaprox.core import conncheck, node_creds


CID = 'cluster_1'
MEMBERS = {'pve1': {'node': 'pve1', 'status': 'online'},
           'pve2': {'node': 'pve2', 'status': 'online'},
           'pve3': {'node': 'pve3', 'status': 'offline'}}
A, B, C = '10.0.0.1', '10.0.0.2', '10.0.0.3'
PW_B = 'pve2-own-root!'
PW_C = 'pve3-own-root?'


@pytest.fixture(autouse=True)
def _fresh():
    """The module keeps short caches per cluster id; every test starts without them."""
    def clean():
        node_creds.invalidate()
        with node_creds._lock:
            node_creds._addresses.clear()
            node_creds._absent.clear()
            node_creds._swept.clear()
    clean()
    yield
    clean()


def _mgr(cid=CID, **cfg):
    """A PegaProxManager without its constructor: config, id, the members it knows."""
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    base = dict(name='lab', host=A, user='root@pam', pass_='cluster-pw', ssh_user='', ssh_key='',
                ssh_port=22, ssh_disabled=False, fallback_hosts=[B, C])
    base.update(cfg)
    m.config = types.SimpleNamespace(**base)
    m.id = cid
    m.logger = logging.getLogger('node-creds-test')
    m._cached_node_dict = dict(MEMBERS)
    m.is_connected = False          # no /cluster/status lookups behind the test's back
    m.current_host = None
    return m


def _placed(cid=CID):
    """The manager's own resolution put each member at its address."""
    for name, ip in (('pve1', A), ('pve2', B), ('pve3', C)):
        node_creds.note_address(cid, name, ip)


@pytest.fixture
def stored(db):
    db.save_node_credential(CID, 'pve2', PW_B, 'alice')
    db.save_node_credential(CID, 'pve3', PW_C, 'alice')
    return db


# --- the store --------------------------------------------------------------------------

def test_the_value_is_sealed_at_rest_and_listed_without_it(db):
    db.save_node_credential(CID, 'pve2', PW_B, 'alice')
    raw = db.conn.execute("SELECT password_encrypted FROM cluster_node_credentials").fetchone()[0]
    assert raw.startswith('aes256:') and PW_B not in raw
    rows = db.list_node_credentials(CID)
    assert rows[0]['node'] == 'pve2' and rows[0]['has_password'] is True
    assert rows[0]['updated_by'] == 'alice' and rows[0]['updated_at']
    assert 'password_encrypted' not in rows[0] and PW_B not in json.dumps(rows)
    assert db.node_credential_secrets(CID) == {'pve2': PW_B}


def test_a_new_password_drops_the_check_of_the_old_one(db):
    db.record_node_credential_checks(CID, {'pve2': ('AUTH_REFUSED', 'Authentication failed.', 'cluster')})
    assert db.list_node_credentials(CID)[0]['check_status'] == 'AUTH_REFUSED'
    db.save_node_credential(CID, 'pve2', PW_B, 'alice')
    db.set_node_credential_address(CID, 'pve2', '10.0.0.2')
    row = db.list_node_credentials(CID)[0]
    assert row['check_status'] == '' and row['checked_at'] is None and row['has_password']
    db.save_node_credential(CID, 'pve2', 'another', 'alice')
    assert db.list_node_credentials(CID)[0]['address'] == '10.0.0.2'
    db.save_node_credential(CID, 'pve2', '', 'bob')
    row = db.list_node_credentials(CID)[0]
    assert row['has_password'] is False and db.node_credential_secrets(CID) == {}
    # a password set later does not start from where the node was before the clear
    assert row['address'] == ''


def test_a_clear_during_a_read_is_not_undone_by_the_cache(stored, monkeypatch):
    """A read that began before a clear must not put the cleared password back into the
    cache for CACHE_TTL."""
    real = stored.node_credential_secrets

    def racing(cid, with_addresses=False):
        out = real(cid, with_addresses=with_addresses)
        node_creds.clear(CID, 'pve2', 'bob')            # the DELETE route lands right here
        return out
    monkeypatch.setattr(stored, 'node_credential_secrets', racing)
    assert 'pve2' in node_creds.secrets_of(CID)          # this one read began before it
    monkeypatch.setattr(stored, 'node_credential_secrets', real)
    assert node_creds.secrets_of(CID) == {'pve3': PW_C}


def test_the_rows_go_with_their_cluster(stored):
    stored.save_cluster(CID, {'name': 'lab', 'host': A, 'user': 'root@pam', 'pass': 'x'})
    stored.save_node_credential('other', 'pve2', 'not-this-one', 'alice')
    stored.delete_cluster(CID)
    assert stored.node_credential_secrets(CID) == {}
    assert stored.node_credential_secrets('other') == {'pve2': 'not-this-one'}


@pytest.mark.parametrize('value,ok', [
    ('s3cret with spaces', True), ('ü' * 256, True), ('x' * 257, False), ('', False),
    (None, False), (12345, False), (['pw'], False), ('line\nbreak', False), ('tab\there', False),
    ('nul\x00', False), ('del\x7f', False), ('sep ', False)])
def test_what_a_node_password_may_be(value, ok):
    assert (node_creds.value_problem(value) is None) is ok


# --- which password goes where ----------------------------------------------------------

def test_each_node_gets_its_own_and_the_others_the_cluster_password(stored):
    m = _mgr()
    _placed()
    assert m.ssh_password_to_offer(B) == PW_B
    assert m.ssh_password_to_offer(f'[{B}]') == PW_B          # as the URL helpers bracket it
    assert m.ssh_password_to_offer(C) == PW_C
    assert m.ssh_password_to_offer(A) == 'cluster-pw'
    assert m.ssh_password_to_offer() == 'cluster-pw'


def test_an_address_outside_the_membership_gets_nothing_extra(stored):
    m = _mgr()
    _placed()
    for host in ('10.0.0.99', 'attacker.example', ''):
        assert m.ssh_password_to_offer(host) == 'cluster-pw', host
    # a name a request might bring is no address of anybody's
    assert m.ssh_password_to_offer('pve2') == 'cluster-pw'


def test_an_address_placed_on_two_nodes_gets_nothing_extra(stored):
    m = _mgr()
    _placed()
    node_creds.note_address(CID, 'pve3', B)      # B is now claimed by pve2 and pve3
    assert m.node_for_address(B) is None
    assert m.ssh_password_to_offer(B) == 'cluster-pw'


def test_a_node_no_longer_listed_gets_nothing_extra(stored):
    m = _mgr()
    _placed()
    m._cached_node_dict = {k: v for k, v in MEMBERS.items() if k != 'pve2'}
    assert m.ssh_password_to_offer(B) == 'cluster-pw'


def test_the_book_is_per_cluster(stored):
    """A node of another cluster at the same address is no node of this one."""
    m = _mgr()
    node_creds.note_address('other', 'pve2', B)
    assert m.node_for_address(B) is None and m.ssh_password_to_offer(B) == 'cluster-pw'


def test_ssh_switched_off_offers_nothing_at_all(stored):
    m = _mgr(ssh_disabled=True)
    _placed()
    assert m.ssh_password_to_offer(B) == '' and m.ssh_blocked_reason(B) == 'SSH_DISABLED'


def test_a_token_cluster_offers_a_node_its_own_and_nothing_else(stored):
    """A per-node password is an account password, a token secret is none (#941)."""
    m = _mgr(user='ops@pve!pegaprox', pass_='token-secret')
    m._is_node_blocked = lambda n: (False, 0)
    _placed()
    assert m.ssh_password_to_offer(B) == PW_B
    assert m.ssh_password_to_offer(A) == ''
    assert m.ssh_blocked_reason(B) is None
    assert m.ssh_blocked_reason(A) == 'SSH_NO_CREDENTIALS'
    assert m.ssh_blocked_reason(node='pve2') is None
    assert m.ssh_blocked_reason(node='pve1') == 'SSH_NO_CREDENTIALS'
    assert m.ssh_blocked_reason() is None          # some node has one: ask per address
    assert m.ssh_diagnose('pve1')[0] == 'SSH_NO_CREDENTIALS'


def test_a_token_cluster_without_node_passwords_stays_blocked(db):
    m = _mgr(user='ops@pve!pegaprox', pass_='token-secret')
    assert m.ssh_blocked_reason() == 'SSH_NO_CREDENTIALS'
    assert m.ssh_blocked_reason(B) == 'SSH_NO_CREDENTIALS'


def test_the_step_swaps_in_the_own_password_and_refuses_another_nodes(stored):
    m = _mgr()
    _placed()
    assert m._step_password(B, 'cluster-pw') == PW_B
    assert m._step_password(A, PW_B) == ''              # node B's password to node A
    assert m._step_password('10.0.0.99', PW_C) == ''    # or to anybody else
    assert m._step_password(A, 'cluster-pw') == 'cluster-pw'


def test_the_sshpass_step_never_hands_node_b_password_to_node_a(stored, monkeypatch):
    import pegaprox.core.manager as manager_mod
    sent = []

    def node_cmd(argv, **kw):
        sent.append((kw.get('host'), kw.get('env', {}).get('SSHPASS')))
        return types.SimpleNamespace(returncode=0, stdout='ok', stderr='')
    monkeypatch.setattr(manager_mod, 'node_cmd', node_cmd)
    m = _mgr()
    m.ha_config = {}
    _placed()
    assert m._ssh_run_command_with_password_output(A, 'root', 'uptime', PW_B) is None
    assert sent == []
    assert m._ssh_run_command_with_password_output(B, 'root', 'uptime', 'cluster-pw') == 'ok'
    assert sent == [(B, PW_B)]


def test_ssh_connect_offers_the_password_of_the_node_it_dials(stored, monkeypatch):
    import paramiko
    import pegaprox.core.manager as manager_mod
    from pegaprox import globals as g
    tried = []

    class _Client:
        def set_missing_host_key_policy(self, *a): pass
        def load_host_keys(self, *a): pass

        def connect(self, **kw):
            tried.append((kw['hostname'], kw.get('password')))
            raise paramiko.ssh_exception.AuthenticationException('no')

    fake = types.SimpleNamespace(SSHClient=_Client, ssh_exception=paramiko.ssh_exception)
    monkeypatch.setattr(manager_mod, 'get_paramiko', lambda: fake)
    monkeypatch.setattr('pegaprox.utils.ssh_security.apply_host_key_policy', lambda c, p: None)
    monkeypatch.setattr(g, '_ssh_semaphore', threading.Semaphore(4))
    m = _mgr()
    _placed()
    for host in (A, B, C, '10.0.0.99'):
        failure = {}
        assert m._ssh_connect(host, retries=1, failure=failure) is None
        assert failure['kind'] == 'auth'
    assert tried == [(A, 'cluster-pw'), (B, PW_B), (C, PW_C), ('10.0.0.99', 'cluster-pw')]


def test_the_key_still_goes_first(stored, monkeypatch):
    """With a key stored _ssh_connect offers the key and no password at all, as before."""
    import paramiko
    import pegaprox.core.manager as manager_mod
    from pegaprox import globals as g
    seen = []

    class _Client:
        def set_missing_host_key_policy(self, *a): pass

        def connect(self, **kw):
            seen.append(kw)
            raise paramiko.ssh_exception.AuthenticationException('no')

    key = object()
    loads = types.SimpleNamespace(from_private_key=lambda f: key)
    fake = types.SimpleNamespace(SSHClient=_Client, ssh_exception=paramiko.ssh_exception,
                                 RSAKey=loads, Ed25519Key=loads, ECDSAKey=loads)
    monkeypatch.setattr(manager_mod, 'get_paramiko', lambda: fake)
    monkeypatch.setattr('pegaprox.utils.ssh_security.apply_host_key_policy', lambda c, p: None)
    monkeypatch.setattr(g, '_ssh_semaphore', threading.Semaphore(4))
    m = _mgr(ssh_key='-----BEGIN OPENSSH PRIVATE KEY-----')
    _placed()
    m._ssh_connect(B, retries=1, failure={})
    assert seen and seen[0]['pkey'] is key and 'password' not in seen[0]


def test_the_node_command_shell_out_uses_the_node_password(stored, monkeypatch):
    import pegaprox.utils.ssh as ssh_mod
    used = []
    m = _mgr()
    m._api_post = lambda *a, **k: types.SimpleNamespace(status_code=501)
    m._is_node_blocked = lambda n: (False, 0)
    m._get_node_ip = lambda n: {'pve1': A, 'pve2': B}[n]
    m._reset_node_failures = m._register_node_failure = lambda n: None
    m.current_host = A
    _placed()
    ssh_mod._node_ip_cache.clear()
    monkeypatch.setattr(ssh_mod, '_ssh_exec', lambda host, user, pw, cmd, **kw: used.append((host, pw)) or (0, '', ''))
    ssh_mod._pve_node_exec(m, 'pve2', 'true')
    ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert used == [(B, PW_B), (A, 'cluster-pw')]
    ssh_mod._node_ip_cache.clear()


def _sync_to(m, target, scp_rc=0):
    """sync_content_to_nodes pve1 -> target; what each node's shell got (host, cmd, stdin)
    and every host dialled from here."""
    log, dialled = [], []

    def connect(host, **kw):
        dialled.append(host)
        client = MagicMock()

        def exec_command(cmd, timeout=None):
            stdin = MagicMock()
            written = []
            stdin.write.side_effect = written.append
            log.append((host, cmd, written))
            out = MagicMock()
            out.channel.recv_exit_status.return_value = scp_rc if cmd.startswith(('scp ', 'IFS=')) else 0
            out.read.return_value = b''
            return stdin, out, MagicMock()
        client.exec_command.side_effect = exec_command
        client.open_sftp.side_effect = OSError('no sftp in tests')
        return client
    m.is_connected = True
    m._get_syncable_storage = lambda *a, **k: ({}, None)
    m.get_node_status = lambda: dict(MEMBERS, pve3={'status': 'online'})
    m.member_node_ip = lambda n: {'pve1': A, 'pve2': B, 'pve3': C}[n]
    m._resolve_storage_path = lambda *a, **k: '/var/lib/vz/template/iso'
    m._ssh_connect = connect
    res = m.sync_content_to_nodes('pve1', 'local', 'debian.iso', target_nodes=[target])
    return log, dialled, res


def test_the_content_sync_hands_the_source_no_password_of_a_target_with_its_own(stored):
    """The node-to-node scp runs in a shell on the source: a target with a root password of
    its own is reached with the nodes' keys there, never with its password in that shell."""
    m = _mgr()
    _placed()
    log, _relay, res = _sync_to(m, 'pve2')
    on_source = [(cmd, ''.join(w)) for host, cmd, w in log if host == A]
    scp = [cmd for cmd, _w in on_source if 'scp ' in cmd]
    assert scp and 'BatchMode=yes' in scp[0] and 'sshpass' not in scp[0], on_source
    assert not any(PW_B in w or 'cluster-pw' in w for _c, w in on_source)
    assert res[0]['success'] and res[0]['method'] == 'scp'


def test_without_node_keys_the_relay_logs_in_to_each_side_from_here(stored):
    m = _mgr()
    _placed()
    log, dialled, res = _sync_to(m, 'pve2', scp_rc=1)
    # the scp was refused, the relay dials both from here (_ssh_connect: each its own password)
    assert any('scp ' in cmd for host, cmd, _w in log if host == A)
    assert dialled[-2:] == [A, B]
    assert res[0]['success'] is False and 'sftp' in res[0]['error']


def test_a_target_on_the_cluster_password_still_gets_it_over_sshpass(db):
    db.save_node_credential(CID, 'pve3', PW_C, 'alice')     # the source side does not matter
    m = _mgr()
    _placed()
    log, _relay, _res = _sync_to(m, 'pve2')
    on_source = [(cmd, ''.join(w)) for host, cmd, w in log if host == A]
    assert any('sshpass -e' in cmd and 'cluster-pw' in w for cmd, w in on_source), on_source
    assert not any(PW_C in w for _c, w in on_source)


def test_ssh_password_to_falls_back_for_managers_without_the_method():
    from pegaprox.utils.ssh import ssh_password_to
    cfg = types.SimpleNamespace(user='root@pam', pass_='pw', ssh_disabled=False)
    assert ssh_password_to(types.SimpleNamespace(config=cfg), B) == 'pw'
    mock = MagicMock()
    mock.config = cfg
    assert ssh_password_to(mock, B) == 'pw'


def test_a_resolution_places_the_node_and_keeps_its_address(stored):
    m = _mgr()
    m._is_node_blocked = lambda n: (False, 0)
    m._reset_node_failures = m._register_node_failure = lambda n: None
    m._get_node_ip_impl = lambda n: {'pve1': A, 'pve2': B}[n]
    assert m._get_node_ip('pve2') == B and m._get_node_ip('pve1') == A
    assert m.ssh_password_to_offer(B) == PW_B
    rows = {r['node']: r for r in stored.list_node_credentials(CID)}
    # kept for the node with a password of its own only
    assert rows['pve2']['address'] == B and 'pve1' not in rows


def test_after_a_restart_the_kept_address_still_finds_the_node(stored):
    """No resolution yet (the registered host is down at start): the address the node was
    last placed at is all there is, and only for a node with a password of its own."""
    stored.set_node_credential_address(CID, 'pve2', B)
    m = _mgr()
    assert node_creds.nodes_at(CID, A) == set()
    assert m.ssh_password_to_offer(B) == PW_B and m.api_password_for(B) == PW_B
    # what the manager resolves now wins over the kept address
    node_creds.note_address(CID, 'pve3', B)
    assert m.ssh_password_to_offer(B) == PW_C


def test_a_standby_keeps_no_address(stored, monkeypatch):
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    node_creds.note_address(CID, 'pve2', B, primary=True)
    rows = {r['node']: r for r in stored.list_node_credentials(CID)}
    assert rows['pve2']['address'] in ('', None)
    # the same on the active keeps it: the counterproof
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    node_creds.note_address(CID, 'pve2', B, primary=True)
    assert {r['node']: r for r in stored.list_node_credentials(CID)}['pve2']['address'] == B


def test_connect_with_the_registered_host_down_uses_the_kept_address(stored, monkeypatch):
    import requests
    import pegaprox.core.manager as manager_mod
    stored.set_node_credential_address(CID, 'pve2', B)
    posts = []

    class _Session:
        def __init__(self):
            self.verify, self.headers, self.cookies = False, {}, MagicMock()

        def mount(self, *a, **k): pass

        def post(self, url, data=None, **kw):
            host = url.split('//')[1].split(':')[0]
            posts.append((host, data['password']))
            if host == A:
                raise requests.exceptions.ConnectionError('down')
            ok = data['password'] == PW_B
            return types.SimpleNamespace(status_code=200 if ok else 401, text='', json=lambda: {
                'data': {'ticket': 'PVE:t', 'CSRFPreventionToken': 'c'}})

    monkeypatch.setattr(manager_mod.requests, 'Session', _Session)
    monkeypatch.setattr(manager_mod.PegaProxManager, '_try_create_api_token', lambda self, *a, **k: None)
    m = manager_mod.PegaProxManager(CID, manager_mod.PegaProxConfig(
        {'name': 'lab', 'host': A, 'user': 'root@pam', 'pass': 'cluster-pw', 'fallback_hosts': [B]}))
    assert m.connect_to_proxmox() is True
    assert posts == [(A, 'cluster-pw'), (B, PW_B)]


# --- the PVE API login at a fallback host -------------------------------------------------

def test_a_fallback_host_logs_in_with_its_nodes_password(stored):
    m = _mgr()
    _placed()
    assert m.api_password_for(A) == 'cluster-pw'       # the registered host keeps the cluster's
    assert m.api_password_for(B) == PW_B
    assert m.api_password_for('10.0.0.99') == 'cluster-pw'
    for cfg in (dict(user='admin@pve'), dict(user='ops@pam!pegaprox', pass_='tok'),
                dict(ssh_user='pegaprox')):
        assert _mgr(**cfg).api_password_for(B) == _mgr(**cfg).config.pass_, cfg


def test_connect_gives_a_fallback_with_its_own_password_its_try(stored, monkeypatch):
    import pegaprox.core.manager as manager_mod
    _placed()
    posts = []

    class _Resp:
        def __init__(self, code, data=None):
            self.status_code, self._d, self.text = code, data, ''

        def json(self):
            return {'data': self._d}

    class _Session:
        def __init__(self):
            self.verify, self.headers, self.cookies = False, {}, MagicMock()

        def mount(self, *a, **k): pass

        def post(self, url, data=None, **kw):
            host = url.split('//')[1].split(':')[0]
            posts.append((host, data['password']))
            if host == B and data['password'] == PW_B:
                return _Resp(200, {'ticket': 'PVE:t', 'CSRFPreventionToken': 'c'})
            return _Resp(401)

    monkeypatch.setattr(manager_mod.requests, 'Session', _Session)
    monkeypatch.setattr(manager_mod.PegaProxManager, '_try_create_api_token', lambda self, *a, **k: None)
    m = manager_mod.PegaProxManager(CID, manager_mod.PegaProxConfig(
        {'name': 'lab', 'host': A, 'user': 'root@pam', 'pass': 'cluster-pw', 'fallback_hosts': [C, B]}))
    m._cached_node_dict = dict(MEMBERS)
    assert m.connect_to_proxmox() is True
    # the cluster password once, at the registered host; pve3 shares no password with it
    # and has its own, pve2 its own
    assert posts == [(A, 'cluster-pw'), (C, PW_C), (B, PW_B)]
    assert m.current_host == B


def test_a_refused_cluster_password_is_not_sprayed_over_the_fallbacks(db, monkeypatch):
    import pegaprox.core.manager as manager_mod
    _placed()
    posts = []

    class _Session:
        def __init__(self):
            self.verify, self.headers, self.cookies = False, {}, MagicMock()

        def mount(self, *a, **k): pass

        def post(self, url, data=None, **kw):
            posts.append(url.split('//')[1].split(':')[0])
            return types.SimpleNamespace(status_code=401, text='', json=lambda: {})

    monkeypatch.setattr(manager_mod.requests, 'Session', _Session)
    m = manager_mod.PegaProxManager(CID, manager_mod.PegaProxConfig(
        {'name': 'lab', 'host': A, 'user': 'root@pam', 'pass': 'cluster-pw', 'fallback_hosts': [B, C]}))
    assert m.connect_to_proxmox() is False
    assert posts == [A]


def test_the_console_ticket_tries_a_fallback_with_its_own_password_once(stored, monkeypatch):
    import urllib.error
    import urllib.request as ur
    from urllib.parse import parse_qs
    m = _mgr()
    m._ssl_verify = False
    _placed()
    tried = []

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps({'data': {'ticket': 'PVE:t', 'CSRFPreventionToken': 'c'}}).encode()

    def opener(req, context=None, timeout=None):
        host = req.full_url.split('//')[1].split(':')[0]
        pw = parse_qs(req.data.decode())['password'][0]
        tried.append((host, pw))
        if host == C and pw == PW_C:
            return _Resp()
        raise urllib.error.HTTPError(req.full_url, 401, 'no', {}, None)
    monkeypatch.setattr(ur, 'urlopen', opener)
    m.config.fallback_hosts = [B, C]
    assert m.mint_console_auth_ticket() == 'PVE:t'
    assert tried == [(A, 'cluster-pw'), (B, PW_B), (C, PW_C)]


# --- nodes that leave -----------------------------------------------------------------------

def test_a_node_missing_from_the_list_long_enough_loses_its_row(stored, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(node_creds, '_now', lambda: clock[0])
    names = ['pve1', 'pve3']
    assert node_creds.note_membership(CID, names) == []          # first miss: noted only
    clock[0] += node_creds.SWEEP_EVERY
    assert node_creds.note_membership(CID, ['pve1', 'pve2', 'pve3']) == []  # back again
    clock[0] += node_creds.SWEEP_EVERY
    assert node_creds.note_membership(CID, names) == []
    clock[0] += node_creds.LEAVE_GRACE
    assert node_creds.note_membership(CID, names) == ['pve2']
    assert stored.node_credential_secrets(CID) == {'pve3': PW_C}
    rows = [dict(r) for r in stored.query(
        "SELECT * FROM audit_log WHERE action = 'cluster.node_credential_removed'")]
    assert rows and 'pve2' in rows[-1]['details'] and PW_B not in json.dumps(rows)


def test_an_empty_list_is_no_reason_to_forget(stored, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(node_creds, '_now', lambda: clock[0])
    for _ in range(3):
        assert node_creds.note_membership(CID, []) == []
        clock[0] += node_creds.LEAVE_GRACE
    assert set(stored.node_credential_secrets(CID)) == {'pve2', 'pve3'}


def test_a_standby_forgets_nothing(stored, monkeypatch):
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    clock = [1000.0]
    monkeypatch.setattr(node_creds, '_now', lambda: clock[0])
    node_creds.note_membership(CID, ['pve1'])
    clock[0] += node_creds.LEAVE_GRACE + node_creds.SWEEP_EVERY
    assert node_creds.note_membership(CID, ['pve1']) == []
    assert set(stored.node_credential_secrets(CID)) == {'pve2', 'pve3'}


# --- the check ------------------------------------------------------------------------------

def test_the_check_names_the_credential_each_node_got(stored):
    m = _mgr()
    _placed()
    m._get_node_ip = lambda n: {'pve1': A, 'pve2': B}[n]
    m.ssh_diagnose = lambda n: None

    def connect(ip, failure=None, **kw):
        if ip == A:
            failure.update(kind='auth', detail='Authentication failed.')
            return None
        return MagicMock()
    m._ssh_connect = connect
    items = conncheck.check_ssh(m, [{'name': 'pve1', 'online': 1}, {'name': 'pve2', 'online': 1}])
    by = {i['node']: i for i in items}
    assert by['pve1']['code'] == 'AUTH_REFUSED' and by['pve1']['credential'] == 'cluster'
    assert by['pve2']['code'] == 'OK' and by['pve2']['credential'] == 'node'
    assert node_creds.refused(items) == ['pve1']
    node_creds.record(CID, items, ['pve1', 'pve2'])
    rows = {r['node']: r for r in stored.list_node_credentials(CID)}
    assert rows['pve1']['check_status'] == 'AUTH_REFUSED' and not rows['pve1']['has_password']
    assert rows['pve2']['check_status'] == 'OK' and rows['pve2']['check_credential'] == 'node'


def test_the_rolling_update_line_points_to_node_credentials(db):
    from pegaprox.core.manager import UpdateTask
    m = _mgr()
    m.nodes_in_maintenance = {}
    m._get_node_ip = lambda n: B
    m._ssh_connect = lambda ip, failure=None, **kw: failure.update(kind='auth') or None
    m._schedule_update_clear = lambda *a: None
    task = UpdateTask('pve2', reboot=False)
    m._perform_node_update('pve2', task)
    assert task.status == 'failed'
    assert 'Node credentials' in task.error and 'Node-Zugangsdaten' in task.error
    assert 'configure an SSH key' not in task.error


# --- the routes -----------------------------------------------------------------------------

BASE = f'/api/clusters/{CID}/node-credentials'


def _fake(api, cid=CID, cluster_type='proxmox'):
    fake = api.make_fake_manager(cluster_id=cid, cluster_type=cluster_type)
    fake.config = types.SimpleNamespace(name=cid, host=A, user='root@pam', pass_='cluster-pw', ssh_user='',
                                        ssh_key='', ssh_disabled=False, ha_enabled=False,
                                        auto_migrate=False, dry_run=False, fallback_hosts=[B, C])
    fake.nodes = dict(MEMBERS)
    fake.is_connected = True
    fake.running, fake.connection_error, fake.last_run, fake.current_host = True, None, None, A
    return api.set_manager(cid, fake)


@pytest.fixture
def admin(seed):
    return seed.user('root', role='admin')


def _audit(db, action):
    return [dict(r) for r in db.query("SELECT * FROM audit_log WHERE action = ?", (action,))]


def test_set_list_and_clear_never_show_the_value(api, seed, admin, db):
    _fake(api)
    c = api.as_user(admin)
    r = c.put(f'{BASE}/pve2', json={'password': PW_B})
    assert r.status_code == 200 and r.get_json() == {'success': True, 'node': 'pve2', 'has_password': True}
    assert db.node_credential_secrets(CID) == {'pve2': PW_B}

    r = c.get(BASE)
    assert r.status_code == 200
    body = r.get_json()
    assert PW_B not in r.get_data(as_text=True)
    nodes = {n['node']: n for n in body['nodes']}
    assert set(nodes) == {'pve1', 'pve2', 'pve3'}
    assert nodes['pve2']['has_password'] is True and nodes['pve2']['updated_by'] == 'root'
    assert nodes['pve1']['has_password'] is False and nodes['pve1']['updated_by'] is None
    assert nodes['pve3']['online'] is False and nodes['pve2']['member'] is True
    assert body['cluster_password'] is True and body['token_auth'] is False

    set_rows = _audit(db, 'cluster.node_credential_set')
    assert set_rows and 'pve2' in set_rows[-1]['details']

    r = c.delete(f'{BASE}/pve2')
    assert r.status_code == 200 and r.get_json()['has_password'] is False
    assert db.node_credential_secrets(CID) == {}
    assert c.delete(f'{BASE}/pve2').status_code == 404
    assert _audit(db, 'cluster.node_credential_cleared')
    every = [dict(r) for r in db.query("SELECT details FROM audit_log")]
    assert PW_B not in json.dumps(every)


def test_the_value_stays_out_of_the_logs(api, seed, admin, caplog):
    _fake(api)
    with caplog.at_level(logging.DEBUG):
        assert api.as_user(admin).put(f'{BASE}/pve2', json={'password': PW_B}).status_code == 200
    assert PW_B not in caplog.text


def test_the_value_stays_out_of_the_support_bundle(api, seed, admin):
    _fake(api)
    c = api.as_user(admin)
    assert c.put(f'{BASE}/pve2', json={'password': PW_B}).status_code == 200
    r = c.get('/api/support-bundle')
    assert r.status_code == 200, r.data[:300]
    with zipfile.ZipFile(io.BytesIO(r.data)) as zf:
        for name in zf.namelist():
            assert PW_B.encode() not in zf.read(name), name


@pytest.mark.parametrize('body,code', [
    ('not json', 400), ([1, 2], 400), ({}, 400), ({'password': ''}, 400), ({'password': 5}, 400),
    ({'password': 'x' * 257}, 400), ({'password': 'a\nb'}, 400), ({'password': None}, 400)])
def test_a_malformed_body_is_a_400(api, seed, admin, body, code):
    _fake(api)
    c = api.as_user(admin)
    if isinstance(body, str):
        r = c.put(f'{BASE}/pve2', data=body, content_type='application/json')
    else:
        r = c.put(f'{BASE}/pve2', json=body)
    assert r.status_code == code, r.data


def test_only_a_member_gets_a_password(api, seed, admin, db):
    fake = _fake(api)
    c = api.as_user(admin)
    assert c.put(f'{BASE}/pve9', json={'password': 'x'}).status_code == 404
    assert c.put(f'{BASE}/bad%20name', json={'password': 'x'}).status_code == 400
    fake.nodes = {}
    assert c.put(f'{BASE}/pve2', json={'password': 'x'}).status_code == 503
    assert db.node_credential_secrets(CID) == {}


def test_xcpng_has_no_node_credentials(api, seed, admin):
    _fake(api, cluster_type='xcpng')
    r = api.as_user(admin).get(BASE)
    assert r.status_code == 400 and r.get_json()['code'] == 'PVE_ONLY'


def test_the_check_route_names_who_refused(api, seed, admin, db, monkeypatch):
    _fake(api)
    status_nodes = [{'type': 'node', 'name': 'pve1', 'online': 1}, {'type': 'node', 'name': 'pve2', 'online': 1}]
    monkeypatch.setattr(conncheck, '_cluster_status', lambda mgr: (None, status_nodes))
    monkeypatch.setattr(conncheck, 'check_ssh', lambda mgr, nodes: [
        {'kind': 'ssh', 'id': 'ssh:pve1', 'node': 'pve1', 'status': 'fail', 'code': 'AUTH_REFUSED',
         'credential': 'cluster', 'detail': 'Authentication failed.'},
        {'kind': 'ssh', 'id': 'ssh:pve2', 'node': 'pve2', 'status': 'ok', 'code': 'OK', 'credential': 'node'}])
    c = api.as_user(admin)
    r = c.post(f'{BASE}/check', json={})
    assert r.status_code == 200, r.data
    assert r.get_json()['refused'] == ['pve1'] and r.get_json()['checked'] == ['pve1', 'pve2']
    nodes = {n['node']: n for n in c.get(BASE).get_json()['nodes']}
    assert nodes['pve1']['last_check']['code'] == 'AUTH_REFUSED'
    assert nodes['pve2']['last_check']['credential'] == 'node'
    rows = _audit(db, 'cluster.node_credential_check')
    assert rows and 'refused by pve1' in rows[-1]['details']
    assert c.post(f'{BASE}/check', json={'nodes': 'pve1'}).status_code == 400
    assert c.post(f'{BASE}/check', json={'nodes': ['ok', 'b a d']}).status_code == 400


def test_the_check_wants_a_connected_cluster(api, seed, admin):
    fake = _fake(api)
    fake.is_connected = False
    r = api.as_user(admin).post(f'{BASE}/check', json={})
    assert r.status_code == 409 and r.get_json()['code'] == 'NOT_CONNECTED'


ROUTES = [('get', BASE, None), ('put', f'{BASE}/pve2', {'password': 'x'}),
          ('delete', f'{BASE}/pve2', None), ('post', f'{BASE}/check', {})]


@pytest.mark.parametrize('method,path,body', ROUTES, ids=[r[0] for r in ROUTES])
@pytest.mark.parametrize('kind', ['user', 'viewer', 'capped_admin', 'other_tenant', 'pool_scoped'])
def test_who_may_not_see_or_set_them(api, seed, db, method, path, body, kind):
    _fake(api)
    db.save_node_credential(CID, 'pve2', PW_B, 'alice')
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
        seed.tenant('acme', ['cluster_acme'])
        caller = seed.user('poolops', role='user', tenant_id='acme', permissions=['cluster.config'])
        seed.pool(CID, 'pool1', 'poolops', ['vm.view'])
    c = api.as_user(caller)
    r = getattr(c, method)(path, **({'json': body} if body is not None else {}))
    assert r.status_code == 403, (kind, r.data)
    assert PW_B not in r.get_data(as_text=True)
    assert db.node_credential_secrets(CID) == {'pve2': PW_B}


def test_the_other_tenant_manages_its_own_cluster(api, seed, db):
    """The positive control: the 403 above came from the tenant, not the permission."""
    seed.tenant('acme', ['cluster_acme'])
    caller = seed.user('acmeops', role='user', tenant_id='acme', permissions=['cluster.config'])
    _fake(api, cid='cluster_acme')
    c = api.as_user(caller)
    assert c.put('/api/clusters/cluster_acme/node-credentials/pve2', json={'password': 'x'}).status_code == 200
    assert c.get('/api/clusters/cluster_acme/node-credentials').status_code == 200


@pytest.mark.parametrize('method,path,body', ROUTES[1:], ids=[r[0] for r in ROUTES[1:]])
def test_a_standby_does_not_change_them(api, seed, admin, db, monkeypatch, method, path, body):
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha, 'forwarding', lambda: False)
    monkeypatch.setattr(ha, 'forward_writes', lambda: False)
    _fake(api)
    db.save_node_credential(CID, 'pve2', PW_B, 'alice')
    r = getattr(api.as_user(admin), method)(path, json=body)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert db.node_credential_secrets(CID) == {'pve2': PW_B}


def test_the_connection_check_keeps_what_each_node_said(api, seed, admin, db, monkeypatch):
    _fake(api)
    monkeypatch.setattr(conncheck, 'run_check', lambda mgr, include_ssh=True: {
        'cluster_type': 'proxmox', 'connected': True, 'checked_at': 'now', 'duration_ms': 1,
        'summary': {'ok': 1, 'warn': 0, 'fail': 1, 'skip': 0},
        'items': [{'kind': 'ssh', 'id': 'ssh:pve2', 'node': 'pve2', 'status': 'fail',
                   'code': 'AUTH_REFUSED', 'credential': 'cluster'}]})
    r = api.as_user(admin).post(f'/api/clusters/{CID}/connection-check', json={})
    assert r.status_code == 200 and r.get_json()['refused'] == ['pve2']
    assert db.list_node_credentials(CID)[0]['check_status'] == 'AUTH_REFUSED'


def test_adding_a_cluster_starts_one_check_in_the_background(api, seed, admin, monkeypatch):
    import pegaprox.api.clusters as clusters_api
    started = []
    monkeypatch.setattr(node_creds, 'check_in_background', lambda cid, delay=5.0: started.append(cid))

    class _Mgr:
        cluster_type = 'proxmox'
        _token_auto_created = False

        def __init__(self, cid, config):
            self.id, self.config = cid, config

        def connect_to_proxmox(self):
            return True

        def start(self):
            pass

    monkeypatch.setattr(clusters_api, 'PegaProxManager', _Mgr)
    monkeypatch.setattr(clusters_api, 'save_config', lambda: None)
    r = api.as_user(admin).post('/api/clusters', json={'name': 'new', 'host': A, 'user': 'root@pam',
                                                       'pass': 'pw'})
    assert r.status_code == 201, r.data
    assert started == [r.get_json()['id']] and r.get_json()['node_check'] is True


# --- an edit that points the cluster elsewhere ------------------------------------------------
# The cluster password has to be typed again for such an edit, and a stored secret nobody
# re-entered is dropped (_config_edit_checks). The nodes' own passwords are such secrets: they
# go wherever the cluster then says its nodes are.

def _endpoint_fake(api, **cfg):
    fake = _fake(api)
    base = dict(vars(fake.config), ssh_port=22, ssl_verification=False, api_token_user='',
                api_token_secret='')
    base.update(cfg)
    fake.config = types.SimpleNamespace(**base)
    return fake


@pytest.mark.parametrize('method,path,body,cfg', [
    ('put', f'/api/clusters/{CID}', {'host': '192.0.2.50', 'pass': 'cluster-pw'}, {}),
    ('patch', f'/api/clusters/{CID}/config', {'ssh_port': 2222, 'pass': 'cluster-pw'}, {}),
    ('patch', f'/api/clusters/{CID}/config', {'ssl_verification': False, 'pass': 'cluster-pw'},
     {'ssl_verification': True}),
    ('put', f'/api/clusters/{CID}/fallback-hosts',
     {'fallback_hosts': [B, '192.0.2.51'], 'pass': 'cluster-pw'}, {}),
], ids=['host', 'ssh_port', 'ssl_verification', 'fallback_hosts_route'])
def test_moving_the_endpoint_clears_the_node_passwords(api, seed, admin, db, monkeypatch,
                                                       method, path, body, cfg):
    import pegaprox.api.clusters as clusters_api
    monkeypatch.setattr(clusters_api, 'save_config', lambda: None)
    _endpoint_fake(api, **cfg)
    db.save_node_credential(CID, 'pve2', PW_B, 'alice')
    db.save_node_credential(CID, 'pve3', PW_C, 'alice')
    db.set_node_credential_address(CID, 'pve2', B)
    _placed()

    r = getattr(api.as_user(admin), method)(path, json=body)

    assert r.status_code == 200, r.data
    assert r.get_json()['node_passwords_cleared'] == ['pve2', 'pve3']
    assert db.node_credential_secrets(CID) == {}
    rows = {row['node']: row for row in db.list_node_credentials(CID)}
    assert rows['pve2']['address'] in ('', None) and rows['pve2']['updated_by'] == 'root'
    # what the manager placed where came from the old endpoint
    assert node_creds.nodes_at(CID, B) == set()
    removed = _audit(db, 'cluster.node_credential_removed')
    assert removed and 'pve2, pve3' in removed[-1]['details']
    every = json.dumps([dict(x) for x in db.query("SELECT details FROM audit_log")])
    assert PW_B not in every and PW_C not in every


@pytest.mark.parametrize('body', [
    {'host': B, 'pass': 'cluster-pw'},              # an address it already went to
    {'migration_threshold': 40},
    {'fallback_hosts': [C]},
], ids=['known-host', 'no-endpoint-field', 'fewer-fallbacks'])
def test_an_edit_that_moves_nothing_keeps_them(api, seed, admin, db, monkeypatch, body):
    import pegaprox.api.clusters as clusters_api
    monkeypatch.setattr(clusters_api, 'save_config', lambda: None)
    _endpoint_fake(api, migration_threshold=30)
    db.save_node_credential(CID, 'pve2', PW_B, 'alice')

    r = api.as_user(admin).put(f'/api/clusters/{CID}', json=body)

    assert r.status_code == 200, r.data
    assert 'node_passwords_cleared' not in r.get_json()
    assert db.node_credential_secrets(CID) == {'pve2': PW_B}
    assert not _audit(db, 'cluster.node_credential_removed')


def test_a_move_without_the_cluster_password_changes_nothing(api, seed, admin, db):
    _endpoint_fake(api)
    db.save_node_credential(CID, 'pve2', PW_B, 'alice')
    r = api.as_user(admin).put(f'/api/clusters/{CID}', json={'host': '192.0.2.50'})
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED'
    assert db.node_credential_secrets(CID) == {'pve2': PW_B}


class _OldMgr:
    cluster_type = 'proxmox'

    def __init__(self, **cfg):
        base = dict(name='lab', host=A, user='root@pam', pass_='cluster-pw', ssh_user='', ssh_key='',
                    ssh_port=22, ssl_verification=False, fallback_hosts=[B, C], ha_settings={})
        base.update(cfg)
        self.config = types.SimpleNamespace(**base)

    def stop(self):
        pass


@pytest.fixture
def reconfigure(api, seed, db, monkeypatch):
    """POST /reconfigure as the dialog sends it, the new manager stubbed."""
    import pegaprox.api.clusters as clusters_api
    from test_ha_api import _admin, ADMIN_PW

    class _NewMgr:
        cluster_type = 'proxmox'
        _token_auto_created = False

        def __init__(self, cid, config):
            self.id, self.config = cid, config

        def connect_to_proxmox(self):
            return True

        def start(self):
            pass

    monkeypatch.setattr(clusters_api, 'PegaProxManager', _NewMgr)
    monkeypatch.setattr(clusters_api, 'save_config', lambda: None)
    api.set_manager(CID, _OldMgr())
    db.save_node_credential(CID, 'pve2', PW_B, 'alice')
    client = _admin(api, seed)

    def send(**body):
        dialog = {'current_password': ADMIN_PW, 'name': 'lab', 'host': A, 'user': 'root@pam',
                  'pass': 'new-cluster-pw', 'fallback_hosts': [B, C], 'ssh_port': 22,
                  'ssl_verification': False}
        dialog.update(body)
        return client.post(f'/api/clusters/{CID}/reconfigure', json=dialog)
    return send


@pytest.mark.parametrize('body', [{'host': '192.0.2.50'}, {'fallback_hosts': [B, '192.0.2.51']},
                                  {'ssh_port': 2222}],
                         ids=['host', 'fallback_hosts', 'ssh_port'])
def test_re_configure_to_another_endpoint_clears_them(reconfigure, db, body):
    r = reconfigure(**body)
    assert r.status_code == 200, r.data
    assert r.get_json()['node_passwords_cleared'] == ['pve2']
    assert db.node_credential_secrets(CID) == {}
    assert _audit(db, 'cluster.node_credential_removed')


@pytest.mark.parametrize('body', [{}, {'host': B}, {'fallback_hosts': [C]}],
                         ids=['same', 'a-known-host', 'fewer-fallbacks'])
def test_re_configure_at_the_same_endpoint_keeps_them(reconfigure, db, body):
    r = reconfigure(**body)
    assert r.status_code == 200, r.data
    assert 'node_passwords_cleared' not in r.get_json()
    assert db.node_credential_secrets(CID) == {'pve2': PW_B}


def test_a_failed_read_of_the_passwords_is_not_kept(monkeypatch):
    """A read that failed is no answer: the next call asks again instead of serving 'none'
    for the length of the cache."""
    import pegaprox.core.db as dbmod
    calls = []

    class _Db:
        def node_credential_secrets(self, cluster_id, with_addresses=False):
            calls.append(cluster_id)
            if len(calls) == 1:
                raise RuntimeError('database is locked')
            return {'pve2': 'own-pw'}, {'pve2': '10.0.0.2'}
    monkeypatch.setattr(dbmod, 'get_db', lambda: _Db())
    assert node_creds._loaded(CID) == ({}, {})
    assert node_creds._loaded(CID) == ({'pve2': 'own-pw'}, {'pve2': '10.0.0.2'})
    assert len(calls) == 2
