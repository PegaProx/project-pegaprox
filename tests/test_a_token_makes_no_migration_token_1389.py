"""The temporary token of a cross-cluster migration on a cluster we talk to with a token.

PVE makes and deletes an API token for the user itself, or for someone with User.Modify
on its groups, and an API token never counts as its own user. A cluster added with an API token as its login put that token id where PVE
wants a user name, and a cluster added with a password switches to a token of its own at
the first connect, after which the token of the migration got a 403. The temporary token
now goes over a password login of the account itself, and a cluster that has only a
token says what to change instead of passing on PVE's parser error. Its own token is not
handed to the source node.

Real requests: an HTTPS endpoint on loopback keeps PVE's rule for the token paths.

MK Nov 2026 (#1389)
"""
import json
import types
import uuid
from urllib.parse import parse_qs, unquote

import pytest

import pegaprox.core.manager as mgrmod
from pegaprox.models.tasks import PegaProxConfig
from tests.test_cluster_clients_follow_no_redirects import _serve, tls  # noqa: F401 - fixture by name
from tests.test_remote_migrate_slow_answer import by_hand, clock, node  # noqa: F401 - fixtures by name
from tests.test_transfer_network import _fresh_caches  # noqa: F401 - fixture by name

PASSWORD = 'pw-of-the-pegaprox-account'
TOKEN_PATH = '/api2/json/access/users/'


class FakePVE:
    """The calls of one PVE cluster: logins, the token paths and what else connect reads.

    `strong` are token ids that hold User.Modify and Permissions.Modify (root's do), `tfa`
    accounts that log in with a second factor."""

    def __init__(self, users, strong=(), tfa=()):
        self.users, self.strong, self.tfa = dict(users), set(strong), set(tfa)
        self.tokens = {}      # 'user@realm!name' -> secret
        self.tickets = {}     # ticket -> (user, csrf)
        self.seen = []        # (method, path, who, form)
        self.login_down = False   # pveproxy restarting: the login gets a 503

    def _who(self, headers):
        auth = headers.get('Authorization') or ''
        if auth.startswith('PVEAPIToken='):
            tid, _, secret = auth[len('PVEAPIToken='):].rpartition('=')
            return ('token', tid) if self.tokens.get(tid) == secret else None
        for part in (headers.get('Cookie') or '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == 'PVEAuthCookie' and unquote(v) in self.tickets:
                return ('user', self.tickets[unquote(v)])
        return None

    def answer(self, method, path, headers, body):
        form = {k: v[0] for k, v in parse_qs(body).items()}
        who = self._who(headers)
        self.seen.append((method, unquote(path), who and who[0], form))
        if path == '/api2/json/access/ticket' and method == 'POST':
            if self.login_down:
                return 503, {'data': None}
            user, pw = form.get('username'), form.get('password')
            if self.users.get(user) != pw:
                return 401, {'data': None}
            ticket, csrf = f'PVE:{user}:{uuid.uuid4().hex}', uuid.uuid4().hex
            if user in self.tfa:
                return 200, {'data': {'ticket': ticket, 'CSRFPreventionToken': csrf, 'NeedTFA': 1}}
            self.tickets[ticket] = (user, csrf)
            return 200, {'data': {'ticket': ticket, 'CSRFPreventionToken': csrf,
                                  'username': user}}
        if who is None:
            return 401, {'data': None}
        if who[0] == 'user' and method != 'GET' and headers.get('CSRFPreventionToken') != who[1][1]:
            return 401, {'data': None}
        if path.startswith(TOKEN_PATH) and '/token/' in path:
            userid, _, name = unquote(path[len(TOKEN_PATH):]).partition('/token/')
            return self._token(method, userid, name, who, form)
        return 200, {'data': []}

    def _token(self, method, userid, name, who, form):
        # PVE/API2/User.pm: the userid parameter is a user name, and
        # ['or', ['userid-param', 'self'], ['userid-group', ['User.Modify']]]
        if '!' in userid or '@' not in userid:
            return 400, {'message': f"value '{userid}' does not look like a valid user name\n",
                         'data': None}
        allowed = (who[0] == 'user' and who[1][0] == userid) or \
            (who[0] == 'token' and who[1] in self.strong)
        if not allowed:
            return 403, {'message': 'Permission check failed\n', 'data': None}
        tid = f'{userid}!{name}'
        if method == 'POST':
            if tid in self.tokens:
                return 400, {'message': f"Token already exists.\n", 'data': None}
            self.tokens[tid] = str(uuid.uuid4())
            return 200, {'data': {'full-tokenid': tid, 'value': self.tokens[tid],
                                  'info': {'privsep': form.get('privsep')}}}
        if method == 'DELETE':
            if self.tokens.pop(tid, None) is None:
                return 500, {'message': f"no such token '{name}' for user '{userid}'\n"}
            return 200, {'data': None}
        return 501, {'data': None}

    def token_calls(self):
        return [(m, p.split('/access/users/', 1)[1], who) for m, p, who, _ in self.seen
                if '/token/' in p]

    def logins(self):
        return [f['username'] for m, p, _, f in self.seen if p.endswith('/access/ticket')]


@pytest.fixture
def pve(tls, db, monkeypatch):  # noqa: F811
    monkeypatch.setattr(mgrmod, 'save_config', lambda *a, **k: None)
    servers = []

    def start(fake):
        def answer(method, path, headers=None, body=''):
            code, value = fake.answer(method, path, headers or {}, body)
            return code, {'Content-Type': 'application/json'}, json.dumps(value).encode()
        srv = _serve(answer, tls)
        servers.append(srv)
        return srv
    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


@pytest.fixture(autouse=True)
def _handler_passes_headers(monkeypatch):
    """The loopback handler of the redirect tests answers by method and path; these
    answers need the auth headers and the form too."""
    from tests import test_cluster_clients_follow_no_redirects as base

    def _any(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n).decode('utf-8', 'replace') if n else ''
        self.server.seen.append((self.command, self.path, body))
        code, headers, out = self.server.answer(self.command, self.path, self.headers, body)
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    for verb in ('GET', 'POST', 'PUT', 'DELETE'):
        monkeypatch.setattr(base._Handler, f'do_{verb}', _any)


def _cluster(port, user, pw, **extra):
    data = {'name': 'target', 'host': '127.0.0.1', 'api_port': port, 'user': user, 'pass': pw}
    data.update(extra)
    return mgrmod.PegaProxManager('c1389', PegaProxConfig(data))


def _connected(fake, start, user, pw, **extra):
    srv = start(fake)
    m = _cluster(srv.port, user, pw, **extra)
    assert m.connect_to_proxmox(), m.connection_error
    fake.seen.clear()
    return m


# --- a cluster added with a password ---------------------------------------------------------

def test_a_password_cluster_on_its_own_token_makes_the_migration_token_as_its_user(pve):
    """The reporter's second case: the cluster switched to the token minted at the first
    connect, and that token may make no other one."""
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    m = _connected(fake, pve, 'pegaprox@pve', PASSWORD)
    assert m._using_api_token and m.config.api_token_user.startswith('pegaprox@pve!pegaprox_')

    got = m.create_api_token('mig-1', expire=1893456000)

    assert got['success'], got
    assert got['token_id'] == 'pegaprox@pve!mig-1'
    assert fake.tokens['pegaprox@pve!mig-1'] == got['token_value']
    # the token we talk to it with first, then the account itself; nothing else asked
    assert fake.token_calls() == [('POST', 'pegaprox@pve/token/mig-1', 'token'),
                                  ('POST', 'pegaprox@pve/token/mig-1', 'user')]
    assert fake.logins() == ['pegaprox@pve']
    # and the cluster goes on with its own token
    assert m._using_api_token and m._ticket is None

    fake.seen.clear()
    assert m.delete_api_token('mig-1') == {'success': True}
    assert 'pegaprox@pve!mig-1' not in fake.tokens
    assert fake.token_calls() == [('DELETE', 'pegaprox@pve/token/mig-1', 'token'),
                                  ('DELETE', 'pegaprox@pve/token/mig-1', 'user')]
    # the management token is still there
    assert m.config.api_token_user in fake.tokens


def test_the_migration_token_is_made_with_what_the_caller_asked_for(pve):
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    m = _connected(fake, pve, 'pegaprox@pve', PASSWORD)
    assert m.create_api_token('mig-2', expire=1893456000)['success']
    [form] = [f for meth, p, who, f in fake.seen if p.endswith('/token/mig-2') and who == 'user']
    assert form['privsep'] == '0' and form['expire'] == '1893456000'


def test_a_token_that_holds_the_rights_makes_it_without_a_login(pve):
    """root's token (privsep 0) has User.Modify and Permissions.Modify: no password login
    for it, the way it worked before."""
    fake = FakePVE({'root@pam': PASSWORD})
    m = _connected(fake, pve, 'root@pam', PASSWORD)
    fake.strong.add(m.config.api_token_user)

    assert m.create_api_token('mig-3')['success']
    assert m.delete_api_token('mig-3') == {'success': True}
    assert fake.logins() == []
    assert [who for _, _, who in fake.token_calls()] == ['token', 'token']


def test_a_cluster_still_on_its_password_login_makes_it_at_once(pve):
    """No management token (a second instance of an HA pair never mints one): the
    session is the user itself."""
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    srv = pve(fake)
    m = _cluster(srv.port, 'pegaprox@pve', PASSWORD)
    m._try_create_api_token = lambda *a, **k: None
    assert m.connect_to_proxmox()
    assert not m._using_api_token
    fake.seen.clear()

    assert m.create_api_token('mig-4')['success']
    assert fake.token_calls() == [('POST', 'pegaprox@pve/token/mig-4', 'user')]
    assert fake.logins() == []


def test_a_stale_token_of_the_same_name_is_dropped_the_same_way(pve):
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    m = _connected(fake, pve, 'pegaprox@pve', PASSWORD)
    fake.tokens['pegaprox@pve!mig-5'] = 'left-over'

    got = m.create_api_token('mig-5')
    assert got['success'] and fake.tokens['pegaprox@pve!mig-5'] == got['token_value'] != 'left-over'


def test_an_account_with_two_factor_login_is_told_so(pve):
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    m = _connected(fake, pve, 'pegaprox@pve', PASSWORD)
    fake.tfa.add('pegaprox@pve')

    got = m.create_api_token('mig-6')
    assert got['success'] is False and got['refused'] is True
    assert 'two-factor' in got['error'] and 'pegaprox@pve' in got['error']
    assert not any(k.endswith('!mig-6') for k in fake.tokens)
    assert [who for _, _, who in fake.token_calls()] == ['token']


def test_a_stored_password_pve_refuses_is_said(pve):
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    m = _connected(fake, pve, 'pegaprox@pve', PASSWORD)
    fake.users['pegaprox@pve'] = 'changed-on-the-cluster'

    got = m.create_api_token('mig-7')
    assert got['success'] is False and got['refused'] is True
    assert 'pegaprox@pve password authentication failed (HTTP 401)' in got['error']


# --- a cluster added with an API token as its login -------------------------------------------

def test_a_token_cluster_is_told_what_to_change_and_keeps_its_token(pve):
    """The reporter's first case. The user part goes in the path, PVE refuses the token,
    and the answer says what to do. The secret is never sent as a password, and the token
    the cluster signs in with is not offered as the one of the migration."""
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    fake.tokens['pegaprox@pve!pegaprox'] = 'tok-secret'
    m = _connected(fake, pve, 'pegaprox@pve!pegaprox', 'tok-secret')

    got = m.create_api_token('mig-8')

    assert got['success'] is False and got['refused'] is True
    assert 'does not look like a valid user name' not in got['error']
    assert 'pegaprox@pve!pegaprox' in got['error'] and 'password of pegaprox@pve' in got['error']
    assert 'token_value' not in got and 'tok-secret' not in json.dumps(got)
    assert fake.token_calls() == [('POST', 'pegaprox@pve/token/mig-8', 'token')]
    assert fake.logins() == []


def test_a_strong_token_cluster_makes_it_under_the_user_part(pve):
    """A token typed in as the login that holds the rights (root@pam's) now works: before,
    its whole id went where PVE wants the user name."""
    fake = FakePVE({'root@pam': PASSWORD}, strong={'root@pam!pp'})
    fake.tokens['root@pam!pp'] = 'tok-secret'
    m = _connected(fake, pve, 'root@pam!pp', 'tok-secret')

    got = m.create_api_token('mig-9')
    assert got['success'] and got['token_id'] == 'root@pam!mig-9'
    assert m.delete_api_token('mig-9') == {'success': True}
    assert fake.token_calls() == [('POST', 'root@pam/token/mig-9', 'token'),
                                  ('DELETE', 'root@pam/token/mig-9', 'token')]


def test_a_refused_delete_of_a_token_cluster_is_said_as_well(pve):
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    fake.tokens['pegaprox@pve!pegaprox'] = 'tok-secret'
    m = _connected(fake, pve, 'pegaprox@pve!pegaprox', 'tok-secret')
    got = m.delete_api_token('mig-10')
    assert got['success'] is False and 'password of pegaprox@pve' in got['error']
    assert fake.logins() == []


# --- the migration of linked mode ---------------------------------------------------------------

def test_the_token_of_a_migration_from_another_site_goes_the_same_way(pve, monkeypatch):
    from pegaprox.core import federation_migrate as fmig
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    m = _connected(fake, pve, 'pegaprox@pve', PASSWORD)

    token = fmig._make_token(m, 'fedmig-1', 101, ['local-lvm'], ['vmbr0'])
    assert token['token_id'] == 'pegaprox@pve!fedmig-1'
    [form] = [f for meth, p, who, f in fake.seen if p.endswith('/token/fedmig-1') and who == 'user']
    assert form['privsep'] == '1'
    # the rights of the token go on over the cluster's own session
    acls = [(f['path'], who) for meth, p, who, f in fake.seen if p.endswith('/access/acl')]
    assert acls and all(who == 'token' for _, who in acls)


def test_a_token_cluster_refuses_a_migration_from_another_site_by_name(pve):
    from pegaprox.core import federation_migrate as fmig
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    fake.tokens['pegaprox@pve!pegaprox'] = 'tok-secret'
    m = _connected(fake, pve, 'pegaprox@pve!pegaprox', 'tok-secret')

    with pytest.raises(fmig.MigrationRefused) as e:
        fmig._make_token(m, 'fedmig-2', 101, ['local-lvm'], ['vmbr0'])
    assert e.value.status == 409 and 'password of pegaprox@pve' in e.value.error


# --- a login PVE refused is not sent again for every guest ----------------------------------------

def test_a_refused_login_is_not_sent_again_until_the_password_changes(pve):
    """A Site Recovery run asks once per guest, and each failed login counts on the realm's
    lockout and on a fail2ban of pveproxy."""
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    m = _connected(fake, pve, 'pegaprox@pve', PASSWORD)
    fake.users['pegaprox@pve'] = 'changed-on-the-cluster'

    first = m.create_api_token('mig-11')
    again = [m.create_api_token(f'mig-1{i}') for i in (2, 3)] + [m.delete_api_token('mig-11')]
    assert fake.logins() == ['pegaprox@pve']
    assert all(r['success'] is False and r['error'] == first['error'] for r in again)
    assert 'wrong, or its realm asks for a second factor' in first['error']

    # the password typed in again on our side: tried at once
    m.config.pass_ = 'changed-on-the-cluster'
    assert m.create_api_token('mig-14')['success']
    assert fake.logins() == ['pegaprox@pve', 'pegaprox@pve']


def test_a_login_without_an_answer_is_no_refusal(pve):
    """pveproxy restarting answers 5xx: an error a retry can clear, not a 409, and nothing
    held back for the next try."""
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    m = _connected(fake, pve, 'pegaprox@pve', PASSWORD)
    fake.login_down = True

    got = m.create_api_token('mig-15')
    assert got['success'] is False and 'refused' not in got
    assert '(HTTP 503)' in got['error']

    fake.login_down = False
    assert m.create_api_token('mig-16')['success']
    assert fake.logins() == ['pegaprox@pve', 'pegaprox@pve']


# --- removing the cluster ---------------------------------------------------------------------

def test_removing_the_cluster_takes_its_own_token_off_pve(pve, api, seed, monkeypatch):
    """The token minted at the first connect has no expire; refused to delete itself, it
    stayed on PVE after the cluster was gone from PegaProx."""
    from pegaprox.api import clusters
    import pegaprox.utils.ssh_security as ssh_security
    monkeypatch.setattr(clusters, '_retire_cluster_claim', lambda mgr: None)
    monkeypatch.setattr(ssh_security, 'remove_host_keys', lambda hosts: 0)
    fake = FakePVE({'pegaprox@pve': PASSWORD})
    m = _connected(fake, pve, 'pegaprox@pve', PASSWORD)
    own = m.config.api_token_user
    assert own in fake.tokens
    api.set_manager('c1389', m)

    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.delete('/api/clusters/c1389')

    assert r.status_code == 200, r.get_data(as_text=True)
    assert own not in fake.tokens
    assert [who for _, _, who in fake.token_calls()] == ['token', 'user']


# --- what the routes answer -------------------------------------------------------------------

def test_the_migration_by_hand_answers_a_refusal_with_409_and_starts_nothing(by_hand):
    from pegaprox import globals as g
    from tests.test_remote_migrate_slow_answer import TGT
    said = 'this cluster signs in with the API token pegaprox@pve!pegaprox only'
    g.cluster_managers[TGT].create_api_token = \
        lambda name, **kw: {'success': False, 'refused': True, 'error': said}

    r = by_hand.start()
    assert r.status_code == 409
    assert said in r.get_json()['error']
    assert by_hand.node.posts == [] and by_hand.kept == []


def test_a_token_that_was_not_made_for_another_reason_stays_a_500(by_hand):
    from pegaprox import globals as g
    from tests.test_remote_migrate_slow_answer import TGT
    g.cluster_managers[TGT].create_api_token = \
        lambda name, **kw: {'success': False, 'error': 'pegaprox@pve password authentication failed (HTTP 503)'}
    assert by_hand.start().status_code == 500
