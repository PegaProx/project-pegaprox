"""The API tokens PegaProx makes on a cluster with a Proxmox VE 9.3 API token policy.

PVE 9.3 can hold a datacenter API token policy (datacenter.cfg 'token-policy'): an expire
on every new token, a longest lifetime, privilege separation. It refuses a token that does
not fit with a 500 before it makes one. PegaProx asked for every temporary migration token
to last eight days, so a policy of a week or less stopped every cross-cluster move, and it
made the management token of the first connect without an expire, so a policy that wants
one left the cluster on password logins with a line at debug level. A management token
that ran out (an expire the policy gave it) stayed in the config, was tried first on every
connect and never replaced, and an account with two-factor login was told nothing about
it. The 'Rotate API Token' button sent a POST to the token it has, which PVE 9.2 and later
answer with "Token already exists", and on older PVE deleted the token the session signs
in with before it tried a new one.

Now the policy is read from GET /cluster/options before a token is made: the expire stays
within its lifetime on PVE's clock, a policy that wants privilege separation gets no token
and says why, a management token of ours PVE refuses with a 401 is replaced once the
password login works, and the rotation renews the secret in place (PUT regenerate=1) or
makes the new token before the old one goes, with the session on the new secret at once.

Real requests: an HTTPS endpoint on loopback keeps PVE's rules for the token paths and
the policy as pve-access-control's assert_token_policy has it.

MK Nov 2026
"""
import logging
import time
import uuid
from types import SimpleNamespace

import pytest

from pegaprox.core import transfer_net
from pegaprox.core.manager import token_policy_of
from tests.test_a_token_makes_no_migration_token_1389 import (  # noqa: F401 - fixtures by name
    PASSWORD, FakePVE, _cluster, _handler_passes_headers, pve)
from tests.test_cluster_clients_follow_no_redirects import tls  # noqa: F401 - fixture by name
from tests.test_transfer_network import _fresh_caches  # noqa: F401 - fixture by name

USER = 'pegaprox@pve'
DAY = 86400


class PolicyPVE(FakePVE):
    """FakePVE with the token policy, the expire of a token and the renewal of its secret
    of PVE 9.3 (pve-access-control AccessControl.pm assert_token_policy, User.pm)."""

    def __init__(self, users, policy=None, release='9.3', regenerate=True, **kw):
        super().__init__(users, **kw)
        self.policy = dict(policy or {})
        self.release, self.regenerate = release, regenerate
        self.expires = {}     # token id -> its expire, 0 for none
        self.forms = {}       # token id -> the form it was made with

    def _who(self, headers):
        who = super()._who(headers)
        # verify_token: "token '...' access expired" is a 401 like any other refusal
        if who and who[0] == 'token' and 0 < self.expires.get(who[1], 0) < time.time():
            return None
        return who

    def answer(self, method, path, headers, body):
        code, value = super().answer(method, path, headers, body)
        if code == 200 and method == 'GET' and path == '/api2/json/cluster/options':
            return 200, {'data': {'token-policy': dict(self.policy)} if self.policy else {}}
        if code == 200 and method == 'GET' and path == '/api2/json/version':
            return 200, {'data': {'version': f'{self.release}.0', 'release': self.release}}
        return code, value

    def _refused(self, form):
        """assert_token_policy for a new token: (reason or None, the expire it gets)."""
        p = self.policy
        expire = int(form.get('expire') or 0)
        life = p.get('max-lifetime')
        if not expire and p.get('default-to-max-lifetime') and life:
            expire = int(time.time()) + life
        if (p.get('require-expiry') or life) and not expire:
            return 'the datacenter token policy requires an expiration date', expire
        if life and expire > time.time() + life:
            return (f'the expiration date exceeds the maximum token lifetime of {life} seconds '
                    f'set by the datacenter token policy'), expire
        if p.get('require-privilege-separation') and not int(form.get('privsep', 1)):
            return 'the datacenter token policy requires privilege separation', expire
        return None, expire

    def _token(self, method, userid, name, who, form):
        tid = f'{userid}!{name}'
        mine = (who[0] == 'user' and who[1][0] == userid) or \
            (who[0] == 'token' and who[1] in self.strong)
        if method == 'PUT':
            if not self.regenerate:
                # update_token_info before the regenerate parameter: additionalProperties 0
                return 400, {'message': 'Parameter verification failed.\n', 'data': None,
                             'errors': {'regenerate': 'property is not defined in schema and '
                                                      'the schema does not allow additional '
                                                      'properties'}}
            # 0f7428412e: a new secret over a token wants Permissions.Modify on /
            if not mine:
                return 403, {'message': 'Permission check failed\n', 'data': None}
            if tid not in self.tokens:
                return 500, {'message': f"no such token '{name}' for user '{userid}'\n"}
            self.tokens[tid] = str(uuid.uuid4())
            return 200, {'data': {'value': self.tokens[tid], 'full-tokenid': tid,
                                  'expire': self.expires.get(tid, 0)}}
        if method == 'POST' and mine and tid not in self.tokens:
            why, expire = self._refused(form)
            if why:
                return 500, {'message': f"generating token failed: error with cfs lock "
                                        f"'file-user_cfg': {why}\n", 'data': None}
            code, value = super()._token(method, userid, name, who, form)
            self.expires[tid], self.forms[tid] = expire, dict(form)
            value['data']['info'] = {'expire': expire, 'privsep': form.get('privsep')}
            return code, value
        return super()._token(method, userid, name, who, form)

    def posts(self):
        return [p.split('/token/', 1)[1] for m, p, _w in self.token_calls() if m == 'POST']


class _Said(logging.Handler):
    """The records of a manager's logger, which does not reach the root logger."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def at(self, level):
        return [r.getMessage() for r in self.records if r.levelno == level]


def _connect(fake, start, said=None):
    srv = start(fake)
    m = _cluster(srv.port, USER, PASSWORD)
    if said is not None:
        m.logger.addHandler(said)
    assert m.connect_to_proxmox(), m.connection_error
    return m


# --- the temporary token of a migration ------------------------------------------------------

def test_the_migration_token_ends_within_the_lifetime_the_policy_allows(pve):
    fake = PolicyPVE({USER: PASSWORD}, policy={'max-lifetime': DAY})
    said = _Said()
    m = _connect(fake, pve, said)
    asked = transfer_net.token_expiry()
    assert asked > time.time() + 7 * DAY

    got = m.create_api_token('mig-1', expire=asked)

    assert got['success'], got
    expire = fake.expires[got['token_id']]
    assert time.time() + DAY - 300 < expire <= time.time() + DAY
    # a migration that runs longer loses the target: said where an operator looks
    assert any('loses its access' in s for s in said.at(logging.WARNING))


def test_a_migration_token_that_ran_out_is_still_deleted_after_its_task(pve):
    """A token the policy cut short can end before its task does. PVE keeps it until it
    is deleted (User.pm remove_token asks only whether it is there), and the delete goes
    over the cluster's own login, so the cleanup takes it as before."""
    fake = PolicyPVE({USER: PASSWORD}, policy={'max-lifetime': DAY})
    m = _connect(fake, pve)
    got = m.create_api_token('mig-3', expire=transfer_net.token_expiry())
    fake.expires[got['token_id']] = time.time() - 1

    assert m.delete_api_token('mig-3') == {'success': True}
    assert got['token_id'] not in fake.tokens


def test_a_policy_that_wants_privilege_separation_refuses_the_migration_token_up_front(pve):
    fake = PolicyPVE({USER: PASSWORD}, policy={'require-privilege-separation': 1})
    m = _connect(fake, pve)
    fake.seen.clear()

    got = m.create_api_token('mig-2', expire=transfer_net.token_expiry())

    assert got['success'] is False and got['refused'] is True
    assert 'Require Privilege Separation' in got['error'] and 'API Token Policy' in got['error']
    assert fake.posts() == []


# --- the management token of the first connect -----------------------------------------------

@pytest.mark.parametrize('policy,life', [
    ({'max-lifetime': 30 * DAY}, 30 * DAY),
    ({'max-lifetime': 30 * DAY, 'default-to-max-lifetime': 1}, 30 * DAY),
    ({'require-expiry': 1}, 365 * DAY),
], ids=['max-lifetime', 'default-to-max', 'require-expiry'])
def test_the_management_token_gets_an_end_the_policy_takes(pve, policy, life):
    fake = PolicyPVE({USER: PASSWORD}, policy=policy)
    m = _connect(fake, pve)

    tid = m.config.api_token_user
    assert m._using_api_token and tid.startswith(f'{USER}!pegaprox_') and tid in fake.tokens
    assert fake.forms[tid]['privsep'] == '0'
    assert time.time() + life - 300 < fake.expires[tid] <= time.time() + life


def test_a_policy_that_wants_privilege_separation_gets_no_management_token_and_says_so(pve):
    fake = PolicyPVE({USER: PASSWORD}, policy={'require-privilege-separation': 1})
    said = _Said()
    m = _connect(fake, pve, said)

    assert not m.config.api_token_user and not m._using_api_token and m._ticket
    assert fake.posts() == []
    assert any('privilege separation' in s for s in said.at(logging.WARNING))


def test_a_management_token_pve_refuses_is_said_at_warning(pve):
    """An answer the policy reading did not see coming (a policy set in between)."""
    fake = PolicyPVE({USER: PASSWORD})
    srv = pve(fake)
    m = _cluster(srv.port, USER, PASSWORD)
    said = _Said()
    m.logger.addHandler(said)
    real = fake._refused
    fake._refused = lambda form: ('the datacenter token policy requires an expiration date',
                                  real(form)[1])

    assert m.connect_to_proxmox()

    assert not m.config.api_token_user
    assert any('requires an expiration date' in s for s in said.at(logging.WARNING))


# --- a management token that ran out ---------------------------------------------------------

@pytest.fixture
def stored(api, monkeypatch):
    """The cluster in the registry, and save_config writing its row for real."""
    import pegaprox.core.manager as mgrmod
    from pegaprox.core import config
    monkeypatch.setattr(mgrmod, 'save_config', config.save_config)

    def register(fake, start):
        m = api.set_manager('c1389', _cluster(start(fake).port, USER, PASSWORD))
        assert m.connect_to_proxmox(), m.connection_error
        return m
    return register


def test_a_management_token_that_ran_out_is_replaced_once_the_password_login_works(pve, stored, db):
    fake = PolicyPVE({USER: PASSWORD}, policy={'max-lifetime': 30 * DAY})
    m = stored(fake, pve)
    old = m.config.api_token_user
    assert old and db.get_cluster('c1389')['api_token_user'] == old
    fake.expires[old] = time.time() - 1     # its 30 days are over
    fake.seen.clear()

    assert m.connect_to_proxmox(), m.connection_error

    new = m.config.api_token_user
    assert new and new != old and new.startswith(f'{USER}!pegaprox_')
    assert m._using_api_token and m._api_token == f'{new}={fake.tokens[new]}'
    # stored the way the first one was, and the dead one is gone from PVE
    row = db.get_cluster('c1389')
    assert (row['api_token_user'], row['api_token_secret']) == (new, fake.tokens[new])
    assert old not in fake.tokens
    assert time.time() + 30 * DAY - 300 < fake.expires[new] <= time.time() + 30 * DAY


def test_a_request_the_dead_token_still_had_out_does_not_cost_the_new_one(pve, stored):
    """The pollers keep asking with the dead token while the connect logs in, and each 401
    they get empties the manager's ticket (_api_get). The new token is made with the
    ticket of the login itself."""
    fake = PolicyPVE({USER: PASSWORD}, policy={'max-lifetime': 30 * DAY})
    m = stored(fake, pve)
    old = m.config.api_token_user
    fake.expires[old] = time.time() - 1
    real = m._auto_discover_fallback_hosts

    def meanwhile():
        m._ticket = m._csrf_token = None    # what a 401 of a poller does
        real()
    m._auto_discover_fallback_hosts = meanwhile
    m.config.fallback_hosts = []

    assert m.connect_to_proxmox(), m.connection_error
    assert m.config.api_token_user not in ('', old) and old not in fake.tokens


def test_a_dead_token_leaves_the_config_also_where_no_new_one_may_be_made(pve, stored, db):
    fake = PolicyPVE({USER: PASSWORD}, policy={'max-lifetime': 30 * DAY})
    m = stored(fake, pve)
    old = m.config.api_token_user
    fake.expires[old] = time.time() - 1
    fake.policy['require-privilege-separation'] = 1

    assert m.connect_to_proxmox(), m.connection_error

    assert not m.config.api_token_user and not m._using_api_token and m._ticket
    assert not db.get_cluster('c1389')['api_token_user']
    assert old not in fake.tokens
    # tried first no more on the next connect
    fake.seen.clear()
    assert m.connect_to_proxmox()
    assert [p for meth, p, who, _f in fake.seen if who == 'token'] == []


def test_an_account_with_two_factor_login_is_told_its_token_ran_out(pve):
    fake = PolicyPVE({USER: PASSWORD}, policy={'max-lifetime': 30 * DAY})
    m = _connect(fake, pve)
    old = m.config.api_token_user
    fake.expires[old] = time.time() - 1
    fake.tfa.add(USER)
    fake.seen.clear()

    assert m.connect_to_proxmox() is False

    assert m.connection_error_code == 'NEEDS_2FA'
    assert old in m.connection_error and 'expired' in m.connection_error
    assert 'two-factor' in m.connection_error and 'Reconfigure' in m.connection_error
    assert fake.tokens[old] not in m.connection_error
    assert fake.posts() == []


def _poll(m, times=12):
    """What the pollers get, one request after the other."""
    url = f'https://127.0.0.1:{m.api_port}/api2/json/nodes'
    return [m._api_get(url).status_code for _ in range(times)]


def test_a_management_token_that_runs_out_while_pegaprox_runs_is_replaced_at_its_first_401(
        pve, stored, db):
    """Nothing connects anew when the token runs out under way: the pollers got 401s,
    and the auth breaker blocked the connect that would replace the token for half an
    hour. The first 401 of our own token has the password login make a new one now."""
    fake = PolicyPVE({USER: PASSWORD}, policy={'max-lifetime': 30 * DAY})
    m = stored(fake, pve)
    old = m.config.api_token_user
    assert m._using_api_token and m._api_token.startswith(f'{old}=')
    fake.expires[old] = time.time() - 1     # its 30 days are over
    fake.seen.clear()

    got = _poll(m)

    assert got[0] == 401 and set(got[1:]) == {200}
    new = m.config.api_token_user
    assert new not in ('', old) and old not in fake.tokens
    assert db.get_cluster('c1389')['api_token_user'] == new
    assert m._is_auth_blocked() == (False, 0) and m._auth_failures == 0
    assert fake.logins() == [USER]


def test_a_request_still_out_with_the_dead_token_costs_the_new_login_nothing(pve, stored):
    fake = PolicyPVE({USER: PASSWORD}, policy={'max-lifetime': 30 * DAY})
    m = stored(fake, pve)
    old, secret = m.config.api_token_user, m.config.api_token_secret
    fake.expires[old] = time.time() - 1
    assert _poll(m, 1) == [401]
    now_on = m._api_token
    assert m.config.api_token_user != old and now_on.startswith(f'{m.config.api_token_user}=')

    # the 401 of a poller that sent its request with the dead token before
    m._auth_refused(SimpleNamespace(headers={'Authorization': f'PVEAPIToken={old}={secret}'}))

    assert m._api_token == now_on and m._auth_failures == 0
    assert _poll(m, 1) == [200]


def test_a_password_pve_refuses_then_arms_the_auth_breaker_as_before(pve, stored):
    fake = PolicyPVE({USER: PASSWORD}, policy={'max-lifetime': 30 * DAY})
    m = stored(fake, pve)
    old = m.config.api_token_user
    fake.expires[old] = time.time() - 1
    fake.users[USER] = 'changed on the cluster'
    fake.seen.clear()

    got = _poll(m)

    assert set(got) == {401}
    # one login, then #444: the 30 minutes after ten 401s
    assert fake.logins() == [USER]
    blocked, left = m._is_auth_blocked()
    assert blocked and left > 1700
    assert m.connect_to_proxmox() is False and fake.logins() == [USER]


def test_a_401_of_a_token_pegaprox_did_not_make_counts_as_before(pve):
    fake = PolicyPVE({USER: PASSWORD})
    fake.tokens[f'{USER}!by-hand'] = 'hand-secret'
    srv = pve(fake)
    m = _cluster(srv.port, USER, PASSWORD, api_token_user=f'{USER}!by-hand',
                 api_token_secret='hand-secret')
    assert m.connect_to_proxmox() and m._using_api_token
    fake.expires[f'{USER}!by-hand'] = time.time() - 1
    fake.seen.clear()

    assert set(_poll(m, 3)) == {401}

    assert m._auth_failures == 3 and m._is_auth_blocked()[0]
    assert fake.logins() == [] and fake.posts() == []
    assert m.config.api_token_user == f'{USER}!by-hand'


def test_a_token_pegaprox_did_not_make_is_left_where_it_is(pve):
    """Only a token of ours goes: one typed in by hand stays on PVE and in the config."""
    fake = PolicyPVE({USER: PASSWORD})
    fake.tokens[f'{USER}!by-hand'] = 'hand-secret'
    fake.expires[f'{USER}!by-hand'] = time.time() - 1
    srv = pve(fake)
    m = _cluster(srv.port, USER, PASSWORD, api_token_user=f'{USER}!by-hand',
                 api_token_secret='hand-secret')

    assert m.connect_to_proxmox()

    assert m.config.api_token_user == f'{USER}!by-hand' and f'{USER}!by-hand' in fake.tokens
    assert fake.posts() == [] and m._ticket


# --- the rotation of the cluster's token -----------------------------------------------------

def _rotate(api, seed, m):
    api.set_manager('c1389', m)
    admin = api.as_user(seed.user('root', role='admin'))
    return admin.post('/api/clusters/c1389/api-token/rotate', json={})


def test_rotating_on_pve_9_3_renews_the_secret_in_place_and_the_session_follows(pve, api, seed, db):
    fake = PolicyPVE({USER: PASSWORD})
    m = _connect(fake, pve)
    tid, before = m.config.api_token_user, m.config.api_token_secret
    fake.seen.clear()

    r = _rotate(api, seed, m)

    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['acls_preserved'] is True
    assert fake.tokens[tid] != before
    assert m.config.api_token_user == tid and m.config.api_token_secret == fake.tokens[tid]
    assert m._api_token == f'{tid}={fake.tokens[tid]}'
    assert db.get_cluster('c1389')['api_token_secret'] == fake.tokens[tid]
    # the token may not renew itself on 9.3 without Permissions.Modify: the account does
    name = tid.split('!', 1)[1]
    assert fake.token_calls() == [('PUT', f'{USER}/token/{name}', 'token'),
                                  ('PUT', f'{USER}/token/{name}', 'user')]
    assert before not in r.get_data(as_text=True) and fake.tokens[tid] not in r.get_data(as_text=True)
    # and the session goes on with the new secret
    assert m._api_get(f'https://127.0.0.1:{m.api_port}/api2/json/nodes').status_code == 200


@pytest.mark.parametrize('release,regenerate', [('9.1', False), ('9.2', False)],
                         ids=['pve-9.1', 'pve-9.2-without-regenerate'])
def test_rotating_on_older_pve_makes_the_new_token_before_the_old_one_goes(pve, api, seed,
                                                                         release, regenerate):
    fake = PolicyPVE({USER: PASSWORD}, release=release, regenerate=regenerate)
    m = _connect(fake, pve)
    old = m.config.api_token_user
    fake.seen.clear()

    r = _rotate(api, seed, m)

    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['acls_preserved'] is False
    new = m.config.api_token_user
    assert new != old and new.startswith(f'{USER}!pegaprox_') and old not in fake.tokens
    assert m._api_token == f'{new}={fake.tokens[new]}'
    # the old one, which the session signed in with, went only once the new one was there
    calls = [(meth, p.split('/token/', 1)[1]) for meth, p, _w in fake.token_calls()]
    made = calls.index(('POST', new.split('!', 1)[1]))
    gone = calls.index(('DELETE', old.split('!', 1)[1]))
    assert made < gone
    assert fake.forms[new]['privsep'] == '0'
    assert m._api_get(f'https://127.0.0.1:{m.api_port}/api2/json/nodes').status_code == 200


def _audits(monkeypatch):
    from pegaprox.api import clusters
    said = []
    monkeypatch.setattr(clusters, 'log_audit',
                        lambda user, action, details=None, **kw: said.append((action, details)))
    return said


def test_a_rotation_pve_took_is_one_also_when_the_old_token_could_not_be_deleted(
        pve, api, seed, monkeypatch):
    """Before 9.2 the old token goes after the new one is in use: over the new token, which
    may delete no token, then over a password login that can get no answer (pveproxy
    restarting). That answered 500 'Token rotation failed' for a cluster already on the
    new token, and wrote no audit entry for the change of its credential."""
    audits = _audits(monkeypatch)
    fake = PolicyPVE({USER: PASSWORD}, release='9.1', regenerate=False)
    m = _connect(fake, pve)
    old = m.config.api_token_user
    real = m._token_request

    def login_down_for_the_delete(method, *a, **kw):
        fake.login_down = method == 'DELETE'
        return real(method, *a, **kw)
    m._token_request = login_down_for_the_delete

    r = _rotate(api, seed, m)

    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['success'] is True and f'The old token {old} is still on the cluster' in body['message']
    assert 'warning' not in body
    new = m.config.api_token_user
    assert new != old and old in fake.tokens and m._api_token == f'{new}={fake.tokens[new]}'
    (action, details), = audits
    assert action == 'cluster.api_token_rotated' and old in details and new in details
    assert fake.tokens[new] not in details


def test_a_rotation_pve_took_but_could_not_be_stored_says_so_and_is_audited(
        pve, api, seed, monkeypatch):
    from pegaprox.api import clusters
    audits = _audits(monkeypatch)
    monkeypatch.setattr(clusters, 'save_config', lambda: False)
    fake = PolicyPVE({USER: PASSWORD})
    m = _connect(fake, pve)
    tid = m.config.api_token_user

    r = _rotate(api, seed, m)

    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['success'] is True and body['acls_preserved'] is True
    assert 'could not store' in body['warning'] and body['warning'] in body['message']
    assert m._api_token == f'{tid}={fake.tokens[tid]}'
    (action, details), = audits
    assert action == 'cluster.api_token_rotated' and 'not stored' in details


# --- how the policy is read ------------------------------------------------------------------

class _Options:
    def __init__(self, data, date=None):
        self._data, self.headers = data, ({'Date': date} if date else {})

    def json(self):
        return {'data': self._data}


@pytest.mark.parametrize('data,policy', [
    ({'token-policy': {'max-lifetime': 86400, 'require-expiry': 1}},
     {'max-lifetime': 86400, 'require-expiry': 1}),
    ({'token-policy': {'max-lifetime': '604800', 'require-privilege-separation': '1'}},
     {'max-lifetime': 604800, 'require-privilege-separation': 1}),
    ({'token-policy': 'require-expiry=1,max-lifetime=3600,disallow-expiry-extension=yes'},
     {'require-expiry': 1, 'max-lifetime': 3600, 'disallow-expiry-extension': 1}),
    ({'token-policy': {'max-lifetime': 'forever', 'unknown-key': 1}}, {}),
    ({'keyboard': 'de'}, {}),
    ([], {}),
], ids=['numbers', 'strings', 'property-string', 'junk', 'none', 'no-object'])
def test_the_policy_is_read_as_pve_hands_it_out(data, policy):
    assert token_policy_of(_Options(data))[0] == policy


def test_pve_s_clock_is_read_off_the_date_header():
    from email.utils import formatdate
    ahead = token_policy_of(_Options({}, formatdate(time.time() + 600, usegmt=True)))[1]
    assert 598 <= ahead <= 601
    assert token_policy_of(_Options({}))[1] == 0.0
