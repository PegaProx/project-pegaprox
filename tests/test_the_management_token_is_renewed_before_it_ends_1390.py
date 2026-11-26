"""The management token is renewed before the API token policy of PVE 9.3 ends it.

Under a policy that gives every new token an end, the token PegaProx makes at the first
connect (pegaprox_NNNNNN, without privilege separation) ran out after its lifetime, and
the first 401 replaced it over a password login of the cluster's account. An account with
two-factor login, or a cluster without a stored password, cannot log in that way and lost
its access with the token.

Now the IP refresh loop looks at the token's end every few minutes, and once it is within
two days (a fifth of its lifetime where that is less) renews it: over the password login
where there is one, else over the token itself, which PVE takes from a token that may
manage the tokens of its user. A new token is made, stored and read back, and only then
is the old one deleted; the secret is renewed in place only where PVE refuses that and the
policy lets a new secret move the end, as PVE drops the old secret as it does so. When
nothing works, the admin is told once per lifetime of the token, at WARNING and as an
alert, while there is still time, and nothing tries again in a loop; a lock or a restart
of pveproxy is tried again soon. A cluster without such a policy, a token typed in by hand
and a login that is a token itself are left alone.

The end a token was made with is kept beyond a restart, and the renewal goes by it, not by
the policy of the day. An end neither the token nor a login may read (a token made before
PegaProx kept it, which most often has none) is said once at INFO, without an alert, and
the two-factor login is not tried at every look. A new token whose POST got no answer is
deleted at the next look, also after a restart.

Real requests: an HTTPS endpoint on loopback keeps PVE's rules for the token paths, the
policy (assert_token_policy) and what a token of the Administrator role may do.

MK Nov 2026
"""
import logging
import time
import types
import uuid

import pytest

import pegaprox.core.manager as mgrmod
from tests.test_a_cluster_token_policy_bounds_the_tokens_pegaprox_makes import (  # noqa: F401
    DAY, PASSWORD, USER, PolicyPVE, _cluster, _fresh_caches, _handler_passes_headers, _Said,
    pve, tls)

POLICY = {'max-lifetime': 30 * DAY}
ALLOW = {'max-lifetime': 30 * DAY, 'disallow-expiry-extension': 1, 'allow-extension-on-regenerate': 1}
NODES = '/api2/json/nodes'


class RenewPVE(PolicyPVE):
    """PolicyPVE with what a renewal asks of PVE 9.3 (pve-access-control User.pm): the
    info of a token, an expire on PUT, and the rights of a token of its own user.

    `admins`: accounts whose tokens without privilege separation hold every right (the
    Administrator role). `modify_only`: accounts whose tokens hold User.Modify, which reads
    and deletes the tokens of their user, but not Permissions.Modify on /, which a token
    without privilege separation for another user wants (a token never counts as its own
    user). `refuse`: a 500 for every new token or secret a token asks for. `refuse_new`:
    the same for a new token only, a refusal a new secret does not share. `keep_end`: a
    new secret keeps the end it had, whatever the request said. `slow_put`, `slow_post`:
    seconds a new secret or a new token takes to answer once PVE has made it (a user.cfg
    lock, a lossy link)."""

    def __init__(self, users, admins=(), modify_only=(), **kw):
        kw.setdefault('policy', POLICY)
        super().__init__(users, **kw)
        self.admins, self.modify_only = set(admins), set(modify_only)
        self.refuse, self.refuse_new, self.keep_end, self.slow_put = None, None, False, 0
        self.slow_post = 0

    def _token(self, method, userid, name, who, form):
        owner = who[1].split('!', 1)[0] if who[0] == 'token' else None
        if owner in self.admins or owner in self.modify_only:
            self.strong.add(who[1])
        tid = f'{userid}!{name}'
        mine = (who[0] == 'user' and who[1][0] == userid) or \
            (who[0] == 'token' and who[1] in self.strong)
        if not mine:
            return 403, {'message': 'Permission check failed\n', 'data': None}
        if method == 'GET':
            if tid not in self.tokens:
                return 500, {'message': f"no such token '{name}' for user '{userid}'\n", 'data': None}
            return 200, {'data': {'expire': self.expires.get(tid, 0), 'comment': 'x',
                                  'privsep': int((self.forms.get(tid) or {}).get('privsep', 1))}}
        if who[0] == 'token' and method in ('POST', 'PUT'):
            if owner in self.modify_only:
                return 403, {'message': 'Permission check failed (/, Permissions.Modify)\n', 'data': None}
            refuse = self.refuse or (self.refuse_new if method == 'POST' else None)
            if refuse:
                return 500, {'message': f'generating token failed: {refuse}\n', 'data': None}
        if method == 'PUT':
            return self._update(tid, name, userid, form)
        out = super()._token(method, userid, name, who, form)
        if method == 'POST' and out[0] == 200:
            time.sleep(self.slow_post)
        return out

    def _update(self, tid, name, userid, form):
        if tid not in self.tokens:
            return 500, {'message': f"no such token '{name}' for user '{userid}'\n", 'data': None}
        p = self.policy
        regen = str(form.get('regenerate', '0')).lower() in ('1', 'true')
        before = self.expires.get(tid, 0)
        expire = before if (regen and self.keep_end) else int(form.get('expire', before) or 0)
        life = p.get('max-lifetime')
        if life and (not expire or expire > time.time() + life):
            return 500, {'message': f'updating token failed: the expiration date exceeds the maximum '
                                    f'token lifetime of {life} seconds\n', 'data': None}
        longer = expire != before and (not expire or expire > before)
        if longer and p.get('disallow-expiry-extension') and \
                not (regen and p.get('allow-extension-on-regenerate')):
            return 500, {'message': 'updating token failed: the datacenter token policy does not '
                                    'allow extending the expiration date\n', 'data': None}
        self.expires[tid] = expire
        out = {'full-tokenid': tid, 'expire': expire}
        if regen:
            self.tokens[tid] = str(uuid.uuid4())
            out['value'] = self.tokens[tid]
        time.sleep(self.slow_put)
        return 200, {'data': out}

    def calls(self, *methods):
        """(method, token name, who) of the token calls, of `methods` only where given."""
        return [(m, p.split('/token/', 1)[1], w) for m, p, w in self.token_calls()
                if not methods or m in methods]


@pytest.fixture
def cluster(pve, api, db, monkeypatch):
    """make(fake): the cluster connected the first time, its token made, registered so that
    save_config writes its row for real. restart(m): a new manager from what is stored,
    the way the next start of PegaProx has it."""
    from pegaprox.core import config
    monkeypatch.setattr(mgrmod, 'save_config', config.save_config)

    def make(fake, user=USER, pw=PASSWORD):
        m = api.set_manager('c1389', _cluster(pve(fake).port, user, pw))
        assert m.connect_to_proxmox(), m.connection_error
        assert config.save_config() is True
        return m

    def restart(m, pw=PASSWORD):
        row = db.get_cluster('c1389')
        n = api.set_manager('c1389', _cluster(m.api_port, USER, pw,
                                              api_token_user=row['api_token_user'],
                                              api_token_secret=row['api_token_secret']))
        assert n.connect_to_proxmox(), n.connection_error
        assert n._using_api_token and n.config.api_token_user == row['api_token_user']
        return n
    return type('C', (), {'make': staticmethod(make), 'restart': staticmethod(restart)})


@pytest.fixture
def said(monkeypatch):
    """What the manager logged, and the alerts and audit entries it handed on."""
    from pegaprox import globals as ppglobals
    from pegaprox.utils import audit, webhooks
    rec = _Said()
    rec.alerts, rec.hooks, rec.audits = [], [], []
    logger = logging.getLogger('PegaProx_target')
    monkeypatch.setattr(ppglobals, '_notification_handlers', [rec.alerts.append])
    monkeypatch.setattr(webhooks, 'send_to_channels',
                        lambda alert, channel_ids=None: rec.hooks.append(alert))
    monkeypatch.setattr(audit, 'log_audit', lambda user, action, details=None, **kw: rec.audits.append(
        (user, action, details)))

    def listen(m):
        # a new manager of the same name drops handlers without a file
        if rec not in m.logger.handlers:
            m.logger.addHandler(rec)
        return m
    rec.listen = listen
    yield rec
    logger.removeHandler(rec)


def _near(fake, tid, left=DAY):
    """Its end comes in `left` seconds: on PVE, and in the end PegaProx kept of it, as that
    much of its lifetime went by."""
    fake.expires[tid] = int(time.time()) + left
    _kept_end(tid, fake.expires[tid])


def _kept_end(tid, ends):
    """The end PegaProx kept of `tid` is `ends`, whatever PVE has."""
    kept = mgrmod._management_token_kept('c1389')
    if kept.get('token') == tid:
        assert mgrmod._keep_management_token('c1389', {**kept, 'expire': ends})
    from pegaprox.globals import cluster_managers
    for m in cluster_managers.values():
        if (getattr(m, '_token_end_held', None) or ('',))[0] == tid:
            m._token_end_held = (tid, ends)


def _end_not_kept():
    """The token was made by a PegaProx that kept no end of it (1.5.0 and before)."""
    from pegaprox.core.db import get_db
    conn = get_db().conn
    conn.execute('CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)')
    conn.execute('DELETE FROM pegaprox_kv WHERE k = ?', (mgrmod.MANAGEMENT_TOKEN_KV + 'c1389',))
    conn.commit()


def _tokens_of(fake):
    return {t for t in fake.tokens if t.startswith(f'{USER}!pegaprox_')}


class _Passes:
    """A stop_event that lets the IP refresh loop run `n` passes."""

    def __init__(self, n):
        self.n = n

    def is_set(self):
        return self.n <= 0

    def wait(self, timeout=None):
        if timeout == 15:     # the delay before its first pass
            return False
        self.n -= 1
        return self.n <= 0


@pytest.fixture(autouse=True)
def _unwatched(monkeypatch):
    """Nobody looks at the cluster: the loop reads no guest IPs, which would ask PVE too."""
    monkeypatch.setattr(mgrmod, 'is_cluster_watched', lambda cid: False)


def _pass(m, n=1):
    """`n` passes of the IP refresh loop, the background path the renewal runs in."""
    m.stop_event = _Passes(n)
    m._ip_refresh_loop()


def _look(m):
    """A pass of the loop past the minutes between two looks at the token."""
    m._token_renew_checked = None
    _pass(m)


def _works(m):
    return m._api_get(f'https://127.0.0.1:{m.api_port}{NODES}').status_code == 200


def _no_secret_in(said, *secrets):
    text = ' '.join([r.getMessage() for r in said.records] + [str(a) for a in said.alerts]
                    + [str(a) for a in said.hooks] + [str(a) for a in said.audits])
    for s in secrets:
        assert s and s not in text


def _renewed_and_stored(fake, m, db, old):
    new = m.config.api_token_user
    assert new.startswith(f'{USER}!pegaprox_') and new != old
    assert m._api_token == f'{new}={fake.tokens[new]}' and m._using_api_token and m._ticket is None
    row = db.get_cluster('c1389')
    assert (row['api_token_user'], row['api_token_secret']) == (new, fake.tokens[new])
    assert old not in fake.tokens and fake.forms[new]['privsep'] == '0'
    assert time.time() + 30 * DAY - 300 < fake.expires[new] <= time.time() + 30 * DAY
    assert _works(m)
    return new


# --- nothing to do ----------------------------------------------------------------------------

@pytest.mark.parametrize('admin', [True, False], ids=['token-reads-its-end', 'token-may-not'])
def test_a_token_far_from_its_end_is_left_alone(cluster, admin):
    fake = RenewPVE({USER: PASSWORD}, admins=[USER] if admin else [])
    m = cluster.make(fake)
    tid = m.config.api_token_user
    fake.seen.clear()

    _look(m)

    assert fake.calls('POST', 'PUT', 'DELETE') == []
    # no password login only to look: a token that may not read its end has it from its making
    assert fake.logins() == []
    assert m.config.api_token_user == tid


def test_no_policy_that_ends_a_token_asks_nothing_more(cluster):
    """PVE before 9.3, or a policy without an end: the token was made without one, and a
    policy set later gives the tokens made after it one."""
    fake = RenewPVE({USER: PASSWORD}, policy={}, admins=[USER])
    m = cluster.make(fake)
    fake.seen.clear()

    _look(m)
    assert fake.seen == []

    # the end it was made with is kept beyond a restart
    n = cluster.restart(m)
    fake.seen.clear()
    _look(n)
    assert fake.seen == []

    # a token made before PegaProx kept its end: the policy is read, and again only in an hour
    _end_not_kept()
    n = cluster.restart(m)
    fake.seen.clear()
    _look(n)
    assert [p for _m, p, _w, _f in fake.seen] == ['/api2/json/cluster/options']
    fake.seen.clear()
    _look(n)
    assert fake.seen == []


def test_a_token_typed_in_by_hand_is_never_renewed(cluster, pve):
    fake = RenewPVE({USER: PASSWORD}, admins=[USER])
    fake.tokens[f'{USER}!by-hand'] = 'hand-secret'
    _near(fake, f'{USER}!by-hand')
    m = _cluster(pve(fake).port, USER, PASSWORD, api_token_user=f'{USER}!by-hand',
                 api_token_secret='hand-secret')
    assert m.connect_to_proxmox() and m._using_api_token
    fake.seen.clear()

    _look(m)

    assert fake.calls() == [] and fake.logins() == []
    assert m.config.api_token_user == f'{USER}!by-hand' and fake.tokens[f'{USER}!by-hand'] == 'hand-secret'


def test_a_login_that_is_a_token_itself_is_never_renewed(cluster, pve):
    fake = RenewPVE({USER: PASSWORD}, admins=[USER])
    tid = f'{USER}!pegaprox_123456'
    fake.tokens[tid] = 'its-secret'
    _near(fake, tid)
    m = _cluster(pve(fake).port, tid, 'its-secret')
    assert m.connect_to_proxmox() and m._using_api_token
    fake.seen.clear()

    _look(m)

    assert fake.calls() == [] and fake.logins() == [] and fake.tokens[tid] == 'its-secret'


def test_a_standby_renews_nothing(cluster, monkeypatch):
    fake = RenewPVE({USER: PASSWORD}, admins=[USER])
    m = cluster.make(fake)
    _near(fake, m.config.api_token_user)
    monkeypatch.setattr(mgrmod.ha, 'is_active', lambda: False)
    fake.seen.clear()

    _look(m)
    assert fake.seen == []


def test_the_end_is_looked_at_every_few_minutes_only(cluster):
    fake = RenewPVE({USER: PASSWORD}, admins=[USER])
    m = cluster.make(fake)
    fake.seen.clear()
    _pass(m)
    assert fake.calls('GET') != []
    fake.seen.clear()

    _pass(m, 3)
    assert fake.seen == []


# --- renewed --------------------------------------------------------------------------------

@pytest.mark.parametrize('kept', [True, False], ids=['end-kept', 'made-before-it-was-kept'])
def test_a_token_near_its_end_is_renewed_over_the_password_login(cluster, db, said, kept):
    """The account's token may manage no token (the documented PegaProx role). After a
    restart PegaProx knows when it ends from what it kept at its making, or, for a token
    made before it kept that, reads it once over the password login. The new token is made
    there, stored, and the old one deleted."""
    fake = RenewPVE({USER: PASSWORD})
    m = cluster.make(fake)
    old = m.config.api_token_user
    old_secret = fake.tokens[old]
    _near(fake, old)
    if not kept:
        _end_not_kept()
    m = said.listen(cluster.restart(m))
    fake.seen.clear()

    _look(m)

    new = _renewed_and_stored(fake, m, db, old)
    assert ('POST', new.split('!', 1)[1], 'user') in fake.calls()
    assert ('DELETE', old.split('!', 1)[1], 'user') in fake.calls()
    assert set(fake.logins()) == {USER}
    (user, action, details), = said.audits
    assert action == 'cluster.api_token_renewed' and old in details and new in details
    _no_secret_in(said, old_secret, fake.tokens[new], PASSWORD)
    # far from its end now
    fake.seen.clear()
    _look(m)
    assert fake.calls('POST', 'PUT', 'DELETE') == []


@pytest.mark.parametrize('how', ['two-factor', 'no-password'])
def test_without_a_password_login_an_administrator_token_renews_itself(cluster, db, said, how):
    fake = RenewPVE({USER: PASSWORD}, admins=[USER])
    m = cluster.make(fake)
    old = m.config.api_token_user
    old_secret = fake.tokens[old]
    if how == 'two-factor':
        fake.tfa.add(USER)
    else:
        m = cluster.restart(m, pw='')
    said.listen(m)
    _near(fake, old)
    fake.seen.clear()

    _look(m)

    new = _renewed_and_stored(fake, m, db, old)
    # made by the old token, the old one deleted by the new one once the row held it
    assert fake.calls('POST', 'DELETE') == [('POST', new.split('!', 1)[1], 'token'),
                                            ('DELETE', old.split('!', 1)[1], 'token')]
    assert fake.logins() == ([USER] if how == 'two-factor' else [])
    assert not said.at(logging.WARNING) and said.alerts == []
    _no_secret_in(said, old_secret, fake.tokens[new], PASSWORD)


def test_where_the_policy_lets_a_new_secret_move_the_end_a_new_token_still_comes_first(
        cluster, db, said):
    """PVE drops the old secret as it carries a new one out. Asked first, a new secret whose
    answer came too late (a user.cfg lock, a lossy link to a remote cluster) left PegaProx
    with a dead secret days before the token ended, and nobody was told. A new token holds
    up against that: the old one goes only once the new one is in use and stored."""
    fake = RenewPVE({USER: PASSWORD}, admins=[USER], policy=ALLOW)
    m = said.listen(cluster.make(fake))
    old = m.config.api_token_user
    fake.tfa.add(USER)
    fake.slow_put = 2.5     # a new secret answers after the manager stopped waiting
    m.api_timeout = 1
    _near(fake, old)
    fake.seen.clear()

    _look(m)

    # the secret in use and the one stored both still open the cluster
    assert _works(m)
    row = db.get_cluster('c1389')
    assert fake.tokens.get(row['api_token_user']) == row['api_token_secret']
    new = _renewed_and_stored(fake, m, db, old)
    assert fake.calls('POST', 'PUT', 'DELETE') == [('POST', new.split('!', 1)[1], 'token'),
                                                   ('DELETE', old.split('!', 1)[1], 'token')]


def test_the_secret_is_renewed_in_place_only_where_pve_refuses_a_new_token(cluster, db, said):
    fake = RenewPVE({USER: PASSWORD}, admins=[USER], policy=ALLOW)
    m = said.listen(cluster.make(fake))
    tid = m.config.api_token_user
    old_secret = fake.tokens[tid]
    fake.tfa.add(USER)
    fake.refuse_new = 'the datacenter token policy says no'
    _near(fake, tid)
    fake.seen.clear()

    _look(m)

    assert m.config.api_token_user == tid and fake.tokens[tid] != old_secret
    assert m._api_token == f'{tid}={fake.tokens[tid]}'
    assert db.get_cluster('c1389')['api_token_secret'] == fake.tokens[tid]
    assert time.time() + 30 * DAY - 300 < fake.expires[tid] <= time.time() + 30 * DAY
    assert [c[0] for c in fake.calls('POST', 'PUT', 'DELETE')] == ['POST', 'PUT']
    [form] = [f for meth, p, _w, f in fake.seen if meth == 'PUT']
    assert form['regenerate'] == '1' and int(form['expire']) == fake.expires[tid]
    assert _works(m)
    assert not [s for s in said.at(logging.WARNING) if '[TOKEN]' in s] and said.alerts == []
    _no_secret_in(said, old_secret, fake.tokens[tid])


def test_where_the_policy_keeps_the_end_of_a_token_a_new_one_is_made(cluster, db):
    fake = RenewPVE({USER: PASSWORD}, admins=[USER], policy={
        'max-lifetime': 30 * DAY, 'disallow-expiry-extension': 1})
    m = cluster.make(fake)
    old = m.config.api_token_user
    fake.tfa.add(USER)
    _near(fake, old)
    fake.seen.clear()

    _look(m)

    _renewed_and_stored(fake, m, db, old)
    assert fake.calls('PUT') == []


def test_a_new_secret_that_left_the_end_where_it_was_is_said_once(cluster, db, said):
    """PVE refused a new token and renewed the secret but kept its end: the new secret is in
    use and stored, and the admin is told once, as nothing moved the end. Not renewed
    again at the next look, five minutes on."""
    fake = RenewPVE({USER: PASSWORD}, admins=[USER], policy=ALLOW)
    m = said.listen(cluster.make(fake))
    tid = m.config.api_token_user
    fake.tfa.add(USER)
    fake.refuse_new, fake.keep_end = 'the datacenter token policy says no', True
    _near(fake, tid)
    fake.seen.clear()

    _look(m)

    assert [c[0] for c in fake.calls('POST', 'PUT', 'DELETE')] == ['POST', 'PUT']
    assert m._api_token == f'{tid}={fake.tokens[tid]}' and _works(m)
    assert db.get_cluster('c1389')['api_token_secret'] == fake.tokens[tid]
    [warned] = [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]
    assert 'kept the end it had' in warned and len(said.alerts) == 1
    fake.seen.clear()
    _look(m)
    assert fake.calls('POST', 'PUT', 'DELETE') == []


def test_a_new_token_that_could_not_be_stored_leaves_the_old_one_on_pve(cluster, db, said, monkeypatch):
    """save_config answers True for a row it could not write: the row read back decides. The
    next start signs in with the old token while it lasts; the next looks store the new one
    and delete the old one then."""
    fake = RenewPVE({USER: PASSWORD}, admins=[USER])
    m = said.listen(cluster.make(fake))
    old = m.config.api_token_user
    old_secret = fake.tokens[old]
    fake.tfa.add(USER)
    _near(fake, old)
    monkeypatch.setattr(mgrmod, 'save_config', lambda: True)

    _look(m)

    assert fake.tokens.get(old) == old_secret and fake.calls('DELETE') == []
    assert db.get_cluster('c1389')['api_token_user'] == old
    new = m.config.api_token_user
    assert new != old and m._api_token == f'{new}={fake.tokens[new]}'
    assert any('could not be stored' in s and old in s for s in said.at(logging.ERROR))
    (_user, _action, details), = said.audits
    assert 'not stored' in details

    # the database takes it again
    from pegaprox.core import config
    monkeypatch.setattr(mgrmod, 'save_config', config.save_config)
    _look(m)
    row = db.get_cluster('c1389')
    assert (row['api_token_user'], row['api_token_secret']) == (new, fake.tokens[new])
    assert old not in fake.tokens and _works(m)


def test_a_new_secret_the_row_did_not_take_is_said_at_once_and_stored_later(
        cluster, db, said, monkeypatch):
    """PVE takes the secret before it no more, so a restart before the row holds the new one
    signs in with a dead secret. The admin hears of it at once, and the next looks store it."""
    fake = RenewPVE({USER: PASSWORD}, admins=[USER], policy=ALLOW)
    m = said.listen(cluster.make(fake))
    tid = m.config.api_token_user
    fake.tfa.add(USER)
    fake.refuse_new = 'the datacenter token policy says no'
    _near(fake, tid)
    monkeypatch.setattr(mgrmod, 'save_config', lambda: True)

    _look(m)

    secret = fake.tokens[tid]
    assert m._api_token == f'{tid}={secret}' and _works(m)
    assert db.get_cluster('c1389')['api_token_secret'] != secret
    assert len(said.alerts) == 1
    assert said.alerts[0]['severity'] == 'critical' and 'restart' in said.alerts[0]['message']
    assert any('could not store' in s and tid in s for s in said.at(logging.ERROR))
    _no_secret_in(said, secret)

    from pegaprox.core import config
    monkeypatch.setattr(mgrmod, 'save_config', config.save_config)
    _look(m)
    assert db.get_cluster('c1389')['api_token_secret'] == secret
    cluster.restart(m)


@pytest.mark.parametrize('how', ['two-factor', 'password'])
def test_a_token_with_an_end_is_renewed_after_the_policy_is_relaxed(cluster, db, said, how):
    """The renewal went by the policy of now, not by the end of the token: a policy relaxed
    after the token got its end left it to run out, and an account with two-factor login
    lost the cluster with it. Renewed as before; under no policy the new token has no end."""
    fake = RenewPVE({USER: PASSWORD}, admins=[USER] if how == 'two-factor' else [])
    m = said.listen(cluster.make(fake))
    old = m.config.api_token_user
    assert fake.expires[old] > 0
    if how == 'two-factor':
        fake.tfa.add(USER)
    fake.policy = {}
    m._token_policy_held = None
    _near(fake, old)
    fake.seen.clear()

    _look(m)

    new = m.config.api_token_user
    assert new != old and old not in fake.tokens and _tokens_of(fake) == {new}
    assert fake.expires[new] == 0 and fake.forms[new]['privsep'] == '0'
    row = db.get_cluster('c1389')
    assert (row['api_token_user'], row['api_token_secret']) == (new, fake.tokens[new])
    assert _works(m) and said.alerts == []
    # and a token without an end asks nothing more, also after a restart
    fake.seen.clear()
    _look(m)
    assert fake.seen == []
    n = cluster.restart(m)
    fake.seen.clear()
    _look(n)
    assert fake.seen == []


@pytest.mark.parametrize('how', ['over-the-token', 'over-the-login', 'restart-between'])
def test_a_new_token_whose_answer_never_came_is_deleted_before_the_next_one(cluster, db, how):
    """A POST for a new token whose answer came too late left a token without privilege
    separation on PVE, and every retry made another one under a new name. Its name is noted
    before it goes out, and the next look deletes it, also after a restart."""
    fake = RenewPVE({USER: PASSWORD}, admins=[] if how == 'over-the-login' else [USER])
    m = cluster.make(fake)
    if how != 'over-the-login':
        fake.tfa.add(USER)
    old = m.config.api_token_user
    _near(fake, old, 36 * 3600)
    fake.slow_post, m.api_timeout = 2.5, 1
    fake.seen.clear()

    _look(m)

    # PVE made one, the answer did not come: still on the old token
    time.sleep(2)
    [lost] = _tokens_of(fake) - {old}
    assert m.config.api_token_user == old and _works(m)

    fake.slow_post, m.api_timeout = 0, 10
    if how == 'restart-between':
        m = cluster.restart(m)
    m._token_renew_held = None
    _look(m)

    new = m.config.api_token_user
    assert new not in (old, lost) and _tokens_of(fake) == {new}
    assert ('DELETE', lost.split('!', 1)[1]) in [(c[0], c[1]) for c in fake.calls('DELETE')]
    row = db.get_cluster('c1389')
    assert (row['api_token_user'], row['api_token_secret']) == (new, fake.tokens[new])
    # nothing left to delete
    assert mgrmod._management_token_kept('c1389').get('unanswered') == []


def test_a_token_stored_at_a_later_look_deletes_the_one_before_over_the_password_login(
        cluster, db, said, monkeypatch):
    """The documented role renews over the password login, and its token may delete no
    token. A new token the row took only at a later look deleted the one it replaced over
    itself: PVE said no, and the old token, with every right of the account, stayed until
    its own end."""
    fake = RenewPVE({USER: PASSWORD})
    m = said.listen(cluster.make(fake))
    old = m.config.api_token_user
    _near(fake, old)
    monkeypatch.setattr(mgrmod, 'save_config', lambda: True)

    _look(m)

    new = m.config.api_token_user
    assert new != old and old in fake.tokens and db.get_cluster('c1389')['api_token_user'] == old

    from pegaprox.core import config
    monkeypatch.setattr(mgrmod, 'save_config', config.save_config)
    fake.seen.clear()
    _look(m)

    row = db.get_cluster('c1389')
    assert (row['api_token_user'], row['api_token_secret']) == (new, fake.tokens[new])
    assert _tokens_of(fake) == {new}
    assert ('DELETE', old.split('!', 1)[1], 'user') in fake.calls('DELETE')
    assert not [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]
    assert _works(m)


def test_a_name_noted_for_a_token_in_use_is_never_deleted(cluster, db):
    """A note the database kept of a name that is now the token in use (the answer came
    after all) deletes nothing."""
    fake = RenewPVE({USER: PASSWORD}, admins=[USER])
    m = cluster.make(fake)
    tid = m.config.api_token_user
    mgrmod._keep_management_token('c1389', {**mgrmod._management_token_kept('c1389'),
                                            'unanswered': [tid.split('!', 1)[1]]})
    m = cluster.restart(m)
    fake.seen.clear()

    _look(m)

    assert fake.calls('DELETE') == [] and fake.tokens.get(tid) == m.config.api_token_secret


# --- nothing works ----------------------------------------------------------------------------

@pytest.mark.parametrize('refusal', ['403', '500'])
def test_a_token_pve_refuses_its_successor_is_said_once_and_not_tried_in_a_loop(
        cluster, said, monkeypatch, refusal):
    """403: the token holds User.Modify, so it reads its end, but not Permissions.Modify on
    /. 500: PVE (its token policy) refused the new token."""
    if refusal == '403':
        fake = RenewPVE({USER: PASSWORD}, modify_only=[USER])
    else:
        fake = RenewPVE({USER: PASSWORD}, admins=[USER])
        fake.refuse = "error with cfs lock 'file-user_cfg': the datacenter token policy says no"
    m = said.listen(cluster.make(fake))
    tid = m.config.api_token_user
    secret = fake.tokens[tid]
    fake.tfa.add(USER)
    _near(fake, tid)
    fake.seen.clear()

    _look(m)

    # still on the token it has, which still works until its end
    assert m.config.api_token_user == tid and fake.tokens[tid] == secret and _works(m)
    warned = [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]
    assert len(warned) == 1
    assert tid in warned[0] and 'two-factor' in warned[0] and 'Permissions.Modify' in warned[0]
    # what PVE said goes with it
    assert (f'HTTP {refusal} ' + ('Permission check failed' if refusal == '403' else 'generating token failed')
            ) in warned[0]
    assert len(said.alerts) == 1 and said.hooks == said.alerts
    alert = said.alerts[0]
    assert alert['severity'] == 'warning' and alert['message'] in warned[0]
    assert alert['target_type'] == 'instance' and alert['target_name'] == 'target'
    _no_secret_in(said, secret, PASSWORD)

    # the next looks ask nothing for hours
    fake.seen.clear()
    _look(m)
    _look(m)
    assert fake.seen == [] and len(said.alerts) == 1

    # and once they ask again, the warning is not said a second time
    monkeypatch.setattr(m, '_token_renew_held', None)
    _look(m)
    assert fake.calls('POST') != []
    assert len(said.alerts) == 1 and len([s for s in said.at(logging.WARNING) if '[TOKEN]' in s]) == 1


@pytest.mark.parametrize('how', ['two-factor', 'no-password'])
def test_after_a_restart_the_end_kept_from_its_making_needs_no_login(cluster, said, how):
    """A token that may not read itself (the documented role) and no password login: after
    a restart PegaProx said the token had an end it could neither read nor renew, alerted,
    told the admin to grant privileges, and tried the two-factor login again every six
    hours, also for every token made before a policy, which has no end at all."""
    fake = RenewPVE({USER: PASSWORD})
    m = cluster.make(fake)
    tid = m.config.api_token_user
    if how == 'two-factor':
        fake.tfa.add(USER)
        m = said.listen(cluster.restart(m))
    else:
        m = said.listen(cluster.restart(m, pw=''))
    fake.seen.clear()

    for _ in range(3):
        m._token_renew_held = None
        _look(m)

    assert fake.logins() == [] and fake.calls('POST', 'PUT', 'DELETE') == []
    assert said.alerts == [] and said.hooks == []
    assert not [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]
    assert not [s for s in said.at(logging.INFO) if '[TOKEN]' in s and tid in s]
    assert m.config.api_token_user == tid and _works(m)


def test_an_end_that_cannot_be_read_is_said_once_at_info_without_an_alert(cluster, said):
    """A token made before PegaProx kept its end, that may not read itself, and an account
    with two-factor login: nobody can say when it ends, which for most such tokens is never.
    Said once per token at INFO, without an alert and without a claim that it ends; the
    two-factor login is not tried again at every look."""
    fake = RenewPVE({USER: PASSWORD})
    m = cluster.make(fake)
    tid = m.config.api_token_user
    _end_not_kept()
    fake.tfa.add(USER)
    m = said.listen(cluster.restart(m))
    fake.seen.clear()

    _look(m)

    assert fake.calls('POST', 'PUT', 'DELETE') == []
    [told] = [s for s in said.at(logging.INFO) if '[TOKEN]' in s and 'cannot read' in s]
    assert tid in told and 'Permissions.Modify' not in told and 'User.Modify' not in told
    assert not [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]
    assert said.alerts == [] and said.hooks == []
    assert fake.logins() == [USER]

    # the next looks ask over the token only, and say nothing more
    for _ in range(3):
        m._token_renew_held = None
        _look(m)
    assert fake.logins() == [USER]
    assert len([s for s in said.at(logging.INFO) if '[TOKEN]' in s and 'cannot read' in s]) == 1

    # nor after a restart
    m = said.listen(cluster.restart(m))
    _look(m)
    assert len([s for s in said.at(logging.INFO) if '[TOKEN]' in s and 'cannot read' in s]) == 1
    assert said.alerts == []


@pytest.mark.parametrize('how', ['two-factor', 'no-password'])
def test_a_kept_end_that_passed_while_pve_still_takes_the_token_is_no_end(cluster, said, how):
    """The documented role, and no password login: PegaProx said the token ends and cannot
    be renewed, and the admin moved its end on the cluster (Expire in the GUI), which the
    token may not read. Once the end PegaProx kept had passed the cluster still worked, yet
    every look asked PVE for a new token, the two-factor login went out every half hour, and
    every restart warned and alerted that the token ends at a time already gone, with the
    advice to grant privileges. A kept end that has passed while PVE takes the token is no
    end: read like one never kept, and said once at INFO."""
    fake = RenewPVE({USER: PASSWORD})
    m = cluster.make(fake)
    tid = m.config.api_token_user
    pw = '' if how == 'no-password' else PASSWORD
    if how == 'two-factor':
        fake.tfa.add(USER)
    m = said.listen(cluster.restart(m, pw=pw))
    _near(fake, tid)
    _look(m)
    assert len(said.alerts) == 1        # nothing renews it, as it should be said

    # the admin moves its end on the cluster, and the end PegaProx kept goes by
    fake.expires[tid] = int(time.time()) + 20 * DAY
    _kept_end(tid, int(time.time()) - 3600)
    m._token_renew_held = m._token_login_refused = None     # hours went by
    fake.seen.clear()
    for _ in range(6):
        _look(m)                        # five minutes apart
    for _ in range(3):
        m._token_renew_held = m._token_login_refused = None
        _look(m)                        # hours apart

    assert m.config.api_token_user == tid and _works(m)
    assert fake.calls('POST', 'PUT', 'DELETE') == []
    assert len(fake.logins()) <= (1 if how == 'two-factor' else 0)
    assert len(said.alerts) == 1 and len([s for s in said.at(logging.WARNING) if '[TOKEN]' in s]) == 1
    [told] = [s for s in said.at(logging.INFO) if '[TOKEN]' in s and 'cannot read' in s]
    assert tid in told and 'passed' in told and 'Permissions.Modify' not in told
    assert mgrmod._management_token_kept('c1389').get('expire') is None

    # nor after a restart
    m = said.listen(cluster.restart(m, pw=pw))
    fake.seen.clear()
    _look(m)
    assert fake.calls('POST', 'PUT', 'DELETE') == [] and len(said.alerts) == 1
    assert len([s for s in said.at(logging.WARNING) if '[TOKEN]' in s]) == 1
    assert len([s for s in said.at(logging.INFO) if '[TOKEN]' in s and 'cannot read' in s]) == 1


def test_a_kept_end_that_passed_is_left_alone_while_pve_says_nothing(cluster, said, monkeypatch):
    """A look PVE does not answer tells nothing of whether it still takes the token: the
    end that passed is neither acted on nor forgotten."""
    fake = RenewPVE({USER: PASSWORD})
    m = cluster.make(fake)
    tid = m.config.api_token_user
    fake.tfa.add(USER)
    m = said.listen(cluster.restart(m))
    passed = int(time.time()) - 3600
    _kept_end(tid, passed)
    fake.seen.clear()
    real = m._api_get

    def busy(url, **kw):
        if '/token/' in url:
            raise mgrmod.requests.exceptions.Timeout('pveproxy busy')
        return real(url, **kw)
    monkeypatch.setattr(m, '_api_get', busy)

    _look(m)

    assert fake.calls() == [] and fake.logins() == []
    assert said.alerts == [] and not [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]
    assert mgrmod._management_token_kept('c1389').get('expire') == passed


def test_a_new_secret_whose_answer_never_came_is_said_at_once(cluster, said):
    """Where PVE refused a new token the secret is renewed in place. An answer that comes too
    late leaves PegaProx with a secret PVE takes no more: said at once, not taken for no
    answer and left to the next 401."""
    fake = RenewPVE({USER: PASSWORD}, admins=[USER], policy=ALLOW)
    m = said.listen(cluster.make(fake))
    tid = m.config.api_token_user
    old_secret = fake.tokens[tid]
    fake.tfa.add(USER)
    fake.refuse_new, fake.slow_put = 'the datacenter token policy says no', 2.5
    m.api_timeout = 1
    _near(fake, tid)

    _look(m)

    assert fake.tokens[tid] != old_secret      # PVE carried it out
    assert len(said.alerts) == 1 and said.alerts[0]['severity'] == 'critical'
    [error] = [s for s in said.at(logging.ERROR) if '[TOKEN]' in s]
    assert tid in error and 'never came' in error and 'two-factor' in error
    _no_secret_in(said, old_secret, fake.tokens[tid], PASSWORD)


def test_a_new_secret_pve_did_not_carry_out_is_tried_again_soon(cluster, said):
    """pveproxy restarting answers the PUT with a 503: the secret PegaProx has still works,
    so it is tried again in a quarter of an hour, and nothing is said yet."""
    fake = RenewPVE({USER: PASSWORD}, admins=[USER], policy=ALLOW)
    m = said.listen(cluster.make(fake))
    tid = m.config.api_token_user
    secret = fake.tokens[tid]
    fake.tfa.add(USER)
    fake.refuse_new = 'the datacenter token policy says no'
    fake._update = lambda *a: (503, {'data': None})
    _near(fake, tid, 36 * 3600)    # inside the margin of two days, not past half of it

    _look(m)

    assert fake.tokens[tid] == secret and m._api_token == f'{tid}={secret}' and _works(m)
    assert said.alerts == [] and not [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]
    _tid, until = m._token_renew_held
    assert until - time.monotonic() <= 15 * 60


def test_a_refusal_is_said_again_in_the_next_lifetime_of_a_token_renewed_in_place(
        cluster, said, monkeypatch):
    """A secret renewed in place keeps the id of the token: what was said in its last
    lifetime must not keep the next one quiet."""
    fake = RenewPVE({USER: PASSWORD}, admins=[USER], policy=ALLOW)
    m = said.listen(cluster.make(fake))
    tid = m.config.api_token_user
    fake.tfa.add(USER)
    fake.refuse_new = 'the datacenter token policy says no'
    fake.refuse = 'privileges taken away'
    _near(fake, tid)
    _look(m)
    assert len(said.alerts) == 1

    # given back: renewed in place, the same token
    fake.refuse = None
    monkeypatch.setattr(m, '_token_renew_held', None)
    _look(m)
    assert m.config.api_token_user == tid and _works(m) and len(said.alerts) == 1

    # its next end comes near, and they are gone again
    _near(fake, tid)
    fake.refuse = 'privileges taken away'
    _look(m)
    assert len(said.alerts) == 2
    assert len([s for s in said.at(logging.WARNING) if '[TOKEN]' in s]) == 2


def test_a_kept_end_with_a_secret_the_row_did_not_take_is_stored_at_the_next_look(
        cluster, db, said, monkeypatch):
    """PVE renewed the secret in place and kept the end. The row did not take the secret,
    and the critical alert promised a store every few minutes, but the hold of the refusal
    (up to six hours) came first; the warning told the admin to grant privileges the token
    had just used."""
    fake = RenewPVE({USER: PASSWORD}, admins=[USER], policy=ALLOW)
    m = said.listen(cluster.make(fake))
    tid = m.config.api_token_user
    fake.tfa.add(USER)
    fake.refuse_new, fake.keep_end = 'the datacenter token policy says no', True
    _near(fake, tid)
    monkeypatch.setattr(mgrmod, 'save_config', lambda: True)

    _look(m)

    secret = fake.tokens[tid]
    assert m._api_token == f'{tid}={secret}' and db.get_cluster('c1389')['api_token_secret'] != secret
    assert [a['severity'] for a in said.alerts] == ['critical', 'warning']
    [warned] = [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]
    assert 'kept the end it had' in warned and 'Permissions.Modify' not in warned
    assert 'User.Modify' not in warned and 'two-factor' in warned

    from pegaprox.core import config
    monkeypatch.setattr(mgrmod, 'save_config', config.save_config)
    _look(m)
    assert db.get_cluster('c1389')['api_token_secret'] == secret
    cluster.restart(m)


LOCK = "error with cfs lock 'file-user_cfg': got lock request timeout"


def test_a_lock_timeout_is_tried_again_soon_and_said_once_time_runs_short(cluster, said, monkeypatch):
    """A lifetime of a day is renewed 4.8 hours ahead. A lock timeout of user.cfg is no
    refusal: held for six hours like one, a token with four hours left got no second try
    before its end, and the admin was told to change privileges."""
    fake = RenewPVE({USER: PASSWORD}, admins=[USER], policy={'max-lifetime': DAY})
    m = said.listen(cluster.make(fake))
    tid = m.config.api_token_user
    fake.tfa.add(USER)
    _near(fake, tid, 4 * 3600)
    fake.refuse = LOCK

    _look(m)

    # tried again well before the end, and nothing to do for the admin yet
    _tid, until = m._token_renew_held
    assert until - time.monotonic() < (fake.expires[tid] - time.time()) / 4
    assert said.alerts == [] and not [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]

    # under half the margin left it is said, once, as something PVE gets over
    _near(fake, tid, 2 * 3600)
    for _ in range(2):
        monkeypatch.setattr(m, '_token_renew_held', None)
        _look(m)
    [warned] = [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]
    assert 'tries again' in warned and 'lock request timeout' in warned
    assert 'Permissions.Modify' not in warned and len(said.alerts) == 1

    # and the try once the lock is free renews it
    fake.refuse = None
    monkeypatch.setattr(m, '_token_renew_held', None)
    _look(m)
    assert m.config.api_token_user != tid and _works(m)


def test_a_refusal_close_to_the_end_is_tried_again_before_it(cluster, said):
    """Six hours between two tries outlast a token with four hours left."""
    fake = RenewPVE({USER: PASSWORD}, modify_only=[USER], policy={'max-lifetime': DAY})
    m = said.listen(cluster.make(fake))
    tid = m.config.api_token_user
    fake.tfa.add(USER)
    _near(fake, tid, 4 * 3600)

    _look(m)

    assert len(said.alerts) == 1
    _tid, until = m._token_renew_held
    assert until - time.monotonic() <= (fake.expires[tid] - time.time()) / 4 + 1


# --- a password login without an answer -----------------------------------------------------

_real_monotonic = time.monotonic


class _Minutes:
    """The monotonic clock of the manager, moved on by hand: the looks of the IP refresh
    loop come five minutes apart without the test waiting for them."""

    def __init__(self):
        self.ahead = 0

    def __call__(self):
        return _real_monotonic() + self.ahead


@pytest.fixture
def minutes(monkeypatch):
    clock = _Minutes()
    monkeypatch.setattr(mgrmod, 'time', types.SimpleNamespace(**{**vars(time), 'monotonic': clock}))
    return clock


def _login_without_answer(fake, monkeypatch, how):
    """The password login gets neither a yes nor a no. 'login-down': pveproxy answers 503,
    as while it restarts. 'timeout': the login reaches PVE and its answer does not come
    back within the ten seconds PegaProx waits, as from a realm whose LDAP or AD server is
    slow or gone. Returns what brings the login back."""
    if how == 'login-down':
        fake.login_down = True
        return lambda: setattr(fake, 'login_down', False)
    real = mgrmod._password_login

    def answer_lost(mgr, usr, pwd, what):
        sess, _why, _status = real(mgr, usr, pwd, what)
        if sess is not None:
            sess.close()
        raise mgrmod.requests.exceptions.ReadTimeout('Read timed out. (read timeout=10)')
    monkeypatch.setattr(mgrmod, '_password_login', answer_lost)
    return lambda: monkeypatch.setattr(mgrmod, '_password_login', real)


LOST = 'pegaprox_999999'


def _asking_for_a_login(cluster, fake, path):
    """The documented role, whose token may neither read nor make a token, at the point
    where `path` wants a password login of the account: (manager after a restart, token)."""
    m = cluster.make(fake)
    tid = m.config.api_token_user
    if path == 'end-unknown':
        # made by a PegaProx that kept no end of it: read once over the login
        _end_not_kept()
    elif path == 'end-passed':
        # its end moved on the cluster by hand: the kept end passed and PVE still takes it
        fake.expires[tid] = int(time.time()) + 20 * DAY
        _kept_end(tid, int(time.time()) - 3600)
    elif path == 'new-token':
        _near(fake, tid, 36 * 3600)
    else:
        # a new token whose making got no answer, deleted over the login
        fake.tokens[f'{USER}!{LOST}'] = 'its-secret'
        kept = mgrmod._management_token_kept('c1389')
        assert mgrmod._keep_management_token('c1389', {**kept, 'unanswered': [LOST]})
    return cluster.restart(m), tid


@pytest.mark.parametrize('how', ['login-down', 'timeout'])
@pytest.mark.parametrize('path', ['end-unknown', 'end-passed', 'new-token', 'unanswered-delete'])
def test_a_password_login_without_an_answer_goes_out_once_per_hold(
        cluster, said, minutes, monkeypatch, path, how):
    """The login that reads an end the token may not read was to go out once per token and
    password, but only a login that got a yes or a no counted. A realm whose directory does
    not answer in time, or pveproxy restarting, left every look sending another one, five
    minutes apart, 288 a day: each fails in PVE's log, and a fail2ban of pveproxy (maxretry
    3) bans the address of PegaProx, although the token itself needs no directory. A new
    token over the login and the delete of a token whose making got no answer did the same.
    Such a login now waits like a refused one, and what it was for is done once the login
    answers again."""
    fake = RenewPVE({USER: PASSWORD})
    m, tid = _asking_for_a_login(cluster, fake, path)
    said.listen(m)
    back = _login_without_answer(fake, monkeypatch, how)
    fake.seen.clear()

    sent = []
    for _ in range(12):
        before = len(fake.logins())
        _pass(m)
        sent += [minutes()] * (len(fake.logins()) - before)
        minutes.ahead += 300

    # tried, and once more after the hold, never sooner
    gaps = [b - a for a, b in zip(sent, sent[1:])]
    assert len(sent) == 2 and all(g >= m.TOKEN_LOGIN_HOLD for g in gaps), gaps
    if path != 'unanswered-delete':
        # the looks in between wait a quarter of an hour
        assert len(fake.calls('GET')) <= 4
    [told] = [s for s in said.at(logging.INFO) if '[TOKEN]' in s and 'neither a yes nor a no' in s]
    assert USER in told and PASSWORD not in told
    assert said.alerts == [] and not [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]
    assert m.config.api_token_user == tid and _works(m)

    # the login answers again: what it was for is done at the next look after the hold
    back()
    minutes.ahead += m.TOKEN_LOGIN_HOLD
    fake.seen.clear()
    _pass(m)

    assert len(fake.logins()) == 1
    if path in ('end-unknown', 'end-passed'):
        # an outage did not lose the end
        assert mgrmod._management_token_kept('c1389').get('expire') == fake.expires[tid]
    elif path == 'new-token':
        new = m.config.api_token_user
        assert new != tid and _tokens_of(fake) == {new} and _works(m)
    else:
        assert f'{USER}!{LOST}' not in fake.tokens
        assert mgrmod._management_token_kept('c1389').get('unanswered') == []


def test_a_migration_logs_in_at_once_after_the_renewal_got_no_answer(cluster, said, minutes):
    """Only the looks of the renewal wait: a migration tries the login right away, as
    before, and a login that answers lets the renewal read the end at its next look."""
    fake = RenewPVE({USER: PASSWORD})
    m, tid = _asking_for_a_login(cluster, fake, 'end-unknown')
    fake.login_down = True
    fake.seen.clear()
    _pass(m)
    assert len(fake.logins()) == 1

    fake.login_down = False
    got = m.create_api_token('mig-1390')
    assert got['success'], got
    assert len(fake.logins()) == 2

    minutes.ahead += 3 * m.TOKEN_RENEW_EVERY
    _pass(m)
    assert len(fake.logins()) == 3
    assert mgrmod._management_token_kept('c1389').get('expire') == fake.expires[tid]


# --- the loop -------------------------------------------------------------------------------

def test_a_look_that_fails_does_not_end_the_loop(monkeypatch):
    m = _cluster(1, USER, PASSWORD)
    tid = f'{USER}!pegaprox_000001'
    m.config.api_token_user, m._api_token = tid, f'{tid}=s'
    m.is_connected = m._using_api_token = True
    asked = []

    def unreadable():
        asked.append(1)
        raise RuntimeError('no policy today')
    monkeypatch.setattr(m, 'token_policy', unreadable)

    _pass(m, 3)

    # looked once, the minutes between two looks hold the other passes back
    assert asked == [1] and m.stop_event.n == 0
