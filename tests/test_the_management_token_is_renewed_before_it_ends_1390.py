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

Real requests: an HTTPS endpoint on loopback keeps PVE's rules for the token paths, the
policy (assert_token_policy) and what a token of the Administrator role may do.

MK Nov 2026
"""
import logging
import time
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
    new secret keeps the end it had, whatever the request said. `slow_put`: seconds a new
    secret takes to answer once PVE has carried it out (a user.cfg lock, a lossy link)."""

    def __init__(self, users, admins=(), modify_only=(), **kw):
        kw.setdefault('policy', POLICY)
        super().__init__(users, **kw)
        self.admins, self.modify_only = set(admins), set(modify_only)
        self.refuse, self.refuse_new, self.keep_end, self.slow_put = None, None, False, 0

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
        return super()._token(method, userid, name, who, form)

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
    """Its end comes in `left` seconds."""
    fake.expires[tid] = int(time.time()) + left


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

    # after a restart the end is not known: the policy is read, and again only in an hour
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

def test_a_token_near_its_end_is_renewed_over_the_password_login(cluster, db, said):
    """The account's token may manage no token (the documented PegaProx role), and after a
    restart PegaProx does not know when it ends: read once over the password login, then
    the new token is made there, stored, and the old one deleted."""
    fake = RenewPVE({USER: PASSWORD})
    m = cluster.make(fake)
    old = m.config.api_token_user
    old_secret = fake.tokens[old]
    _near(fake, old)
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


def test_an_end_neither_the_token_nor_a_login_may_read_is_said_once(cluster, said):
    """After a restart, a token that may manage no token and an account with two-factor
    login: PegaProx can neither read the end nor renew the token. Said at once, as the time
    left is not known."""
    fake = RenewPVE({USER: PASSWORD})
    m = cluster.make(fake)
    tid = m.config.api_token_user
    m = said.listen(cluster.restart(m))
    fake.tfa.add(USER)
    fake.seen.clear()

    _look(m)

    assert fake.calls('POST', 'PUT', 'DELETE') == []
    [warned] = [s for s in said.at(logging.WARNING) if '[TOKEN]' in s]
    assert tid in warned and 'neither read nor renew' in warned and 'two-factor' in warned
    assert len(said.alerts) == 1
    fake.seen.clear()
    _look(m)
    assert fake.logins() == [] and fake.seen == []


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
