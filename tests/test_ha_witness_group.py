"""The witness in a group (#625 stage 2): two data members and a witness are three votes.

The data members are the instances of tests/_ha_lease_harness.py, each with its state
file and the real routes; the witness is pegaprox/witness.py in a state directory of its
own, and every call to its address goes to Witness.handle through the same cuts and
pauses. Its lease clock is the one of instance e, which plays no other part here.

MK Oct 2026 (#625)
"""
import base64
import contextvars
import errno
import json
import os
import time

import pytest

from pegaprox import witness as wm
from pegaprox.core import ha_vote as hv
from pegaprox.core import ha_wire
from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_api import ADMIN_PW, _audit
from test_ha_lease_members import _restore
from test_ha_members import IDS, URLS, _post, _sync, group  # noqa: F401  (the fixture)

WURL = 'https://witness.example:5005'


class _Answer:
    def __init__(self, status, payload):
        self.status_code = status
        self.content = json.dumps(payload).encode()
        self.headers = {}

    def json(self):
        return json.loads(self.content)


class Host:
    """The witness next to the group."""

    def __init__(self, auto, tmp_path, monkeypatch):
        self.auto, self.g = auto, auto.g
        self.dir = wm.check_dir(str(tmp_path / 'witness'))
        self.down = False
        self.calls = []
        self.answers = []
        self.w = self.make()
        member_call = auto._call
        ha = self.g.ha

        def call(method, base_url, fingerprint, path, json_body=None, auth=None, headers=None,
                 timeout=15, keep_alive=False):
            if base_url.rstrip('/') != WURL:
                return member_call(method, base_url, fingerprint, path, json_body=json_body, auth=auth,
                                   headers=headers, timeout=timeout, keep_alive=keep_alive)
            me = self.g.name()
            raw = ha._wire_body(json_body)
            h = dict(auth(method, path, raw)) if auth is not None else {}
            h.update(headers or {})
            self.calls.append((me, method, path, h, raw))
            if self.down or 'w' in auto.paused:
                raise ha.PeerNoAnswer('The peer took the call but sent no answer: ReadTimeout')
            if (me, 'w') in auto.cuts:
                raise ha.PeerUnreachable('Cannot reach the peer: ConnectTimeout')
            status, payload = self.w.handle(method, path, h, raw, remote='198.51.100.5')
            if ('w', me) in auto.cuts:
                raise ha.PeerNoAnswer('The peer took the call but sent no answer: ReadTimeout')
            return _Answer(status, payload)
        monkeypatch.setattr(ha, '_peer_call', call)

    def make(self):
        return wm.Witness(self.dir, clock=lambda: self.auto.clock['e'], wall=time.time, started=0,
                          boot_id='boot-w', call=self._to_member)

    def _to_member(self, method, url, fingerprint, path, raw, headers, timeout=15):
        to = self.g.by_url[url.rstrip('/')]
        h = dict(headers, **{'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'})
        if raw:
            h['Content-Type'] = 'application/json'
        resp = contextvars.Context().run(self.g._serve, to, method, path, raw, h)
        try:
            data = resp.json()
        except Exception:
            data = None
        if path == wm.PAIR_PATH:
            self.answers.append(data)
        return resp.status_code, data if isinstance(data, dict) else None

    def restart(self):
        self.w = self.make()
        self.w.start()

    @property
    def node(self):
        return self.w.node

    def file(self):
        with open(os.path.join(self.dir, wm.STATE_NAME), encoding='utf-8') as fh:
            return json.load(fh)


@pytest.fixture
def host(auto, tmp_path, monkeypatch):
    return Host(auto, tmp_path, monkeypatch)


def _code(auto, site='dc3', on='a'):
    return auto.post(on, '/api/ha/witness/pairing-code',
                     {'url': URLS[on], 'user_password': ADMIN_PW, 'site': site})


def _pair(auto, host, site='dc3'):
    r = _code(auto, site)
    assert r.status_code == 200, r.data
    code = r.get_json()['code']
    assert code.startswith(ha_wire.WITNESS_CODE_PREFIX) and code in r.get_json()['commands']['package']
    assert host.w.join(code, WURL) == IDS['a']
    host.w.start()
    return code


def _form(auto, host, seed, standbys='b', accept=None):
    """An automatic group of a and `standbys` and the witness; a leads."""
    auto.pair(seed, standbys)
    _pair(auto, host)
    for n in standbys:
        assert _sync(auto.g, auto.admin, n) == 'applied'
    r = auto.switch_on(accept=accept)
    assert r.status_code == 200, r.data
    assert all(auto.mode(n) == 'auto' for n in auto.members)
    assert host.node.view.mode == hv.MODE_AUTO
    assert auto.leader() == 'a'


def _wid(host):
    return host.w.instance_id()


# --- pairing ---------------------------------------------------------------------------------

def test_a_witness_pairs_with_the_leader_and_is_no_member(auto, host, seed):
    auto.pair(seed, 'b')
    _pair(auto, host)
    wid = _wid(host)
    a = auto.file('a')
    rec = a['witness']
    assert rec == {'instance_id': wid, 'url': WURL, 'fingerprint': wm.tls_pair(host.dir)[2],
                   'public_key': ha_wire.public_of(ha_wire.private_key(host.file()['signing_key'])),
                   'site': 'dc3'}
    assert wid not in a['members'] and 'witness_pairing' not in a
    # the voter config names it, and the chain the witness holds is the leader's
    cfg = a['lease']['cfg']
    assert cfg['body']['witness'] == {'id': wid, 'public_key': rec['public_key'], 'site': 'dc3'}
    assert cfg['body']['mode'] == 'manual' and host.file()['cfg'] == cfg
    assert host.file()['epoch'] == a['epoch']
    with auto.at('a') as ha:
        assert ha.standby_count() == 1 and len(ha.members()) == 1 and not ha.group_full()
        assert ha.public_status()['auto']['witness']['url'] == WURL
    assert len(_audit('ha.witness_paired')) == 1 and len(_audit('ha.witness_code_created')) == 1
    # the member takes the record with its next sync, and reaches the witness
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    assert auto.file('b')['witness'] == rec
    with auto.at('b') as ha:
        ha._ask_witness()
        seen = ha._rt().seen[wid]
    assert seen['mark'] == ha_wire.LEASE_MARK and seen['mode'] == 'manual' and abs(seen['skew']) < 2
    # signed with b's key, which the witness knows from the voter config: no old secret
    assert all(ha_wire.PEER_HEADER in h and ':' not in h[ha_wire.PEER_HEADER]
               for _me, _m, _p, h, _r in host.calls)


def test_a_full_group_takes_a_witness_besides(auto, host, seed):
    """MAX_MEMBERS counts data members: three standbys and a witness."""
    auto.pair(seed, 'bcd')
    _pair(auto, host)
    with auto.at('a') as ha:
        assert ha.group_full() and ha.standby_count() == 3 and len(ha.members()) == 3
        assert len(ha.public_status()['members']) == 3
        body = ha._voter_body(ha._load(), 20)
    assert hv.CfgView({'id': [1, 1], 'body': body}).n == 5
    r = auto.post('a', '/api/ha/pairing-code', {'url': URLS['a'], 'user_password': ADMIN_PW})
    assert r.status_code == 409 and 'already has 3 standbys' in r.get_json()['error']


@pytest.mark.parametrize('case', ['no_password', 'second', 'standby', 'not_shipped', 'old_member',
                                  'site'])
def test_the_code_route_refuses(auto, host, seed, monkeypatch, case):
    auto.pair(seed, 'b')
    on, body = 'a', {'url': URLS['a'], 'user_password': ADMIN_PW}
    if case == 'no_password':
        body.pop('user_password')
    elif case == 'second':
        _pair(auto, host)
    elif case == 'standby':
        on, body['url'] = 'b', URLS['b']
    elif case == 'not_shipped':
        monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    elif case == 'old_member':
        with auto.at('a') as ha:
            monkeypatch.setattr(ha, '_ask_members', lambda timeout, refused=None: {})
            ha._rt().seen[IDS['b']] = {'mark': None, 'at': time.monotonic()}
    elif case == 'site':
        body['site'] = 'x' * 65
    r = auto.post(on, '/api/ha/witness/pairing-code', body)
    expected = {'no_password': 403, 'second': 409, 'standby': 409, 'not_shipped': 409,
                'old_member': 409, 'site': 400}[case]
    assert r.status_code == expected, r.data
    if case == 'second':
        assert r.get_json()['error'] == 'This group has a witness already - remove it first'
    if case == 'old_member':
        assert 'has not answered on a release with automatic failover' in r.get_json()['error']
    if case == 'not_shipped':
        assert r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED'


@pytest.mark.parametrize('case', ['wrong_code', 'expired', 'member_id', 'member_key', 'no_url',
                                  'member_code'])
def test_the_pair_route_refuses(auto, host, seed, case):
    auto.pair(seed, 'b')
    code = _code(auto).get_json()['code']
    info = ha_wire.decode_code(ha_wire.WITNESS_CODE_PREFIX, code)
    secret = info['secret']
    me = host.w.instance_id() or 'f' * 32
    key = ha_wire.new_signing_key()
    req = {'code': secret, 'instance_id': me, 'url': WURL, 'fingerprint': '',
           'public_key': ha_wire.public_of(ha_wire.private_key(key))}
    if case == 'wrong_code':
        req['code'] = 'x' * 43
    elif case == 'expired':
        with auto.at('a') as ha:
            st = ha._load()
            ha._update(witness_pairing=dict(st['witness_pairing'], expires=int(time.time()) - 1))
    elif case == 'member_id':
        req['instance_id'] = IDS['b']
    elif case == 'member_key':
        req['public_key'] = auto.file('a')['members'][IDS['b']]['public_key']
    elif case == 'no_url':
        req['url'] = ''
    elif case == 'member_code':
        # the code of a witness pairs no member
        r = auto.post('c', '/api/ha/join', {'code': code, 'own_url': URLS['c'], 'confirm': True,
                                            'user_password': ADMIN_PW})
        assert r.status_code == 400 and 'not a PegaProx pairing code' in r.get_json()['error']
        return
    status, data = host._to_member('POST', URLS['a'], '', wm.PAIR_PATH, ha_wire.wire_body(req), {})
    assert status == 403, data
    said = {'wrong_code': 'wrong or has expired', 'expired': 'wrong or has expired',
            'member_id': 'did not identify itself', 'member_key': 'usable public key',
            'no_url': 'must be https://'}[case]
    assert said in data['error'], data
    assert 'witness' not in auto.file('a')
    assert not _audit('ha.witness_paired')
    # the leader's half checks the code by itself too, not only the route before it
    if case == 'wrong_code':
        with auto.at('a') as ha:
            with pytest.raises(ha.HaError, match='wrong or has expired'):
                ha.accept_witness(req['code'], me, WURL, '', req['public_key'])


def test_a_witness_joins_an_automatic_group_by_a_change_of_the_config(auto, host, seed):
    auto.form(seed, 'bc')
    _pair(auto, host)
    wid = _wid(host)
    # the sealed answer carried the config as it is, which does not name the witness yet
    assert host.node.view.witness is None and host.file()['cfg'] == auto.file('a')['lease']['cfg']
    for _ in range(10):
        auto.run(1.0)
        if host.node.view.witness == wid:
            break
    with auto.at('a') as ha:
        view = ha._rts[IDS['a']].node.view
    assert view.witness == wid and view.n == 4
    assert host.node.view.witness == wid and host.node.promise_to == IDS['a']
    assert host.file()['cfg']['id'] == list(view.id)
    with auto.at('a') as ha:
        assert wid in ha._rts[IDS['a']].acked


def _opened(host, code):
    """The sealed part of the pair route's answer, as the witness opened it."""
    secret = ha_wire.decode_code(ha_wire.WITNESS_CODE_PREFIX, code)['secret']
    return ha_wire.unseal(secret, host.answers[-1]['sealed'], aad=host.w.instance_id())


def test_the_pairing_answer_carries_no_field_key(auto, host, seed):
    auto.pair(seed, 'b')
    code = _pair(auto, host)
    opened = _opened(host, code)
    assert set(opened) == {'public_key', 'epoch', 'chain', 'mode'}
    assert opened['mode'] == 'manual' and opened['chain'][-1] == auto.file('a')['lease']['cfg']
    assert set(host.answers[-1]) == {'instance_id', 'epoch', 'sealed'}


def test_in_an_automatic_group_the_answer_carries_the_floor(auto, host, seed):
    auto.form(seed, 'bc')
    code = _pair(auto, host)
    opened = _opened(host, code)
    assert set(opened) == {'public_key', 'epoch', 'chain', 'mode', 'floor_cv'}
    assert opened['mode'] == 'auto' and host.file()['floor_cv'] == opened['floor_cv']


def test_the_leader_never_shows_the_witness_an_old_secret(auto, host, seed):
    """A group from before the keys still has a member secret on the leader: its calls to
    the witness are signed and carry nothing of it."""
    _form(auto, host, seed)
    with auto.at('a') as ha:
        ha._update(member_secret='an-old-secret-from-before-the-keys-' + 'x' * 10)
        ha._ask_witness()
    auto.run(5)
    to_w = [h for me, _m, _p, h, _r in host.calls if me == 'a']
    assert to_w and all(set(h) <= {ha_wire.PEER_HEADER, ha_wire.PEER_TS_HEADER, ha_wire.PEER_NONCE_HEADER,
                                   ha_wire.PEER_SIG_HEADER, ha_wire.PEER_BODY_HEADER} for h in to_w)
    assert all(h[ha_wire.PEER_HEADER] == IDS['a'] for h in to_w)
    assert not any('an-old-secret' in json.dumps(h) for h in to_w)


def test_a_leave_nobody_signed_is_refused(auto, host, seed):
    auto.pair(seed, 'b')
    _pair(auto, host)
    wid = _wid(host)
    raw = ha_wire.wire_body({'epoch': 1})
    forged = ha_wire.signed_headers(ha_wire.private_key(ha_wire.new_signing_key()), wid, IDS['a'], 'POST',
                                    wm.LEAVE_PATH, raw, time.time())
    status, data = host._to_member('POST', URLS['a'], '', wm.LEAVE_PATH, raw, forged)
    assert status == 401 and auto.file('a')['witness']['instance_id'] == wid
    # nor one signed by the witness for another instance, or an old one
    key = ha_wire.private_key(host.file()['signing_key'])
    other = ha_wire.signed_headers(key, wid, IDS['b'], 'POST', wm.LEAVE_PATH, raw, time.time())
    assert host._to_member('POST', URLS['a'], '', wm.LEAVE_PATH, raw, other)[0] == 401
    old = ha_wire.signed_headers(key, wid, IDS['a'], 'POST', wm.LEAVE_PATH, raw, time.time() - 600)
    status, data = host._to_member('POST', URLS['a'], '', wm.LEAVE_PATH, raw, old)
    assert status == 401 and data['code'] == 'HA_CLOCK'
    assert auto.file('a')['witness']['instance_id'] == wid


# --- the third vote ----------------------------------------------------------------------------

def test_two_data_members_and_the_witness_elect_and_renew(auto, host, seed):
    _form(auto, host, seed)
    wid = _wid(host)
    auto.run(30)
    assert auto.leader() == 'a'
    assert host.node.promise_to == IDS['a'] and host.file()['voted_for'] == IDS['a']
    with auto.at('a') as ha:
        assert wid in ha._rts[IDS['a']].acked
        st = ha.lease_status()
    row = next(r for r in st['members'] if r['kind'] == 'witness')
    assert row['instance_id'] == wid and row['url'] == WURL and row['voter'] is True
    assert row['last_heard'] is not None and row['last_heard'] < 5
    assert st['voters'] == 3 and st['majority'] == 2 and st['witness']['url'] == WURL


def test_the_witness_votes_a_member_in_when_the_leader_is_gone(auto, host, seed):
    _form(auto, host, seed)
    auto.run(10)
    auto.crash('a')
    auto.run(150, members='b', until=lambda: auto.leader() == 'b')
    assert auto.leader() == 'b'
    st = host.file()
    assert st['voted_for'] == IDS['b'] and st['epoch'] == auto.file('b')['epoch'] > 1
    assert host.node.promise_to == IDS['b']
    # the one that was gone comes back as a standby of the new leader
    auto.back('a')
    auto.run(30)
    assert auto.leader() == 'b' and auto.state('a')['role'] == 'standby'


def test_without_the_witness_the_two_go_on(auto, host, seed):
    _form(auto, host, seed)
    wid = _wid(host)
    host.down = True
    with auto.at('a') as ha:
        before = ha._rts[IDS['a']].node.lease_until
    auto.run(90)
    assert auto.leader() == 'a'
    with auto.at('a') as ha:
        rt = ha._rts[IDS['a']]
        # renewed all along, by b alone: the witness acked nothing since it went
        assert rt.node.lease_until > before + 60
        assert ha.ha_clock() - rt.acked[wid] > 80 and ha.ha_clock() - rt.acked[IDS['b']] < 5


def test_without_a_member_and_the_witness_the_leader_stops_acting(auto, host, seed):
    _form(auto, host, seed)
    auto.run(10)
    auto.crash('b')
    host.down = True
    with auto.at('a') as ha:
        until = ha._rts[IDS['a']].node.lease_until
    auto.run(T.L, members='a')
    assert auto.active() == []
    with auto.at('a') as ha:
        assert ha.ha_clock() <= until + T.L and not ha.is_active()
    # and it acts again once a majority is back
    host.down = False
    auto.run(120, members='a', until=lambda: auto.leader() == 'a')
    assert auto.leader() == 'a'


def test_a_restarted_witness_keeps_its_promise(auto, host, seed):
    """The witness restarts just after the leader died: the persisted holder is the old
    leader, and the hold after its start keeps it from voting the member in until a
    lease that rested on its forgotten promise surely ran out. b's timer fires 22 to 27 s
    after the last renewal, the hold runs to 29 s."""
    _form(auto, host, seed)
    auto.run(10)
    auto.crash('a')
    auto.run(5, members='b')
    host.restart()
    restarted = auto.clock['e']
    assert host.file()['voted_for'] == IDS['a']
    refused = []
    real = host.w.handle

    def handle(method, path, headers, body=b'', remote=''):
        out = real(method, path, headers, body, remote)
        if path == wm.VOTE_PATH and out[1].get('reason') == 'HOLD_AFTER_START':
            refused.append(auto.clock['e'])
        return out
    host.w.handle = handle
    auto.run(150, members='b', until=lambda: host.file()['voted_for'] == IDS['b'])
    assert refused and host.file()['voted_for'] == IDS['b']
    assert host.node.started == restarted
    granted_at = auto.clock['e']
    assert granted_at >= restarted + T.hold_after_start


def test_the_leader_counts_the_witness_and_says_when_it_is_gone(auto, host, seed, monkeypatch):
    auto.pair(seed, 'b')
    _pair(auto, host)
    wid = _wid(host)
    with auto.at('a') as ha:
        ha._ask_witness()
        found = {f['code']: f for f in ha.auto_findings()}
        assert 'TOO_FEW_VOTERS' not in found and 'VOTER_DOWN' not in found
        ha._rts[IDS['a']].seen[wid]['at'] -= ha.LEASE_SEEN_FRESH + 1
        found = {f['code']: f for f in ha.auto_findings()}
    assert found['VOTER_DOWN']['member'] == wid
    assert found['VOTER_DOWN']['text'].startswith(f'The witness {WURL} has not answered')
    # a witness at the site of a data member
    with auto.at('a') as ha:
        ms = ha._load()['members']
        ha._update(members={k: dict(v, site='dc3') for k, v in ms.items()})
        found = {f['code']: f for f in ha.auto_findings()}
    assert found['WITNESS_SAME_SITE']['level'] == 'warn' and 'dc3' in found['WITNESS_SAME_SITE']['text']


@pytest.mark.parametrize('how', ['enospc', 'readonly_dir'])
def test_the_leader_shows_a_witness_that_cannot_write_as_one_vote_less(auto, host, seed, monkeypatch, how):
    """A witness on a full disk, or whose state directory went read-only, acks the
    renewals that need no write, as the node's rules say. It writes its state again every
    WRITE_CHECK seconds and says with every answer that it cannot: within that and a
    renewal the leader's findings name it as the vote the group lacks - not first at the
    failover, when it refuses the vote that decides it."""
    _form(auto, host, seed)
    wid = _wid(host)
    auto.run(10)

    def findings():
        with auto.at('a') as ha:
            return [f for f in ha.auto_findings() if f['code'] == 'STATE_NOT_WRITTEN']
    assert findings() == []
    real = wm._write_json
    if how == 'enospc':
        def full(path, data, strict=True):
            raise OSError(errno.ENOSPC, 'No space left on device')
        monkeypatch.setattr(wm, '_write_json', full)
    else:
        if os.geteuid() == 0:
            pytest.skip('root writes into a 0500 directory')
        os.chmod(host.dir, 0o500)
    try:
        auto.run(wm.WRITE_CHECK + 2 * T.R, until=lambda: findings() != [])
        found = findings()
        assert [f['member'] for f in found] == [wid] and found[0]['level'] == 'warn'
        assert found[0]['text'].startswith(f'The witness {WURL} cannot write its state file')
        assert 'The group has one vote less, 2 of its 3: one more failure may stop automation.' in found[0]['text']
        with auto.at('a') as ha:
            assert ha.witness_view()['write_failed'] is True
            # what needs no write it still acks: the leader goes on
            assert ha.ha_clock() - ha._rts[IDS['a']].acked[wid] < 5
        assert auto.leader() == 'a' and host.w.status(IDS['a'])['write_failed'] is True
    finally:
        os.chmod(host.dir, 0o700)
        monkeypatch.setattr(wm, '_write_json', real)
    # the disk is back: the next check and renewal clear it
    auto.run(wm.WRITE_CHECK + 2 * T.R, until=lambda: findings() == [])
    assert findings() == []
    with auto.at('a') as ha:
        assert ha.witness_view()['write_failed'] is False


def test_the_witness_waits_while_automatic_failover_is_switched_off(auto, host, seed):
    """Until a majority holds the switch back to manual mode the leader's lease is in
    force and its voter config takes no other change, as set_lease_seconds says: no
    witness is paired, removed or put into the config meanwhile."""
    _form(auto, host, seed)
    auto.past_the_hold()
    auto.isolate('a')
    auto.cut('a', 'w')
    r = auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json()['mode'] == 'auto', r.data
    r = _code(auto)
    assert r.status_code == 409 and 'being switched off' in r.get_json()['error'], r.data
    with auto.at('a') as ha:
        with pytest.raises(ha.HaError, match='being switched off'):
            ha.remove_witness()
        # a record the config does not name as it is: nothing is asked for until then
        rec = ha._load()['witness']
        ha._update(witness=dict(rec, site='dc9'))
        assert ha._witness_into_config() == ''
        assert ha._rts[IDS['a']].node._changes == []
    assert auto.file('a')['witness']['instance_id'] == _wid(host) and host.w.paired()


# --- a promotion by hand asks the witness too -----------------------------------------------------

PROMOTE_FORCED = {'confirm': 'PROMOTE', 'force': True, 'user_password': ADMIN_PW}


def test_a_member_restored_from_before_the_switch_is_not_promoted_next_to_the_leader(auto, host, seed):
    """b, restored from its state before the switch and cut from a, holds a manual config
    and nothing that says otherwise. Of two data members and the witness, the witness is
    the one voter besides the leader that answers it, and it keeps a's promise."""
    auto.pair(seed, 'b')
    _pair(auto, host)
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    backup = auto.file('b')
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    auto.cut('a', 'b')
    _restore(auto, 'b', backup)
    assert auto.mode('b') == 'manual' and auto.leader() == 'a'

    with auto.at('b'):
        r = _post(auto.admin, '/api/ha/promote', PROMOTE_FORCED)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert r.get_json()['error'].startswith(f'The witness {WURL} says this group fails over automatically')
    assert auto.file('b')['role'] == 'standby' and not _audit('ha.promoted')
    auto.run(30, members='a')
    assert auto.leader() == 'a' and auto.active() == ['a']


@pytest.mark.parametrize('force', [True, False])
def test_a_switch_back_only_the_member_took_is_not_promoted_next_to_the_leader(auto, host, seed, force):
    """a switches back to manual mode; only b takes the config, its answer is lost, and the
    witness is cut from a for that round. a loses its lease, drops the config, and is
    elected again with the witness. b, still cut from a, holds a manual config nobody
    committed: the witness says the group is automatic, as a third data member would."""
    _form(auto, host, seed)
    auto.past_the_hold()
    auto.cut('a', 'w')
    auto.cuts.add(('b', 'a'))
    r = auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    auto.run(1, members='a')
    assert auto.mode('b') == 'manual'
    auto.run(40, members='a')
    auto.heal()
    auto.cut('a', 'b')
    auto.run(150, members='a', until=lambda: 'a' in auto.active())
    assert auto.active() == ['a'] and auto.mode('b') == 'manual'
    assert host.node.view.mode == hv.MODE_AUTO and host.node.promise_to == IDS['a']

    # without force as well: the instance it follows does not answer, so no sync comes first
    body = PROMOTE_FORCED if force else dict(PROMOTE_FORCED, force=False)
    with auto.at('b'):
        r = _post(auto.admin, '/api/ha/promote', body)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert r.get_json()['error'].startswith(f'The witness {WURL} says')
    assert auto.file('b')['role'] == 'standby'
    auto.run(30, members='a')
    assert auto.active() == ['a']


def _asked(auto, wid, seen):
    """b's status call: a does not answer, the witness says `seen`."""
    def ask(rec, signer, timeout):
        if rec['instance_id'] != wid:
            raise auto.ha.PeerUnreachable('Cannot reach the peer: ConnectTimeout')
        return 'standby', 1, None, False, (None, None), dict({'mark': auto.ha.LEASE_MARK}, **seen)
    return ask


@pytest.mark.parametrize('seen,refused', [
    ({'mode': 'manual'}, False),
    ({'mode': 'manual', 'holder': 'a'}, False),
    ({'mode': 'auto', 'cfg_id': 'newer'}, True),
    ({'mode': 'auto', 'cfg_id': 'older'}, False),
    ({'mode': 'auto', 'cfg_id': 'older', 'holder': 'a'}, True),
    ({'mode': 'auto_pending', 'cfg_id': 'older', 'holder': 'a'}, True),
])
def test_the_witness_answers_a_promotion_as_a_member_does(auto, host, seed, monkeypatch, seen, refused):
    """b holds the switch back to manual mode and knows it went through (it pulled from the
    manual active). A witness that says automatic with a newer config, or that keeps a
    promise (it holds no lease of its own), is a group that elects; one with an older
    config and no promise missed the switch back, as a member would."""
    _form(auto, host, seed)
    auto.past_the_hold()
    r = auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    auto.run(2 * T.R, dt=1.0)
    assert _sync(auto.g, auto.admin, 'b') in ('applied', 'unchanged')
    held = auto.file('b')['lease']
    assert held['mode'] == 'manual' and held['settled'] == hv.cfg_digest(held['cfg'])
    wid = _wid(host)
    seen = dict(seen)
    with auto.at('b') as ha:
        mine = hv.pair(ha._lease(ha._load())['cfg']['id'])
        if 'cfg_id' in seen:
            seen['cfg_id'] = (mine[0] + 1, 1) if seen['cfg_id'] == 'newer' else (0, 0)
        if 'holder' in seen:
            seen['holder'] = IDS[seen['holder']]
        monkeypatch.setattr(ha, '_ask', _asked(auto, wid, seen))
        said = ha._members_say_auto()
    if refused:
        assert said['instance_id'] == wid and said['kind'] == 'witness' and said['url'] == WURL
    else:
        assert said is None


def test_the_witness_counts_when_a_member_weighs_the_switch_back(auto, host, seed, monkeypatch):
    """Four votes: a, b, c and the witness. b holds the leader's switch back to manual
    mode and never heard that it went through; a lost its lease meanwhile and says
    automatic with the config before it. c and the witness hold the switch back: with b
    three of the four voters before it, so it is the group's and a only missed it.
    Without the witness's answer that is two of four, and b is not promoted."""
    _form(auto, host, seed, standbys='bc', accept=['EVEN_VOTERS'])
    auto.past_the_hold()
    r = auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    auto.run(2 * T.R, dt=1.0, until=lambda: auto.file('a')['role'] == 'active')
    assert host.node.view.mode == hv.MODE_MANUAL and auto.mode('b') == 'manual'
    wid = _wid(host)
    with auto.at('b') as ha:
        lease = ha._lease(ha._load())
        before = lease['cfg_chain'][-1]
        assert before['body']['mode'] == hv.MODE_AUTO
        ha._update(lease={k: v for k, v in lease.items() if k != 'settled'})
        digest = hv.cfg_digest(lease['cfg'])
        answers = {IDS['a']: {'mode': hv.MODE_AUTO, 'cfg_id': hv.pair(before['id']), 'holds': False},
                   IDS['c']: {'mode': hv.MODE_MANUAL, 'cfg_digest': digest},
                   wid: ha._lease_seen(host.w.status(IDS['b']), time.time(), time.time())}
        assert answers[wid]['cfg_digest'] == digest

        def ask(rec, signer, timeout):
            if rec['instance_id'] not in answers:
                raise ha.PeerUnreachable('Cannot reach the peer: ConnectTimeout')
            return 'standby', 1, None, False, (None, None), dict(answers[rec['instance_id']])
        monkeypatch.setattr(ha, '_ask', ask)
        assert ha._members_say_auto() is None
        answers.pop(wid)
        assert ha._members_say_auto()['instance_id'] == IDS['a']


def test_a_pending_switch_is_not_taken_back_while_the_witness_keeps_a_promise(auto, host, seed):
    """An active that leaves the lead takes the switch it started back, unless the group
    elects already: a promise the witness keeps is a lease somebody holds."""
    auto.pair(seed, 'b')
    _pair(auto, host)
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    r = auto.switch_on(settle=False)
    assert r.status_code == 200 and r.get_json()['mode'] == 'auto_pending', r.data
    wid = _wid(host)
    with auto.at('a') as ha:
        pending = hv.pair(ha._lease(ha._load())['cfg']['id'])
        seen = {'mark': ha.LEASE_MARK, 'mode': hv.MODE_PENDING, 'cfg_id': pending, 'holds': False,
                'at': time.monotonic()}
        ha._rt().seen[wid] = dict(seen)
        assert ha._switch_taken_back(ha._load())['mode'] == 'manual'
        ha._rt().seen[wid] = dict(seen, holder=IDS['b'])
        assert ha._switch_taken_back(ha._load()) is None
        ha._rt().seen[wid] = dict(seen, holder=IDS['b'], mode=hv.MODE_MANUAL)
        assert ha._switch_taken_back(ha._load())['mode'] == 'manual'


# --- leaving ------------------------------------------------------------------------------------

def test_the_leader_removes_the_witness_and_tells_it(auto, host, seed):
    auto.pair(seed, 'b')
    _pair(auto, host)
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    r = auto.post('a', '/api/ha/witness/remove', {'confirm': 'REMOVE'})
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'
    r = auto.post('a', '/api/ha/witness/remove', {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json() == {'success': True, 'told': True}
    assert 'witness' not in auto.file('a') and not host.w.paired()
    assert len(_audit('ha.witness_removed')) == 1
    # the members drop it with the next sync
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    assert 'witness' not in auto.file('b')
    # and another one can be paired
    assert _code(auto).status_code == 200


def test_an_automatic_group_keeps_its_third_vote(auto, host, seed):
    _form(auto, host, seed)
    r = auto.post('a', '/api/ha/witness/remove', {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE'
    assert 'fewer than 3 votes' in r.get_json()['error']
    assert auto.file('a')['witness'] and host.w.paired()
    # the witness cannot leave by itself either, unless it is forced to
    with pytest.raises(wm.WitnessError, match='fewer than 3 votes'):
        host.w.leave()
    assert host.w.paired() and auto.file('a')['witness']


def test_with_four_votes_the_witness_goes_by_a_change_of_the_config(auto, host, seed):
    _form(auto, host, seed, standbys='bc', accept=['EVEN_VOTERS'])
    wid = _wid(host)
    r = auto.post('a', '/api/ha/witness/remove', {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    assert r.get_json()['told'] is True and not host.w.paired()
    for _ in range(10):
        auto.run(1.0)
    with auto.at('a') as ha:
        view = ha._rts[IDS['a']].node.view
    assert view.witness is None and view.n == 3 and wid not in view.members
    assert auto.leader() == 'a'


def test_the_witness_leaves_on_its_own(auto, host, seed):
    auto.pair(seed, 'b')
    _pair(auto, host)
    assert host.w.leave() is True
    assert 'witness' not in auto.file('a') and not host.w.paired()
    assert len(_audit('ha.witness_left')) == 1


# --- what the witness never holds --------------------------------------------------------

def _secrets_of_the_group(auto):
    from pegaprox.core.db import get_db
    field = get_db().aes_key
    out = {'field key': [field, base64.b64encode(field), field.hex().encode()]}
    for n in auto.members:
        key = auto.file(n)['signing_key']
        raw = base64.b64decode(key)
        out[f'private key of {n}'] = [key.encode(), raw, raw.hex().encode()]
    return out


def test_nothing_secret_ends_up_on_the_witness(auto, host, seed):
    _form(auto, host, seed)
    auto.run(10)
    auto.crash('a')
    auto.run(150, members='b', until=lambda: auto.leader() == 'b')
    found = []
    for folder, _dirs, files in os.walk(host.dir):
        for name in files:
            with open(os.path.join(folder, name), 'rb') as fh:
                data = fh.read()
            for what, forms in _secrets_of_the_group(auto).items():
                if any(f in data for f in forms):
                    found.append((name, what))
    assert found == []
    st = host.file()
    assert not {'members', 'field_key', 'tombstones', 'lease', 'sync'} & set(st)
    # what the witness holds besides the vote: its own key, its id, its addresses
    assert set(st) <= {'role', 'instance_id', 'signing_key', 'own_url', 'paired', 'epoch', 'voted_for',
                       'gen', 'cfg', 'cfg_chain', 'floor_cv', 'led', 'released', 'campaign_after',
                       'promised'}
