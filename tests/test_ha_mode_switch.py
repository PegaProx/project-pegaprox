"""Switching a group between manual and automatic failover (#625 stage 2, design 4.13).

On: the leader hands every member the voter config as pending, and commits automatic
mode once all of them hold it. Off: committed on a majority, no member out of reach
holds it up. And what is refused: too few votes, clocks apart, releases apart, a
release that does not offer it.

MK Oct 2026 (#625)
"""
import pytest

from pegaprox.core import ha_vote as hv
from test_ha_api import ADMIN_PW, _audit
from test_ha_members import IDS, URLS, _pair, _promote, _sync, _watch, group  # noqa: F401
from _ha_lease_harness import T, auto  # noqa: F401 - the fixture

ON = {'mode': 'auto', 'user_password': ADMIN_PW}
OFF = {'mode': 'manual', 'user_password': ADMIN_PW}


def _findings(r):
    return {f['code']: f for f in r.get_json()['findings']}


# --- refused -----------------------------------------------------------------------------

def test_the_server_refuses_automatic_mode_where_it_does_not_ship(auto, seed, monkeypatch):
    """AUTO_MODE_SHIPPED off, as on a release before the beta: no switch, no vote, no
    renewal, and nothing of the lease in a status answer."""
    auto.pair(seed)
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    assert hv.AUTO_MODE_SHIPPED is False

    r = auto.put('a', '/api/ha/mode', ON)
    assert r.status_code == 409 and r.get_json() == {
        'code': 'HA_AUTO_NOT_SHIPPED', 'error': 'Automatic failover is not available in this release yet'}
    with auto.at('a') as ha:
        with pytest.raises(ha.HaError, match='not available in this release'):
            ha.switch_auto_on()
        assert ha.lease_request(IDS['b'], 'renew', {})['reason'] == 'NOT_SHIPPED'
        assert ha.lease_request(IDS['b'], 'vote', {})['reason'] == 'NOT_SHIPPED'
        assert ha.public_status()['auto'] is None and ha.lease_start() is False
        assert ha.lease_step() is None and ha.mode() == 'manual'
    assert 'lease' not in auto.file('a')
    # the peer status is the one of the release before
    with auto.at('b'):
        said = auto.g.client.get('/api/ha/peer/status', headers=dict(
            auto.g.signed('a', 'b'), **{'X-Requested-With': 'XMLHttpRequest'}),
            base_url='http://localhost').get_json()
    assert sorted(said) == ['cv', 'cv_at', 'epoch', 'group', 'instance_id', 'role', 'serving']


def test_lease_state_on_an_instance_that_does_not_offer_it_keeps_it_passive(auto, seed, monkeypatch):
    """A state file from a release that had automatic failover, under one that does not
    (a downgrade, or the constant switched back): no node is built for it, so the leader
    on disk holds no lease and acts on nothing. The same as a release before it, which
    reads 'leader' as no role it knows."""
    auto.form(seed)
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    auto.g.calls.clear()
    for n in 'ab':
        with auto.at(n) as ha:
            ha._rts.pop(IDS[n], None)
            assert ha._lease_node() is None and ha.lease_step() is None
            assert not ha.is_active() and not ha.holds_lease() and not ha.acting_process()
            # the boot check asks nobody for a lease either
            ha.check_peer_at_boot()
            assert ha._rt().node is None
    assert not [c for c in auto.g.calls if c[3] in ('/api/ha/peer/renew', '/api/ha/peer/vote')]


def test_it_ships_as_a_beta_and_a_group_starts_manual(auto, seed):
    """The constant itself is on (read from the source, the fixture sets it as well), and
    manual mode stays the default: a group formed on this release fails over by hand until
    an admin switches it."""
    import ast
    import inspect
    src = ast.parse(inspect.getsource(hv))
    value = next(n.value.value for n in src.body if isinstance(n, ast.Assign)
                 and n.targets[0].id == 'AUTO_MODE_SHIPPED')
    assert value is True
    auto.pair(seed)
    assert [auto.mode(n) for n in 'abc'] == ['manual'] * 3
    with auto.at('a') as ha:
        assert ha.public_status()['auto']['mode'] == 'manual'


def test_fewer_than_three_votes_is_refused(auto, seed):
    auto.pair(seed, 'b')

    r = auto.put('a', '/api/ha/mode', ON)

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_REFUSED'
    f = _findings(r)['TOO_FEW_VOTERS']
    assert f['level'] == 'block' and 'at least 3 votes, this group has 2' in f['text']
    assert r.get_json()['error'] == f['text']
    assert 'lease' not in auto.file('a') and auto.mode('a') == 'manual'
    # ticking the warning box does not help: it is no warning
    r = auto.put('a', '/api/ha/mode', dict(ON, accept=['TOO_FEW_VOTERS']))
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_REFUSED'


@pytest.mark.parametrize('skew,ok', [(4.0, True), (-4.0, True), (9.0, False), (-9.0, False)])
def test_clocks_more_than_five_seconds_apart_are_refused(auto, seed, skew, ok):
    auto.skew['c'] = skew
    auto.pair(seed)
    with auto.at('a') as ha:
        seen = ha._rt().seen[IDS['c']]
    # measured from the status answer, at the middle of the call
    assert seen['skew'] == pytest.approx(skew, abs=0.5)

    r = auto.put('a', '/api/ha/mode', ON)

    if ok:
        assert r.status_code == 200, r.data
    else:
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_REFUSED'
        f = _findings(r)['CLOCK_SKEW']
        assert f['member'] == IDS['c'] and f['level'] == 'block'
        assert URLS['c'] in f['text'] and '9 s off' in f['text'] and '5 s or less' in f['text']
        assert 'lease' not in auto.file('a')


def test_a_member_on_another_release_is_refused(auto, seed, monkeypatch):
    real = auto.ha.peer_lease_status
    monkeypatch.setattr(auto.ha, 'peer_lease_status', lambda: dict(
        real(), **({'release': '1.1.9'} if auto.g.name() == 'c' else {})))
    auto.pair(seed)

    r = auto.put('a', '/api/ha/mode', ON)

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_REFUSED'
    f = _findings(r)['RELEASE_MISMATCH']
    assert f['member'] == IDS['c'] and 'release 1.1.9' in f['text'] and 'same release' in f['text']
    assert 'lease' not in auto.file('a')


def test_a_member_that_does_not_speak_the_lease_is_refused(auto, seed, monkeypatch):
    """A release before automatic failover answers the status without the mark."""
    real = auto.ha.peer_lease_status
    monkeypatch.setattr(auto.ha, 'peer_lease_status',
                        lambda: {} if auto.g.name() == 'b' else real())
    auto.pair(seed)

    r = auto.put('a', '/api/ha/mode', ON)

    assert r.status_code == 409
    f = _findings(r)['OLD_RELEASE']
    assert f['member'] == IDS['b'] and 'without automatic failover' in f['text']


def test_a_member_that_does_not_answer_is_refused(auto, seed):
    """Every member is asked again right before the switch: what the watch heard half a
    minute ago does not count for one that is gone now."""
    auto.pair(seed)
    auto.crash('b')

    r = auto.put('a', '/api/ha/mode', ON)

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_REFUSED'
    f = _findings(r)['VOTER_DOWN']
    assert f['level'] == 'block' and f['member'] == IDS['b'] and '2 minutes' in f['text']
    assert 'lease' not in auto.file('a')
    # it answers again: no watch pass needed in between, the switch asks for itself
    auto.g.down.discard('b')
    assert auto.put('a', '/api/ha/mode', ON).status_code == 200


def test_an_even_number_of_votes_wants_a_tick_and_says_what_it_costs(auto, seed):
    auto.pair(seed, 'bcd')

    r = auto.put('a', '/api/ha/mode', ON)

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_CONFIRM'
    f = _findings(r)['EVEN_VOTERS']
    assert f['level'] == 'warn'
    # the exact consequence, in numbers
    assert '4 votes survive the loss of 1, the same as 3 would' in f['text']
    assert 'two halves of 2 leaves no leader on either side' in f['text']
    assert 'lease' not in auto.file('a')

    r = auto.switch_on(accept=['EVEN_VOTERS'])
    assert r.status_code == 200 and sorted(r.get_json()['waiting']) == sorted(IDS[n] for n in 'bcd')
    assert all(auto.mode(n) == 'auto' for n in 'abcd') and auto.leader() == 'a'
    assert auto.node('a').view.n == 4 and auto.node('a').view.m == 3


def test_the_switch_is_made_on_the_leader_with_a_password_and_a_valid_lease_length(auto, seed):
    auto.pair(seed)

    assert auto.put('b', '/api/ha/mode', ON).status_code == 409
    assert auto.put('b', '/api/ha/mode', ON).get_json()['code'] == 'HA_STANDBY'
    r = auto.put('a', '/api/ha/mode', {'mode': 'auto'})
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'
    for bad in (14, 121, '20', True, 20.5):
        r = auto.put('a', '/api/ha/mode', dict(ON, lease_s=bad))
        assert r.status_code == 400 and '15 to 120' in r.get_json()['error'], bad
    assert auto.put('a', '/api/ha/mode', {'mode': 'maybe'}).status_code == 400
    assert auto.put('a', '/api/ha/mode', OFF).status_code == 409        # it is in manual mode
    assert 'lease' not in auto.file('a')


# --- switching on ------------------------------------------------------------------------

def test_the_switch_is_pending_until_every_member_holds_it(auto, seed):
    auto.pair(seed)

    r = auto.switch_on(lease_s=30, settle=False)

    assert r.status_code == 200 and r.get_json()['mode'] == 'auto_pending'
    assert sorted(r.get_json()['waiting']) == [IDS['b'], IDS['c']]
    a = auto.file('a')
    # still the manual active: the lease is not in force before the commit
    assert a['role'] == 'active' and a['lease']['mode'] == 'auto_pending'
    assert a['lease']['cfg']['body']['lease_s'] == 30
    with auto.at('a') as ha:
        assert ha.is_active() and not ha.lease_in_force()
    assert 'lease' not in auto.file('b')
    assert [r['details'] for r in _audit('ha.auto_pending')]

    # b hears of it, c does not yet
    auto.cut('a', 'c')
    auto.step('a')
    assert auto.mode('b') == 'auto_pending' and auto.mode('a') == 'auto_pending'
    assert 'lease' not in auto.file('c')
    with auto.at('b') as ha:
        # a member that holds the pending config is no voter yet, and no candidate
        assert not ha.lease_in_force() and ha.is_standby()
        ans = ha.lease_request(IDS['c'], 'vote', {'epoch': 2, 'candidate': IDS['c'], 'pre': True,
                                                  'cv': [1, 1], 'cfg_id': [1, 2], 'lease_s': 30})
        assert ans['granted'] is False and ans['reason'] == 'MODE_MANUAL'
    # nobody is promoted by hand while the switch is on its way
    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE'
    assert auto.file('b')['role'] == 'standby'
    # and the leader hands out no pairing code
    r = auto.post('a', '/api/ha/pairing-code', {'url': URLS['a'], 'user_password': ADMIN_PW})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE'

    auto.heal()
    auto.run(2 * T.R, dt=1.0)
    assert all(auto.mode(n) == 'auto' for n in 'abc') and auto.leader() == 'a'
    assert auto.file('a')['role'] == 'leader'
    assert [r['details'] for r in _audit('ha.auto_on')]


def test_a_member_that_never_takes_it_takes_the_group_back_to_manual_mode(auto, seed):
    auto.pair(seed)

    assert auto.switch_on(settle=False).status_code == 200
    # c answered when the switch asked, and is gone before the config reaches it
    auto.crash('c')
    auto.members = 'ab'
    auto.run(hv.SWITCH_TIMEOUT - 10, dt=4.0)
    assert auto.mode('a') == auto.mode('b') == 'auto_pending' and auto.active() == ['a']

    auto.run(20 + 2 * T.R, dt=2.0)

    assert auto.mode('a') == auto.mode('b') == 'manual'
    assert auto.file('a')['role'] == 'active' and auto.active() == ['a']
    assert [r['details'] for r in _audit('ha.auto_cancelled')]
    # manual mode again: a promotion by hand is what it was
    with auto.at('b') as ha:
        assert not ha.lease_in_force() and ha.mode() == 'manual'


def test_the_admin_takes_a_pending_switch_back(auto, seed):
    auto.pair(seed)
    assert auto.switch_on(settle=False).status_code == 200
    auto.crash('c')
    auto.members = 'ab'
    auto.step('a')
    assert auto.mode('b') == 'auto_pending'

    # not on a member: the instance that started it takes it back
    r = auto.put('b', '/api/ha/mode', OFF)
    assert r.status_code == 409
    r = auto.put('a', '/api/ha/mode', OFF)
    assert r.status_code == 200 and r.get_json()['result'] == 'cancelled'
    auto.run(2 * T.R, dt=1.0)

    assert auto.mode('a') == auto.mode('b') == 'manual' and auto.file('a')['role'] == 'active'


def test_a_restart_of_the_switching_instance_takes_the_switch_back(auto, seed):
    auto.pair(seed)
    assert auto.switch_on(settle=False).status_code == 200
    auto.crash('c')
    auto.members = 'ab'
    auto.step('a')
    assert auto.mode('b') == 'auto_pending'

    auto.restart('a')
    auto.run(2 * T.R, dt=1.0)

    # nothing drove the pending config any more: the members do not wait for ever
    assert auto.mode('a') == auto.mode('b') == 'manual' and auto.active() == ['a']


# --- switching off -----------------------------------------------------------------------

def test_switching_off_makes_the_leader_a_manual_active_again(auto, seed):
    auto.form(seed)

    r = auto.put('b', '/api/ha/mode', OFF)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    r = auto.put('a', '/api/ha/mode', OFF)
    assert r.status_code == 200 and r.get_json()['result'] == 'off'
    auto.run(2 * T.R, dt=1.0)

    a = auto.file('a')
    assert a['role'] == 'active' and a['lease']['mode'] == 'manual' and 'leader' not in a
    assert all(auto.mode(n) == 'manual' for n in 'abc')
    with auto.at('a') as ha:
        assert ha.is_active() and ha.holds_lease() and ha.acting_process()
        assert not ha.lease_in_force() and ha.no_lease() is None
    assert [r['details'] for r in _audit('ha.auto_off')]
    # no renewals any more, and the lease means nothing: time passes, a stays active
    auto.g.calls.clear()
    auto.run(3 * T.L, dt=2.0)
    assert auto.active() == ['a']
    assert not [c for c in auto.g.calls if c[3] in ('/api/ha/peer/renew', '/api/ha/peer/vote')]

    # and a standby is promoted by hand again
    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 200, r.data
    assert auto.file('b')['role'] == 'active' and auto.file('b')['epoch'] == 2


def test_switching_off_needs_a_majority_not_every_member(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    auto.isolate('c')
    auto.members = 'ab'

    assert auto.put('a', '/api/ha/mode', OFF).status_code == 200
    auto.run(2 * T.R, dt=1.0)
    assert auto.mode('a') == auto.mode('b') == 'manual' and auto.file('a')['role'] == 'active'
    assert auto.mode('c') == 'auto'

    # c missed it and campaigns once its promise ran out: every manual member refuses it
    # and hands it the config, which it takes
    auto.heal()
    auto.members = 'abc'
    auto.run(T.P + T.L / 4 + T.R, dt=1.0)
    assert auto.mode('c') == 'manual' and auto.file('c')['role'] == 'standby'
    assert auto.file('c')['epoch'] == 1 and auto.active() == ['a']


def test_switching_off_on_a_leader_without_its_lease_is_refused(auto, seed):
    auto.form(seed)
    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 1)

    r = auto.put('a', '/api/ha/mode', OFF)

    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE'
    assert auto.mode('a') == 'auto'


def test_the_group_switches_on_again_on_the_chain_it_has(auto, seed):
    auto.form(seed)
    first = auto.file('a')['lease']['cfg']
    auto.put('a', '/api/ha/mode', OFF)
    auto.run(2 * T.R, dt=1.0)
    assert auto.mode('a') == 'manual'

    auto.watch('a')
    r = auto.switch_on()

    assert r.status_code == 200 and all(auto.mode(n) == 'auto' for n in 'abc')
    cfg = auto.file('a')['lease']['cfg']
    # the next configs of the same chain, no new start: [epoch, version] only goes up
    assert cfg['id'][1] == first['id'][1] + 3 and auto.leader() == 'a'
    assert auto.file('b')['lease']['cfg'] == cfg


def test_a_group_that_changed_in_manual_mode_switches_on_as_it_is_now(auto, seed):
    auto.form(seed)
    auto.put('a', '/api/ha/mode', OFF)
    auto.run(2 * T.R, dt=1.0)
    # d joins while the group is in manual mode: it has no lease state at all
    assert _pair(auto.g, auto.admin, 'd').status_code == 200
    with auto.at('a') as ha:
        ha.set_member_site(IDS['d'], 'dc-d')
    assert _sync(auto.g, auto.admin, 'd') == 'applied'
    assert 'lease' not in auto.file('d')
    auto.members = 'abcd'
    auto.watch('a')

    r = auto.switch_on(accept=['EVEN_VOTERS'])

    assert r.status_code == 200, r.data
    assert all(auto.mode(n) == 'auto' for n in 'abcd') and auto.leader() == 'a'
    ids = [v['id'] for v in auto.file('d')['lease']['cfg']['body']['voters'] if v['voter']]
    assert sorted(ids) == sorted(IDS[n] for n in 'abcd')
    assert auto.node('a').view.n == 4


def test_a_leader_that_never_held_the_chain_founds_it_anew(auto, seed):
    """d joined in manual mode and was promoted: it is no voter of the chain the others
    hold, so nothing it signs would follow from theirs. It starts a chain of its own,
    and the members take it from the instance they follow."""
    auto.form(seed)
    auto.put('a', '/api/ha/mode', OFF)
    auto.run(2 * T.R, dt=1.0)
    assert _pair(auto.g, auto.admin, 'd').status_code == 200
    with auto.at('a') as ha:
        ha.set_member_site(IDS['d'], 'dc-d')
    for n in 'dbc':
        # the member list with d in it reaches the others with their next sync
        assert _sync(auto.g, auto.admin, n) == 'applied'
    old = auto.file('b')['lease']['cfg']['id']
    assert _promote(auto.g, auto.admin, 'd').status_code == 200
    for n in 'abc':
        _watch(auto.g, n)
    assert auto.file('a')['role'] == 'standby' and auto.file('a')['source'] == IDS['d']
    _watch(auto.g, 'd')
    auto.members = 'abcd'
    import pegaprox.api.ha as ha_api
    from test_ha_members import _fresh_windows
    _fresh_windows(ha_api)

    with auto.at('d'):
        r = auto.admin.put('/api/ha/mode', json=dict(ON, accept=['EVEN_VOTERS']))
    assert r.status_code == 200, r.data
    for _ in range(8):
        auto.step('d')

    assert all(auto.mode(n) == 'auto' for n in 'abcd'), {n: auto.mode(n) for n in 'abcd'}
    assert auto.leader() == 'd' and auto.file('d')['role'] == 'leader'
    cfg = auto.file('b')['lease']['cfg']
    assert cfg == auto.file('d')['lease']['cfg'] and cfg['id'] > old
    # the chain here starts with what d founded: nothing of the old one is left
    chain = auto.file('b')['lease']['cfg_chain']
    assert chain[0]['prev'] == '' and chain[0]['by'] == IDS['d']


# --- the two things this slice added to ha_vote.Node --------------------------------------------

def test_a_pending_switch_is_taken_back_only_where_it_was_started(monkeypatch):
    from test_ha_vote import Box, genesis
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
    box = Box('a', genesis(mode=hv.MODE_MANUAL), role=hv.ROLE_ACTIVE, voted_for=None)
    assert box.node.switch_cancel() == 'NOT_PENDING'          # nothing is pending
    assert box.node.switch_on() == ''
    pending = box.node.view.cfg

    # a member that holds the pending config did not start it
    held = Box('b', pending, chain=[genesis(mode=hv.MODE_MANUAL)], voted_for=None)
    assert held.node.switch_cancel() == 'NOT_PENDING' and held.node.switch is None

    assert box.node.switch_cancel() == ''
    box.later(0.1)
    assert box.node.view.mode == hv.MODE_MANUAL and 'switch_cancelled' in box.names()
    assert box.node.view.id == (1, 3) and box.node.switch['cancelled'] is True
    # the members get the manual config: the rounds go on until each holds it
    box.sent.clear()
    box.later(0.1)
    sent = [s for s in box.sent if s[1] == 'renew' and s[2].get('switch')]
    assert sent and all(s[2]['chain'][-1]['body']['mode'] == hv.MODE_MANUAL for s in sent)
    assert box.node.switch_cancel() == 'NOT_PENDING'

    # after a restart nothing drives the pending config on disk: cancel picks it up
    again = Box('a', pending, chain=[genesis(mode=hv.MODE_MANUAL)], role=hv.ROLE_ACTIVE,
                voted_for=None)
    assert again.node.switch is None and again.node.switch_cancel() == ''
    again.later(0.1)
    assert again.node.view.mode == hv.MODE_MANUAL


def test_readmit_lets_go_of_what_the_leader_held_against_the_voter():
    from test_ha_vote import Box, _leader, _ok, genesis
    # only the leader, and only a voter that is quarantined
    assert Box('b', genesis()).node.readmit('c') == 'NOT_LEADER'
    box = _leader()
    assert box.node.readmit('b') == 'NOT_QUARANTINED'

    def answers(b_gen, others):
        return lambda to, b: dict(_ok(to, b), cfg_id=box.node.view.id,
                                  cfg_digest=hv.cfg_digest(box.node.view.cfg),
                                  gen=b_gen if to == 'b' else others)
    box.answer_all('renew', answers(10, 10))
    box.later(T.R)
    box.answer_all('renew', answers(11, 11))
    for _ in range(8):
        box.later(T.R)
        box.answer_all('renew', answers(3, 12))
    assert box.node.view.cfg['body']['quarantined'] == ['b'] and 'b' in box.node._suspects

    assert box.node.readmit('b') == ''
    assert 'b' not in box.node._suspects and 'b' not in box.node._gens
    for _ in range(8):
        box.later(T.R)
        box.answer_all('renew', answers(4, 13))
    # back in, and it stays in: its generation counts from where it is now
    assert box.node.view.cfg['body']['quarantined'] == [] and 'b' in box.node.view.counting
