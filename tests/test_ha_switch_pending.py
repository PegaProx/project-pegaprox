"""A pending switch to automatic failover has an end on every member (#625 stage 2).

A member that holds the pending voter config is not promoted by hand, and only the
instance that started the switch takes it back. That instance can stop leading while
its switch is pending: a member the pending round did not reach is a manual member and
is promoted by hand, and the active steps down to it as a manual active does. As a
standby it takes nothing back, so it took the switch back as it left and told the
members; one the word does not reach takes the config of the active it follows now,
with that one's own switch; and the one that started it hands the manual config out
again for as long as a member says it still waits. Never into a group that fails over
automatically already: a manual config there would make a member that is promoted by
hand. What stays is the member whose switching instance is gone for good; its status
says who started the switch and since when.

MK Oct 2026 (#625)
"""
from datetime import datetime

import pytest

from pegaprox.core import ha_vote as hv
from test_ha_api import ADMIN_PW, _audit
from test_ha_members import IDS, URLS, _post, _promote, _sync, group  # noqa: F401
from test_ha_lease_members import _second_active
from _ha_lease_harness import T, auto  # noqa: F401 - the fixture

ON = {'mode': 'auto', 'lease_s': 20, 'user_password': ADMIN_PW}
BOUND = T.P + T.L / 4 + T.T_vote + T.W_take + 5
LATER = '2031-01-01T00:00:00+00:00'
RENEW = '/api/ha/peer/renew'


def _pending_on(auto, missed='b', standbys='bc'):
    """a started the switch, and its pending round reached every member but `missed`."""
    auto.pair(seed=auto.seed, standbys=standbys)
    r = auto.switch_on(settle=False, accept=['EVEN_VOTERS'] if len(standbys) == 3 else None)
    assert r.status_code == 200 and r.get_json()['mode'] == 'auto_pending', r.data
    for n in missed:
        auto.cut('a', n, both=False)
    auto.step('a')
    for n in standbys:
        assert auto.mode(n) == ('manual' if n in missed else 'auto_pending'), n


def _promoted_by_hand(auto, n='b', unheard=''):
    """`n`, a manual member, is promoted while no member that holds the pending config
    answers it. The switching instance takes the call and steps down; `unheard` names
    the members its word does not reach."""
    others = [m for m in auto.members if m not in ('a', n)]
    for m in others:
        auto.cut(n, m)
    for m in unheard:
        auto.cut('a', m)
    r = _promote(auto.g, auto.admin, n)
    assert r.status_code == 200, r.data
    assert ('a', 'stepped down to standby') in auto.g.restarts
    auto.heal()
    return r.get_json()['epoch']


@pytest.fixture
def pending(auto, seed):
    auto.seed = seed
    return auto


def _switched_on(auto, n):
    """The active `n` switches the group on, and every member follows."""
    auto.watch()
    r = auto.put(n, '/api/ha/mode', ON)
    assert r.status_code == 200, r.data
    auto.run(4 * T.R, dt=1.0, until=lambda: all(auto.mode(m) == 'auto' for m in auto.members))
    auto.step(n)
    return r


def _nobody_is_promoted_by_hand(auto, leader):
    for n in auto.members:
        if n != leader:
            r = _promote(auto.g, auto.admin, n)
            assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', (n, r.data)
            assert auto.file(n)['role'] == 'standby'


# --- the active that started the switch steps down -----------------------------------------

def test_an_active_that_steps_down_takes_its_pending_switch_back(pending):
    auto = pending
    _pending_on(auto)
    pending_cfg, gen = auto.file('a')['lease']['cfg'], auto.file('a')['lease']['gen']
    assert auto.file('a')['lease']['pending_since'] and auto.file('c')['lease']['pending_since']

    assert _promoted_by_hand(auto) == 2

    a = auto.file('a')
    assert a['role'] == 'standby' and a['source'] == IDS['b'] and a['epoch'] == 2
    # one more config of its own chain, in manual mode, written with the role
    cfg = a['lease']['cfg']
    assert a['lease']['mode'] == 'manual' and cfg['body']['mode'] == 'manual'
    assert cfg['id'] == [1, 3] and cfg['by'] == IDS['a'] and cfg['prev'] == hv.cfg_digest(pending_cfg)
    assert a['lease']['cfg_chain'][-1] == pending_cfg and 'pending_since' not in a['lease']
    assert a['lease']['gen'] == gen + 1
    # and c heard of it before a left
    c = auto.file('c')
    assert c['lease']['cfg'] == cfg and c['lease']['mode'] == 'manual' and 'pending_since' not in c['lease']
    said = [e['details'] for e in _audit('ha.auto_cancelled')]
    assert len(said) == 1 and 'leads no more' in said[0] and '1 of 1' in said[0]
    assert all(auto.mode(n) == 'manual' for n in 'abc')
    with auto.at('a') as ha:
        assert ha.promote_refusal() == '' and ha.pending_switch() is None

    # a manual group with one active, as after any promotion by hand: the new active
    # switches it on, and the members take the chain it founds
    assert _switched_on(auto, 'b').get_json()['mode'] == 'auto_pending'
    assert all(auto.mode(n) == 'auto' for n in 'abc'), {n: auto.mode(n) for n in 'abc'}
    assert auto.active() == ['b'] and auto.holders() == ['b']
    assert auto.file('c')['lease']['cfg']['by'] == IDS['b']
    _nobody_is_promoted_by_hand(auto, 'b')


def test_an_active_that_steps_aside_takes_its_pending_switch_back(pending):
    auto = pending
    _pending_on(auto)

    with auto.at('a') as ha:
        assert ha.step_aside(2, 'a member reports epoch 2') is True

    a = auto.file('a')
    assert a['role'] == 'standby' and a['source'] is None and a['lease']['mode'] == 'manual'
    assert auto.mode('c') == 'manual' and auto.file('c')['lease']['cfg'] == a['lease']['cfg']
    assert len(_audit('ha.auto_cancelled')) == 1


def test_a_release_that_does_not_offer_it_takes_nothing_back(pending, monkeypatch):
    auto = pending
    _pending_on(auto)
    with auto.at('a') as ha:
        assert ha._switch_taken_back(ha._load())['mode'] == 'manual'
        monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
        assert ha._switch_taken_back(ha._load()) is None
    # and a member takes nothing back: the config is not its own
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
    with auto.at('c') as ha:
        assert ha._switch_taken_back(dict(ha._load(), role='active')) is None


def test_the_word_of_a_step_down_starts_no_chain_on_a_member_that_holds_none(pending):
    """d never got the pending round. The manual config tells it nothing it has to
    know, and the instance that sends it leads no more: nothing starts from its word."""
    auto = pending
    _pending_on(auto, missed='bd', standbys='bcd')
    auto.cuts.discard(('a', 'd'))
    auto.g.calls.clear()

    _promoted_by_hand(auto)

    assert auto.mode('c') == 'manual' and auto.file('c')['lease']['cfg']['id'] == [1, 3]
    # d was told like c, and follows a still: it would take a chain from it otherwise
    told = [c[1] for c in auto.g.calls if c[0] == 'a' and c[3] == RENEW]
    assert told == ['c', 'd'] and auto.file('d')['source'] == IDS['a']
    assert 'lease' not in auto.file('d') and auto.rt('d').node is None
    assert '1 of 2' in _audit('ha.auto_cancelled')[0]['details']


def test_the_word_of_a_step_down_ends_no_term(auto, seed):
    """The round says the epoch its sender is at. To a leader that is a renewal of a
    later term, and it would leave; a member in automatic mode waits for no switch."""
    auto.form(seed)
    auto.past_the_hold()
    chain = auto.node('a').chain
    round_ = {'epoch': 5, 'leader': IDS['b'], 'switch': True, 'taken_back': True, 'lease_s': 20,
              'chain': chain}
    before = {n: auto.file(n) for n in 'ac'}

    for n in 'ac':
        with auto.at(n) as ha:
            ans = ha.lease_request(IDS['b'], 'renew', round_)
        assert ans['ok'] is False and ans['reason'] == 'NOT_PENDING', (n, ans)
    assert {n: auto.file(n) for n in 'ac'} == before
    assert auto.file('a')['role'] == 'leader' and auto.holders() == ['a'] and not auto.node('a').dead


# --- a member the word does not reach ----------------------------------------------------------

def test_a_pending_member_says_who_started_the_switch_and_since_when(pending, monkeypatch):
    auto = pending
    _pending_on(auto)
    with auto.at('a'):
        own = auto.admin.get('/api/ha/status').get_json()['auto']['pending']
    assert own['own'] is True and own['by'] == IDS['a'] and 'started on this instance' in own['text']

    _promoted_by_hand(auto, unheard='c')
    auto.watch('c')

    c = auto.file('c')
    assert c['source'] == IDS['b'] and c['lease']['mode'] == 'auto_pending'
    with auto.at('c') as ha:
        said = auto.admin.get('/api/ha/status').get_json()['auto']['pending']
        assert ha.peer_lease_status()['pending_by'] == IDS['a']
    assert said['by'] == IDS['a'] and said['by_url'] == URLS['a'] and said['own'] is False
    assert said['since'] == c['lease']['pending_since']
    assert datetime.fromisoformat(said['since']).tzinfo is not None
    assert 'pending' in said['text'] and URLS['a'] in said['text'] and said['since'] in said['text']
    # the refused promotion says the same, not that the group elects its leader
    r = _promote(auto.g, auto.admin, 'c')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE'
    assert r.get_json()['error'] == said['text']
    # the stamp is of the config, not of the last write: another one leaves it alone
    monkeypatch.setattr(auto.ha, '_now', lambda: LATER)
    with auto.at('c') as ha:
        assert ha._lease_node().set_cv((1, 7)) is True
    assert auto.file('c')['lease']['pending_since'] == said['since'] != LATER
    # nothing of it on a member that holds no pending config
    with auto.at('a'):
        body = auto.admin.get('/api/ha/status').get_json()['auto']
        assert body['pending'] is None and body['mode'] == 'manual'
    with auto.at('a') as ha:
        assert 'pending_by' not in ha.peer_lease_status()
        # a standby that holds no voter config and heard of the switch from the instance
        # it follows: no maker to name, and it is not promoted either
        ha._update(lease=None, group_mode='auto_pending')
        said = ha.pending_switch()
        assert (said['by'], said['since'], said['own']) == (None, None, False)
        assert 'the instance this one follows said' in said['text'] == ha.promote_refusal()


def test_a_member_the_word_did_not_reach_takes_the_config_of_the_active_it_follows(pending):
    """a cannot reach c, at the step-down and ever after. c follows b now, which is not
    the instance that made its pending config: b's switch is what the group does."""
    auto = pending
    _pending_on(auto)
    _promoted_by_hand(auto, unheard='c')
    auto.cut('a', 'c')
    auto.watch()
    assert auto.mode('a') == 'manual' and auto.mode('c') == 'auto_pending'
    assert auto.file('c')['lease']['cfg']['by'] == IDS['a'] and auto.file('c')['source'] == IDS['b']
    with auto.at('a') as ha:
        ha._lease_housekeeping()
    assert auto.mode('c') == 'auto_pending'

    # c says a switch is pending, and b founds a chain all the same: the instance that
    # made that config answers b as a standby
    r = _switched_on(auto, 'b')
    assert sorted(r.get_json()['waiting']) == [IDS['a'], IDS['c']]

    assert all(auto.mode(n) == 'auto' for n in 'abc'), {n: auto.mode(n) for n in 'abc'}
    c = auto.file('c')
    assert c['lease']['cfg']['by'] == IDS['b'] and c['lease']['cfg'] == auto.file('b')['lease']['cfg']
    assert 'pending_since' not in c['lease'] and c['epoch'] == 2
    # nothing of the chain a made is left on it
    assert all(cfg['by'] == IDS['b'] for cfg in c['lease']['cfg_chain'])
    assert auto.active() == ['b'] and auto.holders() == ['b']
    _nobody_is_promoted_by_hand(auto, 'b')
    auto.run(3 * T.R, dt=1.0)
    assert auto.active() == ['b'] and auto.file('c')['lease']['voted_for'] == IDS['b']


def test_a_pending_config_gives_way_only_to_an_active_of_a_later_epoch(pending, monkeypatch):
    """What c gives up is an ack the switching instance may still count. Under a later
    epoch that instance can never commit: the new active takes none of its rounds."""
    auto = pending
    _pending_on(auto)
    _promoted_by_hand(auto, unheard='c')
    auto.cut('a', 'c')
    auto.watch()
    auto.watch('b')
    assert auto.put('b', '/api/ha/mode', ON).status_code == 200
    chain = auto.node('b').chain
    held = auto.file('c')['lease']
    round_ = {'leader': IDS['b'], 'switch': True, 'lease_s': 20, 'chain': chain}

    with auto.at('c') as ha:
        lease = ha._lease(ha._load())
        assert not ha._gives_way(lease, IDS['b'], 1) and ha._gives_way(lease, IDS['b'], 2)
        # never to the instance that made it, and not on an epoch that is no number
        assert not ha._gives_way(lease, IDS['a'], 2) and not ha._gives_way(lease, IDS['b'], None)
        assert not ha._gives_way(dict(lease, mode='auto'), IDS['b'], 9)
        assert ha._gives_way(dict(lease, mode='manual'), IDS['a'], 0)

        ans = ha.lease_request(IDS['b'], 'renew', dict(round_, epoch=1))
        assert ans['ok'] is False and ans['reason'] == 'CFG_GAP'
    assert auto.file('c')['lease'] == held
    with auto.at('c') as ha:
        # and not from a member it does not follow
        ans = ha.lease_request(IDS['a'], 'renew', dict(round_, leader=IDS['a'], epoch=2))
        assert ans['ok'] is False and ans['reason'] == 'CFG_GAP'
        assert auto.file('c')['lease'] == held
        # nor on the word of one that took its own switch back
        ans = ha.lease_request(IDS['b'], 'renew', dict(round_, epoch=2, taken_back=True))
        assert ans['ok'] is False and ans['reason'] == 'NOT_PENDING'
        assert auto.file('c')['lease'] == held

        # the pending config alone is where the new chain starts here: held since now
        monkeypatch.setattr(ha, '_now', lambda: LATER)
        ans = ha.lease_request(IDS['b'], 'renew', dict(round_, epoch=2, chain=chain[-1:]))
        assert ans['ok'] is True and ans['cfg_digest'] == hv.cfg_digest(chain[-1])
    c = auto.file('c')['lease']
    assert c['cfg'] == chain[-1] and c['cfg_chain'] == [] and auto.mode('c') == 'auto_pending'
    assert c['pending_since'] == LATER and c['gen'] == held['gen']
    with auto.at('c') as ha:
        assert ha.pending_switch()['by'] == IDS['b']


def test_the_instance_that_took_its_switch_back_hands_the_config_out_again(pending):
    """c missed the word of the step-down. Nobody switches anything: a sees with its
    next look at the group that c still waits for it."""
    auto = pending
    _pending_on(auto)
    _promoted_by_hand(auto, unheard='c')
    auto.watch()
    assert auto.mode('c') == 'auto_pending'
    auto.g.calls.clear()

    with auto.at('a') as ha:
        ha._lease_housekeeping()

    assert auto.mode('c') == 'manual' and auto.file('c')['lease']['cfg'] == auto.file('a')['lease']['cfg']
    assert [c for c in auto.g.calls if c[3] == RENEW] == [('a', 'c', 'POST', RENEW)]
    # once c says it holds it, a has nothing to hand out
    auto.watch('a')
    auto.g.calls.clear()
    with auto.at('a') as ha:
        assert ha._switch_back_again() == []
        ha._lease_housekeeping()
    assert not [c for c in auto.g.calls if c[3] == RENEW]
    # c is a manual member again, and promoted by hand like one
    r = _promote(auto.g, auto.admin, 'c')
    assert r.status_code == 200 and r.get_json()['epoch'] == 3, r.data


def _away_while_it_went_through_and_back(auto, seed, back=True):
    """c took the pending config and went down before the switch was through; the group
    went automatic and back to manual without it, a its manual active. With `back`, c is
    up again."""
    auto.pair(seed, 'bc')
    assert auto.switch_on(settle=False).get_json()['mode'] == 'auto_pending'
    auto.cut('a', 'b', both=False)
    auto.step('a')
    assert auto.mode('c') == 'auto_pending' and auto.mode('b') == 'manual'
    auto.crash('c')
    auto.members = 'ab'
    auto.run(60, dt=1.0)
    auto.heal()
    auto.run(3 * T.R, dt=1.0)
    assert auto.file('a')['role'] == 'leader' and auto.mode('b') == 'auto'
    assert auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW}).status_code == 200
    auto.run(3 * T.R, dt=1.0)
    assert auto.file('a')['role'] == 'active' and auto.mode('a') == auto.mode('b') == 'manual'
    if back:
        assert auto.back('c') == 'idle'
        auto.members = 'abc'
        assert auto.file('c')['lease']['cfg']['id'] == [1, 2] and auto.mode('c') == 'auto_pending'


def test_a_member_away_while_the_switch_went_through_and_back_takes_the_manual_config(auto, seed):
    """Its chain reads pending, the group's pending, automatic, manual. The active of the
    manual group hands it the chain from the pending config on, whatever lies between."""
    _away_while_it_went_through_and_back(auto, seed)
    auto.watch('a')
    with auto.at('a') as ha:
        assert ha._switch_back_again() == [IDS['c']]
    c = auto.file('c')
    assert c['lease']['mode'] == 'manual' and c['lease']['cfg'] == auto.file('a')['lease']['cfg']
    assert [cfg['id'] for cfg in c['lease']['cfg_chain'][-2:]] == [[1, 2], [1, 3]]
    # a manual member: the day a and b are lost, it is the failover manual mode is for
    auto.crash('a')
    auto.crash('b')
    with auto.at('c'):
        r = _post(auto.admin, '/api/ha/promote', {'confirm': 'PROMOTE', 'force': True,
                                                 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data


def test_an_active_that_did_not_start_the_switch_hands_the_chain_out_as_well(auto, seed):
    """The same, and a is lost before c is back: b is promoted by hand. The pending config
    c holds was made by a, and b holds it in its chain. c takes the chain by what it is -
    it hangs off the config held there, each link signed by a voter of the one before -
    whoever sends it."""
    _away_while_it_went_through_and_back(auto, seed, back=False)
    # b heard from the manual active that the switch back went through: a switch back it
    # holds and nobody confirmed would leave it Force leader as the only way out (S7)
    assert _sync(auto.g, auto.admin, 'b') in ('applied', 'unchanged')
    auto.crash('a')
    auto.members = 'bc'
    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 200 and r.get_json()['epoch'] == 2, r.data
    auto.restart('b')
    assert auto.back('c') == 'idle'
    assert auto.mode('c') == 'auto_pending' and auto.file('c')['lease']['cfg']['by'] == IDS['a']

    auto.watch('b')
    with auto.at('b') as ha:
        assert ha._switch_back_again() == [IDS['c']]
    c, b = auto.file('c'), auto.file('b')
    assert c['lease']['mode'] == 'manual' and c['lease']['cfg'] == b['lease']['cfg']
    assert b['lease']['cfg']['by'] == IDS['a']
    with auto.at('c') as ha:
        assert ha.promote_refusal() == '' and ha.pending_switch() is None
    # the day b is lost, c takes over by hand
    auto.crash('b')
    with auto.at('c'):
        r = _post(auto.admin, '/api/ha/promote', {'confirm': 'PROMOTE', 'force': True,
                                                 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data


def test_a_maker_that_steps_down_takes_its_switch_back_past_a_member_that_missed_a_switch_back(auto, seed):
    """Crashes only. The group went back to manual while c was away: c still says
    automatic, with the config before. a starts a new switch and goes down; b is promoted
    by hand. a comes back and steps down to b: c's word is that of a member behind a's own
    chain, no group that fails over, and a takes its switch back."""
    auto.form(seed)
    auto.past_the_hold()
    auto.isolate('c')
    assert auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW}).status_code == 200
    auto.run(3 * T.R, dt=1.0)
    auto.heal()
    # b heard from the manual active that the switch back went through (its nudge)
    assert _sync(auto.g, auto.admin, 'b') in ('applied', 'unchanged')
    assert auto.mode('a') == auto.mode('b') == 'manual' and auto.mode('c') == 'auto'
    auto.watch('a')
    assert auto.put('a', '/api/ha/mode', ON).get_json()['mode'] == 'auto_pending'
    auto.crash('a')
    auto.rt('a').outbox.clear()
    auto.members = 'bc'
    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 200 and r.get_json()['epoch'] == 2, r.data

    auto.members = 'abc'
    assert auto.back('a') == 'stepped down'
    a = auto.file('a')
    assert a['role'] == 'standby' and a['source'] == IDS['b'] and a['lease']['mode'] == 'manual'
    assert a['lease']['cfg']['by'] == IDS['a'] and a['lease']['cfg_chain'][-1]['body']['mode'] == 'auto_pending'
    # c learns the manual chain the next time it campaigns; nobody waits on a switch
    auto.run(2 * BOUND, dt=1.0, until=lambda: auto.mode('c') == 'manual')
    assert all(auto.mode(n) == 'manual' for n in 'abc') and auto.active() == ['b']
    auto.crash('b')
    for n in 'ac':
        with auto.at(n):
            r = _post(auto.admin, '/api/ha/promote', {'confirm': 'PROMOTE', 'force': True,
                                                     'user_password': ADMIN_PW})
        assert r.status_code == 200, (n, r.data)
        auto.crash(n)


def test_a_maker_left_with_its_switch_takes_it_back_once_it_follows_a_manual_active(pending, monkeypatch):
    """However it came to keep its pending switch as a standby (here the take-back is
    left out at the step-down): once the active it follows answers as a manual one, it
    takes the switch back itself and hands the manual config to whoever holds the
    pending one."""
    auto = pending
    _pending_on(auto)
    with monkeypatch.context() as mp:
        mp.setattr(auto.ha, '_switch_taken_back', lambda st, automatic=False: None)
        _promoted_by_hand(auto, unheard='c')
    a = auto.file('a')
    assert a['role'] == 'standby' and a['lease']['mode'] == 'auto_pending' and auto.mode('c') == 'auto_pending'

    auto.watch('a')
    with auto.at('a') as ha:
        assert ha._switch_back_again() == [IDS['c']]
    a = auto.file('a')
    assert a['lease']['mode'] == 'manual' and a['lease']['cfg']['by'] == IDS['a']
    # under the epoch the switch was made in, as at a step-down: the configs of the active
    # it follows now, promoted later, come after it
    assert a['lease']['cfg']['id'] == [1, 3] and a['epoch'] == 2
    assert auto.file('c')['lease']['cfg'] == a['lease']['cfg']
    assert [e for e in _audit('ha.auto_cancelled') if 'runs the group by hand' in e['details']]
    for n in 'ac':
        with auto.at(n) as ha:
            assert ha.promote_refusal() == ''
    # and that active switches the group on, the members taking the chain it founds
    assert _switched_on(auto, 'b').get_json()['mode'] == 'auto_pending'
    assert all(auto.mode(n) == 'auto' for n in 'abc'), {n: auto.mode(n) for n in 'abc'}
    assert auto.active() == ['b'] and auto.holders() == ['b']


# --- what stands in the way of a new chain -----------------------------------------------------

def test_a_pending_switch_somebody_still_drives_stands_in_the_way_of_a_new_chain(pending):
    auto = pending
    _pending_on(auto)
    _promoted_by_hand(auto, unheard='c')
    auto.watch()
    with auto.at('b') as ha:
        st = ha._load()
        seen = dict(ha._rt().seen[IDS['c']])
        assert seen['mode'] == 'auto_pending' and seen['pending_by'] == IDS['a'] and seen['cfg_id'] == (1, 2)
        assert st['members'][IDS['a']]['role_seen'] == 'standby' and st['epoch'] == 2
        way = ha._holds_a_chain_of_its_own
        assert way(seen, st) is False
        # the instance that made it still answers as an active, or has not answered since
        for role in ('active', None):
            ms = dict(st['members'], **{IDS['a']: dict(st['members'][IDS['a']], role_seen=role)})
            assert way(seen, dict(st, members=ms)) is True
        # it left the group: nobody drives it
        assert way(seen, dict(st, members={IDS['c']: st['members'][IDS['c']]})) is False
        # made under this epoch or a later one: the member would not give it up
        assert way(seen, dict(st, epoch=1)) is True and way(dict(seen, cfg_id=(2, 2)), st) is True
        # this instance made it, or the member does not say who did
        assert way(dict(seen, pending_by=IDS['b']), st) is True
        assert way(dict(seen, pending_by=None), st) is True
        assert way(dict(seen, mode='auto', pending_by=None), st) is True
        assert way(dict(seen, mode='manual', pending_by=None), st) is False

        # and so the switch is refused while a answers as an active
        ms = dict(st['members'], **{IDS['a']: dict(st['members'][IDS['a']], role_seen='active')})
        found = {(f['code'], f['member']) for f in ha.auto_findings(dict(st, members=ms))}
        assert ('MEMBER_AUTO', IDS['c']) in found
        assert ('MEMBER_AUTO', IDS['c']) not in {(f['code'], f['member']) for f in ha.auto_findings(st)}


# --- never into a group that fails over automatically --------------------------------------------

def test_no_switch_is_taken_back_into_a_group_that_fails_over_automatically(auto, seed):
    """d, an active by hand next to the elected leader, started a switch of its own (what
    the guards before the switch refuse). It leaves for the holder of the lease. A
    manual config on it would say: promote me by hand. It keeps the pending one."""
    leader, _others = _second_active(auto, seed)
    ha = auto.ha
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ha, 'auto_findings', lambda st=None, lease_s=20: [])
        mp.setattr(ha, '_ask_members', lambda timeout, refused=None: {})
        mp.setattr(ha, '_ask_witness', lambda: None)
        with auto.at('d') as h:
            h._rt().seen.clear()
            h.switch_auto_on(20, ['EVEN_VOTERS'])
    held = auto.file('d')['lease']
    assert held['mode'] == 'auto_pending' and held['cfg']['by'] == IDS['d']
    with auto.at('d') as h:
        # nobody said anything yet: taken back, as in a manual group
        assert h._switch_taken_back(h._load())['mode'] == 'manual'
        assert h._switch_taken_back(h._load(), automatic=True) is None

        assert h.watch_once() == 'stepped down'

        # the members said it with that look, and the one it left for holds the lease
        assert h._switch_taken_back(dict(h._load(), role='active')) is None
    d = auto.file('d')
    assert d['role'] == 'standby' and d['source'] == IDS[leader]
    assert d['lease']['cfg'] == held['cfg'] and auto.mode('d') == 'auto_pending'
    assert not _audit('ha.auto_cancelled')

    # with no member there to ask, its own state still says no
    for n in 'abc':
        auto.crash(n)
    with auto.at('d'):
        r = _post(auto.admin, '/api/ha/promote', {'confirm': 'PROMOTE', 'force': True,
                                                 'user_password': ADMIN_PW})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert auto.file('d')['role'] == 'standby'
