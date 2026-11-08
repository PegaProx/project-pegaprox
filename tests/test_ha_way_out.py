"""The way out of a group that is or was automatic (#625 stage 2, slice S7; found by the
attack on the witness, S5).

A member cut off from the leader and from the third vote must not become a second
acting instance by the plain ways out: promoted by hand (with or without force) while it
holds a manual voter config that follows an automatic one and was never confirmed as
the group's, unpaired on the strength of its own possibly old state, or promoted after
its state was put back from before the witness was paired. The only way out without the
leader is Force leader (tests/test_ha_force_leader.py). The same with a third data
member in place of the witness: the cause is in promote and unpair, not in the witness.

MK Oct 2026 (#625)
"""
import pytest

from pegaprox.core import ha_vote as hv
from _ha_lease_harness import auto  # noqa: F401  (the fixture)
from test_ha_api import ADMIN_PW
from test_ha_lease_members import _restore
from test_ha_members import _sync, group  # noqa: F401  (the fixture)
from test_ha_witness_group import _form, _pair, host  # noqa: F401  (the fixture)

UNPAIR = {'confirm': 'UNPAIR', 'user_password': ADMIN_PW}


def _promote(auto, n, force=True):
    body = {'confirm': 'PROMOTE', 'user_password': ADMIN_PW}
    if force:
        body['force'] = True
    return auto.post(n, '/api/ha/promote', body)


def _switch_back_only_b_took(auto, third):
    """a switches off with `third` cut from it; b takes the round, its answer is lost.
    a loses its lease and is elected again with `third`. b knows its manual config
    follows an automatic one, and nobody confirmed it."""
    auto.past_the_hold()
    assert auto.leader() == 'a'
    auto.cut('a', third)
    auto.cuts.add(('b', 'a'))
    r = auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    auto.run(1, members='a')
    assert auto.mode('b') == 'manual'
    auto.run(40, members='a')
    auto.heal()
    auto.cut('a', 'b')
    others = 'a' if third == 'w' else 'a' + third
    if third != 'w':
        auto.cut(third, 'b')
    auto.run(150, members=others, until=lambda: auto.active() != [])
    assert auto.active() in (['a'], [third]) and auto.mode('b') == 'manual', auto.active()
    with auto.at('b') as ha:
        st = ha._load()
        assert ha._manual_known(st, ha._lease(st), ()) is False
        assert st['lease']['cfg_chain'][-1]['body']['mode'] == 'auto'


def _setup(auto, host, seed, third):
    if third == 'w':
        _form(auto, host, seed)
    else:
        auto.form(seed, 'bc')
    _switch_back_only_b_took(auto, third)
    # b's site is cut off: it reaches neither the leader nor the third vote
    auto.cut('b', third)


@pytest.mark.parametrize('force', [True, False])
@pytest.mark.parametrize('third', ['w', 'c'])
def test_a_switch_back_nobody_confirmed_is_not_promoted_by_hand(auto, host, seed, third, force):
    _setup(auto, host, seed, third)

    r = _promote(auto, 'b', force)

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert 'Force leader' in r.get_json()['error']
    assert auto.state('b')['role'] == 'standby'
    with auto.at('b') as ha:
        assert not ha.is_active()
        status = ha.lease_status()
    # what the status page says, and the way out it offers
    assert 'no majority of the group has confirmed it' in status['way_out']
    assert status['force_leader']['case'] == 'unknown'


@pytest.mark.parametrize('third', ['w', 'c'])
def test_a_switch_back_nobody_confirmed_is_not_unpaired_by_hand(auto, host, seed, third):
    _setup(auto, host, seed, third)
    with auto.at('b') as ha:
        assert ha.unpair_refusal() == ha.MANUAL_UNKNOWN_ERROR
        with pytest.raises(ha.AutoMode):
            ha.unpair()

    r = auto.post('b', '/api/ha/unpair', UNPAIR)

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert auto.state('b')['role'] == 'standby' and auto.state('b')['members']


def test_a_member_restored_from_before_the_witness_paired_is_not_promoted(auto, host, seed):
    """b's backup predates the witness; b is cut from a only, the witness answers, and
    b's state knows nothing of it."""
    auto.pair(seed, 'b')
    backup = auto.file('b')
    _pair(auto, host)
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    assert auto.leader() == 'a'
    auto.cut('a', 'b')
    _restore(auto, 'b', backup)
    assert 'witness' not in auto.file('b') and auto.mode('b') == 'manual'

    r = _promote(auto, 'b')

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert auto.state('b')['role'] == 'standby'
    with auto.at('b') as ha:
        seen = ha._group_seen(ha._load())
        assert seen['auto'] is True and seen['witness']['url'] == 'https://witness.example:5005'
        assert ha.way_out_refusal() == ha.RESTORED_ERROR


def test_the_witness_the_group_named_is_asked_even_where_the_state_does_not_know_it(auto, host, seed, monkeypatch):
    """The second guard on its own: with the note of the state put aside, the promotion
    still asks the witness b noted while in its group, and hears that a leads."""
    auto.pair(seed, 'b')
    backup = auto.file('b')
    _pair(auto, host)
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    auto.cut('a', 'b')
    _restore(auto, 'b', backup)
    monkeypatch.setattr(auto.ha, 'way_out_check', lambda: '')

    r = _promote(auto, 'b')

    assert r.status_code == 409 and 'The witness' in r.get_json()['error'], r.data


def test_a_switch_back_the_members_confirm_is_promoted_as_ever(auto, seed):
    """The counterproof: the group went back to manual, b holds the config, and the
    member that answers holds the same: a majority of the voters before it, known."""
    auto.form(seed, 'bc')
    auto.past_the_hold()
    assert auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW}).status_code == 200
    auto.run(10, dt=1.0)
    assert auto.mode('a') == auto.mode('b') == auto.mode('c') == 'manual'
    auto.watch('c')
    auto.crash('a')
    auto.members = 'bc'
    with auto.at('b') as ha:
        st = ha._load()
        assert not ha._manual_known(st, ha._lease(st), ())

    r = _promote(auto, 'b')

    assert r.status_code == 200, r.data


def test_a_group_that_never_went_automatic_writes_no_note_and_refuses_nothing(auto, seed):
    auto.pair(seed, 'bc')
    for n in 'abc':
        with auto.at(n) as ha:
            assert ha._group_seen(ha._load()) is None and ha.way_out_refusal() == ''
            assert not ha.lease_status()['way_out']
    assert _promote(auto, 'b', force=False).status_code == 200


def test_the_note_grows_with_the_group_and_goes_when_the_instance_leaves(auto, seed, monkeypatch):
    auto.form(seed, 'bc')
    with auto.at('c') as ha:
        seen = ha._group_seen(ha._load())
        assert seen['auto'] is True and seen['cfg_id'] == hv.pair(auto.file('c')['lease']['cfg']['id'])
    assert auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW}).status_code == 200
    auto.run(10, dt=1.0)
    with auto.at('c') as ha:
        seen = ha._group_seen(ha._load())
        # automatic once, automatic for good: only the config id moves on
        assert seen['auto'] is True and seen['cfg_id'] == hv.pair(auto.file('c')['lease']['cfg']['id'])
    assert _sync(auto.g, auto.admin, 'c') in ('applied', 'unchanged')
    r = auto.post('c', '/api/ha/unpair', UNPAIR)
    assert r.status_code == 200, r.data
    with auto.at('c') as ha:
        assert ha._group_seen(ha._load()) is None
    import os
    assert not os.path.exists(auto.g.files['c'] + '.group')


def test_nothing_is_noted_before_automatic_failover_ships(auto, seed, monkeypatch):
    auto.form(seed, 'bc')
    import os
    for n in 'abc':
        os.unlink(auto.g.files[n] + '.group')
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    auto.ha.reset_for_tests()
    with auto.at('a') as ha:
        ha._update(interval=45)
        assert ha.way_out_refusal() == ''
    assert not os.path.exists(auto.g.files['a'] + '.group')
