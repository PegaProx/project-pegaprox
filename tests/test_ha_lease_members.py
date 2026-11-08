"""Who is in an automatic group and who knows it (#625 stage 2).

A member takes the group's voter config with the first renewal of the leader that
reaches it. Until then it holds no lease state, and three kinds of member may never
have one: a joiner the leader cannot open a connection to, a member whose state file
went back to before the switch, and a voter that paired again. None of them is a manual
member all the same: the pairing answer and every snapshot say the mode, a promotion
by hand asks the members first, the leader sends its chain again to a member that says
it holds none, and an active made by hand leaves for the member that holds the lease.
And nobody leaves an automatic group by hand, or founds a second chain next to the one
it has.

MK Oct 2026 (#625)
"""
import errno
import json
import os
import stat

import pytest

from pegaprox.core import ha_vote as hv
from test_ha_api import ADMIN_PW, _audit
from test_ha_members import IDS, URLS, _pair, _post, _promote, _sync, _watch, group  # noqa: F401
from _ha_lease_harness import NAME_OF, T, ZONE, auto  # noqa: F401 - the fixture

RENEW = '/api/ha/peer/renew'
UNPAIR = {'confirm': 'UNPAIR', 'user_password': ADMIN_PW}
BOUND = T.P + T.L / 4 + T.T_vote + T.W_take + 5


def _restore(auto, n, before):
    """The state file of n as it was at `before`, and a new process on it."""
    with open(auto.g.files[n], 'w', encoding='utf-8') as fh:
        json.dump(before, fh)
    auto.ha._rts.pop(IDS[n], None)
    auto.ha.reset_for_tests()
    with auto.at(n) as ha:
        ha.check_peer_at_boot()
        ha.lease_start()


def _cut_one_way(auto, monkeypatch, frm, to):
    """`frm` cannot open a connection to `to` (a wrong address, a firewall one way)."""
    real = auto._call

    def call(method, base_url, fingerprint, path, **kw):
        me, target = auto.g.name(), auto.g.by_url[base_url.rstrip('/')]
        if (me, target) == (frm, to):
            auto.g.calls.append((me, target, method, path))
            raise auto.ha.PeerUnreachable('Cannot reach the peer: ConnectTimeout')
        return real(method, base_url, fingerprint, path, **kw)
    monkeypatch.setattr(auto.ha, '_peer_call', call)


def _findings(auto, n='a'):
    with auto.at(n) as ha:
        return {(f['code'], f['member']) for f in ha.auto_findings()}


# --- a member the leader's renewals never reach ------------------------------------------

def test_a_newcomer_knows_from_the_pairing_answer_that_the_group_elects(auto, seed, monkeypatch):
    """d joins with an address the leader cannot open. It pulls, so it syncs and looks
    healthy from its side; the renewal that would bring it the voter config never gets
    there. The pairing answer said the mode, and nobody promotes it by hand."""
    auto.form(seed)
    auto.past_the_hold()
    _cut_one_way(auto, monkeypatch, 'a', 'd')

    assert _pair(auto.g, auto.admin, 'd').status_code == 200
    st = auto.file('d')
    # before any sync, and without any lease state
    assert 'lease' not in st and st['group_mode'] == 'auto' and auto.mode('d') == 'auto'
    with auto.at('d') as ha:
        with pytest.raises(ha.AutoMode):
            ha.promote()
    assert _sync(auto.g, auto.admin, 'd') == 'applied'
    auto.members = 'abcd'
    auto.run(120, dt=1.0)
    st = auto.file('d')
    assert 'lease' not in st and st['group_mode'] == 'auto'

    r = _promote(auto.g, auto.admin, 'd')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE'
    assert auto.file('d')['role'] == 'standby' and not _audit('ha.promoted')
    assert auto.active() == ['a'] and auto.holders() == ['a']
    # and the leader says what it sees: a member that does not answer it
    auto.watch('a')
    assert ('VOTER_DOWN', IDS['d']) in _findings(auto)
    # it can still leave, to pair again with the right address: it holds no vote
    with auto.at('d'):
        assert _post(auto.admin, '/api/ha/unpair', UNPAIR).status_code == 200


def test_every_snapshot_says_the_mode_to_a_member_without_a_voter_config(auto, seed):
    """The mode travels with the member list. A member whose state went back to before
    the switch has it again with its next pull, whatever the pairing said back then."""
    auto.pair(seed)
    backup = auto.file('b')
    assert 'lease' not in backup and 'group_mode' not in backup
    with auto.at('a') as ha:
        assert 'mode' not in ha.snapshot_meta()
        manual = ha.snapshot_etag()
    assert auto.switch_on().status_code == 200
    with auto.at('a') as ha:
        assert ha.snapshot_meta()['mode'] == 'auto'
        # so the switch alone reaches every member with its next poll
        assert ha.snapshot_etag() != manual

    _restore(auto, 'b', backup)
    assert auto.mode('b') == 'manual'
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    assert auto.file('b')['group_mode'] == 'auto' and auto.mode('b') == 'auto'
    with auto.at('b') as ha:
        with pytest.raises(ha.AutoMode):
            ha._promote()
    # the watch of such a member follows the holder of the lease, not the highest epoch
    assert _watch(auto.g, 'b') in ('ok', 'source switched')

    # a member that holds the config needs no note next to it
    assert _sync(auto.g, auto.admin, 'c') in ('applied', 'unchanged')
    assert 'group_mode' not in auto.file('c') and auto.mode('c') == 'auto'


def test_the_note_goes_when_the_group_is_manual_again(auto, seed):
    auto.pair(seed)
    backup = auto.file('b')
    assert auto.switch_on().status_code == 200
    _restore(auto, 'b', backup)
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    assert auto.file('b')['group_mode'] == 'auto'
    with auto.at('b') as ha:
        ha._adopt_group({'instance_id': IDS['a'], 'epoch': 1})
        assert 'group_mode' not in ha._load() and ha.mode() == 'manual'


def test_a_voter_config_held_here_outranks_the_note(auto, seed):
    """The leader went back to manual mode and died before this member pulled again.
    The note of its last pull still says automatic, the config it took since says
    manual: the failover by hand is open."""
    auto.form(seed)
    auto.past_the_hold()
    with auto.at('b') as ha:
        ha._update(group_mode='auto')
    r = auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    auto.run(2 * T.R, dt=1.0)
    assert auto.file('b')['group_mode'] == 'auto' and auto.mode('b') == 'manual'
    auto.crash('a')

    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 200, r.data
    assert auto.file('b')['role'] == 'active' and 'group_mode' not in auto.file('b')


# --- a member restored from before the switch ----------------------------------------------

def test_a_restored_member_gets_the_voter_config_again_and_is_quarantined(auto, seed):
    """It answers the renewal as a member without a voter config: the leader sends its
    chain again, and a voter that reported writes before is one whose state went back."""
    auto.pair(seed)
    backup = auto.file('b')
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    assert auto.leader() == 'a' and auto.mode('b') == 'auto'

    _restore(auto, 'b', backup)
    with auto.at('b') as ha:
        ans = ha.lease_request(IDS['c'], 'vote', {'epoch': 2, 'candidate': IDS['c'], 'pre': True})
    assert ans['reason'] == 'MODE_MANUAL' and ans['cfg_id'] == [0, 0] and ans['gen'] == 0
    # what the leader shows while it stays like that. Not at once: a member that acked
    # a renewal a moment ago held the config then, whatever its status says
    auto.watch('a')
    assert ('MEMBER_MANUAL', IDS['b']) not in _findings(auto)
    acked = auto.rt('a').acked
    acked[IDS['b']] -= 2 * (T.R + T.renew_timeout) + 1
    assert ('MEMBER_MANUAL', IDS['b']) in _findings(auto)

    auto.g.sent.clear()
    auto.run(3 * T.L, dt=1.0)
    auto.watch('a')

    to_b = [json.loads(s[4]) for s in auto.g.sent if s[:2] == ('a', 'b') and s[3] == RENEW]
    assert any('chain' in body for body in to_b)
    st = auto.file('b')
    assert st['lease']['mode'] == 'auto' and auto.mode('b') == 'auto'
    assert st['lease']['cfg'] == auto.file('a')['lease']['cfg']
    body = auto.file('a')['lease']['cfg']['body']
    assert body['quarantined'] == [IDS['b']]
    found = _findings(auto)
    assert ('QUARANTINED', IDS['b']) in found and ('MEMBER_MANUAL', IDS['b']) not in found
    assert auto.leader() == 'a'
    assert _promote(auto.g, auto.admin, 'b').get_json()['code'] == 'HA_AUTO_MODE'


def test_a_restored_member_is_not_promoted_by_hand_next_to_the_leader(auto, seed):
    auto.pair(seed)
    backup = auto.file('b')
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    _restore(auto, 'b', backup)

    # at once, before any renewal or sync told it: the route syncs first and learns it
    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert auto.file('b')['role'] == 'standby' and auto.active() == ['a']


def test_a_promotion_by_hand_asks_the_members_first(auto, seed):
    """The leader is down and the restored member has nothing that says the group is
    automatic. The members that answer do."""
    auto.pair(seed)
    backup = auto.file('b')
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    auto.crash('a')
    _restore(auto, 'b', backup)
    assert auto.mode('b') == 'manual' and 'group_mode' not in auto.file('b')

    with auto.at('b'):
        r = _post(auto.admin, '/api/ha/promote', {'confirm': 'PROMOTE', 'force': True,
                                                 'user_password': ADMIN_PW})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert URLS['c'] in r.get_json()['error'] and 'fails over automatically' in r.get_json()['error']
    assert auto.file('b')['role'] == 'standby' and auto.file('b')['epoch'] == 1
    assert not _audit('ha.promoted')


def test_a_member_that_missed_the_switch_back_does_not_hold_a_promotion_up(auto, seed):
    """The group went back to manual mode while c was down. b holds that config and
    knows it is the group's: it pulled from a, the manual active that committed it (a
    commit nudges every member). c, back again, still says automatic, with an older
    one. Its word does not count against b."""
    auto.form(seed)
    auto.past_the_hold()
    auto.crash('c')
    auto.members = 'ab'
    r = auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    auto.run(2 * T.R, dt=1.0)
    assert auto.mode('a') == auto.mode('b') == 'manual' and auto.mode('c') == 'auto'
    assert _sync(auto.g, auto.admin, 'b') in ('applied', 'unchanged')
    assert auto.file('b')['lease']['settled'] == hv.cfg_digest(auto.file('b')['lease']['cfg'])
    auto.g.down.discard('c')
    auto.crash('a')

    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 200, r.data
    assert auto.file('b')['role'] == 'active'


def test_a_member_that_cannot_tell_the_switch_back_went_through_is_not_promoted(auto, seed):
    """The same, and b never heard that a majority took the switch back: a went down
    before b pulled from it. c says automatic with an older config; that is a member
    that missed the switch back, or one of the two that elect a leader because the
    switch back never got through. b cannot tell which, and is not promoted by hand
    next to a group that may fail over automatically."""
    auto.form(seed)
    auto.past_the_hold()
    auto.crash('c')
    auto.members = 'ab'
    assert auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW}).status_code == 200
    auto.run(2 * T.R, dt=1.0)
    assert auto.mode('a') == auto.mode('b') == 'manual' and 'settled' not in auto.file('b')['lease']
    auto.g.down.discard('c')
    auto.crash('a')
    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    # c campaigns once it hears no leader, gets the manual config from b's refusal and
    # says manual: from then on b is promoted
    auto.members = 'bc'
    auto.run(2 * BOUND, dt=1.0, until=lambda: auto.mode('c') == 'manual')
    assert auto.mode('c') == 'manual'
    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 200, r.data


# --- a voter that pairs again ----------------------------------------------------------------

def _wiped(auto, n):
    """n lost its state (a disk set up anew under the same id) and wants back in."""
    auto.g.write(n, {'role': 'standalone', 'epoch': 0, 'instance_id': IDS[n],
                     'interval': 30, 'pairing': None, 'sync': {}})
    auto.ha._rts.pop(IDS[n], None)


def _join(auto, n):
    with auto.at('a'):
        r = _post(auto.admin, '/api/ha/pairing-code', {'url': URLS['a'], 'user_password': ADMIN_PW})
        assert r.status_code == 200, r.data
        code = r.get_json()['code']
    with auto.at(n):
        return _post(auto.admin, '/api/ha/join', {'code': code, 'own_url': URLS[n], 'confirm': True,
                                                 'user_password': ADMIN_PW})


def test_a_voter_of_three_is_not_paired_again_in_an_automatic_group(auto, seed):
    """It would come back with a new key and without its vote, which leaves two: the
    change is one the leader cannot make. Refused at the pairing, and said."""
    auto.form(seed)
    auto.past_the_hold()
    before = auto.file('a')
    _wiped(auto, 'c')

    r = _join(auto, 'c')

    assert r.status_code == 502 and 'Switch automatic failover off' in r.get_json()['error'], r.data
    after = auto.file('a')
    assert after['members'][IDS['c']] == before['members'][IDS['c']]
    assert after['lease']['cfg'] == before['lease']['cfg']
    assert auto.file('c')['role'] == 'standalone' and auto.holders() == ['a']
    with auto.at('a') as ha:
        assert ha.is_active()


def test_a_voter_of_four_pairs_again_without_its_vote_and_takes_the_config(auto, seed):
    auto.form(seed, 'bcd', accept=['EVEN_VOTERS'])
    auto.past_the_hold()
    with auto.at('a') as ha:
        # it had left through one of the ways that stay open, and told the leader
        assert ha.forget_peer(IDS['d']) == 'member'
    _wiped(auto, 'd')
    auto.watch('a')
    assert ('VOTER_DOWN', IDS['d']) in _findings(auto)

    r = _join(auto, 'd')

    assert r.status_code == 200, r.data
    assert auto.file('d')['group_mode'] == 'auto'
    assert _sync(auto.g, auto.admin, 'd') == 'applied'
    auto.run(4 * T.R, dt=1.0)
    rec = next(v for v in auto.file('a')['lease']['cfg']['body']['voters'] if v['id'] == IDS['d'])
    with auto.at('d') as ha:
        assert rec['voter'] is False and rec['public_key'] == ha.own_public_key()
    st = auto.file('d')
    # it holds the config now, and the note next to it has gone with the next pull
    assert st['lease']['cfg'] == auto.file('a')['lease']['cfg'] and auto.node('a').view.n == 3
    assert auto.mode('d') == 'auto'
    auto.watch('a')
    assert _findings(auto) == set()


def test_a_change_of_the_voter_config_that_is_refused_is_said(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    with auto.at('a') as ha:
        node = ha._lease_node()
        # a change that takes a vote too many
        assert node.change_cfg(lambda body: dict(body, voters=[
            dict(v, voter=v['id'] != IDS['c']) for v in body['voters']])) == ''
    auto.run(2 * T.R, dt=1.0)
    said = _audit('ha.voter_config_refused')
    assert len(said) == 1 and 'too few voters' in said[0]['details']
    assert auto.node('a').view.n == 3


def test_the_leader_names_a_member_the_voter_config_does_not_match(auto, seed):
    auto.form(seed)
    auto.watch('a')
    assert _findings(auto) == set()
    with auto.at('e') as eha:
        other = eha._public_of(eha._private_key(eha._new_signing_key()))
    with auto.at('a') as ha:
        ms = dict(ha._load()['members'])
        ms[IDS['c']] = dict(ms[IDS['c']], public_key=other)
        ms[IDS['d']] = dict(ms[IDS['b']], url=URLS['d'], public_key=other)
        ha._update(members=ms)
        found = {(f['code'], f['member']) for f in ha.auto_findings()}
    assert ('KEY_MISMATCH', IDS['c']) in found and ('NOT_IN_CONFIG', IDS['d']) in found


def test_a_voter_that_is_no_member_any_more_shows(auto, seed):
    """Three votes on paper, two that answer: the leader says so."""
    auto.form(seed)
    auto.watch('a')
    with auto.at('a') as ha:
        ms = dict(ha._load()['members'])
        ms.pop(IDS['c'])
        ha._update(members=ms)
        status = ha.public_status()['auto']
    assert (status['voters'], status['majority']) == (3, 2)
    gone = [f for f in status['findings'] if f['member'] == IDS['c']]
    assert [f['code'] for f in gone] == ['VOTER_DOWN'] and 'no member of this group' in gone[0]['text']


# --- nobody leaves an automatic group by hand ------------------------------------------------

def test_nobody_leaves_an_automatic_group_by_hand(auto, seed):
    """A leader that walked out would act on its own while the two it left elect the
    next one; a voter that walked out would stay in the voter config as a vote that
    never answers."""
    auto.form(seed)
    auto.past_the_hold()
    auto.g.calls.clear()

    for n in 'ac':
        with auto.at(n) as ha:
            r = _post(auto.admin, '/api/ha/unpair', UNPAIR)
            assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', (n, r.data)
            # the leader hands its lead on first; a voter of three takes a vote the group
            # cannot do without (with more, it leaves through the leader, design 7.4)
            assert {'a': 'make another member leader first',
                    'c': 'Switch automatic failover off'}[n] in r.get_json()['error']
            # said before the password is asked for, like the promotion
            r = _post(auto.admin, '/api/ha/unpair', {'confirm': 'UNPAIR'})
            assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE'
            with pytest.raises(ha.AutoMode):
                ha.unpair()
    # nobody was told anything
    assert not [c for c in auto.g.calls if c[3] == '/api/ha/peer/unpaired']
    assert auto.file('a')['role'] == 'leader' and auto.file('c')['role'] == 'standby'
    assert set(auto.file('a')['members']) == {IDS['b'], IDS['c']} and auto.leader() == 'a'

    # switched off first, it leaves as ever, and takes nothing of the group with it
    assert auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW}).status_code == 200
    auto.run(2 * T.R, dt=1.0)
    rt = auto.rt('c')
    with auto.at('c') as ha:
        r = _post(auto.admin, '/api/ha/unpair', UNPAIR)
        assert r.status_code == 200, r.data
        st = auto.file('c')
        assert st['role'] == 'standalone' and not {'lease', 'timezone', 'group_mode'} & set(st)
        assert ha.is_active() and ha.mode() == 'manual' and ha._lease_node() is None
    # and what ran its lease is gone with it
    assert rt.stop and auto.rt('c') is not rt


def test_the_ways_out_of_a_group_stay_open(auto, seed, monkeypatch):
    auto.form(seed)
    ha = auto.ha
    with auto.at('c') as h:
        # the group took it out: it holds no vote, and unpairing is how it gets out
        assert h._mark_removed(IDS['a'], 1) == 'standby'
        assert h.unpair_refusal() == '' and auto.rt('c') is None
    with auto.at('b') as h:
        assert h.unpair_refusal() == ha.AUTO_UNPAIR_ERROR
        # its leader says the group is manual again and the config held here does not:
        # it missed the switch back, and pairing again is how it catches up
        h._adopt_group({'instance_id': IDS['a'], 'epoch': 1})
        assert h._load()['group_mode'] == 'manual' and h.mode() == 'auto'
        assert h.unpair_refusal() == ''
        h._adopt_group({'instance_id': IDS['a'], 'epoch': 1, 'mode': 'auto'})
        assert 'group_mode' not in h._load() and h.unpair_refusal() == ha.AUTO_UNPAIR_ERROR
    # a release that does not run automatic failover: nothing elects, and this is the
    # only way out of a state file that says automatic
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    with auto.at('a') as h:
        assert h.unpair_refusal() == ''
        assert _post(auto.admin, '/api/ha/unpair', UNPAIR).status_code == 200


def test_a_pending_switch_is_taken_back_before_the_active_leaves(auto, seed):
    auto.pair(seed)
    r = auto.switch_on(settle=False)
    assert r.status_code == 200 and r.get_json()['mode'] == 'auto_pending'
    auto.cut('a', 'c')
    auto.step('a')
    assert auto.mode('a') == auto.mode('b') == 'auto_pending'

    with auto.at('a'):
        r = _post(auto.admin, '/api/ha/unpair', UNPAIR)
    assert r.status_code == 409 and 'under way' in r.get_json()['error']
    # a member that holds the pending config and waits for nobody leaves: it holds no
    # lease, and nothing else gets it out when the active is gone for good
    with auto.at('b'):
        assert _post(auto.admin, '/api/ha/unpair', UNPAIR).status_code == 200


# --- an active whose last member left ----------------------------------------------------------

def test_an_active_whose_last_member_left_keeps_nothing_of_the_group(auto, seed):
    """Role standalone with a lease nobody renews would take no write for good, and no
    route gets it out of that."""
    auto.form(seed)
    rt = auto.rt('a')
    with auto.at('a') as ha:
        assert ha.forget_peer(IDS['b']) == 'member'
        assert ha._load()['role'] == 'active' and 'lease' in ha._load()
        assert ha.forget_peer(IDS['c']) == 'member'
        st = auto.file('a')
        assert st['role'] == 'standalone' and st['members'] == {}
        assert not {'lease', 'witness', 'timezone', 'group_mode'} & set(st)
        assert ha.is_active() and ha.acting_process() and not ha.lease_in_force()
        r = auto.admin.put('/api/user/preferences', json={'theme': 'corporateDark'})
        assert r.status_code == 200, r.data
    assert rt.stop and IDS['a'] not in auto.ha._rts


def test_what_a_dissolved_group_decided_does_not_go_into_the_next_one(auto, seed):
    auto.pair(seed, 'b')
    with auto.at('a'):
        assert auto.admin.put('/api/ha/timezone', json={'timezone': 'America/New_York'}).status_code == 200
    with auto.at('b'):
        assert _post(auto.admin, '/api/ha/unpair', UNPAIR).status_code == 200
    st = auto.file('a')
    assert st['role'] == 'standalone' and 'timezone' not in st

    # and should a state file hold it still: the next group starts in the zone of the
    # instance that forms it all the same
    auto.g.write('a', dict(st, timezone='America/New_York', group_mode='auto'))
    assert _join(auto, 'c').status_code == 200
    st = auto.file('a')
    assert st['timezone'] == ZONE and 'group_mode' not in st
    with auto.at('a') as h:
        assert h.group_timezone() == ZONE


def test_a_join_takes_nothing_of_a_group_from_before_along(auto, seed):
    auto.form(seed)
    # an instance of its own whose state file still holds what a group decided
    st = auto.file('e')
    auto.g.write('e', dict(st, timezone='America/New_York', lease=auto.file('b')['lease'],
                           witness={'instance_id': IDS['c'], 'url': URLS['c'], 'fingerprint': '',
                                    'public_key': auto.file('a')['members'][IDS['c']]['public_key']}))
    r = _join(auto, 'e')
    assert r.status_code == 200, r.data
    st = auto.file('e')
    assert st['role'] == 'standby' and not {'lease', 'witness', 'timezone'} & set(st)
    # what it knows of this group is what the pairing answer said
    assert st['group_mode'] == 'auto'


# --- an active made by hand next to the holder of the lease ------------------------------------

def _by_hand(auto, n):
    """What the guards above refuse, done all the same: n becomes an active of an epoch
    of its own, next to the group's leader."""
    ha = auto.ha
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ha, '_members_say_auto', lambda timeout=5: None)
        # and what S7 refuses on top: a state older than what it knew of its group
        mp.setattr(ha, 'way_out_check', lambda: '')
        with auto.at(n) as h:
            return h.promote()


def test_an_active_made_by_hand_leaves_for_the_holder_of_the_lease(auto, seed):
    """Design 4.10. Under one epoch the manual rule lets the higher instance id stay,
    and an elected leader leaves for a higher epoch only: neither would yield."""
    auto.pair(seed)
    backup = auto.file('c')
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    _restore(auto, 'c', backup)
    assert _by_hand(auto, 'c') == 2
    assert auto.active() == ['a', 'c']

    # the leader hears of the epoch with its next round and leaves; the two voters
    # left elect, at the very epoch c took by hand (c does not answer them meanwhile)
    auto.members = 'ab'
    auto.run(T.R + 1, dt=1.0)
    assert auto.file('a')['role'] == 'standby'
    auto.isolate('c')
    auto.run(BOUND + 20, dt=0.5, until=lambda: auto.holders() != [])
    winner = auto.holders()[0]
    assert auto.file(winner)['epoch'] == 2 and auto.file('c')['epoch'] == 2
    auto.heal()
    # the higher instance id: by the manual rule for two actives of one epoch, c stays
    assert IDS['c'] > IDS[winner]

    with auto.at('c') as h:
        assert h.watch_once() == 'stepped down'
    st = auto.file('c')
    assert st['role'] == 'standby' and st['source'] == IDS[winner]
    assert ('c', 'stepped down to standby') in auto.g.restarts
    assert [e for e in _audit('ha.stepped_down') if 'holds the lease' in e['details']]
    auto.members = 'abc'
    auto.run(T.W_take + T.R, dt=1.0, until=lambda: auto.active() != [])
    assert auto.active() == [winner]


def test_a_manual_active_keeps_the_lead_while_nobody_holds_a_lease(auto, seed):
    """The control: in a manual group, and for the active that leads it, nothing of
    this bites."""
    auto.pair(seed)
    for n in 'abc':
        _watch(auto.g, n)
    assert auto.active() == ['a'] and auto.file('a')['role'] == 'active'
    with auto.at('a') as ha:
        assert ha._holder_seen({IDS['b']: ('standby', 1)}, 1) is None


def _stray(auto, seed):
    """c, restored from before the switch, made active by hand at epoch 2. The leader
    hears of that epoch and leaves; the two voters elect while c does not answer them,
    at the very epoch c took. Then both act, the leader by its lease and c by hand.
    Returns the leader."""
    auto.pair(seed)
    backup = auto.file('c')
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    _restore(auto, 'c', backup)
    assert _by_hand(auto, 'c') == 2
    auto.run(T.R + 1, dt=1.0, members='ab', until=lambda: auto.file('a')['role'] == 'standby')
    assert auto.file('a')['role'] == 'standby'
    auto.isolate('c')
    auto.run(2 * BOUND, dt=1.0, members='ab', until=lambda: any(n in auto.active() for n in 'ab'))
    winner = next(n for n in 'ab' if n in auto.active())
    auto.heal()
    assert auto.file(winner)['epoch'] == 2 and sorted(auto.active()) == sorted([winner, 'c'])
    return winner


def test_the_holder_of_the_lease_tells_an_active_made_by_hand_to_step_down(auto, seed, monkeypatch):
    """At an epoch as high as its own, whatever the instance ids say, and even when the
    calls of that active do not get out (a member record from a backup, with an address
    or a pin that is out of date): the leader's own look at the group tells it."""
    winner = _stray(auto, seed)
    real = auto._call

    def call(method, base_url, fingerprint, path, **kw):
        if auto.g.name() == 'c':
            raise auto.ha.PeerUnreachable('Cannot reach the peer: ConnectTimeout')
        return real(method, base_url, fingerprint, path, **kw)
    monkeypatch.setattr(auto.ha, '_peer_call', call)
    other = next(n for n in 'ab' if n != winner)
    with auto.at(other) as ha:
        ha.watch_once()
        said = {f['code']: f['member'] for f in ha.auto_findings()}
    assert said.get('ACTIVE_WITHOUT_LEASE') == IDS['c']

    with auto.at(winner) as ha:
        assert ha.watch_once() == 'told peer to step down'
    c = auto.file('c')
    assert c['role'] == 'standby' and c['source'] == IDS[winner]
    assert ('c', 'stepped down to standby') in auto.g.restarts
    assert auto.active() == [winner]


def test_a_manual_active_that_a_member_renews_with_looks_at_the_group_at_once(auto, seed, monkeypatch):
    """The renewal of a leader says it holds a lease: the active looks at the group now,
    in the background, instead of at its next pass, which may be an hour away."""
    winner = _stray(auto, seed)
    looked = []

    def spawn(fn, name):
        if name == 'ha-look':
            looked.append(name)
            fn()
    monkeypatch.setattr(auto.ha, '_lease_spawn', spawn)
    # nobody runs a watch pass here: the renewals of the leader are all c hears
    auto.run(3 * T.R, dt=1.0, until=lambda: auto.file('c')['role'] == 'standby')
    assert auto.file('c')['role'] == 'standby' and looked
    assert ('c', 'stepped down to standby') in auto.g.restarts
    assert auto.active() == [winner]


# --- a second chain next to the one the group holds --------------------------------------------

def _second_active(auto, seed):
    """The group's elected leader at epoch 2, and next to it d, an active by hand at
    epoch 2 that holds nothing of the group's voter config."""
    auto.form(seed)
    auto.past_the_hold()
    assert _pair(auto.g, auto.admin, 'd').status_code == 200
    auto.members = 'abcd'
    for n in 'bcd':
        assert _sync(auto.g, auto.admin, n) == 'applied'
    auto.g.write('d', {k: v for k, v in auto.file('d').items() if k not in ('lease', 'group_mode')})
    auto.ha._rts.pop(IDS['d'], None)
    assert _by_hand(auto, 'd') == 2
    auto.run(T.R + 1, dt=0.5, members='abc', until=lambda: auto.file('a')['role'] == 'standby')
    assert auto.file('a')['role'] == 'standby'
    auto.run(120, dt=1.0, members='abc', until=lambda: len(auto.holders()) == 1)
    leader = auto.holders()[0]
    auto.run(40, dt=1.0, members='abc')
    assert auto.file(leader)['epoch'] == 2 and auto.active() == sorted([leader, 'd'])
    return leader, [n for n in 'abc' if n != leader]


def test_no_chain_is_founded_while_a_member_says_the_group_is_automatic(auto, seed):
    leader, _others = _second_active(auto, seed)

    r = auto.put('d', '/api/ha/mode', {'mode': 'auto', 'lease_s': 20, 'user_password': ADMIN_PW,
                                       'accept': ['EVEN_VOTERS']})

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_REFUSED', r.data
    blocks = {f['member'] for f in r.get_json()['findings'] if f['code'] == 'MEMBER_AUTO'}
    assert blocks == {IDS[n] for n in 'abc'}
    assert 'lease' not in auto.file('d') and auto.holders() == [leader]
    # the same in the place that founds it, whatever the findings said
    with auto.at('d') as ha:
        with pytest.raises(ha.HaError, match='fails over automatically already'):
            ha._lease_found(ha._load(), 20)


def test_a_switch_round_of_a_second_chain_takes_nothing_from_the_group(auto, seed):
    """The guards before the switch out of the way: what the protocol itself does with
    a manual active that switches on next to the elected leader of the same epoch."""
    leader, others = _second_active(auto, seed)
    ha = auto.ha
    before = {n: auto.file(n) for n in 'abc'}
    with pytest.MonkeyPatch.context() as mp:
        # as if no member had said anything
        mp.setattr(ha, 'auto_findings', lambda st=None, lease_s=20: [])
        mp.setattr(ha, '_ask_members', lambda timeout, refused=None: {})
        mp.setattr(ha, '_ask_witness', lambda: None)
        with auto.at('d') as h:
            h._rt().seen.clear()
            waiting = h.switch_auto_on(20, ['EVEN_VOTERS'])
    assert sorted(waiting) == sorted(IDS[n] for n in 'abc')
    assert auto.file('d')['lease']['cfg']['id'] == [2, 2] and auto.mode('d') == 'auto_pending'

    auto.run(6 * T.R, dt=1.0)
    node = auto.node('d')
    # every member answered, with a config id above the pending one - and holds nothing
    assert {NAME_OF[i] for i in node._cfg_seen} == set('abc')
    assert all(not ok for _digest, ok in node._switch_said.values())
    assert node.switch is not None and auto.mode('d') == 'auto_pending'
    assert auto.file('d')['role'] == 'active'
    for n in 'abc':
        st, was = auto.file(n), before[n]
        # no vote, no term, no config, no source, no promise went to d
        assert (st['epoch'], st['lease']['voted_for'], st.get('source')) == (
            was['epoch'], was['lease']['voted_for'], was.get('source'))
        assert st['lease']['cfg']['id'][0] == 2 and st['lease']['cfg']['by'] != IDS['d']
        assert auto.node(n).promise_to != IDS['d']
    assert auto.holders() == [leader] and auto.file(leader)['role'] == 'leader'

    # two minutes of everybody's passes: one lease, and nobody restarts over it
    restarts = len(auto.g.restarts)
    for _ in range(60):
        auto.advance(2.0)
        for n in 'abcd':
            auto.step(n)
            assert auto.holders() == [leader]
    assert auto.g.restarts[restarts:] == []
    for n in others:
        assert auto.file(n)['lease']['voted_for'] == IDS[leader]

    # and the active by hand leaves with its next look at the group
    with auto.at('d') as h:
        assert h.watch_once() == 'stepped down'
    assert auto.file('d')['role'] == 'standby' and auto.file('d')['source'] == IDS[leader]


# --- a vote is on disk, directory included ------------------------------------------------------

def _ask_for_a_vote(auto, frm, to, epoch):
    node = auto.node(frm)
    with auto.at(to) as ha:
        return ha.lease_request(IDS[frm], 'vote', {
            'epoch': epoch, 'candidate': IDS[frm], 'pre': False, 'why': 'timer',
            'cv': list(node.cv), 'cfg_id': list(node.view.id), 'lease_s': 20})


def _without_a_leader(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    auto.crash('a')
    auto.members = 'bc'
    # the promises to the lost leader run out; nobody campaigns by itself here
    auto.advance(T.P + 1)


def _dir_fsync_fails(monkeypatch, code):
    real, failed = os.fsync, []

    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            failed.append(fd)
            raise OSError(code, os.strerror(code))
        return real(fd)
    monkeypatch.setattr(os, 'fsync', fsync)
    return failed


def test_a_vote_whose_directory_could_not_be_synced_is_no_vote(auto, seed, monkeypatch):
    """Until the directory is on disk the rename is not, and a power cut brings back the
    file from before: the voter would vote again in the same term."""
    _without_a_leader(auto, seed)
    failed = _dir_fsync_fails(monkeypatch, errno.EIO)

    ans = _ask_for_a_vote(auto, 'c', 'b', 2)

    assert failed
    assert ans['granted'] is False and ans['reason'] == 'WRITE_FAILED' and ans['epoch'] == 1
    assert auto.node('b').promise_to != IDS['c'] and auto.node('b').epoch == 1
    with auto.at('b') as ha:
        # every other write goes on as before: the note of a member, say
        ha._update(interval=45)
        assert ha._load()['interval'] == 45


def test_a_vote_whose_directory_cannot_be_opened_is_no_vote(auto, seed, monkeypatch):
    _without_a_leader(auto, seed)
    real, refused = os.open, []

    def _open(path, flags, *a, **kw):
        if flags & getattr(os, 'O_DIRECTORY', 0):
            refused.append(path)
            raise OSError(errno.EACCES, 'Permission denied')
        return real(path, flags, *a, **kw)
    monkeypatch.setattr(os, 'open', _open)

    ans = _ask_for_a_vote(auto, 'c', 'b', 2)

    assert refused and ans['granted'] is False and ans['reason'] == 'WRITE_FAILED'
    assert auto.node('b').epoch == 1


def test_a_file_system_that_syncs_no_directory_votes_and_says_so(auto, seed, monkeypatch):
    _without_a_leader(auto, seed)
    monkeypatch.setattr(auto.ha, '_dir_sync', {'unsupported': None})
    _dir_fsync_fails(monkeypatch, errno.EINVAL)

    ans = _ask_for_a_vote(auto, 'c', 'b', 2)

    assert ans['granted'] is True and ans['epoch'] == 2
    with auto.at('b') as ha:
        assert [f['code'] for f in ha.auto_findings() if f['member'] is None
                and f['code'] == 'NO_DIR_SYNC'] == ['NO_DIR_SYNC']
        assert ha.peer_lease_status()['dir_sync'] is False
    # and the members hear it with its status
    with auto.at('c') as ha:
        ha._ask_members(5)
        found = {(f['code'], f['member']) for f in ha.auto_findings()}
    assert ('NO_DIR_SYNC', IDS['b']) in found


def test_a_vote_whose_file_could_not_be_synced_is_no_vote(auto, seed, monkeypatch):
    _without_a_leader(auto, seed)
    real = os.fsync

    def fsync(fd):
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, 'Input/output error')
        return real(fd)
    monkeypatch.setattr(os, 'fsync', fsync)

    ans = _ask_for_a_vote(auto, 'c', 'b', 2)

    assert ans['granted'] is False and ans['reason'] == 'WRITE_FAILED'
    assert auto.file('b')['epoch'] == 1
