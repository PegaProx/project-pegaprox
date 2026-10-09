"""What the status page and the log say about clocks, elections and removals in an
automatic group (#625 stage 2), from the lab re-test on 0f1ff8e.

  * a member that refuses our calls for its time (HA_CLOCK) is there: CLOCK_SKEW, not
    VOTER_DOWN, and the switch is refused for the clock (C1, C2, design 4.2)
  * a call signed before the receiver started hears that, not that the clocks are a
    signature window apart (it reached users as 502 HA_FORWARD_REFUSED)
  * the winner of an election restarting into its takeover wait is no active made by
    hand (ACTIVE_WITHOUT_LEASE for 12-45 s after every election)
  * a removed instance shows its removal and nothing of the voter config it left
  * the first gate after the takeover wait says "acting start" before anything acts
  * a wall clock jump of the acting instance goes out as an alert on both paths

None of it changes who may act.

MK Oct 2026 (#625)
"""
import logging
import re
import time

from pegaprox.core import ha_wire
from _ha_lease_harness import T, auto  # noqa: F401 - the fixture
from test_ha_api import ADMIN_PW, _audit
from test_ha_forward import fwd  # noqa: F401 - the fixture
from test_ha_lease_members import _by_hand, _restore
from test_ha_members import IDS, URLS, _built, _send, group  # noqa: F401 - the fixture
from test_ha_signed_peers import _sign_as
from test_ha_witness import B as W_MEMBER, Box as WitnessBox, genesis as witness_genesis
from test_ha_witness_group import _form, host  # noqa: F401 - the fixture

ON = {'mode': 'auto', 'user_password': ADMIN_PW}
BOUND = T.P + T.L / 4 + T.T_vote + T.W_take + 5
WINDOW_TEXT = 'The clocks of the two instances are more than 120 seconds apart - set both by NTP'


def _findings(auto, n, member=None):
    with auto.at(n) as ha:
        found = ha.auto_findings()
    return {f['code']: f for f in found if member is None or f['member'] == IDS[member]}


def _refuses_for_its_clock(auto, monkeypatch, who):
    """`who` reads every signed call as one from outside the window, as an instance whose
    clock went 10 minutes off does (C1): 401 HA_CLOCK, the signature is good."""
    ha = auto.ha
    check = ha._signature_check

    def checked(headers, method, path, body, sender, public_key, receiver):
        said = check(headers, method, path, body, sender, public_key, receiver)
        return 'skewed' if said == 'ok' and receiver == IDS[who] else said
    monkeypatch.setattr(ha, '_signature_check', checked)


def _signs_behind(ha, monkeypatch, who, seconds):
    """`who` signs its calls by a clock `seconds` behind everybody else's."""
    real = ha._signed_headers

    def signed(private, sender, receiver, method, path, body):
        if sender != IDS[who]:
            return real(private, sender, receiver, method, path, body)
        stream = ha._lease_stream if path in (ha.VOTE_PATH, ha.RENEW_PATH) else ha._call_stream
        return ha_wire.signed_headers(private, sender, receiver, method, path, body, time.time() - seconds,
                                      ha._stream_nonce(stream, receiver))
    monkeypatch.setattr(ha, '_signed_headers', signed)


def _alert_paths(monkeypatch):
    import pegaprox.globals as ppglobals
    import pegaprox.utils.webhooks as webhooks
    hooked, sent = [], []
    monkeypatch.setattr(ppglobals, '_notification_handlers',
                        list(ppglobals._notification_handlers) + [hooked.append])
    monkeypatch.setattr(webhooks, 'send_to_channels', lambda alert, channel_ids=None: sent.append(alert))
    return hooked, sent


def _elected(auto, seed):
    """a led and is gone; b or c won the election at epoch 2 and holds the lease in its
    takeover wait. Returns (winner, the other one)."""
    auto.form(seed)
    auto.past_the_hold()
    # every member heard every other one as it was: b and c answered as standbys
    auto.watch()
    auto.crash('a')
    auto.members = 'bc'
    auto.run(BOUND, until=lambda: auto.holders() != [])
    winner = auto.holders()[0]
    assert auto.active() == [] and auto.file(winner)['epoch'] == 2
    return winner, 'c' if winner == 'b' else 'b'


# --- a member that refuses our calls for its time ---------------------------------------

def test_a_member_far_off_the_clock_is_clock_skew_and_the_switch_says_so(auto, seed, monkeypatch):
    auto.pair(seed)
    _refuses_for_its_clock(auto, monkeypatch, 'c')
    auto.watch('a')

    found = _findings(auto, 'a', 'c')
    assert set(found) == {'CLOCK_SKEW'}, found
    f = found['CLOCK_SKEW']
    assert f['level'] == 'block' and f['text'].startswith(f'The clock of {URLS["c"]} is more than 120 s off')
    assert '5 s or less' in f['text']
    # it answered: what it said is in its record, and nothing counts it as gone
    with auto.at('a') as ha:
        assert ha._load()['members'][IDS['c']]['last_error'] == WINDOW_TEXT

    r = auto.put('a', '/api/ha/mode', ON)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_REFUSED'
    said = {(f['code'], f['member']) for f in r.get_json()['findings']}
    assert ('CLOCK_SKEW', IDS['c']) in said and ('VOTER_DOWN', IDS['c']) not in said
    assert 'lease' not in auto.file('a')


def test_in_a_running_group_it_is_a_warning_and_no_downgrade(auto, seed, monkeypatch):
    auto.form(seed)
    auto.past_the_hold()
    _refuses_for_its_clock(auto, monkeypatch, 'c')
    auto.watch('a')

    found = _findings(auto, 'a', 'c')
    assert set(found) == {'CLOCK_SKEW'} and found['CLOCK_SKEW']['level'] == 'warn', found
    # a refusal says nothing about the release it runs
    with auto.at('a') as ha:
        ha._lease_housekeeping()
    assert _audit('ha.member_downgraded') == []
    # and once it answers again, it is what it says
    monkeypatch.undo()
    auto.watch('a')
    assert 'CLOCK_SKEW' not in _findings(auto, 'a', 'c')


def test_a_witness_far_off_the_clock_is_clock_skew_too(auto, host, seed):
    _form(auto, host, seed)
    wid = host.w.instance_id()
    with auto.at('a') as ha:
        ha._ask_witness()
        assert ha._rt().seen[wid]['wire'] == ha_wire.WITNESS_WIRE
    # its host clock went 200 s ahead: it refuses the status call for the time
    host.w.wall = lambda: time.time() + 200
    with auto.at('a') as ha:
        ha._ask_witness()
        found = {f['code']: f for f in ha.auto_findings() if f['member'] == wid}
        # what it speaks is kept: the lease calls go on with numbered nonces
        assert ha._takes_streams(wid)
    assert set(found) == {'CLOCK_SKEW'}, found
    assert found['CLOCK_SKEW']['text'].startswith('The clock of the witness ')
    assert 'more than 120 s off' in found['CLOCK_SKEW']['text']


def test_a_member_that_restarted_ahead_of_our_clock_says_it_started_after_we_signed(auto, seed, monkeypatch):
    """Lab C2: a member 30 s ahead refuses every call of the others for 30 s after its
    restart ("older than this process"). That is a clock 30 s off, said as such."""
    auto.pair(seed)
    ha = auto.ha
    monkeypatch.setattr(ha, '_PROCESS_STARTED', ha.ha_vote.ha_clock() - 2)
    _signs_behind(ha, monkeypatch, 'a', 30)
    auto.watch('a')

    for n in 'bc':
        found = _findings(auto, 'a', n)
        assert set(found) == {'CLOCK_SKEW'}, found
        assert found['CLOCK_SKEW']['text'].startswith(f'{URLS[n]} started a moment ago and refuses')
        with auto.at('a') as h:
            error = h._load()['members'][IDS[n]]['last_error']
        assert re.search(r'started [23] s ago', error) and re.search(r'3[01] s behind', error), error


# --- a member that missed one ask (lab C1 on 3f43b7e) -------------------------------------

def test_one_unanswered_ask_is_no_voter_down_in_a_running_group(auto, seed):
    """c answered, then restarted while the watch of a asked it: the status said
    VOTER_DOWN "has not answered within the last 2 minutes" seconds after its last answer,
    until the next look. Now only once that answer is as old as the text says. Nothing
    that decides counts the answer it kept."""
    auto.form(seed)
    auto.past_the_hold()
    auto.watch('a')
    auto.crash('c')
    auto.watch('a')

    assert 'VOTER_DOWN' not in _findings(auto, 'a', 'c')
    with auto.at('a') as ha:
        rt = ha._rt()
        # what decides goes by rt.seen, and there it has no record
        assert IDS['c'] not in rt.seen and not ha._says_it_holds(IDS['c'])
        rt.gone[IDS['c']]['at'] -= ha.LEASE_SEEN_FRESH + 1
    found = _findings(auto, 'a', 'c')
    assert found['VOTER_DOWN']['level'] == 'warn'
    assert 'has not answered within the last 2 minutes' in found['VOTER_DOWN']['text']
    # it answers again
    auto.back('c')
    auto.watch('a')
    assert 'VOTER_DOWN' not in _findings(auto, 'a', 'c')
    with auto.at('a') as ha:
        assert IDS['c'] not in ha._rt().gone


def test_a_member_off_the_clock_that_restarts_stays_clock_skew(auto, seed, monkeypatch):
    """C1 phase A: the members showed CLOCK_SKEW for the jumped leader, then VOTER_DOWN for
    30 s once one ask fell into its restart."""
    auto.form(seed)
    auto.past_the_hold()
    _refuses_for_its_clock(auto, monkeypatch, 'c')
    auto.watch('a')
    assert set(_findings(auto, 'a', 'c')) == {'CLOCK_SKEW'}
    auto.crash('c')
    auto.watch('a')
    assert set(_findings(auto, 'a', 'c')) == {'CLOCK_SKEW'}


def test_before_the_switch_one_unanswered_ask_still_blocks_it(auto, seed):
    auto.pair(seed)
    auto.crash('c')
    auto.watch('a')
    assert _findings(auto, 'a', 'c')['VOTER_DOWN']['level'] == 'block'
    r = auto.put('a', '/api/ha/mode', ON)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_REFUSED'
    assert ('VOTER_DOWN', IDS['c']) in {(f['code'], f['member']) for f in r.get_json()['findings']}


# --- the text of an early call ----------------------------------------------------------

def test_a_call_signed_before_the_receiver_started_hears_that(group, seed, monkeypatch):
    g = group
    _built(g, seed, 'bc')
    ha = g.ha
    monkeypatch.setattr(ha, '_PROCESS_STARTED', ha.ha_vote.ha_clock() - 5)

    r = _send(g, 'a', _sign_as(g, 'b', 'a', ts=int(time.time()) - 30))

    said = r.get_json()
    assert r.status_code == 401 and said['code'] == 'HA_CLOCK' and said['clock'] == 'early'
    assert re.search(r'The receiving instance started [56] s ago', said['error']), said
    assert re.search(r'3[01] s behind it', said['error']) and 'NTP' in said['error']
    assert '120 seconds apart' not in said['error']
    # outside the window it is the clocks, as before
    r = _send(g, 'a', _sign_as(g, 'b', 'a', ts=int(time.time()) - 200))
    assert r.status_code == 401 and r.get_json() == {'code': 'HA_CLOCK', 'clock': 'window',
                                                     'error': WINDOW_TEXT}


def test_a_forwarded_write_refused_as_early_tells_the_user_why(fwd, seed, monkeypatch):
    g = fwd
    admin = _built(g, seed, 'b')
    ha = g.ha
    monkeypatch.setattr(ha, '_PROCESS_STARTED', ha.ha_vote.ha_clock() - 5)
    _signs_behind(ha, monkeypatch, 'b', 30)

    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})

    assert r.status_code == 502 and r.get_json()['code'] == 'HA_FORWARD_REFUSED', r.data
    error = r.get_json()['error']
    assert 'The receiving instance started' in error and re.search(r'3[01] s behind it', error), error
    assert '120 seconds apart' not in error


def test_the_witness_says_it_the_same_way(tmp_path):
    box = WitnessBox(tmp_path / 'w', witness_genesis(), started=int(time.time()) - 5)
    status, ans = box.call(W_MEMBER, 'status', ts_off=-30)
    assert status == 401 and ans['code'] == 'HA_CLOCK' and ans['clock'] == 'early'
    assert 'The receiving instance started' in ans['error']
    status, ans = box.call(W_MEMBER, 'status', ts_off=-200)
    assert status == 401 and ans == {'code': 'HA_CLOCK', 'clock': 'window', 'error': WINDOW_TEXT}


# --- the winner on its way in -------------------------------------------------------------

def test_the_winner_in_its_takeover_wait_is_no_active_made_by_hand(auto, seed):
    """Lab E1-E7: the other member took the winner's renewal and marks it active at once
    (_lease_heard); its last status answer is the one it gave as a standby, without the
    lease. That is the member it voted for, not one made active by hand."""
    winner, other = _elected(auto, seed)
    with auto.at(other) as ha:
        assert ha._load()['members'][IDS[winner]]['role_seen'] == 'active'
        assert ha._rt().seen[IDS[winner]]['holds'] is False
    assert 'ACTIVE_WITHOUT_LEASE' not in _findings(auto, other, winner)


def test_the_winner_on_its_boot_is_no_active_made_by_hand_where_nobody_voted_for_it(auto, seed, monkeypatch):
    """The old leader back, before any vote or renewal told it of epoch 2: the winner
    answers as an active without the lease (its boot round has no majority yet), at an
    epoch above every one known there, and in automatic mode."""
    winner, _other = _elected(auto, seed)
    auto.auto_restart = False
    auto.g.down.discard('a')
    with auto.at('a') as ha:
        ha._rts.pop(IDS['a'], None)
        ha.check_peer_at_boot()
    real = auto.ha.peer_lease_status

    def booting():
        out = real()
        if auto.g.name() == winner:
            out.pop('lease', None)
        return out
    monkeypatch.setattr(auto.ha, 'peer_lease_status', booting)
    auto.watch('a')

    with auto.at('a') as ha:
        st = ha._load()
        assert st['epoch'] == 1 and st['members'][IDS[winner]]['epoch_seen'] == 2
        assert st['members'][IDS[winner]]['role_seen'] == 'active'
        assert ha._rt().seen[IDS[winner]]['holds'] is False
    assert 'ACTIVE_WITHOUT_LEASE' not in _findings(auto, 'a', winner)


def test_an_active_made_by_hand_at_a_newer_epoch_is_still_one(auto, seed):
    """c, put back from before the switch, made active by hand at epoch 2: above every
    epoch b knows, but in manual mode. Nobody voted for it."""
    auto.pair(seed)
    backup = auto.file('c')
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    _restore(auto, 'c', backup)
    assert _by_hand(auto, 'c') == 2

    auto.watch('b')
    with auto.at('b') as ha:
        st = ha._load()
        assert st['epoch'] == 1 and st['members'][IDS['c']]['epoch_seen'] == 2
    assert 'ACTIVE_WITHOUT_LEASE' in _findings(auto, 'b', 'c')


def test_the_member_voted_for_made_active_by_hand_at_that_epoch_is_still_one(auto, seed):
    """The winner of epoch 2, put back from before the switch and made active by hand at
    epoch 2: the other member voted for it at that epoch, and it acts in manual mode,
    no takeover."""
    auto.pair(seed)
    backup = {n: auto.file(n) for n in 'bc'}
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    auto.watch()
    auto.crash('a')
    auto.members = 'bc'
    auto.run(BOUND, until=lambda: auto.holders() != [])
    winner = auto.holders()[0]
    other = 'c' if winner == 'b' else 'b'
    _restore(auto, winner, backup[winner])
    assert _by_hand(auto, winner) == 2

    auto.watch(other)
    with auto.at(other) as ha:
        node = ha._rts[IDS[other]].node
        assert node.epoch == 2 and node.st['voted_for'] == IDS[winner]
        rec = ha._load()['members'][IDS[winner]]
        assert rec['role_seen'] == 'active' and rec['epoch_seen'] == 2
        assert ha._rt().seen[IDS[winner]]['mode'] == 'manual'
    assert 'ACTIVE_WITHOUT_LEASE' in _findings(auto, other, winner)


# --- a removed instance -------------------------------------------------------------------

def test_a_removed_leader_does_not_write_its_lease_back_as_it_steps_down(auto, seed):
    """Lab E8 (verify3): removed at epoch 2, then the node that ran before stepped down
    and wrote its lease block back, with epoch 1."""
    auto.form(seed)
    auto.past_the_hold()
    rt = auto.rt('a')
    node = rt.node
    with auto.at('a') as ha:
        assert ha._mark_removed(IDS['b'], 2) == 'active'
        with rt.lock:
            node.step_down('a member holds voter config [2, 5], newer than the [1, 4] held here')
        ha._lease_events(rt)
        st = ha._load()
    assert 'lease' not in st and 'leader' not in st
    assert st['epoch'] == 2 and st['role'] == 'standby' and st['removed']['epoch'] == 2


def test_a_removed_instance_shows_its_removal_and_nothing_of_the_config_it_left(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    st = auto.file('b')
    assert st['lease']['mode'] == 'auto'
    # as an older build left it: removed, with the lease block of the group it left
    auto.g.write('b', dict(st, members={}, source=None, removed={'epoch': 2, 'at': st.get('joined_at') or '2026-10-08T07:50:44+00:00',
                                                                 'by': IDS['c']}))
    auto.ha._rts.pop(IDS['b'], None)

    with auto.at('b') as ha:
        out = ha.public_status()
    assert out['removed']['by'] == IDS['c'] and out['removed']['epoch'] == 2
    assert out['split_safety'] is None
    lease = out['auto']
    assert lease['mode'] == 'manual' and lease['findings'] == [] and lease['members'] == []
    assert lease['cfg_id'] is None and lease['pending'] is None


# --- acting start -------------------------------------------------------------------------

def test_the_first_gate_after_the_takeover_wait_says_acting_start(auto, seed, caplog):
    """Lab E6b: a forwarded write taken 38 ms after acting_from, before the line. The hub
    runs the lease loop late; the gate that finds the wait over says it first."""
    winner, _other = _elected(auto, seed)
    node = auto.node(winner)
    # the lease renewed up to a second before the wait is over, then no tick
    auto.run(node.acting_from - auto.clock[winner] - 1, dt=0.5)
    left = node.acting_from - auto.clock[winner]
    assert 0 < left <= 1.5 and not node.acting_said
    auto.advance(left + 0.04)

    with caplog.at_level(logging.WARNING):
        caplog.clear()
        with auto.at(winner) as ha:
            assert ha.is_active()
        lines = [r.getMessage() for r in caplog.records if 'acting start' in r.getMessage()]
        assert lines == [f'[HA] {IDS[winner][:8]}: acting start epoch=2']
        # the loop's next tick says it no second time
        caplog.clear()
        auto.step(winner)
        assert not [r for r in caplog.records if 'acting start' in r.getMessage()]


# --- a clock jump -------------------------------------------------------------------------

def test_a_clock_jump_of_the_acting_leader_goes_out_on_both_alert_paths(auto, seed, monkeypatch):
    hooked, sent = _alert_paths(monkeypatch)
    monkeypatch.setattr(auto.ha, '_later', lambda delay, fn, name: fn())
    auto.form(seed)
    auto.past_the_hold()
    assert auto.leader() == 'a'

    # within the skew limit: a confirm round, nothing more
    auto.skew['a'] = 3.0
    auto.step('a')
    assert hooked == [] and sent == []

    auto.skew['a'] = 33.0
    auto.step('a')
    assert len(hooked) == 1 and sent == hooked
    alert = hooked[0]
    assert alert['metric'] == 'ha_clock_jump' and alert['severity'] == 'warning'
    assert alert['target_name'] == URLS['a'] or alert['target_name'] == IDS['a'][:8]
    assert 'jumped by +30 s' in alert['message'] and 'Above 120 s the other members refuse' in alert['message']
    assert auto.leader() == 'a'

    # a clock that keeps stepping says so once in CLOCK_ALERT_GAP
    auto.skew['a'] = -200.0
    auto.step('a')
    assert len(hooked) == 1


def test_a_clock_jump_where_nothing_acts_is_only_logged(auto, seed, monkeypatch, caplog):
    hooked, sent = _alert_paths(monkeypatch)
    monkeypatch.setattr(auto.ha, '_later', lambda delay, fn, name: fn())
    winner, _other = _elected(auto, seed)
    auto.skew[winner] = -200.0
    with caplog.at_level(logging.WARNING):
        auto.step(winner)
    assert hooked == [] and sent == []
    assert any('jumped by -200 s' in r.getMessage() for r in caplog.records)
