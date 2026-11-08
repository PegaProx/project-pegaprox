"""Make leader and planned restarts in an automatic group (#625 stage 2, design 7.1 and
7.2, slice S7).

On the leader, Make leader hands the lead to a data member: writes pause (503
HA_TRANSFER), the member catches up, the leader stops acting and hands it its next term,
and the member votes at once. On a member it asks the leader for that, and where no
leader answers it campaigns at once with the pre-vote and every rule. A planned restart
of the leader asks the members to hold its lease until it is back.

The group is the one of tests/_ha_lease_harness.py, with automatic mode offered as this
release ships it; a test that sets ha_vote.AUTO_MODE_SHIPPED off checks what a server
without it answers.

MK Oct 2026 (#625)
"""
import ast
import os

import pytest

from pegaprox.core import ha_vote as hv
from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_api import ADMIN_PW, _audit
from test_ha_members import IDS, _sync, group  # noqa: F401  (the fixture)

WRITE = ('put', '/api/user/preferences', {'theme': 'corporateDark'})


def _write(auto, n):
    method, path, body = WRITE
    with auto.at(n):
        return getattr(auto.admin, method)(path, json=body)


def _make(auto, n, target=None, **extra):
    body = dict({'confirm': 'LEADER', 'user_password': ADMIN_PW}, **extra)
    if target:
        body['target'] = IDS[target]
    return auto.post(n, '/api/ha/make-leader', body)


def _formed(auto, seed, standbys='bc'):
    auto.form(seed, standbys)
    auto.past_the_hold()
    for n in standbys:
        assert _sync(auto.g, auto.admin, n) == 'applied'
    auto.run(2 * T.R, dt=0.5)
    assert auto.leader() == 'a'


def _step_cv(auto, n='a'):
    """A change on `n` that its members have not pulled: the cv of `n` steps ahead."""
    from pegaprox.core.db import get_db
    get_db().save_server_setting('ha_test_note', f'changed {auto.clock[n]}')
    with auto.at(n) as ha:
        assert ha.cv_tick(force=True) == 'stepped'


# --- on the leader --------------------------------------------------------------------------

def test_the_leader_hands_the_lead_to_a_member(auto, seed):
    _formed(auto, seed)
    epoch = auto.state('a')['epoch']

    r = _make(auto, 'a', 'b')

    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'result': 'handed', 'target': IDS['b']}
    with auto.at('a') as ha:
        # it let go before it handed the next term on, and never renews in its old one
        assert not ha.is_active()
        assert auto.state('a')['lease']['released'] == {'to': IDS['b'], 'epoch': epoch + 1}
    auto.run(T.W_take + 10, until=lambda: auto.leader() == 'b')
    assert auto.leader() == 'b'
    assert auto.state('b')['epoch'] == epoch + 1 and auto.state('a')['role'] == 'standby'
    assert any('made https://standby.example:5000 leader' in row['details'] for row in _audit('ha.make_leader'))


def test_writes_pause_while_the_lead_is_handed_on(auto, seed):
    _formed(auto, seed)
    _step_cv(auto)            # b is behind, so the hand-over waits for it
    with auto.at('a') as ha:
        with auto.rt('a').lock:
            assert auto.node('a').transfer_to(IDS['b']) == ''
        assert ha.handing_over() and ha.is_active()

    r = _write(auto, 'a')

    assert r.status_code == 503 and r.get_json()['code'] == 'HA_TRANSFER', r.data
    assert r.headers['Retry-After'] == '10'
    with auto.at('a'):
        # the HA page and reads go on
        assert auto.admin.get('/api/ha/status').get_json()['auto']['transfer']['to'] == IDS['b']
        assert auto.admin.get('/api/users').status_code == 200
    # b never catches up: the leader goes on leading and takes writes again
    auto.run(hv.TRANSFER_CATCHUP + 2, members='a')
    with auto.at('a') as ha:
        assert not ha.handing_over() and ha.is_active()
    assert _write(auto, 'a').status_code == 200
    assert _audit('ha.transfer_refused')


def test_a_write_a_member_hands_on_waits_as_well(auto, seed):
    _formed(auto, seed)
    _step_cv(auto)
    with auto.at('a'):
        with auto.rt('a').lock:
            assert auto.node('a').transfer_to(IDS['b']) == ''
    with auto.at('c') as ha:
        ha.set_forward_writes(True)

    r = _write(auto, 'c')

    assert r.status_code == 503 and r.get_json()['code'] == 'HA_TRANSFER', r.data


def test_a_member_that_does_not_catch_up_is_refused_and_writes_open_again(auto, seed):
    _formed(auto, seed)
    _step_cv(auto)

    r = _make(auto, 'a', 'b')

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_TRANSFER_REFUSED', r.data
    assert 'could not catch up' in r.get_json()['error']
    assert auto.leader() == 'a' and _write(auto, 'a').status_code == 200
    assert 'released' not in (auto.state('a')['lease'] or {}) or not auto.state('a')['lease']['released']


@pytest.mark.parametrize('case', ['itself', 'stranger', 'cut', 'cannot_write'])
def test_the_leader_hands_on_only_to_a_member_that_can_win(auto, seed, case):
    _formed(auto, seed)
    target = {'itself': IDS['a'], 'stranger': 'f' * 32}.get(case, IDS['b'])
    if case == 'cut':
        auto.cut('a', 'b')
        auto.run(2 * (T.R + T.renew_timeout) + 1, members='ac')
    elif case == 'cannot_write':
        auto.rt('a').seen.setdefault(IDS['b'], {})['write_failed'] = True

    r = auto.post('a', '/api/ha/make-leader', {'target': target, 'confirm': 'LEADER',
                                                'user_password': ADMIN_PW})

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_TRANSFER_REFUSED', r.data
    assert {'itself': 'leads already', 'stranger': 'holds no vote', 'cut': 'does not answer',
            'cannot_write': 'cannot write'}[case] in r.get_json()['error']
    assert auto.leader() == 'a'
    with auto.at('a') as ha:
        assert not ha.handing_over()
        row = [m for m in ha.lease_status()['members'] if m['instance_id'] == IDS['b']][0]
    assert row['make_leader'] is (case in ('itself', 'stranger'))


def test_a_replayed_campaign_call_does_nothing(auto, seed):
    _formed(auto, seed)
    with auto.at('b') as ha:
        ans = ha.lease_request(IDS['a'], 'campaign', {'epoch': auto.state('b')['epoch']})
    assert ans['reason'] == 'NO_ALLOWANCE'
    assert auto.leader() == 'a'


# --- on a member ------------------------------------------------------------------------------

def test_a_member_asks_the_leader_to_hand_it_the_lead(auto, seed):
    _formed(auto, seed)

    r = _make(auto, 'b')

    assert r.status_code == 200, r.data
    assert r.get_json()['result'] == 'handed'
    auto.run(T.W_take + 10, until=lambda: auto.leader() == 'b')
    assert auto.leader() == 'b'
    rows = [row['details'] for row in _audit('ha.make_leader')]
    assert any('asked for the lead' in d for d in rows) and any('made' in d for d in rows)


def test_a_member_cut_off_from_the_leader_hears_that_it_holds_a_majority(auto, seed):
    _formed(auto, seed)
    auto.cut('a', 'b')
    auto.run(T.P + 2, members='ac')

    r = _make(auto, 'b')

    assert r.status_code == 409, r.data
    assert r.get_json()['error'] == 'The leader holds a majority - this member is cut off from it'
    assert auto.leader() == 'a' and auto.state('b')['role'] == 'standby'


def test_a_member_campaigns_at_once_when_no_leader_answers(auto, seed):
    _formed(auto, seed)
    epoch = auto.state('b')['epoch']
    auto.crash('a')
    auto.members = 'bc'
    # past every promise, and nobody's timer ran
    auto.advance(T.P + 1)

    r = _make(auto, 'b')

    assert r.status_code == 200 and r.get_json()['result'] == 'elected', r.data
    assert auto.state('b')['epoch'] == epoch + 1
    auto.run(T.W_take + 5, until=lambda: auto.leader() == 'b')
    assert auto.leader() == 'b'


def test_without_a_majority_the_member_says_so_and_force_leader_is_offered(auto, seed):
    _formed(auto, seed)
    auto.crash('a')
    auto.crash('c')
    auto.members = 'b'
    auto.advance(T.P + T.L / 2 + 1)

    r = _make(auto, 'b')

    assert r.status_code == 409, r.data
    assert r.get_json()['error'].startswith('Only 1 of the 2 votes a leader needs answer')
    with auto.at('b') as ha:
        st = ha.lease_status()
    assert st['last_campaign']['unreachable'] is True and st['last_campaign']['majority'] == 2
    assert st['force_leader']['offered'] is True, st['force_leader']
    assert [c['instance_id'] for c in st['force_leader']['cut_out']] == [IDS['a'], IDS['c']]


def test_make_leader_wants_the_word_the_password_and_an_automatic_group(auto, seed, monkeypatch):
    from pegaprox.utils.auth import create_api_token
    auto.pair(seed)
    r = _make(auto, 'a', 'b')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_MANUAL'
    auto.switch_on()
    assert auto.post('a', '/api/ha/make-leader', {'target': IDS['b'], 'confirm': 'leader',
                                                   'user_password': ADMIN_PW}).status_code == 400
    r = auto.post('a', '/api/ha/make-leader', {'target': IDS['b'], 'confirm': 'LEADER',
                                                'user_password': 'wrong'})
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'
    res = create_api_token('root', 'ci', role='admin')
    with auto.at('a'):
        r = auto.g.api.anon().post('/api/ha/make-leader', json={'target': IDS['b'], 'confirm': 'LEADER',
                                                                'user_password': ADMIN_PW},
                                   headers={'Authorization': f"Bearer {res['token']}"})
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    r = _make(auto, 'a', 'b')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED'
    assert auto.state('a')['role'] == 'active' and not _audit('ha.make_leader')


def test_the_transfer_route_is_for_members_and_the_leader_only(auto, seed):
    _formed(auto, seed)
    # a member that does not lead names the leader instead
    with auto.at('b') as ha:
        resp = ha.call_member(ha.member(IDS['c']), 'POST', ha.TRANSFER_PATH, json_body={})
    assert resp.status_code == 409 and resp.json()['follow']['instance_id'] == IDS['a']
    assert auto.leader() == 'a'


# --- the status page -----------------------------------------------------------------------------

def test_the_status_says_who_can_be_made_leader(auto, seed):
    _formed(auto, seed)
    with auto.at('a') as ha:
        st = ha.lease_status()
    assert {m['instance_id']: m['make_leader'] for m in st['members']} == {IDS['b']: True, IDS['c']: True}
    assert st['transfer'] is None and st['planned_restart'] is None and st['forced'] is None
    assert st['make_leader'] == {'phrase': 'LEADER', 'self': False}
    assert st['force_leader']['offered'] is False and st['way_out'] == ''
    with auto.at('b') as ha:
        st = ha.lease_status()
    assert st['make_leader']['self'] is True
    assert all(m['make_leader'] is False for m in st['members'])
    assert st['force_leader']['offered'] is False and st['force_leader']['phrase'] == 'FORCE LEADER'


# --- planned restarts (7.2) ----------------------------------------------------------------------

def test_a_planned_restart_keeps_the_lead_without_a_failover(auto, seed):
    _formed(auto, seed)
    epoch = auto.state('a')['epoch']
    with auto.at('a') as ha:
        assert ha.planned_restart('the restart button') is True
        assert not ha.is_active()
    rows = _audit('ha.planned_restart')
    assert rows and 'the restart button' in rows[0]['details'] and '90 s' in rows[0]['details']
    for n in 'bc':
        with auto.at(n) as ha:
            held = ha.lease_status()['planned_restart']
        assert held['by'] == IDS['a'] and 80 <= held['hold_left'] <= hv.PLANNED_HOLD

    auto.crash('a')
    auto.run(60, members='bc')
    # nobody campaigned while the leader was away
    assert auto.holders() == [] and {auto.state(n)['epoch'] for n in 'bc'} == {epoch}

    auto.back('a')
    auto.members = 'abc'
    auto.run(10, until=lambda: auto.leader() == 'a')
    assert auto.leader() == 'a' and auto.state('a')['epoch'] == epoch
    with auto.at('b') as ha:
        assert ha.lease_status()['planned_restart'] is None


def test_a_leader_that_is_not_back_within_the_hold_is_replaced(auto, seed):
    _formed(auto, seed)
    epoch = auto.state('a')['epoch']
    with auto.at('a') as ha:
        assert ha.planned_restart('update to 9.9') is True
    auto.crash('a')
    auto.members = 'bc'
    auto.run(hv.PLANNED_HOLD + T.L + 10, until=lambda: auto.holders() != [])
    assert auto.holders() and auto.state(auto.holders()[0])['epoch'] == epoch + 1


def test_a_planned_restart_changes_nothing_in_a_manual_group_or_alone(auto, seed, monkeypatch):
    with auto.at('e') as ha:
        assert ha.planned_restart('alone') is False
    auto.pair(seed)
    before = auto.file('a')
    with auto.at('a') as ha:
        assert ha.planned_restart('manual') is False
        assert ha.is_active()
    assert auto.file('a') == before and not _audit('ha.planned_restart')
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    with auto.at('a') as ha:
        assert ha.planned_restart('not shipped') is False


def test_every_restart_an_admin_asks_for_holds_the_lease_first():
    """The update, the rollback and the restart button restart the process in a thread
    of their own: each asks ha.planned_restart before anything that ends the process."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'pegaprox', 'api', 'settings.py')
    tree = ast.parse(open(path, encoding='utf-8').read())
    # systemctl is asked in _restart_through_systemd, the way in place is ha.leave_process
    enders = ('os._exit', 'os.execv', 'subprocess.run', '_restart_through_systemd', 'ha.leave_process')
    found = 0
    for fn in ast.walk(tree):
        if not (isinstance(fn, ast.FunctionDef) and fn.name in ('restart_server', 'do_restart')):
            continue
        calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call)]
        names = [ast.unparse(c.func) for c in calls]
        if not any(n in enders for n in names):
            continue
        found += 1
        held = min(c.lineno for c in calls if ast.unparse(c.func) == 'ha.planned_restart')
        ends = [c.lineno for c in calls if ast.unparse(c.func) in enders]
        assert held < min(ends), fn.name
    assert found >= 3
