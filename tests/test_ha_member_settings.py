"""What an admin sets per member on the leader, the split-safety panel, the banners and the
status line of an automatic group (#625 stage 2, design 3.1, 3.4, 4.12, 6.2 and 8).

The site is a label the split checks go by: a manual group takes it too, and so does a
release that does not offer automatic failover yet. Vote and may lead decide who votes
and who leads on its own: in an automatic group a change of the voter config under a
confirm round, one at a time, never below three votes, never the vote of the leader. The
findings the switch goes by are the ones the panel shows (auto_findings, split_safety).
Every signed-in user hears when the group has no leader, when one is taking over and,
for ten minutes, that the leader changed.

The group is the one of tests/_ha_lease_harness.py, with automatic mode offered as this
release ships it; a test that sets ha_vote.AUTO_MODE_SHIPPED off checks what a server
without it answers.

MK Oct 2026 (#625)
"""
import json
import types
from datetime import datetime, timedelta, timezone

import pytest

from pegaprox.core import ha_vote as hv
from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_api import ADMIN_PW, _admin, _audit, ha_env  # noqa: F401  (the fixture)
from test_ha_members import IDS, URLS, _pair, _sync, group  # noqa: F401  (the fixture)

W_ID = 'f' * 32
W_URL = 'https://witness.example:5005'


def _key():
    from pegaprox.core import ha
    return ha._public_of(ha._private_key(ha._new_signing_key()))


def _site(auto, n, member, site, client=None):
    import pegaprox.api.ha as ha_api
    from test_ha_members import _fresh_windows
    _fresh_windows(ha_api)
    with auto.at(n):
        return (client or auto.admin).put(f'/api/ha/members/{IDS[member]}/site', json={'site': site})


def _vote(auto, n, member, client=None, headers=None, password=ADMIN_PW, **flags):
    import pegaprox.api.ha as ha_api
    from test_ha_members import _fresh_windows
    _fresh_windows(ha_api)
    body = dict(flags)
    if password is not None:
        body['user_password'] = password
    with auto.at(n):
        return (client or auto.admin).put(f'/api/ha/members/{IDS[member]}/vote', json=body, headers=headers)


def _formed(auto, seed, standbys='bc', accept=None):
    auto.form(seed, standbys, accept=accept)
    auto.past_the_hold()
    for n in standbys:
        assert _sync(auto.g, auto.admin, n) == 'applied'
    auto.run(2 * T.R, dt=0.5)
    assert auto.leader() == 'a'


def _cfg_voter(auto, n, member):
    return next(v for v in auto.file(n)['lease']['cfg']['body']['voters'] if v['id'] == IDS[member])


def _status(auto, n='a'):
    with auto.at(n) as ha:
        return ha.public_status()


# --- who reaches the routes ------------------------------------------------------------------

@pytest.mark.parametrize('kind', ['anonymous', 'user', 'viewer', 'capped_admin', 'tenant_admin',
                                  'capped_default_admin', 'admins_viewer_token'])
def test_below_an_unconfined_admin_the_member_routes_change_nothing(auto, seed, kind):
    """On the leader of an automatic group, where each of them would act."""
    _formed(auto, seed)
    api = auto.g.api
    headers = None
    if kind == 'anonymous':
        c = api.anon()
    elif kind == 'user':
        c = api.as_user(seed.user('ops', role='user', permissions=[
            'admin.users', 'admin.settings', 'security.settings.manage', 'ha.view', 'ha.config']))
    elif kind == 'viewer':
        c = api.as_user(seed.user('watcher', role='viewer'))
    elif kind == 'capped_admin':
        seed.tenant('globex', ['cluster_globex'])
        c = api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                  tenant_permissions={'globex': {'role': 'user'}}))
    elif kind == 'tenant_admin':
        # the admin of another tenant and nothing more: it sees that tenant's clusters
        seed.tenant('initech', ['cluster_initech'])
        c = _admin(api, seed, 'ini', role='user', tenant_id='initech',
                   tenant_permissions={'initech': {'role': 'admin'}})
    elif kind == 'capped_default_admin':
        c = _admin(api, seed, 'lowered', tenant_id='default',
                   tenant_permissions={'default': {'role': 'viewer'}})
    else:
        from pegaprox.utils.auth import create_api_token
        res = create_api_token('root', 'ci', role='viewer')
        assert res.get('success'), res
        c, headers = api.anon(), {'Authorization': f"Bearer {res['token']}"}
    before = auto.file('a')

    r1 = _site(auto, 'a', 'b', 'dc9', client=c) if headers is None else None
    with auto.at('a'):
        if headers is not None:
            r1 = c.put(f"/api/ha/members/{IDS['b']}/site", json={'site': 'dc9'}, headers=headers)
    r2 = _vote(auto, 'a', 'b', client=c, headers=headers, may_lead=False)

    for r in (r1, r2):
        assert r.status_code == (401 if kind == 'anonymous' else 403), (kind, r.data)
        if kind in ('capped_admin', 'capped_default_admin'):
            assert b'tenant' in r.data, r.data
    assert auto.file('a') == before
    assert not _audit('ha.member_site_changed') and not _audit('ha.member_vote_changed')


def test_on_a_standby_the_member_routes_say_where_they_are_set(auto, seed):
    _formed(auto, seed)
    before = auto.file('b')
    r = _site(auto, 'b', 'c', 'dc9')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert r.get_json()['error'] == 'The site of a member is set on the leader of a group'
    r = _vote(auto, 'b', 'c', may_lead=False)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert r.get_json()['error'] == 'Vote and may lead are set on the leader of a group'
    assert auto.file('b') == before
    # an instance of its own is no leader of a group either
    with auto.at('e'):
        r = auto.admin.put(f"/api/ha/members/{IDS['b']}/site", json={'site': 'dc9'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'


def test_the_vote_wants_the_password_and_the_site_does_not(auto, seed):
    from pegaprox.utils.auth import create_api_token
    _formed(auto, seed)
    r = _vote(auto, 'a', 'b', password=None, may_lead=False)
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH', r.data
    r = _vote(auto, 'a', 'b', password='not-it', may_lead=False)
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH', r.data
    res = create_api_token('root', 'automation', role='admin')
    token = {'Authorization': f"Bearer {res['token']}"}
    r = _vote(auto, 'a', 'b', client=auto.g.api.anon(), headers=token, may_lead=False)
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH', r.data
    assert _cfg_voter(auto, 'a', 'b')['may_lead'] is True and not _audit('ha.member_vote_changed')
    # a label: the token sets it
    with auto.at('a'):
        r = auto.g.api.anon().put(f"/api/ha/members/{IDS['b']}/site", json={'site': 'dc9'}, headers=token)
    assert r.status_code == 200 and r.get_json() == {'success': True, 'site': 'dc9', 'changed': True}, r.data
    assert auto.file('a')['members'][IDS['b']]['site'] == 'dc9'


# --- the site ----------------------------------------------------------------------------------

def test_before_this_release_offers_it_the_site_is_taken_and_the_vote_refused(auto, seed, monkeypatch):
    """The site decides nothing about who votes, leads or acts: a manual group takes it on a
    release without automatic failover as well. Vote and may lead wait for that release."""
    auto.pair(seed, sites=False)
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)

    r = _site(auto, 'a', 'b', ' dc-west ')

    assert r.status_code == 200 and r.get_json() == {'success': True, 'site': 'dc-west', 'changed': True}, r.data
    assert auto.file('a')['members'][IDS['b']]['site'] == 'dc-west'
    rows = _audit('ha.member_site_changed')
    assert len(rows) == 1 and rows[0]['user'] == 'root'
    assert rows[0]['details'] == f"{URLS['b']} runs at site dc-west (was (none))"
    # the same once more changes nothing and says nothing
    assert _site(auto, 'a', 'b', 'dc-west').get_json()['changed'] is False and len(_audit('ha.member_site_changed')) == 1
    # with the member list: b holds its own site, c the one of b
    for n in 'bc':
        assert _sync(auto.g, auto.admin, n) == 'applied'
    assert auto.file('b')['site'] == 'dc-west' and auto.file('c')['members'][IDS['b']]['site'] == 'dc-west'
    status = _status(auto, 'c')
    assert [m['site'] for m in status['members'] if m['instance_id'] == IDS['b']] == ['dc-west']
    assert status['auto'] is None and status['split_safety'] is None

    r = _vote(auto, 'a', 'b', voter=False)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED', r.data
    assert 'voter' not in auto.file('a')['members'][IDS['b']] and not _audit('ha.member_vote_changed')


def test_the_leader_labels_itself_and_cleared_labels_go_from_the_list(auto, seed):
    auto.pair(seed, sites=False)
    assert _site(auto, 'a', 'a', 'dc-a').status_code == 200
    assert auto.file('a')['site'] == 'dc-a' and _status(auto)['site'] == 'dc-a'
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    assert auto.file('b')['members'][IDS['a']]['site'] == 'dc-a'
    # cleared: gone from the record and from the member list
    assert _site(auto, 'a', 'a', '').get_json() == {'success': True, 'site': '', 'changed': True}
    assert 'site' not in auto.file('a')
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    assert 'site' not in auto.file('b')['members'][IDS['a']]


@pytest.mark.parametrize('site', ['x' * 65, 'dc\n1', 'dc\x001', 'tab\there', 42, None, ['dc1']])
def test_a_site_is_a_label_on_one_line(auto, seed, site):
    auto.pair(seed, sites=False)
    before = auto.file('a')
    with auto.at('a'):
        r = auto.admin.put(f"/api/ha/members/{IDS['b']}/site", json={'site': site})
    assert r.status_code == 400 and r.get_json()['error'] == 'The site is a label of up to 64 characters on one line'
    assert auto.file('a') == before
    assert _site(auto, 'a', 'b', 'y' * 64).status_code == 200


def test_the_site_of_an_instance_outside_the_group_is_not_found(auto, seed):
    auto.pair(seed, sites=False)
    with auto.at('a'):
        r = auto.admin.put(f"/api/ha/members/{IDS['d']}/site", json={'site': 'dc1'})
        assert r.status_code == 404 and r.get_json()['error'] == 'That instance is not a member of this group'
        r = auto.admin.put(f"/api/ha/members/{IDS['d']}/vote", json={'voter': True, 'user_password': ADMIN_PW})
        assert r.status_code == 404


def test_the_witness_is_labelled_like_a_member(auto, seed):
    """In a manual group the record; the voter config takes it with the next switch."""
    auto.pair(seed, sites=False)
    with auto.at('a') as ha:
        st = ha._load()
        ha._commit_locked(dict(st, witness={'instance_id': W_ID, 'url': W_URL, 'fingerprint': '',
                                            'public_key': _key(), 'site': ''}))
    with auto.at('a'):
        r = auto.admin.put(f'/api/ha/members/{W_ID}/site', json={'site': 'dc3'})
    assert r.status_code == 200, r.data
    assert auto.file('a')['witness']['site'] == 'dc3'
    rows = _audit('ha.member_site_changed')
    assert rows[-1]['details'] == f'the witness {W_URL} runs at site dc3 (was (none))'
    with auto.at('a') as ha:
        assert ha._voter_body(ha._load(), 20)['witness']['site'] == 'dc3'


def test_in_an_automatic_group_the_witness_site_reaches_the_voter_config(auto, seed, monkeypatch):
    _formed(auto, seed)
    asked = []
    monkeypatch.setattr(auto.ha, '_witness_into_config', lambda: asked.append(True) or '')
    with auto.at('a') as ha:
        st = ha._load()
        ha._commit_locked(dict(st, witness={'instance_id': W_ID, 'url': W_URL, 'fingerprint': '',
                                            'public_key': _key(), 'site': ''}))
        assert ha.set_member_site(W_ID, 'dc3') is True
        assert ha.set_member_site(IDS['b'], 'dc9') is True
    # once for the witness; a member's site is a label of its record alone
    assert asked == [True]
    assert _cfg_voter(auto, 'a', 'b')['site'] == 'dc-b' and auto.file('a')['members'][IDS['b']]['site'] == 'dc9'


def test_an_automatic_leader_without_its_lease_takes_no_site(auto, seed):
    _formed(auto, seed)
    auto.advance(T.L + 1)           # a never ticks: its lease runs out under it
    before = auto.file('a')['members'][IDS['b']].get('site')
    r = _site(auto, 'a', 'b', 'dc9')
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE', r.data
    assert auto.file('a')['members'][IDS['b']].get('site') == before


def test_a_pending_switch_takes_no_site_and_no_vote(auto, seed):
    auto.pair(seed)
    assert auto.switch_on(settle=False).status_code == 200
    assert auto.mode('a') == 'auto_pending'
    r = _site(auto, 'a', 'b', 'dc9')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    r = _vote(auto, 'a', 'b', may_lead=False)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert auto.file('a')['members'][IDS['b']]['site'] == 'dc-b'


# --- vote and may lead in a manual group -------------------------------------------------------

def test_in_a_manual_group_the_vote_is_noted_for_the_next_switch(auto, seed):
    auto.pair(seed, 'bcd')

    r = _vote(auto, 'a', 'd', voter=False)

    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'changed': True, 'automatic': False, 'voter': False}
    assert auto.file('a')['members'][IDS['d']]['voter'] is False and 'lease' not in auto.file('a')
    assert _audit('ha.member_vote_changed')[-1]['details'] == (
        f"{URLS['d']}: vote off (taken into the voter config at the next switch to automatic failover)")
    # three votes now: the switch wants no tick for an even count any more
    r = auto.switch_on(accept=[])
    assert r.status_code == 200, r.data
    assert _cfg_voter(auto, 'a', 'd')['voter'] is False and auto.node('a').view.n == 3
    # and the member list carried it
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    assert auto.file('b')['members'][IDS['d']]['voter'] is False


def test_a_member_whose_vote_was_taken_counts_the_votes_as_the_leader_does(auto, seed):
    """d holds the leader's word on its own vote with the member list: every member counts
    three votes, d too, and four again once the vote is back."""
    auto.pair(seed, 'bcd')
    assert _vote(auto, 'a', 'd', voter=False).status_code == 200
    for n in 'bcd':
        assert _sync(auto.g, auto.admin, n) == 'applied'

    seen = {n: (_status(auto, n)['split_safety']['voters'], _status(auto, n)['auto']['voters']) for n in 'abcd'}

    assert set(seen.values()) == {(3, 3)}, seen
    assert auto.file('d')['voter'] is False
    assert _vote(auto, 'a', 'd', voter=True).status_code == 200
    assert _sync(auto.g, auto.admin, 'd') == 'applied'
    assert 'voter' not in auto.file('d') and _status(auto, 'd')['auto']['voters'] == 4
    # made active by hand with the mark still on it, it leads with its vote, and the
    # member list it hands out says the same
    with auto.at('d') as ha:
        st = dict(ha._load(), role='active', voter=False)
        assert next(v for v in ha._voter_body(st, 20)['voters'] if v['id'] == IDS['d'])['voter'] is True
        assert 'voter' not in next(e for e in ha._member_list(st) if e['instance_id'] == IDS['d'])


def test_in_a_manual_group_the_rules_hold_as_well(auto, seed):
    auto.pair(seed)
    r = _vote(auto, 'a', 'a', voter=False)
    assert r.status_code == 409 and r.get_json() == {
        'code': 'HA_VOTE_REFUSED', 'error': 'The leader keeps its own vote - make another member leader first'}
    r = _vote(auto, 'a', 'b', voter=False)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_VOTE_REFUSED'
    assert r.get_json()['error'].startswith('Without this vote the group would have fewer than 3 votes')
    # may lead is no vote: taken, and noted for the leader itself too
    assert _vote(auto, 'a', 'a', may_lead=False).get_json()['changed'] is True
    assert auto.file('a')['may_lead'] is False
    with auto.at('a') as ha:
        mine = next(v for v in ha._voter_body(ha._load(), 20)['voters'] if v['id'] == IDS['a'])
        assert mine == dict(mine, voter=True, may_lead=False)
        st = ha._load()
        ha._commit_locked(dict(st, witness={'instance_id': W_ID, 'url': W_URL, 'fingerprint': '',
                                            'public_key': _key(), 'site': ''}))
    with auto.at('a'):
        r = auto.admin.put(f'/api/ha/members/{W_ID}/vote', json={'voter': False, 'user_password': ADMIN_PW})
    assert r.status_code == 409 and r.get_json()['error'] == ('The witness always votes and never leads - '
                                                              'remove it to take its vote')
    assert 'voter' not in auto.file('a')['members'][IDS['b']]


@pytest.mark.parametrize('body', [{}, {'voter': 'no'}, {'may_lead': 1}, {'voter': None}])
def test_the_vote_route_wants_a_flag(auto, seed, body):
    auto.pair(seed)
    with auto.at('a'):
        r = auto.admin.put(f"/api/ha/members/{IDS['b']}/vote", json=dict(body, user_password=ADMIN_PW))
    assert r.status_code == 400 and r.get_json()['error'] == 'voter and may_lead are true or false, one of them at least'


# --- vote and may lead in an automatic group ----------------------------------------------------

def test_in_an_automatic_group_a_vote_is_a_change_of_the_voter_config(auto, seed):
    _formed(auto, seed, 'bcd', accept=['EVEN_VOTERS'])
    before = auto.node('a').view.id

    r = _vote(auto, 'a', 'd', voter=False)

    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'changed': True, 'automatic': True, 'voter': False}
    view = auto.node('a').view
    assert view.id > before and view.n == 3 and IDS['d'] not in view.voters
    assert auto.file('a')['members'][IDS['d']]['voter'] is False
    assert _audit('ha.member_vote_changed')[-1]['details'] == (
        f"{URLS['d']}: vote off (a change of the voter config, in force once a majority holds it)")
    # the members take it with the next rounds, and the group says so
    auto.run(3 * T.R, dt=0.5)
    for n in 'bcd':
        assert _cfg_voter(auto, n, 'd')['voter'] is False, n
    status = _status(auto)
    assert status['auto']['voters'] == 3 and status['split_safety']['voters'] == 3
    assert 'EVEN_VOTERS' not in {f['code'] for f in status['split_safety']['findings']}
    # and back
    assert _vote(auto, 'a', 'd', voter=True).status_code == 200
    assert auto.node('a').view.n == 4 and 'voter' not in auto.file('a')['members'][IDS['d']]


def test_may_lead_goes_the_same_way_and_the_leader_may_give_up_its_own(auto, seed):
    _formed(auto, seed)
    assert _vote(auto, 'a', 'b', may_lead=False).get_json()['changed'] is True
    assert _cfg_voter(auto, 'a', 'b')['may_lead'] is False
    assert auto.file('a')['members'][IDS['b']]['may_lead'] is False
    auto.run(3 * T.R, dt=0.5)
    assert _vote(auto, 'a', 'a', may_lead=False).get_json()['changed'] is True
    assert _cfg_voter(auto, 'a', 'a')['may_lead'] is False and auto.file('a')['may_lead'] is False
    with auto.at('a') as ha:
        st = ha.lease_status()
    assert st['may_lead'] is False
    assert [m['may_lead'] for m in st['members'] if m['instance_id'] == IDS['b']] == [False]
    # nobody else leads on its own now but c, in its own site
    codes = {f['code']: f for f in st['findings']}
    assert codes['CANDIDATES_ONE_SITE']['site'] == 'dc-c'


def test_one_change_of_the_voter_config_at_a_time(auto, seed):
    _formed(auto, seed)
    node = auto.node('a')
    with auto.rt('a').lock:
        node.change_cfg(lambda body: dict(body, lease_s=30))
    assert node.change_pending()

    r = _vote(auto, 'a', 'b', may_lead=False)

    assert r.status_code == 409 and r.get_json() == {
        'code': 'HA_VOTE_REFUSED', 'error': 'A change of the voter config is on its way - try again in a moment'}
    assert _cfg_voter(auto, 'a', 'b')['may_lead'] is True and not _audit('ha.member_vote_changed')


def test_never_below_three_votes_and_never_the_vote_of_the_leader(auto, seed):
    _formed(auto, seed)
    r = _vote(auto, 'a', 'b', voter=False)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_VOTE_REFUSED'
    assert r.get_json()['error'].startswith('Without this vote the group would have fewer than 3 votes')
    r = _vote(auto, 'a', 'a', voter=False)
    assert r.status_code == 409 and r.get_json()['error'] == 'The leader keeps its own vote - make another member leader first'
    assert auto.node('a').view.n == 3 and not _audit('ha.member_vote_changed')


def _quarantined_d(auto, seed):
    """Four votes, d quarantined: a, b and c count, and three of the four are needed."""
    _formed(auto, seed, 'bcd', accept=['EVEN_VOTERS'])
    with auto.rt('a').lock:
        auto.node('a').change_cfg(lambda body: dict(body, quarantined=[IDS['d']]))
    auto.run(3 * T.R, dt=0.5)
    view = auto.node('a').view
    assert (view.n, view.m, len(view.counting)) == (4, 3, 3)


def test_the_three_votes_are_three_that_count(auto, seed):
    """Without b three votes stand on paper and two count (a and c): the next failure would
    stop automation. The quarantined vote itself may go, three that count are left."""
    _quarantined_d(auto, seed)

    r = _vote(auto, 'a', 'b', voter=False)

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_VOTE_REFUSED', r.data
    assert r.get_json()['error'] == ('Without this vote fewer than 3 votes of the group would count (a quarantined '
                                     'member votes on paper only), too few for automatic failover. Re-admit the '
                                     'quarantined member first')
    assert auto.node('a').view.n == 4 and not _audit('ha.member_vote_changed')
    assert 'voter' not in auto.file('a')['members'][IDS['b']]
    r = _vote(auto, 'a', 'd', voter=False)
    assert r.status_code == 200, r.data
    view = auto.node('a').view
    assert (view.n, len(view.counting)) == (3, 3) and IDS['d'] not in view.voters


def test_no_vote_for_a_member_that_does_not_answer(auto, seed):
    _formed(auto, seed, 'bcd', accept=['EVEN_VOTERS'])
    assert _vote(auto, 'a', 'd', voter=False).status_code == 200
    auto.cut('a', 'd')
    auto.run(3 * (T.R + T.renew_timeout), dt=0.5, members='abc')

    r = _vote(auto, 'a', 'd', voter=True)

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_VOTE_REFUSED', r.data
    assert r.get_json()['error'] == (f"{URLS['d']} does not answer the renewals of this leader: a vote it "
                                     'cannot give would only take one from the majority')
    assert auto.node('a').view.n == 3


def test_no_change_after_which_the_members_that_answer_make_no_majority(auto, seed, monkeypatch):
    """d answers and b and c went quiet a moment ago (their acks are older than two
    rounds): a vote for d makes four votes, three of them needed, and two that answer."""
    _formed(auto, seed, 'bcd', accept=['EVEN_VOTERS'])
    assert _vote(auto, 'a', 'd', voter=False).status_code == 200
    auto.run(3 * T.R, dt=0.5)
    ha, rt = auto.ha, auto.rt('a')
    monkeypatch.setattr(ha, 'confirm_lease', lambda need=None: True)
    with auto.at('a'):
        rt.acked[IDS['b']] = rt.acked[IDS['c']] = ha.ha_clock() - 60
        with pytest.raises(ha.VoteRefused) as e:
            ha.set_member_vote(IDS['d'], voter=True)
    assert str(e.value).startswith('After this change the members that answer would not make a majority')
    assert auto.node('a').view.n == 3


def test_the_change_waits_for_the_confirm_round(auto, seed, monkeypatch):
    _formed(auto, seed)
    asked, real = [], auto.ha.confirm_lease
    monkeypatch.setattr(auto.ha, 'confirm_lease', lambda need=hv.Timings().need: asked.append(need) or False)
    r = _vote(auto, 'a', 'b', may_lead=False)
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE', r.data
    assert asked == [hv.Timings().need] and _cfg_voter(auto, 'a', 'b')['may_lead'] is True
    # with the round: through
    monkeypatch.setattr(auto.ha, 'confirm_lease', lambda need=hv.Timings().need: asked.append(need) or real(need))
    assert _vote(auto, 'a', 'b', may_lead=False).status_code == 200
    assert len(asked) == 2 and _cfg_voter(auto, 'a', 'b')['may_lead'] is False


def test_a_member_that_joins_an_automatic_group_has_no_vote_in_its_record_either(auto, seed):
    _formed(auto, seed)
    assert _pair(auto.g, auto.admin, 'd').status_code == 200
    assert auto.file('a')['members'][IDS['d']]['voter'] is False
    auto.run(3 * T.R, dt=0.5)
    assert _cfg_voter(auto, 'a', 'd')['voter'] is False
    # the next switch, after one off, takes the group as the records have it
    with auto.at('a') as ha:
        assert next(v for v in ha._voter_body(ha._load(), 20)['voters'] if v['id'] == IDS['d'])['voter'] is False


# --- split safety: the layouts of the design (3.4) -----------------------------------------------

SITE_CODES = {'SITE_HOLDS_MAJORITY', 'TWO_SITES_NO_THIRD_VOTE', 'WITNESS_SAME_SITE', 'CANDIDATES_ONE_SITE',
              'NO_SITE_LABELS', 'ALL_ONE_SITE', 'EVEN_VOTERS', 'NO_CANDIDATE'}


def _layout(sites, witness=None, no_lead=''):
    """A leader a and its members as a state file holds them: `sites` names the site of
    a, b, c, d in that order ('1' is dc1, '-' none), `witness` the site of the witness
    (None for none), `no_lead` the letters that do not lead on their own."""
    names = 'abcd'[:len(sites)]
    st = {'role': 'active', 'instance_id': IDS['a'], 'epoch': 1, 'members': {}, 'tombstones': {},
          'sync': {}, 'pairing': None}
    if sites[0] != '-':
        st['site'] = f'dc{sites[0]}'
    for n, s in zip(names[1:], sites[1:]):
        st['members'][IDS[n]] = {'url': URLS[n], 'fingerprint': '', 'public_key': _key()}
        if s != '-':
            st['members'][IDS[n]]['site'] = f'dc{s}'
    if witness:
        st['witness'] = {'instance_id': W_ID, 'url': W_URL, 'fingerprint': '', 'public_key': _key(),
                         'site': '' if witness == '-' else f'dc{witness}'}
    for n in no_lead:
        (st if n == 'a' else st['members'][IDS[n]])['may_lead'] = False
    return st


def _site_codes(ha, st):
    return {(f['code'], f.get('site')) for f in ha.auto_findings(st) if f['code'] in SITE_CODES}


@pytest.mark.parametrize('sites,witness,expected', [
    # the table of design 3.4, row by row
    ('11', None, set()),                                            # two votes: TOO_FEW_VOTERS
    ('11', '1', {('ALL_ONE_SITE', 'dc1')}),
    ('111', None, {('ALL_ONE_SITE', 'dc1')}),
    ('1111', None, {('ALL_ONE_SITE', 'dc1'), ('EVEN_VOTERS', None)}),
    ('1111', '1', {('ALL_ONE_SITE', 'dc1')}),
    ('112', None, {('SITE_HOLDS_MAJORITY', 'dc1')}),
    ('1122', None, {('TWO_SITES_NO_THIRD_VOTE', None), ('EVEN_VOTERS', None)}),
    ('12', '3', set()),
    ('1122', '3', set()),
    ('1122', '1', {('WITNESS_SAME_SITE', 'dc1'), ('SITE_HOLDS_MAJORITY', 'dc1')}),
    ('123', None, set()),
    ('1123', None, {('SITE_HOLDS_MAJORITY', 'dc1'), ('EVEN_VOTERS', None)}),
    # and a site with two votes of four, a witness at a third
    ('122', '3', {('SITE_HOLDS_MAJORITY', 'dc2'), ('EVEN_VOTERS', None)}),
])
def test_split_safety_follows_the_layouts_of_the_design(ha_env, sites, witness, expected):
    assert _site_codes(ha_env.ha, _layout(sites, witness)) == expected


def test_the_texts_name_what_is_lost(ha_env):
    ha = ha_env.ha
    found = {f['code']: f for f in ha.auto_findings(_layout('111'))}
    assert found['ALL_ONE_SITE'] == {'code': 'ALL_ONE_SITE', 'level': 'info', 'member': None, 'site': 'dc1',
                                     'text': 'Survives the loss of any 1 member. A site outage stops PegaProx '
                                             'automation until the site is back.'}
    found = {f['code']: f for f in ha.auto_findings(_layout('1111', '1'))}
    assert found['ALL_ONE_SITE']['text'].startswith('Survives the loss of any 2 members.')
    found = {f['code']: f for f in ha.auto_findings(_layout('112'))}
    assert found['SITE_HOLDS_MAJORITY']['text'] == 'Losing site dc1 stops automation everywhere.'
    assert found['SITE_HOLDS_MAJORITY']['level'] == 'warn'
    found = {f['code']: f for f in ha.auto_findings(_layout('1122'))}
    assert found['TWO_SITES_NO_THIRD_VOTE']['text'] == ('Two sites need a third vote at a third location, or a '
                                                        'WAN cut stops automation in both.')
    found = {f['code']: f for f in ha.auto_findings(_layout('1122', '1'))}
    assert found['WITNESS_SAME_SITE']['member'] == W_ID and found['WITNESS_SAME_SITE']['text'].startswith(
        'The witness shares site dc1 with data members')


def test_who_leads_on_its_own(ha_env):
    ha = ha_env.ha
    # the members at site 2 do not lead on their own: losing site 1 waits for Make leader
    found = {f['code']: f for f in ha.auto_findings(_layout('1122', '3', no_lead='cd'))}
    assert found['CANDIDATES_ONE_SITE']['site'] == 'dc1' and found['CANDIDATES_ONE_SITE']['level'] == 'warn'
    assert found['CANDIDATES_ONE_SITE']['text'] == ('Only members in dc1 lead on their own. Losing dc1 stops '
                                                    'automation until an admin uses "Make leader".')
    # a site whose loss stops automation anyway says that, and nothing about candidates
    assert 'CANDIDATES_ONE_SITE' not in {f['code'] for f in ha.auto_findings(_layout('112', no_lead='c'))}
    # nobody at all
    found = {f['code']: f for f in ha.auto_findings(_layout('111', no_lead='abc'))}
    assert found['NO_CANDIDATE']['level'] == 'warn' and 'Make leader' in found['NO_CANDIDATE']['text']
    assert 'NO_CANDIDATE' not in {f['code'] for f in ha.auto_findings(_layout('111', no_lead='bc'))}


def test_a_member_without_a_site_leaves_the_split_unchecked(ha_env):
    ha = ha_env.ha
    found = ha.auto_findings(_layout('1-2'))
    codes = {f['code'] for f in found if f['code'] in SITE_CODES}
    assert codes == {'NO_SITE_LABELS'}
    f = next(f for f in found if f['code'] == 'NO_SITE_LABELS')
    assert f['level'] == 'warn' and f['members'] == [IDS['b']]
    assert f['text'] == f"Set a site for each member to check split safety (no site yet: {URLS['b']})."
    # the witness is a vote as well
    f = next(f for f in ha.auto_findings(_layout('123', '-')) if f['code'] == 'NO_SITE_LABELS')
    assert f['members'] == [W_ID] and f'the witness {W_URL}' in f['text']


# --- split safety: the clusters (6.2, 6.3) ---------------------------------------------------------

class _Pve:
    """A Proxmox cluster with node HA, as its manager holds it in memory: the readers of
    the real manager on a config of the test's making."""
    from pegaprox.core.manager import PegaProxManager as _M
    FENCE_AGENT_VERSION = _M.FENCE_AGENT_VERSION
    CLAIM_WARNING, CLAIM_RESIDUAL = _M.CLAIM_WARNING, _M.CLAIM_RESIDUAL
    _ha_claim_enabled = _M._ha_claim_enabled
    _ha_claim_status = _M._ha_claim_status
    _ha_fencing = _M._ha_fencing
    _ha_fence_readable = _M._ha_fence_readable
    _ha_forces_quorum = _M._ha_forces_quorum
    _ha_unsafe_two_node = _M._ha_unsafe_two_node

    def __init__(self, nodes=('n1', 'n2', 'n3'), name='lab', **ha_config):
        self.ha_enabled = True
        self.config = types.SimpleNamespace(name=name)
        self.ha_config = dict(ha_config)
        self.ha_node_status = {n: {'status': 'online'} for n in nodes}


IPMI = {'type': 'ipmi', 'host': '10.0.0.9', 'user': 'ADMIN', 'password': 'pw'}
V2 = {'n1': 2, 'n2': 2, 'n3': 2}


def _clusters(monkeypatch, **mgrs):
    from pegaprox import globals as g
    for cid, mgr in mgrs.items():
        monkeypatch.setitem(g.cluster_managers, cid, mgr)


def _cluster_codes(ha, st):
    return {(f['code'], f.get('cluster')) for f in ha.auto_findings(st)
            if f['code'] in ('RECOVERY_NOT_READY', 'TWO_NODE_NO_FENCE', 'NO_CLAIM', 'FOREIGN_CLAIM',
                             'CLUSTER_ONE_SITE')}


def test_a_cluster_whose_nodes_neither_self_fence_nor_have_a_fence_is_not_ready(ha_env, monkeypatch):
    ha = ha_env.ha
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
    _clusters(monkeypatch,
              c1=_Pve(fence_agent_versions={'n1': 2, 'n2': 1}, fencing={'n3': IPMI}),
              c2=_Pve(fence_agent_versions={'n1': 2, 'n2': 2}, fencing={'n3': IPMI}),
              c3=_Pve(nodes=()))
    st = _layout('123')
    assert _cluster_codes(ha, st) == {('RECOVERY_NOT_READY', 'c1'), ('RECOVERY_NOT_READY', 'c3')}
    f = next(f for f in ha.auto_findings(st) if f.get('cluster') == 'c1')
    assert f == {'code': 'RECOVERY_NOT_READY', 'level': 'warn', 'member': None, 'cluster': 'c1', 'nodes': ['n2'],
                 'text': 'Cluster lab: node recovery needs agents v2 on every node or a verified IPMI fence.'}
    rows = {r['id']: r for r in ha.split_safety(st)['clusters']}
    assert rows['c1']['ready'] is False and rows['c1']['not_ready'] == ['n2']
    assert rows['c1']['agents'] == {'n1': 2, 'n2': 1, 'n3': 0} and rows['c1']['fence_verified'] == ['n3']
    assert rows['c1']['fence'] == {'n1': None, 'n2': None, 'n3': 'ipmi'} and rows['c1']['agent_version'] == 2
    assert rows['c2']['ready'] is True and rows['c3']['ready'] is None


def test_a_two_node_cluster_without_a_verified_fence_is_said_once(ha_env, monkeypatch):
    ha = ha_env.ha
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
    v2 = {'n1': 2, 'n2': 2}
    _clusters(monkeypatch,
              c1=_Pve(nodes=('n1', 'n2'), two_node_mode=True, fence_agent_versions=v2),
              c2=_Pve(nodes=('n1', 'n2'), two_node_mode=True, fence_agent_versions=v2,
                      fencing={'n1': IPMI, 'n2': dict(IPMI, host='10.0.0.8')}),
              c3=_Pve(nodes=('n1', 'n2'), two_node_mode=True, unsafe_two_node_recovery=True,
                      fence_agent_versions=v2),
              c4=_Pve(nodes=('n1', 'n2'), fencing={'n1': {'type': 'ssh', 'host': '10.0.0.7'}},
                      fence_agent_versions=v2),
              # two nodes and a qdevice: three votes, corosync says so
              c5=_Pve(nodes=('n1', 'n2'), fence_strategy={'expected_votes': 3, 'has_qdevice': True},
                      fence_agent_versions=v2))
    st = _layout('123')
    assert _cluster_codes(ha, st) == {('TWO_NODE_NO_FENCE', 'c1'), ('TWO_NODE_NO_FENCE', 'c4')}
    f = next(f for f in ha.auto_findings(st) if f.get('cluster') == 'c1')
    assert f['level'] == 'warn' and f['text'] == ('Two-node cluster lab has no verified hardware fence. '
                                                  'PegaProx will not recover it automatically.')
    rows = {r['id']: r for r in ha.split_safety(st)['clusters']}
    assert rows['c1']['two_node'] is True and rows['c3']['unsafe_two_node'] is True and rows['c4']['two_node']
    assert rows['c5']['two_node'] is False and rows['c5']['ready'] is True


def test_the_claim_of_a_cluster(ha_env, monkeypatch):
    ha = ha_env.ha
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
    _clusters(monkeypatch,
              c1=_Pve(claim_enabled=True, claim_state={'state': 'unreachable'}, fence_agent_versions=V2),
              c2=_Pve(claim_enabled=True, claim_state={'state': 'higher', 'instance': W_ID, 'epoch': 9},
                      fence_agent_versions=V2),
              c3=_Pve(claim_enabled=True, claim_state={'state': 'unreadable'}, fence_agent_versions=V2),
              c4=_Pve(claim_enabled=True, claim_state={'state': 'ours', 'instance': IDS['a'], 'epoch': 1},
                      fence_agent_versions=V2),
              c5=_Pve(fence_agent_versions=V2))
    st = _layout('123')
    assert _cluster_codes(ha, st) == {('NO_CLAIM', 'c1'), ('FOREIGN_CLAIM', 'c2'), ('FOREIGN_CLAIM', 'c3')}
    found = {f['cluster']: f for f in ha.auto_findings(st) if f.get('cluster')}
    assert found['c1']['text'] == 'Cluster lab has no SSH access, so it carries no leader claim.'
    assert found['c2']['level'] == 'block'
    assert found['c2']['text'] == ('Cluster lab is claimed by ffffffff at epoch 9. Nothing acts on it until the '
                                   'claim is released.')
    assert found['c3']['text'].startswith('Cluster lab carries a claim file that names no instance of this group.')
    rows = {r['id']: r for r in ha.split_safety(st)['clusters']}
    assert rows['c4']['claim']['state'] == 'ours' and rows['c4']['claim']['residual'] is None
    # off, the owner's default (Q9): no finding, and the residual the UI shows
    assert rows['c5']['claim'] == {'enabled': False, 'state': 'off', 'epoch': None, 'instance': None,
                                   'checked_at': None, 'residual': _Pve.CLAIM_RESIDUAL}
    assert ha.split_safety(st)['level'] == 'block'


def test_a_cluster_only_one_site_reaches(ha_env, monkeypatch):
    import time as _time
    ha = ha_env.ha
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
    _clusters(monkeypatch, c1=_Pve(fence_agent_versions=V2))
    st = _layout('112')
    rt = ha._rt()
    rt.reach = {'at': _time.monotonic(), 'clusters': {'c1': True}}
    rt.seen[IDS['b']] = {'at': _time.monotonic(), 'mark': ha.LEASE_MARK, 'reach': {'c1': True}}
    # c has not said: nothing to say
    assert _cluster_codes(ha, st) == set()
    rt.seen[IDS['c']] = {'at': _time.monotonic(), 'mark': ha.LEASE_MARK, 'reach': {'c1': False}}
    found = [f for f in ha.auto_findings(st) if f['code'] == 'CLUSTER_ONE_SITE']
    assert found == [{'code': 'CLUSTER_ONE_SITE', 'level': 'info', 'member': None, 'cluster': 'c1', 'site': 'dc1',
                      'text': 'Cluster lab is reachable only from members in site dc1.'}]
    row = ha.split_safety(st)['clusters'][0]
    assert row['reach'] == {IDS['a']: True, IDS['b']: True, IDS['c']: False} and row['reach_sites'] == ['dc1']


def test_a_cluster_of_another_kind_is_listed_and_checked_for_nothing(ha_env, monkeypatch):
    ha = ha_env.ha
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
    _clusters(monkeypatch, x1=types.SimpleNamespace(ha_enabled=True, config=types.SimpleNamespace(name='pool')),
              x2=types.SimpleNamespace(ha_enabled=False))
    st = _layout('123')
    rows = ha.split_safety(st)['clusters']
    assert [(r['id'], r['kind'], r['ready']) for r in rows] == [('x1', 'other', None)]
    assert _cluster_codes(ha, st) == set()


def test_a_foreign_claim_wants_a_tick_and_stops_nothing_else(auto, seed, monkeypatch):
    auto.pair(seed)
    _clusters(monkeypatch, c1=_Pve(fence_agent_versions=V2, claim_enabled=True,
                                   claim_state={'state': 'same', 'instance': W_ID, 'epoch': 1}))
    r = auto.switch_on(accept=[])
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_CONFIRM', r.data
    assert [f['code'] for f in r.get_json()['findings'] if f['level'] != 'info'] == ['FOREIGN_CLAIM']
    r = auto.switch_on(accept=['FOREIGN_CLAIM'])
    assert r.status_code == 200, r.data
    assert all(auto.mode(n) == 'auto' for n in 'abc')


# --- the switch and the panel read the same findings ---------------------------------------------

def test_the_switch_and_the_panel_read_the_same_findings(auto, seed):
    auto.pair(seed, 'bcd')
    auto.skew['c'] = 30
    auto.watch('a')

    r = auto.switch_on(accept=['EVEN_VOTERS'])

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_REFUSED', r.data
    said = r.get_json()['findings']
    panel = _status(auto)['split_safety']
    with auto.at('a') as ha:
        assert said == panel['findings'] == ha.auto_findings()
    assert panel['level'] == 'block' and {f['code'] for f in said} >= {'CLOCK_SKEW', 'EVEN_VOTERS'}
    assert (panel['voters'], panel['majority'], panel['tolerates']) == (4, 3, 1)
    assert [(s['site'], s['votes'], s['survives_loss']) for s in panel['sites']] == [
        ('dc-a', 1, True), ('dc-b', 1, True), ('dc-c', 1, True), ('dc-d', 1, True)]
    assert panel['unlabeled'] == [] and panel['clusters'] == []


def test_the_findings_of_a_group_that_runs_reach_the_panel(auto, seed):
    import time as _time
    _formed(auto, seed)
    assert _status(auto)['split_safety']['findings'] == []
    rt = auto.rt('a')
    rt.seen[IDS['b']] = dict(rt.seen[IDS['b']], mark=None, at=_time.monotonic())
    rt.seen[IDS['c']] = dict(rt.seen[IDS['c']], at=_time.monotonic() - auto.ha.LEASE_SEEN_FRESH - 1)
    found = {f['code']: f for f in _status(auto)['split_safety']['findings']}
    assert found['DOWNGRADED']['member'] == IDS['b'] and found['DOWNGRADED']['level'] == 'warn'
    assert found['VOTER_DOWN']['member'] == IDS['c'] and found['VOTER_DOWN']['level'] == 'warn'
    with auto.rt('a').lock:
        auto.node('a').change_cfg(lambda body: dict(body, quarantined=[IDS['b']]))
    auto.run(3 * T.R, dt=0.5, members='a')
    found = {f['code']: f for f in _status(auto)['split_safety']['findings']}
    assert found['QUARANTINED']['member'] == IDS['b'] and found['QUARANTINED']['level'] == 'warn'
    # b leads on its own no more while it is quarantined
    assert [s['candidates'] for s in _status(auto)['split_safety']['sites'] if s['site'] == 'dc-b'] == [[]]


def test_a_quarantined_vote_counts_for_no_loss_the_group_survives(auto, seed):
    """Four votes, three needed, d quarantined: a, b and c are all needed. Losing any of
    their sites stops automation, losing d's does not."""
    _quarantined_d(auto, seed)

    split = _status(auto)['split_safety']

    assert (split['voters'], split['majority'], split['tolerates']) == (4, 3, 0)
    assert {s['site']: s['survives_loss'] for s in split['sites']} == {
        'dc-a': False, 'dc-b': False, 'dc-c': False, 'dc-d': True}
    assert sorted(f['site'] for f in split['findings'] if f['code'] == 'SITE_HOLDS_MAJORITY') == ['dc-a', 'dc-b', 'dc-c']
    # all at one site, the loss of no member is survived
    with auto.at('a') as ha:
        for n in 'abcd':
            ha.set_member_site(IDS[n], 'dc1')
    found = {f['code']: f for f in _status(auto)['split_safety']['findings']}
    assert found['ALL_ONE_SITE']['text'] == ('Survives the loss of no member. A site outage stops PegaProx '
                                             'automation until the site is back.')


def test_the_level_of_the_panel_is_the_one_the_switch_goes_by(auto, seed, monkeypatch):
    """A claim of another instance on one cluster is a block of that cluster: the switch
    wants a tick for it, and the panel says warnings, not blocked."""
    auto.pair(seed)
    _clusters(monkeypatch, c1=_Pve(fence_agent_versions=V2, claim_enabled=True,
                                   claim_state={'state': 'same', 'instance': W_ID, 'epoch': 1}))

    split = _status(auto)['split_safety']

    assert [f['level'] for f in split['findings'] if f['code'] == 'FOREIGN_CLAIM'] == ['block']
    assert split['level'] == 'warn', split['findings']
    assert auto.switch_on(accept=['FOREIGN_CLAIM']).status_code == 200
    # a block that names no cluster is one for both (too_few, test_the_findings_before_the_switch_reach_the_panel)
    with auto.at('a') as ha:
        assert ha._gate({'level': 'block'}) == 'block' and ha._gate({'level': 'block', 'cluster': 'c1'}) == 'warn'


def test_a_finding_that_starts_with_an_address_keeps_it_as_it_is(auto, seed):
    """The server's words go into the panel as they are: an address or a short id that
    starts a sentence is not capitalised; the witness is "The witness ..."."""
    import time as _time
    auto.pair(seed)
    with auto.at('a') as ha:
        st = ha._load()
        ha._commit_locked(dict(st, witness={'instance_id': W_ID, 'url': W_URL, 'fingerprint': '',
                                            'public_key': _key(), 'site': 'dc-w'},
                               members=dict(st['members'], **{IDS['c']: dict(st['members'][IDS['c']], url='')})))
    rt = auto.rt('a')
    old = _time.monotonic() - auto.ha.LEASE_SEEN_FRESH - 1
    for n in 'bc':
        rt.seen[IDS[n]] = dict(rt.seen[IDS[n]], at=old)

    texts = {f['member']: f['text'] for f in _status(auto)['split_safety']['findings'] if f['code'] == 'VOTER_DOWN'}

    assert texts[IDS['b']].startswith(f"{URLS['b']} has not answered within the last"), texts[IDS['b']]
    assert texts[IDS['c']].startswith(f"{IDS['c'][:8]} has not answered"), texts[IDS['c']]
    assert texts[W_ID].startswith(f'The witness {W_URL} has not answered'), texts[W_ID]


@pytest.mark.parametrize('case', ['too_few', 'old_release', 'zone'])
def test_the_findings_before_the_switch_reach_the_panel(auto, seed, case):
    if case == 'too_few':
        auto.pair(seed, 'b')
    else:
        auto.pair(seed)
    rt = auto.rt('a')
    if case == 'old_release':
        rt.seen[IDS['b']] = dict(rt.seen[IDS['b']], mark=None)
    elif case == 'zone':
        rt.seen[IDS['b']] = dict(rt.seen[IDS['b']], zone='America/New_York')
    panel = _status(auto)['split_safety']
    found = {f['code']: f for f in panel['findings']}
    code, level = {'too_few': ('TOO_FEW_VOTERS', 'block'), 'old_release': ('OLD_RELEASE', 'block'),
                   'zone': ('TZ_MISMATCH', 'info')}[case]
    assert found[code]['level'] == level and panel['level'] == level
    if case == 'zone':
        assert found[code] == {'code': 'TZ_MISMATCH', 'level': 'info', 'member': IDS['b'],
                               'text': f"{URLS['b']} runs in time zone America/New_York. The group's schedules "
                                       'run in Europe/Vienna whichever member leads.'}
        # something to know: the switch goes through without a tick
        assert auto.switch_on(accept=[]).status_code == 200


def test_split_safety_is_none_alone_and_before_this_release_offers_it(auto, seed, monkeypatch):
    with auto.at('e') as ha:
        assert ha.public_status()['split_safety'] is None
    auto.pair(seed)
    assert _status(auto)['split_safety']['level'] == 'ok'
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    assert _status(auto)['split_safety'] is None and _status(auto)['auto'] is None


# --- the banners, for every signed-in user --------------------------------------------------------

STANDBY_BANNER = {'role', 'peer_url', 'last_sync_at', 'removed', 'live_view', 'forwarding', 'serving',
                  'leader_reachable'}


def _banner(auto, n, client):
    with auto.at(n):
        r = client.get('/api/auth/check')
    assert r.status_code == 200, r.data
    return r.get_json()['ha']


def _viewer(auto, seed):
    return auto.g.api.as_user(seed.user('watcher', role='viewer'))


def _handed_to_b(auto, seed):
    from test_ha_make_leader import _make
    _formed(auto, seed)
    epoch = auto.state('a')['epoch']
    r = _make(auto, 'a', 'b')
    assert r.status_code == 200 and r.get_json()['result'] == 'handed', r.data
    return epoch


def test_a_manual_group_and_an_instance_of_its_own_get_the_banner_they_had(auto, seed):
    viewer = _viewer(auto, seed)
    assert _banner(auto, 'e', viewer) == {'role': 'standalone'}
    auto.pair(seed)
    assert _banner(auto, 'a', viewer) == {'role': 'active'}
    assert set(_banner(auto, 'b', viewer)) == STANDBY_BANNER


def test_all_is_well_in_an_automatic_group(auto, seed):
    _formed(auto, seed)
    viewer = _viewer(auto, seed)
    assert _banner(auto, 'a', viewer) == {'role': 'active', 'automatic': True}
    b = _banner(auto, 'b', viewer)
    assert set(b) == STANDBY_BANNER | {'automatic'} and b['automatic'] is True


def test_no_leader_on_a_leader_without_its_lease_and_on_a_member_without_a_promise(auto, seed):
    _formed(auto, seed)
    viewer = _viewer(auto, seed)
    left = auto.node('b').promise_until - auto.clock['b']
    assert left > auto.node('a').lease_until - auto.clock['a']
    # nobody ticks: the lease of a runs out, the promise of b a moment later
    auto.advance(left - 0.5)
    assert _banner(auto, 'a', viewer) == {'role': 'active', 'automatic': True, 'no_leader': True}
    assert 'no_leader' not in _banner(auto, 'b', viewer)
    auto.advance(1)
    b = _banner(auto, 'b', viewer)
    assert b['no_leader'] is True and 'takeover' not in b
    # a page that asked carries nothing a viewer should not see: no ids, no epochs of a lease
    assert set(b) == STANDBY_BANNER | {'automatic', 'no_leader'}


def test_a_takeover_and_the_change_of_the_leader_reach_every_user(auto, seed):
    epoch = _handed_to_b(auto, seed)
    viewer = _viewer(auto, seed)
    auto.run(T.W_take + 10, until=lambda: 'b' in auto.holders())
    assert 'b' in auto.holders() and auto.leader() != 'b'          # it holds, and waits to act

    seen = {n: _banner(auto, n, viewer) for n in 'bc'}
    named = {n: _banner(auto, n, auto.admin) for n in 'bc'}

    for n in 'bc':
        # every user hears when changes resume and when the leader changed; the addresses
        # go to an admin the HA tab is open to, the epoch of the lease to nobody
        assert set(seen[n]['takeover']) == {'resume_in'}, (n, seen[n])
        assert 1 <= seen[n]['takeover']['resume_in'] <= T.W_take + 1, (n, seen[n])
        assert 'no_leader' not in seen[n]
        assert set(seen[n]['leader_changed']) == {'at'}, (n, seen[n])
        assert named[n]['takeover']['leader'] == URLS['b'] and set(named[n]['takeover']) == {'leader', 'resume_in'}
        assert named[n]['leader_changed'] == {'to': URLS['b'], 'from': URLS['a'], 'at': seen[n]['leader_changed']['at']}
    at = seen['b']['leader_changed']['at']
    # the moment the leader sent along: one for every member
    assert seen['c']['leader_changed']['at'] == at
    renewals = [json.loads(body) for frm, _to, _m, path, body, _h in auto.g.sent
                if frm == 'b' and path == '/api/ha/peer/renew' and body]
    assert renewals and all(r.get('leader_since') == at for r in renewals)
    auto.run(T.W_take + 10, until=lambda: auto.leader() == 'b')
    assert auto.leader() == 'b'
    for n in 'abc':
        ha_banner = _banner(auto, n, viewer)
        assert 'takeover' not in ha_banner and 'no_leader' not in ha_banner, (n, ha_banner)
        assert ha_banner['leader_changed']['at'] == at, n
    with auto.at('c') as ha:
        st = ha.lease_status()
    assert st['leader_change'] == {'from': IDS['a'], 'from_url': URLS['a'], 'to': IDS['b'], 'to_url': URLS['b'],
                                   'epoch': epoch + 1, 'at': at}


@pytest.mark.parametrize('kind', ['capped_admin', 'tenant_admin', 'capped_default_admin', 'user_with_ha'])
def test_the_addresses_go_to_no_account_the_ha_tab_is_closed_to(auto, seed, kind):
    """The accounts the HA routes refuse (test_below_an_unconfined_admin_the_member_routes_change_nothing)."""
    _handed_to_b(auto, seed)
    api = auto.g.api
    if kind == 'capped_admin':
        seed.tenant('globex', ['cluster_globex'])
        c = api.as_user(seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={'globex': {'role': 'user'}}))
    elif kind == 'tenant_admin':
        seed.tenant('initech', ['cluster_initech'])
        c = _admin(api, seed, 'ini', role='user', tenant_id='initech', tenant_permissions={'initech': {'role': 'admin'}})
    elif kind == 'capped_default_admin':
        c = _admin(api, seed, 'lowered', tenant_id='default', tenant_permissions={'default': {'role': 'viewer'}})
    else:
        c = api.as_user(seed.user('ops', role='user', permissions=['ha.view', 'ha.config', 'admin.settings']))
    auto.run(T.W_take + 10, until=lambda: 'b' in auto.holders())

    got = _banner(auto, 'c', c)

    assert got['automatic'] is True and set(got['takeover']) == {'resume_in'}, got
    assert set(got['leader_changed']) == {'at'}, got
    assert set(_banner(auto, 'c', auto.admin)['leader_changed']) == {'to', 'from', 'at'}


def test_the_change_of_the_leader_shows_for_ten_minutes(auto, seed):
    _handed_to_b(auto, seed)
    viewer = _viewer(auto, seed)
    auto.run(2 * T.W_take + 10, until=lambda: auto.leader() == 'b')
    assert 'leader_changed' in _banner(auto, 'c', viewer)
    with auto.at('c') as ha:
        st = ha._load()
        old = (datetime.now(timezone.utc) - timedelta(seconds=ha.LEADER_CHANGED_SHOWN + 1)).replace(microsecond=0)
        ha._commit_locked(dict(st, leader_seen=dict(st['leader_seen'], since=old.isoformat())))
    assert 'leader_changed' not in _banner(auto, 'c', viewer)
    with auto.at('c') as ha:
        assert ha.lease_status()['leader_change']['at'] == old.isoformat()


def test_a_member_takes_no_moment_from_the_future(auto, seed):
    with auto.at('c') as ha:
        later = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        st = {'leader_seen': {'id': IDS['a'], 'epoch': 3, 'from': None, 'since': None}}
        seen = ha._leader_seen_after(st, IDS['b'], 4, since=later)
    assert seen['id'] == IDS['b'] and seen['from'] == IDS['a'] and seen['since'] != later
    # one from the past is the leader's word, taken as it is
    earlier = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(microsecond=0).isoformat()
    assert ha._leader_seen_after(st, IDS['b'], 4, since=earlier)['since'] == earlier
    # an older term says nothing, the same leader re-elected only moves the epoch
    assert ha._leader_seen_after(st, IDS['b'], 2) is None
    assert ha._leader_seen_after(st, IDS['a'], 5) == {'id': IDS['a'], 'epoch': 5, 'from': None, 'since': None}


# --- the status line ---------------------------------------------------------------------------------

def test_the_status_line_on_the_leader(auto, seed):
    from test_ha_make_leader import _step_cv
    _formed(auto, seed)
    with auto.at('a') as ha:
        st = ha.lease_status()
    assert 0 <= st['renewed_ago'] <= T.R + T.renew_timeout
    assert (st['leader_change'], st['unconfirmed'], st['promise'], st['change_pending']) == (None, None, None, False)
    cv = list(auto.node('a').cv)
    for row in st['members']:
        assert row['promised_to'] == IDS['a'] and 0 < row['promised_left'] <= T.P, row
        assert (row['cv'], row['behind'], row['current'], row['unreached_from']) == (cv, 0, True, []), row

    _step_cv(auto)
    auto.run(T.R + 0.5, dt=0.5, members='a')

    with auto.at('a') as ha:
        st = ha.lease_status()
    new = list(auto.node('a').cv)
    assert new == [cv[0], cv[1] + 1]
    assert st['unconfirmed'] == {'count': 1, 'cv': new, 'floor': cv}
    assert all((row['cv'], row['behind'], row['current']) == (cv, 1, False) for row in st['members'])
    for n in 'bc':
        assert _sync(auto.g, auto.admin, n) == 'applied'
    auto.run(T.R + 0.5, dt=0.5, members='a')
    with auto.at('a') as ha:
        st = ha.lease_status()
    assert st['unconfirmed'] is None and all(row['behind'] == 0 for row in st['members'])


def test_the_status_line_on_a_member(auto, seed):
    from test_ha_make_leader import _step_cv
    _formed(auto, seed)
    _step_cv(auto)
    auto.run(T.R + 0.5, dt=0.5, members='a')
    with auto.at('b') as ha:
        st = ha.lease_status()
    assert st['holder'] == IDS['a'] and st['promise']['to'] == IDS['a'] and st['promise']['to_url'] == URLS['a']
    assert 0 < st['promise']['left'] <= T.P and 0 <= st['renewed_ago'] <= T.R + 1
    assert st['leader_cv'] == list(auto.node('a').cv) and st['behind'] == 1 and st['unconfirmed'] is None
    rows = {m['instance_id']: m for m in st['members']}
    assert (rows[IDS['a']]['cv'], rows[IDS['a']]['behind']) == (st['leader_cv'], 0)
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    with auto.at('b') as ha:
        assert ha.lease_status()['behind'] == 0


def test_the_nodes_that_cannot_reach_a_member(auto, seed, monkeypatch):
    _formed(auto, seed)
    _clusters(monkeypatch, c1=_Pve(nodes=('n1', 'n2'), two_node_mode=True, fence_agent_versions={'n1': 2, 'n2': 2},
                                   fencing={'n1': IPMI, 'n2': dict(IPMI, host='10.0.0.8')},
                                   agent_unreachable={'at': '2026-10-04T10:00:00',
                                                      'nodes': {'n1': [URLS['b']], 'n2': [URLS['b'], URLS['c']]}}))
    st = _status(auto)
    rows = {m['instance_id']: m for m in st['auto']['members']}
    assert rows[IDS['b']]['unreached_from'] == [{'cluster': 'c1', 'name': 'lab', 'node': 'n1'},
                                                {'cluster': 'c1', 'name': 'lab', 'node': 'n2'}]
    assert rows[IDS['c']]['unreached_from'] == [{'cluster': 'c1', 'name': 'lab', 'node': 'n2'}]
    row = st['split_safety']['clusters'][0]
    assert row['unreachable_from'] == {IDS['b']: ['n1', 'n2'], IDS['c']: ['n2']}
    assert row['unreachable_checked_at'] == '2026-10-04T10:00:00' and row['ready'] is True
    assert st['split_safety']['findings'] == []


def test_the_agent_check_keeps_who_each_node_could_not_reach(monkeypatch):
    from test_ha_agent_script import _mgr
    m = _mgr(fence_strategy={'strategy': 'quorum', 'expected_votes': 2, 'two_node_flag': True,
                             'detection_reason': 'detected'})
    out = ('FENCE_VERSION=2\nFENCE_MODE=tiebreak\nFENCE_SHA=\nFENCE_ACTIVE=active\nSHARED=none\n'
           'SHARED_ACTIVE=inactive\n')
    answers = {'10.9.0.1': out + f"MEMBER {URLS['a']} 400\nMEMBER {URLS['b']} 000\nAGENT_CHECK_DONE\n",
               '10.9.0.2': out + f"MEMBER {URLS['a']} 400\nMEMBER {URLS['b']} 400\nAGENT_CHECK_DONE\n",
               '10.9.0.3': None}
    monkeypatch.setattr(m, '_ha_node_ip_map', lambda: {f'pve{i}': f'10.9.0.{i}' for i in (1, 2, 3)}, raising=False)
    monkeypatch.setattr(m, '_ha_agent_members', lambda: [URLS['a'], URLS['b']], raising=False)
    monkeypatch.setattr(m, '_ha_agent_ssh', lambda ip, cmd, **kw: answers[ip], raising=False)

    report = m._ha_check_agents()

    assert report['nodes']['pve1']['members_unreachable'] == [URLS['b']]
    seen = m.ha_config['agent_unreachable']
    assert seen['nodes'] == {'pve1': [URLS['b']]} and datetime.fromisoformat(seen['at'])


# --- votes that count: a quarantined member votes on paper only ---------------------------------

def _quarantined_d(auto, seed):
    _formed(auto, seed, 'bcd', accept=['EVEN_VOTERS'])
    auto.watch('a')
    with auto.rt('a').lock:
        auto.node('a').change_cfg(lambda body: dict(body, quarantined=[IDS['d']]))
    auto.run(3 * T.R, dt=0.5)
    view = auto.node('a').view
    assert view.n == 4 and view.m == 3 and len(view.counting) == 3


def test_neither_a_removal_nor_a_leave_takes_the_votes_that_count_below_three(auto, seed):
    """Four voters, d quarantined: a, b and c count. Taking b out, or c leaving through the
    leader, would leave two votes that count - refused as the vote switch refuses it."""
    _quarantined_d(auto, seed)

    r = auto.post('a', f"/api/ha/members/{IDS['b']}/remove", {'confirm': 'REMOVE', 'user_password': ADMIN_PW})

    assert r.status_code == 409 and 'quarantined' in r.get_json()['error'], r.data
    assert len(auto.node('a').view.counting) == 3

    r = auto.post('c', '/api/ha/unpair', {'confirm': 'UNPAIR', 'user_password': ADMIN_PW})

    assert r.status_code == 409, r.data
    assert auto.state('c')['role'] == 'standby' and len(auto.node('a').view.counting) == 3


def test_the_quarantined_member_itself_may_still_go(auto, seed):
    _quarantined_d(auto, seed)

    r = auto.post('a', f"/api/ha/members/{IDS['d']}/remove", {'confirm': 'REMOVE', 'user_password': ADMIN_PW})

    assert r.status_code == 200, r.data
    auto.run(3 * T.R, dt=0.5)
    assert auto.node('a').view.n == 3 and len(auto.node('a').view.counting) == 3


def test_the_even_voters_text_goes_by_the_votes_that_count(auto, seed):
    """The panel's header says what the group survives with d quarantined; the finding
    under it says the same."""
    _quarantined_d(auto, seed)
    split = _status(auto)['split_safety']
    even = next(f for f in split['findings'] if f['code'] == 'EVEN_VOTERS')
    assert split['tolerates'] == 0 and 'survive the loss of no member,' in even['text'], even['text']


def test_a_vote_change_whose_member_record_failed_is_done_and_audited(auto, seed, monkeypatch):
    """The voter config took the change; writing the member record after it failed. The
    change is in force, so the answer says so and the audit row is written."""
    _formed(auto, seed, 'bcd', accept=['EVEN_VOTERS'])

    def full(member_id, asked):
        raise OSError('No space left on device')
    monkeypatch.setattr(auto.ha, '_vote_marks', full)

    r = _vote(auto, 'a', 'd', voter=False)

    assert r.status_code == 200 and r.get_json()['changed'] is True, r.data
    assert auto.node('a').view.n == 3
    assert any(IDS['d'][:8] in (row['details'] or '') or 'vote off' in (row['details'] or '')
               for row in _audit('ha.member_vote_changed'))


def test_a_vm_id_for_a_cluster_no_longer_managed_can_be_removed(auto, seed, monkeypatch):
    """The cluster was deleted from PegaProx since: forgetting the VM there needs no
    managed cluster, setting one does."""
    from pegaprox import globals as g
    import pegaprox.api.ha as ha_api
    from test_ha_members import _fresh_windows
    _formed(auto, seed)
    _clusters(monkeypatch, c1=_Pve(name='lab', fence_agent_versions=V2))
    _fresh_windows(ha_api)
    with auto.at('a'):
        r = auto.admin.put(f"/api/ha/members/{IDS['b']}/agent-vmid", json={'cluster_id': 'c1', 'vmid': 104})
    assert r.status_code == 200, r.data
    monkeypatch.delitem(g.cluster_managers, 'c1')
    _fresh_windows(ha_api)
    with auto.at('a'):
        again = auto.admin.put(f"/api/ha/members/{IDS['b']}/agent-vmid", json={'cluster_id': 'c1', 'vmid': 105})
        r = auto.admin.put(f"/api/ha/members/{IDS['b']}/agent-vmid", json={'cluster_id': 'c1', 'vmid': None})

    assert again.status_code == 404
    assert r.status_code == 200, r.data
    held = next(m for m in _status(auto)['auto']['members'] if m['instance_id'] == IDS['b'])['agent_vmid']
    assert held == {}
