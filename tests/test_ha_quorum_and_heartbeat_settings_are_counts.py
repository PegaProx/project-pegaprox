"""The quorum vote count and the storage heartbeat timeout of the HA settings are
numbers the checks can count with, or the save is refused.

The config route stored quorum_required_votes and storage_heartbeat_timeout as they
were sent. _ha_check_quorum counts the quorum hosts that answer plus its own vote
against the first: 0 or true was quorate with every host down, and a string or null
raised in the check. A heartbeat is alive while it is younger than the second: 0 or
a negative read every node as having none, a string raised. Now the route refuses
such a value before anything of the request is applied, and quorum_hosts has to be
a list of strings.

A row stored before that is cleaned when the manager is built: the HA form sends
back what the status gave it, so a bad stored value would have every later save
refused.

MK Oct 2026
"""
import os
import time

import pytest

from test_ha_api import ha_env, _admin  # noqa: F401
from test_ha_node_safety import URL, _mgr, _stored, _sbp, cluster  # noqa: F401

# what the HA form sends on every save (dashboard.js)
FORM = {'quorum_enabled': True, 'quorum_hosts': [], 'quorum_gateway': '', 'quorum_required_votes': 2,
        'self_fence_enabled': True, 'verify_network': True, 'recovery_delay': 30, 'failure_threshold': 3,
        'two_node_mode': False, 'force_quorum_on_failure': False, 'storage_heartbeat_enabled': False,
        'storage_heartbeat_path': '', 'storage_heartbeat_timeout': 30, 'poison_pill_enabled': True,
        'strict_fencing': False, 'pegaprox_vmid': ''}


def _no_host_answers(m, monkeypatch, hosts=('192.0.2.1', '192.0.2.2')):
    monkeypatch.setattr(m, '_ha_ping_host', lambda host, timeout=3: False, raising=False)
    m.ha_config['quorum_hosts'] = list(hosts)
    m.ha_config['quorum_gateway'] = ''


def _untouched(env):
    m = env.mgr
    assert m.ha_config['quorum_required_votes'] == 2
    assert m.ha_config['storage_heartbeat_timeout'] == 30
    assert m.ha_config['quorum_hosts'] == []
    assert m.ha_config['two_node_mode'] is False and m.ha_config['recovery_delay'] == 30
    stored = _stored(env)
    assert not {'quorum_required_votes', 'storage_heartbeat_timeout', 'quorum_hosts'} & set(stored)


# --- the vote count ----------------------------------------------------------------------------------

@pytest.mark.parametrize('votes', [0, -5, True, False, 'abc', '2', None, 2.0, [2], {}, 65, 10 ** 12])
def test_a_vote_count_that_is_no_count_is_refused_and_nothing_is_applied(cluster, monkeypatch, votes):
    m = cluster.mgr
    r = cluster.client.put(URL, json={'quorum_required_votes': votes, 'two_node_mode': True,
                                      'recovery_delay': 45})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'HA_QUORUM_INVALID'
    _untouched(cluster)
    # what this is about: with no quorum host answering there is no quorum
    _no_host_answers(m, monkeypatch)
    assert m._ha_check_quorum() is False


@pytest.mark.parametrize('votes', [1, 2, 3, 64])
def test_a_vote_count_from_one_to_64_is_taken(cluster, monkeypatch, votes):
    """The counterproof: a count the check can use is stored and counted with."""
    m = cluster.mgr
    r = cluster.client.put(URL, json={'quorum_required_votes': votes})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert m.ha_config['quorum_required_votes'] == votes and _stored(cluster)['quorum_required_votes'] == votes
    _no_host_answers(m, monkeypatch)
    assert m._ha_check_quorum() is (votes == 1)     # only our own vote
    monkeypatch.setattr(m, '_ha_ping_host', lambda host, timeout=3: True)
    assert m._ha_check_quorum() is (votes <= 3)     # two hosts and us


@pytest.mark.parametrize('hosts', ['10.0.0.1', None, {'a': '10.0.0.1'}, 5, ['10.0.0.1', 5], [None], [['x']]])
def test_quorum_hosts_that_are_no_list_of_names_are_refused(cluster, hosts):
    r = cluster.client.put(URL, json={'quorum_hosts': hosts, 'two_node_mode': True})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'HA_QUORUM_INVALID'
    _untouched(cluster)


@pytest.mark.parametrize('hosts', [[], ['10.0.0.1'], ['10.0.0.1', 'quorum.lab.example']])
def test_a_list_of_quorum_hosts_is_taken(cluster, hosts):
    r = cluster.client.put(URL, json={'quorum_hosts': hosts})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert cluster.mgr.ha_config['quorum_hosts'] == hosts and _stored(cluster)['quorum_hosts'] == hosts


# --- the heartbeat timeout ---------------------------------------------------------------------------

def _fresh_heartbeat(m, tmp_path, node='pve2'):
    beat = tmp_path / '.pegaprox' / f'heartbeat_node_{node}'
    beat.parent.mkdir(parents=True, exist_ok=True)
    beat.write_text('')
    os.utime(beat, (time.time() - 5, time.time() - 5))
    m.ha_config['storage_heartbeat_path'] = str(tmp_path)


@pytest.mark.parametrize('timeout', [0, -1, -30, True, False, '30', None, [30], {}])
def test_a_heartbeat_timeout_that_is_no_positive_number_is_refused(cluster, tmp_path, timeout):
    m = cluster.mgr
    _fresh_heartbeat(m, tmp_path)
    r = cluster.client.put(URL, json={'storage_heartbeat_timeout': timeout, 'two_node_mode': True})

    assert r.status_code == 400, r.get_data(as_text=True)
    body = r.get_json()
    assert body['code'] == 'HA_TIMING_INVALID' and 'must be a number' in body['error']
    _untouched(cluster)
    # a node that wrote its heartbeat five seconds ago is alive
    assert m._ha_check_storage_heartbeat('pve2')['alive'] is True
    assert m._ha_check_node_agent_heartbeat('pve2')['alive'] is True


@pytest.mark.parametrize('raw', ['{"storage_heartbeat_timeout": NaN}', '{"storage_heartbeat_timeout": Infinity}',
                                 '{"storage_heartbeat_timeout": -Infinity}'])
def test_a_heartbeat_timeout_that_cannot_be_counted_with_is_refused_too(cluster, raw):
    r = cluster.client.put(URL, data=raw, content_type='application/json')

    assert r.status_code == 400 and r.get_json()['code'] == 'HA_TIMING_INVALID', r.get_data(as_text=True)
    assert cluster.mgr.ha_config['storage_heartbeat_timeout'] == 30


@pytest.mark.parametrize('timeout', [1, 5, 30, 45.5, 600])
def test_a_positive_heartbeat_timeout_is_taken(cluster, tmp_path, timeout):
    """The counterproof: the timeout is stored and the heartbeat is judged by it."""
    m = cluster.mgr
    _fresh_heartbeat(m, tmp_path)
    r = cluster.client.put(URL, json={'storage_heartbeat_timeout': timeout})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert m.ha_config['storage_heartbeat_timeout'] == timeout
    assert _stored(cluster)['storage_heartbeat_timeout'] == timeout
    assert m._ha_check_storage_heartbeat('pve2')['alive'] is (timeout > 5)


def test_what_the_form_sends_is_taken_as_before(cluster):
    r = cluster.client.put(URL, json=FORM)

    assert r.status_code == 200, r.get_data(as_text=True)
    stored = _stored(cluster)
    assert (stored['quorum_required_votes'], stored['storage_heartbeat_timeout'], stored['quorum_hosts']) == (2, 30, [])


# --- what was stored before --------------------------------------------------------------------------

@pytest.mark.parametrize('stored,votes,timeout', [
    ({'quorum_required_votes': 0, 'storage_heartbeat_timeout': 0}, 2, 30),
    ({'quorum_required_votes': -5, 'storage_heartbeat_timeout': -5}, 2, 30),
    ({'quorum_required_votes': True, 'storage_heartbeat_timeout': True}, 2, 30),
    ({'quorum_required_votes': 'abc', 'storage_heartbeat_timeout': '30'}, 2, 30),
    ({'quorum_required_votes': None, 'storage_heartbeat_timeout': None}, 2, 30),
    ({'quorum_required_votes': [1], 'storage_heartbeat_timeout': [30]}, 2, 30),
    ({'quorum_required_votes': 10 ** 12, 'storage_heartbeat_timeout': float('nan')}, 2, 30),
    ({'quorum_required_votes': 1, 'storage_heartbeat_timeout': 5}, 1, 5),          # what was valid stays
    ({'quorum_required_votes': 64, 'storage_heartbeat_timeout': 45.5}, 64, 45.5),
    ({}, 2, 30),
])
def test_a_stored_vote_count_or_timeout_that_is_no_number_is_not_brought_back(monkeypatch, stored, votes, timeout):
    m = _mgr()
    del m.ha_config

    m._apply_ha_settings(stored)

    assert m.ha_config['quorum_required_votes'] == votes
    assert m.ha_config['storage_heartbeat_timeout'] == timeout
    assert type(m.ha_config['quorum_required_votes']) is int
    _no_host_answers(m, monkeypatch)
    assert m._ha_check_quorum() is (votes == 1)


@pytest.mark.parametrize('bad', [{'quorum_required_votes': -5}, {'quorum_required_votes': 100},
                                 {'storage_heartbeat_timeout': -5}])
def test_a_bad_stored_value_does_not_block_the_next_save(cluster, bad):
    """The form fills in parseInt(value) || default from the status: -5 or 100 came
    back as they were and, refused now, every later save would have failed."""
    cluster.mgr._apply_ha_settings(bad)
    sbp = _sbp(cluster)
    assert (sbp['quorum_required_votes'], sbp['storage_heartbeat_timeout']) == (2, 30)

    sent = dict(FORM, quorum_required_votes=int(sbp['quorum_required_votes']) or 2,
                storage_heartbeat_timeout=int(sbp['storage_heartbeat_timeout']) or 30)
    r = cluster.client.put(URL, json=sent)

    assert r.status_code == 200, r.get_data(as_text=True)
    assert (_stored(cluster)['quorum_required_votes'], _stored(cluster)['storage_heartbeat_timeout']) == (2, 30)
