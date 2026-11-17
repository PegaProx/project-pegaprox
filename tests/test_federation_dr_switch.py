"""The disaster recovery of the federation is a switch of its own, off by default.

Enrolled clusters, leases, adoption and takeover run only while it is on. Off, the lease
worker and the record pushes do nothing, the write gate lets a cluster no federation owns
pass without asking for a lease (and keeps refusing a row a federation still owns), the
routes of the disaster recovery answer 409 FED_DR_OFF, and a cluster is enrolled only
while every site says its disaster recovery is on. Every check here has its counterproof
with the switch on.

MK Nov 2026
"""
import pytest

from pegaprox.core import federation
from pegaprox.core import federation_lease as fl
from tests.test_federation import (  # noqa: F401 - fixtures by name
    Side, URL, _add_cluster, _db_of, _defaults_out_of_the_config_dir, _fresh_budgets,
    _post, _sides, _wire, at, iid)


@pytest.fixture
def dr_setting(monkeypatch):
    """The disaster recovery left to the setting of each side (the federation stays on)."""
    monkeypatch.delenv(federation.DR_ENV_SWITCH, raising=False)


def _set_dr(side, value):
    with at(side):
        _db_of(side).save_server_setting(federation.DR_SETTING_KEY, value)
        federation._runtime.pop('dr', None)


class _Tripwire:
    def __init__(self, result=None):
        self.calls, self.result = [], result

    def __call__(self, *a, **kw):
        self.calls.append((a, kw))
        return self.result


# --- the switch ------------------------------------------------------------------------

def test_disaster_recovery_is_off_until_switched_on(tmp_path, dr_setting):
    a = Side(tmp_path, 'a')
    with at(a):
        assert federation.enabled() is True
        assert federation.dr_enabled() is False
    _set_dr(a, True)
    with at(a):
        assert federation.dr_enabled() is True


def test_disaster_recovery_is_off_while_the_federation_is(tmp_path, monkeypatch):
    a = Side(tmp_path, 'a')
    monkeypatch.setenv(federation.ENV_SWITCH, '0')
    with at(a):
        assert federation.dr_enabled() is False
    monkeypatch.setenv(federation.ENV_SWITCH, '1')
    with at(a):
        assert federation.dr_enabled() is True        # the environment of the harness


def test_the_environment_forces_it(tmp_path, dr_setting, monkeypatch):
    a = Side(tmp_path, 'a')
    _set_dr(a, True)
    monkeypatch.setenv(federation.DR_ENV_SWITCH, '0')
    with at(a):
        assert federation.dr_enabled() is False
        with pytest.raises(federation.FederationError) as e:
            federation.set_dr_enabled(True)
        assert e.value.code == 'FED_FORCED'
    monkeypatch.setenv(federation.DR_ENV_SWITCH, 'yes')
    with at(a):
        assert federation.dr_enabled() is True        # an odd value leaves it to the setting


def test_it_does_not_switch_on_without_the_federation(tmp_path, dr_setting, monkeypatch):
    a = Side(tmp_path, 'a')
    monkeypatch.setenv(federation.ENV_SWITCH, '0')
    with at(a):
        with pytest.raises(federation.FederationError) as e:
            federation.set_dr_enabled(True)
        assert e.value.code == 'FED_DISABLED'
        assert _db_of(a).get_server_setting(federation.DR_SETTING_KEY, 'unset') == 'unset'


def test_it_does_not_switch_off_while_a_cluster_is_enrolled(tmp_path, dr_setting):
    a = Side(tmp_path, 'a')
    _set_dr(a, True)
    with at(a):
        me = federation.ensure_identity()
    _add_cluster(a, 'c1', owner=me)
    with at(a):
        with pytest.raises(federation.FederationError) as e:
            federation.set_dr_enabled(False)
        assert e.value.code == 'FED_DR_IN_USE' and e.value.blockers == ['enrolled']
        assert federation.dr_status()['can_disable'] is False
    # counterproof: the row taken out, it switches off
    _add_cluster(a, 'c1', owner='')
    with at(a):
        assert federation.set_dr_enabled(False)['enabled'] is False
        assert federation.dr_enabled() is False


def test_a_copy_of_another_sites_cluster_keeps_it_on(tmp_path, dr_setting):
    a = Side(tmp_path, 'a')
    _set_dr(a, True)
    _add_cluster(a, 'c2', owner='f' * 32)
    with at(a):
        assert federation.dr_blockers() == ['enrolled']


def test_a_promise_given_as_a_voter_keeps_it_on(tmp_path, dr_setting):
    a = Side(tmp_path, 'a')
    _set_dr(a, True)

    def give(st):
        st['promises']['c3'] = {'candidate': 'f' * 32, 'until': 1}
        return True
    with at(a):
        federation.ensure_identity()
        federation._mutate_leases(give)
        assert federation.dr_blockers() == ['lease']


def test_the_settings_form_never_writes_the_switch(tmp_path, dr_setting):
    from pegaprox.api.helpers import save_server_settings
    a = Side(tmp_path, 'a')
    with at(a):
        assert save_server_settings({federation.DR_SETTING_KEY: True, 'language': 'de'})
        db = _db_of(a)
        assert db.get_server_setting(federation.DR_SETTING_KEY, 'unset') == 'unset'
        assert db.get_server_setting('language') == 'de'


# --- what stands aside while it is off -----------------------------------------------------

def test_the_write_gate_asks_for_no_lease_while_off(tmp_path, dr_setting, monkeypatch):
    a = Side(tmp_path, 'a')
    _add_cluster(a, 'c1')
    wire = _Tripwire(True)
    monkeypatch.setattr(fl, 'takes_writes_for', wire)
    with at(a):
        assert federation.guard_exit('c1', 'POST /x') is True
        assert federation.worker_takes_writes_for('c1') is True
    assert wire.calls == []
    # counterproof: switched on, the gate asks
    _set_dr(a, True)
    with at(a):
        assert federation.guard_exit('c1', 'POST /x') is True
        assert federation.worker_takes_writes_for('c1') is True
    assert len(wire.calls) == 2


def test_a_row_a_federation_owns_stays_fenced_while_off(tmp_path, dr_setting):
    a = Side(tmp_path, 'a')
    with at(a):
        me = federation.ensure_identity()
    _add_cluster(a, 'c1', owner=me)
    with at(a):
        with pytest.raises(federation.LeaseRefused):
            federation.guard_exit('c1', 'POST /x')
        assert federation.worker_takes_writes_for('c1') is False
        # reads, consoles and logins still pass
        assert federation.guard_exit('c1', 'GET /x', kind='console') is False


def test_the_lease_worker_does_nothing_while_off(tmp_path, dr_setting, monkeypatch):
    a = Side(tmp_path, 'a')
    wire = _Tripwire()
    monkeypatch.setattr(fl, 'lease_round', wire)
    with at(a):
        federation._lease_tick()
    assert wire.calls == []
    _set_dr(a, True)
    with at(a):
        federation._lease_tick()
    assert len(wire.calls) == 1


def test_the_sync_tick_skips_the_disaster_recovery_while_off(tmp_path, dr_setting, monkeypatch):
    a = Side(tmp_path, 'a')
    keys, records, alone = _Tripwire(), _Tripwire(), _Tripwire()
    monkeypatch.setattr(federation, 'fetch_field_keys', keys)
    monkeypatch.setattr(fl, 'push_records', records)
    monkeypatch.setattr(fl, 'return_alone', alone)
    synced = _Tripwire()
    monkeypatch.setattr(federation, 'sync_identities', synced)
    with at(a):
        federation.ensure_identity()
        federation._sync_tick()
    assert (keys.calls, records.calls, alone.calls) == ([], [], [])
    assert len(synced.calls) == 1                   # the accounts still travel
    _set_dr(a, True)
    with at(a):
        federation._sync_tick()
    assert len(keys.calls) == len(records.calls) == len(alone.calls) == 1


def test_the_epoch_note_is_kept_while_off_as_well(tmp_path, dr_setting):
    """Switched on later, the clock then holds no promotion that did not happen."""
    a = Side(tmp_path, 'a')
    with at(a):
        federation.ensure_identity()
        fl.note_epoch_kept(0, 1)
        assert federation._lease_state().get('epoch_kept') == {'from': 0, 'to': 1}


def test_clusters_enrolled_before_the_switch_keep_it_on(tmp_path, dr_setting):
    """An instance that enrolled clusters before the switch existed would have its writes
    there refused with it off: the first read finds them and saves it on. Counterproof: an
    instance without such rows starts with it off."""
    a, b = Side(tmp_path, 'a'), Side(tmp_path, 'b')
    with at(a):
        me = federation.ensure_identity()
    _add_cluster(a, 'c1', owner=me)
    with at(a):
        assert federation.dr_enabled() is True
        assert _db_of(a).get_server_setting(federation.DR_SETTING_KEY, 'unset') is True
    with at(b):
        federation.ensure_identity()
        assert federation.dr_enabled() is False
        assert _db_of(b).get_server_setting(federation.DR_SETTING_KEY, 'unset') == 'unset'


def test_reads_pass_and_a_refused_write_is_noted_while_off(tmp_path, dr_setting):
    """A row a federation still owns: an SSH command in a GET is a read and passes, as with
    it on; a write is refused and noted for the route's 409."""
    a = Side(tmp_path, 'a')
    with at(a):
        me = federation.ensure_identity()
    _add_cluster(a, 'c1', owner=me)
    _db_of(a).save_server_setting(federation.DR_SETTING_KEY, False)
    with at(a):
        federation._runtime.pop('dr', None)
        with a.app.test_request_context('/api/clusters/c1/x', method='GET'):
            assert federation.guard_exit('c1', 'SSH n1 cat', kind='ssh') is False
        with a.app.test_request_context('/api/clusters/c1/x', method='POST'):
            from flask import request
            with pytest.raises(federation.LeaseRefused):
                federation.guard_exit('c1', 'SSH n1 qm start', kind='ssh')
            assert request.environ.get(federation.FED_REFUSED_ENVIRON) == ['c1']


def test_an_enroll_is_refused_while_off(tmp_path, dr_setting):
    a, b = _sides(tmp_path, 'ab')
    _add_cluster(a, 'c1')
    with at(a):
        with pytest.raises(federation.FederationError) as e:
            fl.enroll_cluster('c1')
    assert e.value.code == 'FED_DR_OFF'
    assert _db_of(a).conn.execute("SELECT fed_owner FROM clusters WHERE id = 'c1'").fetchone()[0] == ''


def test_the_peer_status_says_whether_it_is_on(tmp_path, dr_setting):
    a = Side(tmp_path, 'a')
    with at(a):
        federation.ensure_identity()
        assert federation.peer_status_body()['dr'] is False
    _set_dr(a, True)
    with at(a):
        assert federation.peer_status_body()['dr'] is True


# --- the routes ------------------------------------------------------------------------------

def test_a_cluster_ask_is_refused_while_off_and_the_members_lock_is_not(tmp_path, dr_setting):
    """The members lock of a pairing or a removal is voted on through the lease vote as
    well, so the route stays open: only the clusters in it are refused."""
    a, b, c = _sides(tmp_path, 'abc')         # three sites paired with it off: the lock works
    with at(a):
        status, body = fl.cast_votes(federation.instance_id(),
                                     {'candidate': federation.instance_id(),
                                      'asks': [{'cluster_id': 'c1'}]})
    assert (status, body.get('reason')) == (409, 'dr_off')
    with at(b):
        me_b = federation.instance_id()
    with at(a):
        status, body = fl.cast_votes(me_b, {'candidate': me_b, 'unenroll': ['c1']})
    assert (status, body.get('reason')) == (409, 'dr_off')
    # counterproof: switched on, the cluster ask is a vote again
    _set_dr(a, True)
    with at(a):
        status, body = fl.cast_votes(me_b, {'candidate': me_b, 'asks': [{'cluster_id': 'c9'}]})
    assert body.get('reason') != 'dr_off', body


def test_a_removal_goes_through_while_off(tmp_path, dr_setting):
    a, b, c = _sides(tmp_path, 'abc')
    with at(c):
        gone = federation.instance_id()
    with at(a):
        federation.remove_member(gone, by='test')
        assert gone not in federation.members()


def test_only_sites_with_it_on_count_for_an_enroll(tmp_path, dr_setting):
    a, b, c = _sides(tmp_path, 'abc')
    _set_dr(a, True)
    _set_dr(b, True)
    with at(a):
        assert federation.sites_without_dr() == ['site-c']
    _set_dr(c, True)
    with at(a):
        assert federation.sites_without_dr() == []
    # a silent site counts as one without it
    a.runtime['transport'] = lambda url, *rest: (0, b'', {}) if url == URL['c'] \
        else a.wire(url, *rest)
    with at(a):
        assert federation.sites_without_dr() == ['site-c']


@pytest.fixture
def fed_api(api, monkeypatch):
    monkeypatch.setenv(federation.ENV_SWITCH, '1')
    monkeypatch.delenv(federation.DR_ENV_SWITCH, raising=False)
    yield api
    federation.stop_workers()


_DR_ROUTES = (('get', '/api/federation/leases'),
              ('post', '/api/federation/clusters/c1/enroll'),
              ('post', '/api/federation/clusters/c1/release'),
              ('post', '/api/federation/clusters/c1/unenroll'),
              ('post', '/api/federation/clusters/c1/adopt'),
              ('post', '/api/federation/clusters/c1/takeover'),
              ('post', f'/api/federation/members/{"0" * 32}/takeover'),
              ('post', '/api/federation/clusters/c1/renew'),
              ('get', '/api/federation/peer/field-key'))


def test_every_disaster_recovery_route_answers_dr_off(fed_api, seed):
    c = fed_api.as_user(seed.user('root', role='admin'))
    for method, path in _DR_ROUTES:
        r = getattr(c, method)(path, json={})
        assert r.status_code == 409 and r.get_json()['code'] == 'FED_DR_OFF', (path, r.data)
    # counterproof: switched on, none of them says so any more
    assert c.post('/api/federation/dr', json={'enabled': True}).status_code == 200
    for method, path in _DR_ROUTES:
        r = getattr(c, method)(path, json={})
        assert (r.get_json() or {}).get('code') != 'FED_DR_OFF', (path, r.data)


def test_the_switch_route_is_audited_and_shown_in_the_status(fed_api, seed):
    c = fed_api.as_user(seed.user('root', role='admin'))
    assert c.get('/api/federation/status').get_json()['dr']['enabled'] is False
    r = c.post('/api/federation/dr', json={'enabled': True})
    assert r.status_code == 200 and r.get_json()['enabled'] is True
    assert c.get('/api/federation/status').get_json()['dr']['enabled'] is True
    rows = seed.db.conn.execute("SELECT action FROM audit_log WHERE action LIKE "
                                "'federation.dr_%'").fetchall()
    assert [r['action'] for r in rows] == ['federation.dr_switched_on']
    assert c.post('/api/federation/dr', json={'enabled': 'yes'}).status_code == 400


def test_a_mirrored_admin_does_not_flip_it(fed_api, seed):
    user = seed.user('mirror', role='admin')
    seed.db.conn.execute("UPDATE users SET fed_home = ? WHERE username = 'mirror'",
                         ('f' * 32,))
    seed.db.conn.commit()
    r = fed_api.as_user(user).post('/api/federation/dr', json={'enabled': True})
    assert r.status_code == 403
    assert seed.db.get_server_setting(federation.DR_SETTING_KEY, 'unset') == 'unset'


def test_a_non_admin_does_not_flip_it(fed_api, seed):
    r = fed_api.as_user(seed.user('ops', role='user')).post('/api/federation/dr',
                                                             json={'enabled': True})
    assert r.status_code == 403


def test_a_site_with_it_off_does_not_join_while_clusters_are_enrolled(tmp_path, dr_setting):
    """It would count in every majority of the leases and refuse each vote."""
    from tests.test_federation import _code, _join
    a, c = _sides(tmp_path, 'ac')
    b = Side(tmp_path, 'b')
    _wire([a, b, c])
    for s in (a, c):
        _set_dr(s, True)
    with at(a):
        me = federation.instance_id()
    _add_cluster(a, 'c1', owner=me)
    code = _code(a)
    # without a good code nobody learns that clusters are enrolled
    with at(a):
        with pytest.raises(federation.FederationError) as e:
            federation.accept_join('pgxfd1_x', 'https://b.example:5000', 'b' * 32,
                                   federation.public_key(), 'site-b')
    assert e.value.code == 'FED_CODE'
    with pytest.raises(federation.FederationError) as e:
        _join(b, code)
    assert e.value.code == 'FED_DR_OFF_AT'
    with at(a):
        assert len(federation.members()) == 1
    # counterproof: switched on there, it joins with the same code
    _set_dr(b, True)
    _join(b, code)
    with at(a):
        assert len(federation.members()) == 2


def test_a_site_with_it_off_keeps_no_copy_of_another_sites_cluster(tmp_path, dr_setting):
    from tests.test_federation import _code, _join, _pull
    a, b = Side(tmp_path, 'a'), Side(tmp_path, 'b')
    _wire([a, b])
    _set_dr(a, True)
    _join(b, _code(a))
    with at(a):
        me = federation.instance_id()
    _add_cluster(a, 'c1', owner=me, password='x-secret')
    _pull(b, a)
    assert _db_of(b).conn.execute("SELECT COUNT(*) FROM clusters WHERE id = 'c1'").fetchone()[0] == 0
    with at(b):
        assert federation.dr_blockers() == []
        etag = federation.sync_state()[me]['etag']
        assert etag.endswith(federation.NODR_MARK)
    # counterproof: switched on - here by the setting itself, as an environment change or a
    # read that failed for a moment would - the next pull takes the snapshot whole
    _set_dr(b, True)
    _pull(b, a)
    assert _db_of(b).conn.execute("SELECT fed_owner FROM clusters WHERE id = 'c1'"
                                  ).fetchone()[0] == me


def test_a_vote_refused_for_it_says_so():
    text = fl._refusal_sentence({'votes': 1, 'needed': 2, 'refusals': {'dr_off': 1}})
    assert 'disaster recovery off' in text
