"""The live view of a warm standby (#625, stage two): its managers run and only read.

A standby with the live view on starts its cluster, PBS and ESXi managers like an
active instance, so the UI shows the clusters as they are. Everything in them that
would act asks ha.is_active() and holds back. What that needs, tested here:

  * the contract in core/ha.py - the live view switch, managers_wanted(), the
    signature of how the managers connect, the reload once a change to it has
    settled (what a reload does is tests/test_ha_reload.py), the settings handed to
    running managers in place after each sync;
  * the gates in the managers that only never ran on a v1 standby because it had
    no managers: save_config, the API token, stopping the HA agents on the nodes,
    the HA monitor and recovery, the XCP-ng id map and balancer, the snapshot
    refresh and the SSH side of the metrics collector;
  * managers started the way main() starts them, on a standby, against a fake PVE
    and XAPI: no SSH, no write to a synced table, nothing done on the nodes;
  * main() itself, read as source since it binds a port.

Every test with a role runs as the active too, as the counterproof that it can
tell the two apart.

MK Sep 2026
"""
import ast
import copy
import inspect
import json
import os
import threading
import types
from unittest.mock import MagicMock

import pytest
import requests

from pegaprox.core import ha
import pegaprox.globals as g

A = 'a' * 32   # the active
B = 'b' * 32   # this instance, the standby
ROLES = ['standby', 'active', 'standalone']


# --- harness ---------------------------------------------------------------------

class _Clock:
    """ha.time for a test: monotonic and wall time move only when told to."""

    def __init__(self):
        self.mono = 1000.0
        self.wall = 1790000000.0
        self.naps = []

    def monotonic(self):
        return self.mono

    def time(self):
        return self.wall

    def sleep(self, seconds):
        self.naps.append(seconds)

    def advance(self, seconds):
        self.mono += seconds
        self.wall += seconds


def _peer(pid, **kw):
    p = {'instance_id': pid, 'url': 'https://peer.example:5000', 'fingerprint': '',
         'secret_out': 'o' * 43, 'secret_in_hash': ha._hash_secret('i' * 43),
         'paired_at': '2026-09-29T10:00:00+00:00', 'role_seen': None, 'epoch_seen': 3}
    p.update(kw)
    return p


def _write_state(**st):
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        json.dump(st, fh)
    ha.reset_for_tests()


def _be(role, **kw):
    if role == 'standalone':
        _write_state(role='standalone', instance_id=B, epoch=0, **kw)
    elif role == 'active':
        _write_state(role='active', instance_id=A, epoch=3, peer=_peer(B, role_seen='standby'), **kw)
    else:
        _write_state(role='standby', instance_id=B, epoch=3,
                     peer=_peer(A, role_seen='active'), **kw)
    assert ha.role() == role


def _switch_role(role):
    """The same state file under another role, the rest kept (a step-down mid-way)."""
    with open(ha.STATE_FILE, encoding='utf-8') as fh:
        st = json.load(fh)
    st['role'] = role
    _write_state(**st)


@pytest.fixture
def registries():
    """The manager registries every route and loop imports by reference: emptied for
    the test and given back afterwards, the same dict objects throughout."""
    saved = [(reg, dict(reg)) for reg in (g.cluster_managers, g.pbs_managers, g.vmware_managers)]
    for reg, _ in saved:
        reg.clear()
    yield g
    for reg, content in saved:
        reg.clear()
        reg.update(content)


@pytest.fixture
def env(db, registries, monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(ha, 'time', clock)
    # a fresh process as far as the managers are concerned
    monkeypatch.setattr(ha, '_run', ha._fresh_run())
    monkeypatch.setattr(ha, '_etag_checked', False)
    restarts, audits, reloads = [], [], []
    monkeypatch.setattr(ha, 'restart_process', restarts.append)
    monkeypatch.setattr(ha, '_audit', lambda action, details: audits.append((action, details)))
    # when the managers are reloaded, not how: what a reload stops and builds is
    # tests/test_ha_reload.py, with stand-ins for the managers
    monkeypatch.setattr(ha, '_rebuild', lambda added, removed, changed, clusters:
                        reloads.append((added, removed, changed)) or [])
    serving = [None]

    def peer_call(method, base_url, fingerprint, path, json_body=None, auth='peer',
                  headers=None, timeout=15):
        snap = serving[0]
        if (headers or {}).get('If-None-Match') == snap['etag']:
            return types.SimpleNamespace(status_code=304, json=lambda: {})
        return types.SimpleNamespace(status_code=200, json=lambda: snap)
    monkeypatch.setattr(ha, '_peer_call', peer_call)
    ha.reset_for_tests()
    return types.SimpleNamespace(db=db, clock=clock, restarts=restarts, audits=audits,
                                 reloads=reloads, serving=serving, mp=monkeypatch)


def _active_meta():
    return dict(instance_id=A, role='active', epoch=3, key_fp=ha.key_fingerprint())


def _sync(env, change=None):
    """The active changes something (change()), then this standby pulls."""
    if change:
        change()
    env.serving[0] = json.loads(json.dumps(ha.build_snapshot(meta=_active_meta(), stuck=[]),
                                           default=str))
    return ha.pull_once()


def _poll(env):
    """A poll that finds nothing new."""
    return ha.pull_once()


def _seed_cluster(db, cid='pve1', **over):
    data = dict(name='Lab', host='10.0.0.1', user='root@pam', ssl_verification=False,
                fallback_hosts=[], ha_enabled=False, ha_settings={}, ssh_user='root',
                ssh_key='', ssh_port=22, cluster_type='proxmox', api_port=8006,
                migration_threshold=30, check_interval=300, auto_migrate=False, enabled=True)
    data['pass'] = 'pw'
    data.update(over)
    db.save_cluster(cid, data)


def _insert(db, table, **row):
    cols = ', '.join(row)
    marks = ', '.join('?' * len(row))
    db.conn.execute(f'INSERT OR REPLACE INTO {table} ({cols}) VALUES ({marks})', tuple(row.values()))
    db.conn.commit()


def _seed_pbs(db, pid='pbs1', **over):
    row = dict(id=pid, name='Backup', host='10.0.2.1', port=8007, user='root@pam',
               pass_encrypted=db._encrypt('pw'), api_token_id='', api_token_secret_encrypted='',
               fingerprint='', ssl_verify=0, enabled=1, linked_clusters='[]', notes='',
               ssh_user='', ssh_port=22, ssh_key_encrypted='', updated_at='2026-09-01')
    row.update(over)
    _insert(db, 'pbs_servers', **row)


def _seed_esxi(db, vid='esx1', **over):
    row = dict(id=vid, name='Old farm', host='10.0.3.1', port=443, username='root',
               pass_encrypted=db._encrypt('pw'), server_type='esxi', ssl_verify=0, enabled=1,
               linked_clusters='[]', notes='', updated_at='2026-09-01')
    row.update(over)
    _insert(db, 'vmware_servers', **row)


def _update(db, table, rid, **cols):
    sets = ', '.join(f'{c} = ?' for c in cols)
    db.conn.execute(f'UPDATE {table} SET {sets} WHERE id = ?', tuple(cols.values()) + (rid,))
    db.conn.commit()


def _rows(db, table):
    cur = db.conn.execute(f'SELECT * FROM {table}')
    return sorted(tuple(r) for r in cur.fetchall())


def _started(env):
    """What main() does once the managers are up: note what they started from."""
    ha.note_managers_started(ha.manager_signature())


# --- the live view switch ----------------------------------------------------------

def test_the_live_view_is_on_until_an_admin_switches_it_off(env):
    assert ha.live_view() is True
    assert not os.path.exists(ha.STATE_FILE), 'reading it writes nothing'
    _be('standby')

    assert ha.set_live_view(False) is True
    with open(ha.STATE_FILE, encoding='utf-8') as fh:
        assert json.load(fh)['live_view'] is False
    ha.reset_for_tests()
    assert ha.live_view() is False
    assert ha.set_live_view(False) is False
    for wrong in ('off', 0, None, 1):
        with pytest.raises(ha.HaError):
            ha.set_live_view(wrong)
    assert ha.live_view() is False


def test_the_live_view_stays_on_this_instance_through_a_sync(env):
    _be('standby', live_view=False)
    _seed_cluster(env.db)
    assert _sync(env) == 'applied'
    assert ha.live_view() is False


def test_a_state_file_that_cannot_be_read_takes_no_live_view_switch(env):
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        fh.write('{"role": "stand')
    ha.reset_for_tests()
    with pytest.raises(ha.HaError):
        ha.set_live_view(False)


@pytest.mark.parametrize('role,stored,wanted', [
    ('standalone', None, True),
    ('active', None, True),
    ('active', False, True),        # an acting instance always runs its managers
    ('standby', None, True),        # on by default
    ('standby', True, True),
    ('standby', False, False),      # switched off: v1
    ('standby', 'yes', True),       # not a bool: the default
])
def test_managers_wanted_by_role_and_live_view(env, role, stored, wanted):
    _be(role, **({} if stored is None else {'live_view': stored}))
    assert ha.managers_wanted() is wanted


def test_a_standby_whose_state_file_cannot_be_read_starts_no_managers(env):
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        fh.write('not json')
    ha.reset_for_tests()
    assert ha.is_standby() and ha.managers_wanted() is False


def test_the_status_says_live_view_managers_and_the_restart_it_waits_for(env):
    _be('standby')
    st = ha.public_status()
    assert (st['live_view'], st['managers_running'], st['sync']['restart_pending']) == (True, False, None)

    _started(env)
    assert ha.public_status()['managers_running'] is True
    ha.set_live_view(False)
    pending = ha.public_status()['sync']['restart_pending']
    assert pending['reason'] == 'the live view was switched off' and pending['since']
    ha.set_live_view(True)
    assert ha.public_status()['sync']['restart_pending'] is None

    _switch_role('active')
    ha.set_live_view(False)
    st = ha.public_status()
    assert st['live_view'] is False and st['sync']['restart_pending'] is None


# --- the signature ------------------------------------------------------------------

def _seed_all(db):
    _seed_cluster(db)
    _seed_cluster(db, 'xcp1', name='Pool', host='10.0.1.1', user='root', cluster_type='xcpng')
    _seed_pbs(db)
    _seed_pbs(db, 'pbs-off', host='10.0.2.9', enabled=0)
    _seed_esxi(db)


IDENTITY_CHANGES = [
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', host='10.0.0.9'), id='host'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', user='admin@pve'), id='user'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', pass_encrypted=db._encrypt('new')),
                 id='password'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', api_port=8443), id='api-port'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', ssl_verification=1), id='tls'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', api_token_user='root@pam!pp',
                                    api_token_secret_encrypted=db._encrypt('t')), id='api-token'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', ssh_user='ops'), id='ssh-user'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', ssh_key_encrypted=db._encrypt('KEY')),
                 id='ssh-key'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', ssh_port=2222), id='ssh-port'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', ssh_disabled=1), id='ssh-off'),
    pytest.param(lambda db: _update(db, 'clusters', 'xcp1', cluster_type='proxmox'), id='cluster-type'),
    pytest.param(lambda db: _seed_cluster(db, 'pve2', host='10.0.5.1'), id='cluster-added'),
    pytest.param(lambda db: db.conn.execute("DELETE FROM clusters WHERE id = 'xcp1'"),
                 id='cluster-removed'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs1', host='10.0.2.2'), id='pbs-host'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs1', port=8008), id='pbs-port'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs1', pass_encrypted=db._encrypt('x')),
                 id='pbs-password'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs1', api_token_id='root@pam!b'),
                 id='pbs-token'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs1', fingerprint='AB:CD'), id='pbs-pin'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs1', ssl_verify=1), id='pbs-tls'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs1', ssh_key_encrypted=db._encrypt('K')),
                 id='pbs-ssh-key'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs1', enabled=0), id='pbs-disabled'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs-off', enabled=1), id='pbs-enabled'),
    pytest.param(lambda db: _update(db, 'vmware_servers', 'esx1', host='10.0.3.2'), id='esxi-host'),
    pytest.param(lambda db: _update(db, 'vmware_servers', 'esx1', username='admin'), id='esxi-user'),
    pytest.param(lambda db: _update(db, 'vmware_servers', 'esx1', pass_encrypted=db._encrypt('y')),
                 id='esxi-password'),
    pytest.param(lambda db: _update(db, 'vmware_servers', 'esx1', server_type='vcenter'),
                 id='esxi-type'),
    pytest.param(lambda db: _update(db, 'vmware_servers', 'esx1', enabled=0), id='esxi-disabled'),
]

CHURN = [
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', fallback_hosts='["10.0.0.2"]'),
                 id='fallback-hosts'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', ha_settings=db._encrypt(
        json.dumps({'self_fence_installed': True}))), id='ha-settings'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', ha_enabled=1), id='ha-enabled'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', updated_at='2027-01-01'), id='updated-at'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', name='Renamed', display_name='Shown',
                                    group_id='grp', sort_order=4), id='names'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', migration_threshold=77, check_interval=60,
                                    excluded_nodes='["pve3"]', dry_run=0), id='thresholds'),
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', smbios_autoconfig='{"on": true}',
                                    latitude=48.2, location_label='Vienna'), id='display'),
    # save_config on the active seals every secret again under a new nonce
    pytest.param(lambda db: _update(db, 'clusters', 'pve1', pass_encrypted=db._encrypt('pw')),
                 id='same-password-resealed'),
    pytest.param(lambda db: _seed_cluster(db), id='row-saved-again'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs1', name='B2', notes='n',
                                    linked_clusters='["pve1"]', updated_at='2027-01-01'),
                 id='pbs-display'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs1', pass_encrypted=db._encrypt('pw')),
                 id='pbs-password-resealed'),
    pytest.param(lambda db: _update(db, 'pbs_servers', 'pbs-off', host='10.0.2.10'),
                 id='disabled-pbs-edited'),
    pytest.param(lambda db: _update(db, 'vmware_servers', 'esx1', name='Farm', notes='n',
                                    linked_clusters='["pve1"]'), id='esxi-display'),
]


@pytest.mark.parametrize('change', IDENTITY_CHANGES)
def test_the_signature_changes_with_how_a_manager_connects(env, change):
    _seed_all(env.db)
    before = ha.manager_signature()
    change(env.db)
    env.db.conn.commit()
    assert ha.manager_signature() != before


@pytest.mark.parametrize('change', CHURN)
def test_the_signature_ignores_what_changes_without_a_new_connection(env, change):
    _seed_all(env.db)
    before = ha.manager_signature()
    change(env.db)
    env.db.conn.commit()
    assert ha.manager_signature() == before


def test_a_secret_that_cannot_be_opened_is_a_stable_value(env):
    """Not a crash, and no reload for a nonce either."""
    _seed_all(env.db)
    _update(env.db, 'clusters', 'pve1', pass_encrypted='aes256:bm90IGEgY2lwaGVydGV4dA==')
    first = ha.manager_signature()
    _update(env.db, 'clusters', 'pve1', pass_encrypted='aes256:YW5vdGhlciBnYXJibGU=')
    assert ha.manager_signature() == first


def test_the_signature_never_leaves_memory(env):
    _be('standby')
    _seed_all(env.db)
    assert _sync(env) == 'applied'
    _started(env)
    baseline, items = ha._run['signature'], dict(ha._run['items'])
    env.clock.advance(300)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    pending = json.dumps(ha.public_status())
    env.clock.advance(ha.RELOAD_SETTLE)
    assert _poll(env) == 'unchanged' and len(env.reloads) == 1
    with open(ha.STATE_FILE, encoding='utf-8') as fh:
        text = fh.read()
    shown = json.dumps(ha.public_status())
    for secret in [baseline, ha.manager_signature()] + list(items.values()) + list(ha._run['items'].values()):
        assert secret not in text and secret not in shown and secret not in pending


# --- the reload after a sync ----------------------------------------------------------
# (it used to be a restart of the whole process, which signed out every user of the
# standby; tests/test_ha_reload.py has what a reload stops and builds)

def _standby_with_managers(env, **state):
    _be('standby', **state)
    _seed_all(env.db)
    assert _sync(env) == 'applied'          # the pull at start
    _started(env)


def test_new_connection_settings_reload_a_standby_once_they_have_settled(env):
    _standby_with_managers(env)
    env.clock.advance(300)

    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    st = ha.public_status()['sync']
    assert st['reload_pending']['reason'] == '1 cluster changed' and st['reload_pending']['since']
    assert st['restart_pending'] is None and env.reloads == []

    env.clock.advance(ha.RELOAD_SETTLE - 1)
    assert _poll(env) == 'unchanged' and env.reloads == []
    env.clock.advance(1)
    assert _poll(env) == 'unchanged'
    assert env.reloads == [([], [], ['cluster:pve1'])]
    assert env.audits == [('ha.managers_reloaded', '1 cluster changed')]
    assert ha.public_status()['sync']['reload_pending'] is None
    # and no restart, nor a stamp of one
    assert env.restarts == [] and 'last_config_restart' not in ha._load()
    # done: asking again reloads nothing, nor does an admin who presses "apply now"
    assert _poll(env) == 'unchanged' and len(env.reloads) == 1
    assert ha.apply_config_now() is False and len(env.reloads) == 1


def test_the_reason_names_kinds_and_counts(env):
    _standby_with_managers(env)
    env.clock.advance(300)

    def change():
        _seed_cluster(env.db, 'pve2', host='10.0.5.1')
        _update(env.db, 'pbs_servers', 'pbs1', host='10.0.2.2')
        env.db.conn.execute("DELETE FROM vmware_servers WHERE id = 'esx1'")
        env.db.conn.commit()
    assert _sync(env, change) == 'applied'
    assert ha.public_status()['sync']['reload_pending']['reason'] == \
        '1 cluster added, 1 PBS server changed, 1 ESXi server removed'


def test_a_reload_does_not_wait_for_the_process_to_have_run_a_while(env):
    """A restart waited two minutes after a start, against a restart loop. A reload
    starts nothing over and has no such loop to fear."""
    _standby_with_managers(env)
    env.clock.advance(1)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE)
    assert _poll(env) == 'unchanged' and len(env.reloads) == 1


def test_a_second_change_is_reloaded_without_waiting_ten_minutes(env):
    """Restarts were at most one in ten minutes. Reloads are as often as changes settle,
    and a stamp an older release left in the state file changes nothing."""
    stamp = int(env.clock.wall) - 60
    _standby_with_managers(env, last_config_restart=stamp)
    env.clock.advance(300)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE)
    assert _poll(env) == 'unchanged' and len(env.reloads) == 1
    env.clock.advance(30)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', user='admin@pve')) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE)
    assert _poll(env) == 'unchanged'
    assert env.reloads == [([], [], ['cluster:pve1'])] * 2
    assert ha._load()['last_config_restart'] == stamp and env.restarts == []


def test_a_further_change_starts_the_settle_time_again(env):
    _standby_with_managers(env)
    env.clock.advance(300)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE - 2)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', user='admin@pve')) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE - 1)
    assert _poll(env) == 'unchanged' and env.reloads == []
    env.clock.advance(1)
    assert _poll(env) == 'unchanged' and len(env.reloads) == 1


def test_a_change_undone_before_it_settled_reloads_nothing(env):
    _standby_with_managers(env)
    env.clock.advance(300)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    assert ha.public_status()['sync']['reload_pending']
    env.clock.advance(ha.RELOAD_SETTLE - 5)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.1')) == 'applied'
    assert ha.public_status()['sync']['reload_pending'] is None
    env.clock.advance(3600)
    assert _poll(env) == 'unchanged' and env.reloads == [] and env.restarts == []


def test_what_the_active_rewrites_on_its_own_reloads_nothing(env):
    _standby_with_managers(env)
    env.clock.advance(300)

    def churn():
        for p in CHURN:
            p.values[0](env.db)
        env.db.conn.commit()
    assert _sync(env, churn) == 'applied'
    assert ha.public_status()['sync']['reload_pending'] is None
    env.clock.advance(3600)
    assert _poll(env) == 'unchanged' and env.reloads == [] and env.restarts == []


def test_a_failed_poll_still_lets_a_due_reload_go(env, monkeypatch):
    """The new configuration is in the database already; an active that went away
    must not keep the managers on the old one."""
    _standby_with_managers(env)
    env.clock.advance(300)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE)

    def unreachable(*a, **kw):
        raise ha.HaError('Cannot reach the peer: ConnectTimeout')
    monkeypatch.setattr(ha, '_peer_call', unreachable)
    assert ha.pull_once() == 'failed'
    assert len(env.reloads) == 1


def test_the_loop_wakes_for_a_reload_that_falls_due(env):
    """With an interval of an hour a due reload must not wait for the next poll, should
    its own timer not come."""
    _standby_with_managers(env, interval=3600)
    env.clock.advance(300)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'

    class _Stop(BaseException):
        pass

    def nap(seconds):
        env.clock.naps.append(seconds)
        if len(env.clock.naps) == 2:
            raise _Stop()
    env.clock.sleep = nap
    env.mp.setattr(ha, 'pull_once', lambda **kw: None)
    with pytest.raises(_Stop):
        ha._loop()
    assert env.clock.naps == [5, ha.RELOAD_SETTLE + 1]


def test_the_reload_goes_on_its_own_timer(env, monkeypatch):
    """Noted by the sync, a second past the settle time, and not before it has settled."""
    timers = []
    monkeypatch.setattr(ha, '_later', lambda delay, fn, name: timers.append((delay, fn, name)))
    _standby_with_managers(env)
    env.clock.advance(300)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    assert [(delay, name) for delay, _fn, name in timers] == [(ha.RELOAD_SETTLE + 1, 'ha-reload')]
    fire = timers[0][1]
    env.clock.advance(ha.RELOAD_SETTLE - 1)
    assert fire() is False and env.reloads == []
    env.clock.advance(2)
    assert fire() is True and len(env.reloads) == 1


def test_a_state_file_that_cannot_be_written_holds_no_reload_back(env, monkeypatch):
    """A restart had to note itself in the state file first, or it would have come again
    every two minutes. A reload writes nothing there."""
    _standby_with_managers(env)
    env.clock.advance(300)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE)

    def refuse(st):
        raise OSError('No space left on device')
    monkeypatch.setattr(ha, '_write_locked', refuse)
    assert ha._reload_if_due() is True
    assert len(env.reloads) == 1 and ha.public_status()['sync']['reload_pending'] is None


def test_apply_now_reloads_at_once_when_there_is_something_to_apply(env):
    _be('active')
    with pytest.raises(ha.HaError):
        ha.apply_config_now()

    _standby_with_managers(env)
    assert ha.apply_config_now() is False and env.reloads == []
    # a change no sync has looked at yet is read fresh; no settle time
    _update(env.db, 'pbs_servers', 'pbs1', host='10.0.2.2')
    assert ha.apply_config_now() == 'reload'
    assert env.reloads == [([], [], ['pbs:pbs1'])]
    assert env.restarts == [] and 'last_config_restart' not in ha._load()


def test_apply_now_takes_a_waiting_reload_past_the_settle_time(env):
    _standby_with_managers(env)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    assert _poll(env) == 'unchanged' and env.reloads == []
    assert ha.apply_config_now() == 'reload' and len(env.reloads) == 1
    assert ha.public_status()['sync']['reload_pending'] is None


@pytest.mark.parametrize('start_with,switch_to', [(True, False), (False, True)])
def test_apply_now_restarts_for_a_switched_live_view(env, start_with, switch_to):
    _be('standby', live_view=start_with)
    _seed_all(env.db)
    if start_with:
        _started(env)
    assert ha.set_live_view(switch_to) is True
    assert ha.apply_config_now() == 'restart'
    assert env.restarts == [f'configuration changed on the active instance: '
                            f'the live view was switched {"on" if switch_to else "off"}']
    # the restart is on its way: no second one, and no reload before it
    _update(env.db, 'clusters', 'pve1', host='10.0.0.9')
    assert ha.apply_config_now() is False and len(env.restarts) == 1 and env.reloads == []


def test_a_live_view_switched_back_leaves_nothing_to_apply(env):
    _standby_with_managers(env)
    ha.set_live_view(False)
    ha.set_live_view(True)
    assert ha.apply_config_now() is False and env.restarts == [] and env.reloads == []


# --- in place after a sync ------------------------------------------------------------

def _fake_managers(env):
    from pegaprox.models.tasks import PegaProxConfig
    stops = []
    rows = env.db.get_all_clusters()
    pve = types.SimpleNamespace(config=PegaProxConfig(rows['pve1']), cluster_type='proxmox',
                                stop=lambda: stops.append('pve1'))
    xcp = types.SimpleNamespace(config=PegaProxConfig(rows['xcp1']), cluster_type='xcpng',
                                stop=lambda: stops.append('xcp1'))
    pbs = types.SimpleNamespace(name='Backup', notes='', linked_clusters=[], host='10.0.2.1')
    esx = types.SimpleNamespace(name='Old farm', notes='', linked_clusters=[], host='10.0.3.1')
    wrapper = types.SimpleNamespace(config=types.SimpleNamespace(host='10.0.3.1'), cluster_type='esxi')
    g.cluster_managers.update(pve1=pve, xcp1=xcp, esx1=wrapper)
    g.pbs_managers['pbs1'] = pbs
    g.vmware_managers['esx1'] = esx
    return types.SimpleNamespace(pve=pve, xcp=xcp, pbs=pbs, esx=esx, wrapper=wrapper, stops=stops)


def test_a_sync_hands_the_managers_what_they_read_in_place(env):
    _be('standby')
    _seed_all(env.db)
    assert _sync(env) == 'applied'
    m = _fake_managers(env)
    _started(env)
    env.clock.advance(300)

    def change():
        _update(env.db, 'clusters', 'pve1', name='Lab A', migration_threshold=55, check_interval=60,
                auto_migrate=1, excluded_nodes='["pve3"]', fallback_hosts='["10.0.0.2", "10.0.0.3"]',
                smbios_autoconfig='{"enabled": true}', node_ui_suffix='lab.example', enabled=0)
        _update(env.db, 'clusters', 'xcp1', name='Pool A')
        _update(env.db, 'pbs_servers', 'pbs1', name='Backup A', notes='rack 4',
                linked_clusters='["pve1"]')
        _update(env.db, 'vmware_servers', 'esx1', name='Farm A', notes='leaving')
    assert _sync(env, change) == 'applied'

    cfg = m.pve.config
    assert (cfg.name, cfg.migration_threshold, cfg.check_interval, cfg.auto_migrate) == ('Lab A', 55, 60, True)
    assert cfg.excluded_nodes == ['pve3'] and cfg.enabled is False
    assert cfg.fallback_hosts == ['10.0.0.2', '10.0.0.3']
    assert cfg.smbios_autoconfig == {'enabled': True} and cfg.node_ui_suffix == 'lab.example'
    assert m.xcp.config.name == 'Pool A'
    assert (m.pbs.name, m.pbs.notes, m.pbs.linked_clusters) == ('Backup A', 'rack 4', ['pve1'])
    assert (m.esx.name, m.esx.notes) == ('Farm A', 'leaving')
    # the same objects, nothing stopped, nothing reloaded or restarted, the wrapper left alone
    assert g.cluster_managers['pve1'] is m.pve and g.cluster_managers['esx1'] is m.wrapper
    assert m.stops == [] and not hasattr(m.wrapper.config, 'name')
    assert ha.public_status()['sync']['reload_pending'] is None
    env.clock.advance(3600)
    assert _poll(env) == 'unchanged' and env.reloads == [] and env.restarts == []


def test_a_connection_setting_is_not_changed_in_place(env):
    """A running manager holds its host, auth mode and SSH pool; it gets a new
    connection with the reload, a new manager, not half of one now."""
    _be('standby')
    _seed_all(env.db)
    assert _sync(env) == 'applied'
    m = _fake_managers(env)
    _started(env)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9', ssh_port=2222,
                                      name='Lab B')) == 'applied'
    assert (m.pve.config.host, m.pve.config.ssh_port, m.pve.config.name) == ('10.0.0.1', 22, 'Lab B')
    assert ha.public_status()['sync']['reload_pending']['reason'] == '1 cluster changed'


def test_with_the_live_view_off_a_standby_stays_as_in_v1(env):
    """No managers were started, so there is nothing to refresh and nothing to reload."""
    _be('standby', live_view=False)
    assert ha.managers_wanted() is False
    _seed_all(env.db)
    assert _sync(env) == 'applied'
    env.clock.advance(300)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    env.clock.advance(3600)
    assert _poll(env) == 'unchanged'
    st = ha.public_status()
    assert (st['managers_running'], st['sync']['reload_pending'], env.reloads) == (False, None, [])
    assert st['sync']['restart_pending'] is None and env.restarts == []
    assert g.cluster_managers == {}


def test_the_pull_at_start_is_short_and_never_raises(env, monkeypatch):
    _be('active')
    assert ha.boot_pull() == 'idle'
    _switch_role('standby')
    seen = []

    def slow(method, base_url, fingerprint, path, json_body=None, auth='peer', headers=None,
             timeout=15):
        seen.append(timeout)
        raise ha.HaError('Cannot reach the peer: ReadTimeout')
    monkeypatch.setattr(ha, '_peer_call', slow)
    assert ha.boot_pull() == 'failed' and seen == [10]

    def broken(timeout=60):
        raise RuntimeError('boom')
    monkeypatch.setattr(ha, 'pull_once', broken)
    assert ha.boot_pull() == 'error'


# --- the gates in the managers ---------------------------------------------------------

class _Threads:
    """Stands in for the threading module of manager.py or xcpng.py: a Thread there
    is noted and not started, the test runs its target when it wants to."""

    def __init__(self):
        self.made = []
        outer = self

        class Thread:
            def __init__(self, target=None, args=(), kwargs=None, daemon=None, name=None):
                self.target, self.args, self.kwargs = target, args, kwargs or {}
                self.daemon = daemon

            def start(self):
                outer.made.append(self)

            def is_alive(self):
                return False

            def join(self, timeout=None):
                pass
        self.Thread = Thread

    def __getattr__(self, name):
        return getattr(threading, name)


@pytest.mark.parametrize('which', ROLES)
def test_save_config_leaves_the_clusters_rows_alone_on_a_standby(which, env):
    """It writes every running manager's config back, a cluster the active deleted
    included; on a standby nothing heals that until the active changes something."""
    from pegaprox.core.config import save_config
    from pegaprox.models.tasks import PegaProxConfig
    _be(which)
    _seed_cluster(env.db)
    cfg = PegaProxConfig(env.db.get_all_clusters()['pve1'])
    cfg.fallback_hosts, cfg.name = ['10.0.0.2'], 'drifted'
    gone = PegaProxConfig(dict(env.db.get_all_clusters()['pve1'], name='deleted on the active'))
    g.cluster_managers.update(pve1=types.SimpleNamespace(config=cfg, cluster_type='proxmox'),
                              gone=types.SimpleNamespace(config=gone, cluster_type='proxmox'))
    before = _rows(env.db, 'clusters')

    result = save_config()

    if which == 'standby':
        assert result is False and _rows(env.db, 'clusters') == before
    else:
        rows = env.db.get_all_clusters()
        assert result is True and rows['pve1']['name'] == 'drifted' and 'gone' in rows


@pytest.mark.parametrize('which', ROLES)
def test_no_api_token_is_minted_from_a_standby_whoever_calls(which, env, monkeypatch):
    import pegaprox.core.manager as mgrmod
    _be(which)
    saved = []
    monkeypatch.setattr(mgrmod, 'save_config', lambda: saved.append(1))
    fake_db = MagicMock()
    monkeypatch.setattr(mgrmod, 'get_db', lambda: fake_db)
    fake = MagicMock()
    fake.config.user, fake.api_port, fake._ticket, fake._csrf_token = 'root@pam', 8006, 't', 'c'
    session = MagicMock()
    session.post.return_value = types.SimpleNamespace(
        status_code=200, json=lambda: {'data': {'full-tokenid': 'root@pam!pegaprox_1', 'value': 's'}})

    mgrmod.PegaProxManager._try_create_api_token(fake, session, '10.0.0.1')

    if which == 'standby':
        assert session.post.call_count == 0 and saved == [] and fake_db.mock_calls == []
    else:
        assert session.post.call_count == 1 and saved == [1]


@pytest.mark.parametrize('started_here', [True, False], ids=['monitor-ran-here', 'monitor-never-ran'])
@pytest.mark.parametrize('which', ROLES)
def test_only_the_instance_that_ran_the_monitor_stops_the_agents_on_the_nodes(
        which, started_here, env, monkeypatch):
    """self_fence_installed comes with the synced row: on a standby it describes the
    active's agents, and stopping them switches off its split-brain protection."""
    import pegaprox.core.manager as mgrmod
    _be(which)
    threads = _Threads()
    monkeypatch.setattr(mgrmod, 'threading', threads)
    fake = MagicMock()
    fake.ha_thread = MagicMock(name='monitor thread') if started_here else None
    fake.ha_heartbeat_thread = None
    fake.ha_config = {'self_fence_installed': True}

    mgrmod.PegaProxManager.stop_ha_monitor(fake)

    stops = [t for t in threads.made if t.target is fake._ha_stop_self_fence_agents]
    assert len(stops) == (1 if which != 'standby' and started_here else 0)


@pytest.mark.parametrize('which', ROLES)
def test_the_pve_ha_monitor_loop_checks_nothing_on_a_standby(which, env, monkeypatch):
    import pegaprox.core.manager as mgrmod
    _be(which)
    monkeypatch.setattr(mgrmod, 'time', types.SimpleNamespace(sleep=lambda s: None))
    fake = MagicMock()
    fake.ha_enabled = True
    fake.stop_event.is_set.return_value = False
    # one tick: the check, after which the monitor is switched off
    fake._ha_check_nodes.side_effect = lambda: setattr(fake, 'ha_enabled', False)

    mgrmod.PegaProxManager._ha_monitor_loop(fake)

    assert fake._ha_check_nodes.call_count == (0 if which == 'standby' else 1)


def test_the_pve_ha_monitor_stops_at_the_next_tick_after_a_step_down(env, monkeypatch):
    import pegaprox.core.manager as mgrmod
    _be('active')
    monkeypatch.setattr(mgrmod, 'time', types.SimpleNamespace(sleep=lambda s: None))
    fake = MagicMock()
    fake.ha_enabled = True
    fake.stop_event.is_set.return_value = False
    ticks = []

    def check():
        ticks.append(1)
        if len(ticks) == 2:
            _switch_role('standby')
        if len(ticks) > 5:
            fake.ha_enabled = False
    fake._ha_check_nodes.side_effect = check

    mgrmod.PegaProxManager._ha_monitor_loop(fake)

    assert len(ticks) == 2


def _recovery_fake():
    fake = MagicMock()
    fake.ha_config = {'recovery_delay': 30, 'quorum_enabled': True,
                      'verify_network_before_recovery': True, 'storage_heartbeat_enabled': True}
    # what the worker waits: recovery_delay, on a node without the v2 agent
    fake._ha_fence_timing.return_value = {'wait': 30}
    fake._ha_check_node_agent_heartbeat.return_value = {'alive': False, 'age_seconds': None}
    fake.ha_lock = threading.Lock()
    fake.ha_node_status = {'pve2': {'status': 'offline'}}
    fake.ha_recovery_in_progress = {'pve2': True}
    fake.current_host, fake.is_connected, fake.session = '10.0.0.1', True, True
    fake._ha_acquire_recovery_lock.return_value = True
    fake._ha_check_node_via_ssh.return_value = {'reachable': True, 'running_vms': [100],
                                                'running_cts': [], 'reachable_ips': ['10.0.0.2']}
    fake._ha_ssh_stop_vms_on_node.return_value = True
    fake._ha_check_quorum.return_value = True
    fake._ha_verify_network.return_value = True
    fake._ha_fence_node.return_value = True
    # the safety rules of S6: a quorate cluster, so nothing to fence and read back
    fake._ha_recovery_allowed.return_value = []
    fake._ha_fence_verified.return_value = False
    fake._ha_get_vms_on_node.return_value = [{'vmid': 100, 'name': 'a', 'type': 'qemu'},
                                             {'vmid': 101, 'name': 'b', 'type': 'qemu'}]
    fake._ha_get_available_nodes.return_value = ['pve1']
    fake._ha_check_vm_storage.return_value = 'shared'
    fake._ha_select_target_node.return_value = 'pve1'
    fake._ha_start_vm_on_node.return_value = True
    return fake


def _acted(fake):
    return {name: getattr(fake, name).call_count for name in (
        '_ha_acquire_recovery_lock', '_ha_check_node_via_ssh', '_ha_ssh_stop_vms_on_node',
        '_ha_fence_node', '_ha_start_vm_on_node')}


def _recovery_calls(lock, ssh, stop_vms, fence, start):
    return dict(_ha_acquire_recovery_lock=lock, _ha_check_node_via_ssh=ssh,
                _ha_ssh_stop_vms_on_node=stop_vms, _ha_fence_node=fence, _ha_start_vm_on_node=start)


@pytest.mark.parametrize('step_down_at,expected', [
    pytest.param(None, _recovery_calls(1, 1, 1, 1, 2), id='active-throughout'),
    pytest.param('start', _recovery_calls(0, 0, 0, 0, 0), id='standby-from-the-start'),
    pytest.param('delay', _recovery_calls(1, 0, 0, 0, 0), id='during-the-delay'),
    pytest.param('ssh-check', _recovery_calls(1, 1, 0, 0, 0), id='before-stopping-vms'),
    pytest.param('quorum', _recovery_calls(1, 1, 1, 0, 0), id='before-fencing'),
    pytest.param('first-vm', _recovery_calls(1, 1, 1, 1, 1), id='between-vms'),
])
def test_a_recovery_stops_at_the_next_step_once_this_instance_is_a_standby(
        step_down_at, expected, env, monkeypatch):
    """Between a step-down and the restart that follows it, the old active must not
    fence a node or start VMs next to the new active."""
    import pegaprox.core.manager as mgrmod
    _be('standby' if step_down_at == 'start' else 'active')
    fake = _recovery_fake()
    naps = []

    def nap(seconds):
        naps.append(seconds)
        if (step_down_at, seconds) in (('delay', 30), ('first-vm', 2)):
            _switch_role('standby')
    monkeypatch.setattr(mgrmod, 'time', types.SimpleNamespace(sleep=nap))

    def flip(result):
        def side(*a, **kw):
            _switch_role('standby')
            return result
        return side
    if step_down_at == 'ssh-check':
        fake._ha_check_node_via_ssh.side_effect = flip(fake._ha_check_node_via_ssh.return_value)
    if step_down_at == 'quorum':
        fake._ha_check_quorum.side_effect = flip(True)

    mgrmod.PegaProxManager._ha_recovery_worker(fake, 'pve2')

    assert _acted(fake) == expected
    # asking whether the recovery may run writes the cluster claim: after the delay,
    # and not at all once this instance stepped down
    assert fake._ha_recovery_allowed.call_count == (0 if step_down_at in ('start', 'delay') else 1)
    if step_down_at == 'start':
        assert naps == [] and fake._ha_release_recovery_lock.call_count == 0
        assert 'pve2' not in fake.ha_recovery_in_progress


@pytest.mark.parametrize('which', ROLES)
def test_the_xcpng_balancer_does_nothing_on_a_standby_whoever_calls(which, env):
    from pegaprox.core.xcpng import XcpngManager
    _be(which)
    fake = MagicMock()
    fake.get_node_status.return_value = {}

    XcpngManager.run_balance_check(fake)

    assert fake.get_node_status.call_count == (0 if which == 'standby' else 1)


def test_the_vmid_lookup_can_leave_the_map_alone(env):
    db = env.db
    _insert(db, 'xcpng_vmid_map', cluster_id='xcp1', uuid='u-known', vmid=100)
    assert db.xcpng_get_vmid('xcp1', 'u-known', create=False) == 100
    assert db.xcpng_get_vmid('xcp1', 'u-new', create=False) is None
    assert _rows(db, 'xcpng_vmid_map') == [('xcp1', 'u-known', 100)]
    # the default still hands out the next id, for the clone and create paths
    assert db.xcpng_get_vmid('xcp1', 'u-new') == 101


def _xapi(vms, ha_pool=True):
    """A pool with one VM per (ref, uuid), all halted and on no host."""
    recs = {ref: {'uuid': uuid, 'name_label': f'vm {uuid}', 'power_state': 'Halted',
                  'resident_on': 'OpaqueRef:NULL', 'VBDs': [], 'metrics': 'OpaqueRef:NULL',
                  'guest_metrics': 'OpaqueRef:NULL', 'is_a_template': False,
                  'is_control_domain': False, 'is_a_snapshot': False, 'VCPUs_at_startup': 1,
                  'VCPUs_max': 1, 'memory_dynamic_max': 1024, 'memory_target': 1024}
            for ref, uuid in vms.items()}
    ns = types.SimpleNamespace
    return ns(
        host=ns(get_all=lambda: [], get_hostname=lambda ref: ''),
        VM=ns(get_all=lambda: list(recs), get_record=recs.__getitem__,
              get_is_a_template=lambda ref: False, get_is_control_domain=lambda ref: False,
              get_ha_restart_priority=lambda ref: 'restart',
              get_name_label=lambda ref: recs[ref]['name_label'],
              get_uuid=lambda ref: recs[ref]['uuid'], get_order=lambda ref: 0,
              get_start_delay=lambda ref: 0),
        pool=ns(get_all=lambda: ['OpaqueRef:pool'],
                get_record=lambda ref: {'ha_enabled': ha_pool, 'ha_host_failures_to_tolerate': 1,
                                        'ha_plan_exists_for': 1}),
    )


@pytest.mark.parametrize('which', ROLES)
def test_an_xcpng_vm_without_an_id_waits_for_the_sync_on_a_standby(which, env):
    """The id map is synced: a standby that numbered a VM itself could give it
    another id than the active does, and ACLs by id would then name another VM."""
    from pegaprox.core.xcpng import XcpngManager
    _be(which)
    _insert(env.db, 'xcpng_vmid_map', cluster_id='xcp1', uuid='u-known', vmid=100)
    api = _xapi({'OpaqueRef:1': 'u-known', 'OpaqueRef:2': 'u-new'})
    fake = types.SimpleNamespace(id='xcp1', _api=lambda: api, logger=MagicMock())

    vms = XcpngManager._fetch_vms(fake, api)
    protected = XcpngManager.get_ha_status(fake)['protected_vms']

    if which == 'standby':
        assert [v['vmid'] for v in vms] == [100] and [v['vmid'] for v in protected] == [100]
        assert _rows(env.db, 'xcpng_vmid_map') == [('xcp1', 'u-known', 100)]
    else:
        assert sorted(v['vmid'] for v in vms) == [100, 101]
        assert sorted(v['vmid'] for v in protected) == [100, 101]
        assert len(_rows(env.db, 'xcpng_vmid_map')) == 2


@pytest.mark.parametrize('which', ROLES)
def test_an_efficient_snapshot_refresh_shows_the_stored_rows_on_a_standby(which, env, monkeypatch):
    """The refresh SSHes to the node, may lvextend there and writes a synced table."""
    import pegaprox.core.manager as mgrmod
    _be(which)
    stored = [{'id': 's1', 'node': 'pve1', 'vg_name': 'vg0', 'status': 'active', 'vm_type': 'qemu',
               'snapname': 'before-upgrade',
               'disks': [{'snap_lv': 'snap-100', 'original_lv': 'vm-100-disk-0', 'snap_alloc_gb': 10}]}]
    fake_db = MagicMock()
    fake_db.get_efficient_snapshots.return_value = copy.deepcopy(stored)
    monkeypatch.setattr(mgrmod, 'get_db', lambda: fake_db)
    fake = MagicMock()
    fake._node_ssh_exec.side_effect = lambda node, cmd, **kw: (
        (0, 'snap-100|10|95|\n', '') if cmd.startswith('lvs') else (0, '100\n', ''))
    fake._get_vm_lvm_disks.return_value = [{'lv_name': 'vm-100-disk-0', 'vg_name': 'vg0'}]

    result = mgrmod.PegaProxManager.get_efficient_snapshots(fake, 'pve1', 100, refresh_usage=True)

    commands = [c.args[1] for c in fake._node_ssh_exec.call_args_list]
    if which == 'standby':
        assert result == stored and commands == []
        assert fake_db.update_efficient_snapshot_disks.call_count == 0
        assert fake_db.update_efficient_snapshot_status.call_count == 0
    else:
        assert any(c.startswith('lvextend') for c in commands)
        assert fake_db.update_efficient_snapshot_disks.call_count == 1


@pytest.mark.parametrize('which', ROLES)
def test_the_metrics_collector_keeps_to_the_api_on_a_standby(which, env, monkeypatch):
    import pegaprox.background.metrics as metrics
    import pegaprox.api.nodes as nodes_api
    _be(which)
    probes = []
    monkeypatch.setattr(metrics, '_node_hottest_temp',
                        lambda m, n: probes.append(('ssh-sensors', n)) or 51.0)
    monkeypatch.setattr(metrics, '_node_hw_summary',
                        lambda m, n: probes.append(('bmc', n)) or {'available': False})
    monkeypatch.setattr(metrics, '_node_hw_summary_redfish',
                        lambda m, c, n: probes.append(('redfish', n)) or {'available': True, 'health': 'ok'})
    monkeypatch.setattr(metrics, 'run_per_node',
                        lambda calls, **kw: {name: fn(name) for name, fn in calls.items()})
    monkeypatch.setattr(nodes_api, '_hw_consent_state', lambda: (True, {}))
    monkeypatch.setattr(nodes_api, '_redfish_consent_state', lambda: (True, {}))
    storage = {'data': [{'storage': 'local', 'maxdisk': 100, 'disk': 25}]}
    session = types.SimpleNamespace(get=lambda url, timeout=None: types.SimpleNamespace(
        status_code=200, json=lambda: storage))
    mgr = types.SimpleNamespace(
        is_connected=True, config=types.SimpleNamespace(name='Lab'), cluster_type='proxmox',
        nodes={'pve1': {'status': 'online', 'cpu': 0.25, 'maxcpu': 8, 'mem': 4, 'maxmem': 16}},
        get_vm_resources=lambda: [{'type': 'qemu', 'status': 'running', 'vmid': 100, 'cpu': 0.5,
                                   'mem': 1, 'maxmem': 2, 'maxcpu': 2}],
        host='10.0.0.1', api_port=8006, _create_session=lambda: session)
    monkeypatch.setattr(metrics, 'cluster_managers', {'pve1': mgr})

    snap = metrics.collect_metrics_snapshot()

    lab = snap['clusters']['pve1']
    # what the API gives is there in every role
    assert lab['nodes']['pve1']['cpu'] == 25.0 and lab['totals']['vms_running'] == 1
    assert lab['vms']['100']['cpu'] == 50.0 and lab['storage']['local']['pct'] == 25.0
    if which == 'standby':
        assert probes == [] and 'temp' not in lab['nodes']['pve1']
    else:
        assert probes == [('ssh-sensors', 'pve1'), ('bmc', 'pve1'), ('redfish', 'pve1')]
        assert lab['nodes']['pve1']['temp'] == 51.0


# --- managers started the way main() starts them ------------------------------------------

def _pve_answer(url):
    path = url.split('/api2/json', 1)[-1]
    if path == '/access/ticket':
        return {'data': {'ticket': 'PVE:root@pam:TICKET', 'CSRFPreventionToken': 'csrf',
                         'username': 'root@pam'}}
    if path.startswith('/access/users/') and '/token/' in path:
        return {'data': {'full-tokenid': 'root@pam!pegaprox_123456', 'value': 'minted-secret'}}
    if path == '/nodes':
        return {'data': [{'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'online'}]}
    if path == '/version':
        return {'data': {'version': '9.0.10'}}
    return {'data': []}


class _OnePass:
    """A manager's stop_event that lets its loop run exactly one pass."""

    def __init__(self):
        self._set = False

    def is_set(self):
        return self._set

    def wait(self, timeout=None):
        self._set = True
        return True

    def set(self):
        self._set = True

    def clear(self):
        self._set = False


# every way manager.py reaches a node over SSH, and what each gives back on failure
SSH_LAYER = {
    '_ssh_run_command_output': None, '_ssh_run_command_with_key_output': None,
    '_ssh_run_command_with_password_output': None, '_ssh_run_command': False,
    '_ssh_run_command_with_key': False, '_ssh_run_command_with_password': False,
    '_ssh_connect': None, '_ssh_execute': (255, '', ''), '_node_ssh_exec': (255, '', 'no SSH here'),
    '_ssh_node_output': '', '_ssh_node_output_ex': ('', '', 255),
}


@pytest.mark.parametrize('which', ['standby', 'active'])
def test_live_view_managers_leave_the_nodes_and_the_synced_rows_alone(which, env, tmp_path, monkeypatch):
    """A Proxmox cluster whose synced row says HA is on with self-fence agents installed
    and no fallback hosts yet, and an XCP-ng pool with a VM the id map does not know.
    Started through app._start_managers, one pass of each loop, then stop().

    On the standby: no SSH to any node, the clusters rows and the id map as they
    were, no API token minted - and still connected, reading. The active run of the
    same test is the counterproof: it discovers and saves, mints the token, numbers
    the VM and, on stop(), stops the agents on the nodes."""
    import pegaprox.app as app_mod
    import pegaprox.core.manager as mgrmod
    import pegaprox.core.xcpng as xcpmod
    from pegaprox.core.config import load_config
    _be(which)
    db = env.db
    _seed_cluster(db, ha_enabled=True, ha_settings={'self_fence_installed': True}, fallback_hosts=[])
    _seed_cluster(db, 'xcp1', name='Pool', host='10.0.1.1', user='root', cluster_type='xcpng')
    _insert(db, 'xcpng_vmid_map', cluster_id='xcp1', uuid='u-known', vmid=100)
    clusters_before, vmids_before = _rows(db, 'clusters'), _rows(db, 'xcpng_vmid_map')
    monkeypatch.setattr(mgrmod, 'LOG_DIR', str(tmp_path))
    monkeypatch.setattr(xcpmod, 'LOG_DIR', str(tmp_path))

    # PVE on the wire
    http = []

    def send(adapter, request, **kw):
        http.append((request.method, request.url))
        resp = requests.Response()
        resp.status_code, resp.url, resp.request, resp.encoding = 200, request.url, request, 'utf-8'
        resp._content = json.dumps(_pve_answer(request.url)).encode()
        resp._content_consumed = True
        return resp
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    # the SSH layer
    ssh = []
    for name, result in SSH_LAYER.items():
        monkeypatch.setattr(mgrmod.PegaProxManager, name,
                            lambda self, *a, _n=name, _r=result, **kw: ssh.append((_n,) + a) or _r)
    node_ips = {'pve1': '10.0.0.1', 'pve2': '10.0.0.2'}
    monkeypatch.setattr(mgrmod.PegaProxManager, '_get_node_ip', lambda self, node: node_ips.get(node))
    # XAPI
    api = _xapi({'OpaqueRef:1': 'u-known', 'OpaqueRef:2': 'u-new'})

    def xapi_connect(self):
        self._session, self.is_connected, self.current_host = object(), True, self.config.host
        return True
    monkeypatch.setattr(xcpmod.XcpngManager, 'connect', xapi_connect)
    monkeypatch.setattr(xcpmod.XcpngManager, '_api', lambda self: api)
    # threads are noted; the test runs each loop for one pass itself
    threads = {mgrmod: _Threads(), xcpmod: _Threads()}
    for module, fake in threads.items():
        monkeypatch.setattr(module, 'threading', fake)

    app_mod._start_managers(load_config())
    pve, xcp = g.cluster_managers['pve1'], g.cluster_managers['xcp1']
    try:
        for t in threads[mgrmod].made + threads[xcpmod].made:
            if t.target.__name__ in ('daemon_loop', '_ip_refresh_loop', '_run_loop'):
                t.target.__self__.stop_event = _OnePass()
                t.target(*t.args, **t.kwargs)
        visible = xcp.get_vms()
        protected = xcp.get_ha_status()['protected_vms']
        before_stop = len(ssh)
        started = len(threads[mgrmod].made)
        pve.stop()
        xcp.stop()
        for t in threads[mgrmod].made[started:]:
            t.target(*t.args, **t.kwargs)
    finally:
        for m in (pve, xcp):
            for h in list(m.logger.handlers):
                h.close()
                m.logger.removeHandler(h)

    agents_stopped = [c for c in ssh[before_stop:]
                      if 'systemctl stop pegaprox-fence-agent.service' in ' '.join(map(str, c))]
    token_posts = [u for method, u in http if method == 'POST' and '/token/' in u]
    assert ('POST', 'https://10.0.0.1:8006/api2/json/access/ticket') in http
    if which == 'standby':
        assert ssh == []
        assert _rows(db, 'clusters') == clusters_before
        assert _rows(db, 'xcpng_vmid_map') == vmids_before
        assert token_posts == []
        assert [v['vmid'] for v in visible] == [100] and [v['vmid'] for v in protected] == [100]
        # live all the same: connected, reading, and failing over on its own findings
        assert pve.is_connected and pve.config.fallback_hosts == ['10.0.0.2']
    else:
        assert len(agents_stopped) >= 2, ssh
        assert len(_rows(db, 'xcpng_vmid_map')) == 2 and len(visible) == 2
        assert token_posts and pve.config.fallback_hosts == ['10.0.0.2']
        # (the active discovers inside start(), before main() registers the manager, so
        # that save_config finds nothing to write yet; the row itself is covered by
        # test_save_config_leaves_the_clusters_rows_alone_on_a_standby)


# --- main() -------------------------------------------------------------------------------
# main() cannot run in a test (it binds a port), so these read it, like the boot
# wiring tests in tests/test_ha_api.py.

def _callee(call):
    f = call.func
    return f.id if isinstance(f, ast.Name) else getattr(f, 'attr', None)


def _names(nodes):
    return {_callee(n) for node in nodes for n in ast.walk(node) if isinstance(n, ast.Call)}


def _lines(fn, name):
    return [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Call) and _callee(n) == name]


def _main():
    import pegaprox.app as app_mod
    return ast.parse(inspect.getsource(app_mod.main)).body[0]


MANAGER_STARTERS = ('PegaProxManager', 'XcpngManager', 'ESXiClusterManager', 'load_pbs_servers',
                    'load_vmware_servers', 'start')


def test_main_starts_the_managers_wherever_managers_wanted_says_so():
    """One helper for every role: an acting instance and a standby with the live view
    start them, a standby without it (managers_wanted() False) does not."""
    import pegaprox.app as app_mod
    fn = _main()
    assigned = {ast.unparse(n.targets[0]): ast.unparse(n.value)
                for n in fn.body if isinstance(n, ast.Assign) and len(n.targets) == 1}
    assert assigned['live_managers'] == 'ha.managers_wanted()'
    assert assigned['standby'] == 'ha.is_standby()'

    gates = [n for n in fn.body if isinstance(n, ast.If) and ast.unparse(n.test) == 'live_managers']
    assert len(gates) == 1 and not gates[0].orelse
    assert {'_start_managers', 'note_managers_started', 'manager_signature'} <= _names(gates[0].body)
    assert len(_lines(fn, '_start_managers')) == 1, 'the helper is the only way in'
    # nothing in main() builds a manager past the helper
    assert not {'PegaProxManager', 'XcpngManager', 'ESXiClusterManager', 'load_pbs_servers',
                'load_vmware_servers'} & _names(fn.body)
    helper = ast.parse(inspect.getsource(app_mod._start_managers)).body[0]
    assert set(MANAGER_STARTERS) <= _names(helper.body)
    # and the helper asks nobody about the role: that is main()'s one decision
    assert not {'is_standby', 'is_active', 'managers_wanted', 'role'} & _names(helper.body)


def test_main_pulls_once_before_a_live_standby_starts_its_managers():
    fn = _main()
    branch = [n for n in fn.body if isinstance(n, ast.If)
              and ast.unparse(n.test) == 'standby and live_managers']
    assert len(branch) == 1
    pulls = [n for n in ast.walk(branch[0]) if isinstance(n, ast.Call) and _callee(n) == 'boot_pull']
    assert len(pulls) == 1 and len(_lines(fn, 'boot_pull')) == 1
    assert pulls[0] in [n for stmt in branch[0].body for n in ast.walk(stmt)]
    assert [(k.arg, getattr(k.value, 'value', None)) for k in pulls[0].keywords] == [('timeout', 10)]
    # a standby with the live view off says so and goes the v1 way
    v1 = branch[0].orelse
    assert len(v1) == 1 and ast.unparse(v1[0].test) == 'standby' and 'live view off' in ast.unparse(v1[0])
    order = [min(_lines(fn, name)) for name in ('managers_wanted', 'boot_pull', 'load_config',
                                                '_start_managers', 'note_managers_started',
                                                'start_loop')]
    assert order == sorted(order)


def test_the_manager_start_block_behaves_by_role(env, monkeypatch):
    """The decision in main(), run: the few statements from the role to the helper,
    with the helper and the pull replaced by recorders."""
    import pegaprox.app as app_mod
    fn = _main()
    first = next(i for i, n in enumerate(fn.body) if isinstance(n, ast.Assign)
                 and ast.unparse(n.targets[0]) == 'standby')
    last = next(i for i, n in enumerate(fn.body) if isinstance(n, ast.If)
                and ast.unparse(n.test) == 'live_managers')
    block = ast.Module(body=fn.body[first:last + 1], type_ignores=[])
    code = compile(ast.fix_missing_locations(block), 'main-block', 'exec')

    def run(role, **state):
        _be(role, **state)
        seen = []
        monkeypatch.setattr(ha, 'boot_pull', lambda timeout: seen.append(('pull', timeout)) or 'applied')
        monkeypatch.setattr(ha, 'note_managers_started', lambda sig: seen.append(('noted', len(sig))))
        scope = {'ha': ha, 'logging': app_mod.logging,
                 'load_config': lambda: seen.append(('load',)) or {},
                 '_start_managers': lambda config: seen.append(('managers',))}
        exec(code, scope)
        return seen

    assert run('standby') == [('pull', 10), ('load',), ('managers',), ('noted', 64)]
    assert run('standby', live_view=False) == [('load',)]
    assert run('active', live_view=False) == [('load',), ('managers',), ('noted', 64)]
    assert run('standalone') == [('load',), ('managers',), ('noted', 64)]
