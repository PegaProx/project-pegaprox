"""The recovery lock on the storage heartbeat path (#625, stage two S0).

One file per epoch and instance under .pegaprox/recovery/<node>/, made with O_EXCL.
The single file before named every instance "pegaprox_<cluster id>", the same on
every member, so each one took the lock as its own; and a worker that lost returned
through a finally that deleted the winner's lock.

The managers here are PegaProxManager objects without __init__, carrying only what
the lock reads. Who "this instance" is comes from ha.lock_holder, swapped per test,
except where the test is about lock_holder itself. One process holds a node directory
once; a second instance is another process, with its own record of who holds what
(_another_process).

MK Oct 2026
"""
import contextlib
import json
import os
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as manager_mod
from pegaprox.core import ha
from pegaprox.core.manager import PegaProxManager
from test_ha_core import env, _write_state, _key_next_to_the_db, _fake_active, ZK  # noqa: F401

A = 'a' * 32
B = 'b' * 32
C = 'c' * 32


@pytest.fixture
def storage(tmp_path):
    root = tmp_path / 'shared'
    (root / '.pegaprox').mkdir(parents=True)
    return root


@pytest.fixture(autouse=True)
def _no_holder_left():
    """The record of who holds a directory lives as long as the process: a test leaves
    nothing in it, and no refreshing behind."""
    yield
    with manager_mod._recovery_lock_guard:
        held = list(manager_mod._recovery_lock_owners.values())
        manager_mod._recovery_lock_owners.clear()
    for _owner, stop in held:
        if stop is not None:
            stop.set()


@contextlib.contextmanager
def _another_process():
    """What a second PegaProx process sees: none of the holders of this one."""
    saved = manager_mod._recovery_lock_owners
    manager_mod._recovery_lock_owners = {}
    try:
        yield
    finally:
        manager_mod._recovery_lock_owners = saved


@pytest.fixture
def audits(monkeypatch):
    seen = []
    import pegaprox.utils.audit as audit
    monkeypatch.setattr(audit, 'log_audit', lambda user, action, details, **kw: seen.append((action, details)))
    return seen


def _mgr(storage, cid='c1'):
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = cid
    m.config = types.SimpleNamespace(name='lab', ha_enabled=True)
    m.ha_config = {'storage_heartbeat_path': str(storage), 'storage_heartbeat_enabled': True,
                   'poison_pill_enabled': True}
    m.ha_recovery_locks = {}
    m.logger = MagicMock()
    return m


def _as(monkeypatch, instance, epoch):
    monkeypatch.setattr(ha, 'lock_holder', lambda: (instance, epoch))


def _lock_dir(storage, node='pve2'):
    return storage / '.pegaprox' / 'recovery' / node


def _files(storage, node='pve2'):
    d = _lock_dir(storage, node)
    return sorted(os.listdir(d)) if d.exists() else []


def _plant(storage, name, age=0, node='pve2'):
    d = _lock_dir(storage, node)
    d.mkdir(parents=True, exist_ok=True)
    path = d / name
    path.write_text('{}')
    if age:
        then = time.time() - age
        os.utime(path, (then, then))
    return path


def test_the_lock_is_a_file_per_epoch_and_instance_made_with_o_excl(storage, monkeypatch):
    _as(monkeypatch, A, 3)
    flags = []
    real_open = os.open

    def recording(path, f, *a, **kw):
        if '/recovery/' in str(path):
            flags.append(f)
        return real_open(path, f, *a, **kw)
    monkeypatch.setattr(os, 'open', recording)
    m = _mgr(storage)

    assert m._ha_acquire_recovery_lock('pve2') is True

    assert _files(storage) == [f'3-{A}']
    assert flags and all(f & os.O_EXCL and f & os.O_CREAT for f in flags)
    body = json.loads((_lock_dir(storage) / f'3-{A}').read_text())
    assert (body['instance_id'], body['epoch'], body['node'], body['cluster_id']) == (A, 3, 'pve2', 'c1')


def test_a_second_instance_under_the_same_epoch_is_refused_and_says_so(storage, monkeypatch, audits):
    """Two standalones on one cluster, or two actives of one epoch: the first one
    recovers, the second one does nothing and raises the alarm. Before, both held
    the lock as 'pegaprox_c1'."""
    a, b = _mgr(storage), _mgr(storage)
    _as(monkeypatch, A, 0)
    assert a._ha_acquire_recovery_lock('pve2') is True
    _as(monkeypatch, B, 0)

    with _another_process():
        assert b._ha_acquire_recovery_lock('pve2') is False

    assert _files(storage) == [f'0-{A}']
    assert b.ha_recovery_locks == {}
    assert [act for act, _ in audits] == ['ha.recovery_lock_conflict']
    assert A in audits[0][1] and 'same epoch' in audits[0][1]
    assert str(_lock_dir(storage) / f'0-{A}') in audits[0][1]


def test_two_instances_with_their_own_cluster_ids_still_see_each_other(storage, monkeypatch, audits):
    """Each instance numbers the clusters it added itself, so the same PVE cluster has
    another id on each of two standalones. The lock is per node name for that."""
    _as(monkeypatch, A, 0)
    assert _mgr(storage, cid='1a2b3c4d')._ha_acquire_recovery_lock('pve2') is True
    _as(monkeypatch, B, 0)
    with _another_process():
        assert _mgr(storage, cid='9f8e7d6c')._ha_acquire_recovery_lock('pve2') is False
    assert 'same epoch' in audits[0][1]


def test_a_higher_epoch_wins_and_the_stale_instance_steps_back(storage, monkeypatch, audits):
    _plant(storage, f'5-{B}')
    _as(monkeypatch, A, 4)
    m = _mgr(storage)

    assert m._ha_acquire_recovery_lock('pve2') is False

    assert _files(storage) == [f'5-{B}']
    assert 'stale' in audits[0][1] and str(_lock_dir(storage) / f'5-{B}') in audits[0][1]


def test_a_lower_epoch_is_a_former_holder_and_does_not_count(storage, monkeypatch, audits):
    _plant(storage, f'4-{B}')
    _as(monkeypatch, A, 5)

    assert _mgr(storage)._ha_acquire_recovery_lock('pve2') is True

    assert _files(storage) == [f'4-{B}', f'5-{A}']
    assert audits == []


@pytest.mark.parametrize('age,taken', [
    pytest.param(200, False, id='fresh-blocks'),
    pytest.param(PegaProxManager.RECOVERY_LOCK_STALE + 1, True, id='five-minutes-old-is-a-crash'),
])
def test_a_same_epoch_lock_of_a_crashed_instance_blocks_for_five_minutes(storage, monkeypatch, audits,
                                                                          age, taken):
    _plant(storage, f'0-{B}', age=age)
    _as(monkeypatch, A, 0)
    assert _mgr(storage)._ha_acquire_recovery_lock('pve2') is taken


@pytest.mark.parametrize('age,kept', [
    pytest.param(100, True, id='recent'),
    pytest.param(PegaProxManager.RECOVERY_LOCK_SWEEP + 1, False, id='an-hour-old'),
])
def test_locks_of_older_epochs_are_swept_after_an_hour(storage, monkeypatch, age, kept):
    _plant(storage, f'2-{B}', age=age)
    _as(monkeypatch, A, 3)

    assert _mgr(storage)._ha_acquire_recovery_lock('pve2') is True

    assert (f'2-{B}' in _files(storage)) is kept


def test_our_own_lock_from_before_a_restart_is_ours(storage, monkeypatch):
    mine = _plant(storage, f'3-{A}', age=200)
    _as(monkeypatch, A, 3)

    assert _mgr(storage)._ha_acquire_recovery_lock('pve2') is True

    assert time.time() - os.path.getmtime(mine) < 60, 'held from now on, not from before'


def test_release_takes_away_only_the_file_this_process_made(storage, monkeypatch):
    _plant(storage, f'2-{B}')
    _as(monkeypatch, A, 3)
    m = _mgr(storage)

    # nothing taken yet: a release gives back nothing, whoever's files lie there
    _plant(storage, f'3-{A}')
    m._ha_release_recovery_lock('pve2')
    assert _files(storage) == [f'2-{B}', f'3-{A}']

    assert m._ha_acquire_recovery_lock('pve2') is True
    m._ha_release_recovery_lock('pve2')
    m._ha_release_recovery_lock('pve2')

    assert _files(storage) == [f'2-{B}']


def test_without_the_shared_storage_mounted_here_nothing_is_made(tmp_path, monkeypatch):
    _as(monkeypatch, A, 3)
    m = _mgr(tmp_path / 'not-mounted')

    assert m._ha_acquire_recovery_lock('pve2') is False

    assert not (tmp_path / 'not-mounted').exists()


@pytest.mark.parametrize('node', ['../etc', '', '.hidden', 'a/b'])
def test_a_node_name_that_is_no_name_takes_no_lock(storage, monkeypatch, node):
    _as(monkeypatch, A, 3)
    assert _mgr(storage)._ha_acquire_recovery_lock(node) is False
    assert not (storage / '.pegaprox' / 'recovery').exists()


def test_a_restarted_standalone_finds_its_own_lock(storage, tmp_path, monkeypatch):
    """A standalone that never paired has saved no state: its instance id was a new one
    at every start, so its lock from before a restart read as somebody else's and
    blocked its own recovery for five minutes. lock_holder saves the id first."""
    monkeypatch.setattr(ha, 'STATE_FILE', str(tmp_path / 'ha_state.json'))
    ha.reset_for_tests()
    assert not os.path.exists(ha.STATE_FILE)

    assert _mgr(storage)._ha_acquire_recovery_lock('pve2') is True
    first = ha.instance_id()
    ha.reset_for_tests()                      # the restart
    with _another_process():
        assert _mgr(storage)._ha_acquire_recovery_lock('pve2') is True

    assert ha.instance_id() == first and _files(storage) == [f'0-{first}']
    assert ha.role() == 'standalone' and ha.public_status()['broken'] == ''


# --- what a file left behind does ---------------------------------------------------

@pytest.mark.parametrize('age', [
    pytest.param(10, id='a-restart-a-moment-ago'),
    pytest.param(7 * 86400, id='an-unpairing-days-ago'),
])
def test_a_file_of_ours_under_any_epoch_is_ours(storage, monkeypatch, audits, age):
    """A recovery under epoch 5 was cut short (a role change restarts the process, so do
    an update and a crash) and its file stayed. The instance was unpaired since, its
    epoch is 0 now. 5-A read as a higher epoch's lock, and only an acquirer with an
    epoch of at least 5 ever removed it: this node was never recovered again."""
    _plant(storage, f'5-{A}', age=age)
    _plant(storage, f'2-{A}', age=age)
    _as(monkeypatch, A, 0)

    assert _mgr(storage)._ha_acquire_recovery_lock('pve2') is True

    assert _files(storage) == [f'0-{A}']
    assert audits == []


@pytest.mark.parametrize('age,taken', [
    pytest.param(PegaProxManager.RECOVERY_LOCK_SWEEP - 60, False, id='refreshed-within-the-hour'),
    pytest.param(PegaProxManager.RECOVERY_LOCK_SWEEP + 60, True, id='an-hour-without-a-refresh'),
])
def test_a_higher_epoch_counts_while_its_holder_refreshes_it(storage, monkeypatch, audits, age, taken):
    """The former partner's file under epoch 7, and this instance runs a new group at
    epoch 1 (a group after an unpairing starts at 1). A holder refreshes its file while
    it recovers, so an hour without that is a holder that is gone."""
    theirs = os.path.realpath(_plant(storage, f'7-{B}', age=age))
    _as(monkeypatch, A, 1)

    assert _mgr(storage)._ha_acquire_recovery_lock('pve2') is taken

    if taken:
        assert _files(storage) == [f'1-{A}']
        assert [act for act, _ in audits] == ['ha.recovery_lock_expired']
    else:
        assert _files(storage) == [f'7-{B}']
        assert [act for act, _ in audits] == ['ha.recovery_lock_conflict']
    assert theirs in audits[0][1]


def test_the_holder_keeps_its_file_fresh_while_it_recovers(storage, monkeypatch, audits):
    """A recovery can run longer than RECOVERY_LOCK_STALE (one VM after another, the wait
    for a poison pill). A file that kept the time it was taken looked like a crashed
    holder's by then, and a second instance under the same epoch went ahead."""
    monkeypatch.setattr(PegaProxManager, 'RECOVERY_LOCK_REFRESH', 0.05)
    _as(monkeypatch, A, 0)
    a = _mgr(storage)
    assert a._ha_acquire_recovery_lock('pve2') is True
    mine = _lock_dir(storage) / f'0-{A}'
    then = time.time() - PegaProxManager.RECOVERY_LOCK_STALE - 60
    os.utime(mine, (then, then))                 # six minutes into the recovery

    deadline = time.time() + 5
    while time.time() - os.path.getmtime(mine) > 60 and time.time() < deadline:
        time.sleep(0.02)

    _as(monkeypatch, B, 0)
    with _another_process():
        assert _mgr(storage, cid='9f8e7d6c')._ha_acquire_recovery_lock('pve2') is False
    assert _files(storage) == [f'0-{A}']
    assert 'same epoch' in audits[0][1]

    # the release ends the refreshing: no complaint about a file that is gone
    a._ha_release_recovery_lock('pve2')
    time.sleep(0.2)
    assert _files(storage) == []
    assert not a.logger.error.called


def test_one_recovery_per_node_directory_in_this_process(storage, monkeypatch, audits):
    """The file names the instance, not the manager. A second manager here on the same
    directory (the same cluster added twice, or two clusters with a node of this name
    on one heartbeat path) met EEXIST on that name, took the file for its own from
    before a restart, and recovered next to the first. The first one's release then
    took the file away under the second."""
    _as(monkeypatch, A, 0)
    one, two = _mgr(storage, cid='c1'), _mgr(storage, cid='c2')
    assert one._ha_acquire_recovery_lock('pve2') is True

    assert two._ha_acquire_recovery_lock('pve2') is False

    assert _files(storage) == [f'0-{A}'] and two.ha_recovery_locks == {}
    assert [act for act, _ in audits] == ['ha.recovery_lock_conflict']
    assert str(_lock_dir(storage)) in audits[0][1] and 'in this PegaProx' in audits[0][1]
    # another node is another directory
    assert two._ha_acquire_recovery_lock('pve3') is True
    # the refused one gives back nothing, the holder its own, and then it is free
    two._ha_release_recovery_lock('pve2')
    assert _files(storage) == [f'0-{A}']
    one._ha_release_recovery_lock('pve2')
    assert _files(storage) == []
    assert two._ha_acquire_recovery_lock('pve2') is True
    assert _files(storage) == [f'0-{A}']


def test_a_lock_held_by_an_earlier_recovery_of_this_cluster_is_no_conflict(storage, monkeypatch, audits):
    """The recovery of a node that was back for a pass and down again, while the one
    of the outage before still waits out its delay with the lock: the same manager,
    not a cluster added twice. Refused, without the audit line that asks whether it
    is; the worker marks the node to be tried again (test_ha_recovery_midloop)."""
    _as(monkeypatch, A, 0)
    one = _mgr(storage)
    assert one._ha_acquire_recovery_lock('pve2') is True

    assert one._ha_acquire_recovery_lock('pve2') is False

    assert audits == [] and _files(storage) == [f'0-{A}'] and list(one.ha_recovery_locks) == ['pve2']
    one._ha_release_recovery_lock('pve2')
    assert _files(storage) == [] and one.ha_recovery_locks == {}


def test_the_directory_is_given_up_only_after_the_file(storage, monkeypatch, audits):
    """A second manager here that comes while the first one lets go: it must not meet
    the first one's file under its own name, take it for one left from before a
    restart, and then lose it to the first one's remove."""
    _as(monkeypatch, A, 0)
    one, two = _mgr(storage, cid='c1'), _mgr(storage, cid='c2')
    assert one._ha_acquire_recovery_lock('pve2') is True
    mine = os.path.realpath(_lock_dir(storage) / f'0-{A}')
    seen = []
    real_remove = os.remove

    def remove(path, *a, **kw):
        if str(path) == mine and not seen:
            seen.append(two._ha_acquire_recovery_lock('pve2'))
        return real_remove(path, *a, **kw)
    monkeypatch.setattr(os, 'remove', remove)

    one._ha_release_recovery_lock('pve2')

    assert seen == [False]
    assert two._ha_acquire_recovery_lock('pve2') is True
    assert _files(storage) == [f'0-{A}'] and two.ha_recovery_locks == {'pve2': mine}


@pytest.mark.parametrize('how', ['unpair', 'pair', 'join'])
def test_leaving_or_joining_a_group_takes_our_files_along(env, db, storage, monkeypatch, how):
    """After an unpairing the epoch is 0, in a group joined it is that group's: a file
    this instance left under its old epoch stood in the way of the group's active, one
    above its epoch for good. They go then, on every heartbeat path the managers use.
    Another instance's file stays, and so does one a recovery here holds right now."""
    import pegaprox.globals as g
    if how == 'unpair':
        _write_state(role='active', instance_id=A, epoch=5,
                     members={B: {'url': 'https://pp2.example:5000', 'role_seen': 'standby'}})
    elif how == 'pair':
        code, _ = ha.create_pairing_code('https://pp1.example:5000', '')
    me = ha.instance_id()
    monkeypatch.setitem(g.cluster_managers, 'c1', _mgr(storage, cid='c1'))
    monkeypatch.setitem(g.cluster_managers, 'c2', _mgr(storage, cid='c2'))   # the same path
    monkeypatch.setitem(g.cluster_managers, 'esxi', MagicMock())
    _plant(storage, f'9-{me}', age=2 * 86400)
    _plant(storage, f'9-{C}', age=60)
    _plant(storage, f'3-{me}', age=60, node='pve3')
    _as(monkeypatch, me, 9)
    holder = _mgr(storage, cid='c3')
    assert holder._ha_acquire_recovery_lock('pve4') is True

    if how == 'unpair':
        ha.unpair()
    elif how == 'pair':
        ha.accept_pairing(ha.decode_code(code)['secret'], B, 'https://pp2.example', '', ZK)
    else:
        _key_next_to_the_db(env)
        with open(ha.AES_KEY_FILE, 'wb') as fh:
            fh.write(db.aes_key)
        _fake_active(monkeypatch, 's' * 43, os.urandom(32))
        ha.join(ha.encode_code('https://pp1.example:5000', '', 's' * 43, A), 'https://pp2.example', '')

    assert ha.role() == {'unpair': 'standalone', 'pair': 'active', 'join': 'standby'}[how]
    assert _files(storage) == [f'9-{C}']
    assert _files(storage, node='pve3') == []
    assert _files(storage, node='pve4') == [f'9-{me}']


# --- the recovery worker ------------------------------------------------------------

def _worker_fake(acquired):
    fake = MagicMock()
    fake.ha_config = {'recovery_delay': 30, 'storage_heartbeat_enabled': True}
    fake.ha_lock = threading.Lock()
    fake.ha_node_status = {'pve2': {'status': 'offline'}}
    fake.ha_recovery_in_progress = {'pve2': True}
    fake._ha_acquire_recovery_lock.return_value = acquired
    fake._ha_get_vms_on_node.return_value = []
    fake._ha_check_node_via_ssh.return_value = {'reachable': False}
    fake._ha_check_node_agent_heartbeat.return_value = {'alive': False, 'age_seconds': None}
    fake.current_host, fake.is_connected, fake.session = '10.0.0.1', True, True
    return fake


@pytest.mark.parametrize('acquired', [
    pytest.param(False, id='lost-the-lock'),
    pytest.param(True, id='took-the-lock'),
])
def test_a_worker_gives_back_only_a_lock_it_took(monkeypatch, acquired):
    import pegaprox.core.manager as mgrmod
    monkeypatch.setattr(mgrmod, 'time', types.SimpleNamespace(sleep=lambda s: None))
    assert ha.is_active()
    fake = _worker_fake(acquired)

    PegaProxManager._ha_recovery_worker(fake, 'pve2')

    assert fake._ha_acquire_recovery_lock.call_count == 1
    assert bool(fake._ha_release_recovery_lock.call_count) is acquired
    assert 'pve2' not in fake.ha_recovery_in_progress


# --- what else lands on the shared storage ------------------------------------------

def test_the_poison_pill_names_the_instance_and_its_epoch(storage, monkeypatch):
    monkeypatch.setattr(ha, 'instance_id', lambda: A)
    monkeypatch.setattr(ha, 'epoch', lambda: 7)
    m = _mgr(storage)

    assert m._ha_write_poison_pill('pve2', 'test') is True

    pill = json.loads((storage / '.pegaprox' / 'poison_pve2').read_text())
    assert (pill['issued_by'], pill['epoch'], pill['cluster_id']) == (f'pegaprox_{A}', 7, 'c1')


def test_the_heartbeat_names_the_instance_and_its_epoch(storage, monkeypatch):
    monkeypatch.setattr(ha, 'instance_id', lambda: A)
    monkeypatch.setattr(ha, 'epoch', lambda: 7)
    m = _mgr(storage)
    m.current_host, m.ha_node_status = '10.0.0.1', {}
    m.ha_heartbeat_stop = threading.Event()
    m._ha_check_poison_pills = m.ha_heartbeat_stop.set    # one pass

    m._ha_storage_heartbeat_writer()

    beat = json.loads((storage / '.pegaprox' / 'heartbeat_pegaprox_c1').read_text())
    assert (beat['instance_id'], beat['epoch'], beat['cluster_id']) == (A, 7, 'c1')
