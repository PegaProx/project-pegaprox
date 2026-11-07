"""Confirm before each step, interrupted recoveries and schedules across a change of
leader (#625 stage 2, design 5.2, 5.6 and 5.7; slice S4).

  * a leader that loses its lease in the middle of an automation starts no further step
  * each step of the table below asks for a confirmed lease and does not start without
    one (tests/test_ha_exits.py proves the order in the source for every site)
  * a node recovery writes each step before and after into ha_recovery_journal, in an
    automatic group only; what a leader left half done survives a restart and is listed
  * schedules: a new leader skips the minute the former one may have fired, a schedule
    is written before it acts, and what fell due without a leader is reported

MK Oct 2026 (#625)
"""
import types
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from pegaprox.core import ha as _ha
from test_ha_members import IDS, group  # noqa: F401
from _ha_lease_harness import T, auto  # noqa: F401


def _balancer(nodes=8):
    fake = MagicMock()
    fake.config.auto_migrate, fake.config.dry_run = True, False
    fake.config.excluded_nodes, fake.config.predictive_balancing = [], False
    fake.config.name = 'c1'
    fake.get_node_status.return_value = {f'n{i}': {'status': 'online', 'score': 10 * i}
                                         for i in range(nodes)}
    fake.check_balance_needed.return_value = (True, 'n7', 'n0')
    fake.find_migration_candidate.side_effect = lambda *a, **k: {'vmid': 100 + len(fake.migrated),
                                                                 'name': 'vm'}
    fake._vm_migration_cooldown = {}
    fake._enforce_affinity_rules.return_value = 0
    fake.migrated = []
    return fake


# --- a leader that loses its lease mid-automation -----------------------------------------

def test_a_leader_that_loses_its_lease_mid_balance_starts_no_further_migration(auto, seed):
    from pegaprox.core.manager import PegaProxManager
    auto.form(seed)
    fake = _balancer()

    def migrate(vm, target):
        fake.migrated.append(vm['vmid'])
        # the link to every voter goes right after the first migration was sent
        auto.isolate('a')
        return True
    fake.migrate_vm.side_effect = migrate
    with auto.at('a') as ha:
        assert ha.is_active()
        PegaProxManager.run_balance_check(fake, force=True)
        # the lease itself still runs: only the confirm round found no majority
        assert ha.is_active()
    assert fake.migrated == [100]


def test_with_the_lease_held_the_balance_goes_on(auto, seed):
    from pegaprox.core.manager import PegaProxManager
    auto.form(seed)
    fake = _balancer()
    fake.migrate_vm.side_effect = lambda vm, target: fake.migrated.append(vm['vmid']) or True
    with auto.at('a'):
        PegaProxManager.run_balance_check(fake, force=True)
    assert fake.migrated == [100, 101, 102]


def test_a_recovery_that_loses_the_lease_after_the_move_starts_nothing_and_leaves_it_listed(
        auto, seed, db, monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgr_mod
    auto.form(seed)
    _no_sleep(monkeypatch, mgr_mod)
    m = PegaProxManager.__new__(PegaProxManager)
    m.id, m.logger = 'c1', MagicMock()
    m.config = types.SimpleNamespace(user='root@pam', host='10.0.0.1', name='c1')
    m.current_host, m.ha_config, m._using_api_token = '10.0.0.1', {}, False
    session = MagicMock()
    # the config is on the target (status/current answers): only the confirm stops the start
    session.get.return_value.status_code = 200
    m._create_session = lambda: session
    m._ha_clear_vm_lock = MagicMock(return_value=True)

    def moved(*a):
        auto.isolate('a')
        return True
    m._ha_move_vm_config = MagicMock(side_effect=moved)
    m._ha_fence_node = MagicMock(return_value=False)
    m._ha_node_back = MagicMock(return_value=False)      # pve2 stays down
    with auto.at('a') as ha:
        run = ha.recovery_begin('c1', 'pve2')
        m.__dict__['_ha_recovery_runs'] = {'pve2': run}
        assert m._ha_start_vm_on_node(101, 'qemu', 'pve1', 'pve2') is False
        session.post.assert_not_called()
        # the process ends (the lease is gone): the next leader reads the journal
        ha._recovery_live.clear()
        left = ha.recovery_leftovers('c1')
    assert len(left) == 1 and left[0]['node'] == 'pve2' and left[0]['moved'] == [101]
    # the start was written down (and sent on) before its round, which said no
    assert left[0]['open'] == ['start 101'] and left[0]['instance_id'] == IDS['a']


# --- each step asks, and does not start without a confirmed lease ---------------------------

def _no_sleep(monkeypatch, module):
    import time as _time
    monkeypatch.setattr(module, 'time', types.SimpleNamespace(
        sleep=lambda s: None, time=_time.time, monotonic=_time.monotonic,
        strftime=_time.strftime, perf_counter=_time.perf_counter))


@pytest.fixture
def denied(monkeypatch):
    """confirm_step answers no and says what it was asked for."""
    asked = []
    monkeypatch.setattr(_ha, 'confirm_step',
                        lambda what, need=_ha.NEED_STEP: asked.append((what, need)) and False)
    return asked


def _site_balance(monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    fake = _balancer()
    PegaProxManager.run_balance_check(fake, force=True)
    return fake.migrate_vm.call_count


def _site_affinity(monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgr_mod
    fake = MagicMock()
    fake.id = 'c1'
    fake.config.balance_containers, fake.config.balance_local_disks = True, False
    fake.config.excluded_nodes = []
    fake._derive_proxlb_tag_rules.return_value = {'rules': [], 'ignored': set(), 'pins': {}}
    fake.get_vm_resources.return_value = [
        {'vmid': 1, 'type': 'qemu', 'status': 'running', 'node': 'n1'},
        {'vmid': 2, 'type': 'qemu', 'status': 'running', 'node': 'n1'}]
    rules = {'c1': [{'type': 'separate', 'enforce': True, 'vm_ids': [1, 2], 'name': 'r'}]}
    monkeypatch.setattr(mgr_mod, 'get_db', lambda: types.SimpleNamespace(get_affinity_rules=lambda cid: rules))
    try:
        PegaProxManager._enforce_affinity_rules(fake, {'n1': {'status': 'online', 'score': 1},
                                                       'n2': {'status': 'online', 'score': 2}})
    except RuntimeError:
        # a move to a node no rule member was on adds to the dict it walks (an older
        # bug, run_balance_check catches it); the migration went out before it
        pass
    return fake.migrate_vm.call_count


def _site_xcpng_balance(monkeypatch):
    from pegaprox.core.xcpng import XcpngManager
    import pegaprox.core.xcpng as xcpng_mod
    _no_sleep(monkeypatch, xcpng_mod)
    fake = MagicMock()
    fake.get_node_status.return_value = {'h1': {}, 'h2': {}, 'h3': {}, 'h4': {}}
    fake.check_balance_needed.side_effect = [(True, 'h1', 'h2'), (False, None, None)]
    fake.find_migration_candidate.return_value = {'vmid': 5, 'storage_type': 'shared'}
    XcpngManager.run_balance_check(fake)
    return fake._do_balance_migrate.call_count


def _site_restore_quorum(monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    fake = MagicMock()
    fake.ha_config = {'two_node_mode': True}
    fake.ha_node_status = {'n1': {'status': 'online'}, 'n2': {'status': 'online'}}
    fake._ha_get_node_ip.return_value = '10.0.0.1'
    fake.config.user, fake.config.pass_, fake.config.ssh_key = 'root@pam', 'pw', 'KEY'
    fake._ha_claimed.side_effect = lambda c: c
    PegaProxManager._ha_check_restore_quorum(fake)
    return (fake._ssh_run_command.call_count + fake._ssh_run_command_with_key.call_count
            + fake._ssh_run_command_with_password.call_count)


def _site_start_vm(monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgr_mod
    _no_sleep(monkeypatch, mgr_mod)
    fake = MagicMock()
    fake.ha_config = {}
    fake.__dict__['_ha_recovery_runs'] = {}
    fake._ha_clear_vm_lock.return_value = True
    fake._ha_move_vm_config.return_value = True
    fake._create_session.return_value.post.return_value.status_code = 200
    PegaProxManager._ha_start_vm_on_node(fake, 101, 'qemu', 'pve1', 'pve2')
    return (fake._ha_fence_node.call_count + fake._ha_clear_vm_lock.call_count
            + fake._ha_move_vm_config.call_count + fake._create_session.return_value.post.call_count)


def _site_scheduled_task(monkeypatch):
    import pegaprox.background.scheduler as sched
    now = datetime(2026, 10, 3, 2, 0)
    monkeypatch.setattr(_ha, 'schedule_now', lambda: now)
    task = {'id': 't1', 'name': 'nightly', 'enabled': True, 'schedule_type': 'daily',
            'schedule_time': '02:00', 'action': 'start'}
    ran = []
    monkeypatch.setattr(sched, 'load_scheduled_tasks', lambda: {'tasks': [task]})
    monkeypatch.setattr(sched, 'execute_scheduled_task', ran.append)
    monkeypatch.setattr(sched, '_touch_last_run', lambda *a: None)
    sched.run_scheduled_tasks()
    return len(ran)


def _site_prune(monkeypatch):
    from pegaprox.api.snapshots import _prune
    mgr = MagicMock()
    mgr.list_snapshots.return_value = [{'name': 'pegaprox-p1-old', 'snaptime': 1}, {'name': 'pegaprox-p1-new', 'snaptime': 2}]
    _prune(mgr, 'n1', 101, 'qemu', {'id': 'p1', 'retention_count': 1, 'retention_days': 0})
    return mgr.delete_snapshot.call_count


def _site_lvextend(monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgr_mod
    fake = MagicMock()
    snaps = [{'id': 's1', 'node': 'n1', 'vg_name': 'vg', 'status': 'active', 'vm_type': 'qemu',
              'snapname': 's', 'disks': [{'snap_lv': 'snap1', 'snap_alloc_gb': 4, 'original_lv': 'o'}]}]

    def ssh(node, cmd, **k):
        if cmd.startswith('lvs'):
            return 0, 'snap1|4|95|\n', ''
        if cmd.startswith('vgs'):
            return 0, '100\n', ''
        return 0, '', ''
    fake._node_ssh_exec.side_effect = ssh
    monkeypatch.setattr(mgr_mod, 'get_db', lambda: MagicMock(get_efficient_snapshots=lambda c, v: snaps))
    PegaProxManager.get_efficient_snapshots(fake, 'c1', 101, refresh_usage=True)
    return sum(1 for c in fake._node_ssh_exec.call_args_list if 'lvextend' in c.args[1])


SITES = [
    ('balancer migration', _site_balance, 'balancing'),
    ('anti-affinity migration', _site_affinity, 'anti-affinity'),
    ('XCP-ng balancer migration', _site_xcpng_balance, 'balancing VM 5'),
    ("restore quorum 'pvecm expected N'", _site_restore_quorum, 'pvecm expected 2'),
    ('recovery: fence, lock, config move, start', _site_start_vm, 'fencing pve2 again'),
    ('scheduled task', _site_scheduled_task, 'scheduled task nightly'),
    ('snapshot policy prune', _site_prune, 'pruning pegaprox-p1-old'),
    ('lvextend of an efficient snapshot', _site_lvextend, 'lvextend of snap1'),
]


@pytest.mark.parametrize('label,site,said', SITES, ids=[s[0] for s in SITES])
def test_each_step_asks_and_does_not_start_without_a_confirmed_lease(label, site, said, denied,
                                                                      monkeypatch, db):
    assert site(monkeypatch) == 0, f'{label}: the step went out although the confirm said no'
    assert denied and any(said in what for what, _need in denied), denied


@pytest.mark.parametrize('label,site,said', SITES, ids=[s[0] for s in SITES])
def test_each_step_goes_out_when_the_confirm_says_yes(label, site, said, monkeypatch, db):
    """The mirror: with the confirm saying yes (an instance of its own) the step runs."""
    assert site(monkeypatch) > 0, label


def test_the_steps_on_the_failed_node_ask_for_no_lease_time():
    """Design 5.4: stopping its guests, the poison pill and fencing it are the goal a newer
    leader has too; they need no lease left."""
    import ast
    import inspect
    import textwrap
    from pegaprox.core.manager import PegaProxManager
    tree = ast.parse(textwrap.dedent(inspect.getsource(PegaProxManager._ha_recovery_worker)))
    needs = {}
    for c in ast.walk(tree):
        if isinstance(c, ast.Call) and getattr(c.func, 'attr', None) == 'confirm_step':
            needs[ast.unparse(c.args[0])] = ast.unparse(c.args[1]) if len(c.args) > 1 else 'NEED_STEP'
    same_goal = [t for t, n in needs.items() if n.endswith('NEED_SAME_GOAL')]
    assert any('stopping the guests' in t for t in same_goal)
    assert any('poison pill' in t for t in same_goal)
    assert any('fencing' in t for t in same_goal)
    # what comes after the waits needs the full lease time again
    assert [t for t, n in needs.items() if n == 'NEED_STEP']


# --- the recovery journal (5.6) ----------------------------------------------------------------

def test_the_journal_is_written_in_an_automatic_group_only(db):
    assert _ha.recovery_begin('c1', 'pve2') is None
    _ha.recovery_step(None, 'c1', 'pve2', 'fence')
    assert 'ha_recovery_journal' not in _ha._existing_tables(db.conn.cursor())
    assert _ha.recovery_leftovers() == []


def test_the_journal_survives_a_restart_and_says_what_was_left(auto, seed, db):
    import pegaprox.core.db as dbmod
    auto.form(seed)
    with auto.at('a') as ha:
        run = ha.recovery_begin('c1', 'pve2')
        for step, vmid in (('fence', None), ('clear_lock', 101), ('move_config', 101), ('start', 101),
                           ('clear_lock', 102), ('move_config', 102)):
            ha.recovery_step(run, 'c1', 'pve2', step, vmid=vmid)
            ha.recovery_step(run, 'c1', 'pve2', step, vmid=vmid, done=True)
        ha.recovery_step(run, 'c1', 'pve2', 'start', vmid=102)
        # this process's own live run is not a leftover
        assert ha.recovery_leftovers('c1') == []
        # the shared table goes to the members with the configuration
        assert 'ha_recovery_journal' in ha.build_snapshot()['tables']
    # the process ends: memory gone, the database file stays
    db.conn.close()
    dbmod._db = None
    dbmod.PegaProxDB._instance = None
    _ha._recovery_live.clear()
    with auto.at('b') as ha:
        left = ha.recovery_leftovers('c1')
    assert len(left) == 1
    rec = left[0]
    assert (rec['node'], rec['instance_id'], rec['moved'], rec['open']) == \
        ('pve2', IDS['a'], [102], ['start 102'])
    assert _ha.recovery_leftovers('other cluster') == []


def test_a_run_that_got_through_leaves_nothing(auto, seed, db):
    auto.form(seed)
    with auto.at('a') as ha:
        run = ha.recovery_begin('c1', 'pve2')
        ha.recovery_step(run, 'c1', 'pve2', 'fence')
        ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=101, done=True)
        ha.recovery_step(run, 'c1', 'pve2', 'start', vmid=101, done=True)
        # a step on the failed node that did not finish is done again by the next pass
        # of the monitor: nothing to keep for it
        assert ha.recovery_end(run) is None
        ha._recovery_live.clear()
        assert ha.recovery_leftovers() == []


def test_a_run_that_left_a_guest_moved_stays_listed_on_the_leader_too(auto, seed, db):
    """The review of S4: one failed confirm before the start, the lease still held. The
    run is kept and listed as interrupted here at once, not only by the next leader."""
    auto.form(seed)
    with auto.at('a') as ha:
        run = ha.recovery_begin('c1', 'pve2')
        ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=101, done=True)
        # a move begun and not marked done: its config may have left pve2
        ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=102)
        left = ha.recovery_end(run)
        assert ha.is_active()
        assert (left['run'], left['moved'], left['guests_open']) == (run, [101], [102])
        assert [r['run'] for r in ha.recovery_leftovers('c1')] == [run]


def test_the_moved_guests_are_started_by_an_admin_and_the_run_is_forgotten(auto, seed, db, monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    auto.form(seed)
    with auto.at('a') as ha:
        run = ha.recovery_begin('c1', 'pve2')
        ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=101, done=True)
        ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=102, done=True)
        ha._recovery_live.clear()
        m = MagicMock()
        m.id = 'c1'
        m.get_vm_resources.return_value = [
            {'vmid': 101, 'node': 'pve1', 'type': 'qemu', 'status': 'stopped'},
            {'vmid': 102, 'node': 'pve1', 'type': 'qemu', 'status': 'running'}]
        m.ha_interrupted_recoveries.side_effect = lambda: PegaProxManager.ha_interrupted_recoveries(m)
        m._create_session.return_value.post.return_value.status_code = 200
        listed = PegaProxManager.ha_interrupted_recoveries(m)
        assert [r['moved'] for r in listed] == [[101]]
        # PVE refused it: the run stays listed for the next try
        m._create_session.return_value.post.return_value.status_code = 500
        assert PegaProxManager.ha_start_moved_vms(m) == {101: False}
        # 102 runs: the listing let its rows go, 101 is left for the next try
        assert [r['moved'] for r in ha.recovery_leftovers()] == [[101]]
        m._create_session.return_value.post.return_value.status_code = 200
        assert PegaProxManager.ha_start_moved_vms(m) == {101: True}
        assert ha.recovery_leftovers() == []


def test_a_new_leader_says_what_was_left_when_its_monitor_starts(monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    forgot = []
    monkeypatch.setattr(_ha, 'recovery_forget', forgot.extend)
    m = MagicMock()
    m.ha_interrupted_recoveries.return_value = [
        {'run': 'r', 'node': 'pve2', 'instance_id': IDS['a'], 'epoch': 3, 'moved': [102],
         'open': ['start 102']},
        # cut short in the middle of the fence: nothing for the guests (the listing
        # forgets such a run once the guests could be read)
        {'run': 'nothing left', 'node': 'pve3', 'instance_id': IDS['a'], 'epoch': 3, 'moved': [],
         'guests_open': [], 'held': [], 'open': ['fence']}]
    PegaProxManager._ha_say_interrupted(m)
    action, text = m._ha_refuse.call_args.args
    assert m._ha_refuse.call_count == 1 and action == 'ha.recovery_interrupted'
    assert 'pve2' in text and 'aaaaaaaa' in text and '102' in text and 'start 102' in text
    assert forgot == []


# --- schedules across a change of leader (5.7) ----------------------------------------------------

def test_a_new_leader_skips_the_minute_the_former_one_may_have_fired(auto, seed):
    auto.form(seed)
    with auto.at('a') as ha:
        rt = ha._rts[IDS['a']]
        rt.node.acting_from = ha.ha_clock()        # acts from this moment
        # the switch: it fired the schedules itself until now, nothing to skip
        assert ha.schedule_held() is False
        rt.came_up = True                           # a takeover (the boot check said so)
        assert ha.schedule_held() is True
        rt.node.acting_from = ha.ha_clock() - 130   # acting for two minutes
        assert ha.schedule_held() is False
    with auto.at('b') as ha:
        assert ha.schedule_held() is True           # no leader fires nothing


def test_nothing_is_held_or_written_first_outside_an_automatic_group(auto, seed):
    assert _ha.schedule_held() is False and _ha.schedule_fire_first() is False
    assert _ha.missed_schedule_window('scheduled tasks') is None
    auto.pair(seed)
    for n in 'ab':
        with auto.at(n) as ha:
            assert ha.schedule_held() is False and ha.schedule_fire_first() is False


def _run_tasks(monkeypatch, order):
    import pegaprox.background.scheduler as sched
    now = _ha.schedule_now()
    task = {'id': 't1', 'name': 'nightly', 'enabled': True, 'schedule_type': 'daily',
            'schedule_time': now.strftime('%H:%M'), 'action': 'start'}
    monkeypatch.setattr(sched, 'load_scheduled_tasks', lambda: {'tasks': [task]})
    monkeypatch.setattr(sched, 'execute_scheduled_task', lambda t: order.append('acts'))
    monkeypatch.setattr(sched, '_touch_last_run', lambda tid, when: order.append('last_run'))
    monkeypatch.setattr(_ha, 'schedule_fired', lambda: order.append('to the members'))
    sched.run_scheduled_tasks()


def test_in_an_automatic_group_a_schedule_is_written_and_sent_before_it_acts(auto, seed, monkeypatch):
    auto.form(seed)
    order = []
    with auto.at('a') as ha:
        ha._rts[IDS['a']].node.acting_from = ha.ha_clock() - 130
        _run_tasks(monkeypatch, order)
    assert order == ['last_run', 'to the members', 'acts', 'last_run']


def test_elsewhere_a_schedule_acts_and_is_written_as_before(monkeypatch):
    order = []
    _run_tasks(monkeypatch, order)
    assert order == ['acts', 'last_run']


def test_a_held_minute_fires_nothing(auto, seed, monkeypatch):
    auto.form(seed)
    order = []
    with auto.at('a') as ha:
        ha._rts[IDS['a']].came_up = True
        ha._rts[IDS['a']].node.acting_from = ha.ha_clock()
        _run_tasks(monkeypatch, order)
    assert order == []


def test_what_fell_due_without_a_leader_is_reported_once(auto, seed, monkeypatch):
    import pegaprox.background.scheduler as sched
    auto.form(seed)
    said = []
    monkeypatch.setattr(_ha, 'missed_schedules', lambda kind, names, window: said.append((kind, names)))
    with auto.at('a') as ha:
        rt = ha._rts[IDS['a']]
        assert ha.missed_schedule_window('scheduled tasks') is None    # the switch: no gap
        # came up by a start (a takeover): the boot check said so, it acts from now
        rt.came_up = True
        rt.node.acting_from = ha.ha_clock()
        window = ha.missed_schedule_window('scheduled tasks')
        assert window is not None and window[1] > window[0]
        assert ha.missed_schedule_window('scheduled tasks') is None       # once
        _ha._missed_said.clear()
        # the minute the window ends in is always one it covers, wherever in a minute
        # the test runs
        due = ha.schedule_at(window[1])
        ran = due.replace(second=1).isoformat()
        tasks = [{'name': 'in the gap', 'enabled': True, 'schedule_type': 'daily',
                  'schedule_time': due.strftime('%H:%M')},
                 {'name': 'ran before the change', 'enabled': True, 'schedule_type': 'daily',
                  'schedule_time': due.strftime('%H:%M'), 'last_run': ran},
                 {'name': 'elsewhere', 'enabled': True, 'schedule_type': 'daily',
                  'schedule_time': ha.schedule_at(window[0] - 3600).strftime('%H:%M')}]
        sched._report_missed(tasks)
        sched._report_missed(tasks)
    assert said == [('scheduled tasks', ['in the gap'])]


def test_the_gap_reaches_back_to_the_vote_the_leader_won(auto, seed, monkeypatch):
    """The window starts before the last renewal the winner could have heard: from the
    vote round it won (take_after on this boot), not from the start of its process after
    the restart, which lies up to W_take later."""
    auto.form(seed)
    with auto.at('a') as ha:
        rt = ha._rts[IDS['a']]
        rt.came_up = True
        node, t = rt.node, rt.node.t
        node.acting_from = ha.ha_clock()
        node.started = ha.ha_clock() - 1                # the restart after the win took 25 s
        won = node.started - 25
        st = ha._load()
        led = dict(st['lease'].get('led') or {}, take_after={'boot_id': node.boot_id, 'at': won + t.W_take})
        # as the state file of the winner says it (a commit here would rebuild the node)
        held = dict(st, lease=dict(st['lease'], led=led))
        with monkeypatch.context() as m:
            m.setattr(ha, '_load', lambda: held)
            window = ha.missed_schedule_window('scheduled tasks')
        heard = ha._wall() - (ha.ha_clock() - won) - (t.P + t.L / 4 + t.L / 2 + t.T_vote)
        assert window[0] == pytest.approx(heard, abs=0.5)


def test_a_leader_that_took_the_lead_in_its_own_process_reports_no_gap(auto, seed):
    auto.form(seed)       # the switch to automatic mode: acting at once, no restart
    with auto.at('a') as ha:
        assert ha.missed_schedule_window('scheduled tasks') is None


def _run_updates(monkeypatch, order, kind='recurring'):
    import pegaprox.api.schedules as sch
    monkeypatch.setattr(_ha, 'schedule_now', lambda: datetime(2026, 10, 3, 3, 0))
    schedule = {'enabled': True, 'schedule_type': kind, 'day': 'daily', 'time': '03:00'}
    mgr = MagicMock()
    mgr.is_connected, mgr._rolling_update = True, None
    monkeypatch.setattr(sch, 'load_all_update_schedules', lambda: {'c1': schedule})
    monkeypatch.setattr(sch, '_creator_may_update', lambda cid, s: True)   # its own file (#1093)
    monkeypatch.setitem(sch.cluster_managers, 'c1', mgr)
    monkeypatch.setattr(sch, 'execute_scheduled_rolling_update', lambda m, cid, a: order.append('acts'))
    monkeypatch.setattr(sch, 'update_schedule_last_run', lambda cid, last, nxt: order.append('last_run'))
    monkeypatch.setattr(sch, 'save_update_schedule', lambda cid, s: order.append(f"off={not s['enabled']}"))
    monkeypatch.setattr(_ha, 'schedule_fired', lambda: order.append('to the members'))
    sch.check_scheduled_updates()


def test_in_an_automatic_group_a_scheduled_update_is_written_before_it_starts(auto, seed, monkeypatch):
    auto.form(seed)
    order, once = [], []
    with auto.at('a'):
        _run_updates(monkeypatch, order)
        _run_updates(monkeypatch, once, kind='once')
    assert order == ['last_run', 'to the members', 'acts', 'last_run']
    # a one-time update switches itself off before it starts
    assert once == ['last_run', 'off=True', 'to the members', 'acts', 'last_run', 'off=True']


def test_elsewhere_a_scheduled_update_starts_and_is_written_as_before(monkeypatch):
    order = []
    _run_updates(monkeypatch, order)
    assert order == ['acts', 'last_run']


def _starter(monkeypatch, moved):
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgr_mod
    _no_sleep(monkeypatch, mgr_mod)
    m = PegaProxManager.__new__(PegaProxManager)
    m.id, m.logger = 'c1', MagicMock()
    m.config = types.SimpleNamespace(user='root@pam', host='10.0.0.1', name='c1')
    m.current_host, m.ha_config, m._using_api_token = '10.0.0.1', {}, False
    session = MagicMock()
    session.post.return_value.status_code = 200
    m._create_session = lambda: session
    m._ha_clear_vm_lock = MagicMock(return_value=True)
    m._ha_move_vm_config = MagicMock(return_value=moved)
    m._ha_fence_node = MagicMock(return_value=False)
    m._ha_node_back = MagicMock(return_value=False)      # pve2 stays down
    return m, session


@pytest.mark.parametrize('moved', [False, True])
def test_in_an_automatic_group_a_guest_is_started_only_where_its_config_is(auto, seed, monkeypatch, moved):
    """Design 5.2: the config location is the token PVE checks. A guest whose config the
    target does not hold is not started from here, whether the move said it failed (it
    used to start anyway) or not."""
    auto.form(seed)
    m, session = _starter(monkeypatch, moved)
    with auto.at('a'):
        session.get.return_value.status_code = 500       # "does not exist" on the target
        assert m._ha_start_vm_on_node(101, 'qemu', 'pve1', 'pve2') is False
        session.post.assert_not_called()
        asked = [c.args[0] for c in session.get.call_args_list if 'status/current' in c.args[0]]
        assert asked and all('/nodes/pve1/qemu/101/status/current' in u for u in asked)
        session.get.return_value.status_code = 200
        assert m._ha_start_vm_on_node(101, 'qemu', 'pve1', 'pve2') is True
        session.post.assert_called_once()


def test_elsewhere_a_failed_move_still_tries_the_start(monkeypatch):
    m, session = _starter(monkeypatch, False)
    session.get.return_value.status_code = 500
    assert m._ha_start_vm_on_node(101, 'qemu', 'pve1', 'pve2') is True
    assert not [c for c in session.get.call_args_list if 'status/current' in c.args[0]]
