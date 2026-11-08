"""The cluster claim (#625, stage two S6, design 6.3; owner decision: optional per
cluster, off by default).

/etc/pve/pegaprox/claim names the PegaProx instance that acts on a cluster. The
commands that write, remove and check it are shell the manager builds; here they run
as built against a directory that stands in for /etc/pve (their `pve` argument). The
manager tests run the same commands through a stand-in for SSH that executes them
locally with /etc/pve swapped for that directory. Nothing touches a node.

MK Oct 2026
"""
import os
import subprocess
import threading
import types
from unittest.mock import MagicMock

import pytest

from pegaprox.core import ha
from pegaprox.core.manager import PegaProxManager
from test_ha_api import ha_env, _admin, _audit, ADMIN_PW  # noqa: F401

A = 'a' * 32
B = 'b' * 32


@pytest.fixture
def pve(tmp_path):
    root = tmp_path / 'pve'
    (root / 'priv' / 'lock').mkdir(parents=True)
    return root


def _sh(cmd):
    r = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _write(pve, epoch, instance, **kw):
    return _sh(PegaProxManager._claim_write_cmd(epoch, instance, pve=str(pve), **kw))[1]


def _claim(pve):
    path = pve / 'pegaprox' / 'claim'
    return path.read_text() if path.exists() else None


def _plant(pve, text):
    (pve / 'pegaprox').mkdir(exist_ok=True)
    (pve / 'pegaprox' / 'claim').write_text(text)


def _lock(pve):
    return pve / 'priv' / 'lock' / 'pegaprox-claim'


# --- the write: compare and swap under the lock directory ------------------------------------

def test_a_cluster_without_a_claim_gets_ours(pve):
    assert _write(pve, 3, A) == f'CLAIM_OURS 3 {A}'

    epoch, instance, cfg, wall, forced = _claim(pve).split()
    assert (epoch, instance, cfg, forced) == ('3', A, '-', '0') and wall.isdigit()
    assert _claim(pve).endswith('\n') and _claim(pve).count('\n') == 1
    assert not _lock(pve).exists()
    assert sorted(p.name for p in (pve / 'pegaprox').iterdir()) == ['claim']


def test_our_own_claim_is_ours_without_a_write(pve):
    """A cluster that lost quorum is read-only: a claim written before must still read
    as ours there, so the check comes before the lock and the write."""
    _plant(pve, f'3 {A} - 1700000000 0\n')
    _lock(pve).parent.rmdir()             # nothing can be locked or written now

    assert _write(pve, 3, A) == f'CLAIM_OURS 3 {A}'
    assert _claim(pve) == f'3 {A} - 1700000000 0\n'


def test_a_claim_under_a_lower_epoch_is_a_former_leaders(pve):
    _plant(pve, f'2 {B} - 1700000000 0\n')

    assert _write(pve, 3, A) == f'CLAIM_OURS 3 {A}'
    assert _claim(pve).startswith(f'3 {A} ')


@pytest.mark.parametrize('theirs,answer', [
    (f'9 {B} - 1700000000 0\n', f'CLAIM_HIGHER 9 {B}'),
    (f'3 {B} - 1700000000 0\n', f'CLAIM_SAME 3 {B}'),
    (f'9 {A} - 1700000000 0\n', f'CLAIM_HIGHER 9 {A}'),       # ours from a later epoch: stale all the same
    ('this is no claim\n', 'CLAIM_UNREADABLE'),
    ('\n', 'CLAIM_UNREADABLE'),
])
def test_a_claim_that_is_not_ours_to_take_stays(pve, theirs, answer):
    """The counterproof to the two tests above. A file that cannot be read as a claim is
    not read as no claim."""
    _plant(pve, theirs)

    assert _write(pve, 3, A) == answer
    assert _claim(pve) == theirs
    assert not _lock(pve).exists()


def test_a_held_lock_means_busy_and_nothing_is_written(pve):
    _lock(pve).mkdir()

    assert _write(pve, 3, A) == 'CLAIM_BUSY'
    assert _claim(pve) is None and _lock(pve).exists()


def test_a_cluster_that_takes_no_writes_says_so(pve):
    _lock(pve).parent.rmdir()
    assert _write(pve, 3, A) == 'CLAIM_READONLY'
    assert _claim(pve) is None


@pytest.mark.parametrize('theirs', [f'9 {B} - 1700000000 0\n', f'3 {B} - 1700000000 0\n', 'garbage\n'])
def test_a_release_writes_over_whatever_is_there(pve, theirs):
    _plant(pve, theirs)

    assert _write(pve, 3, A, takeover=True) == f'CLAIM_OURS 3 {A}'
    assert _claim(pve).startswith(f'3 {A} ') and not _lock(pve).exists()


def test_cfg_and_forced_go_into_the_line(pve):
    _write(pve, 4, A, cfg_id='7.12', forced=True)
    assert _claim(pve).split()[2::2] == ['7.12', '1']
    (pve / 'pegaprox' / 'claim').unlink()
    _write(pve, 4, A, cfg_id='x"; reboot; "')
    assert _claim(pve).split()[2] == '-'


@pytest.mark.parametrize('epoch,instance', [(-1, A), (True, A), ('3', A), (3, 'a' * 31), (3, 'A' * 32),
                                            (3, '$(reboot)'), (3, None)])
def test_only_an_epoch_and_an_instance_id_go_into_the_shell(epoch, instance):
    for build in (PegaProxManager._claim_write_cmd, PegaProxManager._claim_remove_cmd):
        with pytest.raises(ValueError):
            build(epoch, instance)
    with pytest.raises(ValueError):
        PegaProxManager._claim_guard_cmd(epoch, instance, 'true')


def test_the_default_paths_are_the_ones_in_etc_pve():
    cmd = PegaProxManager._claim_write_cmd(3, A)
    assert 'D=/etc/pve/pegaprox;' in cmd and 'L=/etc/pve/priv/lock/pegaprox-claim;' in cmd
    assert '/etc/pve/pegaprox/claim' in PegaProxManager._claim_guard_cmd(3, A, 'true')


# --- removing it -------------------------------------------------------------------------

def test_our_claim_can_be_taken_away_again(pve):
    _write(pve, 3, A)

    assert _sh(PegaProxManager._claim_remove_cmd(3, A, pve=str(pve)))[1] == 'CLAIM_REMOVED'
    assert _claim(pve) is None and not (pve / 'pegaprox').exists() and not _lock(pve).exists()
    assert _sh(PegaProxManager._claim_remove_cmd(3, A, pve=str(pve)))[1] == 'CLAIM_ABSENT'


@pytest.mark.parametrize('theirs', [f'3 {B} - 1 0\n', f'2 {B} - 1 0\n', f'4 {A} - 1 0\n', 'this is no claim\n',
                                    f'x {A} - 1 0\n'])
def test_another_claim_is_not_ours_to_remove(pve, theirs):
    """Another instance's under any epoch, and this instance's under a later one: a
    restored copy of this instance must not take the claim of the one that still runs."""
    _plant(pve, theirs)

    out = _sh(PegaProxManager._claim_remove_cmd(3, A, pve=str(pve)))[1]

    assert out.startswith('CLAIM_NOT_OURS') and _claim(pve) == theirs
    assert not _lock(pve).exists()


@pytest.mark.parametrize('stale', [None, f'2 {B} - 1 0\n', f'3 {A} - 1 0\n', 'this is no claim\n'],
                         ids=['no-claim', 'a-former-leaders', 'ours', 'unreadable'])
def test_a_node_that_takes_no_writes_has_no_answer_about_the_claim(pve, stale):
    """A node outside the quorum shows the /etc/pve it had when it left, and that copy
    takes no write. Asked to remove the claim it answered CLAIM_ABSENT or
    CLAIM_NOT_OURS from the copy, and nothing had asked it whether it is in the
    quorum. The lock comes first now; the counterproofs are the tests above, where
    the lock can be taken and the same files give those answers."""
    if stale:
        _plant(pve, stale)
    _lock(pve).parent.rmdir()             # nothing can be locked or written

    assert _sh(PegaProxManager._claim_remove_cmd(3, A, pve=str(pve)))[1] == 'CLAIM_READONLY'
    assert _claim(pve) == stale


def test_a_claim_this_instance_wrote_under_an_earlier_epoch_is_ours_to_remove(pve):
    """It led before, and the write under the new epoch did not get through. Only an
    exact match counted, so that file was called another instance's and stayed."""
    _plant(pve, f'2 {A} - 1 0\n')

    assert _sh(PegaProxManager._claim_remove_cmd(3, A, pve=str(pve)))[1] == 'CLAIM_REMOVED'
    assert _claim(pve) is None and not _lock(pve).exists()


@pytest.mark.parametrize('theirs,goes', [(f'3 {A} - 1 0\n', True), (f'2 {A} - 1 0\n', True),
                                         (f'4 {A} - 1 0\n', False), (f'3 {B} - 1 0\n', False),
                                         (f'9 {B} - 1 0\n', False), ('this is no claim\n', False)])
def test_the_command_for_the_admin_removes_our_claim_and_no_other(pve, theirs, goes):
    """What the response hands out when PegaProx could not remove the file itself: the
    same rule as the removal, in one line an admin can paste on a node."""
    _plant(pve, theirs)
    cmd = PegaProxManager._claim_by_hand(3, A)
    assert cmd.count('/etc/pve/pegaprox') == 3 and A in cmd and '\n' not in cmd

    _sh(cmd.replace('/etc/pve', str(pve)))

    assert (_claim(pve) is None) is goes
    assert (pve / 'pegaprox').exists() is not goes
    for epoch, instance in ((3, "x' /etc/passwd; reboot; '"), ('3; reboot', A)):
        with pytest.raises(ValueError):
            PegaProxManager._claim_by_hand(epoch, instance)


# --- the guard in front of an SSH step ------------------------------------------------------

def _guarded(pve, tmp_path, epoch, instance, exact=True):
    """Run `touch ran` behind the guard; (exit code, whether it ran, stderr)."""
    marker = tmp_path / 'ran'
    code, _out, err = _sh(PegaProxManager._claim_guard_cmd(epoch, instance, f'touch {marker}',
                                                          exact=exact, pve=str(pve)))
    ran = marker.exists()
    if ran:
        marker.unlink()
    return code, ran, err


def test_a_step_runs_while_the_claim_is_ours(pve, tmp_path):
    _write(pve, 3, A)
    assert _guarded(pve, tmp_path, 3, A)[:2] == (0, True)


@pytest.mark.parametrize('theirs', [None, f'4 {B} - 1 0\n', f'3 {B} - 1 0\n', f'2 {A} - 1 0\n',
                                    f'4 {A} - 1 0\n', 'garbage\n'])
def test_a_step_is_refused_at_the_node_under_any_other_claim(pve, tmp_path, theirs):
    """What a former leader that froze between its check and the send runs into: the
    new leader's claim is on the node by then. An exact match, so no claim at all
    refuses too - the claim is written before anything is done to a cluster."""
    if theirs:
        _plant(pve, theirs)

    code, ran, err = _guarded(pve, tmp_path, 3, A)

    assert (code, ran) == (97, False)
    assert err.startswith('CLAIM_REFUSED')


@pytest.mark.parametrize('theirs,runs', [
    (None, True),                        # no claim on the node
    (f'2 {B} - 1 0\n', True),            # the claim from before the split, a former leader's
    (f'3 {A} - 1 0\n', True),
    (f'4 {B} - 1 0\n', False),           # a newer leader's: we are the former one
    (f'3 {B} - 1 0\n', False),
    ('garbage\n', True),
])
def test_a_stop_on_the_failed_node_is_refused_only_by_a_newer_claim(pve, tmp_path, theirs, runs):
    """The failed node is outside the quorum and cannot have seen a claim written since.
    Under the exact rule a new leader could not stop the guests there, and the worker
    goes on without the stop unless strict fencing is set."""
    if theirs:
        _plant(pve, theirs)

    code, ran, _err = _guarded(pve, tmp_path, 3, A, exact=False)

    assert ran is runs and code == (0 if runs else 97)


def test_the_exit_code_of_the_step_is_kept(pve):
    _write(pve, 3, A)
    assert _sh(PegaProxManager._claim_guard_cmd(3, A, 'exit 5', pve=str(pve)))[0] == 5


# --- the manager: off unless switched on --------------------------------------------------

def _mgr(pve=None, ssh=None, **ha_config):
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = 'c1'
    m.config = types.SimpleNamespace(name='lab', user='root@pam', pass_='pw', ssh_key='', ha_settings={},
                                     host='10.9.0.1')
    m.current_host = '10.9.0.1'
    m.ha_config = dict(ha_config)
    m.ha_failure_threshold = 3
    m.ha_lock = threading.Lock()
    m.ha_node_status = {'pve1': {'status': 'online'}, 'pve2': {'status': 'offline'}}
    m.logger = MagicMock()
    m.sent = []

    def node_output(node, cmd, timeout=60):
        m.sent.append((node, cmd))
        if ssh is not None:
            return ssh(node, cmd)
        if pve is None:
            return None
        return subprocess.run(['bash', '-c', cmd.replace('/etc/pve', str(pve))],
                              capture_output=True, text=True).stdout
    m._ssh_node_output = node_output
    return m


@pytest.fixture
def me(monkeypatch):
    monkeypatch.setattr(ha, 'lock_holder', lambda: (A, 3))
    return A, 3


def test_with_the_claim_off_nothing_is_written_and_no_step_changes(pve, me):
    m = _mgr(pve)

    assert m._ha_claim_ensure() == {'state': 'off'}
    assert m.sent == [] and _claim(pve) is None
    for exact in (True, False):
        assert m._ha_claimed('pvecm expected 1', exact=exact) == 'pvecm expected 1'
    status = m._ha_claim_status()
    assert status['enabled'] is False and status['state'] == 'off'
    assert status['residual'] == PegaProxManager.CLAIM_RESIDUAL


def test_with_the_claim_on_the_active_writes_its_epoch(pve, me):
    """The counterproof to the test above: the same calls with the switch on."""
    m = _mgr(pve, claim_enabled=True)

    result = m._ha_claim_ensure()

    assert (result['state'], result['epoch'], result['instance'], result['node']) == ('ours', 3, A, 'pve1')
    assert _claim(pve).startswith(f'3 {A} ')
    assert m._ha_claimed('pvecm expected 1') == PegaProxManager._claim_guard_cmd(3, A, 'pvecm expected 1')
    assert m._ha_claimed('qm stop 100', exact=False) == \
        PegaProxManager._claim_guard_cmd(3, A, 'qm stop 100', exact=False)
    status = m._ha_claim_status()
    assert (status['enabled'], status['state'], status['epoch'], status['residual']) == (True, 'ours', 3, None)


@pytest.mark.parametrize('switch', [None, False, 'yes', 1, 'true'])
def test_only_true_switches_the_claim_on(pve, me, switch):
    m = _mgr(pve, claim_enabled=switch)
    assert m._ha_claim_ensure() == {'state': 'off'} and m.sent == []


def test_a_standby_writes_no_claim(pve, me, monkeypatch):
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    m = _mgr(pve, claim_enabled=True)

    assert m._ha_claim_ensure() == {'state': 'standby'}
    assert m.sent == [] and _claim(pve) is None


@pytest.mark.parametrize('theirs,state', [(f'9 {B} - 1 0\n', 'higher'), (f'3 {B} - 1 0\n', 'same'),
                                          ('garbage\n', 'unreadable')])
def test_a_foreign_claim_is_reported_and_left(pve, me, theirs, state, monkeypatch):
    audits = []
    import pegaprox.utils.audit as audit
    monkeypatch.setattr(audit, 'log_audit', lambda user, action, details, **kw: audits.append(action))
    _plant(pve, theirs)
    m = _mgr(pve, claim_enabled=True)

    result = m._ha_claim_ensure()

    assert result['state'] == state and _claim(pve) == theirs
    assert audits == ['ha.claim_foreign']
    # and the admin's release takes it
    assert m._ha_claim_ensure(takeover=True)['state'] == 'ours'
    assert _claim(pve).startswith(f'3 {A} ')


def test_the_node_that_answers_is_asked_and_the_online_ones_come_first(pve, me):
    m = _mgr(pve, claim_enabled=True)
    m.ha_node_status = {'pve2': {'status': 'offline'}, 'pve1': {'status': 'online'},
                        'pve3': {'status': 'online'}}
    real = m._ssh_node_output
    m._ssh_node_output = lambda node, cmd, timeout=60: None if node == 'pve1' else real(node, cmd)

    assert m._ha_claim_ensure()['node'] == 'pve3'

    # no node answers: not ours, and nothing a recovery could go ahead on
    m._ssh_node_output = lambda node, cmd, timeout=60: None
    assert m._ha_claim_ensure()['state'] == 'unreachable'
    assert m._ha_claim_status()['state'] == 'unreachable'


def test_switching_off_takes_our_claim_away_and_leaves_a_foreign_one(pve, me):
    m = _mgr(pve, claim_enabled=True)
    m._ha_claim_ensure()
    assert m._ha_claim_remove()['state'] == 'removed' and _claim(pve) is None

    _plant(pve, f'9 {B} - 1 0\n')
    assert m._ha_claim_remove()['state'] == 'foreign' and _claim(pve) == f'9 {B} - 1 0\n'


def test_a_removal_goes_past_a_node_that_takes_no_writes_and_a_write_does_not(pve, me):
    """Read-only is one node's answer. For the removal the next node is asked, up to
    the limit, and read-only stands when none of them says anything else. A write
    keeps the answer of the first node: a recovery is refused on it and tried again."""
    m = _mgr(pve, claim_enabled=True)
    m._ha_claim_ensure()
    m.ha_node_status = {f'pve{i}': {'status': 'online'} for i in range(1, 6)}
    _lock(pve).parent.rmdir()
    m.sent.clear()

    assert m._ha_claim_remove(limit=3)['state'] == 'readonly'
    assert [node for node, _cmd in m.sent] == ['pve1', 'pve2', 'pve3']
    assert _claim(pve).startswith(f'3 {A} ')

    (pve / 'pegaprox' / 'claim').unlink()
    m.sent.clear()
    assert m._ha_claim_ensure()['state'] == 'readonly'
    assert [node for node, _cmd in m.sent] == ['pve1']


# --- the recovery steps go through it ----------------------------------------------------------

def _step_mgr(pve, **ha_config):
    """A manager whose recovery SSH steps run locally against the stand-in /etc/pve,
    with pvecm, qm and mv replaced by writing down what was asked."""
    m = _mgr(pve, **ha_config)
    m.steps = []

    def run(host, user, cmd, *a, **kw):
        log = pve / 'steps'
        local = cmd.replace('/etc/pve', str(pve))
        script = (f'pvecm() {{ echo "pvecm $*" >> {log}; }}; qm() {{ echo "qm $*" >> {log}; }}; '
                  f'pct() {{ echo "pct $*" >> {log}; }}; mv() {{ echo "mv $*" >> {log}; }}; ' + local)
        code = subprocess.run(['bash', '-c', script], capture_output=True, text=True).returncode
        m.steps.append(cmd)
        return code == 0
    m._ssh_run_command = run
    m._ssh_run_command_with_password = lambda host, user, cmd, password, **kw: run(host, user, cmd)
    m._ssh_run_command_with_key = lambda host, user, cmd, key, **kw: run(host, user, cmd)
    m._ssh_run_command_output = lambda host, user, cmd, **kw: 'OK'
    m._ha_get_node_ip = lambda node: '10.9.0.1'
    m._ha_get_all_node_ips = lambda node: ['10.9.0.2']
    return m


def _ran(pve):
    path = pve / 'steps'
    return path.read_text().splitlines() if path.exists() else []


def test_the_ssh_steps_of_a_recovery_run_under_our_claim(pve, me):
    m = _step_mgr(pve, claim_enabled=True, two_node_mode=True)
    m._ha_claim_ensure()

    assert m._ha_try_force_quorum('pve1') is True
    assert m._ha_move_vm_config(100, 'qemu', 'pve2', 'pve1') is True
    assert m._ha_ssh_stop_vms_on_node('pve2', vmids=['100'], ctids=['200'], reachable_ips=['10.9.0.2']) is True
    m.ha_node_status = {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
    m._ha_check_restore_quorum()

    assert _ran(pve) == ['pvecm expected 1',
                         f'mv {pve}/nodes/pve2/qemu-server/100.conf {pve}/nodes/pve1/qemu-server/100.conf',
                         'qm stop 100 --timeout 30', 'pct stop 200 --timeout 30', 'pvecm expected 2']
    assert all('/etc/pve/pegaprox/claim' in step for step in m.steps)


def test_a_node_with_the_v2_agent_gets_the_same_guarded_command_as_any_other(pve, me):
    """Forcing quorum is `pvecm expected 1` behind the claim, whatever self-fence agent
    PegaProx knows the node to run. Nothing for the agent goes with it."""
    m = _step_mgr(pve, claim_enabled=True, two_node_mode=True, fence_agent_versions={'pve1': 2, 'pve2': 1})
    m._ha_claim_ensure()

    assert m._ha_try_force_quorum('pve1') is True
    assert m._ha_try_force_quorum('pve2') is True

    assert m.steps == [PegaProxManager._claim_guard_cmd(3, A, 'pvecm expected 1')] * 2
    assert _ran(pve) == ['pvecm expected 1', 'pvecm expected 1']
    _plant(pve, f'4 {B} - 1 0\n')
    assert m._ha_try_force_quorum('pve1') is False and len(_ran(pve)) == 2


def test_the_same_steps_are_refused_once_another_instance_claimed_the_cluster(pve, me):
    """A former leader: its claim was ours, then a new leader wrote its own. Every step
    that changes /etc/pve or corosync stops at the node, and so does a stop, because the
    claim there is newer than ours."""
    m = _step_mgr(pve, claim_enabled=True, two_node_mode=True)
    m._ha_claim_ensure()
    _plant(pve, f'4 {B} - 1 0\n')

    assert m._ha_try_force_quorum('pve1') is False
    assert m._ha_move_vm_config(100, 'qemu', 'pve2', 'pve1') is False
    assert m._ha_ssh_stop_vms_on_node('pve2', vmids=['100'], reachable_ips=['10.9.0.2']) is False
    m.ha_node_status = {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
    m._ha_check_restore_quorum()

    assert _ran(pve) == []


def test_with_the_claim_off_the_steps_go_out_as_they_always_did(pve, me):
    m = _step_mgr(pve, two_node_mode=True)
    _plant(pve, f'4 {B} - 1 0\n')          # whatever is there is nobody's business

    assert m._ha_try_force_quorum('pve1') is True
    assert m._ha_move_vm_config(100, 'qemu', 'pve2', 'pve1') is True
    assert m._ha_ssh_stop_vms_on_node('pve2', vmids=['100'], reachable_ips=['10.9.0.2']) is True

    assert m.steps[0] == 'pvecm expected 1'
    assert m.steps[1] == 'mv /etc/pve/nodes/pve2/qemu-server/100.conf /etc/pve/nodes/pve1/qemu-server/100.conf'
    assert m.steps[2] == 'qm stop 100 --timeout 30 2>&1 || qm stop 100 --skiplock --timeout 30 2>&1'
    assert not any('pegaprox' in step for step in m.steps)
    assert m.sent == [] and _claim(pve) == f'4 {B} - 1 0\n'


def test_a_recovery_needs_the_claim_to_be_ours(pve, me, monkeypatch):
    import pegaprox.utils.audit as audit
    audits = []
    monkeypatch.setattr(audit, 'log_audit', lambda user, action, details, **kw: audits.append((action, details)))
    m = _mgr(pve, claim_enabled=True)
    m._ha_cluster_quorum = lambda: (True, [])

    assert m._ha_recovery_allowed('pve2') == []
    assert _claim(pve).startswith(f'3 {A} ')

    _plant(pve, f'4 {B} - 1 0\n')
    assert m._ha_recovery_allowed('pve2') is None
    assert [a for a, _d in audits] == ['ha.claim_foreign', 'ha.recovery_refused']
    assert 'claim' in audits[-1][1]

    # a cluster the claim cannot be written to gets no recovery either
    m._ssh_node_output = lambda node, cmd, timeout=60: None
    assert m._ha_recovery_allowed('pve2') is None

    # counterproof: with the claim off the same cluster is recovered, the file unread
    m.ha_config['claim_enabled'] = False
    m.sent.clear()
    assert m._ha_recovery_allowed('pve2') == [] and m.sent == []


def test_the_monitor_writes_the_claim_when_it_starts(monkeypatch):
    import pegaprox.core.manager as mgrmod
    made = []
    monkeypatch.setattr(mgrmod, 'threading', types.SimpleNamespace(
        Thread=lambda target=None, **kw: made.append(target) or MagicMock()))
    for on in (True, False):
        made.clear()
        fake = MagicMock()
        fake.ha_thread = None
        fake.ha_config = {'storage_heartbeat_path': '/x', 'claim_enabled': on}
        fake.config = types.SimpleNamespace(ha_settings={}, ha_enabled=False)
        fake._create_session.return_value.get.return_value.status_code = 500
        fake._ha_claim_enabled = lambda on=on: on

        PegaProxManager.start_ha_monitor(fake)

        assert (fake._ha_claim_ensure in made) is on


# --- the switch: admin, own password, typed phrase ------------------------------------------------

URL = '/api/clusters/c1/ha/claim'


@pytest.fixture
def claimed(ha_env, seed, pve, me):
    seed.db.save_cluster('c1', dict(name='lab', host='10.9.0.1', user='root@pam', ssl_verification=False,
                                    fallback_hosts=[], ha_enabled=True, ha_settings={}, ssh_user='root',
                                    ssh_key='', ssh_port=22, cluster_type='proxmox', api_port=8006,
                                    **{'pass': 'pw'}))
    m = _mgr(pve)
    m.cluster_type = 'proxmox'
    m.ssh_blocked_reason = lambda: None
    ha_env.api.set_manager('c1', m)
    return types.SimpleNamespace(api=ha_env.api, seed=seed, mgr=m, pve=pve, db=seed.db)


def _stored(env):
    return env.db.get_cluster('c1')['ha_settings'].get('claim_enabled')


def test_an_admin_switches_the_claim_on_with_password_and_phrase(claimed):
    c = _admin(claimed.api, claimed.seed)

    r = c.post(URL, json={'action': 'enable', 'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW})

    assert r.status_code == 200, r.get_data(as_text=True)
    claim = r.get_json()['claim']
    assert (claim['enabled'], claim['state'], claim['epoch'], claim['instance']) == (True, 'ours', 3, A)
    assert _claim(claimed.pve).startswith(f'3 {A} ')
    assert claimed.mgr.ha_config['claim_enabled'] is True and _stored(claimed) is True
    assert claimed.mgr.config.ha_settings['claim_enabled'] is True
    assert [a['user'] for a in _audit('ha.claim_enabled')] == ['root']
    assert '/etc/pve/pegaprox/claim' in _audit('ha.claim_enabled')[0]['details']


@pytest.mark.parametrize('body,code', [
    ({'action': 'enable', 'user_password': ADMIN_PW}, 400),                             # no phrase
    ({'action': 'enable', 'confirm': 'write claim', 'user_password': ADMIN_PW}, 400),
    ({'action': 'enable', 'confirm': True, 'user_password': ADMIN_PW}, 400),
    ({'action': 'enable', 'confirm': 'WRITE CLAIM'}, 403),                              # no password
    ({'action': 'enable', 'confirm': 'WRITE CLAIM', 'user_password': 'not it'}, 403),
    ({'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW}, 400),                       # no action
    ({'action': 'on', 'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW}, 400),
])
def test_without_the_proof_nothing_is_switched_and_nothing_is_written(claimed, body, code):
    """The counterproof to the test above: the same admin, one part of the proof short."""
    c = _admin(claimed.api, claimed.seed)

    r = c.post(URL, json=body)

    assert r.status_code == code, r.get_data(as_text=True)
    assert claimed.mgr.sent == [] and _claim(claimed.pve) is None
    assert not claimed.mgr.ha_config.get('claim_enabled') and not _stored(claimed)
    assert _audit('ha.claim_enabled') == []


def test_the_refusal_without_the_phrase_carries_the_warning(claimed):
    r = _admin(claimed.api, claimed.seed).post(URL, json={'action': 'enable', 'user_password': ADMIN_PW})

    body = r.get_json()
    assert body['code'] == 'HA_CLAIM_CONFIRM' and 'WRITE CLAIM' in body['error']
    assert body['warning'] == PegaProxManager.CLAIM_WARNING
    assert '/etc/pve/pegaprox/claim' in body['warning'] and '/etc/pve/priv/lock/pegaprox-claim' in body['warning']


@pytest.mark.parametrize('kind', ['anon', 'ha-config-user', 'viewer', 'capped-admin', 'api-token'])
def test_nobody_below_an_unconfined_admin_at_the_keyboard_switches_it(claimed, kind):
    api, seed = claimed.api, claimed.seed
    body = {'action': 'enable', 'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW}
    headers = None
    if kind == 'anon':
        c = api.anon()
    elif kind == 'ha-config-user':
        # may change every other HA setting of the cluster, and types the right
        # password: nothing but the admin role stands in the way
        c = _admin(api, seed, 'ops', role='user', permissions=['ha.config', 'ha.view', 'cluster.view'])
    elif kind == 'viewer':
        c = _admin(api, seed, 'watcher', role='viewer')
    elif kind == 'capped-admin':
        # an admin a tenant mapping lowered where they live; the right password too
        c = _admin(api, seed, 'lowered', tenant_id='default',
                   tenant_permissions={'default': {'role': 'viewer'}})
    else:
        from pegaprox.utils.auth import create_api_token
        _admin(api, seed)
        res = create_api_token('root', 'ci', role='admin')
        assert res.get('success'), res
        c, headers = api.anon(), {'Authorization': f"Bearer {res['token']}"}

    r = c.post(URL, json=body, headers=headers)

    assert r.status_code in (401, 403), (kind, r.status_code, r.get_data(as_text=True))
    assert claimed.mgr.sent == [] and _claim(claimed.pve) is None and not _stored(claimed)


def test_switching_off_wants_the_password_and_takes_the_claim_away(claimed):
    c = _admin(claimed.api, claimed.seed)
    c.post(URL, json={'action': 'enable', 'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW})

    assert c.post(URL, json={'action': 'disable'}).status_code == 403
    assert _claim(claimed.pve) is not None and _stored(claimed) is True

    r = c.post(URL, json={'action': 'disable', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json()['removed'] == 'removed'
    assert r.get_json()['claim']['enabled'] is False
    assert _claim(claimed.pve) is None and _stored(claimed) is False
    assert len(_audit('ha.claim_disabled')) == 1


def test_a_foreign_claim_is_released_only_with_its_own_phrase(claimed):
    c = _admin(claimed.api, claimed.seed)
    _plant(claimed.pve, f'9 {B} - 1 0\n')
    r = c.post(URL, json={'action': 'enable', 'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW})
    assert r.get_json()['claim']['state'] == 'higher' and _claim(claimed.pve) == f'9 {B} - 1 0\n'

    r = c.post(URL, json={'action': 'release', 'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW})
    assert r.status_code == 400 and _claim(claimed.pve) == f'9 {B} - 1 0\n'

    r = c.post(URL, json={'action': 'release', 'confirm': 'RELEASE CLAIM', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json()['claim']['state'] == 'ours'
    assert _claim(claimed.pve).startswith(f'3 {A} ')
    details = _audit('ha.claim_released')[0]['details']
    assert B in details and 'epoch 9' in details

    # nothing to release now
    r = c.post(URL, json={'action': 'release', 'confirm': 'RELEASE CLAIM', 'user_password': ADMIN_PW})
    assert r.status_code == 409


def test_a_release_needs_the_claim_to_be_on(claimed):
    c = _admin(claimed.api, claimed.seed)
    _plant(claimed.pve, f'9 {B} - 1 0\n')

    r = c.post(URL, json={'action': 'release', 'confirm': 'RELEASE CLAIM', 'user_password': ADMIN_PW})

    assert r.status_code == 409 and _claim(claimed.pve) == f'9 {B} - 1 0\n' and claimed.mgr.sent == []


def test_a_cluster_without_ssh_cannot_switch_it_on(claimed):
    claimed.mgr.ssh_blocked_reason = lambda: 'SSH_DISABLED'
    c = _admin(claimed.api, claimed.seed)

    r = c.post(URL, json={'action': 'enable', 'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW})

    assert r.status_code == 409 and not _stored(claimed)


def test_the_ha_status_carries_the_claim_and_the_warning(claimed):
    c = _admin(claimed.api, claimed.seed)
    m = claimed.mgr
    m.ha_enabled, m.ha_check_interval, m.is_connected = True, 10, False
    m.ha_recovery_in_progress, m.ha_have_quorum, m.ha_last_quorum_check = {}, True, None
    m.ha_last_heartbeat_write = None
    m.config.fallback_hosts = []
    m.ha_node_status = {}

    off = c.get('/api/clusters/c1/ha').get_json()['cluster_claim']
    assert (off['enabled'], off['state'], off['path']) == (False, 'off', '/etc/pve/pegaprox/claim')
    assert off['warning'] == PegaProxManager.CLAIM_WARNING and off['residual'] == PegaProxManager.CLAIM_RESIDUAL

    m.ha_node_status = {'pve1': {'status': 'online', 'last_seen': None}}
    c.post(URL, json={'action': 'enable', 'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW})
    on = c.get('/api/clusters/c1/ha').get_json()['cluster_claim']
    assert (on['enabled'], on['state'], on['epoch'], on['residual']) == (True, 'ours', 3, None)


# --- the claim goes with HA, and with the cluster -------------------------------------------------

def _on(env):
    """Switch the claim on through the route; the client that did it."""
    c = _admin(env.api, env.seed)
    r = c.post(URL, json={'action': 'enable', 'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and _claim(env.pve).startswith(f'3 {A} ')
    # what POST .../ha/disable and DELETE need of a manager besides the claim
    m = env.mgr
    m.stop_ha_monitor = lambda: None
    m.stop = lambda: None
    m.get_ha_status = lambda: {'cluster_claim': m._ha_claim_status()}
    m._ha_node_ip_map = lambda: {'pve1': '10.9.0.1', 'pve2': '10.9.0.2'}
    m._ha_agent_ssh = lambda ip, cmd, timeout=30: 'AGENT_UNINSTALLED\nNODE_AGENT_REMOVED\n'
    m._ha_cleanup_storage_heartbeat = lambda: {'attempted': False}
    m.is_connected = False
    m.sent.clear()
    return c


def _leave(env, c, how):
    if how == 'ha-disable':
        return c.post('/api/clusters/c1/ha/disable', json={})
    return c.delete('/api/clusters/c1')


@pytest.mark.parametrize('how', ['ha-disable', 'cluster-delete'])
def test_our_claim_leaves_the_cluster_with_ha_and_with_the_cluster(claimed, how):
    """POST .../ha/disable took the agents and the heartbeat directory off the cluster
    and left /etc/pve/pegaprox/claim there, with the switch still stored as on.
    Deleting the cluster from PegaProx left the file with nobody to remove it."""
    c = _on(claimed)

    r = _leave(claimed, c, how)

    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert _claim(claimed.pve) is None and not (claimed.pve / 'pegaprox').exists()
    assert not _lock(claimed.pve).exists()
    assert body['claim'] == {'state': 'removed', 'removed': True, 'path': '/etc/pve/pegaprox/claim',
                             'instance': None, 'epoch': None, 'warning': None, 'by_hand': None}
    assert not body.get('warning')
    assert claimed.mgr.ha_config['claim_enabled'] is False
    if how == 'ha-disable':
        assert _stored(claimed) is False and claimed.mgr.config.ha_settings['claim_enabled'] is False
        assert body['status']['cluster_claim']['enabled'] is False
        assert 'our claim: removed' in _audit('ha.disabled')[0]['details']
    else:
        assert claimed.db.get_cluster('c1') is None
        assert 'our cluster claim: removed' in _audit('cluster.deleted')[0]['details']


@pytest.mark.parametrize('how', ['ha-disable', 'cluster-delete'])
@pytest.mark.parametrize('theirs', [f'9 {B} - 1700000000 0\n', f'3 {B} - 1700000000 0\n', 'this is no claim\n'],
                         ids=['later-epoch', 'our-epoch', 'no-claim'])
def test_a_foreign_claim_stays_when_ha_or_the_cluster_goes(claimed, how, theirs):
    """Another instance took the cluster over in the meantime. Its claim is not ours
    to remove; the switch goes off here all the same, and the response says whose it is."""
    c = _on(claimed)
    _plant(claimed.pve, theirs)

    r = _leave(claimed, c, how)

    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert _claim(claimed.pve) == theirs
    assert (body['claim']['state'], body['claim']['removed'], body['claim']['by_hand']) == ('foreign', False, None)
    assert 'left where it is' in body['claim']['warning'] and 'left where it is' in body['warning']
    if theirs[0].isdigit():
        assert B in body['claim']['warning'] and f'epoch {theirs[0]}' in body['claim']['warning']
    assert claimed.mgr.ha_config['claim_enabled'] is False
    if how == 'ha-disable':
        assert _stored(claimed) is False


@pytest.mark.parametrize('how', ['ha-disable', 'cluster-delete'])
@pytest.mark.parametrize('why', ['unreachable', 'readonly', 'busy'])
def test_a_claim_that_could_not_be_removed_is_reported_with_the_way_by_hand(claimed, how, why):
    """No node answers, the cluster is not quorate, or another writer holds the lock:
    HA goes off and the cluster is deleted all the same, and the response says that
    the file may still be there and how to remove it."""
    c = _on(claimed)
    m = claimed.mgr
    m.ha_node_status = {f'pve{i}': {'status': 'online'} for i in range(1, 8)}
    if why == 'unreachable':
        tried = []
        m._ssh_node_output = lambda node, cmd, timeout=60: tried.append(node)
    elif why == 'readonly':
        _lock(claimed.pve).parent.rmdir()
    else:
        _lock(claimed.pve).mkdir()

    r = _leave(claimed, c, how)

    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert _claim(claimed.pve).startswith(f'3 {A} ')
    assert (body['claim']['state'], body['claim']['removed']) == (why, False)
    by_hand = body['claim']['by_hand']
    assert by_hand == PegaProxManager._claim_by_hand(3, A)
    assert 'To remove it by hand' in body['warning'] and by_hand in body['warning']
    assert claimed.mgr.ha_config['claim_enabled'] is False
    if why == 'unreachable':
        assert tried == ['pve1', 'pve2', 'pve3']        # a request does not wait out every node
    if how == 'ha-disable':
        assert _stored(claimed) is False
        assert f'our claim: {why}' in _audit('ha.disabled')[0]['details']
    else:
        assert claimed.db.get_cluster('c1') is None


@pytest.mark.parametrize('how', ['ha-disable', 'cluster-delete'])
@pytest.mark.parametrize('stale', ['no-claim', 'a-former-leaders'])
def test_a_node_outside_the_quorum_does_not_answer_for_the_cluster(claimed, tmp_path, how, stale):
    """PegaProx sees pve1 online and asks it first, and pve1 is outside the quorum: its
    /etc/pve never got our claim, or still shows the one of the leader before us. Its
    answer was taken for the cluster. Our claim stayed on the quorate side, and the
    response said there was none, or blamed another instance and offered no command
    to remove ours."""
    c = _on(claimed)
    m = claimed.mgr
    old = tmp_path / 'pve1-copy'
    (old / 'priv').mkdir(parents=True)          # no lock directory can be made there
    if stale == 'a-former-leaders':
        (old / 'pegaprox').mkdir()
        (old / 'pegaprox' / 'claim').write_text(f'2 {B} - 1700000000 0\n')
    asked = []

    def ssh(node, cmd, timeout=60):
        asked.append(node)
        where = old if node == 'pve1' else claimed.pve
        return subprocess.run(['bash', '-c', cmd.replace('/etc/pve', str(where))],
                              capture_output=True, text=True).stdout
    m._ssh_node_output = ssh

    r = _leave(claimed, c, how)

    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert asked == ['pve1', 'pve2']
    assert _claim(claimed.pve) is None and not _lock(claimed.pve).exists()
    assert (body['claim']['state'], body['claim']['removed'], body['claim']['warning']) == ('removed', True, None)
    assert not body.get('warning')
    # the copy of the node outside is as it was
    assert sorted(p.name for p in old.iterdir()) == (['pegaprox', 'priv'] if stale != 'no-claim' else ['priv'])
    assert list((old / 'priv').iterdir()) == []


def _outside(tmp_path, name, claim=None, lock=False):
    """The /etc/pve of a node outside the quorum: the copy it had when it left, which
    takes no write (0555 here, what a mkdir under a pmxcfs without quorum comes to).
    `lock`: a claim writer held the lock directory when the node left."""
    root = tmp_path / f'{name}-copy'
    (root / 'priv' / 'lock').mkdir(parents=True)
    if lock:
        (root / 'priv' / 'lock' / 'pegaprox-claim').mkdir()
    if claim:
        (root / 'pegaprox').mkdir()
        (root / 'pegaprox' / 'claim').write_text(claim)
    for d, _, _ in os.walk(root, topdown=False):
        os.chmod(d, 0o555)
    return root


def _writable_again(root):
    for d, _, _ in os.walk(root):
        os.chmod(d, 0o755)


def _views(env, views):
    """SSH that runs each node's command against that node's own view of /etc/pve;
    the nodes that were asked."""
    asked = []

    def ssh(node, cmd, timeout=60):
        asked.append(node)
        where = views.get(node, env.pve)
        return subprocess.run(['bash', '-c', cmd.replace('/etc/pve', str(where))],
                              capture_output=True, text=True).stdout
    env.mgr._ssh_node_output = ssh
    return asked


def _retire(env, c, how):
    """(response, the state it reports for our claim)"""
    if how == 'claim-off':
        r = c.post(URL, json={'action': 'disable', 'user_password': ADMIN_PW})
        return r, r.get_json()['removed']
    r = _leave(env, c, how)
    return r, r.get_json()['claim']['state']


@pytest.mark.skipif(os.geteuid() == 0, reason='root writes through 0555')
@pytest.mark.parametrize('how', ['ha-disable', 'cluster-delete', 'claim-off'])
@pytest.mark.parametrize('stale', [None, f'2 {B} - 1700000000 0\n', f'3 {A} - 1700000000 0\n'],
                         ids=['no-claim', 'a-former-leaders', 'ours'])
def test_a_lock_directory_in_the_copy_of_a_node_outside_does_not_end_the_retire(claimed, tmp_path, how, stale):
    """The node PegaProx asks first left the quorum while a claim writer held the lock,
    or the writer's rmdir did not get through any more: its copy shows the lock
    directory. It cannot take it and answers CLAIM_BUSY, not CLAIM_READONLY, because
    the directory is there. Busy ended the retire: the quorate node was never asked
    and our claim stayed in the cluster, with the claim switched off."""
    c = _on(claimed)
    old = _outside(tmp_path, 'pve1', claim=stale, lock=True)
    asked = _views(claimed, {'pve1': old})
    try:
        r, state = _retire(claimed, c, how)
    finally:
        _writable_again(old)

    assert r.status_code == 200, r.get_data(as_text=True)
    assert asked == ['pve1', 'pve2']
    assert state == 'removed' and _claim(claimed.pve) is None and not _lock(claimed.pve).exists()
    assert claimed.mgr.ha_config['claim_enabled'] is False
    # the copy of the node outside is as it was
    assert (old / 'priv' / 'lock' / 'pegaprox-claim').is_dir()
    assert ((old / 'pegaprox' / 'claim').read_text() if stale else None) == stale


def test_a_write_still_stops_at_a_lock_that_is_held(pve, me):
    """The counterproof for the other direction: only the removal goes past a busy
    node. A recovery is refused on the first answer and tried again."""
    m = _mgr(pve, claim_enabled=True)
    m.ha_node_status = {f'pve{i}': {'status': 'online'} for i in range(1, 4)}
    _lock(pve).mkdir()

    assert m._ha_claim_ensure()['state'] == 'busy'
    assert [node for node, _cmd in m.sent] == ['pve1']

    # and a removal that every node answers busy to says busy
    m.sent.clear()
    assert m._ha_claim_remove(limit=3)['state'] == 'busy'
    assert [node for node, _cmd in m.sent] == ['pve1', 'pve2', 'pve3']


@pytest.mark.parametrize('why', ['unreachable', 'readonly', 'busy'])
def test_switching_the_claim_off_says_when_the_file_may_still_be_there(claimed, why):
    """POST .../ha/claim with action disable answered {"removed": "busy"} and nothing
    else: the switch was off, the file still in the cluster, and no word on how to
    take it away. HA disable and the delete said so all along."""
    c = _on(claimed)
    m = claimed.mgr
    m.ha_node_status = {f'pve{i}': {'status': 'online'} for i in range(1, 6)}
    tried = []
    if why == 'unreachable':
        m._ssh_node_output = lambda node, cmd, timeout=60: tried.append(node)
    elif why == 'readonly':
        _lock(claimed.pve).parent.rmdir()
    else:
        _lock(claimed.pve).mkdir()

    r = c.post(URL, json={'action': 'disable', 'user_password': ADMIN_PW})

    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert _claim(claimed.pve).startswith(f'3 {A} ')
    assert body['removed'] == why and body['claim']['enabled'] is False and _stored(claimed) is False
    assert body['by_hand'] == PegaProxManager._claim_by_hand(3, A)
    assert body['warning'].startswith('The cluster claim could not be removed (')
    assert 'To remove it by hand' in body['warning'] and body['by_hand'] in body['warning']
    # the same words HA disable reports for it
    m.ha_config['claim_enabled'] = True
    assert m._ha_claim_retire()['warning'] == body['warning']
    if why == 'unreachable':
        assert tried[:5] == ['pve1', 'pve2', 'pve3', 'pve4', 'pve5']       # the switch asks every node
    assert f'our claim: {why}' in _audit('ha.claim_disabled')[0]['details']


@pytest.mark.parametrize('theirs', [None, f'9 {B} - 1700000000 0\n'], ids=['ours', 'foreign'])
def test_switching_the_claim_off_has_nothing_to_warn_of_when_ours_is_gone(claimed, theirs):
    c = _on(claimed)
    if theirs:
        _plant(claimed.pve, theirs)

    body = c.post(URL, json={'action': 'disable', 'user_password': ADMIN_PW}).get_json()

    assert body['by_hand'] is None
    if theirs:
        assert body['removed'] == 'foreign' and 'left where it is' in body['warning']
        assert _claim(claimed.pve) == theirs
    else:
        assert body['removed'] == 'removed' and body['warning'] is None

    # off already: nothing is asked of the cluster
    claimed.mgr.sent.clear()
    again = c.post(URL, json={'action': 'disable', 'user_password': ADMIN_PW}).get_json()
    assert (again['removed'], again['warning'], again['by_hand']) == ('off', None, None)
    assert claimed.mgr.sent == []


@pytest.mark.parametrize('how', ['ha-disable', 'cluster-delete'])
def test_with_the_claim_off_nothing_in_etc_pve_is_looked_at_or_touched(claimed, how):
    """The counterproof: a cluster whose claim was never switched on. A file that is
    there is nobody's business, and the response carries no claim."""
    c = _admin(claimed.api, claimed.seed)
    m = claimed.mgr
    m.stop_ha_monitor = m.stop = lambda: None
    m.get_ha_status = lambda: {}
    m._ha_node_ip_map = lambda: {'pve1': '10.9.0.1'}
    m._ha_agent_ssh = lambda ip, cmd, timeout=30: 'AGENT_UNINSTALLED\nNODE_AGENT_REMOVED\n'
    m._ha_cleanup_storage_heartbeat = lambda: {'attempted': False}
    m.is_connected = False
    _plant(claimed.pve, f'3 {A} - 1700000000 0\n')

    r = _leave(claimed, c, how)

    assert r.status_code == 200, r.get_data(as_text=True)
    assert not r.get_json().get('claim') and not r.get_json().get('warning')
    assert m.sent == [] and _claim(claimed.pve) == f'3 {A} - 1700000000 0\n'


def test_a_standby_takes_no_claim_off_a_cluster(pve, me, monkeypatch):
    m = _mgr(pve, claim_enabled=True)
    m._ha_claim_ensure()
    m.sent.clear()
    monkeypatch.setattr(ha, 'is_active', lambda: False)

    report = m._ha_claim_retire()

    assert m.sent == [] and _claim(pve).startswith(f'3 {A} ')
    assert (report['state'], report['removed']) == ('standby', False) and report['by_hand']


# --- a claim call that raises ------------------------------------------------------------------

def _boom(*a, **kw):
    raise RuntimeError('boom at /var/lib/pegaprox/secret')


@pytest.mark.parametrize('where', ['retire', 'remove'])
@pytest.mark.parametrize('how', ['ha-disable', 'cluster-delete', 'claim-off'])
def test_a_removal_that_raises_is_reported_as_failed_and_not_as_off(claimed, how, where):
    """_ha_claim_retire raised, or the removal under it did. The first answered None
    to HA disable and to the delete, which their responses show as "the claim was
    off": our file was still in /etc/pve/pegaprox and nothing said so. The switch in
    the HA settings answered a bare 500 for it, with no audit line. All three report
    a removal that failed, with the command that removes the file by hand, and none
    of them shows what was raised."""
    c = _on(claimed)
    setattr(claimed.mgr, '_ha_claim_retire' if where == 'retire' else '_ha_claim_remove', _boom)

    if how == 'claim-off':
        r = c.post(URL, json={'action': 'disable', 'user_password': ADMIN_PW})
        body = r.get_json()
        report = {'state': body['removed'], 'warning': body['warning'], 'by_hand': body['by_hand']}
        assert body['claim']['enabled'] is False
    else:
        r = _leave(claimed, c, how)
        body = r.get_json()
        report = body['claim']
        assert report['removed'] is False and report['path'] == '/etc/pve/pegaprox/claim'
        assert body['warning'] and report['warning'] in body['warning']

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _claim(claimed.pve).startswith(f'3 {A} ')            # it is still there
    assert report['state'] == 'failed'
    assert report['by_hand'] == PegaProxManager._claim_by_hand(3, A)
    assert report['warning'].startswith('The cluster claim could not be removed (')
    assert '/etc/pve/pegaprox/claim may still be there' in report['warning']
    assert 'To remove it by hand' in report['warning'] and report['by_hand'] in report['warning']
    assert 'boom' not in r.get_data(as_text=True) and '/var/lib' not in r.get_data(as_text=True)
    # the switch goes off as it does for every other removal that did not get through
    assert claimed.mgr.ha_config['claim_enabled'] is False
    if how == 'cluster-delete':
        assert claimed.db.get_cluster('c1') is None
        assert 'our cluster claim: failed' in _audit('cluster.deleted')[0]['details']
    else:
        assert _stored(claimed) is False
        action = 'ha.disabled' if how == 'ha-disable' else 'ha.claim_disabled'
        assert 'our claim: failed' in _audit(action)[0]['details']


def test_a_removal_that_raises_without_a_holder_names_no_command(claimed, monkeypatch):
    """The command for the admin removes the file only while it names this instance
    under its epoch. Where neither can be had, no command is made up: a plain rm
    would take the claim of another instance."""
    c = _on(claimed)
    claimed.mgr._ha_claim_retire = _boom
    monkeypatch.setattr(ha, 'lock_holder', _boom)

    r = c.delete('/api/clusters/c1')

    assert r.status_code == 200, r.get_data(as_text=True)
    report = r.get_json()['claim']
    assert (report['state'], report['removed'], report['by_hand']) == ('failed', False, None)
    assert 'remove it when it names this PegaProx instance' in report['warning']
    assert 'rm ' not in report['warning'] and 'boom' not in r.get_data(as_text=True)


@pytest.mark.parametrize('how', ['ha-disable', 'cluster-delete'])
def test_a_report_without_a_warning_does_not_break_the_answer(claimed, how):
    """Both routes read the report by key. One that names no warning or no state was a
    KeyError after HA was off or the cluster gone, so the answer was a bare 500."""
    c = _on(claimed)
    claimed.mgr._ha_claim_retire = lambda *a, **kw: {'removed': True}

    r = _leave(claimed, c, how)

    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['claim'] == {'removed': True}
    assert not r.get_json().get('warning')


@pytest.mark.parametrize('action', ['enable', 'release'])
def test_a_claim_write_that_raises_is_the_state_failed(claimed, action):
    """POST .../ha/claim with enable or release, and _ha_claim_ensure raises: a bare
    500 before, with the switch stored as on and no audit line. It is the state
    'failed' now, as a write the node refused is, and as the removal reports it. The
    switch stays where the admin put it and the next look at the claim tries again."""
    c = _admin(claimed.api, claimed.seed)
    theirs = f'9 {B} - 1700000000 0\n'
    if action == 'release':
        _plant(claimed.pve, theirs)
        r = c.post(URL, json={'action': 'enable', 'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW})
        assert r.get_json()['claim']['state'] == 'higher'
    real = claimed.mgr._ha_claim_ensure
    claimed.mgr._ha_claim_ensure = _boom
    phrase = 'WRITE CLAIM' if action == 'enable' else 'RELEASE CLAIM'

    r = c.post(URL, json={'action': action, 'confirm': phrase, 'user_password': ADMIN_PW})

    assert r.status_code == 200, r.get_data(as_text=True)
    claim = r.get_json()['claim']
    assert (claim['enabled'], claim['state']) == (True, 'failed')
    assert 'boom' not in r.get_data(as_text=True)
    assert _stored(claimed) is True
    assert _claim(claimed.pve) == (theirs if action == 'release' else None)
    line = _audit('ha.claim_enabled' if action == 'enable' else 'ha.claim_released')[-1]
    assert line['user'] == 'root' and '(failed)' in line['details']
    # no recovery goes ahead on it
    assert claimed.mgr.ha_config['claim_state']['state'] in PegaProxManager._CLAIM_PASSING

    # the same request once the call goes through
    claimed.mgr._ha_claim_ensure = real
    r = c.post(URL, json={'action': action, 'confirm': phrase, 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json()['claim']['state'] == 'ours'
    assert _claim(claimed.pve).startswith(f'3 {A} ')
