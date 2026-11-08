"""The node-HA safety rules in every mode (#625, stage two S6, design 6.2; owner
decision: for new configurations, existing two-node setups keep the old way behind
a switch).

A recovery runs only when the API host reports the cluster quorate. Where it does
not and quorum would be forced, every node outside is powered off first and read
back as off. Setups that forced quorum before the rules existed carry
unsafe_two_node_recovery and behave as they did; the HA status says so.

The managers are PegaProxManager objects without __init__, carrying what the rule
under test reads. ipmitool is a stand-in for subprocess.run.

MK Oct 2026
"""
import threading
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as manager_mod
from pegaprox.core import ha
from pegaprox.core.manager import PegaProxManager
from test_ha_api import ha_env, _admin, _audit  # noqa: F401

IPMI = {'type': 'ipmi', 'host': '10.8.0.2', 'user': 'ADMIN', 'password': 'bmc-pw'}


def _mgr(fencing=None, status=None, **ha_config):
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = 'c1'
    m.config = types.SimpleNamespace(name='lab', user='root@pam', pass_='pw', ssh_key='', host='10.9.0.1',
                                     ha_settings={}, fallback_hosts=[])
    m.current_host = '10.9.0.1'
    # where the fences live: with the HA settings, not on the cluster config
    m.ha_config = dict(ha_config, fencing=dict(fencing or {}))
    m.ha_failure_threshold = 3
    m.ha_lock = threading.Lock()
    m.ha_node_status = {}
    m.logger = MagicMock()
    session = MagicMock()
    if isinstance(status, Exception):
        session.get.side_effect = status
    elif isinstance(status, int):
        session.get.return_value = MagicMock(status_code=status)
    else:
        session.get.return_value = MagicMock(status_code=200, json=lambda: {'data': status})
    m._create_session = lambda: session
    m.session_mock = session
    return m


def _status(quorate, online=('pve1',), offline=('pve2',)):
    return ([{'type': 'cluster', 'name': 'lab', 'quorate': 1 if quorate else 0, 'nodes': len(online) + len(offline)}]
            + [{'type': 'node', 'name': n, 'online': 1} for n in online]
            + [{'type': 'node', 'name': n, 'online': 0} for n in offline])


@pytest.fixture
def audits(monkeypatch):
    seen = []
    import pegaprox.utils.audit as audit
    monkeypatch.setattr(audit, 'log_audit', lambda user, action, details, **kw: seen.append((action, details)))
    return seen


class Ipmi:
    """ipmitool as subprocess.run sees it: `power off` is taken, `power status`
    answers from `reads`, the last one for good."""

    def __init__(self, monkeypatch, reads=('Chassis Power is off',), off_rc=0, missing=False):
        self.calls, self.reads, self.off_rc, self.missing = [], list(reads), off_rc, missing
        monkeypatch.setattr(manager_mod.subprocess, 'run', self.run)
        monkeypatch.setattr(manager_mod, 'time', types.SimpleNamespace(
            sleep=lambda s: None, monotonic=lambda: self.now, time=lambda: 0))
        self.now = 1000.0

    def run(self, argv, **kw):
        if self.missing:
            raise FileNotFoundError('ipmitool')
        assert argv[0] == 'ipmitool' and '-E' in argv and 'bmc-pw' not in argv
        assert kw['env']['IPMITOOL_PASSWORD'] == 'bmc-pw'
        self.calls.append((argv[argv.index('-H') + 1], ' '.join(argv[-2:])))
        if argv[-1] == 'off':
            return types.SimpleNamespace(returncode=self.off_rc, stdout='', stderr='')
        text = self.reads.pop(0) if len(self.reads) > 1 else self.reads[0]
        return types.SimpleNamespace(returncode=0, stdout=text + '\n', stderr='')


# --- what the API host says about quorum ---------------------------------------------------

def test_quorum_is_read_from_cluster_status_in_one_pass():
    m = _mgr(status=_status(True, online=('pve1', 'pve3'), offline=('pve2',)))

    assert m._ha_cluster_quorum() == (True, ['pve2'])
    assert m.session_mock.get.call_count == 1
    assert m.session_mock.get.call_args[0][0] == 'https://10.9.0.1:8006/api2/json/cluster/status'


@pytest.mark.parametrize('status,expected', [
    (_status(False), (False, ['pve2'])),
    (500, (None, None)),
    (RuntimeError('timed out'), (None, None)),
    ([], (None, [])),                                                   # an answer with nothing in it
    ([{'type': 'node', 'name': 'solo', 'online': 1}], (True, [])),       # a node in no cluster
])
def test_no_answer_is_not_a_yes(status, expected):
    assert _mgr(status=status)._ha_cluster_quorum() == expected


# --- the preconditions of a recovery ------------------------------------------------------------

def test_a_quorate_cluster_is_recovered_and_needs_no_fence(audits):
    m = _mgr(status=_status(True))
    assert m._ha_recovery_allowed('pve2') == [] and audits == []


@pytest.mark.parametrize('status', [_status(False, online=('pve1',), offline=('pve2', 'pve3')), 500,
                                    RuntimeError('down')], ids=['minority', 'http-500', 'no-answer'])
def test_from_the_minority_side_nothing_is_recovered(audits, status):
    """The leader sits where the PegaProx majority is, which can be the minority of a
    stretched cluster. The old check pinged hosts outside the cluster and never asked
    corosync, so it recovered from there. A host that does not answer is no yes either."""
    m = _mgr(status=status)

    assert m._ha_recovery_allowed('pve2') is None
    assert [a for a, _d in audits] == ['ha.recovery_refused']
    assert 'quorate' in audits[0][1]


@pytest.mark.parametrize('flag', ['two_node_mode', 'force_quorum_on_failure'])
def test_a_new_two_node_setup_without_a_fence_that_can_be_read_back_is_not_recovered(audits, flag):
    m = _mgr(status=_status(False), **{flag: True})

    assert m._ha_recovery_allowed('pve2') is None
    assert audits[0][0] == 'ha.recovery_refused' and 'no verified fence of pve2' in audits[0][1]


@pytest.mark.parametrize('kind', ['ssh', 'proxmox', 'ipmi-without-password'])
def test_ssh_and_proxmox_fences_do_not_count(audits, kind):
    """_ha_fence_node answers True for both without proof. That stays for the old way;
    forcing quorum does not go by it."""
    fence = {'type': 'ipmi', 'host': '10.8.0.2'} if kind.startswith('ipmi') else {'type': kind, 'host': '10.9.0.2'}
    m = _mgr(fencing={'pve2': fence}, status=_status(False), two_node_mode=True)

    assert m._ha_recovery_allowed('pve2') is None
    assert m._ha_fence_node_verified('pve2') is False
    assert 'no verified fence' in audits[0][1]


def test_with_ipmi_configured_the_nodes_outside_are_what_has_to_be_fenced(audits):
    m = _mgr(fencing={'pve2': IPMI, 'pve3': dict(IPMI, host='10.8.0.3')},
             status=_status(False, online=('pve1',), offline=('pve3', 'pve2')), force_quorum_on_failure=True)

    assert m._ha_recovery_allowed('pve2') == ['pve2', 'pve3'] and audits == []

    # one node outside without a fence that can be read back: no recovery at all
    m.ha_config['fencing'].pop('pve3')
    assert m._ha_recovery_allowed('pve2') is None and 'no verified fence of pve3' in audits[0][1]


def test_an_existing_two_node_setup_keeps_what_it_had_behind_the_switch(audits):
    """The counterproof to the refusals above: the same cluster, the same moment, with
    unsafe_two_node_recovery on - no question to corosync, no fence, quorum forced."""
    m = _mgr(status=_status(False), two_node_mode=True, unsafe_two_node_recovery=True)

    assert m._ha_recovery_allowed('pve2') == []
    assert m.session_mock.get.call_count == 0 and audits == []
    assert m._ha_may_force_quorum('pve2') is True


def test_the_switch_means_nothing_where_quorum_is_not_forced(audits):
    m = _mgr(status=_status(False), unsafe_two_node_recovery=True)

    assert m._ha_unsafe_two_node() is False
    assert m._ha_recovery_allowed('pve2') is None


# --- the fence that is read back ------------------------------------------------------------------

def test_a_fence_counts_once_the_bmc_reads_off(monkeypatch):
    ipmi = Ipmi(monkeypatch, reads=['Chassis Power is on', 'Chassis Power is on', 'Chassis Power is off'])
    m = _mgr(fencing={'pve2': IPMI})

    assert m._ha_fence_node_verified('pve2') is True
    assert ipmi.calls == [('10.8.0.2', 'power off')] + [('10.8.0.2', 'power status')] * 3
    assert m._ha_fence_verified('pve2') is True and m._ha_may_force_quorum('pve2') is True


def test_a_power_off_that_was_only_accepted_is_no_fence(monkeypatch):
    """The counterproof: ipmitool took `power off` with exit code 0 - which is all the
    old _ha_fence_node asks - and the chassis still reads on."""
    ipmi = Ipmi(monkeypatch, reads=['Chassis Power is on'], off_rc=0)
    m = _mgr(fencing={'pve2': IPMI})

    assert m._ha_fence_node_verified('pve2') is False
    assert len(ipmi.calls) == 1 + PegaProxManager.FENCE_VERIFY_READS
    assert m._ha_fence_verified('pve2') is False and m._ha_may_force_quorum('pve2') is False


def test_a_refused_power_off_still_counts_when_the_node_reads_off(monkeypatch):
    Ipmi(monkeypatch, reads=['Chassis Power is off'], off_rc=1)
    assert _mgr(fencing={'pve2': IPMI})._ha_fence_node_verified('pve2') is True


def test_without_ipmitool_there_is_no_fence(monkeypatch):
    Ipmi(monkeypatch, missing=True)
    assert _mgr(fencing={'pve2': IPMI})._ha_fence_node_verified('pve2') is False


def test_a_fence_that_was_read_back_covers_one_recovery(monkeypatch):
    ipmi = Ipmi(monkeypatch)
    m = _mgr(fencing={'pve2': IPMI})
    m._ha_fence_node_verified('pve2')

    ipmi.now += PegaProxManager.FENCE_VERIFIED_FOR + 1
    assert m._ha_fence_verified('pve2') is False


def test_every_node_outside_has_to_read_off(monkeypatch, audits):
    Ipmi(monkeypatch)
    m = _mgr(fencing={'pve2': IPMI, 'pve3': dict(IPMI, host='10.8.0.3')}, force_quorum_on_failure=True)
    assert m._ha_fence_outside('pve2', ['pve2', 'pve3']) is True and audits == []

    ipmi = Ipmi(monkeypatch, reads=['Chassis Power is on'])
    m = _mgr(fencing={'pve2': IPMI, 'pve3': dict(IPMI, host='10.8.0.3')}, force_quorum_on_failure=True)
    assert m._ha_fence_outside('pve2', ['pve2', 'pve3']) is False
    assert {host for host, _c in ipmi.calls} == {'10.8.0.2', '10.8.0.3'}
    assert 'no verified fence of pve2, pve3' in audits[0][1]


# --- forcing quorum ------------------------------------------------------------------------------

def _start_vm(m):
    m._ha_fence_node = MagicMock(return_value=False)
    m._ha_clear_vm_lock = MagicMock(return_value=True)
    m._ha_move_vm_config = MagicMock(return_value=True)
    m._ha_try_force_quorum = MagicMock(return_value=True)
    m.session_mock.get.return_value = MagicMock(status_code=200, json=lambda: {'data': []})
    m.session_mock.post.return_value = MagicMock(status_code=200, text='')
    return m._ha_start_vm_on_node(100, 'qemu', 'pve1', 'pve2')


@pytest.mark.parametrize('flag', ['two_node_mode', 'force_quorum_on_failure'])
def test_quorum_is_forced_only_after_a_fence_that_was_read_back(monkeypatch, flag):
    monkeypatch.setattr(manager_mod.time, 'sleep', lambda s: None)
    m = _mgr(**{flag: True})

    assert _start_vm(m) is True
    m._ha_try_force_quorum.assert_not_called()

    m.__dict__['_ha_verified_fences'] = {'pve2': manager_mod.time.monotonic()}
    assert _start_vm(m) is True
    m._ha_try_force_quorum.assert_called_once_with('pve1')


def test_on_the_unsafe_switch_quorum_is_forced_as_before(monkeypatch):
    monkeypatch.setattr(manager_mod.time, 'sleep', lambda s: None)
    m = _mgr(two_node_mode=True, unsafe_two_node_recovery=True)

    assert _start_vm(m) is True
    m._ha_try_force_quorum.assert_called_once_with('pve1')


def test_a_cluster_that_forces_nothing_never_did(monkeypatch):
    monkeypatch.setattr(manager_mod.time, 'sleep', lambda s: None)
    m = _mgr()
    m.__dict__['_ha_verified_fences'] = {'pve2': manager_mod.time.monotonic()}

    assert _start_vm(m) is True
    m._ha_try_force_quorum.assert_not_called()


# --- the worker ----------------------------------------------------------------------------------

def _worker(allowed, fence_ok=True):
    fake = MagicMock()
    fake.ha_config = {'recovery_delay': 30}
    fake.ha_lock = threading.Lock()
    fake.ha_node_status = {'pve2': {'status': 'offline'}}
    fake.ha_recovery_in_progress = {'pve2': True}
    fake._ha_get_vms_on_node.return_value = [{'vmid': 100, 'name': 'vm100', 'type': 'qemu'}]
    fake._ha_get_available_nodes.return_value = ['pve1']
    fake._ha_check_vm_storage.return_value = 'shared'
    fake._ha_select_target_node.return_value = 'pve1'
    fake._ha_check_node_via_ssh.return_value = {'reachable': True, 'running_vms': ['100'], 'running_cts': []}
    fake._ha_check_node_agent_heartbeat.return_value = {'alive': False, 'age_seconds': None}
    fake.current_host, fake.is_connected, fake.session = '10.9.0.1', True, True
    fake._ha_recovery_allowed.return_value = allowed
    fake._ha_fence_timing.return_value = {'wait': 30}
    fake._ha_fence_outside.return_value = fence_ok
    fake._ha_fence_verified.return_value = bool(allowed) and fence_ok
    return fake


def _order(fake):
    return [c[0] for c in fake.mock_calls if c[0].startswith('_ha_')]


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(manager_mod, 'time', types.SimpleNamespace(sleep=lambda s: None))
    assert ha.is_active()


def test_a_refused_recovery_does_nothing_to_the_node(no_sleep):
    """Asked before the SSH check and the stop: from the minority side the 'failed' node
    is the healthy majority, and its guests are not ours to stop."""
    fake = _worker(None)

    PegaProxManager._ha_recovery_worker(fake, 'pve2')

    assert _order(fake) == ['_ha_fence_timing', '_ha_recovery_allowed']
    assert 'pve2' not in fake.ha_recovery_in_progress


def test_the_worker_waits_what_the_timing_says(monkeypatch):
    """Its wait was recovery_delay read on the spot. It comes from _ha_fence_timing,
    which also gives the agents their fence delay."""
    slept = []
    monkeypatch.setattr(manager_mod, 'time', types.SimpleNamespace(sleep=slept.append))
    fake = _worker(None)
    fake._ha_fence_timing.return_value = {'wait': 47}

    PegaProxManager._ha_recovery_worker(fake, 'pve2')

    fake._ha_fence_timing.assert_called_once_with('pve2')
    assert slept[0] == 47


def test_an_allowed_recovery_goes_on_and_fences_nothing_extra(no_sleep):
    fake = _worker([])

    PegaProxManager._ha_recovery_worker(fake, 'pve2')

    order = _order(fake)
    assert order.index('_ha_recovery_allowed') < order.index('_ha_check_node_via_ssh') \
        < order.index('_ha_ssh_stop_vms_on_node') < order.index('_ha_start_vm_on_node')
    fake._ha_fence_outside.assert_not_called()
    fake._ha_fence_node.assert_called_once_with('pve2')


def test_where_quorum_will_be_forced_the_fence_comes_before_any_start(no_sleep):
    fake = _worker(['pve2'])

    PegaProxManager._ha_recovery_worker(fake, 'pve2')

    order = _order(fake)
    fake._ha_fence_outside.assert_called_once_with('pve2', ['pve2'])
    assert order.index('_ha_ssh_stop_vms_on_node') < order.index('_ha_fence_outside') \
        < order.index('_ha_start_vm_on_node')
    # read back as off already: not powered off a second time
    fake._ha_fence_node.assert_not_called()


def test_a_fence_that_does_not_read_back_ends_the_recovery(no_sleep):
    fake = _worker(['pve2'], fence_ok=False)

    PegaProxManager._ha_recovery_worker(fake, 'pve2')

    fake._ha_fence_outside.assert_called_once()
    fake._ha_start_vm_on_node.assert_not_called()
    fake._ha_get_vms_on_node.assert_not_called()


# --- guest ids that go into the stop command ------------------------------------------------------

def test_a_guest_id_that_is_no_number_is_not_sent_to_the_node():
    """The ids can come from the heartbeat file on the shared storage. They went into
    `qm stop <id>` in a root shell on the node as they were."""
    m = _mgr()
    sent = []
    m._ssh_run_command_output = lambda ip, user, cmd, **kw: 'OK'
    m._ssh_run_command = lambda ip, user, cmd, *a, **kw: sent.append(cmd) or True

    ok = m._ha_ssh_stop_vms_on_node('pve2', vmids=['100', '101; reboot', '$(id)'], ctids=['200', '`id`'],
                                    reachable_ips=['10.9.0.2'])

    assert ok is False                      # what was not stopped is not reported as stopped
    assert sent == ['qm stop 100 --timeout 30 2>&1 || qm stop 100 --skiplock --timeout 30 2>&1',
                    'pct stop 200 --timeout 30 2>&1']
    assert m._ha_ssh_stop_vms_on_node('pve2', vmids=['100', 101], ctids=[], reachable_ips=['10.9.0.2']) is True


# --- which setups carry the switch ---------------------------------------------------------------

@pytest.mark.parametrize('saved,fencing,expected', [
    ({'two_node_mode': True}, {}, True),                                   # before the rules: keeps the old way
    ({'force_quorum_on_failure': True}, {}, True),
    # no key means a setup from before the rules, whatever fence the row holds: one
    # node with IPMI was read as "has a fence", and the other node lost its recovery
    ({'two_node_mode': True}, {'pve2': IPMI}, True),
    ({'two_node_mode': True}, {'pve2': {'type': 'ssh', 'host': 'x'}}, True),
    ({}, {}, False),
    ({'two_node_mode': False, 'force_quorum_on_failure': False}, {}, False),
    ({'two_node_mode': True, 'unsafe_two_node_recovery': False}, {}, False),   # stored: a new setup, or switched off
    ({'two_node_mode': True, 'unsafe_two_node_recovery': False}, {'pve2': IPMI}, False),
    ({'two_node_mode': True, 'unsafe_two_node_recovery': True}, {'pve2': IPMI}, True),
    ({'two_node_mode': True, 'unsafe_two_node_recovery': 'yes'}, {}, False),
])
def test_a_setup_from_before_the_rules_keeps_the_old_way_and_a_new_one_does_not(saved, fencing, expected):
    m = _mgr()
    del m.ha_config

    m._apply_ha_settings(dict(saved, fencing=fencing))

    assert m.ha_config['unsafe_two_node_recovery'] is expected
    assert m._ha_unsafe_two_node() is expected


def test_the_stored_settings_bring_back_what_the_installs_recorded():
    m = _mgr()
    del m.ha_config

    m._apply_ha_settings({'pegaprox_vmid': '900', 'agent_token': 'ab' * 32, 'claim_enabled': True,
                          'fence_agent_versions': {'pve1': 2}})

    assert m.ha_config['pegaprox_vmid'] == '900' and m.ha_config['agent_token'] == 'ab' * 32
    assert m.ha_config['claim_enabled'] is True and m.ha_config['fence_agent_versions'] == {'pve1': 2}
    m._apply_ha_settings({'claim_enabled': 'true'})
    assert m.ha_config['claim_enabled'] is False and m.ha_config['pegaprox_vmid'] == ''


def test_the_monitor_puts_the_switch_into_the_stored_settings(monkeypatch):
    monkeypatch.setattr(manager_mod, 'threading', types.SimpleNamespace(Thread=lambda **kw: MagicMock()))
    for stored, unsafe, expected in (({}, True, True), ({}, False, False),
                                     ({'unsafe_two_node_recovery': False}, True, False)):
        fake = MagicMock()
        fake.ha_thread = None
        fake.ha_config = {'storage_heartbeat_path': '/x', 'unsafe_two_node_recovery': unsafe}
        fake.config = types.SimpleNamespace(ha_settings=dict(stored), ha_enabled=False)
        fake._create_session.return_value.get.return_value.status_code = 500
        fake._ha_claim_enabled.return_value = False

        PegaProxManager.start_ha_monitor(fake)

        assert fake.config.ha_settings['unsafe_two_node_recovery'] is expected


# --- what the API reports and takes ----------------------------------------------------------------

URL = '/api/clusters/c1/ha/config'


@pytest.fixture
def cluster(ha_env, seed):
    seed.db.save_cluster('c1', dict(name='lab', host='10.9.0.1', user='root@pam', ssl_verification=False,
                                    fallback_hosts=[], ha_enabled=False, ha_settings={}, ssh_user='root',
                                    ssh_key='', ssh_port=22, cluster_type='proxmox', api_port=8006,
                                    **{'pass': 'pw'}))
    m = _mgr(status=_status(True))
    m.cluster_type = 'proxmox'
    m.ha_enabled, m.ha_check_interval, m.is_connected = False, 10, False
    m.ha_recovery_in_progress, m.ha_have_quorum, m.ha_last_quorum_check = {}, True, None
    m.ha_last_heartbeat_write = None
    m._apply_ha_settings({})
    ha_env.api.set_manager('c1', m)
    return types.SimpleNamespace(api=ha_env.api, seed=seed, mgr=m, db=seed.db,
                                 client=_admin(ha_env.api, seed))


def _stored(env):
    return env.db.get_cluster('c1')['ha_settings']


def _sbp(env):
    return env.client.get('/api/clusters/c1/ha').get_json()['split_brain_prevention']


def test_a_new_two_node_setup_gets_the_rules_and_the_status_says_what_it_needs(cluster):
    r = cluster.client.put(URL, json={'two_node_mode': True})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(cluster)['two_node_mode'] is True and _stored(cluster)['unsafe_two_node_recovery'] is False
    sbp = _sbp(cluster)
    assert sbp['unsafe_two_node_recovery'] is False and sbp['unsafe_two_node_warning'] is None
    assert sbp['verified_fence_required'] is True and sbp['verified_fence_configured'] is False
    # with two votes the node that is left keeps its guests: the note is not for it
    assert sbp['fenced_survivor_note'] is None
    cluster.mgr.ha_config['fence_strategy'] = {'strategy': 'wait', 'expected_votes': 2, 'two_node_flag': False}
    assert _sbp(cluster)['fenced_survivor_note'] is None
    cluster.mgr.ha_config['fence_strategy'] = {'strategy': 'quorum', 'expected_votes': 2, 'two_node_flag': True}
    assert _sbp(cluster)['fenced_survivor_note'] is None
    # with three or more a node without quorum stops its own guests: what becomes of them
    cluster.mgr.ha_config['fence_strategy'] = {'strategy': 'quorum', 'expected_votes': 3, 'two_node_flag': False,
                                              'detection_reason': 'detected'}
    assert cluster.mgr._ha_agent_plan(detect=False)['minority_fences'] is True
    note = _sbp(cluster)['fenced_survivor_note']
    assert note == PegaProxManager.FENCED_SURVIVOR_NOTE
    assert 'a node that loses quorum stops its own guests' in note
    assert 'PegaProx brings back the guests of the failed nodes after a verified fence' in note
    assert "the last node's own guests stay stopped until an admin starts them" in note
    assert "The 'unsafe two-node recovery' switch keeps the old behaviour" in note and 'at the old risk' in note
    # no agent brings a guest back: the note must not promise it
    assert 'again' not in note and 'automatic' not in note
    assert note.count('. ') == 1 and chr(0x2014) not in note            # two sentences


def test_the_note_on_the_fenced_survivor_is_for_setups_under_the_rules_only(cluster):
    assert _sbp(cluster)['fenced_survivor_note'] is None             # nothing forces quorum
    cluster.mgr._apply_ha_settings({'force_quorum_on_failure': True})       # from before the rules
    assert cluster.mgr._ha_unsafe_two_node() is True
    assert _sbp(cluster)['fenced_survivor_note'] is None


def test_the_status_reports_the_switch_so_the_ui_can_show_a_banner(cluster):
    cluster.mgr._apply_ha_settings({'two_node_mode': True})       # a setup from before the rules

    sbp = _sbp(cluster)

    assert sbp['unsafe_two_node_recovery'] is True
    assert 'without proof that the failed node is off' in sbp['unsafe_two_node_warning']
    assert sbp['verified_fence_required'] is False and sbp['force_quorum_on_failure'] is False


def test_switching_it_off_is_free_and_stays_off(cluster):
    cluster.mgr._apply_ha_settings({'two_node_mode': True})

    r = cluster.client.put(URL, json={'unsafe_two_node_recovery': False})

    assert r.status_code == 200 and _stored(cluster)['unsafe_two_node_recovery'] is False
    assert _sbp(cluster)['unsafe_two_node_recovery'] is False
    # and the stored value is what the next start reads, not what it would work out
    cluster.mgr._apply_ha_settings(_stored(cluster))
    assert cluster.mgr._ha_unsafe_two_node() is False


def test_switching_it_on_has_to_be_typed_out(cluster):
    cluster.client.put(URL, json={'two_node_mode': True})

    r = cluster.client.put(URL, json={'unsafe_two_node_recovery': True, 'recovery_delay': 99})
    assert r.status_code == 400 and r.get_json()['code'] == 'HA_UNSAFE_CONFIRM'
    assert _stored(cluster)['unsafe_two_node_recovery'] is False
    assert cluster.mgr.ha_config['recovery_delay'] != 99        # nothing of the request was applied

    r = cluster.client.put(URL, json={'unsafe_two_node_recovery': True, 'confirm_unsafe_two_node': 'UNSAFE',
                                     'recovery_delay': 99})
    assert r.status_code == 200 and _stored(cluster)['unsafe_two_node_recovery'] is True
    assert _sbp(cluster)['unsafe_two_node_recovery'] is True and cluster.mgr.ha_config['recovery_delay'] == 99

    # already on: saving the form again asks for nothing
    assert cluster.client.put(URL, json={'unsafe_two_node_recovery': True}).status_code == 200


@pytest.mark.parametrize('setup,off', [
    ({'force_quorum_on_failure': True}, {'force_quorum_on_failure': False}),
    ({'two_node_mode': True, 'force_quorum_on_failure': True}, {'two_node_mode': False, 'force_quorum_on_failure': False}),
], ids=['force-quorum', 'the-form'])
def test_the_switch_does_not_come_back_with_forced_quorum(cluster, setup, off):
    """It only counts where quorum gets forced, and the status reports it as off everywhere
    else. Stored on underneath, the next save of 2-node mode made a setup from before the
    rules unsafe again without the phrase, and the UI had shown it as off all along."""
    cluster.mgr._apply_ha_settings(setup)                  # from before the rules: derived on
    assert cluster.mgr._ha_unsafe_two_node() is True

    r = cluster.client.put(URL, json=off)

    assert r.status_code == 200, r.get_data(as_text=True)
    assert cluster.mgr.ha_config['unsafe_two_node_recovery'] is False
    assert _stored(cluster)['unsafe_two_node_recovery'] is False

    # forcing quorum again is a new setup under the rules
    r = cluster.client.put(URL, json={'two_node_mode': True, 'force_quorum_on_failure': True})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(cluster)['unsafe_two_node_recovery'] is False
    sbp = _sbp(cluster)
    assert sbp['unsafe_two_node_recovery'] is False and sbp['verified_fence_required'] is True
    cluster.mgr._apply_ha_settings(_stored(cluster))       # and so after a restart
    assert cluster.mgr._ha_unsafe_two_node() is False
    # going unsafe takes the phrase
    r = cluster.client.put(URL, json={'unsafe_two_node_recovery': True})
    assert r.status_code == 400 and r.get_json()['code'] == 'HA_UNSAFE_CONFIRM'
    r = cluster.client.put(URL, json={'unsafe_two_node_recovery': True, 'confirm_unsafe_two_node': 'UNSAFE'})
    assert r.status_code == 200 and _sbp(cluster)['unsafe_two_node_recovery'] is True


def test_a_switch_stored_on_without_forced_quorum_is_off(cluster):
    """A row written before the switch went with forced quorum: on, while nothing forces
    quorum. The status shows it as off, and so it is to the route: forcing quorum leaves it
    off, and switching it on wants the phrase like any switch that is off."""
    cluster.mgr._apply_ha_settings({'two_node_mode': False, 'unsafe_two_node_recovery': True})
    assert cluster.mgr.ha_config['unsafe_two_node_recovery'] is True and _sbp(cluster)['unsafe_two_node_recovery'] is False

    r = cluster.client.put(URL, json={'two_node_mode': True, 'unsafe_two_node_recovery': True})
    assert r.status_code == 400 and r.get_json()['code'] == 'HA_UNSAFE_CONFIRM'
    assert cluster.mgr.ha_config['two_node_mode'] is False             # nothing of it applied

    r = cluster.client.put(URL, json={'two_node_mode': True})
    assert r.status_code == 200
    assert _stored(cluster)['unsafe_two_node_recovery'] is False and cluster.mgr._ha_unsafe_two_node() is False
    assert _sbp(cluster)['verified_fence_required'] is True


def test_a_save_that_keeps_quorum_forced_keeps_the_switch(cluster):
    """The counterproof: a setup from before the rules that still forces quorum keeps the old
    way through a save of another setting, and an unsafe setup through a fence."""
    cluster.mgr._apply_ha_settings({'two_node_mode': True})

    assert cluster.client.put(URL, json={'recovery_delay': 40}).status_code == 200
    assert _stored(cluster)['unsafe_two_node_recovery'] is True and cluster.mgr._ha_unsafe_two_node() is True

    r = cluster.client.put(URL, json={'fencing': {'pve2': dict(IPMI)}})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _sbp(cluster)['unsafe_two_node_recovery'] is True


@pytest.mark.parametrize('sent', [
    {'recovery_delay': False}, {'recovery_delay': True}, {'failure_threshold': True}, {'failure_threshold': False},
    {'recovery_delay': '30'}, {'failure_threshold': '3'}, {'recovery_delay': None}, {'failure_threshold': [3]},
    {'recovery_delay': -1}, {'failure_threshold': -3}, {'recovery_delay': {}},
    {'recovery_delay': 45, 'failure_threshold': True},
])
def test_a_delay_or_threshold_that_is_no_number_is_refused_and_nothing_is_applied(cluster, sent):
    """The route stored both as they were sent. A JSON true is 1 to time.sleep and to
    the monitor's comparison and no number to the timing: the wait of a node with the
    v2 agent lost its floor, and its recovery began before the agent had stopped the
    guests."""
    m = cluster.mgr
    m.ha_config['fence_agent_versions'] = {'pve2': 2}
    need = PegaProxManager.FENCE_AGENT_T_SF + PegaProxManager.FENCE_AGENT_MARGIN
    assert m._ha_fence_timing('pve2')['earliest_recovery'] == need

    r = cluster.client.put(URL, json=dict(sent, two_node_mode=True))

    assert r.status_code == 400, r.get_data(as_text=True)
    body = r.get_json()
    assert body['code'] == 'HA_TIMING_INVALID' and 'must be a number' in body['error']
    assert m.ha_config['recovery_delay'] == 30 and m.ha_failure_threshold == 3
    assert m.ha_config['two_node_mode'] is False            # nothing of the request was applied
    assert 'recovery_delay' not in _stored(cluster) and 'failure_threshold' not in _stored(cluster)
    assert m._ha_fence_timing('pve2')['earliest_recovery'] == need


@pytest.mark.parametrize('raw', ['{"recovery_delay": NaN}', '{"recovery_delay": Infinity}',
                                 '{"failure_threshold": -Infinity}', '{"failure_threshold": NaN}'])
def test_a_number_that_cannot_be_counted_with_is_refused_too(cluster, raw):
    r = cluster.client.put(URL, data=raw, content_type='application/json')

    assert r.status_code == 400 and r.get_json()['code'] == 'HA_TIMING_INVALID', r.get_data(as_text=True)
    assert cluster.mgr.ha_config['recovery_delay'] == 30 and cluster.mgr.ha_failure_threshold == 3


@pytest.mark.parametrize('sent', [{'recovery_delay': 0}, {'recovery_delay': 45.5}, {'failure_threshold': 1},
                                  {'recovery_delay': 120, 'failure_threshold': 6}, {'failure_threshold': 0}])
def test_the_numbers_the_form_sends_are_taken_as_before(cluster, sent):
    """The counterproof: what was a valid setting stays one, zero included."""
    r = cluster.client.put(URL, json=sent)

    assert r.status_code == 200, r.get_data(as_text=True)
    stored = _stored(cluster)
    assert all(stored[k] == v for k, v in sent.items())
    assert cluster.mgr.ha_config['recovery_delay'] == sent.get('recovery_delay', 30)
    assert cluster.mgr.ha_failure_threshold == sent.get('failure_threshold', 3)


@pytest.mark.parametrize('stored,delay,threshold', [
    ({'recovery_delay': True, 'failure_threshold': True}, 30, 3),
    ({'recovery_delay': False, 'failure_threshold': False}, 30, 3),
    ({'recovery_delay': '45', 'failure_threshold': '2'}, 30, 3),
    ({'recovery_delay': None, 'failure_threshold': None}, 30, 3),
    ({'recovery_delay': -5, 'failure_threshold': -1}, 30, 3),
    ({'recovery_delay': float('nan'), 'failure_threshold': float('inf')}, 30, 3),
    ({'recovery_delay': 0, 'failure_threshold': 1}, 0, 1),               # what was valid stays
    ({'recovery_delay': 45.5, 'failure_threshold': 6}, 45.5, 6),
    ({}, 30, 3),
])
def test_a_stored_delay_or_threshold_that_is_no_number_is_not_brought_back(stored, delay, threshold):
    """A row written before the route refused them. The manager starts with the
    defaults instead, and the timing of a v2 node holds either way."""
    m = _mgr()
    del m.ha_config

    m._apply_ha_settings(dict(stored, fence_agent_versions={'pve2': 2}))

    assert m.ha_config['recovery_delay'] == delay and m.ha_failure_threshold == threshold
    assert type(m.ha_config['recovery_delay']) is not bool and type(m.ha_failure_threshold) is not bool
    need = PegaProxManager.FENCE_AGENT_T_SF + PegaProxManager.FENCE_AGENT_MARGIN
    assert m._ha_fence_timing('pve2')['earliest_recovery'] >= need


def test_saving_the_settings_keeps_what_the_installs_recorded(cluster):
    """The config route rebuilt the stored settings from its own fields. What the agent
    installs had put there was gone after the next save, and after a restart the
    instance no longer knew that its nodes run agents."""
    cluster.mgr.ha_config.update(self_fence_installed=True, self_fence_nodes=['pve1', 'pve2'],
                                 node_agent_installed={'pve1': True}, agent_token='ab' * 32,
                                 fence_agent_versions={'pve1': 2}, pegaprox_vmid='900')
    cluster.mgr.config.ha_settings = {'node_ips': {'pve1': '10.9.0.1'}, 'self_fence_installed': True}

    assert cluster.client.put(URL, json={'recovery_delay': 45}).status_code == 200

    stored = _stored(cluster)
    assert stored['recovery_delay'] == 45
    assert stored['self_fence_installed'] is True and stored['self_fence_nodes'] == ['pve1', 'pve2']
    assert stored['node_agent_installed'] == {'pve1': True} and stored['agent_token'] == 'ab' * 32
    assert stored['fence_agent_versions'] == {'pve1': 2} and stored['pegaprox_vmid'] == '900'
    assert stored['node_ips'] == {'pve1': '10.9.0.1'}             # a key no route writes stays
    # and a restart reads them back
    cluster.mgr._apply_ha_settings(stored)
    assert cluster.mgr.ha_config['self_fence_installed'] is True and cluster.mgr.ha_config['pegaprox_vmid'] == '900'


def test_the_agent_token_is_never_in_the_status(cluster):
    cluster.mgr.ha_config['agent_token'] = 'ab' * 32

    body = cluster.client.get('/api/clusters/c1/ha').get_data(as_text=True)

    assert 'ab' * 32 not in body and 'agent_token' not in body


def test_the_agents_are_redeployed_when_forcing_quorum_changes(cluster, monkeypatch):
    """Whether quorum is forced decides how the agents decide, so they are installed
    again; a change that does not touch it leaves them."""
    import pegaprox.api.clusters as clusters_api
    ran = []
    monkeypatch.setattr(clusters_api, 'threading', types.SimpleNamespace(
        Thread=lambda target=None, **kw: types.SimpleNamespace(start=lambda: ran.append(target.__name__))))
    cluster.mgr.ha_config['self_fence_installed'] = True

    cluster.client.put(URL, json={'recovery_delay': 31})
    assert ran == []
    cluster.client.put(URL, json={'force_quorum_on_failure': True})
    assert ran == ['_reinstall']
    # and when the unsafe switch changes: the leader then decides for a node without quorum
    cluster.client.put(URL, json={'unsafe_two_node_recovery': True, 'confirm_unsafe_two_node': 'UNSAFE'})
    assert ran == ['_reinstall'] * 2
    cluster.client.put(URL, json={'unsafe_two_node_recovery': True})
    assert ran == ['_reinstall'] * 2


def test_saving_a_setting_brings_the_v2_agents_up_to_date_and_installs_nothing(cluster, monkeypatch):
    """The redeploy after a change of pegaprox_vmid or of the two-node settings ran the
    install on every node. On a node with the agent of an older PegaProx that put v2
    there, as a side effect of saving a setting."""
    import pegaprox.api.clusters as clusters_api
    monkeypatch.setattr(clusters_api, 'threading', types.SimpleNamespace(
        Thread=lambda target=None, **kw: types.SimpleNamespace(start=target)))
    m = cluster.mgr
    m.ha_config.update(self_fence_installed=True, self_fence_nodes=['pve1', 'pve2'],
                       fence_agent_versions={'pve1': 2, 'pve2': 1})
    m._ha_install_self_fence_on_all_nodes = MagicMock(return_value={'pve1': True, 'pve2': True})
    m._ha_redeploy_fence_agents = MagicMock(return_value={'pve1': True})

    r = cluster.client.put(URL, json={'pegaprox_vmid': '900'})

    assert r.status_code == 200, r.get_data(as_text=True)
    m._ha_install_self_fence_on_all_nodes.assert_not_called()
    m._ha_redeploy_fence_agents.assert_called_once_with('the HA settings changed', wait=True)
    # the books keep both nodes: the pass answers for the ones it touched only
    assert _stored(cluster)['self_fence_nodes'] == ['pve1', 'pve2']
    assert r.get_json()['status']['fence_agent']['outdated'] == ['pve2']


# --- the teardown and the check over the API ----------------------------------------------------

def test_disabling_ha_takes_both_agents_off_and_keeps_the_books(cluster):
    m = cluster.mgr
    m.stop_ha_monitor = MagicMock()
    m._ha_cleanup_storage_heartbeat = MagicMock(return_value={'cleaned': True})
    m._ha_uninstall_agents_on_all_nodes = MagicMock(return_value={'pve1': True, 'pve2': False})
    m._ha_uninstall_self_fence_on_all_nodes = MagicMock(return_value={'pve1': True, 'pve2': True})
    m.ha_config.update(self_fence_installed=True, self_fence_nodes=['pve1', 'pve2'],
                       node_agent_installed={'pve1': True, 'pve2': True})

    r = cluster.client.post('/api/clusters/c1/ha/disable', json={})

    assert r.status_code == 200, r.get_data(as_text=True)
    m._ha_uninstall_agents_on_all_nodes.assert_called_once_with()
    m._ha_uninstall_self_fence_on_all_nodes.assert_not_called()     # that one leaves the node agent
    body = r.get_json()
    assert body['agents_failed'] == ['pve2']
    assert 'pegaprox-fence-agent.service' in body['warning'] and 'pegaprox-agent.service' in body['warning']
    stored = _stored(cluster)
    assert stored['node_agent_installed'] == {'pve2': True}
    assert stored['self_fence_nodes'] == ['pve2'] and stored['self_fence_installed'] is True


def test_the_agent_check_route_reports_and_stores_the_versions(cluster):
    node = {'fence_agent': {'version': 2, 'mode': 'quorum', 'active': True, 'sha256': 'x',
                            'legacy_shared_name': False, 'current': False},
            'node_agent': {'installed': False, 'active': False}, 'members_unreachable': []}
    old = dict(node, fence_agent=dict(node['fence_agent'], version=1, legacy_shared_name=True))

    def check():
        cluster.mgr.ha_config['fence_agent_versions'] = {'pve1': 2, 'pve2': 1}
        return {'nodes': {'pve1': node, 'pve2': old, 'pve3': None}, 'expected_version': 2,
                'mode': 'quorum', 'strategy': 'quorum', 'members': []}
    cluster.mgr._ha_check_agents = check

    r = cluster.client.post('/api/clusters/c1/ha/agent-check', json={})

    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['outdated'] == ['pve2'] and body['unreachable'] == ['pve3'] and body['not_current'] == ['pve1']
    assert _stored(cluster)['fence_agent_versions'] == {'pve1': 2, 'pve2': 1}
    assert 'on pve2 is version 1' in body['outdated_warning'] and 'keeps running as it is' in body['outdated_warning']
    status = cluster.client.get('/api/clusters/c1/ha').get_json()['fence_agent']
    assert status['expected_version'] == 2 and status['versions'] == {'pve1': 2, 'pve2': 1}
    # counted from the pass that first sees the node offline: pve1 waits for its v2
    # agent, pve2 two more checks and the recovery_delay of 30 s
    assert status['nodes'] == {'pve1': {'version': 2, 'outdated': False, 'earliest_recovery': 60},
                               'pve2': {'version': 1, 'outdated': True, 'earliest_recovery': 50}}
    assert status['outdated'] == ['pve2'] and status['outdated_warning'] == body['outdated_warning']
    assert 'two-node settings does not reach the version 1 agent on pve2' in status['outdated_settings_warning']
    assert status['fence_delay'] == 30


def test_the_status_has_nothing_to_offer_where_no_old_agent_runs(cluster):
    cluster.mgr.ha_config.update(self_fence_installed=True, self_fence_nodes=['pve1', 'pve2', 'pve3'],
                                 fence_agent_versions={'pve1': 2, 'pve2': 2}, recovery_delay=5)

    status = cluster.client.get('/api/clusters/c1/ha').get_json()['fence_agent']

    assert status['outdated'] == [] and status['outdated_warning'] is None
    assert status['outdated_settings_warning'] is None
    assert status['unchecked'] == ['pve3']              # installed, never looked at: the check tells
    # recovery_delay turned down: where v2 runs the recovery still waits for the agent
    assert status['nodes']['pve1'] == {'version': 2, 'outdated': False, 'earliest_recovery': 60}


def test_the_agent_check_is_for_who_may_configure_ha(cluster):
    api, seed = cluster.api, cluster.seed
    cluster.mgr._ha_check_agents = MagicMock(return_value=None)
    assert api.anon().post('/api/clusters/c1/ha/agent-check', json={}).status_code == 401
    assert api.as_user(seed.user('watcher', role='viewer')).post(
        '/api/clusters/c1/ha/agent-check', json={}).status_code == 403
    cluster.mgr._ha_check_agents.assert_not_called()
    # the cluster does not list its nodes: an error, not an empty report
    assert cluster.client.post('/api/clusters/c1/ha/agent-check', json={}).status_code == 502


def test_disabling_ha_keeps_the_books_when_no_node_was_reached(cluster):
    """The API host does not list the nodes at that moment (it is the node in trouble,
    the reason HA gets switched off). No agent was stopped or removed, and the empty
    result emptied the books: self_fence_installed off, no warning, no word in the
    audit line. The agents kept running and fencing with PegaProx saying there are
    none, and the redeploy, the stop and the start all ask that flag."""
    m = cluster.mgr
    m.stop_ha_monitor = MagicMock()
    m._ha_cleanup_storage_heartbeat = MagicMock(return_value={'attempted': False})
    m._ha_uninstall_agents_on_all_nodes = MagicMock(return_value={})      # /nodes answered 5xx
    m.ha_config.update(self_fence_installed=True, self_fence_nodes=['pve1', 'pve2'],
                       node_agent_installed={'pve1': True, 'pve2': True})

    r = cluster.client.post('/api/clusters/c1/ha/disable', json={})

    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['agents_total'] == 0 and body['agents_unconfirmed'] == ['pve1', 'pve2']
    assert 'no agent was stopped or removed' in body['warning'] and 'pve1, pve2' in body['warning']
    assert 'systemctl disable --now pegaprox-fence-agent.service pegaprox-agent.service' in body['warning']
    stored = _stored(cluster)
    assert stored['self_fence_installed'] is True and stored['self_fence_nodes'] == ['pve1', 'pve2']
    assert stored['node_agent_installed'] == {'pve1': True, 'pve2': True}
    assert m.ha_config['self_fence_installed'] is True
    assert 'manual cleanup required on: pve1, pve2' in _audit('ha.disabled')[0]['details']

    # books that only say "installed", without the nodes: the flag stays as well
    m.ha_config.update(self_fence_installed=True, self_fence_nodes=[], node_agent_installed={})
    body = cluster.client.post('/api/clusters/c1/ha/disable', json={}).get_json()
    assert 'every node of the cluster' in body['warning']
    assert _stored(cluster)['self_fence_installed'] is True


def test_disabling_ha_drops_a_node_only_when_its_own_teardown_answered(cluster):
    m = cluster.mgr
    m.stop_ha_monitor = MagicMock()
    m._ha_cleanup_storage_heartbeat = MagicMock(return_value={'attempted': False})
    m.ha_config.update(self_fence_installed=True, self_fence_nodes=['pve1', 'pve2', 'pve3'],
                       node_agent_installed={'pve1': True, 'pve3': True})
    # pve3 is not listed by the cluster just now
    m._ha_uninstall_agents_on_all_nodes = MagicMock(return_value={'pve1': True, 'pve2': True})

    body = cluster.client.post('/api/clusters/c1/ha/disable', json={}).get_json()

    assert body['agents_failed'] == [] and body['agents_unconfirmed'] == ['pve3']
    assert 'pve3' in body['warning']
    stored = _stored(cluster)
    assert stored['self_fence_nodes'] == ['pve3'] and stored['self_fence_installed'] is True
    assert stored['node_agent_installed'] == {'pve3': True}

    # counterproof: every node answered, the books are empty and there is nothing to say
    m.ha_config.update(self_fence_installed=True, self_fence_nodes=['pve1', 'pve2'],
                       node_agent_installed={'pve1': True})
    body = cluster.client.post('/api/clusters/c1/ha/disable', json={}).get_json()
    assert body['warning'] is None and body['agents_unconfirmed'] == []
    stored = _stored(cluster)
    assert stored['self_fence_installed'] is False and stored['self_fence_nodes'] == []
    assert stored['node_agent_installed'] == {}


def test_a_cluster_that_never_had_an_agent_is_disabled_without_a_warning(cluster):
    cluster.mgr.stop_ha_monitor = MagicMock()
    cluster.mgr._ha_cleanup_storage_heartbeat = MagicMock(return_value={'attempted': False})
    cluster.mgr._ha_uninstall_agents_on_all_nodes = MagicMock(return_value={})

    body = cluster.client.post('/api/clusters/c1/ha/disable', json={}).get_json()

    assert body['warning'] is None and _stored(cluster)['self_fence_installed'] is False


# --- the fence of each node can be configured ---------------------------------------------------

FENCING = {'pve1': dict(IPMI, host='10.8.0.1'), 'pve2': dict(IPMI)}


def test_the_fence_the_rules_ask_for_can_be_configured(cluster):
    """The rules read config.fencing, which nothing ever set: no field on the cluster
    config, no column, no route. verified_fence_configured was false on every cluster,
    a new two-node setup was never recovered, and the refusal told the admin to
    configure what could not be configured."""
    r = cluster.client.put(URL, json={'two_node_mode': True, 'fencing': FENCING})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(cluster)['fencing'] == FENCING
    sbp = _sbp(cluster)
    assert sbp['verified_fence_required'] is True and sbp['verified_fence_configured'] is True
    assert sbp['fencing'] == {
        'pve1': {'type': 'ipmi', 'host': '10.8.0.1', 'user': 'ADMIN', 'password_set': True, 'verifiable': True},
        'pve2': {'type': 'ipmi', 'host': '10.8.0.2', 'user': 'ADMIN', 'password_set': True, 'verifiable': True}}

    # the manager the next start builds from the row: the failed node can be fenced
    # and read back, so the recovery of a new two-node setup goes ahead
    m = _mgr(status=_status(False))
    m._apply_ha_settings(_stored(cluster))
    assert m._ha_unsafe_two_node() is False
    assert m._ha_recovery_allowed('pve2') == ['pve2']


def test_the_bmc_password_never_leaves_and_is_kept_when_a_form_leaves_it_out(cluster):
    cluster.client.put(URL, json={'fencing': FENCING})

    for path in ('/api/clusters/c1/ha', '/api/clusters/c1/ha/status'):
        assert 'bmc-pw' not in cluster.client.get(path).get_data(as_text=True)
    assert 'bmc-pw' not in cluster.client.put(URL, json={'recovery_delay': 31}).get_data(as_text=True)
    changed = _audit('ha.fencing_updated')
    assert len(changed) == 1 and 'pve1 (ipmi), pve2 (ipmi)' in changed[0]['details']
    assert 'bmc-pw' not in changed[0]['details']

    # the form sends back what the status gave it: no password
    r = cluster.client.put(URL, json={'fencing': {'pve2': {'type': 'ipmi', 'host': '10.8.0.9', 'user': 'ADMIN'}}})
    assert r.status_code == 200
    assert _stored(cluster)['fencing'] == {'pve1': FENCING['pve1'], 'pve2': dict(IPMI, host='10.8.0.9')}

    # null takes a node's fence away, the others stay
    assert cluster.client.put(URL, json={'fencing': {'pve1': None}}).status_code == 200
    assert list(_stored(cluster)['fencing']) == ['pve2']
    assert 'pve1 (removed)' in _audit('ha.fencing_updated')[-1]['details']


@pytest.mark.parametrize('fencing', [
    'ipmi', ['pve2'],
    {'pve2': 'ipmi'},
    {'pve2': {'type': 'telnet', 'host': '10.8.0.2'}},
    {'pve2': {'type': 'ipmi', 'host': '10.8.0.2'}},                              # no password to keep
    {'pve2': {'type': 'ipmi', 'password': 'x'}},                                 # no host
    {'pve2': dict(IPMI, host='-oProxyCommand=id')},
    {'pve2': dict(IPMI, host='10.8.0.2; reboot')},
    {'pve2': dict(IPMI, user='-l root')},
    {'pve2': dict(IPMI, password='a\nb')},
    {'pve2': dict(IPMI, password='x' * 300)},
    {'pve2"; id; "': dict(IPMI)},
    {'pve2': {'type': 'ssh', 'host': '$(id)'}},
])
def test_a_fence_without_a_shape_is_refused_and_nothing_of_the_request_is_applied(cluster, fencing):
    """Host and user end up on the command line of ipmitool or ssh on the PegaProx host."""
    r = cluster.client.put(URL, json={'fencing': fencing, 'recovery_delay': 77})

    assert r.status_code == 400 and r.get_json()['code'] == 'HA_FENCING_INVALID'
    assert cluster.mgr.ha_config['fencing'] == {} and cluster.mgr.ha_config['recovery_delay'] != 77
    assert not _stored(cluster).get('fencing')


def test_a_fence_in_a_stored_row_that_has_no_shape_is_left_out():
    m = _mgr()
    m._apply_ha_settings({'fencing': {'pve1': dict(IPMI), 'pve2': {'type': 'ipmi', 'host': '-x', 'password': 'p'},
                                      'pve3': 'ipmi', 'pve4"': dict(IPMI),
                                      'pve5': {'type': 'ssh'}, 'pve6': {'type': 'proxmox'}}})
    assert m.ha_config['fencing'] == {'pve1': IPMI, 'pve5': {'type': 'ssh'}, 'pve6': {'type': 'proxmox'}}
    m._apply_ha_settings({'fencing': 'ipmi'})
    assert m.ha_config['fencing'] == {}


def test_fencing_is_for_who_may_configure_ha(cluster):
    api, seed = cluster.api, cluster.seed
    assert api.anon().put(URL, json={'fencing': FENCING}).status_code == 401
    assert api.as_user(seed.user('watcher', role='viewer')).put(URL, json={'fencing': FENCING}).status_code == 403
    assert cluster.mgr.ha_config['fencing'] == {}


def test_the_fence_that_powers_a_node_off_reads_the_same_settings(monkeypatch):
    """_ha_fence_node, the fence of the old way, read config.fencing as well."""
    ipmi = Ipmi(monkeypatch)
    m = _mgr(fencing={'pve2': IPMI})

    assert m._ha_fence_node('pve2') is True and m._ha_fence_node('pve1') is False
    assert ipmi.calls == [('10.8.0.2', 'power off')]


def test_the_bmc_password_is_sealed_in_the_row_and_survives_a_key_rotation(db):
    db.save_cluster('c1', dict(name='lab', host='10.9.0.1', user='root@pam', ha_settings={'fencing': FENCING},
                               **{'pass': 'pw'}))
    raw = db.conn.cursor().execute("SELECT ha_settings FROM clusters WHERE id = 'c1'").fetchone()[0]
    assert raw.startswith('aes256:') and 'bmc-pw' not in raw and '10.8.0.2' not in raw

    assert db.rotate_encryption_key().get('success') is True

    assert db.get_cluster('c1')['ha_settings'] == {'fencing': FENCING}
    again = db.conn.cursor().execute("SELECT ha_settings FROM clusters WHERE id = 'c1'").fetchone()[0]
    assert again != raw and 'bmc-pw' not in again


# --- a refusal that can pass is tried again -------------------------------------------------------

def _monitored(listing=None, **ha_config):
    """A manager whose monitor pass (_ha_check_nodes) is the real one: pve1 online,
    pve2 offline, as the API host lists them. Recoveries are written down, not run."""
    m = _mgr(**ha_config)
    m.is_connected = True
    m.nodes_in_maintenance = set()
    m.ha_recovery_in_progress = {}
    m.ha_node_status = {n: {'status': 'online', 'consecutive_failures': 0, 'last_seen': None,
                            'last_status': 'online'} for n in ('pve1', 'pve2')}
    m.listing = listing or [{'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'offline'}]
    m.session_mock.get.side_effect = lambda url, timeout=10: MagicMock(
        status_code=200, json=lambda: {'data': m.listing})
    m._ha_check_restore_quorum = lambda: None
    m.triggered = []
    m._ha_trigger_recovery = m.triggered.append
    m.redeploys = []
    m._ha_redeploy_in_background = lambda why, only=None: m.redeploys.append((why, only))
    return m


@pytest.fixture
def quiet(monkeypatch):
    monkeypatch.setattr(manager_mod, 'broadcast_sse', lambda *a, **kw: None)


def _refuse_once(m, why):
    """Make the gate refuse for `why`; returns what takes the reason away again."""
    if why.startswith('claim-'):
        m.ha_config['claim_enabled'] = True
        m._ha_claim_ensure = lambda takeover=False: {'state': why[len('claim-'):], 'epoch': None}
        m._ha_cluster_quorum = lambda: (True, [])
        return lambda: setattr(m, '_ha_claim_ensure', lambda takeover=False: {'state': 'ours', 'epoch': 3})
    m._ha_cluster_quorum = {'status-not-read': lambda: (None, None), 'not-quorate': lambda: (False, ['pve2']),
                            'forced-status-not-read': lambda: (None, None)}[why]
    if why == 'forced-status-not-read':
        m.ha_config.update(two_node_mode=True, fencing={'pve2': IPMI})
    return lambda: setattr(m, '_ha_cluster_quorum', lambda: (True, []))


@pytest.mark.parametrize('why', ['claim-busy', 'claim-unreachable', 'claim-readonly', 'claim-failed',
                                 'status-not-read', 'not-quorate', 'forced-status-not-read'])
def test_a_refusal_that_can_pass_is_tried_again_while_the_node_stays_down(quiet, audits, why):
    """_ha_check_nodes starts a recovery once, on the pass that turns the node offline.
    The gate refuses for reasons that last a moment: the claim lock held by another
    writer, one SSH call that did not get through, one read of /cluster/status that
    timed out. The worker returned, and no later pass looked at the node again while
    it stayed offline - its guests stayed down for good, with one audit line."""
    m = _monitored()
    lift = _refuse_once(m, why)
    for _ in range(m.ha_failure_threshold):
        m._ha_check_nodes()
    assert m.triggered == ['pve2']

    assert m._ha_recovery_allowed('pve2') is None       # the worker's gate, then its cooldown
    m.ha_recovery_in_progress['pve2'] = True
    m._ha_check_nodes()
    assert m.triggered == ['pve2']                      # not while the last attempt cools down
    m.ha_recovery_in_progress.clear()

    m._ha_check_nodes()
    assert m.triggered == ['pve2', 'pve2']
    assert m._ha_recovery_allowed('pve2') is None       # still refused: again after the next cooldown
    m._ha_check_nodes()
    assert m.triggered == ['pve2'] * 3
    assert len(audits) == 1                             # the same refusal is said once

    lift()
    assert m._ha_recovery_allowed('pve2') is not None
    for _ in range(10):
        m._ha_check_nodes()
    assert m.triggered == ['pve2'] * 3                  # allowed: that recovery runs, nothing to try again


@pytest.mark.parametrize('why', ['claim-higher', 'claim-same', 'claim-unreadable', 'claim-standby', 'no-fence'])
def test_a_refusal_that_stands_is_not_tried_again(quiet, audits, why):
    """The counterproof: a foreign claim and a fence that is not configured do not go
    away by waiting."""
    m = _monitored()
    if why == 'no-fence':
        m.ha_config['two_node_mode'] = True
        m._ha_cluster_quorum = lambda: (False, ['pve2'])
    else:
        _refuse_once(m, why)
    for _ in range(m.ha_failure_threshold):
        m._ha_check_nodes()

    assert m._ha_recovery_allowed('pve2') is None
    for _ in range(10):
        m._ha_check_nodes()

    assert m.triggered == ['pve2']


def test_a_node_in_maintenance_or_back_online_is_not_tried_again(quiet, audits):
    m = _monitored()
    _refuse_once(m, 'status-not-read')
    for _ in range(m.ha_failure_threshold):
        m._ha_check_nodes()
    assert m._ha_recovery_allowed('pve2') is None

    m.nodes_in_maintenance.add('pve2')
    m._ha_check_nodes()
    assert m.triggered == ['pve2']

    m.nodes_in_maintenance.clear()
    m.listing = [{'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'online'}]
    m._ha_check_nodes()
    assert m.ha_node_status['pve2']['status'] == 'online' and m.triggered == ['pve2']
    # back for good: the mark is off, a later failure starts from the top and is audited anew
    m.listing = [{'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'offline'}]
    for _ in range(m.ha_failure_threshold):
        m._ha_check_nodes()
    assert m.triggered == ['pve2', 'pve2']
    assert m._ha_recovery_allowed('pve2') is None and len(audits) == 2


def test_a_node_that_is_back_gets_its_agent_looked_at(quiet):
    """It may have been down when the agents were brought up to date."""
    m = _monitored()
    m.ha_node_status['pve2']['status'] = 'offline'
    m.listing = [{'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'online'}]

    m._ha_check_nodes()
    m._ha_check_nodes()

    assert m.redeploys == [('node back online', 'pve2')]


# --- next to the minority: look from the quorate side ---------------------------------------------

NODES = ('pve1', 'pve2', 'pve3')
HOSTS = {'10.9.0.1': 'pve1', '10.9.0.2': 'pve2', '10.9.0.3': 'pve3'}


def _split(sides=(('pve1',), ('pve2', 'pve3')), dead=()):
    """Three nodes, this instance connected to pve1 (10.9.0.1), the cluster network
    split into `sides`. Every host answers for the side its node is on; `dead` are
    the hosts that do not answer at all."""
    m = _monitored()
    m.config.fallback_hosts = ['10.9.0.2', '10.9.0.3']
    m.ha_node_status = {n: {'status': 'online', 'consecutive_failures': 0, 'last_seen': None,
                            'last_status': 'online'} for n in NODES}
    m.asked = []

    def get(url, timeout=10, **kw):
        host = url.split('//')[1].split(':')[0]
        m.asked.append((host, url.rsplit('/', 1)[1]))
        if host in dead:
            raise ConnectionError('no route to host')
        seen = next(set(side) for side in sides if HOSTS[host] in side)
        if url.endswith('/cluster/status'):
            data = [{'type': 'cluster', 'name': 'lab', 'quorate': int(len(seen) * 2 > len(NODES))}] + [
                {'type': 'node', 'name': n, 'online': int(n in seen)} for n in NODES]
        else:
            data = [{'node': n, 'status': 'online' if n in seen else 'offline'} for n in NODES]
        return MagicMock(status_code=200, json=lambda: {'data': data})
    m.session_mock.get.side_effect = get
    return m


def test_next_to_the_minority_the_nodes_are_judged_from_the_quorate_side(quiet, audits):
    """pve1 loses the cluster network. Its agent stops its guests (quorum first), and
    PegaProx still gets answers from it: pve2 and pve3 offline, which is not recovered
    (right). Nothing ever asked pve2 or pve3, which are quorate and name pve1 as the
    node that is gone, so the guests the agent stopped on pve1 stayed down."""
    m = _split()

    for _ in range(m.ha_failure_threshold + 1):
        m._ha_check_nodes()

    assert m.current_host == '10.9.0.2'
    assert m.triggered == ['pve1']                                 # the node that is really outside
    assert m.ha_node_status['pve2']['status'] == 'online' and m.ha_node_status['pve3']['status'] == 'online'
    assert m.ha_node_status['pve2']['consecutive_failures'] == 0   # never counted against the majority
    assert m._ha_recovery_allowed('pve1') == [] and audits == []


def test_the_gate_looks_from_the_quorate_side_before_it_refuses(quiet, audits):
    """A recovery that was started from the minority side, before the monitor looked."""
    m = _split()

    assert m._ha_recovery_allowed('pve2') is None

    assert m.current_host == '10.9.0.2'
    assert 'online in the quorate part of the cluster' in audits[0][1]
    assert 'pve2' not in m.__dict__.get('_ha_recovery_retry', ())
    # and the node that is outside, asked from there, is recovered
    assert m._ha_recovery_allowed('pve1') == []


def test_where_quorum_would_be_forced_the_majority_is_not_powered_off(quiet, audits, monkeypatch):
    """force_quorum_on_failure with a fence on every node: from the minority side the
    rules would power off pve2 and pve3, the healthy majority, and force quorum on
    pve1. The look comes first."""
    ipmi = Ipmi(monkeypatch)
    m = _split()
    m.ha_config.update(force_quorum_on_failure=True,
                       fencing={n: dict(IPMI, host=f'10.8.0.{n[-1]}') for n in NODES})

    assert m._ha_recovery_allowed('pve2') is None
    assert ipmi.calls == [] and m.current_host == '10.9.0.2'


def test_without_a_quorate_side_this_instance_stays_where_it_is(quiet, audits):
    """The counterproof: the other hosts do not answer, or are no better off. Nothing
    changes, and the recovery is refused as before."""
    m = _split(dead=('10.9.0.2', '10.9.0.3'))
    for _ in range(m.ha_failure_threshold):
        m._ha_check_nodes()
    assert m.current_host == '10.9.0.1' and sorted(m.triggered) == ['pve2', 'pve3']
    assert m._ha_recovery_allowed('pve2') is None and 'minority side' in audits[0][1]

    m = _split(sides=(('pve1',), ('pve2',), ('pve3',)))        # every node on its own: nobody is quorate
    for _ in range(m.ha_failure_threshold):
        m._ha_check_nodes()
    assert m.current_host == '10.9.0.1'


def test_the_monitor_does_not_ask_around_on_every_pass(quiet, monkeypatch):
    """With every other host down each look costs a timeout: one look per 30 s, and
    none at all while every node is up or the API host is quorate."""
    clock = [1000.0]
    monkeypatch.setattr(manager_mod, 'time', types.SimpleNamespace(
        sleep=lambda s: None, monotonic=lambda: clock[0], time=lambda: 0))
    m = _split(dead=('10.9.0.2', '10.9.0.3'))

    def looks():
        return [h for h, what in m.asked if h != '10.9.0.1']

    for _ in range(3):
        m._ha_check_nodes()
        clock[0] += 10
    assert sorted(looks()) == ['10.9.0.2', '10.9.0.3']
    m._ha_check_nodes()
    assert len(looks()) == 4                           # 30 s later

    quorate = _split(sides=(('pve1', 'pve2'), ('pve3',)))      # this side is the majority
    for _ in range(5):
        quorate._ha_check_nodes()
        clock[0] += 60
    assert {h for h, _w in quorate.asked} == {'10.9.0.1'}


def test_the_nodes_outside_are_asked_by_their_address_eight_at_a_time(quiet):
    """A cluster of many nodes: the hosts to ask are the nodes the API host has
    outside, by the address /cluster/status gives, then the registered and fallback
    hosts. Eight per look, the next ones on the next."""
    m = _mgr()
    m.config.fallback_hosts = ['10.9.0.200']
    m._ha_status_ips = {f'pve{i:02d}': f'10.9.1.{i}' for i in range(1, 21)}
    asked = []
    m._ha_cluster_status = lambda host=None, timeout=10: asked.append(host) or None

    assert m._ha_move_to_quorate_side(now=True) is False
    assert sorted(asked) == [f'10.9.1.{i}' for i in range(1, 9)]
    asked.clear()
    m._ha_move_to_quorate_side(now=True)
    assert sorted(asked) == sorted(f'10.9.1.{i}' for i in range(9, 17))
    asked.clear()
    m._ha_move_to_quorate_side(now=True)
    assert set(asked) == {'10.9.1.17', '10.9.1.18', '10.9.1.19', '10.9.1.20', '10.9.0.200',
                          '10.9.1.1', '10.9.1.2', '10.9.1.3'}
