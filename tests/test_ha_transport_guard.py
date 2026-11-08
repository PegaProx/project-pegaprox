"""The transport guard (#625 stage 2, design 5.3 and 5.4).

In an automatic group a call that changes something on a cluster, a node or a BMC
goes out only from the lease holder, and only after a majority round that started after
it was asked for: the token confirm_lease() leaves in a thread covers one call, every
further call of a step, of a user job or of a request gets a round of its own, and a
background thread that never confirmed is refused. Reads pass, the console proxies and
the logins pass.
In a manual group and on an instance of its own nothing is asked: no round, no
token, no new way to fail. And what goes through each kind of exit (a requests
session, XenAPI, pyvmomi, a paramiko client, node_cmd) is what the guard decides.

MK Oct 2026 (#625)
"""
import subprocess
import sys
import time
import types
from unittest.mock import MagicMock

import gevent
import pytest
import requests

from pegaprox.core import ha as _ha
from pegaprox.core import ha_transport as hx
from test_ha_members import IDS, group  # noqa: F401
from _ha_lease_harness import T, auto  # noqa: F401

# what this file tests is the refusal itself (tests/conftest.py fails any other test the
# guard refuses a write for want of a confirmed lease)
pytestmark = pytest.mark.guard_refusals

START = 'https://10.0.0.1:8006/api2/json/nodes/pve1/qemu/101/status/start'
CONFIG = 'https://10.0.0.1:8006/api2/json/nodes/pve1/qemu/101/config'


def _refused(fn, *args, **kwargs):
    with pytest.raises(_ha.GuardRefused) as e:
        fn(*args, **kwargs)
    return str(e.value)


def _rounds(monkeypatch, ha):
    """The need of every confirm_lease() from here on, the guard's own included."""
    asked = []
    real = ha.confirm_lease
    monkeypatch.setattr(ha, 'confirm_lease', lambda need=ha.NEED_STEP: asked.append(need) or real(need))
    return asked


# --- the rule ---------------------------------------------------------------------------

def test_a_background_write_without_a_token_is_refused_and_named(auto, seed):
    auto.form(seed)
    with auto.at('a') as ha:
        assert ha.is_active()
        why = _refused(hx.guard_http, 'POST', START)
    assert why.startswith('POST /api2/json/nodes/pve1/qemu/N/status/start refused')
    assert 'no step in this thread confirmed the lease first' in why


def test_a_token_is_good_for_one_call_and_every_further_call_gets_a_round(auto, seed, monkeypatch):
    """The decision on the review of S4: a local clock cannot see a pause that held it, so
    no call rides on a round that confirmed another one."""
    auto.form(seed)
    with auto.at('a') as ha:
        rounds = _rounds(monkeypatch, ha)
        assert ha.confirm_lease()
        tok = ha._guard_tls.token
        node = ha._rts[IDS['a']].node
        assert tok.until == pytest.approx(node.lease_until) and tok.need == ha.NEED_STEP
        hx.guard_http('POST', START)              # on the round of the confirm
        assert tok.used and len(rounds) == 1
        hx.guard_http('PUT', CONFIG)              # a round of its own
        assert len(rounds) == 2 and ha._guard_tls.token is not tok
        # an unused token past its own window is not used either: a round first, while
        # the lease itself still runs
        assert ha.confirm_lease()
        tok = ha._guard_tls.token
        auto.advance(tok.until - tok.need - ha.ha_clock() + 0.5)
        assert ha.is_active()
        hx.guard_http('POST', START)
        assert len(rounds) == 4 and not tok.used


def test_the_need_of_a_same_goal_step_is_none(auto, seed):
    auto.form(seed)
    with auto.at('a') as ha:
        assert ha.confirm_lease(ha.NEED_SAME_GOAL)
        node = ha._rts[IDS['a']].node
        tok = ha._guard_tls.token
        assert (tok.until, tok.need) == (pytest.approx(node.lease_until), 0.0)


def test_a_token_from_another_node_does_not_count(auto, seed):
    auto.form(seed)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        ha._guard_tls.token.gen += 1
        assert 'ran out' in _refused(hx.guard_http, 'POST', START)
        assert ha.confirm_lease()
        ha._guard_tls.token.instance = IDS['b']
        _refused(hx.guard_http, 'POST', START)


def test_an_exit_that_asks_for_more_lease_time_gets_it(auto, seed, monkeypatch):
    """Design 5.4: a change inside /etc/pve or corosync wants NEED_STEP left, also after a
    same-goal step (need 0) confirmed in the same thread."""
    auto.form(seed)
    registered = []
    monkeypatch.setattr(_ha, 'register_child_group', registered.append)
    with auto.at('a') as ha:
        assert ha.confirm_lease(ha.NEED_SAME_GOAL)
        node = ha._rts[IDS['a']].node
        tok = ha._guard_tls.token
        # less than NEED_STEP of that lease left: the same-goal call goes out on the token.
        # The wall clock of a moves with its lease clock, as it does outside the harness:
        # one that stood still would be a step of the clock, and void the token (4.2)
        dt = node.lease_until - ha.NEED_STEP - ha.ha_clock() + 0.5
        auto.advance(dt)
        auto.skew['a'] = auto.skew.get('a', 0.0) + dt
        rounds = _rounds(monkeypatch, ha)
        ha.guard('ipmitool pve2 power')
        assert tok.used and rounds == []
        # the change does not: a round of its own that leaves it NEED_STEP
        ha.guard('ssh pve1 mv', need=ha.NEED_STEP)
        assert rounds == [ha.NEED_STEP]
        assert node.lease_until - ha.ha_clock() >= ha.NEED_STEP
        # and without a majority node_cmd starts nothing
        auto.isolate('a')
        why = _refused(hx.node_cmd, ['ssh', 'root@10.0.0.11', 'mv a b'], timeout=5, need=ha.NEED_STEP)
    assert ha.GUARD_UNCONFIRMED in why and registered == []


def test_reads_the_consoles_and_the_logins_pass_without_a_token(auto, seed):
    auto.form(seed)
    for n in 'ab':
        with auto.at(n) as ha:
            hx.guard_http('GET', START)
            hx.guard_http('POST', 'https://10.0.0.1:8006/api2/json/nodes/pve1/qemu/101/vncproxy')
            hx.guard_http('POST', 'https://10.0.0.1:8006/api2/json/nodes/pve1/termproxy')
            hx.guard_http('POST', 'https://10.0.0.1:8006/api2/json/access/ticket')
            hx.guard_http('POST', 'https://esxi.example/api/session')
            with ha.reading():
                hx.guard_ssh('10.0.0.11', 'qm list')


def test_a_member_without_the_lease_refuses_every_change_whatever_the_context(auto, seed):
    auto.form(seed)
    with auto.at('b') as ha:
        assert not ha.is_active()
        with auto.g.api.app.test_request_context('/'):
            why = _refused(hx.guard_http, 'POST', START)
        assert 'does not hold the lease' in why
        # not even the spare API token a login would mint
        _refused(hx.guard_http, 'POST', 'https://h:8006/api2/json/access/users/root@pam/token/pegaprox_1')
        _refused(hx.guard_ssh, '10.0.0.11', 'qm stop 101')


def test_a_request_on_the_holder_asks_for_a_round_for_each_write(auto, seed, monkeypatch):
    auto.form(seed)
    with auto.at('a') as ha:
        rounds = _rounds(monkeypatch, ha)
        with auto.g.api.app.test_request_context('/', method='POST'):
            hx.guard_http('POST', START)
            hx.guard_http('POST', START)
        assert rounds == [ha.NEED_STEP, ha.NEED_STEP]
        # the request is over: a background write that confirmed nothing is refused
        ha._guard_tls.token = None
        _refused(hx.guard_http, 'POST', START)
        # the spare API token needs the lease and no round (design 5.2: cheap)
        hx.guard_http('POST', 'https://h:8006/api2/json/access/users/root@pam/token/pegaprox_1')
        assert len(rounds) == 2


def test_the_leader_in_its_takeover_wait_sends_nothing(auto, seed):
    auto.form(seed)
    with auto.at('a') as ha:
        node = ha._rts[IDS['a']].node
        node.acting_from = ha.ha_clock() + 30
        assert not ha.is_active() and ha.holds_lease()
        why = _refused(hx.guard_http, 'POST', START)
    assert 'does not hold the lease' in why


def test_a_lost_lease_refuses_a_token_that_had_time_left(auto, seed):
    auto.form(seed)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        hx.guard_http('POST', START)
        node = ha._rts[IDS['a']].node
        node.lease_until = ha.ha_clock() - 0.1
        why = _refused(hx.guard_http, 'POST', START)
    assert 'does not hold the lease' in why


def test_a_refusal_in_a_test_is_seen_however_the_code_took_it(auto, seed):
    """Design 5.3: in a test a background write without a confirmed lease fails the test
    (tests/conftest.py), also where a broad except swallowed the refusal. A member
    without the lease refusing is no such write."""
    from conftest import unconfirmed_writes
    auto.form(seed)
    with auto.at('b'):
        _refused(hx.guard_http, 'POST', START)
    assert unconfirmed_writes() == []
    with auto.at('a'):
        try:
            hx.guard_http('POST', START)
        except Exception:
            pass                    # what a loop with a broad except does
    assert unconfirmed_writes() == ['POST /api2/json/nodes/pve1/qemu/N/status/start']


def test_the_refusal_is_logged_once_per_exit(auto, seed, caplog):
    auto.form(seed)
    with auto.at('a'):
        for _ in range(5):
            _refused(hx.guard_http, 'POST', START)
        _refused(hx.guard_http, 'POST', START.replace('101', '102'))   # the same exit
        _refused(hx.guard_http, 'DELETE', CONFIG)
    said = [r.message for r in caplog.records if 'refused at the transport' in r.message]
    assert len(said) == 2, said


# --- where the token comes from and where it goes ---------------------------------------

def test_a_fan_out_carries_the_token_and_a_greenlet_of_its_own_has_none(auto, seed):
    auto.form(seed)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        seen = []

        def send():
            try:
                hx.guard_http('POST', START)
                seen.append('sent')
            except ha.GuardRefused:
                seen.append('refused')
        gevent.spawn(ha.carry(send)).join()
        gevent.spawn(send).join()
        from pegaprox.utils.concurrent import run_concurrent, run_per_node
        run_concurrent([send])
        run_per_node({'pve1': lambda node: send()})
        from pegaprox.core.manager import run_concurrent as mgr_run
        mgr_run([send])
    assert seen == ['sent', 'refused', 'sent', 'sent', 'sent']


def test_a_user_job_asks_for_the_lease_at_the_exit(auto, seed, monkeypatch):
    auto.form(seed)
    with auto.at('a') as ha:
        asked = []
        real = ha.confirm_lease
        monkeypatch.setattr(ha, 'confirm_lease', lambda need=ha.NEED_STEP: asked.append(need) or real(need))

        def job():
            hx.guard_http('POST', START)
            hx.guard_http('POST', START)          # a round of its own as well
        ha.as_job(job, 'a test job')()
        assert len(asked) == 2
        # and a job whose leader lost the lease is refused at its next call
        auto.isolate('a')
        auto.advance(T.per_round + 1)
        _refused(ha.as_job(job, 'a test job'))



def test_confirm_step_says_why_it_did_not_start(auto, seed, caplog):
    auto.form(seed)
    auto.isolate('a')
    with auto.at('a') as ha:
        assert ha.confirm_step('moving the config of 101') is False
    assert any('moving the config of 101: not started' in r.message for r in caplog.records)


# --- manual mode and an instance of its own: nothing changes ----------------------------

@pytest.fixture
def no_lease_machinery(monkeypatch):
    """Anything of the lease the guard could reach explodes."""
    def boom(*a, **k):
        raise AssertionError('the guard asked the lease machinery outside an automatic group')
    for name in ('_lease_live', '_lease_node', '_token_fits', '_in_request', '_request_method',
                 '_guard_refuse'):
        monkeypatch.setattr(_ha, name, boom)
    return boom


def _every_exit_passes():
    hx.guard_http('POST', START)
    hx.guard_http('DELETE', CONFIG)
    hx.guard_ssh('10.0.0.11', 'pvecm expected 1')
    _ha.guard('poison pill for pve2')
    client = hx.guard_client(MagicMock(), '10.0.0.11')
    client.exec_command('qm stop 101')
    session = hx.guard_xapi(types.SimpleNamespace(xenapi_request=lambda m, p: 'ok'))
    assert session.xenapi_request('VM.start', ()) == 'ok'


def test_on_an_instance_of_its_own_every_exit_passes_unasked(no_lease_machinery):
    assert _ha.role() == _ha.ROLE_STANDALONE
    _every_exit_passes()
    assert _ha.confirm_lease() is True and getattr(_ha._guard_tls, 'token', None) is None
    assert _ha.confirm_step('a step') is True
    assert _ha.carry(_every_exit_passes) is _every_exit_passes
    assert _ha.as_job(_every_exit_passes, 'x') is _every_exit_passes


def test_in_a_manual_group_every_exit_passes_unasked(auto, seed, monkeypatch):
    auto.pair(seed)
    for n in 'ab':
        with auto.at(n) as ha, monkeypatch.context() as m:
            assert ha.mode() == 'manual' and not ha.guard_on()
            for name in ('_lease_live', '_lease_node', '_token_fits', '_in_request', '_request_method'):
                m.setattr(ha, name, lambda *a, **k: pytest.fail('asked the lease'))
            _every_exit_passes()
            # no round trip: a confirm is the role, at once
            m.setattr(ha, '_lease_wait', lambda done, s: pytest.fail('waited for a round'))
            assert ha.confirm_lease() is (n == 'a')


def test_node_cmd_is_subprocess_run_as_it_was_outside_an_automatic_group(monkeypatch):
    seen = []
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: seen.append((argv, kw)) or 'done')
    argv = ['ssh', '-o', 'BatchMode=yes', 'root@10.0.0.11', 'qm list']
    assert hx.node_cmd(argv, capture_output=True, text=True, timeout=30, host='10.0.0.11') == 'done'
    assert seen == [(argv, {'capture_output': True, 'text': True, 'timeout': 30})]


def test_the_guard_costs_nothing_worth_measuring_outside_an_automatic_group():
    """Manual mode and standalone: one look at the cached state per call. Measured, not
    assumed: well under a microsecond per guarded write here, against the milliseconds a
    PVE call takes."""
    n = 20000
    t0 = time.perf_counter()
    for _ in range(n):
        hx.guard_http('POST', START)
    per_call = (time.perf_counter() - t0) / n
    assert per_call < 20e-6, per_call


# --- the exits ----------------------------------------------------------------------------

def test_a_guarded_session_asks_before_send_and_once_the_connection_is_up(auto, seed, monkeypatch):
    auto.form(seed)
    sess = hx.guard_session(requests.Session())
    assert sess.adapters['https://'].poolmanager.pool_classes_by_scheme['https'] is hx._GuardedHTTPSPool
    # the connection class asks once it is up: a call that reaches it unasked is stopped
    conn = hx._GuardedHTTPSConnection('127.0.0.1', 9)
    with auto.at('a'):
        _refused(conn.request, 'POST', '/api2/json/nodes/pve1/qemu/101/status/start')
        _refused(sess.post, START)
        # a read goes on to the network (and fails there, nobody listens)
        with pytest.raises(requests.exceptions.RequestException):
            sess.get('https://127.0.0.1:9/api2/json/version', timeout=0.5)


def test_the_cluster_session_of_a_manager_is_guarded(auto, seed):
    from pegaprox.core.manager import PegaProxManager
    mgr = PegaProxManager.__new__(PegaProxManager)
    mgr._api_token, mgr._ticket, mgr._csrf_token, mgr._ssl_verify = None, 't', 'c', False
    sess = mgr._create_session()
    assert getattr(sess, '_ha_guarded', False) is True
    auto.form(seed)
    with auto.at('a'):
        _refused(sess.post, START)


def test_xapi_writes_ask_and_reads_do_not(auto, seed):
    sent = []
    session = types.SimpleNamespace(xenapi_request=lambda m, p: sent.append(m) or 'ok')
    hx.guard_xapi(session)
    auto.form(seed)
    with auto.at('a') as ha:
        for read in ('VM.get_all', 'VM.get_record', 'host.get_hostname', 'event.from',
                     'session.get_uuid', 'task.get_status', 'VM.assert_can_migrate'):
            assert session.xenapi_request(read, ()) == 'ok'
        for write in ('VM.start', 'Async.VM.pool_migrate', 'VM.hard_shutdown', 'VDI.destroy'):
            _refused(session.xenapi_request, write, ())
        assert ha.confirm_lease()
        assert session.xenapi_request('Async.VM.pool_migrate', ()) == 'ok'
    assert hx.xapi_action('Async.VM.pool_migrate') == 'XAPI VM.pool_migrate'
    assert hx.xapi_action('login_with_password') is None


def test_soap_tasks_ask_and_property_reads_do_not(auto, seed):
    sent = []
    stub = types.SimpleNamespace(InvokeMethod=lambda mo, info, args: sent.append(info.wsdlName))
    si = types.SimpleNamespace(_stub=stub)
    hx.guard_soap(si)
    auto.form(seed)
    with auto.at('a'):
        for read in ('RetrieveProperties', 'CurrentTime', 'SearchDatastore_Task'):
            stub.InvokeMethod(None, types.SimpleNamespace(wsdlName=read), ())
        for write in ('PowerOnVM_Task', 'CreateSnapshot_Task', 'ShutdownGuest'):
            _refused(stub.InvokeMethod, None, types.SimpleNamespace(wsdlName=write), ())
    assert sent == ['RetrieveProperties', 'CurrentTime', 'SearchDatastore_Task']


def test_a_paramiko_client_asks_for_each_command(auto, seed):
    client = MagicMock()
    hx.guard_client(client, '10.0.0.11')
    auto.form(seed)
    with auto.at('a') as ha:
        _refused(client.exec_command, 'qm stop 101')
        _refused(client.open_sftp)
        with ha.reading():
            client.exec_command('qm list')
        assert ha.confirm_lease()
        client.exec_command('qm stop 101')


def test_node_cmd_in_an_automatic_group_is_bounded_in_a_group_of_its_own(auto, seed, monkeypatch):
    auto.form(seed)
    registered, forgotten = [], []
    monkeypatch.setattr(_ha, 'register_child_group', registered.append)
    monkeypatch.setattr(_ha, 'forget_child_group', forgotten.append)
    with auto.at('a') as ha:
        _refused(hx.node_cmd, ['ssh', 'root@10.0.0.11', 'qm stop 101'], timeout=5)
        assert registered == []
        # a read passes; it runs under `timeout -k 2 <bound>` in a session of its own
        script = 'import os; print(os.getsid(0) == os.getpid(), os.getppid())'
        r = hx.node_cmd([sys.executable, '-c', script], timeout=5, read=True,
                        capture_output=True, text=True)
        assert r.returncode == 0 and r.stdout.split()[0] in ('True', 'False')
        assert registered and registered == forgotten
        # the bound holds as subprocess.run's timeout did: TimeoutExpired, and the group is gone
        assert ha.confirm_lease()
        t0 = time.monotonic()
        with pytest.raises(subprocess.TimeoutExpired):
            hx.node_cmd([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=1,
                        capture_output=True)
        assert time.monotonic() - t0 < 10


def test_the_poison_pill_is_an_exit_too(auto, seed, tmp_path):
    from pegaprox.core.manager import PegaProxManager
    mgr = PegaProxManager.__new__(PegaProxManager)
    (tmp_path / '.pegaprox').mkdir()
    mgr.ha_config = {'storage_heartbeat_path': str(tmp_path)}
    mgr.id, mgr.logger = 'c1', MagicMock()
    auto.form(seed)
    with auto.at('a') as ha:
        assert mgr._ha_write_poison_pill('pve2', 'test') is False
        assert not (tmp_path / '.pegaprox' / 'poison_pve2').exists()
        assert ha.confirm_lease(ha.NEED_SAME_GOAL)
        assert mgr._ha_write_poison_pill('pve2', 'test') is True


# --- what it costs in an automatic group ---------------------------------------------------

def test_what_a_guarded_write_costs_on_the_leader(auto, seed):
    """The check again on the token a call went out on (the connection up, a retry): a
    look at the state, the node and the lease clock. And a write with its round, which
    in this harness runs both voters' routes in this process. Measured, so the figures in
    the slice report are these."""
    auto.form(seed)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        hx.guard_http('POST', START)
        n = 5000
        t0 = time.perf_counter()
        for _ in range(n):
            hx.guard_http('POST', START, again=True)
        again = (time.perf_counter() - t0) / n
        n = 20
        t0 = time.perf_counter()
        for _ in range(n):
            hx.guard_http('POST', START)
        with_round = (time.perf_counter() - t0) / n
    print(f'\ncheck again {again * 1e6:.1f} us, a write with its round {with_round * 1e3:.2f} ms')
    assert again < 200e-6, again
    assert with_round < 0.5, with_round
